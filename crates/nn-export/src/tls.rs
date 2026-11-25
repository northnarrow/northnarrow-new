//! The TLS client of the syslog sink (lot 276): rustls with the RustCrypto
//! provider (the founder's decision: TLS in Rust only), narrowed to what
//! the export needs and to what the recorded advisories leave reachable
//! (`.cargo/audit.toml`, `docs/operator/EXPORT.md` §7):
//!
//! - TLS 1.3 only (rustls is built without TLS 1.2);
//! - its three TLS 1.3 suites (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305);
//! - key exchange by **X25519 only**, our own group, which refuses a shared
//!   secret of all zeros (RFC 8446 §7.4.2; the provider's does not): the
//!   provider's P-256 and P-384 groups are removed, so their crypto-bigint
//!   never computes on a secret — it verifies signatures, on public data
//!   (crypto-bigint 0.7.11 since lot 398, patched for RUSTSEC-2026-0387;
//!   the narrowing stays: the least code on a secret);
//! - no client certificate, and a key provider that loads no private key:
//!   rsa's private-key paths (rsa 0.10 since lot 398, patched for
//!   RUSTSEC-2023-0071, Marvin) and ECDSA signing never run — an RSA
//!   certificate of the receiver is verified with its public key only (the
//!   provider has no RSA decryption at all);
//! - the receiver's chain checked by rustls' own WebPKI verifier (its
//!   rustls-webpki 0.103), against the CA bundle the signed configuration
//!   pins — the only rustls-webpki in the build: the provider takes its
//!   `alg_id` constants from rustls-pki-types since 0.1.0 (lot 398), and
//!   its copy of rustls-webpki 0.102 left the lockfiles.

use std::sync::Arc;

use nn_proto::ipc::{SinkFault, TlsFault};
use rustls::crypto::{ActiveKeyExchange, CryptoProvider, SharedSecret, SupportedKxGroup};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, NamedGroup, RootCertStore, SupportedCipherSuite};

/// The provider, narrowed (the module's documentation).
pub fn provider() -> CryptoProvider {
    let mut p = rustls_rustcrypto::provider();
    p.cipher_suites
        .retain(|s| matches!(s, SupportedCipherSuite::Tls13(_)));
    // X25519 alone, and ours: the provider's does not refuse a shared
    // secret of all zeros (a peer's key of small order)
    p.kx_groups = vec![&X25519Contributory];
    // the hello's randoms from the generator the key exchange draws from
    p.secure_random = &OsRandom;
    // a unit value: promoted to 'static, no process-wide state
    p.key_provider = &NoKeys;
    p
}

/// The OS generator, the provider's one source of randomness: the key
/// exchange's secret ([`X25519Contributory`]) and the client hello's
/// random and session id ([`OsRandom`]). It is getrandom's `SysRng`, as
/// the provider's own: the `getrandom(2)` system call, or, with glibc
/// 2.41 and later on Linux 6.11 and later, the kernel's vDSO generator,
/// which makes the system call only to reseed and answers its error when
/// that fails (never other bytes). Either way a failure is the caller's
/// error. The unit tests fail it on one thread
/// (`tests::fail_the_generator_on_this_thread`): on a vDSO kernel a
/// seccomp filter has no system call to intercept between two reseeds.
#[derive(Debug, Clone, Copy)]
struct Os;

impl getrandom::rand_core::TryRng for Os {
    type Error = getrandom::Error;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        #[cfg(test)]
        if let Some(e) = tests::GENERATOR_DOWN.with(core::cell::Cell::get) {
            return Err(e);
        }
        getrandom::SysRng.try_fill_bytes(dst)
    }
}

impl getrandom::rand_core::TryCryptoRng for Os {}

/// The provider's randoms of the handshake (the client hello's random and
/// session id): [`Os`]'s, a failed draw rustls'
/// [`rustls::Error::FailedToGetRandomBytes`] — what the provider's own
/// does, through the generator the key exchange draws from.
#[derive(Debug)]
struct OsRandom;

impl rustls::crypto::SecureRandom for OsRandom {
    fn fill(&self, bytes: &mut [u8]) -> Result<(), rustls::crypto::GetRandomFailed> {
        use getrandom::rand_core::TryRng;
        Os.try_fill_bytes(bytes)
            .map_err(|_| rustls::crypto::GetRandomFailed)
    }
}

/// X25519 (RFC 7748) with RFC 8446 §7.4.2's check: a shared secret of
/// all zeros — the peer's key of small order, the secret then known to
/// anyone — ends the handshake (the review of #499, D7: the provider's
/// group does not check it, nor does rustls). The same crates as the
/// provider's (x25519-dalek 3, getrandom's `SysRng` as [`Os`]). Lot 1.8
/// (the review of #610): a failing generator is the handshake's error
/// ([`ephemeral_secret`]), not a panic — the provider's own group panics,
/// and the agent's release profile aborts on one.
#[derive(Debug)]
struct X25519Contributory;

impl SupportedKxGroup for X25519Contributory {
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let secret = ephemeral_secret(&mut Os)?;
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(Box::new(X25519Active { secret, public }))
    }
}

/// An X25519 secret from the OS generator `os`, or
/// [`rustls::Error::FailedToGetRandomBytes`] when one of its draws failed:
/// rustls ends the connection's start with it (the sink's fault, signed by
/// the core with the sink's state), and the secret, whose bytes are then
/// not all the generator's, is dropped before any public key is computed
/// from it. Fail closed: never a weak or zero key, never a panic.
fn ephemeral_secret<R>(os: &mut R) -> Result<x25519_dalek::EphemeralSecret, rustls::Error>
where
    R: getrandom::rand_core::TryCryptoRng + ?Sized,
{
    let mut draw = Checked { os, failed: false };
    let secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut draw);
    if draw.failed {
        drop(secret);
        return Err(rustls::Error::FailedToGetRandomBytes);
    }
    Ok(secret)
}

/// The OS generator as the infallible one x25519-dalek asks for, its
/// failure kept: any draw that fails marks it, for good, and the caller
/// ([`ephemeral_secret`]) discards what was made from it.
struct Checked<'a, R: ?Sized> {
    os: &'a mut R,
    failed: bool,
}

impl<R> getrandom::rand_core::TryRng for Checked<'_, R>
where
    R: getrandom::rand_core::TryCryptoRng + ?Sized,
{
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        if self.os.try_fill_bytes(dst).is_err() {
            self.failed = true;
        }
        Ok(())
    }
}

// A cryptographic generator's draws, or a mark that discards them.
impl<R> getrandom::rand_core::TryCryptoRng for Checked<'_, R> where
    R: getrandom::rand_core::TryCryptoRng + ?Sized
{
}

struct X25519Active {
    secret: x25519_dalek::EphemeralSecret,
    public: x25519_dalek::PublicKey,
}

impl ActiveKeyExchange for X25519Active {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer
            .try_into()
            .map_err(|_| rustls::Error::from(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let shared = self
            .secret
            .diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(rustls::PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared.as_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// The narrowed provider's key provider: it loads no private key. The
/// export worker holds none (no client certificate), and with this the
/// provider's RSA and ECDSA private-key code has no key to run on by
/// construction, not only by configuration (it held the advisories
/// against rsa 0.9 and crypto-bigint 0.5 unreached until lot 398's
/// upgrade fixed them; it stays, the least code on a secret).
#[derive(Debug)]
struct NoKeys;

impl rustls::crypto::KeyProvider for NoKeys {
    fn load_private_key(
        &self,
        _key_der: rustls::pki_types::PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        Err(rustls::Error::General(
            "the export worker loads no private key".into(),
        ))
    }
}

/// The CA bundle's certificates.
pub fn roots(ca_pem: &[u8]) -> Result<RootCertStore, SinkFault> {
    let mut store = RootCertStore::empty();
    for c in CertificateDer::pem_slice_iter(ca_pem) {
        let c = c.map_err(|_| SinkFault::BadTrust)?;
        store.add(c).map_err(|_| SinkFault::BadTrust)?;
    }
    if store.is_empty() {
        return Err(SinkFault::BadTrust);
    }
    Ok(store)
}

/// The client configuration: TLS 1.3, the narrowed provider, the pinned
/// roots, no client authentication.
pub fn client_config(ca_pem: &[u8]) -> Result<Arc<ClientConfig>, SinkFault> {
    let cfg = ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| SinkFault::BadTrust)?
        .with_root_certificates(roots(ca_pem)?)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// The name the receiver's certificate must carry.
pub fn server_name(name: &str) -> Result<ServerName<'static>, SinkFault> {
    ServerName::try_from(name.to_string()).map_err(|_| SinkFault::BadTrust)
}

/// rustls' error, classified for the core.
pub fn classify(e: &rustls::Error) -> TlsFault {
    use rustls::Error as E;
    match e {
        E::InvalidCertificate(_) | E::NoCertificatesPresented | E::UnsupportedNameType => {
            TlsFault::Certificate
        }
        E::AlertReceived(_) => TlsFault::Alert,
        E::InappropriateMessage { .. }
        | E::InappropriateHandshakeMessage { .. }
        | E::InvalidMessage(_)
        | E::PeerMisbehaved(_)
        | E::PeerIncompatible(_)
        | E::DecryptError
        | E::PeerSentOversizedRecord => TlsFault::Protocol,
        _ => TlsFault::Other,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A lab CA and a receiver's certificate for `receiver.lab` and
    /// 127.0.0.1 (P-256, generated with openssl for these tests), and the
    /// receiver's key (PKCS#8): the TLS tests' server.
    pub(crate) const CA_PEM: &str = include_str!(concat!(
        env!("NN_REPO_ROOT"),
        "/crates/nn-export/tests/pki/ca.pem"
    ));
    pub(crate) const SRV_PEM: &str = include_str!(concat!(
        env!("NN_REPO_ROOT"),
        "/crates/nn-export/tests/pki/srv.pem"
    ));
    pub(crate) const SRV_KEY: &str = include_str!(concat!(
        env!("NN_REPO_ROOT"),
        "/crates/nn-export/tests/pki/srv.key"
    ));
    pub(crate) const OTHER_CA_PEM: &str = include_str!(concat!(
        env!("NN_REPO_ROOT"),
        "/crates/nn-export/tests/pki/other-ca.pem"
    ));

    /// The narrowing (lot 276; it held RUSTSEC-2026-0387 and
    /// RUSTSEC-2023-0071 unreached until lot 398's upgrade fixed both): a
    /// change that widens it fails here first.
    #[test]
    fn the_provider_is_narrowed_as_the_advisories_require() {
        let p = provider();
        assert_eq!(
            p.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>(),
            vec![NamedGroup::X25519],
            "no P-256/P-384 key exchange: crypto-bigint computes on no secret"
        );
        assert!(!p.cipher_suites.is_empty());
        assert!(
            p.cipher_suites
                .iter()
                .all(|s| matches!(s, SupportedCipherSuite::Tls13(_)))
        );
        // built without its `tls12` feature, the provider itself has no
        // TLS 1.2 suite: the narrowing's retain removes none today, and is
        // there for a feature another crate would turn on
        assert!(
            rustls_rustcrypto::provider()
                .cipher_suites
                .iter()
                .all(|s| matches!(s, SupportedCipherSuite::Tls13(_)))
        );
        let cfg = client_config(CA_PEM.as_bytes()).unwrap();
        assert!(
            !cfg.client_auth_cert_resolver.has_certs(),
            "no client key: rsa's private-key paths never run"
        );
        // and none can be loaded: the raw provider loads the receiver's
        // test key, the narrowed one refuses it
        use rustls::pki_types::PrivateKeyDer;
        let key = || PrivateKeyDer::from_pem_slice(SRV_KEY.as_bytes()).unwrap();
        assert!(
            rustls_rustcrypto::provider()
                .key_provider
                .load_private_key(key())
                .is_ok()
        );
        assert!(p.key_provider.load_private_key(key()).is_err());
        // the key exchange refuses a shared secret of all zeros (a peer's
        // key of small order: here the all-zero point), takes a real one
        let kx = p.kx_groups[0];
        assert!(matches!(
            kx.start().unwrap().complete(&[0u8; 32]),
            Err(rustls::Error::PeerMisbehaved(
                rustls::PeerMisbehaved::InvalidKeyShare
            ))
        ));
        // the other small-order point: (1, …) — u = 1
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(kx.start().unwrap().complete(&one).is_err());
        assert!(kx.start().unwrap().complete(&[0u8; 31]).is_err());
        let (a, b) = (kx.start().unwrap(), kx.start().unwrap());
        let (pa, pb) = (a.pub_key().to_vec(), b.pub_key().to_vec());
        let (sa, sb) = (a.complete(&pb).unwrap(), b.complete(&pa).unwrap());
        assert_eq!(sa.secret_bytes(), sb.secret_bytes());
        assert_eq!(cfg.alpn_protocols.len(), 0);
        // TLS 1.3 alone by construction (rustls built without `tls12`,
        // `with_protocol_versions(TLS13)`, the suites' retain); the
        // receiver's chain checked: `net::tests`' handshakes against
        // another CA's certificate and another name's
    }

    /// The tests' generator error.
    #[derive(Debug)]
    struct Down;

    impl core::fmt::Display for Down {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("the generator is down")
        }
    }

    impl core::error::Error for Down {}

    /// A generator that hands out `byte`s (`0x42` unless told), records
    /// the length of each draw, and fails the draws whose index `fail_at`
    /// lists.
    struct Scripted {
        byte: u8,
        draws: Vec<usize>,
        fail_at: &'static [usize],
    }

    impl Scripted {
        fn failing_at(fail_at: &'static [usize]) -> Self {
            Self {
                byte: 0x42,
                draws: Vec::new(),
                fail_at,
            }
        }

        fn of(byte: u8) -> Self {
            Self {
                byte,
                ..Self::failing_at(&[])
            }
        }
    }

    impl getrandom::rand_core::TryRng for Scripted {
        type Error = Down;

        fn try_next_u32(&mut self) -> Result<u32, Down> {
            let mut b = [0u8; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }

        fn try_next_u64(&mut self) -> Result<u64, Down> {
            let mut b = [0u8; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Down> {
            let n = self.draws.len();
            self.draws.push(dst.len());
            if self.fail_at.contains(&n) {
                return Err(Down);
            }
            dst.fill(self.byte);
            Ok(())
        }
    }

    impl getrandom::rand_core::TryCryptoRng for Scripted {}

    /// Named (lot 1.8, the review of #610): the key exchange's secret is
    /// the OS generator's draw, or the handshake's error when a draw failed
    /// — never a panic, never a secret made of what a failed draw left.
    #[test]
    fn a_failed_draw_is_the_key_exchanges_error_not_a_panic() {
        use getrandom::rand_core::TryRng;
        assert!(matches!(
            ephemeral_secret(&mut Scripted::failing_at(&[0])),
            Err(rustls::Error::FailedToGetRandomBytes)
        ));
        // a good draw: the secret is made of its 32 bytes, in one draw —
        // x25519-dalek 3.0.0 (pinned exactly) makes a secret of one
        // `fill_bytes` — the same bytes the same key, others another
        let public = |byte: u8| {
            let mut os = Scripted::of(byte);
            let secret = ephemeral_secret(&mut os).unwrap();
            assert_eq!(os.draws, vec![32]);
            x25519_dalek::PublicKey::from(&secret)
        };
        assert_eq!(public(0x42), public(0x42));
        assert_ne!(public(0x42), public(0x43));
        // the mark: set by a failed draw of any kind, kept by the good draws
        // after it
        let mut os = Scripted::failing_at(&[2]);
        let mut c = Checked {
            os: &mut os,
            failed: false,
        };
        assert_eq!(c.try_next_u32(), Ok(0x4242_4242));
        assert_eq!(c.try_next_u64(), Ok(0x4242_4242_4242_4242));
        assert!(!c.failed);
        let mut b = [0u8; 3];
        assert_eq!(c.try_fill_bytes(&mut b), Ok(()));
        assert!(c.failed, "draw 2 failed");
        assert_eq!(c.try_fill_bytes(&mut b), Ok(()));
        assert_eq!(b, [0x42; 3]);
        assert!(c.failed, "kept after a good draw");
        assert_eq!(os.draws, vec![4, 8, 3, 3]);
        let draws: [fn(&mut Checked<'_, Scripted>); 3] = [
            |c| {
                let _ = c.try_next_u32();
            },
            |c| {
                let _ = c.try_next_u64();
            },
            |c| {
                let _ = c.try_fill_bytes(&mut [0u8; 32]);
            },
        ];
        for draw in draws {
            let mut os = Scripted::failing_at(&[0]);
            let mut c = Checked {
                os: &mut os,
                failed: false,
            };
            draw(&mut c);
            assert!(c.failed);
        }
        // the OS generator itself: two secrets, two public keys
        let a = ephemeral_secret(&mut getrandom::SysRng).unwrap();
        let b = ephemeral_secret(&mut getrandom::SysRng).unwrap();
        assert_ne!(
            x25519_dalek::PublicKey::from(&a),
            x25519_dalek::PublicKey::from(&b)
        );
    }

    thread_local! {
        /// The error [`Os`] answers on this thread, once
        /// [`fail_the_generator_on_this_thread`] set it.
        pub(super) static GENERATOR_DOWN: core::cell::Cell<Option<getrandom::Error>> =
            const { core::cell::Cell::new(None) };
    }

    /// The error of [`fail_the_generator_on_this_thread`]'s draws.
    #[cfg(target_os = "linux")]
    const DOWN: getrandom::Error = getrandom::Error::new_custom(18);

    /// Makes [`Os`] fail with `e` on the calling thread, for good: the
    /// injection that needs no system call, where the seccomp filter of
    /// [`fail_getrandom_on_this_thread`] would have none to intercept.
    #[cfg(target_os = "linux")]
    fn fail_the_generator_on_this_thread(e: getrandom::Error) {
        GENERATOR_DOWN.with(|d| d.set(Some(e)));
    }

    /// What the syslog sink's thread sees with its generator failed.
    #[cfg(target_os = "linux")]
    struct Seen {
        /// [`Os`]'s draw, failed.
        draw: getrandom::Error,
        /// The provider's randoms of the hello failed.
        hello: bool,
        kx: Option<rustls::Error>,
        client: Option<rustls::Error>,
        rows: crate::net::Delivered,
        stats: crate::net::Stats,
    }

    /// The syslog sink's thread with its OS generator failed by `fail`,
    /// once the sink and a configuration are made: the generator's draw,
    /// the key exchange's start, the client's start (the worker's
    /// provider, `client_config`'s), a request's rows and the sink's
    /// stats — `None` when `fail` did not fail the draw.
    #[cfg(target_os = "linux")]
    fn the_sink_with_its_generator_failed(fail: fn()) -> Option<Seen> {
        use crate::net::{Framed, SyslogSink};
        use getrandom::rand_core::TryRng;
        use nn_proto::ipc::ExportChain;
        use std::time::{Duration, Instant};
        // a receiver's port: the kernel completes the TCP handshake
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::thread::spawn(move || {
            // what draws before the fault: std's hash keys of this thread,
            // getrandom's choice of its system call, the sink and config
            let _ = std::collections::hash_map::RandomState::new();
            getrandom::fill(&mut [0u8; 1]).unwrap();
            let mut sink = SyslogSink::new(addr, "receiver.lab", CA_PEM.as_bytes()).unwrap();
            let config = client_config(CA_PEM.as_bytes()).unwrap();
            fail();
            let draw = Os.try_fill_bytes(&mut [0u8; 1]).err()?;
            let hello = provider().secure_random.fill(&mut [0u8; 32]).is_err();
            let kx = provider().kx_groups[0].start().err();
            let client =
                rustls::ClientConnection::new(config, server_name("receiver.lab").unwrap()).err();
            let rows = sink.rows(
                ExportChain::Detections,
                &[1u64, 2],
                |r| (0, *r),
                |_| Framed {
                    frames: vec![b"<13>1 - receiver.lab nn - - - x".to_vec()],
                    records: 1,
                    verified: true,
                },
                Instant::now() + Duration::from_secs(2),
            );
            Some(Seen {
                draw,
                hello,
                kx,
                client,
                rows,
                stats: sink.stats,
            })
        })
        .join()
        .expect("a failing generator panicked the sink's thread");
        drop(listener);
        seen
    }

    /// The sink's answer to a failed generator: no session starts — the key
    /// exchange's start, the client's start and the request's rows all
    /// report it.
    #[cfg(target_os = "linux")]
    fn assert_a_sink_fault(seen: &Seen) {
        use nn_proto::ipc::SinkState;
        assert!(seen.hello, "the hello's randoms fail too");
        assert_eq!(seen.kx, Some(rustls::Error::FailedToGetRandomBytes));
        assert_eq!(seen.client, Some(rustls::Error::FailedToGetRandomBytes));
        // the sink's answer: a fault (net.rs names a session that cannot
        // start `BadTrust`), nothing delivered, down with a backoff
        let rows = &seen.rows;
        assert_eq!(rows.fault, Some(SinkFault::BadTrust));
        assert_eq!((rows.acked, rows.committed, rows.records), (None, None, 0));
        assert_eq!(rows.state, SinkState::Down);
        assert!(rows.retry_ms > 0);
        assert_eq!((seen.stats.connects, seen.stats.sessions), (1, 0));
    }

    /// Named (lot 1.8, the CI of #616): the OS generator failing — on any
    /// kernel, by the injection that needs no system call — is the syslog
    /// sink's fault, answered like any other: the thread does not panic
    /// (the release profile would abort the export worker), and no session
    /// starts. The draws of the key exchange and of the hello both go
    /// through [`Os`], the provider's one generator.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failing_generator_is_a_sink_fault_not_a_panic() {
        let seen = the_sink_with_its_generator_failed(|| fail_the_generator_on_this_thread(DOWN))
            .expect("the injection fails the generator");
        assert_eq!(seen.draw, DOWN);
        assert_a_sink_fault(&seen);
        // the other threads keep theirs
        assert!(GENERATOR_DOWN.with(core::cell::Cell::get).is_none());
        assert!(provider().kx_groups[0].start().is_ok());
    }

    /// Makes `getrandom(2)` fail with `errno` on the calling thread, for
    /// good (a seccomp filter without TSYNC: the test's other threads keep
    /// theirs).
    #[cfg(target_os = "linux")]
    fn fail_getrandom_on_this_thread(errno: u32) {
        let insn = |code: u32, jt: u8, jf: u8, k: u32| libc::sock_filter {
            code: code as u16,
            jt,
            jf,
            k,
        };
        let filter = [
            // seccomp_data.nr
            insn(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0, 0, 0),
            insn(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                0,
                1,
                libc::SYS_getrandom as u32,
            ),
            insn(
                libc::BPF_RET | libc::BPF_K,
                0,
                0,
                libc::SECCOMP_RET_ERRNO | errno,
            ),
            insn(libc::BPF_RET | libc::BPF_K, 0, 0, libc::SECCOMP_RET_ALLOW),
        ];
        let prog = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr().cast_mut(),
        };
        // SAFETY: prctl with integer arguments, then with a pointer to a
        // filter program that outlives the call (the kernel copies it).
        unsafe {
            let (one, zero): (libc::c_ulong, libc::c_ulong) = (1, 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, one, zero, zero, zero),
                0
            );
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                    &prog as *const libc::sock_fprog,
                ),
                0,
                "seccomp filter"
            );
        }
    }

    /// Why this host's C library draws without the system call, if it
    /// does: glibc 2.41 or later, and a kernel whose vDSO exports getrandom
    /// (Linux 6.11 and later on x86_64) — the system call made only to
    /// reseed, about once a minute. The one reason the seccomp route of
    /// [`a_failing_getrandom_is_a_sink_fault_not_a_panic`] may be skipped.
    #[cfg(target_os = "linux")]
    fn the_c_library_draws_from_the_vdso() -> Option<String> {
        #[cfg(target_env = "gnu")]
        {
            // SAFETY: glibc's version, a static NUL-terminated string.
            let glibc = unsafe { std::ffi::CStr::from_ptr(libc::gnu_get_libc_version()) }
                .to_str()
                .ok()?
                .to_string();
            let mut v = glibc
                .split(|c: char| !c.is_ascii_digit())
                .map(|n| n.parse::<u32>().ok());
            if (v.next()??, v.next()??) < (2, 41) {
                return None;
            }
            let maps = std::fs::read_to_string("/proc/self/maps").ok()?;
            let range = maps.lines().find(|l| l.ends_with("[vdso]"))?;
            let (lo, hi) = range.split_whitespace().next()?.split_once('-')?;
            let lo = usize::from_str_radix(lo, 16).ok()?;
            let len = usize::from_str_radix(hi, 16).ok()?.checked_sub(lo)?;
            // SAFETY: the vDSO's image, mapped readable for the process's
            // life (`r-xp`), read only.
            let vdso = unsafe { std::slice::from_raw_parts(lo as *const u8, len) };
            let symbol = [&b"__vdso_getrandom\0"[..], &b"__kernel_getrandom\0"[..]]
                .into_iter()
                .find(|s| vdso.windows(s.len()).any(|w| w == *s))?;
            let symbol = String::from_utf8_lossy(&symbol[..symbol.len() - 1]).into_owned();
            let linux = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
            Some(format!(
                "glibc {glibc} draws from the vDSO's {symbol} (Linux {})",
                linux.trim()
            ))
        }
        #[cfg(not(target_env = "gnu"))]
        None
    }

    /// Named (lot 1.8, the review of #610): `getrandom(2)` failing (EIO,
    /// injected by a seccomp filter on the sink's thread) is the syslog
    /// sink's fault, answered like any other (`assert_a_sink_fault`). Where
    /// the C library draws from the kernel's vDSO generator, the filter
    /// has nothing to intercept between two reseeds (the CI of #616:
    /// ubuntu-26.04's glibc and kernel): the route is then SKIPPED by name,
    /// on stderr past the test harness's capture, that reason checked —
    /// any other draw the filter does not fail fails the test — and
    /// [`a_failing_generator_is_a_sink_fault_not_a_panic`] answers on
    /// every kernel.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_failing_getrandom_is_a_sink_fault_not_a_panic() {
        let seen =
            the_sink_with_its_generator_failed(|| fail_getrandom_on_this_thread(libc::EIO as u32));
        let Some(seen) = seen else {
            let why = the_c_library_draws_from_the_vdso();
            assert!(
                why.is_some(),
                "the filter fails getrandom: it did not, and the C library does not draw \
                 from the vDSO"
            );
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr().lock(),
                "SKIP the seccomp route of a_failing_getrandom_is_a_sink_fault_not_a_panic: {} \
                 (no system call to intercept); a_failing_generator_is_a_sink_fault_not_a_panic \
                 checks the sink's answer",
                why.unwrap_or_default()
            );
            return;
        };
        assert_eq!(
            seen.draw.raw_os_error(),
            Some(libc::EIO),
            "the filter fails getrandom"
        );
        assert_a_sink_fault(&seen);
    }

    /// Lot 398 (rustls-rustcrypto 0.0.2-alpha to 0.1.0-pre.0): the
    /// provider offers what lot 276 shipped — no cipher suite, group or
    /// signature scheme added or dropped by the upgrade, the narrowed
    /// provider the same three suites. A release that changes one fails
    /// here, for a reviewed edit (`docs/operator/EXPORT.md` §7).
    #[test]
    fn the_provider_offers_lot_276s_algorithms() {
        use rustls::{CipherSuite as C, SignatureScheme as S};
        let raw = rustls_rustcrypto::provider();
        let narrowed = provider();
        let suites = |p: &CryptoProvider| {
            p.cipher_suites
                .iter()
                .map(|s| s.suite())
                .collect::<Vec<_>>()
        };
        let tls13 = vec![
            C::TLS13_AES_128_GCM_SHA256,
            C::TLS13_AES_256_GCM_SHA384,
            C::TLS13_CHACHA20_POLY1305_SHA256,
        ];
        assert_eq!(suites(&raw), tls13);
        assert_eq!(suites(&narrowed), tls13);
        assert_eq!(
            raw.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>(),
            vec![
                NamedGroup::X25519,
                NamedGroup::secp256r1,
                NamedGroup::secp384r1
            ]
        );
        let schemes = vec![
            S::ECDSA_NISTP384_SHA384,
            S::ECDSA_NISTP256_SHA256,
            S::ED25519,
            S::RSA_PKCS1_SHA256,
            S::RSA_PKCS1_SHA384,
            S::RSA_PKCS1_SHA512,
            S::RSA_PSS_SHA256,
            S::RSA_PSS_SHA384,
            S::RSA_PSS_SHA512,
        ];
        for p in [&raw, &narrowed] {
            let v = &p.signature_verification_algorithms;
            assert_eq!(v.supported_schemes(), schemes);
            // ECDSA P-256 and P-384 each with SHA-256 and SHA-384, Ed25519,
            // RSA PKCS#1 v1.5 and PSS each with SHA-256/384/512
            assert_eq!(v.all.len(), 11);
        }
        // the OS generator behind the handshake's randoms
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        raw.secure_random.fill(&mut a).unwrap();
        narrowed.secure_random.fill(&mut b).unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }

    /// A file of the tests' PKI (`tests/pki/README.md`).
    macro_rules! pki {
        ($f:literal) => {
            include_str!(concat!(
                env!("NN_REPO_ROOT"),
                "/crates/nn-export/tests/pki/",
                $f
            ))
        };
    }

    /// Sends what `from` has to send into `to`, which processes it.
    fn transfer(
        from: &mut rustls::Connection,
        to: &mut rustls::Connection,
    ) -> Result<(), rustls::Error> {
        let mut buf = Vec::new();
        while from.wants_write() {
            from.write_tls(&mut buf).unwrap();
        }
        let mut rd = &buf[..];
        while !rd.is_empty() {
            to.read_tls(&mut rd).unwrap();
            to.process_new_packets()?;
        }
        Ok(())
    }

    /// The narrowed client, trusting `ca`, against a server on the raw
    /// provider with `srv` and `key`, in memory: the handshake, then one
    /// record from the client; what the server read, or the error.
    fn handshake(
        ca: &str,
        srv: &[CertificateDer<'static>],
        key: &str,
    ) -> Result<Vec<u8>, rustls::Error> {
        use std::io::{Read, Write};
        let server =
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_no_client_auth()
                .with_single_cert(
                    srv.to_vec(),
                    rustls::pki_types::PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
                )?;
        let client = client_config(ca.as_bytes()).unwrap();
        let mut c = rustls::Connection::Client(rustls::ClientConnection::new(
            client,
            server_name("receiver.lab").unwrap(),
        )?);
        let mut s = rustls::Connection::Server(rustls::ServerConnection::new(Arc::new(server))?);
        for _ in 0..8 {
            if !c.is_handshaking() && !s.is_handshaking() {
                break;
            }
            transfer(&mut c, &mut s)?;
            transfer(&mut s, &mut c)?;
        }
        assert!(!c.is_handshaking() && !s.is_handshaking());
        if let rustls::Connection::Client(cc) = &c {
            assert_eq!(
                cc.negotiated_key_exchange_group().map(|g| g.name()),
                Some(NamedGroup::X25519)
            );
            assert_eq!(
                cc.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
        }
        c.writer()
            .write_all(b"<13>1 - receiver.lab nn - - - x")
            .unwrap();
        transfer(&mut c, &mut s)?;
        let mut got = vec![0u8; 64];
        let n = s.reader().read(&mut got).unwrap();
        got.truncate(n);
        Ok(got)
    }

    fn certs(pem: &str) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(pem.as_bytes())
            .map(Result::unwrap)
            .collect()
    }

    /// Lot 398 (rsa 0.9 to 0.10 on crypto-bigint 0.7, p256/p384 0.14,
    /// ed25519-dalek 3 in the provider): the export's client completes a
    /// TLS 1.3 handshake with a receiver of each signature family the
    /// provider verifies — the chain's signature and the handshake's
    /// (RSA-PSS for an RSA key) — and refuses each one whose leaf's
    /// signature is altered by one bit, or that another CA signed.
    #[test]
    fn every_signature_family_completes_a_handshake() {
        let families = [
            ("P-256", CA_PEM, SRV_PEM, SRV_KEY),
            (
                "RSA-2048",
                pki!("rsa-ca.pem"),
                pki!("rsa-srv.pem"),
                pki!("rsa-srv.key"),
            ),
            (
                "P-384",
                pki!("p384-ca.pem"),
                pki!("p384-srv.pem"),
                pki!("p384-srv.key"),
            ),
            (
                "Ed25519",
                pki!("ed25519-ca.pem"),
                pki!("ed25519-srv.pem"),
                pki!("ed25519-srv.key"),
            ),
        ];
        for (family, ca, srv, key) in families {
            let chain = certs(srv);
            assert_eq!(
                handshake(ca, &chain, key).unwrap_or_else(|e| panic!("{family}: {e:?}")),
                b"<13>1 - receiver.lab nn - - - x",
                "{family}"
            );
            // the leaf's signature (its DER's last byte) altered
            let mut bad = chain[0].to_vec();
            *bad.last_mut().unwrap() ^= 1;
            assert_eq!(
                handshake(ca, &[CertificateDer::from(bad)], key).unwrap_err(),
                rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature),
                "{family}"
            );
            // trusted by another CA only
            assert_eq!(
                handshake(OTHER_CA_PEM, &chain, key).unwrap_err(),
                rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
                "{family}"
            );
        }
    }

    #[test]
    fn trust_is_the_pinned_bundle_or_nothing() {
        assert!(roots(CA_PEM.as_bytes()).is_ok());
        assert_eq!(roots(b"").unwrap_err(), SinkFault::BadTrust);
        assert_eq!(
            roots(b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n")
                .unwrap_err(),
            SinkFault::BadTrust
        );
        assert!(server_name("receiver.lab").is_ok());
        assert!(server_name("127.0.0.1").is_ok());
        assert_eq!(server_name("a b").unwrap_err(), SinkFault::BadTrust);
        assert_eq!(
            classify(&rustls::Error::InvalidCertificate(
                rustls::CertificateError::UnknownIssuer
            )),
            TlsFault::Certificate
        );
        assert_eq!(
            classify(&rustls::Error::AlertReceived(
                rustls::AlertDescription::HandshakeFailure
            )),
            TlsFault::Alert
        );
        assert_eq!(classify(&rustls::Error::DecryptError), TlsFault::Protocol);
        assert_eq!(
            classify(&rustls::Error::General("x".into())),
            TlsFault::Other
        );
    }
}
