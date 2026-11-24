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
    // a unit value: promoted to 'static, no process-wide state
    p.key_provider = &NoKeys;
    p
}

/// X25519 (RFC 7748) with RFC 8446 §7.4.2's check: a shared secret of
/// all zeros — the peer's key of small order, the secret then known to
/// anyone — ends the handshake (the review of #499, D7: the provider's
/// group does not check it, nor does rustls). The same crates as the
/// provider's (x25519-dalek 3, getrandom's OS generator `SysRng`; a
/// failing generator panics, as the provider's own group does and as
/// rand_core 0.6's `OsRng` did before lot 398).
#[derive(Debug)]
struct X25519Contributory;

impl SupportedKxGroup for X25519Contributory {
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let mut rng = getrandom::rand_core::UnwrapErr(getrandom::SysRng);
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(&mut rng);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(Box::new(X25519Active { secret, public }))
    }
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
