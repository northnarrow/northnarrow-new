//! The TLS client of the syslog sink (lot 276): rustls with the RustCrypto
//! provider (the founder's decision: TLS in Rust only), narrowed to what
//! the export needs and to what the recorded advisories leave reachable
//! (`.cargo/audit.toml`, `docs/operator/EXPORT.md` §7):
//!
//! - TLS 1.3 only (rustls is built without TLS 1.2);
//! - its three TLS 1.3 suites (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305);
//! - key exchange by **X25519 only**, our own group, which refuses a shared
//!   secret of all zeros (RFC 8446 §7.4.2; the provider's does not): the
//!   provider's P-256 and P-384 groups are removed, so crypto-bigint 0.5
//!   (RUSTSEC-2026-0387, timing) never computes on a secret — it verifies
//!   signatures, on public data;
//! - no client certificate, and a key provider that loads no private key:
//!   rsa 0.9's private-key paths (RUSTSEC-2023-0071, Marvin) and ECDSA
//!   signing never run — an RSA certificate of the receiver is verified
//!   with its public key only (the provider has no RSA decryption at all);
//! - the receiver's chain checked by rustls' own WebPKI verifier (its
//!   rustls-webpki 0.103), against the CA bundle the signed configuration
//!   pins — never the provider's rustls-webpki 0.102, whose `alg_id`
//!   constants are all the provider takes of it.

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
/// provider's (x25519-dalek 2, rand_core's OS generator).
#[derive(Debug)]
struct X25519Contributory;

impl SupportedKxGroup for X25519Contributory {
    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, rustls::Error> {
        let secret = x25519_dalek::EphemeralSecret::random_from_rng(rand_core::OsRng);
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
/// provider's RSA and ECDSA private-key code (rsa 0.9's Marvin,
/// crypto-bigint 0.5's timing) has no key to run on by construction, not
/// only by configuration.
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

    /// The advisories' reachability rests on this narrowing
    /// (`.cargo/audit.toml`: RUSTSEC-2026-0387, RUSTSEC-2023-0071): a
    /// change that widens it fails here first.
    #[test]
    fn the_provider_is_narrowed_as_the_advisories_require() {
        let p = provider();
        assert_eq!(
            p.kx_groups.iter().map(|g| g.name()).collect::<Vec<_>>(),
            vec![NamedGroup::X25519],
            "no P-256/P-384 key exchange: crypto-bigint 0.5 computes on no secret"
        );
        assert!(!p.cipher_suites.is_empty());
        assert!(p
            .cipher_suites
            .iter()
            .all(|s| matches!(s, SupportedCipherSuite::Tls13(_))));
        // built without its `tls12` feature, the provider itself has no
        // TLS 1.2 suite: the narrowing's retain removes none today, and is
        // there for a feature another crate would turn on
        assert!(rustls_rustcrypto::provider()
            .cipher_suites
            .iter()
            .all(|s| matches!(s, SupportedCipherSuite::Tls13(_))));
        let cfg = client_config(CA_PEM.as_bytes()).unwrap();
        assert!(
            !cfg.client_auth_cert_resolver.has_certs(),
            "no client key: rsa's private-key paths never run"
        );
        // and none can be loaded: the raw provider loads the receiver's
        // test key, the narrowed one refuses it
        use rustls::pki_types::PrivateKeyDer;
        let key = || PrivateKeyDer::from_pem_slice(SRV_KEY.as_bytes()).unwrap();
        assert!(rustls_rustcrypto::provider()
            .key_provider
            .load_private_key(key())
            .is_ok());
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
        // TLS 1.3 alone, the receiver's chain checked: the handshakes of
        // `net::tests` (a TLS 1.2 receiver, another CA's, another name's)
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
