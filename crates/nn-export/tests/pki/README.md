Test-only TLS material for nn-export's tests (lot 276), made with OpenSSL 3.0
(P-256, valid 20 years): `ca.pem` (a CA whose key was discarded), `srv.pem`
and `srv.key` (a receiver for `receiver.lab` and `127.0.0.1`, signed by that
CA), `other-ca.pem` (a CA that signed nothing here). Trusted by no build: the
export trusts only the CA bundle its signed configuration pins.

Lot 398 (rustls-rustcrypto 0.1.0-pre.0, new RustCrypto majors): one more CA
and receiver per signature family the provider verifies, made the same way
(OpenSSL 3.0, valid 20 years, the CAs' keys discarded): `rsa-*` (RSA-2048,
the chain signed sha256WithRSAEncryption, the handshake RSA-PSS),
`p384-*` (P-384, ecdsa-with-SHA384), `ed25519-*` (Ed25519); each
`*-srv.key` PKCS#8. The test
`every_signature_family_completes_a_handshake` (`nn_export::tls`) uses
them.
