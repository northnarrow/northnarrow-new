Test-only TLS material for nn-export's tests (lot 276), made with OpenSSL 3.0
(P-256, valid 20 years): `ca.pem` (a CA whose key was discarded), `srv.pem`
and `srv.key` (a receiver for `receiver.lab` and `127.0.0.1`, signed by that
CA), `other-ca.pem` (a CA that signed nothing here). Trusted by no build: the
export trusts only the CA bundle its signed configuration pins.
