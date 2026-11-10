//! Thin, `#[doc(hidden)]` wrappers over private parsers so the
//! `fuzz/` crate (cargo-fuzz, libFuzzer) can drive them without making
//! the internals public, and the fixtures some targets check against.
//! Each wrapper must never panic on any input; the targets also assert
//! what each parser promises (`fuzz/README.md`). Not part of the
//! supported API.

use std::path::Path;
use std::sync::OnceLock;

use nn_proto::admin_quorum::{parse_admin_pub, AdminKey};
use nn_proto::shutdown_marker::{verify, Authorised, Expectation, Rejection, ShutdownMarker};

use crate::install_manifest::{check_with, parse_manifest, InstallManifest, IntegrityOutcome};

/// Parse a BTF blob and resolve every offset/enumerator the agent needs.
/// Returns whether the blob parsed; the resolution outcome is discarded.
#[doc(hidden)]
pub fn parse_btf_and_resolve(data: &[u8]) -> bool {
    crate::anti_tamper::btf_revalidate::fuzz_parse_and_resolve(data)
}

/// Chain-log terminator line parser (JSON line → entry hash).
#[doc(hidden)]
pub fn chainlog_terminator_entry_hash(line: &str) -> Option<String> {
    crate::chainlog::fuzz_terminator_entry_hash(line)
}

/// COMBAT management carve-out splice: the generated ACCEPT block into an
/// operator `combat-rules.v4`/`.v6` body (marker line, else before the
/// first DROP, else before COMMIT).
#[doc(hidden)]
pub fn combat_splice_carveout(base: &str, accept_block: &str) -> String {
    crate::anti_tamper::network_isolate::splice_carveout(base, accept_block)
}

/// The marker line [`combat_splice_carveout`] replaces.
#[doc(hidden)]
pub const COMBAT_CARVE_OUT_MARKER: &str = crate::anti_tamper::network_isolate::CARVE_OUT_MARKER;

// ── install manifest (external audit WDG-R05, NN-AUD-371) ────────────

/// The binaries of the `install_manifest` target's fixture directory: one
/// per name of [`crate::install_manifest::RECORDED_NAMES`] but the eBPF
/// object's (a hash, not a file). The target hashes each recorded name's
/// file at start, so a name added there needs its binary here (lab PR
/// 223: `northnarrow-scan` was missing, and the replay of the first input
/// panicked; `install_manifest_fixture_has_every_recorded_binary` checks
/// it on the host).
#[doc(hidden)]
pub const INSTALL_MANIFEST_FIXTURE: [(&str, &[u8]); 4] = [
    ("northnarrow-agent", b"fuzz fixture: northnarrow-agent\n"),
    (
        "northnarrow-watchdog",
        b"fuzz fixture: northnarrow-watchdog\n",
    ),
    ("nn-admin", b"fuzz fixture: nn-admin\n"),
    ("northnarrow-scan", b"fuzz fixture: northnarrow-scan\n"),
];

/// The embedded eBPF object hash the target checks against.
#[doc(hidden)]
pub const INSTALL_MANIFEST_FIXTURE_EBPF_SHA: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Create the fixture binaries in `dir` (a fresh private directory, once
/// per fuzzing process): exclusively, so nothing planted at a name is
/// written through (external audit WDG-R09, the AUT-003 pattern).
#[doc(hidden)]
pub fn write_install_manifest_fixture(dir: &Path) -> std::io::Result<()> {
    use std::io::Write as _;
    for (name, body) in INSTALL_MANIFEST_FIXTURE {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(dir.join(name))?
            .write_all(body)?;
    }
    Ok(())
}

/// The boot check of `json` as the manifest's content, with `bin_dir`
/// forced to `dir` and the agent running from `dir/northnarrow-agent`:
/// every manifest that parses reaches the hash comparison. The target ran
/// [`crate::install_manifest::check`] with `/proc/self/exe`, which never
/// runs from a manifest's `bin_dir`, so every input ended `NotApplicable`.
/// Returns the parsed manifest too (`None` when it does not parse), for
/// the target's own judgement of the outcome. Nothing is written.
#[doc(hidden)]
pub fn install_manifest_check_in_dir(
    json: &[u8],
    dir: &Path,
    ebpf_object_sha: &str,
) -> (Option<InstallManifest>, IntegrityOutcome) {
    let unreadable = |reason: String| IntegrityOutcome::Unreadable {
        path: dir.join("install-manifest.json"),
        reason,
    };
    let text = match std::str::from_utf8(json) {
        Ok(t) => t,
        Err(e) => return (None, unreadable(e.to_string())),
    };
    let mut manifest = match parse_manifest(text) {
        Ok(m) => m,
        Err(reason) => return (None, unreadable(reason)),
    };
    manifest.bin_dir = dir.to_string_lossy().into_owned();
    let outcome = check_with(&manifest, &dir.join("northnarrow-agent"), ebpf_object_sha);
    (Some(manifest), outcome)
}

// ── shutdown marker (external audit WDG-014, NN-AUD-363) ─────────────

/// `admin.pub` of the `shutdown_marker` target: the public halves of the
/// test keys `[1; 32]`, `[2; 32]` and `[3; 32]`; only the first carries
/// `shutdown`. No installed agent or watchdog reads it.
#[doc(hidden)]
pub const SHUTDOWN_FIXTURE_ADMIN_PUB: &str = "\
8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c shutdown
8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394 unlock
ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1 unlock
";

/// The install the fixture's shutdowns are for.
#[doc(hidden)]
pub const SHUTDOWN_FIXTURE_AGENT_ID: [u8; 16] = [7; 16];
/// The pid of the agent that exited.
#[doc(hidden)]
pub const SHUTDOWN_FIXTURE_PID: u32 = 4242;
/// The watchdog's clock; the agent started an hour before.
#[doc(hidden)]
pub const SHUTDOWN_FIXTURE_NOW: u64 = 1_800_000_000;

/// Every shutdown the fixture keys signed — `(nonce, ts, grace_secs)`, the
/// committed seeds: a marker the check honours carries one of these, or
/// the check accepted something no fixture key signed.
#[doc(hidden)]
pub const SHUTDOWN_FIXTURE_SIGNED: [([u8; 32], u64, u32); 1] =
    [([9; 32], SHUTDOWN_FIXTURE_NOW - 5, 30)];

fn shutdown_fixture_keys() -> &'static [AdminKey] {
    static KEYS: OnceLock<Vec<AdminKey>> = OnceLock::new();
    KEYS.get_or_init(|| {
        parse_admin_pub(SHUTDOWN_FIXTURE_ADMIN_PUB).expect("the fixture admin.pub parses")
    })
}

/// The watchdog's check of a marker file's content against the fixture:
/// [`ShutdownMarker::parse`], then [`verify`]; `honoured` answers whether
/// the nonce was honoured before.
#[doc(hidden)]
pub fn shutdown_marker_check(
    raw: &str,
    honoured: bool,
) -> Result<(ShutdownMarker, Authorised), Rejection> {
    let marker = ShutdownMarker::parse(raw)?;
    let exp = Expectation {
        keys: shutdown_fixture_keys(),
        agent_id: SHUTDOWN_FIXTURE_AGENT_ID,
        agent_pid: SHUTDOWN_FIXTURE_PID,
        agent_started: Some(SHUTDOWN_FIXTURE_NOW - 3600),
        now: SHUTDOWN_FIXTURE_NOW,
    };
    let authorised = verify(&marker, &exp, |_| honoured)?;
    Ok((marker, authorised))
}

/// The committed inputs of the fuzz targets reach what the targets assert
/// (external audit WDG-R06, SUP-018): a seed that every parser refuses
/// would leave each assertion behind the first early return, as the empty
/// CI corpus did. The generated seeds are checked byte for byte; run with
/// `NN_BLESS_FUZZ_SEEDS=1` to rewrite them after a format change.
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fuzz_dir() -> PathBuf {
        Path::new(env!("NN_REPO_ROOT")).join("fuzz")
    }

    /// Every file of `fuzz/<kind>/<target>/`, sorted.
    fn inputs(kind: &str, target: &str) -> Vec<(String, Vec<u8>)> {
        let dir = fuzz_dir().join(kind).join(target);
        let mut out: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
            .map(|e| {
                let p = e.unwrap().path();
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    std::fs::read(&p).unwrap(),
                )
            })
            .collect();
        out.sort();
        assert!(!out.is_empty(), "{}: no input", dir.display());
        out
    }

    /// A generated input: equal to `want`, or rewritten under
    /// `NN_BLESS_FUZZ_SEEDS=1`.
    fn generated(kind: &str, target: &str, name: &str, want: &[u8]) {
        let p = fuzz_dir().join(kind).join(target).join(name);
        if std::env::var_os("NN_BLESS_FUZZ_SEEDS").is_some() {
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(&p, want).unwrap();
        }
        let got = std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
        assert!(
            got == want,
            "{} is stale; regenerate with NN_BLESS_FUZZ_SEEDS=1 cargo test -p northnarrow-agent \
             --lib fuzz_api",
            p.display()
        );
    }

    fn text(bytes: &[u8]) -> &str {
        std::str::from_utf8(bytes).unwrap()
    }

    #[test]
    fn shutdown_fixture_keys_are_the_test_seeds() {
        use ed25519_dalek::SigningKey;
        let keys = shutdown_fixture_keys();
        assert_eq!(keys.len(), 3);
        for (i, k) in keys.iter().enumerate() {
            let sk = SigningKey::from_bytes(&[i as u8 + 1; 32]);
            assert_eq!(k.key, sk.verifying_key());
            assert_eq!(
                k.authorizes(nn_proto::admin_signed_payload::Role::Shutdown),
                i == 0
            );
        }
    }

    /// The marker the fixture admins 1 and 2 sign for each
    /// [`SHUTDOWN_FIXTURE_SIGNED`] entry (Ed25519 signs deterministically).
    fn signed_marker(nonce: [u8; 32], ts: u64, grace: u32) -> String {
        use ed25519_dalek::SigningKey;
        use nn_proto::admin_signed_payload::{sign, SignedPayload};
        let payload = SignedPayload::new_shutdown(nonce, ts, SHUTDOWN_FIXTURE_AGENT_ID, grace);
        let sigs: Vec<[u8; 64]> = [1u8, 2]
            .iter()
            .map(|s| sign(&payload, &SigningKey::from_bytes(&[*s; 32])).unwrap())
            .collect();
        ShutdownMarker::new(&payload, &sigs, SHUTDOWN_FIXTURE_PID)
            .unwrap()
            .to_line()
    }

    #[test]
    fn shutdown_marker_seed_is_honoured_and_its_replay_refused() {
        let (nonce, ts, grace) = SHUTDOWN_FIXTURE_SIGNED[0];
        let line = signed_marker(nonce, ts, grace);
        generated(
            "seeds",
            "shutdown_marker",
            "quorum-signed.json",
            line.as_bytes(),
        );
        let (_, a) = shutdown_marker_check(&line, false).expect("the seed is honoured");
        assert_eq!((a.nonce, a.ts, a.grace_secs), (nonce, ts, u64::from(grace)));
        assert_eq!(a.signers, vec![0, 1]);
        assert_eq!(
            shutdown_marker_check(&line, true).unwrap_err(),
            Rejection::Replayed
        );
        // AUT-011 (declined): a payload of 10,000 nested arrays under an
        // unknown key is refused at ciborium's recursion limit, not a crash
        let mut marker = ShutdownMarker::parse(&line).unwrap();
        let mut cbor = vec![0xA1, 0x61, b'x'];
        cbor.extend_from_slice(&[0x81; 10_000]);
        cbor.push(0x00);
        marker.payload = hex::encode(&cbor);
        let nested = marker.to_line();
        generated(
            "regressions",
            "shutdown_marker",
            "nested-cbor-payload.json",
            nested.as_bytes(),
        );
        assert!(matches!(
            shutdown_marker_check(&nested, false),
            Err(Rejection::Malformed(m)) if m.contains("RecursionLimitExceeded")
        ));
        // AUT-005: the two good signatures and seven copies, refused before
        // any is checked (without the cap, the quorum would be met)
        let mut marker = ShutdownMarker::parse(&line).unwrap();
        let two = marker.signatures.clone();
        marker.signatures = two.iter().cycle().take(9).cloned().collect();
        let over = marker.to_line();
        generated(
            "regressions",
            "shutdown_marker",
            "nine-signatures.json",
            over.as_bytes(),
        );
        assert_eq!(
            shutdown_marker_check(&over, false).unwrap_err(),
            Rejection::TooManySignatures(9)
        );
    }

    fn fixture_manifest(entries: &[(&str, &str)]) -> String {
        let files: Vec<String> = entries
            .iter()
            .map(|(n, h)| format!("\"{n}\":\"{h}\""))
            .collect();
        format!(
            "{{\"version\":\"0.0.1\",\"installed_at\":\"2026-10-20T00:00:00Z\",\
             \"provenance\":\"checksums\",\"bin_dir\":\"/usr/local/bin\",\
             \"files\":{{{}}},\"tarball_sha256\":null}}\n",
            files.join(",")
        )
    }

    /// Lab PR 223: the `install_manifest` target hashes the fixture's file
    /// of every recorded name at start; a name without one (the scanner)
    /// panicked on the first input of the CI replay.
    #[test]
    fn install_manifest_fixture_has_every_recorded_binary() {
        use crate::install_manifest::{EBPF_OBJECT_KEY, RECORDED_NAMES};
        use std::collections::BTreeSet;
        let recorded: BTreeSet<&str> = RECORDED_NAMES
            .into_iter()
            .filter(|n| *n != EBPF_OBJECT_KEY)
            .collect();
        let fixture: BTreeSet<&str> = INSTALL_MANIFEST_FIXTURE.iter().map(|(n, _)| *n).collect();
        assert_eq!(
            fixture.len(),
            INSTALL_MANIFEST_FIXTURE.len(),
            "a name twice"
        );
        assert_eq!(
            fixture, recorded,
            "INSTALL_MANIFEST_FIXTURE must hold a binary for every file name of RECORDED_NAMES"
        );
    }

    #[test]
    fn install_manifest_seeds_reach_the_hash_comparison() {
        use crate::install_manifest::{sha256_file, UNKNOWN_NAME};
        let dir = tempfile::tempdir().unwrap();
        write_install_manifest_fixture(dir.path()).unwrap();
        let sha = |n: &str| sha256_file(&dir.path().join(n)).unwrap();
        let (agent, wd, admin, scan) = (
            sha("northnarrow-agent"),
            sha("northnarrow-watchdog"),
            sha("nn-admin"),
            sha("northnarrow-scan"),
        );
        let ebpf = INSTALL_MANIFEST_FIXTURE_EBPF_SHA;
        // what install.sh records since lab PR 223 (one-mismatch.json is a
        // manifest without the scanner, as one written before it)
        let verified = fixture_manifest(&[
            ("ebpf_object", ebpf),
            ("nn-admin", &admin),
            ("northnarrow-agent", &agent),
            ("northnarrow-scan", &scan),
            ("northnarrow-watchdog", &wd),
        ]);
        let zeros = "0".repeat(64);
        let mismatch = fixture_manifest(&[
            ("ebpf_object", ebpf),
            ("nn-admin", &zeros),
            ("northnarrow-agent", &agent),
        ]);
        generated(
            "seeds",
            "install_manifest",
            "verified.json",
            verified.as_bytes(),
        );
        generated(
            "seeds",
            "install_manifest",
            "one-mismatch.json",
            mismatch.as_bytes(),
        );
        let run = |json: &[u8]| install_manifest_check_in_dir(json, dir.path(), ebpf).1;
        assert!(matches!(
            run(verified.as_bytes()),
            IntegrityOutcome::Verified { checked: 5, .. }
        ));
        assert!(matches!(
            run(mismatch.as_bytes()),
            IntegrityOutcome::Mismatch { ref mismatches, .. } if mismatches.len() == 1
        ));
        // WDG-R05: a name that aliases the agent, and one that is absolute
        let alias = fixture_manifest(&[
            ("northnarrow-agent", &agent),
            ("./northnarrow-agent", &agent),
        ]);
        let absolute = fixture_manifest(&[("northnarrow-agent", &agent), ("/dev/zero", &zeros)]);
        generated(
            "regressions",
            "install_manifest",
            "relative-alias.json",
            alias.as_bytes(),
        );
        generated(
            "regressions",
            "install_manifest",
            "absolute-dev-zero.json",
            absolute.as_bytes(),
        );
        for json in [&alias, &absolute] {
            match run(json.as_bytes()) {
                IntegrityOutcome::Mismatch { mismatches, .. } => {
                    assert_eq!(mismatches.len(), 1);
                    assert_eq!(mismatches[0].actual, UNKNOWN_NAME);
                }
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn admin_frame_seeds_decode() {
        use nn_proto::admin_protocol::{
            decode_frame, decode_versioned_frame, encode_frame, encode_versioned_frame,
            AdminMessage, ChallengeRequest, KeyedSignature, ShutdownRequest, StatusRequest,
            VersionedAdminMessage,
        };
        use nn_proto::admin_signed_payload::SignedPayload;
        let v1 =
            |m: AdminMessage| encode_versioned_frame(&VersionedAdminMessage::current(m)).unwrap();
        let status = v1(AdminMessage::Status(StatusRequest {}));
        let challenge = v1(AdminMessage::ChallengeRequest(ChallengeRequest {}));
        let (nonce, ts, grace) = SHUTDOWN_FIXTURE_SIGNED[0];
        let shutdown = v1(AdminMessage::ShutdownRequest(ShutdownRequest {
            payload: SignedPayload::new_shutdown(nonce, ts, SHUTDOWN_FIXTURE_AGENT_ID, grace),
            signatures: vec![KeyedSignature::from([0x5a; 64]); 2],
        }));
        let legacy = encode_frame(&AdminMessage::Status(StatusRequest {})).unwrap();
        generated("seeds", "admin_frame", "v1-status.bin", &status);
        generated(
            "seeds",
            "admin_frame",
            "v1-challenge-request.bin",
            &challenge,
        );
        generated("seeds", "admin_frame", "v1-shutdown-request.bin", &shutdown);
        generated("seeds", "admin_frame", "v0-status.bin", &legacy);
        // lot 299 (BUG-36): the envelopes through the strict decoder, the
        // bare v0 body through the live wire's (the v0 fallback is retired)
        for (name, bytes) in inputs("seeds", "admin_frame") {
            let decoded = if name.starts_with("v0-") {
                decode_frame(&bytes).map(|m| m.is_some())
            } else {
                decode_versioned_frame(&bytes).map(|m| m.is_some())
            };
            assert!(matches!(decoded, Ok(true)), "{name}");
        }
    }

    /// R14a, review of #480 (F1): the `ipc_check` seeds — a hello and an
    /// answer of every kind a worker gives, each accepted by the core's
    /// checks — and the regression: a JA4 with a two-byte character across
    /// byte 23, which sliced the `&str` and panicked the core.
    #[test]
    fn ipc_check_seeds_are_accepted_and_the_f1_input_refused() {
        use nn_proto::ipc::{
            check_hello, check_response, decode, encode, Answer, Expected, ExportAddr, ExportChain,
            ExportRow, ExportRows, ExportRowsOut, ExportSetup, ExportSetupOut, ExportSink,
            FileSetup, FromWorker, LandlockEnforced, QnameForm, QnameIn, QnameOut, Request,
            Response, RowPos, SandboxLevel, SinkState, SniOut, SyslogSetup, TlsOut, WorkerHello,
            WorkerKind, EXPORT_DIR_RULE, IPC_VERSION,
        };
        let packet = |sel: u8, m: &FromWorker| {
            let mut v = vec![sel];
            v.extend(encode(m).unwrap());
            v
        };
        let answer = |a: Answer| FromWorker::Response(Response { id: 7, answer: a });
        let hello = FromWorker::Hello(WorkerHello {
            version: IPC_VERSION,
            kind: WorkerKind::Parse,
            pid: 4242,
            sandbox: SandboxLevel {
                landlock_abi: 4,
                landlock: LandlockEnforced::Partial,
                fs_denied: true,
                net_denied: true,
                seccomp: true,
                no_new_privs: true,
                uid: 990,
                gid: 990,
                nofile: 8,
                ..SandboxLevel::default()
            },
        });
        let export_hello = FromWorker::Hello(WorkerHello {
            version: IPC_VERSION,
            kind: WorkerKind::Export,
            pid: 4243,
            sandbox: SandboxLevel {
                landlock_abi: 4,
                landlock: LandlockEnforced::Partial,
                fs_denied: true,
                net_denied: false,
                seccomp: true,
                no_new_privs: true,
                uid: 990,
                gid: 990,
                nofile: 16,
                fs_rules: vec![EXPORT_DIR_RULE.to_string()],
                ..SandboxLevel::default()
            },
        });
        let tls = |ja4: &str| {
            answer(Answer::Tls(TlsOut::Complete {
                ja3: "0123456789abcdef0123456789abcdef".into(),
                ja4: ja4.into(),
                sni: SniOut::Host("example.com".into()),
                alpn: vec!["h2".into(), "http/1.1".into()],
            }))
        };
        // the selector: the request's kind in the two low bits, its size
        // above them (a hello: the kernel's Landlock ABI)
        let seeds = [
            ("hello-abi4.bin", packet(4 << 2, &hello)),
            ("pong.bin", packet(0, &answer(Answer::Pong))),
            (
                "dns-names.bin",
                packet(
                    1 | (4 << 2),
                    &answer(Answer::DnsNames(vec![QnameOut {
                        name: "example.com".into(),
                        end: None,
                    }])),
                ),
            ),
            (
                "tls-complete.bin",
                packet(2 | (8 << 2), &tls("t13d1516h2_8daaf6152771_02713d6af862")),
            ),
            (
                "dns-answers.bin",
                packet(
                    // lot 275: 64 bytes, room for the question and the record
                    3 | (4 << 2),
                    &answer(Answer::DnsAnswers(Some(nn_proto::ipc::DnsAnswersOut {
                        qname: "example.com".into(),
                        qtype: 1,
                        rcode: 0,
                        records: vec![nn_proto::ipc::DnsRecordOut::A {
                            name: "example.com".into(),
                            ttl: 60,
                            addr: [192, 0, 2, 1],
                        }],
                        complete: true,
                    }))),
                ),
            ),
            // lot 276: the export worker's hello (the selector's low bit),
            // a rows answer (sink syslog: bit 2) and a setup's (both sinks,
            // the pin asked for: bits 2, 3, 4)
            ("hello-export-abi4.bin", packet(1 | (4 << 2), &export_hello)),
            (
                "export-rows.bin",
                packet(
                    4 | (1 << 4),
                    &answer(Answer::ExportRows(ExportRowsOut {
                        acked: Some(RowPos { file: 1, line: 1 }),
                        committed: Some(RowPos { file: 1, line: 2 }),
                        records: 1,
                        unverified: 0,
                        state: SinkState::Up,
                        fault: None,
                        retry_ms: 0,
                    })),
                ),
            ),
            (
                "export-setup.bin",
                packet(
                    4 | 8 | 16,
                    &answer(Answer::ExportSetup(ExportSetupOut {
                        port_pinned: true,
                        file: SinkState::Up,
                        syslog: SinkState::Connecting,
                        fault: None,
                    })),
                ),
            ),
        ];
        for (name, bytes) in &seeds {
            generated("seeds", "ipc_check", name, bytes);
        }
        let f1 = format!("t13d1516h2_{}é{}", "a".repeat(11), "a".repeat(12));
        assert_eq!(f1.len(), 36);
        let f1 = packet(2 | (8 << 2), &tls(&f1));
        generated(
            "regressions",
            "ipc_check",
            "review480-f1-ja4-multibyte-at-23.bin",
            &f1,
        );
        // each seed reaches acceptance; the regression is refused
        // as the fuzz target's `export_request`
        let export_req = |sel: u8, a: &Answer| match a {
            Answer::ExportRows(_) => Some(Request::ExportRows(ExportRows {
                sink: if sel & 4 == 0 {
                    ExportSink::File
                } else {
                    ExportSink::Syslog
                },
                chain: if sel & 8 == 0 {
                    ExportChain::Detections
                } else {
                    ExportChain::CanaryAccess
                },
                rows: (1..=u64::from(sel >> 4) + 1)
                    .map(|l| ExportRow {
                        file: if sel & 8 == 0 {
                            1 + u64::from(l > 8)
                        } else {
                            0
                        },
                        line: l,
                        end: 100 * l,
                        raw: b"{}".to_vec(),
                        rotate: None,
                    })
                    .collect(),
                budget_ms: 1000,
            })),
            Answer::ExportSetup(_) => Some(Request::ExportSetup(ExportSetup {
                agent_id: "0".repeat(32),
                hostname: "host".into(),
                version: "1".into(),
                pubkey: [0; 32],
                file: (sel & 4 != 0).then_some(FileSetup {
                    max_bytes: 1 << 20,
                    max_files: 2,
                }),
                syslog: (sel & 8 != 0 || sel & 4 == 0).then(|| SyslogSetup {
                    addr: ExportAddr::V4([127, 0, 0, 1]),
                    port: 6514,
                    server_name: "receiver.lab".into(),
                    ca_pem: b"-".to_vec(),
                    facility: 13,
                    pin_port: sel & 16 != 0,
                }),
            })),
            _ => None,
        };
        let req_for = |sel: u8, a: &Answer| match sel & 3 {
            _ if export_req(sel, a).is_some() => export_req(sel, a).unwrap(),
            0 => Request::Ping,
            1 => Request::DnsNames(
                (0..match a {
                    Answer::DnsNames(o) => o.len(),
                    _ => 1,
                })
                    .map(|_| QnameIn {
                        // as the fuzz target's `name_bytes`
                        bytes: (0..usize::from((sel >> 2) & 0xf) * 8)
                            .map(|i| (i as u8).wrapping_add(sel))
                            .collect(),
                        form: match sel >> 6 {
                            1 => QnameForm::Nss,
                            2 => QnameForm::WireFindEnd,
                            _ => QnameForm::Wire,
                        },
                    })
                    .collect(),
            ),
            2 => Request::TlsClientHello(vec![0x16; usize::from(sel >> 2)]),
            _ => Request::DnsAnswers(vec![0; usize::from(sel >> 2) * 16]),
        };
        let verdict = |bytes: &[u8]| {
            let (sel, p) = bytes.split_first().unwrap();
            match decode::<FromWorker>(p).unwrap() {
                FromWorker::Hello(h) => check_hello(
                    &h,
                    &Expected {
                        kind: if sel & 1 == 0 {
                            WorkerKind::Parse
                        } else {
                            WorkerKind::Export
                        },
                        pid: h.pid,
                        uid: h.sandbox.uid,
                        gid: h.sandbox.gid,
                        kernel_landlock_abi: sel >> 2,
                    },
                )
                .is_ok(),
                FromWorker::Response(r) => {
                    check_response(&req_for(*sel, &r.answer), &r.answer).is_ok()
                }
            }
        };
        for (name, bytes) in inputs("seeds", "ipc_check") {
            assert!(verdict(&bytes), "{name}");
        }
        for (name, bytes) in inputs("regressions", "ipc_check") {
            assert!(!verdict(&bytes), "{name}");
        }
    }

    /// Lab PR 224: the resolv.conf seeds name resolvers (both families,
    /// a zone index, an IPv4-mapped one) and skip what is no nameserver.
    #[test]
    fn resolv_conf_seeds_name_resolvers() {
        let mut all = Vec::new();
        for (_, bytes) in inputs("seeds", "resolv_conf") {
            all.extend(crate::net::resolvers::parse_resolv_conf(text(&bytes)));
        }
        assert!(all.iter().any(|ip| ip.is_ipv4()) && all.iter().any(|ip| ip.is_ipv6()));
        assert!(all.contains(&"198.51.100.53".parse().unwrap()), "{all:?}");
        assert!(all.contains(&"fe80::1".parse().unwrap()), "{all:?}");
        assert!(!all.contains(&"10.0.0.9".parse().unwrap()), "{all:?}");
    }

    /// Lab PR 236: the rule-policy seeds reach both sides — a policy of
    /// every directive accepted, and refusals (an exemption by name, of
    /// uid 0, of a staged executable) named by their line.
    #[test]
    fn rule_policy_seeds_reach_acceptance_and_refusal() {
        use crate::decision::rule_policy::parse;
        let (mut ok, mut refused) = (0, 0);
        for (name, bytes) in inputs("seeds", "rule_policy") {
            match parse(text(&bytes)) {
                Ok(p) => {
                    assert!(p.modes().count() >= 4, "{name}");
                    assert!(p.all_exemptions().next().is_some(), "{name}");
                    assert!(p.ransomware_combat_without_corroboration, "{name}");
                    ok += 1;
                }
                Err(e) => {
                    assert_eq!(e.line, 2, "{name}: {e}");
                    refused += 1;
                }
            }
        }
        assert!(ok >= 1 && refused >= 2, "ok {ok}, refused {refused}");
        // review of #495, N6: a seed whose refused enforce the start applies
        // as alert, the rest in force
        let mut demoted = 0;
        for (name, bytes) in inputs("seeds", "rule_policy") {
            let b = crate::decision::rule_policy::boot_policy(Some((
                std::path::Path::new("/etc/northnarrow/rule-policy.local"),
                text(&bytes),
            )));
            if b.demoted.is_some() {
                assert!(!b.policy.is_builtin(), "{name}");
                demoted += 1;
            }
        }
        assert!(demoted >= 1, "no seed reaches the start's demotion");
    }

    #[test]
    fn text_and_binary_seeds_reach_the_asserted_paths() {
        use crate::anti_tamper::combat_allow::{
            generate_accept_rules, generate_accept_rules_v6, parse_allow_text,
        };
        // combat_allow: IPv4 and IPv6 lines generated and spliced
        let (mut v4, mut v6) = (0, 0);
        for (_, bytes) in inputs("seeds", "combat_allow") {
            let t = text(&bytes);
            let (allow, base) = t.split_once('\0').expect("allow text, NUL, base ruleset");
            let load = parse_allow_text(allow);
            v4 += generate_accept_rules(&load.entries, "NORTHNARROW_COMBAT")
                .lines()
                .count();
            v6 += generate_accept_rules_v6(&load.entries, "NORTHNARROW_COMBAT")
                .lines()
                .count();
            assert!(!base.is_empty());
        }
        assert!(v4 > 0 && v6 > 0, "v4 {v4}, v6 {v6}");
        // canary_template: one template per family, each renders
        use crate::canary::templates::{render, CredFamily};
        let families = ["aws", "azure", "gcp", "docker", "generic"];
        let mut rendered = std::collections::BTreeSet::new();
        for (name, bytes) in inputs("seeds", "canary_template") {
            let (sel, body) = bytes.split_first().unwrap();
            let family = CredFamily::from_wire(families[*sel as usize % families.len()]).unwrap();
            let dir = tempfile::tempdir().unwrap();
            std::fs::write(dir.path().join(format!("{}.tmpl", family.as_wire())), body).unwrap();
            render(family, "9f3c8a01b2c3d4e5f6a7b8c9d0e1f2a3", Some(dir.path()))
                .unwrap_or_else(|e| panic!("{name}: {e}"));
            rendered.insert(family.as_wire());
        }
        assert_eq!(rendered.len(), families.len(), "{rendered:?}");
        // tls_client_hello: parses, with SNI and ALPN
        for (name, bytes) in inputs("seeds", "tls_client_hello") {
            let hello =
                nn_parse::tls::parse_client_hello(&bytes).unwrap_or_else(|| panic!("{name}"));
            assert!(nn_parse::tls::extract_sni(&hello).is_some(), "{name}");
            assert!(!nn_parse::tls::extract_alpn(&hello).is_empty(), "{name}");
        }
        // dns_records: A and AAAA answers, and names
        let (mut a, mut aaaa, mut names) = (0, 0, 0);
        for (_, bytes) in inputs("seeds", "dns_records") {
            a += nn_parse::dns_records::parse_a_records(&bytes).len();
            aaaa += nn_parse::dns_records::parse_aaaa_records(&bytes).len();
            if nn_parse::dns_qname::qname_wire_end(&bytes).is_some() {
                names += 1;
            }
        }
        assert!(a > 0 && aaaa > 0 && names > 0, "{a} {aaaa} {names}");
        // the rest: each seed is accepted
        for (name, bytes) in inputs("seeds", "btf_parse") {
            assert!(parse_btf_and_resolve(&bytes), "{name}");
        }
        for (name, bytes) in inputs("seeds", "tracefs_format") {
            let t = text(&bytes);
            assert!(
                crate::anti_tamper::btf_revalidate::parse_format_field_offset(t, "filename")
                    .is_some(),
                "{name}"
            );
        }
        for (name, bytes) in inputs("seeds", "role_list") {
            assert!(
                crate::anti_tamper::admin_auth::parse_role_list(text(&bytes)).is_ok(),
                "{name}"
            );
        }
        for (name, bytes) in inputs("seeds", "chainlog_line") {
            assert!(
                chainlog_terminator_entry_hash(text(&bytes)).is_some(),
                "{name}"
            );
        }
    }
}
