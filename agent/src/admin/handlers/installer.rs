//! The signed trusted-installer grant (R11d, lab PR 263: from
//! `admin_socket.rs`): the window an upgrade needs, armed for the signed
//! span.

use std::path::Path;
use std::time::Instant;

use tracing::{info, warn};

use nn_proto::admin_protocol::{AdminResult, TrustedInstallerGrantRequest};

use crate::admin::verify::{Verified, signed};
use crate::anti_tamper::admin_auth::ConnAuth;
use crate::anti_tamper::trusted_installer::{TrustedInstallerOverride, installer_of_requester};

/// FIM-009 self-upgrade (§15.1) — handle one
/// [`TrustedInstallerGrantRequest`]. Verifies the signed grant (M=1
/// quorum carrying `Role::TrustedInstaller`, with the full nonce +
/// agent_id + skew binding the standard `verify_signed_payload_quorum`
/// enforces), then arms the TTL'd FS-pin override + the NN-L-FIM-009
/// own-unit detection downgrade for the (clamped) signed window. The
/// ARM is recorded in the audit chain by `emit_audit_for`; the
/// close/expiry record is written by the override itself.
///
/// M=1 today — like COMBAT reactivation — but expressed through the
/// pipeline's quorum (`verify::Quorum`) so a future hardening can require
/// co-signers without touching this dispatcher.
///
/// Lot 278: asked for by an installer for its own tree (`requester`: the
/// peer's `SO_PEERCRED` pid, from
/// [`AdminMessage::TrustedInstallerGrantForInstallerRequest`] only — review
/// of #493, note a), the window is granted to that installer, the
/// requester's parent ([`installer_of_requester`]), so that R009 records,
/// rather than kills, what its own process tree executes from its source
/// tree. A plain grant (`None`) names no installer.
///
/// [`AdminMessage::TrustedInstallerGrantForInstallerRequest`]: nn_proto::admin_protocol::AdminMessage::TrustedInstallerGrantForInstallerRequest
pub(in crate::admin) fn dispatch_trusted_installer_grant(
    req: TrustedInstallerGrantRequest,
    auth: &ConnAuth<'_>,
    installer_override: Option<&TrustedInstallerOverride>,
    requester: Option<u32>,
    fps_out: &mut Vec<String>,
) -> AdminResult {
    // Required distinct signatures (M of N): 1 today, the pipeline's
    // (`verify::signed`); raise it there to harden.
    signed(
        &req,
        auth,
        fps_out,
        |r| r,
        |v| trusted_installer_grant(v, installer_override, requester),
    )
}

/// The verified grant: the window armed for the (clamped) signed span.
fn trusted_installer_grant(
    v: Verified<'_, TrustedInstallerGrantRequest>,
    installer_override: Option<&TrustedInstallerOverride>,
    requester: Option<u32>,
) -> AdminResult {
    // The op/extra invariant is enforced inside the verify; this pulls
    // the signed window out.
    let window_secs = v.extra().window_secs;

    match installer_override {
        Some(ov) => {
            let installer =
                requester.and_then(|pid| installer_of_requester(Path::new("/proc"), pid));
            let window = ov.arm_for(
                window_secs,
                Instant::now(),
                v.fingerprints()
                    .first()
                    .map(String::as_str)
                    .unwrap_or("(unknown)"),
                installer,
            );
            info!(
                target: "admin.trusted_installer_grant",
                signer_fp = %v.signer_fp(),
                window_secs = window.as_secs(),
                requester,
                installer_pid = installer.map(|(pid, _)| pid),
                "trusted-installer override ARMED via signed grant (FIM-009 §15.1)"
            );
            AdminResult::Success
        }
        None => {
            // Legacy serve path with no override wired — verified but
            // nothing to arm. Surface as UnknownOperation so a stale
            // test fixture doesn't read as a successful arm.
            warn!(
                target: "admin.trusted_installer_grant",
                "trusted-installer grant verified but no override wired (legacy serve path)"
            );
            AdminResult::UnknownOperation
        }
    }
}

// ── Lot 2.3b: the window per process tree, the real handler ────────────

use nn_proto::admin_protocol::{TrustedInstallerTreeGrantRequest, WindowReply};
use nn_proto::admin_signed_payload::{MAX_ACCEPTED_FOREIGN, TrustedInstallerTreeGrantExtra};

use crate::anti_tamper::trusted_installer::{
    LineReader, ProcFs, TreeRoot, TreeRootKind, admit_line,
};

/// Where `--interactive` reads whether an unprivileged `TIOCSTI` is open.
const LEGACY_TIOCSTI: &str = "/proc/sys/dev/tty/legacy_tiocsti";

/// Lot 2.3b (the design's section 1): `--interactive` is refused where
/// `dev.tty.legacy_tiocsti` is 1 or absent (before 6.2): anyone's
/// `TIOCSTI` could then type into the window's terminal. Where it is 0 the
/// window opens marked degraded (the sysctl does not bind a
/// `CAP_SYS_ADMIN` caller, and the terminal's other end is outside the
/// tree). `sysctl`: the file's content, `None` when absent.
pub(in crate::admin) fn interactive_refusal(sysctl: Option<&str>) -> Option<String> {
    match sysctl.map(str::trim) {
        Some("0") => None,
        Some(v) => Some(format!(
            "--interactive is refused while dev.tty.legacy_tiocsti is {v} (any process may type \
             into the window's terminal)"
        )),
        None => Some(
            "--interactive is refused on a kernel without dev.tty.legacy_tiocsti (before 6.2: \
             any process may type into the window's terminal)"
                .to_string(),
        ),
    }
}

/// The installed `nn-admin` a `window-run` root must run: the one beside
/// the agent's own binary, by its `(st_dev, st_ino)`.
fn installed_admin() -> Option<(u64, u64)> {
    let exe = antitamper_bpf::kernel_roots::current_exe().ok()?;
    let f = antitamper_bpf::kernel_roots::open(
        exe.parent()?.join("nn-admin"),
        libc::O_PATH | libc::O_CLOEXEC,
    )
    .ok()?;
    // the kernel's identity, as a process's executable link gives it
    let c = antitamper_bpf::kernel_roots::cached(&f).ok()?;
    Some((c.dev, c.ino))
}

/// What a tree grant reads of its host besides `/proc` (the tests' fakes).
pub(in crate::admin) struct TreeHost<'a> {
    pub reader: &'a dyn LineReader,
    pub installed_admin: Option<(u64, u64)>,
    pub legacy_tiocsti: Option<String>,
    pub pregrant: &'a dyn Fn() -> super::pregrant::PregrantReport,
}

/// Lot 2.3b (D2, D3, D5): the verified tree grant `v` asked by `requester`
/// (the socket's `SO_PEERCRED` peer): the admission policy, the pre-grant
/// check, then the arming (the members, the frozen objects, PID 1's
/// environment, the grant). Every refusal is signed with its reason
/// (`trusted_installer_tree_grant_refused`) and answered `ActionFailed`
/// with it; nothing is armed. Never a host-wide window instead.
pub(in crate::admin) fn dispatch_tree_grant(
    req: &TrustedInstallerTreeGrantRequest,
    auth: &ConnAuth<'_>,
    installer_override: Option<&TrustedInstallerOverride>,
    requester: u32,
    fps_out: &mut Vec<String>,
) -> WindowReply {
    signed(
        req,
        auth,
        fps_out,
        |r| WindowReply::new(r, 0, ""),
        |v| {
            let sigs: Vec<[u8; 64]> = v.request().signatures.iter().map(|s| s.signature).collect();
            let pregrant =
                || super::pregrant::check(None, &super::pregrant::HostDatabase::open(None));
            let host = TreeHost {
                reader: &ProcFs(Path::new("/proc")),
                installed_admin: installed_admin(),
                // unreadable: refused as absent (fails closed)
                legacy_tiocsti: antitamper_bpf::kernel_roots::read_to_string(LEGACY_TIOCSTI).ok(),
                pregrant: &pregrant,
            };
            let reply = tree_grant(v.extra(), installer_override, requester, &host);
            if let (Some(ov), nn_proto::admin_protocol::AdminResult::Success) =
                (installer_override, &reply.result)
            {
                ov.set_tree_proof(reply.generation, &v.request().payload, &sigs);
            }
            reply
        },
    )
}

/// [`dispatch_tree_grant`]'s decision on the verified `extra`.
pub(in crate::admin) fn tree_grant(
    extra: &TrustedInstallerTreeGrantExtra,
    installer_override: Option<&TrustedInstallerOverride>,
    requester: u32,
    host: &TreeHost<'_>,
) -> WindowReply {
    use nn_proto::admin_protocol::AdminResult;
    let Some(ov) = installer_override else {
        warn!(
            target: "admin.trusted_installer_grant",
            "tree grant verified but no override wired (legacy serve path)"
        );
        return WindowReply::new(AdminResult::UnknownOperation, 0, "");
    };
    let refuse = |why: String| {
        ov.note_tree_refusal(&why);
        WindowReply::new(AdminResult::ActionFailed, 0, &why)
    };
    if extra.accepted_foreign.len() > MAX_ACCEPTED_FOREIGN {
        return refuse(format!(
            "the request accepts {} foreign files, at most {MAX_ACCEPTED_FOREIGN}",
            extra.accepted_foreign.len()
        ));
    }
    if extra.interactive {
        if extra.root_kind != TreeRootKind::WindowRun {
            return refuse(format!(
                "an {} window is never interactive",
                extra.root_kind.as_str()
            ));
        }
        if let Some(why) = interactive_refusal(host.legacy_tiocsti.as_deref()) {
            return refuse(why);
        }
    }
    let root = TreeRoot {
        pid: extra.root_pid,
        start_ticks: extra.root_start_ticks,
        root_kind: extra.root_kind,
        script_sha256: extra.script_sha256,
    };
    let line = match ov
        .own_tgids()
        .and_then(|own| admit_line(host.reader, requester, &root, &own, host.installed_admin))
    {
        Ok(line) => line,
        Err(why) => return refuse(why),
    };
    // D5: code planted before the window
    let report = (host.pregrant)();
    let (accepted, foreign): (Vec<_>, Vec<_>) = report
        .foreign
        .iter()
        .partition(|f| f.sha256 != [0; 32] && extra.accepted_foreign.contains(&f.sha256));
    if !foreign.is_empty() {
        let named: Vec<String> = foreign
            .iter()
            .map(|f| format!("{} ({}, sha256 {})", f.path, f.why, hex::encode(f.sha256)))
            .collect();
        return refuse(format!(
            "foreign code before the window: {} (checked {} files in {} ms; accept a file you \
             have verified with --accept-foreign <sha256>)",
            named.join("; "),
            report.checked,
            report.millis
        ));
    }
    let notes = serde_json::json!({
        "root_kind": extra.root_kind.as_str(),
        "interactive": extra.interactive,
        "degraded": extra.interactive,
        "pregrant": {
            "checked": report.checked,
            "millis": report.millis,
            "accepted_foreign": accepted
                .iter()
                .map(|f| serde_json::json!({ "path": f.path, "sha256": hex::encode(f.sha256), "why": f.why }))
                .collect::<Vec<_>>(),
        },
    });
    let root_pair = (extra.root_pid, extra.root_start_ticks);
    match ov.arm_tree(extra.window_secs, root_pair, &line, notes) {
        Ok(generation) => {
            info!(
                target: "admin.trusted_installer_grant",
                generation,
                root_pid = root_pair.0,
                root_kind = extra.root_kind.as_str(),
                requester,
                members = line.len(),
                degraded = extra.interactive,
                "trusted-installer window per process tree ARMED via signed grant"
            );
            let mut detail = format!(
                "window {generation} armed for the process tree of {} ({}), {} members",
                root_pair.0,
                extra.root_kind.as_str(),
                line.len()
            );
            if extra.interactive {
                detail.push_str(
                    "; DEGRADED: interactive (the terminal's other end is outside the tree)",
                );
            }
            if !accepted.is_empty() {
                detail.push_str(&format!("; {} foreign file(s) accepted", accepted.len()));
            }
            WindowReply::new(AdminResult::Success, generation, &detail)
        }
        // logged and recorded by `arm_tree`
        Err(why) => WindowReply::new(AdminResult::ActionFailed, 0, &why),
    }
}

#[cfg(test)]
mod tree_tests {
    use super::*;
    use crate::admin::handlers::pregrant::{Foreign, PregrantReport};
    use crate::anti_tamper::trusted_installer::ProcHop;
    use nn_proto::admin_protocol::AdminResult;

    /// A `/proc` of two processes: a login shell 300 (started at 30) ran
    /// nn-admin 301 (31), the requester, running the installed nn-admin.
    struct Fake;

    impl LineReader for Fake {
        fn hop(&self, pid: u32) -> std::result::Result<ProcHop, String> {
            let (ppid, start_ticks) = match pid {
                300 => (1, 30),
                301 => (300, 31),
                _ => return Err(format!("{pid}: gone")),
            };
            Ok(ProcHop {
                ppid,
                start_ticks,
                kthread: false,
            })
        }
        fn guards(&self, _pid: u32) -> std::result::Result<(u32, u32), String> {
            Ok((0, 0))
        }
        fn exe(&self, _pid: u32) -> std::result::Result<((u64, u64), String), String> {
            Ok(((1, 2), "/usr/bin/nn-admin".to_string()))
        }
    }

    fn extra(root_pid: u32, root_start_ticks: u64) -> TrustedInstallerTreeGrantExtra {
        TrustedInstallerTreeGrantExtra {
            window_secs: 60,
            root_pid,
            root_start_ticks,
            root_kind: TreeRootKind::WindowRun,
            interactive: false,
            script_sha256: [0; 32],
            accepted_foreign: Vec::new(),
        }
    }

    fn host<'a>(pregrant: &'a dyn Fn() -> PregrantReport, tiocsti: Option<&str>) -> TreeHost<'a> {
        TreeHost {
            reader: &Fake,
            installed_admin: Some((1, 2)),
            legacy_tiocsti: tiocsti.map(str::to_string),
            pregrant,
        }
    }

    fn clean() -> PregrantReport {
        PregrantReport::default()
    }

    fn planted() -> PregrantReport {
        PregrantReport {
            checked: 3,
            foreign: vec![Foreign {
                path: "/etc/apt/apt.conf.d/99planted".to_string(),
                sha256: [9; 32],
                why: "owned by no package",
            }],
            millis: 2,
        }
    }

    /// Lot 2.3b: a tree grant refused by the admission policy (a root that
    /// is not the requesting nn-admin, a start another, PID 1), by the
    /// interactive rule, or by foreign code before the window, is answered
    /// `ActionFailed` with its reason; one this start cannot arm (no pin
    /// root) too: never a window, never the host-wide one.
    #[test]
    fn a_tree_grant_is_refused_with_its_reason_and_never_falls_back() {
        let ov = TrustedInstallerOverride::new(None, 7, None, std::time::Duration::from_secs(600));
        for (e, why) in [
            (extra(300, 30), "requesting nn-admin itself"),
            (extra(301, 99), "the signed one 99"),
            (extra(1, 1), "PID 1"),
        ] {
            let r = tree_grant(&e, Some(&ov), 301, &host(&clean, None));
            assert_eq!(r.result, AdminResult::ActionFailed);
            assert!(r.detail.contains(why), "{why}: {}", r.detail);
        }
        // interactive: refused where TIOCSTI is open to everyone, or absent
        let mut i = extra(301, 31);
        i.interactive = true;
        for t in [None, Some("1")] {
            let r = tree_grant(&i, Some(&ov), 301, &host(&clean, t));
            assert!(
                r.detail.contains("--interactive is refused"),
                "{}",
                r.detail
            );
        }
        // a script root is never interactive
        let mut s = i.clone();
        s.root_kind = TreeRootKind::InstallScript;
        let r = tree_grant(&s, Some(&ov), 301, &host(&clean, Some("0")));
        assert!(r.detail.contains("never interactive"), "{}", r.detail);
        // foreign code before the window, named with its digest
        let r = tree_grant(&extra(301, 31), Some(&ov), 301, &host(&planted, None));
        assert_eq!(r.result, AdminResult::ActionFailed);
        assert!(r.detail.contains("99planted"), "{}", r.detail);
        assert!(r.detail.contains(&hex::encode([9u8; 32])), "{}", r.detail);
        // accepted by its signed digest: the check passes, and only the
        // arming refuses (no kernel programs this start: the manifest)
        let mut a = extra(301, 31);
        a.accepted_foreign.push([9; 32]);
        let r = tree_grant(&a, Some(&ov), 301, &host(&planted, None));
        assert_eq!(r.result, AdminResult::ActionFailed);
        assert!(r.detail.contains("window_tree_unavailable"), "{}", r.detail);
        assert!(!r.detail.contains("99planted"), "{}", r.detail);
        // too many accepted digests
        let mut m = extra(301, 31);
        m.accepted_foreign = vec![[1; 32]; MAX_ACCEPTED_FOREIGN + 1];
        let r = tree_grant(&m, Some(&ov), 301, &host(&clean, None));
        assert!(r.detail.contains("at most"), "{}", r.detail);
        assert!(!ov.tree_window_open() && !ov.is_window_open());
        // no override wired: as the plain grant's legacy serve path
        let r = tree_grant(&extra(301, 31), None, 301, &host(&clean, None));
        assert_eq!(r.result, AdminResult::UnknownOperation);
    }

    #[test]
    fn interactive_is_refused_unless_legacy_tiocsti_is_zero() {
        assert_eq!(interactive_refusal(Some("0\n")), None);
        assert!(interactive_refusal(Some("1\n")).unwrap().contains("is 1"));
        assert!(interactive_refusal(None).unwrap().contains("before 6.2"));
        assert!(interactive_refusal(Some("")).is_some());
    }
}
