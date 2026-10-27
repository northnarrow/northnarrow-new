//! R013 — Namespace / container-escape tooling from a non-standard
//! path (Tappa 10.5 D2).
//!
//! MITRE T1611 (Escape to Host). `nsenter` / `unshare` / `runc` are
//! the canonical container-escape primitives. They legitimately ship
//! under the standard binary dirs (util-linux / the container
//! runtime); a copy running from anywhere ELSE (a dropped binary in
//! `/tmp`, `/dev/shm`, a home dir, …) is the escape-attempt shape.
//! Design §7.1: comm ∈ {nsenter, unshare, runc} & filename ∉ standard
//! path, gated by `process-comm-allowlist`.
//!
//! Lab PR 166: a copy run from a staging directory is killed with its
//! tree, as R001..R003 would ([`super::tool_kill`]); from another
//! non-standard path (`/opt`, a home) it keeps the single-process kill.
//!
//! External audit EBPF-021: the argv flags only enrich the reasoning; when
//! the kernel cut the argv, the reasoning says so, since a flag may be
//! past the cut.

use std::sync::Arc;

use nn_model::{Event, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::config::comm_allowlist::Judgement;
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{rules::build_verdict, Rule};
use crate::posture::host::PostureHost;

/// Container/namespace escape tool comms (design §7.1).
const ESCAPE_TOOLS: &[&str] = &["nsenter", "unshare", "runc"];

/// Standard system binary directories these tools legitimately live
/// in. A match from outside all of these is the suspicious case.
const STD_EXEC_PREFIXES: &[&str] = &["/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/"];

pub struct R013NamespaceEscapeTooling<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
}

impl<H: PostureHost> R013NamespaceEscapeTooling<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self { allowlist }
    }
}

impl<H: PostureHost> Rule for R013NamespaceEscapeTooling<H> {
    fn id(&self) -> &'static str {
        "R013_NamespaceEscapeTooling"
    }
    fn name(&self) -> &'static str {
        "Namespace/escape tooling from non-standard path"
    }
    fn category(&self) -> &'static str {
        "privilege_escalation"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::PrivilegeEscalation, "T1611")];
        ATTACK
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            comm,
            filename,
            argv,
            exe,
            ..
        } = event
        else {
            return None;
        };
        if !ESCAPE_TOOLS.contains(&comm.as_str()) {
            return None;
        }
        // Review 61: the file the kernel executed (`/usr/bin/../../tmp/x`
        // is not under /usr/bin; a symlink to /usr/bin/x is).
        let filename = exe.path_or(filename);
        // Fail-safe: an EMPTY filename means the sensor could not read
        // the exec path (a tracepoint layout the agent did not expect —
        // RHEL 9 shifted `sched_process_exec.filename` and this rule
        // killed every `sh` on AlmaLinux 9). "Not under a standard
        // prefix" must never be inferred from a missing attribute.
        if filename.is_empty() {
            return None;
        }
        if STD_EXEC_PREFIXES.iter().any(|p| filename.starts_with(p)) {
            return None;
        }
        // External audit NETR-003 class: the allowlist judged on what the
        // kernel executed, not on the comm the process chose.
        let judgement = super::judge_spawn(&self.allowlist, event);
        if judgement == Judgement::Allowed {
            return None;
        }
        // D5: argv flags reveal a host-escape attempt (e.g. `nsenter -t 1
        // -m`, `--privileged`, `--mount`, `--net=host`). Additive.
        let mut reasoning = String::from(
            "Namespace/escape tool (nsenter/unshare/runc) exec from a \
             non-standard path — container-escape primitive (T1611); \
             posture → ENGAGED",
        );
        if argv.iter().any(|a| {
            a == "--privileged"
                || a == "--security-opt"
                || a.starts_with("--net=host")
                || a == "-t"
                || a == "--target"
                || a == "--mount"
                || a == "-m"
        }) {
            reasoning = format!(
                "{reasoning} — host-escape flags in argv ({})",
                argv.join(" ")
            );
        }
        // External audit EBPF-021: flags past a cut argv were not seen.
        let reasoning = super::with_argv_cut_note(reasoning, event);
        // External audit PROC-008: and on the program's lineage.
        Some(super::judge_actor(
            &self.allowlist,
            event,
            judgement.apply(
                build_verdict(
                    self,
                    event,
                    super::tool_kill(filename),
                    Severity::High,
                    &reasoning,
                ),
                comm,
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type CommAllowlist = crate::config::comm_allowlist::CommAllowlist<H>;
    type R013NamespaceEscapeTooling = super::R013NamespaceEscapeTooling<H>;
    use crate::decision::rules::testutil::{argv_cut, spawn, spawn_full};
    use nn_model::ResponseAction;

    fn rule() -> R013NamespaceEscapeTooling {
        R013NamespaceEscapeTooling::new(Arc::new(CommAllowlist::default()))
    }

    /// Lab PR 166: a staged copy is killed with its tree; one elsewhere
    /// keeps the single-process kill.
    #[test]
    fn r013_staged_copy_kills_the_process_tree() {
        let v = rule()
            .evaluate(&spawn("nsenter", "/var/tmp/nsenter"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        let v = rule()
            .evaluate(&spawn("nsenter", "/opt/tools/nsenter"))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcess);
    }

    /// Empty filename = sensor could not read the path; must not fire.
    #[test]
    fn empty_filename_never_fires() {
        assert!(rule().evaluate(&spawn("nsenter", "")).is_none());
    }

    #[test]
    fn fires_on_escape_tool_from_nonstandard_path() {
        for tool in ESCAPE_TOOLS {
            let v = rule()
                .evaluate(&spawn(tool, &format!("/tmp/{tool}")))
                .unwrap_or_else(|| panic!("should fire on /tmp/{tool}"));
            assert_eq!(v.rule_id, "R013_NamespaceEscapeTooling");
            assert_eq!(v.action, ResponseAction::KillProcessTree);
            assert_eq!(v.severity, Severity::High);
            // Graceful degrade: empty argv → no escape-flag clause.
            assert!(!v.reasoning.contains("host-escape flags"));
        }
    }

    #[test]
    fn argv_escape_flags_enrich_reasoning() {
        let ev = spawn_full(
            "nsenter",
            "/tmp/nsenter",
            0,
            &["nsenter", "-t", "1", "-m", "--", "/bin/sh"],
            "bash",
        );
        let v = rule().evaluate(&ev).expect("fires");
        assert!(v.reasoning.contains("host-escape flags in argv"));
        assert!(!v.reasoning.contains("truncated"), "{}", v.reasoning);
    }

    /// External audit EBPF-021: with the argv cut, no host-escape flag in
    /// the part kept proves nothing; the reasoning names the cut, and the
    /// verdict stays the same.
    #[test]
    fn r013_cut_argv_is_named() {
        let mut args = vec!["unshare"];
        args.extend(std::iter::repeat_n("--fork", 80));
        let whole = spawn_full("unshare", "/tmp/unshare", 0, &args, "bash");
        let cut = argv_cut(whole.clone());
        let (w, c) = (
            rule().evaluate(&whole).unwrap(),
            rule().evaluate(&cut).unwrap(),
        );
        assert_eq!((w.action, w.severity), (c.action, c.severity));
        assert!(!w.reasoning.contains("argv truncated"), "{}", w.reasoning);
        assert!(
            c.reasoning.contains("argv truncated at 511 bytes"),
            "{}",
            c.reasoning
        );
    }

    #[test]
    fn ignores_escape_tool_from_standard_path() {
        // Legit util-linux / runtime location → no fire.
        assert!(rule()
            .evaluate(&spawn("nsenter", "/usr/bin/nsenter"))
            .is_none());
        assert!(rule().evaluate(&spawn("runc", "/usr/sbin/runc")).is_none());
        // Non-escape tool from a weird path is not R013's concern.
        assert!(rule().evaluate(&spawn("ls", "/tmp/ls")).is_none());
    }

    #[test]
    fn allowlisted_comm_is_exempt() {
        let r = R013NamespaceEscapeTooling::new(Arc::new(CommAllowlist::from_iter_owned([
            "runc".to_string()
        ])));
        assert!(r.evaluate(&spawn("runc", "/opt/cri/runc")).is_none());
        // A different escape tool from a non-standard path still fires.
        assert!(r.evaluate(&spawn("nsenter", "/tmp/nsenter")).is_some());
    }
}
