//! Lab PR 224 (CM-02 d, research defect D9): the transfer tools of the
//! network allowlist are exempt, not the dropper that drives them.
//!
//! `netflow-comm-allowlist` exempts `curl`, `wget`, `ssh`, `scp`, `rsync`
//! and `git` from the record and port rules of the network family
//! (NN-L-NET-006/007/009/010/011/013/018/019). The exemption is justified
//! for the tools themselves — an administrator's `rsync` backup is a big
//! flow, `git fetch` from cron a regular one, `ssh` reaches internal hosts
//! — and it was judged on the exec identity since external audit NET-010.
//! It also covered the `curl … | sh` of every cryptojacking dropper
//! (Kinsing, TeamTNT, 8220) and the `ssh` of lateral movement with stolen
//! keys, because the tool is the same program whoever drives it.
//!
//! [`precursor_of`] says when the lineage of a transfer tool makes it a
//! dropper's instrument: the process or an ancestor holds a live chain
//! precursor (an exec from a staging directory, a credential-store read,
//! a canary trip: the correlation store), an ancestor runs an image from a
//! staging directory (a dropper whose precursor aged out), or the tool
//! runs under a shell that an exposed service started (the web shell's
//! `www-data → sh → curl`). Then the allowlist answers
//! [`Judgement::Revoked`](crate::config::comm_allowlist::Judgement::Revoked)
//! and the rule judges the flow as any other. Everything is read on exec
//! identity (the spawn cache, else `/proc`), never on `comm`.

use std::sync::Arc;

use parking_lot::Mutex;

use crate::posture::host::PostureHost;

use crate::config::comm_allowlist::PrecursorCheck;
use crate::decision::correlation::{CorrelationStore, PrecursorKind};
use crate::posture::lineage::AuthSessionTracker;

/// The conditional entries of the network allowlist.
pub const TRANSFER_TOOLS: &[&str] = &["curl", "wget", "ssh", "scp", "sftp", "rsync", "git"];

/// Programs that serve the network and should not start shells that run
/// transfer tools: web servers and their application runtimes, databases,
/// mail and file servers. `sshd` is not one: a login shell is the
/// administrator's.
pub const EXPOSED_SERVICES: &[&str] = &[
    "nginx",
    "apache2",
    "httpd",
    "lighttpd",
    "caddy",
    "php-fpm",
    "php-cgi",
    "uwsgi",
    "gunicorn",
    "java",
    "tomcat",
    "mysqld",
    "mariadbd",
    "postgres",
    "redis-server",
    "memcached",
    "vsftpd",
    "proftpd",
    "exim4",
    "smbd",
];

/// Ancestors walked at most.
const MAX_HOPS: usize = 8;

/// `base` is the program `name`, or `name` with a version suffix
/// (`php-fpm8.3`, `python3.12`).
pub(crate) fn program_is(base: &str, name: &str) -> bool {
    base.strip_prefix(name)
        .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit() || c == '.'))
}

fn base_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// A shell, by the basename of what the kernel executed.
pub(crate) fn is_shell_base(base: &str) -> bool {
    crate::decision::rules::r020_shell_with_socket_stdio::SHELLS
        .iter()
        .any(|s| program_is(base, s))
}

/// What in `pid`'s lineage makes a transfer tool a dropper's instrument
/// (module docs), at `now_ns`; `None` when nothing does.
pub fn precursor_of<H: PostureHost>(
    store: &Mutex<CorrelationStore<H>>,
    lineage: &AuthSessionTracker<H>,
    pid: u32,
    now_ns: u64,
) -> Option<&'static str> {
    let (held, ancestors) = {
        let store = store.lock();
        let held = store.precursor_in_lineage(
            pid,
            &[
                PrecursorKind::TmpExec,
                PrecursorKind::CredRead,
                PrecursorKind::CanaryTrip,
            ],
            now_ns,
        );
        (held, store.ancestry().get_ancestors(pid))
    };
    match held {
        Some(PrecursorKind::TmpExec) => return Some("an exec from a staging directory"),
        Some(PrecursorKind::CredRead) => return Some("a credential-store read"),
        Some(PrecursorKind::CanaryTrip) => return Some("a canary trip"),
        Some(PrecursorKind::PrivEsc) | None => {}
    }
    let mut shell_below = false;
    for hop in ancestors.iter().take(MAX_HOPS) {
        let Some(id) = lineage.exec_identity(hop.pid) else {
            // Gone or deleted: `image_path` still names a staged image.
            if lineage
                .image_path(hop.pid)
                .is_some_and(|p| crate::decision::rules::is_staging_path(&p))
            {
                return Some("a staging-directory image among its ancestors");
            }
            continue;
        };
        let exe = id.exe.to_string_lossy();
        if crate::decision::rules::is_staging_path(&exe)
            || id
                .script
                .as_deref()
                .is_some_and(crate::decision::rules::is_staging_path)
        {
            return Some("a staging-directory image among its ancestors");
        }
        let base = base_of(&exe);
        let program = id.script.as_deref().map(base_of).unwrap_or(base);
        if shell_below && EXPOSED_SERVICES.iter().any(|s| program_is(program, s)) {
            return Some("a shell started by an exposed network service");
        }
        if is_shell_base(base) {
            shell_below = true;
        }
    }
    None
}

/// The check the network allowlist runs for its transfer tools.
pub fn precursor_check<H: PostureHost>(
    store: Arc<Mutex<CorrelationStore<H>>>,
    lineage: AuthSessionTracker<H>,
) -> PrecursorCheck {
    Arc::new(move |pid| precursor_of(&store, &lineage, pid, H::monotonic_ns()))
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type AuthSessionTracker = crate::posture::lineage::AuthSessionTracker<H>;
    type CorrelationStore = crate::decision::correlation::CorrelationStore<H>;
    use crate::decision::correlation::ProcKey;

    fn lineage_of(execs: &[(u32, u32, &str)]) -> (tempfile::TempDir, AuthSessionTracker) {
        let tmp = tempfile::TempDir::new().unwrap();
        let t = AuthSessionTracker::new(tmp.path());
        for (pid, ppid, exe) in execs {
            t.ingest_spawn_with_argv(*pid, *ppid, exe, &[exe.to_string()], 1);
        }
        (tmp, t)
    }

    fn store_of(edges: &[(u32, u32)]) -> Mutex<CorrelationStore> {
        let mut s = CorrelationStore::new();
        for (child, parent) in edges {
            s.observe_spawn(*child, *parent, 0);
        }
        Mutex::new(s)
    }

    #[test]
    fn a_clean_lineage_keeps_the_exemption() {
        let (_t, l) = lineage_of(&[(10, 1, "/usr/bin/bash"), (11, 10, "/usr/bin/curl")]);
        let s = store_of(&[(11, 10)]);
        assert_eq!(precursor_of(&s, &l, 11, 1_000), None);
    }

    #[test]
    fn a_staged_parent_or_its_precursor_revokes_it() {
        let (_t, l) = lineage_of(&[(20, 1, "/tmp/.x/dropper"), (21, 20, "/usr/bin/curl")]);
        let s = store_of(&[(21, 20)]);
        assert_eq!(
            precursor_of(&s, &l, 21, 1_000),
            Some("a staging-directory image among its ancestors")
        );
        s.lock().record(
            ProcKey {
                pid: 20,
                start_ns: 0,
            },
            PrecursorKind::TmpExec,
            900,
        );
        assert_eq!(
            precursor_of(&s, &l, 21, 1_000),
            Some("an exec from a staging directory")
        );
    }

    #[test]
    fn a_credential_read_by_an_ancestor_revokes_it() {
        let (_t, l) = lineage_of(&[(30, 1, "/usr/bin/python3"), (31, 30, "/usr/bin/curl")]);
        let s = store_of(&[(31, 30)]);
        s.lock().record(
            ProcKey {
                pid: 30,
                start_ns: 0,
            },
            PrecursorKind::CredRead,
            500,
        );
        assert_eq!(
            precursor_of(&s, &l, 31, 1_000),
            Some("a credential-store read")
        );
    }

    #[test]
    fn a_shell_of_an_exposed_service_revokes_it_an_admin_shell_does_not() {
        let (_t, l) = lineage_of(&[
            (40, 1, "/usr/sbin/php-fpm8.3"),
            (41, 40, "/usr/bin/dash"),
            (42, 41, "/usr/bin/curl"),
            (50, 1, "/usr/sbin/sshd"),
            (51, 50, "/usr/bin/bash"),
            (52, 51, "/usr/bin/curl"),
        ]);
        let s = store_of(&[(41, 40), (42, 41), (51, 50), (52, 51)]);
        assert_eq!(
            precursor_of(&s, &l, 42, 1_000),
            Some("a shell started by an exposed network service")
        );
        assert_eq!(precursor_of(&s, &l, 52, 1_000), None);
    }

    #[test]
    fn version_suffixes_name_the_same_program() {
        assert!(program_is("php-fpm8.3", "php-fpm"));
        assert!(program_is("python3.12", "python3"));
        assert!(!program_is("nginx-debugger", "nginx"));
        assert!(program_is("nginx", "nginx"));
    }
}
