//! Lab PR 265 (review #466 F4-bis): the start is the same agent as the
//! one before it — its directories are its own, not a mount laid over
//! them, and its signing key is not missing where an earlier identity is
//! on record.
//!
//! Since review #466 F4 a key that is there but cannot be loaded refuses
//! the start. An absent key was minted, as at a first boot, and root can
//! make the key look absent without unlinking it (the deny hooks refuse
//! that): a bind mount over `/etc/northnarrow` on the host (no deny hook
//! covers `mount(2)`), or a runtime drop-in (`BindPaths=`,
//! `TemporaryFileSystem=`) and a `cgroup.kill`. The next start then minted
//! a new key, published its public half over the old one and went on
//! signing every chain under it — the signing identity reset with one INFO
//! line. Two checks of the preflight, before anything is read, written or
//! loaded, close that:
//!
//! - [`mounts_over`]: no mount at or under the agent's own directories
//!   but a bind of a directory onto itself (what the unit's
//!   `ReadWritePaths=` makes: the same filesystem, the same directory);
//!   anything else at one of them — another directory bound there, another
//!   filesystem — hides the files the agent had. Mounts above them are not
//!   judged here: a separate `/var` (or any ancestor) on its own
//!   filesystem is a normal layout. The self-integrity watcher reports
//!   those, and a mount that swaps only one of the two trees leaves the
//!   other's evidence for [`prior_identity`].
//! - [`prior_identity`]: what says this install had a signing identity —
//!   the key's public half (`agent.sig.pub`), the install's id
//!   (`agent_id`), a signed row in the audit chain or in one of the other
//!   chains. A key absent with any of it is a key removed or hidden: the
//!   start refuses, and only a start with none of it (a first install)
//!   mints one.
//!
//! Both refusals are the journal's alone: nothing can sign them — the key
//! is the one hidden, and a mount over the agent's directories puts any
//! chain the start could open in the view it refuses.

use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

/// The agent's own mount table.
pub const OWN_MOUNTINFO: &str = "/proc/self/mountinfo";

/// The bytes of a chain read to find its first row: a row is a few hundred
/// bytes, an `agent_boot` a few kilobytes.
const FIRST_ROW_MAX: u64 = 64 * 1024;

/// One line of a `mountinfo` text (`proc(5)`): the fields the check reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub id: u64,
    pub parent: u64,
    /// `major:minor` of the filesystem.
    pub dev: String,
    /// The directory of that filesystem mounted here (`/` for its root).
    pub root: PathBuf,
    pub mount_point: PathBuf,
    pub fstype: String,
    pub source: String,
}

/// The lines of a `mountinfo` text, in order, their paths unescaped
/// (`\040` a space, `\011` a tab, `\012` a newline, `\134` a backslash);
/// malformed lines are skipped.
pub fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        // id parent major:minor root mount_point opts [optional…] - fstype source superopts
        let Some((left, right)) = line.split_once(" - ") else {
            continue;
        };
        let fields: Vec<&str> = left.split_whitespace().collect();
        if fields.len() < 5 {
            continue;
        }
        let (Ok(id), Ok(parent)) = (fields[0].parse(), fields[1].parse()) else {
            continue;
        };
        let mut right = right.split_whitespace();
        out.push(MountEntry {
            id,
            parent,
            dev: fields[2].to_string(),
            root: PathBuf::from(unescape(fields[3])),
            mount_point: PathBuf::from(unescape(fields[4])),
            fstype: right.next().unwrap_or("").to_string(),
            source: unescape(right.next().unwrap_or("")),
        });
    }
    out
}

fn unescape(s: &str) -> String {
    s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

/// `p` without `.` components and with `..` taken back lexically: the
/// spelling `mountinfo` uses for an absolute path.
fn lexical(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// The directories to check, as `mountinfo` spells them: each absolute,
/// its links resolved when it exists (a lookup crosses the mounts of the
/// path the links lead to), `/` left out (it is always a mount point), each
/// once.
pub fn spelled(dirs: &[&Path]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for d in dirs {
        let abs = std::fs::canonicalize(d).unwrap_or_else(|_| {
            lexical(&std::path::absolute(d).unwrap_or_else(|_| d.to_path_buf()))
        });
        if abs.parent().is_none() || out.contains(&abs) {
            continue;
        }
        out.push(abs);
    }
    out
}

/// The mounts at or under `dirs` (spelled as `mountinfo` spells them,
/// [`spelled`]) that hide what was there: every one but a bind of a
/// directory onto itself. A mount `m` is that when the mount it sits on
/// (its parent, by id) is of the same filesystem and shows, at `m`'s
/// mount point, the directory `m` mounts — `m`'s root is the parent's root
/// joined with the path from the parent's mount point to `m`'s. That is
/// what the unit's `ReadWritePaths=` (and `RuntimeDirectory=`) make in the
/// agent's namespace, on any layout: a separate `/var`, a btrfs subvolume
/// mounted as `/`. Another directory bound there (its root another path),
/// another filesystem (a tmpfs, a loop device, an overlay: another
/// `major:minor`), a mount whose parent is not in the table: each is one
/// finding, saying what is mounted there. Stacked mounts are each judged
/// against the one below.
pub fn mounts_over(table: &[MountEntry], dirs: &[PathBuf]) -> Vec<String> {
    let mut out = Vec::new();
    for m in table {
        let Some(dir) = dirs.iter().find(|d| m.mount_point.starts_with(d)) else {
            continue;
        };
        let what = format!(
            "{} ({} {}, its directory {})",
            m.mount_point.display(),
            if m.fstype.is_empty() { "?" } else { &m.fstype },
            if m.source.is_empty() { "?" } else { &m.source },
            m.root.display()
        );
        let Some(parent) = table.iter().find(|p| p.id == m.parent && p.id != m.id) else {
            out.push(format!(
                "{what}: a mount over the agent's directory {} whose underlying mount is not in \
                 the table",
                dir.display()
            ));
            continue;
        };
        let Ok(rel) = m.mount_point.strip_prefix(&parent.mount_point) else {
            out.push(format!(
                "{what}: a mount over the agent's directory {} outside the mount it sits on ({})",
                dir.display(),
                parent.mount_point.display()
            ));
            continue;
        };
        let expected = parent.root.join(rel);
        if m.dev == parent.dev && lexical(&m.root) == lexical(&expected) {
            continue;
        }
        out.push(if m.dev != parent.dev {
            format!(
                "{what}: another filesystem mounted there, over the agent's directory {} (the \
                 one under it is {}, mounted at {})",
                dir.display(),
                parent.dev,
                parent.mount_point.display()
            )
        } else {
            format!(
                "{what}: another directory or file bound there, over the agent's directory {} \
                 (what is there is {})",
                dir.display(),
                expected.display()
            )
        });
    }
    out
}

/// The paths whose presence says the install had a signing identity
/// before this start: the key's public half beside `signing_key`, the
/// install's id, and the chains whose signed rows count.
#[derive(Debug, Clone)]
pub struct IdentityPaths {
    pub signing_key: PathBuf,
    pub agent_id: PathBuf,
    /// The audit log and the other chains (their active files).
    pub chains: Vec<PathBuf>,
}

/// Is the key at `path` absent — its name holds nothing? Read without
/// following a link and without opening it (a key the previous agent's
/// hooks close to this process is there); an error other than "not found"
/// counts as there: the key's load decides on it.
pub fn key_absent(path: &Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// What says this install had a signing identity before this start, each
/// as a line for the journal (empty: none, a first install): the key's
/// public half (`agent.sig.pub`, any file at its name), the install's id
/// (any file at its name), a chain whose first line is a signed row (a
/// JSON object with a non-empty `entry_hash` and `agent_sig`: what every
/// row of the audit chain and of the other chains carries). A chain is
/// read as the chains are — no link followed, no FIFO waited on, a regular
/// file only, at most its first 64 KiB —; an empty one (install.sh creates
/// the audit log and the head anchor empty), one that is not a regular
/// file or whose first line is not a row is no evidence: the chain's own
/// check judges it.
pub fn prior_identity(paths: &IdentityPaths) -> Vec<String> {
    let mut out = Vec::new();
    let public = crate::keys::verifying_key_path(&paths.signing_key);
    if std::fs::symlink_metadata(&public).is_ok() {
        out.push(format!("its public half {} is there", public.display()));
    }
    if std::fs::symlink_metadata(&paths.agent_id).is_ok() {
        out.push(format!(
            "the install's id {} is there",
            paths.agent_id.display()
        ));
    }
    for chain in &paths.chains {
        if has_signed_row(chain) {
            out.push(format!("{} holds signed rows", chain.display()));
        }
    }
    out
}

/// Whether the chain at `path` starts with a signed row ([`prior_identity`]).
fn has_signed_row(path: &Path) -> bool {
    let Ok(f) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    else {
        return false;
    };
    if !f.metadata().is_ok_and(|m| m.file_type().is_file()) {
        return false;
    }
    let mut head = Vec::new();
    if f.take(FIRST_ROW_MAX).read_to_end(&mut head).is_err() {
        return false;
    }
    let Some(line) = head.split(|b| *b == b'\n').next() else {
        return false;
    };
    let Ok(row) = serde_json::from_slice::<serde_json::Value>(line) else {
        return false;
    };
    let signed = |k: &str| {
        row.get(k)
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty())
    };
    signed("entry_hash") && signed("agent_sig")
}

/// Why a start whose key is absent must not mint one ([`prior_identity`]'s
/// evidence), for the refusal and the journal; how to re-key on purpose.
pub fn refusal_detail(signing_key: &Path, evidence: &[String]) -> String {
    format!(
        "the agent's signing key {} is absent, but this install had one: {}. The key was removed \
         or is hidden (a mount over its directory, a runtime drop-in): a new key would restart \
         every chain under another identity, so none is minted. Put the key back, or remove what \
         hides it; to re-key on purpose, retire the install's identity \
         (docs/operator/INSTALL_UPGRADE_UNINSTALL.md, \"Re-keying the agent\")",
        signing_key.display(),
        evidence.join("; ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host's `/` on ext4 and, in the agent's namespace, the unit's
    /// `ReadWritePaths=` binds (each directory onto itself), as the lab
    /// guest shows them.
    const SANDBOX: &str = "\
29 1 252:1 / / ro,relatime shared:1 - ext4 /dev/vda1 rw,discard
28 29 0:25 / /run rw,nosuid,nodev shared:5 - tmpfs tmpfs rw,mode=755
701 29 252:1 /etc/northnarrow /etc/northnarrow rw,relatime shared:1 - ext4 /dev/vda1 rw,discard
702 29 252:1 /var/lib/northnarrow /var/lib/northnarrow rw,relatime shared:1 - ext4 /dev/vda1 rw
703 28 0:25 /northnarrow /run/northnarrow rw,nosuid,nodev shared:5 - tmpfs tmpfs rw,mode=755
";

    fn dirs() -> Vec<PathBuf> {
        vec![
            PathBuf::from("/etc/northnarrow"),
            PathBuf::from("/var/lib/northnarrow"),
        ]
    }

    #[test]
    fn the_units_own_binds_are_not_findings() {
        let t = parse_mountinfo(SANDBOX);
        assert_eq!(t.len(), 5);
        assert!(
            mounts_over(&t, &dirs()).is_empty(),
            "{:?}",
            mounts_over(&t, &dirs())
        );
    }

    /// A separate `/var` partition (and the unit's bind of the state
    /// directory on it), a btrfs `/` whose subvolume is `@`, a bind of the
    /// directory onto itself twice: none is a finding.
    #[test]
    fn a_separate_var_and_a_btrfs_subvolume_are_normal_layouts() {
        let var = "\
29 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw
40 29 252:2 / /var rw,relatime shared:20 - ext4 /dev/vda2 rw
702 40 252:2 /lib/northnarrow /var/lib/northnarrow rw,relatime - ext4 /dev/vda2 rw
703 702 252:2 /lib/northnarrow /var/lib/northnarrow rw,relatime - ext4 /dev/vda2 rw
";
        assert!(mounts_over(&parse_mountinfo(var), &dirs()).is_empty());
        let btrfs = "\
29 1 0:31 /@ / rw,relatime shared:1 - btrfs /dev/vda1 rw,subvol=/@
41 29 0:31 /@var /var rw,relatime shared:2 - btrfs /dev/vda1 rw,subvol=/@var
701 29 0:31 /@/etc/northnarrow /etc/northnarrow rw - btrfs /dev/vda1 rw,subvol=/@
702 41 0:31 /@var/lib/northnarrow /var/lib/northnarrow rw - btrfs /dev/vda1 rw,subvol=/@var
";
        assert!(mounts_over(&parse_mountinfo(btrfs), &dirs()).is_empty());
    }

    /// The review's case: an empty directory bound over `/etc/northnarrow`
    /// on the host (and the unit's bind of what is there now on top), a
    /// tmpfs there (`TemporaryFileSystem=`), another directory bound over
    /// the state directory, a file bound over the key, a mount over a
    /// directory inside: each is a finding naming what is mounted.
    #[test]
    fn a_mount_that_hides_the_agents_files_is_a_finding() {
        let host_bind = "\
29 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw
500 29 252:1 /root/empty /etc/northnarrow rw,relatime shared:1 - ext4 /dev/vda1 rw
701 500 252:1 /root/empty /etc/northnarrow rw,relatime shared:1 - ext4 /dev/vda1 rw
";
        let f = mounts_over(&parse_mountinfo(host_bind), &dirs());
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(
            f[0].contains("another directory or file bound there, over the agent's directory /etc/northnarrow"),
            "{}",
            f[0]
        );
        assert!(f[0].contains("its directory /root/empty"), "{}", f[0]);
        assert!(
            f[0].contains("what is there is /etc/northnarrow)"),
            "{}",
            f[0]
        );

        let tmpfs = "\
29 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw
800 29 0:90 / /etc/northnarrow rw,nosuid,nodev - tmpfs tmpfs rw,mode=755
";
        let f = mounts_over(&parse_mountinfo(tmpfs), &dirs());
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(
            f[0].contains("another filesystem mounted there"),
            "{}",
            f[0]
        );
        assert!(f[0].contains("tmpfs tmpfs"), "{}", f[0]);

        let others = "\
29 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw
701 29 252:1 /etc/northnarrow /etc/northnarrow rw - ext4 /dev/vda1 rw
702 29 252:1 /srv/copy /var/lib/northnarrow rw - ext4 /dev/vda1 rw
703 701 252:1 /root/other.key /etc/northnarrow/agent.sig.key rw - ext4 /dev/vda1 rw
704 702 7:0 / /var/lib/northnarrow/detections rw - ext4 /dev/loop0 rw
";
        let f = mounts_over(&parse_mountinfo(others), &dirs());
        assert_eq!(f.len(), 3, "{f:?}");
        assert!(f[0].starts_with("/var/lib/northnarrow (ext4 /dev/vda1, its directory /srv/copy)"));
        assert!(
            f[1].starts_with("/etc/northnarrow/agent.sig.key"),
            "{}",
            f[1]
        );
        assert!(f[2].contains("/dev/loop0"), "{}", f[2]);
    }

    /// A mount whose underlying mount is not in the table cannot be shown
    /// to be a bind of the directory onto itself: a finding. A mount above
    /// the agent's directories (a bind over `/etc`) is not judged here.
    #[test]
    fn an_unknown_parent_is_a_finding_and_an_ancestor_is_not_judged() {
        let t = "\
29 1 252:1 / / rw - ext4 /dev/vda1 rw
701 999 252:1 /etc/northnarrow /etc/northnarrow rw - ext4 /dev/vda1 rw
";
        let f = mounts_over(&parse_mountinfo(t), &dirs());
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(f[0].contains("is not in the table"), "{}", f[0]);
        let t = "\
29 1 252:1 / / rw - ext4 /dev/vda1 rw
600 29 252:1 /srv/fake-etc /etc rw - ext4 /dev/vda1 rw
";
        assert!(mounts_over(&parse_mountinfo(t), &dirs()).is_empty());
    }

    /// `mountinfo` escapes the blanks of a path; the mount point is
    /// matched by components, not as a string prefix.
    #[test]
    fn paths_are_unescaped_and_matched_by_component() {
        let t = "\
29 1 252:1 / / rw - ext4 /dev/vda1 rw
701 29 252:1 /tmp/a\\040b /tmp/st\\040ate rw - ext4 /dev/vda1 rw
702 29 0:91 / /etc/northnarrow-other rw - tmpfs tmpfs rw
";
        let table = parse_mountinfo(t);
        assert_eq!(table[1].mount_point, PathBuf::from("/tmp/st ate"));
        assert_eq!(table[1].root, PathBuf::from("/tmp/a b"));
        let f = mounts_over(&table, &[PathBuf::from("/tmp/st ate")]);
        assert_eq!(f.len(), 1, "{f:?}");
        assert!(mounts_over(&table, &dirs()).is_empty());
    }

    #[test]
    fn directories_are_spelled_as_mountinfo_spells_them() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let canon = std::fs::canonicalize(&real).unwrap();
        let absent = PathBuf::from("/nonexistent-k265/./a/../b");
        let s = spelled(&[&link, &real, Path::new("/"), &absent]);
        assert_eq!(s, vec![canon, PathBuf::from("/nonexistent-k265/b")]);
    }

    fn row(hash: &str, sig: &str) -> String {
        format!("{{\"op\":\"agent_boot\",\"entry_hash\":\"{hash}\",\"agent_sig\":\"{sig}\"}}\n")
    }

    /// The evidence of an earlier identity, one by one: a fresh directory
    /// has none; the public half, the id, a signed row of the audit chain
    /// or of another chain each is; an empty chain (install.sh's
    /// placeholder), a directory, a link or a first line that is not a
    /// signed row is not.
    #[test]
    fn the_evidence_of_an_earlier_identity_one_by_one() {
        let d = tempfile::tempdir().unwrap();
        let paths = IdentityPaths {
            signing_key: d.path().join("agent.sig.key"),
            agent_id: d.path().join("agent_id"),
            chains: vec![
                d.path().join("audit.log"),
                d.path().join("detections.jsonl"),
            ],
        };
        assert!(key_absent(&paths.signing_key));
        assert!(prior_identity(&paths).is_empty());

        std::fs::write(d.path().join("audit.log"), "").unwrap();
        std::fs::write(d.path().join("detections.jsonl"), "{\"not\": \"a row\"}\n").unwrap();
        assert!(
            prior_identity(&paths).is_empty(),
            "{:?}",
            prior_identity(&paths)
        );
        std::fs::write(d.path().join("detections.jsonl"), row("", "c2ln")).unwrap();
        assert!(prior_identity(&paths).is_empty());

        std::fs::remove_file(d.path().join("audit.log")).unwrap();
        std::fs::create_dir(d.path().join("audit.log")).unwrap();
        assert!(prior_identity(&paths).is_empty());
        std::fs::remove_dir(d.path().join("audit.log")).unwrap();
        std::fs::write(d.path().join("elsewhere"), row("ab", "c2ln")).unwrap();
        std::os::unix::fs::symlink(d.path().join("elsewhere"), d.path().join("audit.log")).unwrap();
        assert!(prior_identity(&paths).is_empty(), "a link is not followed");
        std::fs::remove_file(d.path().join("audit.log")).unwrap();

        std::fs::write(
            d.path().join("audit.log"),
            row("ab", "c2ln") + &row("cd", "ZQ=="),
        )
        .unwrap();
        let e = prior_identity(&paths);
        assert_eq!(e.len(), 1, "{e:?}");
        assert!(e[0].ends_with("audit.log holds signed rows"), "{e:?}");
        std::fs::remove_file(d.path().join("audit.log")).unwrap();

        std::fs::write(d.path().join("detections.jsonl"), row("ab", "c2ln")).unwrap();
        let e = prior_identity(&paths);
        assert!(
            e.len() == 1 && e[0].ends_with("detections.jsonl holds signed rows"),
            "{e:?}"
        );
        std::fs::remove_file(d.path().join("detections.jsonl")).unwrap();

        std::fs::write(&paths.agent_id, "00".repeat(16) + "\n").unwrap();
        let e = prior_identity(&paths);
        assert!(e.len() == 1 && e[0].contains("the install's id"), "{e:?}");
        std::fs::remove_file(&paths.agent_id).unwrap();

        std::fs::write(d.path().join("agent.sig.pub"), "").unwrap();
        let e = prior_identity(&paths);
        assert!(e.len() == 1 && e[0].contains("its public half"), "{e:?}");
        assert!(key_absent(&paths.signing_key));

        // a key there in any form is not absent: its load decides
        std::os::unix::fs::symlink("/dev/null", &paths.signing_key).unwrap();
        assert!(!key_absent(&paths.signing_key));
    }

    /// A FIFO where a chain goes is not waited on.
    #[test]
    fn a_fifo_where_a_chain_goes_is_not_waited_on() {
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("audit.log");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(has_signed_row(&fifo));
        });
        let got = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("blocked on a FIFO for 5 s");
        assert!(!got);
    }

    /// The refusal says what was found and how to re-key on purpose.
    #[test]
    fn the_refusal_names_the_evidence_and_the_way_to_re_key() {
        let why = refusal_detail(
            Path::new("/etc/northnarrow/agent.sig.key"),
            &["its public half /etc/northnarrow/agent.sig.pub is there".to_string()],
        );
        assert!(
            why.contains("/etc/northnarrow/agent.sig.key is absent"),
            "{why}"
        );
        assert!(why.contains("agent.sig.pub is there"), "{why}");
        assert!(why.contains("none is minted"), "{why}");
        assert!(why.contains("Re-keying the agent"), "{why}");
    }
}
