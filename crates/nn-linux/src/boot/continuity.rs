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
//! loaded, close that, on two kinds of proof — what the start can read in
//! its own view, and (the review of #468, R2) what the kernel keeps of the
//! previous agent, which no view of the filesystem changes:
//!
//! - [`mounts_over`]: no mount at or under the agent's own directories
//!   but a bind of a directory onto itself (what the unit's
//!   `ReadWritePaths=` makes: the same filesystem, the same directory);
//!   anything else at one of them — another directory bound there, another
//!   filesystem — hides the files the agent had. Mounts above them are not
//!   judged by the table: a separate `/var` (or any ancestor) on its own
//!   filesystem is a normal layout. [`bpffs_findings`]: one bpffs instance
//!   at `/sys/fs/bpf`, nothing over the pin root — the pins are the next
//!   proof.
//! - The previous agent's pins ([`previous_agent`]: they outlive it — a
//!   `cgroup.kill`, a crash —, not a reboot), when they are there: its
//!   `PROTECTED_INODES` holds the inodes it protected. [`view_findings`]:
//!   the agent's directories as this start sees them must be those inodes
//!   (a copy bound over an ancestor, a rename above them, another root show
//!   others). [`restart_findings`]: this start is that agent's restart —
//!   in a release build whatever binary it runs (the re-review's S1,
//!   [`COPIES_EXEMPT`]) — and keeps its identity: its key, id and audit log
//!   in directories that agent protected, and there. A restart never mints.
//! - [`prior_identity`]: what says this install had a signing identity —
//!   the key's public half (`agent.sig.pub`), the install's id
//!   (`agent_id`), a signed row in the audit chain or in one of the other
//!   chains. A key absent with any of it is a key removed or hidden: the
//!   start refuses, and only a start with none of it and no pins (a first
//!   install) mints one — once, from the preflight's decision
//!   (`boot::checks::KeyDecision`, the review of #468 R4; what still opens
//!   the way is in `docs/operator/BOOT_INTEGRITY.md` §1.1).
//!
//! The refusals are the journal's alone: nothing can sign them — the key
//! is the one hidden, and a mount over the agent's directories puts any
//! chain the start could open in the view it refuses.

use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use common::wire::InodeKey;

pub use crate::mountinfo::{MountEntry, MountTable};

/// The agent's own mount table.
pub const OWN_MOUNTINFO: &str = "/proc/self/mountinfo";

/// The bpffs the agent pins into, and the directory of its pins.
pub const BPFFS_MOUNT: &str = "/sys/fs/bpf";

/// The bytes of a chain read to find its first row: a row is a few hundred
/// bytes, an `agent_boot` a few kilobytes.
const FIRST_ROW_MAX: u64 = 64 * 1024;

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
/// directory onto itself ([`crate::mountinfo::is_self_bind`]: the mount it
/// sits on is of the same filesystem and shows, at its mount point, the
/// directory it mounts — what the unit's `ReadWritePaths=` and
/// `RuntimeDirectory=` make in the agent's namespace, on any layout: a
/// separate `/var`, a btrfs subvolume mounted as `/`). Another directory or
/// file bound there (its root another path, the same basename included),
/// another filesystem (a tmpfs, a loop device, an overlay: another
/// `major:minor`, the same path included), a mount whose parent is not in
/// the table: each is one finding, saying what is mounted there. Stacked
/// mounts are each judged against the one below. A line of the table that
/// is not in the kernel's shape is a finding when its mount point is at or
/// under one of `dirs`, or cannot be read (review of #468 R3: a line about
/// anything else never refuses).
pub fn mounts_over(table: &MountTable, dirs: &[PathBuf]) -> Vec<String> {
    let mut out = Vec::new();
    for m in &table.entries {
        let Some(dir) = dirs.iter().find(|d| m.mount_point.starts_with(d)) else {
            continue;
        };
        let what = format!(
            "{} ({} {}, its directory {})",
            m.mount_point.display(),
            m.fstype.to_string_lossy(),
            m.source.to_string_lossy(),
            m.root.display()
        );
        let Some(parent) = table.parent_of(m) else {
            out.push(format!(
                "{what}: a mount over the agent's directory {} whose underlying mount is not in \
                 the table",
                dir.display()
            ));
            continue;
        };
        if crate::mountinfo::is_self_bind(m, parent) {
            continue;
        }
        let Ok(rel) = m.mount_point.strip_prefix(&parent.mount_point) else {
            out.push(format!(
                "{what}: a mount over the agent's directory {} outside the mount it sits on ({})",
                dir.display(),
                parent.mount_point.display()
            ));
            continue;
        };
        out.push(if !m.same_dev(parent) {
            format!(
                "{what}: another filesystem mounted there, over the agent's directory {} (the \
                 one under it is {}, mounted at {})",
                dir.display(),
                parent.dev(),
                parent.mount_point.display()
            )
        } else {
            format!(
                "{what}: another directory or file bound there, over the agent's directory {} \
                 (what is there is {})",
                dir.display(),
                parent.root.join(rel).display()
            )
        });
    }
    for bad in &table.malformed {
        let concerns = match &bad.mount_point {
            Some(mp) => dirs.iter().find(|d| mp.starts_with(d)).cloned(),
            None => Some(PathBuf::from("(any)")),
        };
        if let Some(dir) = concerns {
            out.push(format!(
                "line {} of the mount table is not in the kernel's shape ({}), and it may be a \
                 mount over the agent's directory {}",
                bad.line,
                bad.why,
                dir.display()
            ));
        }
    }
    out
}

/// Lab PR 265 (review of #468 R2): the bpffs the previous agent's pins are
/// in must be the one at [`BPFFS_MOUNT`], alone there and nothing mounted
/// over its pin root (`pin_root`): a second bpffs or a tmpfs stacked on
/// it, a bind of one of its directories over it, or a mount over the pin
/// root, hides the pins — and with them the kernel's proof of what the
/// previous agent protected ([`view_findings`], [`restart_findings`]). The
/// re-review of #468, S3: what counts is the instances, not the mounts — a
/// bind of the same bpffs (its `major:minor`) onto itself, its root `/`
/// (what a node or CNI script may lay there), shows the same pins and is
/// not a finding. A host without a bpffs there has no pins: nothing to
/// judge. A bpffs mounted elsewhere is the self-integrity watcher's finding.
pub fn bpffs_findings(table: &MountTable, pin_root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let at: Vec<&MountEntry> = table
        .entries
        .iter()
        .filter(|m| m.mount_point == Path::new(BPFFS_MOUNT))
        .collect();
    if let Some(first) = at.first() {
        // the bottom one is the instance; every mount stacked on it must be
        // that instance again, whole
        let one_instance = at
            .iter()
            .all(|m| m.same_dev(first) && m.root == Path::new("/") && m.fstype == first.fstype);
        if at.len() > 1 && !one_instance {
            out.push(format!(
                "{} mounts stacked on {BPFFS_MOUNT}, not one instance bound onto itself ({}): \
                 one hides the previous agent's pins",
                at.len(),
                at.iter()
                    .map(|m| format!(
                        "{} {} {}",
                        m.fstype.to_string_lossy(),
                        m.dev(),
                        m.root.display()
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        } else if first.fstype != "bpf" {
            out.push(format!(
                "{BPFFS_MOUNT} is a {} mount, not a bpffs",
                first.fstype.to_string_lossy()
            ));
        }
    }
    for m in table
        .entries
        .iter()
        .filter(|m| m.mount_point.starts_with(pin_root))
    {
        out.push(format!(
            "{} ({} {}): a mount over the pin root {}",
            m.mount_point.display(),
            m.fstype.to_string_lossy(),
            m.source.to_string_lossy(),
            pin_root.display()
        ));
    }
    for bad in &table.malformed {
        if bad
            .mount_point
            .as_deref()
            .is_none_or(|mp| mp == Path::new(BPFFS_MOUNT) || mp.starts_with(pin_root))
        {
            out.push(format!(
                "line {} of the mount table is not in the kernel's shape ({}), and it may be a \
                 mount over {BPFFS_MOUNT}",
                bad.line, bad.why
            ));
        }
    }
    out
}

/// The key `PROTECTED_INODES` holds for the inode at `path`, read as the
/// previous agent read it when it registered the inode (the name itself,
/// `lstat`; the kernel's encoding of the device).
pub fn inode_key(path: &Path) -> std::io::Result<InodeKey> {
    let meta = std::fs::symlink_metadata(path)?;
    Ok(InodeKey {
        dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(meta.dev()),
        ino: meta.ino(),
    })
}

/// The previous agent's kernel state (lab PR 265, review of #468 R2): its
/// pins outlive it — a `cgroup.kill`, a crash —, and `PROTECTED_INODES`
/// holds the inodes it protected, so they are a proof of what the start
/// before this one saw that no view of the filesystem can change.
pub enum PreviousAgent {
    /// No pins under the bpffs root: no agent has run since the bpffs was
    /// mounted (a boot), or they were removed on purpose (an upgrade, an
    /// uninstall, a re-key: each removes them before it touches a file).
    None,
    /// Its pins, and the inodes it protected (`contains`).
    Pinned(Box<dyn Fn(InodeKey) -> bool>),
    /// Pinned, but its inode map cannot be read: why.
    Unreadable(String),
}

/// [`PreviousAgent`] from the pins under `bpffs_root`: `PROTECTED_PIDS` or
/// `PROTECTED_INODES` there (looked at without following a link: what is
/// at the name, as `preregister_self` asks), then the inode map opened.
pub fn previous_agent(bpffs_root: &Path) -> PreviousAgent {
    let pinned = |name: &str| {
        !matches!(std::fs::symlink_metadata(bpffs_root.join(name)),
                  Err(e) if e.kind() == std::io::ErrorKind::NotFound)
    };
    if !pinned(crate::anti_tamper::PROTECTED_PIDS_MAP_NAME) && !pinned("PROTECTED_INODES") {
        return PreviousAgent::None;
    }
    match crate::anti_tamper::filesystem::ProtectedInodesHandle::open(bpffs_root) {
        Ok(h) => PreviousAgent::Pinned(Box::new(move |k| h.contains(k))),
        Err(e) => PreviousAgent::Unreadable(format!("{e:#}")),
    }
}

/// The `contains` of `previous`, or the finding that says why there is
/// none to ask (no pins: `Ok(None)`).
fn pinned_inodes(previous: &PreviousAgent) -> Result<Option<&dyn Fn(InodeKey) -> bool>, String> {
    match previous {
        PreviousAgent::None => Ok(None),
        PreviousAgent::Unreadable(why) => Err(format!(
            "the previous agent's pins are there but its PROTECTED_INODES cannot be read \
             ({why}): what it protected cannot be compared"
        )),
        PreviousAgent::Pinned(c) => Ok(Some(c.as_ref())),
    }
}

/// Lab PR 265 (review of #468 R2, fix a), the view: each of `dirs` (the
/// agent's own directories, the configuration and the state directory, as
/// this start sees them) that exists must be the inode the previous agent
/// protected. A copy bound over an ancestor (`/etc`, `/var/lib`), a
/// directory swapped by a rename above it, another root
/// (`RootDirectory=`) each show another inode. Every agent registers the
/// host's directories (their paths are fixed), so the privileged tests'
/// agents, which keep their own files elsewhere, see the same ones. No
/// pins: nothing to compare (a boot, or the pins removed on purpose);
/// pins whose inode map cannot be read: a finding.
pub fn view_findings(previous: &PreviousAgent, dirs: &[PathBuf]) -> Vec<String> {
    let contains = match pinned_inodes(previous) {
        Ok(Some(c)) => c,
        Ok(None) => return Vec::new(),
        Err(why) => return vec![why],
    };
    let mut out = Vec::new();
    for d in dirs {
        match inode_key(d) {
            Ok(k) if contains(k) => {}
            Ok(k) => out.push(format!(
                "{} (dev {}, inode {}) is not the directory the previous agent protected: the \
                 view changed since it ran (a mount or a rename above it, another root)",
                d.display(),
                k.dev,
                k.ino
            )),
            // absent now: nothing to compare (the restart's own check holds
            // the installed agent's key)
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => out.push(format!(
                "{}: {e} — whether it is the directory the previous agent protected cannot be \
                 shown",
                d.display()
            )),
        }
    }
    out
}

/// The re-review of #468, S1: a start of another binary than the one the
/// previous agent protected (a copy) is judged by the evidence alone, not as
/// that agent's restart — in the lab builds only: the privileged tests
/// (`test-privileged`) run copies of the binary, with files of their own,
/// beside the installed agent, and a `debug-trigger` build's BPF guard
/// observes. A release build has no exemption: with the pins there every
/// start is a restart, whatever it runs — a copy started by a drop-in
/// (`ExecStart=` naming a copy, or `ld.so` and the binary) with the key's
/// path elsewhere is refused by [`restart_findings`], not only by the BPF
/// guard denying it a handle on the inode map (which holds while the guard
/// enforces, and not with `NN_BPF_DEFENSE_OBSERVE=1`).
pub const COPIES_EXEMPT: bool = cfg!(any(feature = "test-privileged", feature = "debug-trigger"));

/// Lab PR 265 (review of #468 R2, fix a; its re-review, S1 and S2), the
/// restart: with the previous agent's pins there, this start is that
/// agent's restart — whatever binary it runs (`exe`, followed), unless
/// `copies_exempt` ([`COPIES_EXEMPT`], the lab builds) and it is not the one
/// that agent protected — and a restart keeps its identity. Its signing key,
/// its id and its audit log (the first of `paths.chains`) must each be in a
/// directory that agent protected (a drop-in redefining `ExecStart=` with
/// them in an empty directory is refused) and be there: a restart never
/// mints a key or an id, nor starts a new audit chain (an upgrade, an
/// uninstall and a re-key remove the pins first). No pins: nothing to
/// compare; pins whose inode map cannot be read: a finding.
pub fn restart_findings(
    previous: &PreviousAgent,
    exe: &Path,
    paths: &IdentityPaths,
    copies_exempt: bool,
) -> Vec<String> {
    let contains = match pinned_inodes(previous) {
        Ok(Some(c)) => c,
        Ok(None) => return Vec::new(),
        Err(why) => return vec![why],
    };
    let protected = std::fs::metadata(exe)
        .map(|m| InodeKey {
            dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
            ino: m.ino(),
        })
        .is_ok_and(contains);
    if copies_exempt && !protected {
        return Vec::new();
    }
    // the binary by its path (`/proc/self/exe` is a link to it)
    let shown = std::fs::read_link(exe).unwrap_or_else(|_| exe.to_path_buf());
    let restart = if protected {
        format!(
            "this start runs the binary the previous agent protected ({}), a restart of it",
            shown.display()
        )
    } else {
        format!(
            "the previous agent's pins are there, so this start is its restart, whatever it runs \
             ({}, not the binary that agent protected)",
            shown.display()
        )
    };
    let mut files = vec![
        (
            "signing key",
            &paths.signing_key,
            "a restart never mints a key",
        ),
        ("id", &paths.agent_id, "a restart never mints an id"),
    ];
    if let Some(audit) = paths.chains.first() {
        files.push((
            "audit log",
            audit,
            "a restart never starts a new audit chain",
        ));
    }
    let mut out = Vec::new();
    for (what, path, never) in files {
        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        if !inode_key(dir).is_ok_and(contains) {
            out.push(format!(
                "{restart}, but its {what} {} is not in a directory that agent protected: a \
                 restart keeps its identity",
                path.display()
            ));
        }
        if key_absent(path) {
            out.push(format!(
                "{restart}, and its {what} {} is absent: {never} (an upgrade, an uninstall and a \
                 re-key remove the pins before the {what} goes)",
                path.display()
            ));
        }
    }
    out
}

/// The paths whose presence says the install had a signing identity
/// before this start: the key's public half beside `signing_key`, the
/// install's id, the head anchor, and the chains whose signed rows count.
#[derive(Debug, Clone)]
pub struct IdentityPaths {
    pub signing_key: PathBuf,
    pub agent_id: PathBuf,
    /// The head anchor (`chain_heads.json`): install.sh creates it empty,
    /// the agent writes it.
    pub heads: PathBuf,
    /// The audit log and the other chains (their active files; their
    /// manifests and sealed archives are looked at too).
    pub chains: Vec<PathBuf>,
}

/// Is the key at `path` absent — its name holds nothing? Read without
/// following a link and without opening it (a key the previous agent's
/// hooks close to this process is there); an error other than "not found"
/// counts as there: the key's load decides on it.
pub fn key_absent(path: &Path) -> bool {
    matches!(std::fs::symlink_metadata(path), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// What is at `path`, looked at without following a link: `None` when the
/// name holds nothing; any other answer — a file, a link, an error that is
/// not "not found" — is something (review of #468 R8: a lookup that fails
/// counts against minting).
fn something_at(path: &Path) -> Option<String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Some("is there".to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => Some(format!("cannot be looked at ({e}): counted as there")),
    }
}

/// What says this install had a signing identity before this start, each
/// as a line for the journal (empty: none, a first install): the key's
/// public half (`agent.sig.pub`) and the install's id — anything at their
/// names, or a lookup that fails otherwise than "not found" —; the head
/// anchor when it is not an empty file (install.sh creates it empty); a
/// chain, one of its manifests or sealed archives whose first line is a
/// signed row (a JSON object with a non-empty `entry_hash` and
/// `agent_sig`: what every row of the audit chain and of the other chains
/// carries), or that cannot be opened otherwise than "not found". A chain
/// is read as the chains are — no link followed (a link counts), no FIFO
/// waited on, at most its first 64 KiB —; an empty one, a directory or
/// another non-file at its name, or a first line that is not a signed row
/// is no evidence: the chain's own check judges it.
pub fn prior_identity(paths: &IdentityPaths) -> Vec<String> {
    let mut out = Vec::new();
    let public = crate::keys::verifying_key_path(&paths.signing_key);
    if let Some(what) = something_at(&public) {
        out.push(format!("its public half {} {what}", public.display()));
    }
    if let Some(what) = something_at(&paths.agent_id) {
        out.push(format!(
            "the install's id {} {what}",
            paths.agent_id.display()
        ));
    }
    match std::fs::symlink_metadata(&paths.heads) {
        Ok(m) if m.file_type().is_file() && m.len() == 0 => {}
        Ok(_) => out.push(format!(
            "the head anchor {} is not an empty file",
            paths.heads.display()
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => out.push(format!(
            "the head anchor {} cannot be looked at ({e}): counted as there",
            paths.heads.display()
        )),
    }
    for chain in &paths.chains {
        let mut files = vec![chain.clone(), crate::chainlog::manifest_path(chain)];
        files.extend(crate::chainlog::archives_newest_first(chain));
        for f in files {
            if let Some(what) = chain_evidence(&f) {
                out.push(format!("{} {what}", f.display()));
            }
        }
    }
    out
}

/// What the chain file at `path` says of an earlier identity
/// ([`prior_identity`]): `None` for nothing.
fn chain_evidence(path: &Path) -> Option<String> {
    let f = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        Err(e) => return Some(format!("cannot be opened ({e}): counted as rows")),
    };
    match f.metadata() {
        Ok(m) if m.file_type().is_file() => {}
        Ok(_) => return None,
        Err(e) => return Some(format!("cannot be looked at ({e}): counted as rows")),
    }
    let mut head = Vec::new();
    if let Err(e) = f.take(FIRST_ROW_MAX).read_to_end(&mut head) {
        return Some(format!("cannot be read ({e}): counted as rows"));
    }
    let line = head.split(|b| *b == b'\n').next()?;
    let row = serde_json::from_slice::<serde_json::Value>(line).ok()?;
    let signed = |k: &str| {
        row.get(k)
            .and_then(|v| v.as_str())
            .is_some_and(|s| !s.is_empty())
    };
    (signed("entry_hash") && signed("agent_sig")).then(|| "holds signed rows".to_string())
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

    fn parse_mountinfo(text: &str) -> MountTable {
        crate::mountinfo::parse(text.as_bytes())
    }

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
        assert_eq!(t.entries.len(), 5);
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

    /// Review of #468 (M2, M2d): another directory with the agent's
    /// directory's basename (`/srv/copy/northnarrow`), and the same path on
    /// another filesystem (a loop image holding `/etc/northnarrow`), are
    /// findings; so are the review's NBSP variants — a directory named
    /// `fake<U+00A0>` bound over the directory, and one named
    /// `/etc/northnarrow<U+00A0>/etc/northnarrow` that a split on Unicode
    /// spaces read as a self-bind.
    #[test]
    fn the_same_basename_the_same_path_elsewhere_and_nbsp_are_findings() {
        let base = "29 1 252:1 / / rw - ext4 /dev/vda1 rw\n";
        for (extra, want) in [
            (
                "701 29 252:1 /srv/copy/northnarrow /etc/northnarrow rw - ext4 /dev/vda1 rw\n",
                "another directory or file",
            ),
            (
                "701 29 7:0 /etc/northnarrow /etc/northnarrow rw - ext4 /dev/loop0 rw\n",
                "another filesystem",
            ),
        ] {
            let f = mounts_over(&parse_mountinfo(&format!("{base}{extra}")), &dirs());
            assert!(f.len() == 1 && f[0].contains(want), "{extra}: {f:?}");
        }
        let mut nbsp = base.as_bytes().to_vec();
        nbsp.extend_from_slice(
            b"701 29 252:1 /tmp/fake\xc2\xa0/x /etc/northnarrow rw - ext4 /dev/vda1 rw\n",
        );
        nbsp.extend_from_slice(
            b"702 701 252:1 /tmp/fake\xc2\xa0/x /etc/northnarrow rw - ext4 /dev/vda1 rw\n",
        );
        let f = mounts_over(&crate::mountinfo::parse(&nbsp), &dirs());
        assert!(
            f.len() == 1 && f[0].contains("another directory or file"),
            "{f:?}"
        );
        let mut lookalike = base.as_bytes().to_vec();
        lookalike.extend_from_slice(
            b"701 29 252:1 /etc/northnarrow\xc2\xa0/etc/northnarrow /etc/northnarrow rw - ext4 /dev/vda1 rw\n",
        );
        let f = mounts_over(&crate::mountinfo::parse(&lookalike), &dirs());
        assert!(
            f.len() == 1 && f[0].contains("another directory or file"),
            "{f:?}"
        );
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

    /// The re-review of #468: a line not in the kernel's shape whose mount
    /// point cannot be read may be a mount over any directory: a finding of
    /// `mounts_over` itself (`(any)`), not only of the bpffs rule.
    #[test]
    fn a_malformed_line_without_a_mount_point_is_a_finding() {
        let t = parse_mountinfo("29 1 252:1 / / rw - ext4 /dev/vda1 rw\n900 29\n");
        assert_eq!(t.malformed.len(), 1);
        assert_eq!(t.malformed[0].mount_point, None);
        let f = mounts_over(&t, &dirs());
        assert!(
            f.len() == 1 && f[0].contains("over the agent's directory (any)"),
            "{f:?}"
        );
        assert!(bpffs_findings(&t, Path::new("/sys/fs/bpf/northnarrow")).len() == 1);
        // with a readable mount point elsewhere: none
        let t = parse_mountinfo(
            "29 1 252:1 / / rw - ext4 /dev/vda1 rw\n900 29 252:1 / /srv rw - ext4\n",
        );
        assert_eq!(t.malformed.len(), 1);
        assert!(mounts_over(&t, &dirs()).is_empty());
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
        assert_eq!(table.entries[1].mount_point, PathBuf::from("/tmp/st ate"));
        assert_eq!(table.entries[1].root, PathBuf::from("/tmp/a b"));
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
            heads: d.path().join("chain_heads.json"),
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
        // review of #468 R8: a link is not followed, and it counts (a lookup
        // that is not "not found" is something)
        std::fs::write(d.path().join("elsewhere"), "").unwrap();
        std::os::unix::fs::symlink(d.path().join("elsewhere"), d.path().join("audit.log")).unwrap();
        let e = prior_identity(&paths);
        assert!(
            e.len() == 1 && e[0].contains("audit.log cannot be opened"),
            "{e:?}"
        );
        std::fs::remove_file(d.path().join("audit.log")).unwrap();
        // the head anchor: empty (install.sh's) is none, written is
        std::fs::write(&paths.heads, "").unwrap();
        assert!(prior_identity(&paths).is_empty());
        std::fs::write(&paths.heads, "{\"slots\":[]}").unwrap();
        let e = prior_identity(&paths);
        assert!(e.len() == 1 && e[0].contains("head anchor"), "{e:?}");
        std::fs::remove_file(&paths.heads).unwrap();
        // a sealed archive and a manifest of a chain count like its active file
        let archive = crate::chainlog::archive_path_for(&d.path().join("detections.jsonl"), 1);
        std::fs::write(&archive, row("ab", "c2ln")).unwrap();
        let e = prior_identity(&paths);
        assert!(
            e.len() == 1 && e[0].contains(".000001 holds signed rows"),
            "{e:?}"
        );
        std::fs::remove_file(&archive).unwrap();
        let manifest = crate::chainlog::manifest_path(&d.path().join("audit.log"));
        std::fs::write(&manifest, row("ab", "c2ln")).unwrap();
        let e = prior_identity(&paths);
        assert!(
            e.len() == 1 && e[0].contains("manifest.jsonl holds signed rows"),
            "{e:?}"
        );
        std::fs::remove_file(&manifest).unwrap();

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
        std::fs::remove_file(d.path().join("agent.sig.pub")).unwrap();
        // a lookup that fails otherwise than "not found" counts (ENOTDIR:
        // the id's directory is a file)
        let odd = IdentityPaths {
            agent_id: d.path().join("elsewhere").join("agent_id"),
            ..paths.clone()
        };
        let e = prior_identity(&odd);
        assert!(
            e.len() == 1 && e[0].contains("cannot be looked at"),
            "{e:?}"
        );

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
            let _ = tx.send(chain_evidence(&fifo));
        });
        let got = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("blocked on a FIFO for 5 s");
        assert_eq!(got, None);
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
