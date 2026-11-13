//! Lot 285: the files the kernel's module-load judge trusts — the running
//! kernel's tree walked from its directory, each module file classified.
//!
//! A file is trusted ([`classify`]) when it is a regular file owned by root
//! that neither its group nor others may write, and:
//!
//! - unchanged since boot (its change time before the boot's) and a
//!   verified package's — listed by the package database with the digest
//!   the database recorded, read from the file (dpkg's `md5sums`, rpm's
//!   file digests) — or DKMS's build (in a DKMS or akmods output
//!   directory, the same content as DKMS's own copy of a module it
//!   registered for this kernel, [`dkms_registered`]);
//! - or changed since boot, and written inside a package transaction: the
//!   kernel's write history of the inode says a package manager's lineage
//!   created it and nothing else opened it for writing since
//!   (`common::module_judge::write_step`); a package's or DKMS's file as
//!   above;
//! - or named by a signed per-module opt-out (`module-allow <module>`).
//!
//! The coordinator's matrix (lot 285) adds one kind, let through but
//! recorded, never trusted ([`trust_flag::UNATTESTED`]): a file of a DKMS or
//! akmods output directory that a package or DKMS's registry vouches for as
//! above, but changed since boot outside a recognised package transaction
//! (built by hand, or before the agent started: `akmods` at boot) — in the
//! map unless the policy enforces R018 ([`Inputs::unattested`]). Anywhere
//! else in the tree such a file is refused, and a file of those directories
//! nothing vouches for is refused.
//!
//! What vouches for a file is cached by `(dev, ino, ctime, size)`: a file
//! hashed once is not hashed again until it changes.

use std::collections::{BTreeSet, HashMap};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use common::module_judge::{
    module_file_name, module_name_of, safe_owner, trust_flag, written_by_package, FileFacts,
    NAME_TAIL,
};
use common::wire::InodeKey;

/// The directories a walk descends at most below the tree.
const MAX_DEPTH: usize = 16;

/// A module file of the tree, as `lstat` read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeFile {
    pub path: PathBuf,
    /// `InodeKey` with the kernel's device encoding (the eBPF side's).
    pub key: InodeKey,
    pub facts: FileFacts,
}

/// The `InodeKey` of `m`, the kernel's encoding of its device.
pub fn key_of(m: &std::fs::Metadata) -> InodeKey {
    InodeKey {
        dev: crate::anti_tamper::filesystem::stat_dev_to_kernel_dev(m.dev()),
        ino: m.ino(),
    }
}

/// What the judge reads of a file, from its metadata.
pub fn facts_of(m: &std::fs::Metadata) -> FileFacts {
    FileFacts {
        uid: m.uid(),
        mode: m.mode(),
        ctime_sec: m.ctime(),
        ctime_nsec: m.ctime_nsec() as u32,
        size: m.size() as i64,
    }
}

/// `name` is a module file's, by the judge's own rule (the kernel reads a
/// name's last bytes; so does this).
pub fn is_module_file(name: &str) -> bool {
    let b = name.as_bytes();
    let tail = &b[b.len().saturating_sub(NAME_TAIL - 1)..];
    let mut t = [0u8; NAME_TAIL];
    t[..tail.len()].copy_from_slice(tail);
    module_file_name(&t)
}

/// Every module file under `tree` (symbolic links not followed: a link's
/// target is not the tree's), at most `max` of them; the count of files
/// left out past it.
pub fn walk(tree: &Path, max: usize) -> (Vec<TreeFile>, usize) {
    let mut out = Vec::new();
    let mut over = 0usize;
    let mut stack = vec![(tree.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            let Ok(m) = std::fs::symlink_metadata(e.path()) else {
                continue;
            };
            if m.is_dir() {
                if depth < MAX_DEPTH {
                    stack.push((e.path(), depth + 1));
                }
                continue;
            }
            if !m.is_file() || !e.file_name().to_str().is_some_and(is_module_file) {
                continue;
            }
            if out.len() >= max {
                over += 1;
                continue;
            }
            out.push(TreeFile {
                path: e.path(),
                key: key_of(&m),
                facts: facts_of(&m),
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    (out, over)
}

/// What [`classify`] reads besides the file.
pub struct Inputs<'a> {
    /// The running kernel's release (`uname -r`).
    pub release: &'a str,
    /// The tree's directory as walked.
    pub tree: &'a Path,
    /// The boot's time (`/proc/stat` `btime`, seconds since the epoch).
    pub boot_sec: i64,
    /// DKMS's registry (`/var/lib/dkms`).
    pub dkms_registry: &'a Path,
    /// The signed per-module opt-outs (module names, `_` for `-`).
    pub opt_outs: &'a BTreeSet<String>,
    /// A DKMS or akmods build written since boot outside a recognised
    /// package transaction is let through and recorded
    /// ([`trust_flag::UNATTESTED`]): every policy but `enforce R018`.
    pub unattested: bool,
    /// From when the kernel's write history covers every write (wall
    /// clock: seconds, nanoseconds; `nn_linux::module_writes`): a file
    /// changed since boot before it has no history to read — a package's or
    /// DKMS's file is then let through and recorded like an unattested
    /// build, never refused in silence. `(i64::MAX, 0)`: the history is not
    /// reliable this boot.
    pub history_since: (i64, u32),
}

/// Why a file is not trusted.
pub const NOT_SAFE: &str =
    "not a regular file owned by root that neither its group nor others may write";
pub const CHANGED_SINCE_BOOT: &str = "changed since boot outside a package transaction (the \
                                      kernel's write history of the file does not show one)";
pub const UNVOUCHED: &str = "no verified package or DKMS build vouches for it";
pub const UNATTESTED_ENFORCED: &str = "a DKMS or akmods build its registry vouches for, or a \
                                       package's file changed before the write history covers, \
                                       written since boot outside a recognised package \
                                       transaction: refused while the policy enforces R018";

/// What vouches for the content of `f`: [`trust_flag::PACKAGE`] (a
/// verified package's file: `packaged` reads it and compares the database's
/// digest), else [`trust_flag::DKMS`] (in a DKMS or akmods output directory,
/// the same content as DKMS's copy of a module it registered for this
/// kernel), else 0. The controller caches it by the file's identity and
/// change stamp.
pub fn vouched_by(
    f: &TreeFile,
    inputs: &Inputs<'_>,
    packaged: impl FnOnce(&TreeFile) -> bool,
) -> u32 {
    if packaged(f) {
        return trust_flag::PACKAGE;
    }
    let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let registered = in_dkms_dir(inputs.tree, &f.path)
        && module_name_of(name)
            .is_some_and(|m| dkms_registered(inputs.dkms_registry, inputs.release, &m, &f.path));
    if registered {
        trust_flag::DKMS
    } else {
        0
    }
}

/// The trust flags of `f` (`common::module_judge::trust_flag`), or why it
/// is not trusted. `history` is the kernel's write history of the inode;
/// `vouch` answers what vouches for its content ([`vouched_by`]: a verified
/// package, DKMS's registry, nothing) — asked only of a file whose answer
/// can change the verdict.
pub fn classify(
    f: &TreeFile,
    inputs: &Inputs<'_>,
    history: Option<u32>,
    vouch: &mut dyn FnMut(&TreeFile) -> u32,
) -> Result<u32, &'static str> {
    if !safe_owner(&f.facts) {
        return Err(NOT_SAFE);
    }
    let name = f.path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let module = module_name_of(name);
    let since_boot = f.facts.ctime_sec >= inputs.boot_sec;
    // the history covers the file's last change
    let covered = (f.facts.ctime_sec, f.facts.ctime_nsec) >= inputs.history_since;
    let pkg_written = covered && written_by_package(history);
    let attested = !since_boot || pkg_written;
    let dkms_dir = in_dkms_dir(inputs.tree, &f.path);
    let unknown = since_boot && !covered;
    let by = if attested || dkms_dir || unknown {
        vouch(f)
    } else {
        0
    };
    let mut flags = 0u32;
    if attested && by != 0 {
        flags = by;
        if since_boot {
            flags |= trust_flag::PKG_WRITTEN;
        }
    }
    // the coordinator's matrix: a registered build of a DKMS or akmods
    // output directory written outside a recognised transaction, and a
    // vouched file changed before the history covers (outside a
    // transaction, `vouch` is asked only for those)
    let late = !attested && by != 0;
    if flags == 0 && module.is_some_and(|m| inputs.opt_outs.contains(&m)) {
        flags = trust_flag::OPT_OUT;
    } else if flags == 0 && late && inputs.unattested {
        flags = trust_flag::UNATTESTED;
    }
    if flags != 0 {
        Ok(flags)
    } else if late {
        Err(UNATTESTED_ENFORCED)
    } else if !attested {
        Err(CHANGED_SINCE_BOOT)
    } else {
        Err(UNVOUCHED)
    }
}

/// `path` is in DKMS's install directory of the tree: `updates/dkms/`
/// (Debian, Ubuntu) or `extra/` (the RPM family's DKMS and kmod packages).
pub fn in_dkms_dir(tree: &Path, path: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(tree) else {
        return false;
    };
    rel.starts_with("updates/dkms") || rel.starts_with("extra")
}

/// Lot 313 (BUG-87): one test of DKMS's build, R018's and this judge's —
/// the content DKMS's registry holds, never a name.
pub use nn_core::decision::rules::module_provenance::{dkms_registered, same_content};

/// The boot's time from `/proc/stat` (`btime`).
pub fn boot_time(proc_stat: &str) -> Option<i64> {
    proc_stat
        .lines()
        .find_map(|l| l.strip_prefix("btime "))
        .and_then(|v| v.trim().parse().ok())
}

/// What vouches for a file ([`vouched_by`]), cached by the file's identity
/// and change stamp.
#[derive(Default)]
pub struct PackagedCache {
    seen: HashMap<(InodeKey, i64, u32, i64), u32>,
}

impl PackagedCache {
    /// `ask` once per `(dev, ino, ctime, size)`.
    pub fn get(&mut self, f: &TreeFile, ask: impl FnOnce(&TreeFile) -> u32) -> u32 {
        let k = (f.key, f.facts.ctime_sec, f.facts.ctime_nsec, f.facts.size);
        if let Some(v) = self.seen.get(&k) {
            return *v;
        }
        let v = ask(f);
        if self.seen.len() >= 65_536 {
            self.seen.clear();
        }
        self.seen.insert(k, v);
        v
    }

    /// Forget the files no longer in the tree.
    pub fn retain(&mut self, keep: &std::collections::HashSet<InodeKey>) {
        self.seen.retain(|k, _| keep.contains(&k.0));
    }
}

/// rpm's file digests of the module files of `tree` (one `rpm -qa` for the
/// whole tree, not one process per file): path → (algorithm id, hex).
/// `None` when rpm cannot be asked.
pub fn rpm_tree_digests(tree_prefixes: &[String]) -> Option<HashMap<String, (u32, String)>> {
    let rpm = crate::trusted_bin::resolve("rpm").ok()?;
    let out = rpm
        .command()
        .args([
            "-qa",
            "--qf",
            "[%{FILENAMES}\\t%{FILEDIGESTALGO}\\t%{FILEDIGESTS}\\n]",
        ])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(parse_rpm_dump(
        &String::from_utf8_lossy(&out.stdout),
        tree_prefixes,
    ))
}

/// The lines of an `rpm -qa --qf '[%{FILENAMES}\t%{FILEDIGESTALGO}\t%{FILEDIGESTS}\n]'`
/// dump under one of `prefixes`, with a digest (algorithm 1 MD5, 8 SHA-256).
pub fn parse_rpm_dump(text: &str, prefixes: &[String]) -> HashMap<String, (u32, String)> {
    let mut out = HashMap::new();
    for l in text.lines() {
        let mut f = l.split('\t');
        let (Some(name), Some(algo), Some(sum)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if sum.is_empty() || !prefixes.iter().any(|p| name.starts_with(p.as_str())) {
            continue;
        }
        let Ok(algo) = algo.trim().parse::<u32>() else {
            continue;
        };
        if algo != 1 && algo != 8 {
            continue;
        }
        out.insert(name.to_string(), (algo, sum.trim().to_ascii_lowercase()));
    }
    out
}

/// The content of `file` hashed as rpm recorded it, compared.
pub fn rpm_digest_matches(file: &Path, algo: u32, want: &str) -> bool {
    use sha2::Digest;
    let Ok(bytes) = std::fs::read(file) else {
        return false;
    };
    let got = match algo {
        1 => hex::encode(md5::Md5::digest(&bytes)),
        8 => hex::encode(sha2::Sha256::digest(&bytes)),
        _ => return false,
    };
    got == want
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::module_judge::{
        finit_verdict, mode, trust_flag, verdict, write_flag, write_step, ModuleTrust,
    };
    use std::os::unix::fs::PermissionsExt;

    const REL: &str = "6.8.0-nn";

    struct Fixture {
        _tmp: tempfile::TempDir,
        root: PathBuf,
        tree: PathBuf,
        registry: PathBuf,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let tree = root.join("lib/modules").join(REL);
        std::fs::create_dir_all(tree.join("kernel/net")).unwrap();
        std::fs::create_dir_all(tree.join("updates/dkms")).unwrap();
        let registry = root.join("var/lib/dkms");
        std::fs::create_dir_all(&registry).unwrap();
        Fixture {
            _tmp: tmp,
            root,
            tree,
            registry,
        }
    }

    fn put(p: &Path, content: &[u8]) {
        std::fs::write(p, content).unwrap();
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// The test runs as some uid; the judge wants root's files. The
    /// metadata as root would have it (uid 0), the rest read.
    fn as_root(mut f: TreeFile) -> TreeFile {
        f.facts.uid = 0;
        f
    }

    fn file(p: &Path) -> TreeFile {
        let m = std::fs::symlink_metadata(p).unwrap();
        as_root(TreeFile {
            path: p.to_path_buf(),
            key: key_of(&m),
            facts: facts_of(&m),
        })
    }

    fn inputs<'a>(fx: &'a Fixture, boot_sec: i64, opt: &'a BTreeSet<String>) -> Inputs<'a> {
        Inputs {
            release: REL,
            tree: &fx.tree,
            boot_sec,
            dkms_registry: &fx.registry,
            opt_outs: opt,
            unattested: true,
            history_since: (0, 0),
        }
    }

    /// What vouches for a file as the agent asks it: no package, DKMS's
    /// registry read.
    fn registry<'a>(inputs: &'a Inputs<'a>) -> impl FnMut(&TreeFile) -> u32 + 'a {
        move |f| vouched_by(f, inputs, |_| false)
    }

    /// The file's change time is now: a boot an hour later makes it older
    /// than the boot, one an hour earlier newer.
    fn after_files() -> i64 {
        now() + 3600
    }
    fn before_files() -> i64 {
        now() - 3600
    }
    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// The entry the agent writes for `f` with `flags`.
    fn entry(f: &TreeFile, flags: u32) -> ModuleTrust {
        ModuleTrust {
            ctime_sec: f.facts.ctime_sec,
            size: f.facts.size,
            ctime_nsec: f.facts.ctime_nsec,
            flags,
        }
    }

    /// The trust map the scan of `files` writes, as the kernel looks it up.
    fn trust_map(
        files: &[TreeFile],
        inputs: &Inputs<'_>,
        writes: &HashMap<InodeKey, u32>,
        vouch: &mut dyn FnMut(&TreeFile) -> u32,
    ) -> HashMap<InodeKey, ModuleTrust> {
        files
            .iter()
            .filter_map(|f| {
                classify(f, inputs, writes.get(&f.key).copied(), vouch)
                    .ok()
                    .map(|fl| (f.key, entry(f, fl)))
            })
            .collect()
    }

    #[test]
    fn the_walk_finds_module_files_only() {
        let fx = fixture();
        put(&fx.tree.join("kernel/net/tls.ko.zst"), b"tls");
        put(&fx.tree.join("modules.dep"), b"dep");
        put(&fx.tree.join("updates/dkms/vboxdrv.ko"), b"vbox");
        std::os::unix::fs::symlink(fx.root.join("elsewhere.ko"), fx.tree.join("kernel/link.ko"))
            .unwrap();
        let (files, over) = walk(&fx.tree, 100);
        let names: Vec<_> = files
            .iter()
            .map(|f| f.path.strip_prefix(&fx.tree).unwrap().display().to_string())
            .collect();
        assert_eq!(names, ["kernel/net/tls.ko.zst", "updates/dkms/vboxdrv.ko"]);
        assert_eq!(over, 0);
        let (files, over) = walk(&fx.tree, 1);
        assert_eq!((files.len(), over), (1, 1));
    }

    /// Named test (lot 285): a copy of a trusted module in /tmp is another
    /// inode — not in the map the tree's walk fills — and the kernel's
    /// judge refuses it; the original loads.
    #[test]
    fn a_copy_of_a_trusted_module_in_tmp_is_denied() {
        let fx = fixture();
        let orig = fx.tree.join("kernel/net/tls.ko.zst");
        put(&orig, b"tls module");
        let (files, _) = walk(&fx.tree, 100);
        let files: Vec<_> = files.into_iter().map(as_root).collect();
        let opt = BTreeSet::new();
        let map = trust_map(
            &files,
            &inputs(&fx, after_files(), &opt),
            &HashMap::new(),
            &mut |_| trust_flag::PACKAGE,
        );
        let o = file(&orig);
        assert_eq!(
            finit_verdict(map.get(&o.key), &o.facts, false, mode::DENY),
            verdict::TRUSTED
        );
        let copy = fx.root.join("tmp-copy.ko.zst");
        std::fs::copy(&orig, &copy).unwrap();
        let c = file(&copy);
        assert_ne!(c.key, o.key);
        assert_eq!(
            finit_verdict(map.get(&c.key), &c.facts, false, mode::DENY),
            verdict::DENIED
        );
        // a hard link is the same file: the same verdict as the original
        let link = fx.root.join("hard.ko");
        std::fs::hard_link(&orig, &link).unwrap();
        let l = file(&link);
        assert_eq!(l.key, o.key);
    }

    /// Named test (lot 285, the scan's half): a file of the tree older than
    /// the boot that a verified package installed is trusted; changed since
    /// boot outside a package transaction it is not, and the kernel
    /// refuses the version it reads now (the entry's change time is the
    /// one verified).
    #[test]
    fn a_trusted_module_modified_after_boot_is_not_vouched_for() {
        let fx = fixture();
        let p = fx.tree.join("kernel/net/tls.ko.zst");
        put(&p, b"tls module");
        let opt = BTreeSet::new();
        let f = file(&p);
        // older than the boot, packaged: trusted
        assert_eq!(
            classify(&f, &inputs(&fx, after_files(), &opt), None, &mut |_| {
                trust_flag::PACKAGE
            }),
            Ok(trust_flag::PACKAGE)
        );
        // a package's digest that no longer matches: not
        assert_eq!(
            classify(&f, &inputs(&fx, after_files(), &opt), None, &mut |_| 0),
            Err(UNVOUCHED)
        );
        // changed since boot, no history (or a tainted one): not
        for h in [
            None,
            Some(write_flag::TAINT),
            Some(write_flag::PKG | write_flag::TAINT),
        ] {
            assert_eq!(
                classify(&f, &inputs(&fx, before_files(), &opt), h, &mut |_| {
                    trust_flag::PACKAGE
                }),
                Err(CHANGED_SINCE_BOOT),
                "{h:?}"
            );
        }
        // the kernel: the entry verified before the change, the file read after
        let verified = entry(&f, trust_flag::PACKAGE);
        std::thread::sleep(std::time::Duration::from_millis(20));
        put(&p, b"tls module, patched");
        let now = file(&p);
        assert_eq!(
            finit_verdict(Some(&verified), &now.facts, false, mode::DENY),
            verdict::DENIED
        );
        assert_eq!(
            finit_verdict(Some(&verified), &now.facts, true, mode::DENY),
            verdict::WINDOW
        );
        // owner and mode: never trusted
        let mut loose = f.clone();
        loose.facts.mode |= 0o002;
        assert_eq!(
            classify(&loose, &inputs(&fx, after_files(), &opt), None, &mut |_| {
                trust_flag::PACKAGE
            }),
            Err(NOT_SAFE)
        );
        let mut theirs = f.clone();
        theirs.facts.uid = 1000;
        assert_eq!(
            classify(
                &theirs,
                &inputs(&fx, after_files(), &opt),
                None,
                &mut |_| trust_flag::PACKAGE
            ),
            Err(NOT_SAFE)
        );
    }

    /// Named test (lot 285, the coordinator's decision on #513): a
    /// package's modules for the running kernel installed this boot stay
    /// trusted through an agent restart or upgrade — the history pinned and
    /// adopted covers their write (`nn_linux::module_writes`). When the
    /// history does not cover it (a reset: another layout, a history not
    /// the registered one, the boot's first start after the write; or not
    /// reliable), a file a package vouches for is let through and recorded,
    /// never refused in silence — refused only under `enforce R018`; one
    /// nothing vouches for is refused. A change after the history covers,
    /// with no transaction in it, is refused as before.
    #[test]
    fn a_package_s_modules_installed_this_boot_stay_trusted_across_an_agent_restart() {
        let fx = fixture();
        let p = fx.tree.join("kernel/drivers/net/arcnet/arcnet.ko.zst");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        put(&p, b"linux-modules-extra's arcnet");
        let f = file(&p);
        let opt = BTreeSet::new();
        let written = (f.facts.ctime_sec, f.facts.ctime_nsec);
        let created = write_step(None, true, true);
        let in_tx = Some(created);
        // the restarted agent adopted the history of the start before it
        let adopted = Inputs {
            history_since: (written.0 - 60, 0),
            ..inputs(&fx, before_files(), &opt)
        };
        assert_eq!(
            classify(&f, &adopted, in_tx, &mut |_| trust_flag::PACKAGE),
            Ok(trust_flag::PACKAGE | trust_flag::PKG_WRITTEN)
        );
        let map = trust_map(
            std::slice::from_ref(&f),
            &adopted,
            &[(f.key, created)].into_iter().collect(),
            &mut |_| trust_flag::PACKAGE,
        );
        assert_eq!(
            finit_verdict(map.get(&f.key), &f.facts, false, mode::DENY),
            verdict::TRUSTED
        );
        // a reset after the write (or not reliable): no history to read,
        // whatever the map holds
        for since in [(written.0 + 60, 0), (i64::MAX, 0)] {
            let reset = Inputs {
                history_since: since,
                ..inputs(&fx, before_files(), &opt)
            };
            for h in [None, in_tx] {
                assert_eq!(
                    classify(&f, &reset, h, &mut |_| trust_flag::PACKAGE),
                    Ok(trust_flag::UNATTESTED),
                    "{since:?} {h:?}"
                );
            }
            let v = finit_verdict(
                Some(&entry(&f, trust_flag::UNATTESTED)),
                &f.facts,
                false,
                mode::DENY,
            );
            assert!(!common::module_judge::refuses(v));
            let enforce = Inputs {
                unattested: false,
                ..reset
            };
            assert_eq!(
                classify(&f, &enforce, None, &mut |_| trust_flag::PACKAGE),
                Err(UNATTESTED_ENFORCED)
            );
            // nothing vouches for it: refused
            assert_eq!(
                classify(&f, &reset, None, &mut |_| 0),
                Err(CHANGED_SINCE_BOOT)
            );
        }
        // the history covers the change, and no transaction made it
        assert_eq!(
            classify(&f, &adopted, None, &mut |_| trust_flag::PACKAGE),
            Err(CHANGED_SINCE_BOOT)
        );
        assert_eq!(
            classify(
                &f,
                &adopted,
                Some(write_flag::PKG | write_flag::TAINT),
                &mut |_| trust_flag::PACKAGE
            ),
            Err(CHANGED_SINCE_BOOT)
        );
        // older than the boot: the history is not asked
        let older = Inputs {
            history_since: (i64::MAX, 0),
            ..inputs(&fx, after_files(), &opt)
        };
        assert_eq!(
            classify(&f, &older, None, &mut |_| trust_flag::PACKAGE),
            Ok(trust_flag::PACKAGE)
        );
    }

    /// Named test (lot 285): a DKMS module built and installed inside a
    /// package transaction since boot — the kernel's history says a package
    /// manager's lineage created it, DKMS registered it for this kernel —
    /// is trusted and loads; built by hand (no such history) it is not, and
    /// an untrusted file in DKMS's directory is no DKMS build.
    #[test]
    fn a_dkms_module_under_a_package_transaction_is_allowed() {
        let fx = fixture();
        let p = fx.tree.join("updates/dkms/vboxdrv.ko.zst");
        put(&p, b"vbox");
        let reg = fx
            .registry
            .join("virtualbox/7.0.16")
            .join(REL)
            .join("x86_64/module");
        std::fs::create_dir_all(&reg).unwrap();
        put(&reg.join("vboxdrv.ko.zst"), b"vbox");
        let opt = BTreeSet::new();
        let f = file(&p);
        let since = inputs(&fx, before_files(), &opt);
        let created_in_tx = write_step(None, true, true);
        let flags = classify(&f, &since, Some(created_in_tx), &mut registry(&since)).unwrap();
        assert_eq!(flags, trust_flag::DKMS | trust_flag::PKG_WRITTEN);
        let mut writes = HashMap::new();
        writes.insert(f.key, created_in_tx);
        let map = trust_map(
            std::slice::from_ref(&f),
            &since,
            &writes,
            &mut registry(&since),
        );
        assert_eq!(
            finit_verdict(map.get(&f.key), &f.facts, false, mode::DENY),
            verdict::TRUSTED
        );
        // built by hand (a root shell's `dkms install`), or rewritten by
        // hand after the transaction: not trusted — the coordinator's
        // matrix lets it through, recorded (its own test below)
        let by_hand = write_step(None, true, false);
        let after = write_step(Some(created_in_tx), false, false);
        for h in [by_hand, after] {
            assert_eq!(
                classify(&f, &since, Some(h), &mut registry(&since)),
                Ok(trust_flag::UNATTESTED),
                "{h}"
            );
        }
        // older than the boot: DKMS's registered build for this kernel
        let before = inputs(&fx, after_files(), &opt);
        assert_eq!(
            classify(&f, &before, None, &mut registry(&before)),
            Ok(trust_flag::DKMS)
        );
        // DKMS registered another module for this kernel, not this one
        let fx2 = fixture();
        let p2 = fx2.tree.join("updates/dkms/vboxdrv.ko.zst");
        put(&p2, b"vbox");
        let reg2 = fx2
            .registry
            .join("other/1.0")
            .join(REL)
            .join("x86_64/module");
        std::fs::create_dir_all(&reg2).unwrap();
        put(&reg2.join("zfs.ko.zst"), b"zfs");
        let in2 = inputs(&fx2, after_files(), &opt);
        assert_eq!(
            classify(&file(&p2), &in2, None, &mut registry(&in2)),
            Err(UNVOUCHED)
        );
        // not registered for this kernel: nothing vouches for it
        let other = Inputs {
            release: "6.8.0-other",
            ..inputs(&fx, after_files(), &opt)
        };
        assert_eq!(
            classify(&f, &other, None, &mut registry(&other)),
            Err(UNVOUCHED)
        );
        // a file of DKMS's name outside DKMS's directory: not DKMS's
        let q = fx.tree.join("kernel/net/vboxdrv.ko.zst");
        put(&q, b"vbox");
        // written in a transaction since boot, but no package's and not
        // DKMS's: nothing vouches for it (not "changed outside one")
        assert_eq!(
            classify(
                &file(&q),
                &since,
                Some(created_in_tx),
                &mut registry(&since)
            ),
            Err(UNVOUCHED)
        );
        assert_eq!(
            classify(&file(&q), &before, None, &mut registry(&before)),
            Err(UNVOUCHED)
        );
    }

    /// A DKMS registry fixture: `module`'s build for [`REL`] holding
    /// `content`.
    fn register(fx: &Fixture, package: &str, module_file: &str, content: &[u8]) {
        let reg = fx
            .registry
            .join(package)
            .join("1.0")
            .join(REL)
            .join("x86_64/module");
        std::fs::create_dir_all(&reg).unwrap();
        put(&reg.join(module_file), content);
    }

    /// Named test (lot 285, the coordinator's matrix): a file of a DKMS
    /// output directory whose content is DKMS's registered build, written
    /// since boot outside a recognised package transaction (a hand
    /// rebuild, or before the agent started), is let through and recorded
    /// under the default policy; under `enforce R018` it is left out of
    /// the map and refused. An akmods build (`extra/`, the content the
    /// package database recorded) is the same; a packaged file anywhere
    /// else in the tree changed outside a transaction is refused.
    #[test]
    fn a_registered_dkms_build_written_after_boot_outside_a_transaction_is_allowed_and_recorded() {
        let fx = fixture();
        let p = fx.tree.join("updates/dkms/zfs.ko.zst");
        put(&p, b"zfs build");
        register(&fx, "zfs", "zfs.ko.zst", b"zfs build");
        let opt = BTreeSet::new();
        let f = file(&p);
        let default = inputs(&fx, before_files(), &opt);
        for h in [
            None,
            Some(write_flag::TAINT),
            Some(write_flag::PKG | write_flag::TAINT),
        ] {
            assert_eq!(
                classify(&f, &default, h, &mut registry(&default)),
                Ok(trust_flag::UNATTESTED),
                "{h:?}"
            );
        }
        // what vouches for it: the registry (a package first, when one does)
        assert_eq!(registry(&default)(&f), trust_flag::DKMS);
        assert_eq!(vouched_by(&f, &default, |_| true), trust_flag::PACKAGE);
        let map = trust_map(
            std::slice::from_ref(&f),
            &default,
            &HashMap::new(),
            &mut registry(&default),
        );
        let v = finit_verdict(map.get(&f.key), &f.facts, false, mode::DENY);
        assert_eq!(v, verdict::UNATTESTED);
        assert!(!common::module_judge::refuses(v));
        // `enforce R018`: left out of the map, refused
        let enforce = Inputs {
            unattested: false,
            ..inputs(&fx, before_files(), &opt)
        };
        assert_eq!(
            classify(&f, &enforce, None, &mut registry(&enforce)),
            Err(UNATTESTED_ENFORCED)
        );
        let map = trust_map(
            std::slice::from_ref(&f),
            &enforce,
            &HashMap::new(),
            &mut registry(&enforce),
        );
        assert_eq!(
            finit_verdict(map.get(&f.key), &f.facts, false, mode::DENY),
            verdict::DENIED
        );
        // a signed opt-out over it: the operator's choice
        let named: BTreeSet<String> = ["zfs".to_string()].into();
        let opted = inputs(&fx, before_files(), &named);
        assert_eq!(
            classify(&f, &opted, None, &mut registry(&opted)),
            Ok(trust_flag::OPT_OUT)
        );
        // akmods: a kmod package's file in `extra/`, vouched for by the
        // package database, written since boot without a transaction seen
        let k = fx.tree.join("extra/nvidia/nvidia.ko.xz");
        std::fs::create_dir_all(k.parent().unwrap()).unwrap();
        put(&k, b"kmod-nvidia");
        assert_eq!(
            classify(&file(&k), &default, None, &mut |_| trust_flag::PACKAGE),
            Ok(trust_flag::UNATTESTED)
        );
        assert_eq!(
            classify(&file(&k), &enforce, None, &mut |_| trust_flag::PACKAGE),
            Err(UNATTESTED_ENFORCED)
        );
        // the same outside a DKMS or akmods directory: refused
        let t = fx.tree.join("kernel/net/tls.ko.zst");
        put(&t, b"tls");
        assert_eq!(
            classify(&file(&t), &default, None, &mut |_| trust_flag::PACKAGE),
            Err(CHANGED_SINCE_BOOT)
        );
    }

    /// Named test (lot 285, the coordinator's matrix): a file of a DKMS
    /// output directory nothing vouches for — no registered build of its
    /// module, or a registered name whose build holds other content — is
    /// refused, written before or after boot; an in-tree file that fails
    /// the package check outside those directories is refused.
    #[test]
    fn a_file_in_a_dkms_location_nothing_vouches_for_is_denied() {
        let fx = fixture();
        let p = fx.tree.join("updates/dkms/vboxdrv.ko");
        put(&p, b"a rootkit under vboxdrv's name");
        register(&fx, "virtualbox", "vboxdrv.ko", b"virtualbox's build");
        let opt = BTreeSet::new();
        let f = file(&p);
        let since = inputs(&fx, before_files(), &opt);
        let before = inputs(&fx, after_files(), &opt);
        assert_eq!(registry(&since)(&f), 0);
        assert_eq!(
            classify(&f, &since, None, &mut registry(&since)),
            Err(CHANGED_SINCE_BOOT)
        );
        assert_eq!(
            classify(&f, &before, None, &mut registry(&before)),
            Err(UNVOUCHED)
        );
        // in a package transaction, still nothing vouches for it
        assert_eq!(
            classify(
                &f,
                &since,
                Some(write_step(None, true, true)),
                &mut registry(&since)
            ),
            Err(UNVOUCHED)
        );
        // not registered at all
        let q = fx.tree.join("extra/rk.ko");
        std::fs::create_dir_all(q.parent().unwrap()).unwrap();
        put(&q, b"rk");
        assert_eq!(
            classify(&file(&q), &since, None, &mut registry(&since)),
            Err(CHANGED_SINCE_BOOT)
        );
        // in the tree, the package check failed, before boot
        let t = fx.tree.join("kernel/net/tls.ko.zst");
        put(&t, b"tls");
        assert_eq!(
            classify(&file(&t), &before, None, &mut |_| 0),
            Err(UNVOUCHED)
        );
        // the registry's build with the same content: DKMS's
        register(
            &fx,
            "virtualbox",
            "vboxdrv.ko",
            b"a rootkit under vboxdrv's name",
        );
        assert_eq!(registry(&before)(&f), trust_flag::DKMS);
    }

    #[test]
    fn the_registry_build_is_compared_byte_for_byte() {
        let d = tempfile::tempdir().unwrap();
        let a = d.path().join("a");
        let b = d.path().join("b");
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&a, &big).unwrap();
        std::fs::write(&b, &big).unwrap();
        assert!(same_content(&a, &b, big.len() as u64));
        let mut other = big.clone();
        other[150_000] ^= 1;
        std::fs::write(&b, &other).unwrap();
        assert!(!same_content(&a, &b, big.len() as u64));
        // b longer than the length its metadata gave
        let mut longer = big.clone();
        longer.push(0);
        std::fs::write(&b, &longer).unwrap();
        assert!(!same_content(&a, &b, big.len() as u64));
        // a of another length
        assert!(!same_content(&a, &b, big.len() as u64 + 1));
        // a symbolic link is no build, even one whose own length (its
        // target's name) is the file's
        let t = d.path().join("target");
        let n = t.as_os_str().len();
        std::fs::write(&t, vec![b'x'; n]).unwrap();
        let l = d.path().join("l");
        std::os::unix::fs::symlink(&t, &l).unwrap();
        assert_eq!(std::fs::symlink_metadata(&l).unwrap().len(), n as u64);
        assert!(same_content(&t, &t, n as u64));
        assert!(!same_content(&l, &t, n as u64));
        assert!(!same_content(&d.path().join("missing"), &b, 1));
        // empty files
        let e1 = d.path().join("e1");
        let e2 = d.path().join("e2");
        std::fs::write(&e1, b"").unwrap();
        std::fs::write(&e2, b"").unwrap();
        assert!(same_content(&e1, &e2, 0));
    }

    /// Named test (lot 285, the scan's half): a signed opt-out by module
    /// name puts the module's files in the map, flagged as such (the rule
    /// records each load); the opt-out does not make an unsafe file safe.
    #[test]
    fn a_signed_per_module_opt_out_puts_the_file_in_the_map() {
        let fx = fixture();
        let p = fx.tree.join("updates/dkms/nvidia-drm.ko");
        put(&p, b"nv");
        let f = file(&p);
        let none = BTreeSet::new();
        assert_eq!(
            classify(&f, &inputs(&fx, before_files(), &none), None, &mut |_| 0),
            Err(CHANGED_SINCE_BOOT)
        );
        let opt: BTreeSet<String> = ["nvidia_drm".to_string()].into();
        let flags = classify(&f, &inputs(&fx, before_files(), &opt), None, &mut |_| 0).unwrap();
        assert_eq!(flags, trust_flag::OPT_OUT);
        assert_eq!(
            finit_verdict(Some(&entry(&f, flags)), &f.facts, false, mode::DENY),
            verdict::OPT_OUT
        );
        let mut loose = f.clone();
        loose.facts.mode |= 0o020;
        assert_eq!(
            classify(&loose, &inputs(&fx, before_files(), &opt), None, &mut |_| 0),
            Err(NOT_SAFE)
        );
        // another module's opt-out is not this one's
        let other: BTreeSet<String> = ["nvidia".to_string()].into();
        assert!(classify(&f, &inputs(&fx, before_files(), &other), None, &mut |_| 0).is_err());
        // a file something else vouches for is not the opt-out's (its loads
        // are not the opt-out's records)
        assert_eq!(
            classify(&f, &inputs(&fx, after_files(), &opt), None, &mut |_| {
                trust_flag::PACKAGE
            }),
            Ok(trust_flag::PACKAGE)
        );
    }

    #[test]
    fn the_package_answer_is_cached_by_the_change_stamp() {
        let fx = fixture();
        let p = fx.tree.join("kernel/net/tls.ko");
        put(&p, b"a");
        let mut cache = PackagedCache::default();
        let mut asked = 0;
        let f = file(&p);
        assert_eq!(
            cache.get(&f, |_| {
                asked += 1;
                trust_flag::PACKAGE
            }),
            trust_flag::PACKAGE
        );
        assert_eq!(
            cache.get(&f, |_| {
                asked += 1;
                0
            }),
            trust_flag::PACKAGE
        );
        assert_eq!(asked, 1);
        let mut changed = f.clone();
        changed.facts.size += 1;
        assert_eq!(cache.get(&changed, |_| trust_flag::DKMS), trust_flag::DKMS);
        let keep = std::collections::HashSet::new();
        cache.retain(&keep);
        assert_eq!(cache.get(&f, |_| 0), 0);
    }

    #[test]
    fn the_boot_time_and_the_rpm_dump() {
        assert_eq!(
            boot_time("cpu 1 2\nbtime 1762400000\nprocesses 9\n"),
            Some(1_762_400_000)
        );
        assert_eq!(boot_time("cpu 1 2\n"), None);
        let dump = "/usr/lib/modules/5.14.0/kernel/a.ko.xz\t8\tABCD\n\
                    /usr/lib/modules/5.14.0/kernel/b.ko.xz\t1\tef01\n\
                    /usr/lib/modules/5.14.0/kernel/c.ko.xz\t8\t\n\
                    /usr/lib/modules/5.14.0/kernel/e.ko.xz\t2\tabcd\n\
                    /usr/lib/modules/6.0/kernel/d.ko.xz\t8\taa\n\
                    /usr/bin/x\t8\tbb\n";
        let got = parse_rpm_dump(dump, &["/usr/lib/modules/5.14.0/".to_string()]);
        assert_eq!(got.len(), 2);
        assert_eq!(
            got["/usr/lib/modules/5.14.0/kernel/a.ko.xz"],
            (8, "abcd".to_string())
        );
        assert_eq!(
            got["/usr/lib/modules/5.14.0/kernel/b.ko.xz"],
            (1, "ef01".to_string())
        );
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("x");
        std::fs::write(&p, b"abc").unwrap();
        assert!(rpm_digest_matches(
            &p,
            8,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        ));
        assert!(rpm_digest_matches(
            &p,
            1,
            "900150983cd24fb0d6963f7d28e17f72"
        ));
        assert!(!rpm_digest_matches(&p, 8, "00"));
        assert!(!rpm_digest_matches(
            &p,
            2,
            "900150983cd24fb0d6963f7d28e17f72"
        ));
    }

    #[test]
    fn dkms_directories() {
        let t = Path::new("/lib/modules/6.8.0");
        assert!(in_dkms_dir(
            t,
            Path::new("/lib/modules/6.8.0/updates/dkms/x.ko")
        ));
        assert!(in_dkms_dir(t, Path::new("/lib/modules/6.8.0/extra/x.ko")));
        assert!(!in_dkms_dir(
            t,
            Path::new("/lib/modules/6.8.0/updates/x.ko")
        ));
        assert!(!in_dkms_dir(
            t,
            Path::new("/lib/modules/6.8.0/kernel/extra/x.ko")
        ));
        assert!(!in_dkms_dir(t, Path::new("/tmp/updates/dkms/x.ko")));
    }
}
