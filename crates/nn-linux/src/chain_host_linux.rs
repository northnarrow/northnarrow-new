//! The Linux host of the signed chains: the file operations of
//! [`ChainHost`], as the chain code made them itself before R04a (Wave 4
//! restructure, lab PR 241). Each body is the call that was in `chainlog`,
//! `audit`, `chain_anchor` or `chain_tail`, with the same flags and modes.

use std::fs::{DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::chain_host::ChainHost;

/// The agent's host: Linux.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxHost;

impl ChainHost for LinuxHost {
    /// `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`: a symlink at the name is not
    /// the chain, and a FIFO cannot stall the reader.
    fn open_read_nofollow(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    }

    /// `O_NOFOLLOW` on a symlink: `ELOOP`.
    fn is_symlink_refusal(err: &io::Error) -> bool {
        err.raw_os_error() == Some(libc::ELOOP)
    }

    fn open_with_mode(options: &mut OpenOptions, mode: u32, path: &Path) -> io::Result<File> {
        options.mode(mode).open(path)
    }

    /// `O_NOFOLLOW | O_NONBLOCK` (R11b, lab PR 262, review #466 F1: the
    /// non-blocking open too — a FIFO at the name cannot stall the writer;
    /// on a regular file the flag changes nothing).
    fn open_with_mode_nofollow(
        options: &mut OpenOptions,
        mode: u32,
        path: &Path,
    ) -> io::Result<File> {
        options
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    }

    fn create_dir_all_with_mode(dir: &Path, mode: u32) -> io::Result<()> {
        DirBuilder::new().mode(mode).recursive(true).create(dir)
    }

    /// `renameat2(RENAME_NOREPLACE)`. External audit NN-AUD-115. On a
    /// filesystem without the flag, fall back to an `lstat` check then a
    /// plain rename (the window is inside the rotation's `+i` dance).
    fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let cstr = |p: &Path| {
            std::ffi::CString::new(p.as_os_str().as_bytes())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))
        };
        let (f, t) = (cstr(from)?, cstr(to)?);
        // SAFETY: two NUL-terminated paths that outlive the call; renameat2
        // only reads them.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                f.as_ptr(),
                libc::AT_FDCWD,
                t.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if rc == 0 {
            return Ok(());
        }
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EINVAL) | Some(libc::ENOSYS) => {
                if std::fs::symlink_metadata(to).is_ok() {
                    return Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists));
                }
                std::fs::rename(from, to)
            }
            _ => Err(err),
        }
    }

    /// `pwrite` until all of `buf` is written.
    fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
        FileExt::write_all_at(file, buf, offset)
    }

    /// Review entry 44: through the directory fd held since the first call
    /// for the path's parent ([`crate::anchored::anchor`]).
    fn anchor(path: &Path) -> PathBuf {
        crate::anchored::anchor(path)
    }

    /// Lot 319 (external bug hunt BUG10's partial): a stalled retention is
    /// a degradation of the agent ([`RETENTION_DEGRADATION`], one line per
    /// log, named by its file): in `nn-admin status` and the trust level,
    /// signed in the audit chain; it leaves them when a pass runs again (or
    /// stops at another archive: that line takes its place).
    fn retention_stalled(active: &Path, why: Option<&str>) {
        let name = active.file_name().map_or_else(
            || active.display().to_string(),
            |n| n.to_string_lossy().into_owned(),
        );
        let prefix = format!("{name}: ");
        let line = why.map(|w| format!("{prefix}{w}"));
        crate::boot::degradation::withdraw_where(RETENTION_DEGRADATION, |d| {
            d.starts_with(&prefix) && Some(d) != line.as_deref()
        });
        if let Some(line) = &line {
            crate::boot::degradation::report(RETENTION_DEGRADATION, line);
        }
    }
}

/// Lot 319: the degradation's source of a rotating chain whose retention
/// stalled ([`LinuxHost::retention_stalled`]).
pub const RETENTION_DEGRADATION: &str = "chain_retention";

/// What is Linux about the chains, on the agent's host: modes, symlinks,
/// FIFOs. R04a (lab PR 241): from the tests of `chainlog`, `audit`,
/// `chain_anchor` and `chain_tail`, which run on a portable host since
/// (`chain_host::testing`); these run the agent's.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AgentSigningKey, AuditEntryDraft, AuditLog};
    use crate::chain_anchor::{HeadsSnapshot, HeadsStore, HEADS_FILE_NAME};
    use crate::chain_tail::{read_chain_tail, ChainTail, TailQuery};
    use crate::chainlog::{
        archive_path_for, manifest_path, ChainPayload, ManifestEvent, NoProtection,
        RotatingChainLog, RotationConfig,
    };
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn key(dir: &Path) -> AgentSigningKey {
        AgentSigningKey::load_or_bootstrap(&dir.join("agent.sig.key")).unwrap()
    }

    fn sample_draft(seq: u32) -> AuditEntryDraft {
        AuditEntryDraft {
            op: format!("test_op_{seq}"),
            extra: serde_json::json!({ "seq": seq }),
            key_fp: format!("{seq:08x}"),
            cosigner_fps: vec![],
            result: "success".to_string(),
            client_pid: 12345,
            client_uid: 0,
            client_comm: "nn-admin".to_string(),
            client_exe: None,
        }
    }

    /// External audit NN-AUD-115: the fresh active file after a rotation is
    /// created with `O_EXCL` — a symlink, dangling or not, is never followed
    /// (`chainlog::create_fresh_active`, `chainlog`'s
    /// `fresh_active_is_created_exclusively` before lab PR 241).
    #[test]
    fn an_exclusive_create_follows_no_symlink() {
        let dir = TempDir::new().unwrap();
        let create = |p: &Path| {
            LinuxHost::open_with_mode(OpenOptions::new().create_new(true).write(true), 0o600, p)
        };
        let victim = dir.path().join("victim");
        fs::write(&victim, b"victim").unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(create(&link).is_err());
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        let dangling = dir.path().join("dangling");
        std::os::unix::fs::symlink(dir.path().join("nowhere"), &dangling).unwrap();
        assert!(create(&dangling).is_err());
        assert!(!dir.path().join("nowhere").exists());
        let fresh = dir.path().join("fresh");
        create(&fresh).unwrap();
        assert_eq!(
            fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
    struct P {
        ts: String,
        n: u64,
    }

    impl ChainPayload for P {
        const KIND: &'static str = "test_payload";
    }

    fn p(n: u64) -> P {
        P {
            ts: format!("2026-05-30T00:00:{n:02}.000000Z"),
            n,
        }
    }

    fn data_lines(path: &Path) -> usize {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.contains("\"rotate\""))
            .count()
    }

    /// External audit NN-AUD-115: the slot check is an lstat, and the rename
    /// never replaces: a symlink at the slot of an interrupted rotation (the
    /// active file sealed, not renamed) is neither followed nor overwritten
    /// when the open completes the rotation (`chainlog`'s
    /// `a_symlink_at_the_slot_of_an_interrupted_rotation_is_left_alone`
    /// before lab PR 241; the crash is made with a real rotation put back).
    #[test]
    fn a_symlink_at_the_slot_of_an_interrupted_rotation_is_left_alone() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("test.jsonl");
        let cfg = RotationConfig {
            size_cap_bytes: 300,
            max_archives: 50,
            file_mode: 0o600,
        };
        let open = || {
            RotatingChainLog::<P>::open(
                &active,
                key(dir.path()),
                cfg,
                std::sync::Arc::new(NoProtection),
            )
            .unwrap()
        };
        let mut log = open();
        let mut n = 0;
        while !archive_path_for(&active, 1).exists() {
            log.append(p(n)).unwrap();
            n += 1;
        }
        drop(log);
        // A crash between the seal and the rename: the sealed file is the
        // active file again, the fresh one never made.
        let sealed = archive_path_for(&active, 1);
        let sealed_rows = data_lines(&sealed);
        fs::remove_file(&active).unwrap();
        fs::rename(&sealed, &active).unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, b"victim").unwrap();
        std::os::unix::fs::symlink(&victim, &sealed).unwrap();
        let mut log = open();
        log.append(p(99)).unwrap();
        drop(log);
        assert!(fs::symlink_metadata(&sealed)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        let archived = archive_path_for(&active, 2);
        assert_eq!(
            data_lines(&archived),
            sealed_rows,
            "sealed file archived intact"
        );
        assert_eq!(data_lines(&active), 1);
        let foreign = fs::read_to_string(manifest_path(&active))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<crate::chainlog::ManifestLine>(l).unwrap())
            .any(|m| {
                matches!(m.manifest.event,
                ManifestEvent::ForeignArchive { seq: 1, ref entry_type, .. } if entry_type == "symlink")
            });
        assert!(foreign, "the foreign symlink is attested");
    }

    /// `rename_noreplace` replaces nothing: a file, a symlink (not followed)
    /// or a dangling symlink at the target is `AlreadyExists`.
    #[test]
    fn rename_noreplace_replaces_nothing() {
        let dir = TempDir::new().unwrap();
        let from = dir.path().join("from");
        let victim = dir.path().join("victim");
        fs::write(&victim, b"victim").unwrap();
        for (name, make) in [("file", 0), ("link", 1), ("dangling", 2)] {
            fs::write(&from, b"from").unwrap();
            let to = dir.path().join(name);
            match make {
                0 => fs::write(&to, b"to").unwrap(),
                1 => std::os::unix::fs::symlink(&victim, &to).unwrap(),
                _ => std::os::unix::fs::symlink(dir.path().join("nowhere"), &to).unwrap(),
            }
            let e = LinuxHost::rename_noreplace(&from, &to).unwrap_err();
            assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists, "{name}");
            assert_eq!(fs::read(&from).unwrap(), b"from");
        }
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        LinuxHost::rename_noreplace(&from, &dir.path().join("free")).unwrap();
        assert!(!from.exists());
    }

    /// External audit EVD-019 (NN-AUD-281): the log the first append
    /// creates is closed to other users (0640), and a later append keeps
    /// the mode and group an installer set (`audit`'s test before lab PR
    /// 241).
    #[test]
    fn audit_log_is_created_closed_to_other_users() {
        let dir = TempDir::new().unwrap();
        let log_path = dir.path().join("audit.log");
        let key = key(dir.path());
        let mut log = AuditLog::open(&log_path, key, [0u8; 16]).unwrap();
        log.append(sample_draft(1)).unwrap();
        let mode = fs::metadata(&log_path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640, "audit.log mode {mode:o}");
        assert_eq!(mode & 0o007, 0, "no access for other users");
        // an installer's choice (here: owner only) survives the next append
        fs::set_permissions(&log_path, fs::Permissions::from_mode(0o600)).unwrap();
        log.append(sample_draft(2)).unwrap();
        assert_eq!(
            fs::metadata(&log_path).unwrap().permissions().mode() & 0o7777,
            0o600
        );
    }

    /// `f` on its own thread, which must be done within five seconds: an
    /// open of a FIFO for reading without `O_NONBLOCK` waits for a writer.
    fn within_5s<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("blocked for 5 s")
    }

    fn mkfifo(p: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    }

    /// R11b (lab PR 262, review #466 F1, the reviewer's four probes on the
    /// audit chain's own open): a symbolic link at the log's name — to the
    /// agent's key, to a file whose last line has no newline, dangling — and
    /// a FIFO there. The open refuses and says what it found, never what the
    /// target holds; the target is left as it was, nothing is created, and
    /// nothing blocks. The read-only readers (the head, the verified boot)
    /// alike.
    #[test]
    fn the_audit_chain_open_follows_no_link_and_blocks_on_no_fifo() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let d = dir.path().to_path_buf();
        let key_file = d.join("agent.sig.key");
        drop(key(&d));
        let key_text = fs::read_to_string(&key_file).unwrap();
        let refused = |name: &str| -> Vec<String> {
            let p = d.join(name);
            let d2 = d.clone();
            within_5s(move || {
                vec![
                    format!(
                        "{:#}",
                        AuditLog::open(&p, key(&d2), [1; 16]).map(drop).unwrap_err()
                    ),
                    format!(
                        "{:#}",
                        crate::audit::read_head::<LinuxHost>(&p).unwrap_err()
                    ),
                    format!(
                        "{:#}",
                        crate::audit::verified_boot_recorded::<LinuxHost>(&p).unwrap_err()
                    ),
                ]
            })
        };
        // 1. a link to the key: refused, the key in no message, unchanged
        symlink(&key_file, d.join("to-key.log")).unwrap();
        for e in refused("to-key.log") {
            assert!(e.contains("symbolic link"), "{e}");
            assert!(!e.contains(key_text.trim()), "{e}");
        }
        assert_eq!(fs::read_to_string(&key_file).unwrap(), key_text);
        // 2. a link to a file without a final newline: not truncated, not
        // terminated, its lines in no message
        let target = d.join("protected.json");
        let body = b"{\"first\":1}\n{\"second\": \"no newline\"";
        fs::write(&target, body).unwrap();
        symlink(&target, d.join("to-file.log")).unwrap();
        for e in refused("to-file.log") {
            assert!(e.contains("symbolic link"), "{e}");
            assert!(!e.contains("first") && !e.contains("second"), "{e}");
        }
        assert_eq!(fs::read(&target).unwrap(), body);
        // 3. a dangling link: its target is not created
        fs::create_dir(d.join("elsewhere")).unwrap();
        symlink(d.join("elsewhere/planted.jsonl"), d.join("dangling.log")).unwrap();
        for e in refused("dangling.log") {
            assert!(e.contains("symbolic link"), "{e}");
        }
        assert!(!d.join("elsewhere/planted.jsonl").exists());
        // 4. a FIFO: refused at once, not a regular file
        mkfifo(&d.join("fifo.log"));
        for e in refused("fifo.log") {
            assert!(e.contains("not a regular file"), "{e}");
        }
    }

    /// R11b (lab PR 262, review #466 F1): the append opens the name again
    /// (through the directory anchored at the open): a link or a FIFO put
    /// there after the open is not written through, its target neither
    /// created nor changed, and the append does not block.
    #[test]
    fn the_audit_append_follows_no_link_and_blocks_on_no_fifo() {
        use std::os::unix::fs::symlink;
        let dir = TempDir::new().unwrap();
        let d = dir.path().to_path_buf();
        let victim = d.join("victim");
        fs::write(&victim, b"victim").unwrap();
        fs::create_dir(d.join("elsewhere")).unwrap();
        for (name, plant) in [("link", 0), ("dangling", 1), ("fifo", 2)] {
            let path = d.join(format!("{name}.log"));
            let mut log = AuditLog::open(&path, key(&d), [1; 16]).unwrap();
            match plant {
                0 => symlink(&victim, &path).unwrap(),
                1 => symlink(d.join("elsewhere/planted"), &path).unwrap(),
                _ => mkfifo(&path),
            }
            let e = within_5s(move || format!("{:#}", log.append(sample_draft(1)).unwrap_err()));
            assert!(
                e.contains("symbolic link") || e.contains("for append"),
                "{name}: {e}"
            );
        }
        assert_eq!(fs::read(&victim).unwrap(), b"victim");
        assert!(!d.join("elsewhere/planted").exists());
    }

    /// External audit EVD-019 (NN-AUD-281): the head anchor the agent
    /// creates is closed to other users, like the audit log next to it
    /// (`chain_anchor`'s test before lab PR 241).
    #[test]
    fn the_heads_file_is_created_closed_to_other_users() {
        let dir = TempDir::new().unwrap();
        let k = key(dir.path());
        let file = dir.path().join(HEADS_FILE_NAME);
        let s = HeadsSnapshot {
            counter: 1,
            ts: "t1".into(),
            agent_id: "00".into(),
            second_key_added: false,
            heads: vec![],
        };
        HeadsStore::write(&file, &k, &s).unwrap();
        let mode = std::fs::metadata(&file).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640, "chain_heads.json mode {mode:o}");
    }

    fn row(i: u64) -> String {
        format!(
            "{{\"ts\":\"2026-10-15T10:{:02}:{:02}.000000Z\",\"n\":{i}}}",
            i / 60,
            i % 60
        )
    }

    fn write_rows(path: &Path, range: std::ops::Range<u64>) {
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        for i in range {
            writeln!(f, "{}", row(i)).unwrap();
        }
    }

    fn all(cap: usize) -> TailQuery<'static> {
        TailQuery {
            since: None,
            keep: None,
            soft_cap: cap,
            max_rows: usize::MAX,
        }
    }

    fn numbers(t: &ChainTail) -> Vec<u64> {
        t.jsonl
            .lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["n"]
                    .as_u64()
                    .unwrap()
            })
            .collect()
    }

    /// A symlink or a FIFO at an archive name is not read; the active path
    /// as a symlink neither (`chain_tail`'s test before lab PR 241). Lot 298
    /// (external bug hunt, BUG07): the answer says rows were left unread —
    /// the symlink's open refused (`O_NOFOLLOW`), the FIFO no regular file.
    #[test]
    fn symlinked_and_special_files_are_not_read() {
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("log.jsonl");
        let secret = dir.path().join("secret");
        std::fs::write(&secret, "{\"ts\":\"2026-10-15T09:00:00Z\",\"n\":666}\n").unwrap();
        std::os::unix::fs::symlink(&secret, dir.path().join("log.jsonl.000002")).unwrap();
        let fifo = std::ffi::CString::new(
            dir.path()
                .join("log.jsonl.000001")
                .as_os_str()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        // SAFETY: a NUL-terminated path that outlives the call.
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        write_rows(&active, 0..2);
        let t = read_chain_tail::<LinuxHost>(&active, &all(1 << 20));
        assert_eq!(numbers(&t), vec![1, 0]);
        assert!(t.truncated, "archive 000002 (a symlink) left unread");
        // the FIFO alone: no regular file, said
        std::fs::remove_file(dir.path().join("log.jsonl.000002")).unwrap();
        let t = read_chain_tail::<LinuxHost>(&active, &all(1 << 20));
        assert_eq!((numbers(&t), t.truncated), (vec![1, 0], true));
        // The active path itself as a symlink is refused too.
        let link = dir.path().join("link.jsonl");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        let t = read_chain_tail::<LinuxHost>(&link, &all(1 << 20));
        assert_eq!((t.count, t.truncated), (0, true));
    }

    // ── Lot 296 (external bug hunt BUG15, BUG17): the kernel's own short
    //    write, in the agent's writers on the agent's host ──

    /// Lowers this process's file size limit to `limit` bytes for `f`: the
    /// kernel's own short write, as a full disk makes it (the first `write`
    /// takes what fits, the next fails `EFBIG`). Only in a helper process of
    /// its own: the limit is the process's, the other tests' threads must
    /// not see it.
    fn with_file_size_limit<T>(limit: u64, f: impl FnOnce() -> T) -> T {
        let mut old = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: signal/getrlimit/setrlimit with valid arguments; the limit
        // is put back at once.
        unsafe {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
            assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut old), 0);
            let low = libc::rlimit {
                rlim_cur: limit,
                rlim_max: old.rlim_max,
            };
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &low), 0);
        }
        let r = f();
        // SAFETY: as above.
        unsafe {
            assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &old), 0);
        }
        r
    }

    const SHORT_WRITE_DIR: &str = "NN_LINUX_SHORT_WRITE_DIR";

    /// The writer of [`a_short_write_glues_no_row_to_the_next`], in a
    /// process of its own. A no-op without its variable.
    #[test]
    #[ignore = "a helper: run by a_short_write_glues_no_row_to_the_next"]
    fn short_write_writer() {
        let Some(dir) = std::env::var_os(SHORT_WRITE_DIR) else {
            return;
        };
        let dir = Path::new(&dir);
        // the audit log
        let log_path = dir.join("audit.log");
        let mut log = AuditLog::open(&log_path, key(dir), [0u8; 16]).unwrap();
        log.append(sample_draft(1)).unwrap();
        let len = fs::metadata(&log_path).unwrap().len();
        let e = with_file_size_limit(len + 55, || log.append(sample_draft(2))).unwrap_err();
        assert_eq!(
            e.root_cause()
                .downcast_ref::<io::Error>()
                .and_then(io::Error::raw_os_error),
            Some(libc::EFBIG),
            "{e:#}"
        );
        assert_eq!(
            fs::metadata(&log_path).unwrap().len(),
            len + 55,
            "a short write"
        );
        log.append(sample_draft(3)).unwrap();
        // a rotating chain
        let active = dir.join("log.jsonl");
        let mut chain = RotatingChainLog::<P, _>::open(
            &active,
            key(dir),
            RotationConfig::default(),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        chain.append(p(0)).unwrap();
        let len = fs::metadata(&active).unwrap().len();
        assert!(with_file_size_limit(len + 50, || chain.append(p(1))).is_err());
        assert_eq!(
            fs::metadata(&active).unwrap().len(),
            len + 50,
            "a short write"
        );
        chain.append(p(2)).unwrap();
    }

    /// BUG15 and BUG17 with the kernel's own short write (the file size
    /// limit) on the agent's host: the writers' `write_all` stops part-way.
    /// The next row is glued to no fragment — the audit log opens again (a
    /// start in enforce mode refused it), the rotating chain verifies (it
    /// was Malformed for good) —, and each cut is attested.
    #[test]
    fn a_short_write_glues_no_row_to_the_next() {
        let dir = TempDir::new().unwrap();
        let st = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "chain_host_linux::tests::short_write_writer",
                "--test-threads=1",
            ])
            .env(SHORT_WRITE_DIR, dir.path())
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "the writer: {st}");
        let k = key(dir.path());
        let log_path = dir.path().join("audit.log");
        if let Err(e) = AuditLog::open(&log_path, key(dir.path()), [0u8; 16]) {
            panic!("the audit log does not open again after a short write: {e:#}");
        }
        let text = fs::read_to_string(&log_path).unwrap();
        let rows: Vec<crate::audit::AuditEntry> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not a row: {e}")))
            .collect();
        let ops: Vec<&str> = rows.iter().map(|r| r.op.as_str()).collect();
        assert_eq!(
            ops,
            [
                "test_op_1",
                crate::audit::CHAIN_TAIL_REPAIRED_OP,
                "test_op_3"
            ]
        );
        crate::audit::verify_chain(&rows, &k.verifying_key()).unwrap();
        let active = dir.path().join("log.jsonl");
        let r = crate::chainlog::verify_log_set::<P>(&active, &k.verifying_key());
        assert!(r.as_ref().is_ok_and(|r| r.total_records == 2), "{r:?}");
        let manifest = fs::read_to_string(manifest_path(&active)).unwrap();
        let cut: Vec<ManifestEvent> = manifest
            .lines()
            .map(|l| {
                serde_json::from_str::<crate::chainlog::ManifestLine>(l)
                    .unwrap()
                    .manifest
                    .event
            })
            .filter(|e| matches!(e, ManifestEvent::TornTailRepaired { .. }))
            .collect();
        assert!(
            matches!(&cut[..], [ManifestEvent::TornTailRepaired { role, dropped_bytes: 50, .. }] if role == "active"),
            "{cut:?}"
        );
    }

    // ── Lot 319 (lot 296's backlog): the flat chains of the agent's host —
    //    the canary registry and access log, the FIM baseline, the listener
    //    log — after the kernel's own short write ──

    const FLAT_SHORT_WRITE_DIR: &str = "NN_LINUX_FLAT_SHORT_WRITE_DIR";

    /// The flat chains [`flat_short_write_writer`] writes, by file name.
    const FLAT_CHAINS: [&str; 4] = [
        "canary_access.jsonl",
        "canaries.jsonl",
        "baseline.jsonl",
        "netflow_listeners.jsonl",
    ];

    /// `append` cut short by the file size limit, 40 bytes into its row:
    /// it fails, and the start of its row is in the file.
    fn cut_short<T>(path: &Path, append: impl FnOnce() -> anyhow::Result<T>) {
        let len = fs::metadata(path).unwrap().len();
        let r = with_file_size_limit(len + 40, append);
        assert!(r.is_err(), "premise: {} took the whole row", path.display());
        assert_eq!(
            fs::metadata(path).unwrap().len(),
            len + 40,
            "premise: a short write in {}",
            path.display()
        );
    }

    /// The writer of [`a_short_write_glues_no_row_in_the_flat_chains`], in a
    /// process of its own (the file size limit is the process's). A no-op
    /// without its variable.
    #[test]
    #[ignore = "a helper: run by a_short_write_glues_no_row_in_the_flat_chains"]
    fn flat_short_write_writer() {
        use crate::canary::{access_log, registry};
        let Some(dir) = std::env::var_os(FLAT_SHORT_WRITE_DIR) else {
            return;
        };
        let dir = Path::new(&dir);
        // the audit chain the agent signs its repairs in
        let audit = std::sync::Arc::new(parking_lot::Mutex::new(
            AuditLog::open(&dir.join("audit.log"), key(dir), [0u8; 16]).unwrap(),
        ));
        crate::boot::degradation::attach_audit_log(Some(audit));
        let access = |n: u32| access_log::CanaryAccessDraft {
            canary_id: format!("canary_id_{n}"),
            canary_name: format!("decoy_{n}"),
            canary_type: nn_model::CanaryTypeTag::File,
            access_kind: nn_model::CanaryAccessKind::FileOpen,
            accessor_pid: 1000 + n,
            accessor_uid: 0,
            accessor_comm: format!("attacker_{n}"),
            accessor_exe: None,
            first_trip: n == 1,
        };
        let p = dir.join(FLAT_CHAINS[0]);
        let mut db = access_log::CanaryAccessDb::open(&p, key(dir), [0u8; 16]).unwrap();
        db.append(access(1)).unwrap();
        cut_short(&p, || db.append(access(2)));
        db.append(access(3)).unwrap();
        let canary = |n: u32| registry::CanaryTokenDraft {
            name: format!("test_canary_{n}"),
            canary_type: nn_proto::admin_signed_payload::CanaryTypeWire::File,
            deployment: nn_proto::admin_signed_payload::CanaryDeploymentWire::File {
                path: format!("/tmp/decoy_{n}.txt"),
                template: None,
            },
            deployed_by_fp: format!("{n:08x}"),
            content: None,
        };
        let p = dir.join(FLAT_CHAINS[1]);
        let mut reg = registry::Registry::open(&p, key(dir), [0u8; 16]).unwrap();
        reg.deploy(canary(1)).unwrap();
        cut_short(&p, || reg.deploy(canary(2)));
        reg.deploy(canary(3)).unwrap();
        let entry = |n: u32| crate::fim::baseline::BaselineEntryDraft {
            path: format!("/etc/test_{n}"),
            sha256: hex::encode([n as u8; 32]),
            mode: "0o644".to_string(),
            uid: 0,
            gid: 0,
            size_bytes: 1024,
            is_symlink: false,
            target: None,
        };
        let p = dir.join(FLAT_CHAINS[2]);
        let mut base = crate::fim::baseline::BaselineDb::open(&p, key(dir), [0u8; 16]).unwrap();
        base.append(entry(1)).unwrap();
        cut_short(&p, || base.append(entry(2)));
        base.append(entry(3)).unwrap();
        let listener = |n: u64| nn_model::telemetry::NetListenerEvent {
            timestamp_ns: n,
            family: 2,
            bind_addr: "0.0.0.0".parse().unwrap(),
            bind_port: 8080,
            proto: 6,
            pid: 42,
            uid: 0,
            comm: "nc".to_string(),
            exe: None,
        };
        let p = dir.join(FLAT_CHAINS[3]);
        let mut net = crate::net::drain::NetListenerDb::open(&p, key(dir), [0u8; 16]).unwrap();
        net.append(&listener(1)).unwrap();
        cut_short(&p, || net.append(&listener(2)));
        net.append(&listener(3)).unwrap();
        crate::boot::degradation::flush();
    }

    /// The rows of the flat chain at `path`, each line one: a line that is
    /// not a row (a fragment with a row glued to it) fails.
    fn flat_rows<T: serde::de::DeserializeOwned>(path: &Path) -> Vec<T> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| {
                serde_json::from_str(l).unwrap_or_else(|e| {
                    panic!("{}: a line that is no row ({e}): {l}", path.display())
                })
            })
            .collect()
    }

    /// Lot 296's poisoned-writer scheme on the flat chains: a write stopped
    /// part-way (a full disk: the kernel's own short write, by the file size
    /// limit) left the start of its row, and the next row was glued to it —
    /// one line no row (the registry and the access log skipped it at the
    /// next start and their chains broke; the listener log no longer opened,
    /// so the next start wrote no listener). The next row now reads the tail
    /// first: the fragment is cut, the cut signed in the audit chain
    /// (`chain_tail_repaired`), and each chain verifies whole.
    #[test]
    fn a_short_write_glues_no_row_in_the_flat_chains() {
        use crate::canary::{access_log, registry};
        let dir = TempDir::new().unwrap();
        let st = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "chain_host_linux::tests::flat_short_write_writer",
                "--test-threads=1",
            ])
            .env(FLAT_SHORT_WRITE_DIR, dir.path())
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "the writer: {st}");
        let pk = key(dir.path()).verifying_key();
        let d = |i: usize| dir.path().join(FLAT_CHAINS[i]);
        let rows: Vec<access_log::CanaryAccessEntry> = flat_rows(&d(0));
        assert_eq!(rows.len(), 2);
        access_log::verify_chain(&rows, &pk).unwrap();
        let rows: Vec<registry::CanaryToken> = flat_rows(&d(1));
        assert_eq!(rows.len(), 2);
        registry::verify_chain(&rows, &pk).unwrap();
        let rows: Vec<crate::fim::baseline::BaselineEntry> = flat_rows(&d(2));
        assert_eq!(rows.len(), 2);
        crate::fim::baseline::verify_chain(&rows, &pk).unwrap();
        let rows: Vec<crate::net::drain::NetListenerEntry> = flat_rows(&d(3));
        assert_eq!(rows.len(), 2);
        assert_eq!(
            rows[1].prev_hash, rows[0].entry_hash,
            "the listener rows chain"
        );
        // each opens again with nothing to repair or skip
        let mut a = access_log::CanaryAccessDb::open(&d(0), key(dir.path()), [0u8; 16]).unwrap();
        assert_eq!(a.take_open_findings(), (None, 0));
        assert!(a.take_chain_findings().is_empty());
        let mut r = registry::Registry::open(&d(1), key(dir.path()), [0u8; 16]).unwrap();
        assert_eq!(r.take_open_findings(), (None, 0));
        assert!(r.take_chain_findings().is_empty());
        assert_eq!(r.len(), 2, "two canaries deployed");
        let mut b =
            crate::fim::baseline::BaselineDb::open(&d(2), key(dir.path()), [0u8; 16]).unwrap();
        assert_eq!(b.take_open_findings(), (None, 0));
        let mut n = crate::net::drain::NetListenerDb::open(&d(3), key(dir.path()), [0u8; 16])
            .expect("the listener log opens again");
        assert!(n.take_tail_repair().is_none());
        // each cut signed once in the audit chain, naming its file
        let audit: Vec<serde_json::Value> = fs::read_to_string(dir.path().join("audit.log"))
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .filter(|v: &serde_json::Value| v["op"] == crate::audit::CHAIN_TAIL_REPAIRED_OP)
            .collect();
        let mut files: Vec<String> = audit
            .iter()
            .map(|v| v["extra"]["file"].as_str().unwrap().to_string())
            .collect();
        files.sort();
        let mut want: Vec<String> = (0..4).map(|i| d(i).display().to_string()).collect();
        want.sort();
        assert_eq!(files, want, "{audit:?}");
        assert!(audit
            .iter()
            .all(|v| v["extra"]["detail"].as_str().unwrap().contains("(40 bytes")));
    }

    // ── Lot 296 (external bug hunt BUG27): a real failed fsync ──

    thread_local! {
        static PIPE_NEXT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
        static PIPE: std::cell::RefCell<Option<std::io::PipeReader>> =
            const { std::cell::RefCell::new(None) };
    }

    /// The agent's host, but its next append-open hands out a pipe: the
    /// write succeeds, the fsync fails (`EINVAL`, the kernel's), and the test
    /// then puts the bytes written in the file — the line is in the file,
    /// its fsync failed (the triage's host, in nn-evidence before: a pure
    /// crate names no `std::os`).
    struct PipeHost;

    impl ChainHost for PipeHost {
        fn open_read_nofollow(path: &Path) -> io::Result<File> {
            LinuxHost::open_read_nofollow(path)
        }
        fn is_symlink_refusal(err: &io::Error) -> bool {
            LinuxHost::is_symlink_refusal(err)
        }
        fn open_with_mode(options: &mut OpenOptions, mode: u32, path: &Path) -> io::Result<File> {
            if PIPE_NEXT.with(|c| c.replace(false)) {
                let (r, w) = std::io::pipe()?;
                PIPE.with(|p| *p.borrow_mut() = Some(r));
                return Ok(File::from(std::os::fd::OwnedFd::from(w)));
            }
            LinuxHost::open_with_mode(options, mode, path)
        }
        fn open_with_mode_nofollow(
            options: &mut OpenOptions,
            mode: u32,
            path: &Path,
        ) -> io::Result<File> {
            LinuxHost::open_with_mode_nofollow(options, mode, path)
        }
        fn create_dir_all_with_mode(dir: &Path, mode: u32) -> io::Result<()> {
            LinuxHost::create_dir_all_with_mode(dir, mode)
        }
        fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
            LinuxHost::rename_noreplace(from, to)
        }
        fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
            LinuxHost::write_all_at(file, buf, offset)
        }
        fn anchor(path: &Path) -> PathBuf {
            LinuxHost::anchor(path)
        }
    }

    struct PipeKey(AgentSigningKey);

    impl crate::chain_host::ChainSigner for PipeKey {
        type Host = PipeHost;
        fn sign(&self, msg: &[u8]) -> ed25519_dalek::Signature {
            crate::chain_host::ChainSigner::sign(&self.0, msg)
        }
        fn verifying_key(&self) -> ed25519_dalek::VerifyingKey {
            crate::chain_host::ChainSigner::verifying_key(&self.0)
        }
    }

    /// BUG27 with a real failed fsync: the line written whole, its fsync
    /// failed (`EINVAL`); the next line chains off it — `last_hash` and the
    /// position did not move, and the next line forked the chain
    /// (`PrevHashMismatch`, the triage's test on `main`).
    #[test]
    fn a_real_failed_fsync_does_not_fork_the_chain() {
        use std::io::Read as _;
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("log.jsonl");
        let mut log = RotatingChainLog::<P, _>::open(
            &active,
            PipeKey(key(dir.path())),
            RotationConfig::default(),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        log.append(p(0)).unwrap();
        PIPE_NEXT.with(|c| c.set(true));
        let e = log.append(p(1)).unwrap_err();
        assert!(format!("{e:#}").contains("fsync"), "premise: {e:#}");
        let mut written = Vec::new();
        PIPE.with(|p| p.borrow_mut().take())
            .unwrap()
            .read_to_end(&mut written)
            .unwrap();
        assert!(written.ends_with(b"\n") && written.len() > 50);
        OpenOptions::new()
            .append(true)
            .open(&active)
            .unwrap()
            .write_all(&written)
            .unwrap();
        log.append(p(2)).unwrap();
        drop(log);
        let k = key(dir.path());
        let r = crate::chainlog::verify_log_set::<P>(
            &active,
            &crate::chain_host::ChainSigner::verifying_key(&k),
        );
        assert!(
            r.as_ref().is_ok_and(|r| r.total_records == 3),
            "the chain forked after a failed fsync: {r:?}"
        );
    }

    // ── Lot 319 (external bug hunt BUG10, the partial left by lot 296): a
    //    stalled retention in the agent's status ──

    /// An archive that cannot be removed (`chattr +i`, a read-only
    /// filesystem), as a protection: while `on`, its release of the archive
    /// named `name` swaps it for a directory that is not empty (the removal
    /// then fails), and the next dance swaps the archive back — a regular
    /// archive again at every pass.
    struct Stuck {
        name: &'static str,
        aside: PathBuf,
        on: std::sync::atomic::AtomicBool,
    }

    impl Stuck {
        fn swapped(&self, dir: &Path) -> PathBuf {
            dir.join(self.name)
        }
    }

    impl crate::chainlog::ProtectionManager for Stuck {
        fn with_mutable_dir(
            &self,
            f: &mut dyn FnMut() -> anyhow::Result<()>,
        ) -> anyhow::Result<()> {
            let held = self.swapped(self.aside.parent().unwrap());
            if held.is_dir() {
                fs::remove_dir_all(&held)?;
                fs::rename(&self.aside, &held)?;
            }
            f()
        }
        fn register_active(&self, _path: &Path) -> anyhow::Result<()> {
            Ok(())
        }
        fn release(&self, path: &Path) -> anyhow::Result<()> {
            if self.on.load(std::sync::atomic::Ordering::SeqCst)
                && path.file_name().is_some_and(|n| n == self.name)
            {
                fs::rename(path, &self.aside)?;
                fs::create_dir(path)?;
                fs::write(path.join("x"), b"x")?;
            }
            Ok(())
        }
    }

    fn retention_lines() -> Vec<String> {
        crate::boot::degradation::entries()
            .into_iter()
            .filter(|d| d.source == "chain_retention")
            .map(|d| d.detail)
            .collect()
    }

    /// BUG10: an archive past the retention that cannot be removed stops
    /// every eviction pass (by design: removing the newer ones past it would
    /// leave a gap in the chain) — and that stayed an `error!` at each
    /// rotation, while the disk use grew. On the agent's host it is a
    /// degradation: in `nn-admin status` (and the trust level), signed in
    /// the audit chain, once; it leaves the status when a pass runs again.
    #[test]
    fn retention_stalled_is_a_visible_degradation() {
        let _g = crate::boot::degradation::TEST_LOCK.lock();
        crate::boot::degradation::reset_for_tests();
        let dir = TempDir::new().unwrap();
        let active = dir.path().join("netflow.jsonl");
        let cfg = |archives| RotationConfig {
            size_cap_bytes: 300,
            max_archives: archives,
            file_mode: 0o600,
        };
        let mut log = RotatingChainLog::<P>::open(
            &active,
            key(dir.path()),
            cfg(50),
            std::sync::Arc::new(NoProtection),
        )
        .unwrap();
        let mut i = 0u64;
        let mut rotate_to = |log: &mut RotatingChainLog<P>, seq: u64| {
            while !archive_path_for(&active, seq).exists() {
                log.append(p(i % 60)).unwrap();
                i += 1;
                assert!(i < 2000);
            }
        };
        rotate_to(&mut log, 3);
        drop(log);
        // archive 2 cannot be removed; the retention falls to one archive
        let stuck = std::sync::Arc::new(Stuck {
            name: "netflow.jsonl.000002",
            aside: dir.path().join("aside"),
            on: std::sync::atomic::AtomicBool::new(true),
        });
        let mut log =
            RotatingChainLog::<P>::open(&active, key(dir.path()), cfg(1), stuck.clone()).unwrap();
        rotate_to(&mut log, 4);
        assert!(
            archive_path_for(&active, 3).is_file() && !archive_path_for(&active, 1).exists(),
            "premise: the pass removed 1 and stopped at archive 2"
        );
        let lines = retention_lines();
        assert_eq!(lines.len(), 1, "one degradation: {lines:?}");
        assert!(
            lines[0].contains("netflow.jsonl") && lines[0].contains("archive 2"),
            "it names the log and the archive: {lines:?}"
        );
        assert!(
            !lines[0].contains("/proc/self/fd"),
            "the log's name, not its anchor: {lines:?}"
        );
        // signed in the audit chain when the log is there (the flush)
        let audit = dir.path().join("audit.log");
        let audit_log = std::sync::Arc::new(parking_lot::Mutex::new(
            AuditLog::open(&audit, key(dir.path()), [0u8; 16]).unwrap(),
        ));
        crate::boot::degradation::attach_audit_log(Some(audit_log));
        let signed = || {
            fs::read_to_string(&audit)
                .unwrap()
                .lines()
                .filter(|l| l.contains("subsystem_degraded") && l.contains("archive 2"))
                .count()
        };
        assert_eq!(signed(), 1, "signed once");
        // the next pass stops at 2 again: still one line, signed once
        rotate_to(&mut log, 5);
        assert!(archive_path_for(&active, 3).is_file(), "stopped again");
        assert_eq!(retention_lines(), lines);
        crate::boot::degradation::flush();
        assert_eq!(signed(), 1);
        // the archive can be removed again: the stall ends, the line leaves
        stuck.on.store(false, std::sync::atomic::Ordering::SeqCst);
        rotate_to(&mut log, 6);
        assert!(!archive_path_for(&active, 2).exists(), "removed");
        assert!(
            retention_lines().is_empty(),
            "a pass that ran withdraws it: {:?}",
            retention_lines()
        );
        crate::boot::degradation::reset_for_tests();
    }

    /// Lot 319: one line per log — the end of one log's stall leaves the
    /// other's; a stall at another archive replaces the log's line.
    #[test]
    fn each_log_s_stall_is_its_own_line() {
        let _g = crate::boot::degradation::TEST_LOCK.lock();
        crate::boot::degradation::reset_for_tests();
        let a = Path::new("/proc/self/fd/9/netflow.jsonl");
        let b = Path::new("/proc/self/fd/9/fim_drift.jsonl");
        LinuxHost::retention_stalled(a, Some("the retention stopped at archive 2"));
        LinuxHost::retention_stalled(b, Some("the retention stopped at archive 7"));
        assert_eq!(retention_lines().len(), 2);
        LinuxHost::retention_stalled(a, Some("the retention stopped at archive 3"));
        let mut lines = retention_lines();
        lines.sort();
        assert_eq!(
            lines,
            [
                "fim_drift.jsonl: the retention stopped at archive 7",
                "netflow.jsonl: the retention stopped at archive 3"
            ]
        );
        LinuxHost::retention_stalled(a, None);
        assert_eq!(
            retention_lines(),
            ["fim_drift.jsonl: the retention stopped at archive 7"]
        );
        crate::boot::degradation::reset_for_tests();
    }

    /// Lot 319: the same stall told again (a writer of the log opened again
    /// in the process) keeps its line — it is not withdrawn and signed a
    /// second time.
    #[test]
    fn the_same_stall_told_again_is_signed_once() {
        let _g = crate::boot::degradation::TEST_LOCK.lock();
        crate::boot::degradation::reset_for_tests();
        let dir = TempDir::new().unwrap();
        let audit = dir.path().join("audit.log");
        crate::boot::degradation::attach_audit_log(Some(std::sync::Arc::new(
            parking_lot::Mutex::new(AuditLog::open(&audit, key(dir.path()), [0u8; 16]).unwrap()),
        )));
        let a = Path::new("/proc/self/fd/9/k319-netflow.jsonl");
        for _ in 0..2 {
            LinuxHost::retention_stalled(a, Some("the retention stopped at archive 4"));
            crate::boot::degradation::flush();
        }
        let signed = fs::read_to_string(&audit)
            .unwrap()
            .lines()
            .filter(|l| l.contains("subsystem_degraded") && l.contains("k319-netflow.jsonl"))
            .count();
        assert_eq!(signed, 1);
        assert_eq!(retention_lines().len(), 1);
        crate::boot::degradation::reset_for_tests();
    }
}
