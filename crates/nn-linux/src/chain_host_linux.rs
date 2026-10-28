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
}

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
    /// as a symlink neither (`chain_tail`'s test before lab PR 241).
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
        // The active path itself as a symlink is refused too.
        let link = dir.path().join("link.jsonl");
        std::os::unix::fs::symlink(&secret, &link).unwrap();
        assert_eq!(read_chain_tail::<LinuxHost>(&link, &all(1 << 20)).count, 0);
    }
}
