//! The Linux host of the content lists: the open of [`ContentHost`], as the
//! content code made it itself before R07 (Wave 4 restructure, lab PR 247):
//! an operator overlay or a shipped `.v1` list (`config::overlay_auth`'s
//! `read_overlay`), an operator canary template (`canary::templates`'
//! `read_template`), with the same flags. The host is the chains' one
//! ([`LinuxHost`], `chain_host_linux`): one type, the agent's.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use nn_core::content_host::ContentHost;

use crate::chain_host_linux::LinuxHost;

impl ContentHost for LinuxHost {
    /// `O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC`: a symlink at the
    /// name is not read through, and a FIFO planted there cannot block the
    /// read (external audit LLMR-013, DEC-016).
    fn open_read_nofollow(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
    }

    /// `O_NOFOLLOW` on a symlink: `ELOOP`.
    fn is_symlink_refusal(err: &io::Error) -> bool {
        err.raw_os_error() == Some(libc::ELOOP)
    }
}

/// What is Linux about the content reads, on the agent's host: a symlink
/// at the name refused, a FIFO there not waited on. R07 (lab PR 247): from
/// the tests of `config::overlay` and `canary::templates`, whose others
/// run on a portable host since; these run the agent's.
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use anyhow::{anyhow, Result};
    use tempfile::TempDir;

    use crate::canary::templates::{render, CredFamily, RenderError};
    use crate::config::overlay::{load_defaults_with, parse_default_text, DefaultsSource, Shipped};
    use crate::config::overlay_auth::content_sha256;

    /// A validator that accepts any non-empty token (as `config::overlay`'s
    /// tests).
    fn accept_any(entry: &str) -> Result<()> {
        if entry.is_empty() {
            return Err(anyhow!("empty entry"));
        }
        Ok(())
    }

    const SHIPPED: &str = "sshd\nnginx\n";
    const EARLIER: &str = "sshd\nnginx\nevil-but-shipped-once\n";

    fn shipped_set() -> BTreeSet<String> {
        ["sshd", "nginx"].iter().map(|s| s.to_string()).collect()
    }

    fn load_test_list(v1: &Path, allow_modified: bool) -> (BTreeSet<String>, DefaultsSource) {
        let earlier = hex::encode(content_sha256(EARLIER.as_bytes()));
        let earlier = [earlier.as_str()];
        load_defaults_with(
            "test-allowlist",
            v1,
            Shipped::new(SHIPPED, &earlier),
            allow_modified,
            true,
            |name, body| parse_default_text(name, body, &accept_any),
        )
    }

    /// Stable seed (as `canary::templates`' tests).
    const TEST_ID: &str = "9f3c8a01b2c3d4e5f6a7b8c9d0e1f2a3";

    /// External audit LLMR-015: a `.v1` is read like an overlay — not
    /// through a link (its target is anything root points it at), not from
    /// a FIFO (the boot would block on it) — and gives way to the built-in
    /// copy, reported as unavailable.
    #[test]
    fn default_through_a_link_or_fifo_is_refused() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "implant\n").unwrap();
        let link = dir.path().join("link.v1");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let (set, source) = load_test_list(&link, true);
        assert_eq!(set, shipped_set());
        assert!(
            matches!(&source, DefaultsSource::BuiltIn(why) if why.contains("symbolic link")),
            "{source:?}"
        );
        // Even when the link points at the shipped content.
        std::fs::write(&target, SHIPPED).unwrap();
        let (_, source) = load_test_list(&link, false);
        assert!(matches!(source, DefaultsSource::BuiltIn(_)));

        let fifo = dir.path().join("fifo.v1");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a valid NUL-terminated path; mkfifo has no other preconditions.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (set, source) = load_test_list(&fifo, false);
        assert_eq!(set, shipped_set());
        assert!(
            matches!(&source, DefaultsSource::BuiltIn(why) if why.contains("not a regular file")),
            "{source:?}"
        );
    }

    /// External audit DEC-016 (lab PR 178): a link at a template's name
    /// (`/dev/zero`, or a file elsewhere) is not read through, and refuses
    /// the render instead of falling back to the built-in one.
    #[test]
    fn symlinked_template_is_refused() {
        let dir = TempDir::new().unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, "aws_access_key_id = {{access_key_id}}\n").unwrap();
        std::os::unix::fs::symlink(&elsewhere, dir.path().join("aws.tmpl")).unwrap();
        std::os::unix::fs::symlink("/dev/zero", dir.path().join("gcp.tmpl")).unwrap();
        for family in [CredFamily::Aws, CredFamily::Gcp] {
            match render(family, TEST_ID, Some(dir.path())) {
                Err(RenderError::TemplateRead { source, .. }) => {
                    assert!(source.to_string().contains("symbolic link"), "{source}")
                }
                other => panic!("expected TemplateRead, got {other:?}"),
            }
        }
        // a directory at the name is refused too
        std::fs::create_dir(dir.path().join("docker.tmpl")).unwrap();
        assert!(matches!(
            render(CredFamily::Docker, TEST_ID, Some(dir.path())),
            Err(RenderError::TemplateRead { .. })
        ));
    }

    /// External audit DEC-016 (lab PR 178): a FIFO at a template's name used
    /// to block the deploy (and its admin connection) until a writer came.
    #[test]
    fn fifo_template_does_not_block() {
        let dir = TempDir::new().unwrap();
        let fifo = dir.path().join("aws.tmpl");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: mkfifo on a NUL-terminated path in our temp dir.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let (tx, rx) = std::sync::mpsc::channel();
        let template_dir = dir.path().to_path_buf();
        std::thread::spawn(move || {
            let _ = tx.send(render(CredFamily::Aws, TEST_ID, Some(&template_dir)).is_err());
        });
        let refused = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the render returns instead of blocking on the FIFO");
        assert!(refused, "a FIFO is not a template");
    }
}
