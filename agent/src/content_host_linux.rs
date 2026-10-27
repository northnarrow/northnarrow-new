//! The Linux host of the content lists: the open of [`ContentHost`], as the
//! content code made it itself before R07 (Wave 4 restructure, lab PR 247):
//! an operator overlay or a shipped `.v1` list (`config::overlay_auth`'s
//! `read_overlay`), an operator canary template (`canary::templates`'
//! `read_template`), with the same flags. The host is the chains' one
//! ([`LinuxHost`], `chain_host_linux`): one type, the agent's.
//!
//! Its tests read through the agent's loaders and renderer bound to this
//! host: they are the agent's (`content_host_tests`, R09a, lab PR 253).

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
