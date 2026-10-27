//! What the content lists need from the host that reads them (Wave 4
//! restructure, R07, lab PR 247).
//!
//! The lists, their operator overlays and the canary templates are parsed
//! and merged the same way on every platform. One thing is not, and it is
//! here as a trait the host implements (the agent: `LinuxHost`, in its
//! `content_host_linux` module): an open that does not follow a final
//! symlink and does not block on a FIFO planted at the name
//! (`O_NOFOLLOW | O_NONBLOCK`), which portable `std` cannot spell. An
//! operator overlay and a shipped `.v1` list are read that way (external
//! audit LLMR-013, LLMR-015), and so is an operator's canary template
//! (DEC-016). The calls are the ones the content code made itself before
//! R07: lab PR 247 moved them, not their arguments.
//!
//! The host is a type parameter of the functions that read (as
//! `nn_evidence::chain_host::ChainHost` is of the chains'): no state, no
//! global, nothing to register.

use std::fs::File;
use std::io;
use std::path::Path;

/// The host's file operations the content code uses.
pub trait ContentHost: 'static {
    /// Open `path` for reading without following a final symlink and
    /// without blocking on a FIFO.
    fn open_read_nofollow(path: &Path) -> io::Result<File>;

    /// `err` is how [`Self::open_read_nofollow`] refuses a final symlink.
    fn is_symlink_refusal(err: &io::Error) -> bool;
}
