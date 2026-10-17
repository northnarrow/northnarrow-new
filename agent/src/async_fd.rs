//! Registering an fd-owning object with tokio's reactor.
//!
//! tokio 1.53.3 deprecated `AsyncFd::new` / `try_new` / `with_interest` as
//! unsound (tokio#8587): nothing in their signature required the fd to stay
//! open and to keep naming the same file description while the `AsyncFd`
//! lives. `AsyncFd::register` states that contract as `unsafe`. Every
//! caller here passes an object that owns its fd for its whole life — an
//! aya `RingBuf` holds its map's fd, the `AsyncFd` holds the `RingBuf` —
//! so the contract is met by ownership; this module is the one place the
//! agent says so.

use std::io;
use std::os::fd::AsRawFd;

use tokio::io::unix::AsyncFd;

/// `AsyncFd::register(inner)`, readable and writable interest, for an
/// `inner` that owns its fd (the ring buffers of the sensors).
pub fn register<T: AsRawFd>(inner: T) -> io::Result<AsyncFd<T>> {
    // SAFETY: `inner` owns its file descriptor (an aya `RingBuf` keeps its
    // map's fd open until it is dropped and always returns the same one
    // from `as_raw_fd`), and the returned `AsyncFd` owns `inner`: the fd is
    // open, and names the same file description, for the whole life of the
    // `AsyncFd`.
    unsafe { AsyncFd::register(inner) }.map_err(io::Error::from)
}
