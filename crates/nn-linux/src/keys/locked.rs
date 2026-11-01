//! The memory a key lives in (Wave 4 restructure, R14c — plan §3.3).
//!
//! [`Locked`] puts one value — the agent's signing key, the vault's master
//! key — in an anonymous mapping of its own: locked in RAM (`mlock`: never
//! written to swap), left out of any core dump (`MADV_DONTDUMP`, beside the
//! process's `PR_SET_DUMPABLE 0` and the unit's `LimitCORE=0`), and on drop
//! the value's own drop (ed25519's key zeroizes itself), then every byte of
//! the mapping zeroed (volatile writes) before it is unlocked and unmapped.
//!
//! What a caller can hold is a reference through the handle the key store
//! hands out; nothing here returns the bytes. The copies a value leaves on
//! the stack while it is built (the decode of a key file, a move into the
//! mapping) are the language's and are cut short where the code has them:
//! the decoded bytes are zeroized after the move.

use std::io;
use std::ops::Deref;
use std::ptr::NonNull;

/// One value in locked, undumpable memory of its own.
pub struct Locked<T> {
    ptr: NonNull<T>,
    map_len: usize,
    locked: bool,
    dontdump: bool,
}

// SAFETY: the mapping is owned by this value alone; access goes through
// `&self` (shared) like any `Box<T>`'s.
unsafe impl<T: Send> Send for Locked<T> {}
// SAFETY: as above.
unsafe impl<T: Sync> Sync for Locked<T> {}

impl<T> Locked<T> {
    /// `value` moved into a mapping of its own; an error only when the
    /// mapping itself cannot be made. A lock or advice the kernel refuses
    /// is kept in [`Self::locked`] / [`Self::dontdump`] (the caller says it).
    pub fn new(value: T) -> io::Result<Self> {
        // SAFETY: sysconf has no preconditions.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .ok()
            .filter(|p| *p > 0)
            .unwrap_or(4096);
        let need = std::mem::size_of::<T>().max(1);
        let map_len = need.div_ceil(page) * page;
        debug_assert!(std::mem::align_of::<T>() <= page);
        // SAFETY: a fresh private anonymous mapping, no address hint.
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                map_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: mlock / madvise on the mapping just made.
        let (locked, dontdump) = unsafe {
            (
                libc::mlock(p, map_len) == 0,
                libc::madvise(p, map_len, libc::MADV_DONTDUMP) == 0,
            )
        };
        let ptr = NonNull::new(p.cast::<T>()).expect("mmap returned a non-null address");
        // SAFETY: the mapping is page-aligned (T's alignment is at most a
        // page), large enough, writable, and holds no value yet.
        unsafe { ptr.as_ptr().write(value) };
        Ok(Self {
            ptr,
            map_len,
            locked,
            dontdump,
        })
    }

    /// The mapping is locked in RAM (`mlock`).
    pub fn locked(&self) -> bool {
        self.locked
    }

    /// The mapping is left out of core dumps (`MADV_DONTDUMP`).
    pub fn dontdump(&self) -> bool {
        self.dontdump
    }
}

impl<T> Deref for Locked<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the value was written in `new` and lives until `drop`.
        unsafe { self.ptr.as_ref() }
    }
}

impl<T> Drop for Locked<T> {
    fn drop(&mut self) {
        let base = self.ptr.as_ptr().cast::<u8>();
        // SAFETY: the value is dropped once, here; then every byte of the
        // mapping is zeroed with volatile writes (not elided), and the
        // mapping is unlocked and unmapped (nothing refers to it after).
        unsafe {
            std::ptr::drop_in_place(self.ptr.as_ptr());
            for i in 0..self.map_len {
                std::ptr::write_volatile(base.add(i), 0u8);
            }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            if self.locked {
                libc::munlock(base.cast(), self.map_len);
            }
            libc::munmap(base.cast(), self.map_len);
        }
    }
}

impl<T> std::fmt::Debug for Locked<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Locked")
            .field("bytes", &self.map_len)
            .field("locked", &self.locked)
            .field("dontdump", &self.dontdump)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The value is there, in its own page, out of the dumps (`dd` in
    /// `VmFlags`) and locked when the kernel let it (`lo`; one page is within
    /// any default `RLIMIT_MEMLOCK`).
    #[test]
    fn a_value_is_kept_locked_and_zeroed_on_drop() {
        let l = Locked::new([0x5au8; 32]).unwrap();
        assert_eq!(*l, [0x5au8; 32]);
        assert!(l.dontdump(), "MADV_DONTDUMP");
        let addr = l.ptr.as_ptr() as usize;
        assert_eq!(addr % 4096, 0, "a mapping of its own");
        // /proc/self/smaps: the area holding it (the kernel may have merged
        // it with a neighbour of the same flags) is out of the dumps, and
        // locked when mlock succeeded
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let holds = |line: &str| {
            let range = line.split_whitespace().next().unwrap_or("");
            let Some((a, b)) = range.split_once('-') else {
                return false;
            };
            match (usize::from_str_radix(a, 16), usize::from_str_radix(b, 16)) {
                (Ok(a), Ok(b)) => a <= addr && addr < b,
                _ => false,
            }
        };
        let block: Vec<&str> = smaps
            .split('\n')
            .skip_while(|line| !holds(line))
            .take(30)
            .collect();
        assert!(!block.is_empty(), "the mapping is listed");
        let vm_flags = block.iter().find(|l| l.starts_with("VmFlags:")).unwrap();
        assert!(vm_flags.contains(" dd"), "{vm_flags}");
        if l.locked() {
            assert!(vm_flags.contains(" lo"), "{vm_flags}");
        }
        drop(l);
    }

    #[test]
    fn a_value_with_its_own_drop_is_dropped_once() {
        use std::sync::atomic::{AtomicU32, Ordering};
        static DROPS: AtomicU32 = AtomicU32::new(0);
        struct D(u64);
        impl Drop for D {
            fn drop(&mut self) {
                assert_eq!(self.0, 7);
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }
        drop(Locked::new(D(7)).unwrap());
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    }
}
