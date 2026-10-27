//! The operating system's CSPRNG as an infallible generator (lab PR 234).
//!
//! rand 0.10 removed `rand::rngs::OsRng`. Its successor, `SysRng`, is the
//! same source — getrandom, i.e. the `getrandom(2)` syscall on Linux, with
//! the `/dev/urandom` fallback after polling `/dev/random` — but fallible:
//! it implements `TryRng`, and `SigningKey::generate` or `fill_bytes` want
//! an infallible `CryptoRng`. [`OsRng`] is that adapter: every byte comes
//! straight from `SysRng`, with no buffer and no userland PRNG in between,
//! and a getrandom failure panics, as rand 0.8's `OsRng` did.
//!
//! Keys, nonces, challenges and seeds use it (or `SysRng` directly where
//! the caller handles the error: `agent_id`, `audit`, `telemetry_probe`).
//! Never `rand::rng()` (`ThreadRng`, a ChaCha reseeded from the OS) for
//! that material: a key must not depend on a userland generator's state.

use core::convert::Infallible;

use rand::rngs::{SysError, SysRng};
use rand::{TryCryptoRng, TryRng};

/// The OS CSPRNG (getrandom). A zero-sized, stateless handle: construct it
/// as `OsRng`, as with rand 0.8.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRng;

#[cold]
#[inline(never)]
fn os_rng_failed(e: SysError) -> ! {
    panic!("the OS random number generator failed: {e}")
}

impl TryRng for OsRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(SysRng.try_next_u32().unwrap_or_else(|e| os_rng_failed(e)))
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(SysRng.try_next_u64().unwrap_or_else(|e| os_rng_failed(e)))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        SysRng
            .try_fill_bytes(dst)
            .unwrap_or_else(|e| os_rng_failed(e));
        Ok(())
    }
}

// `SysRng` is a `TryCryptoRng`; `OsRng` adds nothing but the panic.
impl TryCryptoRng for OsRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{CryptoRng, Rng};

    fn assert_crypto_rng<R: CryptoRng>(_: &mut R) {}

    #[test]
    fn os_rng_is_an_infallible_crypto_rng() {
        assert_crypto_rng(&mut OsRng);
        // What the 102 `SigningKey::generate(&mut OsRng)` sites need.
        let a = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let b = ed25519_dalek::SigningKey::generate(&mut OsRng);
        assert_ne!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn os_rng_fills_every_byte_and_never_repeats() {
        // 2^-256 per draw to be all zero or equal: a failure is a broken
        // source, not bad luck.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut a);
        OsRng.fill_bytes(&mut b);
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
        assert_ne!(OsRng.next_u64(), OsRng.next_u64());
        // Longer than one getrandom block, filled to the end.
        let mut big = vec![0u8; 4096];
        OsRng.fill_bytes(&mut big);
        assert_ne!(big[4064..], [0u8; 32]);
    }
}
