//! Lot 314 (the third bug hunt, family F3 "state, windows and counts"): the
//! state machines tested as such. A model test drives a machine — the
//! posture, the corroboration ledger, a rule that fires once per process,
//! the exec policy's repeat table — with sequences of operations a seeded
//! generator draws, and checks the machine's invariants after every step
//! against an oracle of its own:
//! - a command toward the current state changes nothing (except the
//!   explicit COMBAT lock);
//! - a quiet window counts from the last signal;
//! - a "once" rule gives at most one verdict per key;
//! - every table has a cap.
//!
//! The generator is a SplitMix64 ([`Rng`]): no dependency, the same
//! sequences on every host and every run. A failing sequence is named by
//! its seed ([`check`]), and is replayed by that seed alone; the
//! counterexamples the lot found are cases of the golden replays.

/// Sequences each model test runs (CI runs them all: each machine's
/// sequences take a few seconds).
pub const SEQUENCES: u64 = 10_000;

/// SplitMix64 (Steele, Lea, Flood 2014): a 64-bit state, one addition and
/// a mix per draw.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A draw in `0..n` (`n` > 0).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n.max(1)
    }

    /// A draw in `lo..=hi`.
    pub fn range(&mut self, lo: u64, hi: u64) -> u64 {
        lo + self.below(hi - lo + 1)
    }

    /// `true` once in `n` draws, about.
    pub fn one_in(&mut self, n: u64) -> bool {
        self.below(n) == 0
    }

    /// One of `items` (not empty).
    pub fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len() as u64) as usize]
    }
}

/// Run `sequences` sequences of `name`'s model, one seed each (`base` +
/// the sequence's number): `run` returns `Err(what)` when an invariant
/// broke. Panics naming the machine, the seed and what broke.
pub fn check(
    name: &str,
    base: u64,
    sequences: u64,
    mut run: impl FnMut(&mut Rng) -> Result<(), String>,
) {
    for i in 0..sequences {
        let seed = base.wrapping_add(i);
        if let Err(what) = run(&mut Rng::new(seed)) {
            panic!("{name}: the model's sequence of seed {seed:#x} broke an invariant: {what}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generator_is_the_same_on_every_run() {
        let mut a = Rng::new(7);
        let mut b = Rng::new(7);
        let xs: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        let ys: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
        assert_eq!(xs, ys);
        // SplitMix64's first draw from seed 0 (the reference value)
        assert_eq!(Rng::new(0).next_u64(), 0xE220_A839_7B1D_CDAF);
        let mut r = Rng::new(1);
        assert!((0..1000).all(|_| r.range(3, 5) >= 3 && r.range(3, 5) <= 5));
    }

    #[test]
    #[should_panic(expected = "seed 0x2a broke an invariant: odd")]
    fn a_broken_invariant_names_its_seed() {
        check("demo", 40, 3, |rng| {
            if rng.clone().next_u64() == Rng::new(42).next_u64() {
                Err("odd".into())
            } else {
                Ok(())
            }
        });
    }
}
