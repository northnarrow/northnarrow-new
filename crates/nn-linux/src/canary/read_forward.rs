//! Process-wide set of canary file inodes whose READ opens must reach
//! the rule engine.
//!
//! Why a global: the FIM drain (`fim::drain::process_drift`) drops every
//! `FimOp::Opened` on a non-credential watched path (BUG-012 v2 — a read
//! is not integrity drift). That gate is correct for `/etc/passwd`-style
//! watches but it also silenced the K3 file-canary detector: a decoy
//! deployed at an arbitrary path is "non-credential", so `cat decoy`
//! never produced an `Event::Fim` and NN-L-CANARY-001 never fired (lab
//! guest, 2026-10-08: `canary access log … held 0 rows`). The drain is
//! spawned before the canary state exists and its entry points are
//! already 8-argument functions shared with six unit-test call sites,
//! so the inode set is published here by [`CanaryIndexes`] rebuilds and
//! consulted by the drain, with no new wiring.
//!
//! [`CanaryIndexes`]: crate::canary::detector::CanaryIndexes

use std::collections::HashSet;
use std::sync::LazyLock;

use common::wire::InodeKey;
use parking_lot::RwLock;

static CANARY_INODES: LazyLock<RwLock<HashSet<InodeKey>>> =
    LazyLock::new(|| RwLock::new(HashSet::new()));

/// Replace the published set (called after every K3 index rebuild).
pub fn replace(keys: impl IntoIterator<Item = InodeKey>) {
    let mut set = CANARY_INODES.write();
    set.clear();
    set.extend(keys);
}

/// `true` if a read-open of `key` must be forwarded to the rule engine.
pub fn contains(key: &InodeKey) -> bool {
    CANARY_INODES.read().contains(key)
}

/// Number of published canary inodes (metrics / tests).
pub fn len() -> usize {
    CANARY_INODES.read().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_then_contains() {
        let a = InodeKey { dev: 7, ino: 1 };
        let b = InodeKey { dev: 7, ino: 2 };
        replace([a]);
        assert!(contains(&a));
        assert!(!contains(&b));
        replace([b]);
        assert!(!contains(&a));
        assert!(contains(&b));
        replace([]);
        assert_eq!(len(), 0);
    }
}
