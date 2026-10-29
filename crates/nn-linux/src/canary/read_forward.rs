//! The set of canary file inodes whose READ opens must reach the rule
//! engine.
//!
//! The FIM drain (`fim::drain::process_drift`) drops every `FimOp::Opened`
//! on a non-credential watched path (BUG-012 v2 — a read is not integrity
//! drift). That gate is correct for `/etc/passwd`-style watches but it
//! also silenced the K3 file-canary detector: a decoy deployed at an
//! arbitrary path is "non-credential", so `cat decoy` never produced an
//! `Event::Fim` and NN-L-CANARY-001 never fired (lab guest, 2026-10-08:
//! `canary access log … held 0 rows`). The canary indexes publish the
//! decoys' inodes here at every rebuild ([`CanaryIndexes`]), and the drain
//! forwards their reads.
//!
//! R11c (lab PR 264): the set is the FIM drain's own (its `InodePathMap`
//! holds it), which the start gives the canary indexes; it was a
//! process-wide set "with no new wiring", which every test's indexes
//! published into and every drain read.
//!
//! [`CanaryIndexes`]: nn_core::canary::detector::CanaryIndexes

use std::collections::HashSet;
use std::sync::Arc;

use common::wire::InodeKey;
use parking_lot::RwLock;

/// The published inodes. Clones share them.
#[derive(Clone, Debug, Default)]
pub struct ReadForward(Arc<RwLock<HashSet<InodeKey>>>);

impl ReadForward {
    /// An empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the published set (called after every K3 index rebuild).
    pub fn replace(&self, keys: impl IntoIterator<Item = InodeKey>) {
        let mut set = self.0.write();
        set.clear();
        set.extend(keys);
    }

    /// `true` if a read-open of `key` must be forwarded to the rule engine.
    pub fn contains(&self, key: &InodeKey) -> bool {
        self.0.read().contains(key)
    }

    /// Number of published canary inodes (metrics / tests).
    pub fn len(&self) -> usize {
        self.0.read().len()
    }

    /// No canary inode is published.
    pub fn is_empty(&self) -> bool {
        self.0.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replace_then_contains() {
        let a = InodeKey { dev: 7, ino: 1 };
        let b = InodeKey { dev: 7, ino: 2 };
        let set = ReadForward::new();
        let drain = set.clone();
        set.replace([a]);
        assert!(drain.contains(&a));
        assert!(!drain.contains(&b));
        set.replace([b]);
        assert!(!drain.contains(&a));
        assert!(drain.contains(&b));
        assert!(!ReadForward::new().contains(&b), "another set is its own");
        set.replace([]);
        assert_eq!(drain.len(), 0);
        assert!(drain.is_empty());
    }
}
