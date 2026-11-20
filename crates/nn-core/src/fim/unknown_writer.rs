//! Lot 373 (the rc7 soak's NN-L-FIM-024 at every boot): a creation of a
//! watched file that no kernel record reported — the drain found the file
//! at a look (`nn_linux::fim::drain`'s `returned_raw`: a file of the watch list absent at the
//! start, or one back at a path it was renamed away from), its writer
//! unknown (`modifier_pid` 0, no `comm`).
//!
//! What the drain cannot know it does not invent: such a creation is judged
//! on what it can read, the file's content. The drain reads the content of
//! a bait it found so ([`keep`]); NN-L-FIM-024 and the posture's
//! `ControlSurfaceTamper` raise no Critical and no COMBAT on the unknown
//! writer alone ([`benign_bait`]): a bait that holds what the agent and the
//! install write is recorded High, "writer unknown". A bait whose content
//! is anything else (`paused=true`) — or could not be read — is an attempt
//! on the control surface: Critical, as before. A creation a kernel record
//! reported names its writer and is judged as before (a root shell's
//! `touch` of a bait is Critical).

use std::collections::{HashMap, VecDeque};
use std::sync::LazyLock;

use nn_model::telemetry::{FimEvent, FimOp};
use parking_lot::Mutex;

/// `fe` is a creation no kernel record reported: the drain's own record of
/// a file found at a look (the kernel's records always carry the writer's
/// thread-group id, never 0).
pub fn writer_unknown(fe: &FimEvent) -> bool {
    fe.modifier_pid == 0 && fe.op == FimOp::Created
}

/// The facts kept at most (the oldest out): the decision reads one right
/// after the drain sent its event.
pub const KEPT: usize = 256;

/// (the record's time, the file): one creation.
type Key = (u64, String);

#[derive(Default)]
struct Kept {
    own_content: HashMap<Key, bool>,
    order: VecDeque<Key>,
}

static FACTS: LazyLock<Mutex<Kept>> = LazyLock::new(Default::default);

fn key(fe: &FimEvent) -> Key {
    (fe.timestamp_ns, fe.path.clone())
}

/// The drain's call, for a creation whose writer it cannot know
/// ([`writer_unknown`]): `own_content` — the file it read holds the bait
/// of its path as the agent and the install write it
/// (`crate::fim::baits::is_bait_rendering`).
pub fn keep(fe: &FimEvent, own_content: bool) {
    if !writer_unknown(fe) {
        return;
    }
    let k = key(fe);
    let mut kept = FACTS.lock();
    if kept.own_content.insert(k.clone(), own_content).is_none() {
        kept.order.push_back(k);
    }
    while kept.order.len() > KEPT {
        if let Some(old) = kept.order.pop_front() {
            kept.own_content.remove(&old);
        }
    }
}

/// `fe` is a bait created with no record of its writer that holds the
/// bait's own content, as the drain read it: no hostile content, and no
/// writer to act on — High at most, no COMBAT. `false` for a creation a
/// kernel record reported, a content not the bait's, one not read.
pub fn benign_bait(fe: &FimEvent) -> bool {
    writer_unknown(fe) && FACTS.lock().own_content.get(&key(fe)).copied() == Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn created(pid: u32, ts: u64, path: &str) -> FimEvent {
        FimEvent {
            timestamp_ns: ts,
            path: path.to_string(),
            op: FimOp::Created,
            new_sha256: None,
            baseline_sha256: None,
            new_size: None,
            baseline_size: None,
            modifier_exe: None,
            modifier_pid: pid,
            modifier_uid: 0,
            modifier_comm: String::new(),
            dest_path: None,
            child_truncated: false,
            wide_coverage: false,
            owner_uid: None,
            reader_dac_capable: false,
            capability: None,
            attrs: None,
            file_key: None,
            is_dir: false,
            moved_in: false,
            appends_only: false,
            truncated_by_another: false,
            unchanged_since_read: false,
            renamed_away: false,
            modifier_start: 0,
        }
    }

    /// Only the drain's own creations are kept, and only an own content
    /// read is benign; a kernel record's writer is never "unknown".
    #[test]
    fn only_an_unknown_writer_s_own_content_is_benign() {
        let p = "/run/northnarrow/pause.flag";
        let own = created(0, 7_000_001, p);
        let foreign = created(0, 7_000_002, p);
        let unread = created(0, 7_000_003, p);
        let by_shell = created(4242, 7_000_004, p);
        keep(&own, true);
        keep(&foreign, false);
        keep(&by_shell, true);
        assert!(benign_bait(&own));
        assert!(!benign_bait(&foreign), "a hostile content");
        assert!(!benign_bait(&unread), "a content not read");
        assert!(!benign_bait(&by_shell), "a writer the kernel named");
        let mut modified = own.clone();
        modified.op = FimOp::Modified;
        assert!(!benign_bait(&modified), "only a creation");
    }
}
