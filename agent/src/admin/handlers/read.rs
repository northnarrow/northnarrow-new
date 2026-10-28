//! The read verbs' bounded reads (R11d, lab PR 263: from
//! `admin_socket.rs`): the newest rows of a chain log, its rotated archives
//! included.

use std::path::Path;

use nn_proto::admin_protocol::MAX_FRAME_BODY;

/// Half a frame: the rest of a read verb's response fits in the other
/// half.
pub(in crate::admin) const READ_VERB_SOFT_CAP: usize = MAX_FRAME_BODY / 2;

/// External audit NN-AUD-080: the body of a read verb — the newest rows
/// of the chain log whose active file is `path` (the active file, then
/// its rotated archives), newest first, within [`READ_VERB_SOFT_CAP`] and
/// `max_rows`. With `since` (UNIX seconds), rows whose `ts` is earlier are
/// left out. `keep` selects rows by their raw line. Returns `(jsonl_body,
/// count, truncated)`; `truncated` means older matching rows were left
/// out. The read bounds are in [`crate::chain_tail`].
pub(in crate::admin) fn read_tail_jsonl(
    path: &Path,
    since: Option<u64>,
    keep: Option<&dyn Fn(&str) -> bool>,
    max_rows: usize,
) -> (String, u32, bool) {
    let since = since.map(format_iso8601_unix);
    let tail = crate::chain_tail::read_chain_tail::<crate::chain_host_linux::LinuxHost>(
        path,
        &crate::chain_tail::TailQuery {
            since: since.as_deref(),
            keep,
            soft_cap: READ_VERB_SOFT_CAP,
            max_rows,
        },
    );
    (tail.jsonl, tail.count, tail.truncated)
}

fn format_iso8601_unix(unix_ts: u64) -> String {
    use chrono::TimeZone;
    chrono::Utc
        .timestamp_opt(unix_ts as i64, 0)
        .single()
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S").to_string())
        .unwrap_or_else(|| "1970-01-01T00:00:00".to_string())
}

/// Extract the `ts` field from a JSONL drift entry without a
/// full JSON parse. Returns the string between the value's
/// opening + closing `"` quotes. Returns `None` on a malformed
/// line — the caller treats that as "include the entry" to
/// avoid silently dropping evidence the operator might need.
pub(in crate::admin) fn extract_ts_field(line: &str) -> Option<String> {
    // Expected shape: {"ts":"<iso8601>", ...
    // We find `"ts":"` and then the next `"`.
    let key = "\"ts\":\"";
    let start = line.find(key)? + key.len();
    let end = line[start..].find('"')?;
    Some(line[start..start + end].to_string())
}
