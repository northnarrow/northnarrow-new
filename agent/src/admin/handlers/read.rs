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

/// The latest time the rows' fixed-width `ts` can say (a four-digit year).
const LAST_TS: &str = "9999-12-31T23:59:59";

/// `since` as the rows' `ts` prefix, compared as text. Lot 319 (the
/// mini-hunt of BUG12's partial): `unix_ts as i64` — a `since` of 2^63 or
/// more turned negative, a time before 1970, and one past year 9999 was
/// beyond chrono's range or formatted `+10000-…`, which sorts before every
/// row; both answered with every row instead of none. A `since` past the
/// last time a row can carry keeps no row.
fn format_iso8601_unix(unix_ts: u64) -> String {
    use chrono::TimeZone;
    i64::try_from(unix_ts)
        .ok()
        .and_then(|t| chrono::Utc.timestamp_opt(t, 0).single())
        .map(|dt| dt.format("%Y-%m-%dT%H:%M:%S").to_string())
        .filter(|s| s.len() == LAST_TS.len() && s.as_str() <= LAST_TS)
        .unwrap_or_else(|| LAST_TS.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Lot 319 (the mini-hunt of BUG12's partial): a `since` past what a
    /// row's time can say keeps no row — it kept every row.
    #[test]
    fn a_since_past_any_row_keeps_none() {
        assert_eq!(format_iso8601_unix(0), "1970-01-01T00:00:00");
        assert_eq!(format_iso8601_unix(1_762_900_000), "2025-11-11T22:26:40");
        assert_eq!(format_iso8601_unix(253_402_300_799), LAST_TS);
        let row = "2026-11-11T21:00:00.000000Z";
        for huge in [
            253_402_300_800,
            1u64 << 40,
            i64::MAX as u64,
            1u64 << 63,
            u64::MAX,
        ] {
            let since = format_iso8601_unix(huge);
            assert!(row < since.as_str(), "{huge}: {since} keeps a 2026 row");
        }
    }
}
