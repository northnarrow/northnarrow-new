//! Lot 332 (the review of #551, F1): the host's subordinate uid ranges
//! (`/etc/subuid`) for the key of the shares (`agent-ebpf`'s
//! `task_scratch::nn_share_key`, `common::wire::execq::share_key`).
//!
//! A user with a range can make a binary owned by any uid N of it setuid
//! (`chown` inside a user namespace it made, where N is mapped), run it in
//! the initial namespace and take N as its real uid (`setresuid`), or make
//! a namespace whose creator is N: 65,536 keys of its own, a row each, and
//! about 67 rows fill the candidates' map (the global cap holds back
//! greedy shares only). The agent publishes the ranges into an LPM trie
//! (`SHARE_SUBUID`: the uid big-endian → the owner's uid), and the kernel
//! looks the uid, or the namespace's creator, up there first.
//!
//! - Fail closed. The ranges' whole span is published first as the
//!   overflow row's ([`OVERFLOW_SHARE`]), then each part of it that one
//!   resolved owner holds, as longer prefixes: a uid of the span no single
//!   owner is known for (an owner name `/etc/passwd` does not resolve, two
//!   users' ranges overlapping, a gap, a range the trie had no room for)
//!   is the overflow row's — one row under the same cap — never a row of
//!   its own. A `/etc/subuid` that cannot be read (other than missing)
//!   puts every uid from 65,536 up there.
//! - Bounded: [`SUBUID_TRIE_MAX`] entries (about 1,300 users' useradd ranges);
//!   past them the ranges are the overflow row's, counted in the log.
//! - Refreshed: both files' stamps (device, inode, modification time,
//!   size) are checked every [`REFRESH`], and the trie is rewritten when
//!   either changed — a range added a moment ago is keyed by its uids
//!   until then.
//!
//! `/etc/subgid` is not read: the key is a uid (the real uid, a
//! namespace's creator), never a gid.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::MapData;
use aya::Ebpf;
use common::wire::execq::{OVERFLOW_SHARE, SUBUID_TRIE_MAX};
use tracing::{info, warn};

/// The trie (`agent-ebpf/src/task_scratch.rs`).
pub const MAP: &str = "SHARE_SUBUID";
/// The ranges, and the accounts their owners' names resolve through.
pub const SUBUID: &str = "/etc/subuid";
const PASSWD: &str = "/etc/passwd";
/// How often the files' stamps are checked.
pub const REFRESH: Duration = Duration::from_secs(2);
/// The most of either file read; a longer `/etc/subuid` is unreadable
/// (fail closed: the ranges past it would be unknown).
const READ_MAX: u64 = 16 << 20;
/// The classic 16-bit account space: below it no uid is held to the
/// overflow row when `/etc/subuid` cannot be read.
pub const ACCOUNTS_END: u64 = 65_536;
const UID_END: u64 = 1 << 32;

/// One line of `/etc/subuid`: `[start, end)`, and the uid of its owner
/// when `/etc/passwd` (or a numeric owner field) resolves it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub owner: Option<u32>,
    pub start: u64,
    pub end: u64,
}

/// The ranges of an `/etc/subuid` text (`owner:start:count`; the owner a
/// name or a uid, as `newuidmap` matches it). Comments, empty and malformed
/// lines, and empty ranges are skipped: `newuidmap` grants none of them.
pub fn ranges(subuid: &str, passwd: &str) -> Vec<Range> {
    let mut names: BTreeMap<&str, u32> = BTreeMap::new();
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 || f[0].is_empty() || f[0].starts_with('+') || f[0].starts_with('-') {
            continue;
        }
        if let Ok(uid) = f[2].parse::<u32>() {
            names.entry(f[0]).or_insert(uid);
        }
    }
    let mut out = Vec::new();
    for line in subuid.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split(':').collect();
        if f.len() != 3 || f[0].is_empty() {
            continue;
        }
        let (Ok(start), Ok(count)) = (f[1].parse::<u32>(), f[2].parse::<u64>()) else {
            continue;
        };
        if count == 0 {
            continue;
        }
        let owner = names
            .get(f[0])
            .copied()
            .or_else(|| f[0].parse::<u32>().ok());
        let start = u64::from(start);
        out.push(Range {
            owner,
            start,
            end: start.saturating_add(count).min(UID_END),
        });
    }
    out
}

/// `[start, end)` (within `[0, 2^32]`) as the fewest aligned prefixes:
/// `(prefix length, base)`.
pub fn prefixes(start: u64, end: u64) -> Vec<(u32, u32)> {
    let mut out = Vec::new();
    let end = end.min(UID_END);
    let mut s = start;
    while s < end {
        let mut size = if s == 0 {
            UID_END
        } else {
            1u64 << s.trailing_zeros()
        };
        while size > end - s {
            size >>= 1;
        }
        out.push((32 - size.trailing_zeros(), s as u32));
        s += size;
    }
    out
}

/// What the trie holds: `(prefix length, base) → value` (an owner's uid,
/// or [`OVERFLOW_SHARE`]).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Table {
    pub entries: BTreeMap<(u32, u32), u32>,
    /// Ranges read.
    pub ranges: usize,
    /// Parts of the span one owner holds that the trie had no room for
    /// (the overflow row's).
    pub unplaced: usize,
    /// `/etc/subuid` could not be read: every uid from [`ACCOUNTS_END`] up
    /// is the overflow row's.
    pub unreadable: bool,
}

/// The trie for `ranges`, at most `cap` entries: the span's own entries
/// (the overflow row's) first, then each part of it one resolved owner
/// holds alone.
pub fn table(ranges: &[Range], cap: usize) -> Table {
    let mut t = Table {
        ranges: ranges.len(),
        ..Table::default()
    };
    let (Some(lo), Some(hi)) = (
        ranges.iter().map(|r| r.start).min(),
        ranges.iter().map(|r| r.end).max(),
    ) else {
        return t;
    };
    for p in prefixes(lo, hi) {
        t.entries.insert(p, OVERFLOW_SHARE);
    }
    for (start, end, owner) in owned_parts(ranges) {
        let ps = prefixes(start, end);
        let new = ps.iter().filter(|p| !t.entries.contains_key(p)).count();
        if t.entries.len() + new > cap {
            t.unplaced += 1;
            continue;
        }
        for p in ps {
            t.entries.insert(p, owner);
        }
    }
    t
}

/// The trie when `/etc/subuid` cannot be read: every uid from
/// [`ACCOUNTS_END`] up is the overflow row's.
pub fn unreadable() -> Table {
    Table {
        entries: prefixes(ACCOUNTS_END, UID_END)
            .into_iter()
            .map(|p| (p, OVERFLOW_SHARE))
            .collect(),
        unreadable: true,
        ..Table::default()
    }
}

/// The parts of the ranges' span one resolved owner holds alone, merged
/// where adjacent: `(start, end, owner)`.
fn owned_parts(ranges: &[Range]) -> Vec<(u64, u64, u32)> {
    let mut bounds: Vec<u64> = ranges.iter().flat_map(|r| [r.start, r.end]).collect();
    bounds.sort_unstable();
    bounds.dedup();
    let mut starts: Vec<&Range> = ranges.iter().collect();
    starts.sort_by_key(|r| r.start);
    let mut ends: Vec<&Range> = ranges.iter().collect();
    ends.sort_by_key(|r| r.end);
    let (mut si, mut ei) = (0, 0);
    // the owners covering the current part (None: unresolved), counted
    let mut active: BTreeMap<Option<u32>, usize> = BTreeMap::new();
    let mut out: Vec<(u64, u64, u32)> = Vec::new();
    for w in bounds.windows(2) {
        let (b, next) = (w[0], w[1]);
        while ei < ends.len() && ends[ei].end <= b {
            if let Some(n) = active.get_mut(&ends[ei].owner) {
                *n -= 1;
                if *n == 0 {
                    active.remove(&ends[ei].owner);
                }
            }
            ei += 1;
        }
        while si < starts.len() && starts[si].start <= b {
            *active.entry(starts[si].owner).or_insert(0) += 1;
            si += 1;
        }
        let owner = match active.keys().collect::<Vec<_>>()[..] {
            [Some(o)] => *o,
            _ => continue,
        };
        match out.last_mut() {
            Some(last) if last.1 == b && last.2 == owner => last.1 = next,
            _ => out.push((b, next, owner)),
        }
    }
    out
}

/// The trie's answer for `uid` (its longest matching prefix), as the
/// kernel's lookup gives it.
pub fn lookup(entries: &BTreeMap<(u32, u32), u32>, uid: u32) -> Option<u32> {
    entries
        .iter()
        .filter(|((len, base), _)| *len == 0 || (u64::from(uid ^ base) >> (32 - len)) == 0)
        .max_by_key(|((len, _), _)| *len)
        .map(|(_, v)| *v)
}

/// The trie as [`write_trie`] writes it (a trait, so a test can stand in).
pub trait SubuidTrie {
    fn keys(&self) -> Result<Vec<(u32, u32)>>;
    fn remove(&mut self, key: (u32, u32)) -> Result<()>;
    fn insert(&mut self, key: (u32, u32), value: u32) -> Result<()>;
}

impl SubuidTrie for LpmTrie<MapData, [u8; 4], u32> {
    fn keys(&self) -> Result<Vec<(u32, u32)>> {
        Ok(LpmTrie::keys(self)
            .take(SUBUID_TRIE_MAX as usize)
            .filter_map(|k| k.ok())
            .map(|k| (k.prefix_len(), u32::from_be_bytes(k.data())))
            .collect())
    }
    fn remove(&mut self, (len, base): (u32, u32)) -> Result<()> {
        Ok(LpmTrie::remove(self, &Key::new(len, base.to_be_bytes()))?)
    }
    fn insert(&mut self, (len, base): (u32, u32), value: u32) -> Result<()> {
        Ok(LpmTrie::insert(
            self,
            &Key::new(len, base.to_be_bytes()),
            value,
            0,
        )?)
    }
}

/// Rewrite `trie` to `t`: the keys `t` does not hold removed, then every
/// entry of `t` written (a key both hold is overwritten in place, never
/// absent).
pub fn write_trie(trie: &mut impl SubuidTrie, t: &Table) -> Result<()> {
    for k in trie.keys()? {
        if !t.entries.contains_key(&k) {
            trie.remove(k)?;
        }
    }
    for (k, v) in &t.entries {
        trie.insert(*k, *v)?;
    }
    Ok(())
}

/// The trie for the host's files as read now.
fn read_table() -> Table {
    table_of(read(SUBUID), read(PASSWD))
}

/// The trie for `/etc/subuid` and `/etc/passwd` as read: no ranges when
/// the first is missing; every uid from [`ACCOUNTS_END`] up the overflow
/// row's when it cannot be read; owner names unresolved (their ranges the
/// overflow row's) when the second cannot.
fn table_of(subuid: std::io::Result<String>, passwd: std::io::Result<String>) -> Table {
    let passwd = passwd.unwrap_or_default();
    match subuid {
        Ok(text) => table(&ranges(&text, &passwd), SUBUID_TRIE_MAX as usize),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Table::default(),
        Err(e) => {
            warn!(
                error = %e,
                "shares: {SUBUID} unreadable — every uid from {ACCOUNTS_END} up shares the \
                 overflow row"
            );
            unreadable()
        }
    }
}

fn read(path: &str) -> std::io::Result<String> {
    crate::response::on_host_path(Path::new(path), |p| {
        let mut s = Vec::new();
        std::fs::File::open(p)?
            .take(READ_MAX + 1)
            .read_to_end(&mut s)?;
        within_read_max(s)
    })
}

/// A file's bytes as text, or an error past [`READ_MAX`] (the ranges past
/// it would be unknown: the caller fails closed).
fn within_read_max(bytes: Vec<u8>) -> std::io::Result<String> {
    if bytes.len() as u64 > READ_MAX {
        return Err(std::io::Error::other("longer than the most read"));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

type Stamps = (crate::accounts::Stamp, crate::accounts::Stamp);

/// The publisher's state: the files' stamps last published, and what was
/// last said in the journal.
#[derive(Default)]
struct Publisher {
    done: Option<Stamps>,
    said: Option<(usize, usize, usize, bool)>,
}

impl Publisher {
    /// Publish again when either file changed, the last write failed, or
    /// `/etc/subuid` could not be read (a passing error is not kept).
    fn tick(&mut self, trie: &mut impl SubuidTrie) {
        let now = (
            crate::accounts::stamp(SUBUID),
            crate::accounts::stamp(PASSWD),
        );
        let _ = self.tick_with(now, read_table, trie);
    }

    /// [`Self::tick`] on given stamps and reader; whether the journal was
    /// told (only when what was published changed: an unreadable file read
    /// again every [`REFRESH`] is said once).
    fn tick_with(
        &mut self,
        now: Stamps,
        read: impl FnOnce() -> Table,
        trie: &mut impl SubuidTrie,
    ) -> bool {
        if self.done == Some(now) {
            return false;
        }
        let t = read();
        let mut told = false;
        match write_trie(trie, &t) {
            Ok(()) => {
                let said = (t.ranges, t.entries.len(), t.unplaced, t.unreadable);
                if self.said != Some(said) {
                    info!(
                        ranges = t.ranges,
                        entries = t.entries.len(),
                        unplaced = t.unplaced,
                        unreadable = t.unreadable,
                        "shares: subordinate uid ranges published (a user's subuids share its row)"
                    );
                    if t.unplaced > 0 {
                        warn!(
                            unplaced = t.unplaced,
                            "shares: subordinate uid ranges past the trie's room share the overflow row"
                        );
                    }
                    self.said = Some(said);
                    told = true;
                }
                self.done = (!t.unreadable).then_some(now);
            }
            Err(e) => {
                warn!(
                    error = format!("{e:#}"),
                    "shares: publishing the subordinate uid ranges failed — retried"
                );
                self.done = None;
                told = true;
            }
        }
        told
    }
}

/// Set once [`ensure`] took the trie and started its publisher.
static STARTED: AtomicBool = AtomicBool::new(false);

/// Take [`MAP`] out of the agent's object and keep the host's ranges
/// published in it: a thread of its own publishes them at once, then
/// checks the files every [`REFRESH`]. `Ok(true)`: this call started it;
/// `Ok(false)`: it was already.
pub fn ensure(ebpf: &mut Ebpf) -> Result<bool> {
    if STARTED.load(Ordering::Acquire) {
        return Ok(false);
    }
    let map = ebpf
        .take_map(MAP)
        .ok_or_else(|| anyhow!("{MAP} missing from the eBPF object"))?;
    let mut trie: LpmTrie<MapData, [u8; 4], u32> = LpmTrie::try_from(map).context(MAP)?;
    STARTED.store(true, Ordering::Release);
    std::thread::Builder::new()
        .name("nn-subuid".into())
        .spawn(move || {
            // the core's set, whoever starts it (the loader's thread does):
            // the bpf() map writes, and the host's files read through
            // /proc/1/root as the decision's account table reads them
            crate::caps::restore_core();
            let mut p = Publisher::default();
            loop {
                p.tick(&mut trie);
                std::thread::sleep(REFRESH);
            }
        })
        .context("starting the subordinate uid publisher")?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::wire::execq::{global_cap, share_admits, share_floor, share_key};

    const PASSWD_TEXT: &str = "root:x:0:0:root:/root:/bin/bash\n\
        www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
        alice:x:1000:1000::/home/alice:/bin/bash\n\
        bob:x:1001:1001::/home/bob:/bin/bash\n\
        carol:x:1002:1002::/home/carol:/bin/bash\n";

    /// useradd's ranges (100,000 up, 65,536 each), a numeric owner, a name
    /// `/etc/passwd` does not resolve (an LDAP user's), root's for LXD.
    const SUBUID_TEXT: &str = "# comment\n\
        alice:100000:65536\n\
        bob:165536:65536\n\
        \n\
        1002:231072:65536\n\
        ldapuser:296608:65536\n\
        malformed line\n\
        dave:1:0\n\
        root:1000000:1000000000\n";

    fn host() -> Table {
        table(&ranges(SUBUID_TEXT, PASSWD_TEXT), SUBUID_TRIE_MAX as usize)
    }

    /// The kernel's key for a task: its uid at `level` 0, or the creator
    /// `owner` of its outermost user namespace, looked up as
    /// `nn_share_key` looks it up.
    fn key_of(t: &Table, uid: u32, level: u32, owner: u32, inum: u32) -> u32 {
        let sub = common::wire::execq::share_account(uid, level, owner)
            .and_then(|a| lookup(&t.entries, a));
        share_key(uid, level, owner, inum, sub)
    }

    #[test]
    fn the_ranges_are_read_as_newuidmap_grants_them() {
        let r = ranges(SUBUID_TEXT, PASSWD_TEXT);
        assert_eq!(
            r,
            vec![
                Range {
                    owner: Some(1000),
                    start: 100_000,
                    end: 165_536
                },
                Range {
                    owner: Some(1001),
                    start: 165_536,
                    end: 231_072
                },
                Range {
                    owner: Some(1002),
                    start: 231_072,
                    end: 296_608
                },
                Range {
                    owner: None,
                    start: 296_608,
                    end: 362_144
                },
                Range {
                    owner: Some(0),
                    start: 1_000_000,
                    end: 1_001_000_000
                },
            ]
        );
        // a range past the last uid ends there
        let r = ranges("alice:4294967000:65536\n", PASSWD_TEXT);
        assert_eq!(r[0].end, 1 << 32);
        assert!(ranges("alice:x:1\nalice:1:2:3\n:5:5\n", PASSWD_TEXT).is_empty());
    }

    #[test]
    fn prefixes_cover_a_range_exactly() {
        for (s, e) in [
            (100_000u64, 165_536u64),
            (0, 1),
            (0, 1 << 32),
            (65_536, 1 << 32),
            (7, 8),
            (4_294_967_000, 1 << 32),
            (1_000_000, 1_001_000_000),
        ] {
            let ps = prefixes(s, e);
            let mut at = s;
            for (len, base) in &ps {
                assert_eq!(u64::from(*base), at, "{s}..{e}: contiguous");
                let size = 1u64 << (32 - len);
                assert_eq!(at % size, 0, "{s}..{e}: aligned");
                at += size;
            }
            assert_eq!(at, e, "{s}..{e}: exact");
            assert!(ps.len() <= 62);
        }
        assert_eq!(prefixes(0, 1 << 32), vec![(0, 0)]);
        assert!(prefixes(5, 5).is_empty());
    }

    /// The review of #551 (F1), the reviewer's case: alice runs a binary
    /// owned by her subuid N, setuid, in the initial namespace, and calls
    /// `setresuid(N, N, N)`; or makes a namespace whose creator is N. Both
    /// are alice's row. Without the trie (main of lot 332) each subuid was
    /// a row of its own.
    #[test]
    fn a_setresuid_to_a_subuid_is_its_owner_s_row() {
        let t = host();
        let n = 100_000 + 4242;
        assert_eq!(key_of(&t, n, 0, 0, 0), 1000);
        assert_eq!(
            key_of(&Table::default(), n, 0, 0, 0),
            n,
            "the bug: a fresh row"
        );
        // a namespace made by the process that took N, nested or not
        assert_eq!(key_of(&t, 0, 1, n, 0xF000_0001), 1000);
        assert_eq!(key_of(&t, 5, 3, n, 0xF000_0001), 1000);
        // every subuid of each resolved range is its owner's
        for (lo, owner) in [(100_000u32, 1000u32), (165_536, 1001), (231_072, 1002)] {
            for i in (0..65_536u32).step_by(97).chain([0, 65_535]) {
                assert_eq!(key_of(&t, lo + i, 0, 0, 0), owner, "offset {i} of a range");
                assert_eq!(key_of(&t, 1, 2, lo + i, 7), owner);
            }
        }
        // the accounts themselves, services, root: their own rows
        for uid in [0u32, 33, 1000, 1001, 65_534, 99_999] {
            assert_eq!(key_of(&t, uid, 0, 0, 0), uid);
        }
        // a rootless container of alice's (a namespace she made): hers
        assert_eq!(key_of(&t, 100_000, 1, 1000, 0xF000_0002), 1000);
        // root's range (LXD): a system container is keyed by its namespace
        assert_eq!(key_of(&t, 1_000_123, 1, 0, 0xF000_0042), 0xF000_0042);
        // ... and a uid of it in the initial namespace (root's doing) root's
        assert_eq!(key_of(&t, 1_000_123, 0, 0, 0), 0);
    }

    /// Fail closed: a uid of the span no single owner is known for is the
    /// overflow row's, never a row of its own — an owner name that does
    /// not resolve, a gap, overlapping ranges of two users, a range the
    /// trie had no room for, and an unreadable `/etc/subuid`.
    #[test]
    fn an_unknown_subuid_is_the_overflow_row_s() {
        let t = host();
        // ldapuser's range (no /etc/passwd entry)
        assert_eq!(key_of(&t, 300_000, 0, 0, 0), OVERFLOW_SHARE);
        assert_eq!(key_of(&t, 1, 1, 300_000, 9), OVERFLOW_SHARE);
        // the gap between it and root's range
        assert_eq!(key_of(&t, 500_000, 0, 0, 0), OVERFLOW_SHARE);
        // past the span: no one's subuid, its own row
        assert_eq!(key_of(&t, 1_001_000_000, 0, 0, 0), 1_001_000_000);
        // two users' ranges overlapping: neither's
        let o = table(
            &ranges("alice:100000:65536\nbob:150000:65536\n", PASSWD_TEXT),
            SUBUID_TRIE_MAX as usize,
        );
        assert_eq!(key_of(&o, 120_000, 0, 0, 0), 1000);
        assert_eq!(key_of(&o, 160_000, 0, 0, 0), OVERFLOW_SHARE);
        assert_eq!(key_of(&o, 200_000, 0, 0, 0), 1001);
        // one user's two overlapping lines: still hers
        let same = table(
            &ranges("alice:100000:65536\nalice:150000:65536\n", PASSWD_TEXT),
            SUBUID_TRIE_MAX as usize,
        );
        assert_eq!(key_of(&same, 160_000, 0, 0, 0), 1000);
        // a trie with no room past the span: every range the overflow row's
        let cover = prefixes(100_000, 1_001_000_000).len();
        let small = table(&ranges(SUBUID_TEXT, PASSWD_TEXT), cover);
        assert_eq!(
            (small.unplaced, small.entries.len()),
            (4, cover),
            "the span's cover only"
        );
        for uid in [100_000 + 4242, 170_000, 240_000, 1_000_123] {
            assert_eq!(key_of(&small, uid, 0, 0, 0), OVERFLOW_SHARE);
        }
        // room for alice's range only: bob's is the overflow row's
        let alice = prefixes(100_000, 165_536).len();
        let some = table(&ranges(SUBUID_TEXT, PASSWD_TEXT), cover + alice);
        assert_eq!(key_of(&some, 100_000 + 4242, 0, 0, 0), 1000);
        assert_eq!(key_of(&some, 170_000, 0, 0, 0), OVERFLOW_SHARE);
        // unreadable: from 65,536 up, the overflow row's
        let u = unreadable();
        assert!(u.unreadable);
        assert_eq!(key_of(&u, 100_000 + 4242, 0, 0, 0), OVERFLOW_SHARE);
        assert_eq!(key_of(&u, u32::MAX - 1, 0, 0, 0), OVERFLOW_SHARE);
        assert_eq!(key_of(&u, 1000, 0, 0, 0), 1000);
        assert_eq!(key_of(&u, 65_535, 0, 0, 0), 65_535);
        // no ranges: every uid its own
        assert_eq!(key_of(&Table::default(), 300_000, 0, 0, 0), 300_000);
    }

    /// What is read decides the table: a missing `/etc/subuid` is no
    /// ranges; one that cannot be read (or is longer than the most read)
    /// puts every uid from 65,536 up in the overflow row; an unreadable
    /// `/etc/passwd` leaves owner names unresolved (their ranges the
    /// overflow row's), numeric owners still resolve.
    #[test]
    fn what_cannot_be_read_fails_closed() {
        use std::io::{Error, ErrorKind};
        let ok = |s: &str| Ok::<String, Error>(s.to_string());
        assert_eq!(
            table_of(Err(ErrorKind::NotFound.into()), ok(PASSWD_TEXT)),
            Table::default()
        );
        let t = table_of(Err(ErrorKind::PermissionDenied.into()), ok(PASSWD_TEXT));
        assert_eq!(t, unreadable());
        let t = table_of(ok(SUBUID_TEXT), Err(ErrorKind::PermissionDenied.into()));
        assert_eq!(key_of(&t, 100_000 + 4242, 0, 0, 0), OVERFLOW_SHARE);
        assert_eq!(key_of(&t, 240_000, 0, 0, 0), 1002, "a numeric owner");
        assert_eq!(table_of(ok(SUBUID_TEXT), ok(PASSWD_TEXT)), host());
        // the most read, and one byte more
        let max = READ_MAX as usize;
        assert_eq!(
            within_read_max(vec![b'a'; max]).map(|s| s.len()).ok(),
            Some(max)
        );
        assert!(within_read_max(vec![b'a'; max + 1]).is_err());
    }

    /// The trie's room: 1,300 users' useradd ranges fit, and the span
    /// first, so a range past the room is the overflow row's, never
    /// another's or its own.
    #[test]
    fn the_trie_is_bounded_and_fills_the_span_first() {
        let mut passwd = String::new();
        let mut subuid = String::new();
        for i in 0..1500u32 {
            passwd.push_str(&format!("u{i}:x:{}:100::/home/u{i}:/bin/sh\n", 2000 + i));
            subuid.push_str(&format!("u{i}:{}:65536\n", 100_000 + i * 65_536));
        }
        let t = table(&ranges(&subuid, &passwd), SUBUID_TRIE_MAX as usize);
        assert!(t.entries.len() <= SUBUID_TRIE_MAX as usize);
        assert!(t.unplaced > 0, "{}", t.unplaced);
        assert!(1500 - t.unplaced >= 1300, "{}", t.unplaced);
        let mut overflow = 0;
        for i in 0..1500u32 {
            let k = key_of(&t, 100_000 + i * 65_536 + 7, 0, 0, 0);
            assert!(
                k == 2000 + i || k == OVERFLOW_SHARE,
                "range {i}: not its owner's"
            );
            // a range is placed whole or not at all
            assert_eq!(
                key_of(&t, 100_000 + i * 65_536 + 65_535, 0, 0, 0),
                k,
                "u{i}"
            );
            overflow += usize::from(k == OVERFLOW_SHARE);
        }
        assert_eq!(overflow, t.unplaced);
    }

    /// The candidates' map as the kernel shares it (4,096 entries, 1,024 a
    /// share, the global cap, the floor; 4,096 rows): one share's room is
    /// taken as `share_take` takes it.
    struct Shares {
        rows: BTreeMap<u32, u64>,
        overflow: u64,
        total: u64,
    }
    const CAP: u64 = 4096;
    const PER: u64 = 1024;
    impl Shares {
        fn take(&mut self, key: u32) -> bool {
            let (global, floor) = (global_cap(CAP, PER), share_floor(PER));
            let own = if key == OVERFLOW_SHARE {
                &mut self.overflow
            } else if self.rows.contains_key(&key) || self.rows.len() < 4096 {
                self.rows.entry(key).or_insert(0)
            } else {
                &mut self.overflow
            };
            if self.total >= CAP || !share_admits(*own, self.total, PER, global, floor) {
                return false;
            }
            *own += 1;
            self.total += 1;
            true
        }
    }

    /// The review of #551 (F1): 67 or more keys of one user fill the map
    /// no more. Alice's subuids (taken as real uids, or as the creators of
    /// namespaces) are her row, the uids of the span no owner is known for
    /// the overflow row: two shares at most, and every other user still
    /// takes a candidate. Without the trie the same 100 keys fill it.
    #[test]
    fn a_hundred_subuid_keys_cannot_fill_the_map() {
        let attack = |t: &Table| {
            let mut s = Shares {
                rows: BTreeMap::new(),
                overflow: 0,
                total: 0,
            };
            for i in 0..100u32 {
                // half as real uids, half as namespaces' creators; then
                // ldapuser's range (no owner known)
                let k = if i % 2 == 0 {
                    key_of(t, 100_000 + i * 600, 0, 0, 0)
                } else {
                    key_of(t, 0, 1, 100_000 + i * 600, 0xF000_0000 + i)
                };
                while s.take(k) {}
                let k = key_of(t, 300_000 + i, 0, 0, 0);
                while s.take(k) {}
            }
            s
        };
        let mut s = attack(&host());
        assert!(s.rows.len() <= 1, "{} rows", s.rows.len());
        assert_eq!(s.rows.get(&1000), Some(&PER));
        assert_eq!(s.overflow, PER);
        assert_eq!(s.total, 2 * PER);
        // 64 other users still take their candidates, bob up to his share
        for u in 0..64u32 {
            assert!(s.take(5000 + u), "user {u}");
        }
        let mut bob = 0;
        while s.take(1001) {
            bob += 1;
        }
        assert!(bob >= 16, "{bob}");
        // the bug: the same keys without the trie fill the map
        let mut before = attack(&Table::default());
        assert_eq!(before.total, CAP);
        assert!(!before.take(1001), "the map was full");
    }

    /// The publisher rewrites the trie: keys of the old table it no longer
    /// holds are removed, the rest written; a failed write is tried again
    /// at the next tick.
    #[derive(Default)]
    struct Fake {
        m: BTreeMap<(u32, u32), u32>,
        fail: bool,
    }
    impl SubuidTrie for Fake {
        fn keys(&self) -> Result<Vec<(u32, u32)>> {
            Ok(self.m.keys().copied().collect())
        }
        fn remove(&mut self, key: (u32, u32)) -> Result<()> {
            self.m.remove(&key);
            Ok(())
        }
        fn insert(&mut self, key: (u32, u32), value: u32) -> Result<()> {
            if self.fail {
                return Err(anyhow!("full"));
            }
            self.m.insert(key, value);
            Ok(())
        }
    }

    #[test]
    fn publishing_rewrites_the_trie_to_the_table() {
        let mut f = Fake::default();
        let a = host();
        write_trie(&mut f, &a).unwrap();
        assert_eq!(f.m, a.entries);
        let b = table(
            &ranges("bob:165536:65536\n", PASSWD_TEXT),
            SUBUID_TRIE_MAX as usize,
        );
        write_trie(&mut f, &b).unwrap();
        assert_eq!(f.m, b.entries);
        assert_eq!(lookup(&f.m, 100_000), None, "alice's range is gone");
        assert_eq!(lookup(&f.m, 170_000), Some(1001));
        write_trie(&mut f, &Table::default()).unwrap();
        assert!(f.m.is_empty());
        // the publisher: again only when a stamp changed, and after a
        // failed write
        let (s1, s2): (Stamps, Stamps) = (
            (Some((1, 2, 3, 0, 10)), Some((1, 3, 3, 0, 20))),
            (Some((1, 2, 4, 0, 10)), Some((1, 3, 3, 0, 20))),
        );
        let mut p = Publisher::default();
        let mut reads = 0;
        p.tick_with(
            s1,
            || {
                reads += 1;
                host()
            },
            &mut f,
        );
        assert_eq!((reads, &f.m), (1, &a.entries));
        p.tick_with(
            s1,
            || {
                reads += 1;
                host()
            },
            &mut f,
        );
        assert_eq!(reads, 1, "the same files are not read again");
        f.fail = true;
        assert!(write_trie(&mut f, &b).is_err());
        p.tick_with(
            s2,
            || {
                reads += 1;
                b.clone()
            },
            &mut f,
        );
        assert_eq!(
            (reads, p.done),
            (2, None),
            "a failed publish is tried again"
        );
        f.fail = false;
        p.tick_with(
            s2,
            || {
                reads += 1;
                b.clone()
            },
            &mut f,
        );
        assert_eq!((reads, p.done, &f.m), (3, Some(s2), &b.entries));
        // an unreadable /etc/subuid is published (fail closed) and read
        // again at the next tick, the same stamps or not
        p.tick_with(
            s1,
            || {
                reads += 1;
                unreadable()
            },
            &mut f,
        );
        assert_eq!((reads, p.done, &f.m), (4, None, &unreadable().entries));
        // read again, said once
        let again = p.tick_with(s1, unreadable, &mut f);
        assert!(!again, "the same unreadable table is not said again");
        assert_eq!(p.done, None);
        p.tick_with(
            s1,
            || {
                reads += 1;
                host()
            },
            &mut f,
        );
        assert_eq!((reads, p.done, &f.m), (5, Some(s1), &a.entries));
        assert!(
            !p.tick_with(s2, host, &mut f),
            "the same table, not said again"
        );
        assert!(p.tick_with(s1, || b.clone(), &mut f), "a new one is said");
    }
}
