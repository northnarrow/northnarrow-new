//! Lot 283b: whose account a uid is, for the decision engine's
//! [`DecisionHost::account_kind`](nn_core::decision::host::DecisionHost::account_kind):
//! `UID_MIN` from `/etc/login.defs` and the account's shell from
//! `/etc/passwd`, both of the host's view (`response::on_host_path`),
//! classified by nn-core's
//! [`classify_account`](nn_core::decision::host::classify_account).
//!
//! The two files are read again when either changes (device, inode,
//! modification time, size), on the decision thread, which may open files
//! for reading. A file that cannot be read is `UID_MIN` 1000 and no entry.
//! Accounts of another NSS source (LDAP, SSSD, systemd-homed) have no
//! entry here: from `UID_MIN` up they are a person's, unless a service uid
//! (`nobody`, systemd's dynamic users).

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::OnceLock;

use nn_core::decision::host::{classify_account, AccountKind, DEFAULT_UID_MIN};
use parking_lot::Mutex;

const LOGIN_DEFS: &str = "/etc/login.defs";
const PASSWD: &str = "/etc/passwd";
/// The most of either file read: an account database larger than this is
/// read up to it (the entries past it are not known).
const READ_MAX: u64 = 16 << 20;

/// A file's identity and version: device, inode, mtime (s, ns), size.
pub(crate) type Stamp = Option<(u64, u64, i64, i64, u64)>;

#[derive(Default)]
struct Table {
    key: Option<(Stamp, Stamp)>,
    uid_min: u32,
    shells: HashMap<u32, String>,
}

/// The table, one per process: the host's account database, read again
/// when it changes.
static TABLE: OnceLock<Mutex<Table>> = OnceLock::new();

pub(crate) fn stamp(path: &str) -> Stamp {
    crate::response::on_host_path(Path::new(path), |p| std::fs::metadata(p))
        .ok()
        .map(|m| (m.dev(), m.ino(), m.mtime(), m.mtime_nsec(), m.len()))
}

fn read(path: &str) -> String {
    crate::response::on_host_path(Path::new(path), |p| {
        let mut s = Vec::new();
        std::fs::File::open(p)?.take(READ_MAX).read_to_end(&mut s)?;
        Ok(String::from_utf8_lossy(&s).into_owned())
    })
    .unwrap_or_default()
}

/// `UID_MIN` of a `login.defs` text: its last valid setting, else
/// [`DEFAULT_UID_MIN`].
pub fn uid_min(login_defs: &str) -> u32 {
    let mut found = DEFAULT_UID_MIN;
    for line in login_defs.lines() {
        let mut words = line.split_whitespace();
        if words.next() == Some("UID_MIN") {
            if let Some(n) = words.next().and_then(|w| w.parse::<u32>().ok()) {
                found = n;
            }
        }
    }
    found
}

/// The shell of each uid of a `passwd` text — the first entry of a uid,
/// as `getpwuid(3)` finds it.
pub fn shells(passwd: &str) -> HashMap<u32, String> {
    let mut out = HashMap::new();
    for line in passwd.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 7 || f[0].starts_with('+') || f[0].starts_with('-') {
            continue;
        }
        if let Ok(uid) = f[2].parse::<u32>() {
            out.entry(uid).or_insert_with(|| f[6].to_string());
        }
    }
    out
}

/// Whose account `uid` is on this host.
pub fn kind(uid: u32) -> AccountKind {
    if uid == 0 {
        return AccountKind::Root;
    }
    let key = (stamp(LOGIN_DEFS), stamp(PASSWD));
    let mut t = TABLE.get_or_init(Default::default).lock();
    t.refresh(key, || read(LOGIN_DEFS), || read(PASSWD));
    t.kind(uid)
}

impl Table {
    /// Read the files again when their stamps are not the ones read.
    fn refresh(
        &mut self,
        key: (Stamp, Stamp),
        login_defs: impl FnOnce() -> String,
        passwd: impl FnOnce() -> String,
    ) {
        if self.key != Some(key) {
            self.uid_min = uid_min(&login_defs());
            self.shells = shells(&passwd());
            self.key = Some(key);
        }
    }

    fn kind(&self, uid: u32) -> AccountKind {
        classify_account(uid, self.uid_min, self.shells.get(&uid).map(String::as_str))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_min_is_the_last_valid_setting_or_1000() {
        assert_eq!(uid_min(""), 1000);
        assert_eq!(uid_min("# UID_MIN 500\nUID_MAX 60000\n"), 1000);
        assert_eq!(uid_min("UID_MIN\t\t 1000\n"), 1000);
        assert_eq!(uid_min("UID_MIN 500\nUID_MIN x\n"), 500);
        assert_eq!(uid_min("UID_MIN 500\nUID_MIN 2000\n"), 2000);
        assert_eq!(uid_min("SYS_UID_MIN 100\n"), 1000);
    }

    /// The files are read once per version: again when a stamp changes,
    /// not while both stay the same.
    #[test]
    fn the_table_is_read_again_when_a_file_changes() {
        let mut t = Table::default();
        let a: (Stamp, Stamp) = (Some((1, 2, 3, 0, 10)), Some((1, 3, 3, 0, 20)));
        t.refresh(
            a,
            || "UID_MIN 500\n".into(),
            || "u:x:600:600::/h:/bin/bash\n".into(),
        );
        assert_eq!(t.kind(600), AccountKind::Human);
        t.refresh(a, || panic!("read again"), || panic!("read again"));
        let b: (Stamp, Stamp) = (Some((1, 2, 3, 0, 10)), Some((1, 3, 4, 0, 20)));
        t.refresh(
            b,
            || "UID_MIN 500\n".into(),
            || "u:x:600:600::/h:/usr/sbin/nologin\n".into(),
        );
        assert_eq!(t.kind(600), AccountKind::System);
        // a file that cannot be read: UID_MIN 1000, no entry
        t.refresh((None, None), String::new, String::new);
        assert_eq!(t.kind(600), AccountKind::System);
        assert_eq!(t.kind(1000), AccountKind::Human);
    }

    #[test]
    fn the_first_entry_of_a_uid_names_its_shell() {
        let t = shells(
            "root:x:0:0:root:/root:/bin/bash\n\
             www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n\
             nn:x:1000:1000::/home/nn:/bin/bash\n\
             svc:x:1001:1001::/srv:/usr/sbin/nologin\n\
             dup:x:1000:1000::/x:/bin/false\n\
             +nis::::::\n\
             short:x:1002\n",
        );
        assert_eq!(t.get(&0).map(String::as_str), Some("/bin/bash"));
        assert_eq!(t.get(&33).map(String::as_str), Some("/usr/sbin/nologin"));
        assert_eq!(t.get(&1000).map(String::as_str), Some("/bin/bash"));
        assert_eq!(t.get(&1001).map(String::as_str), Some("/usr/sbin/nologin"));
        assert!(!t.contains_key(&1002));
        assert_eq!(t.len(), 4);
        assert_eq!(
            classify_account(1001, 1000, t.get(&1001).map(String::as_str)),
            AccountKind::System
        );
        assert_eq!(
            classify_account(1000, 1000, t.get(&1000).map(String::as_str)),
            AccountKind::Human
        );
    }
}
