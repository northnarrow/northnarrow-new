//! The exec policy's table (lab PR 226): exec classes × lineage tiers →
//! `allow | audit | quarantine | deny`, the loader-variable rule per tier,
//! the executable-mapping rules, the image exemptions; the two built-in
//! profiles; the signed overlay's text (`exec-policy.local`); and the
//! encoding into the kernel's frozen `EXECPOL_CONF`. Pure and unit-tested.
//!
//! ## The overlay
//!
//! ```text
//! # comment
//! profile server|desktop                     # the base table (else --exec-policy-profile)
//! exec <class|*> <tier|*> allow|audit|quarantine|deny
//! audit <class|*>                            # the class's denies are recorded, not applied
//! preload <tier|*> allow|record|deny|deny-root
//! map <class|*> <tier|*> allow|record|deny
//! exempt <absolute path> [class,class…]      # callers running this image (default: memfd,deleted)
//! ```
//!
//! Lines apply in order over the base. A line that does not parse refuses
//! the whole file (a signature never covers content the loader would skip).

use std::path::PathBuf;

use common::wire::execpol::{conf_slot, flags, mode, tier};
use common::wire::execq::class;

/// Classes, by bit position (`common::wire::execq::class`).
pub const CLASSES: usize = class::COUNT as usize;
/// Tiers, by value (`common::wire::execpol::tier`).
pub const TIERS: usize = tier::COUNT as usize;

/// Class names, by bit position (the record's and the overlay's).
pub const CLASS_NAMES: [&str; CLASSES] = [
    "memfd",
    "deleted",
    "tmpfs",
    "world_writable_dir",
    "tmp",
    "home",
    "guarded_mount",
    "dev_shm",
    "var_tmp",
    "other_home",
];

/// Tier names, by value.
pub const TIER_NAMES: [&str; TIERS] = ["unknown", "admin", "session", "service"];

/// `--exec-policy-profile`: the built-in table the overlay starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Profile {
    /// Servers: memfd, deleted files and `/dev/shm` refused outside an
    /// interactive admin session; the other staging locations handed to
    /// the exec quarantine.
    Server,
    /// Desktops and developer machines: services as on a server; a login
    /// session's own staging locations allowed (AppImage, `go test`, pip
    /// builds), memfd and deleted files recorded as "would deny".
    Desktop,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Server => "server",
            Profile::Desktop => "desktop",
        }
    }
}

/// An exec cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cell {
    Allow,
    /// Allowed, recorded as "would deny".
    Audit,
    /// Handed to the exec quarantine (lab PR 223: held, scanned, judged).
    Quarantine,
    /// `-EACCES` at `bprm_check_security`.
    Deny,
}

/// A mapping cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapCell {
    Allow,
    Record,
    Deny,
}

/// The loader-variable rule of a tier: what an `LD_PRELOAD` / `LD_AUDIT`
/// entry under a staging prefix gets at exec (a set-id target excepted:
/// `AT_SECURE` already makes the loader ignore it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvRule {
    /// Not reported.
    Allow,
    Record,
    /// Refused whatever the caller's uid.
    Deny,
    /// Refused when the caller is root (no `AT_SECURE`: honoured with
    /// root's credentials), recorded otherwise.
    DenyRoot,
}

/// The whole policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub profile: Profile,
    /// `exec[tier][class]`.
    pub exec: [[Cell; CLASSES]; TIERS],
    /// Classes in audit mode.
    pub class_audit: u32,
    pub env: [EnvRule; TIERS],
    /// `map[tier][class]`.
    pub map: [[MapCell; CLASSES]; TIERS],
    /// Caller images exempt from classes (absolute paths, resolved to
    /// `(dev, ino)` by the agent).
    pub exempt: Vec<(PathBuf, u32)>,
}

const A: Cell = Cell::Allow;
const U: Cell = Cell::Audit;
const Q: Cell = Cell::Quarantine;
const D: Cell = Cell::Deny;
const MA: MapCell = MapCell::Allow;
const MR: MapCell = MapCell::Record;
const MD: MapCell = MapCell::Deny;

/// Container runtimes that re-execute a sealed copy of themselves (a memfd
/// or an `O_TMPFILE`, CVE-2019-5736): their callers may run a memfd or an
/// unlinked file.
pub const DEFAULT_EXEMPT_IMAGES: [&str; 8] = [
    "/usr/bin/runc",
    "/usr/sbin/runc",
    "/usr/local/bin/runc",
    "/usr/bin/crun",
    "/usr/local/bin/crun",
    "/usr/bin/lxc-start",
    "/usr/bin/lxc-attach",
    "/usr/bin/lxc-execute",
];

/// The classes a default exemption covers.
pub const EXEMPT_DEFAULT_CLASSES: u32 = class::MEMFD | class::DELETED;

impl Table {
    /// The built-in table of `profile`.
    pub fn builtin(profile: Profile) -> Self {
        // Column order of the rows below: memfd, deleted, tmpfs,
        // world_writable_dir, tmp, home, guarded_mount, dev_shm, var_tmp,
        // other_home.
        let (exec, env, map) = match profile {
            Profile::Server => (
                [
                    // unknown: a caller nothing places — the strictest.
                    [D, D, Q, Q, Q, Q, Q, D, Q, U],
                    // admin: allowed; memfd and deleted recorded.
                    [U, U, A, A, A, A, A, A, A, A],
                    // session: a user's own home allowed.
                    [D, D, Q, Q, Q, A, A, D, Q, Q],
                    // service.
                    [D, D, Q, Q, Q, Q, Q, D, Q, U],
                ],
                [
                    EnvRule::Deny,
                    EnvRule::Record,
                    EnvRule::DenyRoot,
                    EnvRule::Deny,
                ],
                [
                    [MA, MR, MA, MR, MR, MA, MA, MR, MR, MR],
                    [MA; CLASSES],
                    [MA, MR, MA, MA, MA, MA, MA, MR, MA, MA],
                    [MA, MR, MA, MR, MR, MA, MA, MD, MR, MR],
                ],
            ),
            Profile::Desktop => (
                [
                    [U, U, Q, Q, Q, A, A, Q, Q, Q],
                    [A; CLASSES],
                    [U, U, A, A, A, A, A, Q, A, Q],
                    [D, D, Q, Q, Q, Q, Q, D, Q, U],
                ],
                [
                    EnvRule::DenyRoot,
                    EnvRule::Record,
                    EnvRule::DenyRoot,
                    EnvRule::Deny,
                ],
                [
                    [MA, MA, MA, MA, MA, MA, MA, MR, MA, MA],
                    [MA; CLASSES],
                    [MA, MA, MA, MA, MA, MA, MA, MR, MA, MA],
                    [MA, MR, MA, MR, MR, MA, MA, MR, MR, MR],
                ],
            ),
        };
        Table {
            profile,
            exec,
            class_audit: 0,
            env,
            map,
            exempt: DEFAULT_EXEMPT_IMAGES
                .iter()
                .map(|p| (PathBuf::from(p), EXEMPT_DEFAULT_CLASSES))
                .collect(),
        }
    }

    /// Whether any exec cell hands an exec to the exec quarantine.
    pub fn has_quarantine(&self) -> bool {
        self.exec.iter().flatten().any(|c| *c == Cell::Quarantine)
    }

    /// Whether any mapping cell records or denies.
    pub fn has_map_rules(&self) -> bool {
        self.map.iter().flatten().any(|c| *c != MapCell::Allow)
    }

    /// Whether any tier's loader rule does something.
    pub fn has_env_rules(&self) -> bool {
        self.env.iter().any(|r| *r != EnvRule::Allow)
    }

    /// The masks of one exec action for each tier.
    fn exec_mask(&self, t: usize, want: Cell) -> u32 {
        self.exec[t]
            .iter()
            .enumerate()
            .filter(|(_, c)| **c == want)
            .fold(0, |m, (i, _)| m | 1 << i)
    }

    fn map_mask(&self, t: usize, want: MapCell) -> u32 {
        self.map[t]
            .iter()
            .enumerate()
            .filter(|(_, c)| **c == want)
            .fold(0, |m, (i, _)| m | 1 << i)
    }

    /// The kernel's `EXECPOL_CONF` words for `mode_value` (`execpol::mode`).
    /// `quarantine_by_policy`: the exec quarantine holds only the execs a
    /// quarantine cell names.
    pub fn encode(
        &self,
        mode_value: u64,
        env_scan: bool,
        map: bool,
        quarantine_by_policy: bool,
    ) -> [u64; conf_slot::SLOTS as usize] {
        let mut w = [0u64; conf_slot::SLOTS as usize];
        w[conf_slot::MODE as usize] = mode_value;
        for t in 0..TIERS {
            w[(conf_slot::DENY as usize) + t] = u64::from(self.exec_mask(t, Cell::Deny));
            w[(conf_slot::QUARANTINE as usize) + t] =
                u64::from(self.exec_mask(t, Cell::Quarantine));
            w[(conf_slot::AUDIT as usize) + t] = u64::from(self.exec_mask(t, Cell::Audit));
            w[(conf_slot::MAP_DENY as usize) + t] = u64::from(self.map_mask(t, MapCell::Deny));
            w[(conf_slot::MAP_RECORD as usize) + t] =
                u64::from(self.map_mask(t, MapCell::Record) | self.map_mask(t, MapCell::Deny));
            match self.env[t] {
                EnvRule::Allow => {}
                EnvRule::Record => w[conf_slot::ENV_RECORD as usize] |= 1 << t,
                EnvRule::Deny => {
                    w[conf_slot::ENV_DENY as usize] |= 1 << t;
                    w[conf_slot::ENV_RECORD as usize] |= 1 << t;
                }
                EnvRule::DenyRoot => {
                    w[conf_slot::ENV_DENY_ROOT as usize] |= 1 << t;
                    w[conf_slot::ENV_RECORD as usize] |= 1 << t;
                }
            }
        }
        w[conf_slot::CLASS_AUDIT as usize] = u64::from(self.class_audit);
        let mut f = 0u64;
        if env_scan && mode_value != mode::OFF {
            f |= flags::ENV_SCAN;
        }
        if map && mode_value != mode::OFF {
            f |= flags::MAP;
        }
        if quarantine_by_policy {
            f |= flags::QUARANTINE_BY_POLICY;
        }
        w[conf_slot::FLAGS as usize] = f;
        w
    }

    /// The table as text, one exec row per class (for the design document,
    /// `nn-admin`-style output and the lab's plan).
    pub fn render(&self) -> String {
        let name = |c: Cell| match c {
            Cell::Allow => "allow",
            Cell::Audit => "audit",
            Cell::Quarantine => "quarantine",
            Cell::Deny => "deny",
        };
        let mut out = format!(
            "profile {} — class: admin / session / service / unknown\n",
            self.profile.as_str()
        );
        for (i, cname) in CLASS_NAMES.iter().enumerate() {
            out.push_str(&format!(
                "{cname}: {} / {} / {} / {}{}\n",
                name(self.exec[tier::ADMIN as usize][i]),
                name(self.exec[tier::SESSION as usize][i]),
                name(self.exec[tier::SERVICE as usize][i]),
                name(self.exec[tier::UNKNOWN as usize][i]),
                if self.class_audit & (1 << i) != 0 {
                    " (class in audit mode)"
                } else {
                    ""
                }
            ));
        }
        out
    }
}

fn parse_class(s: &str) -> Result<u32, String> {
    if s == "*" {
        return Ok(class::ALL);
    }
    CLASS_NAMES
        .iter()
        .position(|n| *n == s)
        .map(|i| 1u32 << i)
        .ok_or_else(|| {
            format!(
                "unknown class `{s}` (one of {}, or *)",
                CLASS_NAMES.join(", ")
            )
        })
}

fn parse_classes(s: &str) -> Result<u32, String> {
    s.split(',')
        .try_fold(0u32, |m, c| Ok(m | parse_class(c.trim())?))
}

fn parse_tier(s: &str) -> Result<Vec<usize>, String> {
    if s == "*" {
        return Ok((0..TIERS).collect());
    }
    TIER_NAMES
        .iter()
        .position(|n| *n == s)
        .map(|i| vec![i])
        .ok_or_else(|| {
            format!(
                "unknown tier `{s}` (one of {}, or *)",
                TIER_NAMES.join(", ")
            )
        })
}

fn bits(mask: u32) -> impl Iterator<Item = usize> {
    (0..CLASSES).filter(move |i| mask & (1 << i) != 0)
}

/// Parse the overlay over the built-in table of `default_profile` (or of
/// the `profile` line). `Err`: line number and why — the whole file is
/// refused.
pub fn parse(text: &str, default_profile: Profile) -> Result<Table, String> {
    // The profile line, wherever it is, picks the base first.
    let mut profile = default_profile;
    let mut seen_profile = false;
    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        let mut f = line.split_whitespace();
        if f.next() == Some("profile") {
            if seen_profile {
                return Err(format!("line {}: a second `profile` line", n + 1));
            }
            seen_profile = true;
            profile = match (f.next(), f.next()) {
                (Some("server"), None) => Profile::Server,
                (Some("desktop"), None) => Profile::Desktop,
                _ => return Err(format!("line {}: `profile server|desktop`", n + 1)),
            };
        }
    }
    let mut t = Table::builtin(profile);
    for (n, raw) in text.lines().enumerate() {
        let lineno = n + 1;
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        let err = |why: String| format!("line {lineno}: {why}");
        match f.as_slice() {
            ["profile", ..] => {}
            ["exec", c, tr, a] => {
                let cell = match *a {
                    "allow" => Cell::Allow,
                    "audit" => Cell::Audit,
                    "quarantine" => Cell::Quarantine,
                    "deny" => Cell::Deny,
                    other => {
                        return Err(err(format!(
                            "unknown exec action `{other}` (allow, audit, quarantine, deny)"
                        )))
                    }
                };
                let cm = parse_class(c).map_err(err)?;
                for ti in parse_tier(tr).map_err(err)? {
                    for ci in bits(cm) {
                        t.exec[ti][ci] = cell;
                    }
                }
            }
            ["audit", c] => t.class_audit |= parse_class(c).map_err(err)?,
            ["preload", tr, a] => {
                let r = match *a {
                    "allow" => EnvRule::Allow,
                    "record" => EnvRule::Record,
                    "deny" => EnvRule::Deny,
                    "deny-root" => EnvRule::DenyRoot,
                    other => {
                        return Err(err(format!(
                            "unknown preload action `{other}` (allow, record, deny, deny-root)"
                        )))
                    }
                };
                for ti in parse_tier(tr).map_err(err)? {
                    t.env[ti] = r;
                }
            }
            ["map", c, tr, a] => {
                let cell = match *a {
                    "allow" => MapCell::Allow,
                    "record" => MapCell::Record,
                    "deny" => MapCell::Deny,
                    other => {
                        return Err(err(format!(
                            "unknown map action `{other}` (allow, record, deny)"
                        )))
                    }
                };
                let cm = parse_class(c).map_err(err)?;
                for ti in parse_tier(tr).map_err(err)? {
                    for ci in bits(cm) {
                        t.map[ti][ci] = cell;
                    }
                }
            }
            ["exempt", path, rest @ ..] if rest.len() <= 1 => {
                if !path.starts_with('/') || path.contains("/../") || path.ends_with("/..") {
                    return Err(err(format!("exempt: `{path}` is not an absolute path")));
                }
                let cm = match rest.first() {
                    Some(c) => parse_classes(c).map_err(err)?,
                    None => EXEMPT_DEFAULT_CLASSES,
                };
                t.exempt.push((PathBuf::from(path), cm));
            }
            _ => {
                return Err(err(format!(
                    "`{}` is not an exec, audit, preload, map, exempt or profile line",
                    common::log_escape::Escaped(line)
                )))
            }
        }
    }
    Ok(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::wire::execpol::tier as T;

    fn cell(t: &Table, tr: u32, c: u32) -> Cell {
        t.exec[tr as usize][c.trailing_zeros() as usize]
    }

    #[test]
    fn names_follow_the_bits() {
        for (i, n) in CLASS_NAMES.iter().enumerate() {
            assert_eq!(common::wire::execq::class_names(1 << i), [*n]);
        }
        for (i, n) in TIER_NAMES.iter().enumerate() {
            assert_eq!(common::wire::execpol::tier_name(i as u32), *n);
        }
    }

    /// The default policy of the brief: memfd and deleted files refused
    /// for services and non-interactive sessions, `/tmp`, `/var/tmp`
    /// handed to the quarantine, an interactive admin allowed.
    #[test]
    fn the_server_profile() {
        let t = Table::builtin(Profile::Server);
        for tr in [T::SERVICE, T::SESSION, T::UNKNOWN] {
            assert_eq!(cell(&t, tr, class::MEMFD), Cell::Deny);
            assert_eq!(cell(&t, tr, class::DELETED), Cell::Deny);
            assert_eq!(cell(&t, tr, class::DEV_SHM), Cell::Deny);
            assert_eq!(cell(&t, tr, class::TMP), Cell::Quarantine);
            assert_eq!(cell(&t, tr, class::VAR_TMP), Cell::Quarantine);
        }
        assert_eq!(cell(&t, T::SESSION, class::HOME), Cell::Allow);
        assert_eq!(cell(&t, T::SERVICE, class::HOME), Cell::Quarantine);
        for c in 0..CLASSES {
            assert_ne!(t.exec[T::ADMIN as usize][c], Cell::Deny);
            assert_ne!(t.exec[T::ADMIN as usize][c], Cell::Quarantine);
        }
        assert_eq!(cell(&t, T::ADMIN, class::MEMFD), Cell::Audit);
        assert_eq!(t.env[T::SERVICE as usize], EnvRule::Deny);
        assert_eq!(t.env[T::SESSION as usize], EnvRule::DenyRoot);
        assert_eq!(t.map[T::SERVICE as usize][7], MapCell::Deny, "dev_shm");
        assert_eq!(t.map[T::SERVICE as usize][4], MapCell::Record, "tmp");
        assert_eq!(t.map[T::SERVICE as usize][0], MapCell::Allow, "memfd: JIT");
        assert!(t.has_quarantine() && t.has_map_rules() && t.has_env_rules());
    }

    /// A desktop's own session runs AppImages (`/tmp/.mount_*`), Flatpak
    /// and `go test` binaries; services stay as strict as on a server.
    #[test]
    fn the_desktop_profile() {
        let t = Table::builtin(Profile::Desktop);
        assert_eq!(cell(&t, T::SESSION, class::TMP), Cell::Allow);
        assert_eq!(cell(&t, T::SESSION, class::HOME), Cell::Allow);
        assert_eq!(cell(&t, T::SESSION, class::GUARDED_MOUNT), Cell::Allow);
        assert_eq!(cell(&t, T::SESSION, class::MEMFD), Cell::Audit);
        assert_eq!(cell(&t, T::SERVICE, class::MEMFD), Cell::Deny);
        assert_eq!(cell(&t, T::SERVICE, class::DEV_SHM), Cell::Deny);
        let s = Table::builtin(Profile::Server);
        assert_eq!(t.exec[T::SERVICE as usize], s.exec[T::SERVICE as usize]);
    }

    #[test]
    fn the_encoding() {
        let t = Table::builtin(Profile::Server);
        let w = t.encode(mode::ENFORCE, true, true, true);
        assert_eq!(w[conf_slot::MODE as usize], mode::ENFORCE);
        let deny_service = w[(conf_slot::DENY + T::SERVICE) as usize] as u32;
        assert_eq!(
            deny_service,
            class::MEMFD | class::DELETED | class::DEV_SHM,
            "{deny_service:#x}"
        );
        let q = w[(conf_slot::QUARANTINE + T::SERVICE) as usize] as u32;
        assert!(q & class::TMP != 0 && q & class::VAR_TMP != 0 && q & class::MEMFD == 0);
        assert_eq!(w[(conf_slot::DENY + T::ADMIN) as usize], 0);
        assert_eq!(
            w[(conf_slot::AUDIT + T::ADMIN) as usize] as u32,
            class::MEMFD | class::DELETED
        );
        // env: deny for service and unknown, deny-root for session, all recorded
        assert_eq!(
            w[conf_slot::ENV_DENY as usize],
            (1 << T::SERVICE) | (1 << T::UNKNOWN)
        );
        assert_eq!(w[conf_slot::ENV_DENY_ROOT as usize], 1 << T::SESSION);
        assert_eq!(w[conf_slot::ENV_RECORD as usize], 0b1111);
        // a map deny is reported too
        let md = w[(conf_slot::MAP_DENY + T::SERVICE) as usize];
        let mr = w[(conf_slot::MAP_RECORD + T::SERVICE) as usize];
        assert_eq!(md as u32, class::DEV_SHM);
        assert_eq!(mr & md, md);
        assert_eq!(
            w[conf_slot::FLAGS as usize],
            flags::ENV_SCAN | flags::MAP | flags::QUARANTINE_BY_POLICY
        );
        // off: no scan, no mapping check
        let w = t.encode(mode::OFF, true, true, false);
        assert_eq!(w[conf_slot::FLAGS as usize], 0);
    }

    #[test]
    fn the_overlay_applies_in_order() {
        let text = "\
# lab policy
profile desktop
exec tmp service deny
exec * admin quarantine   # everything held for admins too
audit dev_shm
preload session deny
map tmp * deny
exempt /opt/rt/bin/runtime memfd
exempt /opt/x/y
";
        let t = parse(text, Profile::Server).unwrap();
        assert_eq!(t.profile, Profile::Desktop);
        assert_eq!(cell(&t, T::SERVICE, class::TMP), Cell::Deny);
        assert_eq!(cell(&t, T::ADMIN, class::HOME), Cell::Quarantine);
        assert_eq!(t.class_audit, class::DEV_SHM);
        assert_eq!(t.env[T::SESSION as usize], EnvRule::Deny);
        assert!(t.map.iter().all(|row| row[4] == MapCell::Deny));
        assert!(t
            .exempt
            .contains(&(PathBuf::from("/opt/rt/bin/runtime"), class::MEMFD)));
        assert!(t
            .exempt
            .contains(&(PathBuf::from("/opt/x/y"), EXEMPT_DEFAULT_CLASSES)));
        let w = t.encode(mode::ENFORCE, true, true, true);
        assert_eq!(w[conf_slot::CLASS_AUDIT as usize] as u32, class::DEV_SHM);
        // empty text: the default profile, untouched
        assert_eq!(
            parse("", Profile::Server).unwrap(),
            Table::builtin(Profile::Server)
        );
        assert_eq!(
            parse("# only\n\n", Profile::Desktop).unwrap(),
            Table::builtin(Profile::Desktop)
        );
    }

    #[test]
    fn a_bad_line_refuses_the_file() {
        for (text, why) in [
            ("exec tmp service block", "unknown exec action"),
            ("exec temp service deny", "unknown class"),
            ("exec tmp daemon deny", "unknown tier"),
            ("exec tmp service", "is not an exec"),
            ("preload service maybe", "unknown preload action"),
            ("map memfd service kill", "unknown map action"),
            ("exempt runc", "not an absolute path"),
            ("exempt /a/../b", "not an absolute path"),
            ("exempt /usr/bin/runc memfd,bogus", "unknown class"),
            ("profile laptop", "profile server|desktop"),
            ("profile server\nprofile desktop", "a second `profile`"),
            ("allow everything", "is not an exec"),
        ] {
            let e = parse(
                &format!("exec memfd admin allow\n{text}\n"),
                Profile::Server,
            )
            .unwrap_err();
            assert!(e.contains(why), "{text}: {e}");
            assert!(e.starts_with("line "), "{e}");
        }
    }

    #[test]
    fn the_render_names_every_class() {
        let r = Table::builtin(Profile::Server).render();
        for n in CLASS_NAMES {
            assert!(r.contains(&format!("{n}: ")), "{r}");
        }
        assert!(r.contains("memfd: audit / deny / deny / deny"), "{r}");
    }
}
