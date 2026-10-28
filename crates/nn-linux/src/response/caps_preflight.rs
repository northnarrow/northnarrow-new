//! Boot-time capability preflight for the response executor.
//!
//! The agent runs as root under a systemd `CapabilityBoundingSet=`
//! (deploy/systemd/northnarrow-agent.service). That set is the HARD
//! ceiling on what root can do inside the unit, so a capability
//! missing from it silently turns a response action into `EPERM`:
//!
//! - `CAP_KILL` — `kill(2)` from a sender WITHOUT it may only signal
//!   processes whose uid matches the sender's. Root without `CAP_KILL`
//!   can therefore kill root processes only; every KillProcess /
//!   KillProcessTree verdict against a user-owned process fails. That
//!   is the product's primary response, so its absence in enforcement
//!   mode is a refuse-to-start condition, not a log line.
//! - the others are declared at boot: in enforcement, an ERROR line and a
//!   signed `subsystem_degraded` per capability (external audit CMB-028),
//!   so the degraded surface is on record before the first incident, not
//!   found at it; in detect-only, a WARN line each.
//!
//! External audit CMB-028: the effective set is read with `capget(2)` on
//! the calling thread, `CapEff` of `/proc/thread-self/status` being the
//! cross-check; a set that can be read neither way is "unverifiable",
//! and in enforcement that refuses the start as a missing `CAP_KILL`
//! does ([`boot_gate`]).

use std::fmt;

/// Capability bit numbers (linux/capability.h).
const CAP_DAC_OVERRIDE: u32 = 1;
const CAP_KILL: u32 = 5;
const CAP_LINUX_IMMUTABLE: u32 = 9;
const CAP_NET_ADMIN: u32 = 12;
const CAP_SYS_PTRACE: u32 = 19;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;
const CAP_SETFCAP: u32 = 31;

/// Every capability the enforcement path relies on, with the action
/// that breaks without it (for the boot log).
const REQUIRED: &[(u32, &str, &str)] = &[
    (
        CAP_KILL,
        "CAP_KILL",
        "KillProcess/KillProcessTree on non-root targets",
    ),
    (
        CAP_NET_ADMIN,
        "CAP_NET_ADMIN",
        "COMBAT isolation (iptables/ip6tables-restore) and the per-process egress block (nft)",
    ),
    (
        CAP_SYS_PTRACE,
        "CAP_SYS_PTRACE",
        "/proc/<pid>/exe of other users' and more privileged processes: quarantine \
         targets, auth-session lineage, the watchdog's verification (its posture \
         exemption and kernel protection), the COMBAT guard's exe check (sshd and the \
         watchdog are then spared by their uid-0 unit only); /proc/1/root for \
         quarantine and StripFileCapability",
    ),
    (
        CAP_DAC_OVERRIDE,
        "CAP_DAC_OVERRIDE",
        "quarantine of binaries in restrictive-perm dirs",
    ),
    (
        CAP_LINUX_IMMUTABLE,
        "CAP_LINUX_IMMUTABLE",
        "chattr +i on /var/lib/northnarrow",
    ),
    (CAP_BPF, "CAP_BPF", "eBPF map/program load"),
    (
        CAP_SETFCAP,
        "CAP_SETFCAP",
        "StripFileCapability: undoing a granted file capability",
    ),
    (CAP_PERFMON, "CAP_PERFMON", "BPF-LSM / tracing attach"),
];

/// Outcome of the preflight: which required capabilities are absent
/// from the effective set.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MissingCaps {
    pub names: Vec<&'static str>,
    pub kill_missing: bool,
}

impl MissingCaps {
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }
}

impl fmt::Display for MissingCaps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.names.join(", "))
    }
}

/// Parse the `CapEff:` line out of a `/proc/<pid>/status` body.
pub fn parse_cap_eff(status: &str) -> Option<u64> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("CapEff:"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
}

/// Compare an effective-capability mask against [`REQUIRED`].
pub fn missing_from_mask(cap_eff: u64) -> MissingCaps {
    let mut out = MissingCaps::default();
    for &(bit, name, _) in REQUIRED {
        if cap_eff & (1u64 << bit) == 0 {
            out.names.push(name);
            if bit == CAP_KILL {
                out.kill_missing = true;
            }
        }
    }
    out
}

/// Human-readable "what breaks" line for the boot log.
pub fn impact_of(name: &str) -> &'static str {
    REQUIRED
        .iter()
        .find(|(_, n, _)| *n == name)
        .map(|(_, _, impact)| *impact)
        .unwrap_or("unknown")
}

/// External audit CMB-028: the effective capability set, as the boot
/// could read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsReading {
    /// The set (bit N = capability N). `note`: what the cross-check found
    /// (the two sources disagree, or one could not be read), for a WARN.
    Read {
        effective: u64,
        note: Option<String>,
    },
    /// Neither `capget(2)` nor `CapEff` gave a set: why.
    Unverifiable(String),
}

/// `_LINUX_CAPABILITY_VERSION_3`: two 32-bit words per set.
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// `struct __user_cap_header_struct` (linux/capability.h).
#[repr(C)]
struct CapUserHeader {
    version: u32,
    pid: libc::c_int,
}

/// `struct __user_cap_data_struct` (linux/capability.h).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `capget(2)` on the calling thread: its effective set.
fn capget_effective() -> std::io::Result<u64> {
    let mut header = CapUserHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapUserData::default(); 2];
    // SAFETY: a version-3 header and the two data words that version
    // fills, both live for the call; `capget` writes nothing else.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut CapUserHeader,
            data.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(u64::from(data[0].effective) | (u64::from(data[1].effective) << 32))
}

/// `CapEff` of this thread's `/proc/thread-self/status` (the same thread
/// `capget` asks about); `/proc/self/status` on a kernel before 3.17.
fn proc_cap_eff() -> Result<u64, String> {
    let status = std::fs::read_to_string("/proc/thread-self/status")
        .or_else(|_| std::fs::read_to_string("/proc/self/status"))
        .map_err(|e| format!("/proc/thread-self/status: {e}"))?;
    parse_cap_eff(&status).ok_or_else(|| "/proc/thread-self/status: no CapEff to parse".into())
}

/// External audit CMB-028: one reading out of the two sources. Where they
/// disagree, a capability counts only when both report it.
pub fn combine(capget: Result<u64, String>, cap_eff: Result<u64, String>) -> CapsReading {
    match (capget, cap_eff) {
        (Ok(a), Ok(b)) if a == b => CapsReading::Read {
            effective: a,
            note: None,
        },
        (Ok(a), Ok(b)) => CapsReading::Read {
            effective: a & b,
            note: Some(format!(
                "capget reports {a:#x}, CapEff {b:#x}: counting only the capabilities both report"
            )),
        },
        (Ok(a), Err(e)) => CapsReading::Read {
            effective: a,
            note: Some(format!(
                "CapEff cross-check unavailable ({e}); capget's set used"
            )),
        },
        (Err(e), Ok(b)) => CapsReading::Read {
            effective: b,
            note: Some(format!("capget failed ({e}); CapEff's set used")),
        },
        (Err(e1), Err(e2)) => CapsReading::Unverifiable(format!("capget: {e1}; {e2}")),
    }
}

/// This thread's effective capabilities ([`combine`]).
pub fn read_effective() -> CapsReading {
    combine(
        capget_effective().map_err(|e| e.to_string()),
        proc_cap_eff(),
    )
}

/// External audit CMB-028: what the boot does with the reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootGate {
    /// Start. `degraded`: one sentence per missing capability (or why the
    /// set could not be read, in detect-only) — an ERROR line and a signed
    /// `subsystem_degraded` each in enforcement, a WARN line in detect-only.
    Start { degraded: Vec<String> },
    /// Refuse to start (enforcement only): the error.
    Refuse(String),
}

/// The sentence a missing capability is declared with.
pub fn missing_detail(name: &str) -> String {
    format!(
        "{name} missing from the effective capability set: {} unavailable",
        impact_of(name)
    )
}

/// External audit CMB-028: in enforcement, `CAP_KILL` missing — or a set
/// that cannot be verified, which may lack it — refuses the start unless
/// `--detect-only`; every other missing capability starts degraded.
pub fn boot_gate(reading: &CapsReading, detect_only: bool) -> BootGate {
    let missing = match reading {
        CapsReading::Read { effective, .. } => missing_from_mask(*effective),
        CapsReading::Unverifiable(why) if detect_only => {
            return BootGate::Start {
                degraded: vec![format!(
                    "the effective capability set cannot be verified ({why}): every response \
                     may fail with EPERM"
                )],
            };
        }
        CapsReading::Unverifiable(why) => {
            return BootGate::Refuse(format!(
                "the effective capability set cannot be verified ({why}): CAP_KILL may be \
                 missing, and KillProcess would then EPERM on every non-root target. Start \
                 with --detect-only, or fix what keeps capget(2) and /proc/thread-self/status \
                 from the agent."
            ));
        }
    };
    if missing.kill_missing && !detect_only {
        return BootGate::Refuse(
            "CAP_KILL missing from the effective capability set: KillProcess would \
             EPERM on every non-root target. Add CAP_KILL to CapabilityBoundingSet= \
             in northnarrow-agent.service, or start with --detect-only."
                .to_string(),
        );
    }
    BootGate::Start {
        degraded: missing.names.iter().map(|n| missing_detail(n)).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FULL_ROOT: u64 = 0x0000_01ff_ffff_ffff;
    /// The deploy unit's set BEFORE the CAP_KILL fix:
    /// BPF PERFMON NET_ADMIN LINUX_IMMUTABLE SYS_PTRACE DAC_OVERRIDE.
    const OLD_UNIT: u64 = (1 << CAP_BPF)
        | (1 << CAP_PERFMON)
        | (1 << CAP_NET_ADMIN)
        | (1 << CAP_LINUX_IMMUTABLE)
        | (1 << CAP_SYS_PTRACE)
        | (1 << CAP_DAC_OVERRIDE);

    #[test]
    fn parses_cap_eff_line() {
        let body = "Name:\tx\nCapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\nCapBnd:\t0\n";
        assert_eq!(parse_cap_eff(body), Some(FULL_ROOT));
        assert_eq!(parse_cap_eff("Name:\tx\n"), None);
    }

    #[test]
    fn full_root_is_not_missing_anything() {
        assert!(missing_from_mask(FULL_ROOT).is_empty());
    }

    #[test]
    fn old_unit_set_is_missing_cap_kill_and_cap_setfcap() {
        let m = missing_from_mask(OLD_UNIT);
        assert_eq!(m.names, vec!["CAP_KILL", "CAP_SETFCAP"]);
        assert!(m.kill_missing);
    }

    /// The deploy unit's set: the old one plus CAP_KILL and (review 86)
    /// CAP_SETFCAP.
    #[test]
    fn unit_set_passes() {
        let m = missing_from_mask(OLD_UNIT | (1 << CAP_KILL) | (1 << CAP_SETFCAP));
        assert!(m.is_empty(), "{m}");
        assert!(!m.kill_missing);
        // without CAP_SETFCAP: a warning, not a refusal to start.
        let m = missing_from_mask(OLD_UNIT | (1 << CAP_KILL));
        assert_eq!(m.names, vec!["CAP_SETFCAP"]);
        assert!(!m.kill_missing);
    }

    #[test]
    fn unprivileged_reports_everything() {
        let m = missing_from_mask(0);
        assert_eq!(m.names.len(), REQUIRED.len());
        assert!(m.kill_missing);
        assert_eq!(impact_of("CAP_KILL"), REQUIRED[0].2);
    }

    /// External audit CMB-028: the live thread's set reads the same both
    /// ways (whatever set the test runner was started with).
    #[test]
    fn capget_and_cap_eff_agree_on_the_live_thread() {
        let sys = capget_effective().expect("capget");
        assert_eq!(proc_cap_eff(), Ok(sys));
        assert_eq!(
            read_effective(),
            CapsReading::Read {
                effective: sys,
                note: None
            }
        );
    }

    /// External audit CMB-028: a `CapEff` that does not parse, with no
    /// `capget`, is no set at all — not "nothing missing".
    #[test]
    fn unparsable_cap_eff_is_unverifiable() {
        let cap_eff = parse_cap_eff("Name:\tx\nCapEff:\tnot-hex\n").ok_or_else(|| "bad".into());
        let r = combine(Err("ENOSYS".into()), cap_eff);
        assert!(matches!(r, CapsReading::Unverifiable(_)), "{r:?}");
        // One good source is enough; a disagreement keeps the common part.
        assert_eq!(
            combine(Err("ENOSYS".into()), Ok(FULL_ROOT)),
            CapsReading::Read {
                effective: FULL_ROOT,
                note: Some("capget failed (ENOSYS); CapEff's set used".into())
            }
        );
        match combine(Ok(FULL_ROOT), Ok(OLD_UNIT)) {
            CapsReading::Read { effective, note } => {
                assert_eq!(effective, OLD_UNIT);
                assert!(note.is_some());
            }
            r => panic!("{r:?}"),
        }
    }

    /// External audit CMB-028: the boot's decision.
    #[test]
    fn boot_gate_refuses_what_cannot_kill_and_declares_the_rest() {
        let read = |effective| CapsReading::Read {
            effective,
            note: None,
        };
        let unit = OLD_UNIT | (1 << CAP_KILL) | (1 << CAP_SETFCAP);
        // The shipped unit: nothing to say.
        assert_eq!(
            boot_gate(&read(unit), false),
            BootGate::Start { degraded: vec![] }
        );
        // A drop-in without CAP_SYS_PTRACE: starts, and says what is lost.
        let no_ptrace = unit & !(1 << CAP_SYS_PTRACE);
        match boot_gate(&read(no_ptrace), false) {
            BootGate::Start { degraded } => {
                assert_eq!(degraded.len(), 1, "{degraded:?}");
                assert!(
                    degraded[0].starts_with("CAP_SYS_PTRACE missing"),
                    "{}",
                    degraded[0]
                );
                assert!(degraded[0].contains("COMBAT guard"), "{}", degraded[0]);
            }
            g => panic!("{g:?}"),
        }
        // Without CAP_KILL: refused in enforcement, started in detect-only.
        let no_kill = unit & !(1 << CAP_KILL);
        assert!(matches!(
            boot_gate(&read(no_kill), false),
            BootGate::Refuse(_)
        ));
        assert!(matches!(
            boot_gate(&read(no_kill), true),
            BootGate::Start { degraded } if degraded.len() == 1
        ));
        // A set that cannot be verified: the same as a missing CAP_KILL.
        let unverifiable = CapsReading::Unverifiable("capget: EPERM; …".into());
        assert!(matches!(
            boot_gate(&unverifiable, false),
            BootGate::Refuse(_)
        ));
        assert!(matches!(
            boot_gate(&unverifiable, true),
            BootGate::Start { degraded } if degraded.len() == 1
        ));
    }

    /// External audit CMB-028: CAP_NET_ADMIN also carries the nft egress
    /// block.
    #[test]
    fn net_admin_names_both_tools() {
        let t = impact_of("CAP_NET_ADMIN");
        assert!(t.contains("iptables") && t.contains("nft"), "{t}");
    }
}
