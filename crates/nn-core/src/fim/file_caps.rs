//! Lot 373 (the review of #580, F1): the file capabilities a package
//! transaction may lower to a Low record — R012's `setcap` run by a
//! package's maintainer script on a file of that package, NN-L-FIM-025's
//! grant written in a package transaction.
//!
//! What vouches for those is the transaction's lineage and a path in the
//! package's `.list`, and the package's own maintainer script, run as
//! root, controls both: it can append any path to its `.list` before it
//! calls `setcap`, or ship a helper of its own. So the transaction lowers
//! only a grant of the capabilities packages give their own helpers
//! ([`PACKAGE_NARROW_CAPS`]: `ping`'s and `mtr-packet`'s `cap_net_raw`,
//! `gst-ptp-helper`'s `cap_sys_nice,cap_net_bind_service,cap_net_admin`,
//! `dumpcap`'s `cap_net_raw,cap_net_admin`, `gnome-keyring`'s
//! `cap_ipc_lock`); a grant of anything else — a capability equivalent to
//! root (`cap_setuid`, `cap_setgid`, `cap_sys_admin`, `cap_sys_module`,
//! `cap_sys_ptrace`, `cap_dac_override`, `cap_dac_read_search`, `cap_chown`,
//! `cap_fowner`, `cap_bpf`, `cap_sys_rawio`, `cap_setfcap`), the security
//! policy, the kernel, every capability (`=ep`, `all`), a capability this
//! list does not know — stays High in a transaction too.

use nn_model::telemetry::{FimEvent, FimOp};

/// The capabilities a package transaction may lower, by bit
/// (linux/capability.h): none changes an identity, bypasses a file's
/// permissions, reaches the kernel's code, another process's memory or the
/// security policy — `cap_net_bind_service` (10), `cap_net_broadcast` (11),
/// `cap_net_admin` (12: the network's configuration, a firewall's
/// included — said in `KNOWN_LIMITATIONS.md`), `cap_net_raw` (13),
/// `cap_ipc_lock` (14), `cap_sys_nice` (23), `cap_sys_resource` (24),
/// `cap_wake_alarm` (35), `cap_block_suspend` (36).
pub const PACKAGE_NARROW_CAPS: u64 = (1 << 10)
    | (1 << 11)
    | (1 << 12)
    | (1 << 13)
    | (1 << 14)
    | (1 << 23)
    | (1 << 24)
    | (1 << 35)
    | (1 << 36);

/// Every capability bit `cap_from_text(3)`'s `all` (and an empty name list
/// before `=`) names: the 64 bits of a mask, so a capability newer than
/// this list is in it.
pub const ALL_CAPS: u64 = u64::MAX;

/// A grant of the capabilities `mask` (bit N: capability N) is one a
/// package transaction may lower: every one is in [`PACKAGE_NARROW_CAPS`].
pub fn package_may_lower(mask: u64) -> bool {
    mask & !PACKAGE_NARROW_CAPS == 0
}

/// The capabilities a `setcap` capability text names (`cap_from_text(3)`:
/// clauses separated by white space, each a comma-separated list of names
/// followed by one or more `=`, `+` or `-` operators with their `e`, `i`,
/// `p` flags), as a mask — whatever the operators, so a clause that only
/// removes counts too (fail closed). A name is `cap_<name>` as
/// linux/capability.h spells it, in any case, or a decimal number; `all`, or
/// no name before `=` (`=ep`), is every capability ([`ALL_CAPS`]). `None`
/// when the text names nothing or holds what this does not read (a name it
/// does not know, a flag that is not `e`, `i` or `p`).
pub fn caps_text_mask(text: &str) -> Option<u64> {
    let mut mask = 0u64;
    let mut clauses = 0usize;
    for clause in text.split_whitespace() {
        clauses += 1;
        let op = clause.find(['=', '+', '-'])?;
        let (names, ops) = clause.split_at(op);
        if !ops
            .bytes()
            .all(|b| matches!(b, b'=' | b'+' | b'-' | b'e' | b'i' | b'p'))
        {
            return None;
        }
        if names.is_empty() {
            if !ops.starts_with('=') {
                return None;
            }
            mask = ALL_CAPS;
            continue;
        }
        for name in names.split(',') {
            mask |= cap_name_mask(name)?;
        }
    }
    (clauses > 0).then_some(mask)
}

/// One capability name of a capability text, as a mask.
fn cap_name_mask(name: &str) -> Option<u64> {
    let lower = name.to_ascii_lowercase();
    if lower == "all" {
        return Some(ALL_CAPS);
    }
    // The review of #580 (re-check 1, N1): libcap reads a number with
    // `strtoul(.., 0)` — a leading `0` is octal (`023` is 19,
    // `cap_sys_ptrace`), `0x` hex, a sign accepted. Only a plain decimal
    // (no leading zero, digits only) is read; every other numeric form is
    // ambiguous and stays unread, so High.
    if lower
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_digit() || b == b'+' || b == b'-')
    {
        let plain =
            lower == "0" || (!lower.starts_with('0') && lower.bytes().all(|b| b.is_ascii_digit()));
        if !plain {
            return None;
        }
        let bit: u32 = lower.parse().ok()?;
        return (bit < 64).then(|| 1u64 << bit);
    }
    super::rules::CAP_NAMES
        .iter()
        .position(|n| *n == lower)
        .map(|bit| 1u64 << bit)
}

/// NN-L-FIM-025's grant `fe` holds a capability no package transaction
/// lowers ([`package_may_lower`]): the names, for the record — `None` for
/// any other event, a namespaced grant (recorded Medium, whatever the
/// writer) or a narrow one.
pub fn grant_beyond_package(fe: &FimEvent) -> Option<String> {
    if fe.op != FimOp::CapabilitySet {
        return None;
    }
    let cap = fe.capability?;
    if cap.namespaced || package_may_lower(cap.permitted) {
        return None;
    }
    Some(super::rules::capability_names(
        cap.permitted & !PACKAGE_NARROW_CAPS,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lot 373 (the review of #580, F1): what a capability text names.
    #[test]
    fn a_capability_text_is_read_as_cap_from_text_reads_it() {
        assert_eq!(caps_text_mask("cap_net_raw+ep"), Some(1 << 13));
        assert_eq!(caps_text_mask("cap_net_raw=p"), Some(1 << 13));
        assert_eq!(
            caps_text_mask("cap_sys_nice,cap_net_bind_service,cap_net_admin+ep"),
            Some((1 << 23) | (1 << 10) | (1 << 12))
        );
        assert_eq!(caps_text_mask("CAP_SETUID+ep"), Some(1 << 7));
        assert_eq!(caps_text_mask("7+ep"), Some(1 << 7));
        assert_eq!(
            caps_text_mask("cap_net_raw+ep cap_setuid+p"),
            Some((1 << 13) | (1 << 7))
        );
        assert_eq!(caps_text_mask("cap_setuid-ep"), Some(1 << 7));
        assert_eq!(caps_text_mask("cap_net_raw+e-i+p"), Some(1 << 13));
        assert_eq!(caps_text_mask("=ep"), Some(ALL_CAPS));
        assert_eq!(caps_text_mask("all+ep"), Some(ALL_CAPS));
        assert_eq!(caps_text_mask("ALL=eip"), Some(ALL_CAPS));
        for unread in [
            "",
            "   ",
            "cap_bogus+ep",
            "cap_net_raw",
            "+ep",
            "cap_net_raw+ex",
            "cap_net_raw,+ep",
            "64+ep",
            "023+ep",
            "0023+ep",
            "010+ep",
            "036+ep",
            "0x13+ep",
            "0X7+ep",
            "+7+ep",
            "-7+ep",
            "00+ep",
            "99999999999+ep",
            "18446744073709551616+ep",
            "cap_net_raw,023+ep",
            "cap_net_raw+ep cap_bogus=p",
        ] {
            assert_eq!(caps_text_mask(unread), None, "{unread:?}");
        }
    }

    /// Lot 373 (the review of #580, F1): the capabilities equivalent to
    /// root and every capability are never lowered by a package
    /// transaction; the narrow ones (the soak's `gst-ptp-helper` grant, the
    /// network's) are.
    #[test]
    fn root_equivalent_capabilities_are_never_lowered_by_a_package() {
        for name in [
            "cap_setuid",
            "cap_setgid",
            "cap_sys_admin",
            "cap_sys_module",
            "cap_sys_ptrace",
            "cap_dac_override",
            "cap_dac_read_search",
            "cap_chown",
            "cap_fowner",
            "cap_bpf",
            "cap_sys_rawio",
            "cap_setfcap",
            "cap_setpcap",
            "cap_sys_boot",
            "cap_sys_chroot",
            "cap_mac_admin",
            "cap_mac_override",
            "cap_kill",
            "cap_fsetid",
            "cap_linux_immutable",
            "cap_audit_control",
            "cap_sys_time",
            "cap_syslog",
            "cap_perfmon",
            "cap_checkpoint_restore",
        ] {
            let mask = caps_text_mask(&format!("{name}+ep")).expect(name);
            assert!(!package_may_lower(mask), "{name}");
            assert!(
                !package_may_lower(mask | (1 << 13)),
                "{name} with cap_net_raw"
            );
        }
        assert!(!package_may_lower(ALL_CAPS));
        assert!(
            !package_may_lower(1 << 41),
            "a capability newer than the list"
        );
        for name in [
            "cap_net_raw",
            "cap_net_admin",
            "cap_net_bind_service",
            "cap_net_broadcast",
            "cap_ipc_lock",
            "cap_sys_nice",
            "cap_sys_resource",
            "cap_wake_alarm",
            "cap_block_suspend",
        ] {
            let mask = caps_text_mask(&format!("{name}+ep")).expect(name);
            assert!(package_may_lower(mask), "{name}");
        }
        assert!(package_may_lower(0), "a removal grants nothing");
    }
}
