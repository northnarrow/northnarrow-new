//! NN-L-BPF-001/002 — foreign activity in the BPF ecosystem (Tappa 10.8).
//!
//! The `bpf` LSM observer reports `bpf()` calls by processes that are not
//! the agent or the watchdog. BPF is legitimate infrastructure (systemd
//! socket filters and device policies, container runtimes, Cilium,
//! observability agents), so both rules are **Log**: an alert and a
//! baseline, with the known tooling and the operator allowlist exempt —
//! judged on the executable the kernel ran (external audit NETR-003
//! class), not on the `comm` a process can name itself.
//!
//! * `NN-L-BPF-001_BpfProgramLoaded` (Medium): a BPF program loaded,
//!   attached or linked by an unlisted process — a kernel-resident
//!   component appeared on the host (rootkit / sensor-blinding shape).
//! * `NN-L-BPF-002_BpfForeignHandleOrDetach` (High): a handle to one of the
//!   agent's own maps / programs / links taken by id, a write handle on an
//!   agent map (observe mode), or a program / link detach by an unlisted
//!   process — tampering with the sensor itself. In enforce mode the map
//!   write is denied by the kernel and arrives as an anti-tamper denial
//!   instead.

use std::sync::Arc;

#[cfg(test)]
use common::bpf_cmd::BPF_MAP_CREATE;
use common::bpf_cmd::{
    BPF_LINK_CREATE, BPF_LINK_DETACH, BPF_PROG_ATTACH, BPF_PROG_DETACH, BPF_PROG_LOAD,
    BPF_RAW_TRACEPOINT_OPEN,
};
use common::wire::{
    BPF_CMD_FOREIGN_GET_FD, BPF_CMD_FOREIGN_MAP_WRITE, BPF_CMD_FRESH_INSTANCE_GET_FD,
    BPF_CMD_LISTING_GET_FD, BPF_CMD_ROOT_CGROUP_ATTACH, BPF_CMD_VACATED_ROLE_GET_FD, bpf_cmd_name,
};
use nn_model::{Event, ResponseAction, Severity, Verdict};

use crate::config::comm_allowlist::{CommAllowlist, Judgement};
use crate::decision::attack::{AttackRef, Tactic};
use crate::decision::{Rule, rules::build_verdict};
use crate::posture::host::PostureHost;

/// Programs that legitimately drive BPF on a server, matched on the
/// executable the kernel ran (a 15-character name also covers the longer
/// names the kernel truncates `comm` to it), and on `comm` only when that
/// cannot be read. `systemd-udevd` is a symlink to `udevadm` on current
/// systemd, and the kernel reports the target.
pub const KNOWN_BPF_PROGRAMS: &[&str] = &[
    "systemd",
    "systemd-network",
    "systemd-resolve",
    "systemd-udevd",
    "udevadm",
    "dockerd",
    "containerd",
    "containerd-shim",
    "runc",
    "crun",
    "podman",
    "cilium-agent",
    "tetragon",
    "falco",
    "northnarrow-wat",
];

/// External audit NETR-003 class: the known tooling and the operator
/// allowlist judged on what the kernel ran, not on the `comm` a process
/// names itself.
fn judge<H: PostureHost>(
    allowlist: &CommAllowlist<H>,
    pid: u32,
    comm: &str,
    as_of: crate::posture::lineage::AsOf,
) -> Judgement {
    allowlist.judge_with(pid, comm, KNOWN_BPF_PROGRAMS, as_of)
}

pub struct NnLBpf001BpfProgramLoaded<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
}

impl<H: PostureHost> NnLBpf001BpfProgramLoaded<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self { allowlist }
    }
}

impl<H: PostureHost> Rule for NnLBpf001BpfProgramLoaded<H> {
    fn id(&self) -> &'static str {
        "NN-L-BPF-001_BpfProgramLoaded"
    }
    fn name(&self) -> &'static str {
        "BPF program loaded or attached by an unlisted process"
    }
    fn category(&self) -> &'static str {
        "defense_evasion"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::Stealth, "T1014")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::BpfSyscall {
            pid,
            comm,
            cmd,
            arg,
            ..
        } = event
        else {
            return None;
        };
        // Lot 293 (external bug hunt BUG05): and a raw tracepoint opened —
        // an attach of a raw_tp, and through it of a tp_btf, fentry/fexit or
        // LSM program (libbpf before LINK_CREATE took them).
        if !matches!(
            *cmd,
            BPF_PROG_LOAD | BPF_PROG_ATTACH | BPF_LINK_CREATE | BPF_RAW_TRACEPOINT_OPEN
        ) {
            return None;
        }
        let judgement = judge(
            &self.allowlist,
            *pid,
            comm,
            crate::posture::lineage::AsOf::of_event(event),
        );
        if judgement == Judgement::Allowed {
            return None;
        }
        let what = match *cmd {
            BPF_PROG_LOAD => format!("loaded a BPF program (prog_type {arg})"),
            BPF_PROG_ATTACH => format!("attached a BPF program (attach_type {arg})"),
            BPF_RAW_TRACEPOINT_OPEN => {
                format!("attached a BPF program through BPF_RAW_TRACEPOINT_OPEN (prog fd {arg})")
            }
            _ => format!("created a BPF link (attach_type {arg})"),
        };
        let reasoning = format!(
            "`{comm}` {what}: a kernel-resident component outside the known tooling — the \
             rootkit / sensor-blinding shape (T1014). Alert only; add the comm to \
             process-comm-allowlist.local if this is your observability stack."
        );
        Some(judgement.apply(
            build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::Medium,
                &reasoning,
            ),
            comm,
        ))
    }
}

/// NN-L-BPF-002's id (R12b: the bus counts the records about the agent's
/// own objects it capped as this rule's held records).
pub const BPF002_ID: &str = "NN-L-BPF-002_BpfForeignHandleOrDetach";

pub struct NnLBpf002BpfForeignHandleOrDetach<H: PostureHost> {
    allowlist: Arc<CommAllowlist<H>>,
    /// Lot 373: the listing processes recorded lately (pid, the record's
    /// time), so that one listing is one record ([`LISTING_DEDUP_NS`]).
    listings: parking_lot::Mutex<std::collections::VecDeque<(u32, u64)>>,
    /// The review of #580 (re-check 1, N2): the kernel's lot 277/281 marks
    /// of the listing process (production: `DecisionHost::actor_facts`).
    facts: Arc<dyn crate::decision::rule_policy::ActorFacts>,
}

/// Lot 373: how long one process's proven bpftool listing stays one record
/// (bpftool takes a handle on each object it prints: a hundred a run).
pub const LISTING_DEDUP_NS: u64 = 60 * 1_000_000_000;

/// Lot 373: the listing processes [`NnLBpf002BpfForeignHandleOrDetach`]
/// remembers at most (the oldest forgotten first: a forgotten one records
/// again).
const LISTINGS_MAX: usize = 64;

impl<H: PostureHost> NnLBpf002BpfForeignHandleOrDetach<H> {
    pub fn new(allowlist: Arc<CommAllowlist<H>>) -> Self {
        Self {
            allowlist,
            listings: parking_lot::Mutex::new(std::collections::VecDeque::new()),
            facts: Arc::new(crate::decision::rule_policy::NoActorFacts),
        }
    }

    /// The marks the listing's Low reads.
    pub fn with_facts(mut self, facts: Arc<dyn crate::decision::rule_policy::ActorFacts>) -> Self {
        self.facts = facts;
        self
    }

    /// The review of #580 (re-check 1, N2): the listing process carries
    /// clean marks — started where it runs, never moved into another
    /// cgroup, no code-injection access (ptrace, `pidfd_getfd`, a write
    /// handle on its memory) given to another. Not known: not clean.
    fn listing_is_clean(&self, pid: u32) -> bool {
        self.facts.started_in_cgroup(pid) == Some(true)
            && self.facts.injected(pid) == Some(crate::decision::rule_policy::Injected::No)
    }

    /// Lot 373: `pid`'s proven listing at `at_ns` is the first of that
    /// process within [`LISTING_DEDUP_NS`] — the one to record.
    fn first_listing(&self, pid: u32, at_ns: u64) -> bool {
        let mut seen = self.listings.lock();
        if seen
            .iter()
            .any(|&(p, t)| p == pid && at_ns.saturating_sub(t) < LISTING_DEDUP_NS)
        {
            return false;
        }
        seen.retain(|&(p, _)| p != pid);
        if seen.len() >= LISTINGS_MAX {
            seen.pop_front();
        }
        seen.push_back((pid, at_ns));
        true
    }
}

impl<H: PostureHost> Rule for NnLBpf002BpfForeignHandleOrDetach<H> {
    fn id(&self) -> &'static str {
        BPF002_ID
    }
    fn name(&self) -> &'static str {
        "Handle to the agent's BPF objects, or a program/link detach, by an unlisted process"
    }
    fn category(&self) -> &'static str {
        "anti_tamper"
    }
    fn attack(&self) -> &'static [AttackRef] {
        const ATTACK: &[AttackRef] = &[AttackRef::new(Tactic::DefenseImpairment, "T1685")];
        ATTACK
    }
    fn evaluate(&self, event: &Event) -> Option<Verdict> {
        let Event::BpfSyscall {
            pid,
            comm,
            cmd,
            arg,
            ..
        } = event
        else {
            return None;
        };
        // The review of #554 (F2): a fresh instance of the agent or the
        // watchdog opening the agent's pins at its start, let through by the
        // kernel — the family's own start, recorded Low (not silent: a
        // foreign program made "the watchdog by device and inode" through
        // `prctl(PR_SET_MM, PR_SET_MM_EXE_FILE)` while the role was vacant
        // takes the same path).
        if *cmd == BPF_CMD_FRESH_INSTANCE_GET_FD {
            let reasoning = format!(
                "`{comm}` (pid {pid}), a fresh instance of the agent or the watchdog — its binary \
                 by device and inode, its role vacant, its first minute — took a handle to one of \
                 NorthNarrow's own BPF objects (id {arg}) before it was a protected pid: the \
                 family's own start, let through. Recorded because the same path is open to a \
                 program that made itself the watchdog's binary (PR_SET_MM_EXE_FILE) while the \
                 role was vacant: a second record here, without a restart of the agent or the \
                 watchdog, is not a start."
            );
            return Some(build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::Low,
                &reasoning,
            ));
        }
        // Lot 2.2 (the cgroup BPF guard): a foreign packet or device program
        // on the ROOT cgroup — let through by the kernel (it governs the
        // whole host; firewalls and container runtimes attach there), High:
        // a drop-all egress program there cuts the agent's heartbeat and
        // export as one on its own cgroups would.
        if *cmd == BPF_CMD_ROOT_CGROUP_ATTACH {
            let reasoning = format!(
                "`{comm}` (pid {pid}) attached a packet or device BPF program (attach type \
                 {arg}) to the root cgroup: it governs every process of the host, the agent's \
                 heartbeat and export among them. Let through (a firewall or a container \
                 runtime attaches there); the same attach on the agent's own cgroups is \
                 refused. Check that the program is the host's own."
            );
            return Some(build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::High,
                &reasoning,
            ));
        }
        // Lot 370 (F10-4): the role was vacated this boot — its holder
        // exited (the OOM killer, a crash) — and a successor started for it
        // (a unit's restart, the watchdog's respawn) took it: High, not the
        // start's Low. The moment is one an attacker can choose.
        if *cmd == BPF_CMD_VACATED_ROLE_GET_FD {
            let reasoning = format!(
                "`{comm}` (pid {pid}) took the agent's or the watchdog's role after its holder \
                 exited this boot — the OOM killer, a crash, or a vacancy induced on purpose — \
                 and a handle to one of NorthNarrow's own BPF objects (id {arg}) before it was a \
                 protected pid. The kernel let it through only as a successor started for the \
                 role (by PID 1 or the other role's holder, no code injected into it); the \
                 previous holder's exit is the anomaly: see the agent's `previous_run`."
            );
            return Some(build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::High,
                &reasoning,
            ));
        }
        // Lot 373 (the lab of lot 373: `sudo bpftool prog show` in observe
        // mode, High ×100 at every boot): a handle by id — a program's, or a
        // map's opened read-write for the program's metadata — the agent
        // proved, at the bus's barrier, the packaged bpftool's read-only
        // listing — root's, its image by device and inode, its command line
        // read whole (`BPF_CMD_LISTING_GET_FD`): one Low record per listing
        // process, no posture.
        // N2: a listing whose process does not carry clean marks is no
        // listing: the handle is judged as any foreign one (High below)
        let dirty_listing = *cmd == BPF_CMD_LISTING_GET_FD && !self.listing_is_clean(*pid);
        let cmd = &if dirty_listing {
            BPF_CMD_FOREIGN_GET_FD
        } else {
            *cmd
        };
        if *cmd == BPF_CMD_LISTING_GET_FD {
            let timestamp_ns = match event {
                Event::BpfSyscall { timestamp_ns, .. } => *timestamp_ns,
                _ => 0,
            };
            if !self.first_listing(*pid, timestamp_ns) {
                return None;
            }
            let reasoning = format!(
                "`{comm}` (pid {pid}) took a handle by id on one of NorthNarrow's own BPF objects \
                 (id {arg}) and the others it lists: the packaged bpftool run by root (its device \
                 and inode, read by the agent at the record) listing or showing objects (`prog \
                 show`, `map list`, `cgroup tree`), which takes a handle on each — a program's \
                 maps read-write, as libbpf opens them, for its metadata — only to read its \
                 information. Recorded Low, once for the process, and raises no posture (lot \
                 373). A dump, an update, a pin, a detach or any other program's handle stays \
                 High."
            );
            return Some(build_verdict(
                self,
                event,
                ResponseAction::Log,
                Severity::Low,
                &reasoning,
            ));
        }
        let own_object = matches!(*cmd, BPF_CMD_FOREIGN_GET_FD | BPF_CMD_FOREIGN_MAP_WRITE);
        let detach = matches!(*cmd, BPF_PROG_DETACH | BPF_LINK_DETACH);
        if !own_object && !detach {
            return None;
        }
        // Touching the agent's own objects is never exempt: a listed tool
        // doing it is still tampering.
        let judgement = if detach {
            judge(
                &self.allowlist,
                *pid,
                comm,
                crate::posture::lineage::AsOf::of_event(event),
            )
        } else {
            Judgement::Denied { claimed: false }
        };
        if judgement == Judgement::Allowed {
            return None;
        }
        let reasoning = if own_object {
            format!(
                "`{comm}` took a handle to one of NorthNarrow's own BPF objects (id {arg}, {}): the \
                 way `bpftool map update/delete` and link detach reach the sensor — in enforce mode \
                 a write handle is denied by the kernel (anti-tamper denial `bpf_map`).",
                bpf_cmd_name(*cmd)
            )
        } else {
            format!(
                "`{comm}` issued bpf({}) — detaching BPF programs/links on a host that runs a BPF \
                 sensor is the blinding move; the agent's own links are pinned and inode-protected, \
                 this is telemetry on everyone else's.",
                bpf_cmd_name(*cmd)
            )
        };
        Some(judgement.apply(
            build_verdict(self, event, ResponseAction::Log, Severity::High, &reasoning),
            comm,
        ))
    }
}

/// The two BPF rules, sharing the process comm allowlist.
pub fn bpf_rules<H: crate::decision::host::DecisionHost>(
    allowlist: Arc<CommAllowlist<H>>,
) -> Vec<Box<dyn Rule>> {
    vec![
        Box::new(NnLBpf001BpfProgramLoaded::new(Arc::clone(&allowlist))),
        Box::new(
            NnLBpf002BpfForeignHandleOrDetach::new(allowlist)
                .with_facts(H::actor_facts(std::path::Path::new(H::PROC_ROOT))),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    // R08b (lab PR 251): on the portable test host.
    use crate::posture::host::testing::TestHost as H;
    type CommAllowlist = crate::config::comm_allowlist::CommAllowlist<H>;
    type NnLBpf001BpfProgramLoaded = super::NnLBpf001BpfProgramLoaded<H>;
    type NnLBpf002BpfForeignHandleOrDetach = super::NnLBpf002BpfForeignHandleOrDetach<H>;

    fn ev(comm: &str, cmd: u32, arg: u32) -> Event {
        Event::BpfSyscall {
            pid: 777,
            uid: 0,
            comm: comm.to_string(),
            cmd,
            arg,
            timestamp_ns: 1,
        }
    }

    /// Lot 373 (named, the lab of lot 373: `sudo bpftool prog show`, `-j prog
    /// list`, `map show`, `cgroup tree` in observe mode — NN-L-BPF-002 High
    /// ×100 at every boot on Ubuntu 26.04 and Debian 12): a handle the agent
    /// proved the packaged bpftool's listing is one Low record per process
    /// within a minute; another process's listing is its own record. The
    /// attack shapes stay High: a handle or a write handle not proven
    /// (python's ctypes, a copy, a dump, an update), a detach — by bpftool
    /// too.
    #[test]
    fn a_proven_bpftool_listing_is_one_low_record() {
        let (_, r) = rules();
        let r = r.with_facts(Arc::new(MarkFacts {
            started: Some(true),
            injected: Some(Injected::No),
        }));
        let at = |pid: u32, cmd: u32, ts: u64| Event::BpfSyscall {
            pid,
            uid: 0,
            comm: "bpftool".into(),
            cmd,
            arg: 48,
            timestamp_ns: ts,
        };
        const S: u64 = 1_000_000_000;
        let v = r
            .evaluate(&at(1613, BPF_CMD_LISTING_GET_FD, 10 * S))
            .expect("the first handle of the listing");
        assert_eq!(
            (v.severity, v.action.clone()),
            (Severity::Low, ResponseAction::Log),
            "{}",
            v.reasoning
        );
        assert!(
            v.reasoning.contains("lot 373") && v.reasoning.contains("no posture"),
            "{}",
            v.reasoning
        );
        for ts in [10 * S, 11 * S, 69 * S] {
            assert!(
                r.evaluate(&at(1613, BPF_CMD_LISTING_GET_FD, ts)).is_none(),
                "the same listing at {ts}"
            );
        }
        assert!(
            r.evaluate(&at(1614, BPF_CMD_LISTING_GET_FD, 12 * S))
                .is_some(),
            "another listing process"
        );
        assert!(
            r.evaluate(&at(1613, BPF_CMD_LISTING_GET_FD, 71 * S))
                .is_some(),
            "a minute later"
        );
        for (cmd, why) in [
            (BPF_CMD_FOREIGN_GET_FD, "a handle not proven a listing"),
            (
                BPF_CMD_FOREIGN_MAP_WRITE,
                "a write handle not proven a listing",
            ),
            (BPF_PROG_DETACH, "a detach"),
            (BPF_LINK_DETACH, "a link detach"),
        ] {
            let v = r.evaluate(&at(1613, cmd, 72 * S)).expect(why);
            assert_eq!(v.severity, Severity::High, "{why}: {}", v.reasoning);
        }
        // the dedup is bounded, and forgets the oldest past its bound: that
        // one records again within its minute
        let listing = |pid: u32, ts: u64| r.evaluate(&at(pid, BPF_CMD_LISTING_GET_FD, ts));
        assert!(listing(1_999, 80 * S).is_some());
        for pid in 2_000..2_000 + LISTINGS_MAX as u32 {
            assert!(listing(pid, 80 * S).is_some());
        }
        assert_eq!(r.listings.lock().len(), LISTINGS_MAX);
        assert!(listing(1_999, 81 * S).is_some(), "forgotten");
        assert!(
            listing(2_000 + LISTINGS_MAX as u32 - 1, 81 * S).is_none(),
            "still remembered"
        );
    }

    use crate::decision::rule_policy::Injected;

    /// The lot 277/281 marks of every process, as a test sets them.
    struct MarkFacts {
        started: Option<bool>,
        injected: Option<Injected>,
    }

    impl crate::decision::rule_policy::ActorFacts for MarkFacts {
        fn uid(&self, _pid: u32) -> Option<u32> {
            None
        }
        fn cgroup(&self, _pid: u32) -> Option<String> {
            None
        }
        fn trusted_exe(&self, _pid: u32) -> Option<(String, [u8; 32])> {
            None
        }
        fn started_in_cgroup(&self, _pid: u32) -> Option<bool> {
            self.started
        }
        fn injected(&self, _pid: u32) -> Option<Injected> {
            self.injected
        }
        fn unread(
            &self,
            _pid: u32,
            _fact: crate::decision::rule_policy::ExemptionFact,
        ) -> Option<String> {
            None
        }
    }

    /// The review of #580 (re-check 1, N2, named): a packaged bpftool
    /// listing is Low only when its process carries clean lot 277/281
    /// marks. Code-injection access given to it (ptrace, `pidfd_getfd`),
    /// a move into another cgroup, or marks not known: High, and no
    /// listing dedup is consumed.
    #[test]
    fn a_bpftool_listing_with_dirty_marks_is_no_low() {
        let (_, r) = rules();
        let listing = Event::BpfSyscall {
            pid: 1613,
            uid: 0,
            comm: "bpftool".into(),
            cmd: BPF_CMD_LISTING_GET_FD,
            arg: 48,
            timestamp_ns: 10,
        };
        let mut r = r;
        for (started, injected, why) in [
            (
                Some(true),
                Some(Injected::Yes {
                    by: 77,
                    inherited: false,
                }),
                "ptrace or pidfd_getfd",
            ),
            (
                Some(true),
                Some(Injected::Yes {
                    by: 1,
                    inherited: true,
                }),
                "inherited",
            ),
            (Some(false), Some(Injected::No), "moved into another cgroup"),
            (Some(true), None, "injection not known"),
            (None, Some(Injected::No), "start not known"),
        ] {
            r = r.with_facts(Arc::new(MarkFacts { started, injected }));
            let v = r.evaluate(&listing).expect(why);
            assert_eq!(v.severity, Severity::High, "{why}: {}", v.reasoning);
        }
        assert!(r.listings.lock().is_empty(), "no dirty listing was deduped");
        r = r.with_facts(Arc::new(MarkFacts {
            started: Some(true),
            injected: Some(Injected::No),
        }));
        assert_eq!(r.evaluate(&listing).unwrap().severity, Severity::Low);
    }

    fn rules() -> (NnLBpf001BpfProgramLoaded, NnLBpf002BpfForeignHandleOrDetach) {
        let al = Arc::new(CommAllowlist::from_iter_owned(["myobs".to_string()]));
        (
            NnLBpf001BpfProgramLoaded::new(Arc::clone(&al)),
            NnLBpf002BpfForeignHandleOrDetach::new(al),
        )
    }

    #[test]
    fn program_load_by_unlisted_logs_medium_and_known_tooling_is_exempt() {
        let (r1, _) = rules();
        let v = r1
            .evaluate(&ev("bpftool", BPF_PROG_LOAD, 7))
            .expect("fires");
        assert_eq!(v.rule_id, "NN-L-BPF-001_BpfProgramLoaded");
        assert_eq!(v.severity, Severity::Medium);
        assert_eq!(v.action, ResponseAction::Log);
        assert!(r1.evaluate(&ev("systemd", BPF_PROG_LOAD, 7)).is_none());
        assert!(r1.evaluate(&ev("myobs", BPF_LINK_CREATE, 1)).is_none());
        // map create alone is not a load
        assert!(r1.evaluate(&ev("bpftool", BPF_MAP_CREATE, 1)).is_none());
    }

    /// Lot 293 (external bug hunt BUG05): an attach through
    /// `BPF_RAW_TRACEPOINT_OPEN` by an unlisted process is NN-L-BPF-001's,
    /// as an attach through `PROG_ATTACH` or `LINK_CREATE` is; the known
    /// tooling stays exempt.
    #[test]
    fn raw_tracepoint_open_by_unlisted_is_an_attach() {
        let (r1, r2) = rules();
        let v = r1
            .evaluate(&ev("implant", BPF_RAW_TRACEPOINT_OPEN, 5))
            .expect("an attach through the raw tracepoint command fires");
        assert_eq!(v.severity, Severity::Medium);
        assert!(
            v.reasoning
                .contains("attached a BPF program through BPF_RAW_TRACEPOINT_OPEN (prog fd 5)"),
            "{}",
            v.reasoning
        );
        assert!(
            r1.evaluate(&ev("systemd", BPF_RAW_TRACEPOINT_OPEN, 5))
                .is_none()
        );
        assert!(
            r2.evaluate(&ev("implant", BPF_RAW_TRACEPOINT_OPEN, 5))
                .is_none()
        );
    }

    /// The review of #554 (named, F2): a fresh instance of the agent or the
    /// watchdog taking a handle to the agent's own objects at its start is
    /// let through by the kernel and recorded on its own, Low — not silent
    /// (a foreign program made the watchdog's binary through
    /// `PR_SET_MM_EXE_FILE` while the role is vacant takes the same path),
    /// and not the foreign handle's High.
    #[test]
    fn a_fresh_instance_s_handle_is_recorded_low_not_silenced() {
        let (r1, r2) = rules();
        let v = r2
            .evaluate(&ev("northnarrow-wat", BPF_CMD_FRESH_INSTANCE_GET_FD, 9))
            .expect("a fresh instance's handle is recorded");
        assert_eq!(v.rule_id, BPF002_ID);
        assert_eq!(v.severity, Severity::Low);
        assert_eq!(v.action, ResponseAction::Log);
        assert!(
            v.reasoning.contains("PR_SET_MM_EXE_FILE"),
            "{}",
            v.reasoning
        );
        assert!(v.reasoning.contains("(id 9)"), "{}", v.reasoning);
        // the same handle from anyone else is still the foreign one, High
        let f = r2
            .evaluate(&ev("northnarrow-wat", BPF_CMD_FOREIGN_GET_FD, 9))
            .expect("fires");
        assert_eq!(f.severity, Severity::High);
        assert!(
            r1.evaluate(&ev("northnarrow-wat", BPF_CMD_FRESH_INSTANCE_GET_FD, 9))
                .is_none()
        );
    }

    /// Lot 2.2 (named): a packet or device program attached to the root
    /// cgroup — let through by the kernel — is recorded High by NN-L-BPF-002
    /// with its attach type; NN-L-BPF-001 does not take it.
    #[test]
    fn a_root_cgroup_packet_attach_is_high() {
        let (r1, r2) = rules();
        let v = r2
            .evaluate(&ev("iptables", BPF_CMD_ROOT_CGROUP_ATTACH, 1))
            .expect("recorded");
        assert_eq!(v.rule_id, BPF002_ID);
        assert_eq!(
            (v.severity, v.action),
            (Severity::High, ResponseAction::Log)
        );
        assert!(v.reasoning.contains("attach type 1"), "{}", v.reasoning);
        assert!(
            r1.evaluate(&ev("iptables", BPF_CMD_ROOT_CGROUP_ATTACH, 1))
                .is_none()
        );
    }

    /// Lot 370 (F10-4): a role taken after its holder exited this boot is
    /// recorded High — on main every claim of a vacant role was the
    /// start's Low, so a vacancy the OOM killer made on demand was taken
    /// with only a Low record.
    #[test]
    fn a_role_taken_after_its_holder_exited_is_high() {
        let (r1, r2) = rules();
        let v = r2
            .evaluate(&ev("northnarrow-age", BPF_CMD_VACATED_ROLE_GET_FD, 9))
            .expect("recorded");
        assert_eq!(v.rule_id, BPF002_ID);
        assert_eq!(
            (v.severity, v.action),
            (Severity::High, ResponseAction::Log)
        );
        assert!(
            v.reasoning.contains("after its holder exited"),
            "{}",
            v.reasoning
        );
        assert!(v.reasoning.contains("(id 9)"), "{}", v.reasoning);
        assert!(
            r1.evaluate(&ev("northnarrow-age", BPF_CMD_VACATED_ROLE_GET_FD, 9))
                .is_none()
        );
    }

    /// #554's KVM suites: the signed detection record carries no reasoning,
    /// so the watchdog e2e knows the fresh instance's record by its severity
    /// — NN-L-BPF-002 is Low for that command only, High for every other it
    /// fires on, whoever the caller (an allowlisted name included).
    #[test]
    fn bpf002_is_low_for_a_fresh_instance_only() {
        let (_, r2) = rules();
        let mut fired = 0;
        let cmds = (0u32..64).chain([
            BPF_CMD_FOREIGN_MAP_WRITE,
            BPF_CMD_FOREIGN_GET_FD,
            BPF_CMD_FRESH_INSTANCE_GET_FD,
            0xFFFF_0004,
            u32::MAX,
        ]);
        for cmd in cmds {
            for comm in ["northnarrow-wat", "northnarrow-age", "bpftool", "myobs"] {
                let Some(v) = r2.evaluate(&ev(comm, cmd, 9)) else {
                    continue;
                };
                fired += 1;
                assert_eq!(
                    v.severity == Severity::Low,
                    cmd == BPF_CMD_FRESH_INSTANCE_GET_FD,
                    "cmd {cmd:#x} from {comm}: {:?}",
                    v.severity
                );
            }
        }
        assert!(fired > 4, "the rule fired {fired} times");
    }

    #[test]
    fn own_object_handle_is_high_even_for_known_tooling() {
        let (_, r2) = rules();
        let v = r2
            .evaluate(&ev("systemd", BPF_CMD_FOREIGN_GET_FD, 42))
            .expect("fires");
        assert_eq!(v.rule_id, "NN-L-BPF-002_BpfForeignHandleOrDetach");
        assert_eq!(v.severity, Severity::High);
        assert!(v.reasoning.contains("id 42"));
        assert!(
            r2.evaluate(&ev("bpftool", BPF_CMD_FOREIGN_MAP_WRITE, 9))
                .is_some()
        );
        // detach by unlisted: fires; by known/allowlisted: exempt
        assert!(r2.evaluate(&ev("bpftool", BPF_LINK_DETACH, 0)).is_some());
        assert!(
            r2.evaluate(&ev("cilium-agent", BPF_LINK_DETACH, 0))
                .is_none()
        );
        assert!(r2.evaluate(&ev("myobs", BPF_PROG_DETACH, 0)).is_none());
        // a plain load is not this rule's business
        assert!(r2.evaluate(&ev("bpftool", BPF_PROG_LOAD, 7)).is_none());
    }

    // ── external audit LLMR-012 (NN-AUD-055) — judged on exec identity ──

    /// The two rules with the allowlist judged on exec identity, `execs`
    /// ingested as the exec sensor would.
    fn identity_rules(
        execs: &[(u32, &str)],
    ) -> (
        tempfile::TempDir,
        NnLBpf001BpfProgramLoaded,
        NnLBpf002BpfForeignHandleOrDetach,
    ) {
        let tmp = tempfile::TempDir::new().unwrap();
        let t = crate::posture::lineage::AuthSessionTracker::<H>::new(tmp.path());
        for (pid, exe) in execs {
            t.ingest_spawn_with_argv(*pid, 1, exe, &[exe.to_string()], 1);
        }
        let al = Arc::new(CommAllowlist::from_iter_owned(["myobs".to_string()]).with_identity(t));
        (
            tmp,
            NnLBpf001BpfProgramLoaded::new(Arc::clone(&al)),
            NnLBpf002BpfForeignHandleOrDetach::new(al),
        )
    }

    fn by(pid: u32, comm: &str, cmd: u32) -> Event {
        let mut e = ev(comm, cmd, 0);
        if let Event::BpfSyscall { pid: p, .. } = &mut e {
            *p = pid;
        }
        e
    }

    #[test]
    fn a_process_named_like_known_tooling_is_no_longer_exempt() {
        let (_tmp, r1, r2) = identity_rules(&[
            (700, "/tmp/.x/loader"),                    // calls itself `systemd`
            (701, "/usr/lib/systemd/systemd"),          // the real one
            (702, "/usr/bin/udevadm"),                  // systemd-udevd's target
            (703, "/usr/lib/systemd/systemd-networkd"), // comm `systemd-network`
            (704, "/usr/bin/myobs"),                    // the operator's entry
            (705, "/home/u/myobs"),                     // …copied where anyone writes
        ]);
        let v = r1
            .evaluate(&by(700, "systemd", BPF_PROG_LOAD))
            .expect("a loader named systemd that is not systemd fires");
        assert!(v.reasoning.contains("named 'systemd'"), "{}", v.reasoning);
        assert!(r1.evaluate(&by(701, "systemd", BPF_PROG_LOAD)).is_none());
        assert!(
            r1.evaluate(&by(702, "systemd-udevd", BPF_PROG_LOAD))
                .is_none()
        );
        assert!(
            r1.evaluate(&by(703, "systemd-network", BPF_PROG_LOAD))
                .is_none()
        );
        assert!(r1.evaluate(&by(704, "myobs", BPF_LINK_CREATE)).is_none());
        assert!(r1.evaluate(&by(705, "myobs", BPF_LINK_CREATE)).is_some());
        // a detach by the impostor fires, by the real tool it does not
        let v = r2
            .evaluate(&by(700, "cilium-agent", BPF_LINK_DETACH))
            .expect("fires");
        assert!(
            v.reasoning.contains("named 'cilium-agent'"),
            "{}",
            v.reasoning
        );
        assert!(r2.evaluate(&by(701, "systemd", BPF_PROG_DETACH)).is_none());
        // never seen and gone: still reported, with the doubt recorded
        let v = r1
            .evaluate(&by(799, "systemd", BPF_PROG_LOAD))
            .expect("fires");
        assert_eq!(v.action, ResponseAction::Log);
        assert!(v.reasoning.contains("could not be read"), "{}", v.reasoning);
    }
}
