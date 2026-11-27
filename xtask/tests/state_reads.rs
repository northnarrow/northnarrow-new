//! Lot 311 (the third bug hunt, family F4 "a read error becomes a wrong
//! answer", and the triage's N6): a read of the kernel's state never fails
//! on its encoding, and a failed read never empties a protection — and a
//! ratchet so it stays so.
//!
//! A process names itself: its `comm` (`prctl(PR_SET_NAME)`, a write to
//! `/proc/self/comm`, the name of the file it executed) is in its `stat`
//! and `status` byte for byte, a user names the cgroups systemd delegates
//! to it, and a user's FUSE mount puts any bytes in the mount table. A
//! strict `read_to_string` refused each of these files whole: the kill of a
//! process that named itself `\xff\xfe` was reported failed and it ran on
//! (lot 311a), the lineage's sweep took it for gone, one FUSE mount emptied
//! the exec quarantine's guarded roots (BUG-98). Two rules hold that:
//!
//! 1. **None**, by name: the production code of the security crates
//!    ([`SCAN`]) reads no process's own `/proc` entry ([`PROC_ENTRIES`]:
//!    `stat`, `status`, `comm`, `cgroup`, `mountinfo`, `cmdline`,
//!    `environ`) with `read_to_string` — `nn_linux::state_read::read_state`,
//!    the posture hosts' `read_state`, or the byte parser of
//!    `nn_linux::mountinfo` read them.
//! 2. **A ratchet** over the reads whose failure turns into a default: a
//!    `read_to_string(…)` whose statement takes `.ok()` or
//!    `.unwrap_or_default()`, and a `lines()` loop that `continue`s on a
//!    read error. Every file holding one is in [`KNOWN`] with its count and
//!    why a failed read there is not a protection emptied (a missing file
//!    is the default, the file is ours, the answer fails toward the
//!    stricter side…). A new site fails until it is made a read that keeps
//!    the last good state (`nn_linux::state_read::LastGood`) or is listed
//!    with its reason; a count that fell fails until the table is lowered.
//!
//! Lot 1.7a (stage S1, item F12): the scan reads the production code as
//! Rust (`support::ast`; test items and test files left out). A read is a
//! call by its name, a method or a path through the file's imports, or a
//! reader passed as a value (`.map(fs::read_to_string)`); the path it reads
//! is every literal its argument (or its reader) can hold — through a
//! `let`, a `const`, a field a struct literal initialises, a `for` loop's
//! or an iterator closure's item, a parameter as the file's calls pass it,
//! a function's returned value —; its failure turns into a default when
//! the call's own chain (through parentheses, `?`, an array's item) takes
//! `.ok()`, `unwrap_or*`, `map_or*`, `is_ok_and`, `.text()` or a
//! `flatten`, when an `if let Ok`/`let Ok … else` takes it, when a `match`
//! on it has an `Err` arm that is a default, or when a `let` holds it and
//! its next use does one of these. The lexical scan before (kept in
//! [`lexical`] only to show it) missed each spelling planted below. Each
//! rule is shown failing on a planted violation.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use support::ast::{self, Anc, Corpus, Index};
use support::{is_test_file, repo_root};
use syn::Expr;

/// The security crates' sources.
const SCAN: &[&str] = &[
    "crates/nn-core/src",
    "crates/nn-linux/src",
    "agent/src",
    "watchdog/src",
    "crates/nn-admin/src",
    "antitamper-bpf/src",
];

/// A process's own `/proc` entries: a path naming one ends in its name.
const ENTRIES: &[&str] = &[
    "stat",
    "status",
    "comm",
    "cgroup",
    "mountinfo",
    "cmdline",
    "environ",
];

/// Why a process's own `/proc` entry may default: read as bytes, its read
/// fails only when the process is gone (`ENOENT`, `ESRCH`) or the host is
/// out of something, and the caller answers "unknown" — no identity, no
/// start, no exemption, no ancestor — never an emptied protection.
const PROC: &str = "a process's own /proc entry, read as bytes: a failed read is the process \
                    gone or unknown, and the caller answers unknown (no identity, start, \
                    exemption or ancestor), never an emptied protection";
/// Lot 355: the exec pump's AppImage tie reads PID 1's mount table; one it
/// cannot read ties nothing.
const APPIMG: &str = "PID 1's mount table, read for the AppImage tie (lot 355): unreadable, no \
                      filesystem is tied to an image and the exec is judged staged, as before \
                      (the stricter side), never an emptied protection";
/// Why a kernel-written ASCII file may default.
const JUDGE: &str = "a process's own mount table, read for the exec pumps' judge when no host \
    table shows a mount it reached (lot 366, the review of #573, F2): unreadable, no table — the \
    mount is not asked and the facts it would give are judged not verified, never trusted";
const KNOB: &str = "written by the kernel in ASCII (/proc/sys, /sys, meminfo, /proc/stat, fdinfo, \
                    the boot id, the agent's own /proc/self): no user writes it; unreadable, the \
                    built-in value applies (a bound, a new boot, no finding)";
/// Why a file of the agent's own may default.
const OWN: &str = "a file the agent or the watchdog writes itself (its state, records, markers, \
                   journal, vault, pidfile): unreadable, the stricter answer (start afresh, \
                   nothing honoured, nothing trusted, no finding made from nothing)";
/// Why lab tooling may default.
const LAB: &str = "lab, golden-replay or debug-trigger tooling, or the feasibility probe: not \
                   the product's judgement";
/// Why a file given to the operator's tools may default.
const OPER: &str = "a file the operator hands nn-admin, or the operator's signed allow list: the \
                    tool reports what it reads; an unreadable allow list is an empty one (never \
                    an open one)";
/// Why the listing of our drop-ins' settings may default (the review of
/// #538's re-check, G1: the judges themselves never do).
const CONFIG: &str = "a drop-in or an EnvironmentFile= of ours whose NN_ settings are listed \
                      (bounded, a regular file, its bytes made text): one that cannot be read \
                      lists no setting, and its judge holds it harmful (shape_harm: not a \
                      protected regular file; own_harms: unjudgeable) — the judges never \
                      default";
/// Why the kill cgroups' events may default.
const KILLCG: &str = "the kill cgroups the agent creates (neutralize-*): an unreadable \
                      cgroup.events is no 'populated' at the sweep of a leftover (removed only \
                      when empty: rmdir refuses a populated cgroup), and a wait that reads \
                      nothing waits to its deadline";
/// Why a package list may default.
const PKG: &str = "a package's file list or sums (dpkg's .list and .md5sums, a file rpm \
                   recorded): unreadable, its files are not owned — no trust is lent, the \
                   stricter side";
/// Why the account files may default.
const ACCT: &str = "root's account files (/etc/passwd, login.defs, subuid/subgid), read as \
                    bytes: a read that fails (an I/O error, which no user provokes) yields no \
                    account — no carve-out is lent; the file-open sensor's homes are then \
                    /root only for that start (the review of #538, F9: accepted, not a user's \
                    lever)";
/// Why our own cgroup knobs may default.
const CGROUP: &str = "our own units' cgroup files, written and read back by the agent: a value \
                      that cannot be read is not confirmed (reported), never a floor dropped";
/// Why the copy-on-write guard's scope check may default.
const MOUNT: &str = "the copy-on-write guard's start: with no mount table readable a mount scope \
                     is refused as no mount point, and the guard's start reports the refusal";

/// Why a response's read-back may default (lot 312, #543): it fails toward
/// the stricter side.
const READBACK: &str = "a response's read-back of what it did (lot 312): a read that fails is \
                        answered on the stricter side — a cgroup that cannot be read back is no \
                        block in effect, a failure with its reason";

/// Why a tool's unit's process list may default (lot 316, the re-check of
/// #548, N4).
const UNITCG: &str = "a listed tool's unit's cgroup.procs, which the kernel writes: one that \
                      cannot be read, is empty or holds a line that is not a pid sanctions no \
                      reload — the signal is judged (High), the stricter side";
/// Why the agent's own CPU watch may default (lot 349).
const CPUS: &str = "lot 349: the agent's own CPU watch — a cpuset or online file, systemd's \
                    system.conf or the command line that cannot be read narrows nothing the \
                    agent should run on (the wider set is expected: a record, the stricter \
                    side) and names no partition; the online CPUs have two sources";
/// Why the installed shells' list may default (lot 313).
const SHELLS: &str = "lot 313: /etc/shells, one of R020's two lists of installed programs: an \
                      unreadable file adds none, the binary directories are still read, and \
                      what was recorded is never removed (the identities only add a program to \
                      R020's shells, never exempt one; the executed file's name still counts)";

/// Rule 2's sites, each by its read as written (spaces dropped): `(file,
/// read, why)` — none reads a file a process or a user names into an empty
/// answer that a protection then publishes. The readers that keep the last
/// good state (`LastGood`, a `Condition` in the error's arm) are not sites.
const KNOWN: &[(&str, &str, &str)] = &[
    // lot 373: the exec's and its parent's start before the package
    // manager's walk; a package's dpkg list and an account's uid under the
    // host's root (R012, NN-L-NET-013), each failing toward no exemption
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "read_state(proc.join(p.to_string()).join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(self.inner.host_root.join(\"etc/passwd\"))",
        ACCT,
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(list)",
        PKG,
    ),
    (
        "agent/src/admin/transport.rs",
        "read_state(format!(\"/proc/{pid}/comm\"))",
        PROC,
    ),
    (
        "agent/src/boot/manifest.rs",
        "read_to_string(\"/proc/sys/kernel/osrelease\")",
        KNOB,
    ),
    (
        "agent/src/cow/fanotify.rs",
        "read_state(format!(\"/proc/{tid}/status\"))",
        PROC,
    ),
    ("agent/src/cow/guard.rs", "mountinfo::read(t)", MOUNT),
    (
        "agent/src/cow/journal.rs",
        "read_all(host.join(\"index.jsonl\"))",
        OWN,
    ),
    (
        "agent/src/decision/validation_registry.rs",
        "read_to_string(repo_path(rel))",
        LAB,
    ),
    ("agent/src/detection_store.rs", "read_state(path)", OWN),
    (
        "agent/src/detection_store.rs",
        "read_state(dir.join(\"comm\"))",
        PROC,
    ),
    (
        "agent/src/execq/pkgtrust.rs",
        "read_state(entry.path())",
        PKG,
    ),
    (
        "agent/src/export/controller.rs",
        "read_to_string(\"/proc/sys/kernel/hostname\")",
        KNOB,
    ),
    (
        "agent/src/heartbeat.rs",
        "read_to_string(\"/proc/sys/kernel/random/boot_id\")",
        KNOB,
    ),
    ("agent/src/heartbeat.rs", "read_state(path)", OWN),
    // lot 374: the agent's witness import position — unreadable, no key is
    // certified and every row is imported again as uncertified (High)
    ("crates/nn-linux/src/witness.rs", "read_state(&path)", OWN),
    (
        "agent/src/module_trust/mod.rs",
        "read_to_string(\"/proc/sys/kernel/osrelease\")",
        KNOB,
    ),
    (
        "agent/src/module_trust/mod.rs",
        "read_state(\"/proc/stat\")",
        KNOB,
    ),
    ("agent/src/module_trust/scan.rs", "read_all(file)", PKG),
    (
        "agent/src/posture/golden.rs",
        "read_to_string(&self.audit_path)",
        LAB,
    ),
    ("agent/src/run_loop.rs", "read_to_string(&trigger)", LAB),
    // lot 325: the exec guards' map fill of the e2e (`debug-execpol-fill`)
    (
        "agent/src/execpol/controller.rs",
        "read_to_string(&fill)",
        LAB,
    ),
    (
        "antitamper-bpf/src/cgroup_floors.rs",
        "read_to_string(&path)",
        CGROUP,
    ),
    (
        "antitamper-bpf/src/cgroup_floors.rs",
        "read_to_string(&d.path)",
        CGROUP,
    ),
    (
        "antitamper-bpf/src/cgroup_floors.rs",
        "read_to_string(\"/proc/meminfo\")",
        KNOB,
    ),
    (
        "antitamper-bpf/src/cgroup_floors.rs",
        "read_to_string(\"/sys/devices/system/cpu/online\")",
        KNOB,
    ),
    (
        "antitamper-bpf/src/cgroup_floors.rs",
        "read_to_string(p)",
        CGROUP,
    ),
    (
        "antitamper-bpf/src/cgroup_guard.rs",
        "read_all(path)",
        CGROUP,
    ),
    (
        "antitamper-bpf/src/host_dropins.rs",
        "read_config(Path::new(p))",
        KNOB,
    ),
    (
        "antitamper-bpf/src/lib.rs",
        "read_all(format!(\"/proc/{pid}/comm\"))",
        PROC,
    ),
    ("crates/nn-admin/src/cli.rs", "read_to_string(&file)", OPER),
    ("crates/nn-admin/src/cli.rs", "read_to_string(path)", OPER),
    (
        "crates/nn-core/src/anti_tamper/combat_allow.rs",
        "read_to_string(path)",
        OPER,
    ),
    (
        "crates/nn-core/src/decision/correlation/ancestry.rs",
        "read_state(proc_root.join(pid.to_string()).join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-core/src/decision/rules/module_provenance.rs",
        "fs::read(entry.path())",
        PKG,
    ),
    ("crates/nn-core/src/fim/rules.rs", "fs::read(path)", ACCT),
    (
        "crates/nn-core/src/impact/trust.rs",
        "fs::read(entry.path())",
        PKG,
    ),
    (
        "crates/nn-core/src/impair/mod.rs",
        "read_state(proc_root.join(pid.to_string()).join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-core/src/impair/mod.rs",
        "read_state(self.proc_root.join(pid.to_string()).join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-core/src/impair/mod.rs",
        "read_state(self.proc_root.join(pid.to_string()).join(\"cgroup\"))",
        PROC,
    ),
    (
        "crates/nn-core/src/impair/mod.rs",
        "read_state(dir.join(\"cgroup.procs\"))",
        UNITCG,
    ),
    (
        "crates/nn-core/src/posture/exempt.rs",
        "read_state(proc_root.join(pid.to_string()).join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(self.inner.proc_root.join(pid.to_string()).join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(self.inner.proc_root.join(pid.to_string()).join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(self.inner.host_root.join(f))",
        ACCT,
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(self.inner.proc_root.join(pid.to_string()).join(\"mountinfo\"))",
        PROC,
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(self.inner.proc_root.join(pid.to_string()).join(\"cgroup\"))",
        PROC,
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(dir.join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(path)",
        PROC,
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(self.inner.proc_root.join(name).join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(&path)",
        PROC,
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(&status_path)",
        PROC,
    ),
    (
        "crates/nn-linux/src/agent_id.rs",
        "read_all(\"/proc/sys/kernel/random/boot_id\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/anti_tamper/bpf_defense.rs",
        "read_to_string(format!(\"/proc/self/fdinfo/{fd}\"))",
        KNOB,
    ),
    (
        "crates/nn-linux/src/anti_tamper/btf_revalidate.rs",
        "read_all(d.join(m))",
        KNOB,
    ),
    (
        "crates/nn-linux/src/anti_tamper/cgroup_guard.rs",
        "read_to_string(&path)",
        CGROUP,
    ),
    (
        "crates/nn-linux/src/anti_tamper/mod.rs",
        "read_to_string(path)",
        OWN,
    ),
    (
        "crates/nn-linux/src/anti_tamper/trusted_installer.rs",
        "read_state(proc_root.join(pid.to_string()).join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/bpf_crossview.rs",
        "read_state(\"/proc/1/stat\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/caps/mod.rs",
        "read_state(\"/proc/self/status\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/cgroup_join.rs",
        "read_to_string(STATE_PATH)",
        OWN,
    ),
    (
        "crates/nn-linux/src/cgroup_join.rs",
        "read_state(proc_root.join(pid.to_string()).join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/cgroup_join.rs",
        "read_state(proc_root.join(pid.to_string()).join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/cgroup_join.rs",
        "read_to_string(p)",
        KNOB,
    ),
    (
        "crates/nn-linux/src/cgroup_join.rs",
        "read_to_string(\"/proc/sys/kernel/random/boot_id\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/combat/actuator.rs",
        "read_state(dir.join(\"cgroup\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/combat/protected.rs",
        "read_state(self.proc_root.join(pid.to_string()).join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/combat/protected.rs",
        "read_state(self.proc_root.join(pid.to_string()).join(\"cgroup\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/decision_host_linux.rs",
        "read_state(self.proc_root.join(pid.to_string()).join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/decision_host_linux.rs",
        "read_state(self.proc_root.join(pid.to_string()).join(\"cgroup\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/fim/honeypot.rs",
        "read_to_string(\"/proc/sys/kernel/random/boot_id\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/host_hardening.rs",
        "read_to_string(root.join(INSTALL_MANIFEST_REL))",
        OWN,
    ),
    (
        "crates/nn-linux/src/kernel_state.rs",
        "read_to_string(p.join(f))",
        KNOB,
    ),
    ("crates/nn-linux/src/own_cpus.rs", "read_state(p)", CPUS),
    (
        "crates/nn-linux/src/known_system_prog.rs",
        "read_to_string(pdir.join(\"fdinfo\").join(&fd))",
        KNOB,
    ),
    (
        "crates/nn-linux/src/known_system_prog.rs",
        "read_state(p)",
        PROC,
    ),
    (
        "crates/nn-linux/src/net/known_resolver.rs",
        "read_state(format!(\"/proc/{pid}/stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/net/known_resolver.rs",
        "read_state(proc.join(pid.to_string()).join(\"cgroup\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/net/known_resolver.rs",
        "read_all(path)",
        "lot 340: a container runtime's bundle (root's, writable by no one else, checked \
         first): unreadable, the sender is not proven CoreDNS and is judged as any sender — \
         never a protection emptied",
    ),
    (
        // the review of #552 (F3): the container's init pid file
        "crates/nn-linux/src/net/known_resolver.rs",
        "read_all(path)",
        "the review of #552 (F3): a container runtime's init pid file (root's, writable by \
         no one else, checked first): unreadable, the sender is not proven CoreDNS and is \
         judged as any sender — never a protection emptied",
    ),
    (
        // the review of #552 (F4): a resolver service's parent, cgroup, uids
        "crates/nn-linux/src/net/known_resolver.rs",
        "read_state(dir.join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/net/known_resolver.rs",
        "read_state(dir.join(\"cgroup\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/net/known_resolver.rs",
        "read_state(dir.join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/known_system_prog.rs",
        "read_state(pdir.join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/known_system_prog.rs",
        "read_state(pdir.join(\"comm\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/module_writes.rs",
        "read_to_string(STATE_PATH)",
        OWN,
    ),
    (
        "crates/nn-linux/src/own_dropins.rs",
        "read_to_string(\"/proc/sys/kernel/pid_max\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/own_dropins.rs",
        "read_config(Path::new(p))",
        CONFIG,
    ),
    (
        "crates/nn-linux/src/own_dropins.rs",
        "read_config(&from)",
        CONFIG,
    ),
    (
        "crates/nn-linux/src/own_dropins.rs",
        "read_all(&from)",
        CONFIG,
    ),
    (
        "crates/nn-linux/src/program_images.rs",
        "read_all(root.join(\"etc/shells\"))",
        SHELLS,
    ),
    (
        "crates/nn-linux/src/program_images.rs",
        "read_state(proc_root.join(pid.to_string()).join(\"stat\"))",
        PROC,
    ),
    // lot 381 (F6-6): a thread's children, where the runtime compare looks
    // for a process still running a copy whose own process exited
    (
        "crates/nn-linux/src/program_images.rs",
        "read_state(task.join(&tid).join(\"children\"))",
        "lot 381: a thread of the exec's parent lists its children (procfs's own); \
         unreadable (the thread gone), no holder of the copy is found there — the copy is then \
         gone, counted, and never kept as the runtime's clone: in runc 1.1's re-exec under an \
         installed runtime it is kept UNVERIFIED (R004: root's High, never killed — a declared \
         residual, the review of #588 F4; any other uid's the Critical kill), in any other \
         shape nothing is kept (Critical)",
    ),
    (
        "crates/nn-linux/src/fim/drain.rs",
        "read_state(dir.join(\"cgroup\"))",
        PROC,
    ),
    // the review of #556 (F6): the writer's start, read with its image and
    // cgroup; unreadable, no unit fact is kept (the High kill stays)
    (
        "crates/nn-linux/src/fim/drain.rs",
        "read_state(dir.join(\"stat\"))",
        PROC,
    ),
    // lot 348 (lot 347's F6 residual): the writer's start compared with the
    // record's `modifier_start`, before and after its image and cgroup;
    // unreadable, it is not the writer — no unit fact is kept
    (
        "crates/nn-linux/src/fim/drain.rs",
        "read_state(dir.join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/response/containment.rs",
        "read_state(format!(\"/proc/{pid}/cgroup\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/response/containment.rs",
        "read_to_string(path)",
        OWN,
    ),
    (
        "crates/nn-linux/src/response/kill.rs",
        "read_to_string(task.join(t).join(\"children\"))",
        PROC,
    ),
    // lot 353 (the review of #563, F2): the descendant walk's `stat`s,
    // beneath the anchored /proc root (the procfs crate skipped them alike):
    // a process gone mid-walk is not a parent of anyone
    (
        "crates/nn-linux/src/response/kill.rs",
        "read_state(format!(\"/proc/{pid}/stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/response/quarantine.rs",
        "read_to_string(cfg.quarantine_dir.join(\"vault\").join(format!(\"{vault_id}.meta\")),)",
        OWN,
    ),
    (
        "crates/nn-linux/src/response/quarantine.rs",
        "fs::read(e.path())",
        OWN,
    ),
    (
        "crates/nn-linux/src/response/throttle.rs",
        "read_to_string(dir.join(knob))",
        CGROUP,
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "read_state(\"/proc/self/status\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/anti_tamper/mount_guard.rs",
        "read_to_string(\"/proc/self/maps\")",
        "the agent's own mappings (the review of #567): unreadable, no library directory is \
         added to the mount guard's points — the binaries', units' and directories' points \
         remain; no state is defaulted",
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "read_to_string(\"/proc/self/limits\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "read_state(path)",
        OWN,
    ),
    // lot 370 (F10-2): the package managers' lock holders, sampled every
    // poll — an unread sample adds no transaction (nothing is vouched for:
    // fail closed), the next poll samples again
    (
        "agent/src/module_trust/txn.rs",
        "read_state(\"/proc/locks\")",
        KNOB,
    ),
    (
        "agent/src/module_trust/txn.rs",
        "read_state(format!(\"/proc/{pid}/stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "read_state(\"/proc/self/cgroup\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "read_to_string(path)",
        KNOB,
    ),
    (
        "crates/nn-linux/src/sensor_feasibility.rs",
        "read_to_string(\"/proc/sys/kernel/osrelease\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/sensor_feasibility.rs",
        "read_to_string(\"/proc/kallsyms\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/sensors/bus.rs",
        "read_to_string(\"/proc/sys/kernel/random/boot_id\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/sensors/dns_sensor.rs",
        "read_state(path)",
        ACCT,
    ),
    (
        "crates/nn-linux/src/sensors/epg.rs",
        "read_to_string(\"/proc/sys/kernel/pid_max\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/sensors/epg.rs",
        "read_to_string(\"/proc/sys/kernel/threads-max\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/sensors/exec_facts.rs",
        "read_state(dir.join(\"stat\"))",
        PROC,
    ),
    // the review of #578: the loader's process still the exec's (else
    // nothing placed: its names judged by their text), and the agent's own
    // name in its succession record
    (
        "crates/nn-linux/src/sensors/loader_files.rs",
        "read_state(dir.join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/anti_tamper/bpf_defense.rs",
        "read_state(\"/proc/self/comm\")",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "read_state(dir.join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/app_image.rs",
        "mountinfo::read(&proc_root.join(\"1/mountinfo\"))",
        APPIMG,
    ),
    (
        "crates/nn-linux/src/sensors/pump_reads.rs",
        "mountinfo::read(&dir.join(\"mountinfo\"))",
        JUDGE,
    ),
    (
        "crates/nn-linux/src/sensors/app_image.rs",
        "read_state(proc_root.join(pid.to_string()).join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/app_image.rs",
        "read_state(dir.join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/app_image.rs",
        "read_state(dir.join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/app_image.rs",
        "read_state(dir.join(\"fdinfo\").join(fd))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "read_state(dir.join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "read_state(proc.join(format!(\"{pid}/stat\")))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "read_state(proc.join(format!(\"{pid}/status\")))",
        PROC,
    ),
    // lot 369: the module tool's credentials at the exec (its start, then
    // its uids and capability sets), procfs's own
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "read_state(proc.join(format!(\"{pid}/stat\")))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "read_state(proc.join(format!(\"{pid}/status\")))",
        PROC,
    ),
    // lot 380: the forker's start and each of its threads' uids and
    // capability sets, procfs's own (a failed read: not vouched for)
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "read_state(proc.join(format!(\"{pid}/stat\")))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "read_state(dir.join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/multiplexer.rs",
        "read_to_string(\"/proc/sys/kernel/perf_event_paranoid\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/sensors/open_sensor.rs",
        "read_state(format!(\"/proc/{pid}/status\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/open_sensor.rs",
        "read_state(\"/etc/passwd\")",
        ACCT,
    ),
    (
        "crates/nn-linux/src/sensors/open_sensor.rs",
        "read_state(\"/etc/login.defs\")",
        ACCT,
    ),
    (
        "crates/nn-linux/src/sensors/ring_drops.rs",
        "read_state(base.join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/ring_drops.rs",
        "read_all(base.join(\"cmdline\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sysctl_guard.rs",
        "read_to_string(root.join(p.trim_start_matches('/')))",
        KNOB,
    ),
    // lot 2.0: the keyboard's SysRq mask — absent only on a kernel without
    // SysRq (no request at all); any other failure is the advisory's
    // finding ("not known"), never a default
    (
        "crates/nn-linux/src/sysctl_guard.rs",
        "read_to_string(root.join(SYSRQ.trim_start_matches('/')),)",
        "lot 2.0: /proc/sys/kernel/sysrq absent is a kernel built without SysRq (no keyboard \
         request exists); every other failed read is a signed finding, not a default",
    ),
    (
        "crates/nn-linux/src/telemetry_probe.rs",
        "read_to_string(p)",
        LAB,
    ),
    (
        "crates/nn-linux/src/telemetry_probe.rs",
        "read_to_string(\"/proc/modules\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/telemetry_probe.rs",
        "read_to_string(dir.join(\"debug-deny-detach\"))",
        LAB,
    ),
    (
        "crates/nn-linux/src/telemetry_probe.rs",
        "read_to_string(dir.join(\"debug-probe-blind\"))",
        LAB,
    ),
    (
        "crates/nn-linux/src/verifier_check.rs",
        "read_to_string(\"/proc/sys/kernel/osrelease\")",
        KNOB,
    ),
    // lot 332: the kprobe's trace of one load; unreadable, the program has
    // no count and the headroom gate fails it ("unmeasured")
    (
        "crates/nn-linux/src/verifier_check.rs",
        "read_to_string(self.instance.join(\"trace\"))",
        LAB,
    ),
    (
        "crates/nn-linux/src/worker/supervisor.rs",
        "read_state(format!(\"/proc/{pid}/stat\"))",
        PROC,
    ),
    // lot 353: a FUSE connection's waiting count (fusectl, the kernel's):
    // unreadable, no request is known waiting and nothing is aborted
    (
        "watchdog/src/lib.rs",
        "read_to_string(connections.join(conn.to_string()).join(\"waiting\"))",
        KNOB,
    ),
    // lot 353: the agent's and PID 1's mount tables, searched for a FUSE
    // holding a stuck agent: unreadable, none is found and none aborted
    // (lot 1.7a: read as bytes, `mount_tables`)
    ("watchdog/src/lib.rs", "read_all(p)", PROC),
    // lot 353: the watchdog's stuck marker, read at a SIGINT: unreadable,
    // the stop is an operator's `sigint` (the hold record still names the
    // recovery, signed at the next start)
    (
        "crates/nn-linux/src/self_integrity.rs",
        "read_state(path)",
        OWN,
    ),
    // lot 353: the lab's `debug-walk-on-workers` trigger file
    ("agent/src/run_loop.rs", "read_to_string(&trigger)", LAB),
    (
        "watchdog/src/lib.rs",
        "read_all(format!(\"/proc/{pid}/stat\"))",
        PROC,
    ),
    ("watchdog/src/lib.rs", "read_all(\"/proc/stat\")", KNOB),
    // The review of #538's re-check (G3): one entry per site — the second
    // sites under a key listed above — and the sites of the forms rule 2
    // now catches (`is_ok_and`, `map_or`, `Type::default()`, a later
    // statement).
    (
        "agent/src/config/overlay_floor.rs",
        "fs::read(audit_log)",
        OWN,
    ),
    // lot 388: the one reader of PID 1's comm, moved from the agent's
    // pipeline (shared with the workers' supervisor and the watchdog's round)
    (
        "crates/nn-linux/src/self_integrity.rs",
        "read_state(\"/proc/1/comm\")",
        PROC,
    ),
    ("agent/src/run_loop.rs", "read_to_string(&trigger)", LAB),
    ("agent/src/run_loop.rs", "read_to_string(&trigger)", LAB),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(self.inner.proc_root.join(pid.to_string()).join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-core/src/posture/lineage.rs",
        "read_state(self.inner.proc_root.join(pid.to_string()).join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/cgroup_join.rs",
        "read_to_string(STATE_PATH)",
        OWN,
    ),
    (
        "crates/nn-linux/src/fim/honeypot.rs",
        "read_to_string(state_dir.join(BOOT_ID_FILE))",
        OWN,
    ),
    (
        "crates/nn-linux/src/keys/mod.rs",
        "read_to_string(&pub_path)",
        OWN,
    ),
    (
        "crates/nn-linux/src/known_system_prog.rs",
        "read_state(p)",
        PROC,
    ),
    (
        "crates/nn-linux/src/response/block_outbound.rs",
        "read_state(format!(\"/proc/{pid}/cgroup\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/response/block_outbound.rs",
        "read_state(format!(\"/proc/{pid}/cgroup\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/response/kill.rs",
        "read_to_string(dir.join(\"cgroup.events\"))",
        KILLCG,
    ),
    (
        "crates/nn-linux/src/response/kill.rs",
        "read_to_string(dir.join(\"cgroup.events\"))",
        KILLCG,
    ),
    (
        "crates/nn-linux/src/response/kill.rs",
        "read_state(format!(\"/proc/{pid}/cgroup\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "read_state(path)",
        OWN,
    ),
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "read_state(dir.join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "read_state(dir.join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "read_state(task.join(tid).join(\"stat\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sensors/pump.rs",
        "read_to_string(DEBUG_RING_DROP)",
        LAB,
    ),
    // lot 315 (#542, merged in): the copy-on-write guard's task `stat`, read
    // as bytes — a task gone is no task
    (
        "agent/src/cow/fanotify.rs",
        "read_state(format!(\"/proc/{tid}/stat\"))",
        PROC,
    ),
    // lot 312 (#543): the block's read-back and the quarantine's offender
    (
        "crates/nn-linux/src/response/block_outbound.rs",
        "read_state(format!(\"/proc/{pid}/cgroup\"))",
        READBACK,
    ),
    // the filesystem uid the offender acts as: unknown, the quarantine
    // judges no owner its own and refuses
    (
        "crates/nn-linux/src/response/quarantine.rs",
        "read_state(format!(\"/proc/{pid}/status\"))",
        PROC,
    ),
    // lot 1.7a: the sites the AST scan finds and the lexical one missed (an
    // `Err` arm with a guard — `Err(e) if e.kind() == NotFound` — or a
    // `lines()` loop whose skip has a guard): each a missing file or a
    // line that is not UTF-8 taken as the default, any other error kept
    (
        "crates/nn-admin/src/heartbeat.rs",
        "fs::read(path)",
        "nn-admin's heartbeat watch's own state file: absent, the watch starts afresh (no \
         state yet); any other error is the command's error, never an empty state",
    ),
    (
        "crates/nn-admin/src/heartbeat.rs",
        "read_state(&w.state)",
        "nn-admin's heartbeat watch's own state, unreadable: re-anchored only when the operator \
         asked (`--reanchor`, printed as a NOTE); otherwise the check fails with the reason",
    ),
    (
        "crates/nn-linux/src/agent_id.rs",
        "read_to_string(path)",
        "the agent's own id file: absent, a new id is minted (a first boot); present but \
         unreadable or corrupt, refused (never minted again silently)",
    ),
    (
        "crates/nn-linux/src/install_manifest.rs",
        "read_to_string(manifest_path)",
        "install.sh's own manifest: absent, no install profile (not installed by the \
         installer); unreadable, an invalid profile with its reason — the stricter side",
    ),
    (
        "crates/nn-linux/src/response/block_outbound.rs",
        "read_state(dir.join(\"net\").join(table))",
        "a process's own `/proc/<pid>/net/<table>`, read as bytes: absent, a protocol the \
         kernel does not have (that table skipped); any other error counts every socket held, \
         the stricter side",
    ),
    (
        "crates/nn-linux/src/response/quarantine.rs",
        "fs::read(&index_path)",
        OWN,
    ),
    (
        "crates/nn-linux/src/shutdown_marker.rs",
        "read_to_string(path)",
        "the agent's own shutdown marker: absent, no clean stop recorded (the stricter \
         reading of the last boot); any other error is an error",
    ),
    (
        "agent/src/admin/handlers/fim.rs",
        "lines()",
        "the agent's own FIM records: a line that is not UTF-8 is consumed and skipped (lot \
         311, BUG69), any other error ends the read",
    ),
    (
        "agent/src/detection_store.rs",
        "lines()",
        "the agent's own detection store: a line that is not UTF-8 skipped (lot 297, BUG69), \
         any other error the end of the file",
    ),
    (
        "agent/src/detection_store.rs",
        "lines()",
        "the agent's own detection store (lot 297, BUG74): a line that is not UTF-8 skipped, a \
         read error the end of the file",
    ),
];

/// Whether a path's values name a process's own `/proc` entry or the mount
/// table: one ends in an entry's name, or is a per-process path whose last
/// component this reader cannot know (`/proc/{pid}/{entry}`).
fn names_proc_entry(values: &[String]) -> bool {
    values.iter().any(|v| {
        ENTRIES.iter().any(|e| v.ends_with(e))
            || (v.starts_with(&format!("/proc/{}/", ast::UNKNOWN))
                && v.ends_with(&format!("{0}/{0}", ast::UNKNOWN)))
    })
}

/// The read `e` is, or holds through a `let` or an iterator's item (an
/// `unwrap`, `?`, `&` between): its call (`fs::read(p)`, `read_all(p)`;
/// a `read_to_end`'s buffer is no such call).
fn read_call<'a>(
    c: &Corpus<'a>,
    rel: &str,
    e: &'a Expr,
    scope: Option<ast::FnId>,
    depth: u8,
) -> Option<(&'a syn::ExprCall, Option<ast::FnId>)> {
    if depth > 4 {
        return None;
    }
    match ast::peel(e) {
        Expr::MethodCall(m)
            if ["unwrap", "expect", "ok", "as_slice", "as_ref", "to_vec"]
                .contains(&m.method.to_string().as_str()) =>
        {
            read_call(c, rel, &m.receiver, scope, depth + 1)
        }
        Expr::Call(call) if matches!(ast::peel(&call.func), Expr::Path(p) if ast::last(&p.path).contains("read")) => {
            Some((call, scope))
        }
        Expr::Path(p) if p.path.segments.len() == 1 => c
            .bound(rel, scope, &ast::last(&p.path))
            .iter()
            .filter(|b| !b.param)
            .find_map(|b| read_call(c, rel, b.expr, b.scope, depth + 1)),
        _ => None,
    }
}

/// Rule 1's violations in `rel` (their lines): a strict text read —
/// `read_to_string` (a function or a reader's method), `read_line` (lot
/// 1.7a), `String::from_utf8`/`str::from_utf8` of a read (not of a field
/// of one), `lines()` of a reader — of a process's `/proc` entry or the
/// mount table, whatever holds the path ([`names_proc_entry`] of the values
/// the read's path can have: through a `let`, a `const`, an array's item, a
/// helper's parameter or returned value, a reader built over `let`s).
fn strict_proc_reads(c: &Corpus<'_>, rel: &str) -> Vec<usize> {
    let mut out: Vec<usize> = strict_sites(c, rel)
        .into_iter()
        .map(|(l, _, _)| l)
        .collect();
    out.dedup();
    out
}

/// [`strict_proc_reads`] with each site's item and the value that names
/// the entry.
fn strict_sites(c: &Corpus<'_>, rel: &str) -> Vec<(usize, String, String)> {
    let ix = &c.files[rel];
    let mut out = Vec::new();
    for call in &ix.calls {
        let full: Vec<Vec<String>> = call
            .path
            .as_ref()
            .map(|p| ix.full_paths(p))
            .unwrap_or_default();
        let ends = |t: &[&str]| full.iter().any(|p| ast::path_ends(p, t));
        let paths: Vec<String> = match (call.name.as_str(), call.receiver) {
            ("read_to_string" | "read_line", Some(r)) => c.values(rel, r, call.scope),
            ("read_to_string", None) => call
                .args
                .iter()
                .flat_map(|a| c.values(rel, a, call.scope))
                .collect(),
            ("lines", Some(r)) if call.args.is_empty() => {
                // a reader's lines (a file opened), not a string's
                let opened = c.calls_under(rel, r, call.scope);
                if !opened
                    .iter()
                    .any(|n| n.contains("open") || n.contains("BufReader"))
                {
                    continue;
                }
                c.values(rel, r, call.scope)
            }
            ("from_utf8", None)
                if ends(&["String", "from_utf8"]) || ends(&["str", "from_utf8"]) =>
            {
                // a strict decode with a lossy fallback is no strict read
                let (_, chain, parent) = ast::spine(call.expr, &call.anc);
                let lossy = chain
                    .iter()
                    .any(|m| ast::compact(m).contains("from_utf8_lossy"))
                    || matches!(parent, Some(Anc::Expr(Expr::Match(m))) if ast::compact(m).contains("from_utf8_lossy"));
                if lossy {
                    continue;
                }
                let Some((read, scope)) = call
                    .args
                    .first()
                    .and_then(|a| read_call(c, rel, a, call.scope, 0))
                else {
                    continue;
                };
                read.args
                    .iter()
                    .take(1)
                    .flat_map(|a| c.values(rel, a, scope))
                    .collect()
            }
            _ => continue,
        };
        if let Some(v) = paths
            .iter()
            .find(|v| names_proc_entry(std::slice::from_ref(v)))
        {
            out.push((call.line, call.item.clone(), v.clone()));
        }
    }
    out.sort();
    out.dedup_by_key(|(l, _, _)| *l);
    out
}

/// The reads rule 2 looks at by a method's or a path's last name: the
/// strict and the tolerant text reads, the byte read beneath the kernel's
/// views (lot 353).
const READ_NAMES: &[&str] = &[
    "read_to_string",
    "read_state",
    "read_config",
    "read_lossy",
    "read_all",
];

/// The name rule 2 keys a read by (`fs::read`, `mountinfo::read`,
/// `read_state`): the path as written first (what [`KNOWN`] names), then
/// through the file's imports (lot 1.7a: `use std::fs as f; f::read`).
fn read_name(ix: &Index<'_>, segs: &[String]) -> Option<&'static str> {
    std::iter::once(segs.to_vec())
        .chain(ix.full_paths(segs))
        .find_map(|p| {
            if ast::path_ends(&p, &["mountinfo", "read"]) {
                Some("mountinfo::read")
            } else if ast::path_ends(&p, &["fs", "read"]) {
                Some("fs::read")
            } else {
                READ_NAMES
                    .iter()
                    .copied()
                    .find(|n| p.last().is_some_and(|l| l == n))
            }
        })
}

/// The methods that turn a read's failure into a value: an `Option`, a
/// default, a boolean (the review of #538's re-check, G3), the
/// configuration reader's collapse of what cannot be judged into nothing;
/// lot 1.7a: an iterator of the reads that succeeded (`flatten`).
const DEFAULTING: &[&str] = &[
    "ok",
    "unwrap_or_default",
    "unwrap_or",
    "unwrap_or_else",
    "is_ok_and",
    "map_or",
    "map_or_else",
    "text",
    "flatten",
];

/// What an `Err` arm that turns the error into an empty or a default value
/// holds (`Err(_) => return Vec::new()`, `Err(e) => { warn!(..); None }`,
/// `=> continue`).
const DEFAULT_VALUES: &[&str] = &[
    "Vec::new()",
    "String::new()",
    "::default()",
    "HashMap::new()",
    "BTreeMap::new()",
    "HashSet::new()",
    "BTreeSet::new()",
    "None",
    "continue",
    "false",
    "true",
    "\"\"",
];

/// Whether a `match` on a read turns its error into a default: an `Err`
/// arm that is one, or (lot 1.7a: `matches!(read(p), Ok(_))`) a wildcard
/// arm that is one when no arm names the error.
fn default_match(m: &syn::ExprMatch) -> bool {
    let names_err = m
        .arms
        .iter()
        .any(|a| ast::pat_variant(&a.pat).as_deref() == Some("Err"));
    m.arms.iter().any(|a| {
        default_arm(a)
            || (!names_err
                && matches!(&a.pat, syn::Pat::Wild(_))
                && default_body(&ast::compact(&a.body)))
    })
}

/// Whether an `Err` arm's body is a default (not an error, not a
/// condition's failure).
fn default_arm(arm: &syn::Arm) -> bool {
    if ast::pat_variant(&arm.pat).as_deref() != Some("Err") {
        return false;
    }
    default_body(&ast::compact(&arm.body))
}

/// Whether an arm's body (its tokens, whitespace dropped) is a default.
fn default_body(body: &str) -> bool {
    let body: String = body.chars().take(160).collect();
    if body.contains(".failed(") || body.contains(".holds(") || body.contains("Err(") {
        return false;
    }
    DEFAULT_VALUES.iter().any(|d| body.contains(d))
        || body == "[]"
        || body
            .trim_start_matches('{')
            .trim_start_matches("return")
            .starts_with('0')
}

/// The spine of `e` (see [`ast::spine`]), continued through an array or a
/// tuple it is an item of (lot 1.7a: `[read(a), read(b)].into_iter()
/// .flatten()`): `(top, its methods in order, the ancestor above, the
/// ancestors of the top)`.
fn spine_through_items<'a, 'b>(
    e: &'a Expr,
    anc: &'b [Anc<'a>],
) -> (
    &'a Expr,
    Vec<&'a syn::ExprMethodCall>,
    Option<Anc<'a>>,
    &'b [Anc<'a>],
) {
    let (mut e, mut anc) = (e, anc);
    let mut methods = Vec::new();
    loop {
        let (top, chain, parent) = ast::spine(e, anc);
        methods.extend(chain);
        let depth = anc
            .iter()
            .rposition(|a| matches!(a, Anc::Expr(x) if std::ptr::eq(*x, top)))
            .unwrap_or(anc.len());
        let up = &anc[..depth];
        match parent {
            Some(Anc::Expr(p @ (Expr::Array(_) | Expr::Tuple(_)))) => {
                let i = up.len() - 1;
                e = p;
                anc = &up[..i];
            }
            _ => return (top, methods, parent, up),
        }
    }
}

/// Whether the read (or the use of a `let` that holds it) at `e`, with its
/// ancestors `anc`, turns its failure into a default.
fn defaults(e: &Expr, anc: &[Anc<'_>]) -> bool {
    let (top, chain, parent, _) = spine_through_items(e, anc);
    if chain
        .iter()
        .any(|m| DEFAULTING.contains(&m.method.to_string().as_str()))
    {
        return true;
    }
    // the statement before it: an `if let Ok`, a `while let Ok`, a `let
    // Ok(…) = … else`
    let mut child: &Expr = e;
    for a in anc.iter().rev() {
        match a {
            Anc::Local(l) => {
                if ast::pat_variant(&l.pat).as_deref() == Some("Ok")
                    && l.init.as_ref().is_some_and(|i| i.diverge.is_some())
                {
                    return true;
                }
                break;
            }
            Anc::Expr(x) => {
                match x {
                    Expr::Let(l) if ast::pat_variant(&l.pat).as_deref() == Some("Ok") => {
                        return true;
                    }
                    Expr::If(i) if !std::ptr::eq(&*i.cond, child) => break,
                    Expr::While(w) if !std::ptr::eq(&*w.cond, child) => break,
                    Expr::Match(m) if !std::ptr::eq(&*m.expr, child) => break,
                    Expr::Block(_)
                    | Expr::Unsafe(_)
                    | Expr::Loop(_)
                    | Expr::Closure(_)
                    | Expr::Async(_)
                    | Expr::Const(_)
                    | Expr::TryBlock(_)
                    | Expr::ForLoop(_) => break,
                    _ => {}
                }
                child = x;
            }
        }
    }
    // a `match` on it with an `Err` arm that is a default
    matches!(parent, Some(Anc::Expr(Expr::Match(m))) if std::ptr::eq(&*m.expr, top) && default_match(m))
}

/// The review of #538's re-check (G3): a read bound by a `let` whose
/// statement keeps the `Result` (`let r = mountinfo::read(..);`, the bare
/// call), and whose next use in the function turns it into a default.
fn defaults_later(ix: &Index<'_>, call: &ast::Call<'_>) -> bool {
    let (top, chain, parent) = ast::spine(call.expr, &call.anc);
    let Some(Anc::Local(l)) = parent else {
        return false;
    };
    let syn::Pat::Ident(id) = &l.pat else {
        return false;
    };
    // the bare call, in parentheses or not (`?` binds the value instead)
    let mut bare = top;
    while let Expr::Paren(syn::ExprParen { expr, .. }) | Expr::Group(syn::ExprGroup { expr, .. }) =
        bare
    {
        bare = expr;
    }
    if !chain.is_empty()
        || !std::ptr::eq(bare, call.expr)
        || l.init.as_ref().is_none_or(|i| i.diverge.is_some())
    {
        return false;
    }
    let name = id.ident.to_string();
    let end = quote::ToTokens::to_token_stream(&l.semi_token)
        .into_iter()
        .next()
        .map_or(call.at, |t| t.span().byte_range().end);
    ix.paths
        .iter()
        .filter(|p| p.scope == call.scope && p.at > end && p.segs.len() == 1 && p.segs[0] == name)
        .min_by_key(|p| p.at)
        .is_some_and(|p| defaults(p.expr, &p.anc))
}

/// The key of a read: its name and its arguments as written, whitespace
/// and comments dropped, at most 120 characters (what [`KNOWN`] names).
fn key(ix: &Index<'_>, name: &str, e: &Expr) -> String {
    let args = match e {
        Expr::Call(c) => ix.source(c.paren_token.span.open(), c.paren_token.span.close()),
        Expr::MethodCall(m) => ix.source(m.paren_token.span.open(), m.paren_token.span.close()),
        _ => String::new(),
    };
    format!("{name}{args}")
        .chars()
        .filter(|c| !c.is_whitespace())
        .take(120)
        .collect()
}

/// Rule 2's sites in `rel`: `(line, key)` — a read whose failure turns
/// into a default ([`defaults`], [`defaults_later`]), a reader passed as a
/// value to an iterator that keeps only what it read (`flat_map`,
/// `filter_map`, a defaulting chain), and a `lines()` loop that skips its
/// read errors. The key is the read as written, spaces dropped.
fn defaulted_reads(c: &Corpus<'_>, rel: &str) -> Vec<(usize, String)> {
    let ix = &c.files[rel];
    let mut out = Vec::new();
    for call in &ix.calls {
        let name = match (&call.receiver, &call.path) {
            (Some(_), _) => READ_NAMES.iter().copied().find(|n| *n == call.name),
            (None, Some(p)) => read_name(ix, p),
            _ => None,
        };
        let Some(name) = name else {
            continue;
        };
        if defaults(call.expr, &call.anc) || defaults_later(ix, call) {
            out.push((call.line, key(ix, name, call.expr)));
        }
    }
    // a reader as a value: `paths.iter().map(fs::read_to_string).flatten()`
    for r in ix.paths.iter().filter(|r| !r.called) {
        let Some(name) = read_name(ix, &r.segs) else {
            continue;
        };
        let Some(i) = r
            .anc
            .iter()
            .rposition(|a| matches!(a, Anc::Expr(Expr::MethodCall(_))))
        else {
            continue;
        };
        let Anc::Expr(m @ Expr::MethodCall(mc)) = r.anc[i] else {
            continue;
        };
        if i + 1 != r.anc.len() {
            continue;
        }
        if ["flat_map", "filter_map"].contains(&mc.method.to_string().as_str())
            || defaults(m, &r.anc[..i])
        {
            out.push((r.line, format!("{name} (a reader as a value)")));
        }
    }
    // a `lines()` loop that skips its read errors
    for call in ix
        .calls
        .iter()
        .filter(|c| c.name == "lines" && c.receiver.is_some() && c.args.is_empty())
    {
        let (top, chain, parent) = ast::spine(call.expr, &call.anc);
        let skips_in_chain = chain.first().is_some_and(|m| {
            let n = m.method.to_string();
            n == "flatten"
                || n == "flat_map"
                || (["map_while", "filter_map"].contains(&n.as_str())
                    && m.args.first().is_some_and(|a| {
                        let t = ast::compact(a);
                        t == "Result::ok" || t.ends_with(".ok()")
                    }))
        });
        let skips_in_loop = matches!(parent, Some(Anc::Expr(Expr::ForLoop(f))) if std::ptr::eq(&*f.expr, top) && loop_skips(&f.pat, &f.body));
        if skips_in_chain || skips_in_loop {
            out.push((call.line, "lines()".to_string()));
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Whether a `for` loop's body skips an item that is an error: a `match`
/// on the loop's item with an `Err` arm that is `continue`, or a `let
/// Ok(…) = item else { continue }`.
fn loop_skips(pat: &syn::Pat, body: &syn::Block) -> bool {
    let mut names = Vec::new();
    ast::pat_idents(pat, &mut names);
    let is_item = |e: &Expr| matches!(ast::peel(e), Expr::Path(p) if names.iter().any(|n| p.path.is_ident(n)));
    struct Skips<'n> {
        is_item: &'n dyn Fn(&Expr) -> bool,
        found: bool,
    }
    impl<'a> syn::visit::Visit<'a> for Skips<'_> {
        fn visit_expr_match(&mut self, m: &'a syn::ExprMatch) {
            if (self.is_item)(&m.expr)
                && m.arms.iter().any(|a| {
                    ast::pat_variant(&a.pat).as_deref() == Some("Err")
                        && ast::compact(&a.body).starts_with("continue")
                })
            {
                self.found = true;
            }
            syn::visit::visit_expr_match(self, m);
        }
        fn visit_local(&mut self, l: &'a syn::Local) {
            if ast::pat_variant(&l.pat).as_deref() == Some("Ok")
                && l.init.as_ref().is_some_and(|i| {
                    (self.is_item)(&i.expr)
                        && i.diverge
                            .as_ref()
                            .is_some_and(|(_, d)| ast::compact(d).contains("continue"))
                })
            {
                self.found = true;
            }
            syn::visit::visit_local(self, l);
        }
        fn visit_expr_closure(&mut self, _: &'a syn::ExprClosure) {}
    }
    let mut s = Skips {
        is_item: &is_item,
        found: false,
    };
    syn::visit::Visit::visit_block(&mut s, body);
    s.found
}

/// The sources of every file of [`SCAN`] (test files left out).
fn scan_sources(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for dir in SCAN {
        for (rel, text) in ast::tree_sources(root, dir) {
            if !is_test_file(&rel) {
                out.insert(rel, text);
            }
        }
    }
    out
}

/// A corpus of one fixture file (its production code).
fn fixture(text: &str) -> (String, syn::File) {
    (text.to_string(), ast::production("fixture.rs", text))
}

#[test]
fn no_process_entry_is_read_as_strict_text() {
    let sources = scan_sources(&repo_root());
    assert!(sources.len() > 300, "scanned {} files", sources.len());
    let parsed = ast::parse_all(&sources, true);
    let c = Corpus::of(&sources, &parsed);
    let found: Vec<String> = sources
        .keys()
        .flat_map(|f| {
            strict_sites(&c, f)
                .into_iter()
                .map(move |(l, item, v)| format!("{f}:{l} `{item}` reads {v:?}"))
        })
        .collect();
    assert!(
        found.is_empty(),
        "a process's /proc entry read with read_to_string (a comm, a cgroup, a mount \
         that is not UTF-8 fails the whole file): read it with \
         nn_linux::state_read::read_state, the host's read_state or nn_linux::mountinfo — \
         {found:#?}"
    );
}

#[test]
fn reads_that_default_on_failure_are_known() {
    let sources = scan_sources(&repo_root());
    let parsed = ast::parse_all(&sources, true);
    let c = Corpus::of(&sources, &parsed);
    let mut problems = Vec::new();
    let mut used = vec![0usize; KNOWN.len()];
    for file in sources.keys() {
        for (line, key) in defaulted_reads(&c, file) {
            // one entry for one site (G3: a second site under a known key
            // is a site of its own, listed again with its reason)
            match KNOWN
                .iter()
                .enumerate()
                .position(|(n, (f, k, _))| f == file && *k == key && used[n] == 0)
            {
                Some(n) => used[n] += 1,
                None => problems.push(format!(
                    "{file}:{line}: `{key}` turns a failed read into a default — keep the last \
                     good state (nn_linux::state_read::LastGood, a Condition) or list the site \
                     in KNOWN with its reason (one entry per site)"
                )),
            }
        }
    }
    for ((file, key, why), n) in KNOWN.iter().zip(&used) {
        assert!(sources.contains_key(*file), "{file}: in KNOWN, not scanned");
        assert!(why.len() > 20, "{file}: give the reason");
        if *n == 0 {
            problems.push(format!("{file}: `{key}` in KNOWN, no such site any more"));
        }
    }
    assert!(problems.is_empty(), "{problems:#?}");
}

/// Rule 1 fails on every strict form and path source the review of #538
/// (F4) planted, and not on the tolerant readers.
#[test]
fn rule_one_catches_every_planted_strict_read() {
    let planted = r#"
const MI: &str = "/proc/self/mountinfo";
struct Ctl { roots_source: PathBuf }
impl Ctl {
    fn new() -> Self { Ctl { roots_source: "/proc/self/mountinfo".into() } }
    fn roots(&self) -> String {
        std::fs::read_to_string(&self.roots_source)?
    }
}
fn a(pid: u32) -> io::Result<String> {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
}
fn b() -> io::Result<String> {
    std::fs::read_to_string(MI)
}
fn c(pid: u32) -> io::Result<String> {
    let mut s = String::new();
    File::open(format!("/proc/{pid}/status"))?.read_to_string(&mut s)?;
    Ok(s)
}
fn d(pid: u32) -> io::Result<String> {
    Ok(String::from_utf8(fs::read(format!("/proc/{pid}/stat"))?).map_err(io::Error::other)?)
}
fn e(pid: u32, entry: &str) -> io::Result<String> {
    std::fs::read_to_string(format!("/proc/{pid}/{entry}"))
}
fn f() -> usize {
    let r = BufReader::new(File::open("/proc/self/mountinfo").unwrap());
    r.lines().count()
}
fn g(pid: u32) -> io::Result<String> {
    let path = format!("/proc/{pid}/comm");
    std::fs::read_to_string(path)
}
// the copy-on-write writer's start as lot 315 (#542) read it: a writer
// named `\xff\xfe` was "not alive" and the in-place restore ran under it
fn h(proc_root: &Path, pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    parse_stat_start(&stat)
}
"#;
    let (t, f) = fixture(planted);
    let c = Corpus::new([("fixture.rs", t.as_str(), &f)]);
    assert_eq!(
        strict_proc_reads(&c, "fixture.rs"),
        vec![7, 11, 14, 18, 22, 25, 29, 33, 38]
    );
    let clean = r#"
fn a(pid: u32) -> io::Result<String> {
    nn_linux::state_read::read_state(format!("/proc/{pid}/stat"))
}
fn b() -> io::Result<String> {
    std::fs::read_to_string("/proc/sys/kernel/pid_max")
}
fn c() -> io::Result<MountTable> {
    nn_linux::mountinfo::read(Path::new("/proc/self/mountinfo"))
}
"#;
    let (t, f) = fixture(clean);
    let c = Corpus::new([("fixture.rs", t.as_str(), &f)]);
    assert!(strict_proc_reads(&c, "fixture.rs").is_empty());
}

/// Lot 1.7a (the review of #624): the reader reads a `macro_rules!`'s
/// rules as Rust — a strict read in a transcriber is a site of rule 1 —
/// and a macro of a grammar of its own part by part; it fails the walker,
/// naming it, on a macro it does not read: a body of no grammar it knows,
/// `cfg_if!`, a macro in a type, a transcriber that is no Rust, a
/// `matches!` that is none.
#[test]
fn every_macro_is_read_or_fails_the_walker() {
    let planted = r#"
macro_rules! status {
    ($pid:expr) => {
        std::fs::read_to_string(format!("/proc/{}/status", $pid))
    };
}
fn a() {
    tracing::warn!(target: "x", t = %std::fs::read_to_string("/proc/self/mountinfo").unwrap(), "m");
}
"#;
    let (t, f) = fixture(planted);
    let c = Corpus::new([("fixture.rs", t.as_str(), &f)]);
    assert_eq!(strict_proc_reads(&c, "fixture.rs"), vec![4, 8]);
    for (name, text) in [
        ("m!", "fn a() { m!(a => b); }"),
        ("m!", "m! { a => b }"),
        (
            "cfg_if!",
            "cfg_if::cfg_if! { if #[cfg(unix)] { fn a() {} } }",
        ),
        (
            "cfg_if!",
            "fn a() { cfg_if::cfg_if! { if #[cfg(unix)] { b(); } } }",
        ),
        ("m!", "fn a() { let x: m!() = 1; }"),
        ("macro_rules! m", "macro_rules! m { () => { => }; }"),
        ("matches!", "fn a() -> bool { matches!(x) }"),
    ] {
        let e = std::panic::catch_unwind(|| ast::parse("fixture.rs", text)).expect_err(text);
        let m = e.downcast_ref::<String>().cloned().unwrap_or_default();
        assert!(m.contains(&format!("`{name}`")), "{text}: {m}");
    }
}

/// Rule 2 fails on every default the review of #538 (F4) planted — the
/// tolerant readers' included — and the re-check's (G3): `is_ok_and`,
/// `map_or`, `map_or_else`, a `Type::default()` arm, a read bound by a `let`
/// and defaulted in a later statement, the configuration reader's
/// `.text()`; and not on a read whose error is propagated or that keeps the
/// last good state.
#[test]
fn rule_two_catches_every_planted_default() {
    let planted = r#"
fn a(p: &Path) -> String {
    if let Ok(t) = std::fs::read_to_string(p) { return t; }
    String::new()
}
fn b(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_else(|_| String::new())
}
fn c(p: &Path) -> Vec<String> {
    match std::fs::read_to_string(p) {
        Ok(t) => t.lines().map(str::to_string).collect(),
        Err(_) => return Vec::new(),
    }
}
fn d(p: &Path) -> Vec<String> {
    std::fs::read_to_string(p).map(|t| vec![t]).unwrap_or(Vec::new())
}
fn e(r: impl BufRead) -> usize {
    let mut n = 0;
    for line in r.lines() {
        match line {
            Ok(l) => n += l.len(),
            Err(_) => continue,
        }
    }
    n
}
fn f(r: impl BufRead) -> usize {
    r.lines().map_while(Result::ok).count()
}
fn g(p: &Path) -> String {
    nn_linux::state_read::read_state(p).unwrap_or_default()
}
fn h(&self) -> Vec<Root> {
    guarded_roots(&nn_linux::mountinfo::read(&self.roots_source).unwrap_or_default())
}
fn i(p: &Path) -> String {
    read_lossy(p).unwrap_or_default()
}
fn j(p: &Path) -> Option<Vec<u8>> {
    std::fs::read(p).ok()
}
fn k(p: &Path) -> String {
    let Ok(t) = std::fs::read_to_string(p) else {
        return String::new();
    };
    t
}
fn l(p: &Path) -> String {
    match std::fs::read_to_string(p) {
        Ok(t) => t,
        Err(e) => {
            warn!("{e}");
            String::new()
        }
    }
}
fn m(p: &Path) -> bool {
    std::fs::read_to_string(p).is_ok_and(|t| t.contains("x"))
}
fn n(p: &Path) -> usize {
    std::fs::read_to_string(p).map_or(0, |t| t.len())
}
fn o(p: &Path) -> String {
    std::fs::read_to_string(p).map_or_else(|_| String::new(), |t| t)
}
fn q(&self) -> MountTable {
    match nn_linux::mountinfo::read(&self.roots_source) {
        Ok(t) => t,
        Err(_) => MountTable::default(),
    }
}
fn r(&self) -> MountTable {
    let read = nn_linux::mountinfo::read(&self.roots_source);
    let table = read.unwrap_or_default();
    table
}
fn s(p: &Path) -> String {
    let r = std::fs::read_to_string(p);
    if let Ok(t) = r { t } else { String::new() }
}
fn t(p: &Path) -> String {
    let got = read_state(p);
    match got {
        Ok(t) => t,
        Err(_) => String::new(),
    }
}
fn u(p: &Path) -> String {
    read_config(p).text().unwrap_or_default()
}
"#;
    let (t, f) = fixture(planted);
    let c = Corpus::new([("fixture.rs", t.as_str(), &f)]);
    let lines: Vec<usize> = defaulted_reads(&c, "fixture.rs")
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    assert_eq!(
        lines,
        vec![
            3, 7, 10, 16, 20, 29, 32, 35, 38, 41, 44, 50, 59, 62, 65, 68, 74, 79, 83, 90
        ],
        "{lines:?}"
    );
    let clean = r#"
fn a(p: &Path) -> io::Result<String> {
    let t = std::fs::read_to_string(p)?;
    Ok(t)
}
fn b(p: &Path) -> io::Result<String> {
    match std::fs::read_to_string(p) {
        Ok(t) => Ok(t),
        Err(e) => return Err(e),
    }
}
fn c(&mut self) {
    match nn_linux::mountinfo::read(&self.source) {
        Ok(t) => self.publish(&t),
        Err(e) => self.read.failed(&e),
    }
}
fn d(p: &Path) -> io::Result<u32> {
    let t = std::fs::read_to_string(p)?;
    Ok(t.trim().parse().unwrap_or(0))
}
fn e(&mut self) {
    let read = nn_linux::mountinfo::read(&self.source);
    match read {
        Ok(t) => self.publish(&t),
        Err(e) => self.read.failed(&e),
    }
}
"#;
    let (t, f) = fixture(clean);
    let c = Corpus::new([("fixture.rs", t.as_str(), &f)]);
    let found = defaulted_reads(&c, "fixture.rs");
    assert!(found.is_empty(), "{found:?}");
}

/// Lot 1.7a: the spellings that passed the lexical scan, each planted in a
/// copy of a scanned file (`crates/nn-linux/src/kernel_state.rs`): the
/// lexical scan finds no site more, the AST scan one more. Rule 1: a path
/// in an array iterated, passed to a helper, returned by a function, held
/// by a reader built over two `let`s; `read_line`; `str::from_utf8` of a
/// read. Rule 2: the read in parentheses, an item of an array flattened, a
/// reader passed as a value, an import under another name, `matches!`'s
/// wildcard arm, a log macro's argument in parentheses, a `let` holding
/// the read in parentheses.
#[test]
fn the_lexical_bypasses_are_caught() {
    let host = "crates/nn-linux/src/kernel_state.rs";
    let text = std::fs::read_to_string(repo_root().join(host)).unwrap();
    let lex = |t: &str| {
        let code = support::production(&support::strip_comments(t));
        (
            lexical::strict_proc_reads(&code).len(),
            lexical::defaulted_reads(&code).len(),
        )
    };
    let ast_n = |t: &str| {
        let parsed = ast::production(host, t);
        let c = Corpus::new([(host, t, &parsed)]);
        (
            strict_proc_reads(&c, host).len(),
            defaulted_reads(&c, host).len(),
        )
    };
    let (base_lex, base) = (lex(&text), ast_n(&text));
    for (rule, plant) in [
        (
            1,
            "fn planted() -> usize { let d = Path::new(\"/proc/self\"); let mut n = 0; for e in [\"stat\", \"status\"] { n += std::fs::read_to_string(d.join(e)).map_or(0, |t| t.len()); } n }",
        ),
        (
            1,
            "fn under(p: &str) -> std::io::Result<String> { std::fs::read_to_string(p) }\nfn planted() -> std::io::Result<String> { under(\"/proc/self/status\") }",
        ),
        (
            1,
            "fn path_of() -> &'static str { \"/proc/self/cgroup\" }\nfn planted() -> std::io::Result<String> { std::fs::read_to_string(path_of()) }",
        ),
        (
            1,
            "fn planted() -> usize { let p = \"/proc/self/mountinfo\"; let f = std::fs::File::open(p).unwrap(); let r = std::io::BufReader::new(f); r.lines().count() }",
        ),
        (
            1,
            "fn planted(r: &mut std::io::BufReader<std::fs::File>) -> usize { let mut s = String::new(); let f = std::fs::File::open(\"/proc/self/comm\").unwrap(); let mut b = std::io::BufReader::new(f); b.read_line(&mut s).unwrap(); s.len() }",
        ),
        (
            1,
            "fn planted() -> bool { std::str::from_utf8(&std::fs::read(\"/proc/self/cmdline\").unwrap()).is_ok() }",
        ),
        (
            2,
            "fn planted(p: &Path) -> Option<String> { (std::fs::read_to_string(p)).ok() }",
        ),
        (
            2,
            "fn planted(a: &Path, b: &Path) -> Vec<String> { [std::fs::read_to_string(a), Ok(b.display().to_string())].into_iter().flatten().collect() }",
        ),
        (
            2,
            "fn planted(ps: &[&Path]) -> Vec<String> { ps.iter().map(std::fs::read_to_string).flatten().collect() }",
        ),
        (
            2,
            "fn planted(ps: &[&Path]) -> Vec<String> { ps.iter().flat_map(std::fs::read_to_string).collect() }",
        ),
        (
            2,
            "use crate::mountinfo::read as mounts;\nfn planted(p: &Path) -> Option<MountTable> { mounts(p).ok() }",
        ),
        (
            2,
            "fn planted(p: &Path) -> bool { matches!(std::fs::read_to_string(p), Ok(t) if t.is_empty()) }",
        ),
        (
            2,
            "fn planted(p: &Path) { tracing::info!(text = %(std::fs::read_to_string(p)).unwrap_or_default(), \"x\"); }",
        ),
        (
            2,
            "fn planted(p: &Path) -> bool { let r = (std::fs::read_to_string(p)); r.is_ok_and(|t| t.is_empty()) }",
        ),
    ] {
        let copy = format!("{text}\n{plant}\n");
        let (l1, l2) = lex(&copy);
        let (a1, a2) = ast_n(&copy);
        if rule == 1 {
            assert_eq!(l1, base_lex.0, "the lexical scan saw it: {plant}");
            assert_eq!(a1, base.0 + 1, "{plant}");
        } else {
            assert_eq!(l2, base_lex.1, "the lexical scan saw it: {plant}");
            assert_eq!(a2, base.1 + 1, "{plant}");
        }
    }
}

/// The sites of every scanned file, the lexical ones beside them (to fill
/// [`KNOWN`]): a no-op unless `NN_PRINT_STATE_READS=1`.
#[test]
#[ignore = "prints the sites; NN_PRINT_STATE_READS=1, run by hand when the table moves"]
fn print_the_sites() {
    if std::env::var("NN_PRINT_STATE_READS").as_deref() != Ok("1") {
        return;
    }
    let sources = scan_sources(&repo_root());
    let parsed = ast::parse_all(&sources, true);
    let c = Corpus::of(&sources, &parsed);
    for (file, text) in &sources {
        let code = support::production(&support::strip_comments(text));
        let new: Vec<String> = defaulted_reads(&c, file)
            .into_iter()
            .map(|(_, k)| k)
            .collect();
        let old: Vec<String> = lexical::defaulted_reads(&code)
            .into_iter()
            .map(|(_, k)| k)
            .collect();
        for k in &new {
            if !old.contains(k) {
                println!("SITE+ {file}\t{k}");
            }
        }
        for k in &old {
            if !new.contains(k) {
                println!("SITE- {file}\t{k}");
            }
        }
        let (sn, so) = (strict_sites(&c, file), lexical::strict_proc_reads(&code));
        if sn.iter().map(|(l, _, _)| *l).collect::<Vec<_>>() != so {
            println!("STRICT {file}: ast {sn:?} lexical {so:?}");
        }
    }
}

/// The body of `fn name` in `file` (its production code), as tokens with
/// whitespace dropped, and the calls in it: `(tokens, call names, full
/// paths of its path calls)`.
fn fn_tokens(root: &Path, rel: &str, name: &str) -> (String, Vec<String>) {
    let text = std::fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
    let parsed = ast::production(rel, &text);
    let c = Corpus::new([(rel, text.as_str(), &parsed)]);
    let ix = &c.files[rel];
    let (id, f) = ix
        .fns
        .iter()
        .enumerate()
        .find(|(_, f)| f.name == name)
        .unwrap_or_else(|| panic!("fn {name} not found in {rel}"));
    let tokens = f.body.map(ast::compact).unwrap_or_default();
    let calls = ix
        .calls
        .iter()
        .filter(|c| c.scope == Some(id))
        .flat_map(|c| match &c.path {
            Some(p) => ix
                .full_paths(p)
                .into_iter()
                .map(|p| p.join("::"))
                .collect::<Vec<_>>(),
            None => vec![c.name.clone()],
        })
        .collect();
    (tokens, calls)
}

/// The re-check of #558 (F7): a regular FUSE file bound over a file the
/// kernel-state round reads stalled the whole round (`O_NONBLOCK` does not
/// reach FUSE's open and read) — the cross-view, the taint read, the CPU
/// watch, the held set's prune. The round's reads that resolve a path go
/// through its reader with a deadline (`state_read::ROUND_READER`), and a
/// stall of any of them makes the CPU watch's round unjudged (the third in
/// a row signed): the taint mask, the start's `/proc/1/stat`, a loader's
/// `/proc` files, the CPU watch's start reads and sources. Lot 1.7a: the
/// bodies read as Rust (a call by any path, an import, a macro's body).
#[test]
fn the_kernel_state_round_reads_within_a_deadline() {
    let root = repo_root();
    let k = "crates/nn-linux/src/kernel_state.rs";
    let (t, calls) = fn_tokens(&root, k, "tainted");
    assert!(t.contains("crate::state_read::ROUND_READER"), "{t}");
    assert!(
        !calls
            .iter()
            .any(|c| c.ends_with("read_to_string") || c.ends_with("state_read::read_state")),
        "{calls:?}"
    );
    let (spawn, _) = fn_tokens(&root, k, "spawn");
    assert!(
        spawn.contains("crate::own_cpus::round(&mutcpus,&crate::state_read::ROUND_READER)"),
        "{spawn}"
    );
    let text = std::fs::read_to_string(root.join(k)).unwrap();
    let parsed = ast::production(k, &text);
    let c = Corpus::new([(k, text.as_str(), &parsed)]);
    assert_eq!(
        c.files[k]
            .calls
            .iter()
            .filter(|c| c.name == "judge_on_host")
            .count(),
        1,
        "the loader's proof only within the deadline (known_within)"
    );
    assert!(
        fn_tokens(&root, k, "known_within")
            .0
            .contains("ROUND_READER")
    );
    let x = "crates/nn-linux/src/bpf_crossview.rs";
    assert!(
        fn_tokens(&root, x, "host_user_space_start_ns")
            .0
            .contains("ROUND_READER")
    );
    let (r, _) = fn_tokens(&root, "crates/nn-linux/src/own_cpus.rs", "round");
    for n in [
        "host_now,",
        "reader.run(\"the CPU watch's sources\",Sources::open)",
        "unjudged_by_stall(&mutr,reader.take_stall());",
    ] {
        let n: String = n.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(r.contains(&n), "{n}: {r}");
    }
    assert!(
        !r.contains("host_now()") && !r.contains("Sources::open()"),
        "{r}"
    );
}

/// The lexical scan before lot 1.7a, kept only to show the spellings it
/// missed.
mod lexical {
    /// A process's own `/proc` entries, as a path argument names them: a
    /// literal ending in the name, or a `join` of it.
    const PROC_ENTRIES: &[&str] = &[
        "stat\"",
        "status\"",
        "comm\"",
        "cgroup\"",
        "mountinfo\"",
        "cmdline\"",
        "environ\"",
    ];

    /// The argument list of the call whose `(` is at `open` in `code`.
    fn arguments(code: &str, open: usize) -> &str {
        let b = code.as_bytes();
        let mut depth = 0usize;
        for (i, c) in b.iter().enumerate().skip(open) {
            match c {
                b'(' => depth += 1,
                b')' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return &code[open + 1..i];
                    }
                }
                _ => {}
            }
        }
        &code[open + 1..]
    }

    /// `at` moved down to a char boundary of `code`.
    fn floor(code: &str, mut at: usize) -> usize {
        at = at.min(code.len());
        while !code.is_char_boundary(at) {
            at -= 1;
        }
        at
    }

    /// The start of the function `at` is in (its `fn `), or the file's start.
    fn function_start(code: &str, at: usize) -> usize {
        code[..at].rfind("fn ").unwrap_or(0)
    }

    /// The statement the call at `at` is in, before it: from the statement's
    /// start (the last `;`, `{` or `}` — never before the function's start).
    /// The review of #538's re-check (G3): a read bound by a `let` whose
    /// statement keeps the `Result` (`let r = mountinfo::read(..);`), and whose
    /// next use in the function turns it into a default
    /// (`let t = r.unwrap_or_default();`, `if let Ok(t) = r`, a `match r` arm).
    /// Only a statement that is the bare call (`let r = read(p);`): one with
    /// `?` or a chain binds the value, not the `Result`.
    fn defaults_later(code: &str, at: usize, name: &str) -> bool {
        let h = head(code, at).trim_start();
        let Some(rest) = h.strip_prefix("let ") else {
            return false;
        };
        let rest = rest.trim_start().trim_start_matches("mut ").trim_start();
        let bound: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if bound.is_empty() || bound == "_" || !rest[bound.len()..].trim_start().starts_with('=') {
            return false;
        }
        let open = at + name.len();
        let end = open + arguments(code, open).len() + 2;
        if !code[floor(code, end)..].trim_start().starts_with(';') {
            return false;
        }
        let end = floor(code, end);
        // the rest of the function: up to the next `fn`
        let stop = code[end..]
            .find("fn ")
            .map_or(code.len(), |j| end + j)
            .min(floor(code, end + 2000));
        let after = &code[end..stop];
        let is_ident = |c: char| c.is_alphanumeric() || c == '_';
        let mut from = 0;
        while let Some(j) = after[from..].find(bound.as_str()) {
            let k = from + j;
            from = k + bound.len();
            let before_ok = after[..k]
                .chars()
                .next_back()
                .is_none_or(|c| !is_ident(c) && c != '.');
            let after_ok = after[k + bound.len()..]
                .chars()
                .next()
                .is_none_or(|c| !is_ident(c));
            if !(before_ok && after_ok) {
                continue;
            }
            let pos = end + k;
            return defaults(head(code, pos), tail(code, pos));
        }
        false
    }

    fn head(code: &str, at: usize) -> &str {
        let from = function_start(code, at);
        let h = &code[from..at];
        // the last `;`, `{` or `}` outside a string literal (`format!("{pid}")`)
        let mut cut = 0;
        let mut in_str = false;
        let mut escaped = false;
        for (i, c) in h.char_indices() {
            match c {
                _ if escaped => escaped = false,
                '\\' if in_str => escaped = true,
                '"' => in_str = !in_str,
                ';' | '{' | '}' if !in_str => cut = i + 1,
                _ => {}
            }
        }
        &h[cut..]
    }

    /// The statement the call at `at` is in, from it: to its `;` at its own
    /// depth, or the end of the block it is in, at most 800 bytes and never
    /// into the next function — a `match` or an `if let` block whole.
    fn tail(code: &str, at: usize) -> &str {
        let b = code.as_bytes();
        let stop = floor(code, at + 800);
        let mut depth: i32 = 0;
        let mut i = at;
        while i < stop {
            match b[i] {
                b'(' | b'{' | b'[' => depth += 1,
                b')' | b'}' | b']' => {
                    depth -= 1;
                    if depth < 0 {
                        break;
                    }
                }
                b';' if depth == 0 => break,
                b'f' if code[i..].starts_with("fn ") && i > at => break,
                _ => {}
            }
            i += 1;
        }
        &code[at..floor(code, i)]
    }

    /// The calls named `names` in `code`: `(position, name)`, a definition
    /// (`fn name(`) left out; a longer name is not the shorter one's (`read(`
    /// inside `read_state(` is not a read).
    fn calls<'a>(code: &str, names: &[&'a str]) -> Vec<(usize, &'a str)> {
        let mut out: Vec<(usize, &str)> = Vec::new();
        for name in names {
            for (i, _) in code.match_indices(&format!("{name}(")) {
                let before = code[..i].chars().next_back();
                if before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
                    continue;
                }
                if code[..i].ends_with("fn ") {
                    continue;
                }
                out.push((i, name));
            }
        }
        out.sort();
        out
    }

    /// A path expression that names a process's own `/proc` entry or the mount
    /// table: a literal of [`PROC_ENTRIES`], or a per-process path whose last
    /// component is a variable (`format!("/proc/{pid}/{entry}")`).
    fn names_proc_entry(text: &str) -> bool {
        PROC_ENTRIES.iter().any(|e| text.contains(e))
            || text.contains("\"/proc/{") && text.contains("}/{")
    }

    /// The literal a path expression stands for in `code`, when the expression
    /// is a variable bound in the same function (`let x = …`), a `const`, or a
    /// field initialised with a literal (`field: "…"`, `field = "…"`).
    fn resolved<'a>(code: &'a str, at: usize, expr: &str) -> Vec<&'a str> {
        let word: String = expr
            .trim()
            .trim_start_matches('&')
            .trim_start_matches("self.")
            .trim_start_matches("Path::new(")
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '.')
            .collect();
        let leaf = word.rsplit('.').next().unwrap_or("").to_string();
        if leaf.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        let from = function_start(code, at);
        let body = &code[from..at];
        for pat in [format!("let {leaf} "), format!("let mut {leaf} ")] {
            if let Some(j) = body.rfind(&pat) {
                out.push(tail(code, from + j));
            }
        }
        for pat in [
            format!("const {leaf}:"),
            format!("static {leaf}:"),
            format!("{leaf}: \""),
            format!("{leaf} = \""),
            format!("{leaf}: PathBuf::from(\""),
            format!("{leaf}: Path::new(\""),
        ] {
            for (j, _) in code.match_indices(&pat) {
                out.push(tail(code, j));
            }
        }
        out
    }

    /// Rule 1's violations in one file's production code (their lines): a
    /// strict text read — `read_to_string` (a function or a reader's method),
    /// `String::from_utf8` of a read, `lines()` of a reader — of a process's
    /// `/proc` entry or the mount table, named in the read's argument or bound
    /// to it (a `let`, a `const`, a field's literal).
    pub fn strict_proc_reads(code: &str) -> Vec<usize> {
        let line = |i: usize| code[..i].matches('\n').count() + 1;
        let mut out = Vec::new();
        for (i, name) in calls(code, &["read_to_string", "String::from_utf8", "lines"]) {
            let args = arguments(code, i + name.len());
            // the path: the call's argument, or what the statement opened
            let mut exprs: Vec<&str> = vec![args];
            let stmt = format!("{}{}", head(code, i), tail(code, i));
            for opener in ["File::open(", ".open(", "fs::read(", "BufReader::new("] {
                for (j, _) in stmt.match_indices(opener) {
                    exprs.push(arguments(&stmt, j + opener.len() - 1));
                }
            }
            if name == "lines" || args.trim_start().starts_with("&mut") {
                // a reader's method: the reader bound earlier in the function
                let recv: String = head(code, i)
                    .chars()
                    .rev()
                    .skip_while(|c| *c == '.' || c.is_whitespace())
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                if !recv.is_empty() {
                    exprs.extend(resolved(code, i, &recv));
                }
            }
            let mut texts: Vec<String> = Vec::new();
            for e in &exprs {
                texts.push(e.to_string());
                texts.extend(resolved(code, i, e).into_iter().map(str::to_string));
            }
            if name == "String::from_utf8" && !stmt.contains("read") {
                continue;
            }
            if name == "lines"
                && !stmt.contains("open")
                && !texts.iter().skip(1).any(|t| t.contains("open"))
            {
                continue;
            }
            if texts.iter().any(|t| names_proc_entry(t)) {
                out.push(line(i));
            }
        }
        out.sort();
        out.dedup();
        out
    }

    /// The reads rule 2 looks at: the strict and the tolerant text reads, the
    /// byte read, the mount table's read.
    const READS: &[&str] = &[
        "read_to_string",
        "read_state",
        "read_config",
        "read_lossy",
        "mountinfo::read",
        "fs::read",
        // lot 353: `antitamper_bpf::kernel_roots::read_all`, `std::fs::read`
        // beneath the kernel's views
        "read_all",
    ];

    /// Whether the statement of a read turns its failure into a default.
    fn defaults(head: &str, tail: &str) -> bool {
        let h = head.replace(char::is_whitespace, "");
        let t = tail.replace(char::is_whitespace, "");
        if h.contains("ifletOk(")
            || h.contains("whileletOk(")
            || h.contains("letOk(") && t.contains("else")
        {
            return true;
        }
        // the read's own method chain: up to the block a `match` or an `if`
        // opens (its arms are looked at below), not into them
        let mut depth = 0i32;
        let mut chain_end = t.len();
        for (i, c) in t.char_indices() {
            match c {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                '{' if depth == 0 => {
                    chain_end = i;
                    break;
                }
                _ => {}
            }
        }
        let chain = &t[..chain_end];
        if [
            ".ok()",
            ".unwrap_or_default()",
            ".unwrap_or(",
            ".unwrap_or_else(",
            "map_while(Result::ok)",
            // the review of #538's re-check (G3): a failure folded into a
            // boolean or a value, and the configuration reader's collapse of
            // what cannot be judged into nothing
            ".is_ok_and(",
            ".map_or(",
            ".map_or_else(",
            ".text()",
        ]
        .iter()
        .any(|d| chain.contains(d))
        {
            return true;
        }
        // a `match` arm that turns the error into an empty or a default value
        // (`Err(_) => return Vec::new()`, `Err(e) => { warn!(..); None }`,
        // `=> continue`), not into an error or an outcome of its own
        t.match_indices("Err(").any(|(j, _)| {
            let arm = &t[j..];
            let Some(arrow) = arm.find("=>") else {
                return false;
            };
            if arm[..arrow].contains("Ok(") {
                return false;
            }
            let body = &arm[arrow + 2..arm.len().min(arrow + 2 + 160)];
            // the arm's end: the next arm (`Ok(`, `_ =>`) or the block's end
            let end = ["Ok(", "_=>", "}}"]
                .iter()
                .filter_map(|m| body.find(m))
                .min()
                .unwrap_or(body.len());
            let body = &body[..end];
            if body.contains(".failed(") || body.contains(".holds(") || body.contains("Err(") {
                return false;
            }
            [
                "Vec::new()",
                "String::new()",
                // `Default::default()`, `MountTable::default()` (G3)
                "::default()",
                "HashMap::new()",
                "BTreeMap::new()",
                "HashSet::new()",
                "BTreeSet::new()",
                "vec![]",
                "None",
                "continue",
                "false",
                "true",
                "\"\"",
            ]
            .iter()
            .any(|d| body.contains(d))
                || body
                    .trim_start_matches("return")
                    .trim_start_matches('{')
                    .starts_with('0')
        })
    }

    /// Rule 2's sites in one file's production code: `(line, key)` — a read of
    /// [`READS`] whose statement turns its failure into a default (`.ok()`,
    /// `unwrap_or*`, `if let Ok`, `let Ok(…) else`, a `match` arm that is no
    /// error), and a `lines()` loop that skips its read errors. The key is the
    /// read as written, spaces dropped (what [`KNOWN`] names).
    pub fn defaulted_reads(code: &str) -> Vec<(usize, String)> {
        let line = |i: usize| code[..i].matches('\n').count() + 1;
        let mut out = Vec::new();
        for (i, name) in calls(code, READS) {
            if !defaults(head(code, i), tail(code, i)) && !defaults_later(code, i, name) {
                continue;
            }
            let call = format!("{name}({})", arguments(code, i + name.len()));
            let key: String = call
                .chars()
                .filter(|c| !c.is_whitespace())
                .take(120)
                .collect();
            out.push((line(i), key));
        }
        for (i, _) in code.match_indices(".lines()") {
            let t: String = code[i..floor(code, i + 300)]
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let skips = t.starts_with(".lines().flatten()")
                || t.starts_with(".lines().map_while(Result::ok)")
                || t.starts_with(".lines().filter_map(Result::ok)")
                || t.starts_with(".lines().filter_map(|l|l.ok())")
                || (t.contains("Err(_)=>continue")
                    || t.contains("else{continue") && t.contains("letOk(line)"))
                    && t.find("Err(_)=>continue")
                        .or_else(|| t.find("else{continue"))
                        .is_some_and(|j| j < 200);
            if skips {
                out.push((line(i), "lines()".to_string()));
            }
        }
        out.sort();
        out.dedup();
        out
    }
}
