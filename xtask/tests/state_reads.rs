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
//! The scan is lexical (comments blanked, test items and test files left
//! out). Each rule is shown failing on a planted violation.

mod support;

use std::collections::BTreeMap;
use std::path::Path;

use support::{is_test_file, production, repo_root, rs_files, strip_comments};

/// The security crates' sources.
const SCAN: &[&str] = &[
    "crates/nn-core/src",
    "crates/nn-linux/src",
    "agent/src",
    "watchdog/src",
    "crates/nn-admin/src",
    "antitamper-bpf/src",
];

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

/// Why a process's own `/proc` entry may default: read as bytes, its read
/// fails only when the process is gone (`ENOENT`, `ESRCH`) or the host is
/// out of something, and the caller answers "unknown" — no identity, no
/// start, no exemption, no ancestor — never an emptied protection.
const PROC: &str = "a process's own /proc entry, read as bytes: a failed read is the process \
                    gone or unknown, and the caller answers unknown (no identity, start, \
                    exemption or ancestor), never an emptied protection";
/// Why a kernel-written ASCII file may default.
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
/// Why the host-hardening check's bpffs count may default.
const HARDEN: &str = "the host-hardening check's bpffs count: a mount table that cannot be \
                      read is reported so by the same check (a warning naming the error), \
                      never as 'not mounted'";
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

/// Rule 2's sites, each by its read as written (spaces dropped): `(file,
/// read, why)` — none reads a file a process or a user names into an empty
/// answer that a protection then publishes. The readers that keep the last
/// good state (`LastGood`, a `Condition` in the error's arm) are not sites.
const KNOWN: &[(&str, &str, &str)] = &[
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
        "fs::read(host.join(\"index.jsonl\"))",
        OWN,
    ),
    (
        "agent/src/cow/trust.rs",
        "fs::read(proc_root.join(pid.to_string()).join(\"stat\"))",
        PROC,
    ),
    ("agent/src/decision/golden.rs", "read_to_string(&path)", LAB),
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
    ("agent/src/module_trust/scan.rs", "fs::read(file)", PKG),
    (
        "agent/src/posture/golden.rs",
        "read_to_string(&self.audit_path)",
        LAB,
    ),
    ("agent/src/posture/golden.rs", "read_to_string(&path)", LAB),
    ("agent/src/run_loop.rs", "read_to_string(&trigger)", LAB),
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
        "fs::read(path)",
        CGROUP,
    ),
    (
        "antitamper-bpf/src/host_dropins.rs",
        "read_config(Path::new(p))",
        KNOB,
    ),
    (
        "antitamper-bpf/src/lib.rs",
        "fs::read(format!(\"/proc/{pid}/comm\"))",
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
        "fs::read(\"/proc/sys/kernel/random/boot_id\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/anti_tamper/bpf_defense.rs",
        "read_to_string(format!(\"/proc/self/fdinfo/{fd}\"))",
        KNOB,
    ),
    (
        "crates/nn-linux/src/anti_tamper/btf_revalidate.rs",
        "fs::read(d.join(m))",
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
        "read_state(self.root.join(pid.to_string()).join(\"status\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/decision_host_linux.rs",
        "read_state(self.root.join(pid.to_string()).join(\"cgroup\"))",
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
        "crates/nn-linux/src/host_hardening.rs",
        "read_state(p)",
        KNOB,
    ),
    (
        "crates/nn-linux/src/kernel_state.rs",
        "read_to_string(p.join(f))",
        KNOB,
    ),
    (
        "crates/nn-linux/src/known_system_prog.rs",
        "read_to_string(pdir.join(\"fdinfo\").join(fd.file_name()))",
        KNOB,
    ),
    (
        "crates/nn-linux/src/known_system_prog.rs",
        "read_state(p)",
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
        "fs::read(&from)",
        CONFIG,
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
        "read_to_string(t.ok()?.path().join(\"children\"))",
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
        "crates/nn-linux/src/self_integrity.rs",
        "read_to_string(\"/proc/self/limits\")",
        KNOB,
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "read_state(path)",
        OWN,
    ),
    (
        "crates/nn-linux/src/self_integrity.rs",
        "read_to_string(\"/proc/meminfo\")",
        KNOB,
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
        "crates/nn-linux/src/sensors/kmod_exec.rs",
        "read_state(dir.join(\"stat\"))",
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
        "fs::read(base.join(\"cmdline\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/sysctl_guard.rs",
        "read_to_string(root.join(p.trim_start_matches('/')))",
        KNOB,
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
    (
        "crates/nn-linux/src/worker/supervisor.rs",
        "read_state(format!(\"/proc/{pid}/stat\"))",
        PROC,
    ),
    ("watchdog/src/lib.rs", "read_to_string(&honoured_path)", OWN),
    (
        "watchdog/src/lib.rs",
        "fs::read(format!(\"/proc/{pid}/stat\"))",
        PROC,
    ),
    ("watchdog/src/lib.rs", "fs::read(\"/proc/stat\")", KNOB),
    // The review of #538's re-check (G3): one entry per site — the second
    // sites under a key listed above — and the sites of the forms rule 2
    // now catches (`is_ok_and`, `map_or`, `Type::default()`, a later
    // statement).
    (
        "agent/src/config/overlay_floor.rs",
        "fs::read(audit_log)",
        OWN,
    ),
    (
        "agent/src/pipeline/mod.rs",
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
        "crates/nn-linux/src/host_hardening.rs",
        "mountinfo::read(&root.join(\"proc/self/mountinfo\"))",
        HARDEN,
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
    (
        "crates/nn-linux/src/user_units.rs",
        "read_state(proc_root.join(pid.to_string()).join(\"cgroup\"))",
        PROC,
    ),
    (
        "crates/nn-linux/src/user_units.rs",
        "read_to_string(root.join(\"etc/passwd\"))",
        "lot 310b: the user's home, to find the units and drop-ins of the user's side: a passwd \
         that cannot be read finds no home, and a user without one is taken to have overrides \
         (no packaged unit vouched for) — the stricter side",
    ),
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
fn strict_proc_reads(code: &str) -> Vec<usize> {
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
fn defaulted_reads(code: &str) -> Vec<(usize, String)> {
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

/// The production code of every file of [`SCAN`], by path.
fn scan_code(root: &Path) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for dir in SCAN {
        let mut files = Vec::new();
        rs_files(&root.join(dir), &mut files);
        for f in files {
            let rel = f
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if is_test_file(&rel) {
                continue;
            }
            let text = std::fs::read_to_string(&f).unwrap_or_else(|e| panic!("{rel}: {e}"));
            out.insert(rel, production(&strip_comments(&text)));
        }
    }
    out
}

#[test]
fn no_process_entry_is_read_as_strict_text() {
    let code = scan_code(&repo_root());
    assert!(code.len() > 300, "scanned {} files", code.len());
    let found: Vec<String> = code
        .iter()
        .flat_map(|(f, text)| {
            strict_proc_reads(text)
                .into_iter()
                .map(move |l| format!("{f}:{l}"))
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
    let code = scan_code(&repo_root());
    let mut problems = Vec::new();
    let mut used = vec![0usize; KNOWN.len()];
    for (file, text) in &code {
        for (line, key) in defaulted_reads(text) {
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
        assert!(code.contains_key(*file), "{file}: in KNOWN, not scanned");
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
    assert_eq!(
        strict_proc_reads(planted),
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
    assert!(
        strict_proc_reads(clean).is_empty(),
        "{:?}",
        strict_proc_reads(clean)
    );
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
    let lines: Vec<usize> = defaulted_reads(planted)
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    assert_eq!(
        lines,
        vec![3, 7, 10, 16, 20, 29, 32, 35, 38, 41, 44, 50, 59, 62, 65, 68, 74, 79, 83, 90],
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
    let found = defaulted_reads(clean);
    assert!(found.is_empty(), "{found:?}");
}

/// The sites of every scanned file (to fill [`KNOWN`]): a no-op unless
/// `NN_PRINT_STATE_READS=1`.
#[test]
#[ignore = "prints the sites; NN_PRINT_STATE_READS=1, run by hand when the table moves"]
fn print_the_sites() {
    if std::env::var("NN_PRINT_STATE_READS").as_deref() != Ok("1") {
        return;
    }
    for (file, text) in scan_code(&repo_root()) {
        for (line, key) in defaulted_reads(&text) {
            println!("SITE {file}:{line}\t{key}");
        }
        for l in strict_proc_reads(&text) {
            println!("STRICT {file}:{l}");
        }
    }
}
