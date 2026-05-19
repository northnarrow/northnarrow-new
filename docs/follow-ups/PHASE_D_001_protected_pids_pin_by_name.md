# PHASE_D_001 — agent doesn't pin PROTECTED_PIDS by name

**Discovered:** Tappa 7 task 6 W8 (privileged_e2e bring-up, 2026-05-19).
**Severity:** ARCHITECTURAL — watchdog's W3 layer-2 evict is unreachable in production.
**Blast radius:** All three W8 privileged tests are blocked. Production
watchdog respawn loop will fail at `ProtectedPidsHandle::open(bpffs_root)`.

## Symptom

`bpftool map show` shows the `PROTECTED_PIDS` map loaded and populated
(matching the agent's "PIDs registered with kernel" log line), but
`/sys/fs/bpf/northnarrow/` contains only the seven LSM `link_*` /
`prog_*` files — no `PROTECTED_PIDS` map file. `bpftool map dump
pinned /sys/fs/bpf/northnarrow/PROTECTED_PIDS` returns
`bpf obj get: No such file or directory`.

## Root cause

The agent's `agent/src/sensors/multiplexer.rs:62-65` constructs an
`EbpfLoader` with `loader.map_pin_path(root)`, and the eBPF source
declares `pub static PROTECTED_PIDS: HashMap<u32, u8> = HashMap::pinned(16, 0);`
in `agent-ebpf/src/task_kill.rs:66`. The combination is supposed to
trigger aya's BPF_F_RDONLY_PROG / BPF_PIN_FD pinning during `Ebpf::load`.

Empirically on aya 0.13.x + kernel 6.8 it does not — only the
programs and links pinned manually via `prog.pin(...)` and
`link.pin(...)` in `antitamper-bpf/src/lib.rs` actually appear in
the bpffs directory.

## Fix

Add an explicit `ebpf.map_mut(PROTECTED_PIDS_MAP_NAME)?.pin(<path>)?`
call in the agent's post-`Ebpf::load` path, alongside the existing LSM
program pins. Location: end of `agent/src/sensors/multiplexer.rs::new`
or inside `agent/src/anti_tamper/mod.rs::attach` before any LSM
hook attach.

## Impact on W8 privileged tests

All three integration tests in `watchdog/tests/privileged_e2e.rs`
are `#[ignore]`'d pending this fix:

1. `watchdog_evicts_agent_pid_on_pidfd_pollin` — needs to dump
   PROTECTED_PIDS via bpftool to verify evict.
2. `watchdog_respawns_agent_3_cycles_with_backoff` — watchdog's
   `reinsert_new_agent_pid` opens the pinned map.
3. `stuck_recovery_kills_sigint_ignoring_subprocess_via_real_bpf` —
   `stuck_recovery` opens the pinned map to evict the stuck PID.

All three will run successfully against any agent build with the
above one-line fix; the test harness itself is correct.
