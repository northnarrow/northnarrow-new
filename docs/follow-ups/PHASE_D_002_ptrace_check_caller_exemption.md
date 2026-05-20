# PHASE_D_002 — ptrace_access_check has no W6 caller-side exemption

**Status:** RESOLVED 2026-05-19 (fixed in `agent-ebpf/src/ptrace_check.rs`).
**Discovered:** Tappa 7 task 6 W8 (privileged_e2e bring-up, 2026-05-19).
**Severity:** ARCHITECTURAL — watchdog cannot read `/proc/<agent_pid>/exe`
in production without an explicit `--agent-bin` flag (added in W8 as a
workaround).
**Blast radius:** any operator-driven respawn discovery path that goes
through the agent's `/proc` interfaces (readlink, /proc/<pid>/maps, etc.)
is denied — including the watchdog's `derive_agent_argv` at boot.

## Resolution

Added a caller-side mutual-whitelist exemption to the BPF program
in `agent-ebpf/src/ptrace_check.rs`. Right before the final `-EPERM`
branch, the program now reads the calling task's tgid via
`bpf_get_current_pid_tgid() >> 32` and consults the same
`PROTECTED_PIDS` map: if the caller's own tgid is present, the
access is allowed. This is symmetric to W6's target-side
protection — the agent and the watchdog are already mutually
inserted into `PROTECTED_PIDS`, so the agent's BPF program now
exempts the watchdog (and any future in-family supervisor) from
the ptrace deny while continuing to refuse every other root
caller.

Implementation choice: PID-based exemption over comm-based.
PID-based piggy-backs on the W6 `PROTECTED_PIDS` mechanism
without introducing a new map, and is not spoofable via
`prctl(PR_SET_NAME)` — any process can set its comm to
`"northnarrow-wat"` but only processes the agent has decided to
insert can match the PID check.

Verified by new privileged e2e test `watchdog/tests/privileged_e2e.rs
::ptrace_access_check_exempts_caller_in_protected_pids`: spawns the
real agent, asserts the test process can't readlink
`/proc/<agent_pid>/exe`, inserts the test PID into PROTECTED_PIDS
via bpftool, asserts the same readlink now succeeds. Live: PASS
on Hetzner.

The W8 `--agent-bin` flag remains in the CLI as defense-in-depth
and as a clean operator override (production systemd ExecStart
pinning the binary path is still good practice independent of
this fix).

## Symptom

Watchdog logs at startup:

```
watchdog exited with error: reading /proc/<agent_pid>/exe for
argv reconstruction
```

The `read_link()` returns EPERM because the kernel's
`proc_pid_readlink` requires `PTRACE_MODE_READ_FSCREDS`, which goes
through `security_ptrace_access_check`, which the agent's BPF program
denies for any caller targeting a PID in `PROTECTED_PIDS`.

## Root cause

`agent-ebpf/src/ptrace_check.rs:65-113` denies the access whenever
the target's `tgid` is in `PROTECTED_PIDS`, with no caller-side
check beyond the Tappa-8 stubbed `PTRACE_OVERRIDE` slot. The W6
sister mechanism in `agent-ebpf/src/task_kill.rs` does check the
caller's `comm` against an allowed-comms map; the ptrace hook does
not.

## W8 workaround (shipped)

The watchdog gained an optional `--agent-bin <PATH>` CLI flag
(`watchdog/src/lib.rs` Cli, `watchdog/src/main.rs` boot path). When
provided, it skips the `/proc/<pid>/exe` readlink entirely. The W7
systemd unit file should be updated to pass this in `ExecStart=`
once the operator picks the canonical agent binary path
(typically `/usr/local/bin/northnarrow-agent`).

## Fix

Mirror the W6 task_kill comm-allowlist mechanism into
`ptrace_access_check`:

1. Read the calling task's `tgid` via `bpf_get_current_pid_tgid()`.
2. Look up the caller's `tgid` in `PROTECTED_PIDS` — if present,
   allow (mutual whitelist).
3. Optionally: also check the caller's `comm` against an
   `ALLOWED_PTRACE_COMMS` map (parallel to `ALLOWED_TASK_KILL_COMMS`).

After this fix the `--agent-bin` flag stops being load-bearing for
correctness — it remains useful as an operator-configurable
override.

## Impact on W8 privileged tests

None — the tests already pass `--agent-bin` to work around this.
The flag stays in the CLI as a defensible production convenience
even after PHASE_D_002 lands.
