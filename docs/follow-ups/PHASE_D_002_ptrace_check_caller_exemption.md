# PHASE_D_002 — ptrace_access_check has no W6 caller-side exemption

**Discovered:** Tappa 7 task 6 W8 (privileged_e2e bring-up, 2026-05-19).
**Severity:** ARCHITECTURAL — watchdog cannot read `/proc/<agent_pid>/exe`
in production without an explicit `--agent-bin` flag (added in W8 as a
workaround).
**Blast radius:** any operator-driven respawn discovery path that goes
through the agent's `/proc` interfaces (readlink, /proc/<pid>/maps, etc.)
is denied — including the watchdog's `derive_agent_argv` at boot.

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
