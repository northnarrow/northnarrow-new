# Tappa 7 — Technical prerequisites

> **Historical record (May 2026), not an operator guide.** Updated on
> 2026-10-20 (lab PR 209, external audit DEP-013 NN-AUD-385, DEP-021
> NN-AUD-441). This file records how Tappa 7 was prepared and first tested
> on one development host. It is not shipped with the release, and two of
> its statements no longer hold:
>
> - **The grub step.** The list written there named the modules that host
>   ran, plus `bpf`. Do not copy a fixed list: `lsm=` replaces the kernel's
>   built-in one, and a module it does not name (SELinux on the RHEL family,
>   AppArmor on Debian and Ubuntu) is not started. The procedure that
>   extends the running list, for Debian/Ubuntu (`update-grub`) and the RHEL
>   family (`grubby`), is
>   [`docs/operator/KERNEL_COMPATIBILITY.md`, "Enabling the `bpf` LSM"](operator/KERNEL_COMPATIBILITY.md#enabling-the-bpf-lsm-kernel-command-line).
> - **SIGQUIT.** The 12 May test table allowed `kill -3`; the hook then
>   denied SIGKILL and SIGTERM only. Since NN_REVIEW_2026-10-08 #5
>   (`task-kill-signals-1`) the `task_kill` hook denies every signal to a
>   protected pid except the existence probe (signal 0), a process
>   signalling itself and the agent and watchdog signalling each other;
>   since external audit EBPF-001 (lab PR 94) PID 1 too, outside a signed
>   trusted-installer window and the very end of a shutdown. `kill -3`, like
>   `kill -9`, gets `Operation not permitted`. How the agent is stopped
>   today: `docs/operator/INSTALL_UPGRADE_UNINSTALL.md` §3.7.

> Status: PREP — to read before starting the Tappa 7
> implementation (BPF-LSM anti-tamper). Document written during the
> 12 May 2026 session, after checking the state of the Hetzner server.

## Context

Tappa 7 (ROADMAP.md) needs real BPF-LSM hooks for Linux
anti-tamper. The current commits (9 May 2026) use tracepoints
as a workaround, because of bpf-linker BTF emission limits.
The research of 12 May 2026 found that these limits can be
solved now with the right configuration.

## Verified state (12 May 2026)

Server: `northnarrow-dev-01` (Hetzner Helsinki CCX23)
Kernel: Linux 6.8.0-111-generic Ubuntu 24.04.4 LTS

**Kernel config (positive):**
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_LSM=y
CONFIG_LSM_MMAP_MIN_ADDR=0
CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"

**Kernel BTF (positive):**
$ ls /sys/kernel/btf/vmlinux
/sys/kernel/btf/vmlinux  ✓

**Active LSMs at runtime (negative):**
$ cat /sys/kernel/security/lsm
lockdown,capability,landlock,yama,apparmor
"bpf" is missing. BPF-LSM hooks will fail at load.

**Aya ecosystem (positive):**
agent/Cargo.toml:        aya = "0.13"  aya-log = "0.2"
agent-ebpf/Cargo.toml:   aya-ebpf = "0.1"
agent-ebpf/rust-toolchain.toml:
channel = "nightly"
components = ["rust-src", "rustfmt", "clippy"]

Aya 0.13 supports BTF + LSM hooks. The nightly + rust-src setup is
already in place. The build infrastructure is ready.

## Blocker 1 — The kernel's runtime LSM list does not include "bpf"

**Fix (Monday 19 May or later):**

1. Back up the GRUB config:
sudo cp /etc/default/grub /etc/default/grub.bak

2. Edit `/etc/default/grub`: on that host (Ubuntu 24.04, AppArmor) the
   list became `landlock,lockdown,yama,apparmor,bpf`, the modules it ran
   plus `bpf`. **Historical, do not copy:** a fixed list can switch the host's
   SELinux or AppArmor off. The current procedure:
   `docs/operator/KERNEL_COMPATIBILITY.md`, "Enabling the `bpf` LSM".

3. Update GRUB:
sudo update-grub

4. Reboot:
sudo reboot

5. Check after the reboot:
cat /sys/kernel/security/lsm
   Expected output: `lockdown,capability,landlock,yama,apparmor,bpf`

**Risk:** a GRUB syntax error → the server does not boot. For
Hetzner, recovery through the web console is always available. The
server holds no production data: the risk is acceptable.

**When to run it:** Monday 19 May 2026 or later. NOT
while travelling or in production.

## Blocker 2 — bpf-linker BTF emission not turned on

**Context:** earlier commits (`exec_check.rs`, `file_open.rs`)
carry an explicit note:

> "bpf-linker 0.10 doesn't emit BTF, so LSM CO-RE reloc would
>  fail at load time. The tracepoint gives userland every field
>  listed in the spec. When eBPF BTF lands properly, we'll
>  switch the hook for Tappa 7 enforcement."

**Solution (checked against the official aya-rs + bpf-linker
docs, 2026):**

Add the `--btf` flag to the linker through `RUSTFLAGS` in the
agent-ebpf build. Two options:

**Option A — through .cargo/config.toml (recommended):**

In `agent-ebpf/.cargo/config.toml`:
```toml
[build]
target = "bpfel-unknown-none"
rustflags = "-C debuginfo=2 -C link-arg=--btf"

[unstable]
build-std = ["core"]
```

**Option B — through an environment variable (ad hoc):**
RUSTFLAGS="-C debuginfo=2 -C link-arg=--btf" 
cargo +nightly build --target=bpfel-unknown-none 
-Z build-std=core --release

**Effect:** the ELF binary at
`target/bpfel-unknown-none/release/northnarrow-agent-ebpf`
will contain a BTF section. The Aya LSM loader can do CO-RE relocations
against kernel structs (`struct task_struct`, `struct file`,
etc.).

**Check that BTF is in the ELF:**
llvm-objdump -h target/bpfel-unknown-none/release/northnarrow-agent-ebpf 
| grep -i btf

## Side effect — Moving Tappe 1-4 to LSM (optional)

Once blockers 1+2 are solved, the existing code can move from
tracepoints to real LSM hooks:

- `exec_check.rs`: `sys_enter_execve` tracepoint →
  `bprm_check_security` LSM hook
- `file_open.rs`: `sys_enter_openat` tracepoint →
  `file_open` LSM hook

Benefit: `-EPERM` enforcement (denial) becomes possible, not
only telemetry.

Decision to move: after Tappa 7 is closed, weigh whether to
backport LSM to the existing sensors or keep the tracepoints.

## Tappa 7 proper (after the fix of blockers 1+2)

Original specification (ROADMAP.md):

1. **BPF-LSM hook task_kill** — `agent-ebpf/src/task_kill.rs`
   - Deny SIGKILL/SIGTERM to the agent's PID
   - Exception: Ed25519-signed channel (Tappa 8 dependency)

2. **BPF-LSM hook ptrace_access_check** —
   `agent-ebpf/src/ptrace_check.rs`
   - Deny ptrace to the NorthNarrow daemon

3. **Protection of the `/var/lib/northnarrow/` filesystem:**
   - `chattr +i` (immutable bit) on critical files
   - LSM inode hooks to prevent changes

4. **Secondary watchdog:**
   - Separate daemon, standard Rust (not eBPF)
   - Watches the main agent
   - Restarts it if it goes down

## Final Tappa 7 check demo
$ sudo kill -9 $(pidof northnarrow-agent)
kill: (12345) - Operation not permitted

Even root cannot kill the agent.

## Steps for Monday 19 May 2026

1. SSH to the server, check that Phase A Reasoning LoRA is OK (desktop PC)
2. Back up the GRUB config: `sudo cp /etc/default/grub /etc/default/grub.bak`
3. Edit `/etc/default/grub`: add `bpf` to the `lsm=` list (historical;
   today: `docs/operator/KERNEL_COMPATIBILITY.md`, "Enabling the `bpf` LSM")
4. `sudo update-grub`
5. `sudo reboot`
6. Check: `cat /sys/kernel/security/lsm` contains `bpf`
7. Edit `agent-ebpf/.cargo/config.toml`: add the BTF rustflags
8. Check that bpf-linker is installed:
   `cargo install --list | grep bpf-linker`
   If it is missing: `cargo install bpf-linker`
9. Test build:
   `cd ~/dev/northnarrow-new/ && cargo xtask build`
10. Check that the ELF contains BTF:
    `llvm-objdump -h target/bpfel-unknown-none/release/* | grep -i btf`
11. Only then: start implementing the `task_kill.rs` LSM hook

Estimated setup time: 1-2 hours.
Estimated Tappa 7 development time: 2-3 weeks (from ROADMAP.md).

## Critical notes

- The `northnarrow-dev-01` server is a DEV environment, not production.
  A reboot for the GRUB fix is acceptable.
- WSL2 (development on the founder's desktop PC) has NO working BPF-LSM.
  Tappa 7 development and tests = on the Hetzner server or a local KVM VM.
- The Phase A Reasoning training running on the desktop PC does not
  interfere with the server work (separate hardware).

---

## UPDATE 12 May 2026 — 15:15 UTC — IMPLEMENTATION + LIVE TEST

### Implementation (via Claude Code, autopilot mode)

Commits on `main` (already pushed to origin):

- `9396e26` — `feat(agent-ebpf): task_kill.rs LSM hook denies SIGKILL/SIGTERM`
- `ed1e3c3` — `feat(agent-ebpf): ptrace_check.rs LSM hook denies ptrace`
- `1dcd0dd` — `feat(agent): userland LSM loader (anti_tamper module)`

Build verification: 258 tests passing, BTF section present in
agent-ebpf ELF, cargo clippy clean.

### Live test on northnarrow-dev-01

Agent launched as root via:
sudo nohup ./target/release/northnarrow-agent --no-ade > /tmp/nn-agent.log 2>&1 &

Log confirmed at launch:
INFO anti-tamper: agent PID registered with kernel agent_pid=14112 map="PROTECTED_PID"
INFO anti-tamper: LSM hook attached (denies SIGKILL/SIGTERM to agent) program="task_kill"
INFO anti-tamper: LSM hook attached (denies ptrace to agent) program="ptrace_access_check"

### Test results

> Historical (12 May 2026): row 4 and the SIGQUIT workaround below
> describe the first hook, which denied SIGKILL and SIGTERM only. Today
> every signal to the agent is denied outside a trusted-installer window,
> SIGQUIT included (note at the top of this file).

| # | Test | Command | Expected | Actual | Verdict |
|---|------|---------|----------|--------|---------|
| 1 | SIGKILL | `sudo kill -9 14112` | denied | `kill: Operation not permitted`, agent Rl | PASS |
| 2 | SIGTERM | `sudo kill -15 14112` | denied | `kill: Operation not permitted`, agent Rl | PASS |
| 3 | PTRACE | `sudo gdb -p 14112` | denied | `Could not attach to process`, `ptrace: Inappropriate ioctl` | PASS |
| 4 | SIGQUIT | `sudo kill -3 14112` | allowed | exit 0, agent terminated cleanly | PASS |

### Known issues (non-blocking)

- `SIGINT` (signal 2) and `SIGHUP` (signal 1) not handled by
  userland agent (tokio `signal::ctrl_c` doesn't catch
  `sudo kill -2`). Workaround: use `SIGQUIT` for shutdown.
  Fix scheduled with subsequent Tappa 7 tasks.

### Conclusion

Anti-tamper layer of Tappa 7 (task_kill + ptrace_access_check)
is VERIFIED FUNCTIONAL on production-grade kernel:

- Root cannot kill the agent with SIGKILL or SIGTERM.
- Root cannot attach a debugger to the agent.
- Agent remains responsive to graceful shutdown (SIGQUIT) —
  historical: SIGQUIT has been denied too since `task-kill-signals-1`.
- LSM hooks correctly filter only the targeted signals
  (no over-blocking) — historical: the policy is deny-by-default since
  `task-kill-signals-1`.

### Remaining Tappa 7 work

- Task 5: filesystem protection `/var/lib/northnarrow/`
  (chattr +i + LSM inode hooks).
- Task 6: secondary watchdog process.
- Bug fix: SIGINT/SIGHUP handler in agent userland.
- Optional: migrate Tappe 1-4 from tracepoint to LSM hooks
  now that BTF emission works.

Target completion: the week of Monday 19 May 2026.

---

## UPDATE 19 May 2026 — Task 7 ENI ✅ SHIPPED

### Status

Task 7 (Emergency Network Isolation autonomous via COMBAT) is
**SHIPPED**. Live-verify complete on
`northnarrowdev` (Ubuntu Server VM, kernel `6.8.0-117-generic`).

### Live-verify evidence

- **Host:** `northnarrowdev`
- **Kernel:** `6.8.0-117-generic`
- **LSM chain runtime:**
  `lockdown,capability,landlock,yama,apparmor,bpf` (bpf present)
- **Build:** `cargo test --release --features
  test-privileged,debug-trigger -p northnarrow-agent --test
  privileged_e2e --no-run`
- **Run dir:** `/tmp/eni_run/r009fix_1779177273/`
- **Target test (`e2e_force_combat_then_unlock_via_cli`):**
  exit code **0**, `test result: ok. 1 passed; 0 failed`,
  finished in **1.11 s**.
- **Full privileged_e2e suite:** exit code **0**, `3 passed;
  0 failed; 1 ignored` (the ignored one is the
  rate-limit-window timing test, still `#[ignore]` per existing
  doc note).
- **iptables side-effect:** pre-vs-post diff shows only
  packet/byte counter deltas; no chain added, no rule added,
  `NORTHNARROW_COMBAT` absent post-run — full engage→unlock
  cycle clean.
- **Agent log excerpts** (full log at
  `/tmp/eni_run/r009fix_1779177273/test.log`):
  ```
  decision engine ready rules=10 demo_tappa5=false
  admin socket listening (mode 0600) ...
  COMBAT: network isolated (loopback only) ...
  admin challenge issued (32-byte nonce)
  admin signature verified, unlock token minted
  COMBAT: network isolation released
  ```
- **Workspace clippy:** clean
  (`cargo clippy --workspace --all-targets -- -D warnings`).
- **Workspace default test suite:** `381 lib tests: 371 passed,
  0 failed, 10 ignored` + 50 integration tests, 0 failures.

### What shipped

Code-complete since the BPF pinning sprint
(`tappa-7-task6-bpf-pinning-WIP`); the live-verify was blocked
by `ISSUE_001` (test self-kill via R009 from `/home/*` paths)
and is now unblocked. No production code change shipped in this
verify step — only the test infrastructure under
`agent/tests/privileged_e2e.rs` was modified to sudo-install
both binaries into `/usr/local/bin/<name>-e2etest-<ts>-<pid>`
before each test (Option A from ISSUE_001 §4). RAII cleanup via
the existing `AgentGuard` removes both binaries on test exit;
verified no residue in `/usr/local/bin/` post-run.

The same Option-A pattern was independently re-applied across
the full agent priv-e2e suite in **Tappa 9 polish #1** (PR #46,
SHA `18baa66`, merged 2026-05-20) — the ENI fix was thereby
generalised to every test that spawns `nn-admin` against a
running agent.

### Invariants preserved

- ✅ No change to `agent/src/decision/rules/r009_*.rs`
- ✅ No change to `agent/src/anti_tamper/network_isolate.rs`
- ✅ No change to `configs/combat-rules.v4`
- ✅ No new agent CLI flags
- ✅ `cargo clippy -- -D warnings` 0/0
- ✅ All workspace tests pass

### Cross-references

- `docs/issues/ISSUE_001_eni_test_r009_selfkill.md` (root cause +
  remediation analysis + RESOLVED status with this same evidence).
- `docs/CLAUDE_BRIEFING.md` § "FASE 3: Anti-Tamper", Task 7 line.
- `agent/tests/privileged_e2e.rs` — fixture changes.
