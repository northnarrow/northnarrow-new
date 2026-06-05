# Tappa 7 task 7 / Tappa 8 — Integration test runbook

The `agent/tests/privileged_e2e.rs` test module exercises the full
COMBAT → admin-unlock cycle against a live kernel: it spawns the
real `northnarrow-agent` and `nn-admin` binaries, forces a Combat
transition, asserts the iptables ruleset is live, signs the admin
challenge, and asserts the ruleset has been torn down.

CI compiles this module (bit-rot guard) but does **not** execute it
— the runners lack root and `iptables`. Manual execution lives here.

## Prerequisites

- Linux box (tested on Ubuntu 24.04 / kernel 6.8) with `iptables`
  userland present:
  ```sh
  command -v iptables iptables-restore iptables-save
  ```
- Sudo access (CAP_NET_ADMIN is required for the iptables shell-outs;
  CAP_BPF/CAP_PERFMON only if the agent's sensor multiplexer is being
  exercised in the same run, which `--no-ade` plus the debug-trigger
  posture path avoids).
- BPF-LSM enabled if you want the Tappa 7 LSM hooks active too:
  ```sh
  cat /sys/kernel/security/lsm | tr ',' '\n' | grep -E '^bpf$'
  ```
  Not required for *this* test module — `privileged_e2e.rs` uses the
  `debug-trigger` posture override to skip the trigger-event path.
- Tempdir on **tmpfs** strongly preferred. The agent writes `admin.sock`
  there, and the iptables ruleset's stale state can otherwise persist
  across runs if a test crashes between create and cleanup.

## Build

```sh
cargo build --release \
  --features test-privileged,debug-trigger \
  -p northnarrow-agent
```

This produces:
- `target/release/northnarrow-agent`
- `target/release/nn-admin`

Both must be in `target/release/` for the tests to find them (Cargo
sets `CARGO_BIN_EXE_*` env vars automatically at test-build time).

## Run

```sh
sudo -E env "PATH=$PATH" \
  cargo test --release \
    --features test-privileged \
    --test privileged_e2e \
    -- --test-threads=1 --nocapture
```

Flags:

- `sudo -E` preserves `$PATH` so cargo's own binary resolves;
  `--test-threads=1` is **mandatory** because iptables rules collide
  across parallel test invocations (they all use the same global
  `NORTHNARROW_COMBAT` chain);
- `--nocapture` is optional but very helpful — failures otherwise
  swallow the agent's stderr.

Expected: **3 tests passing, 1 ignored** in ~30 s on a fast machine:

```
running 4 tests
test e2e_status_no_admin_action_initially ... ok
test e2e_force_combat_then_unlock_via_cli ... ok
test e2e_unlock_with_wrong_key ... ok
test e2e_rate_limit_via_full_stack ... ignored, 5-min production rate-limit window too long for CI; run manually or after V1.1 adds a runtime override (see runbook)
```

`e2e_rate_limit_via_full_stack` is `#[ignore]` because AdminAuth's
production rate-limit window is hard-coded at 5 minutes with no
runtime override; the test's loop would block CI for that long. The
skeleton is already in place — when V1.1 adds an environment-variable
or CLI override (`NN_ADMIN_RATE_LIMIT_WINDOW_SECS=10`, say), drop the
`#[ignore]` and replace the commented-out final `assert_eq!` near
the end of the test body.

## Troubleshooting

- **`iptables-restore: command not found`** — install the userland
  package (`apt install iptables` on Debian/Ubuntu, `dnf install
  iptables-services` on RHEL). The agent shells out by name; PATH
  resolution finds it under `/usr/sbin/` on Debian-family distros.
- **`Permission denied` opening the socket** — the agent forces
  `0600 root:root` on the socket file. Make sure the test runner
  is itself running as root (the `sudo` in the run command above
  is the easy fix); a non-root `nn-admin` will hit EACCES on
  connect.
- **`agent never opened admin socket`** (panic in `wait_for_socket`) —
  the agent failed to start. Check:
  1. `--features debug-trigger` is on the build command (default
     build hides the `debug` subcommand and the integration test
     can't drive Combat without it);
  2. `/etc/northnarrow/admin.pub` is not the path being used (the
     tests use a tempdir — make sure the binary actually reads the
     `--admin-pub` flag, which it does today, but a future refactor
     might regress this).
- **`iptables -S NORTHNARROW_COMBAT` returns rules after a test fails** —
  manually flush: `sudo iptables -F NORTHNARROW_COMBAT && sudo
  iptables -X NORTHNARROW_COMBAT` (after first removing any stray
  jump rules from `INPUT`/`OUTPUT`/`FORWARD`). The agent's release
  path is idempotent; if you restart the test runner before
  cleanup, the next run will re-engage successfully.
- **BPF-LSM not active** — the test module doesn't exercise the LSM
  hooks (it uses the debug posture override), so this isn't a
  blocker. If you want to verify LSM behaviour separately, check
  `cat /sys/kernel/security/lsm` for `bpf` in the comma-separated
  list; if missing, set `lsm=bpf,...` in the kernel command line
  and reboot.

## Manual smoke sequence (human verification on Hetzner)

For ad-hoc validation outside the test harness:

```sh
# Terminal 1 — agent (release build with debug-trigger):
sudo ./target/release/northnarrow-agent \
  --combat-rules /tmp/nn-test/combat-rules.v4 \
  --admin-pub /tmp/nn-test/admin.pub \
  --admin-socket /tmp/nn-test/admin.sock \
  --no-ade

# Terminal 2 — admin:
# 1. Generate keypair (only once per fresh tempdir).
./target/release/nn-admin init \
  --priv-out /tmp/nn-test/admin.priv \
  --pub-append /tmp/nn-test/admin.pub

# 2. Confirm Observing / clear.
./target/release/nn-admin status --socket /tmp/nn-test/admin.sock

# 3. Force Combat — iptables -L should now show NORTHNARROW_COMBAT
#    chain dropping everything except loopback.
./target/release/nn-admin debug force-posture combat \
  --socket /tmp/nn-test/admin.sock

# 4. Confirm Combat / ENGAGED.
./target/release/nn-admin status --socket /tmp/nn-test/admin.sock

# 5. Unlock.
./target/release/nn-admin unlock \
  --key /tmp/nn-test/admin.priv \
  --socket /tmp/nn-test/admin.sock

# 6. Confirm Alerted / clear. Chain should now be gone.
./target/release/nn-admin status --socket /tmp/nn-test/admin.sock
sudo iptables -S NORTHNARROW_COMBAT  # → "No chain by that name"

# Cleanup: SIGQUIT the agent (SIGKILL/SIGTERM are LSM-blocked).
sudo kill -QUIT <agent pid>
```

## Future work (tracked, not blocking)

- **Migrate `admin_release_combat` (bool stub) call sites** to
  `admin_release_combat_with_token` and apply `#[deprecated]` on the
  bool path. Five test sites + the `posture_demo` example are the
  current callers.
- **`--strict-anti-tamper` boot flag**: today missing
  `combat-rules.v4` or `admin.pub` produces a WARN and the agent
  continues without isolation; production deployment configs will
  want the inverse default.
- **Runtime rate-limit window override** for the e2e rate-limit test;
  see the `#[ignore]` reason in `privileged_e2e.rs`.
- **Small-order Ed25519 signature fixture test** for
  `AdminAuth::verify_unlock` — deferred from commit #4 because
  constructing a known small-order curve point as a test fixture is
  non-trivial. `verify_strict` already rejects them at runtime.

---

## Tappa 7 task 6 Watchdog (W7+) — systemd unit pair

The Watchdog sprint (W1–W6 already shipped) introduces a second
daemon, `northnarrow-watchdog`, that supervises the agent's
liveness and respawns it on death. Production deployment runs
both as a systemd unit pair per
`docs/design/TAPPA7_TASK6_WATCHDOG_DESIGN.md` §10.

### Install layout

The W7 install skeleton (`deploy/install.sh`) ships:

- `/usr/local/bin/northnarrow-agent` (already installed pre-W7
  by ad-hoc means; install.sh now formalises)
- `/usr/local/bin/northnarrow-watchdog` (NEW)
- `/etc/systemd/system/northnarrow-agent.service` — sets
  `Restart=no` so the watchdog owns respawn (design §2.3 — avoids
  the systemd-vs-watchdog double-restart race)
- `/etc/systemd/system/northnarrow-watchdog.service` — `Type=notify`,
  `Restart=on-failure RestartSec=2s`,
  `After=northnarrow-agent.service`, `BindsTo=northnarrow-agent.service`,
  resource ceilings (`MemoryMax=64M`, `CPUQuota=10%`, `TasksMax=8`),
  hardening (`NoNewPrivileges`, `ProtectSystem=strict`,
  `CapabilityBoundingSet=CAP_BPF CAP_SYS_ADMIN`)

After `install.sh`, the operator runs:

```
sudo systemctl daemon-reload   # install.sh already did this; idempotent
sudo systemctl enable --now northnarrow-agent.service
sudo systemctl enable --now northnarrow-watchdog.service
journalctl --namespace=northnarrow -u northnarrow-agent.service -u northnarrow-watchdog.service -f
```

### Pre-flight checklist before enabling the units

1. **`/etc/northnarrow/` populated** — `admin.pub` (operator-managed)
   + `combat-rules.v4` (operator-managed). `agent_id` bootstraps on
   first start; you can also pre-seed.
2. **bpffs mounted** — `mount | grep ' /sys/fs/bpf'`. If absent:
   `mount -t bpf bpf /sys/fs/bpf`.
3. **`bpf` LSM in kernel chain** — `cat /sys/kernel/security/lsm`
   must include `bpf`. If absent: edit `/etc/default/grub`,
   add `lsm=...,bpf` to `GRUB_CMDLINE_LINUX`, `update-grub`,
   `reboot`. See `docs/TAPPA7_PREREQ.md`.

### Manual integration tests on the unit pair

The Watchdog sprint's privileged e2e (W8) will automate these.
Until then, the manual sequence below validates the W1–W6 flow
end-to-end on a Hetzner-class test box:

#### Test 1 — Cold start + steady-state

```
sudo systemctl start northnarrow-agent.service
sudo systemctl start northnarrow-watchdog.service
sleep 5

# Both PID files written?
sudo cat /run/northnarrow/agent.pid    # → agent's PID
sudo cat /run/northnarrow/watchdog.pid # → watchdog's PID

# Both PIDs in PROTECTED_PIDS? (W6 mutual protection)
sudo bpftool map dump pinned /sys/fs/bpf/northnarrow/PROTECTED_PIDS
# Expect 2 entries: agent_pid → 1, watchdog_pid → 1

# Steady-state journal shows no errors:
journalctl --namespace=northnarrow -u northnarrow-watchdog.service --since "1 minute ago" | grep -iE 'error|warn'
# Expect: empty (or only the "NOTIFY_SOCKET unset" debug from a
# Type=notify init misconfig, which shouldn't fire under systemd)
```

#### Test 2 — Agent death → watchdog respawn (W3 + W4)

```
AGENT_PID=$(sudo cat /run/northnarrow/agent.pid)

# Force-kill agent (only works because we test from the host —
# in normal operation the LSM hook denies SIGKILL; we use the
# unprotect+kill recipe from docs/verify-2b.sh)
sudo bpftool map delete pinned /sys/fs/bpf/northnarrow/PROTECTED_PIDS \
    key $(printf '%d %d %d %d' \
        $((AGENT_PID & 255)) \
        $(((AGENT_PID >> 8) & 255)) \
        $(((AGENT_PID >> 16) & 255)) \
        $(((AGENT_PID >> 24) & 255)))
sudo kill -9 $AGENT_PID

# Expect within ~1s:
journalctl --namespace=northnarrow -u northnarrow-watchdog.service --since "10 seconds ago"
# Look for, in order:
#   "agent pidfd POLLIN — agent has exited"        (W3)
#   "layer-2 evict complete"                       (W3)
#   "no shutdown-authorisation marker"             (W4)
#   "spawning agent"                               (W4)
#   "new agent pidfile observed"                   (W4)
#   "defensive PROTECTED_PIDS reinsert complete"   (W4)

# New agent PID published:
NEW_PID=$(sudo cat /run/northnarrow/agent.pid)
[[ $NEW_PID != $AGENT_PID ]] && echo "OK: PID changed $AGENT_PID → $NEW_PID"
```

#### Test 3 — Operator stop → BindsTo stops watchdog too

```
sudo systemctl stop northnarrow-agent.service
sleep 2
systemctl is-active northnarrow-watchdog.service
# Expect: "inactive" (BindsTo brought it down WITH the agent —
# no respawn loop)
```

#### Test 4 — Watchdog crash → systemd respawns watchdog;
####         agent's PROTECTED_PIDS entry survives

```
sudo systemctl start northnarrow-agent.service northnarrow-watchdog.service
sleep 3
OLD_WPID=$(sudo cat /run/northnarrow/watchdog.pid)
sudo kill -9 $OLD_WPID            # the watchdog isn't in PROTECTED_PIDS
                                  # from systemd's view; SIGKILL works
sleep 4
NEW_WPID=$(sudo cat /run/northnarrow/watchdog.pid)
[[ $NEW_WPID != $OLD_WPID ]] && echo "OK: watchdog respawned by systemd"

# Agent still alive + still in PROTECTED_PIDS:
sudo cat /run/northnarrow/agent.pid    # unchanged
sudo bpftool map dump pinned /sys/fs/bpf/northnarrow/PROTECTED_PIDS
# Expect: agent_pid still there
```

### Future work (W8)

The W8 privileged e2e bundles the §12 row deferrals:
- W3 "1 privileged integration test on Hetzner that kills a fake
  'agent' sentinel and asserts evict latency < 1 ms"
- W4 "1 integration test cycling 3 restarts"
- W5 "1 integration test wedging a sleep(99999) 'agent' and
  asserting unstuck-then-restart"

All three want the same coordinated harness (fake-agent
subprocess that writes its pidfile + sleeps + optionally hangs
the admin socket + exits on signal), so they ship together in
W8 rather than as three separate near-duplicate harnesses.
