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

## Local lab (QEMU/KVM, also from WSL2)

`deploy/lab/nn-lab.sh` turns the prerequisites above into a repeatable
guest: Ubuntu 24.04 cloud image, kernel 6.8, `lsm=…,bpf` set through
cloud-init (one automatic reboot), iptables + bpftool + rustup inside,
SSH on `127.0.0.1:2222`. WSL2 needs nested virtualization (`/dev/kvm`
present) and the user in the `kvm` group.

```sh
sudo apt install qemu-system-x86 qemu-utils cloud-image-utils   # host, once
deploy/lab/nn-lab.sh up            # download + provision + boot (~5-10 min first time)
deploy/lab/nn-lab.sh check         # kernel / lsm has bpf / bpffs / iptables / cargo
deploy/lab/nn-lab.sh sync          # cargo xtask build-ebpf on host, rsync repo (+ eBPF object) into the guest
deploy/lab/nn-lab.sh build         # guest-side cargo build --release --features test-privileged,debug-trigger
deploy/lab/nn-lab.sh test-e2e      # the "Run" section below, as root, single-threaded
deploy/lab/nn-lab.sh test-ignored  # every #[ignore] test in the workspace
deploy/lab/nn-lab.sh install       # deploy/install.sh + start both units
deploy/lab/nn-lab.sh respawn-check # kill -9 the agent; asserts unit active, cgroup, CAP_KILL, watchdog alive
deploy/lab/nn-lab.sh snapshot clean   # (guest down) revert point before an attack run
```

The eBPF object is built on the **host** (nightly + bpf-linker 0.10.3)
and shipped with its provenance stamp; the guest only builds userland,
so `agent/build.rs`'s staleness guard still holds. `respawn-check` is
the VM half of `docs/design/WATCHDOG_RESPAWN_V2_DESIGN.md` §4.

### Other guests: Debian 12, Ubuntu 22.04, AlmaLinux 9

`NN_LAB_DISTRO=<distro> deploy/lab/nn-lab.sh up` boots a separate guest;
prefix any sub-command with the variable to target it. Each guest has its
own disk, seed, ssh port and reports under `~/.cache/nn-lab/<distro>/`
(the original `ubuntu2404` keeps the flat layout):

| `NN_LAB_DISTRO` | kernel | ssh port | notes |
|---|---|---|---|
| `ubuntu2404` (default) | 6.8 | 2222 (2322 on this host) | build kernel |
| `debian12` | 6.1 | 2422 | `perf_event_paranoid=3` drop-in |
| `ubuntu2204` | 5.15 | 2522 | older verifier, sudo 1.9.9, systemd 249 |
| `alma9` | 5.14 el9 | 2622 | SELinux enforcing, vendor tracepoint header |

The verified matrix and the per-kernel findings are in
`docs/operator/KERNEL_COMPATIBILITY.md`. Memory: each guest takes
`NN_LAB_MEM` (8 GiB); on a 32 GiB host keep at most two guests up during
long runs — four at once starved the host (2026-10-10).

### Nightly, unattended

`deploy/lab/nn-lab.sh nightly` runs check → sync → build → test-e2e →
test-ignored → install → respawn-check → upgrade-check → uninstall-check
(the last two exercise `install.sh --upgrade` on the running install and
`uninstall.sh --purge`, then reinstall — see
`docs/operator/INSTALL_UPGRADE_UNINSTALL.md`) without stopping at the first
failure, writes `~/.cache/nn-lab/reports/<stamp>.md` (status, duration
and every `test result:` line per step; `latest.md` points at the newest)
and exits 1 if any step failed. The privileged tests only *compile* in
GitHub CI, so this is the run that catches a test or a kernel-side
behaviour drifting from the product — the 2026-10-08 lab rounds found
two detection gaps and a dozen stale tests that CI had been green on
for months.

Schedule it from WSL2 with cron (the guest must be reachable; `up` is
run automatically when it is not):

```sh
crontab -e
# 02:30 every night; mail/notify on the report yourself, or just read latest.md
30 2 * * * $HOME/northnarrow-new/deploy/lab/nn-lab.sh nightly >> $HOME/.cache/nn-lab/nightly.log 2>&1
```

`cron` inside WSL2 only ticks while the distro is running; on a desktop
that sleeps, trigger it from Windows Task Scheduler instead:
`wsl.exe -d Ubuntu -u <user> -- bash -lc '~/northnarrow-new/deploy/lab/nn-lab.sh nightly'`.
After a WSL restart `/dev/kvm` must be writable again (`kvm` group
membership, or `sudo chmod 666 /dev/kvm`). `NN_LAB_NIGHTLY_DOWN=1` powers
the guest off at the end; `NN_LAB_NIGHTLY_SKIP="test-ignored"` skips a
step (the ignored suite includes the 5-minute rate-limit test).

### Soak test (hours of synthetic load)

```
NN_LAB_DISTRO=alma9 deploy/lab/nn-lab.sh soak start 24      # hours; sample every 60 s
deploy/lab/nn-lab.sh soak status                            # last sample, generator iterations
deploy/lab/nn-lab.sh soak wait                              # block until the end, then report
deploy/lab/nn-lab.sh soak report                            # ~/.cache/nn-lab/<distro>/reports/soak-<stamp>.md
deploy/lab/nn-lab.sh soak stop                              # end early
```

`soak start` installs the units if they are not active, ships
`deploy/lab/soak/{generate,sample}.sh` to `~/soak` on the guest and runs
them detached: the generator (as `nn`) keeps a steady, benign load on
every sensor — execs of standard-path binaries, create/append/rename/
delete in `/var/tmp/nn-soak`, reads of a watched system file, HTTP
requests to a local listener, UDP datagrams, DNS lookups of a fixed set
(rates via `SOAK_*_PER_S`); the sampler (as root, installed under
`/usr/local/sbin` because the agent kills root execs from `/home`) appends
one CSV row per interval: agent/watchdog RSS, VSZ, CPU, threads, fds,
systemd restart counters, journal WARN/ERROR/COMBAT counts, chain-log
sizes, occupancy of the growable eBPF maps (`FLOW_SOCK_MAP`,
`UDP_UNCONNECTED_SEEN`, `FIM_DIRTY_INODES`) and the ring-buffer drop
counter. The report fits a least-squares slope to the RSS series and
fails on any restart, any journal ERROR, an RSS slope above
`NN_LAB_SOAK_MAX_RSS_MB_H` (5 MB/h, judged on runs of at least 2 h) or an
fd count that grew by more than half. Planned use: 24 h on each guest
before a release, 72 h once before `0.1.0`.

### Release check (the CI tarball on every guest)

```
gh run download <release workflow run id> -D /tmp/nn-release   # tarball, packages, SBOMs, SHA256SUMS
deploy/lab/nn-lab.sh release-check /tmp/nn-release             # per guest (NN_LAB_DISTRO=…)
```

The Tappa 10.8 demo is the *same* tarball, built and attested by CI,
installed and verified on every distribution. `release-check` copies the
tarball and `SHA256SUMS` to the guest, stops the lab's source install and
then checks, in order: the tarball against `SHA256SUMS`; that the release
binaries run on the guest's glibc (CI builds on Ubuntu 24.04; the only
newer glibc symbols are weak); that `install.sh --tarball --sums` verifies
the tree and records `"provenance": "checksums"`; that the agent boots,
verifies its binaries against that manifest, attaches every deny hook and
arms the telemetry probe; and that an exec from `/tmp` fires R001. The
lab's source install is put back at the end. The attestation itself is
checked off the guest with `gh attestation verify <file> --repo
northnarrow/northnarrow-new` (gh ≥ 2.49) or cosign.

### Packages and the package manager

```
deploy/lab/nn-lab.sh pkgmgr-check     # dpkg/rpm survive the agent (probe package + a real reinstall)
deploy/lab/nn-lab.sh pkg-check        # our .deb/.rpm through their whole lifecycle
```

`pkgmgr-check` installs and removes a probe package that carries every
persistence shape the FIM rules watch (unit, timer, cron drop-in, setuid
binary, PAM and kernel module paths), then reinstalls a real package that
ships a unit. It fails on any destructive verdict or on a broken package
database; the writes must show up as Low log-only detections (review 49).

`pkg-check` builds the packages on the guest from the synced tree in the
guest's native format, then installs them over the lab's `install.sh`
layout (migration), upgrades, checks that an upgrade without a usable
trusted-installer key is refused with the agent untouched, removes,
purges, and does a fresh install whose install manifest says
`"provenance": "package"`. It puts the lab layout back with `install` at
the end.

### Overhead (agent off vs on)

```
deploy/lab/nn-lab.sh overhead          # 3 rounds; ~/.cache/nn-lab/<distro>/reports/overhead-<stamp>/overhead.md
deploy/lab/nn-lab.sh overhead 5        # more rounds, steadier medians
```

Measures what the agent costs the operations it hooks. Each round runs
`deploy/lab/overhead/nn-bench.c` twice, once with the agent off (units
stopped and pin root purged, so no hook is attached) and once with it on
(units started, 20 s to settle), on four workloads:

| workload | what one operation is | hooks it crosses |
|---|---|---|
| `open` | open + read 64 bytes + close, cycling over 64 files | `sys_enter_openat` tracepoint, LSM `file_open` and `file_permission` |
| `wopen` | open `O_WRONLY` + 4 KiB `pwrite` + close of one file | the same, on the write path |
| `exec` | fork + `execve(/bin/true)` + wait | `sys_enter_execve` and `sched_process_exec` tracepoints |
| `connect` | TCP connect + accept + close on `127.0.0.1` | `tcp_v4_connect` kprobe, `tcp_close` fexit |

The report gives the median throughput off and on, the throughput lost
and the agent's own CPU time while each workload ran (utime + stime of
its pid). These are worst-case microbenchmarks: every iteration is a
hooked operation, so real services lose far less. Run it on an otherwise
idle host, with no other guest busy: the off/on alternation cancels slow
drift, not a neighbour's load. The benchmark binary is built under
`/usr/local/libexec/nn-lab` and runs as root, because the agent kills a
root exec from a user-writable path (R009).

### Sensor feasibility (Tappa 10.9 step 0)

```
deploy/lab/nn-lab.sh build                          # the runner is in the lab build only
deploy/lab/nn-lab.sh sensor-feasibility             # ~/.cache/nn-lab/<distro>/reports/sensor-feasibility-<distro>-<stamp>.md
deploy/lab/nn-lab.sh sensor-feasibility /mnt/other  # the file checks on another filesystem (fixtures in /mnt/other/nn-feasibility)
```

Loads the throw-away probes of `agent-ebpf/src/sensor_probe.rs` on the
guest's kernel with `northnarrow-agent --sensor-feasibility` (feature
`test-privileged`) and exercises them from the runner's own process: the
LSM `file_open` observer (watched directory, name and ancestor tables,
write counter, a concurrent rename race), LSM `bprm_check_security` on
five kinds of exec, and the DNS payload read from the socket buffer over
IPv4 and IPv6. It prints one line per program (verifier verdict,
instruction count where the kernel reports it, attach) and per property,
and exits 1 if a required property fails. The installed agent is stopped
for the run and started again at the end. Results and their meaning:
`docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md` §9.
`NN_FEASIBILITY_BENCH=500000 deploy/lab/nn-lab.sh sensor-feasibility`
adds a cost-per-open table (§9.1): open + close of an unwatched file
with no program, an LSM program that returns at once, the open's key plus
one lookup, the step 1 fast path, and the full observer.

### btrfs inode keys (review 55)

```
deploy/lab/nn-lab.sh btrfs-check      # SKIP on kernels without btrfs (RHEL 9)
```

Reads `/root/.aws/credentials` (a watched file) after an agent restart,
first on the root filesystem as a control, then from a btrfs subvolume
(loop filesystem bind-mounted on `/root/.aws`). Both reads must draw
NN-L-FIM-011, or the kernel's inode keys do not match the ones userland
computed with `stat()`. The guest is put back as it was.

### RAG release gates need the real corpus

`rag::bench` holds three `#[ignore]` release gates (golden retrieval
≥ 90 %, retrieve p95 ≤ 50 ms, end-to-end `RAG_CONTEXT:` shape). They
index `target/kb/*.jsonl`, the pinned ATT&CK + SigmaHQ dumps produced by:

```sh
cargo xtask rag-kb            # fetches upstream (network), writes target/kb/
cargo xtask rag-kb --mirror <dir>   # install-time: from a local mirror
```

Without the dumps the engine silently indexes only the built-in seed, so
the gates now **fail fast** with that message instead of reporting a
meaningless pass rate (the "36.7 %" seen on the first lab nightly was
exactly this). `nn-lab.sh sync` ships `target/kb` to the guest when the
host has it, and `test-ignored` skips the gates (and says so) when it
does not. Reference result on the real corpus: golden 28/30 = 93.3 %,
retrieve p95 ≈ 1.9 ms, cold open ≈ 0.4 s.

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
    --features test-privileged,debug-trigger \
    --test privileged_e2e \
    -- --test-threads=1 --nocapture
```

Flags:
- `--features test-privileged,debug-trigger` — BOTH, same as the build
  step: cargo rebuilds `nn-admin` with the features of this invocation,
  and without `debug-trigger` the `nn-admin debug force-posture` call
  fails with `unrecognized subcommand 'debug'` (seen on the lab guest,
  2026-10-08);

- `sudo -E` preserves `$PATH` so cargo's own binary resolves;
  `--test-threads=1` is **mandatory** because iptables rules collide
  across parallel test invocations (they all use the same global
  `NORTHNARROW_COMBAT` chain);
- `--nocapture` is optional but very helpful — failures otherwise
  swallow the agent's stderr.

Expected: **6 tests passing, 3 ignored** in ~90 s (the two COMBAT tests
each wait for the graduated ladder to reach ISOLATE — ~30 s investigate
window — before checking the iptables chain):

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
