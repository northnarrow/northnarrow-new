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
SSH on `127.0.0.1:2222`. On Ubuntu `/usr/sbin/bpftool` is only a wrapper
around `linux-tools-$(uname -r)`: `up` installs that package (again after
a kernel change), `check` reports `bpftool : missing` when `bpftool
version` fails, and `test-e2e` / `test-ignored` refuse to start then —
the fixtures stop their agents through bpftool (lab PR 153). WSL2 needs nested virtualization (`/dev/kvm`
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
deploy/lab/nn-lab.sh respawn-check # refused kill -9 / systemctl kill, then a death in a window; asserts unit active, cgroup, CAP_KILL, watchdog alive
deploy/lab/nn-lab.sh snapshot clean   # (guest down) revert point before an attack run
```

The eBPF object is built on the **host** (nightly + bpf-linker 0.10.3)
and shipped with its provenance stamp; the guest only builds userland,
so `agent/build.rs`'s staleness guard still holds. `respawn-check` is
the VM half of `docs/design/WATCHDOG_RESPAWN_V2_DESIGN.md` §4.

**Base images are verified** (external audit LAB-009,
`deploy/lab/lib/verify-download.sh`). `up` downloads an image only
against the vendor's list: Ubuntu's `SHA256SUMS` signed by the UEC Image
Automatic Signing Key (`D2EB4462…7DB87C81`), AlmaLinux's `CHECKSUM` signed
by the AlmaLinux OS 9 key (`BF18AC28…B86B3716`). The keys are pinned by
fingerprint in the script and cached in `~/.cache/nn-lab/keys/`; a list
counts only with a good signature by the pinned primary key (an expired or
revoked key is refused). Debian signs none of its current cloud images: its
`SHA512SUMS` is taken over HTTPS only (Debian's documented method) and the
record says `unsigned`. The image keeps its final name only once its digest
matches the list, and the digest is recorded in
`<image>.verified` next to it; a new guest disk (first `up`, or after
`destroy`) is only layered on an image that still matches its record. An
image downloaded before these checks is neither downloaded again nor
deleted (the guests are layered on it): `up` warns, and

```sh
NN_LAB_DISTRO=<distro> deploy/lab/nn-lab.sh verify-image   # host side, no guest needed
```

looks for its digest in the lists the vendor still publishes (the current
build, then up to `NN_LAB_VERIFY_BUILDS`=40 dated builds for Ubuntu and
Debian; AlmaLinux's `CHECKSUM` lists its recent builds) and writes the
record when it finds it; otherwise it fails and says to download again. The
nightly report names the image and its record. Host packages: `gnupg`,
`gpgv`. In the guest, cloud-init runs a pinned `rustup-init` checked
against its pinned SHA-256 (no `curl | sh`). The self-test runs without
network or guest: `bash deploy/lab/lib/verify-download-test.sh`.

### Other guests: Debian 12, Debian 13, Ubuntu 22.04, AlmaLinux 9

`NN_LAB_DISTRO=<distro> deploy/lab/nn-lab.sh up` boots a separate guest;
prefix any sub-command with the variable to target it. Each guest has its
own disk, seed, ssh port and reports under `~/.cache/nn-lab/<distro>/`
(the original `ubuntu2404` keeps the flat layout):

| `NN_LAB_DISTRO` | kernel | ssh port | notes |
|---|---|---|---|
| `ubuntu2404` (default) | 6.8 | 2222 (2322 on this host) | build kernel |
| `debian12` | 6.1 | 2422 | `perf_event_paranoid=3` drop-in |
| `debian13` | 6.12 | 2722 | first guest from 6.9 (`inode_setattr` takes `mnt_idmap` first); `nftables` installed; `perf_event_paranoid=3` drop-in |
| `ubuntu2204` | 5.15 | 2522 | older verifier, sudo 1.9.9, systemd 249 |
| `alma9` | 5.14 el9 | 2622 | SELinux enforcing, vendor tracepoint header; `kernel.io_uring_disabled=2` (no ring, not even for root); sudo's `secure_path` has no `/usr/local/bin`, so call `/usr/local/bin/nn-admin` |

`install` builds the tree already on the guest: run `sync` first
(`sync && install`), or the guest builds what it had. On a guest whose
agent ran for a long time, `sync` can be refused on a file whose inode
number an earlier, deleted protected file had (candidate review 80): the
next `install` purges the pins, and a second `sync` goes through.

**Lockdown guest** (lab PR 206). `NN_LAB_LOCKDOWN=integrity
NN_LAB_DISTRO=<distro> deploy/lab/nn-lab.sh up` boots a separate guest of
that distro with `lockdown=integrity` added to its `lsm=` line (the
templates end that line in `__NN_LAB_KARGS__`): its own disk, seed and
reports under `~/.cache/nn-lab/<distro>-lockdown-integrity/`, the
distro's ssh port + 1000 (3222 for 24.04, 3522 for 22.04), layered on the
distro's base image. `check` prints the lockdown state and fails on that
guest when the kernel is not locked down. It is the guest where the
anti-tamper suite's C27 (an unsigned module refused by the kernel) runs;
elsewhere C27 is a listed KNOWN GAP. Prefix every sub-command with both
variables to target it.

The verified matrix and the per-kernel findings are in
`docs/operator/KERNEL_COMPATIBILITY.md`. Memory: each guest takes
`NN_LAB_MEM` (8 GiB); on a 32 GiB host keep at most two guests up during
long runs — four at once starved the host (2026-10-10).

### Nightly, unattended

`deploy/lab/nn-lab.sh nightly` runs check → sync → build → test-e2e →
test-ignored → install → the security checks (tamper-check → pkgmgr-check
→ open-sensor-check → fim-reuse-check → btrfs-check → overlay-check, on
the fresh install; lab PR 206) → respawn-check → upgrade-check →
uninstall-check (the last two exercise `install.sh --upgrade` on the
running install and `uninstall.sh --purge`, then reinstall — see
`docs/operator/INSTALL_UPGRADE_UNINSTALL.md`) without stopping at the first
failure, writes `~/.cache/nn-lab/reports/<stamp>.md` (status, duration
and, per step, its verdict lines: every `test result:`, each check's own
verdict, the anti-tamper rows that are a DEVIATION, a KNOWN GAP or N/A;
`latest.md` points at the newest) and exits 1 if any step failed. A step
that says it does not apply (btrfs-check on a kernel without btrfs) is
`N/A`, not ok; a `NOT RUN` fails whatever its exit status. Each security
check starts the units it finds stopped. The security checks add tens of
minutes; `NN_LAB_NIGHTLY_SKIP` takes their names too. The privileged tests only *compile* in
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
step.

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

First run, AlmaLinux 9.8 (5.14), 24 h to 2026-10-12: PASS. RSS slope
0.04 MB/h (34.6 → 37.7 MB), no restart, no journal ERROR, fds 100 (max
102). The only ring drops (22,025) were on the old `file_open` tracepoint
ring of the build under test, which predates the LSM file-open sensor.
The ~216 NN-L-BPF-002 detections per hour came from the sampler's own
`bpftool` calls, not from the workload.

### Release check (the CI tarball on every guest)

```
gh run download <release workflow run id> -D /tmp/nn-release   # tarball, packages, SBOMs, SHA256SUMS
deploy/lab/nn-lab.sh release-check /tmp/nn-release             # per guest (NN_LAB_DISTRO=…)
```

The Tappa 10.8 demo is the *same* tarball, built and attested by CI,
installed and verified on every distribution. `release-check` copies the
tarball and `SHA256SUMS` to the guest, stops the lab's source install and
then checks, in order: the tarball against its own line in `SHA256SUMS`
(exactly one; external audit LAB-010: nothing is extracted otherwise, and
the archive's owners and modes are not kept); that the release
binaries run on the guest's glibc (CI builds on Ubuntu 24.04; the only
newer glibc symbols are weak); that `install.sh --tarball --sums` verifies
the tree and records `"provenance": "checksums"`; that the agent boots,
verifies its binaries against that manifest, attaches every deny hook and
arms the telemetry probe; and that an exec from `/tmp` fires R001. The
lab's source install is put back at the end. The attestation itself is
checked off the guest (gh ≥ 2.49 or cosign) with the tag-bound command of
`docs/operator/INSTALL_UPGRADE_UNINSTALL.md` §5: an artefact of a dispatch
run on a branch fails it by design (external audit SUP-001), so the
attestation check needs a tag build.

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
(units started, 20 s to settle), on six workloads:

| workload | what one operation is | hooks it crosses |
|---|---|---|
| `open` | open + read 64 bytes + close, cycling over 64 files | LSM `file_open` (FIM watch and file-open sensor), `file_permission`, `file_free_security` |
| `wopen` | open `O_WRONLY` + 4 KiB `pwrite` + close of one file | the same, on the write path |
| `exec` | fork + `execve(/bin/true)` + wait | LSM `bprm_check_security`, `sched_process_exec` tracepoint |
| `connect` | TCP connect + accept + close on `127.0.0.1` | `tcp_v4_connect` kprobe, `tcp_close` fexit |
| `udp` | connected UDP `send()` to `127.0.0.1` | `udp_sendmsg` kprobe (per-destination aggregation, review 73), `udp_send_skb` kprobe |
| `dns` | one DNS query to `127.0.0.1:53` | `udp_send_skb` kprobe (the DNS sensor and its per-process budget, review 78) |

The report gives the median throughput off and on, the throughput lost
and the agent's own CPU time while each workload ran (utime + stime of
its pid). These are worst-case microbenchmarks: every iteration is a
hooked operation, so real services lose far less. Run it on an otherwise
idle host, with no other guest busy: the off/on alternation cancels slow
drift, not a neighbour's load.

Official numbers, Ubuntu 24.04 (6.8), idle host, 3 rounds, `main` 1777e6f
(2026-10-12): open +25.4 %, wopen +29.1 %, exec +8.6 %, connect +34.1 %,
udp +25.2 %, dns +14.2 %. The agent's own CPU was 0 ms for open and wopen
(the cost is in the kernel hooks, review 59), 220 ms for exec, 240 ms for
connect, 120 ms for udp and 20 ms for dns. The dns workload is one process,
so beyond its budget its queries are counted, not recorded. The benchmark binary is built under
`/usr/local/libexec/nn-lab` and runs as root, because the agent kills a
root exec from a user-writable path (R009).

### Sensor feasibility (Tappa 10.9 step 0)

```
deploy/lab/nn-lab.sh build                          # the runner is in the lab build only
deploy/lab/nn-lab.sh sensor-feasibility             # ~/.cache/nn-lab/<distro>/reports/sensor-feasibility-<distro>-<stamp>.md
deploy/lab/nn-lab.sh sensor-feasibility /mnt/other  # the file checks on another filesystem (fixtures in /mnt/other/nn-feasibility.XXXXXX)
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

### File-open sensor (Tappa 10.9 step 1)

```
deploy/lab/nn-lab.sh open-sensor-check   # after sync + install
```

Checks the default (LSM) mode end to end on the running agent:

- the sensor is armed and `sys_enter_openat` retired, with no
  missing-link report from the BPF self-check;
- `~/.aws/credentials` of the lab user, read by root's `cat` and through
  `io_uring`, gives NN-L-FIM-011 with the Log action (design Q8);
- 25 write-opens give exactly one `MassWrite`;
- a write under `/etc/cron.d` from the `observing` posture raises
  `PersistenceMechanism`;
- a write under `/etc/ssh/sshd_config.d` raises
  `CriticalFileModification` (the posture list is a path prefix, and the
  kernel classifies by directory);
- a write-open of `/etc/crontab` through a symlink raises
  `CriticalFileModification`: the record names the file the kernel
  opened, not the caller's path (in tracepoint mode this case fails);
- the telemetry probe never went silent.

Put a unit drop-in with `Environment=NN_FILE_OPEN_SENSOR=tracepoint` to
compare with the old sensor, for example under `nn-lab.sh overhead`.

### Exec sensor (Tappa 10.9 step 2)

```
deploy/lab/nn-lab.sh exec-sensor-check   # after sync + install
```

Checks the default (LSM) mode end to end on the running agent. Run as the
lab user, the execs below must be killed by the rule that names the file
the kernel executed, not the string the caller passed (review 61):

- the sensor is armed on `bprm_check_security`, with no missing-link
  report;
- `cd /tmp && ./x`, a symlink in a root-owned directory pointing to
  `/tmp/x`, `/usr/bin/../../tmp/x`, and a script in `/tmp` run as `./x.sh`
  are killed by R001;
- a memfd run through an ordinary symlink in the home (to
  `/proc/self/fd/N`) is killed by R004 on the kernel's memfd flag;
- `/usr/bin/sleep` runs untouched;
- the telemetry probe never went silent.

The helper `deploy/lab/exec-sensor/memfd-exec.c` is built on the guest
(`/usr/local/libexec/nn-lab/nn-memfd-exec`). With a unit drop-in setting
`Environment=NN_EXEC_SENSOR=tracepoint` (the old sensor) the evasion
cases fail: that is the gap the step closes.

### DNS sensor (Tappa 10.9 step 3)

```
deploy/lab/nn-lab.sh dns-sensor-check   # after sync + install
```

Checks the default (`skb`) mode end to end on the running agent. Run as
the lab user, a helper sends one query for a name with NET-004's
tunnelling shape to a local port 53, in a different way per case. The
sender must be killed by NET-004, because the sensor reads the kernel's
copy of the query (reviews 66, 67):

- the sensor is armed on `udp_send_skb` and `udp_v6_send_skb`, with no
  missing-link report;
- connected `send()` and unconnected `sendto()` to `127.0.0.1:53`;
- connected `send()` to `[::1]:53`;
- the query in a file mapping the process has not touched yet;
- a zero byte inside the first label, in a long name;
- the query sent in two pieces (`MSG_MORE`) gives a NET-004 record (Log)
  for a partial name, and the sender is not killed;
- `getent hosts` through the system resolver gives no NET record;
- the telemetry probe never went silent.

The helper `deploy/lab/dns-sensor/dns-send.c` is built on the guest
(`/usr/local/libexec/nn-lab/nn-dns-send`). With a unit drop-in setting
`Environment=NN_DNS_SENSOR=sendmsg` (the old sensor), the IPv6, unfaulted
page and zero-byte cases fail: that is the gap the step closes.

### btrfs inode keys (review 55)

```
deploy/lab/nn-lab.sh btrfs-check      # SKIP on kernels without btrfs (RHEL 9)
```

Reads `/root/.aws/credentials` (a watched file) after an agent restart,
first on the root filesystem as a control, then from a btrfs subvolume
(loop filesystem bind-mounted on `/root/.aws`). Both reads must draw
NN-L-FIM-011, or the kernel's inode keys do not match the ones userland
computed with `stat()`. The guest is put back as it was.

### FIM: a deleted watched file's inode (reviews 57, 58)

```
deploy/lab/nn-lab.sh fim-reuse-check
```

Moves a file into `/etc/cron.d`, which the drain must enroll by inode
(review 58), and deletes it. It then creates files in `/tmp` until one
reuses that inode number and appends to it. The write must not reach the
FIM rules as a modification of the deleted cron file (review 57: it did,
and NN-L-FIM-007 killed the writer). SKIP when the number is not reused
within 2000 files.

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

The suite passes when **every test it lists runs and passes**: no test
failed, ignored or filtered out. The runbook carries no count (it drifted:
"9 passing, 2 ignored" was written for a suite of ten with none ignored,
external audit NN-AUD-421); `nn-lab.sh test-e2e` checks it on each run.
For each of its three suites it takes the number of tests from
`cargo test … -- --list` and compares it with the run's one `test result:`
line, which must read `ok. N passed; 0 failed; 0 ignored; …; 0 filtered
out` with that same N (`deploy/lab/lib/suite-count.sh`, self-test
`bash deploy/lab/lib/suite-count-test.sh`). It prints `count ok: <suite>:
N of N passed`, or a `FAIL: <suite>: …` line that names what is missing
(also in the nightly report), and the step fails if any suite does.
`NN_LAB_E2E_TEST_ARGS` adds libtest arguments to the runs, not to the
listing: `NN_LAB_E2E_TEST_ARGS="--skip e2e_status_no_admin_action_initially"`
must fail the agent suite (`… of … passed (0 failed, 0 ignored, 1 filtered
out)`). The two COMBAT tests each wait for the graduated ladder to reach
ISOLATE (~30 s investigate window) before checking the iptables chain.

### The privileged suites

Every suite below needs a build with the eBPF object (`cargo xtask
build-ebpf`) and runs as root, single-threaded:
`sudo -E env "PATH=$PATH" cargo test --release -p <crate> --features <features> --test <suite> -- --test-threads=1`
(add `--ignored` where the tests are `#[ignore]`d). The fixtures stop their
agents through `bpftool` and refuse to start one without it.

| Suite (`--test`) | Crate, features | Run as | Needs besides root and bpftool | `nn-lab.sh` step |
|---|---|---|---|---|
| `privileged_e2e` | agent, `test-privileged,debug-trigger` | plain tests | iptables | `test-e2e`; `test-ignored` (last run) |
| `fim_privileged_e2e` | agent, `test-privileged,debug-trigger` | plain tests | BPF-LSM, bpffs, no agent holding the pin root | `test-e2e`; `test-ignored` (last run) |
| `privileged_e2e` (watchdog) | watchdog, `test-privileged` | plain tests | BPF-LSM, bpffs | `test-e2e`; `test-ignored` (own run) |
| `privileged_map_pin` | agent, `test-privileged` | the restart test `#[ignore]`d (it purges the pin root), its parsers plain | BPF-LSM, bpffs, no agent running | `test-ignored` (first, alone) |
| `fixture_selftest` | agent; `test-privileged` for the iptables tests | iptables tests `#[ignore]`d; the helper tests plain, in `cargo test --workspace` | iptables, no NorthNarrow daemon running | `test-ignored` (first) |
| `canary_privileged_e2e` | agent, `test-privileged,debug-trigger` | `#[ignore]` | BPF-LSM, bpffs, iptables | `test-ignored` |
| `net_privileged_e2e` | agent, `test-privileged,debug-trigger` | `#[ignore]` | BPF-LSM with fexit, bpffs, iptables, python3 | `test-ignored` |
| `detection_rules_at_scale_privileged_e2e` | agent, `test-privileged,debug-trigger` | `#[ignore]` | BPF-LSM, bpffs, iptables, `cc` (it compiles its helpers) | `test-ignored` |
| `response_privileged_e2e` | agent, `test-privileged,debug-trigger` | `#[ignore]` | BPF-LSM, bpffs, `cc`, `/tmp` mounted exec | `test-ignored` |
| `fs_deny_privileged_e2e` | agent, `test-privileged,debug-trigger` | `#[ignore]` | BPF-LSM; it uses the real `/etc/northnarrow`, `detections/` and pin root (units stopped, pins purged) | `test-ignored` |
| `honeypot_tamper_e2e` | agent, `test-privileged,debug-trigger` | `#[ignore]` | BPF-LSM; a disposable host (an nn-lab guest, or `NN_TEST_DISPOSABLE_HOST=1`), no NorthNarrow daemon running; it rewrites the real bait files and puts them back | `test-ignored` |
| `exec_sensor_live` | agent, no feature | `#[ignore]` | BPF tracepoints (`CAP_BPF` + `CAP_PERFMON` suffice) | `test-ignored` |

What the fixtures guarantee (external audit Wave 3, lab PR 195): the
agents run from root-owned copies under `/usr/local/bin`
(`common::install_to_priv_bin`), never from `target/` under a home
directory, and are stopped before their tempdirs go; the JSONL logs are
read strictly (`common::read_jsonl_strict`: a malformed complete line fails
the test with its file, line number and first 200 bytes; only an
unterminated last line, a write in progress, is left for later); the
iptables guard removes every jump to `NORTHNARROW_COMBAT` (v4 and v6),
reads the tables back and fails the test when anything is left.

`bpf_guard_enforce_refuses_protected_pids_write` (external audit TST-001,
TST-010) starts the agent with `NN_BPF_DEFENSE_ENFORCE=1` — the BPF guard
as in production — and `--detect-only`, then asserts: the registration
line says `mode="enforce"`; `bpftool map delete pinned …/PROTECTED_PIDS
key <agent pid>` and `kill -9 <agent pid>` from root both fail with
`Operation not permitted` and leave `ANTI-TAMPER DENIAL op=bpf_map` /
`op=signal` in the agent log; the fixtures' own teardown
(`common::try_quit_agent`: eviction, then SIGQUIT) fails and says the
eviction was refused; a signed 2-of-N `nn-admin shutdown` stops the agent.
The guard outlives the agent and would refuse the next fixture's agent (a
different installed copy), so the test ends by starting the same binary
without the variable, which re-arms the guard in observe mode, and stopping
it. If that last step fails the test says so; `nn-lab.sh` then recovers the
pin root by restarting the guest (`lab_purge_pins`). Every other fixture
stops its agent with `common::quit_agent`, which only a `debug-trigger`
build (guard in observe mode) allows, and which now fails the test when
the agent survives (it used to print a line and leave the agent running).

`e2e_failures_on_other_connections_do_not_rate_limit` replaced the
ignored `e2e_rate_limit_via_full_stack` (external audit NN-AUD-079):
signature failures now count per connection, and a connection is closed
after three, so there is no agent-wide five-minute window left to wait
for.

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
- **`` `sudo bpftool version` fails … not starting one ``** (panic before
  the agent starts) or **`quit_agent: the agent of sudo pid … is still
  alive`** — the fixtures evict their agent from `PROTECTED_PIDS` with
  bpftool before signalling it. Install `linux-tools-$(uname -r)` (Ubuntu);
  an agent left running is stopped with a signed `nn-admin shutdown` or by
  restarting the host, never by more signals (each refused one is a tamper
  attempt the agent answers).
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

# Cleanup: the task_kill hook refuses every signal from a root shell,
# SIGQUIT included. Stop it with a signed shutdown: two keys carrying the
# `shutdown` role in admin.pub (`<hex> unlock,shutdown`, see
# init_admin_keypair_with_roles in privileged_e2e.rs).
./target/release/nn-admin shutdown --key /tmp/nn-test/admin.priv \
  --cosign-key /tmp/nn-test/admin2.priv --socket /tmp/nn-test/admin.sock
```

## Future work (tracked, not blocking)

- **Migrate `admin_release_combat` (bool stub) call sites** to
  `admin_release_combat_with_token`. Five test sites + the
  `posture_demo` example are the current callers; since external audit
  POS-013 the stub is compiled only for tests and the `posture-demo`
  feature (the example's `required-features`), so no production build
  contains it.
- **`--strict-anti-tamper` boot flag**: a missing `combat-rules.v4` or
  `admin.pub` is an ERROR, no longer a WARN, and the agent continues:
  without isolation and without its admin socket for the first (the
  ERROR says so), without its admin socket for the second, which also
  writes a signed `subsystem_degraded` record ("admin socket disabled: …",
  external audit AUT-004; asserted by
  `privileged_e2e::agent_without_admin_pub_starts_degraded_and_says_so`).
  A flag that refuses to start instead, for production deployment
  configs, is still open.
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

The agent is in `PROTECTED_PIDS`: the task_kill hook refuses every
signal from a root shell, and `systemctl kill` too unless a signed
trusted-installer window is open (external audit EBPF-001). An
unexpected death is produced the operator's way: the window, then the
SIGKILL delivered by systemd. No shutdown marker is written (only a
signed `nn-admin shutdown` writes one), so the watchdog treats it as a
crash. `deploy/lab/nn-lab.sh respawn-check` runs this sequence and fails
if either refusal is missing.

Do not take the agent's pid out of `PROTECTED_PIDS` to kill it (the
recipe this test used to publish). On a production build the BPF guard
refuses the write (`Operation not permitted`, recorded as NN-L-AT-001);
only a `debug-trigger` build, whose guard observes, lets it through, and
the privileged e2e `bpf_guard_enforce_refuses_protected_pids_write`
asserts the refusal (external audit TST-002).

```
AGENT_PID=$(sudo cat /run/northnarrow/agent.pid)

# Both refused (FAIL if either succeeds):
sudo kill -9 "$AGENT_PID"            # → Operation not permitted
sudo systemctl kill --kill-who=main -s SIGKILL northnarrow-agent.service
                                     # → Access denied

# The window (a key with the trusted-installer role), then systemd's kill:
sudo nn-admin trusted-installer-grant --key <trusted-installer key> --window-secs 120
sudo systemctl kill --kill-who=main -s SIGKILL northnarrow-agent.service

# Expect within a few seconds:
journalctl --namespace=northnarrow -u northnarrow-watchdog.service --since "1 minute ago"
# Look for, in order:
#   "agent pidfd POLLIN — agent has exited"        (W3)
#   "layer-2 evict complete"                       (W3)
#   "no shutdown-authorisation marker"             (W4)
#   "respawning agent"                             (W4)
#   "defensive PROTECTED_PIDS reinsert complete"   (W4)

# New agent PID published, under the agent's own unit; the respawned
# agent boots with the window closed (grants are bound to its session):
NEW_PID=$(sudo cat /run/northnarrow/agent.pid)
[[ $NEW_PID != $AGENT_PID ]] && echo "OK: PID changed $AGENT_PID → $NEW_PID"
systemctl is-active northnarrow-agent.service      # → active
sudo kill -9 "$NEW_PID"                            # → Operation not permitted
```

#### Test 3 — Authorised stop → the watchdog stands down

The units refuse a manual stop (`RefuseManualStop=yes`); the watchdog no
longer `BindsTo` the agent. The authorised stop is a 2-of-N signed
shutdown: the agent writes the shutdown marker and exits, the watchdog
verifies the marker against `admin.pub` and does not respawn.

```
sudo systemctl stop northnarrow-agent.service
# → refused: "Operation refused, unit … may be requested by dependency only"
sudo nn-admin shutdown --key <shutdown key A> --cosign-key <shutdown key B> --grace-secs 30
sleep 5
systemctl is-active northnarrow-agent.service       # → inactive
journalctl --namespace=northnarrow -u northnarrow-watchdog.service --since "1 minute ago" \
  | grep "watchdog standing down"
# Expect: "admin-authorised shutdown verified against admin.pub — watchdog standing down"
```

#### Test 4 — Watchdog death → systemd restarts it; the agent stays protected

The watchdog is a protected pid too: `kill -9` from a root shell is
refused. Its death is produced like the agent's, inside a window.

```
sudo systemctl start northnarrow-agent.service northnarrow-watchdog.service
sleep 3
OLD_WPID=$(sudo cat /run/northnarrow/watchdog.pid)
sudo kill -9 "$OLD_WPID"             # → Operation not permitted
sudo nn-admin trusted-installer-grant --key <trusted-installer key> --window-secs 120
sudo systemctl kill --kill-who=main -s SIGKILL northnarrow-watchdog.service
sleep 4                              # Restart=on-failure, RestartSec=2s
NEW_WPID=$(sudo cat /run/northnarrow/watchdog.pid)
[[ $NEW_WPID != $OLD_WPID ]] && echo "OK: watchdog restarted by systemd"

# Agent unchanged and still protected:
sudo cat /run/northnarrow/agent.pid   # unchanged
sudo kill -9 "$(sudo cat /run/northnarrow/agent.pid)"   # → Operation not permitted
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
