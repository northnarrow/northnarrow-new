# Performance

How NorthNarrow's agent is built for speed (§1), and how its cost is
measured on a lab guest and gated against a committed baseline (§2).
Reading the committed baseline and its thresholds:
[`validation/PERF_BASELINE.md`](validation/PERF_BASELINE.md).

**Where numbers come from.** A performance figure about NorthNarrow is a
measurement only when it comes from a committed result file:
`docs/validation/results/perf-<date>-<guest>-<commit>.json`, which holds
every raw sample with the host, the tree and the method it was taken with,
and the `.md` summary written with it (§2.3). A figure anywhere else — this
file, the README, the runbook, the roadmap, a design note, a pull request —
either quotes such a file and names it, or is an expectation and says so.
The first baseline is
[`validation/results/perf-2026-10-21-ubuntu2404-40fd666.json`](validation/results/perf-2026-10-21-ubuntu2404-40fd666.json)
(Ubuntu 24.04, kernel 6.8, lab PR 228).

History: until lab PR 228 this file described the on-host LLM advisor's
tuning (build flags, threads, streaming; removed with the advisor in Wave 4,
lab PR 214) and quoted its expected speed-ups and a May 2026 table from the
CCX23 host, and the runbook and the roadmap quoted an agent overhead of
+8.6 % to +34.1 % (open, write, exec, connect, UDP, DNS; one set of three
rounds on one nested Ubuntu 24.04 guest, `main` 1777e6f, 2026-10-12); none
of them kept the raw data, and they are withdrawn.

## 1. Build flags (`target-cpu` + LTO fat)

Since external audit SUP-017 the default in `/.cargo/config.toml` is the
ISA the release ships, so no build is tied to the host that compiled it:

```toml
[build]
rustflags = ["-C", "target-cpu=x86-64-v2"]
```

A build that only ever runs on the host that compiles it opts into
`native` for the x86_64 target, which leaves the eBPF build's flags alone
and which `cargo xtask build` passes on:

```bash
CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-cpu=native" cargo xtask build --release
```

The release profile of `Cargo.toml`:

```toml
[profile.release]
opt-level = 3
codegen-units = 1
lto = "fat"
panic = "abort"
strip = "symbols"
```

`lto = "fat"` allows cross-crate inlining across the agent's crates and
their dependencies; `panic = "abort"` removes the unwind tables; `strip`
keeps the installed binaries small. A second profile, `release-bench`,
inherits release but keeps debug symbols, so `perf record` and flame graphs
can name the agent's functions:

```bash
cargo build --profile release-bench -p northnarrow-agent
```

The lab builds with thin LTO (`NN_LAB_LTO`, default `thin`: fat LTO can
peak at 6–8 GiB at link, more than a guest has); a baseline records which
(§2.2). The effect of these flags on the agent's cost has no result file.

### Trade-offs

- LTO fat builds take several times longer than thin and need several
  GiB of RAM at link; downgrade to `lto = "thin"` where a smaller host
  runs out of memory at link time.
- `target-cpu=native` makes the binary non-portable: it only runs on
  the build host's exact ISA or newer (review 64: a release built on an
  AVX-512 runner died with SIGILL elsewhere). Releases, packages, the lab
  and the range therefore build for x86-64-v2, and what they measure is
  for that ISA; `native` needs the opt-in above.

## 2. Agent cost baseline and regression gate (lab PR 228)

What the agent costs the operations it hooks, how fast it records a
detection, what it loses under a burst, what it uses, and how long it
takes to start — measured the same way every time on a lab guest, kept
with every raw sample, and compared by a gate. Every later lot that can
move these figures (dependency bumps, the crate restructuring R00–R14, a
new hook or sensor) is run against the committed baseline.

Tools: `deploy/lab/perf/perf-run.sh` (on the guest, as root),
`deploy/lab/perf/perf_lib.py` (the measurement loops and the report),
`deploy/lab/perf/nn-perf-probe.c` (three probes),
`deploy/lab/overhead/nn-bench.c` (the hooked-operation workloads, shared
with `nn-lab.sh overhead`), `deploy/lab/soak/generate.sh` (the burst
load), `nn-lab.sh perf` (ships, runs, fetches), `cargo xtask perf-compare`
(the gate).

### 2.1 What is measured

| metric | unit | one sample | gated |
|---|---|---|---|
| `syscall_getppid_ns` | ns/op | one pass of 2,000,000 `getppid(2)`: the raw-syscall path and nothing else | yes |
| `syscall_read_devzero_ns` | ns/op | 1,000,000 `read(2)` of 64 B from `/dev/zero` | yes |
| `open_unwatched_ns` | ns/op | 100,000 open + read 64 B + close of copies of the watched files below, in an unwatched scratch directory | yes |
| `open_watched_ns` | ns/op | the same on the FIM-listed files of `/etc` (`hosts`, `group`, `nsswitch.conf`, `fstab`, `profile`: those of them in the installed `fim-paths.v1`); the two differ only by the watch | yes |
| `write_open_ns` | ns/op | 25,000 open `O_WRONLY` + `pwrite` 4 KiB + close | yes |
| `exec_true_ns` | ns/op | 1,000 fork + `execve(/bin/true)` + wait | yes |
| `tcp_connect_close_ns` | ns/op | 3,000 TCP connect + accept + close on 127.0.0.1 | yes |
| `udp_send_ns` | ns/op | 100,000 `sendto()` of 64 B to a local socket | yes |
| `dns_send_ns` | ns/op | 20,000 DNS queries sent to 127.0.0.1:53 (nobody listens: the sensor's cost without the resolver's) | yes |
| `dns_resolver_query_ns` | ns/op | 2,000 A queries for `localhost` to the guest's resolver, each answer awaited | yes |
| `event_to_record_ms` | ms | one probe read of a `.aws/credentials` fixture → the `ts` of its signed `NN-L-FIM-011_AwsCredsRead` record | yes |
| `event_to_disk_ms` | ms | the same read → that record's line read back from `detections.jsonl` (2 ms polling) | yes |
| `agent_cpu_idle_pct`, `agent_cpu_load_pct` | % of one CPU | the agent's utime + stime over a 10 s window, idle and under the burst | yes |
| `agent_rss_idle_kib`, `agent_rss_load_kib` | KiB | the agent's VmRSS, every second, idle and under the burst | yes |
| `agent_rss_after_load_kib` | KiB | the same during the cool-down after the burst | no |
| `burst_ring_drops`, `burst_ring_rejected` | count | ring records dropped / rejected during the burst (signed status, after − before) | yes |
| `burst_netflow_pending_evicted`, `burst_flow_sock_forgotten` | count | network-tracker losses during the burst (signed `net status`) | yes |
| `burst_netflow_rows_skipped`, `burst_detections_held` | count | rows the per-uid pacing held back, detections the per-rule budget did not store (both by design) | no |
| `burst_generator_iterations` | count | the generator's completed iterations: the load actually applied | no |
| `burst_forks_per_s` | processes/s | the guest's process creations per 10 s window during the burst (`/proc/stat` `processes`): the exec event rate the agent kept up with | no |
| `boot_to_ready_ms` | ms | a cold start (pin root purged): systemd's `ExecMainStartTimestampMonotonic` → `ActiveEnterTimestampMonotonic` (READY=1) | yes |
| `<workload>_off` | ns/op | each workload with the agent stopped: the reference | no |

The iteration counts are at `--scale 1`; each pass lasts a fraction of a
second to about a second on the lab guests. The `.md` also gives the
overhead of each workload, (on − off) / off of the medians, and the
agent's own CPU per operation.

### 2.2 How

- **Where.** A lab guest of `deploy/lab/nn-lab.sh`, the installed agent
  (`nn-lab.sh install`), an otherwise idle host. `nn-lab.sh perf --fresh`
  syncs and installs the host checkout first, so the measured agent is
  that commit; without `--fresh` the result says the tree was installed
  before and is not checked.
- **Agent off.** The units refuse a manual stop and the kernel refuses
  systemd's signals outside a signed trusted-installer window (external
  audit EBPF-001). The run opens the window with the lab's admin key
  (`nn-admin trusted-installer-grant`), sends the watchdog then the agent
  SIGTERM (SIGKILL after 10 s), and removes the pin root, whose links keep
  the deny hooks attached otherwise — the operator path of
  [`operator/INSTALL_UPGRADE_UNINSTALL.md`](operator/INSTALL_UPGRADE_UNINSTALL.md)
  §3.7, as `nn-lab.sh`'s `lab_purge_pins`. Nothing of the
  product is changed or bypassed: without the window the run stops (exit
  3). The LSM programs still loaded afterwards are counted and recorded.
- **Agent on.** `systemctl start`, the boot time from systemd, the
  agent's own `all LSM hooks attached` line (read with
  `deploy/lab/lib/lab-records.py`), the watchdog, 20 s to settle; then the
  idle window (60 s), the workloads, the latency probes (2 warm-up + 20),
  the burst (60 s), a cool-down (65 s: the per-rule budget reports what it
  held once a minute), then 5 more cold starts for the boot time. After
  the probes and after the burst the posture is put back to observing (a
  debug-trigger build, as the other lab checks do).
- **Repetitions.** Each pass runs every workload once, in turn: 1 warm-up
  pass (dropped) and 10 measured passes per phase, so a slow drift spreads
  over all workloads instead of landing on one. `--rounds R` alternates
  off and on R times and pools the samples.
- **Pinning.** The workloads run on the last vCPU (`taskset`); the agent
  is not touched (its affinity is the product's). The host's vCPU threads
  are not pinned by `nn-lab.sh`.
- **Latency probe.** `nn-perf-probe credread` takes `CLOCK_REALTIME` just
  before it opens a `.aws/credentials` fixture in the run's own root-only
  scratch directory: the file-open sensor classifies it in the kernel,
  `NN-L-FIM-011` records root's read (`Log`: a wide-coverage read is
  reported, never acted on), the record's `ts` is the same clock. The lab
  user's `~/.aws` is not touched, and `/root/.aws` (FIM-listed: there the
  rule kills) is not used.
- **Burst.** `deploy/lab/soak/generate.sh` as the lab user at 200 execs,
  100 file cycles, 20 HTTP requests, 200 UDP datagrams and 5 DNS lookups
  per second (`--burst-rates`), its own ports; `nn-admin status --key`
  and `nn-admin net status --key` before, every 10 s, and 5 s after the
  end (one signed `telemetry_status` audit row each); the guest's process
  creations per window (`/proc/stat` `processes`), the event rate the
  agent kept up with.
- **Recorded with every run**: kernel, OS, CPU model, vCPUs, memory,
  virtualisation, clocksource, kernel command line; the tree commit, its
  uncommitted changes and how it was installed, its branch point on
  `origin/main` and which build inputs (the agent's, eBPF, common,
  watchdog and scanner crates, the lockfile and toolchain, `configs/`,
  `install.sh`, the units) differ from it, the build features and LTO
  (with `--fresh`); the SHA-256 of the agent, watchdog and `nn-admin`;
  the unit's `ExecStart`, environment and drop-ins, the running agent's
  argv, the overlays in `/etc/northnarrow` with their hashes, the hash of
  `fim-paths.v1`, detect-only and the posture at the start; every
  parameter of the method.
- **Duration**: about 7.5 minutes on the Ubuntu 24.04 guest, plus the
  sync and the incremental install of `--fresh`. `--quick` (3 passes, 1/20
  of the iterations, short windows, one cold start) checks the whole path
  in about 3 minutes and is never a baseline (the gate says so).

### 2.3 Output

`nn-lab.sh perf` fetches `perf.json` and `perf.md` into
`$LAB_DIR/reports/perf-<stamp>.{json,md}` (the guest keeps them, with
`raw.jsonl` and `env.json`, in `/var/lib/nn-perf/<stamp>/`). The JSON
(schema `northnarrow-perf/1`): `host`, `tree`, `build`, `agent`,
`method`; `metrics.<name>` with `unit`, `better` (lower or higher), `kind`
(ratio, or count: one total per run), `gate`, `samples` (every measured
sample) and their `n`, `median`, `p05`, `p95`, `min`, `max`, `mean`,
`noise_pct`; `derived.overhead`; `counters` (drops by ring, the status
before and after, the generator); `notes`; `status` (`complete`, or
`partial` with `failed_metrics`, exit 1).

Quantiles interpolate linearly between closest ranks (Hyndman–Fan type 7);
the noise of a series is (p95 − p5) / 2 as a share of its median, defined
from three samples up. The gate computes both from the samples again.

### 2.4 The gate

```bash
cargo xtask perf-compare BASE.json NEW.json [--thresholds FILE | --no-thresholds] \
    [--threshold 10] [--metric-threshold NAME=PCT]… [--abs-floor NAME=VALUE]… \
    [--noise-floor 1] [--allow-host-mismatch]
```

It prints every metric (base median, new median, the change in percent
with positive = worse, the noise, the limit, the verdict) and exits

- **0** — no gated metric regressed and none is missing;
- **1** — a gated metric regressed, or the base measured it and the new
  run did not;
- **2** — unreadable input, another schema, a misspelt metric in an
  option, or runs from different hosts (kernel, CPU model, vCPUs, memory,
  virtualisation, clocksource) without `--allow-host-mismatch`.

A gated metric regresses when its new median is worse than the base median

1. by more than its threshold — the committed one,
   `deploy/lab/perf/thresholds.tsv` (one reasoned line per gated metric,
   set from the baseline's A/A check, §2.5; `--thresholds FILE` for
   another file, `--no-thresholds` for none), else `--threshold` (10 %);
   `--metric-threshold NAME=PCT` overrides one;
2. and by more than the noise — the larger of the two runs' noise, never
   less than the noise floor (`--noise-floor`, 1 %): a change the
   repetitions themselves spread over is not a regression ("within noise");
3. and by more than its absolute floor, in its own unit — the
   measurement's resolution, below which a relative change says nothing
   (the thresholds file's floor, else the built-in one below;
   `--abs-floor NAME=VALUE` overrides one):

| metric | built-in floor |
|---|---|
| `agent_cpu_idle_pct` | 0.5 (percentage points; 10 ms ticks over 10 s) |
| `agent_cpu_load_pct` | 2.0 |
| `agent_rss_idle_kib` | 2048 |
| `agent_rss_load_kib`, `agent_rss_after_load_kib` | 4096 |
| `event_to_record_ms` | 1.0 |
| `event_to_disk_ms` | 2.0 (the polling) |
| `boot_to_ready_ms` | 100 |
| everything else | 0 |

The loss counters are one total per run: no noise, a floor of 0 (the
design target is no loss, review 45), so from 0 any loss fails. The same
rule, the other way, reports an improvement. Metrics that are not gated
are printed and never fail; an agent-off reference that moved beyond its
limit is a warning (the host or the kernel moved under the comparison). A
difference in the method (passes, scale, windows, `--quick`) is noted.

An A/A check (§2.5) shows how much a metric moves between runs of the same
tree on the same guest; the committed thresholds sit above that with a
margin: at least 10 %, twice the move and five points above it, the move
of a workload's agent-off reference counted too
([`validation/PERF_BASELINE.md`](validation/PERF_BASELINE.md) §5).

### 2.5 Taking a baseline, gating a lot

1. On a host as idle as it gets, with the guest up: `nn-lab.sh perf
   --fresh` on the base tree (`main`, or a lot whose build inputs are
   `main`'s: the JSON records `tree.build_inputs_changed`), three times.
2. Commit one run as
   `docs/validation/results/perf-<YYYY-MM-DD>-<guest>-<commit7>.json` and
   `.md`, the others as its A/A partners `…-aa.json`, `…-aa2.json`; set
   each gated metric's line in `deploy/lab/perf/thresholds.tsv` by the
   rule above, with its A/A move as the reason; the A/A result goes in the
   commit message. `xtask/tests/perf_baseline.rs` checks that the
   baseline passes against every partner and that each threshold keeps
   its margin.
3. For a lot: `nn-lab.sh perf --fresh` on its branch, then `cargo xtask
   perf-compare <baseline>.json <new>.json`; the `result:` line goes in
   the pull request. A regression is fixed, or accepted in the pull
   request with the reason and the per-metric threshold that lets it
   through. A lot that moves the figures on purpose commits a new
   baseline.
4. A kernel change on the guest makes the gate refuse (exit 2): take a new
   baseline of the base tree on the new kernel, with its A/A check.

### 2.6 Limits

- A lab guest is nested (QEMU/KVM in WSL2, or QEMU for Windows with WHPX):
  the host's vCPU threads are not pinned, and another guest's load is
  noise the off/on alternation cannot cancel. The agent-off reference
  shows a host that moved; the gate warns about it.
- The workloads are worst cases: every operation is a hooked one. A real
  service loses far less than the overhead column says.
- One result is one guest, one kernel, one build. It says nothing about
  another distribution, kernel or bare-metal host until a result file for
  it exists.
- The latency probe follows one path: the file-open sensor, the FIM rule,
  the detection store. The exec, network and DNS rules have no latency
  probe yet.
- The burst rates are the generator's targets; the iterations it completed
  are recorded.
