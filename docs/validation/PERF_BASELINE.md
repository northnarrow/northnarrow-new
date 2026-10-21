# Performance baseline: how to read it (lab PR 228)

The committed baseline of the agent's cost, the A/A check its thresholds
rest on, and how to read a comparison against it. The method — what each
metric is, how a run stops and starts the agent, what the gate computes — is
[`../PERFORMANCE.md`](../PERFORMANCE.md) §2; this file is about the numbers.

## 1. The files

| file | what it is |
|---|---|
| `results/perf-2026-10-21-ubuntu2404-40fd666.json` | the baseline: one full run (`nn-lab.sh perf --fresh`), every raw sample, the host, the tree, the method |
| `results/perf-2026-10-21-ubuntu2404-40fd666.md` | its summary, as the run wrote it |
| `results/perf-2026-10-21-ubuntu2404-40fd666-aa.json`, `-aa2.json` | the A/A partners: two more full runs of the same tree on the same guest, just before (A) and after (C) the baseline (B) |
| `../../deploy/lab/perf/thresholds.tsv` | the gate's threshold and floor for each gated metric, with its reason |

A baseline is named `perf-<date>-<guest>-<commit7>`: the day of the run, the
lab guest, the commit the run recorded (`tree.commit`).

## 2. What was measured

| | |
|---|---|
| guest | `ubuntu2404` (Ubuntu 24.04.5 LTS), kernel 6.8.0-147-generic, `lsm=…,bpf` |
| hardware | 4 vCPU of an AMD Ryzen 9 3900XT, 7.8 GiB (8,131,764 KiB), QEMU for Windows with WHPX (`systemd-detect-virt`: `microsoft`), clocksource `hyperv_clocksource_tsc_page` |
| agent | built from `main` 8180540: the run's tree `40fd666` is this lot's working commit, branch point 8180540 on `origin/main`, **no build input changed** (`tree.build_inputs_changed: none` — the agent, eBPF, common, watchdog, scanner, lockfile, toolchain, `configs/`, `install.sh`, the units); features `test-privileged,debug-trigger` (the lab build), thin LTO; agent sha256 `93308a27…`, the same in both runs |
| configuration | the installed defaults: no overlay, enforcing (not detect-only), posture OBSERVING at the start |
| date | 2026-10-21, 21:19 UTC (A/A partner 21:11 and 21:27 UTC) |
| method | 10 measured passes after 1 warm-up per workload and phase, workloads pinned to vCPU 3, scale 1, idle 60 s, burst 60 s at 200 execs, 100 file cycles, 20 HTTP requests, 200 UDP datagrams and 5 DNS lookups per second, 20 latency probes, 5 cold starts; about 7.5 minutes |

The JSON records all of it (`host`, `tree`, `build`, `agent`, `method`): a
comparison on another host is refused (exit 2), a different method is noted.

## 3. The baseline

Hooked operations, ns per operation, medians of 10 passes:

| workload | agent off | agent on | overhead | noise (on) |
|---|---|---|---|---|
| `getppid` (no hook: the control) | 176.1 | 175.7 | −0.3 % | 3.3 % |
| `read` 64 B of `/dev/zero` | 326.7 | 448.5 | +37.3 % | 2.0 % |
| open + read + close, unwatched | 3,706 | 5,149 | +38.9 % | 2.9 % |
| open + read + close, FIM-watched | 3,794 | 5,717 | +50.7 % | 2.1 % |
| open for write + 4 KiB + close | 4,527 | 6,538 | +44.4 % | 1.6 % |
| fork + exec `/bin/true` + wait | 795,868 | 879,135 | +10.5 % | 1.2 % |
| TCP connect + accept + close | 42,076 | 59,113 | +40.5 % | 7.9 % |
| UDP send 64 B | 3,730 | 4,753 | +27.4 % | 2.4 % |
| DNS query sent (nobody listens) | 4,967 | 6,063 | +22.1 % | 5.1 % |
| DNS query to the resolver, answer awaited | 92,464 | 98,136 | +6.1 % | 2.0 % |

The workloads are worst cases: every operation is a hooked one, in a tight
loop. A watched file costs about 11 % more to open than an unwatched one
(5,717 against 5,149 ns): the FIM watch itself.

The rest:

| metric | median | p95 | n |
|---|---|---|---|
| a credential read → its signed record's `ts` (`event_to_record_ms`) | 0.23 ms | 0.41 ms | 20 |
| the same read → the record's line on disk (`event_to_disk_ms`, 2 ms polling) | 2.50 ms | 2.61 ms | 20 |
| agent CPU, idle (`agent_cpu_idle_pct`) | 0.20 % of one CPU | 0.35 % | 6 windows of 10 s |
| agent CPU under the burst (`agent_cpu_load_pct`) | 7.40 % | 7.88 % | 6 |
| agent RSS, idle | 34,352 KiB | 34,396 KiB | 61 |
| agent RSS under the burst | 44,008 KiB | 46,920 KiB | 61 |
| agent RSS after the burst (not gated) | 47,512 KiB | 47,948 KiB | 66 |
| ring drops, rejected records, pending connects evicted, sockets forgotten during the burst | 0, 0, 0, 0 | | one total each |
| process creations per second during the burst (`burst_forks_per_s`, not gated) | 455.2 /s | 455.3 /s | 6 |
| generator iterations completed (not gated) | 60 in 60 s | | |
| cold start → READY (`boot_to_ready_ms`) | 4,506 ms | 4,575 ms | 6 |

## 4. The A/A check

Three full runs of the same tree on the same guest, one after the other:
A (21:11 UTC), B (21:19 UTC, the baseline) and C (21:27 UTC). The guest
runs on a workstation shared with other jobs: during the agent-off phase of
A and of C another job's test suite ran on the host (a test binary at
10–17 cores), which is what the lab's real conditions are. For each metric,
the A/A move is the largest change of its median between two of the three
runs, in percent of the smaller of the two; for a workload, also of its agent-off
reference (what the host alone moved, which the agent-on figure of a later
run will move with):

| metric | A | B (baseline) | C | A/A move | agent-off move | overhead A / B / C | threshold | floor |
|---|---|---|---|---|---|---|---|---|
| `syscall_getppid_ns` (ns/op) | 179 | 176 | 179 | 1.7 % | 3.3 % | -1.1 % / -0.3 % / -1.9 % | 10 % | 0 |
| `syscall_read_devzero_ns` (ns/op) | 456 | 449 | 454 | 1.6 % | 2.1 % | +36.6 % / +37.3 % / +36.1 % | 10 % | 0 |
| `open_unwatched_ns` (ns/op) | 5,146 | 5,149 | 5,150 | 0.1 % | 0.3 % | +39.0 % / +38.9 % / +38.7 % | 10 % | 0 |
| `open_watched_ns` (ns/op) | 5,738 | 5,717 | 5,718 | 0.4 % | 3.8 % | +45.6 % / +50.7 % / +47.2 % | 10 % | 0 |
| `write_open_ns` (ns/op) | 6,592 | 6,538 | 6,514 | 1.2 % | 2.8 % | +41.6 % / +44.4 % / +40.5 % | 10 % | 0 |
| `exec_true_ns` (ns/op) | 903,342 | 879,135 | 898,877 | 2.8 % | 8.6 % | +4.5 % / +10.5 % / +8.4 % | 20 % | 0 |
| `tcp_connect_close_ns` (ns/op) | 60,827 | 59,113 | 68,178 | 15.3 % | 4.0 % | +43.2 % / +40.5 % / +67.0 % | 35 % | 0 |
| `udp_send_ns` (ns/op) | 4,764 | 4,753 | 4,720 | 0.9 % | 4.7 % | +22.0 % / +27.4 % / +21.1 % | 10 % | 0 |
| `dns_send_ns` (ns/op) | 6,162 | 6,063 | 6,137 | 1.6 % | 3.6 % | +20.2 % / +22.1 % / +19.3 % | 10 % | 0 |
| `dns_resolver_query_ns` (ns/op) | 99,123 | 98,136 | 101,023 | 2.9 % | 7.5 % | -0.3 % / +6.1 % / +2.2 % | 20 % | 0 |
| `event_to_record_ms` (ms) | 0.23 | 0.23 | 0.24 | 7.5 % | — | — | 20 % | 1 |
| `event_to_disk_ms` (ms) | 2.51 | 2.50 | 2.57 | 2.7 % | — | — | 10 % | 2 |
| `agent_cpu_idle_pct` (% of one CPU) | 0.25 | 0.20 | 0.20 | 25.0 % | — | — | 50 % | 0.5 |
| `agent_cpu_load_pct` (% of one CPU) | 8.85 | 7.40 | 7.70 | 19.6 % | — | — | 40 % | 2 |
| `agent_rss_idle_kib` (KiB) | 35,160 | 34,352 | 35,196 | 2.5 % | — | — | 10 % | 2048 |
| `agent_rss_load_kib` (KiB) | 46,828 | 44,008 | 42,336 | 10.6 % | — | — | 25 % | 4096 |
| `burst_ring_drops` (events) | 0 | 0 | 0 | 0 in every run | — | — | 10 % | 0 |
| `burst_ring_rejected` (records) | 0 | 0 | 0 | 0 in every run | — | — | 10 % | 0 |
| `burst_netflow_pending_evicted` (connects) | 0 | 0 | 0 | 0 in every run | — | — | 10 % | 0 |
| `burst_flow_sock_forgotten` (sockets) | 0 | 0 | 0 | 0 in every run | — | — | 10 % | 0 |
| `burst_forks_per_s` (processes/s) | 454.75 | 455.20 | 455.20 | 0.1 % | — | — | not gated |  |
| `boot_to_ready_ms` (ms) | 4,505 | 4,506 | 4,501 | 0.1 % | — | — | 10 % | 100 |

`cargo xtask perf-compare` of the baseline (B) and its A/A partners with
the committed thresholds passes against both; against C, the partner that
moved most:

```
$ cargo xtask perf-compare results/perf-2026-10-21-ubuntu2404-40fd666.json \
      results/perf-2026-10-21-ubuntu2404-40fd666-aa2.json      # B against C
metric                           unit             base median     new median      delta    noise    limit  verdict
syscall_getppid_ns               ns/op                  175.7          178.5      +1.6%     3.3%    10.0%  ok
syscall_read_devzero_ns          ns/op                  448.5          453.5      +1.1%     3.0%    10.0%  ok
open_unwatched_ns                ns/op                 5148.6         5150.1      +0.0%     3.5%    10.0%  ok
open_watched_ns                  ns/op                 5717.3         5718.3      +0.0%     2.8%    10.0%  ok
write_open_ns                    ns/op                 6537.8         6514.2      -0.4%     4.3%    10.0%  ok
exec_true_ns                     ns/op               879134.6       898876.6      +2.2%     1.9%    20.0%  ok
tcp_connect_close_ns             ns/op                59113.1        68177.9     +15.3%     7.9%    35.0%  ok
udp_send_ns                      ns/op                 4753.4         4719.6      -0.7%     2.4%    10.0%  ok
dns_send_ns                      ns/op                 6063.3         6137.1      +1.2%     5.1%    10.0%  ok
dns_resolver_query_ns            ns/op                98135.7       101022.6      +2.9%     6.7%    20.0%  ok
event_to_record_ms               ms                    0.2300         0.2425      +5.4%    45.4%    45.4%  ok
event_to_disk_ms                 ms                     2.500          2.567      +2.7%    42.0%    42.0%  ok
agent_cpu_idle_pct               % of one CPU          0.2000         0.2000      +0.0%    62.5%    62.5%  ok
agent_cpu_load_pct               % of one CPU           7.400          7.700      +4.1%     8.1%    40.0%  ok
agent_rss_idle_kib               KiB                  34352.0        35196.0      +2.5%     1.7%    10.0%  ok
agent_rss_load_kib               KiB                  44008.0        42336.0      -3.8%     4.5%    25.0%  ok
burst_ring_drops                 events                0.0000         0.0000      +0.0%     1.0%    10.0%  ok
burst_ring_rejected              records               0.0000         0.0000      +0.0%     1.0%    10.0%  ok
burst_netflow_pending_evicted    connects              0.0000         0.0000      +0.0%     1.0%    10.0%  ok
burst_flow_sock_forgotten        sockets               0.0000         0.0000      +0.0%     1.0%    10.0%  ok
boot_to_ready_ms                 ms                    4505.9         4500.7      -0.1%     1.0%    10.0%  ok
(delta: positive = worse; the agent-off rows, not gated, all ok)
note: thresholds: deploy/lab/perf/thresholds.tsv (21 metrics)
result: 0 regression(s), 0 missing, 0 improved — PASS
```

## 5. The thresholds

`deploy/lab/perf/thresholds.tsv`, one line per gated metric: threshold in
percent worse, floor in the metric's unit, reason. The rule that set them:

- the threshold is at least 10 %, at least **twice** the metric's A/A move
  and at least **five points** above it, rounded up to a multiple of 5 —
  above the spread with a margin, so a run of the same tree does not flap;
- the floor is the measurement's resolution (CPU from 10 ms ticks over
  10 s windows, RSS that moves with the allocator, the disk latency polled
  every 2 ms, a boot that moves with the BPF load) — a change below it is
  never a regression, whatever its percentage;
- the loss counters have a floor of 0: the design target is no loss
  (review 45), so from 0 any loss fails.

The thresholds and floors are the last two columns of the table in §4; their
reasons, line by line, are in the file. In short: every workload 10 % except
fork + exec (20 %: its agent-off reference moved 8.6 %), the resolver query
(20 %: 7.5 % off) and TCP connect + close (35 %: its agent-on median moved
15.3 % between B and C, the noisiest workload on this host — 7–8 % within a
run); the signed-record latency 20 % (and a 1 ms floor that the 0.02 ms
moves are far below); the agent's CPU 50 % idle and 40 % under load (floors
0.5 and 2 points: the moves, 0.05 and 1.45 points, are within them); RSS
10 % idle and 25 % under load (floors 2 and 4 MiB); the boot 10 % (floor
100 ms); every loss counter floor 0.

On top of the threshold, the gate widens the limit of a metric to the noise
of the two runs ((p95 − p5) / 2 over the median, the larger of the two):
a change inside the repetitions' own spread is "within noise", not a
regression. `xtask/tests/perf_baseline.rs` holds the committed files to
this: the baseline and its A/A partner pass, every gated metric has a line,
and each threshold is twice that pair's move and five points above it
unless the move is within the floor.

## 6. Reading a comparison

```bash
deploy/lab/nn-lab.sh perf --fresh                 # the lot's tree, on the baseline's guest
cargo xtask perf-compare docs/validation/results/perf-2026-10-21-ubuntu2404-40fd666.json \
    ~/.cache/nn-lab/reports/perf-<stamp>.json
```

One row per metric: base median, new median, the change (positive =
worse), the noise, the limit (the threshold, or the noise when larger),
the verdict:

- `ok` — inside the threshold, or below the floor;
- `within noise` — beyond the threshold but inside the runs' noise: not a
  regression; rerun if the row matters;
- `REGRESSION` — beyond the threshold, the noise and the floor: exit 1;
- `improved` — the same the other way;
- `MISSING` — the baseline measured it and the run did not: exit 1;
- the agent-off rows are references: when one moved beyond its limit the
  output warns that the host or the kernel moved under the comparison.

A regression is fixed, or accepted in the pull request with its reason and
a per-metric threshold that lets it through (`--metric-threshold
NAME=PCT`), never by editing `thresholds.tsv` without a new A/A check. A lot
that moves the figures on purpose commits a new baseline. A kernel update
on the guest makes the gate refuse (exit 2): take a new baseline of the base
tree on the new kernel, with its A/A partner, and recompute the thresholds
by the rule above.

## 7. Limits

- One guest, one kernel, one build: nothing here says what the agent costs
  on another distribution, kernel or bare metal until a baseline exists
  there (each its own file: the gate refuses cross-host comparisons).
- The guest is nested on a shared workstation: the agent-off reference is
  how the gate tells a host that moved from an agent that did.
- The lab build has the `test-privileged` and `debug-trigger` features and
  thin LTO; a release build has neither feature and fat LTO.
- The latency probe follows one path (the file-open sensor, the FIM rule,
  the detection store); the exec, network and DNS rules have no latency
  probe yet.
