#!/usr/bin/env python3
# Measurement loops and report of the performance baseline (lab PR 228,
# deploy/lab/perf/perf-run.sh, docs/PERFORMANCE.md §2).
#
# Standard library only. perf-run.sh runs it as `python3 -I perf_lib.py …`
# as root on a lab guest; `assemble` and `--selftest` run anywhere (the
# xtask tests run both). Every measurement appends one JSON object per line
# to the raw file (RAW); `assemble` turns RAW and the environment record
# into perf.json (raw samples and their statistics) and perf.md.
#
#   micro    --raw RAW --phase off|on --round R --bench BIN --probe BIN
#            --workdir DIR --watched F,… --unwatched F,… --resolver IP
#            --reps N --warmup W --scale S [--cpu C] [--agent-pid P]
#            The hooked-operation workloads, interleaved: each pass runs
#            every workload once, W warm-up passes then N measured ones.
#   latency  --raw RAW --probe BIN --file F --det DETECTIONS --rule ID
#            --samples K --warmup W [--interval S] [--timeout S]
#            One probe read of F at a time; the probe's CLOCK_REALTIME
#            before the open against the `ts` of its signed record, and
#            against the moment the record's line is read back.
#   sample   --raw RAW --label L --pid P --secs S [--window S]
#            The agent's CPU (per window) and RSS (per second).
#   burst    --raw RAW --gen SCRIPT --gen-user U --secs S --windows N
#            --rates exec=…,file=…,tcp=…,udp=…,dns=… --pid P
#            --nn-admin BIN --key KEY [--drain S]
#            The soak generator at a high rate; signed status reads before,
#            at each window and after the drain.
#   status   --raw RAW --label L --nn-admin BIN --key KEY
#   held     --raw RAW --audit FILE --from-line N
#            The per-rule budget's signed `detections_held` counts since N.
#   emit     RAW TYPE key=value…   (one raw record from the shell)
#   envinfo  --env ENV --part off|on [--pid P] [--nn-admin BIN --key KEY]
#            [--set key=value …]   (host, tree, agent configuration)
#   assemble --raw RAW --env ENV --json OUT.json --md OUT.md
#   --selftest
import argparse
import calendar
import hashlib
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import time

SCHEMA = "northnarrow-perf/1"
DET_RULE = "NN-L-FIM-011_AwsCredsRead"

# The hooked-operation workloads: metric, tool, mode, iterations at scale 1,
# what one operation is. Order = interleaving order = report order.
MICRO = [
    ("syscall_getppid_ns", "bench", "getppid", 2_000_000,
     "getppid(2): the raw_syscalls enter/exit path and nothing else"),
    ("syscall_read_devzero_ns", "bench", "rdzero", 1_000_000,
     "read(2) of 64 bytes from /dev/zero"),
    ("open_unwatched_ns", "probe", "ropen-unwatched", 100_000,
     "open + read 64 B + close, copies of the watched files in an unwatched scratch directory"),
    ("open_watched_ns", "probe", "ropen-watched", 100_000,
     "open + read 64 B + close of FIM-watched files in /etc"),
    ("write_open_ns", "bench", "wopen", 25_000,
     "open(O_WRONLY) + pwrite 4 KiB + close of one file"),
    ("exec_true_ns", "bench", "exec", 1_000,
     "fork + execve(/bin/true) + waitpid"),
    ("tcp_connect_close_ns", "bench", "connect", 3_000,
     "TCP connect + accept + close on 127.0.0.1"),
    ("udp_send_ns", "bench", "udp", 100_000,
     "sendto() of 64 B to a local UDP socket"),
    ("dns_send_ns", "bench", "dns", 20_000,
     "sendto() of a DNS query to 127.0.0.1:53 (nobody listens)"),
    ("dns_resolver_query_ns", "probe", "dnsq", 2_000,
     "A query for localhost to the configured resolver, answer awaited"),
]
MICRO_NAMES = [m[0] for m in MICRO]

# metric -> unit, better, kind, gate, group, description. Off-phase copies
# of the MICRO metrics ("<name>_off") are added by `metric_meta`.
META = {
    "event_to_record_ms": ("ms", "lower", "ratio", True, "latency",
                           "probe read of a .aws/credentials fixture -> `ts` of its signed "
                           + DET_RULE + " record"),
    "event_to_disk_ms": ("ms", "lower", "ratio", True, "latency",
                         "the same read -> that record's line read back from detections.jsonl (2 ms polling)"),
    "agent_cpu_idle_pct": ("% of one CPU", "lower", "ratio", True, "resources",
                           "agent CPU, idle host, per window"),
    "agent_cpu_load_pct": ("% of one CPU", "lower", "ratio", True, "resources",
                           "agent CPU under the burst load, per window"),
    "agent_rss_idle_kib": ("KiB", "lower", "ratio", True, "resources",
                           "agent RSS, idle host, per second"),
    "agent_rss_load_kib": ("KiB", "lower", "ratio", True, "resources",
                           "agent RSS under the burst load, per second"),
    "agent_rss_after_load_kib": ("KiB", "lower", "ratio", False, "resources",
                                 "agent RSS after the burst (cool-down), per second"),
    "burst_ring_drops": ("events", "lower", "count", True, "loss",
                         "ring-buffer records dropped during the burst (all rings)"),
    "burst_ring_rejected": ("records", "lower", "count", True, "loss",
                            "malformed ring records rejected during the burst"),
    "burst_netflow_pending_evicted": ("connects", "lower", "count", True, "loss",
                                      "pending connects the flow tracker evicted at capacity"),
    "burst_flow_sock_forgotten": ("sockets", "lower", "count", True, "loss",
                                  "outbound sockets FLOW_SOCK_MAP forgot (at least)"),
    "burst_netflow_rows_skipped": ("rows", "lower", "count", False, "loss",
                                   "netflow rows held back from the rules by the per-uid pacing (by design)"),
    "burst_detections_held": ("detections", "lower", "count", False, "loss",
                              "detections acted on but not stored (per-rule budget, signed detections_held)"),
    "burst_generator_iterations": ("iterations", "higher", "count", False, "loss",
                                   "generator iterations completed (the load actually applied)"),
    "burst_forks_per_s": ("processes/s", "higher", "ratio", False, "loss",
                          "process creations per second on the guest during the burst, per window "
                          "(/proc/stat `processes`): the exec event rate the agent kept up with"),
    "boot_to_ready_ms": ("ms", "lower", "ratio", True, "boot",
                         "cold start (pin root purged): ExecMainStart -> READY=1 (ActiveEnter)"),
}


def metric_meta(name):
    if name in MICRO_NAMES:
        desc = MICRO[MICRO_NAMES.index(name)][4]
        return ("ns/op", "lower", "ratio", True, "micro", desc)
    if name.endswith("_off") and name[:-4] in MICRO_NAMES:
        desc = MICRO[MICRO_NAMES.index(name[:-4])][4]
        return ("ns/op", "lower", "ratio", False, "reference", desc + " (agent off)")
    return META[name]


def metric_order():
    names = list(MICRO_NAMES)
    names += ["event_to_record_ms", "event_to_disk_ms",
              "agent_cpu_idle_pct", "agent_cpu_load_pct",
              "agent_rss_idle_kib", "agent_rss_load_kib", "agent_rss_after_load_kib",
              "burst_ring_drops", "burst_ring_rejected", "burst_netflow_pending_evicted",
              "burst_flow_sock_forgotten", "burst_netflow_rows_skipped",
              "burst_detections_held", "burst_generator_iterations", "burst_forks_per_s",
              "boot_to_ready_ms"]
    names += [n + "_off" for n in MICRO_NAMES]
    return names


# ── statistics (the gate in xtask/src/perf_compare.rs uses the same) ─────

def quantile(xs, p):
    """Linear interpolation between closest ranks (Hyndman-Fan type 7)."""
    s = sorted(xs)
    if not s:
        return None
    h = (len(s) - 1) * p
    lo, hi = math.floor(h), math.ceil(h)
    return s[lo] + (h - lo) * (s[hi] - s[lo])


def summary(xs):
    if not xs:
        return {"n": 0, "median": None, "p05": None, "p95": None,
                "min": None, "max": None, "mean": None, "noise_pct": None}
    med = quantile(xs, 0.5)
    p05, p95 = quantile(xs, 0.05), quantile(xs, 0.95)
    noise = None
    if len(xs) >= 3 and med != 0:
        noise = 100.0 * (p95 - p05) / (2.0 * abs(med))
    r = lambda v: None if v is None else round(v, 4)
    return {"n": len(xs), "median": r(med), "p05": r(p05), "p95": r(p95),
            "min": r(min(xs)), "max": r(max(xs)), "mean": r(sum(xs) / len(xs)),
            "noise_pct": r(noise)}


# ── raw records ──────────────────────────────────────────────────────────

def emit(raw, rec):
    with open(raw, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def read_raw(raw):
    out = []
    with open(raw, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if isinstance(r, dict):
                out.append(r)
    return out


def typed(v):
    """A shell value: plain integers and decimals become numbers (not
    `1e5`, nor a commit id that happens to read as one), true/false/null
    their JSON values, anything else stays text."""
    if re.fullmatch(r"-?[0-9]+", v):
        return int(v)
    if re.fullmatch(r"-?[0-9]+\.[0-9]+", v):
        return float(v)
    if v in ("true", "false"):
        return v == "true"
    if v == "null":
        return None
    return v


def kv_pairs(items):
    out = {}
    for it in items:
        k, sep, v = it.partition("=")
        if not sep or not k:
            raise SystemExit("perf_lib: not key=value: %r" % it)
        out[k] = typed(v)
    return out


def log(msg):
    try:
        print("perf: " + msg, file=sys.stderr, flush=True)
    except OSError:  # a closed ssh connection: the run goes on
        pass


# ── /proc ────────────────────────────────────────────────────────────────

CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100


def stat_ticks(text):
    """utime + stime of a /proc/<pid>/stat line (the comm may hold spaces
    and parentheses: the fields are read after the last ')')."""
    rest = text[text.rindex(")") + 2:].split()
    return int(rest[11]) + int(rest[12])


def proc_sample(pid):
    try:
        with open("/proc/%d/stat" % pid, encoding="utf-8", errors="replace") as f:
            ticks = stat_ticks(f.read())
        rss = thr = None
        with open("/proc/%d/status" % pid, encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1])
                elif line.startswith("Threads:"):
                    thr = int(line.split()[1])
        return ticks, rss, thr
    except (OSError, ValueError, IndexError):
        return None


# ── micro ────────────────────────────────────────────────────────────────

def micro_command(a, tool, mode, iters):
    pin = []
    if a.cpu is not None and a.cpu != "none" and shutil.which("taskset"):
        pin = ["taskset", "-c", str(a.cpu)]
    if tool == "bench":
        return pin + [a.bench, mode, str(iters), a.workdir]
    if mode == "ropen-watched":
        return pin + [a.probe, "ropen", str(iters)] + a.watched.split(",")
    if mode == "ropen-unwatched":
        return pin + [a.probe, "ropen", str(iters)] + a.unwatched.split(",")
    if mode == "dnsq":
        return pin + [a.probe, "dnsq", str(iters), a.resolver]
    raise ValueError(mode)


def cmd_micro(a):
    skip = set(filter(None, (a.skip or "").split(",")))
    for p in range(a.warmup + a.reps):
        warm = p < a.warmup
        for name, tool, mode, base, _ in MICRO:
            if name in skip:
                continue
            if mode.startswith("ropen") and not (a.watched and a.unwatched):
                continue
            if mode == "dnsq" and not a.resolver:
                continue
            iters = max(10, int(base * a.scale))
            cmd = micro_command(a, tool, mode, iters)
            before = proc_sample(a.agent_pid) if a.agent_pid else None
            rec = {"t": "micro", "phase": a.phase, "round": a.round, "metric": name,
                   "pass": p, "warmup": warm, "iters": iters, "ok": False}
            try:
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                after = proc_sample(a.agent_pid) if a.agent_pid else None
                fields = out.stdout.split()
                if out.returncode == 0 and len(fields) >= 2:
                    ops = float(fields[-1])
                    rec.update(ok=ops > 0, ops_per_s=ops, ns_per_op=round(1e9 / ops, 4) if ops > 0 else None)
                else:
                    rec["err"] = (out.stderr.strip() or out.stdout.strip() or "exit %d" % out.returncode)[-300:]
                if before and after:
                    rec["agent_cpu_ms"] = round((after[0] - before[0]) * 1000.0 / CLK_TCK, 1)
            except (OSError, subprocess.SubprocessError, ValueError) as e:
                rec["err"] = str(e)[-300:]
            emit(a.raw, rec)
        log("micro %s round %d: pass %d/%d%s" % (a.phase, a.round, p + 1, a.warmup + a.reps,
                                                  " (warm-up)" if warm else ""))
    return 0


# ── latency ──────────────────────────────────────────────────────────────

def ts_ns(ts):
    """`2026-10-21T10:00:00.123456Z` (detection_store::now_ts) -> ns."""
    if not isinstance(ts, str) or not ts.endswith("Z"):
        return None
    base, _, frac = ts[:-1].partition(".")
    try:
        t = time.strptime(base, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
    frac = (frac + "000000000")[:9] if frac.isdigit() or frac == "" else None
    if frac is None:
        return None
    return calendar.timegm(t) * 1_000_000_000 + int(frac)


def find_record(lines, rule, pid):
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if isinstance(r, dict) and r.get("rule_id") == rule \
                and isinstance(r.get("principal"), dict) and r["principal"].get("pid") == pid:
            return r
    return None


def cmd_latency(a):
    for seq in range(a.warmup + a.samples):
        warm = seq < a.warmup
        rec = {"t": "latency", "seq": seq, "warmup": warm, "ok": False}
        try:
            pos = os.stat(a.det).st_size
        except OSError:
            pos = 0
        try:
            out = subprocess.run([a.probe, "credread", a.file], capture_output=True, text=True, timeout=10)
            t0_s, pid_s = out.stdout.split()[:2]
            t0, pid = int(t0_s), int(pid_s)
        except (OSError, subprocess.SubprocessError, ValueError) as e:
            rec["err"] = "probe: %s" % e
            emit(a.raw, rec)
            continue
        rec.update(t0_ns=t0, pid=pid)
        found, seen, buf = None, None, b""
        deadline = time.monotonic() + a.timeout
        while time.monotonic() < deadline and found is None:
            try:
                size = os.stat(a.det).st_size
                if size < pos:  # rotated: the new file from its start
                    pos, buf = 0, b""
                if size > pos:
                    with open(a.det, "rb") as f:
                        f.seek(pos)
                        data = f.read(size - pos)
                    pos += len(data)
                    buf += data
                    lines = buf.split(b"\n")
                    buf = lines.pop()  # an unterminated line is still being written
                    found = find_record(lines, a.rule, pid)
                    if found is not None:
                        seen = time.time_ns()
                        break
            except OSError:
                pass
            time.sleep(0.002)
        if found is None:
            rec["err"] = "no %s record for pid %d within %.0f s" % (a.rule, pid, a.timeout)
        else:
            rts = ts_ns(found.get("ts"))
            rec.update(ok=rts is not None, record_id=found.get("id"), record_ts=found.get("ts"),
                       signed=bool(found.get("agent_sig")), response=found.get("response"),
                       lat_record_ms=None if rts is None else round((rts - t0) / 1e6, 3),
                       lat_disk_ms=round((seen - t0) / 1e6, 3))
        emit(a.raw, rec)
        time.sleep(a.interval)
    return 0


# ── agent CPU / RSS sampling ─────────────────────────────────────────────

class Sampler:
    def __init__(self, raw, label, pid, window):
        self.raw, self.label, self.pid, self.window = raw, label, pid, window
        self.sec = 0
        self.w = 0
        self.w_start = None

    def tick(self):
        """One per-second sample; closes a CPU window every `window` samples."""
        now = time.monotonic()
        s = proc_sample(self.pid)
        if s is None:
            emit(self.raw, {"t": "sample", "label": self.label, "sec": self.sec, "ok": False,
                            "err": "pid %d gone" % self.pid})
            self.sec += 1
            return
        ticks, rss, thr = s
        emit(self.raw, {"t": "sample", "label": self.label, "sec": self.sec, "ok": True,
                        "ticks": ticks, "rss_kib": rss, "threads": thr})
        if self.w_start is None:
            self.w_start = (now, ticks)
        elif self.sec % self.window == 0:
            t0, k0 = self.w_start
            if now > t0:
                emit(self.raw, {"t": "cpu_window", "label": self.label, "window": self.w,
                                "secs": round(now - t0, 3),
                                "cpu_pct": round((ticks - k0) * 100.0 / CLK_TCK / (now - t0), 3)})
            self.w += 1
            self.w_start = (now, ticks)
        self.sec += 1


def run_for(secs, every, fn):
    """fn() every `every` seconds for `secs` seconds (drift-free)."""
    start = time.monotonic()
    n = 0
    while True:
        fn(n)
        n += 1
        nxt = start + n * every
        if nxt - start > secs + 1e-9:
            break
        delay = nxt - time.monotonic()
        if delay > 0:
            time.sleep(delay)


def cmd_sample(a):
    s = Sampler(a.raw, a.label, a.pid, a.window)
    run_for(a.secs, 1.0, lambda _n: s.tick())
    return 0


# ── signed status reads ──────────────────────────────────────────────────

def read_status(nn_admin, key, net=False):
    cmd = [nn_admin] + (["net", "status"] if net else ["status"]) + ["--key", key, "--json"]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as e:
        return None, str(e)
    for line in reversed(out.stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line), None
            except ValueError:
                break
    return None, (out.stderr.strip() or "exit %d, no JSON" % out.returncode)[-300:]


def status_record(raw, label, nn_admin, key):
    st, err = read_status(nn_admin, key)
    net, nerr = read_status(nn_admin, key, net=True)
    emit(raw, {"t": "status", "label": label, "status": st, "net": net,
               "err": err, "net_err": nerr, "mono": round(time.monotonic(), 3)})


def cmd_status(a):
    status_record(a.raw, a.label, a.nn_admin, a.key)
    return 0


# ── burst ────────────────────────────────────────────────────────────────

RATE_ENV = {"exec": "SOAK_EXEC_PER_S", "file": "SOAK_FILE_PER_S", "tcp": "SOAK_TCP_PER_S",
            "udp": "SOAK_UDP_PER_S", "dns": "SOAK_DNS_PER_S"}


def parse_rates(text):
    rates = {}
    for part in filter(None, text.split(",")):
        k, _, v = part.partition("=")
        if k not in RATE_ENV or not v.isdigit():
            raise SystemExit("perf_lib: --rates takes exec=,file=,tcp=,udp=,dns= (integers): %r" % part)
        rates[k] = int(v)
    return rates


def read_forks():
    """Processes created since boot (/proc/stat `processes`)."""
    for line in (read_text("/proc/stat") or "").splitlines():
        if line.startswith("processes "):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return None
    return None


def as_user(user, *cmd):
    return subprocess.run(["runuser", "-u", user, "--"] + list(cmd), capture_output=True, text=True, timeout=30)


def read_small_int(path):
    """An integer the generator wrote, read without following a link."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            return int(os.read(fd, 32).decode().strip())
        finally:
            os.close(fd)
    except (OSError, ValueError):
        return None


def cmd_burst(a):
    rates = parse_rates(a.rates)
    mk = as_user(a.gen_user, "mktemp", "-d", "/var/tmp/nn-perf-gen.XXXXXXXX")
    gdir = mk.stdout.strip()
    st = os.lstat(gdir) if gdir.startswith("/var/tmp/nn-perf-gen.") else None
    import pwd
    if st is None or not os.path.isdir(gdir) or os.path.islink(gdir) or st.st_uid != pwd.getpwnam(a.gen_user).pw_uid:
        emit(a.raw, {"t": "gen", "ok": False, "err": "generator directory: %s" % (mk.stderr.strip() or gdir)})
        return 1
    env = ["SOAK_DIR=%s" % gdir, "SOAK_SCRATCH=%s/scratch" % gdir,
           "SOAK_HTTP_PORT=%d" % a.http_port, "SOAK_UDP_PORT=%d" % (a.http_port + 1)]
    env += ["%s=%d" % (RATE_ENV[k], v) for k, v in sorted(rates.items())]
    status_record(a.raw, "burst_before", a.nn_admin, a.key)
    log("burst: %d s at %s as %s" % (a.secs, a.rates, a.gen_user))
    gen = subprocess.Popen(["runuser", "-u", a.gen_user, "--", "env"] + env + ["bash", a.gen],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, start_new_session=True)
    s = Sampler(a.raw, "load", a.pid, max(1, a.secs // a.windows))
    every = max(1, a.secs // a.windows)
    forks = [time.monotonic(), read_forks()]

    def step(n):
        s.tick()
        if n and n % every == 0:
            now, count = time.monotonic(), read_forks()
            if count is not None and forks[1] is not None and now > forks[0]:
                emit(a.raw, {"t": "fork_window", "label": "load", "window": n // every,
                             "secs": round(now - forks[0], 3),
                             "forks_per_s": round((count - forks[1]) / (now - forks[0]), 3)})
            forks[0], forks[1] = now, count
            status_record(a.raw, "burst_w%d" % (n // every), a.nn_admin, a.key)
    try:
        try:
            run_for(a.secs, 1.0, step)
        finally:
            # also when the run is interrupted (SIGTERM from perf-run.sh): no
            # load generator is left behind
            stop_generator(gen, gdir, a.gen_user)
        iters = read_small_int(gdir + "/generate.iter")
        time.sleep(a.drain)
        status_record(a.raw, "burst_after", a.nn_admin, a.key)
    finally:
        as_user(a.gen_user, "rm", "-rf", "--", gdir)
    emit(a.raw, {"t": "gen", "ok": iters is not None, "iterations": iters, "rates": rates,
                 "secs": a.secs, "user": a.gen_user, "exit": gen.returncode})
    return 0


def stop_generator(gen, gdir, user):
    """The generator's own stop file first (it stops its listeners), then its
    process group."""
    try:
        as_user(user, "touch", gdir + "/stop")
    except (OSError, subprocess.SubprocessError):
        pass
    for sig, grace in ((None, 30), (signal.SIGTERM, 10), (signal.SIGKILL, 10)):
        if sig is not None:
            try:
                os.killpg(gen.pid, sig)
            except OSError:
                pass
        try:
            gen.wait(timeout=grace)
            break
        except subprocess.TimeoutExpired:
            continue
    # its listeners, if the generator itself is gone before its EXIT trap
    try:
        os.killpg(gen.pid, signal.SIGTERM)
    except OSError:
        pass


# ── held detections ──────────────────────────────────────────────────────

def held_total(lines):
    total, entries = 0, 0
    for line in lines:
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if not isinstance(r, dict) or r.get("op") != "detections_held":
            continue
        extra = r.get("extra") if isinstance(r.get("extra"), dict) else {}
        for h in extra.get("held") or []:
            if isinstance(h, dict) and isinstance(h.get("count"), int):
                total += h["count"]
        entries += 1
    return total, entries


def cmd_held(a):
    try:
        with open(a.audit, "rb") as f:
            lines = f.read().split(b"\n")
    except OSError as e:
        emit(a.raw, {"t": "held", "ok": False, "err": str(e)})
        return 0
    if len(lines) - 1 < a.from_line:  # rotated or truncated since
        emit(a.raw, {"t": "held", "ok": False, "err": "audit log shorter than at the start of the burst"})
        return 0
    total, entries = held_total(lines[a.from_line:])
    emit(a.raw, {"t": "held", "ok": True, "count": total, "entries": entries})
    return 0


# ── environment ──────────────────────────────────────────────────────────

def read_text(path, limit=1 << 20):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return None


def sha256_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def run_text(cmd):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        return out.stdout.strip() if out.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def unit_exe(unit):
    es = run_text(["systemctl", "show", "-p", "ExecStart", "--value", unit]) or ""
    for word in es.split():
        if word.startswith("path="):
            return word[5:].rstrip(";")
    return None


def host_info():
    cpu = None
    for line in (read_text("/proc/cpuinfo") or "").splitlines():
        if line.startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
    mem = None
    for line in (read_text("/proc/meminfo") or "").splitlines():
        if line.startswith("MemTotal:"):
            mem = int(line.split()[1])
    osname = None
    for line in (read_text("/etc/os-release") or "").splitlines():
        if line.startswith("PRETTY_NAME="):
            osname = line.split("=", 1)[1].strip().strip('"')
    try:
        vcpus = len(os.sched_getaffinity(0))
    except (AttributeError, OSError):
        vcpus = os.cpu_count()
    loginuid = (read_text("/proc/self/loginuid") or "").strip()
    return {
        "kernel": os.uname().release,
        "os": osname,
        "cpu_model": cpu,
        "vcpus": vcpus,
        "mem_total_kib": mem,
        "virt": run_text(["systemd-detect-virt"]) or "none",
        "clocksource": (read_text("/sys/devices/system/clocksource/clocksource0/current_clocksource") or "").strip() or None,
        "cmdline": (read_text("/proc/cmdline") or "").strip(),
        "loginuid_set": loginuid not in ("", "4294967295"),
    }


def agent_off_info():
    agent = unit_exe("northnarrow-agent.service")
    wd = unit_exe("northnarrow-watchdog.service")
    nn_admin = os.path.join(os.path.dirname(agent), "nn-admin") if agent else None
    overlays = {}
    try:
        for name in sorted(os.listdir("/etc/northnarrow")):
            if name.endswith(".local") or name.endswith(".local.sig"):
                overlays[name] = sha256_file(os.path.join("/etc/northnarrow", name))
    except OSError:
        pass
    show = run_text(["systemctl", "show", "-p", "ExecStart", "-p", "Environment", "-p", "EnvironmentFiles",
                     "-p", "DropInPaths", "-p", "FragmentPath", "northnarrow-agent.service"]) or ""
    unit = {}
    for line in show.splitlines():
        k, _, v = line.partition("=")
        unit[k] = v
    return {
        "binaries": {
            "agent": {"path": agent, "sha256": sha256_file(agent) if agent else None},
            "watchdog": {"path": wd, "sha256": sha256_file(wd) if wd else None},
            "nn_admin": {"path": nn_admin, "sha256": sha256_file(nn_admin) if nn_admin else None},
        },
        "unit": unit,
        "overlays": overlays,
        "fim_paths_v1_sha256": sha256_file("/etc/northnarrow/fim-paths.v1"),
    }


def cmd_envinfo(a):
    env = {}
    if os.path.exists(a.env):
        with open(a.env, encoding="utf-8") as f:
            env = json.load(f)
    if a.part == "off":
        env["host"] = host_info()
        env["agent_files"] = agent_off_info()
    else:
        on = {}
        if a.pid:
            raw = read_text("/proc/%d/cmdline" % a.pid) or ""
            on["argv"] = [w for w in raw.split("\0") if w]
        if a.nn_admin and a.key:
            st, err = read_status(a.nn_admin, a.key)
            on["status_at_start"] = st
            if err:
                on["status_err"] = err
        env["agent_running"] = on
    sets = kv_pairs(a.set or [])
    for k, v in sets.items():
        section, _, key = k.partition(".")
        if key:
            env.setdefault(section, {})[key] = v
        else:
            env[k] = v
    tmp = a.env + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(env, f, indent=1, sort_keys=True)
    os.replace(tmp, a.env)
    return 0


# ── assemble ─────────────────────────────────────────────────────────────

def counter_delta(before, after, key):
    if not isinstance(before, dict) or not isinstance(after, dict):
        return None
    b, c = before.get(key), after.get(key)
    if isinstance(b, (int, float)) and isinstance(c, (int, float)):
        return c - b
    return None


def build(raw_records, env):
    samples = {n: [] for n in metric_order()}
    errors = {}
    notes = []

    def err(name, text):
        errors.setdefault(name, [])
        if text not in errors[name] and len(errors[name]) < 5:
            errors[name].append(text)

    agent_cpu = {}
    for r in raw_records:
        t = r.get("t")
        if t == "micro" and r.get("metric") in MICRO_NAMES:
            name = r["metric"] + ("_off" if r.get("phase") == "off" else "")
            if r.get("warmup"):
                continue
            if r.get("ok") and isinstance(r.get("ns_per_op"), (int, float)):
                samples[name].append(r["ns_per_op"])
                if r.get("phase") == "on" and isinstance(r.get("agent_cpu_ms"), (int, float)):
                    agent_cpu.setdefault(r["metric"], []).append((r["agent_cpu_ms"], r.get("iters")))
            else:
                err(name, r.get("err") or "failed")
        elif t == "latency" and not r.get("warmup"):
            if r.get("ok"):
                samples["event_to_record_ms"].append(r["lat_record_ms"])
                samples["event_to_disk_ms"].append(r["lat_disk_ms"])
                if not r.get("signed"):
                    notes.append("latency probe %s: the record carries no agent_sig" % r.get("seq"))
            else:
                err("event_to_record_ms", r.get("err") or "failed")
                err("event_to_disk_ms", r.get("err") or "failed")
        elif t == "fork_window" and r.get("label") == "load":
            if isinstance(r.get("forks_per_s"), (int, float)):
                samples["burst_forks_per_s"].append(r["forks_per_s"])
        elif t == "cpu_window":
            name = {"idle": "agent_cpu_idle_pct", "load": "agent_cpu_load_pct"}.get(r.get("label"))
            if name:
                samples[name].append(r["cpu_pct"])
        elif t == "sample":
            name = {"idle": "agent_rss_idle_kib", "load": "agent_rss_load_kib",
                    "after": "agent_rss_after_load_kib"}.get(r.get("label"))
            if name and r.get("ok") and isinstance(r.get("rss_kib"), int):
                samples[name].append(r["rss_kib"])
            elif name:
                err(name, r.get("err") or "no sample")
        elif t == "boot":
            if isinstance(r.get("boot_ms"), (int, float)):
                samples["boot_to_ready_ms"].append(r["boot_ms"])
                if not r.get("health"):
                    notes.append("boot %s: no `all LSM hooks attached` line from the agent" % r.get("label"))
            else:
                err("boot_to_ready_ms", r.get("err") or "no boot time")
        elif t == "note":
            notes.append(str(r.get("text")))

    status = {r.get("label"): r for r in raw_records if r.get("t") == "status"}
    before, after = status.get("burst_before"), status.get("burst_after")
    counters = {}
    if before and after:
        sb, sa = before.get("status"), after.get("status")
        nb, na = before.get("net"), after.get("net")
        pairs = [
            ("burst_ring_drops", sb, sa, "ringbuf_drops_total"),
            ("burst_ring_rejected", sb, sa, "ringbuf_rejected_total"),
            ("burst_netflow_pending_evicted", nb, na, "netflow_pending_evicted_total"),
            ("burst_flow_sock_forgotten", nb, na, "flow_sock_forgotten_min"),
            ("burst_netflow_rows_skipped", nb, na, "netflow_rows_skipped_total"),
        ]
        for name, b, c, key in pairs:
            d = counter_delta(b, c, key)
            if d is None:
                err(name, "%s not read signed before and after the burst (%s)"
                    % (key, before.get("err") or after.get("err") or before.get("net_err")
                       or after.get("net_err") or "field absent"))
            else:
                samples[name].append(d)
        per_ring = {}
        for src in ("status", "net"):
            b = (before.get(src) or {}).get("ringbuf_drops") if isinstance(before.get(src), dict) else None
            c = (after.get(src) or {}).get("ringbuf_drops") if isinstance(after.get(src), dict) else None
            if isinstance(b, dict) and isinstance(c, dict):
                for ring, v in c.items():
                    if isinstance(v, int):
                        per_ring[ring] = v - (b.get(ring) if isinstance(b.get(ring), int) else 0)
        counters["ring_drops_by_ring"] = per_ring
        counters["status_before"] = sb
        counters["status_after"] = sa
        counters["windows"] = [
            {"label": k, "ringbuf_drops_total": (v.get("status") or {}).get("ringbuf_drops_total")
             if isinstance(v.get("status"), dict) else None}
            for k, v in sorted(status.items()) if k and k.startswith("burst_w")]
    elif any(r.get("t") == "gen" for r in raw_records):
        for name in ("burst_ring_drops", "burst_ring_rejected", "burst_netflow_pending_evicted",
                     "burst_flow_sock_forgotten", "burst_netflow_rows_skipped"):
            err(name, "no status read before and after the burst")
    for r in raw_records:
        if r.get("t") == "held":
            if r.get("ok"):
                samples["burst_detections_held"].append(r["count"])
            else:
                err("burst_detections_held", r.get("err") or "failed")
        elif r.get("t") == "gen":
            counters["generator"] = {k: r.get(k) for k in ("rates", "secs", "user", "iterations", "exit")}
            if r.get("ok"):
                samples["burst_generator_iterations"].append(r["iterations"])
            else:
                err("burst_generator_iterations", r.get("err") or "no iteration count")

    metrics = {}
    for i, name in enumerate(metric_order()):
        unit, better, kind, gate, group, desc = metric_meta(name)
        xs = samples[name]
        if not xs and name not in errors:
            continue  # not run (skipped)
        m = {"order": i, "unit": unit, "better": better, "kind": kind, "gate": gate,
             "group": group, "description": desc, "samples": xs}
        m.update(summary(xs))
        if name in errors:
            m["errors"] = errors[name]
        metrics[name] = m

    derived = {}
    for name in MICRO_NAMES:
        on, off = metrics.get(name), metrics.get(name + "_off")
        if on and off and on.get("median") and off.get("median"):
            d = {"off_median_ns": off["median"], "on_median_ns": on["median"],
                 "overhead_pct": round(100.0 * (on["median"] - off["median"]) / off["median"], 2)}
            cpu = agent_cpu.get(name)
            if cpu:
                per_op = [ms * 1e6 / it for ms, it in cpu if it]
                d["agent_cpu_ns_per_op_median"] = round(quantile(per_op, 0.5), 2) if per_op else None
            derived[name] = d

    gated = [n for n, m in metrics.items() if m["gate"]]
    failed = sorted(n for n in gated if metrics[n]["n"] == 0)
    doc = {
        "schema": SCHEMA,
        "created_utc": env.get("created_utc"),
        "status": "complete" if not failed else "partial",
        "failed_metrics": failed,
        "guest": env.get("guest"),
        "host": env.get("host", {}),
        "tree": env.get("tree", {}),
        "build": env.get("build", {}),
        "agent": {
            "files": env.get("agent_files", {}),
            "running": env.get("agent_running", {}),
        },
        "method": env.get("method", {}),
        "metrics": metrics,
        "derived": {"overhead": derived},
        "counters": counters,
        "notes": notes + list(env.get("notes", [])),
    }
    return doc


def fmt(v, digits=1):
    if v is None:
        return "—"
    if isinstance(v, float) and abs(v) >= 1000:
        return "{:,.0f}".format(v)
    if isinstance(v, int):
        return "{:,}".format(v)
    return ("{:,.%df}" % digits).format(v)


def markdown(doc):
    h, tr, me, ag = doc["host"], doc["tree"], doc["method"], doc["agent"]
    m = doc["metrics"]
    st = (ag.get("running") or {}).get("status_at_start") or {}
    files = ag.get("files") or {}
    bins = files.get("binaries") or {}
    lines = ["# NorthNarrow performance baseline — %s — %s" % (doc.get("guest") or "?", h.get("kernel")), ""]
    lines.append("- Status: **%s**%s; created %s (UTC)." % (
        doc["status"], (" — not measured: " + ", ".join(doc["failed_metrics"])) if doc["failed_metrics"] else "",
        doc.get("created_utc")))
    lines.append("- Tree: `%s`%s (%s); branch point on origin/main `%s`, build inputs changed since: %s; "
                 "build: %s; agent sha256 `%s`." % (
                     tr.get("commit") or "unknown",
                     " (dirty: %s files)" % tr.get("dirty") if tr.get("dirty") else "",
                     tr.get("source") or "?", tr.get("base") or "unknown",
                     tr.get("build_inputs_changed") or "unknown",
                     ", ".join("%s %s" % (k, v) for k, v in sorted((doc.get("build") or {}).items())) or "?",
                     ((bins.get("agent") or {}).get("sha256") or "?")[:16]))
    lines.append("- Host: %s, %s vCPU, %s MiB, %s, clocksource %s, %s." % (
        h.get("cpu_model"), h.get("vcpus"), (h.get("mem_total_kib") or 0) // 1024, h.get("virt"),
        h.get("clocksource"), h.get("os")))
    argv = (ag.get("running") or {}).get("argv") or []
    yesno = {True: "yes", False: "no"}
    lines.append("- Agent: `%s`; detect-only %s; posture at start %s; overlays: %s." % (
        " ".join(argv[1:]) or "?", yesno.get(st.get("detect_only"), "?"), st.get("posture") or "?",
        ", ".join(sorted(files.get("overlays") or {})) or "none"))
    lines.append("- Method: %s measured passes after %s warm-up per workload and phase, %s round(s), "
                 "workloads pinned to CPU %s, scale %s%s; idle %s s; burst %s s at %s; %s latency probes; "
                 "%s cold boots." % (
                     me.get("reps"), me.get("warmup"), me.get("rounds"), me.get("pin_cpu"), me.get("scale"),
                     " (quick)" if me.get("quick") else "", me.get("idle_secs"), me.get("burst_secs"),
                     me.get("burst_rates"), me.get("latency_samples"), me.get("boot_cycles")))
    lines.append("")
    lines.append("Medians of the samples; p95 the 95th percentile; noise = (p95 − p5) / 2 as a share of the "
                 "median (what `cargo xtask perf-compare` uses). The raw samples are in the JSON "
                 "(`metrics.<name>.samples`).")
    lines.append("")
    lines.append("## Hooked operations (agent off → on)")
    lines.append("")
    lines.append("| metric | off median | on median | on p95 | noise (on) | overhead | agent CPU per op | n |")
    lines.append("|---|---|---|---|---|---|---|---|")
    ov = doc["derived"]["overhead"]
    for name in MICRO_NAMES:
        on, off = m.get(name), m.get(name + "_off")
        if not on and not off:
            continue
        d = ov.get(name, {})
        lines.append("| `%s` | %s | %s | %s | %s | %s | %s | %s |" % (
            name, fmt((off or {}).get("median")), fmt((on or {}).get("median")), fmt((on or {}).get("p95")),
            fmt((on or {}).get("noise_pct")) + " %" if (on or {}).get("noise_pct") is not None else "—",
            ("%+.1f %%" % d["overhead_pct"]) if "overhead_pct" in d else "—",
            (fmt(d.get("agent_cpu_ns_per_op_median")) + " ns") if d.get("agent_cpu_ns_per_op_median") is not None else "—",
            (on or {}).get("n", 0)))
    lines.append("")
    lines.append("ns per operation. Overhead = (on − off) / off of the medians.")
    for title, group in (("Event → signed detection record", "latency"), ("Agent resources", "resources"),
                         ("Loss under the burst", "loss"), ("Boot to READY", "boot")):
        rows = [(n, x) for n, x in sorted(m.items(), key=lambda kv: kv[1]["order"]) if x["group"] == group]
        if not rows:
            continue
        lines += ["", "## " + title, "", "| metric | unit | median | p95 | noise | n | gated |", "|---|---|---|---|---|---|---|"]
        for n, x in rows:
            digits = 0 if x["kind"] == "count" else 2
            lines.append("| `%s` | %s | %s | %s | %s | %s | %s |" % (
                n, x["unit"], fmt(x.get("median"), digits), fmt(x.get("p95"), digits),
                (fmt(x["noise_pct"]) + " %") if x.get("noise_pct") is not None else "—",
                x["n"], "yes" if x["gate"] else "no"))
    per_ring = (doc.get("counters") or {}).get("ring_drops_by_ring") or {}
    if per_ring:
        lines += ["", "Ring drops during the burst, by ring: " + ", ".join(
            "%s %s" % (k, v) for k, v in sorted(per_ring.items())) + "."]
    gen = (doc.get("counters") or {}).get("generator")
    if gen:
        rates = gen.get("rates") if isinstance(gen.get("rates"), dict) else {}
        lines += ["", "Generator: %s iterations in %s s at %s per second, as %s." % (
            gen.get("iterations"), gen.get("secs"),
            ", ".join("%s %s" % (k, v) for k, v in sorted(rates.items())) or "?", gen.get("user"))]
    errs = [(n, x["errors"]) for n, x in m.items() if x.get("errors")]
    if errs or doc["notes"]:
        lines += ["", "## Notes", ""]
        for n, e in errs:
            lines.append("- `%s`: %s" % (n, "; ".join(e)))
        for note in doc["notes"]:
            lines.append("- " + note)
    lines += ["", "Compare: `cargo xtask perf-compare BASE.json THIS.json` (docs/PERFORMANCE.md §2.4)."]
    return "\n".join(lines) + "\n"


def cmd_assemble(a):
    env = {}
    if os.path.exists(a.env):
        with open(a.env, encoding="utf-8") as f:
            env = json.load(f)
    doc = build(read_raw(a.raw), env)
    with open(a.json, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=True)
        f.write("\n")
    with open(a.md, "w", encoding="utf-8") as f:
        f.write(markdown(doc))
    return 0 if doc["status"] == "complete" else 1


# ── self-test ────────────────────────────────────────────────────────────

def synthetic_raw():
    """A run's raw records, made up: what `assemble` and the xtask gate test read."""
    raw = []
    for phase, base in (("off", 100.0), ("on", 120.0)):
        for p in range(4):
            for i, name in enumerate(MICRO_NAMES):
                ns = (base + 10 * i) * (1 + 0.01 * (p % 3))
                raw.append({"t": "micro", "phase": phase, "round": 1, "metric": name, "pass": p,
                            "warmup": p == 0, "iters": 1000, "ok": True, "ops_per_s": 1e9 / ns,
                            "ns_per_op": round(ns, 4), "agent_cpu_ms": 2.0 if phase == "on" else None})
    for s in range(6):
        raw.append({"t": "latency", "seq": s, "warmup": s < 1, "ok": True, "t0_ns": 1, "pid": 100 + s,
                    "lat_record_ms": 3.0 + 0.1 * s, "lat_disk_ms": 5.0 + 0.1 * s, "signed": True})
    for w in range(6):
        raw.append({"t": "cpu_window", "label": "idle", "window": w, "secs": 10.0, "cpu_pct": 0.2 + 0.01 * w})
        raw.append({"t": "cpu_window", "label": "load", "window": w, "secs": 10.0, "cpu_pct": 20.0 + w})
        raw.append({"t": "fork_window", "label": "load", "window": w, "secs": 10.0, "forks_per_s": 400.0 + w})
    for sec in range(10):
        for label, rss in (("idle", 30000), ("load", 34000), ("after", 33000)):
            raw.append({"t": "sample", "label": label, "sec": sec, "ok": True, "ticks": sec,
                        "rss_kib": rss + sec, "threads": 20})
    st0 = {"posture": "Observing", "ringbuf_drops_total": 5, "ringbuf_drops": {"file_open": 5},
           "ringbuf_rejected_total": 0}
    st1 = {"posture": "Observing", "ringbuf_drops_total": 12, "ringbuf_drops": {"file_open": 7, "exec": 5},
           "ringbuf_rejected_total": 0}
    net0 = {"netflow_pending_evicted_total": 0, "flow_sock_forgotten_min": 0, "netflow_rows_skipped_total": 3}
    net1 = {"netflow_pending_evicted_total": 0, "flow_sock_forgotten_min": 0, "netflow_rows_skipped_total": 9}
    raw.append({"t": "status", "label": "burst_before", "status": st0, "net": net0})
    raw.append({"t": "status", "label": "burst_w1", "status": st0, "net": net0})
    raw.append({"t": "status", "label": "burst_after", "status": st1, "net": net1})
    raw.append({"t": "gen", "ok": True, "iterations": 55, "rates": {"exec": 200}, "secs": 60, "user": "nn", "exit": 0})
    raw.append({"t": "held", "ok": True, "count": 0, "entries": 0})
    for c in range(3):
        raw.append({"t": "boot", "label": "cycle%d" % c, "boot_ms": 1500.0 + 10 * c,
                    "health": "anti-tamper: all LSM hooks attached deny_attached=19 deny_expected=19"})
    return raw


def synthetic_env():
    return {"created_utc": "2026-10-21T00:00:00Z", "guest": "ubuntu2404",
            "host": {"kernel": "6.8.0-1-generic", "cpu_model": "Test CPU", "vcpus": 4,
                     "mem_total_kib": 8000000, "virt": "kvm", "clocksource": "tsc", "os": "Test OS"},
            "tree": {"commit": "0" * 40, "dirty": 0, "source": "selftest"},
            "method": {"reps": 3, "warmup": 1, "rounds": 1, "scale": 1.0, "quick": False},
            "agent_files": {"binaries": {"agent": {"path": "/usr/local/bin/northnarrow-agent", "sha256": "ab" * 32}}},
            "agent_running": {"argv": ["/usr/local/bin/northnarrow-agent", "--admin-pub", "x"],
                              "status_at_start": {"detect_only": False, "posture": "Observing"}}}


def selftest():
    fails, n = [], 0

    def check(cond, what):
        nonlocal n
        n += 1
        if not cond:
            fails.append(what)

    check(quantile([1, 2, 3, 4], 0.5) == 2.5, "median of 4")
    check(abs(quantile([10, 20, 30, 40, 50], 0.95) - 48.0) < 1e-9, "p95 type 7")
    check(quantile([7], 0.95) == 7, "one sample")
    s = summary([100, 102, 98, 101, 99])
    check(s["median"] == 100 and s["noise_pct"] is not None and 1.5 < s["noise_pct"] < 2.0,
          "noise of a tight series: %r" % s)
    check(summary([5, 5])["noise_pct"] is None, "no noise below 3 samples")
    check(stat_ticks("42 (a) b) c) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15") == 11 + 12,
          "stat after the last ')'")
    check(ts_ns("2026-10-21T10:00:00.123456Z") == calendar.timegm(time.strptime(
        "2026-10-21T10:00:00", "%Y-%m-%dT%H:%M:%S")) * 10**9 + 123456000, "record ts")
    check(ts_ns("2026-10-21 10:00:00") is None and ts_ns(None) is None, "bad ts refused")
    lines = [b'{"rule_id":"%s","principal":{"pid":7}}' % DET_RULE.encode(),
             b'{"rule_id":"X","principal":{"pid":8}}', b"{torn"]
    check(find_record(lines, DET_RULE, 7) is not None and find_record(lines, DET_RULE, 8) is None,
          "the probe's record by rule and pid")
    check(held_total([b'{"op":"detections_held","extra":{"held":[{"count":3},{"count":4}]}}',
                      b'{"op":"x"}', b"junk"]) == (7, 1), "held counts")
    check(kv_pairs(["a=1", "b=x", "c=1.5", "d=true", "e=null", "f=1580e89", "g=x=y"])
          == {"a": 1, "b": "x", "c": 1.5, "d": True, "e": None, "f": "1580e89", "g": "x=y"},
          "key=value, a commit id stays text")
    doc = build(synthetic_raw(), synthetic_env())
    m = doc["metrics"]
    check(doc["schema"] == SCHEMA and doc["status"] == "complete", "complete: %r" % doc["failed_metrics"])
    check(m["syscall_getppid_ns"]["n"] == 3 and m["syscall_getppid_ns_off"]["gate"] is False,
          "warm-up dropped, off phase is a reference")
    check(m["burst_ring_drops"]["samples"] == [7] and m["burst_ring_drops"]["kind"] == "count",
          "drops = after - before")
    check(doc["counters"]["ring_drops_by_ring"] == {"file_open": 2, "exec": 5}, "drops by ring")
    check(m["event_to_record_ms"]["n"] == 5 and m["boot_to_ready_ms"]["n"] == 3, "latency, boot")
    check(m["burst_forks_per_s"]["n"] == 6 and m["burst_forks_per_s"]["better"] == "higher"
          and m["burst_forks_per_s"]["gate"] is False, "fork rate under the burst: informational")
    ov = doc["derived"]["overhead"]["syscall_getppid_ns"]["overhead_pct"]
    check(abs(ov - 20.0) < 0.5, "overhead from the medians: %r" % ov)
    md = markdown(doc)
    check("| `open_watched_ns` |" in md and "## Loss under the burst" in md, "markdown tables")
    part = build([r for r in synthetic_raw() if r.get("t") != "latency"]
                 + [{"t": "latency", "seq": 0, "warmup": False, "ok": False, "err": "no record"}],
                 synthetic_env())
    check(part["status"] == "partial" and "event_to_record_ms" in part["failed_metrics"]
          and part["metrics"]["event_to_record_ms"]["errors"] == ["no record"], "a failed metric is partial")
    print("perf_lib selftest: %d checks, %d failed%s"
          % (n, len(fails), "".join("\n  FAIL: " + f for f in fails)))
    return 1 if fails else 0


# ── CLI ──────────────────────────────────────────────────────────────────

def _terminate(signum, _frame):
    # perf-run.sh stops the helper with SIGTERM: unwind, so that the
    # `finally` blocks stop what was started (the burst's generator) and
    # subprocess.run kills its workload
    raise SystemExit(128 + signum)


def main(argv):
    signal.signal(signal.SIGTERM, _terminate)
    signal.signal(signal.SIGHUP, _terminate)
    if argv == ["--selftest"]:
        return selftest()
    if argv and argv[0] == "synthetic":
        # the xtask gate test: a run's raw records and environment, made up
        raw, env = argv[1], argv[2]
        for r in synthetic_raw():
            emit(raw, r)
        with open(env, "w", encoding="utf-8") as f:
            json.dump(synthetic_env(), f)
        return 0
    if argv and argv[0] == "emit":
        if len(argv) < 3:
            print("usage: perf_lib.py emit RAW TYPE key=value…", file=sys.stderr)
            return 2
        rec = {"t": argv[2]}
        rec.update(kv_pairs(argv[3:]))
        emit(argv[1], rec)
        return 0
    p = argparse.ArgumentParser(prog="perf_lib.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("micro")
    m.add_argument("--raw", required=True)
    m.add_argument("--phase", choices=("off", "on"), required=True)
    m.add_argument("--round", type=int, default=1)
    m.add_argument("--bench", required=True)
    m.add_argument("--probe", required=True)
    m.add_argument("--workdir", required=True)
    m.add_argument("--watched", default="")
    m.add_argument("--unwatched", default="")
    m.add_argument("--resolver", default="")
    m.add_argument("--reps", type=int, default=10)
    m.add_argument("--warmup", type=int, default=1)
    m.add_argument("--scale", type=float, default=1.0)
    m.add_argument("--cpu", default=None)
    m.add_argument("--agent-pid", type=int, default=0)
    m.add_argument("--skip", default="")
    lat = sub.add_parser("latency")
    lat.add_argument("--raw", required=True)
    lat.add_argument("--probe", required=True)
    lat.add_argument("--file", required=True)
    lat.add_argument("--det", required=True)
    lat.add_argument("--rule", default=DET_RULE)
    lat.add_argument("--samples", type=int, default=20)
    lat.add_argument("--warmup", type=int, default=2)
    lat.add_argument("--interval", type=float, default=1.0)
    lat.add_argument("--timeout", type=float, default=10.0)
    s = sub.add_parser("sample")
    s.add_argument("--raw", required=True)
    s.add_argument("--label", required=True)
    s.add_argument("--pid", type=int, required=True)
    s.add_argument("--secs", type=int, default=60)
    s.add_argument("--window", type=int, default=10)
    b = sub.add_parser("burst")
    b.add_argument("--raw", required=True)
    b.add_argument("--gen", required=True)
    b.add_argument("--gen-user", required=True)
    b.add_argument("--secs", type=int, default=60)
    b.add_argument("--windows", type=int, default=6)
    b.add_argument("--rates", default="exec=200,file=100,tcp=20,udp=200,dns=5")
    b.add_argument("--pid", type=int, required=True)
    b.add_argument("--nn-admin", required=True)
    b.add_argument("--key", required=True)
    b.add_argument("--drain", type=float, default=5.0)
    b.add_argument("--http-port", type=int, default=18090)
    st = sub.add_parser("status")
    st.add_argument("--raw", required=True)
    st.add_argument("--label", required=True)
    st.add_argument("--nn-admin", required=True)
    st.add_argument("--key", required=True)
    hd = sub.add_parser("held")
    hd.add_argument("--raw", required=True)
    hd.add_argument("--audit", required=True)
    hd.add_argument("--from-line", type=int, required=True)
    e = sub.add_parser("envinfo")
    e.add_argument("--env", required=True)
    e.add_argument("--part", choices=("off", "on"), required=True)
    e.add_argument("--pid", type=int, default=0)
    e.add_argument("--nn-admin", default="")
    e.add_argument("--key", default="")
    e.add_argument("--set", action="append")
    asm = sub.add_parser("assemble")
    asm.add_argument("--raw", required=True)
    asm.add_argument("--env", required=True)
    asm.add_argument("--json", required=True)
    asm.add_argument("--md", required=True)
    a = p.parse_args(argv)
    return {"micro": cmd_micro, "latency": cmd_latency, "sample": cmd_sample, "burst": cmd_burst,
            "status": cmd_status, "held": cmd_held, "envinfo": cmd_envinfo,
            "assemble": cmd_assemble}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
