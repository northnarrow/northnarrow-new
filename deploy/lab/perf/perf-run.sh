#!/usr/bin/env bash
# The performance baseline (lab PR 228, docs/PERFORMANCE.md §2): what the
# agent costs the operations it hooks, how fast it records a detection,
# what it loses under a burst, what it uses, how long it takes to start.
# Runs ON a lab guest, as root, from an ssh session (`nn-lab.sh perf` ships
# it to /usr/local/libexec/nn-lab/perf and runs it there; from the synced
# tree: `sudo bash deploy/lab/perf/perf-run.sh`). Benign: the workloads are
# the overhead check's (deploy/lab/overhead/nn-bench.c) and the soak's
# generator; the latency probe reads a `.aws/credentials` fixture in the
# run's own scratch directory (NN-L-FIM-011, recorded, never acted on for
# root's read; the lab user's ~/.aws is not touched).
#
# Phases: the agent stopped — units stopped through the trusted-installer
# window with the lab's admin key and the pin root purged, as
# `nn-lab.sh`'s lab_purge_pins does it (review entry 39, external audit
# EBPF-001; nothing of the product is changed or bypassed: without the
# window the run stops, exit 3) — then running. In each phase every
# workload runs in turn, W warm-up passes then N measured ones, pinned to
# one CPU. With the agent running, after it settled: the idle window
# (CPU, RSS), the workloads, the latency probes, the burst (the soak
# generator at a high rate, signed status reads before, during and after),
# a cool-down window; then B cold starts (pin root purged) for the boot
# time to READY. The agent and the watchdog are left running.
#
# Usage: perf-run.sh [--out DIR] [--reps N] [--warmup W] [--rounds R]
#   [--scale F] [--quick] [--cpu N|none] [--settle S] [--idle-secs S]
#   [--burst-secs S] [--burst-rates exec=200,file=100,tcp=20,udp=200,dns=5]
#   [--latency-samples K] [--boot-cycles B] [--key FILE] [--gen-user USER]
#   [--resolver IPV4] [--skip micro,latency,burst,idle,boot,<metric>…]
# Environment (set by nn-lab.sh perf): NN_PERF_TREE_COMMIT,
#   NN_PERF_TREE_DIRTY, NN_PERF_TREE_SOURCE, NN_PERF_GUEST,
#   NN_PERF_BUILD_FEATURES, NN_PERF_BUILD_LTO, NN_PERF_TREE_BASE,
#   NN_PERF_TREE_BUILD_CHANGES.
# Output: DIR/perf.json (every raw sample and its statistics), DIR/perf.md,
#   DIR/raw.jsonl, DIR/env.json; default DIR /var/lib/nn-perf/<UTC stamp>.
# Exit: 0 every gated metric measured, 1 some were not (the JSON names
#   them), 2 usage or not a lab guest, 3 the agent could not be stopped the
#   documented way.
set -u -o pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LIBEXEC=/usr/local/libexec/nn-lab
PIN_ROOT=/sys/fs/bpf/northnarrow
DET=/var/lib/northnarrow/detections/detections.jsonl
AUDIT=/etc/northnarrow/audit.log
NN_LAB_GUEST_MARKER=/var/lib/nn-lab-provisioned

OUT= REPS=10 WARMUP=1 ROUNDS=1 SCALE=1 QUICK=0 CPU=auto SETTLE=20 IDLE_SECS=60
BURST_SECS=60 BURST_RATES="exec=200,file=100,tcp=20,udp=200,dns=5" LAT_SAMPLES=20
BOOT_CYCLES=5 KEY= GEN_USER=${SUDO_USER:-} RESOLVER= SKIP=

log() { printf 'perf: %s\n' "$*" >&2 2>/dev/null || true; }
stop_run() { log "ERROR: $2"; exit "$1"; }
usage() { sed -n '/^# Usage:/,/^# Exit:/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }

while (($#)); do
    case "$1" in
        --out) OUT=${2:?}; shift 2 ;;
        --reps) REPS=${2:?}; shift 2 ;;
        --warmup) WARMUP=${2:?}; shift 2 ;;
        --rounds) ROUNDS=${2:?}; shift 2 ;;
        --scale) SCALE=${2:?}; shift 2 ;;
        --quick) QUICK=1; shift ;;
        --cpu) CPU=${2:?}; shift 2 ;;
        --settle) SETTLE=${2:?}; shift 2 ;;
        --idle-secs) IDLE_SECS=${2:?}; shift 2 ;;
        --burst-secs) BURST_SECS=${2:?}; shift 2 ;;
        --burst-rates) BURST_RATES=${2:?}; shift 2 ;;
        --latency-samples) LAT_SAMPLES=${2:?}; shift 2 ;;
        --boot-cycles) BOOT_CYCLES=${2:?}; shift 2 ;;
        --key) KEY=${2:?}; shift 2 ;;
        --gen-user) GEN_USER=${2:?}; shift 2 ;;
        --resolver) RESOLVER=${2:?}; shift 2 ;;
        --skip) SKIP=${2:?}; shift 2 ;;
        -h | --help) usage ;;
        *) log "unknown argument: $1"; usage ;;
    esac
done
if ((QUICK)); then
    # a smoke run of the whole path (minutes): not a baseline
    REPS=3 SCALE=0.05 SETTLE=10 IDLE_SECS=10 BURST_SECS=12 LAT_SAMPLES=5 BOOT_CYCLES=1
fi
for v in REPS WARMUP ROUNDS SETTLE IDLE_SECS BURST_SECS LAT_SAMPLES BOOT_CYCLES; do
    [[ ${!v} =~ ^[0-9]+$ ]] || stop_run 2 "--${v,,} takes a whole number: ${!v}"
done
[[ $SCALE =~ ^[0-9]*\.?[0-9]+$ ]] || stop_run 2 "--scale takes a number: $SCALE"
((REPS >= 3)) || stop_run 2 "--reps below 3 measures no noise"
skipped() { [[ ",$SKIP," == *",$1,"* ]]; }

# ── preconditions ─────────────────────────────────────────────────────
(($(id -u) == 0)) || stop_run 2 "run as root (sudo)"
# It stops and starts the agent, purges its pin root and loads the host:
# a lab guest (cloud-init's marker, as the other lab checks), or a host
# declared disposable.
if [[ ! -e $NN_LAB_GUEST_MARKER && ${NN_TEST_DISPOSABLE_HOST:-} != 1 ]]; then
    stop_run 2 "not an nn-lab guest ($NN_LAB_GUEST_MARKER missing) and NN_TEST_DISPOSABLE_HOST=1 not set"
fi
for b in python3 cc systemctl journalctl runuser mktemp sha256sum; do
    command -v "$b" >/dev/null 2>&1 || stop_run 2 "missing on the guest: $b"
done
find_src() { local f; for f in "$@"; do [[ -f $f ]] && { echo "$f"; return 0; }; done; return 1; }
PYLIB=$(find_src "$SCRIPT_DIR/perf_lib.py") || stop_run 2 "perf_lib.py not next to $0"
PROBE_SRC=$(find_src "$SCRIPT_DIR/nn-perf-probe.c") || stop_run 2 "nn-perf-probe.c not next to $0"
BENCH_SRC=$(find_src "$SCRIPT_DIR/nn-bench.c" "$SCRIPT_DIR/../overhead/nn-bench.c") || stop_run 2 "nn-bench.c not found"
GEN=$(find_src "$SCRIPT_DIR/generate.sh" "$SCRIPT_DIR/../soak/generate.sh") || stop_run 2 "the soak's generate.sh not found"
RECORDS=$(find_src "$SCRIPT_DIR/lab-records.py" "$SCRIPT_DIR/../lib/lab-records.py") || RECORDS=
# The helper and the pauses run in the background and are waited for: bash
# runs a trap only once its foreground command is done, and an interrupted
# run must put the agent back (and stop the generator) now, not after the
# current minute of measurement.
PY_PID=
py() {
    python3 -I "$PYLIB" "$@" &
    PY_PID=$!
    local rc=0
    wait "$PY_PID" || rc=$?
    PY_PID=
    return "$rc"
}
pause() { sleep "$1" & wait $!; }

systemctl list-unit-files northnarrow-agent.service >/dev/null 2>&1 || stop_run 2 "the agent is not installed (nn-lab.sh install)"
AGENT_EXE=$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)
NN_ADMIN=$(dirname "${AGENT_EXE:-/usr/local/bin/northnarrow-agent}")/nn-admin
[[ -x $NN_ADMIN ]] || stop_run 2 "no nn-admin next to the agent ($NN_ADMIN)"
# External audit DEP-001: install.sh writes the bootstrap key to
# /root/northnarrow-admin.key; a guest installed before keeps it in
# /etc/northnarrow. The lab never edits admin.pub (external audit LAB-002).
if [[ -z $KEY ]]; then
    for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do
        [[ -r $k ]] && { KEY=$k; break; }
    done
fi
[[ -n $KEY && -r $KEY ]] || stop_run 2 "no admin key with the trusted-installer role (--key; /root/northnarrow-admin.key)"
if [[ -z $GEN_USER || $GEN_USER == root ]]; then GEN_USER=nobody; fi
id -u "$GEN_USER" >/dev/null 2>&1 || stop_run 2 "--gen-user $GEN_USER: no such user"
if [[ -z $RESOLVER ]]; then
    RESOLVER=$(awk '$1 == "nameserver" && $2 ~ /^[0-9.]+$/ { print $2; exit }' /etc/resolv.conf 2>/dev/null)
fi
[[ -z $RESOLVER || $RESOLVER =~ ^[0-9]+(\.[0-9]+){3}$ ]] || stop_run 2 "--resolver takes an IPv4 address: $RESOLVER"
NCPU=$(nproc)
if [[ $CPU == auto ]]; then
    CPU=none
    ((NCPU >= 2)) && command -v taskset >/dev/null 2>&1 && CPU=$((NCPU - 1))
fi
[[ $CPU == none || ($CPU =~ ^[0-9]+$ && CPU -lt NCPU) ]] || stop_run 2 "--cpu takes a CPU number below $NCPU, or none: $CPU"
BPFTOOL=0
bpftool version >/dev/null 2>&1 && BPFTOOL=1

STAMP=$(date -u +%Y%m%d-%H%M%S)
if [[ -z $OUT ]]; then
    install -d -m 0755 /var/lib/nn-perf
    OUT=/var/lib/nn-perf/$STAMP
fi
[[ -L $OUT ]] && stop_run 2 "--out is a symbolic link: $OUT"
install -d -m 0755 "$OUT" || stop_run 2 "cannot create $OUT"
RAW=$OUT/raw.jsonl ENV=$OUT/env.json
: > "$RAW"
rm -f "$ENV"
# External audit LAB-008: a fresh root-only scratch directory (mktemp: 0700,
# an unpredictable name), never a fixed path another user could create first.
WORK=$(mktemp -d /var/tmp/nn-perf.XXXXXXXX) || stop_run 2 "mktemp failed"
BENCH=$LIBEXEC/nn-bench PROBE=$LIBEXEC/nn-perf-probe
STOPPED_BY_US=0

agent_pid() {
    local p
    p=$(systemctl show -p MainPID --value northnarrow-agent 2>/dev/null || echo 0)
    if [[ $p =~ ^[0-9]+$ ]] && ((p > 1)); then echo "$p"; else echo 0; fi
}
start_units() {
    systemctl start northnarrow-agent || return 1
    sleep 3
    systemctl start northnarrow-watchdog || log "the watchdog did not start"
}
cleanup() {
    local rc=$?
    # the helper stops the generator and its workload on SIGTERM
    if [[ -n $PY_PID ]]; then
        kill -TERM "$PY_PID" 2>/dev/null
        wait "$PY_PID" 2>/dev/null
    fi
    if ((STOPPED_BY_US)) && ! systemctl is-active --quiet northnarrow-agent; then
        log "starting the agent and the watchdog again"
        start_units || log "the agent did not start: nn-lab.sh install"
    fi
    rm -rf -- "$WORK"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
# A closed ssh connection (no tty: no SIGHUP) only breaks stderr: the run
# goes on to its end and puts the agent back; the results stay in $OUT.
trap '' PIPE

# ── the agent off, the documented way ─────────────────────────────────
# As nn-lab.sh lab_purge_pins: the units refuse a manual stop
# (RefuseManualStop=yes) and the task_kill hook refuses systemd's signals
# outside a signed trusted-installer window (external audit EBPF-001). The
# window is opened with the lab's admin key, through the running agent;
# inside it systemd's signals are delivered — watchdog first (it would
# respawn the agent), SIGTERM, SIGKILL for whatever outlives 10 s — and the
# pin root, protected while an agent ran, can be removed. The deny hooks
# outlive the agent through their pinned links (by design): with the pins
# gone, nothing of the agent stays attached.
lsm_programs() { bpftool prog show 2>/dev/null | grep -c " lsm "; }
agent_off() {
    if [[ -d $PIN_ROOT ]] || systemctl is-active --quiet northnarrow-agent; then
        if ! systemctl is-active --quiet northnarrow-agent; then
            # pins left without an agent (an e2e run): a started agent, a
            # protected pid, purges stale pins at boot and opens the window
            start_units || stop_run 3 "the agent does not start: nn-lab.sh install"
            pause 5
        fi
        if ! "$NN_ADMIN" trusted-installer-grant --key "$KEY" --window-secs 300 >"$WORK/grant.log" 2>&1; then
            stop_run 3 "trusted-installer window refused: $(tail -1 "$WORK/grant.log"). The lab does not edit admin.pub (external audit LAB-002): a guest whose key lacks the role is recreated (nn-lab.sh destroy, up, sync, install)"
        fi
        STOPPED_BY_US=1
        local u i
        for u in northnarrow-watchdog northnarrow-agent; do
            systemctl kill --signal=SIGTERM "$u" 2>/dev/null
            for i in $(seq 1 20); do
                [[ -z $(cat "/sys/fs/cgroup/system.slice/$u.service/cgroup.procs" 2>/dev/null) ]] && break
                sleep 0.5
            done
            systemctl kill --signal=SIGKILL "$u" 2>/dev/null
            systemctl reset-failed "$u" 2>/dev/null
        done
        rm -rf "$PIN_ROOT" 2>/dev/null
        [[ -d $PIN_ROOT ]] && stop_run 3 "the pin root is still there after the window ($PIN_ROOT): not stopped"
        systemctl is-active --quiet northnarrow-agent && stop_run 3 "the agent unit is still active after the window"
    fi
    local n=unknown i
    if ((BPFTOOL)); then
        for i in $(seq 1 20); do
            n=$(lsm_programs)
            [[ $n == 0 ]] && break
            sleep 1
        done
    fi
    py emit "$RAW" off "label=$1" "lsm_programs_left=$n"
    [[ $n == 0 || $n == unknown ]] || py emit "$RAW" note "text=agent off ($1): $n LSM program(s) still loaded (another program's, or the agent's not detached)"
}

# The agent's own health line (lab-records.py: the journal's trusted fields).
health_line() {
    [[ -n $RECORDS ]] || return 0
    local i h=
    for i in $(seq 1 15); do
        h=$(journalctl --namespace=northnarrow -u northnarrow-agent _PID="$1" --no-pager -o json 2>/dev/null \
            | python3 -I "$RECORDS" journal northnarrow-agent.service "$1" INFO "anti-tamper: all LSM hooks attached " | tail -1)
        [[ -n $h ]] && break
        sleep 1
    done
    printf '%s' "$h"
}

# Start; the boot time is systemd's: ExecMainStart -> ActiveEnter (READY=1,
# Type=notify), both CLOCK_MONOTONIC.
agent_on() {
    local t0 t1 ms me ae pid h
    systemctl reset-failed northnarrow-agent northnarrow-watchdog 2>/dev/null
    t0=$(date +%s%N)
    if ! systemctl start northnarrow-agent; then
        py emit "$RAW" boot "label=$1" "err=systemctl start failed"
        return 1
    fi
    t1=$(date +%s%N)
    me=$(systemctl show -p ExecMainStartTimestampMonotonic --value northnarrow-agent)
    ae=$(systemctl show -p ActiveEnterTimestampMonotonic --value northnarrow-agent)
    pid=$(agent_pid)
    sleep 3
    systemctl start northnarrow-watchdog || log "the watchdog did not start"
    h=$(health_line "$pid")
    ms=null
    if [[ $me =~ ^[0-9]+$ && $ae =~ ^[0-9]+$ ]] && ((ae > me)); then
        ms=$(awk -v a="$ae" -v b="$me" 'BEGIN { printf "%.3f", (a - b) / 1000 }')
    fi
    py emit "$RAW" boot "label=$1" "boot_ms=$ms" "start_wall_ms=$(((t1 - t0) / 1000000))" "pid=$pid" "health=$h"
}

reset_posture() {
    # what the lab checks do after a detection that raises the posture
    # (debug-trigger builds; a package build has no `debug`)
    "$NN_ADMIN" debug force-posture observing >/dev/null 2>&1 || true
}

# ── binaries and fixtures ──────────────────────────────────────────────
# Root-owned, outside /home: as root from a user-writable path the agent's
# R009 would kill them.
install -d -m 0755 "$LIBEXEC"
cc -O2 -o "$WORK/nn-bench" "$BENCH_SRC" && install -m 0755 "$WORK/nn-bench" "$BENCH" \
    || stop_run 2 "cc $BENCH_SRC failed"
cc -O2 -o "$WORK/nn-perf-probe" "$PROBE_SRC" && install -m 0755 "$WORK/nn-perf-probe" "$PROBE" \
    || stop_run 2 "cc $PROBE_SRC failed"
"$BENCH" getppid 1 "$WORK/bench" >/dev/null || stop_run 2 "$BENCH has no getppid mode (nn-bench.c older than lab PR 219)"

# Workloads on the watch: FIM-listed files of /etc that every resolver and
# shell reads (not the credential files: a read of those is a detection).
WATCHED=() UNWATCHED=()
install -d -m 0700 "$WORK/unwatched"
for f in /etc/hosts /etc/group /etc/nsswitch.conf /etc/fstab /etc/profile; do
    [[ -f $f && ! -L $f && -r $f ]] || continue
    grep -qxF "$f" /etc/northnarrow/fim-paths.v1 2>/dev/null || continue
    WATCHED+=("$f")
    UNWATCHED+=("$WORK/unwatched/$(basename "$f")")
done
watched_csv=$(IFS=,; echo "${WATCHED[*]}")
unwatched_csv=$(IFS=,; echo "${UNWATCHED[*]}")
((${#WATCHED[@]})) || py emit "$RAW" note "text=no FIM-listed file of the watched set exists here: open_watched_ns and open_unwatched_ns not measured"
[[ -n $RESOLVER ]] || py emit "$RAW" note "text=no IPv4 resolver in /etc/resolv.conf (--resolver): dns_resolver_query_ns not measured"

ensure_running() {
    systemctl is-active --quiet northnarrow-agent && return 0
    log "the agent is not running: starting it"
    start_units || stop_run 2 "the agent does not start: nn-lab.sh install"
    pause "$SETTLE"
}
ensure_running

method_sets=(
    "--set" "created_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    "--set" "guest=${NN_PERF_GUEST:-$(hostname)}"
    "--set" "tree.commit=${NN_PERF_TREE_COMMIT:-unknown}"
    "--set" "tree.dirty=${NN_PERF_TREE_DIRTY:-null}"
    "--set" "tree.source=${NN_PERF_TREE_SOURCE:-not given (perf-run.sh run by hand)}"
    "--set" "tree.base=${NN_PERF_TREE_BASE:-unknown}"
    "--set" "tree.build_inputs_changed=${NN_PERF_TREE_BUILD_CHANGES:-unknown}"
    "--set" "build.features=${NN_PERF_BUILD_FEATURES:-unknown (installed before this run)}"
    "--set" "build.lto=${NN_PERF_BUILD_LTO:-unknown (installed before this run)}"
    "--set" "method.reps=$REPS" "--set" "method.warmup=$WARMUP" "--set" "method.rounds=$ROUNDS"
    "--set" "method.scale=$SCALE" "--set" "method.quick=$( ((QUICK)) && echo true || echo false)"
    "--set" "method.pin_cpu=$CPU" "--set" "method.settle_secs=$SETTLE" "--set" "method.idle_secs=$IDLE_SECS"
    "--set" "method.burst_secs=$BURST_SECS" "--set" "method.burst_rates=$BURST_RATES"
    "--set" "method.latency_samples=$LAT_SAMPLES" "--set" "method.boot_cycles=$BOOT_CYCLES"
    "--set" "method.gen_user=$GEN_USER" "--set" "method.resolver=${RESOLVER:-none}"
    "--set" "method.watched_files=$watched_csv" "--set" "method.skip=${SKIP:-none}"
    "--set" "method.bpftool=$( ((BPFTOOL)) && echo true || echo false)"
)
py envinfo --env "$ENV" --part on --pid "$(agent_pid)" --nn-admin "$NN_ADMIN" --key "$KEY" "${method_sets[@]}"

micro() {   # <phase> <round>
    skipped micro && return 0
    local pid=0
    [[ $1 == on ]] && pid=$(agent_pid)
    py micro --raw "$RAW" --phase "$1" --round "$2" --bench "$BENCH" --probe "$PROBE" \
        --workdir "$WORK/bench" --watched "$watched_csv" --unwatched "$unwatched_csv" \
        --resolver "$RESOLVER" --reps "$REPS" --warmup "$WARMUP" --scale "$SCALE" \
        --cpu "$CPU" --agent-pid "$pid" --skip "$SKIP"
}

# ── the run ───────────────────────────────────────────────────────────
log "$(uname -r), $NCPU vCPU, workloads on CPU $CPU; output $OUT"
for r in $(seq 1 "$ROUNDS"); do
    log "round $r: agent off"
    agent_off "round$r"
    if ((r == 1)); then
        # with the agent off: the binaries' hashes, and the fixtures (their
        # writes are no detection then)
        py envinfo --env "$ENV" --part off
        for f in "${WATCHED[@]}"; do cp -- "$f" "$WORK/unwatched/$(basename "$f")"; done
        install -d -m 0700 "$WORK/probe" "$WORK/probe/.aws"
        printf '[default]\naws_access_key_id = NNPERFPROBE\n' > "$WORK/probe/.aws/credentials"
        chmod 0600 "$WORK/probe/.aws/credentials"
    fi
    pause 5
    micro off "$r"
    log "round $r: agent on"
    agent_on "round$r" || stop_run 1 "the agent did not start"
    log "settling ${SETTLE} s"
    pause "$SETTLE"
    pid=$(agent_pid)
    if ((r == 1)) && ! skipped idle; then
        log "idle window ${IDLE_SECS} s"
        py sample --raw "$RAW" --label idle --pid "$pid" --secs "$IDLE_SECS" --window 10
    fi
    micro on "$r"
    if ((r == 1)) && ! skipped latency; then
        log "latency: $LAT_SAMPLES probes"
        py latency --raw "$RAW" --probe "$PROBE" --file "$WORK/probe/.aws/credentials" --det "$DET" \
            --samples "$LAT_SAMPLES" --warmup 2
        reset_posture
    fi
    if ((r == 1)) && ! skipped burst; then
        audit_from=$(wc -l < "$AUDIT" 2>/dev/null || echo 0)
        py burst --raw "$RAW" --gen "$GEN" --gen-user "$GEN_USER" --secs "$BURST_SECS" --windows 6 \
            --rates "$BURST_RATES" --pid "$pid" --nn-admin "$NN_ADMIN" --key "$KEY"
        # the budget reports what it held once a minute: the cool-down covers it
        cool=$(( IDLE_SECS > 65 ? IDLE_SECS : 65 ))
        log "cool-down ${cool} s"
        py sample --raw "$RAW" --label after --pid "$pid" --secs "$cool" --window 10
        py held --raw "$RAW" --audit "$AUDIT" --from-line "$audit_from"
        reset_posture
    fi
    if [[ $(agent_pid) != "$pid" ]]; then
        py emit "$RAW" note "text=round $r: the agent's pid changed while it was measured ($pid -> $(agent_pid)): a restart, the round is suspect"
    fi
done
if ! skipped boot; then
    for c in $(seq 1 "$BOOT_CYCLES"); do
        log "cold start $c/$BOOT_CYCLES"
        agent_off "boot$c"
        pause 2
        agent_on "boot$c" || stop_run 1 "the agent did not start"
        pause 5
    done
fi
reset_posture
STOPPED_BY_US=0
systemctl is-active --quiet northnarrow-watchdog || systemctl start northnarrow-watchdog || log "the watchdog did not start"

rc=0
py assemble --raw "$RAW" --env "$ENV" --json "$OUT/perf.json" --md "$OUT/perf.md" || rc=$?
chmod 0644 "$OUT"/* 2>/dev/null
log "report: $OUT/perf.md, raw samples and statistics: $OUT/perf.json"
echo "$OUT/perf.json" 2>/dev/null || true
exit "$rc"
