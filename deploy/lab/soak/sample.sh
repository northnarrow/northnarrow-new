#!/usr/bin/env bash
# deploy/lab/soak/sample.sh — periodic resource sampler for the soak test
# (runs ON THE GUEST as root, started by `nn-lab.sh soak start`).
#
# Appends one CSV row every $SOAK_INTERVAL seconds to $SOAK_DIR/samples.csv:
# memory and CPU of the agent and watchdog, fds/threads, systemd restart
# counters, journal warning/error counts since the start, chain-log
# sizes, eBPF map occupancy (LRU/hash maps that could grow) and the
# ring-buffer drop counter. Stops when $SOAK_DIR/stop exists.
#
# External audit NN-AUD-216: the agent and watchdog pids are the units'
# MainPID, checked against the process name (the pid file goes when the
# watchdog holds, and the old pgrep pattern missed the package layout);
# agent_alive / wd_alive say whether a live process was found, and
# map_pct is the fullest sampled map's occupancy of its max_entries.
#
# External audit ASK-009 (lab PR 213): the unsigned `nn-admin status` no
# longer carries the ring-drop counter; it is read signed, with the lab's
# admin key ($SOAK_ADMIN_KEY, else the first readable of
# /root/northnarrow-admin.key and /etc/northnarrow/admin.key: audit-read is
# enough), one `telemetry_status` audit row per sample. Without a key, or
# when the read fails, the ringbuf_dropped column is left empty and
# `nn-lab.sh soak report` fails the run (drops not read), instead of the 0
# the sampler used to write.
set -u
SOAK_DIR=${SOAK_DIR:-/home/nn/soak}
INTERVAL=${SOAK_INTERVAL:-60}
OUT="$SOAK_DIR/samples.csv"
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "$$" > "$SOAK_DIR/sample.pid"
echo "$START" > "$SOAK_DIR/start"
if [ ! -s "$OUT" ]; then
    echo "epoch,agent_pid,agent_rss_kb,agent_vsz_kb,agent_cpu_pct,agent_threads,agent_fds,wd_rss_kb,agent_restarts,wd_restarts,journal_warn,journal_err,combat_lines,det_bytes,status_bytes,audit_bytes,fim_bytes,flow_sock,udp_seen,fim_dirty,protected_pids,ringbuf_dropped,generate_iter,agent_alive,wd_alive,map_pct" > "$OUT"
fi

map_count() { # elements of the first map named $1 (0 when absent)
    bpftool map dump name "$1" 2>/dev/null | grep -c '^key' || true
}
map_max() { # max_entries of the first map named $1 (0 when absent)
    bpftool map show name "$1" 2>/dev/null | grep -oE 'max_entries [0-9]+' | head -1 | grep -oE '[0-9]+' || echo 0
}
# The unit's MainPID when it runs the expected program (comm is cut to 15).
unit_pid() { # unit comm
    local p
    p=$(systemctl show -p MainPID --value "$1" 2>/dev/null || echo 0)
    if [[ "$p" =~ ^[0-9]+$ ]] && [ "$p" -gt 1 ] && [ "$(cat "/proc/$p/comm" 2>/dev/null)" = "$2" ]; then
        echo "$p"
    else
        echo 0
    fi
}
ADMIN_KEY=${SOAK_ADMIN_KEY:-}
for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do
    [ -z "$ADMIN_KEY" ] && [ -r "$k" ] && ADMIN_KEY=$k
done
[ -n "$ADMIN_KEY" ] || echo "sample.sh: no admin key (SOAK_ADMIN_KEY, /root/northnarrow-admin.key): the ring drops are not read" >&2
prev_ticks=0; prev_time=0; hz=$(getconf CLK_TCK)
# map sizes are sampled every MAP_EVERY samples (see the loop)
MAP_EVERY=${SOAK_MAP_EVERY:-15}
MAP_N=0
fs=0; us=0; fd=0; pp=0; mp=0
while [ ! -e "$SOAK_DIR/stop" ]; do
    pid=$(unit_pid northnarrow-agent northnarrow-age)
    alive=0; [ "$pid" != 0 ] && alive=1
    now=$(date +%s)
    rss=0; vsz=0; thr=0; fds=0; cpu=0
    if [ "$pid" != 0 ] && [ -r "/proc/$pid/stat" ]; then
        read -r rss vsz thr < <(awk '/^VmRSS/{r=$2} /^VmSize/{v=$2} /^Threads/{t=$2} END{print r+0, v+0, t+0}' "/proc/$pid/status")
        fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
        ticks=$(awk '{print $14+$15}' "/proc/$pid/stat")
        if [ "$prev_time" != 0 ] && [ "$now" -gt "$prev_time" ]; then
            cpu=$(( (ticks - prev_ticks) * 100 / hz / (now - prev_time) ))
            [ "$cpu" -lt 0 ] && cpu=0
        fi
        prev_ticks=$ticks; prev_time=$now
    fi
    wdpid=$(unit_pid northnarrow-watchdog northnarrow-wat)
    wdalive=0; [ "$wdpid" != 0 ] && wdalive=1
    wdrss=0; [ "$wdpid" != 0 ] && wdrss=$(awk '/^VmRSS/{print $2}' "/proc/$wdpid/status" 2>/dev/null || echo 0)
    ar=$(systemctl show -p NRestarts --value northnarrow-agent 2>/dev/null || echo 0)
    wr=$(systemctl show -p NRestarts --value northnarrow-watchdog 2>/dev/null || echo 0)
    # The agent logs through tracing on stdout in its own journal
    # namespace, so every line has journald priority 6: count the
    # tracing levels by text, in the `northnarrow` namespace.
    jlog=$(journalctl --namespace=northnarrow -u northnarrow-agent --since "$START" -q --no-pager 2>/dev/null)
    # Match the tracing level right after the timestamp (`…Z  WARN `),
    # not anywhere in the line: process-spawn events echo argv, and the
    # sampler's own `grep ERROR` used to count itself.
    jw=$(printf '%s\n' "$jlog" | grep -cE 'Z +WARN ' || true)
    je=$(printf '%s\n' "$jlog" | grep -cE 'Z +ERROR ' || true)
    cb=$(printf '%s\n' "$jlog" | grep -cE 'POSTURE TRANSITION state=COMBAT|combat_stage' || true)
    sz() { stat -c %s "$1" 2>/dev/null || echo 0; }
    det=$(sz /var/lib/northnarrow/detections/detections.jsonl)
    sts=$(sz /var/lib/northnarrow/detections/status_events.jsonl)
    aud=$(sz /etc/northnarrow/audit.log)
    fim=$(sz /var/lib/northnarrow/fim_drift.jsonl)
    # The agent's own maps: every `bpftool map dump` takes a handle on
    # them, which the BPF self-defence records (NN-L-BPF-002, observe
    # builds) or denies (enforce builds). Read their sizes only every
    # MAP_EVERY samples; the ring-drop total comes from `nn-admin status
    # --key` (signed since ASK-009), which does not touch the maps at all.
    if (( MAP_N % MAP_EVERY == 0 )); then
        fs=$(map_count FLOW_SOCK_MAP); us=$(map_count UDP_UNCONNECTED_SEEN); fd=$(map_count FIM_DIRTY_INODES); pp=$(map_count PROTECTED_PIDS)
        mp=0
        for m in "FLOW_SOCK_MAP $fs" "UDP_UNCONNECTED_SEEN $us" "FIM_DIRTY_INODES $fd" "PROTECTED_PIDS $pp"; do
            set -- $m; mx=$(map_max "$1")
            if [ "${mx:-0}" -gt 0 ]; then pct=$(( $2 * 100 / mx )); [ "$pct" -gt "$mp" ] && mp=$pct; fi
        done
    fi
    MAP_N=$((MAP_N + 1))
    drops=""
    if [ -n "$ADMIN_KEY" ]; then
        drops=$(/usr/local/bin/nn-admin status --key "$ADMIN_KEY" --json 2>>"$SOAK_DIR/sample.err" | grep -oE '"ringbuf_drops_total": *[0-9]+' | grep -oE '[0-9]+$' || true)
    fi
    gi=$(cat "$SOAK_DIR/generate.iter" 2>/dev/null || echo 0)
    echo "$now,$pid,$rss,$vsz,$cpu,$thr,$fds,$wdrss,$ar,$wr,$jw,$je,$cb,$det,$sts,$aud,$fim,$fs,$us,$fd,$pp,$drops,$gi,$alive,$wdalive,$mp" >> "$OUT"
    sleep "$INTERVAL"
done
rm -f "$SOAK_DIR/sample.pid"
