#!/bin/bash
# Tappa 10.9 step 3 — the DNS sensor on the socket buffer, end to end on a
# lab guest (`nn-lab.sh dns-sensor-check`). Run as the lab user with sudo,
# with the agent installed and running in its default (`skb`) mode.
# Reviews 66 and 67: the `udp_sendmsg` sensor read the name from user
# memory before the kernel copied it, and saw no IPv6 query.
set -u
DET=/var/lib/northnarrow/detections/detections.jsonl
HELPER=/usr/local/libexec/nn-lab/nn-dns-send
RULE=NN-L-NET-004_SuspiciousDnsQname
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
INV=$(systemctl show -p InvocationID --value northnarrow-agent)
journal() { sudo journalctl --namespace=northnarrow --no-pager "_SYSTEMD_INVOCATION_ID=$INV" | grep -v "process spawn detected"; }
det_count() { sudo cat "$DET" 2>/dev/null | wc -l; }
new_dets() { sudo tail -n "$(( $(det_count) - $1 ))" "$DET" 2>/dev/null; }
# run "$@"; prints its exit code (137 = killed)
run_rc() { "$@" >/dev/null 2>&1; echo $?; }

# 1. armed, and the BPF self-check quiet about the retired program
if journal | grep -q "DNS sensor armed on udp_send_skb + udp_v6_send_skb"; then
    pass "DNS sensor armed on udp_send_skb + udp_v6_send_skb"
else
    bad "DNS sensor not armed on the socket buffer: $(journal | grep -m1 'DNS sensor' | cut -c1-200)"
fi
if journal | grep -q "own BPF links is GONE"; then
    bad "the BPF self-check reports a missing link since the agent started"
else
    pass "no missing-link report"
fi

if [[ ! -x $HELPER ]]; then
    sudo mkdir -p "$(dirname "$HELPER")" && sudo cc -O2 -o "$HELPER" "$(dirname "$0")/dns-send.c" \
        || { bad "dns-send helper not built"; exit 1; }
fi
# A first label of 40 base64 characters: NET-004's tunnelling shape. Each
# case uses its own name, so NET-004's per-name dedup never hides one.
name() { printf 'ZGVhZGJlZWZjYWZlYmFiZWRlYWRiZWVm%s.nn-lab.invalid' "$1"; }
# NET-004 records whose principal is the helper (the record carries the
# sender, not the name), since baseline $1
net004() { new_dets "$1" | grep "\"rule_id\":\"$RULE\"" | grep '"comm":"nn-dns-send"'; }
# kill_case <label> <mode> <name>: the sender must be killed by NET-004
kill_case() {
    local label=$1 mode=$2 qname=$3
    local b rc n
    b=$(det_count); rc=$(run_rc "$HELPER" "$mode" "$qname" 5); sleep 2
    n=$(net004 "$b" | grep -c '"KillProcess"')
    if [[ $rc -eq 137 && $n -ge 1 ]]; then
        pass "$label: killed by NET-004"
    else
        bad "$label: rc=$rc NET-004 kill records=$n"
    fi
}
# 2–4. IPv4 connected and unconnected, IPv6
kill_case "connected send() to 127.0.0.1:53" connect4 "$(name c4c4c4c4)"
kill_case "unconnected sendto() to 127.0.0.1:53" sendto4 "$(name s4s4s4s4)"
kill_case "connected send() to [::1]:53" connect6 "$(name c6c6c6c6)"
# 5. the payload in a page the process has not touched yet
kill_case "query in a file mapping not faulted in yet" unfaulted "$(name pfpfpfpf)"
# 6. a zero byte inside the first label: the name is read past it (a
# string read stops there and keeps one character); it is long, so NET-004
# kills on length
long="x$(printf 'a%.0s' $(seq 1 50)).nn-lab.invalid"
kill_case "a zero byte inside the first label" nul "$long"
# 7. the query in two pieces (MSG_MORE): the name is not in the linear
# data; NET-004 records it without killing
b=$(det_count); rc=$(run_rc "$HELPER" cork "$(name ckckckck)" 1); sleep 2
n=$(net004 "$b" | grep -c '"Log"')
if [[ $rc -eq 0 && $n -ge 1 ]]; then
    pass "query sent in two pieces: NET-004 record for a partial name, sender untouched"
else
    bad "query sent in two pieces: rc=$rc partial-name records=$n"
fi
# 8. an ordinary lookup through the system resolver is not touched
b=$(det_count); getent hosts nn-lab-dns-check.invalid >/dev/null 2>&1; sleep 2
n=$(new_dets "$b" | grep -c '"rule_id":"NN-L-NET-0')
[[ $n -eq 0 ]] && pass "getent hosts: no NET record" || bad "getent hosts: $n NET record(s)"
# The kills also escalate the posture: back to observing.
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1
# 9. the telemetry probe (its own DNS query included) never went silent
gaps=$(journal | grep -c "TELEMETRY GAP\|still SILENT")
[[ $gaps -eq 0 ]] && pass "telemetry probe: no gap since the agent started" \
                  || bad "telemetry probe: $gaps gap line(s) since the agent started"

[[ $fail -eq 0 ]] && echo "dns-sensor check: OK" || echo "dns-sensor check: FAILED"
exit $fail
