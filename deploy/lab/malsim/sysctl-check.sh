#!/usr/bin/env bash
# Lot 280a — the guarded sysctls judged on the kernel's copy of the write
# (`nn-lab.sh sysctl-check`; run by the lab user from the synced tree, sudo
# inside, the lab key with the trusted-installer and config-manage roles).
# Benign: sysctl writes put back as they were, a throwaway child cgroup,
# a policy file removed at the end (inside a window).
#
#  S1  the cgroup/sysctl judge on the root cgroup (multi), pinned beside the
#      pin root; the manifest names it;
#  S2  a second thread flips the written buffer (the TOCTOU lot 273d
#      declared): kernel.pid_max 140000 / 040000 (octal: the kernel's
#      16384) and kernel.sched_rt_runtime_us 950000 / 990000 — how many of N
#      writes put the harmful value in (expected 0), how many refused, the
#      signed sysctl_value records;
#  S3  an octal and a hexadecimal value below the floor, written plainly:
#      refused, the value kept;
#  S4  tuned's realtime profile (kernel.sched_rt_runtime_us = -1): refused
#      without an opt-out; let through and recorded (sysctl_opt_out) under a
#      signed `sysctl-allow`, left by the round; refused again once the
#      policy's signature is invalid (the file edited, the agent restarted);
#  S5  a program in a child cgroup — attached none, override and multi —
#      that lets every write through and rewrites the value after the root's
#      would have judged it: the guarded write still refused, the value
#      kept; the control (an unguarded sysctl) shows the child's program
#      runs and rewrites;
#  S6  the cost: run_time_ns / run_cnt of the judge a write and a read (BPF
#      statistics on for that step only), and wall clock a write with the
#      judge attached, detached (`bpftool link detach`, inside a window: the
#      agent holds its link, so an unpinned link stays attached) and
#      attached again after an agent restart (S7: the restart swaps the
#      pinned program for its own, one program on the root).
set -u
PATH=$PATH:/usr/sbin:/sbin
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
DET=/var/lib/northnarrow/detections/detections.jsonl
AUDIT=/etc/northnarrow/audit.log
PINS=/sys/fs/bpf/northnarrow-sysctl
CG=/sys/fs/cgroup
PM=/proc/sys/kernel/pid_max
RT=/proc/sys/kernel/sched_rt_runtime_us
PR=/proc/sys/kernel/printk_ratelimit
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
N=${N:-2000}
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
lines() { sudo wc -l < "$1" 2>/dev/null || echo 0; }
since() { sudo tail -n +"$(( $2 + 1 ))" "$1" 2>/dev/null; }
ops() { since "$DET" "$1" | grep -o '"operation":"[a-z_]*"' | sort | uniq -c | tr -s ' ' | tr '\n' ';'; }
judge_ids() { sudo bpftool cgroup show "$CG" 2>/dev/null | awk '/nn_sysctl_guard/ {print $1}' | tr '\n' ' '; }
window() { sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs "${1:-60}" >/dev/null 2>&1; }
restart_agent() {
    local old new i
    window 300 || { bad "trusted-installer-grant"; return 1; }
    old=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
    sudo systemctl kill --signal=SIGTERM northnarrow-agent
    for i in $(seq 1 60); do
        sleep 1
        new=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
        [[ -n $new && $new != "$old" ]] && sudo kill -0 "$new" 2>/dev/null && { sleep 8; return 0; }
    done
    sudo systemctl start northnarrow-agent; sleep 8
}
race() { # <path> <good> <bad> <bad as the kernel prints it> <tries>
    sudo python3 -I - "$@" <<'PY'
import errno, os, sys, threading, time
path, good, badv, shown, tries = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5])
g, b = good.encode() + b"\n", badv.encode() + b"\n"
diff = [i for i in range(len(g)) if g[i] != b[i]]
assert len(g) == len(b) and len(diff) == 1, "one byte apart"
i, gv, bv = diff[0], g[diff[0]], b[diff[0]]
sys.setswitchinterval(0.00005)
buf = bytearray(g)
stop = []
def flip():
    while not stop:
        buf[i] = bv
        buf[i] = gv
fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
now = lambda: os.pread(fd, 32, 0).strip()
refused = wins = other = 0
th = threading.Thread(target=flip, daemon=True)
t = time.monotonic()
th.start()
for n in range(1, tries + 1):
    try:
        os.pwrite(fd, buf, 0)
    except OSError as e:
        if e.errno in (errno.EPERM, errno.EACCES):
            refused += 1
        else:
            other += 1
    if now() == shown.encode():
        wins += 1
        os.pwrite(fd, g, 0)
stop.append(1)
print("%d of %d writes put %s in (%d refused, %d other errors, %.1f s)" % (wins, n, badv, refused, other, time.monotonic() - t))
PY
}
echo "nn-admin: $NNADMIN  key: $KEY  kernel $(uname -r)"
sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 6; }

echo "== S1. the judge on the root cgroup"
sudo bpftool cgroup show "$CG" 2>&1 | sed 's/^/    /'
row=$(sudo bpftool cgroup show "$CG" 2>/dev/null | grep nn_sysctl_guard)
pins=$(sudo ls "$PINS" 2>/dev/null | tr '\n' ' ')
note=$(sudo "$NNADMIN" capabilities --key "$KEY" 2>/dev/null | grep -i "sysctl_judge" | head -2 | tr -s ' ' | tr '\n' ';')
echo "    pins: $pins; manifest: $note"
if [[ $row == *sysctl*multi* && $pins == *link_nn_sysctl_guard* && $pins == *prog_nn_sysctl_guard* ]]; then
    pass "S1 nn_sysctl_guard on the root cgroup, sysctl multi; pinned in $PINS"
else bad "S1 row=[$row] pins=[$pins]"; fi
[[ $note == *cgroup/sysctl* ]] && pass "S1 the manifest's sysctl_judge: $note" || bad "S1 manifest note [$note]"
ID1=$(judge_ids)

echo "== S2. a second thread flips the buffer"
PM0=$(cat "$PM"); RT0=$(cat "$RT")
d0=$(lines "$DET")
m=$(race "$PM" 140000 040000 16384 "$N"); echo "    pid_max: $m"
[[ $m == "0 of $N writes"* ]] && pass "S2 pid_max 140000/040000: $m" || bad "S2 pid_max: $m"
echo "$PM0" | sudo tee "$PM" >/dev/null
if [[ $RT0 == 950000 ]]; then
    m=$(race "$RT" 950000 990000 990000 "$N"); echo "    sched_rt_runtime_us: $m"
    [[ $m == "0 of $N writes"* ]] && pass "S2 sched_rt_runtime_us 950000/990000 (C106r): $m" || bad "S2 rt: $m"
    echo 950000 | sudo tee "$RT" >/dev/null
fi
sleep 3
o=$(ops "$d0"); echo "    signed refusals: $o"
[[ $o == *sysctl_value* ]] && pass "S2 refusals on the kernel's copy signed (sysctl_value): $o" || bad "S2 no sysctl_value record: $o"

echo "== S3. octal and hexadecimal below the floor"
for v in 040000 0x4000; do
    r=$(printf '%s\n' "$v" | sudo tee "$PM" 2>&1 >/dev/null); now=$(cat "$PM")
    [[ $r == *"not permitted"* && $now == "$PM0" ]] && pass "S3 pid_max=$v refused, kept $now" || bad "S3 $v: [$r] now $now"
done

echo "== S4. tuned's realtime profile: kernel.sched_rt_runtime_us = -1"
r=$(sudo sysctl -w kernel.sched_rt_runtime_us=-1 2>&1); now=$(cat "$RT")
[[ $r == *"not permitted"* && $now == "$RT0" ]] && pass "S4a no opt-out: refused ($now)" || bad "S4a [$r] now $now"
printf '# lot 280a lab: tuned realtime\nsysctl-allow kernel.sched_rt_runtime_us -1\n' > /tmp/k280a-rp.local
a0=$(lines "$AUDIT"); d0=$(lines "$DET")
sudo "$NNADMIN" policy set --file /tmp/k280a-rp.local --key "$KEY" | sed 's/^/    /'
sudo "$NNADMIN" policy show | grep sysctl-allow | sed 's/^/    /'
r=$(sudo sysctl -w kernel.sched_rt_runtime_us=-1 2>&1); now=$(cat "$RT")
sleep 12
later=$(cat "$RT"); o=$(ops "$d0")
echo "    write: [$r] now $now, 12 s later $later; records: $o"
[[ $now == -1 && $later == -1 ]] && pass "S4b signed sysctl-allow: -1 let through and left by the round" || bad "S4b now $now later $later [$r]"
[[ $o == *sysctl_opt_out* ]] && pass "S4b the write recorded (sysctl_opt_out): $o" || bad "S4b no sysctl_opt_out record: $o"
f=$(since "$AUDIT" "$a0" | grep -c 'sysctl_opted_out')
echo "    round findings sysctl_opted_out: $f"
# an invalid signature: the file edited (inside a window), the agent restarted
window 120 && printf '# edited\nsysctl-allow kernel.sched_rt_runtime_us -1..0\n' | sudo tee /etc/northnarrow/rule-policy.local >/dev/null
a0=$(lines "$AUDIT")
restart_agent
drift=$(since "$AUDIT" "$a0" | grep -c 'unauthorized_overlay')
for i in $(seq 1 20); do [[ $(cat "$RT") != -1 ]] && break; sleep 1; done
after=$(cat "$RT")
# (a restart ends the window: the new agent boot-zeroes its grant)
r=$(sudo sysctl -w kernel.sched_rt_runtime_us=-1 2>&1); now=$(cat "$RT")
echo "    invalid signature: unauthorized_overlay rows $drift; put back to $after; a new -1: [$r] now $now"
[[ $drift -ge 1 && $after != -1 && $r == *"not permitted"* && $now != -1 ]] \
    && pass "S4c invalid signature: the opt-out not honoured — -1 put back ($after) and refused" || bad "S4c drift=$drift after=$after [$r] now $now"
window 120 && sudo rm -f /etc/northnarrow/rule-policy.local /etc/northnarrow/rule-policy.local.sig
rm -f /tmp/k280a-rp.local
[[ $(cat "$RT") == "$RT0" ]] || { window 60; echo "$RT0" | sudo tee "$RT" >/dev/null; }

echo "== S5. a program in a child cgroup"
P=/usr/local/libexec/nn280a-sysctl-child-probe
cc -O2 -o /tmp/nn280a-probe "$ROOT/deploy/lab/adversarial/sysctl-child-probe.c" && sudo install -m 0755 /tmp/nn280a-probe "$P"; rm -f /tmp/nn280a-probe
if [[ -x $P ]]; then
    sudo mkdir -p "$CG/nn280a-probe"
    PR0=$(cat "$PR")
    c=$(sudo "$P" "$CG/nn280a-probe" none kernel/printk_ratelimit "$PR0" 300); echo "    control: $c"
    [[ $c == *"errno=0; now 300"* ]] && pass "S5 control: the child's program runs and rewrites an unguarded sysctl ($c)" || bad "S5 control: $c"
    echo "$PR0" | sudo tee "$PR" >/dev/null
    for mode in none override multi; do
        c=$(sudo "$P" "$CG/nn280a-probe" "$mode" kernel/pid_max "$(cat "$PM")" 300); echo "    $c"
        [[ $c == *"errno=EPERM; now $PM0;"* ]] && pass "S5 child program ($mode): the rewritten 300 refused on the kernel's copy" || bad "S5 $mode: $c"
    done
    sudo rmdir "$CG/nn280a-probe"; sudo rm -f "$P"
else bad "S5 the probe was not built"; fi

echo "== S6/S7. the cost; the restart swaps the pinned judge"
prog_stat() { sudo bpftool prog show 2>/dev/null | awk '/ name nn_sysctl_guard / { for (i=1;i<=NF;i++) { if ($i=="run_time_ns") t+=$(i+1); if ($i=="run_cnt") c+=$(i+1) } } END { print c+0, t+0 }'; }
bench() { sudo python3 -I -c '
import os, sys, time
p, n, w = sys.argv[1], int(sys.argv[2]), sys.argv[3] == "w"
fd = os.open(p, os.O_RDWR)
v = os.pread(fd, 32, 0)
t = time.perf_counter_ns()
for _ in range(n):
    if w: os.pwrite(fd, v, 0)
    else: os.pread(fd, 32, 0)
print((time.perf_counter_ns() - t) // n)' "$PM" "${1:-20000}" "${2:-w}"; }
sudo sysctl -q kernel.bpf_stats_enabled=1
read -r c0 t0 < <(prog_stat); bench 20000 w >/dev/null; read -r c1 t1 < <(prog_stat)
w_calls=$((c1 - c0)); w_ns=$(( w_calls > 0 ? (t1 - t0) / w_calls : 0 ))
read -r c0 t0 < <(prog_stat); bench 20000 r >/dev/null; read -r c1 t1 < <(prog_stat)
r_calls=$((c1 - c0)); r_ns=$(( r_calls > 0 ? (t1 - t0) / r_calls : 0 ))
sudo sysctl -q kernel.bpf_stats_enabled=0
echo "RESULT per-call: a write $w_ns ns ($w_calls calls), a read $r_ns ns ($r_calls calls) — run_time_ns / run_cnt of nn_sysctl_guard"
on1=$(for _ in 1 2 3; do bench 20000 w; done | sort -n | sed -n 2p)
window 300
sudo rm -f "$PINS/link_nn_sysctl_guard"; sleep 1
held=$(judge_ids)
lid=$(sudo bpftool -j link show 2>/dev/null | python3 -I -c '
import json, sys
ids = set(sys.argv[1].split())
for l in json.load(sys.stdin):
    if l.get("type") == "cgroup" and str(l.get("prog_id")) in ids:
        print(l["id"])' "$ID1")
sudo bpftool link detach id "$lid" 2>&1 | sed 's/^/    /'
sleep 1
off=$(for _ in 1 2 3; do bench 20000 w; done | sort -n | sed -n 2p)
gone=$(judge_ids)
restart_agent
ID2=$(judge_ids)
on2=$(for _ in 1 2 3; do bench 20000 w; done | sort -n | sed -n 2p)
echo "RESULT wall: a write of pid_max (same value) attached $on1 / $on2 ns, detached $off ns (medians of 3 × 20,000)"
echo "    judge ids: before [$ID1], its pin removed [$held] (the agent holds the link), link $lid detached [$gone], after the restart [$ID2]"
n2=$(wc -w <<<"$ID2")
[[ $held == "$ID1" ]] && pass "S7 its pin removed inside a window, the judge stays attached (the agent holds its link)" || bad "S7 held=[$held] before=[$ID1]"
[[ -z ${gone// /} && $n2 == 1 && $ID2 != "$ID1" ]] && pass "S7 detached inside a window; the restart linked its own program, one on the root" || bad "S7 gone=[$gone] after=[$ID2] before=[$ID1]"
echo "sysctl check: $( ((fail)) && echo FAIL || echo PASS)"
exit $fail
