#!/usr/bin/env bash
# Lot 280b — the switches that blind the sensors (`nn-lab.sh switches-check`;
# run by the lab user from the synced tree, sudo inside, the lab key with the
# trusted-installer role). On a LAB GUEST ONLY: T4 adds taint flags to the
# running kernel and T6 raises its lockdown mode, which only the next boot
# clears — the lab powers the guest off after the round.
#
#  T0  the check channel at rest: with ftrace on, the births the tracker's
#      fentry missed (CGROUP_JOIN_SILENT) stay where they are while the host
#      forks — "silent because nothing happened" is not a miss;
#  T1  kernel.ftrace_enabled=0 inside a window (6.x; 5.15: EBUSY, nothing
#      stops): a process started meanwhile is "not known" at once (its byte
#      in CGROUP_JOIN_LOST), the births are counted, the signed degradation
#      cgroup_join_marks names the period; ftrace back on: the marks' epoch
#      reset (CGROUP_JOIN_EPOCH moves), the reset's line signed;
#  T2  /sys/kernel/debug/kprobes/enabled and debug.kprobes-optimization
#      outside a window: refused, kept at 1, signed (kprobes, sysctl); 0
#      written inside a window: put back to 1 at the window's close (or the
#      next round), signed sysctl_restored;
#  T3  /sys/kernel/security/lockdown outside a window: refused, the mode
#      kept, signed (lockdown);
#  T4  a new taint while the agent runs: an unsigned test module when the
#      guest can build one, else the flags written to kernel.tainted (said
#      so) — E (unsigned) signed Critical, K (livepatch) High
#      (kernel_taint); the manifest's kernel_code carries the mask;
#  T5  a cgroup/sysctl program on the ROOT cgroup: refused outside a window
#      (sysctl_root_attach); attached inside one and held, found by the
#      kernel-state round and signed (sysctl_root_prog);
#  T6  (SWITCHES_CONFIDENTIALITY=1: T6 alone) lockdown raised to
#      confidentiality inside a window: the host check's warning, then the
#      agent restarted under it — what its start says and loads.
set -u
PATH=$PATH:/usr/sbin:/sbin
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
DET=/var/lib/northnarrow/detections/detections.jsonl
AUDIT=/etc/northnarrow/audit.log
CG=/sys/fs/cgroup
FT=/proc/sys/kernel/ftrace_enabled
KE=/sys/kernel/debug/kprobes/enabled
KO=/proc/sys/debug/kprobes-optimization
LD=/sys/kernel/security/lockdown
PR=/proc/sys/kernel/printk_ratelimit
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
lines() { sudo sh -c 'wc -l < "$1"' _ "$1" 2>/dev/null || echo 0; }
since() { sudo tail -n +"$(( $2 + 1 ))" "$1" 2>/dev/null; }
ops() { since "$DET" "$1" | grep -o '"operation":"[a-z_]*"' | sort | uniq -c | tr -s ' ' | tr '\n' ';'; }
sev_of() { since "$DET" "$1" | grep "\"operation\":\"$2\"" | grep -o '"severity":"[A-Za-z]*"' | sort -u | tr '\n' ' '; }
WIN_END=0
window() { WIN_END=$(( $(date +%s) + ${1:-60} )); sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs "${1:-60}" >/dev/null 2>&1; }
no_window() { while (( $(date +%s) <= WIN_END + 2 )); do sleep 1; done; }
status_lines() { sudo "$NNADMIN" status --key "$KEY" 2>/dev/null | grep -E "$1" | sed 's/^ *//'; }
tracker_dir() { sudo ls -d /sys/fs/bpf/northnarrow-cgroup-join-v* 2>/dev/null | head -1; }
# an array of u64's values, in key order, as one line (bpftool -j: raw
# bytes, or the formatted value with BTF)
map_words() {
    sudo bpftool -j map dump "$@" 2>/dev/null | python3 -I -c '
import json, sys
out = []
for e in json.load(sys.stdin):
    v = e.get("value", e.get("formatted", {}).get("value") if isinstance(e.get("formatted"), dict) else None)
    if isinstance(v, int):
        out.append(str(v))
    elif isinstance(v, list):
        b = bytes(int(x, 16) if isinstance(x, str) else int(x) for x in v)
        out += [str(int.from_bytes(b[i:i+8], "little")) for i in range(0, len(b) - len(b) % 8, 8)]
print(" ".join(out))'
}
# the newest map of that (kernel-truncated, 15-byte) name
map_id() {
    sudo bpftool -j map show 2>/dev/null | python3 -I -c '
import json, sys
ids = [m["id"] for m in json.load(sys.stdin) if m.get("name") == sys.argv[1]]
print(max(ids) if ids else "")' "$1"
}
silent() { local id; id=$(map_id CGROUP_JOIN_SIL); [[ -n $id ]] && map_words id "$id" | awk '{print $2}'; }
epoch_boot() { map_words pinned "$(tracker_dir)/CGROUP_JOIN_EPOCH" | awk '{print $2}'; }
lost_byte() { # <tgid>: its byte in the pinned CGROUP_JOIN_LOST (64 a slot)
    local t=$1 slot byte
    slot=$(( t / 64 )); byte=$(( t % 64 ))
    sudo bpftool -j map lookup pinned "$(tracker_dir)/CGROUP_JOIN_LOST" key $(( slot & 255 )) $(( (slot >> 8) & 255 )) $(( (slot >> 16) & 255 )) 0 2>/dev/null \
        | python3 -I -c '
import json, sys
v = json.load(sys.stdin)["value"]
x = v[int(sys.argv[1])]
print(int(x, 16) if isinstance(x, str) else int(x))' "$byte"
}
echo "nn-admin: $NNADMIN  key: $KEY  kernel $(uname -r)  lockdown $(cat $LD 2>/dev/null)"
sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 8; }
sudo mountpoint -q /sys/kernel/debug || sudo mount -t debugfs debugfs /sys/kernel/debug

# T6 alone (SWITCHES_CONFIDENTIALITY=1): the mode lasts until the next boot,
# so it is a round of its own, the lab's last before the power-off.
t6() {
    echo "== T6. lockdown confidentiality (the guest keeps it until its next boot)"
    window 600
    echo confidentiality | sudo tee "$LD" >/dev/null; echo "    mode now: $(cat $LD)"
    sudo "$NNADMIN" host-check 2>/dev/null | grep -A2 -i 'lockdown' | sed 's/^/    /'
    hc=$(sudo "$NNADMIN" host-check --json 2>/dev/null | python3 -I -c 'import json,sys; [print(c["status"]) for c in json.load(sys.stdin) if c.get("id")=="lockdown"]' 2>/dev/null)
    [[ $hc == warn ]] && pass "T6 the host check warns on [confidentiality]" || bad "T6 host check [$hc]"
    t=$(date '+%F %T')
    # the unit refuses a manual stop: the agent ended inside the window,
    # systemd starts it again
    old=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
    sudo systemctl kill --signal=SIGTERM northnarrow-agent
    sleep 30
    echo "    agent after a restart under confidentiality: $(systemctl is-active northnarrow-agent) (pid $old → $(sudo cat /run/northnarrow/agent.pid 2>/dev/null))"
    sudo journalctl -u northnarrow-agent --since "$t" --no-pager -o cat 2>/dev/null | grep -iE 'refus|unknown func|lockdown|probe_read|degrad|not attached|FAILED' | cut -c1-240 | sort | uniq -c | sort -rn | head -25 | sed 's/^/    /'
    echo "    programs loaded: $(sudo bpftool prog show 2>/dev/null | grep -c ' name nn_\| name cgroup_join\| name epg\| name fim')"
}
if [[ ${SWITCHES_CONFIDENTIALITY:-0} == 1 ]]; then
    [[ -e $LD ]] || { echo "no lockdown LSM: T6 not run"; exit 1; }
    t6
    echo "switches check (T6): $( ((fail)) && echo FAIL || echo PASS)"
    exit $fail
fi

echo "== T0. the check channel at rest"
s0=$(silent); for _ in $(seq 1 20); do /bin/true; done; sleep 6; s1=$(silent)
echo "    births the fentry missed: $s0 → $s1 over 6 s of forks, ftrace $(cat $FT)"
[[ -n $s0 && $s0 == "$s1" ]] && pass "T0 ftrace on: no birth counted missed ($s1) — the forks were seen" || bad "T0 [$s0] → [$s1]"

echo "== T1. kernel.ftrace_enabled=0 inside a window"
a0=$(lines "$AUDIT"); e0=$(epoch_boot)
window 180
r=$(echo 0 | sudo tee "$FT" 2>&1 >/dev/null); now=$(cat "$FT")
if [[ $now != 0 ]]; then
    echo "    write: [$r], ftrace_enabled $now"
    [[ $r == *"busy"* ]] && pass "T1 5.15: the write is EBUSY while a trampoline is attached — nothing stops ($now)" || bad "T1 [$r] now $now"
else
    sleep 30 &
    SP=$!
    sleep 3
    lb=$(lost_byte "$SP"); kill "$SP" 2>/dev/null; wait "$SP" 2>/dev/null
    for i in $(seq 1 15); do d=$(status_lines 'cgroup_join_marks: .*lost since'); [[ -n $d ]] && break; sleep 1; done
    s=$(silent)
    echo "    a process started with ftrace off: pid $SP, its byte in CGROUP_JOIN_LOST $lb; births missed $s"
    echo "    status: $d"
    [[ $lb == 1 ]] && pass "T1 a process started while ftrace is off is not known at once (its byte 1)" || bad "T1 lost byte [$lb] for $SP"
    [[ -n $s && $s -gt ${s1:-0} ]] && pass "T1 the fork's tracepoint counted the births the fentry missed ($s1 → $s)" || bad "T1 silent [$s1] → [$s]"
    [[ -n $d ]] && pass "T1 the signed degradation cgroup_join_marks while ftrace is off" || bad "T1 no cgroup_join_marks degradation"
    echo 1 | sudo tee "$FT" >/dev/null
    for i in $(seq 1 25); do e1=$(epoch_boot); [[ -n $e1 && $e1 != "$e0" ]] && break; sleep 1; done
    sleep 2
    rl=$(status_lines 'cgroup_join_marks: .*were lost from')
    au=$(since "$AUDIT" "$a0" | grep -c 'cgroup_join_marks')
    echo "    epoch (boot ns) $e0 → $e1; signed rows naming cgroup_join_marks: $au"
    echo "    status: $rl"
    [[ -n $e1 && $e1 != "$e0" ]] && pass "T1 ftrace back on: the marks' epoch reset ($e1)" || bad "T1 epoch [$e0] → [$e1]"
    [[ -n $rl && $au -ge 2 ]] && pass "T1 the period signed (lost, then reset: $au rows)" || bad "T1 reset line [$rl], rows $au"
fi
[[ $(cat "$FT") == 1 ]] || echo 1 | sudo tee "$FT" >/dev/null
no_window

echo "== T2. the kprobes' switches"
d0=$(lines "$DET")
if [[ -e $KE ]]; then
    r=$(echo 0 | sudo tee "$KE" 2>&1 >/dev/null); now=$(cat "$KE")
    [[ $r == *"not permitted"* && $now == 1 ]] && pass "T2 kprobes/enabled=0 outside a window refused, kept 1" || bad "T2 kprobes/enabled [$r] now $now"
else bad "T2 $KE absent"; fi
if [[ -e $KO ]]; then
    r=$(sudo sysctl -w debug.kprobes-optimization=0 2>&1); now=$(cat "$KO")
    [[ $r == *"not permitted"* && $now == 1 ]] && pass "T2 debug.kprobes-optimization=0 outside a window refused, kept 1" || bad "T2 kprobes-optimization [$r] now $now"
else echo "    $KO absent (no CONFIG_OPTPROBES)"; fi
sleep 3
o=$(ops "$d0"); echo "    signed: $o"
[[ $o == *'"kprobes"'* ]] && pass "T2 the debugfs refusal signed (kprobes)" || bad "T2 no kprobes record: $o"
[[ ! -e $KO || $o == *'"sysctl'* ]] && pass "T2 the sysctl refusal signed" || bad "T2 no sysctl record: $o"
a0=$(lines "$AUDIT")
window 20
echo 0 | sudo tee "$KE" >/dev/null; inside=$(cat "$KE")
no_window
for i in $(seq 1 40); do [[ $(cat "$KE") == 1 ]] && break; sleep 1; done
back=$(cat "$KE"); rs=$(since "$AUDIT" "$a0" | grep -c 'kprobes/enabled was')
echo "    inside a window: 0 written ($inside); after its close: $back; signed restores: $rs"
[[ $inside == 0 && $back == 1 && $rs -ge 1 ]] && pass "T2 a 0 written inside a window put back to 1, signed (sysctl_restored)" || bad "T2 inside=$inside back=$back restores=$rs"
[[ $(cat "$KE") == 1 ]] || { window 15; echo 1 | sudo tee "$KE" >/dev/null; no_window; }

echo "== T3. the lockdown file"
d0=$(lines "$DET"); m0=$(cat "$LD" 2>/dev/null)
if [[ -n $m0 ]]; then
    r=$(echo integrity | sudo tee "$LD" 2>&1 >/dev/null); now=$(cat "$LD"); sleep 3
    o=$(ops "$d0"); echo "    write: [$r] mode $m0 → $now; signed: $o"
    [[ $r == *"not permitted"* && $now == "$m0" ]] && pass "T3 lockdown written outside a window: refused, mode kept" || bad "T3 [$r] $m0 → $now"
    [[ $o == *'"lockdown"'* ]] && pass "T3 signed (lockdown)" || bad "T3 no lockdown record: $o"
else echo "    no lockdown LSM: T3 not run"; fi

echo "== T4. a new taint while the agent runs"
d0=$(lines "$DET"); t0=$(cat /proc/sys/kernel/tainted)
how=simulated
MD=/tmp/nn280b-taint
if [[ -d /lib/modules/$(uname -r)/build ]] && command -v make >/dev/null && command -v gcc >/dev/null; then
    mkdir -p "$MD"
    printf '#include <linux/module.h>\nstatic int __init h(void){return 0;}\nstatic void __exit g(void){}\nmodule_init(h);\nmodule_exit(g);\nMODULE_LICENSE("GPL");\nMODULE_DESCRIPTION("nn lot 280b taint probe");\n' > "$MD/nn280b_taint.c"
    echo 'obj-m := nn280b_taint.o' > "$MD/Makefile"
    if make -s -C "/lib/modules/$(uname -r)/build" M="$MD" modules >/dev/null 2>&1 && sudo insmod "$MD/nn280b_taint.ko" 2>/dev/null; then
        how="an unsigned out-of-tree module loaded (insmod)"
        sudo rmmod nn280b_taint 2>/dev/null
    fi
    rm -rf "$MD"
fi
if [[ $how == simulated ]]; then
    how="simulated: E written to kernel.tainted (no module could be built or loaded here)"
    echo 8192 | sudo tee /proc/sys/kernel/tainted >/dev/null
fi
t1=$(cat /proc/sys/kernel/tainted)
sleep 9
sevE=$(sev_of "$d0" kernel_taint); echo "    $how: tainted $t0 → $t1; kernel_taint severities: $sevE"
[[ $sevE == *Critical* ]] && pass "T4 a new E taint signed Critical ($how)" || bad "T4 E: [$sevE]"
d1=$(lines "$DET")
echo 32768 | sudo tee /proc/sys/kernel/tainted >/dev/null
sleep 9
sevK=$(sev_of "$d1" kernel_taint); echo "    simulated: K written to kernel.tainted; severities: $sevK"
[[ $sevK == *High* && $sevK != *Critical* ]] && pass "T4 a new K (livepatch) taint signed High (simulated)" || bad "T4 K: [$sevK]"
kc=$(sudo "$NNADMIN" capabilities --key "$KEY" --json 2>/dev/null | python3 -I -c 'import json,sys; k=json.load(sys.stdin).get("kernel_code") or {}; print(k.get("tainted"), k.get("taint"))' 2>/dev/null)
echo "    manifest kernel_code: $kc"
[[ $kc == "$(cat /proc/sys/kernel/tainted) "* ]] && pass "T4 the manifest records the taint ($kc)" || bad "T4 manifest [$kc]"

echo "== T5. a cgroup/sysctl program on the root cgroup"
P=/usr/local/libexec/nn280b-sysctl-probe
cc -O2 -o /tmp/nn280b-probe "$ROOT/deploy/lab/adversarial/sysctl-child-probe.c" && sudo install -m 0755 /tmp/nn280b-probe "$P"; rm -f /tmp/nn280b-probe
if [[ -x $P ]]; then
    PR0=$(cat "$PR"); d0=$(lines "$DET")
    c=$(sudo "$P" "$CG" multi kernel/printk_ratelimit "$PR0" 300); echo "    outside a window: $c"
    sleep 3; o=$(ops "$d0")
    [[ $c == *"attach (multi): errno=EPERM"* ]] && pass "T5 attached to the root outside a window: refused" || bad "T5 refused? $c"
    [[ $o == *'"sysctl_root_attach"'* ]] && pass "T5 the refusal signed (sysctl_root_attach)" || bad "T5 no sysctl_root_attach: $o"
    d0=$(lines "$DET")
    window 60
    c=$(sudo env NN_PROBE_HOLD_SECS=12 "$P" "$CG" multi kernel/printk_ratelimit "$PR0" 300); echo "    inside a window, held 12 s: $c"
    echo "$PR0" | sudo tee "$PR" >/dev/null
    sleep 2; o=$(ops "$d0"); sv=$(sev_of "$d0" sysctl_root_prog)
    echo "    signed: $o ($sv)"
    [[ $c == *"errno=0"* ]] && pass "T5 attached inside a window" || bad "T5 inside: $c"
    [[ $o == *'"sysctl_root_prog"'* && $sv == *High* ]] && pass "T5 found on the root by the kernel-state round, signed High" || bad "T5 not found: $o [$sv]"
    sudo rm -f "$P"
    no_window
else bad "T5 the probe was not built"; fi

echo "switches check: $( ((fail)) && echo FAIL || echo PASS)"
exit $fail
