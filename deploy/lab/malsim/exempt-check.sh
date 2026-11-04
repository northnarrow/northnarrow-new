#!/usr/bin/env bash
# Lot 277 — an exemption by unit holds for processes started in the unit's
# cgroup, not for one moved into it, end to end on a lab guest
# (`nn-lab.sh exempt-check`; run by the lab user, sudo inside, the lab key
# with config-manage). Benign: the ransomware simulator of lab PR 225 (files
# under /srv/nn-malsim only), restored at the end.
#
# The signed test policy: `enforce NN-L-IMP-001` and `exempt NN-L-IMP-001
# unit nn-lab-exempt.service`.
#  0) the start-in-cgroup tracker is attached (the boot's journal line);
#  1) control: MS-23 run as nn-lab-exempt.service itself (systemd starts it
#     in the unit's cgroup) → exempt: recorded, not killed, runs to its end;
#  2) spoof: while nn-lab-exempt.service runs, a root shell writes its own
#     pid into the unit's cgroup.procs and runs MS-23 → in the unit's cgroup
#     (/proc/self/cgroup says so) but NOT exempt: killed, and the move is a
#     signed NN-L-AT-001 `cgroup_join` naming the exemption;
#  3) spoof through an orphan: the moved shell forks the simulator and exits
#     (the simulator is reparented to PID 1) → still not exempt: killed;
#  3b) the review of #494, B1: a root process whose second thread writes its
#     leader into a threaded child of its own session scope named like the
#     unit (`…/session-N.scope/nn-lab-exempt.service`, `cgroup.threads`) →
#     the unit by name, but NOT exempt: killed, and signed;
#  4) a root shell that moves itself into a cgroup no exemption names →
#     marked (the pinned map, read-only: cgroup-marks.py), no signed record;
#  5) the review of #494, C: RESTARTS (200) starts of the exempt unit by
#     systemd under a busy CPU → no main process marked, no root counted for
#     them.
# Then the policy files are removed (in a trusted-installer window), the
# units stopped: the guest is put back.
set -u
PATH=$PATH:/usr/sbin:/sbin
DET=/var/lib/northnarrow/detections/detections.jsonl
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
HERE=$(cd "$(dirname "$0")" && pwd)
SIM="$HERE/ransom-sim.py"
MARKS="$HERE/cgroup-marks.py"
RESTARTS=${RESTARTS:-200}
UNIT=nn-lab-exempt.service
CG=/sys/fs/cgroup/system.slice/$UNIT
OTHER=nn-lab-other.service
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
lines() { sudo wc -l "$1" | cut -d" " -f1; }
since() { sudo tail -n +"$(( $2 + 1 ))" "$1"; }
imp() { python3 -I -c '
import json,sys
for l in sys.stdin:
    try: r=json.loads(l)
    except Exception: continue
    ms=r.get("matches") or []
    ids=[m["rule_id"] for m in ms] or [r.get("rule_id")]
    if not any(i and i.startswith("NN-L-IMP-001") for i in ids): continue
    print(r.get("rule_id"),"response",repr(r.get("response")),"matches",[(m["rule_id"].split("_")[0],m["mode"],m.get("exempt")) for m in ms])
'; }
joins() { python3 -I -c '
import json,sys
for l in sys.stdin:
    try: r=json.loads(l)
    except Exception: continue
    if r.get("operation") != "cgroup_join": continue
    p=r.get("principal") or {}
    print(r.get("rule_id"),"| by",p.get("comm"),p.get("pid"),r.get("exe"),"|",r.get("response"),"| signed",bool(r.get("agent_sig")))
'; }
prepare() {
    sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1; sleep 1
    sudo python3 -I "$SIM" clean; sudo python3 -I "$SIM" prepare --files 300 >/dev/null
}
locked() { sudo find /srv/nn-malsim/data -name '*.locked' | wc -l; }
echo "nn-admin: $NNADMIN  key: $KEY  kernel: $(uname -r)  systemd: $(systemctl --version | head -1)"

echo "== 0. the tracker"
t=$(sudo journalctl --namespace=northnarrow -u northnarrow-agent -b --no-pager 2>/dev/null | grep -E "start-in-cgroup tracker is attached|cgroup exemptions: tracker" | tail -1 | cut -c1-300)
echo "    $t"
grep -q "tracker is attached" <<<"$t" && pass "the start-in-cgroup tracker is attached" || bad "tracker: [$t]"

echo "== 1. the signed test policy"
printf '# lot 277 test policy\nenforce NN-L-IMP-001\nexempt NN-L-IMP-001 unit %s\n' "$UNIT" > /tmp/rp277.local
sudo "$NNADMIN" policy set --file /tmp/rp277.local --key "$KEY" | sed 's/^/    /'
sudo "$NNADMIN" policy show | sed 's/^/    /'

echo "== 2. control: MS-23 started by systemd as $UNIT"
prepare; b=$(lines "$DET")
sudo systemd-run --quiet --wait --pipe --collect --unit="$UNIT" -- python3 -I "$SIM" inplace; rc=$?
sleep 3; n=$(locked); rec=$(since "$DET" "$b" | imp)
echo "    sim rc=$rc locked=$n"; echo "$rec" | sed 's/^/    /'
if [[ $rc -eq 0 && $n -eq 300 ]] && grep -q "'exempt', 'unit $UNIT'" <<<"$rec"; then
    pass "control: started in the unit's cgroup — exempt (recorded, ran to its end)"
else bad "control: rc=$rc locked=$n rec=[$rec]"; fi
j=$(since "$DET" "$b" | joins); [[ -z $j ]] && pass "control: no cgroup_join record (systemd's placement)" || bad "control: join [$j]"

echo "== 3. spoof: a root shell moves itself into $UNIT's cgroup"
sudo systemd-run --quiet --collect --unit="$UNIT" -- sleep 600
sleep 1; [[ -d $CG ]] || bad "no $CG"
prepare; b=$(lines "$DET")
sudo bash -c "echo \$BASHPID > $CG/cgroup.procs && cat /proc/self/cgroup > /tmp/nn277-cg && exec python3 -I $SIM inplace"; rc=$?
sleep 3; n=$(locked); rec=$(since "$DET" "$b" | imp); j=$(since "$DET" "$b" | joins)
echo "    in: $(cat /tmp/nn277-cg)  sim rc=$rc locked=$n"; echo "$rec" | sed 's/^/    /'; echo "$j" | sed 's/^/    join: /'
grep -q "$UNIT" /tmp/nn277-cg && pass "spoof: the shell ran in the unit's cgroup" || bad "spoof: cgroup [$(cat /tmp/nn277-cg)]"
if grep -q "KillProcessTree" <<<"$rec" && ! grep -q "'exempt'" <<<"$rec" && [[ $n -lt 300 ]]; then
    pass "spoof: not exempt — killed ($n of 300 files locked)"
else bad "spoof: rc=$rc locked=$n rec=[$rec]"; fi
grep -q "NN-L-AT-001" <<<"$j" && grep -q "unit $UNIT" <<<"$j" \
    && pass "spoof: the move is a signed NN-L-AT-001 cgroup_join naming the exemption" || bad "spoof: join [$j]"

echo "== 4. spoof through an orphan: the moved shell forks MS-23 and exits"
prepare; b=$(lines "$DET")
sudo bash -c "echo \$BASHPID > $CG/cgroup.procs && { setsid python3 -I $SIM inplace > /tmp/nn277-orphan.out 2>&1 & echo \$! > /tmp/nn277-orphan.pid; } ; exit 0"
op=$(cat /tmp/nn277-orphan.pid 2>/dev/null)
echo "    orphan pid $op, parent now $(sudo awk '{print $4}' /proc/"$op"/stat 2>/dev/null), cgroup $(sudo cat /proc/"$op"/cgroup 2>/dev/null)"
for _ in $(seq 1 60); do sudo kill -0 "$op" 2>/dev/null || break; sleep 1; done
sleep 3; n=$(locked); rec=$(since "$DET" "$b" | imp)
echo "    locked=$n"; echo "$rec" | sed 's/^/    /'
if grep -q "KillProcessTree" <<<"$rec" && ! grep -q "'exempt'" <<<"$rec" && [[ $n -lt 300 ]]; then
    pass "orphan: a process forked from the moved shell is not exempt either — killed ($n of 300)"
else bad "orphan: locked=$n rec=[$rec]"; fi

echo "== 4b. threaded spoof: a second thread moves its leader into a threaded child named like the unit"
prepare; b=$(lines "$DET")
sudo python3 -I - "$SIM" <<'PY'
import os, sys, threading
own = [l[3:] for l in open("/proc/self/cgroup").read().splitlines() if l.startswith("0::")][0]
d = "/sys/fs/cgroup" + own + "/nn-lab-exempt.service"
os.mkdir(d)
open(d + "/cgroup.type", "w").write("threaded")
def mover():
    with open(d + "/cgroup.threads", "w") as f:
        f.write(str(os.getpid()))
t = threading.Thread(target=mover); t.start(); t.join()
open("/tmp/nn277-thr", "w").write(d + "\n" + open("/proc/%d/cgroup" % os.getpid()).read())
os.execv(sys.executable, [sys.executable, "-I", sys.argv[1], "inplace"])
PY
rc=$?
sleep 3; n=$(locked); rec=$(since "$DET" "$b" | imp); j=$(since "$DET" "$b" | joins)
td=$(sudo head -1 /tmp/nn277-thr 2>/dev/null)
echo "    leader in: $(sudo tail -n +2 /tmp/nn277-thr 2>/dev/null)  sim rc=$rc locked=$n"; echo "$rec" | sed 's/^/    /'; echo "$j" | sed 's/^/    join: /'
sudo grep -q "/nn-lab-exempt.service" /tmp/nn277-thr && pass "threaded: the leader ran in a cgroup named like the unit" || bad "threaded: [$(sudo cat /tmp/nn277-thr 2>/dev/null)]"
if grep -q "KillProcessTree" <<<"$rec" && ! grep -q "'exempt'" <<<"$rec" && [[ $n -lt 300 ]]; then
    pass "threaded: not exempt — killed ($n of 300 files locked)"
else bad "threaded: rc=$rc locked=$n rec=[$rec]"; fi
grep -q "NN-L-AT-001" <<<"$j" && grep -q "unit $UNIT" <<<"$j" \
    && pass "threaded: the move is a signed cgroup_join naming the exemption" || bad "threaded: join [$j]"
[[ -n $td ]] && for _ in $(seq 1 30); do sudo rmdir "$td" 2>/dev/null && break; sleep 1; done

echo "== 5. a move into a cgroup no exemption names: marked, not signed"
sudo systemd-run --quiet --collect --unit="$OTHER" -- sleep 600
sleep 1; b=$(lines "$DET")
sudo bash -c "echo \$BASHPID > /sys/fs/cgroup/system.slice/$OTHER/cgroup.procs && echo \$BASHPID > /tmp/nn277-other.pid && sleep 3" &
sleep 1; opid=$(sudo cat /tmp/nn277-other.pid 2>/dev/null); m=$(sudo python3 -I "$MARKS" mark "$opid")
wait; sleep 1; j=$(since "$DET" "$b" | joins)
echo "    $m"
grep -q " moved $opid" <<<"$m" && pass "a move into $OTHER: the shell marked (moved, by itself)" || bad "other: mark [$m]"
[[ -z $j ]] && pass "no exemption names $OTHER: no cgroup_join record" || bad "other: join [$j]"

echo "== 6. systemd's placement: $RESTARTS starts of $UNIT under a busy CPU, no mark"
busy=(); for _ in $(seq 1 "$(nproc)"); do ( while :; do :; done ) & busy+=($!); done
s0=$(sudo python3 -I "$MARKS" stat); marked=0; noppid=0
for i in $(seq 1 "$RESTARTS"); do
    sudo systemctl stop "$UNIT" 2>/dev/null
    sudo systemd-run --quiet --collect --unit="$UNIT" -- sleep 600
    mp=$(systemctl show -p MainPID --value "$UNIT")
    if [[ -z $mp || $mp == 0 ]]; then noppid=$((noppid+1)); continue; fi
    m=$(sudo python3 -I "$MARKS" mark "$mp")
    [[ $m == "$mp -" ]] || { marked=$((marked+1)); echo "    round $i: $m"; }
done
s1=$(sudo python3 -I "$MARKS" stat)
kill "${busy[@]}" 2>/dev/null; wait 2>/dev/null
echo "    stats before: $s0"; echo "    stats after:  $s1"; echo "    $(systemctl --version | head -1); rounds without a main pid: $noppid"
[[ $marked -eq 0 && $noppid -lt $RESTARTS ]] && pass "placement: $RESTARTS starts by systemd, $marked main processes marked" || bad "placement: $marked of $RESTARTS marked ($noppid without a main pid)"

echo "== put back"
sudo systemctl stop "$UNIT" "$OTHER" 2>/dev/null
sudo python3 -I "$SIM" clean
printf '# no directive: the built-in defaults\n' > /tmp/rp277-empty.local
sudo "$NNADMIN" policy set --file /tmp/rp277-empty.local --key "$KEY" >/dev/null
sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1
sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 120 >/dev/null 2>&1 \
    && sudo rm -f /etc/northnarrow/rule-policy.local /etc/northnarrow/rule-policy.local.sig
rm -f /tmp/rp277.local /tmp/rp277-empty.local; sudo rm -f /tmp/nn277-cg /tmp/nn277-orphan.out /tmp/nn277-orphan.pid /tmp/nn277-thr /tmp/nn277-other.pid
echo "exempt check: $( ((fail)) && echo FAIL || echo PASS)"
exit $fail
