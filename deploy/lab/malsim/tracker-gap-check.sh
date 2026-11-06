#!/usr/bin/env bash
# Lot 281 (#494's N2) — the tracker through an agent's absence, measured on
# a lab guest (`nn-lab.sh tracker-gap-check`; run by the lab user, sudo
# inside, the lab key with config-manage): `install.sh --upgrade` with the
# same build, and in its gap — the old agent stopped, the new one not yet
# started — a debugger's attach (ptrace by python) at a process: the
# tracker's pinned programs taint it with no agent running, and the new
# agent finds the taint (the same tracker directory, adopted, no reset).
# Timed: the old agent down, the new one starting, its tracker attached and
# armed (the window in which no exemption is honoured).
set -u
PATH=$PATH:/usr/sbin:/sbin
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
HERE=$(cd "$(dirname "$0")" && pwd)
TREE=$(cd "$HERE/../../.." && pwd)
MARKS="$HERE/cgroup-marks.py"
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
attach() {
    sudo python3 -I -c 'import ctypes,os,sys
l=ctypes.CDLL(None,use_errno=True); l.ptrace.argtypes=[ctypes.c_long]*2+[ctypes.c_void_p]*2
p=int(sys.argv[1])
if l.ptrace(16,p,None,None)!=0: raise SystemExit("PTRACE_ATTACH errno %d" % ctypes.get_errno())
os.waitpid(p,0); l.ptrace(17,p,None,None); print(os.getpid())' "$1"
}
echo "nn-admin: $NNADMIN  kernel: $(uname -r)"
dir0=$(sudo python3 -I "$MARKS" dir)
echo "tracker pin directory: $dir0"

echo "== install.sh --upgrade (the same build), timed, an attach in its gap"
sleep 900 & sp=$!
U=/root/nn281-tree
sudo rm -rf "$U"
sudo mkdir -p "$U/target/release" "$U/agent-ebpf/target/bpfel-unknown-none/release"
sudo rsync -a --exclude /target --exclude /agent-ebpf/target --exclude /.git "$TREE"/ "$U"/
for b in northnarrow-agent northnarrow-watchdog nn-admin northnarrow-scan; do
    sudo cp -a "$TREE/target/release/$b" "$U/target/release/" 2>/dev/null
done
sudo cp -a "$TREE"/agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf "$TREE"/agent-ebpf/target/bpfel-unknown-none/release/northnarrow-agent-ebpf.buildhash "$U/agent-ebpf/target/bpfel-unknown-none/release/"
t0=$(date +%s.%N)
sudo "$U/deploy/install.sh" --source-tree --upgrade --grant-key "$KEY" > /tmp/nn281-upgrade.log 2>&1 &
ip=$!
# the gap: no agent process in the unit's cgroup
ta=""; by=""
for _ in $(seq 1 600); do
    if [ -z "$(sudo cat /sys/fs/cgroup/system.slice/northnarrow-agent.service/cgroup.procs 2>/dev/null)" ] \
        && ! systemctl is-active --quiet northnarrow-agent; then
        by=$(attach "$sp"); ta=$(date +%s.%N)
        st=$(systemctl is-active northnarrow-agent)
        m0=$(sudo python3 -I "$MARKS" mark "$sp" 2>&1)
        break
    fi
    sleep 0.1
done
wait "$ip"; rc=$?
t1=$(date +%s.%N)
sudo rm -rf "$U"
echo "    install.sh --upgrade: rc $rc, $(awk -v a="$t0" -v b="$t1" 'BEGIN {printf "%.2f", b - a}') s"
grep -q "UPGRADE complete — health check passed" /tmp/nn281-upgrade.log && pass "upgrade completed" || bad "upgrade: $(grep -E 'UPGRADE|ROLLBACK|FAIL' /tmp/nn281-upgrade.log | tail -2 | tr '\n' ' ')"
sleep 8
after() { awk -v t="$t0" '$1 + 0 >= t + 0'; }
sysj=$(sudo journalctl -u northnarrow-agent -b -o short-unix --no-pager 2>/dev/null | after | grep -E 'Stopping|Stopped|Deactivated|Starting|Started')
agj=$(sudo journalctl --namespace=northnarrow -b -o short-unix --no-pager 2>/dev/null | after | grep -E 'tracker is attached|tracker is armed|marks reset|not the tracker')
echo "$sysj" | cut -c1-140 | sed 's/^/    /'; echo "$agj" | cut -c1-260 | sed 's/^/    /'
down=$(grep -E 'Stopped|Deactivated' <<<"$sysj" | head -1 | cut -d' ' -f1)
start=$(grep -E 'Starting' <<<"$sysj" | tail -1 | cut -d' ' -f1)
armed=$(grep -E 'tracker is armed' <<<"$agj" | tail -1 | cut -d' ' -f1)
plan=$(grep -E 'tracker is armed' <<<"$agj" | tail -1 | grep -oE 'since_plan_ms=[0-9]+')
gap() { [[ -n $1 && -n $2 ]] && awk -v a="$1" -v b="$2" 'BEGIN {printf "%.2f s", b - a}' || echo "?"; }
echo "    MEASURE the old agent down→the new starting $(gap "$down" "$start"); starting→armed $(gap "$start" "$armed") ($plan); the old down→the new armed $(gap "$down" "$armed"); the attach $(gap "$down" "$ta") after the old went down"
[[ -n $armed ]] && pass "the new agent's tracker armed" || bad "no armed line after the upgrade"
grep -q "marks reset" <<<"$agj" && bad "upgrade: marks reset" || pass "upgrade: no marks reset"
if [[ -n $ta ]]; then
    echo "    attached at $ta by $by, the agent then $st; its mark in the gap: $m0"
    grep -q "^$sp injected $by\$" <<<"$m0" && pass "an attach in the upgrade's gap (no agent running): tainted by the pinned programs" || bad "in the gap: [$m0]"
    m1=$(sudo python3 -I "$MARKS" mark "$sp"); echo "    after the upgrade: $m1"
    grep -q "^$sp injected $by\$" <<<"$m1" && pass "the taint found by the new agent's tracker" || bad "after the upgrade: [$m1]"
else bad "no gap seen (the agent never stopped)"; fi
kill "$sp" 2>/dev/null
dir1=$(sudo python3 -I "$MARKS" dir)
[[ $dir1 == "$dir0" ]] && pass "upgrade: the same tracker directory ($dir1)" || bad "upgrade: $dir0 → $dir1"
echo "tracker gap check: $( ((fail)) && echo FAIL || echo PASS)"
exit $fail
