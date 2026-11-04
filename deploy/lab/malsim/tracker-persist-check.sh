#!/usr/bin/env bash
# Lot 277 (the re-review of #494, R2 and D6) — the start-in-cgroup tracker's
# marks outlive a stop of the agent and an `install.sh --upgrade`, and its
# pins are protected, on a lab guest (`nn-lab.sh tracker-persist-check`; run
# by the lab user from the synced tree, sudo inside, the lab key with the
# trusted-installer role). Benign: sleeping processes in throwaway cgroups.
#
#  1) a root process moves itself into a throwaway cgroup → marked;
#  2) the agent and the watchdog stopped (trusted-installer window): the
#     tracker's links stay pinned beside the pin root; a second process
#     moved now is marked too (the programs run with no agent), the first
#     keeps its mark;
#  3) the agent started again: both marks kept, no "marks reset";
#  4) `install.sh --upgrade` with the same build: both marks kept, the same
#     tracker directory, no "marks reset" in the new start's journal;
#  5) the tracker's pins refuse root: unlink of a link, a new entry in its
#     directory (no window open);
#  6) put back: the sleepers killed, the cgroups removed.
set -u
PATH=$PATH:/usr/sbin:/sbin
HERE=$(cd "$(dirname "$0")" && pwd)
TREE=$(cd "$HERE/../../.." && pwd)
MARKS="$HERE/cgroup-marks.py"
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
at_tty() { script -qec "$*" /dev/null < /dev/null; }
mover() {   # <cgroup name> <pid file>: a root sleeper that moved itself
    sudo mkdir -p "/sys/fs/cgroup/$1"
    sudo bash -c "echo \$BASHPID > /sys/fs/cgroup/$1/cgroup.procs && echo \$BASHPID > $2 && exec sleep 900" >/dev/null 2>&1 &
    for _ in $(seq 1 20); do sudo test -s "$2" && break; sleep 0.2; done
    sudo cat "$2"
}
mark_of() { sudo python3 -I "$MARKS" mark "$1"; }
since_start() { sudo journalctl -u northnarrow-agent -b --since "$1" --no-pager -o cat 2>/dev/null; }

sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 5; }
dir0=$(sudo python3 -I "$MARKS" dir)
echo "tracker pin directory: $dir0"

echo "== 1. a move marks"
p1=$(mover nn277-persist-a /tmp/nn277-p1.pid)
m=$(mark_of "$p1"); echo "    $m"
grep -q "^$p1 moved $p1" <<<"$m" && pass "a root process that moved itself: marked" || bad "move: [$m]"

echo "== 2. the agent stopped: the tracker goes on"
sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 300 >/dev/null 2>&1 || bad "window refused"
sudo systemctl stop northnarrow-watchdog northnarrow-agent
sleep 2
systemctl is-active --quiet northnarrow-agent && bad "the agent still runs"
links=$(sudo sh -c "ls $dir0" | grep -c '^link_cgroup_join_')
[[ $links -eq 5 ]] && pass "agent stopped: the tracker's 5 links still pinned in $dir0" || bad "links pinned: $links"
p2=$(mover nn277-persist-b /tmp/nn277-p2.pid)
m2=$(mark_of "$p2"); m1=$(mark_of "$p1"); echo "    $m2"; echo "    $m1"
grep -q "^$p2 moved $p2" <<<"$m2" && pass "a move with no agent running: marked" || bad "move while stopped: [$m2]"
grep -q "^$p1 moved" <<<"$m1" && pass "the earlier mark kept while stopped" || bad "earlier mark: [$m1]"

echo "== 3. the agent started again"
t3=$(date '+%F %T')
sudo systemctl start northnarrow-agent; sleep 6; sudo systemctl start northnarrow-watchdog
m1=$(mark_of "$p1"); m2=$(mark_of "$p2"); echo "    $m1"; echo "    $m2"
grep -q "^$p1 moved" <<<"$m1" && grep -q "^$p2 moved" <<<"$m2" && pass "restart: both marks kept" || bad "restart: [$m1] [$m2]"
j=$(since_start "$t3")
grep -q "start-in-cgroup tracker is attached" <<<"$j" && pass "restart: the tracker attached" || bad "restart: no attach line"
grep -q "marks reset" <<<"$j" && bad "restart: marks reset [$(grep 'marks reset' <<<"$j" | head -1)]" || pass "restart: no marks reset"

echo "== 4. install.sh --upgrade (the same build)"
t4=$(date '+%F %T')
( cd "$TREE" && at_tty sudo ./deploy/install.sh --source-tree --upgrade --grant-key "$KEY" ) >/tmp/nn277-upgrade.log 2>&1
grep -q "UPGRADE complete — health check passed" /tmp/nn277-upgrade.log && pass "upgrade completed" || bad "upgrade: $(grep -E 'UPGRADE|ROLLBACK|FAIL|still loaded' /tmp/nn277-upgrade.log | tail -3 | tr '\n' ' ')"
grep -E "waiting for NorthNarrow's BPF programs|still loaded|dropping" /tmp/nn277-upgrade.log | cut -c1-160 | sed 's/^/    /'
sleep 4
dir1=$(sudo python3 -I "$MARKS" dir)
m1=$(mark_of "$p1"); m2=$(mark_of "$p2"); echo "    $m1"; echo "    $m2"
[[ $dir1 == "$dir0" ]] && pass "upgrade: the same tracker directory ($dir1)" || bad "upgrade: directory $dir0 → $dir1"
grep -q "^$p1 moved" <<<"$m1" && grep -q "^$p2 moved" <<<"$m2" && pass "upgrade: both marks kept" || bad "upgrade: [$m1] [$m2]"
j=$(since_start "$t4")
grep -q "start-in-cgroup tracker is attached" <<<"$j" && pass "upgrade: the new agent's tracker attached" || bad "upgrade: no attach line"
grep -q "marks reset" <<<"$j" && bad "upgrade: marks reset [$(grep 'marks reset' <<<"$j" | head -1)]" || pass "upgrade: no marks reset"

echo "== 5. the tracker's pins refuse root (no window)"
sleep 1
if sudo rm -f "$dir1/link_cgroup_join_mark" 2>/tmp/nn277-rm.err; then
    sudo test -e "$dir1/link_cgroup_join_mark" && pass "unlink of a tracker link refused" || bad "a tracker link was unlinked by root"
else
    pass "unlink of a tracker link refused ($(tail -1 /tmp/nn277-rm.err))"
fi
if sudo touch "$dir1/planted" 2>/dev/null; then bad "a new entry in the tracker's directory"; sudo rm -f "$dir1/planted"; else pass "a new entry in the tracker's directory refused"; fi

echo "== 6. put back"
sudo kill "$p1" "$p2" 2>/dev/null; wait 2>/dev/null
for c in nn277-persist-a nn277-persist-b; do for _ in $(seq 1 20); do sudo rmdir "/sys/fs/cgroup/$c" 2>/dev/null && break; sleep 0.5; done; done
sudo rm -f /tmp/nn277-p1.pid /tmp/nn277-p2.pid /tmp/nn277-rm.err
echo "tracker persist check: $( ((fail)) && echo FAIL || echo PASS)"
exit $fail
