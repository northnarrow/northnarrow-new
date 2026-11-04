#!/usr/bin/env bash
# Lot 277 (the re-review of #494, lab point 4) — what the start-in-cgroup
# tracker costs a fork and an exit, on a lab guest (`nn-lab.sh fork-cost`;
# run by the lab user from the synced tree, sudo inside, the lab key with
# the trusted-installer role). Benign: a loop of fork + _exit + waitpid.
#
#  1) per call, from the kernel's BPF statistics (`kernel.bpf_stats_enabled`
#     on for this step only): run_time_ns / run_cnt of the programs a fork
#     and an exit run (cgroup_join_born, cgroup_join_fork, cgroup_join_exit)
#     over ROUNDS rounds of N forks;
#  2) wall clock, the statistics off: ns per fork + exit + wait, on one
#     CPU, ROUNDS rounds with the tracker attached, ROUNDS with its five
#     links unpinned (trusted-installer window: the programs detach, the
#     rest of the agent runs), then ROUNDS with the tracker attached again
#     (the agent restarted); the medians.
set -u
PATH=$PATH:/usr/sbin:/sbin
HERE=$(cd "$(dirname "$0")" && pwd)
MARKS="$HERE/cgroup-marks.py"
N=${N:-20000}
ROUNDS=${ROUNDS:-5}
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
fail=0
B=/tmp/nn277-forkbench
cat > $B.c <<'C'
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv) {
    int n = argc > 1 ? atoi(argv[1]) : 20000;
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    for (int i = 0; i < n; i++) {
        pid_t p = fork();
        if (p == 0) _exit(0);
        if (p < 0) return 1;
        waitpid(p, 0, 0);
    }
    clock_gettime(CLOCK_MONOTONIC, &b);
    printf("%.0f\n", ((b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec)) / n);
    return 0;
}
C
# The agent kills a program run from /tmp (R001): the bench goes in a
# root-owned system tree for the run.
cc -O2 -o $B $B.c || { echo "FAIL  no C compiler"; exit 1; }
sudo install -m 0755 $B /usr/local/libexec/nn277-forkbench && rm -f $B && B=/usr/local/libexec/nn277-forkbench
median() { sort -n | awk '{a[NR]=$1} END {print (NR%2 ? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2)}'; }
CPU=$(( $(nproc) > 1 ? 1 : 0 ))
bench() { for _ in $(seq 1 "$ROUNDS"); do taskset -c "$CPU" $B "$N"; done; }
moved_marked() {   # a root sleeper that moved itself into a throwaway cgroup: its mark
    local p m
    sudo rm -f /tmp/nn277-cost.pid
    sudo mkdir -p /sys/fs/cgroup/nn277-cost
    sudo bash -c 'echo $BASHPID > /sys/fs/cgroup/nn277-cost/cgroup.procs && echo $BASHPID > /tmp/nn277-cost.pid && exec sleep 30' >/dev/null 2>&1 &
    for _ in $(seq 1 20); do sudo test -s /tmp/nn277-cost.pid && break; sleep 0.2; done
    p=$(sudo cat /tmp/nn277-cost.pid)
    m=$(sudo python3 -I "$MARKS" mark "$p" 2>&1)
    sudo kill "$p" 2>/dev/null
    for _ in $(seq 1 20); do sudo rmdir /sys/fs/cgroup/nn277-cost 2>/dev/null && break; sleep 0.2; done
    sudo rm -f /tmp/nn277-cost.pid
    echo "$m"
}
prog_stat() {   # <name prefix (15 chars)>: "run_cnt run_time_ns"
    sudo bpftool prog show 2>/dev/null | awk -v n="$1" '
        $0 ~ " name "n" " { for (i=1;i<=NF;i++) { if ($i=="run_time_ns") t=$(i+1); if ($i=="run_cnt") c=$(i+1) } found=1 }
        END { if (found) print c+0, t+0; else print "0 0" }'
}
sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 5; }
dir=$(sudo python3 -I "$MARKS" dir)
echo "tracker pin directory: $dir; N=$N forks a round, ROUNDS=$ROUNDS; $(uname -r), $(nproc) CPUs"

echo "== 1. per call (BPF statistics on)"
sudo sysctl -q kernel.bpf_stats_enabled=1
declare -A c0 t0
for p in cgroup_join_bor cgroup_join_for cgroup_join_exi; do read -r c0[$p] t0[$p] < <(prog_stat $p); done
bench > /dev/null
total=0
for p in cgroup_join_bor cgroup_join_for cgroup_join_exi; do
    read -r c t < <(prog_stat $p)
    dc=$((c - c0[$p])); dt=$((t - t0[$p]))
    per=$(( dc > 0 ? dt / dc : 0 )); total=$((total + per))
    echo "    $p: $dc calls, $dt ns, $per ns a call"
done
sudo sysctl -q kernel.bpf_stats_enabled=0
echo "RESULT per-call: born + fork + exit = $total ns a fork and its exit (BPF statistics; the stats' own clock reads included)"

echo "== 2. wall clock (statistics off), ns per fork + exit + wait on CPU $CPU"
on1=$(bench | tr '\n' ' '); m_on1=$(tr ' ' '\n' <<<"$on1" | grep . | median)
echo "    tracker attached:   $on1 (median $m_on1)"
sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 300 >/dev/null 2>&1 || { echo "FAIL  window refused"; fail=1; }
for l in $(sudo sh -c "ls $dir" | grep '^link_cgroup_join_'); do sudo rm -f "$dir/$l"; done
sleep 1
probe=$(moved_marked)
echo "    links unpinned; a move now: [$probe] (detached: no mark)"
grep -q " -$" <<<"$probe" || { echo "FAIL  the tracker still marks with its links unpinned"; fail=1; }
off=$(bench | tr '\n' ' '); m_off=$(tr ' ' '\n' <<<"$off" | grep . | median)
echo "    tracker detached:   $off (median $m_off)"
t2=$(date '+%F %T')
for u in northnarrow-watchdog northnarrow-agent; do
    sudo systemctl kill --signal=SIGTERM "$u" 2>/dev/null
    for i in $(seq 1 30); do [ -z "$(sudo cat /sys/fs/cgroup/system.slice/$u.service/cgroup.procs 2>/dev/null)" ] && break; sleep 0.5; done
    sudo systemctl kill --signal=SIGKILL "$u" 2>/dev/null; sudo systemctl reset-failed "$u" 2>/dev/null
done
sudo systemctl start northnarrow-agent; sleep 6
sudo journalctl -u northnarrow-agent -b --since "$t2" --no-pager -o cat | grep -q "start-in-cgroup tracker is attached" || { echo "FAIL  the tracker did not attach again"; fail=1; }
probe=$(moved_marked)
echo "    agent restarted; a move now: [$probe] (attached: marked)"
grep -q " moved " <<<"$probe" || { echo "FAIL  the tracker does not mark after the restart"; fail=1; }
on2=$(bench | tr '\n' ' '); m_on2=$(tr ' ' '\n' <<<"$on2" | grep . | median)
echo "    tracker attached:   $on2 (median $m_on2)"
echo "RESULT wall: attached $m_on1 / $m_on2 ns, detached $m_off ns a fork + exit + wait (medians of $ROUNDS rounds of $N)"
sudo systemctl is-active --quiet northnarrow-watchdog || sudo systemctl start northnarrow-watchdog
sudo rm -f /usr/local/libexec/nn277-forkbench; rm -f /tmp/nn277-forkbench /tmp/nn277-forkbench.c
exit $fail
