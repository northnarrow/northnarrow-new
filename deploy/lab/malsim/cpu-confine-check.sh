#!/usr/bin/env bash
# Lot 349 (pre-alpha R001) — the agent's own CPUs (`nn-lab.sh
# cpu-confine-check`; run by the lab user from the synced tree, sudo
# inside). On a LAB GUEST ONLY, with an agent installed and an admin key
# (/root/northnarrow-admin.key) for the window of C3. Every case reads stdin
# from /dev/null; what it changes is put back. One `=== CASE <label>: rc=<n>
# …` line per case, then PASS/FAIL/MEASURE lines.
#
#  C0  the cpuset controller enabled at the root (as a container runtime
#      does, #557) when it was not: no cpu_confined record;
#  C1  a sibling cgroup in cpuset.cpus.partition=root takes every CPU but
#      CPU 0: the agent's threads run on CPU 0 alone — a signed NN-L-AT-001
#      cpu_confined High naming the partition within 15 s, and the
#      degradation own_cpus in `nn-admin status`; the partition undone: the
#      degradation leaves the status;
#  C2  the last CPU taken offline, then online again: no cpu_confined;
#  C3  systemd's own AllowedCPUs= on northnarrow.slice, set in a signed
#      window (a reservation the drop-in judge keeps), then reset: no
#      cpu_confined;
#  C4  the agent still active, same pid.
set -u
PATH=$PATH:/usr/sbin:/sbin
DET=/var/lib/northnarrow/detections/detections.jsonl
CG=/sys/fs/cgroup
PART=$CG/nn-cpu-check
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
measure() { printf 'MEASURE %s\n' "$*"; }
lines() { sudo sh -c 'wc -l < "$1"' _ "$1" 2>/dev/null </dev/null || echo 0; }
since() { sudo tail -n +"$(( $2 + 1 ))" "$1" 2>/dev/null </dev/null; }
confined() { since "$DET" "$1" | grep '"operation":"cpu_confined"'; }
put() { sudo sh -c 'echo "$1" > "$2"' _ "$1" "$2" </dev/null 2>&1; }
agent_pid() { sudo cat /run/northnarrow/agent.pid 2>/dev/null </dev/null; }
APID=$(agent_pid)
[[ -n $APID ]] || { bad "no agent running"; exit 1; }
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent </dev/null | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" </dev/null && { echo "$k"; break; }; done)
status() { sudo timeout 20 "$NNADMIN" status --key "$KEY" </dev/null 2>&1; }
affinity() { for t in /proc/"$APID"/task/*; do taskset -pc "${t##*/}" </dev/null 2>/dev/null | awk '{print $NF}'; done | sort | uniq -c | tr -s ' ' | tr '\n' ';'; }
# wait up to $2 s for `confined $1` to give a line
wait_record() { local n=$1 left=$2; while (( left > 0 )); do confined "$n" | grep -q . && return 0; sleep 1; left=$((left - 1)); done; return 1; }
NCPU=$(nproc --all)
ONLINE=$(cat /sys/devices/system/cpu/online)
echo "=== CASE $(date -u +%T) C0 info: rc=0 kernel $(uname -r) cpus $NCPU online $ONLINE agent $APID affinity $(affinity) subtree [$(cat $CG/cgroup.subtree_control)]"

# C0: the cpuset controller enabled at the root
n0=$(lines "$DET")
ENABLED=0
if ! grep -qw cpuset $CG/cgroup.subtree_control; then
    e=$(put +cpuset $CG/cgroup.subtree_control); rc=$?
    ENABLED=1
    sleep 12
    echo "=== CASE $(date -u +%T) C0 cpuset enabled at the root: rc=$rc $e subtree [$(cat $CG/cgroup.subtree_control)] affinity $(affinity)"
    [[ -z $(confined "$n0") ]] && pass "C0 the cpuset controller enabled above the agent: no cpu_confined" || bad "C0 a cpu_confined record at the controller's enable: $(confined "$n0" | head -1 | cut -c1-200)"
else
    measure "C0 the cpuset controller was already enabled at the root"
fi

# C1: a sibling partition
if (( NCPU < 2 )); then
    measure "C1 one CPU only: no partition can take any"
else
    n1=$(lines "$DET")
    sudo mkdir -p "$PART" </dev/null
    e1=$(put "1-$((NCPU - 1))" "$PART/cpuset.cpus"); r1=$?
    e2=$(put root "$PART/cpuset.cpus.partition"); r2=$?
    echo "=== CASE $(date -u +%T) C1 partition root: rc=$r1/$r2 $e1 $e2 state [$(cat $PART/cpuset.cpus.partition 2>&1)] root-effective $(cat $CG/cpuset.cpus.effective) affinity $(affinity)"
    if wait_record "$n1" 15; then
        r=$(confined "$n1" | head -1)
        sev=$(echo "$r" | grep -o '"severity":"[A-Za-z]*"' | head -1)
        why=$(echo "$r" | grep -oE '"(reasoning|response)":"[^"]*' | head -2 | cut -c1-260 | tr '\n' ' ')
        echo "    record: $sev $why"
        [[ $sev == *High* && $r == *nn-cpu-check* ]] && pass "C1 the agent confined by a sibling partition: signed cpu_confined High, the partition named" || bad "C1 the record: $sev / $why"
    else
        bad "C1 no cpu_confined record within 15 s of the partition"
    fi
    st=$(status)
    # the degradation's own line (the manifest's revisions quote it too)
    deg=$(printf '%s\n' "$st" | grep -E '^  - own_cpus: ' | head -1 | cut -c1-200)
    echo "    status: ${deg:-(no own_cpus line)}"
    [[ -n $deg ]] && pass "C1 nn-admin status shows the confinement" || bad "C1 nn-admin status does not show it"
    put member "$PART/cpuset.cpus.partition" >/dev/null
    sudo rmdir "$PART" </dev/null
    sleep 12
    st=$(status)
    echo "=== CASE $(date -u +%T) C1 partition undone: rc=0 affinity $(affinity)"
    printf '%s\n' "$st" | grep -qE '^  - own_cpus: ' && bad "C1 the confinement still in the status after the partition went" || pass "C1 the partition undone: the degradation left the status"
fi

# C2: a CPU offline and online again
LAST=$((NCPU - 1))
if (( NCPU >= 2 )) && [[ -e /sys/devices/system/cpu/cpu$LAST/online ]]; then
    n2=$(lines "$DET")
    e=$(put 0 /sys/devices/system/cpu/cpu$LAST/online); r=$?
    sleep 15
    echo "=== CASE $(date -u +%T) C2 cpu$LAST offline: rc=$r $e online $(cat /sys/devices/system/cpu/online) affinity $(affinity)"
    put 1 /sys/devices/system/cpu/cpu$LAST/online >/dev/null
    sleep 15
    echo "=== CASE $(date -u +%T) C2 cpu$LAST online: rc=0 online $(cat /sys/devices/system/cpu/online) affinity $(affinity)"
    [[ -z $(confined "$n2") ]] && pass "C2 a CPU offline and back: no cpu_confined" || bad "C2 a cpu_confined record at a hotplug: $(confined "$n2" | head -1 | cut -c1-200)"
else
    measure "C2 no CPU hotplug here"
fi

# C3: systemd's own AllowedCPUs= on the slice, in a signed window
if [[ -n $KEY ]] && (( NCPU >= 2 )); then
    n3=$(lines "$DET")
    sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 120 </dev/null >/dev/null 2>&1; w=$?
    WEND=$(( $(date +%s) + 120 ))
    o=$(sudo timeout 30 systemctl set-property --runtime northnarrow.slice AllowedCPUs=0-$((NCPU - 2)) </dev/null 2>&1); r=$?
    sleep 15
    echo "=== CASE $(date -u +%T) C3 slice AllowedCPUs=0-$((NCPU - 2)): rc=$w/$r ${o:0:80} slice cpuset.cpus [$(cat $CG/northnarrow.slice/cpuset.cpus 2>&1)] affinity $(affinity)"
    [[ -z $(confined "$n3") ]] && pass "C3 systemd's AllowedCPUs= on the slice: no cpu_confined" || bad "C3 a cpu_confined record for the slice's AllowedCPUs=: $(confined "$n3" | head -1 | cut -c1-200)"
    n3=$(lines "$DET")
    sudo timeout 30 systemctl set-property --runtime northnarrow.slice AllowedCPUs= </dev/null >/dev/null 2>&1
    # systemd may leave the slice's last value: the file put back inside the window
    put "" $CG/northnarrow.slice/cpuset.cpus >/dev/null
    sudo rm -f /run/systemd/system.control/northnarrow.slice.d/50-AllowedCPUs.conf </dev/null
    sudo timeout 30 systemctl daemon-reload </dev/null
    sleep 12
    now=$(affinity)
    echo "=== CASE $(date -u +%T) C3 slice AllowedCPUs reset: rc=0 slice cpuset.cpus [$(cat $CG/northnarrow.slice/cpuset.cpus 2>&1)] affinity $now"
    if [[ $now == *" $(cat /sys/devices/system/cpu/online);" && $now != *";"*";"* ]]; then
        [[ -z $(confined "$n3") ]] && pass "C3 the reset gave every CPU back: no cpu_confined" || bad "C3 a cpu_confined record after the reset gave every CPU back: $(confined "$n3" | head -1 | cut -c1-200)"
    else
        # measured on 5.15: the kernel left the threads' masks narrowed when
        # the slice's cpuset went: the agent does run on fewer CPUs
        confined "$n3" | grep -q . && measure "C3 the kernel left the agent's threads on $now after the reset: signed cpu_confined (true)" || bad "C3 the agent left on $now after the reset, no cpu_confined"
    fi
    # the window's end: what follows runs outside it
    while (( $(date +%s) <= WEND )); do sleep 2; done
else
    measure "C3 no admin key (or one CPU): no window"
fi

if (( ENABLED )); then
    put -cpuset $CG/cgroup.subtree_control >/dev/null || measure "C0 the cpuset controller left enabled at the root (in use)"
fi
systemctl is-active --quiet northnarrow-agent && [[ $(agent_pid) == "$APID" ]] && pass "C4 the agent active, same pid" || bad "C4 the agent restarted or stopped"
# measured, not a verdict: the watch's own journal lines of this run
sudo journalctl --namespace=northnarrow -b -u northnarrow-agent --no-pager </dev/null 2>/dev/null | grep 'own CPUs' | cut -c1-200 | sed 's/^/    journal: /' | tail -n 12
echo "=== CASE $(date -u +%T) C-END: rc=$fail"
exit $fail
