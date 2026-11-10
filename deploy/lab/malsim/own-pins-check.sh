#!/usr/bin/env bash
# Lot 301 — every BPF object the agent pins is its own to the BPF guard
# (`nn-lab.sh own-pins-check`; run by the lab user from the synced tree,
# sudo inside, the lab key with the trusted-installer role). On a LAB GUEST
# ONLY. The guard is put in enforce mode for the run (the lab build
# observes: NN_BPF_DEFENSE_ENFORCE=1 in the manager's environment, the agent
# restarted in a window) and put back after, unless KEEP_ENFORCE=1.
#
#  (O2 runs first when the start named the tracker's links, O1 after.)
#  O1  every link on the host taken by id from root outside a window
#      (BPF_LINK_GET_FD_BY_ID): none that runs one of the agent's programs
#      (/run/northnarrow/bpf-own-ids) is given — the start-in-cgroup
#      tracker's among them (lot 300: pinned beside the pin root and
#      closed, they were given); a handle given on one is tried with
#      BPF_LINK_DETACH (measured);
#  O2  the tracker's links, by the ids the start registered (its journal:
#      "the links pinned in this directory registered", the tracker's
#      directory): a handle by id and `bpftool link detach id` refused with
#      EPERM, each refusal signed (a `bpf_link` detection per attempt);
#  O3  the tracker still marks: a root process that moves itself into a
#      throwaway cgroup is marked "moved" (its maps read in a window);
#  O4  the agent is the same process, no `bpf_link_missing` signed.
set -u
PATH=$PATH:/usr/sbin:/sbin
HERE=$(cd "$(dirname "$0")" && pwd)
DET=/var/lib/northnarrow/detections/detections.jsonl
AUDIT=/etc/northnarrow/audit.log
PROBE="python3 -I $HERE/bpf-probe.py"
MARKS="sudo python3 -I $HERE/cgroup-marks.py"
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
measure() { printf 'MEASURE %s\n' "$*"; }
lines() { sudo sh -c 'wc -l < "$1"' _ "$1" 2>/dev/null || echo 0; }
since() { sudo tail -n +"$(( $2 + 1 ))" "$1" 2>/dev/null; }
WIN_END=0
window() { WIN_END=$(( $(date +%s) + ${1:-30} )); sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs "${1:-30}" >/dev/null 2>&1; }
no_window() { while (( $(date +%s) <= WIN_END + 2 )); do sleep 1; done; }
agent_pid() { sudo cat /run/northnarrow/agent.pid 2>/dev/null; }
# the agent's own events (journald's attribution, the message from its
# start: lab-records.py), never a grep of text another user can make it log
event() {   # <pid> <level> <message prefix>
    sudo journalctl --namespace=northnarrow -u northnarrow-agent _PID="$1" --no-pager -o json 2>/dev/null \
        | python3 -I "$HERE/../lib/lab-records.py" journal northnarrow-agent.service "$1" "$2" "$3"
}
mode_of() { event "$1" INFO "BPF self-defence: own objects registered " | tail -1 | grep -oE 'mode="[a-z]+"$'; }
enforcing() { [[ $(mode_of "$(agent_pid)") == 'mode="enforce"' ]]; }
restart_agent() {
    local old new i
    window 120 || { bad "trusted-installer-grant"; return 1; }
    old=$(agent_pid)
    sudo systemctl kill --signal=SIGTERM northnarrow-agent
    for i in $(seq 1 60); do
        sleep 1
        new=$(agent_pid)
        [[ -n $new && $new != "$old" ]] && sudo kill -0 "$new" 2>/dev/null && break
    done
    sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl reset-failed northnarrow-agent; sudo systemctl start northnarrow-agent; }
    sleep 15; WIN_END=0
}
echo "nn-admin: $NNADMIN  key: $KEY  kernel $(uname -r)"
sudo systemctl is-active --quiet northnarrow-agent || { sudo systemctl start northnarrow-agent; sleep 15; }
SET=0
if ! enforcing; then
    sudo systemctl set-environment NN_BPF_DEFENSE_ENFORCE=1 && SET=1 && restart_agent
fi
A=$(agent_pid)
M=$(mode_of "$A")
enforcing && pass "the guard enforces (agent $A)" || bad "the guard does not enforce (agent $A: ${M:-no registration line})"
TDIR=$(sudo sh -c "ls -d /sys/fs/bpf/northnarrow-cgroup-join-v* 2>/dev/null" | head -1)
echo "tracker directory: ${TDIR:-none}; its link pins: $(sudo sh -c "ls $TDIR 2>/dev/null" | grep -c '^link_')"
REG=$(event "$A" INFO "BPF self-defence: the links pinned in this directory registered as the agent's own " | sed 's/^.*registered as the agent.s own //')
echo "$REG" | sed 's/^/    registered: /'
TIDS=$(echo "$REG" | grep -F "dir=$TDIR " | grep -oE 'links=\[[0-9, ]*\]' | tr -dc '0-9 ,' | tr ',' ' ')
A0=$(lines "$AUDIT")

o1() {
    echo "== O1. every link by id, outside a window"
    window 30
    OWN=$(sudo awk '$1 ~ /^[0-9]+$/ {print $1 ":" $2}' /run/northnarrow/bpf-own-ids 2>/dev/null)
    no_window
    echo "    the agent's programs: $(echo "$OWN" | grep -c .) ($(echo "$OWN" | grep -c ':cgroup_join_') of the tracker's)"
    name_of() { echo "$OWN" | awk -F: -v p="$1" '$1 == p {print $2; exit}'; }
    o=$(sudo $PROBE link-ids)
    [[ $o == OK* ]] || bad "link-ids: $o"
    given=0; refused=0; own_given=0; tracker_given=""
    for id in ${o#OK}; do
        r=$(sudo $PROBE link-fd-by-id "$id")
        case "$r" in
            "ERR EPERM"*) refused=$((refused + 1)) ;;
            OK*)
                given=$((given + 1))
                p=$(sed -n 's/^OK fd [0-9]* prog \([0-9]*\).*/\1/p' <<<"$r")
                n=$(name_of "$p")
                if [[ -n $n ]]; then
                    own_given=$((own_given + 1))
                    bad "O1 link $id runs the agent's program $p ($n): a handle given to root"
                    if [[ $n == cgroup_join_* ]]; then
                        tracker_given="$tracker_given $id"
                        measure "O1 detach of the tracker's link $id (program $n): $(sudo $PROBE link-fd-by-id "$id" --detach)"
                    fi
                fi ;;
            *) measure "O1 link $id: $r" ;;
        esac
    done
    measure "O1 links on the host: $((given + refused)); refused (EPERM) $refused, given $given (of the agent's: $own_given)"
    (( own_given == 0 && refused > 0 )) && pass "O1 no link of the agent's is given by id ($refused refused)"
}

o2() {
    echo "== O2. the tracker's links: handle and detach refused, signed"
    n1=$(lines "$DET")
    if [[ -z ${TIDS// /} ]]; then
        bad "O2 no tracker link id (no registration line for $TDIR)"
    else
        nt=0
        for id in $TIDS; do
            nt=$((nt + 1))
            r=$(sudo $PROBE link-fd-by-id "$id" --detach)
            [[ $r == "ERR EPERM"* ]] && pass "O2 link $id: handle by id refused ($r)" || bad "O2 link $id: $r"
            b=$(sudo bpftool link detach id "$id" 2>&1); rc=$?
            (( rc != 0 )) && grep -q 'Operation not permitted' <<<"$b" && pass "O2 link $id: bpftool link detach refused" || bad "O2 link $id: bpftool link detach rc $rc: $b"
        done
        sleep 3
        nl=$(since "$DET" "$n1" | grep -c '"operation":"bpf_link"')
        measure "O2 bpf_link records of these attempts: $nl ($(since "$DET" "$n1" | grep '"operation":"bpf_link"' | grep -o '"severity":"[A-Za-z]*"' | sort | uniq -c | tr -s ' ' | tr '\n' ' '))"
        # the detection names the caller, not the link: each attempt above is
        # a process of its own (no dedup between them), two per link
        (( nl >= 2 * nt )) && pass "O2 every refusal signed ($nl bpf_link records for $((2 * nt)) refused attempts)" || bad "O2 $nl bpf_link records for $((2 * nt)) refused attempts"
    fi
}

# the tracker's links refused one by one first (O2), the sweep of every
# link after (O1: a refusal each of the agent's ~70, within NN-L-AT-001's
# per-uid budget of 100 records); without the start's registration line (a
# build before lot 301) the sweep finds them by their programs, first
if [[ -n ${TIDS// /} ]]; then
    o2; o1
else
    o1; TIDS=$tracker_given; o2
fi

echo "== O3. the tracker still marks"
CG=/sys/fs/cgroup/nn301-own-pins
sudo mkdir -p "$CG"
sudo bash -c "echo \$BASHPID > $CG/cgroup.procs && echo \$BASHPID > /tmp/nn301.pid && exec sleep 300" >/dev/null 2>&1 &
for _ in $(seq 1 20); do sudo test -s /tmp/nn301.pid && break; sleep 0.2; done
P=$(sudo cat /tmp/nn301.pid 2>/dev/null)
window 20
m=$($MARKS mark "$P" 2>&1)
no_window
grep -q "^$P moved" <<<"$m" && pass "O3 a root process that moved itself into a cgroup: marked ($m)" || bad "O3 mark of $P: [$m]"
sudo kill "$P" 2>/dev/null; sleep 0.5; sudo rmdir "$CG" 2>/dev/null; sudo rm -f /tmp/nn301.pid

echo "== O4. the agent untouched"
[[ $(agent_pid) == "$A" ]] && sudo kill -0 "$A" 2>/dev/null && pass "O4 the agent is the same process ($A)" || bad "O4 the agent changed: $A -> $(agent_pid)"
nm=$(since "$AUDIT" "$A0" | grep -c '"op":"bpf_link_missing"')
(( nm == 0 )) && pass "O4 no bpf_link_missing signed" || bad "O4 bpf_link_missing signed: $nm"
gone=$(event "$A" ERROR "ANTI-TAMPER: one of the agent's own BPF links is GONE" | grep -c .)
(( gone == 0 )) && pass "O4 the link self-check found every link" || bad "O4 the link self-check: $gone GONE line(s)"

if (( SET )) && [[ ${KEEP_ENFORCE:-0} != 1 ]]; then
    sudo systemctl unset-environment NN_BPF_DEFENSE_ENFORCE; restart_agent
    echo "guard back in the lab build's mode: $(mode_of "$(agent_pid)")"
fi
(( fail == 0 )) && echo "own-pins-check: PASS" || echo "own-pins-check: FAIL"
exit $fail
