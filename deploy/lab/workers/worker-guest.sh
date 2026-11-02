#!/usr/bin/env bash
# R14a (plan §3.1, §3.5): the agent's workers on an nn-lab guest — run as
# root ON THE GUEST by worker-lab.sh, against the installed agent (a lab
# build: the debug-trigger worker faults). Our own lab guests only.
#
# usage: worker-guest.sh roles|faults|parse <out-dir>
#
#   roles  — the parse worker as the kernel sees it: its account, no
#            capability, no_new_privs, its seccomp filter, its descriptors,
#            its command line and image (the agent's); PROTECTED_PIDS: the
#            agent and the watchdog 0x03 (protected, exempt), the worker
#            0x02 (protected, not exempt); a root `kill -9` of the worker
#            refused; then the roles' meaning in the BPF LSM hooks, on a
#            root shell registered with each role in turn: no role and the
#            worker's role are denied the agent's key and a signal to the
#            agent, the agent's role is not; the manifest's worker entry
#            (state, the sandbox level, the kernel's Landlock ABI).
#   faults — a worker crash, a hang, a kill by the core: each a new worker,
#            the agent's pid and its unit's restarts unchanged; a crash loop:
#            disabled after 5 failures in a row, signed (a degradation, a
#            capability_manifest_change), then ready again once a worker
#            stays up.
#   parse  — (R14b) DNS names while the worker serves, and none from the
#            core while it is disabled: no parsing in the core.
# Each check prints PASS or FAIL and lands in <out-dir>/steps.tsv; the exit
# status is the number of FAILs.
set -u
PHASE=${1:?roles|faults|parse}
OUT=${2:?out dir}
mkdir -p "$OUT"
RUN=/run/northnarrow
PINS=/sys/fs/bpf/northnarrow/PROTECTED_PIDS
KEY=
for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do [ -r "$k" ] && { KEY=$k; break; }; done
NNADMIN=/usr/local/bin/nn-admin
fails=0
TSV=$OUT/steps.tsv
[ -f "$TSV" ] || printf 'phase\tstep\tat\tresult\n' > "$TSV"
note() { printf '%s\t%s\t%s\t%s\n' "$PHASE" "$1" "$(date -u +%FT%T.%3NZ)" "$2" >> "$TSV"; }
pass() { echo "PASS $1: $2"; note "$1" "ok: $2"; }
bad() { echo "FAIL $1: $2"; note "$1" "FAIL: $2"; fails=$((fails + 1)); }
check() { # name condition-description command...
    local n=$1 d=$2; shift 2
    if "$@"; then pass "$n" "$d"; else bad "$n" "$d"; fi
}
agent() { cat "$RUN/agent.pid" 2>/dev/null; }
restarts() { systemctl show -p NRestarts --value northnarrow-agent 2>/dev/null; }
# the parse worker: the agent's child named nn-worker-parse
worker() {
    local a t
    a=$(agent) || return 1
    [ -n "$a" ] || return 1
    for t in /proc/[0-9]*; do
        [ "$(awk '{print $4}' "$t/stat" 2>/dev/null)" = "$a" ] || continue
        [ "$(cat "$t/comm" 2>/dev/null)" = nn-worker-parse ] && { echo "${t#/proc/}"; return 0; }
    done
    return 1
}
wait_worker() { # within-seconds [a pid it must not be]
    local end=$((SECONDS + $1)) w
    while ((SECONDS < end)); do
        w=$(worker) && [ "$w" != "${2:-}" ] && { echo "$w"; return 0; }
        sleep 0.2
    done
    return 1
}
le() { local p=$1; printf '%02x %02x %02x %02x' $((p & 255)) $(((p >> 8) & 255)) $(((p >> 16) & 255)) $(((p >> 24) & 255)); }
# the PROTECTED_PIDS value of a pid (two hex digits), empty when absent
role_of() { bpftool map lookup pinned "$PINS" key hex $(le "$1") 2>/dev/null | grep -o 'value: *[0-9a-f]*' | grep -o '[0-9a-f]*$'; }
status_field() { awk -v k="$2:" '$1 == k {print $2}' "/proc/$1/status" 2>/dev/null; }
caps_json() { "$NNADMIN" capabilities --key "$KEY" --json 2>/dev/null; }
worker_entry() { # field of the manifest's parse worker entry
    caps_json | python3 -I -c 'import json, sys
m = json.load(sys.stdin)["manifest"]
w = [x for x in m.get("workers", []) if x["kind"] == "parse"]
v = w[0] if w else {}
for k in sys.argv[1].split("."):
    v = v.get(k) if isinstance(v, dict) else None
print(json.dumps(v) if isinstance(v, (dict, list, bool)) or v is None else v)' "$1"
}
journal_since() { journalctl --namespace=northnarrow -u northnarrow-agent --since "$1" -q --no-pager 2>/dev/null; }

[ -n "$KEY" ] || { bad prereq "no lab admin key"; exit 1; }
systemctl is-active --quiet northnarrow-agent || { bad prereq "the agent is not active"; exit 1; }
/usr/local/bin/northnarrow-agent --build-features 2>/dev/null | grep -q debug-trigger \
    || { bad prereq "not a lab build (no debug-trigger)"; exit 1; }
A0=$(agent); R0=$(restarts)
echo "agent $A0, restarts $R0, kernel $(uname -r), lsm $(cat /sys/kernel/security/lsm)"

case "$PHASE" in
roles)
    W=$(wait_worker 30) || { bad worker "no parse worker within 30 s"; exit 1; }
    pass worker "pid $W, $(tr '\0' ' ' < "/proc/$W/cmdline")"
    check account "runs as northnarrow-worker" test "$(stat -c %U "/proc/$W")" = northnarrow-worker
    check nnp "NoNewPrivs 1" test "$(status_field "$W" NoNewPrivs)" = 1
    check seccomp "Seccomp 2 (filter)" test "$(status_field "$W" Seccomp)" = 2
    check capeff "CapEff 0" test "$(status_field "$W" CapEff)" = 0000000000000000
    check capprm "CapPrm 0" test "$(status_field "$W" CapPrm)" = 0000000000000000
    check capamb "CapAmb 0" test "$(status_field "$W" CapAmb)" = 0000000000000000
    echo "CapBnd $(status_field "$W" CapBnd) (kept: no CAP_SETPCAP to drop it; no_new_privs makes it moot)"
    check groups "no supplementary group" test -z "$(status_field "$W" Groups)"
    check cmdline "northnarrow-agent --worker parse --ipc-fd 3" \
        test "$(tr '\0' ' ' < "/proc/$W/cmdline")" = "northnarrow-agent --worker parse --ipc-fd 3 "
    check image "the agent's own image" test "$(readlink "/proc/$W/exe")" = "$(readlink "/proc/$A0/exe")"
    nfd=$(ls "/proc/$W/fd" | wc -l)
    check fds "stdio and its channel only ($nfd)" test "$nfd" -le 4
    check core "not dumpable (no core)" test "$(awk '/^Max core file size/ {print $5}' "/proc/$W/limits")" = 0
    # review of #480, F12: the OOM killer's first, the scheduler's last. (F4,
    # its stderr a pipe the agent reads, is the harness's check: a root
    # shell may not read a protected worker's descriptor links here.)
    check oom "oom_score_adj 1000" test "$(cat "/proc/$W/oom_score_adj")" = 1000
    check nice "nice 10" test "$(sed 's/.*) //' "/proc/$W/stat" | awk '{print $17}')" = 10
    WD=$(cat "$RUN/watchdog.pid" 2>/dev/null)
    check role-agent "agent 0x03 (protected, exempt)" test "$(role_of "$A0")" = 03
    [ -n "$WD" ] && check role-watchdog "watchdog 0x03" test "$(role_of "$WD")" = 03
    check role-worker "worker 0x02 (protected, not exempt)" test "$(role_of "$W")" = 02
    # Each attempt is a disposable child of its own, the actor the agent
    # answers (a refused signal or open is an anti-tamper denial: COMBAT,
    # NEUTRALIZE kills the actor), never this script. Exit 0: it went
    # through; 1: refused; killed: refused, and the actor neutralized.
    attempt() { # <out-name> <bash code>; prints went|refused|refused+killed
        bash -c "$2" > /dev/null 2>&1
        local rc=$?
        case $rc in
            0) echo went ;;
            1) echo refused ;;
            137) echo refused+killed ;;
            *) echo "rc=$rc" ;;
        esac
    }
    got=$(attempt kill-worker "kill -9 $W 2>/dev/null && exit 0 || exit 1")
    check kill-worker "a root kill -9 of the worker: $got (task_kill: protected)" test "${got%%+*}" = refused
    sleep 2
    check worker-alive "the worker lives on" test "$(worker)" = "$W"
    # The roles' meaning in the hooks: a root shell registered with each
    # role in turn (a lab build: the BPF guard observes, bpftool may write
    # the map) reads the agent's key, or signals the agent (SIGCONT) — a
    # bash builtin each time, so the registered pid is the one that acts.
    role_attempt() { # <role|none> <what> <bash code>
        local role=$1 fifo sp rc
        fifo=$(mktemp -u /tmp/nn-roles.XXXXXX); mkfifo -m 600 "$fifo"
        bash -c "read _ < '$fifo'; $3" > /dev/null 2>&1 &
        sp=$!
        [ "$role" = none ] || bpftool map update pinned "$PINS" key hex $(le "$sp") value hex "$role"
        echo go > "$fifo"
        wait "$sp"; rc=$?
        [ "$role" = none ] || bpftool map delete pinned "$PINS" key hex $(le "$sp") 2>/dev/null
        rm -f "$fifo"
        case $rc in 0) echo went ;; 1) echo refused ;; 137) echo refused+killed ;; *) echo "rc=$rc" ;; esac
    }
    for role in none 02 03; do
        r=$(role_attempt "$role" read "if read -r -n1 _x < /etc/northnarrow/agent.sig.key; then exit 0; else exit 1; fi")
        s=$(role_attempt "$role" signal "kill -CONT $A0 2>/dev/null && exit 0 || exit 1")
        echo "role $role: read the key $r, signal the agent $s" | tee "$OUT/role-$role.txt"
        case "$role" in
            03) check "role-$role" "role 03 (the agent's): read $r, signal $s" test "$r $s" = "went went" ;;
            *) check "role-$role" "role $role: read $r, signal $s" test "${r%%+*} ${s%%+*}" = "refused refused" ;;
        esac
        sleep 2
    done
    # the denials above put the agent in COMBAT (NEUTRALIZE): released with
    # the lab's key, as an operator would
    "$NNADMIN" unlock --key "$KEY" > "$OUT/unlock.txt" 2>&1 || true
    check manifest-state "the manifest's parse worker: ready" test "$(worker_entry state)" = ready
    check manifest-seccomp "its sandbox: seccomp" test "$(worker_entry sandbox.seccomp)" = true
    check manifest-uid "its sandbox: the worker's uid" test "$(worker_entry sandbox.uid)" = "$(id -u northnarrow-worker)"
    echo "manifest: kernel_landlock_abi $(worker_entry kernel_landlock_abi), worker: landlock $(worker_entry sandbox.landlock_abi) $(worker_entry sandbox.landlock) fs $(worker_entry sandbox.fs_denied) net $(worker_entry sandbox.net_denied) scope $(worker_entry sandbox.scoped)"
    check manifest-abi "the declared ABI is the kernel's" test "$(worker_entry kernel_landlock_abi)" = "$(worker_entry sandbox.landlock_abi)"
    caps_json > "$OUT/caps-roles.json"
    ;;
faults)
    T0=$(date '+%F %T')
    W=$(wait_worker 30) || { bad worker "no parse worker within 30 s"; exit 1; }
    for f in crash hang kill; do
        touch "$RUN/debug-worker-$f"
        if W2=$(wait_worker 20 "$W"); then pass "$f" "worker $W → $W2"; W=$W2
        else bad "$f" "no new worker within 20 s"; W=$(worker); fi
    done
    sleep 2
    j=$(journal_since "$T0")
    check crash-seen "the crash seen (SIGABRT)" grep -q 'SIGABRT' <<< "$j"
    check hang-seen "the hang seen (no answer to debug_hang)" grep -q 'no answer to debug_hang' <<< "$j"
    check kill-seen "the core's kill seen" grep -q 'killed by the core' <<< "$j"
    check agent-same "the agent's pid unchanged" test "$(agent)" = "$A0"
    # a crash loop: disabled, signed; then ready again
    T1=$(date '+%F %T')
    touch "$RUN/debug-worker-crashloop"
    end=$((SECONDS + 120)); st=
    while ((SECONDS < end)); do st=$(worker_entry state); [ "$st" = disabled ] && break; sleep 2; done
    check disabled "the crash loop disabled the kind ($st after $((SECONDS - end + 120)) s)" test "$st" = disabled
    check disabled-why "why it is disabled" test -n "$(worker_entry why)"
    "$NNADMIN" status --key "$KEY" > "$OUT/status-disabled.txt" 2>&1
    check degradation "a signed degradation: worker_parse disabled" grep -q 'worker_parse: disabled' "$OUT/status-disabled.txt"
    rm -f "$RUN/debug-worker-crashloop"
    end=$((SECONDS + 180)); st=
    while ((SECONDS < end)); do st=$(worker_entry state); [ "$st" = ready ] && break; sleep 3; done
    check enabled "ready again once a worker stayed up ($st)" test "$st" = ready
    sleep 65   # the manifest's change rows: at most one a minute for a better state
    grep -a '"op":"capability_manifest_change"' /etc/northnarrow/audit.log | grep -a 'worker parse' > "$OUT/manifest-rows.jsonl"
    check row-disabled "a signed capability_manifest_change to disabled" grep -q 'worker parse: [a-z]* → disabled' "$OUT/manifest-rows.jsonl"
    check row-ready "and back to ready" grep -q 'worker parse: [a-z]* → ready' "$OUT/manifest-rows.jsonl"
    check agent-same2 "the agent's pid unchanged through the loop" test "$(agent)" = "$A0"
    check restarts "the unit's restarts unchanged" test "$(restarts)" = "$R0"
    journal_since "$T1" | grep -E 'worker|disabled' | tail -40 > "$OUT/journal-loop.txt"
    ;;
parse)
    # R14b: the DNS pump's names are the parse worker's. The telemetry
    # probe's DNS round (R13) is seen only when its name was decoded: with
    # the worker disabled the core leaves the names undecoded (a WARN), the
    # probe finds a gap; with the worker back the probe sees it again.
    probe() { # the manifest's dns_query probe word
        caps_json | python3 -I -c 'import json, sys
m = json.load(sys.stdin)["manifest"]
s = [x for x in m.get("sources", []) if x["source"] == "dns_query"]
print(s[0].get("probe") if s else "none")'
    }
    query() { # a DNS query to the local stub from a python3 of its own
        python3 -I -c 'import os, socket, struct, sys
name = sys.argv[1]
q = struct.pack(">HHHHHH", os.getpid() & 0xFFFF, 0x0100, 1, 0, 0, 0)
q += b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
s.sendto(q, ("127.0.0.53", 53))
try:
    s.recv(512)
except OSError:
    pass' "$1" > /dev/null 2>&1
    }
    W=$(wait_worker 30) || { bad worker "no parse worker within 30 s"; exit 1; }
    end=$((SECONDS + 200)); p=
    while ((SECONDS < end)); do p=$(probe); [ "$p" = seen ] && break; sleep 5; done
    check probe-seen "the DNS probe's name decoded and seen ($p)" test "$p" = seen
    T1=$(date '+%F %T')
    touch "$RUN/debug-worker-crashloop"
    end=$((SECONDS + 120)); st=
    while ((SECONDS < end)); do st=$(worker_entry state); [ "$st" = disabled ] && break; sleep 2; done
    check disabled "the worker disabled ($st)" test "$st" = disabled
    for i in $(seq 1 30); do query "nn-r14b-$i-$$.invalid"; done
    sleep 3
    j=$(journal_since "$T1")
    check unparsed "names left without a decode, said (no parsing in the core)" \
        grep -q 'DNS names left without a decode' <<< "$j"
    end=$((SECONDS + 200)); p=
    while ((SECONDS < end)); do p=$(probe); [ "$p" = gap ] && break; sleep 5; done
    check probe-gap "the DNS probe finds a gap while the worker is disabled ($p)" test "$p" = gap
    rm -f "$RUN/debug-worker-crashloop"
    end=$((SECONDS + 180)); st=
    while ((SECONDS < end)); do st=$(worker_entry state); [ "$st" = ready ] && break; sleep 3; done
    check enabled "the worker ready again ($st)" test "$st" = ready
    end=$((SECONDS + 200)); p=
    while ((SECONDS < end)); do p=$(probe); [ "$p" = seen ] && break; sleep 5; done
    check probe-back "the DNS probe sees the names again ($p)" test "$p" = seen
    check agent-same "the agent's pid unchanged" test "$(agent)" = "$A0"
    journal_since "$T1" | grep -E 'without a decode|worker' | tail -30 > "$OUT/journal-parse.txt"
    ;;
*) echo "no phase $PHASE" >&2; exit 2 ;;
esac
echo "worker-guest $PHASE: $fails FAIL(s)"
exit "$fails"
