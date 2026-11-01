#!/usr/bin/env bash
# R14c (lot 272, plan §3.1, §3.2): what each of the agent's threads asks of
# its capabilities, measured on an nn-lab guest (the provisioning marker),
# as root. Our own guests only.
#
#   start  <dir>        kprobe + kretprobe on cap_capable(), for the tasks
#                       whose name is the agent's (nn-*, tokio-runtime-*,
#                       northnarrow-ag*), and their entries into the calls
#                       the unit's SystemCallFilter refuses and the decision
#                       thread's filter refuses (that thread's), streamed to
#                       <dir>/trace.raw
#   stop   <dir>        the probes removed; <dir>/checks.tsv: per thread
#                       group (the name, a trailing number as *), per
#                       capability, audited or a probe (CAP_OPT_NOAUDIT),
#                       how many checks were granted and how many refused;
#                       <dir>/calls.tsv: per thread group, per refused call,
#                       how many times it was made (0 lines: none);
#                       <dir>/overrun: events the trace buffer lost
#   census <dir> <tag>  the running agent's threads: name, CapEff, CapPrm,
#                       Seccomp, NoNewPrivs (<dir>/census-<tag>.tsv)
#
# A check refused on a thread is an action that thread could not take with
# its capabilities (or a probe the kernel makes and does without: noaudit).
# Exit: 0 done, 1 a step failed, 2 usage or not a lab guest.
set -u -o pipefail
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export LC_ALL=C
MARKER=/var/lib/nn-lab-provisioned
die() { echo "thread-caps: $*" >&2; exit 2; }
[[ -e $MARKER ]] || die "not an nn-lab guest ($MARKER missing)"
[[ $(id -u) == 0 ]] || die "run as root"
CMD=${1:-}; DIR=${2:-}
[[ -n $CMD && -n $DIR ]] || die "usage: thread-caps.sh start|stop|census <dir> [tag]"
mkdir -p "$DIR"

T=/sys/kernel/tracing
[[ -e $T/kprobe_events ]] || T=/sys/kernel/debug/tracing
if [[ ! -e $T/kprobe_events ]]; then
    mount -t tracefs nodev /sys/kernel/tracing 2>/dev/null
    T=/sys/kernel/tracing
fi
[[ -e $T/kprobe_events ]] || die "no tracefs"
FILTER='comm ~ "nn-*" || comm ~ "tokio-runtime*" || comm ~ "northnarrow-ag*"'
# x86_64 numbers. The unit's denylist (SystemCallFilter=~…): ptrace 101,
# process_vm_writev 311, kexec_load 246, kexec_file_load 320, init_module
# 175, finit_module 313, delete_module 176, swapon 167, swapoff 168, reboot
# 169, mount 165, umount2 166, pivot_root 155, userfaultfd 323,
# open_by_handle_at 304. The decision thread's: capset 126, execve 59,
# execveat 322, bpf 321, ptrace 101, process_vm_readv 310,
# process_vm_writev 311, pidfd_getfd 438.
UNIT_IDS="101 311 246 320 175 313 176 167 168 169 165 166 155 323 304"
DECISION_IDS="126 59 322 321 101 310 311 438"
ors() { local f= i; for i in "$@"; do f="$f${f:+ || }id == $i"; done; echo "$f"; }
CALLS="(($FILTER) && ($(ors $UNIT_IDS))) || (comm == \"nn-decision\" && ($(ors $DECISION_IDS)))"

# x86_64: cap_capable(cred, ns, cap, opts) — cap in %dx, opts in %cx
probes_off() {
    echo 0 > "$T/events/raw_syscalls/sys_enter/enable"
    echo 0 > "$T/events/raw_syscalls/sys_enter/filter"
    if [[ -e $T/events/nncap/enable ]]; then
        echo 0 > "$T/events/nncap/enable"
        echo '-:nncap/c' >> "$T/kprobe_events"
        echo '-:nncap/r' >> "$T/kprobe_events"
    fi
}

case "$CMD" in
start)
    [[ $(uname -m) == x86_64 ]] || die "x86_64 only (the probe's registers)"
    grep -qw cap_capable /proc/kallsyms || die "cap_capable not in kallsyms"
    probes_off
    echo 8192 > "$T/buffer_size_kb"
    echo > "$T/trace"
    # the name from the event itself ($comm): the trace's own pid → name
    # cache forgets names under an exec storm
    echo 'p:nncap/c cap_capable cap=%dx:s32 opts=%cx:u32 comm=$comm' >> "$T/kprobe_events" || exit 1
    echo 'r:nncap/r cap_capable ret=$retval:s32' >> "$T/kprobe_events" || exit 1
    echo "$FILTER" > "$T/events/nncap/c/filter" || exit 1
    echo "$FILTER" > "$T/events/nncap/r/filter" || exit 1
    echo "$CALLS" > "$T/events/raw_syscalls/sys_enter/filter" || exit 1
    : > "$DIR/trace.raw"
    nohup cat "$T/trace_pipe" >> "$DIR/trace.raw" 2>/dev/null &
    echo $! > "$DIR/reader.pid"
    echo 1 > "$T/events/nncap/enable" || exit 1
    echo 1 > "$T/events/raw_syscalls/sys_enter/enable" || exit 1
    date -u +%FT%TZ > "$DIR/started"
    echo "tracing cap_capable for the agent's threads into $DIR/trace.raw (reader $(cat "$DIR/reader.pid"))"
    ;;
stop)
    [[ -e $T/events/nncap/enable ]] && echo 0 > "$T/events/nncap/enable"
    echo 0 > "$T/events/raw_syscalls/sys_enter/enable"
    sleep 1
    # the reader started above, by its pid, only if it is still that cat
    if [[ -s $DIR/reader.pid ]]; then
        rp=$(cat "$DIR/reader.pid")
        if [[ -r /proc/$rp/cmdline ]] && tr '\0' ' ' < "/proc/$rp/cmdline" | grep -q "trace_pipe"; then
            kill "$rp"
        fi
    fi
    grep -h overrun "$T"/per_cpu/cpu*/stats 2>/dev/null | awk '{s+=$2} END {print s+0}' > "$DIR/overrun"
    probes_off
    date -u +%FT%TZ > "$DIR/stopped"
    awk '
        BEGIN {
            split("CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID KILL SETGID SETUID SETPCAP LINUX_IMMUTABLE NET_BIND_SERVICE NET_BROADCAST NET_ADMIN NET_RAW IPC_LOCK IPC_OWNER SYS_MODULE SYS_RAWIO SYS_CHROOT SYS_PTRACE SYS_PACCT SYS_ADMIN SYS_BOOT SYS_NICE SYS_RESOURCE SYS_TIME SYS_TTY_CONFIG MKNOD LEASE AUDIT_WRITE AUDIT_CONTROL SETFCAP MAC_OVERRIDE MAC_ADMIN SYSLOG WAKE_ALARM BLOCK_SUSPEND AUDIT_READ PERFMON BPF CHECKPOINT_RESTORE", n, " ")
            for (i = 1; i <= 41; i++) name[i - 1] = n[i]
        }
        function tid_of(f,   i) {
            i = match(f, /-[0-9]+$/)
            TID = substr(f, i + 1)
        }
        / c: \(cap_capable/ {
            tid_of($1)
            cap = ""; opts = 0; WHO = "?"
            for (i = 2; i <= NF; i++) {
                if ($i ~ /^cap=/) cap = substr($i, 5)
                if ($i ~ /^opts=/) opts = substr($i, 6)
                if ($i ~ /^comm=/) { WHO = substr($i, 6); gsub(/"/, "", WHO) }
            }
            sub(/-[0-9]+$/, "-*", WHO)
            # CAP_OPT_NOAUDIT is bit 1 (0x2)
            na = (int(opts / 2) % 2) ? "probe" : "audited"
            pend[TID] = WHO "\t" ((cap in name) ? name[cap] : cap) "\t" na
            next
        }
        / r: \(/ {
            tid_of($1)
            if (!(TID in pend)) next
            ret = ""
            for (i = 2; i <= NF; i++) if ($i ~ /^ret=/) ret = substr($i, 5)
            k = pend[TID]; delete pend[TID]; seen[k] = 1
            if (ret == "0") g[k]++; else d[k]++
        }
        END { for (k in seen) printf "%s\t%d\t%d\n", k, g[k], d[k] }
    ' "$DIR/trace.raw" | sort > "$DIR/checks.tsv"
    { printf 'thread\tcapability\tkind\tgranted\trefused\n'; cat "$DIR/checks.tsv"; } > "$DIR/checks.tsv.new"
    mv "$DIR/checks.tsv.new" "$DIR/checks.tsv"
    # sys_enter: "NR <id> (args)"; the thread's name from the trace's cache
    awk '
        / sys_enter: NR / {
            f = $1; sub(/-[0-9]+$/, "", f); sub(/-[0-9]+$/, "-*", f)
            for (i = 2; i <= NF; i++) if ($i == "NR") { n[f "\t" $(i + 1)]++; break }
        }
        END { for (k in n) printf "%s\t%d\n", k, n[k] }
    ' "$DIR/trace.raw" | sort > "$DIR/calls.tsv"
    { printf 'thread\tsyscall\tcalls\n'; cat "$DIR/calls.tsv"; } > "$DIR/calls.tsv.new"
    mv "$DIR/calls.tsv.new" "$DIR/calls.tsv"
    echo "refused calls made: $(($(wc -l < "$DIR/calls.tsv") - 1)) kinds"
    cat "$DIR/calls.tsv"
    echo "$(wc -l < "$DIR/trace.raw") trace lines, $(cat "$DIR/overrun") lost; refused audited checks:"
    awk -F'\t' 'NR > 1 && $3 == "audited" && $5 > 0' "$DIR/checks.tsv"
    ;;
census)
    TAG=${3:-now}
    pid=$(systemctl show -p MainPID --value northnarrow-agent.service)
    [[ -n $pid && $pid != 0 ]] || { echo "no agent running" >&2; exit 1; }
    {
        printf 'tid\tthread\tCapEff\tCapPrm\tSeccomp\tNoNewPrivs\n'
        for t in /proc/"$pid"/task/*; do
            awk -v tid="${t##*/}" '
                /^Name:/ { n = $2 } /^CapEff:/ { e = $2 } /^CapPrm:/ { p = $2 }
                /^Seccomp:/ { s = $2 } /^NoNewPrivs:/ { nnp = $2 }
                END { printf "%s\t%s\t%s\t%s\t%s\t%s\n", tid, n, e, p, s, nnp }' "$t/status" 2>/dev/null
        done
    } > "$DIR/census-$TAG.tsv"
    cat "$DIR/census-$TAG.tsv"
    ;;
*) die "unknown command: $CMD" ;;
esac
