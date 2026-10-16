#!/usr/bin/env bash
# Structured adversarial check of the anti-tamper (Tappa 10.8).
#
# Runs ON THE GUEST as root against the installed agent (one case per
# documented way of neutralising a Linux EDR, and answers two questions for
# each: was the action denied, and did it leave EVIDENCE in the signed chain
# logs (audit.log ops, detections.jsonl rule ids) or at least in the journal?
# Every case states its expectation; a deviation fails the run, a KNOWN GAP
# is printed as such (feeds Tappa 10.9) and does not fail it.
#
# Output: a markdown table on stdout; exit 1 on any deviation.
# usage: sudo anti-tamper.sh [--only C03,C08]
#        sudo anti-tamper.sh --persistence   # after a reboot: hooks, pins, +i back (C62)
#        anti-tamper.sh --selftest           # the helpers, unprivileged; touches nothing
#
# External audit LAB-003/LAB-005/LAB-007 (lab PR 154): a case's outcome is
# the errno its helper reports (or, for an external tool, its C-locale
# message), and a "denied" needs the end state to have held as well
# (POST=, below). A process is signalled only after its identity is checked
# (comm and start time, then a pidfd), never through a bare PID, 0 or -1.
# Every mount the run makes is undone by a trap, and a mount left behind
# after its case fails the run and stops it.
#
# Reboot persistence: after `nn-lab.sh tamper-check`, boot the guest again
# (`nn-lab.sh down && nn-lab.sh up`, or `sudo systemctl reboot` in it), then
# `nn-lab.sh ssh 'cd ~/northnarrow && sudo bash deploy/lab/adversarial/anti-tamper.sh --persistence'`.
set -u
# LAB-005: the external tools' messages are read in the C locale only.
export LC_ALL=C
unset LANGUAGE
ETC=/etc/northnarrow
STATE=/var/lib/northnarrow
PINS=/sys/fs/bpf/northnarrow
AUDIT=$ETC/audit.log
DETS=$STATE/detections/detections.jsonl
ONLY=
MODE=run
while (( $# )); do
    case "$1" in
        --only) ONLY=${2:-}; shift ;;
        --persistence) MODE=persistence ;;
        --selftest) MODE=selftest ;;
        *) echo "usage: anti-tamper.sh [--only C01,C02 | --persistence | --selftest]" >&2; exit 2 ;;
    esac
    shift
done
# External audit LAB-008: root's scratch files live in a fresh 0700
# directory, never at a fixed /tmp name another user could create first (C14
# would bind that user's directory over /etc/northnarrow, C24 sign that
# user's overlay with the lab key). Still under /tmp: C21 needs an exec there.
TMPD=$(mktemp -d /tmp/nn-tamper.XXXXXXXX) || { echo "anti-tamper: mktemp failed" >&2; exit 1; }
export TMPD
trap 'rm -rf "$TMPD"' EXIT

fail=0
rows=()

# ── helpers (external audit LAB-003, LAB-005, LAB-007) ────────────────────
# One small python3 helper does every operation whose outcome is an errno:
# it prints "errno=<NAME>" for the operation under test, "target=absent"
# when the process it was given is not the one it was told to expect, and
# never prints the content of a file it reads.
NNPY_SRC=$(cat <<'PY'
import errno, hashlib, io, json, os, signal, subprocess, sys, tempfile, time
from contextlib import redirect_stdout

PROTECTED_COMMS = ("northnarrow-age", "northnarrow-wat")
SIGNALS = ("KILL", "TERM", "INT", "HUP", "QUIT", "STOP", "CONT", "SEGV", "ABRT", "BUS")

def ename(e):
    return errno.errorcode.get(e, "E%d" % e)

def valid_pid(s):
    # decimal digits only and above 1: never 0 (the caller's process
    # group), -1 (every process) or init
    return s.isdigit() and len(s) <= 10 and int(s) > 1

def parse_stat(text):
    # (comm, state, starttime) of /proc/<pid>/stat; comm may hold ") "
    l, r = text.index("("), text.rindex(")")
    rest = text[r + 2:].split()
    return text[l + 1:r], rest[0], rest[19]

def ident(pid):
    try:
        with open("/proc/%s/stat" % pid) as f:
            return parse_stat(f.read())
    except (OSError, ValueError, IndexError):
        return None

def resolve(pid, comm, start):
    if not valid_pid(pid):
        return None, "pid %r is not a process id above 1" % pid
    if int(pid) in (os.getpid(), os.getppid()):
        return None, "pid %s is this helper or its caller" % pid
    cur = ident(pid)
    if cur is None:
        return None, "no process %s" % pid
    if cur[0] != comm:
        return None, "pid %s runs %r, not %r" % (pid, cur[0], comm)
    if cur[2] != start:
        return None, "pid %s started at %s, not %s (another process)" % (pid, cur[2], start)
    return cur, ""

def cmd_ident(pid):
    cur = ident(pid) if valid_pid(pid) else None
    if cur is None:
        return 1
    print("%s %s %s" % (cur[2], cur[1], cur[0]))
    return 0

def cmd_signal(pid, comm, start, sig):
    if sig not in SIGNALS:
        print("setup: unknown signal %r" % sig)
        return 2
    cur, why = resolve(pid, comm, start)
    if cur is None:
        print("target=absent (%s; nothing signalled)" % why)
        return 3
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        print("setup: python3 3.9+ is needed for pidfd signals; nothing signalled")
        return 2
    try:
        fd = os.pidfd_open(int(pid))
    except OSError as e:
        print("target=absent (pidfd_open %s: %s; nothing signalled)" % (pid, ename(e.errno)))
        return 3
    try:
        # the pidfd now pins one process: if <pid> still has the identity,
        # it is the one the pidfd refers to
        again = ident(pid)
        if again is None or again[0] != cur[0] or again[2] != cur[2]:
            print("target=absent (pid %s changed while it was opened; nothing signalled)" % pid)
            return 3
        try:
            signal.pidfd_send_signal(fd, getattr(signal, "SIG" + sig))
        except OSError as e:
            if e.errno == errno.ESRCH:
                print("target=absent (pid %s exited before the signal)" % pid)
                return 3
            print("SIG%s to %s (%s): errno=%s" % (sig, pid, comm, ename(e.errno)))
            return 1
        print("SIG%s to %s (%s): delivered" % (sig, pid, comm))
        return 0
    finally:
        os.close(fd)

def cmd_procopen(pid, comm, start, name, offset):
    if name not in ("mem", "environ"):
        print("setup: unknown /proc file %r" % name)
        return 2
    cur, why = resolve(pid, comm, start)
    if cur is None:
        print("target=absent (%s; nothing opened)" % why)
        return 3
    path = "/proc/%s/%s" % (pid, name)
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as e:
        print("open %s: errno=%s" % (path, ename(e.errno)))
        return 1
    try:
        again = ident(pid)
        if again is None or again[2] != cur[2]:
            print("target=absent (pid %s changed while it was opened)" % pid)
            return 3
        try:
            n = len(os.pread(fd, 1, int(offset)))
            print("open %s: granted, read %d byte(s)" % (path, n))
        except OSError as e:
            print("open %s: granted (read: %s)" % (path, ename(e.errno)))
        return 0
    finally:
        os.close(fd)

def cmd_file(op, path, arg=None):
    try:
        if op == "open-append":
            os.close(os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK))
            msg = "opened for writing (nothing written)"
        elif op == "open-trunc":
            os.close(os.open(path, os.O_WRONLY | os.O_TRUNC | os.O_NOFOLLOW | os.O_NONBLOCK))
            msg = "opened with O_TRUNC (emptied)"
        elif op == "truncate":
            os.truncate(path, 0)
            msg = "truncated to 0 bytes"
        elif op == "rename" and arg:
            os.rename(path, arg)
            msg = "renamed to %s" % arg
        elif op == "unlink":
            os.unlink(path)
            msg = "unlinked"
        elif op == "read":
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                msg = "read %d byte(s) (not shown)" % len(os.read(fd, 4096))
            finally:
                os.close(fd)
        else:
            print("setup: unknown file operation %r" % op)
            return 2
    except OSError as e:
        print("%s %s: errno=%s" % (op, path, ename(e.errno)))
        return 1
    print("%s %s: %s" % (op, path, msg))
    return 0

def file_id(path, kind):
    st = os.lstat(path)
    out = "%d:%d" % (st.st_dev, st.st_ino)
    if kind in ("size", "hash"):
        out += ":%d" % st.st_size
    if kind == "hash":
        h = hashlib.sha256()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        out += ":" + h.hexdigest()
    return out

def cmd_fileid(path, kind):
    if kind not in ("ino", "size", "hash"):
        return 2
    try:
        print(file_id(path, kind))
        return 0
    except OSError as e:
        print("missing (%s)" % ename(e.errno))
        return 1

def map_pids(text):
    # bpftool -j map dump: keys are little-endian byte lists (no BTF) or,
    # with BTF, numbers under "formatted"
    pids = []
    for entry in json.loads(text):
        key = entry.get("formatted", {}).get("key", entry.get("key"))
        if isinstance(key, list):
            key = int.from_bytes(bytes(int(b, 16) for b in key), "little")
        pids.append(int(key))
    stale = [p for p in pids if (ident(str(p)) or ("",))[0] not in PROTECTED_COMMS]
    return pids, stale

def cmd_map_pids():
    try:
        pids, stale = map_pids(sys.stdin.read())
    except (ValueError, TypeError, AttributeError):
        print("unreadable")
        return 1
    print("total=%d stale=%d%s" % (len(pids), len(stale),
                                   " pids=" + ",".join(map(str, stale)) if stale else ""))
    return 0

def quiet(fn, *a):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = fn(*a)
    return rc, buf.getvalue()

def selftest():
    checks, fails = 0, []
    def check(cond, what):
        nonlocal checks
        checks += 1
        if not cond:
            fails.append(what)
    stat = "77 (a) b (c) S 1 2 3 0 -1 4194560 10 0 0 0 5 6 0 0 20 0 1 0 98765 4096 1"
    check(parse_stat(stat) == ("a) b (c", "S", "98765"), "parse_stat with ') ' in comm")
    me = ident(str(os.getpid()))
    check(me is not None and me[2].isdigit(), "ident of this process")
    for bad in ("", "0", "1", "-1", "abc", "12a", "1" * 11, " 5"):
        check(not valid_pid(bad), "valid_pid refuses %r" % bad)
    check(valid_pid("2"), "valid_pid accepts 2")
    for bad in ("0", "-1", "1", "", str(os.getpid()), str(os.getppid())):
        rc, out = quiet(cmd_signal, bad, "x", "0", "TERM")
        check(rc == 3 and out.startswith("target=absent"), "no signal to %r" % bad)
    child = subprocess.Popen(["sleep", "30"])
    try:
        for _ in range(100):
            cur = ident(str(child.pid))
            if cur and cur[0] == "sleep":
                break
            time.sleep(0.02)
        pid, start = str(child.pid), cur[2]
        rc, out = quiet(cmd_signal, pid, "northnarrow-age", start, "TERM")
        check(rc == 3 and child.poll() is None, "wrong comm: not signalled")
        rc, out = quiet(cmd_signal, pid, "sleep", str(int(start) + 1), "TERM")
        check(rc == 3 and child.poll() is None, "wrong start time: not signalled")
        rc, out = quiet(cmd_signal, pid, "sleep", start, "NOPE")
        check(rc == 2 and child.poll() is None, "unknown signal refused")
        rc, out = quiet(cmd_procopen, pid, "sleep", start, "environ", "0")
        check(rc == 0 and "granted" in out, "procopen on an own child")
        rc, out = quiet(cmd_signal, pid, "sleep", start, "STOP")
        state = ""
        for _ in range(100):
            state = (ident(pid) or ("", ""))[1]
            if state in ("T", "t"):
                break
            time.sleep(0.02)
        check(rc == 0 and state in ("T", "t"), "STOP delivered to the right process")
        rc, out = quiet(cmd_signal, pid, "sleep", start, "CONT")
        check(rc == 0, "CONT delivered")
        rc, out = quiet(cmd_signal, pid, "sleep", start, "TERM")
        check(rc == 0 and "delivered" in out, "TERM delivered")
        check(child.wait(timeout=5) == -signal.SIGTERM, "the child died of SIGTERM")
        rc, out = quiet(cmd_signal, pid, "sleep", start, "TERM")
        check(rc == 3, "a reaped pid is absent")
    finally:
        if child.poll() is None:
            child.kill()
            child.wait()
    with tempfile.TemporaryDirectory() as d:
        f, g = os.path.join(d, "f"), os.path.join(d, "g")
        with open(f, "w") as fh:
            fh.write("secret")
        before = file_id(f, "hash")
        check(before.endswith(":6:" + hashlib.sha256(b"secret").hexdigest()), "fileid hash")
        rc, out = quiet(cmd_file, "open-append", f)
        check(rc == 0 and file_id(f, "hash") == before, "open-append writes nothing")
        rc, out = quiet(cmd_file, "read", f)
        check(rc == 0 and "secret" not in out and "6 byte" in out, "read never prints content")
        rc, out = quiet(cmd_file, "rename", f, g)
        check(rc == 0 and os.path.exists(g), "rename")
        rc, out = quiet(cmd_file, "unlink", g)
        check(rc == 0 and not os.path.exists(g), "unlink")
        rc, out = quiet(cmd_file, "unlink", g)
        check(rc == 1 and "errno=ENOENT" in out, "errno name reported")
        rc, out = quiet(cmd_fileid, g, "ino")
        check(rc == 1 and out.startswith("missing"), "fileid of a missing file")
        if os.geteuid() != 0:
            with open(f, "w") as fh:
                fh.write("x")
            os.chmod(d, 0o500)
            try:
                rc, out = quiet(cmd_file, "unlink", f)
                check(rc == 1 and "errno=EACCES" in out, "EACCES reported")
            finally:
                os.chmod(d, 0o700)
    gone = 4194304 + 4242
    keys = [{"key": ["0x%02x" % b for b in os.getpid().to_bytes(4, "little")], "value": ["0x01"]},
            {"formatted": {"key": gone, "value": 1}}]
    pids, stale = map_pids(json.dumps(keys))
    check(pids == [os.getpid(), gone] and stale == pids, "map-pids parse and stale test")
    print("python helper selftest: %d checks, %d failed%s" % (
        checks, len(fails), "".join("\n  FAIL: " + x for x in fails)))
    return 1 if fails else 0

def main(argv):
    cmds = {
        "ident": (cmd_ident, 1), "signal": (cmd_signal, 4),
        "procopen": (cmd_procopen, 5), "fileid": (cmd_fileid, 2),
        "map-pids": (cmd_map_pids, 0), "selftest": (selftest, 0),
    }
    if argv and argv[0] == "file" and len(argv) in (3, 4):
        return cmd_file(*argv[1:])
    if not argv or argv[0] not in cmds or len(argv) - 1 != cmds[argv[0]][1]:
        print("setup: bad helper call %r" % (argv,))
        return 2
    return cmds[argv[0]][0](*argv[1:])

sys.exit(main(sys.argv[1:]))
PY
)
# -I: the helper runs as root from a user's checkout; nothing from the
# current directory or the environment is imported.
nnpy() { python3 -I -c "$NNPY_SRC" "$@"; }

# valid_pid <pid> <comm>: a decimal PID above 1 whose /proc/<pid>/comm is
# <comm> (comm is readable without ptrace; /proc/<agent>/exe is not, C04b)
valid_pid() {
    [[ ${1:-} =~ ^[1-9][0-9]{0,9}$ ]] && (( $1 > 1 )) || return 1
    [[ "$(cat "/proc/$1/comm" 2>/dev/null)" == "$2" ]]
}
proc_start() { nnpy ident "${1:-0}" 2>/dev/null | cut -d' ' -f1; }

# External audit LAB-003: the agent's PID from its pidfile only when it
# names a live agent process. A stale pidfile (the watchdog recycling the
# agent after C15/C20) is waited on for up to $1 s (default 15), then reads
# as empty: a case aimed at it reports "target absent".
agent_pid() {
    local p i n=$(( ${1:-15} * 2 ))
    for (( i = 0; i <= n; i++ )); do
        p=$(cat /run/northnarrow/agent.pid 2>/dev/null)
        valid_pid "$p" northnarrow-age && { echo "$p"; return 0; }
        (( i < n )) && sleep 0.5
    done
    return 1
}
# The watchdog's PID: the unit's MainPID (0 when the unit is down), else
# its pidfile; only a live northnarrow-wat process counts.
wd_pid() {
    local p
    for p in "$(systemctl show -p MainPID --value northnarrow-watchdog 2>/dev/null)" \
             "$(cat /run/northnarrow/watchdog.pid 2>/dev/null)"; do
        valid_pid "$p" northnarrow-wat && { echo "$p"; return 0; }
    done
    return 1
}

# outcome_of <output> <postcondition: held|failed|none>
#   denied   the operation reported EPERM/EACCES and the end state held
#   partial  it reported EPERM/EACCES but the end state changed (rm -rf
#            goes on after a refused entry)
#   allowed  no refusal reported; "error (errno=X)" another errno
#   target absent  the process the case aims at was not there
outcome_of() {
    local out=$1 e
    if [[ "$out" == *"target=absent"* ]]; then echo "target absent"; return; fi
    if grep -qE '(^|[^A-Za-z0-9_])errno=(EPERM|EACCES)([^A-Za-z0-9_]|$)' <<<"$out" \
        || grep -qE 'Operation not permitted|Permission denied|Access denied' <<<"$out"; then
        if [[ "$2" == failed ]]; then echo partial; else echo denied; fi
        return
    fi
    e=$(grep -oE 'errno=E[A-Z0-9]+' <<<"$out" | head -1)
    if [[ -n "$e" ]]; then echo "error ($e)"; else echo allowed; fi
}

# ── postconditions (POST="$(post <fn> <args>)" run_case …) ─────────────────
# Evaluated in a subshell after the case; each prints why it failed.
post() { printf '%q ' "$@"; }
# the same process (pid and start time), alive and not stopped; a stopped
# one is resumed (best effort) and still fails the case
post_proc() {   # <pid> <start> <comm>
    local st state comm
    read -r st state comm <<<"$(nnpy ident "${1:-0}")"
    [[ -n "${st:-}" ]] || { echo "pid ${1:-?} is gone"; return 1; }
    [[ "$st" == "$2" && "$comm" == "$3" ]] || { echo "pid $1 is another process now"; return 1; }
    [[ "$state" == Z || "$state" == X ]] && { echo "pid $1 exited"; return 1; }
    if [[ "$state" == T || "$state" == t ]]; then
        nnpy signal "$1" "$3" "$2" CONT >/dev/null 2>&1
        echo "pid $1 was stopped"; return 1
    fi
}
post_same() {   # <path> <ino|size|hash> <id before>
    local now; now=$(nnpy fileid "$1" "$2")
    [[ "$now" == "$3" ]] || { echo "${1##*/} changed (${3:0:30} -> ${now:0:30})"; return 1; }
}
post_not_shrunk() {   # <path> <dev:ino:size before>
    local now; now=$(nnpy fileid "$1" size)
    [[ "${now%:*}" == "${2%:*}" && "${now##*:}" =~ ^[0-9]+$ && "${2##*:}" =~ ^[0-9]+$ ]] \
        && (( ${now##*:} >= ${2##*:} )) && return 0
    echo "${1##*/} replaced or shrunk ($2 -> $now)"; return 1
}
post_flag() {   # <path> <letter> <present|absent>
    local f; f=$(lsattr -d "$1" 2>/dev/null | awk '{print $1}')
    [[ -n "$f" ]] || { echo "lsattr ${1##*/} failed"; return 1; }
    if [[ "$3" == present && "$f" != *"$2"* ]]; then echo "${1##*/} lost +$2 ($f)"; return 1; fi
    if [[ "$3" == absent && "$f" == *"$2"* ]]; then echo "${1##*/} has +$2 ($f)"; return 1; fi
}
pin_list() { find "$PINS" -mindepth 1 2>/dev/null | sort; }
post_pins_kept() {   # <file with pin_list before>
    local gone; gone=$(comm -23 "$1" <(pin_list) | wc -l)
    (( gone == 0 )) || { echo "$gone pin(s) removed"; return 1; }
}
post_module_absent() { ! grep -q "^$1 " /proc/modules || { echo "module $1 is loaded"; return 1; }; }
post_kexec_empty() {
    [[ "$(cat /sys/kernel/kexec_loaded 2>/dev/null)" == 0 ]] || { echo "a kexec image is loaded"; return 1; }
}

# ── cleanup (external audit LAB-007) ──────────────────────────────────────
# Mount points the run may cover, undone newest first; the other state a
# case leaves while it runs (a frozen cgroup, a runtime mask, a file to
# put back) is undone here too, on EXIT and on INT/TERM/HUP/PIPE.
MOUNTS=()
RESTORE=()   # "path|backup": copied back when path is missing
CLEAN_FILES=()   # scratch files a case made outside $SCRATCH
CG_FROZEN=
WD_MASKED=0
SCRATCH=
UMOUNT_RETRY_SLEEP=${UMOUNT_RETRY_SLEEP:-1}
unmount_one() {   # unmount (stacked mounts included), then lazily; 0 when gone
    local m=$1 i
    for i in 1 2 3 4 5; do
        mountpoint -q "$m" 2>/dev/null || return 0
        if (( i < 5 )); then
            umount "$m" 2>/dev/null || sleep "$UMOUNT_RETRY_SLEEP"
        else
            umount -l "$m" 2>/dev/null
        fi
    done
    ! mountpoint -q "$m" 2>/dev/null
}
cleanup_mounts() {
    local i m rc=0
    for (( i = ${#MOUNTS[@]} - 1; i >= 0; i-- )); do
        m=${MOUNTS[i]}
        if ! unmount_one "$m"; then
            echo "WARNING: $m is still mounted — unmount it by hand (findmnt $m)" >&2
            fail=1; rc=1
        fi
    done
    return $rc
}
# mount_gone <case> <path>: after a case that mounts over <path>, the mount
# must be gone; one left behind fails the run (and is unmounted)
mount_gone() {
    mountpoint -q "$2" 2>/dev/null || return 0
    fail=1
    rows+=("| $1 | (cleanup) $2 still mounted after the case | unmounted by the suite | — | DEVIATION (mount left behind) |")
    echo "$1: $2 still mounted after the case — unmounting" >&2
    unmount_one "$2"
}
restore_missing() {   # <path> <backup>
    [[ -e "$1" || ! -s "$2" ]] && return 0
    cp -p "$2" "$1" && echo "restored $1 from $2" >&2
}
cleanup_done=0
cleanup_all() {   # idempotent; 1 when a mount could not be undone
    (( cleanup_done )) && return 0
    cleanup_done=1
    local r rc=0
    [[ -n "$CG_FROZEN" ]] && echo 0 > "$CG_FROZEN" 2>/dev/null
    if (( WD_MASKED )); then
        systemctl unmask --runtime northnarrow-watchdog >/dev/null 2>&1
        WD_MASKED=0
    fi
    for r in ${RESTORE[@]+"${RESTORE[@]}"}; do restore_missing "${r%%|*}" "${r#*|}"; done
    for r in ${CLEAN_FILES[@]+"${CLEAN_FILES[@]}"}; do rm -f "$r"; done
    cleanup_mounts || rc=1
    [[ -n "$SCRATCH" && -d "$SCRATCH" ]] && rm -rf "$SCRATCH"
    return $rc
}
# a second signal while cleaning up (Ctrl-C kills the case's child too,
# and bash runs the INT trap for that as well) must not cut the cleanup short
on_signal() { trap '' INT TERM HUP PIPE; cleanup_all; exit "$1"; }
on_exit() {
    cleanup_all && return 0
    echo "anti-tamper check: DEVIATIONS (a mount could not be undone)"
    exit 1
}

selected() { [[ -z "$ONLY" || ",$ONLY," == *",$1,"* ]]; }

# ── --selftest: the helpers above, unprivileged, on this host ─────────────
selftest() {
    local n=0 bad=0 child st ids dup src
    t() { n=$((n + 1)); if ! "$@"; then bad=$((bad + 1)); echo "  FAIL: $*" >&2; fi; }
    eq() { [[ "$1" == "$2" ]] || { echo "    got '$1', want '$2'" >&2; return 1; }; }
    t eq "$LC_ALL" C
    t eq "$(outcome_of 'kill: errno=EPERM' none)" denied
    t eq "$(outcome_of 'open: errno=EACCES' held)" denied
    t eq "$(outcome_of 'rm: errno=EPERM' failed)" partial
    t eq "$(outcome_of "rm: cannot remove 'x': Operation not permitted" none)" denied
    t eq "$(outcome_of 'Failed to kill unit x: Access denied' none)" denied
    t eq "$(outcome_of 'SIGKILL to 7 (x): delivered' held)" allowed
    t eq "$(outcome_of 'unlink x: errno=ENOENT' none)" "error (errno=ENOENT)"
    t eq "$(outcome_of 'x: errno=EPERMX' none)" "error (errno=EPERMX)"
    t eq "$(outcome_of 'target=absent (no process 7)' failed)" "target absent"
    t eq "$(outcome_of 'rm: impossibile rimuovere: Operazione non permessa' none)" allowed
    for p in "" 0 1 -1 abc 12x 007 99999999999; do t eval "! valid_pid '$p' bash"; done
    t valid_pid $$ "$(cat /proc/$$/comm)"
    t eval '! valid_pid $$ northnarrow-age'
    sleep 30 & child=$!
    sleep 0.2
    st=$(proc_start "$child")
    t eval "[[ '$st' =~ ^[0-9]+$ ]]"
    t post_proc "$child" "$st" sleep
    t eval "! post_proc $child $(( st + 1 )) sleep >/dev/null"
    t eval "nnpy signal $child sleep $st STOP >/dev/null"
    sleep 0.2
    t eval "! post_proc $child $st sleep >/dev/null"   # stopped: fails, and resumes it
    sleep 0.2
    t post_proc "$child" "$st" sleep                   # running again
    t eval "nnpy signal $child sleep $st TERM | grep -q delivered"
    wait "$child" 2>/dev/null
    t eval "! post_proc $child $st sleep >/dev/null"
    t eval "nnpy signal 0 sleep 1 KILL | grep -q '^target=absent'"
    t eval "nnpy signal -1 sleep 1 KILL | grep -q '^target=absent'"
    t nnpy selftest
    # mount cleanup, newest first, with stubbed mount tools
    t eval '(FAKE=" /a /b "; ORDER=""
        mountpoint() { [[ "$FAKE" == *" ${!#} "* ]]; }
        umount() { ORDER+="${!#} "; FAKE=${FAKE/ ${!#} / }; }
        MOUNTS=(/a /b); fail=0; cleanup_mounts; [[ "$ORDER" == "/b /a " && $fail == 0 ]])'
    t eval '(mountpoint() { return 0; }; umount() { return 1; }
        UMOUNT_RETRY_SLEEP=0; MOUNTS=(/stuck); fail=0
        cleanup_mounts 2>/dev/null; [[ $fail == 1 ]])'
    # every case id once (lab PRs adding cases in parallel can collide)
    ids=$(grep -oE '^[[:space:]]*(POST=[^ ]+ |WAIT=[0-9]+ )*(run_case|agent_signal_case|watchdog_signal_case|agent_mem_case|state_row) "?C[0-9]+[a-z]?' "$0" \
        | grep -oE 'C[0-9]+[a-z]?$')
    dup=$(sort <<<"$ids" | uniq -d | tr '\n' ' ')
    t eq "$dup" ""
    # the io_uring probe builds and its tamper modes behave on scratch files
    src="$(dirname "$0")/iouring-probe.c"
    if command -v cc >/dev/null && [[ -f "$src" ]] && [[ $(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo 0) != 2 ]]; then
        local d; d=$(mktemp -d)
        if cc -O2 -o "$d/iou" "$src" 2>"$d/cc.log"; then
            echo data > "$d/f"; echo data > "$d/u"
            t eval "'$d/iou' --modes | grep -qw rename"
            t eval "'$d/iou' --rename '$d/f' '$d/g' | grep -q 'renamed back' && [[ -f '$d/f' && ! -e '$d/g' ]]"
            t eval "'$d/iou' --unlink '$d/u' | grep -q unlinked && [[ ! -e '$d/u' ]]"
            t eval "'$d/iou' --open-write '$d/missing' | grep -q 'errno=ENOENT'"
        else
            t eval "false # iouring-probe.c does not build: $(head -1 "$d/cc.log")"
        fi
        rm -rf "$d"
    fi
    echo "anti-tamper selftest: $n checks, $bad failed"
    (( bad == 0 ))
}
if [[ "$MODE" == selftest ]]; then
    selftest
    exit $?
fi

command -v python3 >/dev/null || { echo "python3 is required (identity-checked signals, errno helpers)"; exit 2; }
trap on_exit EXIT
trap 'on_signal 130' INT
trap 'on_signal 143' TERM
trap 'on_signal 129' HUP
trap 'on_signal 141' PIPE
# One scratch directory (LAB-008, made at the top), removed by cleanup_all.
SCRATCH=$TMPD
# A mount left over by an earlier run that could not clean up (SIGKILL):
# every case would run against the fake directory. Stop here.
for m in "$ETC" /sys/kernel/btf; do
    if mountpoint -q "$m" 2>/dev/null; then
        echo "$m is a mount point (an earlier run left it? findmnt $m): unmount it first"
        exit 2
    fi
done
# Review 26: the layout the agent was installed with (install.sh puts the
# binaries in /usr/local/bin and the units in /etc/systemd/system; a
# package uses /usr/bin and /usr/lib/systemd/system).
# (from the unit's ExecStart: /proc/<agent>/exe is ptrace-protected, C04b)
AGENT_EXE=$(systemctl show -p ExecStart --value northnarrow-agent 2>/dev/null | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)
NNADMIN=$(dirname "${AGENT_EXE:-/usr/local/bin/northnarrow-agent}")/nn-admin
UNIT=$(systemctl show -p FragmentPath --value northnarrow-agent 2>/dev/null)
UNIT=${UNIT:-/etc/systemd/system/northnarrow-agent.service}
# External audit EBPF-001: the units refuse `systemctl stop`/`restart`, and
# systemd's signals reach the agent only inside a signed trusted-installer
# window. The cases that restart the agent on purpose take the operator's
# path: the window (lab key), SIGTERM, the watchdog brings it back.
# The lab's admin key: /root/northnarrow-admin.key since external audit
# DEP-001 (install.sh writes it there), /etc/northnarrow/admin.key on a
# guest installed before.
ADMIN_KEY=${NN_ADMIN_KEY:-}
for k in /root/northnarrow-admin.key "$ETC/admin.key"; do
    [[ -z "$ADMIN_KEY" && -r "$k" ]] && ADMIN_KEY=$k
done
grant_window() { "$NNADMIN" trusted-installer-grant --key "$ADMIN_KEY" --window-secs "${1:-120}" >/dev/null 2>&1; }
restart_agent() {
    local old new i
    old=$(cat /run/northnarrow/agent.pid 2>/dev/null)
    grant_window
    systemctl kill --signal=SIGTERM northnarrow-agent
    for i in $(seq 1 30); do
        sleep 1
        new=$(cat /run/northnarrow/agent.pid 2>/dev/null)
        [[ -n "$new" && "$new" != "$old" ]] && kill -0 "$new" 2>/dev/null && return 0
    done
    systemctl start northnarrow-agent
}
export -f grant_window restart_agent
export NNADMIN ETC ADMIN_KEY
jlines() { journalctl --namespace=northnarrow -u northnarrow-agent -u northnarrow-watchdog --since "$1" --no-pager -o cat 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -v "process spawn detected"; }
audit_count() { wc -l < "$AUDIT" 2>/dev/null || echo 0; }
dets_count() { wc -l < "$DETS" 2>/dev/null || echo 0; }

# evidence since (t0, audit lines before, detection lines before)
evidence() {
    local t0=$1 a0=$2 d0=$3
    local j denials verdicts errors audit dets
    j=$(jlines "$t0")
    denials=$(echo "$j" | grep -oE "ANTI-TAMPER DENIAL .*op=[a-z_]+" | grep -oE "op=[a-z_]+" | sort | uniq -c | awk '{printf "%s×%s ", $2, $1}')
    verdicts=$(echo "$j" | grep -oE "VERDICT \(rule\) rule=[A-Za-z0-9_-]+" | grep -oE "rule=[A-Za-z0-9_-]+" | cut -d= -f2 | sort | uniq -c | awk '{printf "%s×%s ", $2, $1}')
    errors=$(echo "$j" | grep -cE " ERROR ")
    audit=$(tail -n +"$((a0 + 1))" "$AUDIT" 2>/dev/null | grep -oE '"op":"[a-z_]+"' | cut -d'"' -f4 | sort | uniq -c | awk '{printf "%s×%s ", $2, $1}')
    dets=$(tail -n +"$((d0 + 1))" "$DETS" 2>/dev/null | grep -oE '"rule_id":"[A-Za-z0-9_-]+"' | cut -d'"' -f4 | sort | uniq -c | awk '{printf "%s×%s ", $2, $1}')
    # a boot that reports its predecessor died without agent_stop
    if tail -n +"$((a0 + 1))" "$AUDIT" 2>/dev/null | grep -q '"ended":"abrupt"'; then
        audit="${audit}prev_run_abrupt "
    fi
    # Tappa 10.8: an overlay refused at boot / a signed one accepted
    if tail -n +"$((a0 + 1))" "$AUDIT" 2>/dev/null | grep -q '"kind":"unauthorized_overlay"'; then
        audit="${audit}unauthorized_overlay "
    fi
    if tail -n +"$((a0 + 1))" "$AUDIT" 2>/dev/null | grep -q '"kind":"unit_shadowed"'; then
        audit="${audit}unit_shadowed "
    fi
    if echo "$j" | grep -q "signed overlay accepted"; then
        denials="${denials}overlay_accepted "
    fi
    echo "journal:[${denials:-}${verdicts:-}errors=${errors}] audit:[${audit:-}] detections:[${dets:-}]"
}

# run_case ID "title" expect_outcome expect_evidence_regex known_gap(0/1) -- command...
# POST="$(post <fn> <args>)" before it: the end state the case must leave.
run_case() {
    local id=$1 title=$2 exp_out=$3 exp_ev=$4 gap=$5; shift 5; [[ "$1" == "--" ]] && shift
    if [[ -n "$ONLY" && ",$ONLY," != *",$id,"* ]]; then return; fi
    local t0 a0 d0 out rc ev status post_state=none post_msg=
    t0=$(date -u +"%Y-%m-%d %H:%M:%S")
    a0=$(audit_count); d0=$(dets_count)
    sleep 1
    out=$("$@" 2>&1); rc=$?
    sleep "${WAIT:-4}"
    # outcome from the error, not the exit code: bpftool exits non-zero
    # after printing an object it was allowed to open
    # (`systemctl kill` reports the kernel's EPERM as "Access denied").
    # External audit LAB-005: the helpers report errno=<NAME>, the tools
    # are read in the C locale, and a refusal counts as "denied" only when
    # the postcondition held as well.
    if [[ -n "${POST:-}" ]]; then
        if post_msg=$(eval "$POST" 2>&1); then post_state=held; else post_state=failed; fi
    fi
    status=$(outcome_of "$out" "$post_state")
    if [[ "$post_state" == failed && "$status" != "target absent" ]]; then
        status+=" (post: $(echo "${post_msg:-failed}" | head -1 | tr '|' '/' | cut -c1-100))"
    fi
    ev=$(evidence "$t0" "$a0" "$d0")
    local verdict="OK"
    # A known gap (e.g. kexec without kernel lockdown, closed by host
    # hardening, not by the agent: `nn-admin host-check`) is reported, not failed.
    if [[ "$status" != "$exp_out" ]]; then
        if (( gap )); then verdict="KNOWN GAP"; else verdict="DEVIATION (expected $exp_out)"; fail=1; fi
    fi
    if [[ -n "$exp_ev" ]] && ! echo "$ev" | grep -qE "$exp_ev"; then
        if (( gap )); then verdict="KNOWN GAP"; else verdict="DEVIATION (evidence /$exp_ev/ missing)"; fail=1; fi
    fi
    rows+=("| $id | $title | $status | $ev | $verdict |")
    echo "$id $title → $status; $ev; $verdict" >&2
    [[ -n "$out" ]] && echo "    $(echo "$out" | head -2 | tr '\n' ' ' | cut -c1-160)" >&2
}

PID=$(agent_pid)
[[ -n "$PID" ]] || { echo "agent not running (no pid file naming a live agent)"; exit 2; }
# A trusted-installer window still open from an earlier step suspends the
# filesystem deny hooks by design: C04-C07 would pass, and C07 would purge
# the pins. Wait until this agent closes it (a restart ends it too: the
# grants are bound to the boot's session nonce).
window_open() {
    journalctl --namespace=northnarrow _PID="$(agent_pid 0)" --since "-30min" --no-pager -o cat 2>/dev/null \
        | grep -oE 'trusted-installer override (ARMED|CLOSED)' | tail -1 | grep -q ARMED
}
for i in $(seq 1 130); do
    window_open || break
    (( i == 1 )) && echo "a trusted-installer window is open: waiting for it to close" >&2
    sleep 1
done
# BPF guard mode of the running agent (lab builds observe unless forced)
BPF_MODE=$(jlines "-2h" | grep -o 'own objects registered.*mode="[a-z]*"' | tail -1 | grep -o 'mode="[a-z]*"' | cut -d'"' -f2)
BPF_MODE=${BPF_MODE:-enforce}
if [[ "$BPF_MODE" == enforce ]]; then BPF_EXPECT=denied; else BPF_EXPECT=allowed; fi
echo "agent pid $PID, kernel $(uname -r), bpf guard mode $BPF_MODE, $(date -u +%FT%TZ)" >&2

# A signal from a root shell to the live agent or watchdog: the target is
# resolved and its identity checked (comm, start time, then a pidfd) right
# before the case; afterwards the same process must be alive and running.
agent_signal_case() {   # <id> <title> <SIG>
    local p s; p=$(agent_pid); s=$(proc_start "$p")
    POST=$(post post_proc "${p:-0}" "${s:-0}" northnarrow-age) \
        run_case "$1" "$2" denied "op=signal" 0 -- nnpy signal "${p:-0}" northnarrow-age "${s:-0}" "$3"
}
watchdog_signal_case() {   # <id> <title> <SIG>
    local p s; p=$(wd_pid); s=$(proc_start "$p")
    POST=$(post post_proc "${p:-0}" "${s:-0}" northnarrow-wat) \
        run_case "$1" "$2" denied "op=signal" 0 -- nnpy signal "${p:-0}" northnarrow-wat "${s:-0}" "$3"
}
agent_mem_case() {   # <id> <title>: open /proc/<agent>/mem (a ptrace attach check)
    local p s; p=$(agent_pid); s=$(proc_start "$p")
    POST=$(post post_proc "${p:-0}" "${s:-0}" northnarrow-age) \
        run_case "$1" "$2" denied "op=ptrace" 0 -- nnpy procopen "${p:-0}" northnarrow-age "${s:-0}" mem 4194304
}
# a row for a state check (no action, no evidence)
state_row() {   # <id> <title> <detail> <check...>
    local id=$1 title=$2 detail=$3 v msg; shift 3
    selected "$id" || return 0
    if msg=$("$@" 2>&1); then v=OK; else v="DEVIATION (${msg:-check failed})"; fail=1; fi
    rows+=("| $id | $title | $detail | — | $v |")
    echo "$id $title → $detail; $v" >&2
}
# External audit NN-AUD-222 (LAB-017): a case that does not run is a table
# row, never just a line on stderr. "Not applicable" (the kernel has the
# feature switched off: kernel.io_uring_disabled=2) is N/A; anything else
# (a probe that did not build) is a DEVIATION, so the run fails.
skipped_case() { # ids reason na(0|1)
    local v
    if [[ "$3" == 1 ]]; then v="N/A ($2)"; else v="DEVIATION (not run: $2)"; fail=1; fi
    rows+=("| $1 | (not run) | SKIPPED ($2) | — | $v |")
    echo "$1 skipped: $2 → $v" >&2
}
print_table() {
    echo
    echo "| case | action | outcome | evidence | verdict |"
    echo "|---|---|---|---|---|"
    printf '%s\n' ${rows[@]+"${rows[@]}"}
    echo
}

# ── after a reboot (external audit LAB-004): --persistence ───────────────
# Run on a guest that rebooted after the suite: the hooks attached at boot
# still refuse (a SIGCONT is harmless if it lands), the protected files are
# write-denied, the state directory kept +i, the pins are back.
if [[ "$MODE" == persistence ]]; then
    echo "boot $(cat /proc/sys/kernel/random/boot_id), up $(cut -d' ' -f1 /proc/uptime) s" >&2
    agent_signal_case C62a "after a boot: SIGCONT the agent from a root shell" CONT
    watchdog_signal_case C62b "after a boot: SIGCONT the watchdog from a root shell" CONT
    POST=$(post post_not_shrunk "$AUDIT" "$(nnpy fileid "$AUDIT" size)") \
        run_case C62c "after a boot: open audit.log for writing" denied "op=write" 0 -- nnpy file open-append "$AUDIT"
    state_row C62d "after a boot: the state directory keeps +i" "lsattr -d $STATE" post_flag "$STATE" i present
    state_row C62e "after a boot: the pins are back" "PROTECTED_PIDS, link_task_kill" \
        test -e "$PINS/PROTECTED_PIDS" -a -e "$PINS/link_task_kill"
    cleanup_all
    print_table
    (( fail == 0 )) && echo "anti-tamper check: OK (known gaps listed)" || echo "anti-tamper check: DEVIATIONS"
    exit $fail
fi

# ── signals and ptrace ────────────────────────────────────────────────────
# External audit LAB-003: no bare `kill -9 $PID`. C02 used to signal
# whatever `systemctl show -p MainPID` printed: 0 when the watchdog unit is
# down, and `kill -9 0` kills the suite's own process group. A watchdog that
# is not running now reads "target absent", a deviation.
agent_signal_case C01 "kill -9 the agent from a root shell" KILL
watchdog_signal_case C02 "kill -9 the watchdog from a root shell" KILL
agent_mem_case C03 "ptrace attach: read /proc/<agent>/mem"
PID=$(agent_pid); START=$(proc_start "$PID")
run_case C04b "ptrace read-mode: /proc/<agent>/environ (silent by design)" denied "" 0 -- nnpy procopen "$PID" northnarrow-age "${START:-0}" environ 0
# ── protected files and pins ──────────────────────────────────────────────
POST=$(post post_same "$ETC/admin.pub" hash "$(nnpy fileid "$ETC/admin.pub" hash)") \
run_case C04 "append to /etc/northnarrow/admin.pub" denied "op=write" 0 -- bash -c "echo x >> $ETC/admin.pub"
POST=$(post post_flag "$STATE" i present) \
run_case C05 "chattr -i on the state dir" denied "op=ioctl" 0 -- chattr -i "$STATE"
POST=$(post post_same "$UNIT" ino "$(nnpy fileid "$UNIT" ino)") \
run_case C06 "unlink the agent unit (systemctl mask)" denied "op=unlink" 0 -- bash -c "rm -f $UNIT"
pin_list > "$SCRATCH/pins.before"
POST=$(post post_pins_kept "$SCRATCH/pins.before") \
run_case C07 "rm -rf the bpffs pin root" denied "op=unlink" 0 -- bash -c "rm -rf $PINS"
run_case C08 "bpftool map update on PROTECTED_PIDS (pinned)" "$BPF_EXPECT" "NN-L-BPF-002|op=bpf_map" 0 -- bpftool map update pinned "$PINS/PROTECTED_PIDS" key 1 0 0 0 value 1
run_case C09 "bpftool link show pinned (link handle)" "$BPF_EXPECT" "NN-L-BPF-002|op=bpf_link" 0 -- bpftool link show pinned "$PINS/link_task_kill"
# ── BPF ecosystem ─────────────────────────────────────────────────────────
run_case C10 "bpftool feature probe (loads test programs)" allowed "NN-L-BPF-001" 0 -- bash -c "bpftool feature probe kernel >/dev/null"
# ── systemd ───────────────────────────────────────────────────────────────
# External audit EBPF-015: where the agent registered its drop-in directory
# at boot (install.sh makes it on Debian-family hosts) a new drop-in is
# refused; elsewhere it is made beside the unit and reported.
C11_EXP=allowed; C11_EV="integrity_drift"
if journalctl --namespace=northnarrow _PID="$PID" --no-pager -o cat 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' \
    | grep -qE "registered in PROTECTED_INODES path=/etc/systemd/system/northnarrow-agent\.service\.d( |$)"; then
    C11_EXP=denied; C11_EV="op=create"
fi
WAIT=40 run_case C11 "unit drop-in with a hostile Environment=" "$C11_EXP" "$C11_EV" 0 -- bash -c "mkdir -p /etc/systemd/system/northnarrow-agent.service.d && printf '[Service]\nEnvironment=NN_ANTI_TAMPER_ALLOW_DEGRADED=1\n' > /etc/systemd/system/northnarrow-agent.service.d/zz-tamper.conf"
rm -rf /etc/systemd/system/northnarrow-agent.service.d/zz-tamper.conf; systemctl daemon-reload
WAIT=40 run_case C12 "systemctl set-property --runtime MemoryMax (OOM path)" allowed "integrity_drift" 0 -- systemctl set-property --runtime northnarrow-agent.service MemoryMax=4G
# resetting the property still leaves an (empty) runtime drop-in behind
rm -f /run/systemd/system.control/northnarrow-agent.service.d/50-MemoryMax.conf
# Review 26: a copy of the unit in a higher-precedence directory of the
# systemd load path (tmpfs, outside the FIM watch) replaces the installed
# unit at the next daemon-reload, for either install layout.
SHADOW=/run/systemd/transient/northnarrow-agent.service
WAIT=40 run_case C25 "shadow the agent unit from /run/systemd/transient" allowed "unit_shadowed" 0 -- bash -c "mkdir -p /run/systemd/transient && cp $UNIT $SHADOW && systemctl daemon-reload && systemctl show -p FragmentPath --value northnarrow-agent"
rm -f "$SHADOW"; systemctl daemon-reload
systemctl daemon-reload
# ── mounts ────────────────────────────────────────────────────────────────
# External audit LAB-007: each mount point is registered before its case,
# so the trap undoes it whatever happens (Ctrl-C in the 40 s, a lost ssh
# session, an umount refused with EBUSY); after the case it must be gone,
# or the run fails and stops (the next cases would run on the fake one).
mkdir -p /mnt/nn-bpf2 "$TMPD/fake-etc"
MOUNTS+=(/mnt/nn-bpf2)
WAIT=40 run_case C13 "second bpffs mount" allowed "integrity_drift" 0 -- mount -t bpf bpf /mnt/nn-bpf2
unmount_one /mnt/nn-bpf2
# mounted, held for one check, unmounted BEFORE the evidence is read: while
# it is mounted the host's /etc/northnarrow/audit.log is the fake one
MOUNTS+=("$ETC")
run_case C14 "bind mount over /etc/northnarrow for 40 s" allowed "integrity_drift" 0 -- bash -c "mount --bind $TMPD/fake-etc $ETC && sleep 40; umount $ETC"
mount_gone C14 "$ETC" || { print_table; echo "anti-tamper check: DEVIATIONS (stopped: $ETC still mounted)"; exit 1; }
# Review 53: hiding the kernel BTF keeps every LSM hook from attaching at
# the agent's next start (which now refuses to start); the mount itself is
# reported while the agent runs.
MOUNTS+=(/sys/kernel/btf)
run_case C26 "tmpfs over /sys/kernel/btf for 40 s" allowed "integrity_drift" 0 -- bash -c "mount -t tmpfs tmpfs /sys/kernel/btf && sleep 40; umount /sys/kernel/btf"
mount_gone C26 /sys/kernel/btf || { print_table; echo "anti-tamper check: DEVIATIONS (stopped: /sys/kernel/btf still mounted)"; exit 1; }
# ── cgroup freezer ────────────────────────────────────────────────────────
CG=/sys/fs/cgroup/system.slice/northnarrow-agent.service/cgroup.freeze
if [[ -w "$CG" ]]; then
    selected C15 && CG_FROZEN=$CG   # thawed by the trap if the run stops here
    WAIT=40 run_case C15 "cgroup v2 freeze of the agent for 45 s" allowed "integrity_drift|agent_boot" 0 -- bash -c "echo 1 > $CG && sleep 45 && echo 0 > $CG"
    CG_FROZEN=
fi
# ── kernel modules / kexec ────────────────────────────────────────────────
if modinfo dummy >/dev/null 2>&1; then
    # R011 kills modprobe within ~10 ms: either the load is prevented (R011)
# or it lands first and is recorded (R018) — both are evidence
run_case C16 "modprobe dummy (in-tree module load)" allowed "R011_KernelModuleTooling|R018_KernelModuleLoad" 0 -- bash -c "rmmod dummy 2>/dev/null; modprobe dummy && rmmod dummy"
fi
# ── OOM and configuration overlays ────────────────────────────────────────
PID=$(agent_pid)   # the watchdog may have recycled a frozen agent
WAIT=40 run_case C18 "raise the agent's oom_score_adj to 900" allowed "integrity_drift" 0 -- bash -c "echo 900 > /proc/$PID/oom_score_adj"
echo -500 > /proc/$PID/oom_score_adj 2>/dev/null || true
# a fresh name each run: once the agent has seen an overlay it protects it,
# so a leftover cannot be removed until the lab purges the pins
OVL="$ETC/zz-tamper-$(date +%s).local"
# External audit EBPF-015: a new entry in /etc/northnarrow is refused.
run_case C19 "drop a .local overlay in /etc/northnarrow" denied "op=create" 0 -- bash -c "echo '+evil-implant' > $OVL"
# ── kills nothing can refuse, saturation, io_uring ────────────────────────
CGK=/sys/fs/cgroup/system.slice/northnarrow-agent.service/cgroup.kill
if [[ -w "$CGK" ]]; then
    # kernel-generated SIGKILL: no task_kill hook on this path. The watchdog
    # brings the agent back; the new boot must say its predecessor died
    # without agent_stop.
    WAIT=25 run_case C20 "cgroup.kill on the agent's unit" allowed "prev_run_abrupt" 0 -- bash -c "echo 1 > $CGK"
    PID=$(agent_pid)
fi
# 20k execs to overflow the exec ring, one exec from /tmp hidden inside:
# either the exec is caught (R001) or the loss itself is signed evidence.
WAIT=12 run_case C21 "exec flood (20k) hiding an exec from /tmp" allowed "R001_ExecFromTmp|R009_RootExecFromUserPath|ringbuf_drop" 0 -- bash -c 'cp /bin/true "$TMPD/nn-sat" && { for i in $(seq 1 20000); do /bin/true; done & sleep 2; "$TMPD/nn-sat"; wait; rm -f "$TMPD/nn-sat"; }'
# open + read + connect through an io_uring ring: no openat/connect syscall
# from userland (the openat tracepoint is blind to it by construction).
IOU_SRC="$(dirname "$0")/iouring-probe.c"
IOU_BIN=/usr/local/libexec/nn-lab/nn-iou-probe
if [[ $(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo 0) == 2 ]]; then
    # RHEL 9 ships kernel.io_uring_disabled=2: no ring, not even for root.
    skipped_case C22 "io_uring_disabled=2" 1
elif [[ -f "$IOU_SRC" ]] && mkdir -p "$(dirname "$IOU_BIN")" && cc -O2 -o "$IOU_BIN" "$IOU_SRC" 2>"$TMPD/iou-cc.log"; then
    WAIT=8 run_case C22 "io_uring: openat + read + connect through a ring" allowed "NN-L-IOU-00[12]" 0 -- "$IOU_BIN" /etc/hostname 127.0.0.1 9
else
    skipped_case C22 "cannot build the io_uring probe: $(head -1 "$TMPD/iou-cc.log" 2>/dev/null)" 0
fi
# ── signed overlays (Tappa 10.8) ──────────────────────────────────────────
# An unsigned exemption appended to the allowlist overlay, then a restart:
# the agent must boot on the shipped defaults and record the refusal. The
# overlay is written inside a window (EBPF-015: a new file in the directory
# is refused outside one), as a stopped agent's host would let it be.
WAIT=20 run_case C23 "unsigned allowlist overlay + agent restart" allowed "unauthorized_overlay" 0 -- bash -c "grant_window && echo '+evil-implant' >> $ETC/process-comm-allowlist.local && restart_agent"
PID=$(agent_pid)
# The same overlay stored the authorised way (lab key, config-manage),
# then a restart: stored with its signature, accepted at boot.
printf '+backupd\n' > "$TMPD/ovl-allow"
WAIT=20 run_case C24 "nn-admin config overlay set + agent restart" allowed "config_overlay_set.*overlay_accepted|overlay_accepted.*config_overlay_set" 0 -- bash -c "$NNADMIN config overlay set process-comm-allowlist --file $TMPD/ovl-allow --key $ADMIN_KEY && restart_agent"
PID=$(agent_pid)
# Review 62: after a restart the task deny hooks must still report. They
# were reused from the pinned link, bound to the previous boot's ring, so
# C01-C03 passed on a fresh install and the same attempts left no
# evidence once the agent had restarted (C23/C24 just did).
agent_signal_case C28 "kill -9 the agent after an agent restart" KILL
agent_mem_case C29 "ptrace attach after an agent restart"
# Review 63: the pinned PROTECTED_INODES map outlives the agent. Each boot
# protects new inodes (the pins of the hooks reattached fresh), and the
# earlier boots' keys piled up until an insert failed at 1024 entries and
# the agent refused to start. One more restart must not grow it.
# External audit LAB-004 (C61): the same for PROTECTED_PIDS, 16 slots
# (task_kill.rs): every boot registers its own PID, and the entries a boot
# leaves behind must be evicted by the next one. A stale entry is worse
# than a full map: whatever process reuses that PID cannot be signalled.
if [[ "$BPF_MODE" == enforce ]]; then
    # bpftool opens maps read-write, which the guard refuses in enforce mode:
    # the count would read 0 → 0 and prove nothing.
    for c in "C30 PROTECTED_INODES" "C61 PROTECTED_PIDS"; do
        selected "${c%% *}" || continue
        rows+=("| ${c%% *} | ${c#* } across an agent restart | SKIPPED (enforce: bpftool cannot open the map) | — | N/A (enforce mode) |")
        echo "${c%% *} skipped: the BPF guard is in enforce mode (bpftool cannot open the map)" >&2
    done
elif selected C30 || selected C61; then
    pi_count() { bpftool -j map dump pinned /sys/fs/bpf/northnarrow/PROTECTED_INODES 2>/dev/null | grep -o '"key":' | wc -l; }
    pp_scan() { bpftool -j map dump pinned "$PINS/PROTECTED_PIDS" 2>/dev/null | nnpy map-pids; }
    n1=$(pi_count); p1=$(pp_scan); restart_agent; sleep 20; n2=$(pi_count); p2=$(pp_scan); PID=$(agent_pid)
    if selected C30; then
        if (( n2 > n1 )); then v="DEVIATION (grew by $(( n2 - n1 )))"; fail=1; else v="OK"; fi
        rows+=("| C30 | PROTECTED_INODES across an agent restart | $n1 → $n2 entries | — | $v |")
        echo "C30 PROTECTED_INODES across an agent restart → $n1 → $n2 entries; $v" >&2
    fi
    if selected C61; then
        # "total=N stale=M[ pids=…]": stale = no live agent or watchdog at that PID
        t1=$(sed -n 's/^total=\([0-9]*\).*/\1/p' <<<"$p1"); t2=$(sed -n 's/^total=\([0-9]*\).*/\1/p' <<<"$p2")
        s2=$(sed -n 's/.* stale=\([0-9]*\).*/\1/p' <<<"$p2")
        if [[ -z "$t1" || -z "$t2" || -z "$s2" ]]; then v="DEVIATION (map unreadable: '$p1' / '$p2')"; fail=1
        elif (( s2 > 0 )); then v="DEVIATION (stale entries after the restart: ${p2#* })"; fail=1
        elif (( t2 > t1 )); then v="DEVIATION (grew by $(( t2 - t1 )))"; fail=1
        else v="OK"; fi
        rows+=("| C61 | PROTECTED_PIDS across an agent restart | ${t1:-?} → ${t2:-?} entries, ${s2:-?} stale | — | $v |")
        echo "C61 PROTECTED_PIDS across an agent restart → $p1 → $p2; $v" >&2
    fi
fi
# Kernel lockdown (integrity or confidentiality) is the host setting that
# closes unsigned modules; without it that is a known gap, with it a missing
# refusal is a deviation. The agent itself runs unchanged under
# lockdown=integrity (verified on Ubuntu 22.04 / 5.15). kexec is refused by
# the agent itself since review 82, lockdown or not.
LOCKDOWN=$(grep -o '\[[a-z]*\]' /sys/kernel/security/lockdown 2>/dev/null | tr -d '[]')
KGAP=1
[[ "$LOCKDOWN" == integrity || "$LOCKDOWN" == confidentiality ]] && KGAP=0
# The initrd is /boot/initrd.img-<ver> on Debian/Ubuntu, /boot/initramfs-<ver>.img
# on RHEL: a missing one made kexec fail before the load, read as "allowed".
KINITRD=/boot/initrd.img-$(uname -r)
[[ -f $KINITRD ]] || KINITRD=/boot/initramfs-$(uname -r).img
if command -v kexec >/dev/null 2>&1; then
    POST=$(post post_kexec_empty) \
    run_case C17 "kexec -l of the running kernel (lockdown: ${LOCKDOWN:-none})" denied "NN-L-AT-001" 0 -- kexec -l /boot/vmlinuz-$(uname -r) --initrd="$KINITRD" --reuse-cmdline
    kexec -u 2>/dev/null || true
fi
# An unsigned module (dummy.ko with its signature stripped), loaded with a
# bare finit_module() so the refusal is the kernel's, not R011 killing a
# module tool. Only under lockdown: without it the load would succeed and
# taint the kernel. Livepatches are modules too and take the same check.
ko=$(modinfo -n dummy 2>/dev/null)
case "$ko" in
    *.ko)     cp "$ko" "$TMPD/nn_signed_dummy.ko" 2>/dev/null ;;
    *.ko.zst) zstd -qdc "$ko" > "$TMPD/nn_signed_dummy.ko" 2>/dev/null ;;
    *.ko.xz)  xz -dc "$ko" > "$TMPD/nn_signed_dummy.ko" 2>/dev/null ;;
    *)        rm -f "$TMPD/nn_signed_dummy.ko" ;;
esac
if (( ! KGAP )) && [[ -s "$TMPD/nn_signed_dummy.ko" ]]; then
    python3 - "$TMPD/nn_signed_dummy.ko" "$TMPD/nn_unsigned_dummy.ko" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
magic = b"~Module signature appended~\n"
if data.endswith(magic):
    sig_len = int.from_bytes(data[-len(magic) - 4:-len(magic)], "big")
    data = data[:-len(magic) - 12 - sig_len]
open(sys.argv[2], "wb").write(data)
PY
    rmmod dummy 2>/dev/null
    POST=$(post post_module_absent dummy) \
    run_case C27 "load an unsigned module (finit_module, lockdown: $LOCKDOWN)" denied "" 0 -- python3 -I -c '
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
fd = os.open(os.environ["TMPD"] + "/nn_unsigned_dummy.ko", os.O_RDONLY)
if libc.syscall(313, fd, b"", 0) != 0:
    print("finit_module: errno=" + errno.errorcode.get(ctypes.get_errno(), "?"))
else:
    print("loaded")
'
    rmmod dummy 2>/dev/null
fi
rm -f "$TMPD/nn_signed_dummy.ko" "$TMPD/nn_unsigned_dummy.ko"

# ── systemd as the relay (external audit EBPF-001) ───────────────────────
# Outside a trusted-installer window PID 1's signals are refused like a root
# shell's (`systemctl kill` reports EPERM) and the units refuse a manual
# stop (RefuseManualStop=yes).
PID=$(agent_pid)
START=$(proc_start "$PID")
POST=$(post post_proc "${PID:-0}" "${START:-0}" northnarrow-age) \
run_case C31 "systemctl kill -s SIGKILL the agent (no window)" denied "op=signal" 0 -- systemctl kill -s SIGKILL northnarrow-agent
WDPID=$(wd_pid); WDSTART=$(proc_start "$WDPID")
POST=$(post post_proc "${WDPID:-0}" "${WDSTART:-0}" northnarrow-wat) \
run_case C32 "systemctl kill -s SIGSTOP the watchdog (no window)" denied "op=signal" 0 -- systemctl kill -s SIGSTOP northnarrow-watchdog
if [[ -z "$ONLY" || ",$ONLY," == *",C33,"* ]]; then
    t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
    out=$(timeout 60 systemctl stop northnarrow-agent 2>&1); rc=$?
    sleep 2; ev=$(evidence "$t0" "$a0" "$d0")
    if (( rc != 0 )) && [[ "$(agent_pid)" == "$PID" ]] && kill -0 "$PID" 2>/dev/null \
       && systemctl is-active --quiet northnarrow-agent; then
        v="OK"; st="denied (refused by systemd: $(echo "$out" | head -1 | cut -c1-60))"
    else
        v="DEVIATION (stopped, or reported stopped)"; fail=1; st="allowed"
    fi
    rows+=("| C33 | systemctl stop the agent (no window) | $st | $ev | $v |")
    echo "C33 systemctl stop the agent (no window) → $st; $ev; $v" >&2
fi

# ── vectors the matrix lacked (external audit LAB-004, lab PR 154) ───────
# C55-C61 (C47-C54 are lab PR 152's new-entry cases, which also cover
# create/link/symlink/mknod/mkdir/xattr in the protected directories; none
# is repeated here). Reboot persistence is C62, run with --persistence.
#
# C55: every signal other than SIGKILL from a root shell. task_kill is
# deny-by-default towards a protected PID (audit task-kill-signals-1:
# SIGINT/SIGHUP stopped the agent cleanly, SIGSTOP froze it); one case each.
for sig in STOP:a INT:b HUP:c QUIT:d SEGV:e ABRT:f BUS:g; do
    agent_signal_case "C55${sig#*:}" "SIG${sig%:*} to the agent from a root shell" "${sig%:*}"
done
# C56: replacing the agent's executables. A running binary cannot be opened
# for writing (ETXTBSY, the kernel's own refusal); what replaces it is a
# rename over it or an unlink, both refused by the inode hooks. The copy
# renamed over the agent binary is byte-identical, and the watchdog binary
# is put back if it was unlinked, so a deviation leaves a working install.
BIN_DIR=$(dirname "${AGENT_EXE:-/usr/local/bin/northnarrow-agent}")
if selected C56a && BIN_TMP=$(mktemp "$BIN_DIR/.nn-lab-c56.XXXXXX") \
        && CLEAN_FILES+=("$BIN_TMP") && cp -p "$BIN_DIR/northnarrow-agent" "$BIN_TMP"; then
    POST=$(post post_same "$BIN_DIR/northnarrow-agent" ino "$(nnpy fileid "$BIN_DIR/northnarrow-agent" ino)") \
    run_case C56a "rename a copy over the agent binary" denied "op=rename" 0 -- nnpy file rename "$BIN_TMP" "$BIN_DIR/northnarrow-agent"
fi
[[ -n "${BIN_TMP:-}" ]] && rm -f "$BIN_TMP"
if selected C56b && cp -p "$BIN_DIR/northnarrow-watchdog" "$SCRATCH/northnarrow-watchdog"; then
    RESTORE+=("$BIN_DIR/northnarrow-watchdog|$SCRATCH/northnarrow-watchdog")
    POST=$(post post_same "$BIN_DIR/northnarrow-watchdog" ino "$(nnpy fileid "$BIN_DIR/northnarrow-watchdog" ino)") \
    run_case C56b "unlink the watchdog binary" denied "op=unlink" 0 -- nnpy file unlink "$BIN_DIR/northnarrow-watchdog"
    restore_missing "$BIN_DIR/northnarrow-watchdog" "$SCRATCH/northnarrow-watchdog"
fi
# C57: destroying the evidence. A path truncate(2) of audit.log goes through
# inode_setattr; `: > detections.jsonl` opens for writing with O_TRUNC
# (file_open). Copies are taken first and, if a chain was cut, kept in
# /root for the operator: the suite does not write into a live chain.
keep_copy() {   # <case> <copy> <name>: a copy of what a deviation destroyed
    local dst; dst="/root/nn-lab-$1-$(date +%s)-$3"
    cp -p "$2" "$dst" 2>/dev/null && echo "$1: the pre-case copy is kept at $dst" >&2
}
if selected C57a && cp -p "$AUDIT" "$SCRATCH/audit.log"; then
    a_before=$(nnpy fileid "$AUDIT" size)
    POST=$(post post_not_shrunk "$AUDIT" "$a_before") \
    run_case C57a "truncate(2) audit.log to 0 bytes" denied "op=setattr" 0 -- nnpy file truncate "$AUDIT"
    post_not_shrunk "$AUDIT" "$a_before" >/dev/null || keep_copy C57a "$SCRATCH/audit.log" audit.log
fi
if selected C57b && cp -p "$DETS" "$SCRATCH/detections.jsonl"; then
    d_before=$(nnpy fileid "$DETS" size)
    POST=$(post post_not_shrunk "$DETS" "$d_before") \
    run_case C57b ": > detections.jsonl (open with O_TRUNC)" denied "op=write" 0 -- nnpy file open-trunc "$DETS"
    post_not_shrunk "$DETS" "$d_before" >/dev/null || keep_copy C57b "$SCRATCH/detections.jsonl" detections.jsonl
fi
# C58: a renamed module tool. R011 matches the comm (insmod, modprobe,
# kmod); a copy of the tool under another name, run as `modprobe` through
# argv[0], is not R011's. The load itself is R018's (kernel_read_file),
# whatever the loader calls itself: expect R018, allowed (an alert).
ko=$(modinfo -n dummy 2>/dev/null)
if selected C58 && [[ -n "$ko" && "$ko" != "(builtin)" ]] && command -v modprobe >/dev/null; then
    MODLD=/usr/local/libexec/nn-lab/nn-modld
    if mkdir -p "$(dirname "$MODLD")" && cp "$(readlink -f "$(command -v modprobe)")" "$MODLD"; then
        rmmod dummy 2>/dev/null
        run_case C58 "a renamed module tool loads dummy (comm nn-modld)" allowed "R018_KernelModuleLoad" 0 -- bash -c "exec -a modprobe $MODLD dummy"
        rmmod dummy 2>/dev/null
    fi
    rm -f "$MODLD"
fi
# C59: io_uring requests on protected paths. The ring executes them in the
# kernel, past every syscall tracepoint; the deny hooks sit in the VFS and
# must refuse them like the syscalls (C22 covers the sensors' blind spot).
# The rename, if it went through, is renamed back by the probe; the
# unlinked file is put back from a copy.
IOU_BIN=/usr/local/libexec/nn-lab/nn-iou-probe
IOU_TGT=$ETC/netflow-blocklist.v1
if [[ $(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo 0) == 2 ]]; then
    skipped_case C59a-C59c "io_uring_disabled=2" 1
elif [[ -x "$IOU_BIN" ]] && "$IOU_BIN" --modes 2>/dev/null | grep -qw rename; then
    POST=$(post post_not_shrunk "$AUDIT" "$(nnpy fileid "$AUDIT" size)") \
    run_case C59a "io_uring: open audit.log for writing through a ring" denied "op=write" 0 -- "$IOU_BIN" --open-write "$AUDIT"
    if cp -p "$IOU_TGT" "$SCRATCH/iou-target"; then
        RESTORE+=("$IOU_TGT|$SCRATCH/iou-target")
        IOU_ID=$(nnpy fileid "$IOU_TGT" ino)
        POST=$(post post_same "$IOU_TGT" ino "$IOU_ID") \
        run_case C59b "io_uring: unlink a protected file through a ring" denied "op=unlink" 0 -- "$IOU_BIN" --unlink "$IOU_TGT"
        restore_missing "$IOU_TGT" "$SCRATCH/iou-target"
        POST=$(post post_same "$IOU_TGT" ino "$IOU_ID") \
        run_case C59c "io_uring: rename a protected file through a ring" denied "op=rename" 0 -- "$IOU_BIN" --rename "$IOU_TGT" "$IOU_TGT.nn-lab-c59c"
    fi
else
    skipped_case C59a-C59c "no io_uring probe with the tamper modes (see C22)" 0
fi
# C60: masking the watchdog. `systemctl mask` cannot replace an installed
# unit file (systemd refuses: the file exists), and in /etc/systemd/system
# the unit is protected; what a root shell can do is a runtime mask — a
# symlink to /dev/null in /run/systemd/system, outside every protected
# directory. Nothing can refuse it (no create hook there): the integrity
# check must report it (unit_shadowed). The runtime mask, unlike a
# persistent one, cannot outlive a reboot; it is undone right after the
# check, and by the trap.
if selected C60; then
    WD_MASKED=1
    WAIT=40 run_case C60 "systemctl mask --runtime the watchdog" allowed "unit_shadowed" 0 -- systemctl mask --runtime northnarrow-watchdog
    systemctl unmask --runtime northnarrow-watchdog >/dev/null 2>&1 && WD_MASKED=0
fi
# C57c: the journal namespace is the secondary evidence channel; root can
# vacuum it and nothing refuses that (KNOWN GAP: the signed chains are the
# record). Without --rotate only archived journal files go, so this run's
# own lines stay readable; it runs after the cases that read older ones.
run_case C57c "journalctl --vacuum-time=1s on the agent's journal namespace" denied "" 1 -- \
    journalctl --namespace=northnarrow --vacuum-time=1s

# ── the agent's own binaries (external audit EBPF-002) ───────────────────
# Running the agent's, the watchdog's or nn-admin's executable is no longer
# an exemption: root could preload its own library into one of them and
# take the agent's maps or links. A fresh agent or watchdog binary takes
# write handles only while its role has no live process (the successor of
# one that exited), from its main thread, in its first minute; no binary is
# exempt from the link deny, and a process running one of the two binaries
# cannot be ptraced before it registers.
PBF_SRC="$(dirname "$0")/bpf-handle-probe.c"
PBF_LIB=/usr/local/libexec/nn-lab/nn-bpf-probe.so
AGENT_BIN=${AGENT_EXE:-/usr/local/bin/northnarrow-agent}
WATCHDOG_BIN=$(dirname "$AGENT_BIN")/northnarrow-watchdog
if [[ -f "$PBF_SRC" ]] && mkdir -p "$(dirname "$PBF_LIB")" && cc -shared -fPIC -O2 -o "$PBF_LIB" "$PBF_SRC" 2>"$TMPD/pbf-cc.log"; then
    env LD_PRELOAD="$PBF_LIB" NNX_SLEEP=20 "$AGENT_BIN" >/dev/null 2>&1 &
    FRESH=$!
    sleep 1
    FRESH_START=$(proc_start "$FRESH")
    run_case C34 "ptrace attach: /proc/<pid>/mem of a fresh agent binary" denied "op=ptrace" 0 -- nnpy procopen "$FRESH" northnarrow-age "${FRESH_START:-0}" mem 4194304
    # our own child, still unreaped; signalled only if it is still that process
    nnpy signal "$FRESH" northnarrow-age "${FRESH_START:-0}" TERM >/dev/null 2>&1; wait "$FRESH" 2>/dev/null
    run_case C35 "nn-admin, preloaded: write handle on PROTECTED_PIDS" "$BPF_EXPECT" "NN-L-BPF-002|op=bpf_map" 0 -- env LD_PRELOAD="$PBF_LIB" "$NNADMIN" --version
    run_case C36 "a second agent binary, preloaded: write handle on PROTECTED_PIDS" "$BPF_EXPECT" "NN-L-BPF-002|op=bpf_map" 0 -- env LD_PRELOAD="$PBF_LIB" "$AGENT_BIN" --version
    run_case C37 "a second watchdog binary, preloaded: handle on link_task_kill" "$BPF_EXPECT" "NN-L-BPF-002|op=bpf_link" 0 -- env LD_PRELOAD="$PBF_LIB" NNX_TARGET="$PINS/link_task_kill" "$WATCHDOG_BIN" --version
    # External audit ATP-013: the twelve ring buffers and RING_DROPS left
    # the eBPF object before the guard listed the agent's maps; by id, a
    # foreign root process got a writable handle on each.
    run_case C43 "a foreign root process: write handles on the agent's ring buffers, by id" "$BPF_EXPECT" "NN-L-BPF-002|op=bpf_map" 0 -- env LD_PRELOAD="$PBF_LIB" NNX_RINGS=1 /bin/true
else
    skipped_case C34-C37 "cannot build the probe library: $(head -1 "$TMPD/pbf-cc.log" 2>/dev/null)" 0
fi
# The way in that stays open: a watchdog restarted inside a window is the
# fresh successor of its role and registers itself (the agent's restart is
# C23/C24/C28-C30). It exits cleanly on SIGTERM (Restart=on-failure does not
# bring it back): the operator starts it, as install.sh does.
if [[ -z "$ONLY" || ",$ONLY," == *",C38,"* ]]; then
    t0=$(date -u +"%Y-%m-%d %H:%M:%S")
    old=$(systemctl show -p MainPID --value northnarrow-watchdog)
    grant_window 20
    systemctl kill --signal=SIGTERM northnarrow-watchdog
    for i in $(seq 1 10); do
        sleep 1
        systemctl is-active --quiet northnarrow-watchdog || break
    done
    systemctl start northnarrow-watchdog
    new=""
    for i in $(seq 1 40); do
        sleep 1
        new=$(systemctl show -p MainPID --value northnarrow-watchdog)
        [[ -n "$new" && "$new" != 0 && "$new" != "$old" ]] && break
    done
    sleep 5
    if [[ -n "$new" && "$new" != 0 && "$new" != "$old" ]] \
       && jlines "$t0" | grep -q "watchdog PID registered in PROTECTED_PIDS pid=$new"; then
        v="OK"; st="restarted $old → $new, registered"
    else
        v="DEVIATION (the restarted watchdog did not register)"; fail=1; st="restarted $old → ${new:-?}"
    fi
    rows+=("| C38 | the watchdog restarted in a window registers itself | $st | — | $v |")
    echo "C38 the watchdog restarted in a window registers itself → $st; $v" >&2
    # the agent kept running: leave no open window behind
    for i in $(seq 1 40); do window_open || break; sleep 1; done
fi

# ── the agent's links (external audit EBPF-010) ──────────────────────────
# A handle on one of the agent's pinned links: through a path padded past
# the hook's buffer (it used to pass the name check), and through a symlink
# (a check on the caller's string cannot follow it). Whatever the handle,
# detaching or replacing the hook is refused to a foreign process — the
# kernels we support refuse both on these link types anyway (EOPNOTSUPP /
# EINVAL in observe mode).
LNK_SRC="$(dirname "$0")/link-detach-probe.c"
LNK_BIN=/usr/local/libexec/nn-lab/nn-link-probe
if [[ -f "$LNK_SRC" ]] && mkdir -p "$(dirname "$LNK_BIN")" && cc -O2 -o "$LNK_BIN" "$LNK_SRC" 2>"$TMPD/lnk-cc.log"; then
    long="$PINS/"
    while (( ${#long} < 280 )); do long+="./"; done
    long+="link_task_kill"
    run_case C39 "link handle through a $(( ${#long} ))-byte path to link_task_kill" "$BPF_EXPECT" "NN-L-BPF-002|op=bpf_link" 0 -- "$LNK_BIN" "$long"
    ln -sfn "$PINS/link_task_kill" "$TMPD/link-alias"
    run_case C40 "link detach/update through a symlink to link_task_kill" "$BPF_EXPECT" "NN-L-BPF-002|op=bpf_link" 0 -- "$LNK_BIN" "$TMPD/link-alias"
    rm -f "$TMPD/link-alias"
else
    skipped_case C39-C40 "cannot build the link probe: $(head -1 "$TMPD/lnk-cc.log" 2>/dev/null)" 0
fi

# External audit EVD-001: the agent's private signing key — every evidence
# chain is signed with it — is closed to any reader outside the agent's
# family, root included; its public half is what verification reads.
run_case C41 "read the agent's private signing key" denied "op=read" 0 -- nnpy file read "$ETC/agent.sig.key"
run_case C42 "verify the audit chain from the public half" allowed "" 0 -- \
    /usr/local/bin/nn-admin audit verify --from "$ETC/audit.log"

# External audit EBPF-008: the inode flags through the fsxattr interface —
# the file_ioctl deny filtered only FS_IOC_SETFLAGS (and held a wrong
# FS_IOC_FSSETXATTR number): root cleared `+i` on the state directory, the
# only thing keeping new entries out of it, or made audit.log append-only
# to the agent. ATP-008: the shipped `.v1` lists were mutation-denied only.
FSX_SRC="$(dirname "$0")/fsxattr-probe.c"
FSX_BIN=/usr/local/libexec/nn-lab/nn-fsxattr-probe
if [[ -f "$FSX_SRC" ]] && mkdir -p "$(dirname "$FSX_BIN")" && cc -O2 -o "$FSX_BIN" "$FSX_SRC" 2>"$TMPD/fsx-cc.log"; then
    POST=$(post post_flag "$STATE" i present) \
    run_case C44 "fsxattr: clear the immutable flag of the state directory" denied "op=ioctl" 0 -- "$FSX_BIN" "$STATE" -i
    POST=$(post post_flag "$ETC/audit.log" a absent) \
    run_case C45 "fsxattr: make audit.log append-only" denied "op=ioctl" 0 -- "$FSX_BIN" "$ETC/audit.log" +a
else
    skipped_case C44-C45 "cannot build the fsxattr probe: $(head -1 "$TMPD/fsx-cc.log" 2>/dev/null)" 0
fi
POST=$(post post_same "$ETC/netflow-blocklist.v1" hash "$(nnpy fileid "$ETC/netflow-blocklist.v1" hash)") \
run_case C46 "append to the shipped netflow blocklist" denied "op=write" 0 -- \
    bash -c "echo '# nn-lab C46' >> $ETC/netflow-blocklist.v1"

# External audit EBPF-015: no new entry in the agent's directories — a
# subdirectory, a symlink, a hard link, a FIFO, a file in the chain
# sub-directory, a directory among the pins — and no extended attribute
# changed on a protected inode (C19 is the plain file). Inside a
# trusted-installer window the same is allowed (C54).
PID=$(agent_pid)
LSRC=/etc/.nn-lab-c49-src
echo nn-lab > "$LSRC"
run_case C47 "mkdir in /etc/northnarrow" denied "op=mkdir" 0 -- mkdir "$ETC/.nn-lab-c47"
run_case C48 "symlink in /etc/northnarrow" denied "op=symlink" 0 -- ln -s /etc/hostname "$ETC/.nn-lab-c48"
run_case C49 "hard link into /etc/northnarrow" denied "op=link" 0 -- ln "$LSRC" "$ETC/.nn-lab-c49"
run_case C50 "FIFO in /etc/northnarrow" denied "op=mknod" 0 -- mkfifo "$ETC/.nn-lab-c50"
run_case C51 "new file in the state chain directory" denied "op=create" 0 -- bash -c ": > $STATE/detections/.nn-lab-c51"
run_case C52 "a directory among the bpffs pins" denied "op=mkdir" 0 -- mkdir "$PINS/nn-lab-c52"
run_case C53 "user.* xattr on admin.pub" denied "op=xattr" 0 -- \
    python3 -c "import os; os.setxattr('$ETC/admin.pub', 'user.nn_lab', b'1')"
rm -f "$LSRC"
if [[ -z "$ONLY" || ",$ONLY," == *",C54,"* ]]; then
    t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
    grant_window 30; sleep 2
    out=$(bash -c "mkdir $ETC/.nn-lab-c54 && rmdir $ETC/.nn-lab-c54 && : > $ETC/.nn-lab-c54f \
        && rm -f $ETC/.nn-lab-c54f && python3 -c \"import os; os.setxattr('$ETC', 'user.nn_lab', b'1'); os.removexattr('$ETC', 'user.nn_lab')\"" 2>&1); rc=$?
    sleep 4; ev=$(evidence "$t0" "$a0" "$d0")
    if (( rc == 0 )) && ! echo "$ev" | grep -qE "op=(create|mkdir|xattr|unlink|rmdir)"; then
        v="OK"; st="allowed"
    else
        v="DEVIATION (refused inside the window: $(echo "$out" | head -1 | cut -c1-80))"; fail=1; st="denied"
    fi
    rows+=("| C54 | new entries and an xattr inside a trusted-installer window | $st | $ev | $v |")
    echo "C54 new entries and an xattr inside a trusted-installer window → $st; $ev; $v" >&2
    for i in $(seq 1 40); do window_open || break; sleep 1; done
fi

echo
echo "| case | action | outcome | evidence | verdict |"
echo "|---|---|---|---|---|"
printf '%s\n' "${rows[@]}"
echo
echo "agent pid now $(agent_pid) (was $PID); units: $(systemctl is-active northnarrow-agent northnarrow-watchdog | tr '\n' ' ')"
(( fail == 0 )) && echo "anti-tamper check: OK (known gaps listed)" || echo "anti-tamper check: DEVIATIONS"
exit $fail
