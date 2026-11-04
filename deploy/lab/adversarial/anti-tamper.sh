#!/usr/bin/env bash
# Structured adversarial check of the anti-tamper (Tappa 10.8).
#
# Runs ON THE GUEST as root against the installed agent (one case per
# documented way of neutralising a Linux EDR, and answers two questions for
# each: was the action denied, and did it leave EVIDENCE in the signed chain
# logs (audit.log ops, detections.jsonl rule ids and, for NN-L-AT-001, the
# refused operation: deny=<op>)? External audit NN-AUD-413 (lab PR 167):
# the journal is not evidence — any user can make the agent log a name
# that reads like one of its lines; it only gives the agent's errors=<n>.
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
# External audit LAB-020/LAB-024/LAB-026 (lab PR 206): `--only` runs the
# setup and cleanup of the cases it names and nothing else, and every id it
# names is a row of the table; a case that cannot run here is a row too (N/A
# when the kernel lacks the interface, KNOWN GAP for C27 without lockdown, a
# DEVIATION otherwise), never a silent omission; what a case changes and the
# suite puts back (C11's drop-in, C12's MemoryMax, C25's unit, C18's
# oom_score_adj) must read as before, or the run fails; the state lines read
# from the journal (BPF guard mode, an open window, C11, C38) are events of
# the unit and process that wrote them (deploy/lab/lib/lab-records.py).
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
# External audit LAB-026 (NN-AUD-416, lab PR 206): `--only` without a value
# ran every case, the destructive ones too, and an id that names no case ran
# nothing and printed OK. It takes a list of case ids now, and each one must
# end up as a row of the table (only_unreported, at the end).
only_list_ok() { [[ ${1:-} =~ ^C([0-9]{2}|[1-9][0-9]{2})[a-z]?(,C([0-9]{2}|[1-9][0-9]{2})[a-z]?)*$ ]]; }  # lot 273c: C100 and later
while (( $# )); do
    case "$1" in
        --only)
            only_list_ok "${2:-}" || { echo "anti-tamper.sh: --only takes case ids, e.g. --only C01,C55a (got '${2:-}')" >&2; exit 2; }
            ONLY=$2; shift ;;
        --persistence) MODE=persistence ;;
        --selftest) MODE=selftest ;;
        *) echo "usage: anti-tamper.sh [--only C01,C02 | --persistence | --selftest]" >&2; exit 2 ;;
    esac
    shift
done
# deploy/lab/lib/lab-records.py: the journal lines the suite reads for state
# (the BPF guard mode, an open trusted-installer window, C11's registration,
# C38's), as events of the unit and process that wrote them (lab PR 206)
LABREC="$(cd "$(dirname "${BASH_SOURCE[0]}")/../lib" 2>/dev/null && pwd)/lab-records.py"
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
import ctypes, errno, hashlib, io, json, os, re, signal, subprocess, sys, tempfile, time
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
        elif op == "write" and arg is not None:
            # lot 273: a cgroup control file — the open is what the deny
            # refuses; a value the kernel rejects after it opened (ERANGE)
            # says it opened
            fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                os.write(fd, arg.encode())
            finally:
                os.close(fd)
            msg = "wrote %r" % arg
        elif op == "mkdir":
            os.mkdir(path)
            msg = "made"
        elif op == "rmdir":
            os.rmdir(path)
            msg = "removed"
        elif op == "chown" and arg is not None and arg.isdigit():
            os.lchown(path, int(arg), -1)
            msg = "owner set to %s" % arg
        else:
            print("setup: unknown file operation %r" % op)
            return 2
    except OSError as e:
        print("%s %s: errno=%s" % (op, path, ename(e.errno)))
        return 1
    print("%s %s: %s" % (op, path, msg))
    return 0

def cmd_cgmove(pid, comm, start, procs):
    # lot 273: move process <pid> (checked by comm and start time, never a
    # bare pid) into the cgroup whose cgroup.procs is <procs>
    cur, why = resolve(pid, comm, start)
    if cur is None:
        print("target=absent (%s)" % why)
        return 3
    if not procs.endswith("/cgroup.procs") or not procs.startswith("/sys/fs/cgroup/"):
        print("setup: %r is not a cgroup.procs under /sys/fs/cgroup" % procs)
        return 2
    try:
        fd = os.open(procs, os.O_WRONLY | os.O_NOFOLLOW)
        try:
            os.write(fd, pid.encode())
        finally:
            os.close(fd)
    except OSError as e:
        print("move %s to %s: errno=%s" % (pid, procs, ename(e.errno)))
        return 1
    print("moved %s to %s" % (pid, procs))
    return 0

def cmd_v1move(pid, comm, start, procs):
    # lot 273b: move process <pid> (checked as cgmove does) into a cgroup v1
    # hierarchy the case mounted under /run/nn-lab-v1/
    cur, why = resolve(pid, comm, start)
    if cur is None:
        print("target=absent (%s)" % why)
        return 3
    if not procs.endswith("/cgroup.procs") or not procs.startswith("/run/nn-lab-v1/"):
        print("setup: %r is not a cgroup.procs under /run/nn-lab-v1" % procs)
        return 2
    try:
        fd = os.open(procs, os.O_WRONLY | os.O_NOFOLLOW)
        try:
            os.write(fd, pid.encode())
        finally:
            os.close(fd)
    except OSError as e:
        print("move %s to %s: errno=%s" % (pid, procs, ename(e.errno)))
        return 1
    print("moved %s to %s" % (pid, procs))
    return 0

def cmd_fdlater(path, value, secs):
    # lot 273b: open <path> for writing now (inside a window, before a
    # registration), write <value> through that descriptor <secs> seconds
    # later; what the write said
    if not secs.isdigit() or int(secs) > 300:
        print("setup: bad delay %r" % secs)
        return 2
    try:
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        print("open %s: errno=%s (the descriptor was not opened)" % (path, ename(e.errno)))
        return 2
    try:
        time.sleep(int(secs))
        os.write(fd, value.encode())
    except OSError as e:
        print("write %r through the earlier descriptor of %s: errno=%s" % (value, path, ename(e.errno)))
        return 1
    finally:
        os.close(fd)
    print("wrote %r through the earlier descriptor of %s" % (value, path))
    return 0

def cmd_handlewrite(mount, path, value):
    # the review of #490 (B): <path>'s file handle (name_to_handle_at), the
    # dentries dropped (drop_caches 2), the file opened again through the
    # handle (open_by_handle_at: a disconnected dentry, named "/") and
    # <value> written; what the open and the write said
    if not path.startswith(mount.rstrip("/") + "/"):
        print("setup: %r is not under %r" % (path, mount))
        return 2
    import ctypes, ctypes.util
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)

    class FileHandle(ctypes.Structure):
        _fields_ = [("handle_bytes", ctypes.c_uint), ("handle_type", ctypes.c_int),
                    ("f_handle", ctypes.c_ubyte * 128)]
    fh = FileHandle()
    fh.handle_bytes = 128
    mount_id = ctypes.c_int()
    if libc.name_to_handle_at(-100, path.encode(), ctypes.byref(fh), ctypes.byref(mount_id), 0) != 0:
        print("name_to_handle_at %s: errno=%s (no handle)" % (path, ename(ctypes.get_errno())))
        return 2
    mfd = os.open(mount, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with open("/proc/sys/vm/drop_caches", "w") as f:
            f.write("2")
        fd = libc.open_by_handle_at(mfd, ctypes.byref(fh), os.O_WRONLY)
        if fd < 0:
            print("open_by_handle_at %s: errno=%s (not opened)" % (path, ename(ctypes.get_errno())))
            return 1
    finally:
        os.close(mfd)
    try:
        seen = os.readlink("/proc/self/fd/%d" % fd)
        os.write(fd, value.encode())
    except OSError as e:
        print("write %r through the handle of %s: errno=%s" % (value, path, ename(e.errno)))
        return 1
    finally:
        os.close(fd)
    print("wrote %r through the handle of %s (the descriptor's path: %s)" % (value, path, seen))
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
    stale = [p for p in pids if not live_entry(p)]
    return pids, stale

def parent_of(pid):
    try:
        with open("/proc/%s/stat" % pid) as f:
            text = f.read()
        return int(text[text.rindex(")") + 2:].split()[1])
    except (OSError, ValueError, IndexError):
        return None

def live_entry(pid):
    # a live agent or watchdog; R14a (lot 272): or a worker of a live agent
    # (its child under the worker's name, `nn-worker-<kind>`), registered
    # with the worker's role
    cur = ident(str(pid))
    if cur is None:
        return False
    if cur[0] in PROTECTED_COMMS:
        return True
    if cur[0].startswith("nn-worker-"):
        parent = parent_of(pid)
        return parent is not None and (ident(str(parent)) or ("",))[0] == "northnarrow-age"
    return False

def cmd_map_pids():
    try:
        pids, stale = map_pids(sys.stdin.read())
    except (ValueError, TypeError, AttributeError):
        print("unreadable")
        return 1
    print("total=%d stale=%d%s" % (len(pids), len(stale),
                                   " pids=" + ",".join(map(str, stale)) if stale else ""))
    return 0

# ── kernel loads through the bare syscall (external audit LAB-024, lab PR
# 206): the numbers of the machine the suite runs on — x86_64's own table,
# the generic one (asm-generic/unistd.h) of arm64 — where C27 used x86_64's
# 313 everywhere; on another machine the case is not run (a deviation).
SYSCALLS = {
    "x86_64": {"finit_module": 313, "kexec_file_load": 320},
    "aarch64": {"finit_module": 273, "kexec_file_load": 294},
}
KEXEC_FILE_UNLOAD, KEXEC_FILE_NO_INITRAMFS = 0x1, 0x4
MODULE_SIG_MAGIC = b"~Module signature appended~\n"

def syscall_nr(name, machine=None):
    return SYSCALLS.get(machine or os.uname().machine, {}).get(name)

def cmd_syscall_nr(name):
    nr = syscall_nr(name)
    if nr is None:
        return 1
    print(nr)
    return 0

def open_input(path):
    # a file the case needs, not the operation under test: a failure here is
    # "setup:", never an errno=/strerror text outcome_of would read as a refusal
    try:
        return os.open(path, os.O_RDONLY)
    except OSError as e:
        print("setup: cannot open %s (%s); nothing loaded" % (path, ename(e.errno)))
        return None

def raw_syscall(nr, *args):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    r = libc.syscall(ctypes.c_long(nr), *args)
    return r, ctypes.get_errno()

def cmd_finit(path):
    nr = syscall_nr("finit_module")
    if nr is None:
        print("setup: no finit_module number for %s; nothing loaded" % os.uname().machine)
        return 2
    fd = open_input(path)
    if fd is None:
        return 2
    try:
        r, e = raw_syscall(nr, ctypes.c_int(fd), ctypes.c_char_p(b""), ctypes.c_int(0))
    finally:
        os.close(fd)
    if r != 0:
        print("finit_module: errno=" + ename(e))
        return 1
    print("finit_module: loaded")
    return 0

def cmd_kexec_file(kernel, initrd):
    nr = syscall_nr("kexec_file_load")
    if nr is None:
        print("setup: no kexec_file_load number for %s; nothing loaded" % os.uname().machine)
        return 2
    with open("/proc/cmdline", "rb") as f:
        cmdline = f.read().strip()
    kfd = open_input(kernel)
    if kfd is None:
        return 2
    ifd, flags = -1, KEXEC_FILE_NO_INITRAMFS
    if initrd and os.path.exists(initrd):
        ifd, flags = open_input(initrd), 0
        if ifd is None:
            os.close(kfd)
            return 2
    try:
        r, e = raw_syscall(nr, ctypes.c_int(kfd), ctypes.c_int(ifd), ctypes.c_ulong(len(cmdline) + 1),
                           ctypes.c_char_p(cmdline), ctypes.c_ulong(flags))
    finally:
        os.close(kfd)
        if ifd >= 0:
            os.close(ifd)
    if r != 0:
        print("kexec_file_load: errno=" + ename(e))
        return 1
    print("kexec_file_load: image loaded")
    return 0

def cmd_kexec_unload():
    # KEXEC_FILE_UNLOAD frees the loaded image whichever call loaded it,
    # and reads no file: no kexec hook stands in its way
    nr = syscall_nr("kexec_file_load")
    if nr is None:
        return 2
    r, e = raw_syscall(nr, ctypes.c_int(-1), ctypes.c_int(-1), ctypes.c_ulong(0),
                       ctypes.c_char_p(None), ctypes.c_ulong(KEXEC_FILE_UNLOAD))
    if r != 0:
        print("kexec unload: errno=" + ename(e))
        return 1
    return 0

def strip_signature(data):
    # an appended module signature: <module><sig><12-byte module_signature
    # with the big-endian sig length last><magic>
    if data.endswith(MODULE_SIG_MAGIC):
        sig_len = int.from_bytes(data[-len(MODULE_SIG_MAGIC) - 4:-len(MODULE_SIG_MAGIC)], "big")
        data = data[:-len(MODULE_SIG_MAGIC) - 12 - sig_len]
    return data

def cmd_strip_sig(src, dst):
    with open(src, "rb") as f:
        data = strip_signature(f.read())
    with open(dst, "wb") as f:
        f.write(data)
    return 0

# ── evidence (external audit NN-AUD-413, lab PR 167) ─────────────────────
# What a case left is read from the agent's signed records, never from
# journal text: another user could write a whole journal line of their own
# (a file in /tmp named "x\nANTI-TAMPER DENIAL ... op=signal", logged with
# a raw Display field) or a field that reads like one. Every token printed
# is checked against a closed pattern; no record content is printed.
#   audit.log         the ops of the entries after line <a0>, plus the
#                     markers prev_run_abrupt / unauthorized_overlay /
#                     unit_shadowed (key and value of the parsed entry)
#   detections.jsonl  the rule ids of the records after line <d0>, and for
#                     NN-L-AT-001 the refused operation: deny=<op>
#   journal (stdin)   `journalctl -o json`; only errors=<n>: entries of the
#                     agent unit's own stdout (_SYSTEMD_UNIT and _TRANSPORT
#                     are set by journald, not by the writer) whose level
#                     field — the second of the line — is ERROR
AT_RULE = "NN-L-AT-001"
TOKEN = re.compile(r"[A-Za-z0-9_-]{1,80}")
OPNAME = re.compile(r"[a-z][a-z_0-9]{0,39}")  # lot 273b: `cgroup_v1`
SGR = re.compile(r"\x1b\[[0-9;]*m")
AUDIT_MARKS = (("ended", "abrupt", "prev_run_abrupt"),
               ("kind", "unauthorized_overlay", "unauthorized_overlay"),
               ("kind", "unit_shadowed", "unit_shadowed"))

def records_after(path, skip):
    recs, bad = [], 0
    try:
        with open(path, "rb") as f:
            for n, line in enumerate(f):
                if n < skip or not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    rec = None
                if isinstance(rec, dict):
                    recs.append(rec)
                else:
                    bad += 1
    except OSError:
        pass
    return recs, bad

def pairs(v):
    if isinstance(v, dict):
        for k, x in v.items():
            yield k, x
            yield from pairs(x)
    elif isinstance(v, list):
        for x in v:
            yield from pairs(x)

def tally(items):
    c = {}
    for x in items:
        c[x] = c.get(x, 0) + 1
    return "".join("%s\u00d7%d " % (k, c[k]) for k in sorted(c))

def journal_errors(lines):
    n = 0
    for line in lines:
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if not isinstance(e, dict) or e.get("_SYSTEMD_UNIT") != "northnarrow-agent.service" \
                or e.get("_TRANSPORT") != "stdout":
            continue
        m = e.get("MESSAGE")
        if isinstance(m, list):
            try:
                m = bytes(m).decode("utf-8", "replace")
            except (TypeError, ValueError):
                continue
        if not isinstance(m, str):
            continue
        f = SGR.sub("", m).split(None, 2)
        if len(f) >= 2 and f[1] == "ERROR":
            n += 1
    return n

def evidence_line(audit, a0, dets, d0, journal):
    arecs, abad = records_after(audit, int(a0))
    ops = [r["op"] for r in arecs if isinstance(r.get("op"), str) and OPNAME.fullmatch(r["op"])]
    marks = []
    for key, val, mark in AUDIT_MARKS:
        if mark not in marks and any(k == key and x == val for r in arecs for k, x in pairs(r)):
            marks.append(mark)
    drecs, dbad = records_after(dets, int(d0))
    rules, denied = [], []
    for r in drecs:
        rid = r.get("rule_id")
        if not isinstance(rid, str) or not TOKEN.fullmatch(rid):
            continue
        rules.append(rid)
        if rid.startswith(AT_RULE):
            op = r.get("operation")
            denied.append("deny=" + (op if isinstance(op, str) and OPNAME.fullmatch(op) else "?"))
    audit_s = tally(ops) + "".join(m + " " for m in marks) + ("unparsed=%d " % abad if abad else "")
    dets_s = tally(rules) + tally(denied) + ("unparsed=%d " % dbad if dbad else "")
    return "journal:[errors=%d] audit:[%s] detections:[%s]" % (journal_errors(journal), audit_s, dets_s)

def cmd_evidence(audit, a0, dets, d0):
    if not (a0.isdigit() and d0.isdigit()):
        print("setup: line counts must be numbers")
        return 2
    out = evidence_line(audit, a0, dets, d0, sys.stdin.buffer)
    sys.stdout.buffer.write((out + "\n").encode("utf-8"))
    sys.stdout.flush()
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
        # lot 273: the cgroup control-file operations, on plain files here
        with open(f, "w") as fh:
            fh.write("0")
        rc, out = quiet(cmd_file, "write", f, "1")
        check(rc == 0 and open(f).read() == "1", "write writes the value")
        rc, out = quiet(cmd_file, "write", g, "1")
        check(rc == 1 and "errno=ENOENT" in out and not os.path.exists(g), "write never creates")
        sub = os.path.join(d, "sub")
        rc, out = quiet(cmd_file, "mkdir", sub)
        check(rc == 0 and os.path.isdir(sub), "mkdir")
        rc, out = quiet(cmd_file, "rmdir", sub)
        check(rc == 0 and not os.path.exists(sub), "rmdir")
        rc, out = quiet(cmd_file, "chown", f, "x")
        check(rc == 2, "chown takes a numeric uid")
        rc, out = quiet(cmd_cgmove, str(os.getpid()), "x", "0", "/sys/fs/cgroup/cgroup.procs")
        check(rc == 3 and out.startswith("target=absent"), "cgmove checks the target's identity")
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
    # R14a: a process under a worker's name whose parent is no agent is stale
    check(not live_entry(os.getpid()) and not live_entry(gone), "a worker only as an agent's child")
    # evidence from the signed records (NN-AUD-413): a forged comm, a
    # file name that holds "op=signal", a journal entry another unit or
    # writer made, a level word inside a field: none of them counts
    forged = "x\nANTI-TAMPER DENIAL pid=1 op=signal"
    with tempfile.TemporaryDirectory() as d:
        a, t = os.path.join(d, "audit.log"), os.path.join(d, "detections.jsonl")
        with open(a, "w") as fh:
            fh.write('{"op":"before"}\n')
            for rec in ({"op": "agent_boot", "extra": {"previous": {"ended": "abrupt"}}},
                        {"op": "integrity_drift", "extra": {"kind": "unit_shadowed"}},
                        {"op": "bad op", "client_comm": forged, "extra": {"note": '"op":"signal"'}}):
                fh.write(json.dumps(rec) + "\n")
        with open(t, "w") as fh:
            fh.write('{"rule_id":"R000_before"}\n')
            for rec in ({"rule_id": "NN-L-AT-001_AntiTamperDenial", "operation": "signal",
                         "principal": {"comm": forged}},
                        {"rule_id": "R001_ExecFromTmp", "exe": "/tmp/x op=signal deny=signal"},
                        {"rule_id": "NN-L-AT-001_AntiTamperDenial", "principal": {"comm": "rm"}}):
                fh.write(json.dumps(rec) + "\n")
            fh.write("not json\n")
        agent = {"_SYSTEMD_UNIT": "northnarrow-agent.service", "_TRANSPORT": "stdout"}
        journal = [json.dumps(dict(agent, MESSAGE="2026-10-16T00:00:00.000000Z ERROR audit log open failed")),
                   json.dumps(dict(agent, MESSAGE="2026-10-16T00:00:00.000000Z  INFO x last=\"a ERROR b\"")),
                   json.dumps(dict(agent, MESSAGE=list(b"2026-10-16T00:00:00.000000Z ERROR \x07x"))),
                   json.dumps({"_SYSTEMD_UNIT": "northnarrow-watchdog.service", "_TRANSPORT": "stdout",
                               "MESSAGE": "2026-10-16T00:00:00.000000Z ERROR wd"}),
                   json.dumps(dict(agent, _TRANSPORT="journal", MESSAGE="t ERROR forged")),
                   json.dumps(dict(agent, MESSAGE="ANTI-TAMPER DENIAL pid=1 op=signal ERROR")),
                   "garbage"]
        ev = evidence_line(a, "1", t, "1", [x.encode() for x in journal])
        check(ev == "journal:[errors=2] audit:[agent_boot\u00d71 integrity_drift\u00d71 "
                    "prev_run_abrupt unit_shadowed ] detections:[NN-L-AT-001_AntiTamperDenial\u00d72 "
                    "R001_ExecFromTmp\u00d71 deny=?\u00d71 deny=signal\u00d71 unparsed=1 ]",
              "evidence from the signed records: %r" % ev)
        check("op=signal" not in ev and ev.count("deny=signal") == 1, "no forged denial counted")
        check(evidence_line(os.path.join(d, "none"), "0", os.path.join(d, "none"), "0", [])
              == "journal:[errors=0] audit:[] detections:[]", "evidence with no records")
    # the machine's own syscall numbers (LAB-024, lab PR 206), and none for
    # a machine without a table
    check(syscall_nr("finit_module", "x86_64") == 313 and syscall_nr("kexec_file_load", "x86_64") == 320,
          "x86_64 numbers")
    check(syscall_nr("finit_module", "aarch64") == 273 and syscall_nr("kexec_file_load", "aarch64") == 294,
          "arm64 numbers")
    check(syscall_nr("finit_module", "s390x") is None, "no number for an unknown machine")
    body = b"\x7fELF module"
    signed = body + b"S" * 7 + bytes(8) + (7).to_bytes(4, "big") + MODULE_SIG_MAGIC
    check(strip_signature(signed) == body and strip_signature(body) == body, "module signature stripped")
    # lot 273b: the v1 move writes only under /run/nn-lab-v1, the earlier
    # descriptor's delay is bounded, an unopened file is a setup failure
    v1child = subprocess.Popen(["sleep", "30"])
    try:
        for _ in range(100):
            cur = ident(str(v1child.pid))
            if cur and cur[0] == "sleep":
                break
            time.sleep(0.02)
        rc, out = quiet(cmd_v1move, str(v1child.pid), "sleep", cur[2], "/sys/fs/cgroup/cgroup.procs")
        check(rc == 2 and out.startswith("setup:"), "v1move refuses another tree: %r" % out)
    finally:
        v1child.kill()
        v1child.wait()
    rc, out = quiet(cmd_fdlater, "/nonexistent/x", "0", "1")
    check(rc == 2 and "errno=ENOENT" in out and "not opened" in out, "fdlater: a file that is not there: %r" % out)
    rc, out = quiet(cmd_fdlater, "/dev/null", "0", "x")
    check(rc == 2 and out.startswith("setup:"), "fdlater: a bad delay: %r" % out)
    rc, out = quiet(cmd_fdlater, "/dev/null", "0", "0")
    check(rc == 0 and "wrote" in out, "fdlater writes through its descriptor: %r" % out)
    rc, out = quiet(cmd_handlewrite, "/sys/fs/cgroup", "/etc/hostname", "x")
    check(rc == 2 and out.startswith("setup:"), "handlewrite: a path outside the mount: %r" % out)
    rc, out = quiet(cmd_finit, "/nonexistent/nn.ko")
    check(rc == 2 and out.startswith("setup:") and "errno=" not in out and "denied" not in out,
          "a missing input is a setup failure, not a refusal: %r" % out)
    # lot 273d: timedwrite — the write's outcome, and the seconds to the
    # first refusal of its kind appended to the detections after it
    import threading
    with tempfile.TemporaryDirectory() as td:
        tgt, dets = os.path.join(td, "ftrace_enabled"), os.path.join(td, "dets.jsonl")
        open(tgt, "w").close()
        with open(dets, "w") as f:
            f.write('{"rule_id":"NN-L-AT-001_AntiTamperDenial","operation":"sysctl"}\n')
        def later():
            time.sleep(0.05)
            with open(dets, "a") as f:
                f.write('{"rule_id":"NN-L-AT-001_AntiTamperDenial","operation":"signal"}\n')
                f.write('{"rule_id":"NN-L-AT-001_AntiTamperDenial","operation":"sysctl"}\n')
        th = threading.Thread(target=later)
        th.start()
        rc, out = quiet(cmd_timedwrite, tgt, "0", dets, "sysctl")
        th.join()
        parts = out.split()
        check(rc == 0 and parts[0] == "wrote" and parts[1] != "none" and 0.04 <= float(parts[1]) < 2,
              "timedwrite: the appended refusal, not the one before: %r" % out)
        check(open(tgt).read() == "0", "timedwrite wrote the value")
        rc, out = quiet(cmd_timedwrite, os.path.join(td, "nodir", "x"), "0", dets, "sysctl")
        check(rc == 0 and out.startswith("errno=ENOENT none"), "timedwrite: a refused write: %r" % out)
    print("python helper selftest: %d checks, %d failed%s" % (
        checks, len(fails), "".join("\n  FAIL: " + x for x in fails)))
    return 1 if fails else 0

# R1 of the external review of 04/11 (lot 273d): kernel.ftrace_enabled.
def write_value(path, value):
    try:
        fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            os.write(fd, value.encode())
        finally:
            os.close(fd)
        return "wrote"
    except OSError as e:
        return "errno=%s" % ename(e.errno)

def cmd_timedwrite(path, value, dets, op):
    # the write, then the seconds to the first NN-L-AT-001 record of `op`
    # appended to the signed detections after it (`none` within 5 s)
    try:
        start = os.path.getsize(dets)
    except OSError:
        start = 0
    t = time.monotonic()
    res = write_value(path, value)
    lat = "none"
    while time.monotonic() - t < 5:
        try:
            with open(dets, "rb") as f:
                if os.fstat(f.fileno()).st_size < start:
                    start = 0
                f.seek(start)
                tail = f.read()
        except OSError:
            tail = b""
        hit = False
        for line in tail.splitlines():
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if isinstance(r, dict) and str(r.get("rule_id", "")).startswith(AT_RULE) and r.get("operation") == op:
                hit = True
                break
        if hit:
            lat = "%.3f" % (time.monotonic() - t)
            break
        time.sleep(0.01)
    print(res, lat)
    return 0

def bpf_runs():
    # the run counts (kernel.bpf_stats_enabled=1) of the loaded BPF-LSM,
    # tracing (fentry/fexit, and tp_btf: a tracepoint, not ftrace) and
    # kprobe programs: {type: [programs, runs]}, and each tracing
    # program's {name: runs} under "per"
    out = subprocess.run(["bpftool", "-j", "prog", "show"], capture_output=True, text=True, timeout=60)
    s = {"lsm": [0, 0], "tracing": [0, 0], "kprobe": [0, 0], "per": {}}
    for p in json.loads(out.stdout or "[]"):
        t = p.get("type")
        if t in ("lsm", "tracing", "kprobe"):
            s[t][0] += 1
            s[t][1] += int(p.get("run_cnt", 0) or 0)
        if t == "tracing":
            k = "%s#%s" % (p.get("name", "?"), p.get("id", "?"))
            s["per"][k] = int(p.get("run_cnt", 0) or 0)
    return s

def ft_load():
    # what fires each kind: execs (bprm_check, file_open, commit_creds),
    # loopback connections (tcp_connect, tcp_close), signals (task_kill)
    for _ in range(40):
        subprocess.run(["/bin/true"])
    import socket
    for _ in range(5):
        try:
            socket.create_connection(("127.0.0.1", 22), timeout=1).close()
        except OSError:
            pass
    for _ in range(20):
        os.kill(os.getpid(), 0)

def cmd_ftmeasure(path):
    phases = []
    def phase():
        a = bpf_runs()
        ft_load()
        b = bpf_runs()
        phases.append({k: b["per"].get(k, 0) - a["per"].get(k, 0) for k in b["per"]})
        return " ".join("%s +%d" % (k, b[k][1] - a[k][1]) for k in ("lsm", "tracing", "kprobe"))
    try:
        first = bpf_runs()
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        print("setup: bpftool: %s" % e)
        return 2
    on = phase()
    w0 = write_value(path, "0\n")
    v0 = open(path).read().strip()
    off = phase()
    w1 = write_value(path, "1\n")
    v1 = open(path).read().strip()
    again = phase()
    # each tracing program that ran with ftrace on: its runs on / at 0 / on again
    per = ", ".join("%s %d/%d/%d" % (k.split("#")[0], phases[0].get(k, 0), phases[1].get(k, 0), phases[2].get(k, 0))
                    for k in sorted(phases[0]) if phases[0].get(k, 0) or phases[1].get(k, 0))
    print("programs lsm %d, tracing %d, kprobe %d; ftrace on: %s; write 0: %s, reads %s; then: %s; write 1: %s, reads %s; on again: %s; tracing on/0/on: %s" % (
        first["lsm"][0], first["tracing"][0], first["kprobe"][0], on, w0, v0, off, w1, v1, again, per or "none ran"))
    return 0

def cmd_sysctl_race(path, good, bad, tries):
    # a MEASURE (lot 273d; the coordinator's decision of 04/11): the write
    # deny judges a value-judged sysctl's bytes in the LSM hook, before the
    # kernel copies them; a second thread flips the one byte where `good`
    # and `bad` differ meanwhile. Part 1: of `tries` writes, how many put
    # `bad` in (each written back to `good` at once: the probe's write of a
    # harmless value goes through). Part 2: one more `bad` let in and left,
    # the seconds until the agent puts it back (its round), 90 s at most.
    import threading
    g, b = good.encode() + b"\n", bad.encode() + b"\n"
    diff = [i for i in range(len(g)) if g[i] != b[i]]
    if len(g) != len(b) or len(diff) != 1:
        print("setup: good and bad must differ in one byte"); return 2
    i, gv, bv = diff[0], g[diff[0]], b[diff[0]]
    sys.setswitchinterval(0.00005)
    buf = bytearray(g)
    stop = []
    def flip():
        while not stop:
            buf[i] = bv
            buf[i] = gv
    def now():
        return os.pread(fd, 32, 0).strip()
    fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
    refused = wins = n = 0
    th = threading.Thread(target=flip, daemon=True)
    t = time.monotonic()
    th.start()
    try:
        for n in range(1, int(tries) + 1):
            try:
                os.pwrite(fd, buf, 0)
            except OSError as e:
                if e.errno in (errno.EPERM, errno.EACCES):
                    refused += 1
                else:
                    print("errno=%s after %d writes" % (ename(e.errno), n)); break
            if now() == b.strip():
                wins += 1
                os.pwrite(fd, g, 0)
        part1 = "%d of %d writes put %s in (%d refused, %.1f s)" % (wins, n, bad, refused, time.monotonic() - t)
        print(part1, flush=True)
        # part 2: one let in, left for the agent
        left = None
        t2 = time.monotonic()
        while time.monotonic() - t2 < 30:
            try:
                os.pwrite(fd, buf, 0)
            except OSError:
                pass
            if now() == b.strip():
                left = time.time()
                break
    finally:
        stop.append(1)
        th.join()
    if left is None:
        os.close(fd)
        print("%s; part 2: no %s let in within 30 s" % (part1, bad))
        return 0
    back = None
    while time.time() - left < 90:
        if now() == g.strip():
            back = time.time() - left
            break
        time.sleep(0.1)
    if back is None:
        os.pwrite(fd, g, 0)
    os.close(fd)
    print("%s; part 2: one let in at %.3f, put back to %s by the agent %s" % (
        part1, left, good, "after %.1f s" % back if back is not None else "NOT within 90 s (written back by the probe)"))
    return 0

def main(argv):
    cmds = {
        "ident": (cmd_ident, 1), "signal": (cmd_signal, 4),
        "procopen": (cmd_procopen, 5), "fileid": (cmd_fileid, 2),
        "map-pids": (cmd_map_pids, 0), "selftest": (selftest, 0),
        "evidence": (cmd_evidence, 4), "syscall-nr": (cmd_syscall_nr, 1),
        "finit": (cmd_finit, 1), "kexec-file": (cmd_kexec_file, 2),
        "kexec-unload": (cmd_kexec_unload, 0), "strip-sig": (cmd_strip_sig, 2),
        "cgmove": (cmd_cgmove, 4), "v1move": (cmd_v1move, 4),
        "fdlater": (cmd_fdlater, 3), "handlewrite": (cmd_handlewrite, 3),
        "timedwrite": (cmd_timedwrite, 4), "ftmeasure": (cmd_ftmeasure, 1),
        "sysctl-race": (cmd_sysctl_race, 4),
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

# evidence since (t0, audit lines before, detection lines before).
# External audit NN-AUD-413 (lab PR 167): from the signed records — the
# NN-L-AT-001 detections (deny=<op>, their refused operation) and rule ids
# after line d0 of detections.jsonl, the ops after line a0 of audit.log —
# read by the python helper (cmd_evidence). The journal gives only
# errors=<n>, counted on the agent unit's own stdout entries by their level
# field: it used to give the denials and verdicts too, grepped anywhere in a
# line any user could make the agent write.
journal_json() { journalctl --namespace=northnarrow -u northnarrow-agent --since "$1" --no-pager -o json 2>/dev/null; }
evidence() {
    journal_json "$1" | nnpy evidence "$AUDIT" "${2:-0}" "$DETS" "${3:-0}"
}
# jentry <unit> <pid> <LEVEL> <message prefix> [since]: the messages of the
# events process <pid> of <unit> wrote at <LEVEL> in this boot whose message
# starts with the prefix (deploy/lab/lib/lab-records.py: journald's own
# _SYSTEMD_UNIT, _TRANSPORT and _PID fields, the message at the start of the
# line). External audit LAB-020/LAB-026 (lab PR 206): the state lines — the
# BPF guard mode, an open trusted-installer window, C11's registration and
# C38's — were grepped anywhere in the text of both units' lines, and a file
# named "… watchdog PID registered in PROTECTED_PIDS pid=<n>", run from /tmp
# by any user, is logged by the agent in a VERDICT line: C38 passed on it.
journal_entries() {   # <unit> <pid> [since]: `journalctl -o json`, this boot
    journalctl --namespace=northnarrow -b -u "$1" _PID="$2" ${3:+--since "$3"} --no-pager -o json 2>/dev/null
}
jentry() {
    [[ ${2:-} =~ ^[1-9][0-9]{0,9}$ ]] || return 1
    journal_entries "$1" "$2" "${5:-}" | python3 -I "$LABREC" journal "$1.service" "$2" "$3" "$4"
}

# valid_pid <pid> <comm>: a decimal PID above 1 whose /proc/<pid>/comm is
# <comm> (comm is readable without ptrace; /proc/<agent>/exe is not, C04b)
valid_pid() {
    [[ ${1:-} =~ ^[1-9][0-9]{0,9}$ ]] && (( $1 > 1 )) || return 1
    [[ "$(cat "/proc/$1/comm" 2>/dev/null)" == "$2" ]]
}
proc_start() { nnpy ident "${1:-0}" 2>/dev/null | cut -d' ' -f1; }
# own_link_ids <link probe output> (lab PR 215): the ids of its "own links:
# <id> …" line, each a decimal above 0; nothing (status 1) for any other
# output, or one token that is not an id.
own_link_ids() {
    local line id ids=()
    line=$(grep -m1 '^own links: ' <<<"${1:-}") || return 1
    for id in ${line#own links: }; do
        [[ $id =~ ^[1-9][0-9]{0,9}$ ]] || return 1
        ids+=("$id")
    done
    (( ${#ids[@]} )) || return 1
    echo "${ids[*]}"
}

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
post_same_text() {   # <path> <text before> (lot 273d: a sysctl's value)
    local now; now=$(cat "$1" 2>/dev/null)
    [[ "$now" == "$2" ]] || { echo "${1##*/} changed ($2 -> $now)"; return 1; }
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
# restored <case> <what> <before> <now> (lab PR 206): a state a case changed
# and the suite put back must read as it did before the case; otherwise the
# run fails with a row naming what was left.
restored() {
    [[ "$3" == "$4" ]] && return 0
    fail=1
    rows+=("| $1 | (cleanup) $2 not put back | $(tr -d '|' <<<"${3:-?} → ${4:-?}" | cut -c1-80) | — | DEVIATION (state left behind) |")
    echo "$1: $2 not put back: '$3' → '$4'" >&2
    return 1
}
# C18's agent, as found: "<pid> <start time> <oom_score_adj>". Written back
# to that same process only (a recycled agent sets its own value at boot).
OOM_RESTORE=
oom_restore() {
    [[ -n "$OOM_RESTORE" ]] || return 0
    local pid st val cst comm
    read -r pid st val <<<"$OOM_RESTORE"
    OOM_RESTORE=
    read -r cst _ comm <<<"$(nnpy ident "$pid" 2>/dev/null)"
    if [[ "$cst" != "$st" || "$comm" != northnarrow-age ]]; then
        echo "C18: the agent it changed (pid $pid) is gone; a new agent sets its own oom_score_adj" >&2
        return 0
    fi
    echo "$val" > "/proc/$pid/oom_score_adj" 2>/dev/null
    restored C18 "the agent's oom_score_adj" "$val" "$(cat "/proc/$pid/oom_score_adj" 2>/dev/null)"
}
# A kexec image C17 let in is unloaded, by the syscall (no file is read, so
# no hook stands in the way), else the tool; one still loaded fails the run.
KEXEC_UNLOAD=0
kexec_unload() {
    (( KEXEC_UNLOAD )) || return 0
    KEXEC_UNLOAD=0
    [[ "$(cat /sys/kernel/kexec_loaded 2>/dev/null)" == 1 ]] || return 0
    nnpy kexec-unload >/dev/null 2>&1 || kexec -u 2>/dev/null
    if [[ "$(cat /sys/kernel/kexec_loaded 2>/dev/null)" == 1 ]]; then
        echo "WARNING: a kexec image is still loaded — unload it by hand (kexec -u)" >&2
        fail=1
    fi
}
cleanup_done=0
cleanup_all() {   # idempotent; 1 when a mount could not be undone
    (( cleanup_done )) && return 0
    cleanup_done=1
    local r rc=0
    [[ -n "$CG_FROZEN" ]] && echo 0 > "$CG_FROZEN" 2>/dev/null
    oom_restore
    kexec_unload
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

# >>> case-selection (xtask/tests/lab_scripts.rs runs this block)
selected() { [[ -z "$ONLY" || ",$ONLY," == *",$1,"* ]]; }
# selected_any C34,C35,…: one of the cases is selected (the setup they share)
selected_any() {
    local id
    for id in ${1//,/ }; do selected "$id" && return 0; done
    return 1
}
# The --only ids no row of the table names (lab PR 206): a case that does
# not exist, or that a condition skipped without a row, must not read as OK.
only_unreported() {
    local id
    [[ -n "$ONLY" ]] || return 0
    for id in ${ONLY//,/ }; do
        printf '%s\n' ${rows[@]+"${rows[@]}"} | grep -qE "^\| ([^|]*,)?$id(,[^|]*)? \|" || echo "$id"
    done
}
report_unreported() {
    local id
    for id in $(only_unreported); do
        fail=1
        rows+=("| $id | (not run) | no such case, or it did not run | — | DEVIATION (--only $id: no row) |")
        echo "$id: asked for with --only, and no row names it → DEVIATION" >&2
    done
}
# External audit NN-AUD-222 (LAB-017): a case that does not run is a table
# row, never just a line on stderr. "Not applicable" (the kernel has the
# feature switched off: kernel.io_uring_disabled=2) is N/A; anything else
# (a probe that did not build) is a DEVIATION, so the run fails.
# External audit LAB-026 (lab PR 206): <ids> is a comma-separated list of
# the cases that did not run (C43 was missing from C34-C37's), and the row is
# made only for a run that selected one of them (--only C01 failed on a probe
# another case needs).
skipped_case() { # ids reason na(0|1)
    local v why
    selected_any "$1" || return 0
    why=$(tr -d '|' <<<"$2")
    if [[ "$3" == 1 ]]; then v="N/A ($why)"; else v="DEVIATION (not run: $why)"; fail=1; fi
    rows+=("| $1 | (not run) | SKIPPED ($why) | — | $v |")
    echo "$1 skipped: $2 → $v" >&2
}
# <<< case-selection

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
    # evidence() reads the signed records, the journal only for errors=
    # (NN-AUD-413): a stubbed journal with a forged denial line, records
    # in scratch files
    t eval '(d=$(mktemp -d); trap "rm -rf $d" EXIT; AUDIT=$d/a; DETS=$d/t
        printf "%s\n" "{\"op\":\"agent_boot\"}" > "$AUDIT"
        printf "%s\n" "{\"rule_id\":\"NN-L-AT-001_AntiTamperDenial\",\"operation\":\"ptrace\"}" > "$DETS"
        journal_json() { printf "%s\n" "{\"_SYSTEMD_UNIT\":\"northnarrow-agent.service\",\"_TRANSPORT\":\"stdout\",\"MESSAGE\":\"ANTI-TAMPER DENIAL pid=1 op=signal\"}"; }
        ev=$(evidence "x" 0 0)
        [[ "$ev" == "journal:[errors=0] audit:[agent_boot×1 ] detections:[NN-L-AT-001_AntiTamperDenial×1 deny=ptrace×1 ]" ]] \
            && ! grep -q "signal" <<<"$ev" && grep -qE "deny=ptrace" <<<"$ev")'
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
    # lab PR 206: --only takes case ids only (without a value it ran them all)
    for p in C01 C01,C55a C59a,C59b,C59c C100 C89,C101; do t only_list_ok "$p"; done
    for p in "" C1 c01 C01, ,C01 "C01 C02" "C01;id" C001 --persistence; do t eval "! only_list_ok '$p'"; done
    # a skipped case is a row only for a run that selected it; an --only id
    # no row names is reported; a restore that did not hold is a deviation
    t eval '(ONLY=C01; rows=(); fail=0; skipped_case C22,C59a "x" 0 2>/dev/null; (( ${#rows[@]} == 0 && fail == 0 )))'
    t eval '(ONLY=C59a; rows=(); fail=0; skipped_case C22,C59a "x" 0 2>/dev/null; (( ${#rows[@]} == 1 && fail == 1 )) && [[ ${rows[0]} == "| C22,C59a | (not run) | SKIPPED (x) | — | DEVIATION (not run: x) |" ]])'
    t eval '(ONLY=; rows=(); fail=0; skipped_case C22 "io|uring" 1 2>/dev/null; (( ${#rows[@]} == 1 && fail == 0 )) && [[ ${rows[0]} == "| C22 | (not run) | SKIPPED (iouring) | — | N/A (iouring) |" ]])'
    t eval '(ONLY=C01,C43,C99,C5; rows=("| C01 | a | denied | e | OK |" "| C34,C35,C43 | (not run) | x | — | N/A (x) |" "| C55a | b | c | d | OK |"); [[ "$(only_unreported | tr "\n" " ")" == "C99 C5 " ]])'
    t eval '(ONLY=C99; rows=(); fail=0; report_unreported 2>/dev/null; (( fail == 1 )) && [[ ${rows[0]} == "| C99 | (not run) |"* ]])'
    t eval '(ONLY=; rows=(); fail=0; report_unreported; (( ${#rows[@]} == 0 && fail == 0 )))'
    t eval '(rows=(); fail=0; restored C12 "x" infinity infinity && (( ${#rows[@]} == 0 && fail == 0 )))'
    t eval '(rows=(); fail=0; ! restored C12 "MemoryMax" infinity 4294967296 2>/dev/null && (( fail == 1 )) && [[ ${rows[0]} == "| C12 | (cleanup) MemoryMax not put back | infinity → 4294967296 | — | DEVIATION (state left behind) |" ]])'
    # the journal's state lines: lab-records.py, and jentry's plumbing with
    # a stubbed journal — a forged file name in a VERDICT line never counts
    t eval "python3 -I '$LABREC' --selftest >/dev/null"
    t eval '(journal_entries() {
            printf "%s\n" "{\"_SYSTEMD_UNIT\":\"northnarrow-watchdog.service\",\"_TRANSPORT\":\"stdout\",\"_PID\":\"$2\",\"MESSAGE\":\"2026-10-20T00:00:00.000000Z  INFO watchdog: watchdog PID registered in PROTECTED_PIDS pid=4242 bpffs_root=/sys/fs/bpf/northnarrow\"}"
        }
        jentry northnarrow-watchdog 4242 INFO "watchdog: watchdog PID registered in PROTECTED_PIDS pid=4242 " >/dev/null \
            && ! jentry northnarrow-watchdog 4242 INFO "watchdog: watchdog PID registered in PROTECTED_PIDS pid=424 " >/dev/null \
            && ! jentry northnarrow-watchdog "" INFO "watchdog:" >/dev/null)'
    t eval '(journal_entries() {
            printf "%s\n" "{\"_SYSTEMD_UNIT\":\"northnarrow-watchdog.service\",\"_TRANSPORT\":\"stdout\",\"_PID\":\"$2\",\"MESSAGE\":\"2026-10-20T00:00:00.000000Z  INFO VERDICT (rule) target_filename=\\\"/tmp/watchdog: watchdog PID registered in PROTECTED_PIDS pid=4242 \\\"\"}"
        }
        ! jentry northnarrow-watchdog 4242 INFO "watchdog: watchdog PID registered in PROTECTED_PIDS pid=4242 " >/dev/null)'
    # lab PR 215: the agent's link ids from the link probe's --own line
    t eq "$(own_link_ids $'x\nown links: 12 40 41')" "12 40 41"
    t eval '! own_link_ids "own links: 12 4x" >/dev/null'
    t eval '! own_link_ids "own links: " >/dev/null'
    t eval '! own_link_ids "own links: 0" >/dev/null'
    t eval '! own_link_ids "setup: no OWN_BPF_IDS map readable on this host; no link id read" >/dev/null'
    # the link probe builds and refuses what is not an id (C39, C40, C63, C64)
    src="$(dirname "$0")/link-detach-probe.c"
    if command -v cc >/dev/null && [[ -f "$src" ]]; then
        local ld; ld=$(mktemp -d)
        if cc -O2 -o "$ld/lnk" "$src" 2>"$ld/cc.log"; then
            for p in "--handle-by-id 0" "--handle-by-id 0x1" "--next-from 1,,x" "--next-from" "--own x" "--bogus"; do
                t eval "'$ld/lnk' $p >/dev/null 2>&1; (( \$? == 2 ))"
            done
            t eval "'$ld/lnk' --next-from 1,2 | grep -q '^BPF_LINK_GET_NEXT_ID after 2: '"
            t eval "'$ld/lnk' --handle-by-id 4294967295 | grep -q '^BPF_LINK_GET_FD_BY_ID 4294967295: '"
        else
            t eval "false # link-detach-probe.c does not build: $(head -1 "$ld/cc.log")"
        fi
        rm -rf "$ld"
    fi
    # this machine's syscall numbers exist (C17's fallback, C27)
    t eval '[[ "$(nnpy syscall-nr finit_module)" =~ ^[0-9]+$ && "$(nnpy syscall-nr kexec_file_load)" =~ ^[0-9]+$ ]]'
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
[[ -r "$LABREC" ]] || { echo "lab-records.py not found at $LABREC (run the suite from the repository: deploy/lab/adversarial/anti-tamper.sh)"; exit 2; }
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
# Lot 273d (C97/C98 seen timing-dependent by lots 275 and 277): each grant
# notes when its window ends and the audit row before it, for
# wait_no_window.
WIN_UNTIL=0; WIN_A0=0
grant_window() {
    local a rc
    a=$(audit_count)
    "$NNADMIN" trusted-installer-grant --key "$ADMIN_KEY" --window-secs "${1:-120}" >/dev/null 2>&1
    rc=$?
    (( rc == 0 )) && { WIN_UNTIL=$(( $(date +%s) + ${1:-120} )); WIN_A0=$a; }
    return $rc
}
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
audit_count() { wc -l < "$AUDIT" 2>/dev/null || echo 0; }
dets_count() { wc -l < "$DETS" 2>/dev/null || echo 0; }

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
    # EV_FORBID: evidence that must not be there (C24: the agent refusing
    # the overlay it was just given).
    if [[ -n "${EV_FORBID:-}" ]] && echo "$ev" | grep -qE "$EV_FORBID"; then
        verdict="DEVIATION (evidence /$EV_FORBID/ present)"; fail=1
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
    jentry northnarrow-agent "$(agent_pid 0)" INFO "trusted-installer override " "-30min" \
        | tail -1 | grep -q '^trusted-installer override ARMED'
}
audit_since() { tail -n +"$(( ${1:-0} + 1 ))" "$AUDIT" 2>/dev/null; }
# Lot 273d: the last window granted here has ended — past its time, its
# signed close row in the audit chain (or a new agent's boot: a restart
# ends a window), and the journal's state line no longer ARMED. A case
# that must start outside a window waits for it (bounded): C95b's window
# still open at C97's reload let PID 1 apply the 4K to system.slice on
# 5.15 (lot 275's main run), where window_open alone had said "closed".
window_ended() {
    (( WIN_UNTIL == 0 )) && { ! window_open; return; }
    (( $(date +%s) > WIN_UNTIL )) || return 1
    audit_since "$WIN_A0" | grep -qE '"op":"(trusted_installer_window_close|agent_boot)"' || return 1
    ! window_open
}
wait_no_window() { local i; for i in $(seq 1 "${1:-90}"); do window_ended && return 0; sleep 1; done; return 1; }
for i in $(seq 1 130); do
    window_open || break
    (( i == 1 )) && echo "a trusted-installer window is open: waiting for it to close" >&2
    sleep 1
done
# BPF guard mode of the running agent (lab builds observe unless forced),
# from its own registration line (jentry)
BPF_MODE=$(jentry northnarrow-agent "$PID" INFO "BPF self-defence: own objects registered " | tail -1 \
    | grep -oE ' mode="(enforce|observe)"' | cut -d'"' -f2)
BPF_MODE=${BPF_MODE:-enforce}
if [[ "$BPF_MODE" == enforce ]]; then BPF_EXPECT=denied; else BPF_EXPECT=allowed; fi
echo "agent pid $PID, kernel $(uname -r), bpf guard mode $BPF_MODE, $(date -u +%FT%TZ)" >&2

# A signal from a root shell to the live agent or watchdog: the target is
# resolved and its identity checked (comm, start time, then a pidfd) right
# before the case; afterwards the same process must be alive and running.
agent_signal_case() {   # <id> <title> <SIG>
    local p s; p=$(agent_pid); s=$(proc_start "$p")
    POST=$(post post_proc "${p:-0}" "${s:-0}" northnarrow-age) \
        run_case "$1" "$2" denied "deny=signal" 0 -- nnpy signal "${p:-0}" northnarrow-age "${s:-0}" "$3"
}
watchdog_signal_case() {   # <id> <title> <SIG>
    local p s; p=$(wd_pid); s=$(proc_start "$p")
    POST=$(post post_proc "${p:-0}" "${s:-0}" northnarrow-wat) \
        run_case "$1" "$2" denied "deny=signal" 0 -- nnpy signal "${p:-0}" northnarrow-wat "${s:-0}" "$3"
}
agent_mem_case() {   # <id> <title>: open /proc/<agent>/mem (a ptrace attach check)
    local p s; p=$(agent_pid); s=$(proc_start "$p")
    POST=$(post post_proc "${p:-0}" "${s:-0}" northnarrow-age) \
        run_case "$1" "$2" denied "deny=ptrace" 0 -- nnpy procopen "${p:-0}" northnarrow-age "${s:-0}" mem 4194304
}
# a row for a state check (no action, no evidence)
state_row() {   # <id> <title> <detail> <check...>
    local id=$1 title=$2 detail=$3 v msg; shift 3
    selected "$id" || return 0
    if msg=$("$@" 2>&1); then v=OK; else v="DEVIATION (${msg:-check failed})"; fail=1; fi
    rows+=("| $id | $title | $detail | — | $v |")
    echo "$id $title → $detail; $v" >&2
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
        run_case C62c "after a boot: open audit.log for writing" denied "deny=write" 0 -- nnpy file open-append "$AUDIT"
    state_row C62d "after a boot: the state directory keeps +i" "lsattr -d $STATE" post_flag "$STATE" i present
    state_row C62e "after a boot: the pins are back" "PROTECTED_PIDS, link_task_kill" \
        test -e "$PINS/PROTECTED_PIDS" -a -e "$PINS/link_task_kill"
    cleanup_all
    report_unreported
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
run_case C04 "append to /etc/northnarrow/admin.pub" denied "deny=write" 0 -- bash -c "echo x >> $ETC/admin.pub"
POST=$(post post_flag "$STATE" i present) \
run_case C05 "chattr -i on the state dir" denied "deny=ioctl" 0 -- chattr -i "$STATE"
POST=$(post post_same "$UNIT" ino "$(nnpy fileid "$UNIT" ino)") \
run_case C06 "unlink the agent unit (systemctl mask)" denied "deny=unlink" 0 -- bash -c "rm -f $UNIT"
selected C07 && pin_list > "$SCRATCH/pins.before"
POST=$(post post_pins_kept "$SCRATCH/pins.before") \
run_case C07 "rm -rf the bpffs pin root" denied "deny=unlink" 0 -- bash -c "rm -rf $PINS"
run_case C08 "bpftool map update on PROTECTED_PIDS (pinned)" "$BPF_EXPECT" "NN-L-BPF-002|deny=bpf_map" 0 -- bpftool map update pinned "$PINS/PROTECTED_PIDS" key 1 0 0 0 value 1
# Lot 273b: where the update went through (a lab build's BPF guard only
# observes), PID 1 is now in the agent's family — every later case of
# systemd's (C12's set-property) would be let through: take it out again
if selected C08 && [[ "$BPF_EXPECT" == allowed ]]; then
    bpftool map delete pinned "$PINS/PROTECTED_PIDS" key 1 0 0 0 >/dev/null 2>&1
    restored C08 "PID 1 out of PROTECTED_PIDS" absent "$(bpftool map lookup pinned "$PINS/PROTECTED_PIDS" key 1 0 0 0 >/dev/null 2>&1 && echo present || echo absent)"
fi
run_case C09 "bpftool link show pinned (link handle)" "$BPF_EXPECT" "NN-L-BPF-002|deny=bpf_link" 0 -- bpftool link show pinned "$PINS/link_task_kill"
# ── BPF ecosystem ─────────────────────────────────────────────────────────
run_case C10 "bpftool feature probe (loads test programs)" allowed "NN-L-BPF-001" 0 -- bash -c "bpftool feature probe kernel >/dev/null"
# ── systemd ───────────────────────────────────────────────────────────────
# External audit EBPF-015: where the agent registered its drop-in directory
# at boot (install.sh makes it on Debian-family hosts) a new drop-in is
# refused; elsewhere it is made beside the unit and reported.
DROPIN_DIR=/etc/systemd/system/northnarrow-agent.service.d
if selected C11; then
    C11_EXP=allowed; C11_EV="integrity_drift"
    if jentry northnarrow-agent "$PID" INFO "anti-tamper FS: agent binary/unit registered in PROTECTED_INODES path=$DROPIN_DIR " >/dev/null; then
        C11_EXP=denied; C11_EV="deny=create"
    fi
    DROPIN_NEW=0; [[ -e $DROPIN_DIR ]] || DROPIN_NEW=1
    WAIT=40 run_case C11 "unit drop-in with a hostile Environment=" "$C11_EXP" "$C11_EV" 0 -- bash -c "mkdir -p $DROPIN_DIR && printf '[Service]\nEnvironment=NN_ANTI_TAMPER_ALLOW_DEGRADED=1\n' > $DROPIN_DIR/zz-tamper.conf"
    rm -f "$DROPIN_DIR/zz-tamper.conf"
    (( DROPIN_NEW )) && rmdir "$DROPIN_DIR" 2>/dev/null
    systemctl daemon-reload
    restored C11 "$DROPIN_DIR/zz-tamper.conf" "absent" "$([[ -e $DROPIN_DIR/zz-tamper.conf ]] && echo present || echo absent)"
fi
# External audit LAB-026 (lab PR 206): the runtime property is taken back
# here (its drop-in removed, then a daemon-reload), and the unit's MemoryMax
# and its cgroup's memory.max must read as before; `--only C12` used to
# leave the 4G cap in force until some later reload.
if selected C12; then
    # Lot 273b: `set-property` of the agent outside a window is refused —
    # PID 1's write of memory.max below the value the unit started with,
    # and the drop-in in the unit's system.control directory (NOCREATE).
    # systemd may answer the client with success and log the failures:
    # the case is judged by its effect (memory.max and the drop-in as
    # before, the agent alive) and by the signed refusal.
    CGROOT=/sys/fs/cgroup
    AG_CG=$(systemctl show -p ControlGroup --value northnarrow-agent 2>/dev/null)
    CG_MEMMAX=$CGROOT${AG_CG:-/system.slice/northnarrow-agent.service}/memory.max
    CTL=/run/systemd/system.control/northnarrow-agent.service.d
    MM0=$(systemctl show -p MemoryMax --value northnarrow-agent.service 2>/dev/null)
    CGMM0=$(cat "$CG_MEMMAX" 2>/dev/null)
    PID=$(agent_pid); START=$(proc_start "$PID")
    t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
    sleep 1
    out=$(timeout 60 systemctl set-property --runtime northnarrow-agent.service MemoryMax=4G 2>&1); rc=$?
    sleep 6; ev=$(evidence "$t0" "$a0" "$d0")
    now=$(cat "$CG_MEMMAX" 2>/dev/null)
    if [[ "$now" == "$CGMM0" && ! -e $CTL/50-MemoryMax.conf ]] && post_proc "${PID:-0}" "${START:-0}" northnarrow-age >/dev/null \
       && echo "$ev" | grep -qE "deny=cgroup_limit|deny=create"; then
        v=OK; st="denied (memory.max kept at $now; systemctl rc=$rc$( [[ -n $out ]] && echo ": $(echo "$out" | head -1 | cut -c1-60 | tr '|' '/')"))"
    else
        v="DEVIATION (memory.max $CGMM0 -> ${now:-?}, drop-in $([[ -e $CTL/50-MemoryMax.conf ]] && echo present || echo absent), rc=$rc)"; fail=1; st="allowed"
    fi
    rows+=("| C12 | systemctl set-property --runtime MemoryMax=4G of the agent (no window) | $st | $ev | $v |")
    echo "C12 set-property MemoryMax=4G → $st; $ev; $v" >&2
    # a drop-in that got through, and what a reload makes of it
    rm -f "$CTL/50-MemoryMax.conf"
    systemctl daemon-reload
    if [[ -n $CGMM0 && "$(cat "$CG_MEMMAX" 2>/dev/null)" != "$CGMM0" ]]; then
        grant_window 30; echo "$CGMM0" > "$CG_MEMMAX" 2>/dev/null
        # the next case must not run inside that window
        for i in $(seq 1 40); do window_open || break; sleep 1; done
    fi
    restored C12 "MemoryMax of the unit" "$MM0" "$(systemctl show -p MemoryMax --value northnarrow-agent.service 2>/dev/null)"
    restored C12 "memory.max of its cgroup" "$CGMM0" "$(cat "$CG_MEMMAX" 2>/dev/null)"
fi
# Review 26: a copy of the unit in a higher-precedence directory of the
# systemd load path (tmpfs, outside the FIM watch) replaces the installed
# unit at the next daemon-reload, for either install layout.
SHADOW=/run/systemd/transient/northnarrow-agent.service
if selected C25; then
    WAIT=40 run_case C25 "shadow the agent unit from /run/systemd/transient" allowed "unit_shadowed" 0 -- bash -c "mkdir -p /run/systemd/transient && cp $UNIT $SHADOW && systemctl daemon-reload && systemctl show -p FragmentPath --value northnarrow-agent"
    rm -f "$SHADOW"; systemctl daemon-reload
    systemctl daemon-reload
    restored C25 "the agent unit's FragmentPath" "$UNIT" "$(systemctl show -p FragmentPath --value northnarrow-agent 2>/dev/null)"
fi
# ── mounts ────────────────────────────────────────────────────────────────
# External audit LAB-007: each mount point is registered before its case,
# so the trap undoes it whatever happens (Ctrl-C in the 40 s, a lost ssh
# session, an umount refused with EBUSY); after the case it must be gone,
# or the run fails and stops (the next cases would run on the fake one).
# (lab PR 206) the mount point C13 makes is removed again, and nothing is
# made for a case --only leaves out
if selected C13; then
    BPF2_NEW=0; [[ -e /mnt/nn-bpf2 ]] || BPF2_NEW=1
    mkdir -p /mnt/nn-bpf2
    MOUNTS+=(/mnt/nn-bpf2)
    WAIT=40 run_case C13 "second bpffs mount" allowed "integrity_drift" 0 -- mount -t bpf bpf /mnt/nn-bpf2
    unmount_one /mnt/nn-bpf2
    (( BPF2_NEW )) && ! mountpoint -q /mnt/nn-bpf2 && rmdir /mnt/nn-bpf2 2>/dev/null
fi
# mounted, held for one check, unmounted BEFORE the evidence is read: while
# it is mounted the host's /etc/northnarrow/audit.log is the fake one
if selected C14; then
    mkdir -p "$TMPD/fake-etc"
    MOUNTS+=("$ETC")
    run_case C14 "bind mount over /etc/northnarrow for 40 s" allowed "integrity_drift" 0 -- bash -c "mount --bind $TMPD/fake-etc $ETC && sleep 40; umount $ETC"
    mount_gone C14 "$ETC" || { print_table; echo "anti-tamper check: DEVIATIONS (stopped: $ETC still mounted)"; exit 1; }
fi
# Review 53: hiding the kernel BTF keeps every LSM hook from attaching at
# the agent's next start (which now refuses to start); the mount itself is
# reported while the agent runs.
if selected C26; then
    MOUNTS+=(/sys/kernel/btf)
    run_case C26 "tmpfs over /sys/kernel/btf for 40 s" allowed "integrity_drift" 0 -- bash -c "mount -t tmpfs tmpfs /sys/kernel/btf && sleep 40; umount /sys/kernel/btf"
    mount_gone C26 /sys/kernel/btf || { print_table; echo "anti-tamper check: DEVIATIONS (stopped: /sys/kernel/btf still mounted)"; exit 1; }
fi
# ── cgroup freezer ────────────────────────────────────────────────────────
# External audit LAB-017/LAB-026 (lab PR 206): a case whose interface is
# missing is a row (skipped_case), never left out of the table.
# Lot 273: the units' cgroups are protected (their cgroup.freeze and
# cgroup.kill, and their slices', refused outside a trusted-installer
# window; C65-C76 below): a freeze is refused and signed (it was allowed,
# and seen only as integrity_drift).
CGROOT=/sys/fs/cgroup
AG_CG=$(systemctl show -p ControlGroup --value northnarrow-agent 2>/dev/null)
WD_CG=$(systemctl show -p ControlGroup --value northnarrow-watchdog 2>/dev/null)
cg_of() { sed -n 's/^0:://p' "/proc/${1:-0}/cgroup" 2>/dev/null; }
post_cgroup() {   # <pid> <cgroup>: the process is in that cgroup
    local now; now=$(cg_of "$1")
    [[ -n "$now" && "$now" == "$2" ]] || { echo "pid $1 is in ${now:-?}, not $2"; return 1; }
}
post_thawed() {   # <cgroup.freeze>
    [[ "$(cat "$1" 2>/dev/null)" == 0 ]] || { echo "${1%/*} is frozen"; return 1; }
}
post_gone() { [[ ! -e "$1" ]] || { echo "$1 exists"; return 1; }; }
# lot 273b: a cgroup or proc file still holds its value
post_value() {   # <file> <value>
    local now; now=$(cat "$1" 2>/dev/null)
    [[ "$now" == "$2" ]] || { echo "${1##*/} is ${now:-?}, not $2"; return 1; }
}
# lot 273b: after a propagated stop (C78), the agent unit active again —
# a unit systemd left failed or inactive with the agent still running is
# reset and started (the start finds the running agent's pidfile lock)
unit_back() {   # <id>
    local st p i; st=$(systemctl is-active northnarrow-agent 2>/dev/null)
    if [[ "$st" != active ]]; then
        p=$(agent_pid 0)
        echo "    $1: the agent unit is $st (the agent ${p:-not running}) — ended inside a window, the unit started" >&2
        # systemd relays the signal inside the window (the operator's
        # path, docs/operator §3.7) — a root shell's own kill would be a
        # refused tamper of this script, the actor COMBAT ends
        grant_window 90
        if [[ -n $p ]]; then
            systemctl kill -s SIGTERM northnarrow-agent >/dev/null 2>&1
            for i in $(seq 1 30); do kill -0 "$p" 2>/dev/null || break; sleep 1; done
        fi
        systemctl reset-failed northnarrow-agent >/dev/null 2>&1
        systemctl start northnarrow-agent >/dev/null 2>&1
        for i in $(seq 1 60); do [[ "$(systemctl is-active northnarrow-agent 2>/dev/null)" == active ]] && break; sleep 1; done
        systemctl is-active --quiet northnarrow-watchdog || systemctl start northnarrow-watchdog >/dev/null 2>&1
        sleep 20
        for i in $(seq 1 90); do window_open || break; sleep 1; done
    fi
    restored "$1" "the agent unit" active "$(systemctl is-active northnarrow-agent 2>/dev/null)"
}
CG=$CGROOT${AG_CG:-/system.slice/northnarrow-agent.service}/cgroup.freeze
if [[ -w "$CG" ]]; then
    selected C15 && CG_FROZEN=$CG   # thawed by the trap if the run stops here
    PID=$(agent_pid); START=$(proc_start "$PID")
    POST="$(post post_proc "${PID:-0}" "${START:-0}" northnarrow-age) && $(post post_thawed "$CG")" \
    run_case C15 "cgroup v2 freeze of the agent (no window)" denied "deny=cgroup_freeze" 0 -- nnpy file write "$CG" 1
    [[ "$(cat "$CG" 2>/dev/null)" == 0 ]] || echo 0 > "$CG" 2>/dev/null
    CG_FROZEN=
elif [[ ! -e /sys/fs/cgroup/cgroup.controllers ]]; then
    skipped_case C15 "no cgroup v2 hierarchy" 1
else
    skipped_case C15 "no writable $CG" 0
fi
# ── kernel modules / kexec ────────────────────────────────────────────────
if modinfo dummy >/dev/null 2>&1; then
    # R011 kills modprobe within ~10 ms: either the load is prevented (R011)
    # or it lands first and is recorded (R018) — both are evidence
    run_case C16 "modprobe dummy (in-tree module load)" allowed "R011_KernelModuleTooling|R018_KernelModuleLoad" 0 -- bash -c "rmmod dummy 2>/dev/null; modprobe dummy && rmmod dummy"
else
    skipped_case C16 "this kernel has no dummy module" 1
fi
# ── OOM and configuration overlays ────────────────────────────────────────
# External audit DEP-005 (lab PR 184): put back the agent's own value — the
# unit's -500, or 0 where the memory cap cannot bind (an 8 GiB guest).
# External audit LAB-026 (lab PR 206): only when C18 runs (`--only C01` used
# to rewrite the agent's value too, and wrote -500 when it could not read
# it), to the process C18 changed (pid and start time), by the trap if the
# run stops in its 40 s, and the value read back must be the one found.
PID=$(agent_pid)   # the watchdog may have recycled a frozen agent
if selected C18; then
    OOM0=$(cat "/proc/${PID:-0}/oom_score_adj" 2>/dev/null)
    if [[ -z $PID || ! $OOM0 =~ ^-?[0-9]+$ ]]; then
        skipped_case C18 "the agent's oom_score_adj could not be read" 0
    else
        OOM_RESTORE="$PID $(proc_start "$PID") $OOM0"
        # Lot 273b (the review of #489): refused outside a window — 900 or
        # 1000 makes the agent the OOM killer's first victim, whose SIGKILL
        # no task_kill hook sees (it was allowed and reported as
        # integrity_drift)
        POST="$(post post_proc "$PID" "$(proc_start "$PID")" northnarrow-age) && $(post post_value "/proc/$PID/oom_score_adj" "$OOM0")" \
        run_case C18 "raise the agent's oom_score_adj to 900 (no window)" denied "deny=oom_adj" 0 -- nnpy file write "/proc/$PID/oom_score_adj" 900
        oom_restore
    fi
fi
# a fresh name each run: once the agent has seen an overlay it protects it,
# so a leftover cannot be removed until the lab purges the pins
OVL="$ETC/zz-tamper-$(date +%s).local"
# External audit EBPF-015: a new entry in /etc/northnarrow is refused.
run_case C19 "drop a .local overlay in /etc/northnarrow" denied "deny=create" 0 -- bash -c "echo '+evil-implant' > $OVL"
# ── kills nothing can refuse, saturation, io_uring ────────────────────────
CGK=$CGROOT${AG_CG:-/system.slice/northnarrow-agent.service}/cgroup.kill
if [[ -w "$CGK" ]]; then
    # kernel-generated SIGKILL: no task_kill hook on this path. Lot 273: the
    # write-open is refused outside a window and signed cgroup_kill (it
    # killed the agent; the watchdog brought it back, prev_run_abrupt). A
    # kill inside a window is C76.
    PID=$(agent_pid); START=$(proc_start "$PID")
    POST=$(post post_proc "${PID:-0}" "${START:-0}" northnarrow-age) \
    WAIT=8 run_case C20 "cgroup.kill on the agent's unit (no window)" denied "deny=cgroup_kill" 0 -- nnpy file write "$CGK" 1
    PID=$(agent_pid)
fi
# 20k execs to overflow the exec ring, one exec from /tmp hidden inside:
# either the exec is caught (R001) or the loss itself is signed evidence.
WAIT=12 run_case C21 "exec flood (20k) hiding an exec from /tmp" allowed "R001_ExecFromTmp|R009_RootExecFromUserPath|ringbuf_drop" 0 -- bash -c 'cp /bin/true "$TMPD/nn-sat" && { for i in $(seq 1 20000); do /bin/true; done & sleep 2; "$TMPD/nn-sat"; wait; rm -f "$TMPD/nn-sat"; }'
# open + read + connect through an io_uring ring: no openat/connect syscall
# from userland (the openat tracepoint is blind to it by construction).
# Built here when C22 or C59 runs (lab PR 206: C59 used whatever an earlier
# run had left at that path when only it was selected).
IOU_SRC="$(dirname "$0")/iouring-probe.c"
IOU_BIN=/usr/local/libexec/nn-lab/nn-iou-probe
IOU_BUILT=0
if [[ $(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo 0) == 2 ]]; then
    # RHEL 9 ships kernel.io_uring_disabled=2: no ring, not even for root.
    skipped_case C22 "io_uring_disabled=2" 1
elif ! selected_any C22,C59a,C59b,C59c,C108; then
    :
elif [[ -f "$IOU_SRC" ]] && mkdir -p "$(dirname "$IOU_BIN")" && cc -O2 -o "$IOU_BIN" "$IOU_SRC" 2>"$TMPD/iou-cc.log"; then
    IOU_BUILT=1
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
# NN-AUD-413 (lab PR 167): the evidence is read from audit.log, not from
# the journal line: the store (config_overlay_set) and no refusal at the
# restart (unauthorized_overlay). The store raises the rollback floor to its
# signature, so the boot that applies it writes no config_overlay_accepted
# (that row marks bytes the chain had not seen; Ubuntu 24.04 gate of lab
# PRs 167-171). The comment line makes the bytes of every run new.
printf '# nn-lab C24 %s\n+backupd\n' "$(date -u +%Y%m%dT%H%M%S%N)" > "$TMPD/ovl-allow"
EV_FORBID="unauthorized_overlay" WAIT=20 run_case C24 "nn-admin config overlay set + agent restart" allowed "config_overlay_set" 0 -- bash -c "$NNADMIN config overlay set process-comm-allowlist --file $TMPD/ovl-allow --key $ADMIN_KEY && restart_agent"
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
    # (lab PR 206) a map bpftool could not dump reads as no count, not as
    # 0 entries: "0 -> 0" passed C30 with nothing read
    pi_count() { local j; j=$(bpftool -j map dump pinned /sys/fs/bpf/northnarrow/PROTECTED_INODES 2>/dev/null) && [[ $j == \[* ]] && grep -o '"key":' <<<"$j" | wc -l; }
    pp_scan() { bpftool -j map dump pinned "$PINS/PROTECTED_PIDS" 2>/dev/null | nnpy map-pids; }
    n1=$(pi_count); p1=$(pp_scan); restart_agent; sleep 20; n2=$(pi_count); p2=$(pp_scan); PID=$(agent_pid)
    if selected C30; then
        if [[ -z "$n1" || -z "$n2" ]]; then v="DEVIATION (map unreadable)"; fail=1
        elif (( n2 > n1 )); then v="DEVIATION (grew by $(( n2 - n1 )))"; fail=1; else v="OK"; fi
        rows+=("| C30 | PROTECTED_INODES across an agent restart | ${n1:-?} → ${n2:-?} entries | — | $v |")
        echo "C30 PROTECTED_INODES across an agent restart → $n1 → $n2 entries; $v" >&2
    fi
    if selected C61; then
        # "total=N stale=M[ pids=…]": stale = no live agent, watchdog or
        # agent's worker (R14a) at that PID
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
# External audit LAB-024 (NN-AUD-414, lab PR 206): without kexec-tools
# (no lab template installs it) C17 left no row at all. The same load is
# made then with the kexec_file_load(2) syscall itself (the agent refuses
# both, review 82), and an image that did load is unloaded by the trap too.
if selected C17; then
    KEXEC_UNLOAD=1
    if command -v kexec >/dev/null 2>&1; then
        K17_HOW="kexec -l"; K17=(kexec -l "/boot/vmlinuz-$(uname -r)" --initrd="$KINITRD" --reuse-cmdline)
    else
        K17_HOW="kexec_file_load(2)"; K17=(nnpy kexec-file "/boot/vmlinuz-$(uname -r)" "$KINITRD")
    fi
    POST=$(post post_kexec_empty) \
    run_case C17 "$K17_HOW of the running kernel (lockdown: ${LOCKDOWN:-none})" denied "NN-L-AT-001" 0 -- "${K17[@]}"
    kexec_unload
fi
# An unsigned module (dummy.ko with its signature stripped), loaded with a
# bare finit_module() so the refusal is the kernel's, not R011 killing a
# module tool. Only under lockdown: without it the load would succeed and
# taint the kernel. Livepatches are modules too and take the same check.
# External audit LAB-024 (lab PR 206): without lockdown it is a listed known
# gap (it left no row), the syscall number is the machine's (it was
# x86_64's 313 on every machine), and nothing is copied for a run --only
# leaves it out. `NN_LAB_LOCKDOWN=integrity nn-lab.sh up` boots a guest
# where it runs.
if ! selected C27; then
    :
elif (( KGAP )); then
    rows+=("| C27 | load an unsigned module (finit_module) | not run: kernel lockdown ${LOCKDOWN:-none} | — | KNOWN GAP (an unsigned module loads without lockdown: a host setting, nn-admin host-check; the lockdown guest: NN_LAB_LOCKDOWN=integrity) |")
    echo "C27 not run: no kernel lockdown → KNOWN GAP" >&2
elif [[ -z "$(nnpy syscall-nr finit_module)" ]]; then
    skipped_case C27 "no finit_module syscall number for $(uname -m)" 0
else
    ko=$(modinfo -n dummy 2>/dev/null)
    case "$ko" in
        *.ko)     cp "$ko" "$TMPD/nn_signed_dummy.ko" 2>/dev/null ;;
        *.ko.zst) zstd -qdc "$ko" > "$TMPD/nn_signed_dummy.ko" 2>/dev/null ;;
        *.ko.xz)  xz -dc "$ko" > "$TMPD/nn_signed_dummy.ko" 2>/dev/null ;;
        *)        rm -f "$TMPD/nn_signed_dummy.ko" ;;
    esac
    if [[ -s "$TMPD/nn_signed_dummy.ko" ]] && nnpy strip-sig "$TMPD/nn_signed_dummy.ko" "$TMPD/nn_unsigned_dummy.ko"; then
        rmmod dummy 2>/dev/null
        POST=$(post post_module_absent dummy) \
        run_case C27 "load an unsigned module (finit_module, lockdown: $LOCKDOWN)" denied "" 0 -- nnpy finit "$TMPD/nn_unsigned_dummy.ko"
        rmmod dummy 2>/dev/null
    else
        skipped_case C27 "no dummy module to strip (${ko:-none})" 1
    fi
    rm -f "$TMPD/nn_signed_dummy.ko" "$TMPD/nn_unsigned_dummy.ko"
fi

# ── systemd as the relay (external audit EBPF-001) ───────────────────────
# Outside a trusted-installer window PID 1's signals are refused like a root
# shell's (`systemctl kill` reports EPERM) and the units refuse a manual
# stop (RefuseManualStop=yes).
PID=$(agent_pid)
START=$(proc_start "$PID")
POST=$(post post_proc "${PID:-0}" "${START:-0}" northnarrow-age) \
run_case C31 "systemctl kill -s SIGKILL the agent (no window)" denied "deny=signal" 0 -- systemctl kill -s SIGKILL northnarrow-agent
WDPID=$(wd_pid); WDSTART=$(proc_start "$WDPID")
POST=$(post post_proc "${WDPID:-0}" "${WDSTART:-0}" northnarrow-wat) \
run_case C32 "systemctl kill -s SIGSTOP the watchdog (no window)" denied "deny=signal" 0 -- systemctl kill -s SIGSTOP northnarrow-watchdog
if [[ -z "$ONLY" || ",$ONLY," == *",C33,"* ]]; then
    # Lot 273: the agent C33 must find running is the one running now (on
    # systemd 257 a C31 that went through killed the agent, and the
    # watchdog's restart read as a stop allowed here)
    PID=$(agent_pid)
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

# ── the units' cgroups (lot 273) ─────────────────────────────────────────
# systemd 257 and later answer `systemctl kill -s SIGKILL` with a write to
# the unit's cgroup.kill once the main process refused the signal (C31): a
# kernel kill no task_kill hook sees. Outside a trusted-installer window
# the agent's and the watchdog's cgroup.kill and cgroup.freeze (and their
# slices') are refused, as are a child cgroup, an rmdir and a chown of the
# unit's cgroup, and a move of the agent or the watchdog to another cgroup
# (where it could be killed or frozen); every one is signed. A slice's
# files are written "0" (a no-op if the open went through: ERANGE for
# cgroup.kill). Inside a window it is all allowed (C76, at the end).
if [[ ! -e $CGROOT/cgroup.controllers || -z "$AG_CG" || -z "$WD_CG" ]]; then
    skipped_case C65,C66,C67,C68,C69,C70,C71,C72,C73,C74,C75,C77a,C77b,C78a,C78b,C78c,C79,C80,C81,C81b,C82,C83,C83b,C84,C85,C86,C87,C88,C89,C90,C91,C92,C93,C94,C95,C95b,C96,C97,C98,C99,C100,C101,C103,C105 "no cgroup v2 hierarchy, or a unit without a ControlGroup" 0
else
    PID=$(agent_pid); START=$(proc_start "$PID")
    WDPID=$(wd_pid); WDSTART=$(proc_start "$WDPID")
    AG_SLICE=${AG_CG%/*}
    POST=$(post post_proc "${WDPID:-0}" "${WDSTART:-0}" northnarrow-wat) \
    run_case C65 "systemctl kill -s SIGKILL the watchdog (no window)" denied "deny=signal|deny=cgroup_kill" 0 -- systemctl kill -s SIGKILL northnarrow-watchdog
    WDPID=$(wd_pid); WDSTART=$(proc_start "$WDPID")
    # systemd 249 marks the unit `freezing` before it writes cgroup.freeze
    # and keeps that state when the write is refused: a second `systemctl
    # freeze` then writes nothing ("Previously requested freezer operation
    # … still in progress") until the next freezer event of the cgroup — a
    # case with nothing to refuse, reported as such while the cgroup is not
    # frozen (252 and later write again, or skip a thaw of a running one)
    FS0=$(systemctl show -p FreezerState --value northnarrow-agent 2>/dev/null)
    if selected C66 && [[ -n $FS0 && $FS0 != running && "$(cat "$CGROOT$AG_CG/cgroup.freeze" 2>/dev/null)" == 0 ]]; then
        skipped_case C66 "systemd's own freezer state of the unit is $FS0 and its cgroup is not frozen: systemd 249 keeps that state after a refused freeze and writes nothing until the next freezer event" 1
    elif selected C66; then
        CG_FROZEN=$CGROOT$AG_CG/cgroup.freeze
        POST="$(post post_proc "${PID:-0}" "${START:-0}" northnarrow-age) && $(post post_thawed "$CGROOT$AG_CG/cgroup.freeze")" \
        run_case C66 "systemctl freeze the agent (no window)" denied "deny=cgroup_freeze" 0 -- systemctl freeze northnarrow-agent
        systemctl thaw northnarrow-agent >/dev/null 2>&1
        CG_FROZEN=
    fi
    POST=$(post post_proc "${WDPID:-0}" "${WDSTART:-0}" northnarrow-wat) \
    run_case C67 "cgroup.kill on the watchdog's unit (no window)" denied "deny=cgroup_kill" 0 -- nnpy file write "$CGROOT$WD_CG/cgroup.kill" 1
    WDPID=$(wd_pid); WDSTART=$(proc_start "$WDPID")
    if selected C75; then
        CG_FROZEN=$CGROOT$WD_CG/cgroup.freeze
        POST="$(post post_proc "${WDPID:-0}" "${WDSTART:-0}" northnarrow-wat) && $(post post_thawed "$CGROOT$WD_CG/cgroup.freeze")" \
        run_case C75 "cgroup.freeze of the watchdog's unit (no window)" denied "deny=cgroup_freeze" 0 -- nnpy file write "$CGROOT$WD_CG/cgroup.freeze" 1
        [[ "$(cat "$CGROOT$WD_CG/cgroup.freeze" 2>/dev/null)" == 0 ]] || echo 0 > "$CGROOT$WD_CG/cgroup.freeze" 2>/dev/null
        CG_FROZEN=
    fi
    if [[ -n "$AG_SLICE" && -e "$CGROOT$AG_SLICE/cgroup.freeze" ]]; then
        run_case C68 "cgroup.freeze of the agent's slice ${AG_SLICE} (write 0, no window)" denied "deny=cgroup_freeze" 0 -- nnpy file write "$CGROOT$AG_SLICE/cgroup.freeze" 0
    else
        skipped_case C68 "the agent's unit is in no slice with a cgroup.freeze (${AG_SLICE:-root})" 0
    fi
    if [[ -n "$AG_SLICE" && -e "$CGROOT$AG_SLICE/cgroup.kill" ]]; then
        run_case C69 "cgroup.kill of the agent's slice ${AG_SLICE} (write 0, no window)" denied "deny=cgroup_kill" 0 -- nnpy file write "$CGROOT$AG_SLICE/cgroup.kill" 0
    else
        skipped_case C69 "the agent's unit is in no slice with a cgroup.kill (${AG_SLICE:-root}; kernel 5.14+)" 0
    fi
    # a move out: into a fresh cgroup at the root, moved back if it went
    MV=$CGROOT/nn-lab-c70
    if selected_any C70,C71; then mkdir -p "$MV"; fi
    POST=$(post post_cgroup "${PID:-0}" "$AG_CG") \
    run_case C70 "move the agent's pid to another cgroup (no window)" denied "deny=cgroup_move" 0 -- nnpy cgmove "${PID:-0}" northnarrow-age "${START:-0}" "$MV/cgroup.procs"
    if selected C70 && [[ "$(cg_of "$PID")" != "$AG_CG" ]]; then
        nnpy cgmove "$PID" northnarrow-age "$START" "$CGROOT$AG_CG/cgroup.procs" >/dev/null 2>&1
        restored C70 "the agent's cgroup" "$AG_CG" "$(cg_of "$PID")"
    fi
    POST=$(post post_cgroup "${WDPID:-0}" "$WD_CG") \
    run_case C71 "move the watchdog's pid to another cgroup (no window)" denied "deny=cgroup_move" 0 -- nnpy cgmove "${WDPID:-0}" northnarrow-wat "${WDSTART:-0}" "$MV/cgroup.procs"
    if selected C71 && [[ "$(cg_of "$WDPID")" != "$WD_CG" ]]; then
        nnpy cgmove "$WDPID" northnarrow-wat "$WDSTART" "$CGROOT$WD_CG/cgroup.procs" >/dev/null 2>&1
        restored C71 "the watchdog's cgroup" "$WD_CG" "$(cg_of "$WDPID")"
    fi
    if selected_any C70,C71; then rmdir "$MV" 2>/dev/null; restored C70 "$MV" absent "$([[ -e $MV ]] && echo present || echo absent)"; fi
    CHILD=$CGROOT$AG_CG/nn-lab-c72
    POST=$(post post_gone "$CHILD") \
    run_case C72 "a child cgroup in the agent's unit cgroup (no window)" denied "deny=mkdir" 0 -- nnpy file mkdir "$CHILD"
    if selected C72 && [[ -d "$CHILD" ]]; then rmdir "$CHILD" 2>/dev/null; fi
    POST=$(post post_proc "${PID:-0}" "${START:-0}" northnarrow-age) \
    run_case C73 "rmdir the agent's unit cgroup (no window)" denied "deny=rmdir" 0 -- nnpy file rmdir "$CGROOT$AG_CG"
    if selected C74; then
        OWN0=$(stat -c %u "$CGROOT$AG_CG/cgroup.procs" 2>/dev/null)
        run_case C74 "chown the agent's cgroup.procs (a delegation, no window)" denied "deny=setattr" 0 -- nnpy file chown "$CGROOT$AG_CG/cgroup.procs" 65534
        [[ "$(stat -c %u "$CGROOT$AG_CG/cgroup.procs" 2>/dev/null)" == "${OWN0:-0}" ]] || chown "${OWN0:-0}" "$CGROOT$AG_CG/cgroup.procs" 2>/dev/null
        restored C74 "the owner of the agent's cgroup.procs" "${OWN0:-0}" "$(stat -c %u "$CGROOT$AG_CG/cgroup.procs" 2>/dev/null)"
    fi
    # ── lot 273b: the moves systemd makes, the stops it propagates ──────
    # C77: a transient scope with the agent's pid in it (StartTransientUnit
    # with PIDs=), and the agent attached to an existing unit
    # (AttachProcessesToUnit, systemd 238+): PID 1 moves the pid, the move
    # guard refuses it.
    # systemd answers StartTransientUnit with a job whatever the attach
    # did: the case is judged by its effect (the agent in its own cgroup)
    # and by the signed refusal.
    if selected C77a; then
        PID=$(agent_pid); START=$(proc_start "$PID")
        t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
        sleep 1
        out=$(busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
            StartTransientUnit 'ssa(sv)a(sa(sv))' nn-lab-c77.scope fail 1 PIDs au 1 "${PID:-0}" 0 2>&1); rc=$?
        sleep 4; ev=$(evidence "$t0" "$a0" "$d0")
        now=$(cg_of "$PID")
        if [[ "$now" == "$AG_CG" ]] && post_proc "${PID:-0}" "${START:-0}" northnarrow-age >/dev/null && echo "$ev" | grep -q "deny=cgroup_move"; then
            v=OK; st="denied (the agent kept in $AG_CG; busctl rc=$rc: $(echo "$out" | head -1 | cut -c1-50 | tr '|' '/'))"
        else
            v="DEVIATION (the agent in ${now:-?}, busctl rc=$rc)"; fail=1; st="allowed"
        fi
        rows+=("| C77a | a transient scope with the agent's pid (StartTransientUnit PIDs=, no window) | $st | $ev | $v |")
        echo "C77a a transient scope with the agent's pid → $st; $ev; $v" >&2
        # an agent the scope took is put back (its scope then stopped)
        if [[ "$(cg_of "$PID")" != "$AG_CG" ]]; then
            grant_window 30; nnpy cgmove "$PID" northnarrow-age "$START" "$CGROOT$AG_CG/cgroup.procs" >/dev/null 2>&1
            for i in $(seq 1 40); do window_open || break; sleep 1; done
        fi
    fi
    systemctl stop nn-lab-c77.scope >/dev/null 2>&1; systemctl reset-failed nn-lab-c77.scope >/dev/null 2>&1
    if selected C77b; then
        systemd-run --unit=nn-lab-c77b --property=Delegate=yes /bin/sleep 120 >/dev/null 2>&1
        PID=$(agent_pid); START=$(proc_start "$PID")
        POST="$(post post_proc "${PID:-0}" "${START:-0}" northnarrow-age) && $(post post_cgroup "${PID:-0}" "$AG_CG")" \
        run_case C77b "attach the agent's pid to another unit (AttachProcessesToUnit, no window)" denied "deny=cgroup_move" 0 -- \
            busctl call org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
            AttachProcessesToUnit 'ssau' nn-lab-c77b.service "" 1 "${PID:-0}"
        systemctl stop nn-lab-c77b.service >/dev/null 2>&1; systemctl reset-failed nn-lab-c77b.service >/dev/null 2>&1
    fi
    # C78: stops systemd propagates — not a manual stop of the unit, so
    # RefuseManualStop= does not apply: a started unit with Conflicts= on
    # the agent, and an isolate to a target that wants every active unit
    # but the agent and the watchdog. systemd's stop job signals the agent
    # (refused) and, on 257+, writes its cgroup.kill (refused). The agent
    # must keep running; systemd's view of the unit is recorded.
    if selected C78a; then
        # a stop job, not a manual stop: systemd runs it — the agent must
        # outlive it (its signals refused, and on 257+ its cgroup.kill);
        # what systemd then records of the unit is reported
        PID=$(agent_pid); START=$(proc_start "$PID")
        t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
        sleep 1
        out=$(systemd-run --unit=nn-lab-c78a --property=Conflicts=northnarrow-agent.service --property=Type=oneshot --property=RemainAfterExit=yes /bin/true 2>&1); rc=$?
        sleep 15; ev=$(evidence "$t0" "$a0" "$d0")
        ust="$(systemctl is-active northnarrow-agent 2>/dev/null)/$(systemctl show -p SubState --value northnarrow-agent 2>/dev/null)"
        if post_proc "${PID:-0}" "${START:-0}" northnarrow-age >/dev/null && echo "$ev" | grep -qE "deny=signal|deny=cgroup_kill"; then
            v=OK; st="denied (the agent $PID outlived the stop job; systemd records the unit $ust)"
        else
            v="DEVIATION (the agent $PID is gone or no refusal signed; the unit $ust)"; fail=1; st="allowed"
        fi
        rows+=("| C78a | start a unit with Conflicts=northnarrow-agent.service (no window) | $st | $ev | $v |")
        echo "C78a a Conflicts= unit → $st; $ev; $v" >&2
        systemctl stop nn-lab-c78a >/dev/null 2>&1; systemctl reset-failed nn-lab-c78a >/dev/null 2>&1
        unit_back C78a
    fi
    if selected C78b; then
        T=/run/systemd/system/nn-lab-c78.target
        { echo "[Unit]"; echo "Description=lab C78b: every active unit but NorthNarrow's"; echo "AllowIsolate=yes"
          systemctl list-units --state=active --no-legend --plain 2>/dev/null | awk '{print $1}' \
            | grep -vE '^northnarrow-|\.(device|scope|slice)$|^nn-lab-|^(multi-user|graphical|default)\.target$' | sed 's/^/Wants=/'; } > "$T"
        systemctl daemon-reload
        # lot 273b: both units carry IgnoreOnIsolate=yes — systemd queues no
        # stop for them (without it, C78a's stop job). The target wants
        # every active unit but NorthNarrow's and the targets that pull
        # them in (multi-user, graphical): the isolate stops nothing else.
        PID=$(agent_pid); START=$(proc_start "$PID")
        t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
        sleep 1
        out=$(systemctl isolate nn-lab-c78.target 2>&1); rc=$?
        sleep 15; ev=$(evidence "$t0" "$a0" "$d0")
        ust="$(systemctl is-active northnarrow-agent 2>/dev/null)/$(systemctl show -p SubState --value northnarrow-agent 2>/dev/null)"
        if post_proc "${PID:-0}" "${START:-0}" northnarrow-age >/dev/null && [[ $ust == active/* ]]; then
            v=OK; st="denied (the agent $PID kept, the unit $ust: not stopped by the isolate)"
        else
            v="DEVIATION (the agent $PID $(post_proc "${PID:-0}" "${START:-0}" northnarrow-age >/dev/null && echo kept || echo gone), the unit $ust)"; fail=1; st="allowed"
        fi
        rows+=("| C78b | systemctl isolate a target without NorthNarrow's units (no window) | $st | $ev | $v |")
        echo "C78b isolate → $st; $ev; $v" >&2
        systemctl isolate default.target >/dev/null 2>&1 || systemctl isolate multi-user.target >/dev/null 2>&1
        rm -f "$T"; systemctl daemon-reload
        unit_back C78b
    fi
    # C78c: a stop of the agent's slice — lot 273d's northnarrow.slice, the
    # units' own (RefuseManualStop=yes) — is refused; before lot 273d the
    # units ran in system.slice, whose stop takes the lab's sshd with it:
    # not run there
    if [[ "$AG_SLICE" == /northnarrow.slice ]]; then
        run_case C78c "systemctl stop northnarrow.slice (the units' own slice)" denied "" 0 -- \
            bash -c 'systemctl stop northnarrow.slice 2>&1 | sed "s/refused/Operation not permitted (refused)/"; systemctl is-active northnarrow-agent'
    else
        skipped_case C78c "systemctl stop ${AG_SLICE:-system.slice}: the stop job of C78a's kind, and the guest's sshd is in that slice" 1
    fi
    # C86 (lot 273b): a unit of the agent's slice started and stopped —
    # systemd 254 and 255 thaw the slices up the tree at every start and
    # stop (a write of 0 to system.slice/cgroup.freeze) and rewrite their
    # siblings' cgroup xattrs: PID 1's thaw and xattrs go through, nothing
    # is refused nor signed
    if selected C86; then
        # started, then stopped by systemctl (systemd thaws a realised
        # unit's slices at its stop on 254/255; its start realises the
        # slice's other units on 257+)
        EV_FORBID="deny=cgroup_freeze|deny=xattr|deny=cgroup_limit" \
        run_case C86 "a unit of the agent's slice started and stopped (systemd's own thaw and xattrs)" allowed "" 0 -- \
            bash -c "systemd-run --quiet --unit=nn-lab-c86 --slice=${AG_SLICE#/} /bin/sleep 60 && sleep 2 && systemctl stop nn-lab-c86 && systemctl restart cron 2>/dev/null; true"
        EV_FORBID=
        systemctl stop nn-lab-c86 >/dev/null 2>&1; systemctl reset-failed nn-lab-c86 >/dev/null 2>&1
    fi
    # ── lot 273b: the units' and slices' resource limits ────────────────
    if [[ -e $CGROOT$AG_CG/memory.max ]]; then
        PID=$(agent_pid); START=$(proc_start "$PID")
        MM0=$(cat "$CGROOT$AG_CG/memory.max" 2>/dev/null)
        POST="$(post post_proc "${PID:-0}" "${START:-0}" northnarrow-age) && $(post post_value "$CGROOT$AG_CG/memory.max" "$MM0")" \
        run_case C79 "memory.max of the agent's unit to 1 page (an OOM kill inside the write, no window)" denied "deny=cgroup_limit" 0 -- nnpy file write "$CGROOT$AG_CG/memory.max" 4096
    else
        skipped_case C79 "no memory.max in the agent's cgroup (memory controller off)" 1
    fi
    if [[ -n "$AG_SLICE" && -e "$CGROOT$AG_SLICE/pids.max" ]]; then
        PM0=$(cat "$CGROOT$AG_SLICE/pids.max" 2>/dev/null)
        POST=$(post post_value "$CGROOT$AG_SLICE/pids.max" "$PM0") \
        run_case C80 "pids.max of the agent's slice ${AG_SLICE} to 1 (no window)" denied "deny=cgroup_limit" 0 -- nnpy file write "$CGROOT$AG_SLICE/pids.max" 1
        # a write that went through (a build without lot 273b) is undone
        [[ "$(cat "$CGROOT$AG_SLICE/pids.max" 2>/dev/null)" == "$PM0" ]] || echo "$PM0" > "$CGROOT$AG_SLICE/pids.max" 2>/dev/null
        restored C80 "the slice's pids.max" "$PM0" "$(cat "$CGROOT$AG_SLICE/pids.max" 2>/dev/null)"
    else
        skipped_case C80 "no pids.max in the agent's slice (${AG_SLICE:-root})" 1
    fi
    if [[ -e $CGROOT$WD_CG/cpu.max ]]; then
        CM0=$(cat "$CGROOT$WD_CG/cpu.max" 2>/dev/null)
        POST=$(post post_value "$CGROOT$WD_CG/cpu.max" "$CM0") \
        run_case C81 "cpu.max of the watchdog's unit to 0.1 % (no window)" denied "deny=cgroup_limit" 0 -- nnpy file write "$CGROOT$WD_CG/cpu.max" "1000 1000000"
        [[ "$(cat "$CGROOT$WD_CG/cpu.max" 2>/dev/null)" == "$CM0" ]] || echo "$CM0" > "$CGROOT$WD_CG/cpu.max" 2>/dev/null
        restored C81 "the watchdog's cpu.max" "$CM0" "$(cat "$CGROOT$WD_CG/cpu.max" 2>/dev/null)"
    else
        skipped_case C81 "no cpu.max in the watchdog's cgroup (cpu controller off)" 1
    fi
    if [[ -e $CGROOT$AG_CG/cpu.idle ]]; then
        POST=$(post post_value "$CGROOT$AG_CG/cpu.idle" 0) \
        run_case C81b "cpu.idle of the agent's unit to 1 (no window)" denied "deny=cgroup_limit" 0 -- nnpy file write "$CGROOT$AG_CG/cpu.idle" 1
        [[ "$(cat "$CGROOT$AG_CG/cpu.idle" 2>/dev/null)" == 0 ]] || echo 0 > "$CGROOT$AG_CG/cpu.idle" 2>/dev/null
        restored C81b "the agent's cpu.idle" 0 "$(cat "$CGROOT$AG_CG/cpu.idle" 2>/dev/null)"
    else
        skipped_case C81b "no cpu.idle in the agent's cgroup (cpu controller off, or a kernel before 5.15)" 1
    fi
    # C82: a descriptor opened inside a window (as one opened before the
    # agent's first start) writes after it closed: refused at the write.
    # The agent's cgroup.freeze, written 0 (a no-op if it went through).
    if selected C82; then
        t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
        grant_window 8; sleep 1
        out=$(nnpy fdlater "$CGROOT$AG_CG/cgroup.freeze" 0 20 2>&1); rc=$?
        sleep 3; ev=$(evidence "$t0" "$a0" "$d0")
        st=$(outcome_of "$out" held)
        if [[ "$st" == denied ]] && echo "$ev" | grep -qE "deny=cgroup_freeze"; then v=OK; else v="DEVIATION (expected denied: $(echo "$out" | head -1 | cut -c1-80 | tr '|' '/'))"; fail=1; fi
        rows+=("| C82 | write the agent's cgroup.freeze through a descriptor opened inside a window, after it closed | $st | $ev | $v |")
        echo "C82 an earlier descriptor of cgroup.freeze → $st; $ev; $v" >&2
        for i in $(seq 1 30); do window_open || break; sleep 1; done
    fi
    # C83: the cgroup v1 freezer (the review of #489, R1): mounted by root on
    # a host whose systemd runs the unified hierarchy, the agent moved into
    # it and frozen — refused at the move's and the freeze's write-open.
    if selected C83; then
        V1=/run/nn-lab-v1
        mkdir -p "$V1"
        if mount -t cgroup -o freezer nn-lab-v1 "$V1" 2>/dev/null; then
            mkdir -p "$V1/c83" 2>/dev/null
            PID=$(agent_pid); START=$(proc_start "$PID")
            POST=$(post post_proc "${PID:-0}" "${START:-0}" northnarrow-age) \
            run_case C83 "the agent moved into a mounted cgroup v1 freezer (no window)" denied "deny=cgroup_v1" 0 -- nnpy v1move "${PID:-0}" northnarrow-age "${START:-0}" "$V1/c83/cgroup.procs"
            if [[ -e $V1/c83/freezer.state ]]; then
                run_case C83b "FROZEN into the v1 freezer's freezer.state (no window)" denied "deny=cgroup_v1" 0 -- nnpy file write "$V1/c83/freezer.state" FROZEN
                echo THAWED > "$V1/c83/freezer.state" 2>/dev/null
            fi
            # back to the v1 root, then gone (a deviation leaves nothing)
            [[ -n $PID ]] && echo "$PID" > "$V1/cgroup.procs" 2>/dev/null
            rmdir "$V1/c83" 2>/dev/null; umount "$V1" 2>/dev/null; rmdir "$V1" 2>/dev/null
            restored C83 "$V1" absent "$(mountpoint -q "$V1" 2>/dev/null && echo mounted || echo absent)"
        else
            skipped_case C83,C83b "this kernel mounts no cgroup v1 freezer (cgroup_no_v1=, or v1 built out)" 1
        fi
    fi
    # C84: the agent's oom_score_adj through a thread's
    # /proc/<pid>/task/<tid> (C18 writes /proc/<pid>): the value is the
    # process's, the file another
    PID=$(agent_pid)
    OA0=$(cat /proc/"${PID:-0}"/oom_score_adj 2>/dev/null)
    TID=$(ls /proc/"${PID:-0}"/task 2>/dev/null | grep -vx "${PID:-0}" | head -1)
    if [[ -n $TID ]]; then
        POST=$(post post_value /proc/"${PID:-0}"/oom_score_adj "${OA0:-0}") \
        run_case C84 "oom_score_adj of an agent thread to 1000 (/proc/<pid>/task/<tid>, no window)" denied "deny=oom_adj" 0 -- nnpy file write /proc/"${PID:-0}"/task/"$TID"/oom_score_adj 1000
        [[ "$(cat /proc/"${PID:-0}"/oom_score_adj 2>/dev/null)" == "${OA0:-0}" ]] || echo "${OA0:-0}" > /proc/"${PID:-0}"/oom_score_adj 2>/dev/null
        restored C84 "the agent's oom_score_adj" "${OA0:-0}" "$(cat /proc/"${PID:-0}"/oom_score_adj 2>/dev/null)"
    else
        skipped_case C84 "the agent has one thread" 1
    fi
    # C85: a persistent set-property of the watchdog (TasksMax=1 for good,
    # applied to every later start's fresh cgroup): its drop-in refused
    if selected C85; then
        CTLW=/etc/systemd/system.control/northnarrow-watchdog.service.d
        WDPID=$(wd_pid); WDSTART=$(proc_start "$WDPID")
        t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
        TM0=$(cat "$CGROOT$WD_CG/pids.max" 2>/dev/null)
        TMP0=$(systemctl show -p TasksMax --value northnarrow-watchdog.service 2>/dev/null)
        out=$(timeout 60 systemctl set-property northnarrow-watchdog.service TasksMax=1 2>&1); rc=$?
        sleep 5; ev=$(evidence "$t0" "$a0" "$d0")
        if [[ ! -e $CTLW/50-TasksMax.conf && "$(cat "$CGROOT$WD_CG/pids.max" 2>/dev/null)" == "$TM0" ]] && echo "$ev" | grep -qE "deny=create|deny=cgroup_limit"; then
            v=OK; st="denied (no drop-in, pids.max kept at $TM0; systemctl rc=$rc)"
        else
            v="DEVIATION (drop-in $([[ -e $CTLW/50-TasksMax.conf ]] && echo present || echo absent), pids.max ${TM0:-?} -> $(cat "$CGROOT$WD_CG/pids.max" 2>/dev/null), rc=$rc)"; fail=1; st="allowed"
        fi
        rows+=("| C85 | systemctl set-property TasksMax=1 of the watchdog, for good (no window) | $st | $ev | $v |")
        echo "C85 persistent set-property of the watchdog → $st; $ev; $v" >&2
        if [[ -e $CTLW/50-TasksMax.conf ]]; then grant_window 30; rm -f "$CTLW/50-TasksMax.conf"; fi
        # A refused set-property still sets systemd's own TasksMax (in
        # memory, until a reload), which the watchdog's next fresh cgroup
        # would get: the reload takes it back (PID 1 writes the unit's
        # values, which the guard lets through).
        systemctl daemon-reload
        [[ -n $TM0 && "$(cat "$CGROOT$WD_CG/pids.max" 2>/dev/null)" != "$TM0" ]] && { grant_window 30; echo "$TM0" > "$CGROOT$WD_CG/pids.max" 2>/dev/null; }
        for i in $(seq 1 40); do window_open || break; sleep 1; done
        restored C85 "the watchdog's pids.max" "${TM0:-}" "$(cat "$CGROOT$WD_CG/pids.max" 2>/dev/null)"
        restored C85 "the watchdog unit's TasksMax" "${TMP0:-}" "$(systemctl show -p TasksMax --value northnarrow-watchdog.service 2>/dev/null)"
    fi
    # C87 (the review of #490, A): a drop-in in the watchdog's directories
    # and in the `northnarrow-.service.d` prefix ones (both units read it):
    # a `MemoryMax=4K` there would reach the next start's fresh cgroup.
    # Comment-only files here (harmless if they went through), refused at
    # their creation (NOCREATE).
    if selected C87; then
        t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
        made=(); mkd=(); refused=0; tried=0
        for d in /etc/systemd/system/northnarrow-watchdog.service.d /run/systemd/system/northnarrow-watchdog.service.d \
                 /etc/systemd/system/northnarrow-.service.d /run/systemd/system/northnarrow-.service.d; do
            # an agent before the review of #490 makes none of them: a root
            # shell makes the directory first, as an attacker would
            [[ -d $d ]] || { mkdir -p "$d" 2>/dev/null && mkd+=("$d"); }
            [[ -d $d ]] || continue
            tried=$((tried + 1))
            if out=$( { printf '# lab C87\n' > "$d/99-nn-lab-c87.conf"; } 2>&1 ) && [[ -e $d/99-nn-lab-c87.conf ]]; then
                made+=("$d")
            elif [[ "$(outcome_of "$out" held)" == denied ]]; then
                refused=$((refused + 1))
            fi
        done
        sleep 4; ev=$(evidence "$t0" "$a0" "$d0")
        if (( tried == 4 && refused == 4 )) && echo "$ev" | grep -qE "deny=create"; then
            v=OK; st="denied (4 of 4 directories)"
        else
            v="DEVIATION (expected 4 refusals: tried $tried, refused $refused, made in: ${made[*]:-none})"; fail=1
            st=$([[ ${#made[@]} -gt 0 ]] && echo allowed || echo partial)
        fi
        rows+=("| C87 | a drop-in in the watchdog's and the prefix drop-in directories (no window) | $st | $ev | $v |")
        echo "C87 drop-ins of the watchdog and the prefix → $st; $ev; $v" >&2
        if (( ${#made[@]} + ${#mkd[@]} )); then
            grant_window 30
            for d in "${made[@]}"; do rm -f "$d/99-nn-lab-c87.conf"; done
            for d in "${mkd[@]}"; do rmdir "$d" 2>/dev/null; done
            systemctl daemon-reload
            for i in $(seq 1 40); do window_open || break; sleep 1; done
        fi
        left=$(ls /etc/systemd/system/northnarrow-watchdog.service.d/99-nn-lab-c87.conf /run/systemd/system/northnarrow-watchdog.service.d/99-nn-lab-c87.conf \
               /etc/systemd/system/northnarrow-.service.d/99-nn-lab-c87.conf /run/systemd/system/northnarrow-.service.d/99-nn-lab-c87.conf 2>/dev/null | wc -l)
        restored C87 "the lab's drop-ins" 0 "$left"
    fi
    # C88 (the review of #490, B): the agent's memory.max opened through a
    # file handle after the dentries were dropped (a disconnected dentry,
    # no name, its own parent) and its current value written back (no
    # change if it went through): refused by the file's kernfs node.
    if selected C88; then
        MM=$CGROOT$AG_CG/memory.max
        if [[ -e $MM ]]; then
            MV=$(cat "$MM" 2>/dev/null)
            run_case C88 "the agent's memory.max opened by handle after drop_caches, its value written back (no window)" denied "deny=cgroup_limit" 0 -- nnpy handlewrite "$CGROOT" "$MM" "$MV"
            restored C88 "the agent's memory.max" "$MV" "$(cat "$MM" 2>/dev/null)"
        else
            skipped_case C88 "no memory.max in the agent's cgroup" 1
        fi
    fi
    # ── lot 273c (the review of #490) ──────────────────────────────────
    # C89-C94: another process's change of the agent's limits, scheduling,
    # nice value, I/O priority (task_setrlimit, task_setscheduler,
    # task_setnice, task_setioprio). `prlimit --cpu=1:1` is a SIGKILL from
    # the kernel (no signal hook sees it); each case puts back what got
    # through.
    PID=$(agent_pid); START=$(proc_start "$PID")
    if selected C89; then
        POST=$(post post_proc "$PID" "$START" northnarrow-age) \
        run_case C89 "prlimit --cpu=1:1 of the agent (an RLIMIT_CPU SIGKILL, no window)" denied "deny=rlimit" 0 -- prlimit --pid "$PID" --cpu=1:1
        PID=$(agent_pid 30); START=$(proc_start "$PID")
    fi
    # a case the agent did not survive (its code before the lot: C89's and
    # C90's limits end it) leaves the next one a new agent to aim at
    live_agent() { kill -0 "$PID" 2>/dev/null || { PID=$(agent_pid 30); START=$(proc_start "$PID"); }; }
    if selected C90; then
        live_agent
        NOF0=$(prlimit --pid "$PID" --nofile --raw --noheadings 2>/dev/null | awk '{print $2":"$3}')
        POST=$(post post_proc "$PID" "$START" northnarrow-age) \
        run_case C90 "prlimit --nofile=0:0 of the agent (no window)" denied "deny=rlimit" 0 -- prlimit --pid "$PID" --nofile=0:0
        now=$(prlimit --pid "$PID" --nofile --raw --noheadings 2>/dev/null | awk '{print $2":"$3}')
        [[ -n $NOF0 && "$now" != "$NOF0" ]] && { grant_window 20; prlimit --pid "$PID" --nofile="$NOF0" 2>/dev/null; for i in $(seq 1 30); do window_open || break; sleep 1; done; }
        # an agent the limit ended took it with it (its successor starts afresh)
        kill -0 "$PID" 2>/dev/null && restored C90 "the agent's RLIMIT_NOFILE" "$NOF0" "$(prlimit --pid "$PID" --nofile --raw --noheadings 2>/dev/null | awk '{print $2":"$3}')"
    fi
    if selected C91; then
        live_agent
        NI0=$(ps -o ni= -p "$PID" | tr -d ' ')
        POST=$(post post_proc "$PID" "$START" northnarrow-age) \
        run_case C91 "renice +19 of the agent (no window)" denied "deny=nice" 0 -- renice -n 19 -p "$PID"
        [[ "$(ps -o ni= -p "$PID" | tr -d ' ')" != "$NI0" ]] && { grant_window 20; renice -n "$NI0" -p "$PID" >/dev/null 2>&1; for i in $(seq 1 30); do window_open || break; sleep 1; done; }
        restored C91 "the agent's nice value" "$NI0" "$(ps -o ni= -p "$PID" | tr -d ' ')"
    fi
    if selected C92; then
        live_agent
        POL0=$(chrt -p "$PID" 2>/dev/null | head -1 | awk -F': ' '{print $2}')
        POST=$(post post_proc "$PID" "$START" northnarrow-age) \
        run_case C92 "chrt --idle (SCHED_IDLE) of the agent (no window)" denied "deny=sched" 0 -- chrt -i -p 0 "$PID"
        [[ "$(chrt -p "$PID" 2>/dev/null | head -1 | awk -F': ' '{print $2}')" != "$POL0" ]] && { grant_window 20; chrt -o -p 0 "$PID" 2>/dev/null; for i in $(seq 1 30); do window_open || break; sleep 1; done; }
        restored C92 "the agent's scheduling policy" "$POL0" "$(chrt -p "$PID" 2>/dev/null | head -1 | awk -F': ' '{print $2}')"
    fi
    if selected C93; then
        live_agent
        AFF0=$(taskset -p "$PID" 2>/dev/null | awk -F': ' '{print $2}')
        POST=$(post post_proc "$PID" "$START" northnarrow-age) \
        run_case C93 "taskset (one CPU) of the agent (no window)" denied "deny=sched" 0 -- taskset -p 1 "$PID"
        [[ "$(taskset -p "$PID" 2>/dev/null | awk -F': ' '{print $2}')" != "$AFF0" ]] && { grant_window 20; taskset -p "$AFF0" "$PID" >/dev/null 2>&1; for i in $(seq 1 30); do window_open || break; sleep 1; done; }
        restored C93 "the agent's CPU affinity" "$AFF0" "$(taskset -p "$PID" 2>/dev/null | awk -F': ' '{print $2}')"
    fi
    if selected C94; then
        live_agent
        IO0=$(ionice -p "$PID" 2>/dev/null)
        POST=$(post post_proc "$PID" "$START" northnarrow-age) \
        run_case C94 "ionice --class idle of the agent (no window)" denied "deny=ioprio" 0 -- ionice -c 3 -p "$PID"
        if [[ "$(ionice -p "$PID" 2>/dev/null)" != "$IO0" ]]; then
            grant_window 20
            case "$IO0" in none*) ionice -c 0 -p "$PID" ;; best-effort*) ionice -c 2 -n "${IO0##*prio }" -p "$PID" ;; esac 2>/dev/null
            for i in $(seq 1 30); do window_open || break; sleep 1; done
        fi
        restored C94 "the agent's I/O priority" "$IO0" "$(ionice -p "$PID" 2>/dev/null)"
    fi
    # C95, C96: PID 1 in attach mode — a tracer (PTRACE_SEIZE: PID 1 is not
    # stopped; the tracer's exit detaches it) and /proc/1/mem for writing
    # (opened, nothing written). The deny hooks trust PID 1's write-backs
    # on the bytes its write(2) carries: its memory must not be root's.
    if selected C95; then
        run_case C95 "PTRACE_SEIZE of PID 1 (no window)" denied "deny=ptrace" 0 -- python3 -I -c 'import ctypes,errno,sys
libc=ctypes.CDLL(None,use_errno=True)
r=libc.ptrace(0x4206,1,None,None)
print("seized pid 1" if r==0 else "errno=%s" % errno.errorcode.get(ctypes.get_errno(),"?"))'
    fi
    if selected C96; then
        run_case C96 "/proc/1/mem opened for writing (nothing written, no window)" denied "deny=ptrace" 0 -- nnpy file open-append /proc/1/mem
    fi
    # C95b: inside a window a debugger attaches to PID 1 (the same seize,
    # detached by the tracer's exit), and nothing is refused.
    if selected C95b; then
        grant_window 30; sleep 2
        EV_FORBID="deny=ptrace" run_case C95b "PTRACE_SEIZE of PID 1 inside a trusted-installer window" allowed "" 0 -- python3 -I -c 'import ctypes,errno,sys
libc=ctypes.CDLL(None,use_errno=True)
r=libc.ptrace(0x4206,1,None,None)
print("seized pid 1" if r==0 else "errno=%s" % errno.errorcode.get(ctypes.get_errno(),"?"))'
        # lot 273d: ended by its time, its signed close and the journal,
        # not the journal alone (C97 next reloads systemd)
        wait_no_window 90 || echo "C95b: its window not seen ended within 90 s" >&2
    fi
    # C97 (the review of #492, C1): the host's type- and slice-wide
    # drop-ins are the host's configuration for every service — a global
    # LimitNOFILE and a hardening SystemCallFilter stay untouched (alerts at
    # most); a MemoryMax below the agent's slice's floor, applied by the
    # host's own `daemon-reload`, is neutralised for our units (PID 1's
    # write of their slice refused) and signed `unit_dropin_harmful`;
    # nothing is moved. Lot 273d: the units' slice is their own
    # (northnarrow.slice), which system.slice.d no longer reaches: the
    # value goes in slice.d (every slice), 600M — below the agent's slice's
    # floor, survivable for the guest's other slices. Before lot 273d (the
    # units in system.slice): a 4K in system.slice.d, as #492 measured it.
    # Lot 273d (C97 seen timing-dependent by lots 275 and 277): the case
    # starts only once every window granted before it has ended (C95b's
    # still open at the reload let PID 1 apply the 4K on 5.15); and PID 1
    # may load a slice's drop-in at the reload without writing it (systemd
    # 257, Debian 13: no write, so no refusal to see) — then a start in the
    # slice realises it (C86's path on 257+), which must be refused the
    # same. Which path it took is in the row.
    if selected C97 && ! wait_no_window 90; then
        rows+=("| C97 | the host's drop-ins | not run | — | DEVIATION (not run: a trusted-installer window still open after 90 s) |")
        echo "C97 not run: a window still open" >&2; fail=1
    elif selected C97; then
        DS=/etc/systemd/system/service.d
        if [[ "$AG_SLICE" == /northnarrow.slice ]]; then
            DL=/etc/systemd/system/slice.d; MEMV=600M
        else
            DL=/etc/systemd/system/system.slice.d; MEMV=4K
        fi
        SLU=${AG_SLICE#/}; SLU=${SLU:-system.slice}
        F1=$DS/99-nn-lab-c97-nofile.conf; F2=$DS/99-nn-lab-c97-scf.conf; F3=$DL/99-nn-lab-c97-mem.conf
        SMX=$CGROOT${AG_SLICE:-/system.slice}/memory.max; SMX0=$(cat "$SMX" 2>/dev/null)
        DS_WAS=$([[ -d $DS ]] && echo present || echo absent); DL_WAS=$([[ -d $DL ]] && echo present || echo absent)
        mkdir -p "$DS" "$DL"
        t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
        printf '[Service]\nLimitNOFILE=1048576\n' > "$F1"
        printf '[Service]\nSystemCallFilter=~@obsolete\n' > "$F2"
        printf '[Slice]\nMemoryMax=%s\n' "$MEMV" > "$F3"
        # PID 1's own word on its writes: a refused cgroup write is a debug
        # line of systemd's ("Failed to set 'memory.max' attribute on …"),
        # so the reload runs at its debug level (back after 5 s)
        LL0=$(systemctl log-level 2>/dev/null); tr0=$(date '+%Y-%m-%d %H:%M:%S')
        [[ -n $LL0 ]] && systemctl log-level debug 2>/dev/null
        systemctl daemon-reload
        sleep 5; [[ -n $LL0 ]] && systemctl log-level "$LL0" 2>/dev/null
        sleep 40; ev=$(evidence "$t0" "$a0" "$d0")
        smx=$(cat "$SMX" 2>/dev/null)
        loaded=$(systemctl show -p MemoryMax --value "$SLU" 2>/dev/null)
        p1() { journalctl -q --no-pager _PID=1 --since "$1" 2>/dev/null | grep -c "Failed to set 'memory.max' attribute on '/$SLU'"; }
        how="written by PID 1 at the reload (PID 1's refused writes: $(p1 "$tr0"))"
        if ! grep -q "deny=cgroup_limit" <<<"$ev" && [[ "$smx" == "$SMX0" ]]; then
            how="loaded by systemd at the reload (its MemoryMax of $SLU: ${loaded:-?}, PID 1's refused writes: $(p1 "$tr0")) but not written; written at a start in the slice"
            tr1=$(date '+%Y-%m-%d %H:%M:%S'); [[ -n $LL0 ]] && systemctl log-level debug 2>/dev/null
            systemd-run --quiet --unit=nn-lab-c97 --slice="$SLU" /bin/sleep 30 >/dev/null 2>&1
            sleep 5; [[ -n $LL0 ]] && systemctl log-level "$LL0" 2>/dev/null
            systemctl stop nn-lab-c97 >/dev/null 2>&1; systemctl reset-failed nn-lab-c97 >/dev/null 2>&1
            sleep 5; ev=$(evidence "$t0" "$a0" "$d0"); smx=$(cat "$SMX" 2>/dev/null)
            how="$how (PID 1's refused writes there: $(p1 "$tr1"))"
            grep -q "deny=cgroup_limit" <<<"$ev" || how="loaded by systemd at the reload (its MemoryMax of $SLU: ${loaded:-?}), written neither at the reload nor at a start in the slice (PID 1's refused writes: $(p1 "$tr0"))"
        fi
        harm=$(audit_since "$a0" | grep 'unit_dropin_harmful')
        h3=$(grep -c '99-nn-lab-c97-mem.conf' <<<"$harm"); h12=$(grep -cE '99-nn-lab-c97-(nofile|scf).conf' <<<"$harm")
        present=0; for f in "$F1" "$F2" "$F3"; do [[ -e $f ]] && present=$((present + 1)); done
        # round 7: a window opened while the 4K is on disk — the agent's own
        # reload at the window's opening must not apply it (PID 1's writes
        # are let through inside a window)
        # lot 273d: the grant itself warns the operator (round 7's case)
        ga=$(audit_count)
        gw=$("$NNADMIN" trusted-installer-grant --key "$ADMIN_KEY" --window-secs 20 2>&1 >/dev/null) \
            && { WIN_UNTIL=$(( $(date +%s) + 20 )); WIN_A0=$ga; }
        warned=$(grep -c 'WARNING — a host drop-in harmful' <<<"$gw")
        sleep 10; smxw=$(cat "$SMX" 2>/dev/null)
        wait_no_window 90 || echo "C97: the grant's window not seen ended within 90 s" >&2
        wh=$(audit_since "$a0" | grep '"systemd_reload"' | grep -c '"withheld"')
        if (( present == 3 && h3 > 0 && h12 == 0 && wh > 0 && warned > 0 )) && [[ "$smx" == "$SMX0" && "$smxw" == "$SMX0" ]] && echo "$ev" | grep -q "deny=cgroup_limit"; then
            v=OK; st="the three left in place; ${AG_SLICE}'s MemoryMax=$MEMV $how, refused (memory.max $smx, $smxw inside a window), signed harmful; LimitNOFILE and SystemCallFilter not harmful; the agent's reloads withheld: $wh; the grant warned"
        else
            v="DEVIATION (files left $present of 3, ${AG_SLICE} memory.max ${smx:-?} / ${smxw:-?} inside a window (was $SMX0), the value $how, harmful signed for the $MEMV $h3, for the other two $h12, reloads withheld $wh, the grant's warning $warned)"; fail=1; st="not as expected"
        fi
        rows+=("| C97 | the host's drop-ins: LimitNOFILE and SystemCallFilter in service.d, MemoryMax=$MEMV in ${DL##*/} | $st | $ev | $v |")
        echo "C97 the host's drop-ins → $st; $ev; $v" >&2
        # removed BEFORE any window: inside one a reload applies the 4K to
        # the slice (PID 1's writes are let through there — round 7 lost
        # the guest's system.slice so); outside one PID 1 writes back the
        # registered value only
        rm -f "$F1" "$F2" "$F3"
        [[ $DS_WAS == absent ]] && rmdir "$DS" 2>/dev/null; [[ $DL_WAS == absent ]] && rmdir "$DL" 2>/dev/null
        systemctl daemon-reload; sleep 5
        restored C97 "the lab's drop-ins" absent "$([[ -e $F1 || -e $F2 || -e $F3 ]] && echo present || echo absent)"
        restored C97 "${AG_SLICE}'s memory.max" "$SMX0" "$(cat "$SMX" 2>/dev/null)"
    fi
    # C98: a floor — the agent's memory.high set below 512 MiB inside a
    # window, the window closed: registered again at the floor, written
    # back, signed.
    # Lot 273d (C98 seen timing-dependent by lot 275): the value set inside
    # the window is below the floor but above what the agent's cgroup holds
    # (its memory.current and 128 MiB) — lot 275's 2404 run set 100 MiB
    # under a larger agent, whose reclaim stalled it: it was respawned
    # inside the window (prev_run_abrupt), no close ran, and the fresh
    # cgroup had systemd's value. An agent restarted during the case is
    # said so, never read as the close's result.
    if selected C98 && [[ -e $CGROOT$AG_CG/memory.high ]]; then
        MH=$CGROOT$AG_CG/memory.high; MH0=$(cat "$MH")
        CUR=$(cat "$CGROOT$AG_CG/memory.current" 2>/dev/null || echo 0)
        LOW=$(( (CUR + (128 << 20)) / 4096 * 4096 )); (( LOW < 104857600 )) && LOW=104857600
        if (( LOW > 536870912 - (32 << 20) )); then
            skipped_case C98 "the agent's cgroup holds $CUR bytes: no value below the 512 MiB floor leaves it room" 1
        else
            wait_no_window 90 || echo "C98: an earlier window not seen ended within 90 s" >&2
            P0=$(agent_pid 0)
            t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
            grant_window 10; sleep 1; echo "$LOW" > "$MH"
            wait_no_window 60 || echo "C98: its window not seen ended within 60 s" >&2
            sleep 40; ev=$(evidence "$t0" "$a0" "$d0"); now=$(cat "$MH"); P1=$(agent_pid 0)
            if [[ "$P1" != "$P0" ]]; then
                v="DEVIATION (the agent restarted during the case, pid $P0 → ${P1:-none}: no close ran; memory.high $now)"; fail=1; st="not exercised"
            elif [[ "$now" == 536870912 ]] && echo "$ev" | grep -q "integrity_drift"; then
                v=OK; st="$LOW (the agent's cgroup at $CUR) restored to the floor"
            else
                v="DEVIATION (memory.high $now after the window, expected the floor 536870912; set $LOW, the agent's cgroup at $CUR)"; fail=1; st="left"
            fi
            rows+=("| C98 | the agent's memory.high below its floor at a window's close | $st | $ev | $v |")
            echo "C98 floor at a window's close → $st; $ev; $v" >&2
            grant_window 15; sleep 1; echo "$MH0" > "$MH"; wait_no_window 60
            restored C98 "the agent's memory.high" "$MH0" "$(cat "$MH")"
        fi
    fi
    # C99: a named cgroup v1 hierarchy (no controller: an old container's
    # name=systemd) — a write to its cgroup.procs is let through (lot 273b
    # refused every v1 write); a freezer hierarchy stays refused (C83).
    if selected C99; then
        V1N=/run/nn-lab-v1n
        mkdir -p "$V1N"
        if mount -t cgroup -o none,name=nnlabc99 nnlabc99 "$V1N" 2>/dev/null; then
            mkdir -p "$V1N/c99"
            sleep 300 & SL=$!
            EV_FORBID="deny=cgroup_v1" run_case C99 "a process moved in a named v1 hierarchy (no controller)" allowed "" 0 -- nnpy file write "$V1N/c99/cgroup.procs" "$SL"
            kill "$SL" 2>/dev/null; wait "$SL" 2>/dev/null
            rmdir "$V1N/c99" 2>/dev/null; umount "$V1N" 2>/dev/null; rmdir "$V1N" 2>/dev/null
        else
            skipped_case C99 "a named v1 hierarchy cannot be mounted here" 1
        fi
    fi
    # C100: a refused set-property: systemd's own copy taken back by the
    # agent's reload (the copy the unit's next start would apply).
    if selected C100; then
        MHP0=$(systemctl show -p MemoryHigh --value northnarrow-agent.service)
        t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
        systemctl set-property --runtime northnarrow-agent.service MemoryHigh=2G >/dev/null 2>&1
        # the reload waits out the agent's 30 s between two (a refusal is kept, not dropped)
        for i in $(seq 1 75); do [[ "$(systemctl show -p MemoryHigh --value northnarrow-agent.service)" == "$MHP0" ]] && break; sleep 1; done
        ev=$(evidence "$t0" "$a0" "$d0"); now=$(systemctl show -p MemoryHigh --value northnarrow-agent.service)
        if [[ "$now" == "$MHP0" ]] && echo "$ev" | grep -q "systemd_reload"; then
            v=OK; st="systemd's copy back ($now)"
        else
            v="DEVIATION (systemd's MemoryHigh $now, expected $MHP0)"; fail=1; st="left"
        fi
        rows+=("| C100 | a refused set-property, systemd's copy taken back by a reload | $st | $ev | $v |")
        echo "C100 refused set-property's copy → $st; $ev; $v" >&2
        systemctl daemon-reload
        restored C100 "systemd's MemoryHigh of the agent" "$MHP0" "$(systemctl show -p MemoryHigh --value northnarrow-agent.service)"
    fi
    # C103 (lot 273d): io.prio.class idle on the agent's unit (its audit
    # log's writes starved under contention): refused.
    if selected C103; then
        if [[ -e $CGROOT$AG_CG/io.prio.class ]]; then
            run_case C103 "io.prio.class idle of the agent's unit (no window)" denied "deny=cgroup_limit" 0 -- nnpy file write "$CGROOT$AG_CG/io.prio.class" idle
        else
            skipped_case C103 "no io.prio.class (CONFIG_BLK_CGROUP_IOPRIO off, or a kernel before 5.14)" 1
        fi
    fi
    # C104 (lot 273d): the global sysctls that abort or starve the agent —
    # vm.max_map_count cut, real-time throttling off — refused outside a
    # window; a harmless write (the value it holds) goes through.
    if selected C104; then
        MMC0=$(cat /proc/sys/vm/max_map_count); RT0=$(cat /proc/sys/kernel/sched_rt_runtime_us)
        POST=$(post post_same_text /proc/sys/vm/max_map_count "$MMC0") \
        run_case C104 "vm.max_map_count=100 (no window)" denied "deny=sysctl" 0 -- nnpy file write /proc/sys/vm/max_map_count 100
        POST=$(post post_same_text /proc/sys/kernel/sched_rt_runtime_us "$RT0") \
        run_case C104b "kernel.sched_rt_runtime_us=-1 (no window)" denied "deny=sysctl" 0 -- nnpy file write /proc/sys/kernel/sched_rt_runtime_us -1
        EV_FORBID="deny=sysctl" run_case C104c "vm.max_map_count written with its own value (no window)" allowed "" 0 -- nnpy file write /proc/sys/vm/max_map_count "$MMC0"
        # before lot 273d the writes went through: put back what they set
        [[ "$(cat /proc/sys/vm/max_map_count)" == "$MMC0" ]] || echo "$MMC0" > /proc/sys/vm/max_map_count
        [[ "$(cat /proc/sys/kernel/sched_rt_runtime_us)" == "$RT0" ]] || echo "$RT0" > /proc/sys/kernel/sched_rt_runtime_us
        restored C104 "vm.max_map_count" "$MMC0" "$(cat /proc/sys/vm/max_map_count)"
        restored C104 "kernel.sched_rt_runtime_us" "$RT0" "$(cat /proc/sys/kernel/sched_rt_runtime_us)"
    fi
    # C105 (lot 273d): a set-property inside a window below the agent's
    # floor (MemoryHigh=300M, survivable): at the window's close its drop-in
    # (made inside the window) is quarantined, systemd reloads (confirmed)
    # and the file at its floor goes back to the configured value.
    if selected C105 && [[ -e $CGROOT$AG_CG/memory.high ]]; then
        MH=$CGROOT$AG_CG/memory.high; MHC=$(systemctl show -p MemoryHigh --value northnarrow-agent.service)
        t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
        grant_window 15; sleep 2
        timeout 60 systemctl set-property --runtime northnarrow-agent.service MemoryHigh=300M >/dev/null 2>&1
        CTL=/run/systemd/system.control/northnarrow-agent.service.d/50-MemoryHigh.conf
        made=$([[ -e $CTL ]] && echo yes || echo no)
        for i in $(seq 1 40); do window_open || break; sleep 1; done
        sleep 45; ev=$(evidence "$t0" "$a0" "$d0")
        q=$(tail -n +"$((a0 + 1))" "$AUDIT" 2>/dev/null | grep '"trusted_installer_window_close"' | grep -c '50-MemoryHigh.conf')
        rl=$(tail -n +"$((a0 + 1))" "$AUDIT" 2>/dev/null | grep '"systemd_reload"' | grep -c '"reloaded"')
        now=$(cat "$MH"); copy=$(systemctl show -p MemoryHigh --value northnarrow-agent.service)
        if [[ $made == yes && ! -e $CTL && "$now" == "$MHC" && "$copy" == "$MHC" ]] && (( q > 0 && rl > 0 )); then
            v=OK; st="the drop-in quarantined at the close, systemd reloaded (confirmed), memory.high back to $now"
        else
            v="DEVIATION (drop-in made $made, now $([[ -e $CTL ]] && echo present || echo gone), quarantined in the close record $q, confirmed reloads $rl, memory.high $now, systemd's copy $copy, expected $MHC)"; fail=1; st="not as expected"
        fi
        rows+=("| C105 | set-property MemoryHigh=300M inside a window: its drop-in at the close | $st | $ev | $v |")
        echo "C105 a below-floor drop-in made inside a window → $st; $ev; $v" >&2
        if [[ -e $CTL ]]; then grant_window 20; sleep 2; rm -f "$CTL"; systemctl daemon-reload; for i in $(seq 1 40); do window_open || break; sleep 1; done; fi
        restored C105 "systemd's MemoryHigh of the agent" "$MHC" "$(systemctl show -p MemoryHigh --value northnarrow-agent.service)"
    fi
    # C101: memory.reclaim of the agent's unit (a forced reclaim, repeated:
    # a thrash): refused to everyone.
    if selected C101; then
        if [[ -e $CGROOT$AG_CG/memory.reclaim ]]; then
            run_case C101 "memory.reclaim of the agent's unit (no window)" denied "deny=cgroup_limit" 0 -- nnpy file write "$CGROOT$AG_CG/memory.reclaim" 1M
        else
            skipped_case C101 "no memory.reclaim (a kernel before 5.19)" 1
        fi
    fi
fi

# ── R1 of the external review of 04/11 (lot 273d): kernel.ftrace_enabled ──
# 0 turns every call site ftrace manages back into a NOP on 6.0 to 7.2 —
# the BPF trampolines on them stop: fentry/fexit, the kprobes on ftrace
# and, by the kernel's code, the BPF-LSM programs (every deny hook); EBUSY
# on 5.15 to 5.19 while a trampoline is attached; refused from 7.3.
#   C106  0 outside a window: refused, the value kept, the signed detection
#         within 1 s;
#   C106a 1 outside a window: refused too (the coordinator's decision of
#         04/11: every write of ftrace_enabled outside a window, unread —
#         nothing for a second thread to race; the agent's own restore
#         passes by its identity, C106b);
#   C106b 0 inside a window: let through (or the kernel's own EBUSY /
#         EOPNOTSUPP), the manifest's degradation signed within 10 s, put
#         back to 1 by the window's close or the round, signed;
#   C106r a MEASURE of the declared residual of the seven sysctls judged
#         by value (lot 280 closes it with cgroup/sysctl): the hook reads
#         the bytes before the kernel copies them, and a second thread flips
#         one — kernel.sched_rt_runtime_us 950000 / 990000 (harmful at 99 %,
#         harmless on a guest without real-time load): how many of N writes
#         put 990000 in, and how long until the agent puts one back;
#   C106c a MEASURE (the lab build's BPF guard observes, so bpftool reads
#         our programs; kernel.bpf_stats_enabled on for it): the run counts
#         of the BPF-LSM, fentry/fexit and kprobe programs under the same
#         load with ftrace on, written 0 inside a window, and on again —
#         whether 0 stops them on this kernel (SENSOR_CONTRACT.md §5a).
FT=/proc/sys/kernel/ftrace_enabled
if ! selected C106 && ! selected C106a && ! selected C106b && ! selected C106c && ! selected C106r; then
    :
elif [[ ! -e $FT ]]; then
    skipped_case C106,C106a,C106b,C106c,C106r "no kernel.ftrace_enabled (a kernel without ftrace)" 1
elif [[ "$(cat "$FT")" != 1 ]]; then
    skipped_case C106,C106a,C106b,C106c,C106r "kernel.ftrace_enabled is $(cat "$FT") before the cases" 0
else
    if selected C106; then
        wait_no_window 90 || echo "C106: an earlier window not seen ended within 90 s" >&2
        t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
        w=$(nnpy timedwrite "$FT" 0 "$DETS" sysctl); rc=${w%% *}; lat=${w##* }
        sleep 3; ev=$(evidence "$t0" "$a0" "$d0"); now=$(cat "$FT")
        if [[ $rc == errno=EPERM && $now == 1 && $lat != none ]] \
            && python3 -I -c 'import sys; sys.exit(0 if float(sys.argv[1]) <= 1.0 else 1)' "$lat" \
            && grep -q "deny=sysctl" <<<"$ev"; then
            v=OK; st="refused (EPERM), the value 1, the signed detection after $lat s"
        else
            v="DEVIATION (the write: $rc, the value $now, the signed detection after $lat s, expected EPERM, 1, within 1 s)"; fail=1; st="not as expected"
        fi
        rows+=("| C106 | kernel.ftrace_enabled=0 (no window) | $st | $ev | $v |")
        echo "C106 kernel.ftrace_enabled=0 outside a window → $st; $ev; $v" >&2
        [[ "$(cat "$FT")" == 1 ]] || echo 1 > "$FT"
        restored C106 "kernel.ftrace_enabled" 1 "$(cat "$FT")"
    fi
    if selected C106a; then
        POST=$(post post_same_text "$FT" 1) \
        run_case C106a "kernel.ftrace_enabled=1 (no window)" denied "deny=sysctl" 0 -- nnpy file write "$FT" 1
    fi
    if selected C106b; then
        wait_no_window 90 || echo "C106b: an earlier window not seen ended within 90 s" >&2
        t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
        grant_window 12; sleep 2
        w=$(nnpy file write "$FT" 0); vin=$(cat "$FT"); tw=$(date +%s)
        # the manifest's degradation, signed at its next build (every 5 s)
        deg=none
        for i in $(seq 1 15); do
            if audit_since "$a0" | grep '"subsystem_degraded"' | grep -q '"source":"ftrace_enabled"'; then deg=$(( $(date +%s) - tw )); break; fi
            sleep 1
        done
        # back to 1: the window's close (12 s) or the round, whichever first
        back=none
        for i in $(seq 1 60); do [[ "$(cat "$FT")" == 1 ]] && { back=$(( $(date +%s) - tw )); break; }; sleep 1; done
        wait_no_window 60 || echo "C106b: its window not seen ended within 60 s" >&2
        sleep 2; ev=$(evidence "$t0" "$a0" "$d0")
        by_close=$(audit_since "$a0" | grep '"trusted_installer_window_close"' | grep -c 'ftrace_enabled')
        by_round=$(audit_since "$a0" | grep '"sysctl_restored"' | grep -c 'ftrace_enabled')
        if [[ $w == *"wrote '0'"* ]]; then
            if [[ $vin == 0 && $deg != none && $back != none ]] && (( deg <= 10 && by_close + by_round > 0 )) && ! grep -q "deny=sysctl" <<<"$ev"; then
                v=OK; st="let through (the value 0), the manifest's degradation signed after ${deg} s, back to 1 after ${back} s (by the close: $by_close, by the round: $by_round)"
            else
                v="DEVIATION (let through, the value $vin, the degradation signed after $deg s, back to 1 after $back s, by the close $by_close, by the round $by_round)"; fail=1; st="not as expected"
            fi
        elif [[ $w == *"errno=EBUSY"* || $w == *"errno=EOPNOTSUPP"* ]] && [[ $vin == 1 ]]; then
            v=OK; st="the kernel's own refusal (${w##*errno=}: on 5.15-5.19 a trampoline is attached, from 7.3 the switch is gone), the value 1"
        else
            v="DEVIATION (the write: $w, the value $vin)"; fail=1; st="not as expected"
        fi
        rows+=("| C106b | kernel.ftrace_enabled=0 inside a window | $st | $ev | $v |")
        echo "C106b kernel.ftrace_enabled=0 inside a window → $st; $ev; $v" >&2
        [[ "$(cat "$FT")" == 1 ]] || { grant_window 10; sleep 1; echo 1 > "$FT"; wait_no_window 60; }
        restored C106b "kernel.ftrace_enabled" 1 "$(cat "$FT")"
    fi
    if selected C106r; then
        RT=/proc/sys/kernel/sched_rt_runtime_us
        if [[ "$(cat "$RT" 2>/dev/null)" != 950000 ]]; then
            skipped_case C106r "kernel.sched_rt_runtime_us is not the default 950000 here" 1
        else
            wait_no_window 90 || echo "C106r: an earlier window not seen ended within 90 s" >&2
            t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
            m=$(nnpy sysctl-race "$RT" 950000 990000 2000 | tail -1)
            sleep 3; ev=$(evidence "$t0" "$a0" "$d0")
            rs=$(audit_since "$a0" | grep '"sysctl_restored"' | grep -c 'sched_rt_runtime_us')
            rows+=("| C106r | kernel.sched_rt_runtime_us=990000 by a thread flipping the written byte (no window; a declared residual, lot 280) | $(tr -d '|' <<<"$m"); signed sysctl_restored: $rs | $ev | MEASURED |")
            echo "C106r the flip race on a value-judged sysctl → $m; restored rows $rs; $ev" >&2
            [[ "$(cat "$RT")" == 950000 ]] || echo 950000 > "$RT"
            restored C106r "kernel.sched_rt_runtime_us" 950000 "$(cat "$RT")"
        fi
    fi
    if selected C106c; then
        ST=/proc/sys/kernel/bpf_stats_enabled
        if ! command -v bpftool >/dev/null 2>&1 || [[ ! -e $ST ]]; then
            skipped_case C106c "no bpftool, or no kernel.bpf_stats_enabled" 1
        elif [[ "$BPF_MODE" != observe ]]; then
            skipped_case C106c "the BPF guard enforces (not a lab build): bpftool cannot read our programs" 1
        else
            wait_no_window 90 || echo "C106c: an earlier window not seen ended within 90 s" >&2
            ST0=$(cat "$ST")
            grant_window 30; sleep 2
            echo 1 > "$ST"
            m=$(nnpy ftmeasure "$FT")
            echo "$ST0" > "$ST"
            [[ "$(cat "$FT")" == 1 ]] || echo 1 > "$FT"
            wait_no_window 90 || echo "C106c: its window not seen ended within 90 s" >&2
            rows+=("| C106c | the BPF programs' runs with ftrace on, 0 (inside a window) and on again | $(tr -d '|' <<<"$m") | — | MEASURED |")
            echo "C106c ftrace_enabled measure → $m" >&2
            restored C106c "kernel.ftrace_enabled" 1 "$(cat "$FT")"
            restored C106c "kernel.bpf_stats_enabled" "$ST0" "$(cat "$ST")"
        fi
    fi
fi

# ── the review of #497 (lot 273d): the sysctls' judgment, our drop-ins ────
#   C107  D1: kernel.pid_max written 040000 (octal: the kernel reads 16384)
#         outside a window — refused, the value kept;
#   C108  D2: kernel.pid_max written by an io-wq worker (IORING_OP_WRITE
#         with IOSQE_ASYNC; the process wrote the same bytes to /dev/null
#         just before, so a worker born at that return carries that write's
#         registers) — refused (its registers are never read), the value
#         kept, even for the value it already holds;
#   C109  D3: kernel.sched_rt_period_us written (its own value) outside a
#         window — refused; then, inside a window, the period cut to the
#         runtime (throttling off): put back by the close or the round to a
#         runtime of 95 % of the period;
#   C110  D4: inside a window a symlink drop-in (to a file outside our
#         directories) and a hard-linked one made in the agent's runtime
#         drop-in directory and a hard-linked one in the persistent one —
#         both moved at the window's close, the link's target untouched.
PM=/proc/sys/kernel/pid_max
if selected C107; then
    PM0=$(cat "$PM")
    POST=$(post post_same_text "$PM" "$PM0") \
    run_case C107 "kernel.pid_max=040000 (octal, the kernel's 16384; no window)" denied "deny=sysctl" 0 -- nnpy file write "$PM" 040000
    [[ "$(cat "$PM")" == "$PM0" ]] || echo "$PM0" > "$PM"
    restored C107 "kernel.pid_max" "$PM0" "$(cat "$PM")"
fi
if selected C108; then
    if (( IOU_BUILT )); then
        PM0=$(cat "$PM")
        POST=$(post post_same_text "$PM" "$PM0") \
        run_case C108 "kernel.pid_max written by an io-wq worker (its own value; no window)" denied "deny=sysctl" 0 -- "$IOU_BIN" --write-async "$PM" "$PM0"
        restored C108 "kernel.pid_max" "$PM0" "$(cat "$PM")"
    else
        skipped_case C108 "the io_uring probe was not built (io_uring_disabled, or no compiler)" 1
    fi
fi
if selected C109; then
    RP=/proc/sys/kernel/sched_rt_period_us; RR=/proc/sys/kernel/sched_rt_runtime_us
    RP0=$(cat "$RP"); RR0=$(cat "$RR")
    POST=$(post post_same_text "$RP" "$RP0") \
    run_case C109 "kernel.sched_rt_period_us written its own value (no window)" denied "deny=sysctl" 0 -- nnpy file write "$RP" "$RP0"
    wait_no_window 90 || echo "C109: an earlier window not seen ended within 90 s" >&2
    t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
    grant_window 12; sleep 2
    w=$(nnpy file write "$RP" "$RR0"); tw=$(date +%s)
    back=none
    for i in $(seq 1 60); do
        r=$(cat "$RR"); p=$(cat "$RP")
        if (( r >= 0 && r * 100 < p * 99 )); then back=$(( $(date +%s) - tw )); break; fi
        sleep 1
    done
    wait_no_window 60 || true
    ev=$(evidence "$t0" "$a0" "$d0")
    r=$(cat "$RR"); p=$(cat "$RP")
    if [[ $w == *"wrote '$RR0'"* && $back != none ]] && (( r == p / 100 * 95 )); then
        v=OK; st="the period cut to the runtime inside a window ($RR0 / $RR0), put back after ${back} s: runtime $r for the period $p (95 %)"
    else
        v="DEVIATION (the write: $w; runtime $r, period $p, back after $back s)"; fail=1; st="not as expected"
    fi
    rows+=("| C109 | kernel.sched_rt_period_us cut to the runtime inside a window | $st | $ev | $v |")
    echo "C109 the RT period → $st; $ev; $v" >&2
    grant_window 10; sleep 1; echo "$RP0" > "$RP"; echo "$RR0" > "$RR"; wait_no_window 60 || true
    restored C109 "kernel.sched_rt_period_us" "$RP0" "$(cat "$RP")"
    restored C109 "kernel.sched_rt_runtime_us" "$RR0" "$(cat "$RR")"
fi
if selected C110; then
    OD=/run/systemd/system/northnarrow-agent.service.d
    # the hard link on the root filesystem, as its source (no link crosses
    # into /run's tmpfs)
    OE=/etc/systemd/system/northnarrow-agent.service.d
    OUT=$(mktemp -d /var/tmp/nn-lab-c110.XXXXXX)
    printf '[Service]\nMemoryHigh=2G\n' > "$OUT/target.conf"
    printf '[Service]\nMemoryHigh=2G\n' > "$OUT/shared.conf"
    wait_no_window 90 || echo "C110: an earlier window not seen ended within 90 s" >&2
    t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
    grant_window 12; sleep 2
    ln -s "$OUT/target.conf" "$OD/60-nn-lab-c110-link.conf" 2>/dev/null
    ln "$OUT/shared.conf" "$OE/61-nn-lab-c110-hard.conf" 2>/dev/null
    made="$([[ -L $OD/60-nn-lab-c110-link.conf ]] && echo link) $([[ -e $OE/61-nn-lab-c110-hard.conf ]] && echo hard)"
    wait_no_window 60 || true
    sleep 5; ev=$(evidence "$t0" "$a0" "$d0")
    q=$(audit_since "$a0" | grep '"trusted_installer_window_close"' | grep -c 'nn-lab-c110')
    left="$([[ -e $OD/60-nn-lab-c110-link.conf || -L $OD/60-nn-lab-c110-link.conf ]] && echo link) $([[ -e $OE/61-nn-lab-c110-hard.conf ]] && echo hard)"
    tgt=$(cat "$OUT/target.conf")
    if [[ $made == "link hard" && $left == " " ]] && (( q > 0 )) && [[ $tgt == *"MemoryHigh=2G"* ]]; then
        v=OK; st="the symlink and the hard link made inside the window moved at its close (in its signed record), the link's target untouched"
    else
        v="DEVIATION (made: $made; left after the close: $left; in the close record $q)"; fail=1; st="not as expected"
    fi
    rows+=("| C110 | a symlink and a hard-linked drop-in made inside a window in our directory | $st | $ev | $v |")
    echo "C110 links in our drop-in directory → $st; $ev; $v" >&2
    if [[ -e $OD/60-nn-lab-c110-link.conf || -L $OD/60-nn-lab-c110-link.conf || -e $OE/61-nn-lab-c110-hard.conf ]]; then
        grant_window 10; sleep 1; rm -f "$OD/60-nn-lab-c110-link.conf" "$OE/61-nn-lab-c110-hard.conf"; wait_no_window 60 || true
    fi
    rm -rf "$OUT"
    restored C110 "the lab's links" absent "$([[ -e $OD/60-nn-lab-c110-link.conf || -L $OD/60-nn-lab-c110-link.conf || -e $OE/61-nn-lab-c110-hard.conf ]] && echo present || echo absent)"
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
    run_case C56a "rename a copy over the agent binary" denied "deny=rename" 0 -- nnpy file rename "$BIN_TMP" "$BIN_DIR/northnarrow-agent"
fi
[[ -n "${BIN_TMP:-}" ]] && rm -f "$BIN_TMP"
if selected C56b && cp -p "$BIN_DIR/northnarrow-watchdog" "$SCRATCH/northnarrow-watchdog"; then
    RESTORE+=("$BIN_DIR/northnarrow-watchdog|$SCRATCH/northnarrow-watchdog")
    POST=$(post post_same "$BIN_DIR/northnarrow-watchdog" ino "$(nnpy fileid "$BIN_DIR/northnarrow-watchdog" ino)") \
    run_case C56b "unlink the watchdog binary" denied "deny=unlink" 0 -- nnpy file unlink "$BIN_DIR/northnarrow-watchdog"
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
    run_case C57a "truncate(2) audit.log to 0 bytes" denied "deny=setattr" 0 -- nnpy file truncate "$AUDIT"
    post_not_shrunk "$AUDIT" "$a_before" >/dev/null || keep_copy C57a "$SCRATCH/audit.log" audit.log
fi
if selected C57b && cp -p "$DETS" "$SCRATCH/detections.jsonl"; then
    d_before=$(nnpy fileid "$DETS" size)
    POST=$(post post_not_shrunk "$DETS" "$d_before") \
    run_case C57b ": > detections.jsonl (open with O_TRUNC)" denied "deny=write" 0 -- nnpy file open-trunc "$DETS"
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
IOU_TGT=$ETC/netflow-blocklist.v1
if [[ $(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo 0) == 2 ]]; then
    skipped_case C59a,C59b,C59c "io_uring_disabled=2" 1
elif ! selected_any C59a,C59b,C59c; then
    :
elif (( IOU_BUILT )) && "$IOU_BIN" --modes 2>/dev/null | grep -qw rename; then
    POST=$(post post_not_shrunk "$AUDIT" "$(nnpy fileid "$AUDIT" size)") \
    run_case C59a "io_uring: open audit.log for writing through a ring" denied "deny=write" 0 -- "$IOU_BIN" --open-write "$AUDIT"
    if selected_any C59b,C59c && cp -p "$IOU_TGT" "$SCRATCH/iou-target"; then
        RESTORE+=("$IOU_TGT|$SCRATCH/iou-target")
        IOU_ID=$(nnpy fileid "$IOU_TGT" ino)
        POST=$(post post_same "$IOU_TGT" ino "$IOU_ID") \
        run_case C59b "io_uring: unlink a protected file through a ring" denied "deny=unlink" 0 -- "$IOU_BIN" --unlink "$IOU_TGT"
        restore_missing "$IOU_TGT" "$SCRATCH/iou-target"
        POST=$(post post_same "$IOU_TGT" ino "$IOU_ID") \
        run_case C59c "io_uring: rename a protected file through a ring" denied "deny=rename" 0 -- "$IOU_BIN" --rename "$IOU_TGT" "$IOU_TGT.nn-lab-c59c"
    fi
else
    skipped_case C59a,C59b,C59c "no io_uring probe with the tamper modes (see C22)" 0
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
# (lab PR 206) built, and C34's fresh agent binary started, only for a run
# that selects one of these cases
if ! selected_any C34,C35,C36,C37,C43; then
    :
elif [[ -f "$PBF_SRC" ]] && mkdir -p "$(dirname "$PBF_LIB")" && cc -shared -fPIC -O2 -o "$PBF_LIB" "$PBF_SRC" 2>"$TMPD/pbf-cc.log"; then
    if selected C34; then
        env LD_PRELOAD="$PBF_LIB" NNX_SLEEP=20 "$AGENT_BIN" >/dev/null 2>&1 &
        FRESH=$!
        sleep 1
        FRESH_START=$(proc_start "$FRESH")
        run_case C34 "ptrace attach: /proc/<pid>/mem of a fresh agent binary" denied "deny=ptrace" 0 -- nnpy procopen "$FRESH" northnarrow-age "${FRESH_START:-0}" mem 4194304
        # our own child, still unreaped; signalled only if it is still that process
        nnpy signal "$FRESH" northnarrow-age "${FRESH_START:-0}" TERM >/dev/null 2>&1; wait "$FRESH" 2>/dev/null
    fi
    run_case C35 "nn-admin, preloaded: write handle on PROTECTED_PIDS" "$BPF_EXPECT" "NN-L-BPF-002|deny=bpf_map" 0 -- env LD_PRELOAD="$PBF_LIB" "$NNADMIN" --version
    run_case C36 "a second agent binary, preloaded: write handle on PROTECTED_PIDS" "$BPF_EXPECT" "NN-L-BPF-002|deny=bpf_map" 0 -- env LD_PRELOAD="$PBF_LIB" "$AGENT_BIN" --version
    run_case C37 "a second watchdog binary, preloaded: handle on link_task_kill" "$BPF_EXPECT" "NN-L-BPF-002|deny=bpf_link" 0 -- env LD_PRELOAD="$PBF_LIB" NNX_TARGET="$PINS/link_task_kill" "$WATCHDOG_BIN" --version
    # External audit ATP-013: the twelve ring buffers and RING_DROPS left
    # the eBPF object before the guard listed the agent's maps; by id, a
    # foreign root process got a writable handle on each. Lab PR 215: the
    # deny hooks' fail-open counters (DENY_FAIL_OPEN) leave it the same way
    # and are asked for too: zeroing them would hide a fail-open.
    run_case C43 "a foreign root process: write handles on the agent's ring buffers, by id" "$BPF_EXPECT" "NN-L-BPF-002|deny=bpf_map" 0 -- env LD_PRELOAD="$PBF_LIB" NNX_RINGS=1 /bin/true
else
    skipped_case C34,C35,C36,C37,C43 "cannot build the probe library: $(head -1 "$TMPD/pbf-cc.log" 2>/dev/null)" 0
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
    # its own line (jentry: the watchdog unit's stdout, its pid, the message
    # at the start), not text anywhere in either unit's lines (lab PR 206)
    if [[ -n "$new" && "$new" != 0 && "$new" != "$old" ]] \
       && jentry northnarrow-watchdog "$new" INFO "watchdog: watchdog PID registered in PROTECTED_PIDS pid=$new " >/dev/null; then
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
LNK_BUILT=0
if ! selected_any C39,C40,C63,C64; then
    :
elif [[ -f "$LNK_SRC" ]] && mkdir -p "$(dirname "$LNK_BIN")" && cc -O2 -o "$LNK_BIN" "$LNK_SRC" 2>"$TMPD/lnk-cc.log"; then
    LNK_BUILT=1
else
    skipped_case C39,C40,C63,C64 "cannot build the link probe: $(head -1 "$TMPD/lnk-cc.log" 2>/dev/null)" 0
fi
if (( LNK_BUILT )) && selected_any C39,C40; then
    long="$PINS/"
    while (( ${#long} < 280 )); do long+="./"; done
    long+="link_task_kill"
    run_case C39 "link handle through a $(( ${#long} ))-byte path to link_task_kill" "$BPF_EXPECT" "NN-L-BPF-002|deny=bpf_link" 0 -- "$LNK_BIN" "$long"
    ln -sfn "$PINS/link_task_kill" "$TMPD/link-alias"
    run_case C40 "link detach/update through a symlink to link_task_kill" "$BPF_EXPECT" "NN-L-BPF-002|deny=bpf_link" 0 -- "$LNK_BIN" "$TMPD/link-alias"
    rm -f "$TMPD/link-alias"
fi
# Lab PR 215: the agent's links by id. The `bpf` hook's own copy of the
# command numbers had BPF_LINK_GET_FD_BY_ID = 31, which is
# BPF_LINK_GET_NEXT_ID in the uapi: a handle by id on one of the agent's
# links (`bpftool link show id N`, the first step of `bpftool link detach id
# N`) was granted and left no record, while the enumeration step `bpftool
# link list` takes before each entry (LINK_GET_NEXT_ID) was refused from one
# of the agent's link ids and recorded as an anti-tamper denial (COMBAT).
# C64: the enumeration from each of the agent's link ids, and a walk of
# every link id from 0, are let through and leave no record. C63: the
# handle by id is refused and recorded (observe mode: granted and recorded,
# NN-L-BPF-002). `bpftool link list` as a whole still takes a handle by id
# on each link it prints, so in enforce mode it stops at the first
# NorthNarrow link with a recorded denial, like `bpftool map show` (the
# documented trade-off); C64 checks the enumeration alone. The ids come from
# the agent's OWN_BPF_IDS map through read-only map handles (the probe's
# --own: the guard refuses write handles only), which the observer records
# as NN-L-BPF-002 before the cases; C64 runs first, after a pause, so no
# record of the setup or of C63 lands in its window.
if (( LNK_BUILT )) && selected_any C63,C64; then
    OWN_OUT=$("$LNK_BIN" --own 2>&1)
    if OWN_LINKS=$(own_link_ids "$OWN_OUT"); then
        sleep 5
        EV_FORBID="deny=bpf_link|NN-L-BPF-002" \
        run_case C64 "enumerate the links from each of the agent's link ids (LINK_GET_NEXT_ID, bpftool link list's step)" allowed "" 0 -- "$LNK_BIN" --next-from "${OWN_LINKS// /,}"
        run_case C63 "link handle by id on the agent's link ${OWN_LINKS%% *} (bpftool link show id)" "$BPF_EXPECT" "NN-L-BPF-002|deny=bpf_link" 0 -- bpftool link show id "${OWN_LINKS%% *}"
    else
        skipped_case C63,C64 "the agent's link ids could not be read: $(head -1 <<<"$OWN_OUT" | cut -c1-100)" 0
    fi
fi

# External audit EVD-001: the agent's private signing key — every evidence
# chain is signed with it — is closed to any reader outside the agent's
# family, root included; its public half is what verification reads.
run_case C41 "read the agent's private signing key" denied "deny=read" 0 -- nnpy file read "$ETC/agent.sig.key"
run_case C42 "verify the audit chain from the public half" allowed "" 0 -- \
    /usr/local/bin/nn-admin audit verify --from "$ETC/audit.log"

# External audit EBPF-008: the inode flags through the fsxattr interface —
# the file_ioctl deny filtered only FS_IOC_SETFLAGS (and held a wrong
# FS_IOC_FSSETXATTR number): root cleared `+i` on the state directory, the
# only thing keeping new entries out of it, or made audit.log append-only
# to the agent. ATP-008: the shipped `.v1` lists were mutation-denied only.
FSX_SRC="$(dirname "$0")/fsxattr-probe.c"
FSX_BIN=/usr/local/libexec/nn-lab/nn-fsxattr-probe
if ! selected_any C44,C45; then
    :
elif [[ -f "$FSX_SRC" ]] && mkdir -p "$(dirname "$FSX_BIN")" && cc -O2 -o "$FSX_BIN" "$FSX_SRC" 2>"$TMPD/fsx-cc.log"; then
    POST=$(post post_flag "$STATE" i present) \
    run_case C44 "fsxattr: clear the immutable flag of the state directory" denied "deny=ioctl" 0 -- "$FSX_BIN" "$STATE" -i
    POST=$(post post_flag "$ETC/audit.log" a absent) \
    run_case C45 "fsxattr: make audit.log append-only" denied "deny=ioctl" 0 -- "$FSX_BIN" "$ETC/audit.log" +a
else
    skipped_case C44,C45 "cannot build the fsxattr probe: $(head -1 "$TMPD/fsx-cc.log" 2>/dev/null)" 0
fi
POST=$(post post_same "$ETC/netflow-blocklist.v1" hash "$(nnpy fileid "$ETC/netflow-blocklist.v1" hash)") \
run_case C46 "append to the shipped netflow blocklist" denied "deny=write" 0 -- \
    bash -c "echo '# nn-lab C46' >> $ETC/netflow-blocklist.v1"

# External audit EBPF-015: no new entry in the agent's directories — a
# subdirectory, a symlink, a hard link, a FIFO, a file in the chain
# sub-directory, a directory among the pins — and no extended attribute
# changed on a protected inode (C19 is the plain file). Inside a
# trusted-installer window the same is allowed (C54).
PID=$(agent_pid)
LSRC=/etc/.nn-lab-c49-src
selected C49 && echo nn-lab > "$LSRC"
run_case C47 "mkdir in /etc/northnarrow" denied "deny=mkdir" 0 -- mkdir "$ETC/.nn-lab-c47"
run_case C48 "symlink in /etc/northnarrow" denied "deny=symlink" 0 -- ln -s /etc/hostname "$ETC/.nn-lab-c48"
run_case C49 "hard link into /etc/northnarrow" denied "deny=link" 0 -- ln "$LSRC" "$ETC/.nn-lab-c49"
run_case C50 "FIFO in /etc/northnarrow" denied "deny=mknod" 0 -- mkfifo "$ETC/.nn-lab-c50"
run_case C51 "new file in the state chain directory" denied "deny=create" 0 -- bash -c ": > $STATE/detections/.nn-lab-c51"
run_case C52 "a directory among the bpffs pins" denied "deny=mkdir" 0 -- mkdir "$PINS/nn-lab-c52"
run_case C53 "user.* xattr on admin.pub" denied "deny=xattr" 0 -- \
    python3 -c "import os; os.setxattr('$ETC/admin.pub', 'user.nn_lab', b'1')"
selected C49 && rm -f "$LSRC"
if [[ -z "$ONLY" || ",$ONLY," == *",C54,"* ]]; then
    t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
    grant_window 30; sleep 2
    out=$(bash -c "mkdir $ETC/.nn-lab-c54 && rmdir $ETC/.nn-lab-c54 && : > $ETC/.nn-lab-c54f \
        && rm -f $ETC/.nn-lab-c54f && python3 -c \"import os; os.setxattr('$ETC', 'user.nn_lab', b'1'); os.removexattr('$ETC', 'user.nn_lab')\"" 2>&1); rc=$?
    sleep 4; ev=$(evidence "$t0" "$a0" "$d0")
    if (( rc == 0 )) && ! echo "$ev" | grep -qE "deny=(create|mkdir|xattr|unlink|rmdir)"; then
        v="OK"; st="allowed"
    else
        v="DEVIATION (refused inside the window: $(echo "$out" | head -1 | cut -c1-80))"; fail=1; st="denied"
    fi
    rows+=("| C54 | new entries and an xattr inside a trusted-installer window | $st | $ev | $v |")
    echo "C54 new entries and an xattr inside a trusted-installer window → $st; $ev; $v" >&2
    for i in $(seq 1 40); do window_open || break; sleep 1; done
fi

# Lot 273: inside a trusted-installer window the units' cgroups are the
# operator's: a freeze and a thaw of the agent, a move out and back, then
# `systemctl kill -s SIGKILL` (cgroup.kill on systemd 257 and later) — all
# allowed, nothing refused; the watchdog brings the agent back, and the new
# boot says its predecessor died without agent_stop.
if [[ -z "$ONLY" || ",$ONLY," == *",C76,"* ]]; then
    if [[ ! -e $CGROOT/cgroup.controllers || -z "$AG_CG" ]]; then
        skipped_case C76 "no cgroup v2 hierarchy, or no ControlGroup for the agent" 0
    else
        PID=$(agent_pid); START=$(proc_start "$PID")
        MV=$CGROOT/nn-lab-c76
        t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
        grant_window 60; sleep 2
        CG_FROZEN=$CGROOT$AG_CG/cgroup.freeze
        out=$(bash -c "echo 1 > $CGROOT$AG_CG/cgroup.freeze && sleep 1 && echo 0 > $CGROOT$AG_CG/cgroup.freeze" 2>&1); rc1=$?
        CG_FROZEN=
        mkdir -p "$MV"
        out2=$(nnpy cgmove "$PID" northnarrow-age "$START" "$MV/cgroup.procs" 2>&1); rc2=$?
        moved=$(cg_of "$PID")
        nnpy cgmove "$PID" northnarrow-age "$START" "$CGROOT$AG_CG/cgroup.procs" >/dev/null 2>&1; rc3=$?
        back=$(cg_of "$PID")
        rmdir "$MV" 2>/dev/null
        out4=$(systemctl kill -s SIGKILL northnarrow-agent 2>&1); rc4=$?
        NEW=""
        for i in $(seq 1 60); do
            sleep 1
            NEW=$(agent_pid 0) && [[ "$NEW" != "$PID" ]] && break
            NEW=""
        done
        sleep 15; ev=$(evidence "$t0" "$a0" "$d0")
        # systemd up to 256 kills the unit's processes one by one and reports
        # the first that failed (the parse worker, gone with the agent:
        # "Invalid argument" on 255): the kill counts by its effect — the
        # agent replaced — unless it was refused
        k_ok=0
        (( rc4 == 0 )) && k_ok=1
        if (( rc4 != 0 )) && [[ -n "$NEW" ]] && ! grep -qE 'Access denied|Operation not permitted|Permission denied' <<<"$out4"; then k_ok=1; fi
        if (( rc1 == 0 && rc2 == 0 && rc3 == 0 && k_ok )) && [[ "$moved" == /nn-lab-c76 && "$back" == "$AG_CG" && -n "$NEW" ]] \
           && echo "$ev" | grep -q prev_run_abrupt && ! echo "$ev" | grep -qE "deny=cgroup_"; then
            v="OK"; st="allowed (agent $PID → $NEW$( (( rc4 )) && echo "; systemctl kill rc=$rc4: $(echo "$out4" | head -1 | cut -c1-50 | tr '|' '/')"))"
        else
            v="DEVIATION (inside the window: freeze rc=$rc1, move rc=$rc2 to ${moved:-?}, back rc=$rc3 ${back:-?}, kill rc=$rc4 $(echo "$out4" | head -1 | cut -c1-60), new agent ${NEW:-none})"; fail=1; st="denied or not done"
        fi
        rows+=("| C76 | freeze, move out and back, systemctl kill -s SIGKILL the agent inside a trusted-installer window | $st | $ev | $v |")
        echo "C76 freeze, move, systemctl kill inside a window → $st; $ev; $v" >&2
        PID=$(agent_pid)
        for i in $(seq 1 40); do window_open || break; sleep 1; done
    fi
fi

# Lot 273c (the review of #490): the agent killed (and restarted) inside a
# window with systemd's copy of its memory.high below the floor (a set-property inside
# the window): the fresh cgroup takes the copy, and is restored to the
# floor — by the watchdog's check of the respawned agent or by the agent's
# own registration at its start — and signed (`limit_floor_restored`; the
# watchdog's record says "the watchdog restored"). systemd's copy is put
# back inside the same window.
if [[ -z "$ONLY" || ",$ONLY," == *",C102,"* ]]; then
    if [[ ! -e $CGROOT/cgroup.controllers || -z "$AG_CG" || ! -e $CGROOT$AG_CG/memory.high ]]; then
        skipped_case C102 "no cgroup v2 hierarchy, no ControlGroup or no memory.high for the agent" 0
    else
        PID=$(agent_pid)
        MHP0=$(systemctl show -p MemoryHigh --value northnarrow-agent.service)
        CTL=/run/systemd/system.control/northnarrow-agent.service.d/50-MemoryHigh.conf
        CTL_WAS=$([[ -e $CTL ]] && echo present || echo absent)
        t0=$(date -u +"%Y-%m-%d %H:%M:%S"); a0=$(audit_count); d0=$(dets_count)
        grant_window 240; sleep 2
        out=$(timeout 60 systemctl set-property --runtime northnarrow-agent.service MemoryHigh=100M 2>&1); rc1=$?
        # RefuseManualStop=yes: no `systemctl restart`; a kill inside the
        # window, as C76 (the unit's Restart= and the watchdog bring it back)
        out2=$(systemctl kill -s SIGKILL northnarrow-agent 2>&1); rc2=$?
        NEW=""
        for i in $(seq 1 60); do
            NEW=$(agent_pid 0) && [[ "$NEW" != "$PID" ]] && break
            NEW=""; sleep 1
        done
        sleep 20; now=$(cat "$CGROOT$AG_CG/memory.high" 2>/dev/null)
        wd=$(journalctl -q --no-pager -u northnarrow-watchdog --since "$t0" 2>/dev/null | grep -c "a resource value below its floor")
        # systemd's copy back inside a window (the new agent starts with
        # none open: the grant above ended with its predecessor)
        grant_window 60; sleep 2
        timeout 60 systemctl set-property --runtime northnarrow-agent.service MemoryHigh="$MHP0" >/dev/null 2>&1
        [[ $CTL_WAS == absent ]] && rm -f "$CTL"
        systemctl daemon-reload
        for i in $(seq 1 260); do window_open || break; sleep 1; done
        sleep 35; ev=$(evidence "$t0" "$a0" "$d0")
        # systemd up to 256 reports the first process its kill missed (C76)
        if (( rc2 != 0 )) && [[ -n "$NEW" ]] && ! grep -qE 'Access denied|Operation not permitted|Permission denied' <<<"$out2"; then rc2=0; fi
        if (( rc1 == 0 && rc2 == 0 )) && [[ -n "$NEW" && "$now" == 536870912 ]] && echo "$ev" | grep -q "integrity_drift"; then
            v=OK; st="restored to the floor in the fresh cgroup (agent $PID → $NEW; the watchdog's restorations: $wd)"
        else
            v="DEVIATION (set-property rc=$rc1, kill rc=$rc2 $(echo "$out2" | head -1 | cut -c1-50 | tr '|' '/'), new agent ${NEW:-none}, memory.high ${now:-?}, expected the floor 536870912)"; fail=1; st="left"
        fi
        rows+=("| C102 | the agent restarted inside a window, systemd's memory.high below the floor | $st | $ev | $v |")
        echo "C102 a restart with a copy below the floor → $st; $ev; $v" >&2
        PID=$(agent_pid)
        restored C102 "systemd's MemoryHigh of the agent" "$MHP0" "$(systemctl show -p MemoryHigh --value northnarrow-agent.service)"
        restored C102 "the runtime drop-in" "$CTL_WAS" "$([[ -e $CTL ]] && echo present || echo absent)"
    fi
fi

report_unreported
print_table
echo "agent pid now $(agent_pid) (was $PID); units: $(systemctl is-active northnarrow-agent northnarrow-watchdog | tr '\n' ' ')"
(( fail == 0 )) && echo "anti-tamper check: OK (known gaps listed)" || echo "anti-tamper check: DEVIATIONS"
exit $fail
