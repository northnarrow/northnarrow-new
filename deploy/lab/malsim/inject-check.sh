#!/usr/bin/env bash
# Lot 281 — an exemption is revoked when code is injected into the exempt
# process, end to end on a lab guest (`nn-lab.sh inject-check`; run by the
# lab user, sudo inside, the lab key with config-manage). Benign: the
# ransomware simulator of lab PR 225 (files under /srv/nn-malsim only).
#
# The signed test policy: `enforce NN-L-IMP-001` and `exempt NN-L-IMP-001
# unit nn-lab-exempt.service`. The service (inject-svc.py) is started by
# systemd in the unit and waits on a FIFO; on a line it execs MS-23 (the
# simulator) — its own action, as the unit's main process.
#  0) the tracker is attached and armed (the boot's journal lines);
#  1) a read-only peek — /proc/<pid>/mem opened read-only and read, and
#     process_vm_readv — at the waiting service: no taint; then its action
#     is exempt (recorded, not killed, runs to its end);
#  2) a debugger's attach (root: gdb -p … -batch, or ptrace by python when
#     gdb is absent) at a fresh instance: its mark tainted (by the
#     debugger), the injection a signed NN-L-AT-001 exempt_injection naming
#     the exemption (High or Critical by the debugger's lineage); then its
#     action is NOT exempt: killed, the record saying why the exemption did
#     not hold;
#  3) the maps refuse a write, root's, inside a trusted-installer window
#     too (frozen; #494's N2).
# Then the policy files are removed (in a window), the unit stopped.
set -u
PATH=$PATH:/usr/sbin:/sbin
DET=/var/lib/northnarrow/detections/detections.jsonl
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
HERE=$(cd "$(dirname "$0")" && pwd)
SIM="$HERE/ransom-sim.py"
SVC="$HERE/inject-svc.py"
MARKS="$HERE/cgroup-marks.py"
UNIT=nn-lab-exempt.service
FIFO=/run/nn281-go
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
    print(r.get("rule_id"),"response",repr(r.get("response")),"signed",bool(r.get("agent_sig")),"matches",[(m["rule_id"].split("_")[0],m["mode"],m.get("exempt")) for m in ms],"revoked",[m.get("revoked") for m in ms if m.get("revoked")])
'; }
injections() { python3 -I -c '
import json,sys
for l in sys.stdin:
    try: r=json.loads(l)
    except Exception: continue
    if r.get("operation") != "exempt_injection": continue
    p=r.get("principal") or {}
    print(r.get("rule_id"),r.get("severity"),"| by",p.get("comm"),p.get("pid"),"uid",p.get("uid"),"|",r.get("response"),"| signed",bool(r.get("agent_sig")),"|",(r.get("reasoning") or "")[:220])
'; }
prepare() {
    sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1; sleep 1
    sudo python3 -I "$SIM" clean; sudo python3 -I "$SIM" prepare --files 300 >/dev/null
}
locked() { sudo find /srv/nn-malsim/data -name '*.locked' | wc -l; }
start_svc() {
    sudo systemctl stop "$UNIT" 2>/dev/null
    sudo rm -f "$FIFO"; sudo mkfifo -m 600 "$FIFO"
    sudo systemd-run --quiet --collect --unit="$UNIT" -- python3 -I "$SVC" "$FIFO" "$SIM"
    for _ in $(seq 1 50); do
        mp=$(systemctl show -p MainPID --value "$UNIT"); [[ -n $mp && $mp != 0 ]] && break; sleep 0.1
    done
    sleep 1
}
go_and_wait() {
    echo go | sudo tee "$FIFO" >/dev/null
    for _ in $(seq 1 90); do systemctl is-active --quiet "$UNIT" || break; sleep 1; done
    sleep 3
}
echo "nn-admin: $NNADMIN  key: $KEY  kernel: $(uname -r)  systemd: $(systemctl --version | head -1)  gdb: $(command -v gdb || echo none)"

echo "== 0. the tracker"
j=$(sudo journalctl --namespace=northnarrow -u northnarrow-agent -b --no-pager -o short-monotonic 2>/dev/null)
t=$(grep -E "start-in-cgroup tracker is attached" <<<"$j" | tail -1 | cut -c1-200)
a=$(grep -E "the tracker is armed" <<<"$j" | tail -1 | cut -c1-300)
echo "    $t"; echo "    $a"
[[ -n $t ]] && pass "the start-in-cgroup tracker is attached" || bad "tracker: not attached"
[[ -n $a ]] && pass "the tracker is armed" || bad "tracker: not armed"

echo "== 1. the signed test policy"
printf '# lot 281 test policy\nenforce NN-L-IMP-001\nexempt NN-L-IMP-001 unit %s\n' "$UNIT" > /tmp/rp281.local
sudo "$NNADMIN" policy set --file /tmp/rp281.local --key "$KEY" | sed 's/^/    /'

echo "== 2. a read-only peek, then the service's action"
prepare; start_svc; b=$(lines "$DET")
mp=$(systemctl show -p MainPID --value "$UNIT")
sudo python3 -I - "$mp" <<'PY'
import ctypes, os, sys
pid = sys.argv[1]
start = int(open("/proc/%s/maps" % pid).readline().split("-")[0], 16)
fd = os.open("/proc/%s/mem" % pid, os.O_RDONLY)
data = os.pread(fd, 16, start)
os.close(fd)
libc = ctypes.CDLL(None, use_errno=True)
class iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
buf = ctypes.create_string_buffer(16)
local = iovec(ctypes.cast(buf, ctypes.c_void_p), 16)
remote = iovec(start, 16)
libc.syscall.restype = ctypes.c_long
L = ctypes.c_long
n = libc.syscall(L(310), L(int(pid)), ctypes.byref(local), L(1), ctypes.byref(remote), L(1), L(0))
print("    peeked: /proc/%s/mem %d bytes, process_vm_readv %d bytes" % (pid, len(data), n))
PY
m=$(sudo python3 -I "$MARKS" mark "$mp"); echo "    mark: $m"
[[ $m == "$mp -" ]] && pass "peek: no taint ($m)" || bad "peek: [$m]"
go_and_wait; n=$(locked); rec=$(since "$DET" "$b" | imp); inj=$(since "$DET" "$b" | injections)
echo "    locked=$n"; echo "$rec" | sed 's/^/    /'
if [[ $n -eq 300 ]] && grep -q "'exempt', 'unit $UNIT'" <<<"$rec"; then
    pass "peek: the action still exempt (recorded, ran to its end)"
else bad "peek: locked=$n rec=[$rec]"; fi
[[ -z $inj ]] && pass "peek: no injection record" || bad "peek: [$inj]"

echo "== 3. a debugger's attach, then the service's action"
prepare; start_svc; b=$(lines "$DET")
mp=$(systemctl show -p MainPID --value "$UNIT")
if command -v gdb >/dev/null; then
    sudo gdb -q -p "$mp" -batch -ex 'info registers rip' -ex detach > /tmp/nn281-gdb.log 2>&1; echo "    gdb rc=$? $(grep -m1 -E '^rip' /tmp/nn281-gdb.log)"
else
    sudo python3 -I - "$mp" <<'PY'
import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
pid = int(sys.argv[1])
if libc.ptrace(16, pid, None, None) != 0:
    raise SystemExit("PTRACE_ATTACH: errno %d" % ctypes.get_errno())
os.waitpid(pid, 0)
libc.ptrace(17, pid, None, None)
print("    attached and detached by python pid", os.getpid())
PY
fi
sleep 2
m=$(sudo python3 -I "$MARKS" mark "$mp"); echo "    mark: $m"
grep -qE "^$mp injected [0-9]+" <<<"$m" && pass "attach: the service's mark tainted ($m)" || bad "attach: [$m]"
go_and_wait; n=$(locked); rec=$(since "$DET" "$b" | imp); inj=$(since "$DET" "$b" | injections)
echo "    locked=$n"; echo "$rec" | sed 's/^/    /'; echo "$inj" | sed 's/^/    injection: /'
grep -q "NN-L-AT-001" <<<"$inj" && grep -q "unit $UNIT" <<<"$inj" && grep -q "signed True" <<<"$inj" \
    && pass "attach: a signed NN-L-AT-001 exempt_injection naming the exemption ($(grep -oE 'AT-001_AntiTamperDenial [A-Za-z]+' <<<"$inj" | head -1))" \
    || bad "attach: injection record [$inj]"
if grep -q "KillProcessTree" <<<"$rec" && ! grep -q "'exempt', 'unit" <<<"$rec" && grep -q "signed True" <<<"$rec" \
    && grep -q "unit $UNIT: code-injection access to it was given to pid" <<<"$rec" && [[ $n -lt 300 ]]; then
    pass "attach: the action NOT exempt — judged and killed ($n of 300 files locked), the signed record names the exemption revoked"
else bad "attach: locked=$n rec=[$rec]"; fi

echo "== 4. the tracker's maps refuse a write, root's, in a window too (frozen)"
sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 60 >/dev/null 2>&1
d=$(sudo python3 -I "$MARKS" dir)
w=$(sudo python3 -I - "$d" <<'PY'
import ctypes, struct, sys
libc = ctypes.CDLL(None, use_errno=True); libc.syscall.restype = ctypes.c_long
out = []
for name, key, size in (("CGROUP_JOINED", struct.pack("<I", 0xFFFFFFFE), 16), ("CGROUP_JOIN_EPOCH", struct.pack("<I", 0), 8), ("CGROUP_JOIN_LOST", struct.pack("<I", 0), 64), ("CGROUP_JOIN_STATS", struct.pack("<I", 0), 8)):
    path = ctypes.create_string_buffer((sys.argv[1] + "/" + name).encode())
    attr = (ctypes.c_uint8 * 128)()
    struct.pack_into("<QII", attr, 0, ctypes.addressof(path), 0, 0)
    fd = libc.syscall(321, 7, ctypes.byref(attr), ctypes.c_uint(128))
    if fd < 0:
        out.append("%s handle errno %d" % (name, ctypes.get_errno())); continue
    k = ctypes.create_string_buffer(key, len(key)); v = ctypes.create_string_buffer(size)
    attr = (ctypes.c_uint8 * 128)()
    struct.pack_into("<IIQQQ", attr, 0, fd, 0, ctypes.addressof(k), ctypes.addressof(v), 0)
    r = libc.syscall(321, 2, ctypes.byref(attr), ctypes.c_uint(128))
    out.append("%s write %s" % (name, "ok" if r == 0 else "errno %d" % ctypes.get_errno()))
print("; ".join(out))
PY
)
echo "    $w"
if ! grep -q "write ok" <<<"$w" && [[ $(grep -oE "write errno 1|handle errno 1" <<<"$w" | wc -l) -eq 4 ]]; then
    pass "frozen: no write through a handle on the tracker's maps ($w)"
else bad "frozen: [$w]"; fi

echo "== put back"
sudo systemctl stop "$UNIT" 2>/dev/null; sudo rm -f "$FIFO"
sudo python3 -I "$SIM" clean
printf '# no directive: the built-in defaults\n' > /tmp/rp281-empty.local
sudo "$NNADMIN" policy set --file /tmp/rp281-empty.local --key "$KEY" >/dev/null
sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1
sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 120 >/dev/null 2>&1 \
    && sudo rm -f /etc/northnarrow/rule-policy.local /etc/northnarrow/rule-policy.local.sig
rm -f /tmp/rp281.local /tmp/rp281-empty.local; sudo rm -f /tmp/nn281-gdb.log
echo "inject check: $( ((fail)) && echo FAIL || echo PASS)"
exit $fail
