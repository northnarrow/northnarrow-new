#!/usr/bin/env bash
# Structured adversarial check of the anti-tamper (Tappa 10.8).
#
# Runs ON THE GUEST as root against the installed agent (25 cases), one case per
# documented way of neutralising a Linux EDR, and answers two questions for
# each: was the action denied, and did it leave EVIDENCE in the signed chain
# logs (audit.log ops, detections.jsonl rule ids) or at least in the journal?
# Every case states its expectation; a deviation fails the run, a KNOWN GAP
# is printed as such (feeds Tappa 10.9) and does not fail it.
#
# Output: a markdown table on stdout; exit 1 on any deviation.
# usage: sudo anti-tamper.sh [--only C03,C08]
set -u
ETC=/etc/northnarrow
STATE=/var/lib/northnarrow
PINS=/sys/fs/bpf/northnarrow
AUDIT=$ETC/audit.log
DETS=$STATE/detections/detections.jsonl
ONLY=
[[ "${1:-}" == "--only" ]] && ONLY=$2

fail=0
rows=()

agent_pid() { cat /run/northnarrow/agent.pid 2>/dev/null; }
# Review 26: the layout the agent was installed with (install.sh puts the
# binaries in /usr/local/bin and the units in /etc/systemd/system; a
# package uses /usr/bin and /usr/lib/systemd/system).
# (from the unit's ExecStart: /proc/<agent>/exe is ptrace-protected, C04b)
AGENT_EXE=$(systemctl show -p ExecStart --value northnarrow-agent 2>/dev/null | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)
NNADMIN=$(dirname "${AGENT_EXE:-/usr/local/bin/northnarrow-agent}")/nn-admin
UNIT=$(systemctl show -p FragmentPath --value northnarrow-agent 2>/dev/null)
UNIT=${UNIT:-/etc/systemd/system/northnarrow-agent.service}
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
run_case() {
    local id=$1 title=$2 exp_out=$3 exp_ev=$4 gap=$5; shift 5; [[ "$1" == "--" ]] && shift
    if [[ -n "$ONLY" && ",$ONLY," != *",$id,"* ]]; then return; fi
    local t0 a0 d0 out rc ev status
    t0=$(date -u +"%Y-%m-%d %H:%M:%S")
    a0=$(audit_count); d0=$(dets_count)
    sleep 1
    out=$("$@" 2>&1); rc=$?
    sleep "${WAIT:-4}"
    # outcome from the error, not the exit code: bpftool exits non-zero
    # after printing an object it was allowed to open
    if echo "$out" | grep -qE "Operation not permitted|Permission denied"; then status=denied; else status=allowed; fi
    ev=$(evidence "$t0" "$a0" "$d0")
    local verdict="OK"
    if [[ "$status" != "$exp_out" ]]; then verdict="DEVIATION (expected $exp_out)"; fail=1; fi
    if [[ -n "$exp_ev" ]] && ! echo "$ev" | grep -qE "$exp_ev"; then
        if (( gap )); then verdict="KNOWN GAP"; else verdict="DEVIATION (evidence /$exp_ev/ missing)"; fail=1; fi
    fi
    rows+=("| $id | $title | $status | $ev | $verdict |")
    echo "$id $title → $status; $ev; $verdict" >&2
    [[ -n "$out" ]] && echo "    $(echo "$out" | head -2 | tr '\n' ' ' | cut -c1-160)" >&2
}

PID=$(agent_pid)
[[ -n "$PID" ]] || { echo "agent not running (no pid file)"; exit 2; }
# BPF guard mode of the running agent (lab builds observe unless forced)
BPF_MODE=$(jlines "-2h" | grep -o 'own objects registered.*mode="[a-z]*"' | tail -1 | grep -o 'mode="[a-z]*"' | cut -d'"' -f2)
BPF_MODE=${BPF_MODE:-enforce}
if [[ "$BPF_MODE" == enforce ]]; then BPF_EXPECT=denied; else BPF_EXPECT=allowed; fi
echo "agent pid $PID, kernel $(uname -r), bpf guard mode $BPF_MODE, $(date -u +%FT%TZ)" >&2

# ── signals and ptrace ────────────────────────────────────────────────────
run_case C01 "kill -9 the agent from a root shell" denied "op=signal" 0 -- kill -9 "$PID"
run_case C02 "kill -9 the watchdog from a root shell" denied "op=signal" 0 -- bash -c 'kill -9 $(systemctl show -p MainPID --value northnarrow-watchdog)'
run_case C03 "ptrace attach: read /proc/<agent>/mem" denied "op=ptrace" 0 -- bash -c "dd if=/proc/$PID/mem bs=1 count=1 skip=4194304 of=/dev/null"
run_case C04b "ptrace read-mode: /proc/<agent>/environ (silent by design)" denied "" 0 -- bash -c "cat /proc/$PID/environ >/dev/null"
# ── protected files and pins ──────────────────────────────────────────────
run_case C04 "append to /etc/northnarrow/admin.pub" denied "op=write" 0 -- bash -c "echo x >> $ETC/admin.pub"
run_case C05 "chattr -i on the state dir" denied "op=ioctl" 0 -- chattr -i "$STATE"
run_case C06 "unlink the agent unit (systemctl mask)" denied "op=unlink" 0 -- bash -c "rm -f $UNIT"
run_case C07 "rm -rf the bpffs pin root" denied "op=unlink" 0 -- bash -c "rm -rf $PINS"
run_case C08 "bpftool map update on PROTECTED_PIDS (pinned)" "$BPF_EXPECT" "NN-L-BPF-002|op=bpf_map" 0 -- bpftool map update pinned "$PINS/PROTECTED_PIDS" key 1 0 0 0 value 1
run_case C09 "bpftool link show pinned (link handle)" "$BPF_EXPECT" "NN-L-BPF-002|op=bpf_link" 0 -- bpftool link show pinned "$PINS/link_task_kill"
# ── BPF ecosystem ─────────────────────────────────────────────────────────
run_case C10 "bpftool feature probe (loads test programs)" allowed "NN-L-BPF-001" 0 -- bash -c "bpftool feature probe kernel >/dev/null"
# ── systemd ───────────────────────────────────────────────────────────────
WAIT=40 run_case C11 "unit drop-in with a hostile Environment=" allowed "integrity_drift" 0 -- bash -c "mkdir -p /etc/systemd/system/northnarrow-agent.service.d && printf '[Service]\nEnvironment=NN_ANTI_TAMPER_ALLOW_DEGRADED=1\n' > /etc/systemd/system/northnarrow-agent.service.d/zz-tamper.conf"
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
mkdir -p /mnt/nn-bpf2 /tmp/nn-fake-etc
WAIT=40 run_case C13 "second bpffs mount" allowed "integrity_drift" 0 -- mount -t bpf bpf /mnt/nn-bpf2
umount /mnt/nn-bpf2 2>/dev/null || true
# mounted, held for one check, unmounted BEFORE the evidence is read: while
# it is mounted the host's /etc/northnarrow/audit.log is the fake one
run_case C14 "bind mount over /etc/northnarrow for 40 s" allowed "integrity_drift" 0 -- bash -c "mount --bind /tmp/nn-fake-etc $ETC && sleep 40; umount $ETC"
# Review 53: hiding the kernel BTF keeps every LSM hook from attaching at
# the agent's next start (which now refuses to start); the mount itself is
# reported while the agent runs.
run_case C26 "tmpfs over /sys/kernel/btf for 40 s" allowed "integrity_drift" 0 -- bash -c "mount -t tmpfs tmpfs /sys/kernel/btf && sleep 40; umount /sys/kernel/btf"
# ── cgroup freezer ────────────────────────────────────────────────────────
CG=/sys/fs/cgroup/system.slice/northnarrow-agent.service/cgroup.freeze
if [[ -w "$CG" ]]; then
    WAIT=40 run_case C15 "cgroup v2 freeze of the agent for 45 s" allowed "integrity_drift|agent_boot" 0 -- bash -c "echo 1 > $CG && sleep 45 && echo 0 > $CG"
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
WAIT=40 run_case C19 "drop a .local overlay in /etc/northnarrow" allowed "integrity_drift" 0 -- bash -c "echo '+evil-implant' > $OVL"
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
WAIT=12 run_case C21 "exec flood (20k) hiding an exec from /tmp" allowed "R001_ExecFromTmp|R009_RootExecFromUserPath|ringbuf_drop" 0 -- bash -c 'cp /bin/true /tmp/nn-sat-$$ && { for i in $(seq 1 20000); do /bin/true; done & sleep 2; /tmp/nn-sat-$$; wait; rm -f /tmp/nn-sat-$$; }'
# open + read + connect through an io_uring ring: no openat/connect syscall
# from userland (the openat tracepoint is blind to it by construction).
IOU_SRC="$(dirname "$0")/iouring-probe.c"
IOU_BIN=/usr/local/libexec/nn-lab/nn-iou-probe
if [[ $(cat /proc/sys/kernel/io_uring_disabled 2>/dev/null || echo 0) == 2 ]]; then
    # RHEL 9 ships kernel.io_uring_disabled=2: no ring, not even for root.
    echo "C22 skipped: io_uring disabled on this host (kernel.io_uring_disabled=2)" >&2
elif [[ -f "$IOU_SRC" ]] && mkdir -p "$(dirname "$IOU_BIN")" && cc -O2 -o "$IOU_BIN" "$IOU_SRC" 2>/tmp/nn-iou-cc.log; then
    WAIT=8 run_case C22 "io_uring: openat + read + connect through a ring" allowed "NN-L-IOU-00[12]" 0 -- "$IOU_BIN" /etc/hostname 127.0.0.1 9
else
    echo "C22 skipped: cannot build the io_uring probe ($(head -1 /tmp/nn-iou-cc.log 2>/dev/null))" >&2
fi
# ── signed overlays (Tappa 10.8) ──────────────────────────────────────────
# An unsigned exemption appended to the allowlist overlay, then a restart:
# the agent must boot on the shipped defaults and record the refusal.
WAIT=20 run_case C23 "unsigned allowlist overlay + agent restart" allowed "unauthorized_overlay" 0 -- bash -c "echo '+evil-implant' >> $ETC/process-comm-allowlist.local && systemctl restart northnarrow-agent"
PID=$(agent_pid)
# The same overlay stored the authorised way (lab key, config-manage),
# then a restart: stored with its signature, accepted at boot.
printf '+backupd\n' > /tmp/nn-ovl-allow
WAIT=20 run_case C24 "nn-admin config overlay set + agent restart" allowed "config_overlay_set.*overlay_accepted|overlay_accepted.*config_overlay_set" 0 -- bash -c "$NNADMIN config overlay set process-comm-allowlist --file /tmp/nn-ovl-allow --key $ETC/admin.key && systemctl restart northnarrow-agent"
PID=$(agent_pid)
# Review 62: after a restart the task deny hooks must still report. They
# were reused from the pinned link, bound to the previous boot's ring, so
# C01-C03 passed on a fresh install and the same attempts left no
# evidence once the agent had restarted (C23/C24 just did).
run_case C28 "kill -9 the agent after an agent restart" denied "op=signal" 0 -- kill -9 "$PID"
run_case C29 "ptrace attach after an agent restart" denied "op=ptrace" 0 -- bash -c "dd if=/proc/$PID/mem bs=1 count=1 skip=4194304 of=/dev/null"
# Review 63: the pinned PROTECTED_INODES map outlives the agent. Each boot
# protects new inodes (the pins of the hooks reattached fresh), and the
# earlier boots' keys piled up until an insert failed at 1024 entries and
# the agent refused to start. One more restart must not grow it.
if [[ -z "$ONLY" || ",$ONLY," == *",C30,"* ]]; then
    pi_count() { bpftool -j map dump pinned /sys/fs/bpf/northnarrow/PROTECTED_INODES 2>/dev/null | grep -o '"key":' | wc -l; }
    n1=$(pi_count); systemctl restart northnarrow-agent; sleep 20; n2=$(pi_count); PID=$(agent_pid)
    if (( n2 > n1 )); then v="DEVIATION (grew by $(( n2 - n1 )))"; fail=1; else v="OK"; fi
    rows+=("| C30 | PROTECTED_INODES across an agent restart | $n1 → $n2 entries | — | $v |")
    echo "C30 PROTECTED_INODES across an agent restart → $n1 → $n2 entries; $v" >&2
fi
# Kernel lockdown (integrity or confidentiality) is the host setting that
# closes kexec and unsigned modules; without it they are known gaps, with it
# a missing refusal is a deviation. The agent itself runs unchanged under
# lockdown=integrity (verified on Ubuntu 22.04 / 5.15).
LOCKDOWN=$(grep -o '\[[a-z]*\]' /sys/kernel/security/lockdown 2>/dev/null | tr -d '[]')
KGAP=1
[[ "$LOCKDOWN" == integrity || "$LOCKDOWN" == confidentiality ]] && KGAP=0
# The initrd is /boot/initrd.img-<ver> on Debian/Ubuntu, /boot/initramfs-<ver>.img
# on RHEL: a missing one made kexec fail before the load, read as "allowed".
KINITRD=/boot/initrd.img-$(uname -r)
[[ -f $KINITRD ]] || KINITRD=/boot/initramfs-$(uname -r).img
if command -v kexec >/dev/null 2>&1; then
    run_case C17 "kexec -l of the running kernel (lockdown: ${LOCKDOWN:-none})" denied "" "$KGAP" -- kexec -l /boot/vmlinuz-$(uname -r) --initrd="$KINITRD" --reuse-cmdline
    kexec -u 2>/dev/null || true
fi
# An unsigned module (dummy.ko with its signature stripped), loaded with a
# bare finit_module() so the refusal is the kernel's, not R011 killing a
# module tool. Only under lockdown: without it the load would succeed and
# taint the kernel. Livepatches are modules too and take the same check.
ko=$(modinfo -n dummy 2>/dev/null)
case "$ko" in
    *.ko)     cp "$ko" /tmp/nn_signed_dummy.ko 2>/dev/null ;;
    *.ko.zst) zstd -qdc "$ko" > /tmp/nn_signed_dummy.ko 2>/dev/null ;;
    *.ko.xz)  xz -dc "$ko" > /tmp/nn_signed_dummy.ko 2>/dev/null ;;
    *)        rm -f /tmp/nn_signed_dummy.ko ;;
esac
if (( ! KGAP )) && [[ -s /tmp/nn_signed_dummy.ko ]]; then
    python3 - /tmp/nn_signed_dummy.ko /tmp/nn_unsigned_dummy.ko <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
magic = b"~Module signature appended~\n"
if data.endswith(magic):
    sig_len = int.from_bytes(data[-len(magic) - 4:-len(magic)], "big")
    data = data[:-len(magic) - 12 - sig_len]
open(sys.argv[2], "wb").write(data)
PY
    rmmod dummy 2>/dev/null
    run_case C27 "load an unsigned module (finit_module, lockdown: $LOCKDOWN)" denied "" 0 -- python3 -c '
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
fd = os.open("/tmp/nn_unsigned_dummy.ko", os.O_RDONLY)
if libc.syscall(313, fd, b"", 0) != 0:
    print(os.strerror(ctypes.get_errno()))
else:
    print("loaded")
'
    rmmod dummy 2>/dev/null
fi
rm -f /tmp/nn_signed_dummy.ko /tmp/nn_unsigned_dummy.ko

echo
echo "| case | action | outcome | evidence | verdict |"
echo "|---|---|---|---|---|"
printf '%s\n' "${rows[@]}"
echo
echo "agent pid now $(agent_pid) (was $PID); units: $(systemctl is-active northnarrow-agent northnarrow-watchdog | tr '\n' ' ')"
(( fail == 0 )) && echo "anti-tamper check: OK (known gaps listed)" || echo "anti-tamper check: DEVIATIONS"
exit $fail
