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
run_case C06 "unlink the agent unit (systemctl mask)" denied "op=unlink" 0 -- bash -c "rm -f /etc/systemd/system/northnarrow-agent.service"
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
systemctl daemon-reload
# ── mounts ────────────────────────────────────────────────────────────────
mkdir -p /mnt/nn-bpf2 /tmp/nn-fake-etc
WAIT=40 run_case C13 "second bpffs mount" allowed "integrity_drift" 0 -- mount -t bpf bpf /mnt/nn-bpf2
umount /mnt/nn-bpf2 2>/dev/null || true
# mounted, held for one check, unmounted BEFORE the evidence is read: while
# it is mounted the host's /etc/northnarrow/audit.log is the fake one
run_case C14 "bind mount over /etc/northnarrow for 40 s" allowed "integrity_drift" 0 -- bash -c "mount --bind /tmp/nn-fake-etc $ETC && sleep 40; umount $ETC"
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
if [[ -f "$IOU_SRC" ]] && mkdir -p "$(dirname "$IOU_BIN")" && cc -O2 -o "$IOU_BIN" "$IOU_SRC" 2>/tmp/nn-iou-cc.log; then
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
WAIT=20 run_case C24 "nn-admin config overlay set + agent restart" allowed "config_overlay_set.*overlay_accepted|overlay_accepted.*config_overlay_set" 0 -- bash -c "nn-admin config overlay set process-comm-allowlist --file /tmp/nn-ovl-allow --key $ETC/admin.key && systemctl restart northnarrow-agent"
PID=$(agent_pid)
if command -v kexec >/dev/null 2>&1; then
    run_case C17 "kexec -l of the running kernel" denied "" 1 -- kexec -l /boot/vmlinuz-$(uname -r) --initrd=/boot/initrd.img-$(uname -r) --reuse-cmdline
    kexec -u 2>/dev/null || true
fi

echo
echo "| case | action | outcome | evidence | verdict |"
echo "|---|---|---|---|---|"
printf '%s\n' "${rows[@]}"
echo
echo "agent pid now $(agent_pid) (was $PID); units: $(systemctl is-active northnarrow-agent northnarrow-watchdog | tr '\n' ' ')"
(( fail == 0 )) && echo "anti-tamper check: OK (known gaps listed)" || echo "anti-tamper check: DEVIATIONS"
exit $fail
