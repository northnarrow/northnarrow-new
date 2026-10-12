#!/bin/bash
# Tappa 10.9 step 1 — the file-open sensor on LSM file_open, end to end on a
# lab guest (`nn-lab.sh open-sensor-check`). Run as the lab user with sudo,
# with the agent installed and running in its default (LSM) mode.
set -u
DET=/var/lib/northnarrow/detections/detections.jsonl
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
IOU_BIN=/usr/local/libexec/nn-lab/nn-iou-probe
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
# The current run of the agent only (a `--since` from ActiveEnterTimestamp
# is not parsed by every journalctl).
INV=$(systemctl show -p InvocationID --value northnarrow-agent)
# The agent logs every spawn with its argv, so the check's own greps show
# up in the journal: their lines are dropped.
journal() {
    if [[ $1 == run ]]; then
        sudo journalctl --namespace=northnarrow --no-pager "_SYSTEMD_INVOCATION_ID=$INV"
    else
        sudo journalctl --namespace=northnarrow -u northnarrow-agent --no-pager --since "$1"
    fi | grep -v "process spawn detected"
}
det_count() { sudo cat "$DET" 2>/dev/null | wc -l; }
new_dets() { sudo tail -n "$(( $(det_count) - $1 ))" "$DET" 2>/dev/null; }

# 1. armed, the old tracepoint gone, and the BPF self-check quiet about it
armed=$(journal run | grep -m1 "file-open sensor armed")
if [[ $armed == *"sys_enter_openat_detached=true"* ]]; then
    pass "sensor armed on LSM file_open, sys_enter_openat detached ($(grep -oE 'inode_rules=[0-9]+ child_rules=[0-9]+ name_rules=[0-9]+ runtime_dirs=[0-9]+' <<<"$armed"))"
else
    bad "sensor not armed: ${armed:-no 'file-open sensor armed' line in this run}"
fi
if journal run | grep -q "own BPF links is GONE"; then
    bad "the BPF self-check reports a missing link since the agent started"
else
    pass "no missing-link report (the detached tracepoint was retired)"
fi

# 2. review 54: a credential store in a user's home, read by another
# process. Reported (High) but not acted on (design Q8): the cat survives.
# The fixture is written by a process the check does not need afterwards.
U=$(id -un); H=$(getent passwd "$U" | cut -d: -f6)
sudo install -d -o "$U" "$H/.aws" && printf '[default]\naws_access_key_id = NNOPENSENSOR\n' | sudo tee "$H/.aws/credentials" >/dev/null
# Detection records name the reader, the journal's VERDICT line the file.
fim011() { # $1 = detection count before, $2 = reader comm
    new_dets "$1" | grep '"NN-L-FIM-011_AwsCredsRead"' | grep "\"comm\":\"$2\"" | grep -c '"Log"'
}
mark=$(date '+%Y-%m-%d %H:%M:%S'); sleep 1
b=$(det_count); sudo cat "$H/.aws/credentials" >/dev/null 2>&1; rc=$?; sleep 3
v=$(journal "$mark" | grep "VERDICT (rule) rule=NN-L-FIM-011_AwsCredsRead" | grep -c "action=Log .*target_filename=$H/.aws/credentials")
if [[ $(fim011 "$b" cat) -ge 1 && $v -ge 1 && $rc -eq 0 ]]; then
    pass "NN-L-FIM-011 (Log, High) for $H/.aws/credentials read by root's cat — a file outside the FIM watch list; the reader was not killed"
else
    bad "NN-L-FIM-011 for $H/.aws/credentials: records=$(fim011 "$b" cat) journal=$v cat rc=$rc"
fi
# ... and through an io_uring ring (no openat syscall at all)
if [[ -x $IOU_BIN ]] || { sudo mkdir -p "$(dirname "$IOU_BIN")" && sudo cc -O2 -o "$IOU_BIN" "$(dirname "$0")/../adversarial/iouring-probe.c" 2>/dev/null; }; then
    b=$(det_count); sudo "$IOU_BIN" "$H/.aws/credentials" 127.0.0.1 9 >/dev/null 2>&1; sleep 3
    [[ $(fim011 "$b" nn-iou-probe) -ge 1 ]] && pass "NN-L-FIM-011 for the same file opened through io_uring" \
                                           || bad "no NN-L-FIM-011 for the io_uring open"
else
    printf 'SKIP  io_uring probe not built\n'
fi
sudo rm -rf "$H/.aws"

# 3. mass write: 25 write-opens counted in the kernel, one event
mark=$(date '+%Y-%m-%d %H:%M:%S')
d=$(mktemp -d /var/tmp/nn-open-mw.XXXXXX)
for i in $(seq 1 25); do : > "$d/f$i"; done
sleep 3; rm -rf "$d"
mw=$(journal "$mark" | grep -c "mass write: write-open threshold crossed")
[[ $mw -eq 1 ]] && pass "one MassWrite event for 25 write-opens (kernel count)" \
               || bad "$mw MassWrite events for 25 write-opens (expected 1)"

# 4. persistence: a root write under /etc/cron.d from a shell (not a package
# manager) raises PersistenceMechanism from the OBSERVING posture
sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1
mark=$(date '+%Y-%m-%d %H:%M:%S'); sleep 1
sudo sh -c 'echo "# nn open-sensor check" > /etc/cron.d/nn-open-sensor-check'
sleep 3
sudo rm -f /etc/cron.d/nn-open-sensor-check
if journal "$mark" | grep -q "trigger=Some(PersistenceMechanism)"; then
    pass "PersistenceMechanism from a write-open under /etc/cron.d"
else
    bad "no PersistenceMechanism transition after a write under /etc/cron.d ($(journal "$mark" | grep -m1 'POSTURE TRANSITION' | cut -c1-120))"
fi
sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1

# 5. sshd drop-ins: the posture's `/etc/ssh/sshd_config` prefix covers
# `sshd_config.d/`, and the kernel classifies by directory, so the list
# names the directory too: a write there raises CriticalFileModification
if [[ -d /etc/ssh/sshd_config.d ]]; then
    f=/etc/ssh/sshd_config.d/99-nn-open-sensor-check.conf
    mark=$(date '+%Y-%m-%d %H:%M:%S'); sleep 1
    sudo sh -c "echo '# nn open-sensor check' > $f"
    sleep 3
    sudo rm -f "$f"
    if journal "$mark" | grep -q "trigger=Some(CriticalFileModification)"; then
        pass "CriticalFileModification from a write-open under /etc/ssh/sshd_config.d"
    else
        bad "no CriticalFileModification transition after a write under /etc/ssh/sshd_config.d ($(journal "$mark" | grep -m1 'POSTURE TRANSITION' | cut -c1-120))"
    fi
    sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1
else
    printf 'SKIP  no /etc/ssh/sshd_config.d on this host\n'
fi

# 6. the file the kernel opened, not the path the process wrote (the
# "Phantom" class: sys_enter_openat read the caller's string): a
# write-open of /etc/crontab through a symlink with an innocuous name
# raises CriticalFileModification. Nothing is written (`: >>`).
ld=$(sudo mktemp -d /var/tmp/nn-open-link.XXXXXX)
sudo ln -s /etc/crontab "$ld/notes.txt"
mark=$(date '+%Y-%m-%d %H:%M:%S'); sleep 1
sudo sh -c ": >> '$ld/notes.txt'"
sleep 3
sudo rm -rf "$ld"
if journal "$mark" | grep -q "trigger=Some(CriticalFileModification)"; then
    pass "CriticalFileModification from a write-open of /etc/crontab through a symlink (the opened file, not the caller's path)"
else
    bad "no CriticalFileModification for /etc/crontab opened through a symlink ($(journal "$mark" | grep -m1 'POSTURE TRANSITION' | cut -c1-120))"
fi
sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1

# 7. the telemetry probe (a file open every 60 s) never went silent
gaps=$(journal run | grep -c "TELEMETRY GAP\|still SILENT")
[[ $gaps -eq 0 ]] && pass "telemetry probe: no gap since the agent started" \
                  || bad "telemetry probe: $gaps gap line(s) since the agent started"

[[ $fail -eq 0 ]] && echo "open-sensor check: OK" || echo "open-sensor check: FAILED"
exit $fail
