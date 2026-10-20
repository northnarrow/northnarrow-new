#!/bin/bash
# External audit EBPF-016 (NN-AUD-267) check, run in a lab guest by
# `nn-lab.sh overlay-check`; modelled on deploy/lab/btrfs/btrfs-check.sh.
#
# The agent keys watched and protected files by (dev, ino) taken from stat().
# On overlayfs, FUSE and NFS it cannot vouch that the eBPF hooks see the same
# pair (overlayfs reports the layer's inode), and a key that does not match is
# neither denied nor recorded. Since lab PR 189 every boot that registers such
# a path says so: a WARN and one signed `subsystem_degraded` with
# `reason: inode_identity_unverified`. This puts a watched credential file on
# an overlay mount (bind-mounted on /root/.aws), restarts the agent so it
# registers the file, reads it, and requires NN-L-FIM-011 in the detection
# store OR the signed record of that boot naming the path. Silence — neither —
# fails. The guest is put back as it was (unmount, agent restarted).
# Exit: 0 PASS, 1 FAIL.
set -u
DET=/var/lib/northnarrow/detections/detections.jsonl
AUD=/etc/northnarrow/audit.log
BASE=
MNT=
fail=0
say() { printf 'overlay-check: %s\n' "$*"; }

# The agent unit refuses `systemctl restart` (external audit EBPF-001): a
# signed trusted-installer window, SIGTERM, and the watchdog brings it back.
restart_agent() {
    local nn_admin old new i key
    nn_admin=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
    old=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
    key=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
    sudo "$nn_admin" trusted-installer-grant --key "$key" --window-secs 120 >/dev/null 2>&1
    sudo systemctl kill --signal=SIGTERM northnarrow-agent
    for i in $(seq 1 30); do
        sleep 1
        new=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
        [ -n "$new" ] && [ "$new" != "$old" ] && sudo kill -0 "$new" 2>/dev/null && return 0
    done
    sudo systemctl start northnarrow-agent
}

cleanup() {
    sudo umount /root/.aws 2>/dev/null
    [ -n "$MNT" ] && sudo umount "$MNT" 2>/dev/null
    [ -n "$BASE" ] && sudo rm -rf "$BASE"
    if [ -d /root/.aws.nn-overlay-check ]; then
        sudo rm -rf /root/.aws && sudo mv /root/.aws.nn-overlay-check /root/.aws
    else
        sudo rmdir /root/.aws 2>/dev/null
    fi
    restart_agent && sleep 8
}
trap cleanup EXIT

sudo umount /root/.aws 2>/dev/null
if sudo test -e /root/.aws; then
    sudo mv /root/.aws /root/.aws.nn-overlay-check
fi

# External audit LAB-008: the layers live in a directory mktemp made (root's,
# unpredictable name), not at a fixed /var/tmp path another user could plant.
BASE=$(sudo mktemp -d /var/tmp/nn-overlay-check.XXXXXXXX) || { say "FAIL — mktemp"; exit 1; }
MNT=$BASE/merged
sudo mkdir -p "$BASE/lower/aws" "$BASE/upper" "$BASE/work" "$MNT"
printf '[default]\naws_access_key_id = NNLABOVERLAYCHECK\n' | sudo tee "$BASE/lower/aws/credentials" >/dev/null
sudo mount -t overlay overlay -o "lowerdir=$BASE/lower,upperdir=$BASE/upper,workdir=$BASE/work" "$MNT" \
    || { say "FAIL — overlay mount"; exit 1; }
sudo mkdir -p /root/.aws && sudo mount --bind "$MNT/aws" /root/.aws || { say "FAIL — bind mount"; exit 1; }
magic=$(sudo stat -f -c %t /root/.aws/credentials)
say "/root/.aws/credentials on filesystem type 0x$magic (overlayfs: 0x794c7630)"
[ "$magic" = 794c7630 ] || { say "FAIL — the bind mount is not on overlayfs"; exit 1; }

a0=$(sudo wc -l "$AUD" 2>/dev/null | cut -d" " -f1); a0=${a0:-0}
restart_agent && sleep 12
systemctl is-active --quiet northnarrow-agent || { say "FAIL — agent not active after restart"; exit 1; }
before=$(sudo cat "$DET" 2>/dev/null | wc -l)
sudo cat /root/.aws/credentials >/dev/null 2>&1
sleep 4
after=$(sudo cat "$DET" 2>/dev/null | wc -l)
hit=$(sudo tail -n "$((after - before))" "$DET" 2>/dev/null | grep -c '"NN-L-FIM-011_AwsCredsRead"')
record=$(sudo tail -n "+$((a0 + 1))" "$AUD" 2>/dev/null | grep -a '"inode_identity_unverified"' | grep -ac '/root/.aws/credentials')
sudo stat -c '  stat(): st_dev %Hd:%Ld, ino %i' /root/.aws/credentials
say "NN-L-FIM-011 records for the read: $hit; signed inode_identity_unverified records of the boot naming the file: $record"
if [ "$record" -ge 1 ]; then
    say "PASS — the boot attested the unverified inode identity (FIM-011 ${hit:-0} time(s))"
elif [ "$hit" -ge 1 ]; then
    say "PASS — NN-L-FIM-011 recorded for the read on overlayfs (no identity record: an agent before lab PR 189?)"
else
    say "FAIL — silence: no NN-L-FIM-011 and no signed inode_identity_unverified record for a watched file on overlayfs"
    fail=1
fi
exit "$fail"
