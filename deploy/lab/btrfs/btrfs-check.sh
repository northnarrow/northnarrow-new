#!/bin/bash
# Review 55 regression check, run in a lab guest by `nn-lab.sh btrfs-check`.
#
# The agent keys watched and protected files by (dev, ino) taken from stat().
# On btrfs stat() reports the subvolume's device, not the superblock's, so
# the kernel side must report the same device or no key ever matches. This
# puts a watched credential file on a btrfs subvolume (a loop filesystem
# bind-mounted on /root/.aws), restarts the agent so it registers the file,
# reads it with cat and expects NN-L-FIM-011 in the detection store. The
# guest is put back as it was at the end (unmount, agent restarted).
set -u
DET=/var/lib/northnarrow/detections/detections.jsonl
# External audit LAB-008: the loop image is created by mktemp (root's,
# unpredictable name) just before use; a fixed /var/tmp name could be a link
# planted by another user, and root truncates and formats it.
IMG=
MNT=/mnt/nn-btrfs-check
fail=0
say() { printf 'btrfs-check: %s\n' "$*"; }

# Built in (Debian's cloud kernel) or a module: /proc/filesystems decides.
grep -qw btrfs /proc/filesystems || sudo modprobe btrfs 2>/dev/null
if ! grep -qw btrfs /proc/filesystems; then
    say "SKIP — this kernel has no btrfs (RHEL 9 does not ship it)"
    exit 0
fi
# mkfs.btrfs lives in /usr/sbin, outside a user's PATH on Debian: look
# through sudo's secure_path.
have_mkfs() { sudo sh -c 'command -v mkfs.btrfs' >/dev/null; }
if ! have_mkfs; then
    if command -v apt-get >/dev/null; then
        sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -q btrfs-progs >/dev/null 2>&1
    fi
    have_mkfs || { say "FAIL — mkfs.btrfs not available"; exit 1; }
fi

# External audit EBPF-001: the agent unit refuses `systemctl restart`, and
# systemd's signals reach the agent only inside a signed trusted-installer
# window: open one with the lab key, SIGTERM the agent, and let the watchdog
# bring it back (started by hand if it has not within 30 s).
restart_agent() {
    local nn_admin old new i key
    nn_admin=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
    old=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
    # the lab key: /root/northnarrow-admin.key since external audit DEP-001
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
    sudo umount "$MNT" 2>/dev/null
    [ -n "$IMG" ] && sudo rm -f "$IMG"
    if [ -d /root/.aws.nn-btrfs-check ]; then
        sudo rm -rf /root/.aws && sudo mv /root/.aws.nn-btrfs-check /root/.aws
    else
        sudo rmdir /root/.aws 2>/dev/null
    fi
    restart_agent && sleep 8
}
trap cleanup EXIT

# One read of /root/.aws/credentials after an agent restart (the agent
# registers the watched files' keys at start): 0 when NN-L-FIM-011 lands.
read_once() {
    restart_agent && sleep 12
    systemctl is-active --quiet northnarrow-agent || { say "  agent not active after restart"; return 1; }
    local before after hit
    before=$(sudo cat "$DET" 2>/dev/null | wc -l)
    sudo cat /root/.aws/credentials >/dev/null 2>&1
    sleep 4
    after=$(sudo cat "$DET" 2>/dev/null | wc -l)
    hit=$(sudo tail -n "$((after - before))" "$DET" 2>/dev/null | grep -c '"NN-L-FIM-011_AwsCredsRead"')
    sudo stat -c '  stat(): st_dev %Hd:%Ld, ino %i' /root/.aws/credentials
    [ "$hit" -ge 1 ]
}

sudo umount /root/.aws 2>/dev/null
sudo umount "$MNT" 2>/dev/null
if sudo test -e /root/.aws; then
    sudo mv /root/.aws /root/.aws.nn-btrfs-check
fi

# Control: the same file on the root filesystem must be detected, or the
# check itself is broken.
sudo mkdir -p /root/.aws
printf '[default]\naws_access_key_id = NNLABCONTROL\n' | sudo tee /root/.aws/credentials >/dev/null
if read_once; then
    say "control (root filesystem): NN-L-FIM-011 recorded"
else
    say "FAIL — control: no NN-L-FIM-011 for the file on the root filesystem; the check cannot conclude"
    exit 1
fi
sudo rm -rf /root/.aws

IMG=$(sudo mktemp /var/tmp/nn-btrfs-check.XXXXXXXX) || { say "FAIL — mktemp"; exit 1; }
sudo truncate -s 512M "$IMG" && sudo mkfs.btrfs -q -f "$IMG" || { say "FAIL — mkfs.btrfs"; exit 1; }
sudo mkdir -p "$MNT" && sudo mount -o loop "$IMG" "$MNT" || { say "FAIL — mount"; exit 1; }
sudo btrfs subvolume create "$MNT/sv" >/dev/null
sudo mkdir -p "$MNT/sv/aws"
printf '[default]\naws_access_key_id = NNLABBTRFSCHECK\n' | sudo tee "$MNT/sv/aws/credentials" >/dev/null
sudo mkdir -p /root/.aws && sudo mount --bind "$MNT/sv/aws" /root/.aws || { say "FAIL — bind mount"; exit 1; }
awk -v m="$MNT" '$5==m {print "  btrfs superblock s_dev (mountinfo): " $3}' /proc/self/mountinfo
if read_once; then
    say "PASS — NN-L-FIM-011 recorded for the same read on a btrfs subvolume"
else
    say "FAIL — no NN-L-FIM-011 on the btrfs subvolume: the kernel's inode key did not match stat()"
    fail=1
fi
exit "$fail"
