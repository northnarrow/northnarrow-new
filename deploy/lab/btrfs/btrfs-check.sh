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
IMG=/var/tmp/nn-btrfs-check.img
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

cleanup() {
    sudo umount /root/.aws 2>/dev/null
    sudo umount "$MNT" 2>/dev/null
    sudo rm -f "$IMG"
    if [ -d /root/.aws.nn-btrfs-check ]; then
        sudo rm -rf /root/.aws && sudo mv /root/.aws.nn-btrfs-check /root/.aws
    else
        sudo rmdir /root/.aws 2>/dev/null
    fi
    sudo systemctl restart northnarrow-agent && sleep 8
}
trap cleanup EXIT

# One read of /root/.aws/credentials after an agent restart (the agent
# registers the watched files' keys at start): 0 when NN-L-FIM-011 lands.
read_once() {
    sudo systemctl restart northnarrow-agent && sleep 12
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
