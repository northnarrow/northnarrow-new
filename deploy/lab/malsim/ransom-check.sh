#!/bin/bash
# Lab PR 225 — malware countermeasures M9 (part), on a lab guest
# (`nn-lab.sh ransom-check`). Benign simulations only: no encryption key, no
# network, files under /srv/nn-malsim and mktemp directories, everything
# restored at the end.
#
#   MS-23  ransomware: NN-L-IMP-001_RansomwareEncryption, Critical, on the
#          simulator (deploy/lab/malsim/ransom-sim.py), in place and
#          copy-delete. Its kill and the posture's COMBAT without
#          corroboration are held behind the per-rule response policy, off
#          by default (decision of 21/10/2026): the record is not a kill, the
#          simulator finishes, the posture reaches ENGAGED (not COMBAT).
#          Negatives — tar, rsync, git checkout, apt install of a package
#          with 300 high-entropy files, and the simulator's own script
#          compressing (log rotation) or moving (mv across filesystems)
#          its files then deleting them — draw no NN-L-IMP-001.
#   MS-25  security tools: `systemctl stop auditd`, `auditctl -e 0`,
#          `ufw disable`, a builtin `kill -STOP` of auditd and a rule file
#          written into /etc/audit/rules.d each leave their NN-L-EVA record.
#
# Run as the lab user with sudo, the agent installed and running (LSM
# sensors). `--only MS23|MS25` runs one group. Every line is PASS, FAIL or
# SKIP; the exit status is 1 on any FAIL.
set -u
# Debian keeps /usr/sbin out of a user's PATH: auditctl and ufw live there
# (MS-25 skipped them as "not installed" on debian12).
PATH=$PATH:/usr/sbin:/sbin
HERE=$(cd "$(dirname "$0")" && pwd)
SIM="$HERE/ransom-sim.py"
DET=/var/lib/northnarrow/detections/detections.jsonl
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
ONLY=${2:-}
[[ ${1:-} == --only ]] || ONLY=""
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
skip() { printf 'SKIP  %s\n' "$*"; }
det_count() { sudo cat "$DET" 2>/dev/null | wc -l; }
new_dets() { sudo tail -n "$(( $(det_count) - $1 ))" "$DET" 2>/dev/null; }
rule_records() { new_dets "$1" | grep -c "\"rule_id\":\"$2\""; }
# records of rule $2 since line $1 that name a kill (none while it is held)
rule_kills() { new_dets "$1" | grep "\"rule_id\":\"$2\"" | grep -c 'Kill'; }
engaged() { [[ $1 == Engaged || $1 == ENGAGED ]]; }
posture() { sudo "$NNADMIN" status 2>/dev/null | awk -F': *' '/^posture/ {print $2; exit}'; }
reset_posture() { sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1; sleep 1; }
# a command run outside the lab user's session (a unit of its own), so no
# administrator's interactive session sanctions it
unit_run() { sudo systemd-run --quiet --wait --pipe --collect -- "$@"; }
want() { [[ -z $ONLY || $ONLY == "$1" ]]; }

if want MS23; then
    # --- MS-23 positive, in place: rewrite with random bytes, rename to .locked
    reset_posture
    sudo python3 -I "$SIM" clean
    sudo python3 -I "$SIM" prepare --files 300 >/dev/null
    b=$(det_count)
    unit_run python3 -I "$SIM" inplace; rc=$?
    sleep 3
    locked=$(sudo find /srv/nn-malsim/data -name '*.locked' | wc -l)
    n=$(rule_records "$b" NN-L-IMP-001_RansomwareEncryption)
    k=$(rule_kills "$b" NN-L-IMP-001_RansomwareEncryption)
    p=$(posture)
    if [[ $n -ge 1 && $k -eq 0 && $rc -eq 0 ]]; then
        pass "MS-23 in place: NN-L-IMP-001_RansomwareEncryption recorded, kill held (simulator finished: $locked of 300 files), posture $p"
    else
        bad "MS-23 in place: NN-L-IMP-001 records=$n kills=$k sim rc=$rc files locked=$locked posture=$p"
    fi
    engaged "$p" && pass "MS-23 in place: posture ENGAGED (COMBAT needs corroboration)" || bad "MS-23 in place: posture $p, want ENGAGED"
    new_dets "$b" | grep -q '"severity":"Critical"' && pass "MS-23 in place: Critical" || bad "MS-23 in place: no Critical record"
    # --- MS-23 positive, delete-originals variant
    reset_posture
    sudo python3 -I "$SIM" clean
    sudo python3 -I "$SIM" prepare --files 300 >/dev/null
    b=$(det_count)
    unit_run python3 -I "$SIM" copy-delete; rc=$?
    sleep 3
    left=$(sudo find /srv/nn-malsim/data -type f ! -name '*.locked' | wc -l)
    n=$(rule_records "$b" NN-L-IMP-001_RansomwareEncryption)
    k=$(rule_kills "$b" NN-L-IMP-001_RansomwareEncryption)
    p=$(posture)
    if [[ $n -ge 1 && $k -eq 0 && $rc -eq 0 ]]; then
        pass "MS-23 copy-delete: NN-L-IMP-001_RansomwareEncryption recorded, kill held ($left originals left), posture $p"
    else
        bad "MS-23 copy-delete: NN-L-IMP-001 records=$n kills=$k sim rc=$rc originals left=$left posture=$p"
    fi
    engaged "$p" && pass "MS-23 copy-delete: posture ENGAGED (COMBAT needs corroboration)" || bad "MS-23 copy-delete: posture $p, want ENGAGED"
    # --- MS-23 negatives by the same unpackaged script (so no trust saves
    # them): the legitimate copy-then-delete shapes stay one shape, the
    # deletions — a log rotation with compression (the copies beside are
    # gzip), a move to another directory (no copy beside)
    for mode in gzip-delete move-away; do
        reset_posture
        sudo python3 -I "$SIM" clean
        sudo python3 -I "$SIM" prepare --files 300 >/dev/null
        b=$(det_count)
        unit_run python3 -I "$SIM" "$mode" >/dev/null; rc=$?
        sleep 3
        n=$(rule_records "$b" NN-L-IMP-001_RansomwareEncryption)
        if [[ $n -eq 0 && $rc -eq 0 ]]; then
            pass "MS-23 negative script $mode: no NN-L-IMP-001, exit 0"
        else
            bad "MS-23 negative script $mode: NN-L-IMP-001 records=$n rc=$rc"
        fi
    done
    sudo python3 -I "$SIM" clean
    reset_posture

    # --- MS-23 negatives: the legitimate bulk tools, started by a unit
    W=$(sudo mktemp -d /srv/nn-malsim/neg.XXXXXX)
    sudo bash -c "mkdir -p '$W/tree' && for i in \$(seq 1 400); do head -c 8192 /dev/urandom > '$W/tree/blob-\$i.bin'; done"
    neg() {
        local label=$1; shift
        local b n
        b=$(det_count)
        unit_run "$@" >/dev/null 2>&1; local rc=$?
        sleep 2
        n=$(rule_records "$b" NN-L-IMP-001_RansomwareEncryption)
        if [[ $n -eq 0 && $rc -eq 0 ]]; then
            pass "MS-23 negative $label: no NN-L-IMP-001, exit 0"
        else
            bad "MS-23 negative $label: NN-L-IMP-001 records=$n rc=$rc"
        fi
    }
    sudo tar -C "$W" -cf "$W/big.tar" tree
    # extracted twice: the second run unlinks and recreates every file
    sudo mkdir -p "$W/x"
    neg "tar xf" tar -C "$W/x" -xf "$W/big.tar"
    neg "tar xf over the same tree" tar -C "$W/x" -xf "$W/big.tar"
    neg "rsync -a" rsync -a "$W/tree/" "$W/r/"
    sudo bash -c "for f in '$W'/tree/*; do head -c 8192 /dev/urandom > \"\$f\"; done"
    neg "rsync -a --inplace over the same tree" rsync -a --inplace "$W/tree/" "$W/r/"
    if command -v git >/dev/null; then
        sudo bash -c "cd '$W' && git init -q g && cd g && git config user.email l@b && git config user.name lab \
            && cp ../tree/* . && git add -A && git commit -qm a && git checkout -qb other \
            && for f in blob-*; do head -c 8192 /dev/urandom > \$f; done && git commit -qam b && git checkout -q -"
        neg "git checkout of a big change" git -C "$W/g" checkout -q other
    else
        skip "MS-23 negative git: git not installed"
    fi
    if command -v dpkg-deb >/dev/null; then
        P=$(sudo mktemp -d /srv/nn-malsim/deb.XXXXXX)
        sudo bash -c "mkdir -p '$P/r/DEBIAN' '$P/r/usr/share/nn-ms-bulk' \
            && printf 'Package: nn-ms-bulk\nVersion: 1.0\nArchitecture: all\nMaintainer: lab <l@b>\nDescription: NorthNarrow lab, 400 random files\n' > '$P/r/DEBIAN/control' \
            && cp '$W'/tree/* '$P/r/usr/share/nn-ms-bulk/' && dpkg-deb -b '$P/r' '$P/nn-ms-bulk.deb' >/dev/null"
        neg "apt install of a package of 400 random files" apt-get install -y "$P/nn-ms-bulk.deb"
        neg "apt reinstall" apt-get install -y --reinstall "$P/nn-ms-bulk.deb"
        unit_run apt-get remove -y nn-ms-bulk >/dev/null 2>&1
        sudo rm -rf "$P"
    else
        skip "MS-23 negative apt: dpkg-deb not installed"
    fi
    sudo rm -rf "$W"
    reset_posture
fi

if want MS25; then
    eva() {
        local label=$1 rule=$2; shift 2
        local b n
        b=$(det_count)
        unit_run "$@" >/dev/null 2>&1
        sleep 2
        n=$(rule_records "$b" "$rule")
        if [[ $n -ge 1 ]] && new_dets "$b" | grep "\"rule_id\":\"$rule\"" | grep -q '"severity":"High"'; then
            pass "MS-25 $label: $rule High"
        else
            bad "MS-25 $label: $rule records=$n (want one, High)"
        fi
    }
    if ! command -v auditctl >/dev/null; then
        skip "MS-25: auditd not installed (sudo apt-get install -y auditd, then restart the agent)"
    else
        # auditd refuses a manual stop on most distributions (RefuseManualStop):
        # the attempt is the evidence either way.
        eva "systemctl stop auditd" NN-L-EVA-001_SecurityServiceStopped systemctl stop auditd
        sudo systemctl start auditd 2>/dev/null || sudo service auditd start 2>/dev/null
        eva "auditctl -e 0" NN-L-EVA-002_SecurityToolSwitchedOff auditctl -e 0
        sudo auditctl -e 1 >/dev/null
        sleep 1
        eva "kill -STOP of auditd (shell builtin, task_kill)" NN-L-EVA-003_SecurityToolKilled \
            bash -c 'kill -STOP $(pidof auditd); kill -CONT $(pidof auditd)'
        sudo kill -CONT "$(pidof auditd)" 2>/dev/null
        eva "rule file written into /etc/audit/rules.d" NN-L-EVA-004_SecurityToolConfigChanged \
            bash -c 'echo "# nn-ms lab rule (empty)" > /etc/audit/rules.d/nn-ms.rules'
        sudo rm -f /etc/audit/rules.d/nn-ms.rules
    fi
    if command -v ufw >/dev/null; then
        was=$(sudo ufw status | head -1)
        eva "ufw disable" NN-L-EVA-002_SecurityToolSwitchedOff ufw disable
        # never re-enabled unless it was active (enabling could cut the lab's ssh)
        [[ $was == *"active"* && $was != *"inactive"* ]] && sudo ufw --force enable >/dev/null
    else
        skip "MS-25 ufw: not installed"
    fi
    reset_posture
fi

# The status counters (signed telemetry; needs the lab's admin key).
if [[ -n ${NN_LAB_KEY:-} ]]; then
    sudo "$NNADMIN" status --key "$NN_LAB_KEY" | grep -E '^(ransomware|security tools)' || bad "status: no ransomware/security-tool lines"
fi
exit $fail
