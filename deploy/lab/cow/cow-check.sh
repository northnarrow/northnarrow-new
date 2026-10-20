#!/usr/bin/env bash
# Lab PR 222 — field check of the copy-on-first-write guard (ransomware
# rollback, EXPERIMENTAL). NorthNarrow's own lab only: run ON THE GUEST, as
# root (sudo), against the installed agent of this branch. It touches only
# /srv/nn-cow-test, /srv/nn-cow-xfs (a loop filesystem it creates), the
# guard's overlay and drop-in, and nothing outside the guest.
#
#   sudo bash deploy/lab/cow/cow-check.sh setup    [--fs ext4|xfs] [--auto]
#   sudo bash deploy/lab/cow/cow-check.sh run      [--fs ext4|xfs]
#   sudo bash deploy/lab/cow/cow-check.sh auto     [--fs ext4|xfs]
#   sudo bash deploy/lab/cow/cow-check.sh negative [--fs ext4|xfs]
#   sudo bash deploy/lab/cow/cow-check.sh bench    [--fs ext4|xfs] [--bench-bin PATH]
#   sudo bash deploy/lab/cow/cow-check.sh cleanup
#
# setup:    the test tree's filesystem (xfs: a 2 GiB loop image, reflink=1),
#           the drop-in (CAP_SYS_ADMIN for fanotify), a signed cow-guard.local
#           naming the scope, response-manage on the lab key, agent restart;
#           `status --key` must say the guard is running.
# run:      a tree of text, binary and one large (20 MiB > the 16 MiB copy
#           cap) file; the BENIGN simulator (deploy/lab/cow/ransom-sim.py) as
#           the unprivileged user rewrites each file with random bytes and
#           renames it .locked; the mass-write detection must fire for it;
#           `nn-admin remediate ransomware --pid` restores; every file's
#           sha256 is compared with the original.
# auto:     auto_restore = true; the simulator runs as root with the
#           anti-tamper tripwire (a refused open of admin.pub: decisive
#           COMBAT with the simulator as offender), the ladder NEUTRALIZEs
#           it, the guard restores on its own; same comparison.
# negative: a trusted writer (vim, package-managed, started by a unit: no
#           script in its lineage) rewrites files in place: no copy taken;
#           then `cp` (not a trusted writer) over a few: copies taken (the
#           guard is live).
# bench:    cow_bench outside and inside the scope (guard off / on).
#
# Exit: 0 PASS, 1 FAIL, 2 NOT RUN (a prerequisite is missing).
set -u
export LC_ALL=C
ETC=/etc/northnarrow
DROPIN_DIR=/etc/systemd/system/northnarrow-agent.service.d
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
FS=ext4
AUTO=0
BENCH_BIN=$REPO/target/release/examples/cow_bench
LAB_USER=${LAB_USER:-nn}
MODE=${1:-}
shift || true
while (( $# )); do
    case "$1" in
        --fs) FS=$2; shift ;;
        --auto) AUTO=1 ;;
        --bench-bin) BENCH_BIN=$2; shift ;;
        *) echo "cow-check: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done
case "$FS" in
    ext4) TREE=/srv/nn-cow-test; SCOPE_LINE="scope = /srv/nn-cow-test mark=dirs budget=1GiB" ;;
    xfs) TREE=/srv/nn-cow-xfs; SCOPE_LINE="scope = /srv/nn-cow-xfs mark=mount budget=1GiB" ;;
    *) echo "cow-check: --fs ext4|xfs" >&2; exit 2 ;;
esac
say() { printf 'cow-check[%s]: %s\n' "$FS" "$*"; }
fail() { say "FAIL — $*"; exit 1; }
notrun() { say "NOT RUN — $*"; exit 2; }
[[ $(id -u) == 0 ]] || notrun "run as root (sudo)"

NN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
[[ -x $NN ]] || NN=/usr/local/bin/nn-admin
KEY=$(for k in /root/northnarrow-admin.key $ETC/admin.key; do test -r "$k" && { echo "$k"; break; }; done)
[[ -n $KEY ]] || notrun "no lab admin key (/root/northnarrow-admin.key)"
A=(--key "$KEY")

agent_pid() { cat /run/northnarrow/agent.pid 2>/dev/null; }
window() { "$NN" trusted-installer-grant "${A[@]}" --window-secs "${1:-120}" >/dev/null 2>&1; }

# External audit EBPF-001: the agent refuses `systemctl restart`; inside a
# signed trusted-installer window SIGTERM stops it and the watchdog brings
# it back (started by hand if not within 30 s).
restart_agent() {
    local old new i
    old=$(agent_pid)
    window 120
    systemctl daemon-reload
    systemctl kill --signal=SIGTERM northnarrow-agent
    for i in $(seq 1 30); do
        sleep 1
        new=$(agent_pid)
        [[ -n $new && $new != "$old" ]] && kill -0 "$new" 2>/dev/null && { sleep 5; return 0; }
    done
    systemctl start northnarrow-agent
    sleep 5
}

guard_status() { "$NN" status "${A[@]}" 2>/dev/null | sed -n '/^copy on write/,$p'; }
counter() { # counter NAME → value from status --key --json
    "$NN" status "${A[@]}" --json 2>/dev/null | python3 -I -c '
import json, sys
d = json.load(sys.stdin).get("cow_guard") or {}
print(dict(d.get("counters", [])).get(sys.argv[1], 0))' "$1"
}
entries() {
    "$NN" status "${A[@]}" --json 2>/dev/null | python3 -I -c '
import json, sys
d = json.load(sys.stdin).get("cow_guard") or {}
print(sum(s["entries"] for s in d.get("scopes", [])))'
}

ensure_role() { # the bootstrap key lacks response-manage: grant it (window + restart)
    grep -q "$1" $ETC/admin.pub && return 0
    say "granting $1 to the lab key"
    window 120
    sed -i -E "/$1/! s/^([0-9a-fA-F]{64})[[:space:]]+([a-z,-]+)\$/\\1 \\2,$1/" $ETC/admin.pub
    restart_agent
}

mount_xfs() {
    mountpoint -q /srv/nn-cow-xfs && return 0
    command -v mkfs.xfs >/dev/null || DEBIAN_FRONTEND=noninteractive apt-get install -y -q xfsprogs >/dev/null 2>&1
    command -v mkfs.xfs >/dev/null || notrun "mkfs.xfs not available"
    if ! grep -qw xfs /proc/filesystems; then
        # R011 kills module tooling while the agent runs: load it in a window
        # with the agent stopped (as deploy/lab/btrfs/btrfs-check.sh does).
        window 120
        systemctl kill --signal=SIGTERM northnarrow-watchdog; sleep 2
        systemctl kill --signal=SIGTERM northnarrow-agent; sleep 3
        modprobe xfs
        systemctl start northnarrow-agent; sleep 4; systemctl start northnarrow-watchdog; sleep 3
        grep -qw xfs /proc/filesystems || notrun "the xfs module did not load"
    fi
    IMG=$(mktemp /var/tmp/nn-cow-xfs.XXXXXX)
    truncate -s 2G "$IMG"
    mkfs.xfs -q -f -m reflink=1 "$IMG" || notrun "mkfs.xfs -m reflink=1 failed"
    mkdir -p /srv/nn-cow-xfs
    mount -o loop "$IMG" /srv/nn-cow-xfs || notrun "loop mount failed"
    echo "$IMG" > /run/nn-cow-xfs.img
    say "XFS (reflink=1) loop filesystem on /srv/nn-cow-xfs ($IMG)"
}

write_overlay() { # write_overlay AUTO(0|1)
    local f
    f=$(mktemp /root/cow-guard.XXXXXX)
    {
        echo "# lab PR 222 — cow-check.sh"
        echo "enabled = true"
        echo "$SCOPE_LINE"
        echo "copy_cap = 16MiB"
        echo "event_budget_ms = 50"
        echo "auto_restore = $([[ $1 == 1 ]] && echo true || echo false)"
    } > "$f"
    "$NN" config overlay set cow-guard --file "$f" "${A[@]}" || { rm -f "$f"; fail "overlay not stored (config-manage?)"; }
    rm -f "$f"
}

setup() {
    mkdir -p /srv
    [[ $FS == xfs ]] && mount_xfs
    mkdir -p "$TREE" "$TREE/docs" "$TREE/bin" "$TREE/big"
    ensure_role response-manage
    if ! cmp -s "$REPO/deploy/systemd/20-cow-guard.conf" "$DROPIN_DIR/20-cow-guard.conf"; then
        window 120
        install -d -m 0755 "$DROPIN_DIR"
        install -m 0644 "$REPO/deploy/systemd/20-cow-guard.conf" "$DROPIN_DIR/20-cow-guard.conf"
        say "drop-in installed (CAP_SYS_ADMIN CAP_CHOWN CAP_FOWNER)"
    fi
    write_overlay "$AUTO"
    restart_agent
    guard_status
    guard_status | head -1 | grep -q ': running' || fail "the guard is not running (journalctl --namespace=northnarrow -u northnarrow-agent | grep 'copy on first write')"
    say "setup done: guard running on $TREE"
}

# The tree's directories are kept from one case to the next: with
# mark=dirs the guard marks the directories it finds (at its start, then
# every 60 s), and a directory made afresh is not marked before the next
# rescan — the simulator ran in new, unmarked directories and nothing was
# copied (lab, 21/10, 24.04 ext4). A directory created here waits for that
# rescan. The guard's journal (.northnarrow-cow) is never touched: it is
# write-denied, and a chown of it is an anti-tamper denial (NN-L-AT-001,
# a locked COMBAT).
make_tree() {
    local d created=0
    find "$TREE" -mindepth 1 -maxdepth 1 ! -name .northnarrow-cow ! -name docs ! -name bin ! -name big -exec rm -rf {} + 2>/dev/null
    for d in docs bin big; do
        if [[ -d "$TREE/$d" ]]; then
            find "$TREE/$d" -mindepth 1 -delete 2>/dev/null
        else
            mkdir -p "$TREE/$d"; created=1
        fi
    done
    touch "$TREE/.nn-cow-test-tree"
    local i
    for i in $(seq -w 1 40); do
        python3 -I -c "import sys; print(('lab PR 222 document $i ' * 400)[:8192])" > "$TREE/docs/doc-$i.txt"
    done
    for i in $(seq -w 1 10); do head -c 65536 /dev/urandom > "$TREE/bin/blob-$i.bin"; done
    head -c $((20 * 1024 * 1024)) /dev/urandom > "$TREE/big/large-20MiB.dat"
    chown "$LAB_USER:$LAB_USER" "$TREE"
    chown -R "$LAB_USER:$LAB_USER" "$TREE/docs" "$TREE/bin" "$TREE/big"
    if (( created )) && [[ $SCOPE_LINE == *mark=dirs* ]]; then
        say "new directories: waiting 65 s for the guard's rescan to mark them (mark=dirs)"
        sleep 65
    fi
    MANIFEST=$(mktemp /root/nn-cow-manifest.XXXXXX)
    (cd "$TREE" && find . -type f ! -name .nn-cow-test-tree ! -path './.northnarrow-cow/*' -print0 | sort -z | xargs -0 sha256sum) > "$MANIFEST"
    say "tree: $(wc -l < "$MANIFEST") files (40 text 8 KiB, 10 binary 64 KiB, 1 of 20 MiB)"
}

compare() { # compare → counts; the 20 MiB file on ext4 is over the cap (expected unprotected)
    local ok=0 bad=0 expected_bad=0 line sum rel
    while read -r sum rel; do
        if [[ -f "$TREE/$rel" ]] && [[ $(sha256sum < "$TREE/$rel" | cut -d' ' -f1) == "$sum" ]]; then
            ok=$((ok + 1))
        elif [[ $FS == ext4 && $rel == ./big/large-20MiB.dat ]]; then
            expected_bad=$((expected_bad + 1))
            say "not restored as designed: $rel (over the copy cap, no reflink on ext4)"
        else
            bad=$((bad + 1)); say "MISMATCH: $rel"
        fi
    done < "$MANIFEST"
    local locked
    locked=$(find "$TREE" -name '*.locked' ! -path '*/.northnarrow-cow/*' | wc -l)
    say "sha256: $ok match, $bad mismatch, $expected_bad expected unprotected; .locked left: $locked"
    [[ $bad == 0 ]]
}

detection_fired() { # detection_fired PID SINCE
    journalctl --namespace=northnarrow -u northnarrow-agent --since "$2" -o cat 2>/dev/null \
        | grep -E 'ConfirmedIntrusion_MassWrite' | grep -E "focal_pid=$1([^0-9]|$)" | head -1
}

run_attack() { # run_attack USER EXTRA...
    local u=$1; shift
    local log
    log=$(mktemp /root/nn-cow-sim.XXXXXX)
    if [[ $u == root ]]; then
        python3 "$HERE/ransom-sim.py" "$TREE" "$@" > "$log" 2>&1 &
    else
        # the simulator, readable by the user, in its own copy
        install -m 0755 -o "$LAB_USER" "$HERE/ransom-sim.py" "/home/$LAB_USER/ransom-sim.py"
        sudo -u "$LAB_USER" python3 "/home/$LAB_USER/ransom-sim.py" "$TREE" "$@" > "$log" 2>&1 &
    fi
    SIM_WAIT=$!
    sleep 1
    SIM_PID=$(grep -oE 'pid [0-9]+' "$log" | head -1 | cut -d' ' -f2)
    wait "$SIM_WAIT" 2>/dev/null
    SIM_PID=$(grep -oE 'pid [0-9]+' "$log" | head -1 | cut -d' ' -f2)
    cat "$log"; rm -f "$log"
}

run() {
    guard_status | head -1 | grep -q ': running' || notrun "the guard is not running (setup first)"
    make_tree
    local since c0
    since=$(date '+%Y-%m-%d %H:%M:%S')
    c0=$(entries)
    run_attack "$LAB_USER"
    [[ -n ${SIM_PID:-} ]] || fail "the simulator did not run"
    sleep 3
    say "journal entries: $c0 → $(entries)"
    local det
    det=$(detection_fired "$SIM_PID" "$since")
    [[ -n $det ]] || fail "no mass-write detection for pid $SIM_PID (ConfirmedIntrusion_MassWrite)"
    say "detection: $det"
    "$NN" status "${A[@]}" | head -3
    "$NN" remediate ransomware --pid "$SIM_PID" --dry-run "${A[@]}" | head -5
    "$NN" remediate ransomware --pid "$SIM_PID" "${A[@]}" | head -8
    compare || fail "files not restored"
    local rows
    rows=$(grep -c '"op":"cow_restore"' $ETC/audit.log)
    say "cow_restore rows in the signed audit log: $rows; audit verify:"
    "$NN" audit verify 2>&1 | tail -1
    guard_status
    say "PASS"
}

auto() {
    write_overlay 1
    restart_agent
    guard_status | head -1 | grep -q ': running' || notrun "the guard is not running"
    make_tree
    run_attack root --tripwire --hold 120 &
    local bg=$! i
    for i in $(seq 1 90); do
        sleep 1
        journalctl --namespace=northnarrow -u northnarrow-agent --since "-2min" -o cat 2>/dev/null \
            | grep -q 'copy on first write: restore done' && break
    done
    wait "$bg" 2>/dev/null
    journalctl --namespace=northnarrow -u northnarrow-agent --since "-3min" -o cat 2>/dev/null \
        | grep -E 'COMBAT: (entered|NEUTRALIZE)|copy on first write' | tail -8
    "$NN" unlock "${A[@]}" >/dev/null 2>&1
    compare || fail "files not restored by the automatic restore"
    write_overlay 0
    restart_agent
    say "PASS"
}

negative() {
    guard_status | head -1 | grep -q ': running' || notrun "the guard is not running (setup first)"
    make_tree
    local t0 c0 e0 i
    t0=$(counter allowed_trusted); c0=$(( $(counter copies_reflink) + $(counter copies_plain) )); e0=$(entries)
    # vim from a unit of its own: the guard trusts an editor only when no
    # ancestor is foreign, and an interpreter running a named script — this
    # very script — is one ("an editor started by a script … is not
    # trusted", agent/src/cow/trust.rs); `sudo -u` from here made every vim
    # untrusted and copied (lab, 21/10)
    for i in $(seq -w 1 10); do
        systemd-run --quiet --wait --pipe --collect -p User="$LAB_USER" -- vim -es -u NONE -i NONE \
            -c 'set backupcopy=yes nobackup nowritebackup noswapfile' \
            -c 'normal Goedited by vim' -c 'wq' "$TREE/docs/doc-$i.txt" </dev/null
    done
    sleep 2
    local t1 c1 e1
    t1=$(counter allowed_trusted); c1=$(( $(counter copies_reflink) + $(counter copies_plain) )); e1=$(entries)
    say "vim: trusted opens $t0 → $t1, copies $c0 → $c1, journal entries $e0 → $e1"
    (( t1 >= t0 + 10 )) || fail "vim's opens were not judged trusted"
    (( c1 == c0 && e1 == e0 )) || fail "copies were taken for a trusted writer"
    for i in 1 2 3; do sudo -u "$LAB_USER" cp "$TREE/docs/doc-2$i.txt" "$TREE/docs/doc-3$i.txt"; done
    sleep 2
    local c2
    c2=$(( $(counter copies_reflink) + $(counter copies_plain) ))
    say "cp (not a trusted writer): copies $c1 → $c2"
    (( c2 >= c1 + 3 )) || fail "cp over existing files was not copied"
    say "PASS"
}

bench() {
    [[ -x $BENCH_BIN ]] || notrun "no $BENCH_BIN (cargo build --release -p northnarrow-agent --example cow_bench)"
    local off=/srv/nn-cow-bench-off on=$TREE/bench
    [[ $FS == xfs ]] && off=/srv/nn-cow-bench-off-xfs-is-another-fs
    local fresh=0
    [[ -d "$on" ]] || fresh=1
    mkdir -p "$off" "$on"; chown "$LAB_USER" "$off" "$on"
    if (( fresh )) && [[ $SCOPE_LINE == *mark=dirs* ]]; then
        # a new directory is marked at the guard's next rescan (60 s): before
        # it the "guard ON" rounds measured no copy path (lab, 21/10)
        say "new directory $on: waiting 65 s for the guard's rescan to mark it (mark=dirs)"
        sleep 65
    fi
    say "guard OFF (outside the scope, same host):"
    sudo -u "$LAB_USER" "$BENCH_BIN" --dir "$off" --files 2000 --size 4096 --rounds 3
    say "guard ON (inside the scope; round 1 = copy path, later rounds = already copied):"
    sudo -u "$LAB_USER" "$BENCH_BIN" --dir "$on" --files 2000 --size 4096 --rounds 3
    sudo -u "$LAB_USER" "$BENCH_BIN" --dir "$on" --files 200 --size 1048576 --rounds 2
    guard_status | grep -E 'open latency|copies|not protected'
    rm -rf "$off" "$on"
}

cleanup() {
    window 300
    rm -f $ETC/cow-guard.local $ETC/cow-guard.local.sig
    rm -f "$DROPIN_DIR/20-cow-guard.conf"
    restart_agent
    rm -rf /srv/nn-cow-test /srv/nn-cow-bench-off
    if mountpoint -q /srv/nn-cow-xfs; then umount /srv/nn-cow-xfs; fi
    [[ -r /run/nn-cow-xfs.img ]] && rm -f "$(cat /run/nn-cow-xfs.img)" /run/nn-cow-xfs.img
    rmdir /srv/nn-cow-xfs 2>/dev/null
    rm -f "/home/$LAB_USER/ransom-sim.py"
    guard_status | head -1
    say "cleaned up"
}

case "$MODE" in
    setup) setup ;;
    run) run ;;
    auto) auto ;;
    negative) negative ;;
    bench) bench ;;
    cleanup) cleanup ;;
    *) sed -n '2,32p' "$0"; exit 2 ;;
esac
