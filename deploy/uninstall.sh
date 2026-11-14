#!/usr/bin/env bash
# NorthNarrow XDR uninstall.
#
# Removes everything deploy/install.sh put on the host, in the order the
# anti-tamper layer requires:
#
#   1. stop + disable the units (watchdog FIRST, or it respawns the agent);
#   2. drop the bpffs pin root — the LSM programs (task_kill, ptrace,
#      inode_* deny hooks, FIM observers) stay attached only through their
#      pinned links, so removing /sys/fs/bpf/northnarrow detaches them;
#      wait until the agent's own programs (the ids it lists in
#      /run/northnarrow/bpf-own-ids) are unloaded — anything still holding
#      an fd keeps denying the unlinks below. Other products' BPF-LSM
#      programs are not waited for (external audit DEP-006);
#   3. lift chattr +i from the state directory (the agent sets it at boot);
#   4. remove binaries, units, the journald namespace config, /run and the
#      10 inert control-surface bait files;
#   5. keep /etc/northnarrow (admin.pub, agent.sig.key, audit.log,
#      agent_id, rule files) and /var/lib/northnarrow (FIM / canary /
#      netflow / detections chain logs) unless --purge is given: the
#      signed audit chain and the admin key are evidence and identity,
#      an uninstall must not destroy them by default. --purge also
#      removes the bootstrap admin private key install.sh wrote
#      (/root/northnarrow-admin.key since external audit DEP-001; it used
#      to live in /etc/northnarrow and went with it).
#
# Usage:
#   sudo ./deploy/uninstall.sh --grant-key KEY          # binaries + units, keep config/state
#   sudo ./deploy/uninstall.sh --purge --grant-key KEY  # also /etc/northnarrow, /var/lib/northnarrow,
#                                         # the namespace journal — NOTHING is kept
#   --grant-key KEY  admin key with the trusted-installer role: the window
#               the stop and the pin root's removal need while the hooks
#               are attached. With both units stopped and the pin root of
#               the last agent still protected, the installed agent is
#               started for the window, then stopped again (external
#               audit DEP-020)
#   --yes       no confirmation prompt
#   --package   run from a package's post-removal hook: the package manager
#               already removed binaries and units and the pre-removal hook
#               stopped the agent; a pin root that is still protected is
#               reported instead of failing the package operation
#
# Lot 341 (alpha 2/4): a WEDGED agent — its unit active but its admin socket
# not answering, or an agent that does not come up for the window — cannot
# open the trusted-installer window, and its hooks refuse the stop until the
# next boot (bpffs does not survive one). The script then disables both
# units (their enablement links are not protected), schedules the rest of
# the removal for the next boot (northnarrow-uninstall.service, a one-shot
# that runs a copy of this script with the same options, --at-boot, and
# then removes itself) and exits 3: reboot to finish. No key is needed for
# that path.
#
# A unit that does not stop (no window on a protected host) stops the
# script before anything is disabled or removed.
#
# Same BIN_DIR / UNIT_DIR / ETC_DIR / STATE_DIR overrides as install.sh.

set -euo pipefail

BIN_DIR=${BIN_DIR:-/usr/local/bin}
UNIT_DIR=${UNIT_DIR:-/etc/systemd/system}
DROPIN_ROOT=${DROPIN_ROOT:-/etc/systemd/system}
ETC_DIR=${ETC_DIR:-/etc/northnarrow}
STATE_DIR=${STATE_DIR:-/var/lib/northnarrow}
RUN_DIR=${RUN_DIR:-/run/northnarrow}
BPFFS_ROOT=${BPFFS_ROOT:-/sys/fs/bpf/northnarrow}
JOURNALD_NS_CONF=/etc/systemd/journald@northnarrow.conf
JOURNALD_NS_RUNTIME=${JOURNALD_NS_RUNTIME:-/run/systemd/journal.northnarrow}
# install.sh's upgrade transactions (lab PR 220): the copies of a run that
# could not finish its rollback; --purge removes them with the rest.
UPGRADE_TXN_ROOT=${UPGRADE_TXN_ROOT:-/var/lib/northnarrow-upgrade}
LSM_DRAIN_TIMEOUT=${LSM_DRAIN_TIMEOUT:-30}
# External audit DEP-006: the ids of the agent's loaded BPF programs, written
# by the agent next to its pid file (anti_tamper/bpf_defense.rs).
OWN_IDS_FILE=${OWN_IDS_FILE:-$RUN_DIR/bpf-own-ids}

PURGE=0
YES=0
PACKAGE=0
AT_BOOT=0
GRANT_KEY=
expect_key=0
# Lot 341: where a wedged agent's removal waits for the next boot (outside
# the agent's own directories, which its hooks keep protected until then).
FINISH_DIR=${FINISH_DIR:-/var/lib/northnarrow-uninstall}
FINISH_UNIT=northnarrow-uninstall.service
# How long the agent has to answer on its socket before it counts as wedged.
ANSWER_TIMEOUT=${ANSWER_TIMEOUT:-10}
# This script, copied for the boot-time run.
SELF_SCRIPT=${SELF_SCRIPT:-$(readlink -f "$0")}
for arg in "$@"; do
    if (( expect_key )); then GRANT_KEY=$arg; expect_key=0; continue; fi
    case "$arg" in
        --purge) PURGE=1 ;;
        --yes|-y) YES=1 ;;
        --package) PACKAGE=1 ;;
        --at-boot) AT_BOOT=1 ;;
        --grant-key) expect_key=1 ;;
        -h|--help) awk 'NR > 1 && !/^#/ { exit } NR > 1 { sub(/^# ?/, ""); print }' "$0"; exit 0 ;;
        *) echo "uninstall.sh: unknown argument: $arg" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "uninstall.sh: must run as root (sudo)" >&2; exit 1; }

log() { echo "uninstall.sh: $*"; }

# External audit EBPF-001: the units refuse a manual stop
# (RefuseManualStop=yes) and their processes take systemd's signals only
# inside the trusted-installer window: stop by signal, SIGTERM first (the
# agent writes agent_stop), SIGKILL only if a process outlives 10 s.
stop_nn_unit() {
    local u=$1 i
    systemctl kill --signal=SIGTERM "$u.service" 2>/dev/null || true
    for ((i = 0; i < 20; i++)); do
        nn_unit_has_procs "$u" || break
        sleep 0.5
    done
    if nn_unit_has_procs "$u"; then
        systemctl kill --signal=SIGKILL "$u.service" 2>/dev/null || true
        sleep 1
    fi
    systemctl reset-failed "$u.service" 2>/dev/null || true
}
nn_unit_has_procs() {
    local cg c
    cg=$(systemctl show -p ControlGroup --value "$1.service" 2>/dev/null)
    # lot 273d: the units' slice of their own; an older install's units ran
    # in system.slice
    for c in "$cg" "/northnarrow.slice/$1.service" "/system.slice/$1.service"; do
        [[ -n "$c" && -n "$(cat "/sys/fs/cgroup$c/cgroup.procs" 2>/dev/null)" ]] && return 0
    done
    return 1
}

NN_SELF=uninstall.sh
# >>> stale_pin_root (the same text in install.sh and uninstall.sh; xtask/tests/install_scripts.rs keeps them equal)
# External audit DEP-020 (NN-AUD-440): both units inactive and the pin root
# of an agent that is gone still there. Its deny hooks outlive it on purpose,
# so the pin root, the binaries and the units stay protected, and the
# trusted-installer window opens only through a running agent's socket: the
# branch meant for this case asked for an active agent, never true there,
# and --grant-key was ignored. With the key, the installed agent is started
# (its unit only; the watchdog stays as it was) until its admin socket is
# up; the caller opens the window, stops it again and does not restart it.
ADMIN_SOCKET=${ADMIN_SOCKET:-/run/northnarrow/admin.sock}
ADMIN_SOCKET_WAIT=${ADMIN_SOCKET_WAIT:-30}
stale_pin_root_help() {
    echo "$NN_SELF: the pin root of a stopped agent is PROTECTED by its hooks, and the trusted-installer window"
    echo "$NN_SELF: opens only through a running agent. Either:"
    echo "$NN_SELF:   - re-run with --grant-key <admin key carrying the trusted-installer role>: the installed"
    echo "$NN_SELF:     agent is started for the window, then stopped again; or"
    echo "$NN_SELF:   - systemctl disable northnarrow-agent northnarrow-watchdog, reboot (bpffs does not survive"
    echo "$NN_SELF:     a reboot), re-run, then enable the units again."
}
start_agent_for_window() {
    local i
    echo "$NN_SELF: starting the installed agent (its unit only) to open the trusted-installer window"
    if ! systemctl start northnarrow-agent.service; then
        echo "$NN_SELF: the installed agent did not start (systemctl status northnarrow-agent.service)." >&2
        stale_pin_root_help >&2
        return 1
    fi
    for ((i = 0; i < ADMIN_SOCKET_WAIT; i++)); do
        [[ -S "$ADMIN_SOCKET" ]] && return 0
        sleep 1
    done
    echo "$NN_SELF: the agent started but $ADMIN_SOCKET did not appear within ${ADMIN_SOCKET_WAIT}s;" >&2
    echo "$NN_SELF: it keeps running — re-run once nn-admin status answers." >&2
    return 1
}
# <<< stale_pin_root

echo "NorthNarrow uninstall"
echo "  binaries : $BIN_DIR/{northnarrow-agent,northnarrow-watchdog,nn-admin,northnarrow-scan}"
echo "  units    : $UNIT_DIR/northnarrow-{agent,watchdog,watchdog-failed}.service, $UNIT_DIR/northnarrow.slice"
echo "  accounts : northnarrow-scan, northnarrow-worker, northnarrow-export"
echo "  bpffs    : $BPFFS_ROOT"
if (( PURGE )); then
    echo "  PURGE    : $ETC_DIR (admin keys, audit chain, agent identity)"
    echo "             $STATE_DIR (FIM/canary/netflow/detections chains)"
    echo "             namespace journal northnarrow"
else
    echo "  kept     : $ETC_DIR and $STATE_DIR (use --purge to remove them)"
fi
if (( ! YES )); then
    read -r -p "Proceed? [y/N] " ans
    [[ "$ans" == y || "$ans" == Y ]] || { echo "aborted"; exit 1; }
fi

# >>> finish_at_boot (run by xtask/tests/install_scripts.rs)
# Lot 341 (alpha 2/4): the agent answers on its admin socket within
# ANSWER_TIMEOUT seconds (each try bounded: a wedged socket never hangs the
# script).
agent_answers() {
    timeout "$ANSWER_TIMEOUT" "$BIN_DIR/nn-admin" status --socket "$ADMIN_SOCKET" --json >/dev/null 2>&1
}
# A wedged agent: both units disabled now, the removal finished at the next
# boot by a one-shot unit running a copy of this script (--at-boot, the same
# options), which then removes itself. Exit 3: reboot to finish.
finish_at_boot() {   # <why>
    local u args=(--yes --at-boot)
    (( PURGE )) && args+=(--purge)
    echo "uninstall.sh: the agent is WEDGED ($1): its trusted-installer window cannot open, and its hooks" >&2
    echo "uninstall.sh: refuse its stop until the next boot. Disabling both units and finishing at the next boot." >&2
    for u in northnarrow-watchdog northnarrow-agent; do
        systemctl disable "$u.service" 2>/dev/null || true
        if systemctl is-enabled --quiet "$u.service" 2>/dev/null; then
            echo "uninstall.sh: $u.service could not be disabled. Reboot with systemd.mask=$u.service on the kernel" >&2
            echo "uninstall.sh: command line (both units), then run this script again. Nothing else was changed." >&2
            exit 1
        fi
    done
    install -d -m 0700 "$FINISH_DIR"
    install -m 0700 "$SELF_SCRIPT" "$FINISH_DIR/uninstall.sh"
    cat > "$UNIT_DIR/$FINISH_UNIT" <<EOT
[Unit]
Description=Finish the NorthNarrow uninstall (its agent was wedged)
After=local-fs.target
Before=northnarrow-agent.service northnarrow-watchdog.service
ConditionPathExists=$FINISH_DIR/uninstall.sh

[Service]
Type=oneshot
Environment=BIN_DIR=$BIN_DIR UNIT_DIR=$UNIT_DIR DROPIN_ROOT=$DROPIN_ROOT ETC_DIR=$ETC_DIR STATE_DIR=$STATE_DIR RUN_DIR=$RUN_DIR BPFFS_ROOT=$BPFFS_ROOT FINISH_DIR=$FINISH_DIR
ExecStart=/bin/bash $FINISH_DIR/uninstall.sh ${args[*]}

[Install]
WantedBy=multi-user.target
EOT
    systemctl daemon-reload 2>/dev/null || true
    systemctl enable "$FINISH_UNIT" 2>/dev/null || true
    echo "uninstall.sh: both units disabled; the removal finishes at the next boot ($FINISH_UNIT)."
    echo "uninstall.sh: REBOOT NOW to finish: sudo systemctl reboot"
    echo "uninstall.sh: afterwards: journalctl -b -u $FINISH_UNIT shows what was removed."
    exit 3
}
# The one-shot's own removal, at the end of a run at boot.
finish_done() {
    systemctl disable "$FINISH_UNIT" 2>/dev/null || true
    rm -f "$UNIT_DIR/$FINISH_UNIT"
    rm -rf "$FINISH_DIR"
    systemctl daemon-reload 2>/dev/null || true
}
# <<< finish_at_boot

# External audit DEP-006: the drain gate used to wait for "no LSM program on
# the host", a count that includes every other product's BPF-LSM programs:
# on such a host it never reached 0 and the uninstall stopped halfway. It
# waits for the agent's own program ids now, read before the stop.
# Numeric first fields only: the list goes to bpftool as arguments.
read_own_prog_ids() {
    [[ -r "$OWN_IDS_FILE" ]] || return 0
    awk '$1 ~ /^[0-9]+$/ {print $1}' "$OWN_IDS_FILE" | sort -un | tr '\n' ' '
}
# The ids among $1 still loaded. Only "No such file or directory" counts as
# unloaded; any other bpftool error keeps the id on the list.
own_progs_loaded() {
    local id out left=()
    for id in $1; do
        if out=$(LC_ALL=C bpftool prog show id "$id" 2>&1); then
            left+=("$id")
        elif [[ "$out" != *"No such file or directory"* ]]; then
            left+=("$id")
        fi
    done
    echo "${left[*]:-}"
}
# ── 0. stale pins (external audit DEP-020) ───────────────────────────
# Both units inactive and the pin root of the last agent still there: one
# nothing protects any more goes now (step 2 would remove it anyway); a
# protected one needs the window, which opens only through a running agent
# — before nothing is disabled or removed. Not for --package: the package
# manager already removed the agent.
STARTED_FOR_WINDOW=0
units_inactive() {
    local u state
    for u in northnarrow-watchdog northnarrow-agent; do
        state=$(systemctl is-active "$u.service" 2>/dev/null || true)
        [[ -z "$state" || "$state" == inactive ]] || return 1
    done
    return 0
}
# Lot 277 (the re-review of #494, R2): the start-in-cgroup tracker's pin
# directories, beside the pin root (an upgrade leaves them; the uninstall
# removes them with it). Lot 280a: and the cgroup/sysctl judge's, whose
# link removed detaches it from the root cgroup. Lot 285: and the module
# files' write history's (its maps, its observer on file_open).
tracker_pin_dirs() {
    local d
    for d in "$BPFFS_ROOT"-cgroup-join-v* "$BPFFS_ROOT"-sysctl "$BPFFS_ROOT"-module-writes; do
        [[ -d "$d" ]] && echo "$d"
    done
    return 0
}
pins_present() {
    [[ -d "$BPFFS_ROOT" || -n "$(tracker_pin_dirs)" ]]
}
remove_pins() {
    local d
    rm -rf "$BPFFS_ROOT" 2>/dev/null || true
    for d in $(tracker_pin_dirs); do
        rm -rf "$d" 2>/dev/null || true
    done
}
# >>> nn_lsm_holders (run by xtask/tests/install_scripts.rs)
# Lot 350 (F2-5): what of NorthNarrow can hold one of its LSM programs —
# when the run starts, its pin root (or the tracker's beside it) or a process
# of its units (NN_HELD); at the wait, a process running a NorthNarrow binary
# (an e2e or a manual run, its file deleted or not). A purge after an
# uninstall that kept the state had none of them, no list of the agent's
# programs either (it went with /run/northnarrow), and waited for every LSM
# program on the host: systemd's own (RestrictFileSystems=, Debian 13)
# never detach, and the purge failed with the state left.
nn_procs_running() {
    local e
    for e in "${PROC_ROOT:-/proc}"/[0-9]*/exe; do
        e=$(readlink "$e" 2>/dev/null) || continue
        case "${e##*/}" in
            northnarrow-agent* | northnarrow-watchdog*) return 0 ;;
        esac
    done
    return 1
}
# <<< nn_lsm_holders
NN_HELD=0
if pins_present || nn_unit_has_procs northnarrow-agent || nn_unit_has_procs northnarrow-watchdog; then
    NN_HELD=1
fi
if (( ! PACKAGE )) && pins_present && units_inactive; then
    log "units inactive but $BPFFS_ROOT (or the tracker's pins beside it) exists — removing the stale pins first"
    remove_pins
    if pins_present; then
        if [[ -z "$GRANT_KEY" ]]; then
            stale_pin_root_help >&2
            exit 1
        fi
        [[ -r "$GRANT_KEY" ]] || { echo "uninstall.sh: --grant-key $GRANT_KEY is not readable" >&2; exit 1; }
        # lot 341: an agent that does not come up for the window is wedged
        start_agent_for_window || finish_at_boot "the installed agent did not come up for the window"
        STARTED_FOR_WINDOW=1
    fi
fi

own_ids=$(read_own_prog_ids)

# ── 1. units ──────────────────────────────────────────────────────────
# Lot 341: an active agent that does not answer cannot open a window: the
# removal is finished at the next boot (finish_at_boot), with or without a
# key. Not for --package (the package manager already stopped it) nor at
# boot (the units are disabled then: nothing runs).
if (( ! PACKAGE && ! AT_BOOT )) && systemctl is-active --quiet northnarrow-agent.service && ! agent_answers; then
    finish_at_boot "northnarrow-agent.service is active but does not answer nn-admin status within ${ANSWER_TIMEOUT}s"
fi
# The pin root is protected by the running agent (review entry 39): open the
# trusted-installer window first, while the agent still answers.
if [[ -n "$GRANT_KEY" ]] && systemctl is-active --quiet northnarrow-agent.service; then
    log "opening the trusted-installer window (300 s) with $GRANT_KEY"
    # Lot 278: for this script's own tree, when the installed nn-admin knows
    # the flag (see install.sh)
    for_installer=()
    # (read whole, not piped into `grep -q`: under pipefail its early exit
    # could fail the pipeline)
    local_help=$("$BIN_DIR/nn-admin" help trusted-installer-grant 2>/dev/null || true)
    if [[ $local_help == *--for-installer* ]]; then
        for_installer=(--for-installer)
    fi
    if ! timeout 60 "$BIN_DIR/nn-admin" trusted-installer-grant ${for_installer[@]+"${for_installer[@]}"} --key "$GRANT_KEY" --window-secs 300; then
        echo "uninstall.sh: trusted-installer grant REFUSED (key without the trusted-installer role?)" >&2
        (( STARTED_FOR_WINDOW )) &&
            echo "uninstall.sh: the agent started for the window keeps running (its stop needs the window)" >&2
        exit 1
    fi
fi
# Stopped first, disabled once both are stopped. Outside a window the
# anti-tamper refuses systemd's signals (external audit EBPF-001): the units
# used to be disabled anyway, still running, and the script stopped at the
# pin root with the host half-uninstalled. Now it stops here, before any
# disable or removal (--package: the pre-removal hook already stopped the
# units; reported, the removal goes on).
for u in northnarrow-watchdog northnarrow-agent; do
    if systemctl list-unit-files "$u.service" >/dev/null 2>&1; then
        log "stopping $u"
        stop_nn_unit "$u"
    fi
done
still=()
for u in northnarrow-watchdog northnarrow-agent; do
    for ((i = 0; i < 10; i++)); do
        nn_unit_has_procs "$u" || break
        sleep 0.5
    done
    if nn_unit_has_procs "$u"; then still+=("$u"); fi
done
if (( ${#still[@]} )); then
    echo "uninstall.sh: still running: ${still[*]} — the anti-tamper refuses their stop outside a trusted-installer" >&2
    echo "uninstall.sh: window (external audit EBPF-001)." >&2
    if (( ! PACKAGE )); then
        echo "uninstall.sh: nothing was disabled or removed. Re-run with --grant-key <admin key carrying the" >&2
        echo "uninstall.sh: trusted-installer role>." >&2
        exit 1
    fi
fi
for u in northnarrow-watchdog northnarrow-agent; do
    if systemctl list-unit-files "$u.service" >/dev/null 2>&1; then
        log "disabling $u"
        systemctl disable "$u.service" 2>/dev/null || true
    fi
done

# ── 2. LSM programs ───────────────────────────────────────────────────
if pins_present; then
    log "removing pinned maps/programs/links under $BPFFS_ROOT and the tracker's beside it"
    remove_pins
    if pins_present; then
        echo "uninstall.sh: $BPFFS_ROOT (or $BPFFS_ROOT-cgroup-join-v*, $BPFFS_ROOT-sysctl, $BPFFS_ROOT-module-writes) is PROTECTED by the anti-tamper and no trusted-installer window is open" >&2
        echo "uninstall.sh: (review entry 39). Start the agent again (systemctl start northnarrow-agent) and re-run" >&2
        echo "uninstall.sh: with --grant-key <admin.key carrying the trusted-installer role>; or, if the agent" >&2
        echo "uninstall.sh: refuses to start (exit 78: its key lost or hidden), follow INSTALL_UPGRADE_UNINSTALL.md" >&2
        echo "uninstall.sh: section 3.10, branch B: systemctl disable northnarrow-agent northnarrow-watchdog, archive," >&2
        echo "uninstall.sh: reboot (bpffs does not survive one), then re-run without --grant-key." >&2
        (( PACKAGE )) || exit 1
        echo "uninstall.sh: package removal continues; the pins detach at the next reboot" >&2
    fi
fi
if ! command -v bpftool >/dev/null 2>&1; then
    # The units' processes and the pin root are the only holders.
    for ((i = 0; i < LSM_DRAIN_TIMEOUT; i++)); do
        nn_unit_has_procs northnarrow-agent || nn_unit_has_procs northnarrow-watchdog || break
        sleep 1
    done
    if nn_unit_has_procs northnarrow-agent || nn_unit_has_procs northnarrow-watchdog; then
        echo "uninstall.sh: a NorthNarrow unit still has processes after ${LSM_DRAIN_TIMEOUT}s — stop them and re-run" >&2
        (( PACKAGE )) || exit 1
    fi
    log "bpftool not found — the agent and watchdog exited and the pin root is gone (the only holders of the"
    log "LSM programs); the unload itself cannot be confirmed"
elif [[ -n "$own_ids" ]]; then
    log "waiting for NorthNarrow's BPF programs to unload (ids: $own_ids)"
    left=$own_ids
    for ((i = 0; i < LSM_DRAIN_TIMEOUT; i++)); do
        left=$(own_progs_loaded "$own_ids")
        [[ -z "$left" ]] && break
        sleep 1
    done
    if [[ -n "$left" ]]; then
        echo "uninstall.sh: NorthNarrow BPF program(s) still loaded after ${LSM_DRAIN_TIMEOUT}s: ids $left" >&2
        echo "uninstall.sh: (bpftool prog show id <id>) — a NorthNarrow process still holds them" >&2
        echo "uninstall.sh: (ps aux | grep northnarrow). Stop it and re-run." >&2
        (( PACKAGE )) || exit 1
    fi
elif (( AT_BOOT )); then
    # Lot 341: the boot-time run of a wedged agent's removal — its units
    # were disabled before this boot and bpffs is new: no NorthNarrow program
    # can be loaded (other products' LSM programs are not ours to wait for).
    log "at boot, the units disabled since before it: no NorthNarrow BPF program is loaded"
elif (( ! NN_HELD )) && ! nn_procs_running; then
    # Lot 350 (F2-5): nothing of NorthNarrow could hold one (no pin root and
    # no unit process when the run started, no NorthNarrow process now): the
    # kernel unloaded the agent's programs with their last reference. Other
    # products' are not waited for (external audit DEP-006).
    log "no $OWN_IDS_FILE, and nothing of NorthNarrow holds an LSM program (no pin root or unit process at the start, no NorthNarrow process): other products' are not waited for"
else
    # An agent older than the list (or none ever ran): every LSM program on
    # the host, as before, naming what is left.
    log "no $OWN_IDS_FILE — waiting for every LSM program on the host to detach"
    for ((i = 0; i < LSM_DRAIN_TIMEOUT; i++)); do
        n=$(bpftool prog show 2>/dev/null | grep -c " lsm " || true)
        [[ "$n" == 0 ]] && break
        (( i == 0 )) && log "waiting for $n LSM program(s) to detach"
        sleep 1
    done
    n=$(bpftool prog show 2>/dev/null | grep -c " lsm " || true)
    if [[ "$n" != 0 ]]; then
        echo "uninstall.sh: $n LSM program(s) still loaded after ${LSM_DRAIN_TIMEOUT}s:" >&2
        bpftool prog show 2>/dev/null | grep " lsm " | sed 's/^/uninstall.sh:   /' >&2
        echo "uninstall.sh: if they are NorthNarrow's, a NorthNarrow process still holds them" >&2
        echo "uninstall.sh: (ps aux | grep northnarrow). Stop it and re-run." >&2
        (( PACKAGE )) || exit 1
    fi
fi

# ── 3. immutable flags ────────────────────────────────────────────────
for d in "$STATE_DIR" "$ETC_DIR"; do
    if [[ -e "$d" ]] && command -v chattr >/dev/null 2>&1; then
        chattr -R -i "$d" 2>/dev/null || true
    fi
done

# ── 4. binaries, units, journald, baits, /run ─────────────────────────
for b in northnarrow-agent northnarrow-watchdog nn-admin northnarrow-scan; do
    [[ -e "$BIN_DIR/$b" ]] && { log "removing $BIN_DIR/$b"; rm -f "$BIN_DIR/$b"; }
done
# The agent's accounts (they own no file): lab PR 223's exec quarantine
# scanner, R14a's workers. Their processes ended with the agent (a worker
# dies with its core). userdel removes each one's own group too.
# >>> remove_users
for u in northnarrow-scan northnarrow-worker northnarrow-export; do
    if getent passwd "$u" >/dev/null 2>&1 && command -v userdel >/dev/null 2>&1; then
        log "removing the system account $u"
        userdel "$u" 2>/dev/null || log "userdel $u failed — remove it by hand"
    fi
done
# <<< remove_users
for u in northnarrow-agent northnarrow-watchdog northnarrow-watchdog-failed; do
    [[ -e "$UNIT_DIR/$u.service" ]] && { log "removing $UNIT_DIR/$u.service"; rm -f "$UNIT_DIR/$u.service"; }
done
# >>> rm_tree (run by xtask/tests/install_scripts.rs)
# Lot 351 (the review of #559, F4): a directory the uninstall removes from
# systemd's trees (/etc/systemd, /run/systemd, the journals) is never a
# mount point — `rm -rf` of a bind mount at that path emptied what it showed
# (only root can make one there): it is left, and said — and nothing below
# it on another file system is removed (`--one-file-system`).
rm_tree() {
    local d
    for d in "$@"; do
        [[ -e "$d" || -L "$d" ]] || continue
        if [[ ! -L "$d" ]] && mountpoint -q -- "$d" 2>/dev/null; then
            log "$d is a mount point: left in place"
            continue
        fi
        rm -rf --one-file-system -- "$d" 2>/dev/null || log "could not remove $d"
    done
    return 0
}
# <<< rm_tree
# Lot 273d: the units' slice and the drop-in directories its units' agent
# made (empty unless a drop-in was added in a window).
[[ -e "$UNIT_DIR/northnarrow.slice" ]] && { log "removing $UNIT_DIR/northnarrow.slice"; rm -f "$UNIT_DIR/northnarrow.slice"; }
rm_tree "$DROPIN_ROOT/northnarrow.slice.d" "${RUNTIME_DROPIN_ROOT:-/run/systemd/system}/northnarrow.slice.d" \
    /etc/systemd/system.control/northnarrow.slice.d /run/systemd/system.control/northnarrow.slice.d
rm_tree "$DROPIN_ROOT/northnarrow-agent.service.d" "$DROPIN_ROOT/northnarrow-watchdog.service.d"
# Lab PR 265: the runtime drop-in directory the unit makes before each start
# (empty unless a drop-in was added in a window).
rm_tree "${RUNTIME_DROPIN_ROOT:-/run/systemd/system}/northnarrow-agent.service.d"
# Lot 273b: the units' `set-property` drop-in directories the agent's unit
# makes before each start (empty unless a property was set in a window).
for d in /etc/systemd/system.control /run/systemd/system.control; do
    rm_tree "$d/northnarrow-agent.service.d" "$d/northnarrow-watchdog.service.d"
done
# The review of #490 (A): the watchdog's runtime drop-in directory and the
# `northnarrow-.service.d` prefix ones the agent's unit makes before each
# start (empty unless a drop-in was added in a window).
rm_tree "${RUNTIME_DROPIN_ROOT:-/run/systemd/system}/northnarrow-watchdog.service.d" \
    "${RUNTIME_DROPIN_ROOT:-/run/systemd/system}/northnarrow-.service.d" \
    "$DROPIN_ROOT/northnarrow-.service.d"
if [[ -e "$JOURNALD_NS_CONF" ]]; then
    log "removing $JOURNALD_NS_CONF"
    rm -f "$JOURNALD_NS_CONF"
    rm_tree "${JOURNALD_NS_CONF}.d"
    systemctl stop systemd-journald@northnarrow.service 2>/dev/null || true
    systemctl stop systemd-journald@northnarrow.socket 2>/dev/null || true
    # Lot 350 (F2-5, the mini-hunt): the namespace's varlink socket too
    systemctl stop systemd-journald-varlink@northnarrow.socket 2>/dev/null || true
fi
# Lot 350 (F2-5, the mini-hunt): the namespace's runtime directory (its
# sockets, /run's tmpfs) outlived the stop until the next boot. Its journal
# files are elsewhere (/var/log/journal, /run/log/journal: --purge below).
if [[ -d "$JOURNALD_NS_RUNTIME" ]]; then
    log "removing $JOURNALD_NS_RUNTIME"
    rm_tree "$JOURNALD_NS_RUNTIME"
fi
# Tappa 9.5.1 control-surface baits: inert files the install dropped
# across /etc, /var/lib and /run. Remove them even when config/state
# are kept — they mean nothing without the agent watching them.
for f in "$ETC_DIR"/{agent.dev.lock,kill_switch.conf,maintenance.mode,debug_disable.flag,agent.legacy.conf} \
         "$STATE_DIR"/{shutdown.signal,disable.token,override.config} \
         "$RUN_DIR"/{pause.flag,unload.signal}; do
    [[ -e "$f" ]] && rm -f "$f"
done
# Lot 351 (the review of #559, F3): the agent's record of the processes it
# contained, and where each came from, for stop_slice's word (below) — it
# goes with $RUN_DIR. Printable characters only (a cgroup's name is any).
CONTAINMENT_RECORD=$(tr -cd '[:print:]' 2>/dev/null < "$RUN_DIR/containment.json" || true)
[[ -d "$RUN_DIR" ]] && { log "removing $RUN_DIR"; rm -rf "$RUN_DIR"; }
# Lot 302: the deny self-test's throwaway cgroup (removed after each round;
# left by an agent stopped in the middle of one) and the boot's move-guard
# self-test's (lot 273b) — empty, at the cgroup v2 root.
for d in /sys/fs/cgroup/northnarrow-deny-selftest /sys/fs/cgroup/northnarrow-move-selftest; do
    if [[ -d "$d" ]] && rmdir "$d" 2>/dev/null; then log "removed $d"; fi
done
systemctl daemon-reload
# >>> stop_slice (run by xtask/tests/install_scripts.rs)
# Lot 350 (F2-5): the units' slice outlived its file until the next boot —
# loaded, active, its cgroup there. Its file is gone at the reload above, and
# with it its RefuseManualStop=: stopped now (both units are stopped), then
# forgotten. The empty `system.control` directories the agent's unit made
# the parents of (`mkdir -p` before every start, their children removed
# above) go too (lot 351: only those `system_control_dirs` names); one that
# holds anything stays.
#
# Lot 351 (the review of #559, F3): the agent's containment is under the
# slice as well — `blocked.scope` and `throttled.scope`, cgroups the agent
# makes itself (no units: systemd does not stop them). Each one empty is
# removed first. One that still holds a process the agent contained stays,
# named with its processes and the agent's record of where each came from,
# and the slice is then not stopped: the uninstall kills nothing (it has no
# verdict on them) and releases nothing (that is the operator's decision,
# `nn-admin` before the uninstall: it hands a process the agent judged back
# its unit and its network, with nothing left to watch it). Such a process
# stays in that cgroup, outside any unit, until it exits or the next boot —
# throttled, under the scope's limits; blocked, its block gone with the
# agent's nftables table.
stop_slice() {
    local state d scope pids held=0
    for scope in blocked throttled; do
        d=$SLICE_CGROUP/$scope.scope
        [[ -d "$d" ]] || continue
        if rmdir "$d" 2>/dev/null; then
            log "removed the empty $d"
            continue
        fi
        pids=$(tr -s '\n' ' ' 2>/dev/null < "$d/cgroup.procs" || true)
        log "$d holds processes the agent contained (pids: ${pids:-?}): left in it, not killed nor released"
        held=1
    done
    if (( held )); then
        if [[ -n "${CONTAINMENT_RECORD:-}" ]]; then
            log "where each came from (the agent's containment record): $CONTAINMENT_RECORD"
        fi
        log "northnarrow.slice is not stopped while they are in it: it goes at the next boot"
    else
        state=$(systemctl show -p ActiveState --value northnarrow.slice 2>/dev/null || true)
        if [[ -n "$state" && "$state" != inactive ]]; then
            if systemctl stop northnarrow.slice 2>/dev/null; then
                log "stopped northnarrow.slice"
            else
                log "northnarrow.slice did not stop ($state): it goes at the next boot"
            fi
        fi
        systemctl reset-failed northnarrow.slice 2>/dev/null || true
    fi
    for d in "${SYSTEM_CONTROL_DIRS[@]}"; do
        if [[ -d "$d" ]] && rmdir "$d" 2>/dev/null; then log "removed the empty $d"; fi
    done
    return 0
}
# <<< stop_slice
# >>> system_control_dirs (run by xtask/tests/install_scripts.rs)
# Lot 351 (the review of #559, F5): the `system.control` directories
# stop_slice may remove, empty. /run's is this boot's (tmpfs: systemd makes
# it again whenever a runtime property needs one). /etc's only when the
# first install recorded that the host had none (`made-dirs`, install.sh's
# `record_made_dirs`): one the host had before stays, even empty. An install
# older than lot 351 recorded nothing: removed when empty, as before.
system_control_dirs() {   # <made-dirs record> <etc's dir> <run's dir>
    SYSTEM_CONTROL_DIRS=("$3")
    if [[ ! -e "$1" ]] || grep -qxF -- "$2" "$1" 2>/dev/null; then
        SYSTEM_CONTROL_DIRS+=("$2")
    fi
}
# <<< system_control_dirs
system_control_dirs "$ETC_DIR/made-dirs" /etc/systemd/system.control /run/systemd/system.control
SLICE_CGROUP=/sys/fs/cgroup/northnarrow.slice
stop_slice

# ── 5. config + state ─────────────────────────────────────────────────
BOOTSTRAP_KEY=/root/northnarrow-admin.key
# >>> kept_report (run by xtask/tests/install_scripts.rs)
# External audit DEP-012 (NN-AUD-384): an install older than external audit
# DEP-001 (lab PR 96) wrote the bootstrap private key into $ETC_DIR, which an
# uninstall without --purge keeps. The summary named only the current path:
# it names every private admin key it leaves (host-check, which knows both,
# is gone with nn-admin).
LEGACY_KEY=$ETC_DIR/admin.key
kept_report() {
    echo ""
    echo "Kept (evidence + identity — remove with --purge if this host is being retired):"
    if [[ -e "$ETC_DIR" ]]; then
        echo "  $ETC_DIR    (admin.pub, agent.sig.key, audit.log, agent_id, rule files)"
    fi
    if [[ -e "$STATE_DIR" ]]; then
        echo "  $STATE_DIR  (FIM / canary / netflow / detections chain logs)"
    fi
    local k
    for k in "$BOOTSTRAP_KEY" "$LEGACY_KEY"; do
        if [[ -f "$k" ]]; then
            echo "  $k  (admin PRIVATE key still on this host — move it offline)"
        fi
    done
    return 0
}
# <<< kept_report
if (( PURGE )); then
    if [[ -f "$LEGACY_KEY" ]]; then
        log "PURGE: removing the admin private key $LEGACY_KEY (an install before external audit DEP-001)"
    fi
    # lot 276: the export's JSONL files (copies of what the chains held)
    for d in "$ETC_DIR" "$STATE_DIR" "$UPGRADE_TXN_ROOT" "${EXPORT_DIR:-/var/log/northnarrow/export}"; do
        [[ -e "$d" ]] && { log "PURGE: removing $d"; rm -rf "$d"; }
    done
    # >>> export_parent (run by xtask/tests/install_scripts.rs)
    # Lot 350 (F2-5, the mini-hunt): the export's parent install.sh made
    # (/var/log/northnarrow), when nothing else is in it
    d=$(dirname "${EXPORT_DIR:-/var/log/northnarrow/export}")
    if [[ ${d##*/} == northnarrow && -d "$d" ]] && rmdir "$d" 2>/dev/null; then
        log "PURGE: removed $d"
    fi
    # <<< export_parent
    # Its admin.pub line went with $ETC_DIR: the key opens nothing here any
    # more, and a reinstall bootstraps a new one at the same path.
    [[ -f "$BOOTSTRAP_KEY" ]] && { log "PURGE: removing the bootstrap admin private key $BOOTSTRAP_KEY"; rm -f "$BOOTSTRAP_KEY"; }
    for j in /var/log/journal/*.northnarrow /run/log/journal/*.northnarrow; do
        [[ -e "$j" ]] && { log "PURGE: removing namespace journal $j"; rm_tree "$j"; }
    done
else
    kept_report
fi

# Lot 341: the boot-time run of a wedged agent's removal removes itself.
if (( AT_BOOT )); then
    finish_done
fi

echo ""
log "uninstall complete."
