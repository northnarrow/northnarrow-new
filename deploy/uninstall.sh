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
LSM_DRAIN_TIMEOUT=${LSM_DRAIN_TIMEOUT:-30}
# External audit DEP-006: the ids of the agent's loaded BPF programs, written
# by the agent next to its pid file (anti_tamper/bpf_defense.rs).
OWN_IDS_FILE=${OWN_IDS_FILE:-$RUN_DIR/bpf-own-ids}

PURGE=0
YES=0
PACKAGE=0
GRANT_KEY=
expect_key=0
for arg in "$@"; do
    if (( expect_key )); then GRANT_KEY=$arg; expect_key=0; continue; fi
    case "$arg" in
        --purge) PURGE=1 ;;
        --yes|-y) YES=1 ;;
        --package) PACKAGE=1 ;;
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
    local cg
    cg=$(systemctl show -p ControlGroup --value "$1.service" 2>/dev/null)
    cg=${cg:-/system.slice/$1.service}
    [[ -n "$(cat "/sys/fs/cgroup$cg/cgroup.procs" 2>/dev/null)" ]]
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
echo "  binaries : $BIN_DIR/{northnarrow-agent,northnarrow-watchdog,nn-admin}"
echo "  units    : $UNIT_DIR/northnarrow-{agent,watchdog}.service"
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
if (( ! PACKAGE )) && [[ -d "$BPFFS_ROOT" ]] && units_inactive; then
    log "units inactive but $BPFFS_ROOT exists — removing the stale pins first"
    rm -rf "$BPFFS_ROOT" 2>/dev/null || true
    if [[ -d "$BPFFS_ROOT" ]]; then
        if [[ -z "$GRANT_KEY" ]]; then
            stale_pin_root_help >&2
            exit 1
        fi
        [[ -r "$GRANT_KEY" ]] || { echo "uninstall.sh: --grant-key $GRANT_KEY is not readable" >&2; exit 1; }
        start_agent_for_window || exit 1
        STARTED_FOR_WINDOW=1
    fi
fi

own_ids=$(read_own_prog_ids)

# ── 1. units ──────────────────────────────────────────────────────────
# The pin root is protected by the running agent (review entry 39): open the
# trusted-installer window first, while the agent still answers.
if [[ -n "$GRANT_KEY" ]] && systemctl is-active --quiet northnarrow-agent.service; then
    log "opening the trusted-installer window (300 s) with $GRANT_KEY"
    if ! "$BIN_DIR/nn-admin" trusted-installer-grant --key "$GRANT_KEY" --window-secs 300; then
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
if [[ -d "$BPFFS_ROOT" ]]; then
    log "removing pinned maps/programs/links under $BPFFS_ROOT"
    rm -rf "$BPFFS_ROOT" 2>/dev/null || true
    if [[ -d "$BPFFS_ROOT" ]]; then
        echo "uninstall.sh: $BPFFS_ROOT is PROTECTED by the anti-tamper and no trusted-installer window is open" >&2
        echo "uninstall.sh: (review entry 39). Start the agent again (systemctl start northnarrow-agent) and re-run" >&2
        echo "uninstall.sh: with --grant-key <admin.key carrying the trusted-installer role>." >&2
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
for b in northnarrow-agent northnarrow-watchdog nn-admin; do
    [[ -e "$BIN_DIR/$b" ]] && { log "removing $BIN_DIR/$b"; rm -f "$BIN_DIR/$b"; }
done
for u in northnarrow-agent northnarrow-watchdog; do
    [[ -e "$UNIT_DIR/$u.service" ]] && { log "removing $UNIT_DIR/$u.service"; rm -f "$UNIT_DIR/$u.service"; }
done
rm -rf "$DROPIN_ROOT/northnarrow-agent.service.d" "$DROPIN_ROOT/northnarrow-watchdog.service.d" 2>/dev/null || true
if [[ -e "$JOURNALD_NS_CONF" ]]; then
    log "removing $JOURNALD_NS_CONF"
    rm -f "$JOURNALD_NS_CONF"
    rm -rf "${JOURNALD_NS_CONF}.d" 2>/dev/null || true
    systemctl stop systemd-journald@northnarrow.service 2>/dev/null || true
    systemctl stop systemd-journald@northnarrow.socket 2>/dev/null || true
fi
# Tappa 9.5.1 control-surface baits: inert files the install dropped
# across /etc, /var/lib and /run. Remove them even when config/state
# are kept — they mean nothing without the agent watching them.
for f in "$ETC_DIR"/{agent.dev.lock,kill_switch.conf,maintenance.mode,debug_disable.flag,agent.legacy.conf} \
         "$STATE_DIR"/{shutdown.signal,disable.token,override.config} \
         "$RUN_DIR"/{pause.flag,unload.signal}; do
    [[ -e "$f" ]] && rm -f "$f"
done
[[ -d "$RUN_DIR" ]] && { log "removing $RUN_DIR"; rm -rf "$RUN_DIR"; }
systemctl daemon-reload

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
    for d in "$ETC_DIR" "$STATE_DIR"; do
        [[ -e "$d" ]] && { log "PURGE: removing $d"; rm -rf "$d"; }
    done
    # Its admin.pub line went with $ETC_DIR: the key opens nothing here any
    # more, and a reinstall bootstraps a new one at the same path.
    [[ -f "$BOOTSTRAP_KEY" ]] && { log "PURGE: removing the bootstrap admin private key $BOOTSTRAP_KEY"; rm -f "$BOOTSTRAP_KEY"; }
    for j in /var/log/journal/*.northnarrow /run/log/journal/*.northnarrow; do
        [[ -e "$j" ]] && { log "PURGE: removing namespace journal $j"; rm -rf "$j"; }
    done
else
    kept_report
fi

echo ""
log "uninstall complete."
