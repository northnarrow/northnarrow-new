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
#      wait until the kernel reports 0 LSM programs (anything still
#      holding an fd keeps denying the unlinks below);
#   3. lift chattr +i from the state directory (the agent sets it at boot);
#   4. remove binaries, units, the journald namespace config, /run and the
#      10 inert control-surface bait files;
#   5. keep /etc/northnarrow (admin.pub, agent.sig.key, audit.log,
#      agent_id, rule files) and /var/lib/northnarrow (FIM / canary /
#      netflow / detections chain logs) unless --purge is given: the
#      signed audit chain and the admin key are evidence and identity,
#      an uninstall must not destroy them by default.
#
# Usage:
#   sudo ./deploy/uninstall.sh            # binaries + units, keep config/state
#   sudo ./deploy/uninstall.sh --purge    # also /etc/northnarrow, /var/lib/northnarrow,
#                                         # the namespace journal — NOTHING is kept
#   sudo ./deploy/uninstall.sh --yes      # no confirmation prompt
#
# Same BIN_DIR / UNIT_DIR / ETC_DIR / STATE_DIR overrides as install.sh.

set -euo pipefail

BIN_DIR=${BIN_DIR:-/usr/local/bin}
UNIT_DIR=${UNIT_DIR:-/etc/systemd/system}
ETC_DIR=${ETC_DIR:-/etc/northnarrow}
STATE_DIR=${STATE_DIR:-/var/lib/northnarrow}
RUN_DIR=${RUN_DIR:-/run/northnarrow}
BPFFS_ROOT=${BPFFS_ROOT:-/sys/fs/bpf/northnarrow}
JOURNALD_NS_CONF=/etc/systemd/journald@northnarrow.conf
LSM_DRAIN_TIMEOUT=${LSM_DRAIN_TIMEOUT:-30}

PURGE=0
YES=0
for arg in "$@"; do
    case "$arg" in
        --purge) PURGE=1 ;;
        --yes|-y) YES=1 ;;
        -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "uninstall.sh: unknown argument: $arg" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "uninstall.sh: must run as root (sudo)" >&2; exit 1; }

log() { echo "uninstall.sh: $*"; }

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

# ── 1. units ──────────────────────────────────────────────────────────
for u in northnarrow-watchdog northnarrow-agent; do
    if systemctl list-unit-files "$u.service" >/dev/null 2>&1; then
        log "stopping + disabling $u"
        systemctl disable --now "$u.service" 2>/dev/null || systemctl stop "$u.service" 2>/dev/null || true
    fi
done

# ── 2. LSM programs ───────────────────────────────────────────────────
if [[ -d "$BPFFS_ROOT" ]]; then
    log "removing pinned maps/programs/links under $BPFFS_ROOT"
    rm -rf "$BPFFS_ROOT"
fi
if command -v bpftool >/dev/null 2>&1; then
    for ((i = 0; i < LSM_DRAIN_TIMEOUT; i++)); do
        n=$(bpftool prog show 2>/dev/null | grep -c " lsm " || true)
        [[ "$n" == 0 ]] && break
        (( i == 0 )) && log "waiting for $n LSM program(s) to detach"
        sleep 1
    done
    n=$(bpftool prog show 2>/dev/null | grep -c " lsm " || true)
    if [[ "$n" != 0 ]]; then
        echo "uninstall.sh: $n LSM program(s) still loaded after ${LSM_DRAIN_TIMEOUT}s — a NorthNarrow process" >&2
        echo "uninstall.sh: still holds them (ps aux | grep northnarrow). Stop it and re-run." >&2
        exit 1
    fi
else
    log "bpftool not found — cannot confirm the LSM programs detached; continuing"
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
rm -rf "$UNIT_DIR/northnarrow-agent.service.d" "$UNIT_DIR/northnarrow-watchdog.service.d" 2>/dev/null || true
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
if (( PURGE )); then
    for d in "$ETC_DIR" "$STATE_DIR"; do
        [[ -e "$d" ]] && { log "PURGE: removing $d"; rm -rf "$d"; }
    done
    for j in /var/log/journal/*.northnarrow /run/log/journal/*.northnarrow; do
        [[ -e "$j" ]] && { log "PURGE: removing namespace journal $j"; rm -rf "$j"; }
    done
else
    echo ""
    echo "Kept (evidence + identity — remove with --purge if this host is being retired):"
    [[ -e "$ETC_DIR" ]]   && echo "  $ETC_DIR    (admin.pub, agent.sig.key, audit.log, agent_id, rule files)"
    [[ -e "$STATE_DIR" ]] && echo "  $STATE_DIR  (FIM / canary / netflow / detections chain logs)"
fi

echo ""
log "uninstall complete."
