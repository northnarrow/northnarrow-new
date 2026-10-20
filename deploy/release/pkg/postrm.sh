#!/bin/sh
# NorthNarrow package post-removal hook (deb postrm / rpm %postun). The package
# files are gone by now, so the cleanup script travels inside this hook. Remove
# keeps /etc/northnarrow and /var/lib/northnarrow (signed audit chain, keys,
# agent identity); a Debian purge removes them too.
set -e
cleanup() {
    script=$(mktemp /run/nn-pkg-uninstall.XXXXXX)
    cat > "$script" <<'NN_UNINSTALL_SH'
@UNINSTALL_SH@
NN_UNINSTALL_SH
    rc=0
    BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system bash "$script" --package --yes "$@" || rc=$?
    rm -f "$script"
    return "$rc"
}
# >>> restart_stopped (the same text in postinst.sh and postrm.sh; a test keeps them equal)
# A failed package operation started again the units the pre-unpack hook
# stopped (their names in the restart list), agent first. External audit
# DEP-010 (NN-AUD-382): each start was `|| true`, so a unit that did not
# come back left the host without NorthNarrow behind a rollback that
# reported success. Now every listed unit must be active afterwards; one
# that is not is named on stderr (the package manager shows it) and in the
# system log (auth.err), the hook fails — the package manager reports the
# rollback as failed — and the list stays for the next attempt.
restart_stopped() {
    list=${PKG_RESTART_FILE:-/run/northnarrow-pkg-restart}
    [ -s "$list" ] || return 0
    for u in northnarrow-agent northnarrow-watchdog; do
        grep -qx "$u" "$list" || continue
        systemctl start "$u.service" || true
        if [ "$u" = northnarrow-agent ]; then sleep 3; fi
    done
    down=
    for u in northnarrow-agent northnarrow-watchdog; do
        grep -qx "$u" "$list" || continue
        state=$(systemctl is-active "$u.service" 2>/dev/null) || true
        [ "$state" = active ] || down="$down $u.service (${state:-unknown})"
    done
    if [ -n "$down" ]; then
        msg="rollback failed: not running after the restart:$down - this host is without NorthNarrow"
        echo "northnarrow: $msg." >&2
        echo "northnarrow: find the cause (systemctl status <unit>; journalctl --namespace=northnarrow -u <unit>), then start the agent, then the watchdog." >&2
        logger -p auth.err -t northnarrow-pkg -- "$msg" 2>/dev/null || true
        return 1
    fi
    rm -f "$list"
}
# <<< restart_stopped
case "${1:-}" in
    # the files are already gone: a failed cleanup is reported, it does not
    # leave the package half-removed
    remove|0) cleanup || echo "northnarrow: cleanup incomplete" >&2 ;;
    purge) cleanup --purge || echo "northnarrow: purge incomplete" >&2 ;;
    abort-install|abort-upgrade)
        # our pre-unpack hook stopped a previous install, then the operation failed
        restart_stopped || exit 1
        ;;
esac
exit 0
