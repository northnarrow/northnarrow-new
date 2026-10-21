#!/bin/sh
# NorthNarrow package post-unpack hook (deb postinst / rpm %post): configure
# the host exactly as install.sh does (journald namespace, seeded configs,
# admin keypair on a first install, state dirs, bait files, install manifest)
# and start again the units the pre-unpack hook stopped. A first install does
# not start anything: the operator enables the units explicitly.
set -e
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
# Lab PR 220: the configure step checks the health of the units it restarted
# (install.sh pkg_health_or_fail) and fails the hook when they do not pass:
# dpkg reports the package half-configured. The rpm runs the same check in
# its %posttrans, once the whole transaction — the old package's scriptlets
# included — is over (posttrans.sh).
case "${1:-}" in
    configure)
        BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system REPO_ROOT=/usr/share/northnarrow \
            bash /usr/share/northnarrow/deploy/install.sh --package-configure
        ;;
    1|2)
        BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system REPO_ROOT=/usr/share/northnarrow \
            bash /usr/share/northnarrow/deploy/install.sh --package-configure --defer-health-check
        ;;
    abort-upgrade|abort-remove|abort-deconfigure)
        # the operation failed after the units were stopped: bring them back
        restart_stopped || exit 1
        ;;
esac
exit 0
