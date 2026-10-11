#!/bin/sh
# NorthNarrow package post-unpack hook (deb postinst / rpm %post): configure
# the host exactly as install.sh does (journald namespace, seeded configs,
# admin keypair on a first install, state dirs, bait files, install manifest)
# and start again the units the pre-unpack hook stopped. A first install does
# not start anything: the operator enables the units explicitly.
set -e
restart_stopped() {
    [ -s /run/northnarrow-pkg-restart ] || return 0
    for u in northnarrow-agent northnarrow-watchdog; do
        if grep -qx "$u" /run/northnarrow-pkg-restart; then
            systemctl start "$u.service" || true
            [ "$u" = northnarrow-agent ] && sleep 3
        fi
    done
    rm -f /run/northnarrow-pkg-restart
}
case "${1:-}" in
    configure|1|2)
        BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system REPO_ROOT=/usr/share/northnarrow \
            bash /usr/share/northnarrow/deploy/install.sh --package-configure
        ;;
    abort-upgrade|abort-remove|abort-deconfigure)
        # the operation failed after the units were stopped: bring them back
        restart_stopped
        ;;
esac
exit 0
