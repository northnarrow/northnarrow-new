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
case "${1:-}" in
    # the files are already gone: a failed cleanup is reported, it does not
    # leave the package half-removed
    remove|0) cleanup || echo "northnarrow: cleanup incomplete" >&2 ;;
    purge) cleanup --purge || echo "northnarrow: purge incomplete" >&2 ;;
    abort-install|abort-upgrade)
        # our pre-unpack hook stopped a previous install, then the operation failed
        if [ -s /run/northnarrow-pkg-restart ]; then
            for u in northnarrow-agent northnarrow-watchdog; do
                grep -qx "$u" /run/northnarrow-pkg-restart && systemctl start "$u.service" || true
            done
            rm -f /run/northnarrow-pkg-restart
        fi
        ;;
esac
exit 0
