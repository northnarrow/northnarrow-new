#!/bin/sh
# NorthNarrow package pre-removal hook (deb prerm / rpm %preun). On removal,
# stop the agent and drop its pins with the trusted-installer window (same key
# rules as the pre-unpack hook); on upgrade the new package's pre-unpack hook
# does it. Without the key the removal stops here and the agent keeps running.
set -e
case "${1:-}" in
    remove|deconfigure|0) ;;
    *) exit 0 ;;
esac
rc=0
BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system REPO_ROOT=/usr/share/northnarrow \
    bash /usr/share/northnarrow/deploy/install.sh --package-stop || rc=$?
if [ "$rc" -ne 0 ]; then
    echo "northnarrow: could not stop the running agent; the package stays installed." >&2
    echo "northnarrow:   NN_GRANT_KEY=/path/to/admin.key <package command>" >&2
    exit "$rc"
fi
rm -f /run/northnarrow-pkg-restart
systemctl disable northnarrow-watchdog.service northnarrow-agent.service >/dev/null 2>&1 || true
exit 0
