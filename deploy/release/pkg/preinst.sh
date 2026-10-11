#!/bin/sh
# NorthNarrow package pre-unpack hook (deb preinst / rpm %pre).
# A running NorthNarrow — an older package or an install.sh install — protects
# its binaries, units and pin root with LSM hooks, so the package manager could
# not replace them. Stop it the way install.sh --upgrade does: trusted-installer
# window, watchdog then agent, drop /sys/fs/bpf/northnarrow, wait for the hooks
# to detach. The window needs a key with the trusted-installer role: NN_GRANT_KEY,
# or /etc/northnarrow/admin.key while it is still on the host. Without it the
# operation stops here, before any file changes, and the old version keeps running.
set -e
case "${1:-}" in
    install|upgrade|1|2) ;;
    *) exit 0 ;;
esac
if [ -x /usr/bin/nn-admin ]; then bindir=/usr/bin
elif [ -x /usr/local/bin/nn-admin ]; then bindir=/usr/local/bin
else exit 0   # nothing installed yet
fi
script=$(mktemp /run/nn-pkg-install.XXXXXX)
cat > "$script" <<'NN_INSTALL_SH'
@INSTALL_SH@
NN_INSTALL_SH
rc=0
BIN_DIR="$bindir" REPO_ROOT=/nonexistent bash "$script" --package-stop || rc=$?
rm -f "$script"
if [ "$rc" -ne 0 ]; then
    echo "northnarrow: could not stop the running agent for the package operation." >&2
    echo "northnarrow: open the trusted-installer window first, e.g.:" >&2
    echo "northnarrow:   NN_GRANT_KEY=/path/to/admin.key <package command>" >&2
    echo "northnarrow:   or: $bindir/nn-admin trusted-installer-grant --key <admin.key> --window-secs 600" >&2
fi
exit "$rc"
