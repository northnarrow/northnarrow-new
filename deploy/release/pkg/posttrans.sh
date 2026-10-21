#!/bin/sh
# NorthNarrow rpm %posttrans (lab PR 220; static review of baf4c25 App.D
# C-46). It runs once the whole rpm transaction is over — the new package's
# %post restarted the units, the old package's %preun and %postun ran after
# it — and checks the health of the units %post restarted (install.sh
# --package-verify: active, every deny hook attached, the admin socket
# answering, the watchdog registered in PROTECTED_PIDS). An upgrade that
# does not pass fails this scriptlet: rpm and dnf report it, the reason is on
# the terminal and in the system log (auth.err, tag northnarrow-pkg). rpm
# cannot restore the previous package at this point (it has no rollback):
# install it again with NN_GRANT_KEY set (docs/operator/INSTALL_UPGRADE_UNINSTALL.md
# §6.2). A first install restarted nothing and checks nothing.
[ -f /usr/share/northnarrow/deploy/install.sh ] || exit 0
BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system REPO_ROOT=/usr/share/northnarrow \
    bash /usr/share/northnarrow/deploy/install.sh --package-verify || exit 1
exit 0
