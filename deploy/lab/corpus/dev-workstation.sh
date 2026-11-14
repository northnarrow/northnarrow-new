#!/usr/bin/env bash
# Lot 283a — benign corpus: a developer's workstation (uid 1000 in its ssh
# session, an authenticated session; sudo only for the packages). Builds and
# tests (a crate from a local git repository, a Go module, an npm project
# installed by npm, yarn, pnpm and bun (lot 346), a Python venv), formatters and file tools over trees of small files (cargo
# fmt, prettier --write, git checkout between two big branches, rsync
# --inplace) and an AppImage-style run (a squashfs image mounted under /tmp
# by squashfuse, its AppRun executed from the mount, then the
# --appimage-extract-and-run layout). Lab guests only; see corpus-lib.sh and
# docs/validation/BENIGN_CORPUS.md.
# usage: dev-workstation.sh      (NN_CORPUS_SMALLFILE=0: without the probe)
set -u
here=${BASH_SOURCE[0]%/*}
[[ $here == "${BASH_SOURCE[0]}" ]] && here=.
# shellcheck source=corpus-lib.sh
. "$here/corpus-lib.sh"
corpus_init dev

fuse_umount() { fusermount3 -u "$1" 2>/dev/null || fusermount -u "$1"; }

corpus_cleanup() {
    local m
    for m in /tmp/.mount_nncorpus*; do
        mountpoint -q "$m" 2>/dev/null && fuse_umount "$m" 2>/dev/null
    done
    rm -rf /tmp/.mount_nncorpus* /tmp/appimage_extracted_nncorpus* /tmp/nn-corpus-control
    chmod -R u+w "$W" 2>/dev/null
    sudo rm -rf "$W"
    sudo rmdir /srv/nn-corpus 2>/dev/null
    js_purge
    corpus_purge
    true
}

echo "== prepare (not measured)"
apt_need git golang-go nodejs npm python3-venv rsync squashfs-tools squashfuse fuse3 build-essential bpftrace
command -v cargo >/dev/null || echo "  no cargo for $LABUSER: the cargo steps fail"
prep_crate
prep_go
prep_npm
prep_js
# two branches of one big tree: 3,000 files (2,400 under 4 KiB), 80 % of
# them different on the other branch
(
    set -e
    mkdir -p "$W/big" && cd "$W/big" && git init -q -b a
    python3 -I - <<'EOF'
import os, random
random.seed(283)
for i in range(3000):
    d = "d%02d" % (i % 60)
    os.makedirs(d, exist_ok=True)
    n = random.randint(200, 3900) if i % 5 else random.randint(5000, 40000)
    with open("%s/f%04d.txt" % (d, i), "w") as f:
        f.write(("a%d " % i) * (n // 6))
EOF
    git add -A && git -c user.name=corpus -c user.email=corpus@example.invalid commit -qm a
    git checkout -q -b b
    python3 -I - <<'EOF'
import os
for i in range(3000):
    if i % 5 == 4:
        continue
    p = "d%02d/f%04d.txt" % (i % 60, i)
    with open(p, "a") as f:
        f.write(" b%d" % i)
EOF
    git add -A && git -c user.name=corpus -c user.email=corpus@example.invalid commit -qm b
    git checkout -q a
)
# rsync: a copy of a tree of 1,000 small files, then the source changed
mkdir -p "$W/rs/src"
python3 -I -c "
for i in range(1000):
    open('$W/rs/src/r%04d.cfg' % i, 'w').write('key%d = %s\n' % (i, 'x' * (i % 3000)))
"
rsync -a "$W/rs/src/" "$W/rs/dst/"
python3 -I -c "
for i in range(1000):
    open('$W/rs/src/r%04d.cfg' % i, 'a').write('changed = 1\n')
"
# the AppImage's payload: AppRun (a script) and a compiled program
mkdir -p "$W/app/AppDir/usr/bin"
printf '#include <stdio.h>\nint main(void){puts("nn-corpus app");return 0;}\n' > "$W/app/hello.c"
cc -O2 -o "$W/app/AppDir/usr/bin/nn-corpus-app" "$W/app/hello.c"
printf '#!/bin/sh\nHERE=$(dirname "$(readlink -f "$0")")\nexec "$HERE/usr/bin/nn-corpus-app" "$@"\n' > "$W/app/AppDir/AppRun"
chmod +x "$W/app/AppDir/AppRun"
mksquashfs "$W/app/AppDir" "$W/app/nn-corpus.squashfs" -quiet -noappend -all-root >/dev/null

echo "== measure"
smallfile_start
corpus_settle
corpus_mark
wl_cargo session dev
step "dev cargo fmt (120 unformatted modules)" 300 -- env CARGO_HOME="$W/cache/cargo" bash -c "cd $W/crate && cargo fmt"
wl_go session dev
wl_npm session dev
wl_js session dev
step "dev prettier --write (300 small files)" 300 -- bash -c "cd $W/web && ./node_modules/.bin/prettier --write --loglevel warn src"
wl_pip session dev
step "dev git checkout b (2,400 of 3,000 differ)" 300 -- git -C "$W/big" checkout -q b
step "dev git checkout a (back)" 300 -- git -C "$W/big" checkout -q a
step "dev rsync -a --inplace (1,000 small files)" 300 -- rsync -a --inplace "$W/rs/src/" "$W/rs/dst/"
# the AppImage runtime mounts its image on /tmp/.mount_<name><random> and
# runs AppRun from there; --appimage-extract-and-run unpacks it under /tmp
MNT=$(mktemp -d /tmp/.mount_nncorpusXXXXXX)
step "dev AppImage: squashfuse mount on /tmp/.mount_*" 60 -- squashfuse "$W/app/nn-corpus.squashfs" "$MNT"
step "dev AppImage: AppRun from the mount" 60 -- "$MNT/AppRun"
step "dev AppImage: unmount" 60 -- fuse_umount "$MNT"
rmdir "$MNT" 2>/dev/null
EX=/tmp/appimage_extracted_nncorpus$(md5sum "$W/app/nn-corpus.squashfs" | cut -c1-16)
step "dev AppImage: extract under /tmp" 60 -- unsquashfs -q -n -f -d "$EX" "$W/app/nn-corpus.squashfs"
step "dev AppImage: AppRun extracted" 60 -- "$EX/AppRun"
rm -rf "$EX"
# the control (lot 283b): one program run from /tmp for a few seconds, by
# the lab user (a person's account: recorded, not killed) and by www-data
# (a system account, the web shell's: killed, rc 137). Lot 344: a copy of
# the shell looping on `sleep 1`, not a copy of `sleep` — Ubuntu 26.04's
# coreutils are uutils' multicall binary, which picks its utility from the
# name it is run by: the copy printed "unknown program" and exited 1, and the
# control proved nothing there.
install -m 755 /bin/sh /tmp/nn-corpus-control
CONTROL_LOOP='i=0; while [ "$i" -lt "$1" ]; do sleep 1; i=$((i + 1)); done'
step "dev control: a program from /tmp, as the lab user (3 s)" 60 -- /tmp/nn-corpus-control -c "$CONTROL_LOOP" nn-corpus-control 3
step "dev control: the same, as www-data (a system account)" 60 -- sudo -u www-data /tmp/nn-corpus-control -c "$CONTROL_LOOP" nn-corpus-control 20
rm -f /tmp/nn-corpus-control
corpus_finish
