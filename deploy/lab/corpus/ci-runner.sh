#!/usr/bin/env bash
# Lot 283a — benign corpus: a CI runner. The workstation's builds and tests
# (a crate from a local git repository, a Go module, an npm project, a Python
# venv) with no session: each in a transient systemd unit as the lab user
# (no login session, no loginuid — a runner service's context), then a
# docker build of a small Dockerfile and the image's removal, as root in a
# unit too. Lab guests only; see corpus-lib.sh and
# docs/validation/BENIGN_CORPUS.md.
# usage: ci-runner.sh
set -u
here=${BASH_SOURCE[0]%/*}
[[ $here == "${BASH_SOURCE[0]}" ]] && here=.
# shellcheck source=corpus-lib.sh
. "$here/corpus-lib.sh"
corpus_init ci
IMG=docker.io/library/alpine:3.20
TAG=nn-corpus-ci:283

corpus_cleanup() {
    if command -v docker >/dev/null; then
        sudo docker rmi -f "$TAG" "$IMG" >/dev/null 2>&1
        sudo docker builder prune -af >/dev/null 2>&1
    fi
    chmod -R u+w "$W" 2>/dev/null
    sudo rm -rf "$W"
    sudo rmdir /srv/nn-corpus 2>/dev/null
    if [[ " $INSTALLED " == *" docker.io "* ]]; then
        sudo systemctl stop docker.socket docker containerd >/dev/null 2>&1
        corpus_purge
        sudo rm -rf /var/lib/docker /var/lib/containerd /etc/docker
    else
        corpus_purge
    fi
    true
}

echo "== prepare (not measured)"
apt_need git golang-go nodejs npm python3-venv build-essential docker.io
command -v cargo >/dev/null || echo "  no cargo for $LABUSER: the cargo steps fail"
prep_crate
prep_go
prep_npm
mkdir -p "$W/img"
printf 'nn-corpus ci build\n' > "$W/img/payload.txt"
cat > "$W/img/Dockerfile" <<EOF
FROM $IMG
COPY payload.txt /srv/payload.txt
RUN cat /srv/payload.txt && mkdir -p /srv/out && echo built > /srv/out/state
CMD ["cat", "/srv/out/state"]
EOF
sudo systemctl start docker >/dev/null 2>&1

echo "== measure"
corpus_settle
corpus_mark
wl_cargo runner ci
wl_go runner ci
wl_npm runner ci
wl_pip runner ci
runner root
step "ci docker build (alpine, COPY, RUN)" 900 -- "${RUN[@]}" docker build -q -t "$TAG" "$W/img"
step "ci docker run of the image" 300 -- "${RUN[@]}" docker run --rm "$TAG"
step "ci docker rmi" 300 -- "${RUN[@]}" docker rmi -f "$TAG" "$IMG"
corpus_finish
