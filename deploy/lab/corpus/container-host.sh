#!/usr/bin/env bash
# Lot 283a — benign corpus: a container host. Rootless podman (the lab user,
# in its session) and docker (root) pull and run a small image; then k3s:
# the vendor's install script (get.k3s.io, as an operator runs it: it
# enables and starts k3s), the node Ready, one pod run to completion, and
# k3s-uninstall.sh. Lab guests only; see corpus-lib.sh and
# docs/validation/BENIGN_CORPUS.md.
# usage: container-host.sh
set -u
here=${BASH_SOURCE[0]%/*}
[[ $here == "${BASH_SOURCE[0]}" ]] && here=.
# shellcheck source=corpus-lib.sh
. "$here/corpus-lib.sh"
corpus_init containers
IMG=docker.io/library/alpine:3.20

corpus_cleanup() {
    [[ -x /usr/local/bin/k3s-uninstall.sh ]] && sudo /usr/local/bin/k3s-uninstall.sh >/dev/null 2>&1
    command -v podman >/dev/null && podman system reset -f >/dev/null 2>&1
    command -v docker >/dev/null && sudo docker rmi -f "$IMG" >/dev/null 2>&1
    sudo rm -rf "$W"
    sudo rmdir /srv/nn-corpus 2>/dev/null
    if [[ " $INSTALLED " == *" docker.io "* ]]; then
        sudo systemctl stop docker.socket docker containerd >/dev/null 2>&1
    fi
    # rootful podman's storage, made by the package the corpus installed
    # (its purge makes it again: removed after it)
    local podman_ours=0
    [[ " $INSTALLED " == *" podman "* ]] && podman_ours=1
    corpus_purge
    ((podman_ours)) && sudo rm -rf /var/lib/containers
    [[ -n ${PODMAN_NEW:-} ]] && rm -rf "$HOME/.local/share/containers" "$HOME/.config/containers"
    [[ -n ${DOCKER_NEW:-} ]] && sudo rm -rf /var/lib/docker /var/lib/containerd /etc/docker
    sudo rm -rf /var/lib/rancher /etc/rancher
    true
}

echo "== prepare (not measured)"
[[ -e $HOME/.local/share/containers ]] || PODMAN_NEW=1
command -v docker >/dev/null || DOCKER_NEW=1
apt_need podman uidmap slirp4netns docker.io curl
sudo systemctl start docker >/dev/null 2>&1
podman system reset -f >/dev/null 2>&1

echo "== measure"
corpus_settle
corpus_mark
step "containers podman pull (rootless)" 600 -- podman pull -q "$IMG"
step "containers podman run (rootless)" 300 -- podman run --rm "$IMG" sh -c 'echo nn-corpus; ls /'
step "containers podman rmi (rootless)" 120 -- podman rmi -f "$IMG"
step "containers docker pull" 600 -- sudo docker pull -q "$IMG"
step "containers docker run" 300 -- sudo docker run --rm "$IMG" sh -c 'echo nn-corpus; ls /'
# lot 347: docker's own start (its iptables/nftables chains through
# xtables-nft-multi, its module loads), a docker exec and a build — each a
# container start through runc
step "containers docker restart (its start)" 300 -- sudo systemctl restart docker
# (the review of #556: a leftover nn-corpus from a failed run removed first,
# and the container removed whatever the exec did — the step's status is
# the run's and the exec's)
step "containers docker exec" 300 -- sudo sh -c "docker rm -f nn-corpus >/dev/null 2>&1; docker run -d --name nn-corpus $IMG sleep 60 && docker exec nn-corpus true; rc=\$?; docker rm -f nn-corpus >/dev/null 2>&1; exit \$rc"
step "containers docker build" 600 -- sudo sh -c "d=\$(mktemp -d) && printf 'FROM $IMG\nRUN true\n' > \$d/Dockerfile && docker build -q -t nn-corpus-img \$d && docker rmi -f nn-corpus-img; rm -rf \$d"
step "containers docker rmi" 120 -- sudo docker rmi -f "$IMG"
step "containers k3s install (get.k3s.io)" 900 -- bash -c 'curl -sfL https://get.k3s.io | sudo sh -'
step "containers k3s node Ready" 300 -- sudo bash -c 'until k3s kubectl get nodes 2>/dev/null | grep -q " Ready"; do sleep 5; done'
step "containers k3s pod run to completion" 600 -- sudo bash -c "k3s kubectl run nn-corpus --image=$IMG --restart=Never -- sh -c 'echo nn-corpus' && until k3s kubectl get pod nn-corpus -o jsonpath='{.status.phase}' 2>/dev/null | grep -q Succeeded; do sleep 5; done"
step "containers k3s pods (all namespaces)" 60 -- sudo k3s kubectl get pods -A
step "containers k3s delete the pod" 120 -- sudo k3s kubectl delete pod nn-corpus --wait=true
step "containers k3s-uninstall.sh" 600 -- sudo /usr/local/bin/k3s-uninstall.sh
corpus_finish
