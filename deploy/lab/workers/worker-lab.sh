#!/usr/bin/env bash
# R14a: the workers' lab on an nn-lab guest (our own guests only), from the
# tree's root with NN_LAB_DISTRO naming the guest: copies worker-guest.sh
# there, runs each phase as root against the installed agent, fetches what
# it wrote.
#
# usage: worker-lab.sh <out-dir> <phase>...   (roles, faults, parse)
set -u -o pipefail
OUT=${1:?out dir}; shift
LAB=./deploy/lab/nn-lab.sh
[[ -x $LAB ]] || { echo "run from the tree's root" >&2; exit 2; }
mkdir -p "$OUT"
"$LAB" ssh "mkdir -p ~/nn-workers-lab" >/dev/null
# the guest script next to this one (a driver run against another tree's
# nn-lab.sh still sends its own)
"$LAB" ssh "cat > ~/nn-workers-lab/worker-guest.sh" < "$(dirname "$0")/worker-guest.sh"
fails=0
for phase in "$@"; do
    "$LAB" ssh "sudo bash ~/nn-workers-lab/worker-guest.sh $phase /var/lib/nn-workers-lab/$phase" > "$OUT/$phase.log" 2>&1
    rc=$?
    fails=$((fails + rc))
    mkdir -p "$OUT/$phase"
    "$LAB" ssh "sudo tar -C /var/lib/nn-workers-lab/$phase -cf - ." 2>/dev/null | tar -xf - -C "$OUT/$phase" 2>/dev/null
    echo "$phase: $(grep -c '^PASS' "$OUT/$phase.log") PASS, $(grep -c '^FAIL' "$OUT/$phase.log") FAIL (rc $rc)"
done
exit $(( fails > 0 ))
