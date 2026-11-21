# shellcheck shell=bash
# NorthNarrow's BPF programs on this host, told by identity (lot 383) —
# never another product's, never PID 1's. systemd 257 and newer (Debian 13,
# Ubuntu 26.04) keep a BPF-LSM program of their own loaded for
# RestrictFileSystems= (`restrict_filesy`), held by PID 1 for as long as it
# runs: no stop of NorthNarrow detaches it, and a count of every LSM program
# on the host never reaches 0 there. Sourced by nn-lab.sh's guest scripts,
# deploy/lab/pkg/pkg-check.sh and deploy/lab/perf/perf-run.sh; it runs
# nothing on its own. The test fixtures do the same in Rust
# (agent/tests/common/mod.rs, our_bpf), from the same list of names.
#
#   our_progs_left [<id>...]   the `bpftool prog show` header line of every
#                              program of ours still loaded: the ids given
#                              (an agent's bpf-own-ids list; any type), or,
#                              with none (an agent older than the list, or
#                              one stopped before it wrote it), the LSM
#                              programs named like one in our-lsm-programs.txt.
#                              Exit 2, printing nothing, when it cannot tell:
#                              bpftool fails, or the list of names is missing.
#   our_progs_count [<id>...]  how many: a number, or `unknown` (exit 2), which
#                              no `== 0` check takes for "none left".
#   own_ids_of <file>...       the ids those bpf-own-ids files list: the first
#                              field of every line that starts with a digit.

NN_OUR_LSM_NAMES=${NN_OUR_LSM_NAMES:-"$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/our-lsm-programs.txt"}

_nn_as_root() { if [ "$(id -u)" = 0 ]; then "$@"; else sudo "$@"; fi; }

own_ids_of() {
    local f
    for f in "$@"; do _nn_as_root awk '$1 ~ /^[0-9]+$/ {print $1}' "$f" 2>/dev/null; done | sort -un | tr '\n' ' '
}

our_progs_left() {
    local listing names=""
    if [ $# = 0 ]; then
        [ -r "$NN_OUR_LSM_NAMES" ] || { echo "our-lsm: $NN_OUR_LSM_NAMES is missing" >&2; return 2; }
        # the kernel keeps 15 bytes of a name
        names=$(grep -v -e '^#' -e '^$' "$NN_OUR_LSM_NAMES" | cut -c1-15 | tr '\n' ' ')
        [ -n "$names" ] || { echo "our-lsm: $NN_OUR_LSM_NAMES lists no name" >&2; return 2; }
    fi
    listing=$(_nn_as_root bpftool prog show 2>/dev/null) || { echo "our-lsm: bpftool prog show failed" >&2; return 2; }
    awk -v ids=" $* " -v byid=$# -v names=" $names " '
        $1 ~ /^[0-9]+:$/ {
            id = substr($1, 1, length($1) - 1)
            if (byid) { if (index(ids, " " id " ")) print; next }
            if ($2 != "lsm") next
            for (i = 3; i < NF; i++) if ($i == "name") { if (index(names, " " $(i + 1) " ")) print; break }
        }' <<<"$listing"
}

our_progs_count() {
    local left
    left=$(our_progs_left "$@") || { echo unknown; return 2; }
    grep -c . <<<"$left" || true
}
