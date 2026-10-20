#!/usr/bin/env bash
# Self-test of deploy/lab/lib/suite-count.sh (external audit NN-AUD-421):
# no VM, no cargo. Listing and run outputs as libtest prints them.
#   bash deploy/lab/lib/suite-count-test.sh      → exit 0 when every case holds
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=deploy/lab/lib/suite-count.sh
source "$HERE/suite-count.sh"

W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

pass=0 fail=0
ok() { local what=$1; shift; if "$@" >/dev/null 2>&1; then echo "ok    $what"; pass=$((pass + 1)); else echo "FAIL  $what"; fail=$((fail + 1)); fi; }
no() { local what=$1; shift; if "$@" >/dev/null 2>&1; then echo "FAIL  $what (accepted)"; fail=$((fail + 1)); else echo "ok    $what (refused)"; pass=$((pass + 1)); fi; }
eq() { local what=$1 want=$2 got=$3; if [[ $want == "$got" ]]; then echo "ok    $what"; pass=$((pass + 1)); else echo "FAIL  $what: '$got' (want '$want')"; fail=$((fail + 1)); fi; }

cat >"$W/list" <<'EOF'
e2e_force_combat_then_unlock_via_cli: test
e2e_unlock_with_wrong_key: test
iptables::iptables_guard_removes_every_duplicate_jump: test
bench_something: benchmark

3 tests, 1 benchmark
EOF
eq "listing counts the tests, not the benchmarks" 3 "$(nnsc_listed "$W/list")"
: >"$W/empty"
eq "an empty listing is 0" 0 "$(nnsc_listed "$W/empty")"
printf 'a: test\r\nb: test\r\n' >"$W/crlf"
eq "CRLF listing" 2 "$(nnsc_listed "$W/crlf")"

run() { printf 'running %s tests\nagent output: test result: ok. 99 passed; is not a summary\n%s\n' "$1" "$2" >"$W/run"; }

run 3 'test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 312.04s'
ok "every listed test passed" nnsc_verdict s 3 "$W/run"
eq "the verdict line" "count ok: s: 3 of 3 passed" "$(nnsc_verdict s 3 "$W/run")"

run 2 'test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 1.00s'
no "a test filtered out (--skip)" nnsc_verdict s 3 "$W/run"
eq "it says how many ran" "FAIL: s: 2 of 3 passed (0 failed, 0 ignored, 1 filtered out)" "$(nnsc_verdict s 3 "$W/run")"

run 3 'test result: ok. 2 passed; 0 failed; 1 ignored; 0 measured; 0 filtered out; finished in 1.00s'
no "an ignored test" nnsc_verdict s 3 "$W/run"

run 3 'test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.00s'
no "a failed test" nnsc_verdict s 3 "$W/run"

run 2 'test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.00s'
no "fewer tests ran than listed" nnsc_verdict s 3 "$W/run"

run 0 'test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s'
no "nothing listed, nothing ran (built without its feature)" nnsc_verdict s 0 "$W/run"
no "a listing that is not a number" nnsc_verdict s "" "$W/run"

printf 'running 3 tests\nthread main panicked\n' >"$W/run"
no "no summary (the run died)" nnsc_verdict s 3 "$W/run"

printf '%s\n%s\n' 'test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s' \
    'test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s' >"$W/run"
no "two summaries (two binaries)" nnsc_verdict s 3 "$W/run"

printf 'test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\r\n' >"$W/run"
ok "a CRLF summary" nnsc_verdict s 3 "$W/run"

echo "$pass passed, $fail failed"
((fail == 0))
