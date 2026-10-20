# shellcheck shell=bash
# Sourced by deploy/lab/nn-lab.sh (test-e2e). External audit NN-AUD-421
# (TST-015): the runbook carried the e2e counts by hand ("9 tests passing,
# 2 ignored" for a suite of 10 with none ignored) and nothing compared them
# with a run. A privileged suite now counts as passed only when every test
# it lists ran and passed: the number from `cargo test … -- --list` and the
# run's one "test result:" line must agree, with nothing failed, ignored or
# filtered out. A suite compiled without its feature lists 0 tests: that
# fails too.
#   bash deploy/lab/lib/suite-count-test.sh   → the self-test (no VM)

# The number of tests in a `cargo test … -- --list` output (`<name>: test`
# lines; benchmarks are not tests).
nnsc_listed() {
    tr -d '\r' <"$1" | grep -cE '^[^ ]+: test$' || true
}

# nnsc_verdict LABEL LISTED RUN_LOG: exit 0 when RUN_LOG holds exactly one
# libtest summary, "test result: ok. N passed; 0 failed; 0 ignored; M
# measured; 0 filtered out", with N == LISTED > 0. Prints one line either
# way; a failure starts with "FAIL:" (the nightly report collects those).
nnsc_verdict() {
    local label=$1 listed=$2 log=$3 results n
    local re='^test result: ([A-Za-z]+)\. ([0-9]+) passed; ([0-9]+) failed; ([0-9]+) ignored; ([0-9]+) measured; ([0-9]+) filtered out'
    results=$(tr -d '\r' <"$log" | grep -E '^test result: ' || true)
    n=$(printf '%s' "$results" | grep -c '^test result: ' || true)
    if [[ ! $listed =~ ^[0-9]+$ ]] || ((listed == 0)); then
        echo "FAIL: $label: no test listed (\`-- --list\` gave '${listed}'): not built with its feature, or the listing failed"
        return 1
    fi
    if [[ $n != 1 ]]; then
        echo "FAIL: $label: $n libtest summaries in the run (1 expected): it did not finish, or ran more than one binary"
        return 1
    fi
    if [[ ! $results =~ $re ]]; then
        echo "FAIL: $label: unreadable summary: $results"
        return 1
    fi
    local status=${BASH_REMATCH[1]} passed=${BASH_REMATCH[2]} failed=${BASH_REMATCH[3]}
    local ignored=${BASH_REMATCH[4]} filtered=${BASH_REMATCH[6]}
    if [[ $status != ok ]] || ((failed != 0 || ignored != 0 || filtered != 0 || passed != listed)); then
        echo "FAIL: $label: $passed of $listed passed ($failed failed, $ignored ignored, $filtered filtered out)"
        return 1
    fi
    echo "count ok: $label: $passed of $listed passed"
}
