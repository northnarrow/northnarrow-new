#!/bin/bash
# Tappa 10.9 step 2 — the exec sensor on LSM bprm_check_security, end to
# end on a lab guest (`nn-lab.sh exec-sensor-check`). Run as the lab user
# with sudo, with the agent installed and running in its default (LSM)
# mode. Review 61: the exec rules match the file the kernel executed, not
# the string the caller passed.
set -u
DET=/var/lib/northnarrow/detections/detections.jsonl
HELPER=/usr/local/libexec/nn-lab/nn-memfd-exec
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
INV=$(systemctl show -p InvocationID --value northnarrow-agent)
journal() { sudo journalctl --namespace=northnarrow --no-pager "_SYSTEMD_INVOCATION_ID=$INV" | grep -v "process spawn detected"; }
det_count() { sudo cat "$DET" 2>/dev/null | wc -l; }
new_dets() { sudo tail -n "$(( $(det_count) - $1 ))" "$DET" 2>/dev/null; }
# run "$@" for at most 5 s; prints its exit code (137 = killed)
run_rc() { "$@" >/dev/null 2>&1; echo $?; }

# 1. armed, and the BPF self-check quiet about the retired tracepoint
if journal | grep -q "exec sensor armed on LSM bprm_check_security"; then
    pass "exec sensor armed on LSM bprm_check_security"
else
    bad "exec sensor not armed: $(journal | grep -m1 'exec sensor' | cut -c1-200)"
fi
if journal | grep -q "own BPF links is GONE"; then
    bad "the BPF self-check reports a missing link since the agent started"
else
    pass "no missing-link report"
fi

X=/tmp/nn-exec-x
cp /bin/sleep "$X"
# kill_case <label> <rule id> <command…>: the command must be killed and
# the rule must name the file the kernel executed
kill_case() {
    local label=$1 rule=$2; shift 2
    local b rc n
    b=$(det_count); rc=$(run_rc "$@"); sleep 2
    n=$(new_dets "$b" | grep -c "\"rule_id\":\"$rule\"")
    if [[ $rc -eq 137 && $n -ge 1 ]]; then
        pass "$label: killed by $rule"
    else
        bad "$label: rc=$rc $rule records=$n"
    fi
}
# 2. `cd /tmp && ./x`: a child of the shell runs execve("./nn-exec-x").
# (Not `exec ./x`: bash's exec builtin passes the absolute path.)
kill_case "relative exec from /tmp (cd /tmp && ./x)" R001_ExecFromTmp bash -c "cd /tmp && ./nn-exec-x 5"
# 3. through a symlink in a root-owned directory
sudo mkdir -p /var/lib/nn-exec-lab && sudo ln -sfn "$X" /var/lib/nn-exec-lab/notes
kill_case "exec through a symlink (/var/lib/nn-exec-lab/notes → /tmp)" R001_ExecFromTmp /var/lib/nn-exec-lab/notes 5
sudo rm -rf /var/lib/nn-exec-lab
# 4. dot segments
kill_case "exec of /usr/bin/../../tmp/nn-exec-x" R001_ExecFromTmp /usr/bin/../../tmp/nn-exec-x 5
# 5. a script in /tmp, run relatively: R001 on the script, not on /bin/sh
printf '#!/bin/sh\nsleep 5\n' > /tmp/nn-exec-x.sh && chmod +x /tmp/nn-exec-x.sh
kill_case "script in /tmp run as ./nn-exec-x.sh" R001_ExecFromTmp bash -c "cd /tmp && ./nn-exec-x.sh"
rm -f "$X" /tmp/nn-exec-x.sh
# 6. a memfd through an ordinary symlink in the home: no fd path in the
# caller's string, R004 on the kernel's memfd flag
if [[ -x $HELPER ]] || { sudo mkdir -p "$(dirname "$HELPER")" && sudo cc -O2 -o "$HELPER" "$(dirname "$0")/memfd-exec.c" 2>/dev/null; }; then
    kill_case "memfd run through $HOME/nn-exec-m (symlink to /proc/self/fd/N)" R004_ExecFromProcSelfFd "$HELPER" "$HOME/nn-exec-m" 5
    rm -f "$HOME/nn-exec-m"
else
    printf 'SKIP  memfd helper not built\n'
fi
# The /tmp execs also escalate the posture: back to observing.
sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1

# 7. an ordinary binary is not touched
b=$(det_count); rc=$(run_rc /usr/bin/sleep 1); sleep 1
n=$(new_dets "$b" | grep -c '"rule_id":"R00[0-9]')
[[ $rc -eq 0 && $n -eq 0 ]] && pass "/usr/bin/sleep runs untouched" || bad "/usr/bin/sleep: rc=$rc exec-rule records=$n"
# 8. the telemetry probe never went silent
gaps=$(journal | grep -c "TELEMETRY GAP\|still SILENT")
[[ $gaps -eq 0 ]] && pass "telemetry probe: no gap since the agent started" \
                  || bad "telemetry probe: $gaps gap line(s) since the agent started"

[[ $fail -eq 0 ]] && echo "exec-sensor check: OK" || echo "exec-sensor check: FAILED"
exit $fail
