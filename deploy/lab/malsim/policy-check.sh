#!/usr/bin/env bash
# Lab PR 236 — the signed per-rule response policy end to end, on a lab
# guest (`nn-lab.sh policy-check`; run by the lab user, sudo inside, the
# lab key with config-manage). Benign: the ransomware simulator of lab PR
# 225 (files under /srv/nn-malsim only), restored at the end.
#
# 1) built-in: MS-23 in place → NN-L-IMP-001 recorded, its kill held;
# 2) a signed test policy `enforce NN-L-IMP-001` set live → MS-23 killed;
# a bad policy refused, the previous one kept; 3) the agent restarted in a
# trusted-installer window boots on the signed policy (rule_policy_loaded);
# 4) a policy of comments only → built-in again, MS-23 held. Then the
# policy files are removed (in a trusted-installer window): the guest is
# put back.
set -u
PATH=$PATH:/usr/sbin:/sbin
DET=/var/lib/northnarrow/detections/detections.jsonl
AUDIT=/etc/northnarrow/audit.log
NNADMIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")/nn-admin
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
HERE=$(cd "$(dirname "$0")" && pwd)
SIM="$HERE/ransom-sim.py"
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
lines() { sudo wc -l "$1" | cut -d" " -f1; }
since() { sudo tail -n +"$(( $2 + 1 ))" "$1"; }
summary() { python3 -I -c '
import json,sys
for l in sys.stdin:
    try: r=json.loads(l)
    except Exception: continue
    ids=[m["rule_id"] for m in (r.get("matches") or [])] or [r.get("rule_id")]
    if not any(i and i.startswith("NN-L-IMP-001") for i in ids): continue
    ms=[(m["rule_id"].split("_")[0],m["mode"],m["action"]) for m in (r.get("matches") or [])]
    print(r.get("rule_id"),r.get("severity"),"verdict",r.get("verdict"),"response",repr(r.get("response")),"matches",ms)
'; }
ms23() {
    sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1; sleep 1
    sudo python3 -I "$SIM" clean; sudo python3 -I "$SIM" prepare --files 300 >/dev/null
    local b; b=$(lines "$DET")
    sudo systemd-run --quiet --wait --pipe --collect -- python3 -I "$SIM" inplace; SIM_RC=$?
    sleep 3
    LOCKED=$(sudo find /srv/nn-malsim/data -name '*.locked' | wc -l)
    REC=$(since "$DET" "$b" | summary)
}
restart_agent() {
    local old new i
    sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 300 >/dev/null 2>&1 || { bad "trusted-installer-grant"; return 1; }
    old=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
    sudo systemctl kill --signal=SIGTERM northnarrow-agent
    for i in $(seq 1 60); do
        sleep 1
        new=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
        [[ -n $new && $new != "$old" ]] && sudo kill -0 "$new" 2>/dev/null && { sleep 8; return 0; }
    done
    sudo systemctl start northnarrow-agent; sleep 8
}
echo "nn-admin: $NNADMIN  key: $KEY"
echo "== 1. built-in defaults"
sudo "$NNADMIN" policy show | sed 's/^/    /'
ms23
echo "    sim rc=$SIM_RC locked=$LOCKED"; echo "$REC" | sed 's/^/    /'
if [[ -n $REC && $SIM_RC -eq 0 ]] && ! grep -q "Kill" <<<"$(echo "$REC" | grep -o "response '[^']*'")"; then
    pass "built-in: NN-L-IMP-001 recorded, its kill held, the simulator ran to its end ($LOCKED files)"
else bad "built-in: rc=$SIM_RC rec=[$REC]"; fi
echo "== 2. signed test policy, set live"
printf '# lab PR 236 test policy\nenforce NN-L-IMP-001\n' > /tmp/rp236.local
a=$(lines "$AUDIT")
sudo "$NNADMIN" policy set --file /tmp/rp236.local --key "$KEY"; rc=$?
row=$(since "$AUDIT" "$a" | grep '"config_overlay_set"' | tail -1)
[[ $rc -eq 0 ]] && grep -q 'applied now' <<<"$row" && grep -q '"result":"success"' <<<"$row" \
    && pass "policy set: stored, applied now, signed config_overlay_set row" || bad "policy set rc=$rc row=${row:0:300}"
sudo "$NNADMIN" policy show | sed 's/^/    /'
printf 'enforce NN-L-IMP-001\nexempt NN-L-IMP-001 comm python3\n' > /tmp/rp236-bad.local
a=$(lines "$AUDIT")
sudo "$NNADMIN" policy set --file /tmp/rp236-bad.local --key "$KEY" 2>&1 | sed 's/^/    /'; rc=${PIPESTATUS[0]}
[[ $rc -ne 0 ]] && pass "a policy exempting by comm refused by nn-admin (exit $rc), nothing sent" || bad "bad policy rc=$rc"
# nn-admin validates before signing, so the bad file never reaches the
# agent (its own check, validate_content in the set handler, is a unit
# test): no row, and the policy in force is unchanged.
row=$(since "$AUDIT" "$a" | grep -c '"config_overlay_set"')
sudo "$NNADMIN" policy show | grep -q "^enforce  NN-L-IMP-001" && [[ $row -eq 0 ]] \
    && pass "after the refusal: no config_overlay_set row, the policy in force unchanged (enforce NN-L-IMP-001)" || bad "after refusal rows=$row"
ms23
echo "    sim rc=$SIM_RC locked=$LOCKED"; echo "$REC" | sed 's/^/    /'
if grep -q "KillProcessTree" <<<"$REC" && grep -q "'IMP-001\|NN-L-IMP-001', 'enforce'" <<<"$REC" && [[ $LOCKED -lt 300 ]]; then
    pass "enforce NN-L-IMP-001: the actor's tree killed ($LOCKED of 300 files locked)"
else bad "enforce: rc=$SIM_RC locked=$LOCKED rec=[$REC]"; fi
echo "== 3. boot on the signed policy"
a=$(lines "$AUDIT"); t=$(date +%s)
restart_agent
row=$(since "$AUDIT" "$a" | grep '"rule_policy_loaded"' | tail -1)
[[ -n $row ]] && pass "restart: signed rule_policy_loaded row (${row:0:200})" || bad "restart: no rule_policy_loaded row"
sudo journalctl --namespace=northnarrow -u northnarrow-agent --since "@$t" --no-pager 2>/dev/null | grep -m1 "per-rule response policy" | sed 's/^/    /'
ms23
echo "    sim rc=$SIM_RC locked=$LOCKED"; echo "$REC" | sed 's/^/    /'
grep -q "KillProcessTree" <<<"$REC" && pass "after the restart: IMP-001 still enforced" || bad "after restart rec=[$REC]"
echo "== 4. back to the built-in defaults"
printf '# no directive: the built-in defaults\n' > /tmp/rp236-empty.local
sudo "$NNADMIN" policy set --file /tmp/rp236-empty.local --key "$KEY" | sed 's/^/    /'
ms23
echo "    sim rc=$SIM_RC locked=$LOCKED"; echo "$REC" | sed 's/^/    /'
if [[ -n $REC && $SIM_RC -eq 0 ]] && ! grep -q "KillProcessTree" <<<"$REC"; then
    pass "built-in again: IMP-001 held, the simulator ran to its end"
else bad "rollback: rc=$SIM_RC rec=[$REC]"; fi
sudo python3 -I "$SIM" clean
sudo "$NNADMIN" debug force-posture observing >/dev/null 2>&1
sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 120 >/dev/null 2>&1 \
    && sudo rm -f /etc/northnarrow/rule-policy.local /etc/northnarrow/rule-policy.local.sig
rm -f /tmp/rp236.local /tmp/rp236-bad.local /tmp/rp236-empty.local
echo "policy check: $( ((fail)) && echo FAIL || echo PASS)"
exit $fail
