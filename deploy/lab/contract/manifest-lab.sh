#!/usr/bin/env bash
# R13 (lab PR 271; report 06 INI-09, R4-01, EXP-37): the signed capability
# manifest on an nn-lab guest, with the heartbeat's external verifier run on
# the HOST. Our own lab guests only (nn-lab.sh's), the agent installed from
# the tree with the lab's features (debug-trigger).
#
# usage: manifest-lab.sh <out-dir> normal|partial|stale|contract|nobpf [nn-admin]   (from the
#        tree's root, NN_LAB_DISTRO naming the guest; nn-admin: a host build
#        of this tree's, default target/release/nn-admin)
#
#   normal — the manifest once settled (the telemetry probe's first round),
#     the same hash after two clean restarts (a trusted-installer window,
#     SIGTERM, start), a probe made to fail (debug-trigger:
#     /run/northnarrow/debug-probe-blind names `dns`) and restored: each a
#     signed `capability_manifest_change` and a DEGRADED of the verifier,
#     the restarts none.
#   partial — (the review of #479) the file-open sensor on its tracepoint
#     (a unit drop-in, NN_FILE_OPEN_SENSOR=tracepoint): `open_sensor`
#     partial with the event kinds it loses, `file_open` carrying the opens,
#     DEGRADED off the host; the drop-in removed: the hash back.
#   stale — (X2) the probe's rounds stopped (debug-trigger:
#     /run/northnarrow/debug-probe-skip): the probed sources `stale`
#     (unknown), DEGRADED; removed: seen again, DEGRADED back.
#   contract — after the lab driver installed a build whose contract's terms
#     differ (and nothing else): a NOTICE of the verifier's, no manifest
#     alert.
#   nobpf — the guest's lsm= without `bpf` (its grub drop-in edited, a
#     reboot): the start refused, signed; then the degraded-mode opt-in (a
#     unit drop-in, NN_ANTI_TAMPER_ALLOW_DEGRADED=1): the start, its manifest
#     (which hooks do not run, which fallbacks), `status --key`, the
#     verifier's DEGRADED across the restart; then the unit and the guest's
#     lsm= restored, a reboot, the manifest's hash back to the one before.
#
# The verifier runs in the background through a phase, its state in
# <out-dir>/state.json, kept between the phases (run `normal`, then `nobpf`,
# in one directory: the verifier sees the change across the reboots).
# Under QEMU for Windows a guest's reboot ends QEMU (-no-reboot):
# `nn-lab.sh up` boots it again (reboot_guest).
# Output: watch.log (UTC-stamped), steps.tsv (step, start, end, result),
# the manifests (caps-<tag>.json), the manifest rows of the audit log
# (rows-<tag>.jsonl), status-<tag>.txt, summary.txt. Exit 0 when every
# check held.
set -u -o pipefail
OUT=${1:?out dir}
PHASE=${2:?normal or nobpf}
NNADMIN=${3:-target/release/nn-admin}
LAB=./deploy/lab/nn-lab.sh
[[ -x $LAB && -x $NNADMIN ]] || { echo "run from the tree's root, with $NNADMIN built" >&2; exit 2; }
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
NNADMIN=$(cd "$(dirname "$NNADMIN")" && pwd)/$(basename "$NNADMIN")
D=${NN_LAB_DISTRO:-ubuntu2404}
ROOT=${NN_LAB_DIR:-$HOME/.cache/nn-lab}
if [[ $D == ubuntu2404 ]]; then DIR=$ROOT; else DIR=$ROOT/$D; fi
PORT=$(cat "$DIR/ssh_port")
g() { "$LAB" ssh "$@"; }
now() { date -u +%FT%T.%6NZ; }
TSV=$OUT/steps.tsv
[[ -f $TSV ]] || printf 'step\tstart\tend\tresult\n' > "$TSV"
fails=0
step() { # name start result(ok|FAIL: …)
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$(now)" "$3" >> "$TSV"
  [[ $3 == ok* ]] || fails=$((fails + 1))
}

KEY=$(g 'for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r $k && { echo $k; break; }; done' | tr -d '\r')
[[ -n $KEY ]] || { echo "no lab admin key on the guest" >&2; exit 1; }
AUDIT=/etc/northnarrow/audit.log
GRUB_CFG=/etc/default/grub.d/99-nn-bpf-lsm.cfg
DROPIN_DIR=/etc/systemd/system/northnarrow-agent.service.d
DROPIN=$DROPIN_DIR/zz-r13-lab-degraded.conf

# the newest revision, as `nn-admin capabilities --key --json` prints it
caps() { g "sudo -n /usr/local/bin/nn-admin capabilities --key $KEY --json" > "$OUT/caps-$1.json" 2>/dev/null; }
field() { python3 -I -c 'import json, sys
m = json.load(open(sys.argv[1]))["manifest"]
v = m
for k in sys.argv[2].split("."):
    v = v[k] if isinstance(v, dict) else v[int(k)]
print(json.dumps(v) if isinstance(v, (list, dict)) else v)' "$OUT/caps-$1.json" "$2" 2>/dev/null; }
wait_settled() { # tag within
  local end=$((SECONDS + $2))
  while ((SECONDS < end)); do
    caps "$1" && [[ $(field "$1" settled) == True ]] && return 0
    sleep 5
  done
  return 1
}
# the manifest's rows of the audit log since the boot of the agent running
rows() { g "sudo grep -a '\"op\":\"capability_manifest' $AUDIT" > "$OUT/rows-$1.jsonl" 2>/dev/null; }
stop_agent() {
  g "sudo /usr/local/bin/nn-admin trusted-installer-grant --key $KEY --window-secs 120 >/dev/null && sudo systemctl kill -s SIGTERM northnarrow-watchdog && sleep 1 && sudo systemctl kill -s SIGTERM northnarrow-agent"
  for _ in $(seq 1 30); do
    [[ $(g 'systemctl is-active northnarrow-agent' | tr -d '\r') != active ]] && return 0
    sleep 2
  done
  return 1
}
start_agent() { g 'sudo systemctl reset-failed northnarrow-agent northnarrow-watchdog; sudo systemctl start northnarrow-agent northnarrow-watchdog' >/dev/null 2>&1; }
wait_ssh() { # within
  local end=$((SECONDS + $1))
  sleep 20
  while ((SECONDS < end)); do
    g true >/dev/null 2>&1 && return 0
    sleep 5
  done
  return 1
}
# A reboot of the guest. Under QEMU for Windows (WHPX) QEMU runs with
# -no-reboot, so the guest's reboot ends it: `nn-lab.sh up` boots it again.
# `up` waits for `bpf` in the active LSM list, which a boot without it never
# shows: then it is left to give up on its own (its own timeout, the guest
# left running) while the ssh wait here goes on.
UP_PID=
reboot_guest() { # nobpf|bpf
  # an earlier `up` still waiting would boot the guest again beside this
  # one's: it ends first (its own timeout)
  if [[ -n $UP_PID ]]; then wait "$UP_PID" 2>/dev/null; UP_PID=; fi
  g 'sudo systemctl reboot' >/dev/null 2>&1
  if [[ $(cat "$ROOT/accel" 2>/dev/null) == whpx ]]; then
    for _ in $(seq 1 60); do
      "$LAB" status 2>&1 | grep -q 'stopped' && break
      sleep 3
    done
    if [[ $1 == nobpf ]]; then
      NN_LAB_BOOT_TIMEOUT=300 "$LAB" up > "$OUT/up-$1.log" 2>&1 &
      UP_PID=$!
    else
      NN_LAB_BOOT_TIMEOUT=600 "$LAB" up > "$OUT/up-$1.log" 2>&1
    fi
  fi
  wait_ssh 600
}

# the verifier on this host: the guest's export over the lab's SSH
g 'cat /etc/northnarrow/agent.sig.pub' > "$OUT/agent.pub" || { echo "no agent.sig.pub" >&2; exit 1; }
cat > "$OUT/fetch.sh" <<EOF
#!/usr/bin/env bash
ssh -i "$ROOT/id_ed25519" -p $PORT -o BatchMode=yes -o ConnectTimeout=5 \\
  -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$DIR/known_hosts" \\
  -o GlobalKnownHostsFile=/dev/null -o HostKeyAlias=nn-lab-$D -o HostKeyAlgorithms=ssh-ed25519 \\
  -o CheckHostIP=no -o LogLevel=ERROR \\
  nn@127.0.0.1 'sudo -n /usr/local/bin/nn-admin heartbeat export --count 64'
EOF
chmod +x "$OUT/fetch.sh"
"$NNADMIN" heartbeat watch --agent-pubkey-file "$OUT/agent.pub" --from-cmd "$OUT/fetch.sh" \
  --state "$OUT/state.json" --every 5 >> "$OUT/watch.log" 2>&1 &
WPID=$!
trap 'kill "$WPID" 2>/dev/null' EXIT
# the first `ALERT DEGRADED` naming the manifest at or after $1 within $2 s
wait_manifest_alert() {
  local since=$1 within=$2 t
  local end=$((SECONDS + within))
  while ((SECONDS < end)); do
    t=$(awk -v s="$since" '$1 >= s && /ALERT DEGRADED/ && /capability manifest changed/ {print $1; exit}' "$OUT/watch.log")
    [[ -n $t ]] && { echo "$t"; return 0; }
    sleep 2
  done
  return 1
}

if [[ $PHASE == normal ]]; then
  t=$(now)
  if wait_settled normal-0 150; then
    step settled "$t" "ok: revision $(field normal-0 revision), hash $(field normal-0 hash)"
  else
    step settled "$t" "FAIL: not settled within 150 s"
  fi
  H0=$(field normal-0 hash)
  echo "$H0" > "$OUT/hash-normal"
  sleep 40   # the verifier anchors on a settled beat
  # two clean restarts: the same settled hash, no manifest alert
  for i in 1 2; do
    t=$(now)
    if stop_agent && start_agent && wait_settled "restart-$i" 150; then
      h=$(field "restart-$i" hash)
      if [[ $h == "$H0" ]]; then
        step "restart-$i" "$t" "ok: the same hash $h (revision $(field "restart-$i" revision))"
      else
        step "restart-$i" "$t" "FAIL: hash $h, not $H0"
      fi
    else
      step "restart-$i" "$t" "FAIL: the agent did not restart and settle"
    fi
  done
  sleep 40
  t=$(now)
  if awk '/capability manifest/' "$OUT/watch.log" | grep -q .; then
    step restarts-quiet "$t" "FAIL: a manifest alert at a restart: $(grep 'capability manifest' "$OUT/watch.log" | head -1)"
  else
    step restarts-quiet "$t" "ok: no manifest alert through two restarts"
  fi
  # a probe made to fail: the DNS sensor's event counted as not seen
  t=$(now)
  g "sudo sh -c 'echo dns > /run/northnarrow/debug-probe-blind'"
  if a=$(wait_manifest_alert "$t" 240); then
    caps blind; rows blind
    step probe-blind "$t" "ok: DEGRADED at $a; revision $(field blind revision), dns_query $(python3 -I -c 'import json,sys
m=json.load(open(sys.argv[1]))["manifest"]
s=[x for x in m["sources"] if x["source"]=="dns_query"][0]
print(s["state"], s.get("probe"), "| change:", "; ".join(m.get("change", [])))' "$OUT/caps-blind.json")"
  else
    step probe-blind "$t" "FAIL: no manifest alert within 240 s"
  fi
  t=$(now)
  g 'sudo rm -f /run/northnarrow/debug-probe-blind'
  if a=$(wait_manifest_alert "$t" 240); then
    caps restored; rows restored
    step probe-restored "$t" "ok: DEGRADED at $a; revision $(field restored revision), hash $(field restored hash) ($([[ $(field restored hash) == "$H0" ]] && echo 'the hash before' || echo 'NOT the hash before'))"
  else
    step probe-restored "$t" "FAIL: no manifest alert within 240 s"
  fi
  g "sudo -n /usr/local/bin/nn-admin status --key $KEY" > "$OUT/status-normal.txt" 2>&1
fi

H0=$(cat "$OUT/hash-normal" 2>/dev/null)
if [[ $PHASE == partial ]]; then
  # the review of #479: a fallback that covers less is partial
  t=$(now)
  # the unit's drop-ins are protected: written and removed with the agent
  # stopped, inside the trusted-installer window stop_agent grants
  if stop_agent \
    && g "sudo mkdir -p $DROPIN_DIR && sudo sh -c 'printf \"[Service]\nEnvironment=NN_FILE_OPEN_SENSOR=tracepoint\n\" > $DROPIN_DIR/zz-r13-lab-partial.conf' && sudo systemctl daemon-reload" > "$OUT/partial-dropin.txt" 2>&1 \
    && start_agent && wait_settled partial 180; then
    sum=$(python3 -I -c 'import json, sys
m = json.load(open(sys.argv[1]))["manifest"]
s = {x["source"]: x for x in m["sources"]}
o, f = s["open_sensor"], s["file_open"]
print("open_sensor %s on %s (%s); file_open %s probe %s evidence %s" % (o["state"], o["on"], " | ".join(o.get("why", [])), f["state"], f.get("probe"), f.get("evidence")))' "$OUT/caps-partial.json")
    if [[ $sum == "open_sensor partial on fallback"*"MassWrite, FileBurst, DefenderSignal"*"file_open ok"* ]]; then
      step partial "$t" "ok: $sum"
    else
      step partial "$t" "FAIL: $sum"
    fi
  else
    step partial "$t" "FAIL: the agent did not restart and settle ($(cat "$OUT/partial-dropin.txt" | tr '\n' ' '))"
  fi
  if a=$(wait_manifest_alert "$t" 240); then
    step verifier-partial "$t" "ok: DEGRADED at $a"
  else
    step verifier-partial "$t" "FAIL: no manifest alert within 240 s"
  fi
  t=$(now)
  if ! stop_agent \
    || ! g "sudo rm -f $DROPIN_DIR/zz-r13-lab-partial.conf && sudo rmdir --ignore-fail-on-non-empty $DROPIN_DIR; sudo systemctl daemon-reload; ! test -e $DROPIN_DIR/zz-r13-lab-partial.conf" > "$OUT/partial-back-dropin.txt" 2>&1; then
    step partial-back "$t" "FAIL: the drop-in was not removed ($(tr '\n' ' ' < "$OUT/partial-back-dropin.txt"))"
    start_agent
  elif start_agent && wait_settled partial-back 180; then
    h=$(field partial-back hash)
    step partial-back "$t" "$([[ $h == "$H0" ]] && echo ok || echo FAIL): hash $h (normal $H0)"
  else
    step partial-back "$t" "FAIL: the agent did not restart and settle"
  fi
  if a=$(wait_manifest_alert "$t" 240); then
    step verifier-partial-back "$t" "ok: DEGRADED at $a (back)"
  else
    step verifier-partial-back "$t" "FAIL: no manifest alert within 240 s"
  fi
fi

if [[ $PHASE == stale ]]; then
  # the review of #479, X2: the probe's rounds stopped
  t=$(now)
  g "sudo sh -c 'touch /run/northnarrow/debug-probe-skip'"
  ok=
  for _ in $(seq 1 60); do
    caps stale
    if [[ $(field stale sources.0.probe) == stale ]]; then ok=1; break; fi
    sleep 5
  done
  if [[ -n $ok ]]; then
    step stale "$t" "ok: process_spawn $(field stale sources.0.state), probe $(field stale sources.0.probe); $(field stale unsigned_changes) change(s) not signed yet, revision $(field stale revision)"
  else
    step stale "$t" "FAIL: the probe's word not stale within 300 s"
  fi
  if a=$(wait_manifest_alert "$t" 300); then
    step verifier-stale "$t" "ok: DEGRADED at $a"
  else
    step verifier-stale "$t" "FAIL: no manifest alert within 300 s"
  fi
  t=$(now)
  if ! g 'sudo rm -f /run/northnarrow/debug-probe-skip && ! test -e /run/northnarrow/debug-probe-skip' >/dev/null 2>&1; then
    step stale-trigger-removed "$t" "FAIL: /run/northnarrow/debug-probe-skip is still there"
  fi
  if a=$(wait_manifest_alert "$t" 240); then
    caps stale-back; rows stale
    step verifier-stale-back "$t" "ok: DEGRADED at $a (seen again: hash $(field stale-back hash))"
  else
    step verifier-stale-back "$t" "FAIL: no manifest alert within 240 s"
  fi
fi

if [[ $PHASE == contract ]]; then
  # an upgrade whose contract's terms differ, and nothing else: a NOTICE
  t=$(now)
  if wait_settled contract 180; then
    sleep 80   # two beats seen by the verifier
    notice=$(awk -v s="$t" '$1 >= s && /NOTICE the sensor contract changed/' "$OUT/watch.log" | head -1)
    alert=$(awk -v s="$t" '$1 >= s && /capability manifest changed/' "$OUT/watch.log" | head -1)
    if [[ -n $notice && -z $alert && $(field contract hash) == "$H0" ]]; then
      step contract "$t" "ok: the same capabilities hash, a NOTICE, no manifest alert: $(echo "$notice" | cut -c1-180)"
    else
      step contract "$t" "FAIL: notice [$notice] alert [$alert] hash $(field contract hash) (normal $H0)"
    fi
  else
    step contract "$t" "FAIL: the agent did not settle"
  fi
fi

if [[ $PHASE == nobpf ]]; then
  caps before; H0=$(field before hash)
  [[ -n $H0 ]] || H0=$(cat "$OUT/hash-normal" 2>/dev/null)
  # the refusals signed before this boot (an earlier run's) are not this one's
  R0=$(g "sudo grep -a -c refused_by $AUDIT" | tr -d '\r')
  # the guest's lsm= without bpf, kept aside to restore
  t=$(now)
  # (a copy kept once: a run cut short and run again keeps the first)
  g "sudo test -e $GRUB_CFG.r13-lab || sudo cp -a $GRUB_CFG $GRUB_CFG.r13-lab; sudo sed -i 's/,bpf\\([\" ]\\)/\\1/' $GRUB_CFG && grep -c ',bpf' $GRUB_CFG; cat $GRUB_CFG; sudo update-grub >/dev/null 2>&1 && echo grub-updated" > "$OUT/grub-nobpf.txt" 2>&1
  if reboot_guest nobpf; then
    lsm=$(g 'cat /sys/kernel/security/lsm' | tr -d '\r')
    step reboot-nobpf "$t" "$([[ $lsm != *bpf* ]] && echo ok || echo FAIL): active LSMs $lsm"
  else
    step reboot-nobpf "$t" "FAIL: the guest did not come back"
  fi
  # the start refused, signed
  sleep 30
  t=$(now)
  g "systemctl is-active northnarrow-agent; sudo grep -a -E 'refused_by|\"bpf_lsm\"' $AUDIT | tail -n 4" > "$OUT/refused.txt" 2>&1
  R1=$(g "sudo grep -a -c refused_by $AUDIT" | tr -d '\r')
  if ((${R1:-0} > ${R0:-0})) && grep -q 'refused_by' "$OUT/refused.txt" && grep -q 'bpf_lsm' "$OUT/refused.txt"; then
    step refused "$t" "ok: the start refused, signed ($((R1 - R0)) agent_boot refused_by bpf_lsm since the reboot)"
  else
    step refused "$t" "FAIL: no signed refusal (refused.txt)"
  fi
  # the degraded-mode opt-in
  t=$(now)
  g "sudo mkdir -p $DROPIN_DIR && sudo sh -c 'printf \"[Service]\nEnvironment=NN_ANTI_TAMPER_ALLOW_DEGRADED=1\n\" > $DROPIN' && sudo systemctl daemon-reload" >/dev/null 2>&1
  start_agent
  if wait_settled nobpf 180; then
    rows nobpf
    g "sudo -n /usr/local/bin/nn-admin status --key $KEY" > "$OUT/status-nobpf.txt" 2>&1
    sum=$(python3 -I -c 'import json, sys
m = json.load(open(sys.argv[1]))["manifest"]
not_invoked = [s["source"] for s in m["sources"] if s["state"] == "attached_not_invoked"]
fallback = [s["source"] for s in m["sources"] if s["on"] == "fallback"]
print("L%s; not invoked: %s; on a fallback: %s; bpf_lsm %s" % (m["trust_level"], ",".join(not_invoked), ",".join(fallback), m["bpf_lsm"]))' "$OUT/caps-nobpf.json")
    ok=ok
    for s in fs_protect module_load bpf_syscall fim_drain; do [[ $sum == *"$s"* ]] || ok="FAIL ($s not said)"; done
    [[ $sum == *"on a fallback: "*exec_check* && $sum == *open_sensor* ]] || ok="FAIL (the fallbacks)"
    step degraded-start "$t" "$ok: $sum"
  else
    step degraded-start "$t" "FAIL: the degraded start did not settle"
  fi
  if a=$(wait_manifest_alert "$t" 240); then
    step verifier-nobpf "$t" "ok: DEGRADED at $a: $(grep "^$a" "$OUT/watch.log" | grep -o 'the capability manifest changed[^;]*' | head -1)"
  else
    step verifier-nobpf "$t" "FAIL: no manifest alert within 240 s"
  fi
  # restore: the unit, the guest's lsm=, a reboot
  t=$(now)
  g "sudo rm -f $DROPIN && sudo rmdir --ignore-fail-on-non-empty $DROPIN_DIR; sudo cp -a $GRUB_CFG.r13-lab $GRUB_CFG && sudo rm -f $GRUB_CFG.r13-lab && cat $GRUB_CFG && sudo update-grub >/dev/null 2>&1 && sudo systemctl daemon-reload && echo restored" > "$OUT/grub-restored.txt" 2>&1
  if reboot_guest bpf; then
    lsm=$(g 'cat /sys/kernel/security/lsm' | tr -d '\r')
    step reboot-restored "$t" "$([[ $lsm == *bpf* ]] && echo ok || echo FAIL): active LSMs $lsm"
  else
    step reboot-restored "$t" "FAIL: the guest did not come back"
  fi
  t=$(now)
  if wait_settled after 240; then
    h=$(field after hash)
    step manifest-back "$t" "$([[ $h == "$H0" ]] && echo ok || echo FAIL): hash $h (before $H0), L$(field after trust_level)"
  else
    step manifest-back "$t" "FAIL: the agent did not settle after the restore"
  fi
  if a=$(wait_manifest_alert "$t" 240); then
    step verifier-back "$t" "ok: DEGRADED at $a (the manifest changed back)"
  else
    step verifier-back "$t" "FAIL: no manifest alert within 240 s"
  fi
  g 'test -e /etc/systemd/system/northnarrow-agent.service.d/zz-r13-lab-degraded.conf && echo DROPIN-LEFT; test -e /etc/default/grub.d/99-nn-bpf-lsm.cfg.r13-lab && echo GRUB-BACKUP-LEFT; grep -c ",bpf" /etc/default/grub.d/99-nn-bpf-lsm.cfg' > "$OUT/clean.txt" 2>&1
fi

sleep 10
if [[ -n $UP_PID ]]; then wait "$UP_PID" 2>/dev/null; fi
kill "$WPID" 2>/dev/null; trap - EXIT
{
  echo "manifest lab ($PHASE) on $D: $fails step(s) failed"
  column -t -s $'\t' "$TSV"
} > "$OUT/summary.txt"
cat "$OUT/summary.txt"
exit $((fails > 0))
