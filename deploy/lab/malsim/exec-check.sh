#!/bin/bash
# Lab PR 226 (EXPERIMENTAL) — the exec policy (CM-01) and the exec
# environment / executable mapping checks (CM-25), end to end on a lab guest
# (`nn-lab.sh malsim-exec-check`; docs/design/EXEC_POLICY.md §9). Benign
# simulations only: copies of /usr/bin/id and /usr/bin/true, a shared object
# whose constructor does nothing, files in mktemp directories marked `nn-ms`,
# everything removed by the EXIT trap. Run as the lab user with sudo, with the
# agent installed by this tree's install.sh and running on LSM (`lsm=…,bpf`).
#
# Phase A — policy off ("ran before"): nothing is refused in the kernel.
#   MS-01  a copy of /usr/bin/id in /dev/shm, run from a service context
#          (`systemd-run`): runs;
#   MS-02  a memfd exec of /usr/bin/true's bytes (python3 os.memfd_create +
#          execve), from a service context: runs;
#   MS-03  an exec of a deleted file (a copy of true opened, unlinked, run
#          through its descriptor), from a service context: runs;
#   MS-32  LD_PRELOAD of a no-op .so from /tmp into a service: runs.
#   MS-01..03 also match rules that predate the policy — R002 (an exec from
#   /dev/shm) and R004 (an exec through a descriptor) — which see the exec
#   only after it ran and kill the process: "ran" is then a non-zero status
#   that is not a refusal (systemd's 203/EXEC, the probe's "refused: 13")
#   with that rule's signed record.
# Phase B — `--exec-policy enforce` (server profile, "denied after"): the four
#   refused with EACCES, each a signed NN-L-EXECPOL-001 / NN-L-EXECENV-001
#   record (decision deny, tier service); `LD_PRELOAD=//tmp/…` (the string
#   check side-stepped) runs and its mapping is recorded (NN-L-EXECENV-003);
#   `HISTFILE=/dev/null bash -c true` recorded Low (NN-L-EXECENV-002);
#   negatives allowed and unrecorded: the lab user's interactive ./script.sh
#   in the home, the same through sudo on a terminal (admin tier: allowed), a
#   package postinst (deploy/lab/pkgmgr/mk-probe-deb.sh), systemd services
#   (`systemd-run /usr/bin/true`, no failed unit); the signed status counts.
#   The server profile has quarantine cells (/tmp, /var/tmp, world-writable,
#   tmpfs) and this phase runs without --exec-quarantine, so the signed
#   status reads "enforce; 1 partial" with that one note (those execs run,
#   counted as `quarantine inactive`); any other partial note is a FAIL.
# Phase C — `--exec-policy audit`: MS-01 runs (R002 may kill it after the
#   exec, as in phase A), recorded "would deny".
# Phase D — `--exec-policy-profile desktop`: an AppImage-shaped run
#   (/tmp/.mount_nnms*/AppRun) and a Flatpak-shaped one
#   (~/.local/share/flatpak/app/…) from the login session: allowed, no record.
# Then it puts the guest back (drop-in removed, agent restarted).
# Verdicts come from the signed detection chain and the signed status, never
# from journal text. Exit: 0 PASS, 1 FAIL, 2 refused (not a lab guest).
set -u

NN_LAB_GUEST_MARKER=/var/lib/nn-lab-provisioned
if ! [[ -e $NN_LAB_GUEST_MARKER || ${NN_TEST_DISPOSABLE_HOST:-} == 1 ]]; then
    echo "exec policy check: refusing to run: not an nn-lab guest ($NN_LAB_GUEST_MARKER missing) and NN_TEST_DISPOSABLE_HOST=1 not set — it changes the agent's unit" >&2
    exit 2
fi

HERE=$(cd "$(dirname "$0")" && pwd)
DET=/var/lib/northnarrow/detections/detections.jsonl
R_EXEC=NN-L-EXECPOL-001_StagingExecDenied
R_PRELOAD=NN-L-EXECENV-001_PreloadFromStaging
R_ENV=NN-L-EXECENV-002_ExecEnvironmentTrick
R_MAP=NN-L-EXECENV-003_ExecMappingFromStaging
BIN=$(dirname "$(systemctl show -p ExecStart --value northnarrow-agent | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)")
NNADMIN=$BIN/nn-admin
KEY=$(for k in /root/northnarrow-admin.key /etc/northnarrow/admin.key; do sudo test -r "$k" && { echo "$k"; break; }; done)
DROPIN_DIR=/etc/systemd/system/northnarrow-agent.service.d
DROPIN=$DROPIN_DIR/nn-lab-execpol.conf
fail=0
pass() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; fail=1; }
skip() { printf 'SKIP  %s\n' "$*"; }
info() { printf 'INFO  %s\n' "$*"; }

[[ -n $KEY ]] || { echo "exec policy check: no admin key" >&2; exit 1; }
command -v python3 >/dev/null || { echo "exec policy check: python3 is needed" >&2; exit 1; }
WORK=$(mktemp -d "$HOME/nn-ms.XXXXXXXX") || exit 1
TMPD=$(mktemp -d /tmp/nn-ms.XXXXXXXX) || exit 1
SHMD=$(mktemp -d /dev/shm/nn-ms.XXXXXXXX) || exit 1
OPTD=/opt/nn-ms.$$
POLICY_ON=0

grant() { sudo "$NNADMIN" trusted-installer-grant --key "$KEY" --window-secs 300 >/dev/null 2>&1; }

# The unit refuses `systemctl restart` (external audit EBPF-001): a signed
# trusted-installer window, SIGTERM, and the watchdog starts it again.
restart_agent() {
    local old new i
    old=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
    grant
    sudo systemctl kill --signal=SIGTERM northnarrow-agent
    for i in $(seq 1 40); do
        sleep 1
        new=$(sudo cat /run/northnarrow/agent.pid 2>/dev/null)
        if [[ -n $new && $new != "$old" ]] && sudo kill -0 "$new" 2>/dev/null \
            && sudo "$NNADMIN" status >/dev/null 2>&1; then
            sleep 2
            return 0
        fi
    done
    sudo systemctl start northnarrow-agent
    sleep 6
}

# policy <env lines…>: the drop-in with these Environment= values, agent
# restarted; `policy` alone removes it.
policy() {
    grant
    if (($#)); then
        sudo install -d -m 0755 "$DROPIN_DIR"
        { echo '[Service]'; for e in "$@"; do echo "Environment=$e"; done; } | sudo tee "$DROPIN" >/dev/null
        POLICY_ON=1
    else
        sudo rm -f "$DROPIN"
        POLICY_ON=0
    fi
    sudo systemctl daemon-reload
    restart_agent
}

det_count() { sudo cat "$DET" 2>/dev/null | wc -l; }

# The exec policy records written after line $1, one TSV line each:
# rule, exe, decision, tier, classes, response, environment, values.
pol_since() {
    sudo tail -n "+$(($1 + 1))" "$DET" 2>/dev/null | python3 -c '
import json, sys
for line in sys.stdin:
    try:
        r = json.loads(line)
    except ValueError:
        continue
    e = r.get("execpol")
    if not e:
        continue
    print("\t".join([r.get("rule_id", ""), r.get("exe") or "", e.get("decision", ""),
                     e.get("tier", ""), ",".join(e.get("classes", [])), r.get("response", ""),
                     ",".join(e.get("environment", [])), " ".join(e.get("values", []))]))
'
}
# Rules that predate the policy and see MS-01..03 only after they ran
# (Critical, KillProcessTree).
PRE_RULES='R002_ExecFromDevShm|R004_ExecFromProcSelfFd'
# The rule ids (comma-separated) of the records written after line $1 whose
# rule_id matches the extended regex $2.
rules_since() {
    sudo tail -n "+$(($1 + 1))" "$DET" 2>/dev/null | python3 -c '
import json, re, sys
pat = re.compile(sys.argv[1])
for line in sys.stdin:
    try:
        r = json.loads(line)
    except ValueError:
        continue
    rid = r.get("rule_id") or ""
    if pat.fullmatch(rid):
        print(rid)
' "$2" | sort -u | paste -sd, -
}
# records of rule $2 since line $1 whose line contains $3
recs() { pol_since "$1" | awk -F'\t' -v r="$2" '$1 == r' | grep -F -- "$3"; }
field() { printf '%s' "$1" | head -1 | cut -f"$2"; }

# One field of the signed status's exec policy object.
pol_status() {
    sudo "$NNADMIN" status --key "$KEY" --json 2>/dev/null | python3 -c '
import json, sys
try:
    v = (json.load(sys.stdin).get("execpol") or {}).get(sys.argv[1])
except ValueError:
    v = None
print("" if v is None else v)
' "$1"
}

# The signed status's degradations, one per line.
status_degradations() {
    sudo "$NNADMIN" status --key "$KEY" --json 2>/dev/null | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin).get("degradations") or []
except ValueError:
    d = []
for x in d:
    print(x)
'
}
QUARANTINE_NOTE='the policy has quarantine cells and the exec quarantine is off'

cleanup() {
    ((POLICY_ON)) && policy
    rm -rf "$WORK" "$TMPD" "$SHMD"
    sudo rm -rf "$OPTD"
    sudo dpkg -r nn-pkgprobe >/dev/null 2>&1 || true
}
trap cleanup EXIT

# ── the simulations, each from a service context (`systemd-run`) ──────
# Each prints "ran" on success; the exit status is kept.
svc() { sudo systemd-run --quiet --wait --pipe --collect -p User=root "$@" 2>&1; }

cp /usr/bin/id "$SHMD/id" && chmod 0755 "$SHMD/id"
cc -shared -fPIC -O2 -o "$TMPD/libnnms_noop.so" "$HERE/libnnms_noop.c" 2>/dev/null \
    || { command -v cc >/dev/null || sudo apt-get install -y gcc >/dev/null 2>&1; cc -shared -fPIC -O2 -o "$TMPD/libnnms_noop.so" "$HERE/libnnms_noop.c"; } \
    || { bad "cannot build the no-op shared object"; exit 1; }
chmod 0755 "$TMPD" "$TMPD/libnnms_noop.so"
sudo install -d -m 0755 "$OPTD"
printf '# nn-ms marker\n' | sudo tee "$OPTD/nn-ms" >/dev/null

ms01() { svc "$SHMD/id"; }
MEMFD_PY='import os,sys
fd = os.memfd_create("nn-ms")
os.write(fd, open("/usr/bin/true", "rb").read())
try:
    os.execve(fd, ["nn-ms"], {})
except OSError as e:
    print("refused:", e.errno); sys.exit(13)'
ms02() { svc /usr/bin/python3 -c "$MEMFD_PY"; }
DELETED_PY='import os,shutil,sys
p = sys.argv[1] + "/nn-ms-deleted"
shutil.copy("/usr/bin/true", p); os.chmod(p, 0o755)
fd = os.open(p, os.O_RDONLY); os.unlink(p)
try:
    os.execve(fd, ["nn-ms-deleted"], {})
except OSError as e:
    print("refused:", e.errno); sys.exit(13)'
ms03() { svc /usr/bin/python3 -c "$DELETED_PY" "$OPTD"; }
ms32() { svc -E "LD_PRELOAD=$TMPD/libnnms_noop.so" /usr/bin/true; }
ms32_evasive() { svc -E "LD_PRELOAD=/$TMPD/libnnms_noop.so" /usr/bin/true; }

run_case() {   # <name> <fn> → "rc"
    local out rc
    out=$("$2"); rc=$?
    printf '%s' "$rc"
}

# ── phase A: policy off — the simulations run ─────────────────────────
policy
st=$(pol_status state)
[[ $st == off ]] && pass "A  policy off (signed status: $st)" || bad "A  policy state '$st', expected off"
for c in ms01 ms02 ms03 ms32; do
    b=$(det_count)
    out=$("$c"); rc=$?
    sleep 2
    pre=$(rules_since "$b" "$PRE_RULES")
    if [[ $rc == 0 ]]; then
        pass "A  ${c^^}: ran before the policy (rc 0${pre:+; then $pre, which predates the policy})"
    elif [[ $rc != 13 && $rc != 203 && $out != *refused:* && -n $pre ]]; then
        pass "A  ${c^^}: ran before the policy, then killed after the exec by $pre (rc $rc; a rule that predates the policy)"
    else
        bad "A  ${c^^}: rc $rc with the policy off (pre-existing rule records: ${pre:-none}; output: ${out:0:80})"
    fi
done

# ── phase B: enforce — denied after ───────────────────────────────────
policy NN_EXEC_POLICY=enforce
st=$(pol_status state)
if [[ $st == enforce ]]; then
    pass "B  policy enforce (signed status: $st)"
elif [[ $st == "enforce; 1 partial" ]] && status_degradations | grep -qF "$QUARANTINE_NOTE"; then
    pass "B  policy enforce (signed status: $st — the one note: quarantine cells without --exec-quarantine)"
else
    bad "B  policy state '$st' (a partial or degraded state names why: $(status_degradations | grep -F 'exec policy' | paste -sd';' -))"
fi
d0=$(pol_status denied)
b=$(det_count)
rc=$(run_case ms01 ms01); sleep 2
r=$(recs "$b" "$R_EXEC" "$SHMD/id")
if [[ $rc != 0 && $(field "$r" 3) == deny && $(field "$r" 4) == service && $(field "$r" 5) == *dev_shm* ]]; then
    pass "B  MS-01 /dev/shm copy of id from a service: refused (rc $rc), signed $R_EXEC deny, tier service, classes $(field "$r" 5)"
else
    bad "B  MS-01: rc $rc, record: ${r:-none}"
fi
b=$(det_count)
rc=$(run_case ms02 ms02); sleep 2
r=$(recs "$b" "$R_EXEC" "memfd")
if [[ $rc == 13 && $(field "$r" 3) == deny && $(field "$r" 5) == *memfd* ]]; then
    pass "B  MS-02 memfd exec from a service: EACCES, signed deny ($(field "$r" 6 | cut -c1-60)…)"
else
    bad "B  MS-02: rc $rc, record: ${r:-none}"
fi
b=$(det_count)
rc=$(run_case ms03 ms03); sleep 2
r=$(recs "$b" "$R_EXEC" "deleted")
if [[ $rc == 13 && $(field "$r" 3) == deny && $(field "$r" 5) == *deleted* ]]; then
    pass "B  MS-03 exec of a deleted file from a service: EACCES, signed deny"
else
    bad "B  MS-03: rc $rc, record: ${r:-none}"
fi
b=$(det_count)
rc=$(run_case ms32 ms32); sleep 2
r=$(recs "$b" "$R_PRELOAD" "libnnms_noop.so")
if [[ $rc != 0 && $(field "$r" 3) == deny && $(field "$r" 7) == *preload_staging* ]]; then
    pass "B  MS-32 LD_PRELOAD from /tmp into a service: refused at exec (rc $rc), signed $R_PRELOAD deny"
else
    bad "B  MS-32: rc $rc, record: ${r:-none}"
fi
b=$(det_count)
rc=$(run_case ms32e ms32_evasive); sleep 2
r=$(recs "$b" "$R_MAP" "libnnms_noop.so")
if [[ $rc == 0 && $(field "$r" 3) == record && $(field "$r" 4) == service ]]; then
    pass "B  MS-32 LD_PRELOAD=//tmp/… (string check side-stepped): the loader's mapping of the file recorded ($R_MAP, tier service)"
else
    bad "B  MS-32 evasive form: rc $rc, mapping record: ${r:-none}"
fi
b=$(det_count)
HISTFILE=/dev/null HISTSIZE=0 bash -c true; sleep 2
r=$(recs "$b" "$R_ENV" "bash")
[[ -n $r ]] && pass "B  HISTFILE=/dev/null bash: recorded ($R_ENV, $(field "$r" 7))" \
    || bad "B  HISTFILE=/dev/null bash: no $R_ENV record"
b=$(det_count)
if command -v su >/dev/null; then
    GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=1 su --help >/dev/null 2>&1; sleep 2
    r=$(recs "$b" "$R_ENV" "GLIBC_TUNABLES")
    [[ -n $r ]] && pass "B  GLIBC_TUNABLES of the CVE-2023-4911 shape at su (set-id; patched glibc, no effect): recorded" \
        || bad "B  GLIBC_TUNABLES at su: no record"
fi

# negatives
b=$(det_count)
printf '#!/bin/sh\n# nn-ms marker\nexit 0\n' > "$WORK/nn-ms.sh" && chmod 0755 "$WORK/nn-ms.sh"
(cd "$WORK" && ./nn-ms.sh); rc1=$?
script -qec "sudo $WORK/nn-ms.sh" /dev/null >/dev/null 2>&1; rc2=$?
sleep 2
n=$(pol_since "$b" | grep -F -c "$WORK/nn-ms.sh")
[[ $rc1 == 0 && $rc2 == 0 && $n == 0 ]] && pass "B  the lab user's ./script.sh in the home (session tier) and through sudo on a terminal (admin tier): allowed, no record" \
    || bad "B  ./script.sh: rc $rc1 / sudo on a terminal rc $rc2, $n record(s)"
if command -v dpkg-deb >/dev/null; then
    b=$(det_count)
    bash "$HERE/../pkgmgr/mk-probe-deb.sh" "$WORK" >/dev/null 2>&1
    sudo dpkg -i "$WORK"/nn-pkgprobe_*.deb >/dev/null 2>&1; rc1=$?
    sudo dpkg -r nn-pkgprobe >/dev/null 2>&1; rc2=$?
    sleep 2
    n=$(pol_since "$b" | awk -F'\t' '$3 == "deny"' | grep -c .)
    [[ $rc1 == 0 && $rc2 == 0 && $n == 0 ]] && pass "B  a package install and removal (postinst, prerm): allowed, no deny" \
        || bad "B  probe package: install rc $rc1, removal rc $rc2, $n deny record(s)"
else
    skip "B  no dpkg-deb: the package negative is for Debian-family guests"
fi
f0=$(systemctl list-units --state=failed --no-legend | grep -c .)
svc /usr/bin/true >/dev/null; rc=$?
cronunit=$(systemctl list-unit-files cron.service crond.service --no-legend 2>/dev/null | awk '{print $1}' | head -1)
[[ -n $cronunit ]] && sudo systemctl restart "$cronunit"
sleep 2
f1=$(systemctl list-units --state=failed --no-legend | grep -c .)
[[ $rc == 0 && $f1 -le $f0 ]] && pass "B  systemd services: a transient unit runs${cronunit:+, $cronunit restarts}, failed units $f0 → $f1" \
    || bad "B  services: systemd-run rc $rc, failed units $f0 → $f1"
d1=$(pol_status denied)
info "B  signed status: denied $d0 → $d1, would deny $(pol_status would_deny), environment denied $(pol_status env_denied) / reported $(pol_status env_recorded), mappings reported $(pol_status map_recorded), quarantine inactive $(pol_status quarantine_inactive)"
((d1 >= d0 + 3)) && pass "B  the denies are counted in the signed status ($d0 → $d1)" || bad "B  denied count $d0 → $d1"

# ── phase C: audit — would deny, ran ──────────────────────────────────
policy NN_EXEC_POLICY=audit
b=$(det_count)
rc=$(run_case ms01 ms01); sleep 2
r=$(recs "$b" "$R_EXEC" "$SHMD/id")
pre=$(rules_since "$b" "$PRE_RULES")
if [[ $rc != 203 && ($rc == 0 || -n $pre) && $(field "$r" 3) == "would deny" ]]; then
    pass "C  audit: MS-01 ran (rc $rc${pre:+, then $pre}), signed \"would deny\" ($(field "$r" 6 | cut -c1-50)…)"
else
    bad "C  audit: MS-01 rc $rc, record: ${r:-none}, pre-existing: ${pre:-none}"
fi

# ── phase D: desktop profile — AppImage and Flatpak shapes allowed ────
policy NN_EXEC_POLICY=enforce NN_EXEC_POLICY_PROFILE=desktop
APPD=$(mktemp -d /tmp/.mount_nnmsXXXXXX)
cp /usr/bin/true "$APPD/AppRun" && chmod 0755 "$APPD/AppRun"
FPD=$HOME/.local/share/flatpak/app/org.nnms.Probe/x86_64/stable/active/files/bin
mkdir -p "$FPD" && cp /usr/bin/true "$FPD/nn-ms-probe"
b=$(det_count)
"$APPD/AppRun"; rc1=$?
"$FPD/nn-ms-probe"; rc2=$?
sleep 2
n=$(pol_since "$b" | grep -E -c "AppRun|nn-ms-probe")
[[ $rc1 == 0 && $rc2 == 0 && $n == 0 ]] && pass "D  desktop profile: an AppImage-shaped run from /tmp/.mount_* and a Flatpak-shaped one from the home (session tier): allowed, no record" \
    || bad "D  desktop profile: AppRun rc $rc1, flatpak-shaped rc $rc2, $n record(s)"
rc=$(run_case ms02 ms02)
[[ $rc == 13 ]] && pass "D  desktop profile: services stay strict (MS-02 memfd from a service refused)" \
    || bad "D  desktop profile: MS-02 rc $rc"
rm -rf "$APPD" "$HOME/.local/share/flatpak/app/org.nnms.Probe"

echo
if ((fail)); then echo "exec policy check: FAIL"; else echo "exec policy check: PASS"; fi
exit "$fail"
