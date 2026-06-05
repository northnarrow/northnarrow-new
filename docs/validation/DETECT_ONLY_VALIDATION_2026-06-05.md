# Detect-only validation — northnarrowdev VM — 2026-06-05

Agent run in detect-only (`NN_DETECT_ONLY=1`): detection + posture run normally,
enforcement suppressed and logged as "would execute". Logs: journal namespace `northnarrow`.

## Validated
- Detect-only suppression holds through COMBAT inclusive. Evidence: `06-03 15:36:54` and
  `06-05 08:05:48` — `state=COMBAT` reached, `iptables NOT applied`.

## Rule catalog (benign harness triggers)
| family | result | rule(s) / note |
|---|---|---|
| exec | FIRES | R001_ExecFromTmp (Med), R002_ExecFromDevShm (High); posture→ENGAGED (ConfirmedIntrusion) |
| persist (cron) | FIRES | NN-L-FIM-007_CronDropInCreated (High) |
| persist (XDG autostart) | GAP | `~/.config/autostart` not watched — no detection |
| network | FIRES | NN-L-NET-004_SuspiciousDnsQname (High), NN-L-NET-001_OutboundToBlockedIp (Critical) |
| discovery | GAP | whoami/id/ps/ss/uname — no recon rule (possibly by design) |
| creds | UNTESTABLE as written | `cat /etc/shadow` as non-root → EACCES before LSM file_open → no FIM event. Needs a *successful* read of a watched cred file by a non-auth process. |

## False-positive / tuning findings
- **NN-L-FIM-005_LogTruncated**: fires on rsyslogd writing its own `/var/log/{kern,syslog,auth}.log` → FP (doesn't model the legit log writer). Response is `action=Log` (rules.rs:350), and Log-tier verdicts are NOT recorded in the corroboration ledger (ENGAGED-tier only) — so this is **noise-only, not a COMBAT-escalation risk**, just poor signal/noise at High severity. Fix: exempt rsyslogd (verified `/proc/exe` + `syslog` uid) on normal appends; keep firing on other writers and on real truncation (size→0 / inode replace).
- **mass-write (ConfirmedIntrusion_MassWrite)**: tripped by Claude Code npm self-update → FP. npm not in package-mgmt exemption (cf. snapd `99c39e2`).
- **NN-L-NET-004**: double-attributes the suspicious DNS to `systemd-resolve` (the forwarder) → killing it = host DNS outage. Attribute to originator only.
- **NN-L-FIM-007**: ~6 verdicts per single crontab edit (per-FIM-op) → dedup per `(pid, path)`.

## Posture / COMBAT model (posture/transitions.rs, mod.rs, tests.rs)
- COMBAT-tier "blunt" signals capped at ENGAGED; **two distinct corroborating signals** → COMBAT. Some signals go straight to COMBAT. COMBAT terminal (admin_release only). This IS the deliberate "COMBAT only with corroboration" anti-lockout.
- Confirmed corroborating pair: **mass-write + persistence** (system-level write, e.g. `/etc/systemd/system/` → PersistenceMechanism). Already on record reaching COMBAT in the 06-03 episode.
- Corroboration window = **15 min**; `SUSTAINED_SAME_TYPE_PROMOTES=false` (same-type repeats don't promote); Decisive triggers bypass straight to COMBAT.
- The ledger records **ENGAGED-tier escalation signals only**. This is why the 08:49 run capped at ENGAGED: only `exec→ConfirmedIntrusion` entered the ledger (1 distinct signal); the persist/network verdicts carried response actions but did not enter it. The 06-03 episode reached COMBAT because mass-write (ConfirmedIntrusion) + persistence (PersistenceMechanism) are two DISTINCT ledger signals.

## Ladder deployment gap (headline)
- Running agent (PID 1197) = **06-03 build** (`build_hash 53f0346f`), predates ladder commit `661dfe0` (06-05). `strings`: **0 ladder symbols**; only old `anti_tamper/network_isolate.rs`. Recorded COMBAT episodes used the V1 direct-isolation path.
- **Deployment gap, not a wiring bug** — source correctly wired (`main.rs` engages/observes the ladder on the non-Combat→Combat edge; detect-only honored in `combat/actuator.rs:171-178`). Consistent with `661dfe0`'s "e2e VM-pending" flag.

## To validate the ladder (next session, clean baseline)
1. `cargo xtask build --release`  (NOT bare `cargo build` — eBPF freshness gate)
2. `sudo ./deploy/install.sh`
3. **reboot**  (clean baseline; also kills the detached/hidden old agent that `systemctl` can't control)
4. `sudo systemctl start northnarrow-agent`  (`detect-only.conf` drop-in still present)
5. Verify banner: `COMBAT graduated-response ladder armed (INVESTIGATE → NEUTRALIZE → ISOLATE…)` + `detect_only=true`
6. Trigger the corroborating pair via `nn_combat_trigger.sh` (scp from laptop if not on the VM yet): mass-write + persistence → COMBAT → expect `target=combat.ladder` STAGE 1/2/3 (STAGE 3 = suppressed "would engage" no-op)

## Operational notes
- Agent hides from `/proc` + `ps` (anti-tamper process-hiding) — pin the live instance via `build_hash` in the startup banner.
- Agent currently detached from systemd (`MainPID=0`). Verify detect-only via the startup banner for the live PID, NOT `systemctl show -p Environment` (config only) or `/proc/<pid>/environ` (anti-tamper-blocked).
- `sudo` needs a password (no NOPASSWD since 06-03).
- Validation scripts: `~/nn_detect_validate.sh` (VM), `~/Downloads/nn_combat_trigger.sh` (laptop) — version in-repo when convenient.
