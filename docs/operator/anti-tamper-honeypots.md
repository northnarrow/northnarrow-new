# Anti-Tamper Honeypots (NN-L-FIM-024)

> **Operator reference.** Tappa 9.5.1. This page documents a transparent
> deception control. Read §5 before touching anything under
> `/etc/northnarrow/`, `/var/lib/northnarrow/`, or `/run/northnarrow/`.

## 1. What they are

NorthNarrow ships a small set of **inert bait files** whose *names*
mimic agent control points — kill switches, maintenance flags, override
tokens, "developer locks". They look like the knobs an attacker would
reach for to turn the agent off. They are **not** real control files:
the agent never reads them and no operator workflow ever writes them.

This is a **transparent** honeypot — fully documented here, deployed at a
known set of paths, with documented behaviour. It is not a hidden mode.
The deployed files and configs are deliberately written so a
*compromised-host* attacker reading them sees only plausible NN config
(the word "honeypot" never appears on the host); the deception is
documented for **you**, the operator, here.

## 2. Why they exist (threat model)

A mid-tier, *targeted* attacker who has done homework on NorthNarrow
will, after gaining a foothold, go looking for the agent's off-switch: a
config flag, a kill-switch file, a disable token. A *real* such control
point would be a single point of failure. The bait turns that
reconnaissance step into a high-confidence detonation: the moment the
attacker tampers with one, NorthNarrow reacts.

MITRE ATT&CK: **T1562.001** — Impair Defenses: Disable or Modify Tools.

Builds on the Tappa-7 anti-tamper layer and the Tappa-9.5 deception
layer.

## 3. Inventory

| Path | Suggested (fake) function |
|------|---------------------------|
| `/etc/northnarrow/agent.dev.lock` | "developer lock" (passive mode) |
| `/etc/northnarrow/kill_switch.conf` | global kill switch |
| `/etc/northnarrow/maintenance.mode` | maintenance bypass |
| `/etc/northnarrow/debug_disable.flag` | disable-on-debug flag |
| `/etc/northnarrow/agent.legacy.conf` | "legacy" config path |
| `/var/lib/northnarrow/shutdown.signal` | graceful-shutdown signal |
| `/var/lib/northnarrow/disable.token` | enforcement-disable token |
| `/var/lib/northnarrow/override.config` | policy override |
| `/run/northnarrow/pause.flag` | runtime pause |
| `/run/northnarrow/unload.signal` | LSM-unload signal |

Contents are realistic config-style (`key=value`) but completely inert.
`deploy/install.sh` writes the `/etc` + `/var/lib` files at install; the
agent verifies all ten at every boot and recreates any missing one
(including the tmpfs `/run` pair after a reboot) — see §6.

**Two protection tiers:**
- The five `/etc` baits and the two `/run` baits are externally
  reachable: tampering them is what NN-L-FIM-024 detects (§4).
- The three `/var/lib/northnarrow` baits sit inside the Tappa-7
  anti-tamper **deny zone** — the kernel LSM already blocks any external
  process from creating/modifying/deleting them at all. They are
  defence-in-depth (deny **and** the FIM-024 watch).

## 4. What happens on tamper

Any unauthorized **create / modify / delete / rename** of a bait fires:

- **Rule:** `NN-L-FIM-024_AntiTamperHoneypotModified`
- **Severity:** Critical
- **Response:** `KillProcessTree` — the tampering process and its tree
  are killed.
- **Posture:** the agent transitions to **COMBAT** — the
  `NORTHNARROW_COMBAT` iptables chain isolates the host to loopback-only
  (the management interface is preserved).

There is no debounce: a single tamper detonates (no benign access
exists to wait out).

## 5. Operator do-not-touch rules

**DO NOT**, on a host running NorthNarrow:

- create, edit, rename, `chmod`, or delete any path in §3;
- "clean up" `/run/northnarrow/` or `/etc/northnarrow/` files you don't
  recognise — recognise the baits and leave them;
- script config management that rewrites `/etc/northnarrow/*` wholesale
  without excluding the bait names.

If you legitimately need to change agent behaviour, use the **signed
`nn-admin`** control surface — never these files (they do nothing).

## 6. Boot integrity sweep

At every boot, after its BPF programs attach, the agent verifies all ten
baits exist and recreates any that are missing from an embedded
template. Because the agent is in `PROTECTED_PIDS`, this recreate is
exempt and never self-triggers NN-L-FIM-024.

- All present → `Honeypot integrity: 10/10 present` (Info).
- Anything recreated, or unrestorable → a Medium
  `NN-L-FIM-024-INTEGRITY` log line listing what was recreated / could
  not be restored. A bait that was *missing at boot* is itself a tamper
  signal (an attacker who deleted it before the agent started).

## 7. Recovery — clearing an accidental COMBAT

If you (or a misconfigured tool) trip a bait, the host enters COMBAT
(loopback-only). To recover:

1. **Confirm it was you**, not an intruder — check the agent log for the
   `NN-L-FIM-024` verdict and the `modifier_comm` / `modifier_pid` of the
   tampering process. If it wasn't an authorized action, treat the host
   as compromised and follow your IR process instead of clearing.
2. Clear COMBAT via the signed admin path — `nn-admin` posture
   reset/unlock (see the admin CLI reference). COMBAT does **not** clear
   on its own; the explicit, audit-chained operator decision is the
   point.
3. The bait the agent killed for is recreated automatically at the next
   integrity sweep / boot; you do not restore it by hand.

## FAQ

**Q: Can I disable the honeypots?**
They are part of the shipped ruleset; there is no per-bait off switch.
If a specific path conflicts with a real workflow on your host, raise it
— the bait set is intentionally small and can be adjusted in a release.

**Q: Will normal admin work trip them?**
No. No documented operator task reads or writes these paths; the signed
`nn-admin` surface is the supported control plane.

**Q: A bait reappeared after I deleted it. Bug?**
No — that's the §6 boot integrity sweep restoring it. (Deleting it also
fired NN-L-FIM-024.)

**Q: Why do some baits sit in a directory I can't even write to as root?**
The `/var/lib/northnarrow/` baits are inside the anti-tamper deny zone
(§3) — the kernel LSM blocks writes there from any non-agent process,
which is intended.
