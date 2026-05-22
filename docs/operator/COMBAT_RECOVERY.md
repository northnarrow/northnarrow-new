# Recovering from COMBAT

*Beta Step 4 — COMBAT reconcile, management carve-out, and admin-key
bootstrap.*

When NorthNarrow confirms an intrusion it escalates posture to
**COMBAT** and the agent isolates the host: `iptables-restore` installs
the `NORTHNARROW_COMBAT` chain, which drops every non-loopback packet.
COMBAT has **no automatic exit** — that is by design (a confirmed
compromise should stay contained). This page covers how to get a host
back, and the safety nets that keep you from being locked out.

---

## 1. The admin key (do this at install time)

Releasing COMBAT requires an **Ed25519 admin key**. On a fresh install
`install.sh` bootstraps one (`nn-admin init`) if `/etc/northnarrow/admin.pub`
is absent, and prints a loud warning: the **private** half is written
to `/etc/northnarrow/admin.key` and you **must move it off the host**:

```sh
mv /etc/northnarrow/admin.key  <secure-offline-location>
```

Leaving the private key on the host means anyone with root on that host
can release COMBAT — defeating containment. Keep only `admin.pub` on the
host.

> If `admin.pub` does not exist, COMBAT is **unrecoverable** except by
> reboot. Always provision an admin key.

---

## 2. Avoiding lockout: the management carve-out

If you administer hosts remotely, full isolation can lock you out before
you can run the unlock. The **opt-in** management carve-out keeps an SSH
path open from a network you declare.

Edit `/etc/northnarrow/combat-allow.cidrs` and add your management
network (one IPv4 address or CIDR per line):

```
# management jump host / admin subnet
198.51.100.7
10.0.10.0/24
```

- **Default is empty** = full isolation (no carve-out).
- Each entry is allowed **both inbound and outbound**, so an SSH session
  to/from it survives COMBAT.
- The file is **re-read at every COMBAT engage** (never cached) — you can
  add an emergency CIDR from a local console and it applies the next time
  isolation engages.
- **Fail-secure**: a malformed line is skipped (and logged), never
  widened; an unreadable file applies no carve-out.
- It is intentionally **not** in the FIM deny-zone, so you can edit it
  during an incident. Changes are still FIM-observed (audited).

> Security note: anything you carve out is **not** contained during an
> incident. Only list networks you trust to reach a possibly-compromised
> host. COMBAT isolation is currently IPv4-only; IPv6 entries are
> validated but produce no rule (none is needed).

When a carve-out is active, the COMBAT engage logs at **WARN** and lists
the CIDRs — they are conspicuous in the audit trail on purpose.

---

## 3. Releasing COMBAT (the normal path)

From a host that has the **private** key and a route to the agent's
admin socket:

```sh
# Check current posture + isolation state first:
nn-admin status

# Release COMBAT (preferred path — signs a server-issued challenge):
nn-admin unlock --key /path/to/admin.key
```

`unlock` drops posture out of COMBAT and tears down the
`NORTHNARROW_COMBAT` chain. (`nn-admin force-posture` exists too but
`unlock` is the preferred COMBAT-release path.)

---

## 4. Recovering from an agent crash mid-COMBAT

If the agent dies while in COMBAT, the `NORTHNARROW_COMBAT` iptables
chain would otherwise be left behind, isolating the host with no live
posture state behind it (the "split-brain"). NorthNarrow handles this
**automatically**:

- On startup the agent boots into `OBSERVING`. If it finds a stale
  `NORTHNARROW_COMBAT` chain, it tears it down and logs at **WARN**:
  `"stale COMBAT chain detected at boot — torn down …"`.
- An audit line is appended to
  `/var/lib/northnarrow/combat-audit.jsonl`
  (`{"event":"combat_reconcile","reason":"stale_reconcile",
  "rules_torn_down":N,…}`).

So after a crash + restart the host comes back on the network on its own.

> **If the threat is still active**, the posture machine will re-confirm
> the intrusion and re-engage COMBAT within seconds. You can also force
> it immediately:
>
> ```sh
> nn-admin force-posture combat --key /path/to/admin.key
> ```

### Known limitation (documented for V1.0+)

This reconcile is restart-scoped only — there is no persistent posture
state across reboots yet, so an attacker who can crash the agent causes
the chain to be torn down on restart, effectively lifting COMBAT. This
is mitigated by the anti-tamper LSM hooks (the agent and watchdog PIDs
are in `PROTECTED_PIDS`; SIGKILL/ptrace against them is denied), and a
successful kill implies kernel-level compromise (the attacker has
already won). Crash-resilient persistent COMBAT is on the V1.0+ roadmap.

---

## 5. Quick reference

| Situation | Action |
|-----------|--------|
| Provision admin key | `install.sh` auto-bootstraps; **move `admin.key` offline** |
| Avoid remote lockout | add your mgmt CIDR to `/etc/northnarrow/combat-allow.cidrs` |
| Check state | `nn-admin status` |
| Release COMBAT | `nn-admin unlock --key <admin.key>` |
| Re-engage after crash | `nn-admin force-posture combat --key <admin.key>` |
| Crash mid-COMBAT | automatic stale-chain reconcile on restart (see §4) |

Related: `configs/combat-rules.v4`,
`agent/src/anti_tamper/network_isolate.rs`,
`agent/src/anti_tamper/combat_allow.rs`.
