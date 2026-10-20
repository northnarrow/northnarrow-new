# Recovering from COMBAT

*Beta Step 4 — COMBAT reconcile, management carve-out, and admin-key
bootstrap.*

When NorthNarrow confirms an intrusion it escalates posture to
**COMBAT** and runs the active-response ladder: INVESTIGATE (network up,
the offender's own egress blocked), NEUTRALIZE (the offending process tree
killed and its binary quarantined), and only if that cannot contain the
threat, ISOLATE — `iptables-restore` / `ip6tables-restore` install the
`NORTHNARROW_COMBAT` chain, which drops every non-loopback packet of both
families. External audit POS-001: ISOLATE runs only in a **locked** COMBAT
(kernel-adjudicated evidence, root changing a system file outside an
administrator's session, or an administrator's order); a COMBAT reached on
heuristics alone is unlocked — it never isolates and decays once quiet. A
locked COMBAT has **no automatic exit** — that is by design (a confirmed
compromise should stay contained). This page covers how to get a host
back, and the safety nets that keep you from being locked out.

---

## 1. The admin key (do this at install time)

Releasing COMBAT requires an **Ed25519 admin key**. On a fresh install
`install.sh` bootstraps one (`nn-admin init`) if `/etc/northnarrow/admin.pub`
is absent, and prints a loud warning: the **private** half is written
to `/root/northnarrow-admin.key` (`--admin-key-out PATH` to choose another
place — never under `/etc/northnarrow` or `/var/lib/northnarrow`, which
`install.sh` refuses) and you **must move it off the host**:

```sh
mv /root/northnarrow-admin.key  <secure-offline-location>
```

Leaving the private key on the host means anyone with root on that host
can release COMBAT, open a trusted-installer window (the anti-tamper
suspended) and sign overlays — defeating containment. Keep only
`admin.pub` on the host. While a key sits at `/root/northnarrow-admin.key`
or `/etc/northnarrow/admin.key` (where installs before external audit
DEP-001 wrote it), the agent records it at every start and while it stays
(`integrity_drift`, kind `admin_key_on_host`, signed) and
`nn-admin host-check` reports `WARN admin_key`. Nothing on the host uses
that key on its own: upgrades and removals take it only when you pass it
(`--grant-key`, `NN_GRANT_KEY`).

> If `admin.pub` does not exist, COMBAT is **unrecoverable** except by
> reboot. Always provision an admin key.

### 1.1 What the install key can do (roles)

`admin.pub` holds one line per key: `<hex64-pubkey> [role,role,...]`.
A line **without** a role list — which is what `nn-admin init` writes —
gets the default allowlist **`unlock,audit-read`** only. `install.sh`
appends an explicit list to the line it bootstraps,
`unlock,audit-read,trusted-installer,config-manage`: `trusted-installer` is
what `install.sh --upgrade --grant-key` and `uninstall.sh --grant-key` use
to open the window that lets them purge the protected pin root (review
entry 39); `config-manage` signs the `*.local` overlays the agent loads
(Tappa 10.8). A key bootstrapped before those changes lacks them; add
them to its line before the next upgrade. The key releases COMBAT, reads
the audit log, opens the installer window and signs overlays, and nothing
else: `nn-admin canary deploy|burn|refresh` (`canary-manage`),
`fim baseline` (`fim-manage`), `response release|restore`
(`response-manage`, §6), `force-posture`, `shutdown` and `rotate-keys` are
refused with an authorisation error.

`response-manage` undoes what the response layer did: it releases a
contained process and writes a quarantined file back out of the vault
(§6). A restore can put malware back on disk, so the role is never in a
default allowlist and `install.sh` does not grant it: give it to a
dedicated key, the way the canary example below does.

Grant extra roles either by editing the line in `admin.pub` (the agent
re-reads it at start; the file is write-protected by the agent's
inode guard, so do it from a root shell **before** starting the unit,
or through `rotate-keys add`), or by adding a dedicated key:

```sh
# dedicated canary-operator key, generated offline
nn-admin init --priv-out canary-ops.key --pub-append /dev/null
nn-admin rotate-keys add --new-pubkey <hex> --new-roles canary-manage,audit-read \
    --key admin.key [--cosign-key ...]
```

`rotate-keys add` delegates, it does not mint (external audit NN-AUD-084):
each role of the new key must be held by one of the signing keys — `all`
only by a key that holds `all` — and an omitted role list stands for
`unlock,audit-read`. The signers of the example above therefore need
`canary-manage` and `audit-read` besides `rotate-keys`. A "custodian" key
holding only `rotate-keys` can no longer add an `unlock` or `all` key: give
it the roles it is meant to delegate. The bootstrap 1-of-N add follows the
same rule. Likewise `force-posture` out of COMBAT releases the containment
like `unlock`, so it needs a key that also holds `unlock` (NN-AUD-083); a
`force-posture`-only key can force COMBAT but not leave it — use
`nn-admin unlock`.

Keep the principle of least privilege: the key that releases COMBAT
does not need `canary-manage`, and a canary operator does not need
`unlock`. The lab runbook's test fixtures grant the roles each suite
needs explicitly, which is why `canary deploy` works there and not
with an untouched install key.

---

## 2. Avoiding lockout: the management carve-out

If you administer hosts remotely, full isolation can lock you out before
you can run the unlock. The **opt-in** management carve-out keeps an SSH
path open from a network you declare.

Write your management network (one IPv4 or IPv6 address or CIDR per line)
into a file, and store it as `/etc/northnarrow/combat-allow.cidrs` with an admin
signature — a key whose `admin.pub` line carries `config-manage`:

```
# management jump host / admin subnet
198.51.100.7
10.0.10.0/24
```

```
nn-admin config overlay set combat-allow --file mgmt.cidrs --key <config-manage key>
```

The agent applies the carve-out only as shipped (empty) or with a valid
signature for its exact content (external audit ATP-001): a carve-out
written by hand — or by an intruder adding their own network — is not
applied, COMBAT isolates without it, and the refusal is an ERROR plus a
signed `integrity_drift` entry. The same holds for `combat-rules.v4` and
`combat-rules.v6` (`combat-rules-v4`, `combat-rules-v6`): an unsigned
change, or a deleted file, makes COMBAT apply the rulesets the agent was
built with. `nn-admin config overlay status` shows what the next COMBAT
will use; `install.sh --upgrade` signs a carve-out edited by hand under an
earlier release with the grant key.

- **Default is empty** = full isolation (no carve-out).
- Each entry is allowed **both inbound and outbound**, so an SSH session
  to/from it survives COMBAT.
- The file is **re-read at every COMBAT engage** (never cached) — you can
  store an emergency CIDR from a local console (`config overlay set`, the
  key on removable media) and it applies the next time isolation engages.
- **Fail-secure**: a malformed line is skipped (and logged), never
  widened; an unreadable file applies no carve-out.
- **At most a /8 (IPv4) or a /48 (IPv6)** per line, and never the
  unspecified (`0.0.0.0`, `::`) or a multicast address (external audit
  NN-AUD-095): a typo such as `10.0.0.0/0` would carve out every address
  and COMBAT would isolate nothing. `config overlay set` refuses such a
  line. In a carve-out signed before this rule it stays signed but is
  skipped at every engage with a WARN, and `nn-admin config overlay
  status` shows it ("N lines skipped at COMBAT engage") — sign the file
  again without it.
- It is protected against deletion and replacement, and its content is
  vouched for by the signature, not by file permissions.

> Security note: anything you carve out is **not** contained during an
> incident. Only list networks you trust to reach a possibly-compromised
> host. COMBAT isolates IPv4 and IPv6 (BUG-031): IPv4 entries become
> iptables ACCEPT rules, IPv6 entries ip6tables ones.

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
- The teardown is signed in the audit chain once it opens (lab PR 180,
  external audit MAIN-013): an `integrity_drift` row of kind
  `combat_reconcile`, `result` `repaired` with `rules_torn_down` — or
  `failed` when the chain could not be checked or torn down, in which case
  the host may still be isolated (by hand, from the console:
  `iptables -D INPUT -j NORTHNARROW_COMBAT` — and `OUTPUT`, `FORWARD`,
  until it fails — then `iptables -F NORTHNARROW_COMBAT; iptables -X
  NORTHNARROW_COMBAT`, the same with `ip6tables`). Check it with
  `sudo nn-admin audit verify && sudo grep '"kind":"combat_reconcile"'
  /etc/northnarrow/audit.log`.
- For compatibility a line is also appended to
  `/var/lib/northnarrow/combat-audit.jsonl`
  (`{"event":"combat_reconcile","reason":"stale_reconcile",
  "rules_torn_down":N,…}`), unsigned; the state directory is immutable
  (`chattr +i`), so the line is added only to a file that already exists
  (created `0600` where the directory is not immutable).

So after a crash + restart the host comes back on the network on its own.

> **If the threat is still active**, the posture machine will re-confirm
> the intrusion and re-engage COMBAT within seconds. You can also force
> it immediately:
>
> ```sh
> nn-admin force-posture combat --key /path/to/admin.key
> ```

### A second isolation, before CMB-006

Agents before external audit CMB-006 could also isolate the host outside
COMBAT: an ADE `Isolate` verdict installed two nftables chains,
`isolation_input` and `isolation_output` (policy drop), in the
`inet northnarrow` table. That isolation had no management carve-out (an
open SSH session died too), no `unlock` and no `status` line. It no longer
exists — host-wide isolation is the COMBAT ladder's alone, and an ADE
`Isolate` verdict kills the process tree it names — and the agent removes
the chains at start (WARN, and a `legacy_isolation_removed` entry in the
signed audit log). By hand, from the console:

```sh
nft flush chain inet northnarrow isolation_input;  nft delete chain inet northnarrow isolation_input
nft flush chain inet northnarrow isolation_output; nft delete chain inet northnarrow isolation_output
rm -f /var/lib/northnarrow/isolated
```

The rest of the `northnarrow` table holds the per-process outbound
blocks; leave it.

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
| Provision admin key | `install.sh` auto-bootstraps; **move `/root/northnarrow-admin.key` offline** |
| Avoid remote lockout | `nn-admin config overlay set combat-allow --file <cidrs> --key <config-manage key>` |
| Check state | `nn-admin status` |
| Release COMBAT | `nn-admin unlock --key <admin.key>` |
| Re-engage after crash | `nn-admin force-posture combat --key <admin.key>` |
| Crash mid-COMBAT | automatic stale-chain reconcile on restart (see §4) |
| Host cut off by an older agent's nftables isolation | agent restart removes it; by hand see §4 |
| See what the response layer holds | `nn-admin response status --key <audit-read key>` (§6) |
| Release a contained process | `nn-admin response release --pid <pid> --key <response-manage key>` |
| Get a quarantined file back | `nn-admin response restore --vault-id <id> [--to <path>] --key <response-manage key>` |

---

## 6. Undoing a response

A response is not always right: a throttled build server, a blocked
backup agent, a quarantined in-house tool. Three signed verbs undo one,
run by the agent itself over the admin socket (it holds the record of
what it did, and the privileges), each recorded in the signed audit log
with the key that signed it (`response_status`, `response_release`,
`response_restore`):

```sh
# what the agent holds: contained processes (scope, the cgroup each came
# from, whether the pid still names that process), the vault, the stage
nn-admin response status --key <audit-read key>

# a process blocked or throttled by the agent, back to its own cgroup
nn-admin response release --pid 4242 --key <response-manage key>

# a quarantined file, back where it was taken from ...
nn-admin response restore --vault-id 3f2a…(32 hex) --key <response-manage key>
# ... or somewhere else, to inspect it first
nn-admin response restore --vault-id 3f2a… --to /root/inspect/sample.bin \
    --key <response-manage key>
```

`response status` needs `audit-read`; `release` and `restore` need
`response-manage` (§1.1). `nn-admin status` also shows the COMBAT stage
and whether COMBAT is locked.

What the verbs will and will not do:

- **Release** works from the containment record
  (`/run/northnarrow/containment.json`): a pid the agent did not contain is
  answered `not contained by this agent`. The process goes back to the
  cgroup it came from, never to the root cgroup, and only while the pid
  still names the process that was moved (same start time); otherwise it
  stays where it is and the reply says why (exit 9). During an open COMBAT
  episode the ladder may contain it again: release COMBAT first (§3) when
  the episode itself was the mistake.
- **Restore** writes a **new** file, mode 0600 owned by root: it never
  replaces an existing file and never follows a symlink, and the directory
  must exist (it is not created). The destination defaults to the path the
  file was taken from; `--to` takes an absolute path. Paths under the
  prefixes the quarantine never touches (`/etc`, `/usr/bin`, `/usr/lib`,
  `/boot`, `/var/lib/northnarrow`, `/run/northnarrow`, the agent's
  binaries, …) are refused, also when a directory of the path is a link
  that leads there. The content is checked against the SHA-256 recorded at
  capture before anything is written. The vault keeps the entry: restore
  again elsewhere if needed.
- **A restored file may be malware.** Restore it to inspect it, or after
  you have established it is not; it comes back non-executable (0600) on
  purpose. The agent detects it again if it runs and is still malicious.

Exit codes: 0 done, 9 verified but nothing done (the reason is printed),
7 role denied, 2 bad signature, 5 transport or an agent without the verbs.

Related: `configs/combat-rules.v4`,
`agent/src/anti_tamper/network_isolate.rs`,
`agent/src/anti_tamper/combat_allow.rs`.
