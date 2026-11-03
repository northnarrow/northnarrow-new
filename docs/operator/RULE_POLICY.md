# The per-rule response policy (lab PR 236)

Every detection rule has a built-in response: a record (`Log`), a kill of the
process or of its tree, a capability stripped from a file. Some kills added by
lab PRs 219–226 are **held** by default (recorded as an alert, the process left
running) until an operator turns them on. The per-rule response policy is
where you do that, rule by rule, and where you tone a noisy rule down or
exempt one known program from it. Design:
https://github.com/northnarrow/northnarrow-new/blob/main/docs/design/MULTI_MATCH_AND_RULE_POLICY.md

Without a policy nothing changes in what the agent *does*: every held kill
stays held, and no event gets a stronger response than the agent gave it
before lab PR 236 (the legacy ceiling, §1). What changes is what it
*records*: every rule that matches an event is named.

## 1. What a decision is

Since lab PR 236 every rule judges every event. When several rules match, the
agent writes **one** record that names all of them (`matches`, each with its
ATT&CK ids), with a primary rule (the highest severity, then the strongest
action, then the most specific rule), and runs, for each process concerned,
the strongest response the matched rules' modes allow. A rule set to `audit`
or exempt for the actor never raises that response.

**The legacy ceiling.** Before lab PR 236 only the first matching rule
answered an event, so some responses never ran: a new `authorized_keys`
under `/home` was NN-L-FIM-002's record, never NN-L-FIM-004's kill. To keep
an administrator's `ssh-copy-id` from being killed the day the agent is
upgraded, a rule without `enforce` never runs more than the first-match
engine would have run on that event (on the same process). Such a match is
recorded with `held: "legacy_ceiling"`, the action it asked for in
`held_action`, and its reasoning names the directive that lifts it:
`enforce <rule>`. To turn FIM-004's kill on:

```
enforce NN-L-FIM-004
```

## 2. Writing a policy

`/etc/northnarrow/rule-policy.local`, one directive per line, `#` comments.
Name a rule by its full id or its short id (`NN-L-IMP-001`, `R020`; see the rule catalogue,
https://github.com/northnarrow/northnarrow-new/blob/main/docs/detection/RULE_CATALOGUE.md).

| directive | effect |
|---|---|
| `enforce <rule>` | the rule's own response, **its held kill included**, above the legacy ceiling |
| `alert <rule>` | recorded as an alert (counted for severity), no response |
| `audit <rule>` | recorded only (no alert line, not counted) |
| `off <rule>` | not recorded, no response (the rule still runs, so chains and windows keep their state) |
| `exempt <rule> uid <uid>` | that uid's matches of the rule are recorded only (not uid 0) |
| `exempt <rule> exe <path> sha256 <hex>` | that executable — root-owned, in `/usr`, `/opt`, `/bin`, `/sbin`, `/lib*`, `/snap` or `/nix/store`, every directory up to `/` root-owned, no one else may write it, and its content exactly that digest |
| `exempt <rule> cgroup <path>` | processes of that cgroup v2 path (it must end in a `.service` or `.scope`) **started there** (§2.1) |
| `exempt <rule> unit <name>` | processes of that systemd unit (`backup.service`) **started there** (§2.1) |
| `combat-without-corroboration NN-L-IMP-001` | the ransomware trigger reaches COMBAT without a second signal (it never locks COMBAT) |

An exemption is **never** by process name: `comm`, `name`, `process` and
`argv` refuse the file (any user can name a process `sshd`). When the agent
cannot read a fact (the process is gone), the match is not exempt.

Any bad line refuses the whole file: an unknown rule or keyword, two modes
for one rule, a rule decided outside the engine (NN-L-AT-001, NN-L-EPG-*,
NN-L-EXECPOL/EXECENV-*, NN-L-EXECQ-001), a refused exemption, more than 64
exemptions for one rule.

Example — enforce the ransomware kill, keep the backup service out of it:

```
# rule-policy.local — signed by config-manage
enforce NN-L-IMP-001
exempt  NN-L-IMP-001 unit backup.service
exempt  NN-L-IMP-001 exe /usr/bin/restic sha256 3f1c…(64 hex digits)
```

### 2.1 Exemptions by cgroup or unit: started there, not moved there (lot 277)

A cgroup's members are not all what the unit started: root can write its
own pid into `/sys/fs/cgroup/system.slice/backup.service/cgroup.procs`, or
start a child there with `clone3(CLONE_INTO_CGROUP)`, and is then "in"
`backup.service`. Since lot 277 an exemption by `cgroup` or `unit` holds
only for a process **started in that cgroup**: spawned into it by systemd
(PID 1), or forked from a process that was.

The kernel tells them apart (`agent-ebpf/src/cgroup_join.rs`, the
start-in-cgroup tracker). It marks a process that was moved into a cgroup
by anyone but systemd's placement, or started by `CLONE_INTO_CGROUP` by
anyone but PID 1. A process it forks after that is marked too, before it
runs, and the mark goes when its last thread exits. The rule's match of a
marked process is not exempt by `cgroup` or `unit`. An exemption by `uid` or
`exe` still covers it: those name the actor, not where it runs. systemd's
placement is a move PID 1 makes (a unit's process at its start, a scope's
process, a process systemd was asked to attach), or the move a child of
PID 1 makes of itself before it ran any program (systemd up to 254 forks,
the child moves itself, then executes the unit's command). A move that
changes nothing is no move: systemd 255's executor moves itself after PID 1
or `CLONE_INTO_CGROUP` already did.

A move into a cgroup an exemption names, by anyone but systemd's placement,
is a **signed detection**: NN-L-AT-001 with `operation` `cgroup_join`
(Log, High). It is not refused, and it raises no posture trigger. The record
names the mover (`principal`, `exe`) and, in `response`, the exemption the
moved tree lost. The move goes through; what the moved process does is
judged by the rules without the exemption. The kernel matches the
destination's whole path against the `cgroup` exemptions and each of its
components against the `unit` names: a move into a cgroup below an exempt
unit (`backup.service/sub`) is signed too. A destination longer than 256
bytes is signed without a name while any such exemption is in force.

Where the exemption is refused:

- on a kernel without the tracker (its targets not in the shape its
  programs read: `northnarrow-agent --btf-check` prints `tracker
  cgroup_join`; a signed `subsystem_degraded` "cgroup exemptions" at
  every start) — every exemption by cgroup or unit;
- after the kernel could not take a mark (32768 marked processes alive at
  once; the counter is pinned): every exemption by cgroup or unit, until
  the host reboots — never one mark lost in silence.

What it does not cover, as measured:

- **A root that changes the unit itself** — a drop-in that rewrites
  `ExecStart=`, a transient unit given the exempt unit's name where none is
  loaded, systemd asked over D-Bus to attach a process
  (`AttachProcessesToUnit`). Those are systemd's placements: the unit
  exemption trusts the unit's definition. To bind an exemption to a
  program, use `exe <path> sha256 <hex>` (a rewritten unit runs another
  digest).
- A move made while no agent ran (before its first start, or between a
  stop and the next start: the marks are pinned and outlive a restart, the
  programs do not run without the agent).
- A start by `CLONE_INTO_CGROUP` is marked, not signed: the kernel's fork
  path gives no destination path to match cheaply.
- The same principle holds for any future exemption by container or
  workload: a process counts as the workload's when the workload's runtime
  started it there, never because its cgroup says so.

## 3. Testing it before it is signed

`nn-admin policy test` replays sample events through an offline engine (the
shipped lists of `--config-dir`, an empty `/proc`) under the candidate and
prints each decision. Nothing is signed, stored, applied or executed.

```sh
nn-admin policy test --policy ./rule-policy.local --events ./sample.jsonl
nn-admin policy test --events ./case.json                  # a golden case of the repository, built-in defaults
nn-admin policy test --policy ./rule-policy.local --events ./sample.jsonl --json
```

The events are one `nn_model::Event` JSON per line (as the agent serialises
them), `{"event": …}` per line, or a golden case. Exemptions by exe, cgroup
or unit never match offline (there is no `/proc` to read); a uid exemption
does.

## 4. Signing and applying it

The policy is an overlay, signed like every other (`config-manage` role in
`admin.pub`, this agent's id, newer than the last accepted signature):

```sh
sudo nn-admin policy set --file ./rule-policy.local --key <config-manage key>
# prints the summary, then: … written; applied now (1 enforce, …; replaces built-in defaults)
sudo nn-admin policy show
```

The agent verifies the signed request, validates the content, stores the file
and its `.sig`, and applies the policy at once (between two events). The
signed `config_overlay_set` audit row records it (`applied now` in its
detail). At each boot a signed policy in force writes a signed
`rule_policy_loaded` row. Offline (agent stopped):
`nn-admin config overlay sign rule-policy --file … --key …`.

Refusals:

- a bad line: `policy set` refuses before sending (exit 2), and the agent
  refuses it too; the policy in force stays;
- an edited or unsigned file at boot: not loaded, the built-in defaults
  apply, a signed `integrity_drift` (`unauthorized_overlay`);
- a signed file that does not parse at boot (an older agent's format): the
  built-in defaults apply, a signed degradation `rule_policy`.

`--detect-only` overrides every mode: no response runs, the kernel denies
nothing; the records say `suppressed (detect-only)`.

## 5. Rolling back

- To the previous policy: `nn-admin policy set --file <the previous file>`
  (a new signature over the older content; the rollback floor refuses an
  older *signature*, not older content).
- To the built-in defaults: `nn-admin policy set` with a file that has only
  comments — applied at once: every held kill held again, the legacy
  ceiling on every rule.
- `nn-admin policy show` exits 1 when a present file would not be loaded.

## 6. Reading the records

`nn-admin detections` / the signed `detections.jsonl`: `rule_id` is the
primary rule; `matches` (absent on a record of one rule under the built-in
defaults) lists every rule with its `action`, `severity`, `mode`
(`builtin`, `enforce`, `alert`, `audit`, `exempt`), `pid`, ATT&CK ids, the
switch or the legacy ceiling still holding it (`held`: the switch's text or
`legacy_ceiling`, with `held_action`) and the exemption that covered the
actor (`exempt`). A held kill reads `Log` with its reasoning ending in
`[held back: …]`; an enforced one names the policy.
