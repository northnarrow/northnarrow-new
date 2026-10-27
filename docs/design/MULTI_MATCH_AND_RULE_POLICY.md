# Multi-match decisions and the signed per-rule response policy (lab PR 236)

Wave 4, Phase 2, capabilities C14 (behavioural detection: multi-match) and
C12 (a response policy per rule). Code: `agent/src/decision/engine.rs` (the
engine), `agent/src/decision/combine.rs` (the combiner),
`agent/src/decision/rule_policy.rs` (the policy: format, defaults, exemptions,
the active policy), `agent/src/decision/response_policy.rs` (the built-in
switches). Userland only: no eBPF program and no sensor changes.

Status: accepted, 22/10/2026 (founder-delegated decision); the legacy
ceiling (§2.1) added the same day, on review.

## 1. Context

Until this lot the engine evaluated the rules in their registration order and
the first rule that returned a verdict won; the later rules never saw the
event ("rule shadowing"). Known consequences:

| shadowed | by | effect |
|---|---|---|
| NN-L-FIM-023 (systemd timer created) | NN-L-FIM-009 (unit dropped), same paths | FIM-023 never fired |
| NN-L-FIM-004 (authorized_keys, kill) | NN-L-FIM-002 (new set-id file, record) | a new `authorized_keys` under `/home` was a Log, not a kill |
| NN-L-NET-009 (UDP / volume to internal hosts, High) | NN-L-NET-007 (internal flow, Medium) | the UDP accumulator never grew, a large internal transfer got Medium |
| R001 / R009 (the exec's own kill) | NN-L-CHAIN-007 on a late exec (lab PR 235) | the exec's record named only the chain |

Lab PRs 219–226 also added kills that the decision of 21/10/2026 holds behind
`PolicySwitch`es, off by default, until a signed per-rule policy can turn
them on. The engine had a special path for them ("a held verdict lets a later
kill through"); multi-match makes it unnecessary.

## 2. Decision algorithm

For each event the engine evaluates **every** rule, in registration order
(the flow ledger of lab PR 224 still skips a rule that already answered the
same flow). Every rule's `evaluate` runs, so every stateful rule (chains,
windows, accumulators, the correlation store) sees every event: the state is
updated by every rule, not only a winner. Each verdict is a **match**.

Each match then goes through the per-rule policy (§3), which gives it its
**mode**:

| mode | the match |
|---|---|
| `off` | dropped from the decision (the rule still ran, its state is kept) |
| `audit` | listed in the record, `Log`; it does not set the decision's severity, action or primary unless every match is `audit` |
| `alert` | `Log`, listed and counted (severity, primary) |
| `enforce` | the rule's own response, a held kill included |
| `builtin` (no policy line) | today's behaviour: the rule's own response, a held kill stays held (`Log`) |

An exempt match (§3.3) becomes `audit`, its reasoning naming the exemption.

The decision is computed from the set:

- **action**: the strongest action among the matches whose mode allows one
  (`builtin`, `enforce`), a `builtin` one under the legacy ceiling (§2.1).
  Strength, weakest first: `Log`, `ThrottleProcess`, `StripFileCapability`,
  `BlockOutbound`, `Quarantine`, `KillProcess`, `KillProcessTree`,
  `FullNetworkIsolation`.
- **responses** (what the executor runs): per target, the strongest action
  aimed at it. A target is the verdict's process (`event_pid`) for the
  process actions and the verdict's file for `StripFileCapability`, so a
  kill of the writer and the strip of the file it granted a capability both
  run; two kills of the same process run once (the stronger one). The
  responses are ordered by strength, then by the rule order.
- **severity**: the maximum over the counted matches.
- **primary rule**: the counted match with the highest severity, then the
  strongest action (its own, also when the legacy ceiling holds it), then
  the most specific — the earliest in registration
  order, which already encodes specificity (Critical first in each family,
  refinements before their general rule). The decision's `rule_id`,
  `rule_name`, `category`, reasoning and target are the primary's; the
  reasoning ends with `[also matched: <rule> (<action>, <severity>), …]`.
- **record**: the primary rule as before, plus `matches`: every match in
  registration order, with its action, severity, mode, target and ATT&CK ids,
  and, when its response is held, what holds it (`held`: a switch's text or
  `legacy_ceiling`) and the action held back (`held_action`).
  The record's `mitre` is the union of the matches' ATT&CK references, the
  primary's first (lab PR 221's ordering inside each). `matches` is absent
  on a single-match record, so such a line keeps its bytes.
- **flow ledger**: every matched rule is noted for the flow (lab PR 224), so
  none answers the same flow twice.

### 2.1 The legacy ceiling

Multi-match must not unmask a destructive response by default. A rule that
the first-match engine never reached on an event never ran its response
there: FIM-004's kill of the writer of a new `authorized_keys` under `/home`
was FIM-002's record, so an administrator's `ssh-copy-id` was recorded, not
killed. Running every match's response would turn on, at once and without
anyone deciding it, every kill that shadowing had hidden.

Rule: **without a signed policy that says `enforce` for the rule supplying
the stronger action, the action executed for an event never exceeds the
action the first-match engine would have executed on that same event.** The
combiner computes that action from the same match set
(`combine::legacy_first_match`): the first rule in registration order that
fired, with the held-kill switches applied — a switch-held verdict let a
later rule's response through and outranked a later record, exactly as the
engine did before this lot — on the rules' own verdicts before the policy,
`off` rules included (turning the first rule off never unmasks a later
one). Then each `builtin` match that would act is held unless its action is
at most that action **and** aimed at the same target (the legacy winner's
process, or its file for `StripFileCapability`): its action becomes `Log`,
the record says `held: "legacy_ceiling"` with the action in `held_action`,
and its reasoning ends with `[legacy ceiling: <action> held — the first-match
engine ran <what> on this event; `enforce <rule>` in the signed per-rule
policy lifts it]`. Every match is still recorded, the severity is still the
maximum, and the primary rule may be the held one. An `enforce` match is not
capped. `--detect-only` still overrides everything.

Lifting it per rule: `enforce NN-L-FIM-004` (golden case
`policy-fim004-enforced`). The ceiling never lowers a response: the legacy
winner's own runs, and a weaker response on its target runs within it.

Determinism: the inputs of the combiner are the rule order (fixed at engine
construction), the verdicts (pure functions of the event and the engine's
state) and the policy (immutable `Arc`, swapped atomically between events).
Every tie-break ends on the registration index, which is unique, so the same
stream gives the same output on any run and thread (the golden replay
checks it on 4 threads, 3 runs).

Cost: the engine already evaluated every rule on an event no rule matched
(most events). Multi-match adds, on a matching event, the rules after the
first match (bounded by the rule count, ~80) and the combiner (linear in the
matches, no allocation beyond the match vector). The policy lookup is a hash
of the matched rule id, only on a match. An exemption check reads `/proc`
only when a matched rule has an exemption of that kind (§3.3); the hash of an
executable is cached by (device, inode, size, mtime, ctime), 64 entries.
Budget: the lab-228 metrics stay within `deploy/lab/perf/thresholds.tsv`
(`cargo xtask perf-compare`).

## 3. The per-rule policy

### 3.1 Format

`/etc/northnarrow/rule-policy.local`, overlay kind `rule-policy`
(`OverlayKind::RulePolicy = 15`, appended: the encoding is positional). One
directive per line; `#` starts a comment; blank lines are ignored. A rule is
named by its full id (`NN-L-IMP-001_RansomwareEncryption`) or its short id
(`NN-L-IMP-001`, `R020`).

```
enforce <rule>                       # the rule's own response, a held kill included
alert   <rule>                       # recorded and counted, Log
audit   <rule>                       # recorded only
off     <rule>                       # dropped from the decisions
exempt  <rule> uid <uid>             # not uid 0
exempt  <rule> exe <path> sha256 <hex>
exempt  <rule> cgroup <cgroup path>  # ends in a .service or .scope
exempt  <rule> unit <unit name>      # a .service or .scope
combat-without-corroboration NN-L-IMP-001
```

Any bad line refuses the whole file, at `overlay set` and at boot: an unknown
keyword or rule, a rule outside the engine (NN-L-AT-001, NN-L-EPG-*,
NN-L-EXECPOL/EXECENV-*, NN-L-EXECQ-001 are decided elsewhere), two modes for
one rule, an exemption by `comm` or `name` (never: any user picks a process
name), an executable outside a root-owned system tree (`/usr`, `/bin`,
`/sbin`, `/lib*`, `/opt`), a digest that is not 64 hex digits, uid 0, a
cgroup that is not absolute or names no unit, `..`, more than 64 exemptions
for one rule, more than 4,096 lines.

`combat-without-corroboration NN-L-IMP-001` is the policy's form of
`posture_types::RANSOMWARE_COMBAT_WITHOUT_CORROBORATION`: the ransomware
trigger reaches COMBAT without corroboration (it never locks it, lab PR 225).
Lab PR 249: the posture reads it from the policy handle it is given
(`PostureMachine::with_rule_policy`; the agent's is the engine's,
`rule_policy::global()`), as the engine reads its modes — `nn-admin policy
set` reaches both at the next event. It was a process-wide flag that
`install_global` set beside the handle.

### 3.2 Built-in defaults

Without a policy every rule is `builtin`. The `PolicySwitch` constants of
`response_policy.rs` stay the built-in values: each held kill stays held
(`Log`, the reasoning naming it) unless its rule is `enforce`, the legacy
ceiling (§2.1) holds every response the first-match engine would not have
run unless its rule is `enforce`, and the posture flag is off. `enforce
<rule>` therefore lifts both the rule's switch and the ceiling for that rule.
`nn-admin policy show` prints the effective table, the switches and the
ceiling.

A switch holds a response inside the rule (`PolicySwitch::hold`); it now also
keeps the response it held (thread-local, read by the engine around each
rule). `enforce` gives it back.

### 3.3 Exemptions

An exemption makes the rule's match `audit` for that actor (the actor is the
verdict's target process). Kinds:

- `uid` — the event's principal (or `/proc/<pid>/status` when the verdict
  names another process).
- `exe <path> sha256 <hex>` — `/proc/<pid>/exe` is opened, the opened file
  must be root-owned, not group- or world-writable, every directory up to `/`
  root-owned and not group- or world-writable, its path the exemption's, and
  the SHA-256 of the opened file the exemption's.
- `cgroup <path>` / `unit <name>` — `/proc/<pid>/cgroup` (the v2 line); a
  unit matches the last `.service` / `.scope` component.

Fail closed: when a fact cannot be read (the process is gone, `/proc` is
empty in the golden replay) the match is not exempt. A root attacker can move
into a cgroup or run as an exempt uid: exemptions narrow false positives, they
are not a trust boundary (root can already stop the agent's rules through
other means only with a signed key; this is the same trust as the comm
allowlist's identity check, never weaker than it: never by name alone).

### 3.4 Signing

As every overlay (`agent/src/config/overlay_auth.rs`): `<file>.sig` binds the
kind, SHA-256 and length of the exact content, signed by a key with the
`config-manage` role in `admin.pub`, for this agent id, not older than the
last accepted signature for the kind (rollback floor). `nn-admin policy set`
signs and stores through the agent (the `config overlay set` verb); `nn-admin
config overlay sign rule-policy` signs offline.

### 3.5 Boot, change and failure

- Boot: the overlay gate reads the file once. Absent: built-in defaults.
  Signed and valid: in force, a signed `config_overlay_accepted` row when new,
  and a signed `rule_policy_loaded` row with the digest and the counts.
  Unsigned or bad signature: refused (`integrity_drift unauthorized_overlay`),
  built-in defaults. Signed but not parsing (a file `overlay set` would have
  refused): built-in defaults and a signed degradation `rule_policy`.
- Change (`nn-admin policy set`): the agent verifies the signed request,
  validates the content, stores it, and swaps the in-memory policy at once
  (between two events); the signed `config_overlay_set` row records it, with
  `applied` in its detail. A refused request changes nothing: the previous
  policy stays in force, and the refusal is a signed `config_overlay_set` row
  with `failure: rejected (…)`.
- Roll back: `nn-admin policy set` with the previous file (a newer signature
  of older content; the floor refuses an older signature, not older content).
  **A policy of comments only restores the built-in defaults** at once (held
  kills held, the legacy ceiling everywhere); `nn-admin policy show` then
  reads "every rule: builtin".
- `--detect-only` overrides every mode: the executor runs nothing (dry run),
  the kernel denies nothing; the records say `suppressed (detect-only)`.

### 3.6 `nn-admin policy`

- `show [--file]` — the effective table (built-in, or the signed file, with
  its gate decision), the switches, the posture flag.
- `set --file F --key K` — validate locally, then sign and store through the
  agent (role `config-manage`); applied at once.
- `test --policy F --events E [--config-dir D]` — replay a sample event file
  (one `nn_model::Event` JSON per line, or a golden case) through an offline
  engine (shipped lists, empty `/proc`) with the candidate policy and print
  each decision. Nothing is signed, stored or applied.

## 4. Migration

- Records: `matches` is new and absent on single-match records; `mitre` of a
  multi-match record is the union. Consumers that read `rule_id` keep working
  (the primary).
- Golden replay: format `northnarrow-golden/2` (a line carries `matches` and
  `primary`; the header the policy). Every case was reviewed (PR body): no
  rule that fired before is lost; held kills stay `Log` without a test
  policy.
- The tests that pinned first-match orderings now pin the combiner.
- No configuration change is needed: without a policy the executed responses
  are the first-match engine's (the legacy ceiling, §2.1); the shadowed
  rules of §1 are recorded, and their responses wait for `enforce`.

## 5. Performance budget

Per matching event: ≤ all rules evaluated (already the case on a
non-matching event), one `Vec` of matches, one policy lookup per match, the
combiner linear in the matches. Measured with the lab PR 228 harness on
ubuntu2404: `cargo xtask perf-compare` against the committed baseline within
`thresholds.tsv`.

## 6. Follow-ups

- The posture is outside the policy: the posture triggers read events, not
  verdicts, so `off`, `audit` and the exemptions silence a rule's record and
  response, not a posture escalation the same signal raises; only the
  ransomware COMBAT flag is in the policy. A per-trigger policy is a
  follow-up (R12's priority bus is where the triggers move).
