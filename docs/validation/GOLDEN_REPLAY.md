# Golden replays: the decision engine (lab PR 228), the posture and the COMBAT ladder (lab PR 243)

What the decision path answers to a recorded event stream, kept as a
committed file and checked byte for byte on every `cargo test`: a change of a
rule, of the rule order, of a policy switch, of a shipped list or of the
engine's state handling shows as a diff of a golden file, in the pull request
that makes it. Lab PR 243 adds the same for what acts on the answers — the
posture state machine and the COMBAT ladder (§6) — before the restructure's
R08 moves them into nn-core.

- Harness: `agent/src/decision/golden.rs` (tests of the agent library: no
  root, no network, no guest; part of `cargo test --workspace`).
- Streams: `agent/tests/golden/cases/<case>.json`.
- Golden files: `agent/tests/golden/expected/<case>.jsonl`.
- Fixture host: `agent/tests/golden/host/` (a package database).
- Runner: `cargo xtask golden` (check), `cargo xtask golden --update`
  (rewrite, for review).

## 1. What a replay is

Each case is replayed on a fresh engine built the way `main.rs` builds it:
the 86 rules of `default_rules_with_net`, in their order, over the shipped
lists of `configs/` (process and network comm allowlists, the network and
JA3 blocklists, `security-tools.v1`), the default fan-out thresholds, and
every per-rule policy switch of `agent/src/decision/response_policy.rs` at
its production value — off — under the case's per-rule policy (lab PR 236:
`policy`, the text of a `rule-policy.local`; none: the built-in defaults).
The engine is built by `agent/src/decision/replay.rs`, which `nn-admin policy
test` uses too. Nothing of the machine running the test is read:

| host state | in a replay |
|---|---|
| `/proc` | an empty directory of its own: every process has exited, the lineage is what the stream's exec events taught the cache |
| `/etc`, container storage | the fixture root (`agent/tests/golden/host`), which has none |
| the package database | the fixture root's `var/lib/dpkg`: the programs of `info/golden-fixture.list` are the packaged ones |
| file content (ransomware entropy) | the case's `entropy` answers, by path prefix; any other path samples as plain content |
| files beside the originals (copy-delete) | the case's `files`, created under a directory of the replay's own, written `@ROOT@` in the case and in the golden file |
| the configured resolvers | the case's `resolvers` (none by default: no port-53 flow is exempt) |
| the trusted-installer window | inert (never open) |

The decision path of one item is that of `process_event` (`main.rs`):

1. an exec event (`ProcessSpawn`) is first ingested into the lineage cache,
   as the posture's trigger detector does before the rules see it;
2. an anti-tamper denial (`FsProtectDenial`) is NN-L-AT-001's and an exploit
   post-condition (`ExploitPostcondition`) NN-L-EPG-001/002's, outside the
   engine, with the record's response line;
3. every other event goes to the engine: every rule judges it and the
   decision is computed from all the matches (lab PR 236, multi-match,
   `docs/design/MULTI_MATCH_AND_RULE_POLICY.md`); a held response is an
   alert unless the case's policy enforces its rule;
4. an exec-policy report (`execpol` item) becomes the exec policy's records
   (`execpol::record::records_of`), outside the engine, with their evidence.

Not replayed here: the posture and the COMBAT ladder (they act on verdicts,
they are not verdicts: their own replay is §6), the canary registry (no case
deploys a canary), the
per-rule budget (it decides what is stored, never the verdict), the exec
sensor's path resolution (a case's paths are absolute), the exec
quarantine's scanner (a process, not a rule over events).

## 2. Reading a golden file

The first line names the format (`northnarrow-golden/2` since lab PR 236),
the case, what it is about, the number of rules, every policy switch with its
state and the per-rule policy (`built-in defaults`, or the policy rendered).
Then
one line per item of the stream, in order (`seq`), with its `decision`:

- `null` — nothing fired;
- an object — the verdict: `rule`, `name`, `category`, `action` (what the
  executor would run: `Log`, `KillProcess`, `KillProcessTree`, …),
  `severity`, `pid` (the target), `file`, `ts` (the event's time),
  `reasoning` (as the record carries it), `mitre` (the record's ATT&CK
  field: tactic ids, technique ids — the union of every match's, the
  primary's first) and, for a record made outside the engine, `response`;
- with several matches, or a policy mode on its one match (lab PR 236):
  `rule` is the primary rule (the highest severity, then the strongest
  action, then the earliest registered), `action` the strongest any match's
  mode allows, `severity` the highest of the counted matches, the reasoning
  ends with `[also matched: …]`, and `matches` lists every match in engine
  order (`rule`, `action`, `severity`, `mode` — builtin, enforce, alert,
  audit, exempt — `pid`, `mitre`, `held` when a switch or the legacy
  ceiling still holds its response — the switch's text or
  `legacy_ceiling` — with `held_action`, `exempt` with the exemption), with
  `responses`: what the executor would run, per target. Without `enforce`,
  a match never runs more than the first-match engine ran on the event (the
  legacy ceiling, `docs/design/MULTI_MATCH_AND_RULE_POLICY.md` §2.1);
- for a connect sweep (`tcp_sweep` item), `{"sweep": N, "decisions": [...]}`:
  the expanded events that gave a verdict, by index (`at`);
- for an exec-policy report, the list of its records, each with its
  `execpol` evidence.

A kill held behind a switch reads `"action": "Log"` with the rule's own
severity, and its reasoning ends in `[held back: <what> — alert only, by
default, until the signed per-rule response policy enables it]`. A kill that
predates the holds (R001 and R009 on a `/tmp` exec, NN-L-FIM-010 on a watched
file's own rename, NN-L-CHAIN-002 on port 443, NN-L-NET-001 on a blocklisted
server) reads its kill. A held verdict never stands in for another rule's
response: `port53-held` shows NN-L-NET-001's kill running while
NN-L-CHAIN-002's alert stays held on the same flow (both listed).

## 3. The cases

| case | scenario | shows |
|---|---|---|
| `fim010-ransomware-rename` | a watched file renamed to `.locked`, the same rename's moved-in record, a rename seen only as a watched directory's new entry | NN-L-FIM-010's kill (not held), one verdict per rename, the moved-in kill held (lab PR 225) |
| `imp001-in-place` | lab MS-22: an unpackaged program rewrites 20 files, ciphertext left; rsync rewrites 20 files | NN-L-IMP-001 decisive, kill held; a packaged writer trusted |
| `imp001-copy-delete` | lab MS-23: 20 new files, 20 originals deleted beside their encrypted copies | NN-L-IMP-001 decisive by copies, kill held |
| `imp002-rename-burst` | 20 renames appending one new extension, plain content | NN-L-IMP-002, one shape |
| `eva001-service-stopped` | auditd stopped by a package transaction, by a root shell, by a lineage holding a `/tmp` program | NN-L-EVA-001 sanctioned (Low), unsanctioned (High), the staged program's kill held; R009's kill of the root exec from `/tmp` (not held) |
| `eva-switched-off-killed-config` | `auditctl -e 0` twice, auditd sent SIGTERM, its configuration modified | NN-L-EVA-002 (the repeat coalesced), NN-L-EVA-003, NN-L-EVA-004 |
| `net026-scan-fanout` | 520 addresses on port 445 in 6 s | NN-L-NET-026's record of the process and of its parent's children, then its kill held |
| `net027-auth-bruteforce` | 105 connects to one host's SSH port in 11 s | NN-L-NET-027's record of the process and of its parent's children, then its kill held |
| `r020-shell-socket-stdio` | a reverse shell under a web server, the pty-wrapped variant, a socket-activated shell | R020, its kill held; nothing for socket activation |
| `port53-held` | a `/tmp` program's flows to a configured resolver, to port 53 of another server, to port 53 of a blocklisted server, to port 443 | the resolver exemption; NN-L-CHAIN-002's port-53 kill held (lab PR 224); the held alert not standing in for NN-L-NET-001's kill; the port-443 kill kept |
| `epg-postcondition` | a credential gained with no mechanism (detect), namespaces left with no mechanism (enforce) | NN-L-EPG-001/002 records (lab PR 219) |
| `execpol-records` | memfd exec denied, `/dev/shm` exec in audit, `LD_PRELOAD` from `/tmp`, Looney Tunables, history off, a `/tmp` library mapped | NN-L-EXECPOL-001, NN-L-EXECENV-001..003 (lab PR 226) |
| `shadow-fim009-fim023-timer` | a `.timer` dropped in `/etc/systemd/system` by a `/tmp` program | NN-L-FIM-009 and NN-L-FIM-023 on one record (FIM-023 was never reached before lab PR 236) |
| `shadow-fim002-fim004-authorized-keys` | a new `~/.ssh/authorized_keys` under `/home` | NN-L-FIM-004 (High) primary with NN-L-FIM-002's record (it was FIM-002's Log alone); FIM-004's kill held by the legacy ceiling |
| `policy-fim004-enforced` | the same under `enforce NN-L-FIM-004` | the ceiling lifted: FIM-004's kill runs (mode enforce) |
| `shadow-net007-net009-internal-volume` | 200 MiB over TCP to an internal host, then 101 UDP datagrams of 1 MiB | NN-L-NET-009 (High) primary over NN-L-NET-007; its UDP sum crosses 100 MiB on the 101st datagram |
| `shadow-chain007-late-exec` | a `/tmp` program's key read and connect, its exec record processed last (lab PR 235) | NN-L-CHAIN-007 with R001 and R009 on the late exec, one kill of the tree |
| `chain002-late-exec` | a `/tmp` program's connect, its exec record processed after it, then the flow's close (lab PR 244) | NN-L-CHAIN-002 completed on the late exec, naming the connect, with R001: one kill of the tree; no chain verdict at the close |
| `chain002-late-exec-resolver` | a `/tmp` program's lookup at the configured resolver, its exec record processed after it (lab PR 244) | the resolver exemption kept on a late exec: R001 alone, no chain |
| `policy-imp001-enforced` | `imp001-in-place` under the test policy `enforce NN-L-IMP-001` | the ransomware kill given back (mode enforce); no other held kill moves |
| `policy-r020-exempt-uid` | `r020-shell-socket-stdio` under `enforce R020` and `exempt R020 uid 33`, the same shell under uid 34 | uid 33 exempt (recorded only), uid 34 killed (enforce) |

Each case names in its file the rules it must fire (`fires`, as the primary
rule or a match), those whose held response it must show (`held`), and,
with a `policy`, those it must show enforced (`enforced`) or exempt
(`exempt`); `every_case_shows_what_it_says` checks them, so an update of a golden file that loses a detection fails
even though the file was rewritten. Across the cases the tests also require
NN-L-EPG-001, NN-L-NET-026/027, R020, NN-L-IMP-001/002, NN-L-EVA-001,
NN-L-FIM-010 and NN-L-EXECPOL-001 to fire; every held kill of R020,
NN-L-NET-026/027, NN-L-IMP-001, NN-L-EVA-001 and NN-L-FIM-010 to show as
action `Log` in the cases without a policy; and no response there to be a
held rule's.

The streams are written in the agent's own serialised event format
(`nn_model::Event`, `common::Event` before the Wave 4 restructure), each shaped on a lab scenario (the MS-nn names are those
of `deploy/lab/malsim/`); they were not captured from a kernel. Pids are
above the kernel's `PID_MAX_LIMIT` (4,194,304), so no case's pid is ever the
test process's own (NN-L-NET-026/027 and NN-L-FIM-024 skip the agent's pid).

## 4. Determinism

`golden_replay_is_deterministic_across_runs_and_threads` replays every case
three times on one thread and once on each of four threads at once, each on
its own engine, and requires the same bytes every time. Two kinds of state
could break it and are handled:

- host state — replaced by the replay's own (§1);
- state of the process rather than of the engine — NN-L-FIM-010's
  two-record dedup list (one engine per agent, by design): the cases use
  their own paths and pids, so replays running at once never share an
  entry.

Map iteration order never reaches a golden line: the ransomware tracker
sorts the shapes it names, the JSON is written with sorted keys.

## 5. Updating the golden files

A change that moves a verdict — a new rule, a reworded reasoning, a switch
turned on by the signed per-rule policy, a shipped list edited — fails
`golden_replay_matches_the_committed_files` with the first line that
differs. If the move is intended:

```bash
cargo xtask golden --update        # NN_GOLDEN_UPDATE=1: the tests write expected/
git diff -- agent/tests/golden/expected
```

Read the diff line by line; the pull request says, for each case that moved,
why its verdict changed. A golden file is never edited by hand. CI checks the
files and never writes them: with `CI` set, `--update` and
`NN_GOLDEN_UPDATE=1` are refused, and a stale or missing golden file, or a
golden file without a case, fails `cargo test`.

To add a case: write `agent/tests/golden/cases/<case>.json` (`about`,
`fires`, the optional `held`, `policy`, `enforced`, `exempt`, `resolvers`,
`files`, `entropy`, and `items`:
`{"event": <Event>}`, `{"tcp_sweep": {...}}` or `{"execpol": {...}}`, see
the harness), run `cargo xtask golden --update`, and review its golden file
like any other.

## 6. The posture and the COMBAT ladder (lab PR 243)

What the posture state machine and the COMBAT ladder do with a recorded
event stream: every posture transition (from, to, trigger, the evidence it
cites), every call the ladder makes into its actuator and what the host did,
every signed row the ladder and the trusted-installer window write, and the
state after each step.

- Harness: `agent/src/posture/golden.rs` (tests of the agent library: no
  root, no network, no real process; part of `cargo test --workspace`).
- Streams: `agent/tests/golden/posture/cases/<case>.json`.
- Golden files: `agent/tests/golden/posture/expected/<case>.jsonl`.
- Fixture host: the decision replay's (`agent/tests/golden/host`), plus a
  `/proc` the replay writes from the case.
- Runner: `cargo xtask golden [--update]` runs both replays.

### 6.1 What a replay is

Each case runs on a posture machine, a ladder and a trusted-installer window
wired the way `main.rs` wires them — the entry hook engages the ladder, the
release hook stands it down and lifts the isolation, the decay hook stands
it down, the ladder isolates only while COMBAT is locked, the posture shares
the ransomware tracker and the security-tool detector built over the shipped
lists — and every item goes the way `process_event` takes it for the
posture and the ladder:

1. an event: the clock moves to its time (never back: an event read late is
   processed when it is read); `PostureMachine::observe` over the recent
   events; on the edge into COMBAT, `engage_with` names the event's process
   to the ladder; an engaged ladder sees the event (`observe`, the
   jump-ahead); the correlation buffer keeps it; the two trackers the rules
   share with the posture assess it, as the rules would (memoised: the
   posture's answer);
2. `{"wait": {"secs": N}}`: the clock moves on;
3. `{"unlock": {}}`: a signed unlock (`OperationCode::Unlock`, lab PR 217)
   by the case's administrator, verified by `ConnAuth` as the admin socket
   verifies it, then `admin_release_combat_with_token`;
4. `{"installer_grant": {"window_secs": N}}`: a signed trusted-installer
   grant, verified the same way, then the window armed for its signer;
5. `{"host": {...}}`: the host changes without an event the agent reads —
   processes exit (`exit`, their children go to init), start (`spawn`: a
   fork with no exec read, or another process taking a freed pid), enter an
   uninterruptible wait (`stuck`), `nft` missing (`nft: false`).

Whenever the clock passes them, `main.rs`'s heartbeats fire: the window's
expiry every second, the posture's decay every 60 s and the ladder's tick
every 5 s, on the events' clock, in that order when they fall together.

| host state | in a replay |
|---|---|
| the clock | the replay's own: the events' clock (`timestamp_ns`) as the posture's and the window's monotonic clock (`posture::clock::Clock`, `PostureMachine::with_clock`, `TrustedInstallerOverride::with_clock`), handed to the ladder as `main.rs` hands it `Instant::now()`; the wall clock is 2026-01-01T00:00:00Z at the events' zero |
| processes | a table: the case's `procs`, every exec event's process, `host` items; written as a `/proc` of the replay's own (`stat` with state, terminal and start, `status`, `loginuid`, `cgroup`, `cmdline`, `exe`) that the lineage, the posture's scopes, the security-tool detector and the ladder's host-critical guard (`SystemProtectedProcs`) read; a child inherits its parent's login uid, cgroup and terminal |
| the actuator | the replay's `CombatActuator` on that table, with the steps and words of `SystemActuator`: a capture is a pid and a start (a process that exited, or whose pid another process holds now — a stale pidfd — reaches nothing); a soft egress block takes unless `nft` is missing; NEUTRALIZE looks up each binary before the kill, kills each offender's tree through a cgroup of its own (the root moved in and frozen, every descendant found by the `/proc` walk moved in, a guarded one refused, the cgroup killed, each member checked by its identity: one in an uninterruptible wait is still running and reported failed) and quarantines each binary once (a system path refused, kill-only); the outcomes go through `SystemActuator::kill_outcome`, `quarantine_text` and `soft_block_of` |
| the isolation | the case's `isolation` (what each engage finds per family, then both isolated) and `release` (what each release reads back, then both clear) |
| the signed rows | the real `AuditEvidence` over a real `AuditLog` in the replay's directory, the trusted-installer window's close rows in the same log |
| the administrator | a fixed Ed25519 key (`unlock,trusted-installer`) in an `admin.pub` of the replay's own; agent id `golden-posture-1` |
| the agent | pid 4,200,000, exempt from the posture as `main.rs` exempts its own |

Not replayed, said so: the rule engine (§1–§5 replay it), the ladder's
worker thread (the steps run in the caller, in the order the worker runs
them; what an event sees while a step is still queued is not replayed), the
admin socket's own audit rows (the unlock's, the grant's), and the Linux
half of the response (`response::kill`'s pidfds and cgroupfs, nft,
iptables): its privileged tests cover it (`a_tree_kill_freezes_the_root…`,
`kill_tree_reaps_a_tree_that_keeps_forking`).

### 6.2 Reading a golden file

The first line names the format (`northnarrow-posture-golden/1`), the case,
what it is about, detect-only, the posture's settings (the ransomware
directive and the mass-write mode in force, the corroboration window, the
quiet window of an unlocked COMBAT, the two decays), the ladder's
(`LadderConfig::default()`, the inline runner) and the heartbeats. Then one
line per item (`item`, its index in the case) and one per heartbeat that
changed something (`tick`: `installer window`, `posture decay`, `ladder`),
each with `seq`, `at_ms` (the events' clock) and:

- `event`: the event's kind and process; `wait_secs`; `unlock` (the
  signer's fingerprint, the outcome as the admin socket words it);
  `installer_grant` (signer, window, its end); `host: "changed"`;
- `posture`: the transitions of the posture's log, each with `from`, `to`,
  `trigger` (the firing one; `null` for decay and release), `reason` and
  `unix_ts_secs`, and for an event's transition its `evidence`: the triggers
  it raised (kind of evidence, level, confidence, whether it locks COMBAT),
  the actor's corroboration scope and the signals that scope held before
  (what corroborates a COMBAT-tier heuristic);
- `signal`: an event that moved no level but re-armed the current one or
  was recorded in the ledger — its scope and what that scope held;
- `assessed`: what the shared trackers made of the event — a security tool
  switched off (`defense`: the EVA rule, the tool, what was done, why it is
  sanctioned or `null`) and the ransomware shapes of its actor
  (`ransomware`: actor, program, trusted or not, shapes, decisive);
- `acts`: in order, the ladder's calls into the actuator (`capture`, `begin
  episode`, `soft egress block`/`release`, `neutralize`, `isolate`,
  `release isolation`, the copy-on-first-write hand-off) with their answers,
  and what the host did (`kill tree`: the cgroup, the processes frozen with
  the root, those spared, those still running — or why nothing was killed;
  `quarantine`; the `host` items' changes);
- `signed`: the audit rows written, whole, with what the replay cannot fix
  named: `ts` → `@TS@`, `entry_hash` → `#n`, `prev_hash` → `#n-1`
  (`genesis` for the first), `agent_sig` → `@SIG@`, `client_pid` (the test
  process) → `@AGENT_PID@`. The replay verifies the chain with the key
  before it names them;
- `state`: the posture (with `since_ms` and `last_trigger_ms`, or `locked`
  in COMBAT), the ladder's stage and offenders, the ledger's size.

### 6.3 The cases

| case | scenario | shows |
|---|---|---|
| `ransomware-corroborated-combat` | a login session's `nc`, then an unpackaged program of the same session renaming 20 files to `.locked` over ciphertext, connecting out; then quiet | OBSERVING → ENGAGED (ExploitAttempt) → COMBAT (RansomwareEncryption, corroborated by the session's execution evidence; unlocked); INVESTIGATE, the exfiltration jump-ahead, NEUTRALIZE of the tree through the kill cgroup, contained; the unlocked COMBAT decays to ENGAGED and the ladder stands down |
| `ransomware-alone-engaged` | the same encryption with nothing before it; another user's `nc`; a second burst | RansomwareEncryption alone stops at ENGAGED (`RANSOMWARE_COMBAT_WITHOUT_CORROBORATION` off); another session's signal does not vouch, nor the actor's own file-system evidence |
| `eva-installer-window` | a root unit's script with a signed 300 s grant stops the agent's unit, then auditd; the window ends; the agent's unit again; a systemd unit dropped | the own-unit stop sanctioned by the window (its key and end named), no transition; auditd's stop DefenseImpairment (ENGAGED) inside the window; the window's signed close; the unit drop corroborated by DefenseImpairment: COMBAT locked; NEUTRALIZE at the deadline, the system binary not quarantined |
| `combat-forking-tree` | a web worker's `/tmp` payload with a child, two grandchildren (forks), a write to the agent's state refused, another child | StagingExec (ENGAGED), AntiTamperDenial (COMBAT locked); the spread jump-ahead; the tree frozen and killed in its cgroup, the attributed child reported gone, the binary quarantined once; the signed unlock (ALERTED); ALERTED decays to OBSERVING |
| `combat-stale-capture` | no `nft`; a `/dev/shm` payload refused a write; it exits and logrotate takes its pid | the failed soft block signed, INVESTIGATE shortened to 10 s; NEUTRALIZE finds the capture stale: gone, the pid's new holder untouched, nothing to quarantine |
| `combat-stuck-isolate-unlock` | a `/var/tmp` miner whose worker is in an uninterruptible wait; a write refused | the tree not contained (a member still running), ISOLATE (evidence first); attempt 1 leaves IPv4 not isolated (signed failure, retried in 5 s), attempt 2 isolates IPv4 with IPv6 unavailable (a hole, signed); the signed unlock lifts it |
| `detect-only` | a forking payload refused a write, in detect-only | the same posture, stages and signed rows; the actuator touches nothing (soft block not needed, NEUTRALIZE what would have been done) |
| `decay-to-observing` | `nmap` twice, then `nc`, then quiet | ALERTED re-armed by the same tier, decays to OBSERVING an hour after the last; ENGAGED decays to ALERTED after 24 h, then to OBSERVING |

Each case names the levels its posture moves to, in order (`path`), the
ladder stages it reaches (`stages`) and the ops of the signed rows it writes
(`signed`); `every_posture_case_shows_what_it_says` checks them, so an update
that loses one fails. `posture_golden_cases_cover_the_lot` requires, across
the cases: COMBAT by RansomwareEncryption and ENGAGED by it, ENGAGED by
DefenseImpairment, an own-unit stop sanctioned by the window with no
transition, a tree killed through its cgroup, an offender gone before
NEUTRALIZE, a stale capture, a signed unlock leaving COMBAT, a decay to
OBSERVING, a detect-only NEUTRALIZE and no kill in detect-only.

Two things the replay showed of production, kept as they are (a behaviour
change is another lot's): the signed `combat_stage` rows of a COMBAT the
posture reached carry `"trigger": null`, and its INVESTIGATE row names no
offender — `main.rs`'s entry hook opens the episode (`engage(None, None)`)
inside `observe`, before `process_event` passes the offender and the firing
trigger, which `engage_with` then only merges (the offender is soft-blocked,
the trigger dropped).

### 6.4 Determinism

`posture_golden_is_deterministic_across_runs_and_threads` replays every case
three times on one thread and once on each of four threads at once, each on
its own host, and requires the same bytes; the committed files are the same
bytes in another process. What could break it, and how it is held:

- the clocks: the posture, the window and the ladder read the replay's
  clock only (the seams above); the audit writer's clock (`ts`, and the
  hashes and signature over it), the test's pid and the replay's directories
  are named, not printed (`@TS@`, `#n`, `@SIG@`, `@AGENT_PID@`, `@PROC@`,
  `@ROOT@`); the challenge nonce of a signed request is the OS's random, and
  only the verification's outcome and the key's fingerprint are printed;
- process-wide switches: `RANSOMWARE_COMBAT_WITHOUT_CORROBORATION`'s
  runtime value (set by the signed per-rule policy) and the kernel
  mass-write mode (`triggers::set_kernel_mass_write`, set by `main.rs` when
  the LSM file-open sensor is armed) are read at their defaults, printed in
  the header; a case cannot change them without racing every other test —
  a case under `combat-without-corroboration NN-L-IMP-001` needs the
  directive to become the machine's own;
- the lineage runs with the live checks off (`AuthSessionTracker::new`, as
  §1): `for_host` compares a cached exec with `/proc`'s start using the
  host's suspended time;
- map order never reaches a line: the ledger's signals are sorted, the
  JSON keys are;
- a replay keeps nothing past its end: its hooks reach the ladder weakly
  (`main.rs`'s live as long as the agent), so the host, its `/proc` and its
  directory go with it (`a_replay_leaves_no_directory_behind`).

### 6.5 Updating

As §5: `cargo xtask golden --update` writes both replays' files, `git diff
-- agent/tests/golden/posture/expected` is read line by line, and the pull
request says why each transition, step or row moved. A case is a
`cases/<case>.json` with `about`, `path`, the optional `stages`, `signed`,
`detect_only`, `start_ns` (the clock's start), `procs` (`pid`, `ppid`,
`start_ns`, `uid`, `comm`, `exe`, `argv`, `loginuid`, `cgroup`, `tty`,
`stuck`, `deleted`), `files`, `entropy`, `isolation`, `release`, and
`items`. Pids are above `PID_MAX_LIMIT`, like §3's.
