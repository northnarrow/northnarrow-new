# Golden replay of the decision engine (lab PR 228)

What the decision path answers to a recorded event stream, kept as a
committed file and checked byte for byte on every `cargo test`: a change of a
rule, of the rule order, of a policy switch, of a shipped list or of the
engine's state handling shows as a diff of a golden file, in the pull request
that makes it.

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

Not replayed: the posture and the COMBAT ladder (they act on verdicts, they
are not verdicts), the canary registry (no case deploys a canary), the
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
| `canary003-trip-owns-its-connection` | a shell's connect to a network canary (the trip), the close of the refused socket synthesised by the flow tracker (`127.0.0.1:0`), its connect-time row after the close, a later flow to another host (lab PR 246, the KVM failure of 27/10/2026) | NN-L-CANARY-003 on the trip; nothing on any row of the trip's own connection; NN-L-CHAIN-003 on the later flow |
| `canary003-close-before-the-trip` | the same close reaching the engine before the trip, then a credential read of the shell processed late, then a later flow (lab PR 246) | nothing on the close (no precursor yet); NN-L-CANARY-003; NN-L-FIM-016 alone on the late read (no chain completed with the trip's connection); NN-L-CHAIN-001 and NN-L-CHAIN-003 on the later flow |
| `canary003-close-before-the-trip-late-exec` | the same close before the trip, then the shell's exec from a staging directory processed late, then a later flow (lab PRs 246 and 244) | nothing on the close; NN-L-CANARY-003; R001 alone on the late exec (no NN-L-CHAIN-002 or CHAIN-007 completed with the trip's connection); NN-L-CHAIN-002 and NN-L-CHAIN-003 on the later flow |
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
