# Tappa 10.7 — Rule × Tool validation matrix

One row per executed test. Schema = design §4.1. The denominator is the
frozen registry below, fixed before V2 runs (external audit NN-AUD-217):
every rule the agent can record, none taken out after a result is known.
The matrix itself is empty by design — V2–V4 populate it.

## Frozen denominator (pre-registration)

| File | What it fixes | Version | Rows | sha256 (LF line endings) |
|---|---|---|---|---|
| [`v2-rules.tsv`](v2-rules.tsv) | the rule denominator and the Critical sub-gate | 3 | 88 | `d1187bf6e2e7f8d236350f29a591bdc083b6e64c51a6f431845db980561fd1a6` |
| [`v2-techniques.tsv`](v2-techniques.tsv) | the ATT&CK technique rows and their expected outcome | 2 | 62 | `f22ae7a6cf96db925177c4cf1d10ed3af0b70b53587e4b9d4f179cf4f767dbb9` |
| [`v2-controls.tsv`](v2-controls.tsv) | one evasion row and one benign control per family | 2 | 22 | `f07c7a7f7cd83059f9bdc2f4993e98f87bd27b39a50277b7144b3f7f186162bd` |

Version 1 was frozen on 2026-10-15, before any V2 run. Its rule rows are
the 76 rules the production engine loads plus NN-L-AT-001 (issued outside
the engine); none is N/A. Version 2 of `v2-rules.tsv` (2026-10-16, also
before any V2 run) keeps the 77 rows and takes NN-L-NET-003 out of the
Critical sub-gate.

- A file changes only as a new version: its `# version:` line, its row in
  this table and a line in the change log below, committed before the
  family it touches runs. A change made after a family ran does not apply
  to that family's figures.
- `agent/src/decision/validation_registry.rs` fails when `v2-rules.tsv`
  differs from the rules the agent ships, when a version, row count or
  hash in this table is stale, when a rule design §13 Q1 names is missing
  from the Critical sub-gate, when a sub-gate rule has no row in the
  evidence table below, or when a cited test, probe or evidence file does
  not exist. It also fails (external audit NN-AUD-444, lab PR 209) when
  `docs/adversarial/V2_ATOMIC_RED_TEAM_SWEEP.md` no longer says HALT while
  the matrix below has no data row or no `evidence/<run-id>/` directory
  exists, and when a row cites a run directory that is not there or has no
  `SHA256SUMS`.

Change log:

- Version 1 (2026-10-15): initial freeze (external audit NN-AUD-217,
  NN-AUD-218, NN-AUD-235).
- `v2-rules.tsv` version 2 (2026-10-16, lab PR 163): NN-L-NET-003 leaves
  the Critical sub-gate (`gate -`), inactive until BUG-025 — no sensor
  produces a TLS fingerprint, so it cannot issue a Critical verdict on the
  agent as built. It stays in the denominator (`status in`): a miss of it
  counts against the headline. It returns to the sub-gate with the version
  that follows BUG-025. NN-L-CANARY-003 stays in the sub-gate: a connect to
  a network canary trips it since lab PR 163. Sub-gate: 25 rules.
- `v2-rules.tsv` version 3, `v2-techniques.tsv` version 2,
  `v2-controls.tsv` version 2 (2026-10-20/21, lab PRs 219, 224 and 225,
  before any V2 run; one version for the three, integrated in that order):
  the exploit post-condition guard's NN-L-EPG-001 (credentials, T1068) and
  NN-L-EPG-002 (namespaces and root, T1611), issued outside the engine,
  Critical, in the sub-gate (family `exploit-guard`); TQ60 for T1068 and
  NN-L-EPG-002 in TQ57; CV17 / CV18 for the family (lab PR 219). R020 (a
  shell or interpreter with its stdio on a network socket, Critical, in the
  sub-gate, family `process`), NN-L-NET-026 (scan fan-out) and NN-L-NET-027
  (outbound brute force), High, family `net`; R020 in TQ19 (T1059.004), TQ61
  T1046 and TQ62 T1110, both checked in the pinned ATT&CK 20.0 list (lab PR
  224; no new family, no new control). The ransomware rules NN-L-IMP-001
  (Critical, KillProcessTree: in the sub-gate) and NN-L-IMP-002 (family
  `impact`), and the security-tool rules NN-L-EVA-001..004 (family
  `evasion`, High at most: out of the sub-gate), with an evasion and a
  benign control for each new family, CV19..CV22 (lab PR 225, which numbered
  them CV17..CV20). 88 rows, sub-gate 29.

## Gate formulas (§13 Q1, as frozen)

- **Rule coverage (headline):** PASS ÷ the rows of `v2-rules.tsv` with
  status `in`. PARTIAL, FAIL — of every triage class, `sensor-gap → T10.6`
  included — and NOT RUN all count against it. Gate: ≥ 80 %.
- **Critical sub-gate:** PASS ÷ the rows with `gate = critical`. Gate:
  100 %. The sub-gate holds every rule Q1 names (FIM-001/002/008/010/021/022
  and every CHAIN rule) and every other rule that can issue a Critical
  verdict on the agent as built: NN-L-NET-003 cannot, inactive until
  BUG-025 (version 2).
- **Technique coverage** (reported apart, no gate): the techniques of
  `v2-techniques.tsv` whose every row has an observed detection, denial or
  drift, with evidence, ÷ every technique in the file. A `known-gap` row is
  not covered unless the run shows a detection.
- **N/A:** none in version 1. A rule leaves the denominator only through a
  new version, with the reason in its `status` cell (`n/a:<reason>`); the
  report prints the N/A count next to the headline.
- **One build:** the figures are computed on one agent build (its hash in
  REPORT.md). Results after a V7 hot-fix are a second figure for that
  build, never merged into the first.
- **Evidence that counts:** a matrix row whose `evidence` cell names an
  `evidence/<run-id>/` directory with the log slice and `SHA256SUMS`
  (design §11). The trigger may be an attacker tool or a lab probe from
  `deploy/lab/` run on the target, its output saved in the same directory.
  Unit tests and the privileged e2e tests are pre-campaign proof (the
  table below); they do not make a matrix row PASS.

## Result semantics (§4.1)

- **PASS** — fires with the exact expected severity, action, and posture transition.
- **PARTIAL** — fires but with a mismatch (severity/action/posture).
- **FAIL** — the trigger was met and nothing fired, whatever the cause: a
  rule-logic gap, a sensor that does not emit the event (sensor gap), or
  a configuration gap.
- **NOT RUN** — no executed test for the row; counts as FAIL in the
  headline.
- **N/A** — only a row whose status is `n/a` in the registry version in
  force.

## Triage class (for non-PASS, §6.3)

`rule-logic` · `sensor-gap → T10.6` · `config-gap`

The class says where the fix goes. It never takes a row out of the
denominator. A re-run after a configuration fix is a new matrix row; the
first stays, with its evidence.

## Matrix

| rule_id | mitre | tool (cmd / atomic-id) | expected (sev + action + posture) | result | latency_ms | evidence | notes |
|---|---|---|---|---|---|---|---|
| <!-- e.g. NN-L-FIM-022_LdSoPreloadModified --> | <!-- TA0003 / T1574.006 --> | | | | | <!-- evidence/<run-id>/… --> | |

## Critical sub-gate — where the proof lives

One row per rule with `gate = critical` in `v2-rules.tsv` (external audit
NN-AUD-235). A proof cell cites `path::test` (a test function), or
`path::text` (a lab probe that asserts that rule), or `no proof`. Columns:

- **unit** — an in-process unit test that fires the rule on a synthetic
  event and asserts its severity and action (unless the notes say
  otherwise).
- **e2e** — a privileged e2e in `agent/tests` (real sensors, run by
  `deploy/lab/nn-lab.sh test-ignored`) that waits for the rule's verdict
  in the agent log. These tests assert the rule id; severity and action
  are asserted by the unit test.
- **lab** — a probe in `deploy/lab/` that asserts the verdict on a lab
  guest.
- **campaign** — the V2–V4 matrix row's evidence directory. None yet.
- **status** — the strongest proof today: `campaign`, `e2e`, `e2e-event`
  (the e2e proves the sensor event reaches the agent, not this verdict),
  `e2e-flaky` (the e2e is ignored as unreliable and does not count),
  `unit`, or `no proof`.

The sub-gate passes only on campaign proof. Until REPORT.md is filled, no
coverage percentage goes into external material.

Out of the sub-gate (`gate -`, still in the denominator), with what
brings each one back:

- `NN-L-NET-003_BadJa3` — inactive until BUG-025: no sensor produces a TLS
  fingerprint (`FlowTracker::attach_tls` has no caller), so it cannot fire;
  registry version 2, lab PR 163.

| rule_id | Q1 | unit | e2e | lab | campaign | status | notes |
|---|---|---|---|---|---|---|---|
| R004_ExecFromProcSelfFd | - | `agent/src/decision/rules/r004_exec_from_proc_self_fd.rs::fires_on_proc_self_fd` | `agent/tests/detection_rules_at_scale_privileged_e2e.rs::process_memfd_fileless_exec_trips_r004` | `deploy/lab/exec-sensor/exec-sensor-check.sh::R004_ExecFromProcSelfFd` | no proof | e2e | The lab probe also checks the kill (exit status 137). |
| R006_ReverseShellTooling | - | `agent/src/decision/rules/r006_reverse_shell_tooling.rs::fires_on_each_offsec_tool` | no proof | no proof | no proof | unit | Critical with KillProcessTree since lab PR 166 (the shell `socat EXEC:` runs is its child). |
| R007_CryptoMiner | - | `agent/src/decision/rules/r007_crypto_miner.rs::match_is_case_insensitive` | no proof | no proof | no proof | unit | - |
| R018_KernelModuleLoad | - | `agent/src/decision/rules/r018_kernel_module_load.rs::fire_nonstandard_path_is_critical_killtree` | no proof | no proof | no proof | unit | Critical only for a module outside the module directories; anti-tamper.sh C16 loads an in-tree module. |
| R020_ShellWithSocketStdio | - | `agent/src/decision/rules/r020_shell_with_socket_stdio.rs::a_shell_on_an_outbound_socket_is_a_critical_reverse_shell` | no proof | `deploy/lab/malsim/net-check.sh::MS06` | no proof | unit | Lab PR 224: the exec sensor reads the new image's fds 0..2 (and its parent's) in `sched_process_exec`; the lab probe (not yet run on a guest) asserts the signed record's `network` "stdio tcp … outbound". |
| NN-L-EPG-001_CredentialPostcondition | - | `agent/src/decision/rules/epg.rs::credential_write_in_detect_mode_is_a_critical_log` | no proof | no proof | no proof | unit | Lab PR 219, experimental. Issued outside the engine; Critical in both responses (detect: Log; enforce: the kernel's SIGKILL, and in lite the use refused), except lite's degraded evidence — a task record the LRU task map evicted, re-taken holding privilege — at High, Log only in either response (`agent/src/decision/rules/epg.rs::a_lost_baseline_is_degraded_evidence`). Lite (default) catches it at the mechanism or at the first use (`capable`, exec, a root-private open), strict around every call; the record names the variant and the point. The lab probe exercises the record and the response through the debug-build injection, not a real kernel credential write. |
| NN-L-EPG-002_NamespaceRootPostcondition | - | `agent/src/decision/rules/epg.rs::namespace_escape_is_epg_002` | no proof | no proof | no proof | unit | Lab PR 219, experimental. As NN-L-EPG-001, for namespaces, the fs_struct and the root. |
| NN-L-FIM-001_SystemBinaryModified | yes | `agent/src/fim/rules.rs::fim001_fires_on_system_binary_modified` | no proof | no proof | no proof | unit | - |
| NN-L-FIM-002_NewSuidBinary | yes | `agent/src/fim/rules.rs::fim002_kills_a_watched_inode_linked_into_a_user_writable_dir` | no proof | no proof | no proof | unit | - |
| NN-L-FIM-008_KernelModuleModified | yes | `agent/src/fim/rules.rs::fim008_fires_on_kmod_modified` | no proof | no proof | no proof | unit | - |
| NN-L-FIM-010_RansomwareExtensionRename | yes | `agent/src/fim/rules.rs::fim010_fires_on_renamed_to_ransomware_extension` | no proof | no proof | no proof | unit | `fim_privileged_e2e.rs` names it only in a comment. |
| NN-L-FIM-021_PamModuleModified | yes | `agent/src/fim/rules.rs::d3_fim_rules_table` | `agent/tests/detection_rules_at_scale_privileged_e2e.rs::fim_pam_module_modify_trips_fim_021_combat` | no proof | no proof | e2e | The e2e writes a module in a temporary `security/` directory, not the system PAM directory. |
| NN-L-FIM-022_LdSoPreloadModified | yes | `agent/src/fim/rules.rs::d3_fim_rules_table` | no proof | no proof | no proof | unit | The predicate is the exact path `/etc/ld.so.preload`; no e2e writes it. |
| NN-L-FIM-024_AntiTamperHoneypotModified | - | `agent/src/fim/rules.rs::fim024_fires_on_every_honeypot_path` | `agent/tests/honeypot_tamper_e2e.rs::delete_kill_switch_conf_trips_fim024_and_kills_the_tamperer` | no proof | no proof | e2e | The e2e checks one signed record (Critical, KillProcessTree, the tamperer's pid) and the tamperer killed; FIM-024 does not move the posture (no trigger reads FIM events). |
| NN-L-IMP-001_RansomwareEncryption | - | `agent/src/decision/rules/impact.rs::imp001_kills_the_actors_tree_on_two_shapes` | no proof | `deploy/lab/malsim/ransom-check.sh::NN-L-IMP-001_RansomwareEncryption` | no proof | unit | Lab PR 225: two shapes of one actor (rewrites, ciphertext, renames to a new extension, deleted originals); the lab probe (MS-23) awaits its first run. |
| NN-L-FIM-025_FileCapabilityGranted | - | `agent/src/fim/rules.rs::fim025_strips_a_granted_capability` | no proof | no proof | no proof | unit | Critical for a root-equivalent capability; the response strips it. |
| NN-L-CANARY-001_FileAccess | - | `agent/src/decision/rules/canary.rs::canary001_fires_on_file_canary_file_open` | `agent/tests/canary_privileged_e2e.rs::file_canary_open_triggers_canary_tripped_event_and_combat` | no proof | no proof | e2e-event | The e2e asserts the signed access row, not the verdict. |
| NN-L-CANARY-002_ProcessExec | - | `agent/src/decision/rules/canary.rs::canary002_fires_on_process_canary_exec` | `agent/tests/canary_privileged_e2e.rs::process_canary_exec_triggers_canary_tripped_event_and_combat` | no proof | no proof | e2e-event | The e2e asserts the signed access row, not the verdict. |
| NN-L-CANARY-003_NetworkConnect | - | `agent/src/decision/rules/canary.rs::canary003_fires_on_network_canary_connect` | `agent/tests/canary_privileged_e2e.rs::network_canary_connect_trips_canary_003_and_kills_the_connector` | no proof | no proof | e2e | Lab PR 163: a local connect to the canary's address and port trips it (the connect kprobe; the agent opens no listener, a connection from another host is not seen). The e2e waits for the signed access row, the rule's detection record (Critical, KillProcessTree) and the connecting shell's kill; `agent/src/canary/detector.rs::a_network_canary_trip_draws_canary_003_on_the_connector` runs connect → trip → verdict in process. |
| NN-L-CANARY-004_CredentialRead | - | `agent/src/decision/rules/canary.rs::canary004_fires_on_credential_canary_read` | no proof | no proof | no proof | unit | - |
| NN-L-NET-001_OutboundToBlockedIp | - | `agent/src/decision/rules/net.rs::net_001_fires_on_blocklist_match` | no proof | no proof | no proof | unit | Needs an entry in the operator blocklist on the target. |
| NN-L-CHAIN-001_CredReadThenEgress | yes | `agent/src/decision/rules/chain.rs::chain001_fires_on_cred_read_then_egress` | no proof | no proof | no proof | unit | Same-PID form; no e2e. |
| NN-L-CHAIN-002_TmpExecThenEgress | yes | `agent/src/decision/rules/chain.rs::chain002_fires_on_tmp_exec_then_nondns_egress` | `agent/tests/detection_rules_at_scale_privileged_e2e.rs::chain_tmp_exec_then_egress_trips_chain_002` | no proof | no proof | e2e | Negative e2e: `chain_tmp_exec_without_egress_does_not_trip_chain_002`. |
| NN-L-CHAIN-003_CanaryThenEgress | yes | `agent/src/decision/rules/chain.rs::chain003_fires_on_canary_then_egress` | no proof | no proof | no proof | unit | Same-PID form; no e2e. |
| NN-L-CHAIN-004_CrossPidCredExfil | yes | `agent/src/decision/rules/chain.rs::chain004_cross_pid_cred_exfil_fires` | `agent/tests/detection_rules_at_scale_privileged_e2e.rs::chain_cred_read_parent_then_descendant_egress_trips_chain_004` | no proof | no proof | e2e | The unit test asserts the rule id, not the severity. |
| NN-L-CHAIN-005_CrossPidTmpC2 | yes | `agent/src/decision/rules/chain.rs::chain005_cross_pid_tmp_c2_fires` | `agent/tests/detection_rules_at_scale_privileged_e2e.rs::chain_tmp_parent_then_descendant_egress_trips_chain_005` | no proof | no proof | e2e | The unit test asserts the rule id, not the severity. |
| NN-L-CHAIN-006_CrossPidCanaryExfil | yes | no proof | `agent/tests/detection_rules_at_scale_privileged_e2e.rs::chain_canary_trip_parent_then_descendant_egress_trips_chain_006` | no proof | no proof | e2e | No unit test fires it; the builder test only lists it. |
| NN-L-CHAIN-007_TmpCredExfilSequence | yes | `agent/src/decision/rules/chain.rs::chain007_three_step_sequence_fires` | `agent/tests/detection_rules_at_scale_privileged_e2e.rs::chain_tmp_then_cred_then_egress_trips_chain_007` | no proof | no proof | e2e-flaky | The e2e is ignored as flaky (same-PID double-kill race, T10.6.2). The unit test asserts the rule id, not the severity. |
| NN-L-CHAIN-008_CrossPidPrivEscExfil | yes | `agent/src/decision/rules/chain.rs::chain008_is_informational_log_not_kill` | `agent/tests/detection_rules_at_scale_privileged_e2e.rs::chain_privesc_then_descendant_egress_trips_chain_008` | no proof | no proof | e2e | A Medium Log verdict by design, not Critical: in the sub-gate because Q1 names every CHAIN rule; its PASS is that Log verdict. |

## Family coverage roll-up (filled in V6)

| Family | Rules | PASS | PARTIAL | FAIL | NOT RUN | N/A | Coverage % |
|---|---|---|---|---|---|---|---|
| `chain` (NN-L-CHAIN-001..008) | 8 | | | | | | |
| `process` (R001–R018, R020) | 19 | | | | | | |
| `fim` (NN-L-FIM-001..025) | 25 | | | | | | |
| `canary` (NN-L-CANARY-001..004) | 4 | | | | | | |
| `net` (NN-L-NET-*) | 19 | | | | | | |
| `io_uring` (NN-L-IOU-001/002) | 2 | | | | | | |
| `bpf` (NN-L-BPF-001/002) | 2 | | | | | | |
| `anti-tamper` (NN-L-AT-001) | 1 | | | | | | |
| `exploit-guard` (NN-L-EPG-001/002) | 2 | | | | | | |
| `impact` (NN-L-IMP-001/002) | 2 | | | | | | |
| `evasion` (NN-L-EVA-001..004) | 4 | | | | | | |
| **Total** | **88** | | | | | | |
| **Critical sub-gate** | **29** | | | | | | |
