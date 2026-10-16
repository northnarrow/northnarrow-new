# Tappa 10.7 — Rule × Tool validation matrix

One row per executed test. Schema = design §4.1. The denominator is the
frozen registry below, fixed before V2 runs (external audit NN-AUD-217):
every rule the agent can record, none taken out after a result is known.
The matrix itself is empty by design — V2–V4 populate it.

## Frozen denominator (pre-registration)

| File | What it fixes | Version | Rows | sha256 (LF line endings) |
|---|---|---|---|---|
| [`v2-rules.tsv`](v2-rules.tsv) | the rule denominator and the Critical sub-gate | 1 | 77 | `4eaa0c2fa7f999277056eb56f92154f1f39174241e08c4a72a8fb31f7fdfe479` |
| [`v2-techniques.tsv`](v2-techniques.tsv) | the ATT&CK technique rows and their expected outcome | 1 | 59 | `c9304cd3d732d7067f41dfe5e981bffeac14cd3e5cd82e0b69f162d174e2a7ab` |
| [`v2-controls.tsv`](v2-controls.tsv) | one evasion row and one benign control per family | 1 | 16 | `d376c91f1c0a9af751d790b2f854127466efd5906ea9a4910baa987e8d2da974` |

Version 1 was frozen on 2026-10-15, before any V2 run. Its rule rows are
the 76 rules the production engine loads plus NN-L-AT-001 (issued outside
the engine); none is N/A.

- A file changes only as a new version: its `# version:` line, its row in
  this table and a line in the change log below, committed before the
  family it touches runs. A change made after a family ran does not apply
  to that family's figures.
- `agent/src/decision/validation_registry.rs` fails when `v2-rules.tsv`
  differs from the rules the agent ships, when a version, row count or
  hash in this table is stale, when a rule design §13 Q1 names is missing
  from the Critical sub-gate, when a sub-gate rule has no row in the
  evidence table below, or when a cited test, probe or evidence file does
  not exist.

Change log:

- Version 1 (2026-10-15): initial freeze (external audit NN-AUD-217,
  NN-AUD-218, NN-AUD-235).

## Gate formulas (§13 Q1, as frozen)

- **Rule coverage (headline):** PASS ÷ the rows of `v2-rules.tsv` with
  status `in`. PARTIAL, FAIL — of every triage class, `sensor-gap → T10.6`
  included — and NOT RUN all count against it. Gate: ≥ 80 %.
- **Critical sub-gate:** PASS ÷ the rows with `gate = critical`. Gate:
  100 %. The sub-gate holds every rule Q1 names (FIM-001/002/008/010/021/022
  and every CHAIN rule) and every other rule that can issue a Critical
  verdict.
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

| rule_id | Q1 | unit | e2e | lab | campaign | status | notes |
|---|---|---|---|---|---|---|---|
| R004_ExecFromProcSelfFd | - | `agent/src/decision/rules/r004_exec_from_proc_self_fd.rs::fires_on_proc_self_fd` | `agent/tests/detection_rules_at_scale_privileged_e2e.rs::process_memfd_fileless_exec_trips_r004` | `deploy/lab/exec-sensor/exec-sensor-check.sh::R004_ExecFromProcSelfFd` | no proof | e2e | The lab probe also checks the kill (exit status 137). |
| R006_ReverseShellTooling | - | `agent/src/decision/rules/r006_reverse_shell_tooling.rs::fires_on_each_offsec_tool` | no proof | no proof | no proof | unit | Critical with KillProcessTree since lab PR 166 (the shell `socat EXEC:` runs is its child). |
| R007_CryptoMiner | - | `agent/src/decision/rules/r007_crypto_miner.rs::match_is_case_insensitive` | no proof | no proof | no proof | unit | - |
| R018_KernelModuleLoad | - | `agent/src/decision/rules/r018_kernel_module_load.rs::fire_nonstandard_path_is_critical_killtree` | no proof | no proof | no proof | unit | Critical only for a module outside the module directories; anti-tamper.sh C16 loads an in-tree module. |
| NN-L-FIM-001_SystemBinaryModified | yes | `agent/src/fim/rules.rs::fim001_fires_on_system_binary_modified` | no proof | no proof | no proof | unit | - |
| NN-L-FIM-002_NewSuidBinary | yes | `agent/src/fim/rules.rs::fim002_kills_a_watched_inode_linked_into_a_user_writable_dir` | no proof | no proof | no proof | unit | - |
| NN-L-FIM-008_KernelModuleModified | yes | `agent/src/fim/rules.rs::fim008_fires_on_kmod_modified` | no proof | no proof | no proof | unit | - |
| NN-L-FIM-010_RansomwareExtensionRename | yes | `agent/src/fim/rules.rs::fim010_fires_on_renamed_to_ransomware_extension` | no proof | no proof | no proof | unit | `fim_privileged_e2e.rs` names it only in a comment. |
| NN-L-FIM-021_PamModuleModified | yes | `agent/src/fim/rules.rs::d3_fim_rules_table` | `agent/tests/detection_rules_at_scale_privileged_e2e.rs::fim_pam_module_modify_trips_fim_021_combat` | no proof | no proof | e2e | The e2e writes a module in a temporary `security/` directory, not the system PAM directory. |
| NN-L-FIM-022_LdSoPreloadModified | yes | `agent/src/fim/rules.rs::d3_fim_rules_table` | no proof | no proof | no proof | unit | The predicate is the exact path `/etc/ld.so.preload`; no e2e writes it. |
| NN-L-FIM-024_AntiTamperHoneypotModified | - | `agent/src/fim/rules.rs::fim024_fires_on_every_honeypot_path` | `agent/tests/honeypot_tamper_e2e.rs::delete_kill_switch_conf_trips_fim024_and_kills_the_tamperer` | no proof | no proof | e2e | The e2e checks one signed record (Critical, KillProcessTree, the tamperer's pid) and the tamperer killed; FIM-024 does not move the posture (no trigger reads FIM events). |
| NN-L-FIM-025_FileCapabilityGranted | - | `agent/src/fim/rules.rs::fim025_strips_a_granted_capability` | no proof | no proof | no proof | unit | Critical for a root-equivalent capability; the response strips it. |
| NN-L-CANARY-001_FileAccess | - | `agent/src/decision/rules/canary.rs::canary001_fires_on_file_canary_file_open` | `agent/tests/canary_privileged_e2e.rs::file_canary_open_triggers_canary_tripped_event_and_combat` | no proof | no proof | e2e-event | The e2e asserts the signed access row, not the verdict. |
| NN-L-CANARY-002_ProcessExec | - | `agent/src/decision/rules/canary.rs::canary002_fires_on_process_canary_exec` | `agent/tests/canary_privileged_e2e.rs::process_canary_exec_triggers_canary_tripped_event_and_combat` | no proof | no proof | e2e-event | The e2e asserts the signed access row, not the verdict. |
| NN-L-CANARY-003_NetworkConnect | - | `agent/src/decision/rules/canary.rs::canary003_fires_on_network_canary_connect` | no proof | no proof | no proof | unit | Nothing in the agent produces a Network canary trip (`CanaryIndexes::is_canary_port` is called by tests only): a sensor gap, so a FAIL unless it is wired before V2. |
| NN-L-CANARY-004_CredentialRead | - | `agent/src/decision/rules/canary.rs::canary004_fires_on_credential_canary_read` | no proof | no proof | no proof | unit | - |
| NN-L-NET-001_OutboundToBlockedIp | - | `agent/src/decision/rules/net.rs::net_001_fires_on_blocklist_match` | no proof | no proof | no proof | unit | Needs an entry in the operator blocklist on the target. |
| NN-L-NET-003_BadJa3 | - | `agent/src/decision/rules/net.rs::net_003_fires_on_ja3_blocklist_match` | no proof | no proof | no proof | unit | The TLS fingerprint is never captured (`FlowTracker::attach_tls` has no caller): a sensor gap, so a FAIL unless it is wired before V2. |
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
| `process` (R001–R018) | 18 | | | | | | |
| `fim` (NN-L-FIM-001..025) | 25 | | | | | | |
| `canary` (NN-L-CANARY-001..004) | 4 | | | | | | |
| `net` (NN-L-NET-*) | 17 | | | | | | |
| `io_uring` (NN-L-IOU-001/002) | 2 | | | | | | |
| `bpf` (NN-L-BPF-001/002) | 2 | | | | | | |
| `anti-tamper` (NN-L-AT-001) | 1 | | | | | | |
| **Total** | **77** | | | | | | |
| **Critical sub-gate** | **26** | | | | | | |
