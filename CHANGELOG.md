# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow the ROADMAP "Tappe"; `0.0.1` covers everything up to Tappa 9.0.

## [Unreleased]

### Added
- nn-admin's output matrix, committed (lab PR 266, Wave 4, test
  infrastructure; `docs/validation/GOLDEN_REPLAY.md` §8). Lab PRs 259 and
  263 proved "nn-admin's output identical to `main`" with 1,964 cases run
  from a scratchpad a stopped session deleted; `agent/tests/nn_admin_matrix/`
  runs the `nn-admin` binary in 2,703 cases (help texts and clap errors,
  `init`, `verify-keys`, `host-check`, `audit`, `chain verify`, overlays,
  `policy show|test`, 37 socket verbs against a mock agent with their
  replies, the ten refusals and the transport faults, key and identity
  errors, closed pipes, default paths) and compares stdout, stderr, exit
  status, files written and requests sent with
  `agent/tests/golden/nn-admin/expected/` on every `cargo test` (about
  10 s); fixed keys, ids and clock, the variable normalised after it is
  checked. `cargo xtask golden [--update]` runs it after the library's
  replays; `--update` is refused with `CI` set.
- Golden replay of the posture and the COMBAT ladder (lab PR 243, Wave 4
  phase 2, before R08 moves them into nn-core;
  `docs/validation/GOLDEN_REPLAY.md` §6). `agent/src/posture/golden.rs`
  replays recorded streams (`agent/tests/golden/posture/cases/`) through
  the path `process_event` takes for the posture and the ladder, wired as
  `main.rs` wires them, on a host of the case's own — no root, network or
  real process: the replay's clock, a process table written as a `/proc`
  of its own, an actuator that carries out the ladder's calls on that table
  in `SystemActuator`'s steps and words (the tree frozen and killed in a
  cgroup of its own, each member checked by its identity, a stale capture
  reaching nothing), the real signed audit log, a fixed administrator key
  whose signed unlock and trusted-installer grant `ConnAuth` verifies. Each
  step is a line of `agent/tests/golden/posture/expected/<case>.jsonl`
  (`northnarrow-posture-golden/1`): the posture's transitions with the
  evidence they cite, the ladder's calls and the host's acts, the signed
  rows (the writer's timestamp, hashes, signature and the test's pid
  named, the chain verified), the state. Eight cases: ransomware
  corroborated to COMBAT and alone held at ENGAGED, security tools switched
  off around a signed trusted-installer window, a forking tree killed with
  an attributed child already gone and the signed unlock, a stale capture
  after a failed soft block, a member that does not die and ISOLATE retried,
  detect-only, decay to OBSERVING. Byte-identical across runs, threads and
  processes; `cargo xtask golden [--update]` runs both replays (refused
  under CI). Seams, no behaviour change: `posture::clock::Clock` (the
  host's clocks by default) read by `PostureMachine` (`with_clock`) and the
  trusted-installer window (`with_clock`, `current_grant`, which the
  security-tool detector's own-unit sanction now asks); the words of
  NEUTRALIZE's outcomes in functions of their own
  (`SystemActuator::kill_outcome`, `quarantine_text`, `soft_block_of`).
  Found, not changed: the signed `combat_stage` rows of a COMBAT the
  posture reached carry `trigger: null`, and its INVESTIGATE row names no
  offender (the entry hook opens the episode before `process_event` names
  them).
- Multi-match decisions and the signed per-rule response policy (lab PR
  236, Wave 4 phase 2, C14/C12; `docs/design/MULTI_MATCH_AND_RULE_POLICY.md`,
  `docs/operator/RULE_POLICY.md`). **Multi-match.** The engine evaluates
  every rule on every event (it stopped at the first match), so every
  stateful rule — chains, windows, accumulators, the correlation store —
  sees every event, and computes the decision from all the matches: the
  strongest action any match's mode allows, run once per target (a process,
  or a file for `StripFileCapability`); the highest severity; a primary rule
  (the highest severity, then the strongest action, then the earliest
  registered); every tie ends on the registration index, so a stream gives
  the same decisions on every run and thread. **Legacy ceiling:** without a
  signed `enforce` for the rule supplying it, no event gets a stronger
  response than the first-match engine gave it (computed from the same
  matches, the switches applied, `off` rules included); a match held by it
  is recorded with `held: "legacy_ceiling"` and `held_action`. A detection record names the
  primary rule in `rule_id`, every match in the new `matches` field (rule,
  action, severity, mode, pid, ATT&CK ids, `held`, `exempt`; absent on a
  single-match record under the built-in defaults, which keeps its bytes),
  and the union of their ATT&CK ids in `mitre` (`held_action`: what a
  switch or the ceiling held back); the journal line lists the
  other rules (`also`). The flow ledger notes every matched rule. **Policy.**
  The signed overlay `rule-policy.local` (`OverlayKind::RulePolicy = 15`,
  appended; role `config-manage`) maps a rule (full or short id) to `off`,
  `audit` (recorded only), `alert` (recorded and counted, no response) or
  `enforce` (its own response, a held kill given back), exempts an actor
  from a rule by uid (not 0), executable (a root-owned system-tree path
  and its SHA-256, checked on the opened file), cgroup or systemd unit —
  never by process name — and carries `combat-without-corroboration
  NN-L-IMP-001` (the runtime form of
  `RANSOMWARE_COMBAT_WITHOUT_CORROBORATION`). Any bad line refuses the
  file. The `PolicySwitch` constants are its built-in defaults: without a
  policy every held kill stays held and every other rule keeps its
  response. The agent reads it through the overlay gate at boot
  (`--rule-policy-local`; a signed `rule_policy_loaded` row; unsigned:
  `unauthorized_overlay`, defaults; signed but unparsable: a signed
  degradation `rule_policy`, defaults) and applies a new one at once when
  `nn-admin policy set` stores it (the signed `config_overlay_set` row says
  `applied now`). `--detect-only` still overrides every mode.
  `nn-admin policy show|set|test`: the effective table, sign and store,
  and an offline replay of sample events (one `Event` per line or a golden
  case) under a candidate policy. Fuzz target `rule_policy`. Golden replay
  format `northnarrow-golden/2` (`matches`, `responses`, the policy in the
  header) and seven new cases: the four shadowing bugs, test policies that
  enforce NN-L-IMP-001 and NN-L-FIM-004, an exemption by uid. Lab harness
  `nn-lab.sh policy-check` (`deploy/lab/malsim/policy-check.sh`).
- Performance baseline, regression gate and golden replay (lab PR 228,
  Wave 4 phase 2). **Baseline.** `nn-lab.sh perf [--fresh] [--quick]` runs
  `deploy/lab/perf/perf-run.sh` on a lab guest, as root: the hooked
  operations (`getppid`, a `read` of `/dev/zero`, open + read + close in a
  watched and in an unwatched directory, open for write + write + close,
  fork + exec of `/bin/true`, TCP connect + close, a UDP send, a DNS query
  sent, a DNS query to the guest's resolver) with the agent stopped (the
  trusted-installer window with the lab key, the pin root purged: the
  operator path, nothing bypassed) and running, 10 measured passes after a
  warm-up, pinned to one vCPU; the latency from a probe read of a
  `.aws/credentials` fixture to its signed NN-L-FIM-011 record; the ring
  drops and the network trackers' losses under the soak generator at a
  high rate for 60 s, read signed, and the process-creation rate the host
  kept up with (`burst_forks_per_s`, events per second); the agent's CPU
  and RSS idle and under that load; the cold start to READY. One JSON keeps
  every raw sample with the kernel, CPU, vCPUs, memory, clocksource, the
  tree commit, its branch point on `origin/main` and which build inputs
  differ from it, the binaries' hashes and the agent's configuration, with
  a Markdown summary. The first baseline is committed:
  `docs/validation/results/perf-2026-10-21-ubuntu2404-40fd666.{json,md}`
  (Ubuntu 24.04, 6.8.0-147, 4 vCPU, 7.8 GiB, QEMU for Windows with WHPX;
  the agent of `main` 8180540, no build input changed): overhead of the
  agent exec +10.5 %, open +38.9 % (unwatched) / +50.7 % (watched), write
  open +44.4 %, TCP connect +40.5 %, UDP send +27.4 %, DNS query sent
  +22.1 %, to the resolver +6.1 %; a detection signed 0.23 ms after the
  read (on disk 2.5 ms); the agent at 0.2 % of one CPU idle and 7.4 % under
  the burst (455 processes/s), RSS 34 MiB idle and 43 MiB under load; no
  ring drop, rejection or tracker loss; READY 4.5 s after the start.
  **Gate.** `cargo xtask perf-compare BASE.json NEW.json` compares the
  medians: a gated metric regresses when it is worse by more than its
  threshold, by more than the noise of the repetitions ((p95 − p5) / 2
  over the median, at least 1 %) and by more than its absolute floor (the
  measurement's resolution); exit 1 on a regression or a missing metric,
  2 on unreadable input or runs from different hosts. The thresholds are
  committed, one reasoned line per gated metric
  (`deploy/lab/perf/thresholds.tsv`), from an A/A check of three full runs
  of the same tree (the baseline and two partners, `-aa.json`, `-aa2.json`,
  committed): each at least 10 %, twice the largest move of its median
  between two runs (with the agent on, and off for a workload: what the
  host alone moved) and five points above it, over the measurement's floor.
  The moves: the workloads 0.1–2.9 % agent on except TCP connect 15.3 %,
  agent off up to 8.6 % (exec; the host was shared with another job's test
  suite during two of the agent-off phases); the signed-record latency
  7.5 % (0.017 ms); CPU 25 % idle and 19.6 % under load (0.05 and 1.45
  points, inside the floors); RSS 2.5 % idle, 10.6 % under load; the boot
  0.1 %; no loss in any run. The thresholds: 10 % for every workload but
  exec and the resolver query (20 %) and TCP connect (35 %), the latency
  20 %, CPU 50 / 40 %, RSS 10 / 25 %, the boot 10 %, the loss counters
  floor 0. `xtask/tests/perf_baseline.rs` holds the committed runs to
  them: the baseline passes against both partners, every gated metric has
  a line, each threshold is twice that pair's move and five points above
  it. **Golden replay.** `agent/src/decision/golden.rs`
  replays recorded event streams (`agent/tests/golden/cases`, twelve cases)
  through the decision path of `process_event` on an engine built as
  `main.rs` builds it, over host state of the case's own (an empty `/proc`,
  a fixture package database, scripted entropy, the case's resolvers), and
  compares every decision byte for byte with `agent/tests/golden/expected`;
  each case is replayed three times and on four threads at once, the same
  bytes each time. It covers the rules of lots 219–226 — NN-L-EPG-001/002,
  NN-L-FIM-010 (the watched file's own rename kills, the moved-in match is
  held), NN-L-IMP-001 in place and by copy-delete, NN-L-IMP-002,
  NN-L-EVA-001 sanctioned, unsanctioned and from a staged program,
  NN-L-EVA-002..004, NN-L-NET-026/027, R020, the port-53 hold (here
  NN-L-CHAIN-002's, and NN-L-NET-001's older kill winning over it),
  NN-L-EXECPOL-001 and NN-L-EXECENV-001..003 — and every kill
  `response_policy` holds shows as action `Log`; each case names the rules
  it must fire and show held, so an update that loses one fails. It runs in `cargo test`
  (no root, no network); `cargo xtask golden --update` rewrites the golden
  files for review and is refused under CI, where a stale file fails
  (`docs/validation/GOLDEN_REPLAY.md`). **Documents.**
  `docs/PERFORMANCE.md` loses the on-host advisor's tuning (removed in lab
  PR 214) and says that a performance figure comes only from a committed
  result file; the figures without raw data — the advisor's expected
  speed-ups and the May 2026 table there, the agent overhead of 2026-10-12
  in the runbook and the roadmap — are withdrawn, with a one-line history.
  `docs/validation/PERF_BASELINE.md` says how to read the baseline, the A/A
  check and the thresholds.
- Synchronous exec policies, EXPERIMENTAL and off by default (capabilities
  C12, C13; countermeasure CM-01; lab PR 226; `docs/design/EXEC_POLICY.md`).
  `bprm_check_security` no longer returns 0 for every exec: with
  `--exec-policy enforce` the LSM exec sensor refuses (`-EACCES`, before the
  exec's point of no return) an exec whose file class (memfd, deleted file,
  `/dev/shm`, `/tmp`, `/var/tmp`, a world-writable directory, tmpfs, a
  home, another user's home, a guarded mount) and caller lineage tier
  (`admin`: an interactive admin session — `user.slice`, uid 0, a
  terminal, a login uid, a root login or sudo/su/doas/pkexec/run0 in the
  lineage; `session`; `service`: `system.slice`; `unknown`), both computed
  in the kernel, meet a deny cell; a quarantine cell hands the exec to the
  exec quarantine (lab PR 223), an audit cell — or a class in audit mode,
  or `--exec-policy audit`, and every detect-only agent — records "would
  deny". Default `server` profile: memfd, deleted files and `/dev/shm`
  refused for services and every non-admin session, `/tmp`, `/var/tmp`,
  world-writable directories and tmpfs quarantined, an admin allowed (memfd
  and deleted recorded); `desktop` profile: a login session's own staging
  locations allowed (AppImage, Flatpak, build trees), memfd and deleted
  "would deny", services as on a server. Exemptions: init (tgid 1) is never
  refused; init's own image (which covers the child it forks before its
  exec), the caller re-executing its own image, root-owned container
  runtimes (runc, crun, lxc) re-executing a sealed self-copy and the
  policy's `exempt` lines lift memfd and deleted only. Every deny and "would
  deny" is a signed
  `NN-L-EXECPOL-001_StagingExecDenied` record (field `execpol`: decision,
  tier and its signals, classes; ATT&CK v20 T1620, T1070.004, T1204.002,
  T1564.001 as fits — lab PR 221's typed mapping, every id in the pinned
  list, T1204.002 checked active in the v20 bundle) and is
  counted in `nn-admin status --key` (`execpol_*`, appended fields). The
  kernel configuration is frozen; the programs detach with the agent.
- Exec environment and executable-mapping checks (CM-25, lab PR 226):
  `sys_enter_execve{,at}` read a bounded prefix of the new environment (64
  variables, the loader variables' values only): `LD_PRELOAD` / `LD_AUDIT`
  naming `/tmp`, `/var/tmp`, `/dev/shm`, anything under `/proc/` or
  `/dev/fd` is refused (server profile) for services and unknown callers and
  for a root caller in a session, recorded otherwise — an admin-tier root
  caller included (`NN-L-EXECENV-001_PreloadFromStaging`); at a
  set-id target it is only recorded — the kernel's `AT_SECURE` already
  makes the loader ignore it; `GLIBC_TUNABLES` at a set-id target (Critical
  in the CVE-2023-4911 shape), a staging `LD_LIBRARY_PATH`, history disabled
  for a shell are recorded (`NN-L-EXECENV-002_ExecEnvironmentTrick`). The
  LSM `mmap_file` program judges executable mappings of files in a class
  by tier — `/dev/shm` refused for services, `/tmp`, `/var/tmp` and the
  others recorded, memfd never (JIT double mapping)
  (`NN-L-EXECENV-003_ExecMappingFromStaging`: T1574.006, T1129 — checked
  active in the v20 bundle — and T1620). A part that cannot start is a
  signed `subsystem_degraded`.
- The exec quarantine refuses a `#!` script it would hold (lab PR 226,
  design review): in enforce mode the interpreter's pass returns `-EACCES`
  (the interpreter would open the script by path after the scan, a TOCTOU);
  a Medium `NN-L-EXECQ-001` record, decision `refuse`,
  `execq_script_refused_total` in the status; observe mode records "would
  refuse". The exec classes split `/var/tmp` (`var_tmp`) out of `tmp`, add
  `dev_shm` and `other_home`, and a file on a filesystem mounted at a
  guarded point gets that point's class.
- Overlay kind `exec-policy` (`/etc/northnarrow/exec-policy.local`: `exec
  <class> <tier> <action>`, `audit <class>`, `preload <tier> <action>`, `map
  <class> <tier> <action>`, `exempt <path> [classes]`, `profile
  server|desktop`), signed and verified like every overlay, MUTATE-protected
  with its signature. `overlay set` refuses a file with a bad line; such a
  file found at boot leaves the built-in profile in force and is a signed
  degradation (`exec_policy`). Flags `--exec-policy`, `--exec-policy-profile`,
  `--exec-policy-local`, `--exec-policy-no-env`, `--exec-policy-no-map`.
  New optional BTF offsets `TASK_STRUCT_SIGNAL_OFFSET`,
  `SIGNAL_STRUCT_TTY_OFFSET` (slots 98 and 99; `INODE_I_UID_OFFSET`, which
  it reads too, is lab PR 219's slot 94) and tracepoint fields
  `sys_enter_execve.envp`, `sys_enter_execveat.envp` (the enum, tracepoint
  and hook-argument slots move up); ring-drop slot `execpol` (21, a
  security ring); `OverlayKind::ExecPolicy` 14 (after lab PR 222's
  `CowGuard` 12 and lab PR 223's `ExecqHashes` 13).
- Lab check `deploy/lab/malsim/exec-check.sh` (`nn-lab.sh
  malsim-exec-check`): MS-01, MS-02, MS-03, MS-32 before and after, audit
  mode, the desktop profile, the negatives.
- Ransomware recorded on its own evidence (lab PR 225, countermeasure
  CM-16, capabilities C14, C17, C19; `docs/design/RANSOMWARE_DECISIVE.md`).
  NN-L-IMP-001_RansomwareEncryption: two of four shapes of one actor's file
  activity within 120 s — (a) 20 existing files of 4 KiB or more rewritten
  in 60 s (the mass-write counter's overwrite crossing), (b) what they, the
  renames or the copies left behind is ciphertext-like (two of up to four
  files sampled in userland when the burst is read: entropy at least 7.5
  bits/byte in a 4 KiB block, no known container signature), (c) 20
  renames to one new extension in 60 s, appended or in place of the old one
  (new `inode_rename` counter, `MASS_RENAME`) of an encryptor's shape, or
  encrypted copies under an extension appended to the names of deleted
  originals — the copies themselves sampled (`<original>.<suffix>` with the
  original gone, in its directory, then below and beside it), never the
  originals still waiting beside them, (d) 20 files of 4 KiB or more
  deleted in 60 s after new files were written (new `inode_unlink`
  counter, `MASS_UNLINK`; both on regular files, while the LSM file-open
  sensor is armed) — Critical, with the new posture trigger
  `RansomwareEncryption`, never locked (POS-001: the lock is now
  `TriggerType::locks_combat`, the kernel-adjudicated triggers only). Its
  KillProcessTree of the actor and the trigger's COMBAT without
  corroboration are new destructive automation: by the decision of
  21/10/2026 both are held behind the per-rule response policy, off by
  default (`response_policy::IMP_001_KILL`,
  `posture_types::RANSOMWARE_COMBAT_WITHOUT_CORROBORATION`) — the verdict
  is a Critical record, the trigger needs corroboration (ENGAGED alone).
  One shape keeps its level: the rewrites raise ENGAGED as before, a rename
  burst alone is NN-L-IMP-002_RenameExtensionBurst (Log, High), deletions
  alone nothing; the legitimate copy-then-delete shapes (`mv` across
  filesystems, `rsync --remove-source-files`, package unpacks, compiler
  temporaries, editors' safe writes, `git gc`, log rotation with
  compression) stay that one shape. Writers are trusted by exec identity,
  package ownership (dpkg lists, `rpm -qf`) and lineage, never by name: a
  root package transaction, or a packaged program with no foreign program
  in its lineage (rsync, tar, git, compilers, packaged backup agents and
  databases), never counts; shapes add up per process (a payload with its
  forked workers), the kill targets the nearest foreign program.
  `Event::FileBurst` and `Event::DefenderSignal` are new variants (the enum
  is serialized by name, as JSON, never by position);
  `AuthSessionTracker::lineage_identities` (the same function as lab PR
  222's).
- Security tools switched off are detected (lab PR 225, CM-18):
  NN-L-EVA-001_SecurityServiceStopped (`systemctl stop/disable/mask/kill`,
  `service … stop`, `invoke-rc.d`, `update-rc.d`, `chkconfig`, `rc-service`,
  `rc-update`, `/etc/init.d/<name> stop`), NN-L-EVA-002_SecurityToolSwitchedOff
  (`auditctl -e 0` and `-D`, `ufw disable`, `setenforce 0`, `nft flush
  ruleset`, `iptables -F`, `aa-teardown`, cloud-agent uninstallers; one
  record per command and process tree within 10 s, the repeats — `ufw
  disable`'s dozens of `iptables` calls — counted in `detections_held` and
  the next record's `suppressed_before`),
  NN-L-EVA-003_SecurityToolKilled (a stop or end signal to a tool's process
  on `task_kill` — reported, never refused, a shell's builtin `kill`
  included; new `DEFENDER_PIDS` map, filled at boot and from the tools'
  execs, each followed by `/proc` scans for the daemon it forks (Debian's
  auditd), and `Event::DefenderSignal` — or `kill`, `pkill`, `killall`),
  NN-L-EVA-004_SecurityToolConfigChanged (the tools' configuration files
  watched by FIM). High and recorded; Low in a package
  transaction, an administrator's interactive session or under a
  configuration-management actor, and for a stop or restart of the agent's
  own units inside a valid signed trusted-installer window (the record's new
  `sanction` field names the window's key id and deadline; no posture move;
  never for another tool); the KillProcessTree of a program run
  from a staging directory or a deleted executable that asked is held
  behind the per-rule response policy (off by default: a High record).
  Posture trigger
  `DefenseImpairment` (ENGAGED, execution evidence). The tools — auditd,
  AppArmor, SELinux, ufw, firewalld, nftables, iptables, rsyslog, journald,
  fail2ban, the agent itself, falco, osquery, wazuh, CrowdStrike,
  SentinelOne, MDE, Elastic, Sophos, Trend Micro, Carbon Black, Qualys,
  Tanium, Datadog and the Alibaba, Tencent, Huawei, AWS, Google and Azure
  host agents — are the shipped content `configs/security-tools.v1`
  (installed by install.sh, write-denied). The list is not signed and has
  no operator overlay: it is pinned to the agent's built-in copy, compared
  byte for byte; a file that differs is never applied, not even under
  `NN_OVERLAY_ALLOW_UNSIGNED=1`, and is a signed `default_list_modified`.
  ATT&CK v20 (lab PR 221's typed mapping,
  Defense Impairment): T1685, T1685.004, T1686; NN-L-IMP-001/002: Impact
  T1486.
- `nn-admin status --key`: the ransomware and security-tool counters
  (`StatusResponse` fields appended at the end). Lab:
  `deploy/lab/nn-lab.sh ransom-check` (MS-23 with the benign simulator
  `deploy/lab/malsim/ransom-sim.py`, MS-25). The validation registry moves
  to `v2-rules.tsv` version 3 and `v2-controls.tsv` version 2, the versions
  lab PRs 219 and 224 open too (88 rules, 29 in the Critical sub-gate; this
  lot's controls CV19..CV22). The copy-on-first-write guard of lab PR 222
  restores (with `auto_restore = true`, off by default) after
  NN-L-FIM-010's kill, and after NN-L-IMP-001's once the per-rule policy
  turns that kill on.

- Network verdicts while a flow is open (lab PR 224, W4 CM-02, capabilities
  C07/C14). A TCP flow used to reach the rules only at its close, so an open
  reverse shell or C2 session had no verdict while it lived. The connect
  pump now hands the rules a connect-time row (`FlowPhase::Connect`, the
  image and DNS name read at the connect) next to `Event::TcpConnect`, and
  the net drain re-judges every flow still open past 60 s once a minute
  (`FlowPhase::Snapshot`, the process's current image; at most 512 per check,
  the rest deferred and counted; `--net-snapshot-interval-secs`,
  `--net-snapshot-min-age-secs`, `--net-snapshot-max`). The rules that need
  no byte count judge every phase (NN-L-NET-001/002/008/010/018, the
  chains); the record-only and byte rules (NET-003/007/009/011/013,
  CHAIN-008) still judge the closed row, paced as before. A per-flow ledger
  in the engine keeps one verdict per rule per flow and one chain verdict
  per flow, so the close does not answer the connect again. Open-phase rows
  are not written to `netflow.jsonl`. The signed detection record gains
  `network` (`"tcp 127.0.0.1:4444 connect"`, `"… snapshot open=65s"`,
  `"… closed"`, `"… denied"`, a connect attempt, a shell's stdio socket);
  the verdict's reasoning says when a flow was judged open.
- Optional synchronous deny of a connect to a blocklisted destination:
  `--net-connect-deny` (`NN_NET_CONNECT_DENY=1`, off by default) loads the
  operator netflow blocklist into two LPM tries and attaches a new BPF-LSM
  program on `socket_connect`; a `connect()` to a listed address fails with
  `EPERM` and is a signed NN-L-NET-001 record (`operation` `connect`).
  Entries wider than /8 (IPv4) or /16 (IPv6), or covering loopback or the
  unspecified address, stay out of the kernel copy (NN-L-NET-001 still
  judges them); IPv4-mapped entries load as IPv4. A detect-only agent never
  arms it: no connect is refused and nothing is killed.
- Destructive responses new in lab PRs 219–226 are held, by the decision
  of 21/10/2026: no new destructive automation is on by default until the
  signed per-rule response policy (Phase 2). Every kill, or COMBAT entry
  without corroboration, that a new rule or a wider match of an existing
  one would make stays in the rule's definition behind a switch that is off
  by default (`decision::response_policy`): the verdict keeps its severity,
  its signed record and its posture escalation, its action is `Log`, its
  reasoning says what was held back. A held verdict never stands in for a
  response that existed before it: the engine keeps evaluating and a later
  rule's kill still runs. Held here: R020's kill, NN-L-NET-026/027's kill
  tier, the kill of NN-L-NET-008 and NN-L-CHAIN-002/005 on port 53 of a
  server that is no configured resolver (port 53 was exempt), and the
  kill of an allowlisted transfer tool whose lineage holds a precursor (it
  was exempt).
- R020_ShellWithSocketStdio (Critical, record; W4 CM-03): the exec
  sensor reads in `sched_process_exec` which of the new image's fds 0..2 —
  and its parent's — are AF_INET/AF_INET6 sockets, their peer and protocol,
  and whether one was connected out (its socket in `FLOW_SOCK_MAP`)
  (`ProcessSpawnRaw.stdio` / `parent_stdio`, `Event::ProcessSpawn::stdio`,
  new optional offset `SOCKET_SK_OFFSET`). A shell or interpreter by exec
  identity whose stdin/stdout is an outbound inet socket (the reverse
  shell), or an accepted one not handed over by an inetd-style launcher
  (PID 1, inetd, xinetd, tcpserver… by identity: the bind shell), or a
  shell whose parent's stdio is an outbound socket (the pty-wrapped reverse
  shell, `dup2` then `pty.spawn`) is recorded, Critical; its kill of the
  tree is held behind the per-rule policy (off by default); the posture
  raises ConfirmedIntrusion for the same shape. ATT&CK (lab PR 221's typed
  mapping, Enterprise 20.0): Execution T1059.004 and Command and Control
  T1095 (the raw socket on its standard streams), as R006.
- NN-L-NET-026_ScanFanOut and NN-L-NET-027_OutboundAuthBruteforce (High;
  W4 CM-14): connect attempts and UDP sends are counted per process and per
  parent's direct children in sliding windows — ≥64 distinct hosts or ≥256
  (host, port) pairs in 60 s is recorded, ≥512 hosts from one process is
  the kill tier; ≥20 connects to SSH/Telnet/RDP/VNC ports in 300 s is
  recorded, ≥100 from one process is the kill tier. The kill tier is held
  behind the per-rule policy (off by default): a second record. Thresholds
  are agent flags (`--net-scan-*`, `--net-brute-*`, environment `NN_NET_*`;
  a weaker value is a signed weakening, `weakening_env` for a variable,
  `weakening_flag` for a flag, as are the `--net-snapshot-*` values). The
  host's monitoring and orchestration (Prometheus, Zabbix, Nagios, kubelet,
  Ansible, …, plus `--net-fanout-exempt`) are exempt by lineage: the name
  of the executable the kernel ran, in a root-owned system tree, never the
  `comm` a process sets. ATT&CK: Discovery T1046 and Credential Access T1110 (lab PR 221's
  typed mapping; both active in the pinned Enterprise 20.0 list).
- `nn-admin net status` (signed telemetry) appends four counters: verdicts
  at connect, open-flow snapshots judged and deferred, connects refused in
  the kernel (`StatusResponse` fields appended at the end).
- Lab suite `deploy/lab/malsim/net-check.sh` (`deploy/lab/nn-lab.sh
  net-check`): benign loopback simulations MS-04/04B/05/05B/06/06B/06N/21
  and a negative run, verdicts read from the signed detections log,
  `--before` prints KNOWN GAP where the starting tree has no verdict. New
  fuzz target `resolv_conf`. Registry: `v2-rules.tsv` version 3 (shared
  with lab PR 219's rows: 82 rows, sub-gate 28), `v2-techniques.tsv`
  version 2 (TQ61 T1046, TQ62 T1110, after lab PR 219's TQ60).
- Cryptographic test vectors pinned before the RustCrypto bump (Wave 4
  Phase 2, D0 of the dependency plan; lab PR 230): 20 vectors in 14 host
  tests (`cargo test crypto_vectors`) fix the bytes produced today through
  our own formats — the quarantine vault's HKDF file key and `nonce ‖
  ciphertext ‖ tag` record, and a vault written by `main` restored
  (`agent/tests/fixtures/vault-v1/`); SHA-256 of the install manifest's
  boot check and of the self-integrity overlay report; MD5 of JA3 and of
  dpkg's `.md5sums`; Ed25519 from a fixed seed and a signed admin payload
  (CBOR, SHA-512 digest, signature); an overlay signed and stored before
  the bump accepted by the overlay gate (`agent/tests/fixtures/overlay-v1/`).
  The vault's encryption and decryption are two functions the tests call
  (`seal`, `open`); what is written and read is unchanged.

### Fixed
- nn-admin's output matrix no longer flakes on a refused connection (lab
  PR 266b, found by lab PR 265's golden runs: `sock.net-status-json.
  refused-connection` read "Connection reset by peer" once in five). A
  child the test started from another thread held a copy of the case's
  listener between its fork and its exec, so the connect went into that
  listener's backlog and was reset when the copy closed. The test now
  starts every child under one lock, held shared from fork to exec, and
  makes and closes the listener of a refused connection and the read end
  of a closed pipe holding it exclusive; the golden files are unchanged
  (`docs/validation/GOLDEN_REPLAY.md` §8).
  The matrix 80 times in a row with no failure: 50 beside a fork storm,
  30 beside a parallel release build.
- Every integrity check before the eBPF load and the pin, enforced by the
  types, and every refused start signed (lab PR 262, Wave 4 restructure,
  R11b; `docs/operator/BOOT_INTEGRITY.md` §1 and §7). **The map.** Lab PR
  218 had moved the capability, install-manifest and audit-writability
  checks before the attach, but the audit chain itself (the key loaded and
  `AuditLog::open`, which repairs a torn last write and refuses a log with
  a line before the end that is not a row) was opened by the attest phase,
  after the object was loaded, its maps pinned, the sensors and the deny
  hooks attached and the self-test run; and only the install manifest's,
  the BPF LSM's and the self-test's refusals were signed — the eBPF
  object, the state directory, the BTF offsets, the demo rules, the
  capability gate and the audit log refused with a journal line (exit 1,
  78 for the BTF), as did the gates after the load. **The proof.**
  nn-linux's `boot::IntegrityVerified` (lab PR 218's `AttachPermit`): no
  public field, not `Clone`, `Copy` or `Default`, its one constructor
  outside tests `BootSequence::verify_integrity`, which requires every
  preflight step; the steps the attach depends on (the eBPF object, the
  state directory — required now too —, the BTF offsets, the capabilities,
  the install manifest, the audit log, the BPF LSM, the deny hooks' pin
  root and the kernel's BTF) are recorded only by `boot::checks`, each
  after its check ran against the host and passed (`BootSequence::done`
  refuses them, `BootOrderError::Unchecked`). A process has one sequence
  (`BootSequence::begin`, the only public way to one, refuses a second),
  and the checks read the host's own roots and the overrides from the
  environment: a caller gives the operator's configuration (the
  manifest's and the audit log's paths, `--detect-only`), never a root.
  The
  load (`SensorMultiplexer::start`, `start_with_net`, `ExecSensor::start`;
  the maps' by-name pins are made there), `attach_anti_tamper` and
  `anti_tamper::attach` (the pins and the deny hooks) and
  `attach_exploit_guard` take `&IntegrityVerified`; every later attach
  goes through the multiplexer's object; `EBPF_BYTES` is nn-linux's own.
  The agent's `attach::load` takes `&IntegrityVerified` and `&StateReady`
  (the plan's `attach(&IntegrityVerified, &StateReady)`; only
  `state::bootstrap` builds one). The BPF LSM gate moved to nn-linux
  (`boot::lsm`, re-exported) so that its check records its step. Tests
  evaluated when they build: neither the proof nor the sequence is
  `Clone`, `Copy` or `Default` (compile-fail examples: no proof written
  as a struct literal, none cloned, no access to the object's bytes;
  stable rustdoc does not check their error codes). Unsafe code forges
  any zero-sized type: the guarantee is safe Rust's. **The audit chain
  before the load.**
  `checks::audit_log` opens the log after the writability preflight; a
  chain that cannot be opened refuses the start before anything is loaded
  (fatal unless `NN_AUDIT_ALLOW_UNWRITABLE=1`), and the attest phase
  appends the boot's rows to that log in the same order as before. When
  the previous agent's hooks close the key or the log to this process (its
  early registration failed), the open stays after the attach, which
  registers it. **Signed refusals.** `boot::refusal`: every gate logs what
  it found, then the refusal is signed — the rollback floor, the identity,
  a `subsystem_degraded` where the gate had one, an `agent_boot` with
  `result: refused` and `refused_by` (`ebpf_object`, `state_dir`,
  `btf_offsets`, `demo_rules`, `capabilities`, `install_manifest`,
  `audit_log`, `bpf_lsm`, `deny_hooks` for the pin root and the BTF;
  after the load `sensors`, `deny_hooks`, `deny_self_test`, `audit_log`;
  `binary_integrity: unchecked` before the manifest's check) — in the
  audit log, else, when the audit log is the gate, in a fallback chain of
  its own (the audit log's format and key): a new file, created
  `O_CREAT|O_EXCL` under a random name in `boot-refusals/` beside
  `--pid-file` (`/run/northnarrow/boot-refusals/` under the unit), a
  directory the agent creates and checks — no name planted there is ever
  opened —, its first row (`boot_refusal_fallback`) naming the audit log
  and its head; else the journal says why, never with a file's content;
  the start's pid is withdrawn from the pinned PROTECTED_PIDS
  (the previous agent's map it registered in before the bootstraps, or
  this boot's after the attach), and the agent exits 78 for every gate.
  The preflight's three refusals, found before the identity is read, are
  signed at the start of the integrity phase, still before the load, and
  no state file is bootstrapped first (a linked state directory is not
  read nor written). The next start that opens the audit log reads each
  fallback chain once (bounded, without following a link or waiting on a
  FIFO), verifies it with the agent's key and records it from those same
  bytes, as one `boot_refusals_recovered` row before its own
  `agent_boot`, when it is bound to that log (its first row a fallback
  chain's, this agent's id, the head it names this log's row, not
  recorded before), and removes the file (anything else in the directory
  is recorded as refused, with why and none of its content, and removed
  too). The gates after the load (the sensors' load
  and attach, the deny hooks, the self-test, the boot's own row) keep
  their place: they need the loaded object, the attached hooks or the
  write. **Happy path unchanged**: the same checks, signed rows and
  capability manifest; the key's `reusing existing agent signing key` line
  comes before the attach now, and the preflight's step list names the
  two new checks. A signing key that is there but cannot be loaded
  (corrupted, empty, a bind mount of `/dev/null`, not a regular file), or
  an absent one that cannot be minted, refuses the start like an
  unwritable audit log, unsigned (it started unaudited); an absent key is
  minted as before. The audit chain's opens (the torn-tail repair, the
  tail read, the append) follow no final symbolic link, wait on no FIFO,
  take a regular file only, and a line that is not a row is named by its
  number and length, never by its content (the independent review of the
  PR, #466: F1–F4, F6–F8). Tests: the
  checks record only when they pass, no proof without every one, the chain
  opens before the load or refuses, the refusals in the audit log, the log
  already open, the fallback chain (a directory there, a failed write, the
  head it names), unsigned without an absolute `--pid-file`, the fallback
  recorded at the next start or refused (another key, a copy put back, a
  prefix of the audit log, another agent id, another log's head); the
  review's four probes where the fallback goes and inside it (a link to
  the key, to a file without a final newline, a dangling one, a FIFO:
  nothing followed, created, changed, quoted or waited on), and on the
  audit chain's own open and append; the key's loader on what is not a
  key; the withdrawal and the exit 78; the start's code (every pre-load
  refusal before the load, the preflight's at the integrity phase's start,
  one exit outside the one-shot modes); privileged e2e
  (`agent/tests/boot_refusal_privileged_e2e.rs`: a tampered binary, an
  unwritable audit log, a broken audit chain, CAP_KILL dropped, the key a
  link to `/dev/null`, the four probes — each exit 78, its row signed and
  verified by `nn-admin audit verify` where it can be, no BPF program,
  link or pin left, no own program-id list, its pid not left in
  PROTECTED_PIDS). Follow-up (review #466 F5): the fallback is on the
  runtime directory's tmpfs, and root can delete it before the next start
  records it (the journal line, with the chain's hash, stays). On the lab
  guest (Ubuntu 24.04), after the review's fixes: `test-ignored` 77
  suites, 91 passed (the six new e2e on the real kernel; CI's KVM suites
  the same on 5.15 and 6.8); `tamper-check` the same 75 outcomes and
  verdicts as `main`; the refusal paths on the installed agent — a
  tampered binary, `chattr +i` on the audit log, CAP_KILL dropped, a
  broken audit chain, a tampered binary with no pin, the pin root a
  symbolic link, a tmpfs over `/sys/kernel/btf`, the key hidden by a bind
  mount of `/dev/null`, the review's four probes where the fallback goes
  and two names planted in it — each exit 78, signed where a key can sign
  it, nothing loaded, followed, created or quoted, no program or pin
  left, the pid withdrawn (on `main`: three unsigned exits 1, the pid left
  in PROTECTED_PIDS, and the broken chain refused after the load with 22
  programs and 22 links left pinned); `upgrade-check` from `main` and back
  OK; the boots the same 204 lines but the key's line and the preflight's
  step list, the same signed rows and capability manifest.
- The agent's signing key made to look absent refuses the start where it
  re-keyed the install, for every way the review of #468 found while the
  previous agent's pins are there; after a reboot, a persistent view that
  hides both trees still looks like a first install (lab PR 265, the
  independent re-review of #466, F4-bis;
  `docs/operator/BOOT_INTEGRITY.md` §1.1,
  `docs/operator/INSTALL_UPGRADE_UNINSTALL.md` §3.10). Since review #466 F4
  a key that is there but cannot be loaded refuses the start; an absent key
  was minted as at a first boot, and root could make it look absent without
  the unlink the deny hooks refuse: a bind mount over `/etc/northnarrow` on
  the host (no deny hook covers `mount(2)`), or a runtime drop-in
  (`TemporaryFileSystem=`, `BindPaths=`) and a `cgroup.kill` (tamper case
  C20). The watchdog's respawn then minted a new key, published its public
  half, signed new chains and appended to the old ones under it, with one
  INFO line. Two checks now run first in the preflight, before the start
  registers, bootstraps a file or reads its identity, each a step the
  integrity proof requires (nn-linux `boot::checks::agent_mounts`,
  `signing_identity`; `boot::continuity`): **mounts** — in the agent's own
  `/proc/self/mountinfo`, every mount at or under `/etc/northnarrow`,
  `/var/lib/northnarrow` and the directories the command line puts the
  key, the identity, `admin.pub`, the manifest, the head anchor and the
  chains in must be a bind of a directory onto itself (the same filesystem
  as the mount under it, the directory that is there: what the unit's
  `ReadWritePaths=` makes, on ext4, on a btrfs subvolume, with a separate
  `/var`); another directory or file bound there, another filesystem, or a
  mount whose underlying one is not in the table refuses (`agent_mounts`),
  naming what is mounted where; a mount above those directories is not
  judged (a separate `/var` is a normal layout); **identity** — a key whose
  name holds nothing, where its public half, the install's id or a signed
  first row of the audit log or another chain is found, refuses
  (`signing_identity`) and nothing is minted; only a start with none of it
  (a first install, as far as those paths tell) mints the key, and the
  key's loader never mints one beside an existing public half. Both refusals are unsigned (nothing can
  sign them: the key is the one hidden or absent), exit 78, the
  registration withdrawn, as review #466 F4's (`boot::refusal::refuse_unsigned`,
  the start's one exit). No override: a variable a drop-in can set would
  come with the drop-in that lays the mount. The unit's runtime drop-in
  directory `/run/systemd/system/northnarrow-agent.service.d` is made
  (empty) before every start (`ExecStartPre=+/bin/mkdir -p`) and registered
  NOCREATE like the persistent one: a drop-in there (`systemctl edit
  --runtime`) needs a signed trusted-installer window; `uninstall.sh`
  removes it. Re-keying on purpose is retiring the identity: archive the
  chains with `agent.sig.pub`, `uninstall.sh --purge --grant-key`, install
  again. Tests: the mount rule on parsed tables (the unit's binds, a
  separate `/var`, a btrfs subvolume, an empty directory bound over the
  configuration directory, a tmpfs, a copy over the state directory, a file
  bound over the key, a mount inside, an unknown parent, an ancestor not
  judged, escaped paths), the real table in a user and mount namespace of
  its own (a bind onto itself passes; an empty directory, a tmpfs, a file
  bound over the key refuse), the evidence one by one (an empty, broken,
  linked or FIFO chain is none), the checks recording their steps only when
  they pass, the loader's refusal to mint, the start's order (both checks
  before the registration, the first key load, the identity and every other
  check; one exit); privileged e2e: the key absent beside an earlier
  identity (exit 78, unsigned, no key minted, the identity's bytes kept), an
  empty directory bound over the state directory in a mount namespace of
  the agent's own (`InstalledAgent::command_with_binds`; refused, nothing
  written). The guard fixture's runs of one directory share the install's
  id: each run's key is made before its first start. On the lab guest
  (Ubuntu 22.04, 5.15), `main` first: an empty directory bound over
  `/etc/northnarrow` (and a copy over `/var/lib/northnarrow`) on the host,
  then `cgroup.kill`: the watchdog's respawn minted a key
  (`bootstrapped fresh agent signing key`, INFO), published a new public
  half, began a new audit chain and appended to the copy's chains, and
  reached READY; a runtime prefix drop-in `TemporaryFileSystem=` did the
  same in a tmpfs; a drop-in in the agent's runtime drop-in directory was
  made at will. On the lot's code: both refused (`agent_mounts`, exit 78,
  unsigned, nothing written in the empty directory or the copy); another
  key bound over the key refused, not loaded; the key moved aside in a
  window refused (`signing_identity`, the evidence named, no key minted);
  the runtime drop-in denied outside a window; the identity, the public
  half and the audit chain unchanged throughout. `test-ignored` 77 suites,
  94 passed (the two new e2e on the real kernel); `tamper-check` the same
  75 outcomes and verdicts as `main` (C30: one more protected inode, the
  runtime drop-in directory); `upgrade-check` from `main` and back OK.
  After the independent review of the PR (#468, "merge after X"): **one
  `mountinfo` reader** (nn-linux `mountinfo`) for the start and the
  self-integrity watcher — the table read as bytes, split on the ASCII
  space only, every `\ooo` escape a byte, the paths `OsString`s, the
  kernel's line shape checked: a split on every Unicode space shifted the
  fields of a path holding U+00A0, so a bind over `/etc/northnarrow` from
  such a directory went unseen (R1), and a byte that is not UTF-8 in any
  mount — an unprivileged FUSE mount can make one — left the table
  unreadable and the agent refused to start (R3); a line not in the
  kernel's shape refuses only when it may concern the agent's
  directories; the watcher's sandbox rule is the start's self-bind rule
  (it was a string suffix). **The kernel's proof** (R2): the previous
  agent's pins outlive a `cgroup.kill`, and its pinned `PROTECTED_INODES`
  holds what it protected; with pins there, `/etc/northnarrow` and
  `/var/lib/northnarrow` as the start sees them must be those inodes (a
  copy bound over `/etc` or `/var/lib`, a rename above them, another root
  refuse: `agent_mounts`), and a start that runs the binary the previous
  agent protected is its restart — its key in a directory that agent
  protected, and there (a drop-in redefining `ExecStart=` with every
  identity path in an empty directory refuses: `signing_identity`); one
  bpffs alone at `/sys/fs/bpf`, nothing over the pin root. The tests'
  agents run copies of the binary and keep their files elsewhere: judged by
  the evidence alone. **The evidence** (R8): any lookup that is not "not
  found" counts, and so do the chains' manifests and sealed archives and a
  written head anchor. **The re-key procedure** (R5,
  `INSTALL_UPGRADE_UNINSTALL.md` §3.10): the journal and the fallback
  chains archived first (`--purge` deletes the only record of the unsigned
  refusals), and the way for an agent that refuses to start (disable the
  units, archive, reboot, `uninstall.sh --purge`, install). What stays open
  is listed in `BOOT_INTEGRITY.md` §1.1: a reboot with a persistent
  mount, drop-in or generator that swaps both trees or moves every
  identity path; a copy of the binary started by a drop-in; the window
  between the check and the key's load (R4). On the lab guest (Ubuntu 22.04), against `main` 8788e0d0: on `main`
  copies of `/etc` and `/var/lib` (an empty `northnarrow` in each) bound
  over them, and a `system.control` drop-in redefining `ExecStart=` with
  every identity path in an empty directory, each followed by a
  `cgroup.kill`, re-keyed the install; on the lot's code both refuse
  (`agent_mounts`: not the inodes the previous agent protected;
  `signing_identity`: a restart of the protected binary, its key elsewhere
  and absent), and so does a bpffs stacked on `/sys/fs/bpf`; the pins
  survive `cgroup.kill`, and a plain start and the watchdog's respawn with
  them there reach READY; `test-ignored` 78 suites, 94 passed; `tamper-check`
  the same 75 outcomes and verdicts as `main` 8788e0d0; `upgrade-check`
  from `main` and back OK; §3.10's two branches run as written (a signed
  uninstall of a running agent; for a refusing one the signed uninstall
  fails, then disable, archive, reboot, `uninstall.sh --purge` without a
  window, a fresh install): new keys, the archives verify with the old
  public halves, the archived journal holds the refusals.
- `nn-admin fim baseline` was answered `Success`, and its signed audit row
  read "success", when no baseline would be recorded (lab PR 263, found
  by R11d's table of the admin socket's verification copies): without
  the FIM's admin state the verb logged "recompute scheduled for next
  agent restart", which no restart does; and on a boot that found no
  baseline database (its open failed, or the agent key did not load) the
  recompute task's receiver is dropped, so the request was dropped with
  it — `trigger` returned `false`, logged as `queued=false` — while the
  reply and the row said success. Now the recompute sender says what
  became of a request (`Triggered::{Queued, Coalesced, Dropped}`,
  nn-linux) and the verb answers `UnknownOperation` without the FIM's
  state (as `fim status` and every verb without its subsystem) and
  `ActionFailed` for a dropped request (verified, not carried out); a
  request a recompute in flight subsumes stays a success. The rows read
  "failure: unknown_operation" / "failure: action_failed"; nn-admin
  prints "fim baseline: nothing was recorded: the agent verified the
  request but has no baseline recompute task this boot (…)" for the
  dropped request (the independent review's L-3) and "server rejected
  operation" without the state, exit 5 both.
- The signed `detections` read served rows it had not verified on a
  degraded boot (lab PR 263, found by R11d's table): without the
  detection store's state — no agent key this boot, or a status-event
  log that did not open, which dropped the whole state — it read the
  built-in paths (not `--detections-file`) with no key to check the rows
  by, so the check of external audit NN-AUD-112 was skipped and any
  well-formed line was served as a detection. `DetectionAdminState` now
  carries the agent key's public half (`agent_key`) and the status log
  as an `Option`: the boot builds it whenever the key loads; the read
  takes its paths and verifies every row with `agent_key`, and is refused
  (`UnknownOperation`, as set-status) without a state; set-status is
  refused when the status log did not open, as before.
- Two `rotate-keys add` requests sent at once while the one-key
  bootstrap was armed could both pass with its one signature (lab PR
  263, the independent review's L-4; on `main` as well): the bootstrap
  gate is read before the verify, and was read outside any lock, so
  both found it armed — the first added the second key, the other a
  third. No escalation (the bootstrap key can add a key of its own and
  co-sign), but not the one add the design allows; and an add and a
  revoke each rewrote the admin.pub it had read, so one could lose the
  other's line (a revoked key kept, an added one dropped). `AdminAuth`
  (nn-linux) holds a rotation lock now, which both rotate-keys verbs
  take before the gate, the verify, the rewrite and the reload: a
  second add waits, then finds the key set at two and the bootstrap
  spent (`QuorumNotMet`).
- A tripped canary came back armed when the agent stopped between the
  trip's two rows (lab PR 260; lab PR 258's KVM run on Ubuntu 24.04:
  the e2e fixture's restart signal landed there, and
  `file_canary_deployed_at_runtime_survives_an_agent_restart` saw the
  next read a first trip). The detector writes and syncs the access row
  (`first_trip: true`) and then the registry's `trip` row naming it; a
  crash, a kill or a power loss between the two — or a `trip` row that
  could not be written — left the registry at its deploy row, and the
  next start re-armed the canary: the trip forgotten by the registry,
  its next access answered as a first trip. The access row is the
  trip's commit now: at each start, before the detector runs, the
  registry reads the access log's first-trip rows of the canaries it
  holds armed (`access_log::first_trip_rows`: hash, signature and
  canonical bytes verified, a row placed by the `seq` it was signed
  with, a copy or a moved row ignored) and finds the ones written in the
  canary's current arming that no registry row names
  (`Registry::unrecorded_trips`): the arming starts after the latest
  first-trip row a registry row names, and a `refresh` row names the
  trip it clears (`first_trip_access_hash`, with `tripped: false`; it
  was always `null`), so a refresh after a `trip` row that could not be
  written does not come back tripped; a refresh that names nothing (of
  an armed canary, or written before) is placed by its time. Each trip
  found is an ERROR, a signed `canary_trip_recovered` (the canary, the
  access row, its accessor) and then a `trip` row naming the access
  row: the canary stays tripped, `nn-admin canary list` shows it. The
  signed access log keeps its format; the registry's rows keep theirs
  (an agent before reads the `refresh` row's hash as cleared). A stop
  after the `trip` row and before the verdict leaves both rows: the
  trip holds, and a response that had not run does not run, as for any
  event the agent had read. Tests: every stop of the detector (before
  the access row, in it torn, after it, in the `trip` row torn, after
  it, none) on nn-linux's stores, then the next start: an access row on
  disk is one trip, recorded once, and the next access is not a first
  trip; none, and the canary is armed; the refresh, legacy and forgery
  cases; and the privileged e2e
  `a_trip_the_agent_stopped_before_recording_is_kept_across_the_restart`,
  which stops the agent at that point with a `debug-trigger` failpoint
  (`debug-canary-stop-before-trip` next to the registry: the agent
  aborts at the detector's trip mark).
- Three host tests failed now and then under load, each on a race of
  its own (lab PR 258; the flakes lab PRs 254 and 256 recorded and lab
  PR 234's hotfix saw); the first race was the product's. The
  quarantine kept the repairs of a vault's index (external audit
  CMB-017) in one list for the process, and every executor's record of
  a quarantine took the whole list, even a refused one: the COMBAT
  actuator's NEUTRALIZE tests took the note nn-linux's
  `a_corrupt_index_is_rebuilt_from_the_meta_files` was waiting for. The
  notes are kept per vault now, its directory the key, and an executor
  takes its own vault's; the agent has one vault, its executor's and the
  exec quarantine's, and records the same notes at the same quarantine.
  The agent's `cow::fanotify::tests::own_threads_and_tgid` asked whether
  a thread `join` had returned for was still listed, then read its
  `status`: the kernel releases the thread after `join` returns, and a
  release between the two reads left a listed thread without a
  `status`. It reads the `status` first now, and looks at a thread it
  holds too. The watchdog's `sd_notify_reaches_an_abstract_notify_socket`
  closed its listener and expected the next `READY=1` refused, but a
  child another test was spawning held a copy of the listener's
  descriptor until its exec, and the socket took the datagram: the
  listener is shut down before it is closed, and so are the sockets of
  two tests with the same race (the watchdog's
  `nothing_listening_at_the_path_is_absent_not_unresponsive`, which
  failed so in this lot's runs, and nn-linux's
  `ready_reaches_an_abstract_notify_socket`). No assertion weakened, no
  sleep added.
- The privileged suites wrote the installed agent's evidence, and the
  boot check's report did not say what was wrong (lab PR 256; lot 255's
  finding). Run as root on the lab guests and in the KVM CI, where an
  agent is installed, six agent spawns of the e2e fixtures gave their
  agent a signing key of its own but not all of its chains, and three
  neither key nor audit log: those agents appended rows under their own
  key to the installed agent's detection, netflow and FIM drift logs —
  every start of the installed agent then reported `chain_verify_failed`
  — and test rows (`nn-admin-e2etest-*`) to its audit chain under its key.
  `agent/tests/common/agent_state.rs` is the one way a test starts an
  agent: every path flag of the agent that names a file it writes or its
  identity (17: the id, the admin keys, the signing key, the audit log,
  the heads anchor, the eight chains, the socket, the shutdown marker,
  the pid files) gets a file in the test's directory, and the watchdog's
  suite uses the same file; `xtask/tests/test_state_isolation.rs` fails
  on an agent started any other way, on a path flag of the agent the
  helper does not classify, on a test naming the agent's state flags and
  on a test naming the agent's host paths without a reason. The boot
  check (the last 4 MiB of each rotating log) now says the class of what
  fails: lines whose hash recomputes and whose link holds but that
  another key signed are counted over the window (`K of the M lines
  checked are signed by another key, from <line> to <line>`, a line
  placed by its byte offset, by its line number when the window starts
  the file, and by its `ts`, where `entry N` counted from the window's
  first line); an altered line, a broken link and the other breaks keep
  their own class and stop the check at the first; the signed
  `chain_verify` gives each log's `class`. It is still a
  `chain_verify_failed`, at every start while the lines are there.
  `docs/operator/EVIDENCE_CHAINS.md` no longer says that finding is
  written once, and says what to do.
- Lab and validation tooling (lab PR 248; no product change). Under whpx
  `nn-lab.sh ssh … bash -s` with the script on stdin (a here-doc, a pipe,
  `< file`) ran none of it and exited 0 (lab PR 245 hit it): there
  `vm_running` is an ssh probe running `true`, and ssh hands its stdin to
  the remote command, which dropped the script. The probes now read
  `/dev/null`, as does every Windows program the script runs (WSL interop
  gives them the caller's stdin, and tasklist.exe read a piped script to
  its end). A whpx guest powered off from inside — the lab host's stop
  helper — took QEMU for Windows down a few seconds later but left its ssh
  forwarder (unit `nn-fwd-<guest>`, which only `down` stops) listening on
  127.0.0.1, and `status` called that "stopped"; `down` said "stopped"
  without checking. `status` now names a forwarder left running, and
  `down` says "stopped" only once tasklist.exe no longer lists QEMU and
  systemd no longer runs the forwarder, else it names what is left and
  exits 1. `cargo xtask perf-compare` took two runs of one guest for two
  hosts (exit 2) when MemTotal moved by a few KiB between boots (8,131,760
  and 8,131,764 KiB), so every comparison needed `--allow-host-mismatch`:
  a MemTotal within ±0.1 % of the base's or ±1 MiB, whichever is larger,
  is the same host now, and the output notes the drift; another kernel,
  CPU model or vCPU count, a larger MemTotal change, another
  virtualisation or clocksource are still refused.
- The signed `combat_stage` rows of a COMBAT the posture reached said
  `"trigger": null`, and the INVESTIGATE row named no offender (lab PR
  245; found by the golden replay of lab PR 243). The posture's entry hook
  took no argument: `main.rs` opened the ladder's episode from it
  (`engage(None, None)`) inside `observe`, before `process_event` named the
  offender and the firing trigger to `engage_with`, which by then only
  merged the offender and dropped the trigger. The hook now receives the
  posture's `CombatEntry` — the firing trigger with the evidence it cites
  (every trigger the event raised, the kind of evidence, decisive or
  corroborated and by which earlier signals of the actor's scope, locked,
  the scope, the event), or a forced COMBAT with its signers, and the
  process the event names (never init) — and the ladder has one entry
  point, `CombatLadder::engage(&CombatEntry, now)`: the episode opens with
  its cause and its offender. Every `combat_stage` row names the trigger
  (`combat_outcome` rows too) and carries `cause` and `offender_details`
  (each offender as captured when attributed: pid, starts, executable and
  cgroup read from `/proc` while the capture still names it, how it joined
  the episode); a later COMBAT entry naming another process during an
  episode adds it with a signed row of its own (`added`: that process and
  the later entry's cause), the episode's trigger unchanged. Older rows
  keep their bytes and verify; `nn-admin audit read`, its `--json` export
  and `audit verify` read both shapes. Posture golden: the six cases that
  reach COMBAT moved (the trigger and the offender, and what follows from
  the offender being there when the episode opens); the decision golden is
  unchanged.
- The close of a network canary trip's own connection could draw
  NN-L-CHAIN-003 (lab PR 246; the KVM failure of
  `network_canary_connect_trips_canary_003_and_kills_the_connector` on
  Ubuntu 22.04, job 122036206565): a second Critical for the one connect
  NN-L-CANARY-003 answers. The connect and the close come on two rings,
  read by two tasks. When the close reached the flow tracker first, its
  row was synthesised starting at the close (`tcp 127.0.0.1:0 closed`: a
  refused connect, the port cleared by the kernel), while the trip owned
  the connection under the connect's time; when the connect then reached
  the engine first, the close was not recognised and was judged as an
  egress after the trip. A synthesised close now starts at its connect
  (the kernel correlator's time); the net drain holds a TCP close until
  the connect pump has put its connect on the bus (at most 500 ms from
  the connect: `CONNECT_WAIT`), so a close resolves against its connect
  and follows it; the engine's flow ledger owns every row of a network
  trip's connection from the trip on, also past the close (a
  connect-time row that followed the close drew the chain too), in place
  of the detector's queue; and a trip drops the egress note its
  connection left when its close was judged first, so no chain completed
  late — NN-L-CHAIN-001 on a credential read, NN-L-CHAIN-002 (lab PR 244)
  on a staging exec, NN-L-CHAIN-007 on either, processed after the close
  — uses the trip's own connection. Any other flow of the process is
  still NN-L-CHAIN-003. Golden cases `canary003-trip-owns-its-connection`,
  `canary003-close-before-the-trip` and
  `canary003-close-before-the-trip-late-exec`.
- NN-L-CHAIN-002 (`/tmp` exec, then egress) was missed when the exec
  record reached the engine after the egress it preceded (lab PR 244; the
  race lab PR 235 fixed for NN-L-CHAIN-007): the egress was judged before
  the staging exec was known, and the exec completed nothing. The egress
  the engine notes for a late precursor now keeps its destination address
  and port, so a late exec completes CHAIN-002 on the kernel timestamps,
  naming the egress, with the in-order rule's resolver exemption, package
  carve-out and port-53 hold. A flow still gets at most two chain verdicts
  — the two-step one, then NN-L-CHAIN-007 — and CHAIN-002 now also claims
  the egress it answers in order, so a second staging exec of the process
  completes no second CHAIN-002 with it.
- An exec record named, as its parent's start (`parent_start_ns`, the
  PID-reuse key of the lineage), the start of the THREAD that forked it
  (lab PR 238, the follow-up of lab PR 120 known as lot 122): the eBPF
  exec sensor read `real_parent->start_time`, and `real_parent` is the
  forking thread. For a child of a thread other than its parent's main
  one, that key matched no record of the parent (whose exec reports its
  thread-group leader's start); once the parent had exited, the COMBAT
  ladder no longer took such a child of an offender for its child. It now
  reads `real_parent->group_leader->start_time`, the parent process's
  start; unread, the field stays 0 ("unknown"), never a thread's start.
  New BTF offset `TASK_STRUCT_GROUP_LEADER_OFFSET` (required, resolved at
  boot like the others): slot 100; the enum, tracepoint and hook-argument
  slots move up by one (117 slots).
- The quarantine vault's records carried no format version (lab PR 238):
  a `.bin` was `nonce ‖ ciphertext ‖ tag`, the version only implied by the
  HKDF salt `northnarrow-quarantine-v1`. New entries are written as v2:
  `"NNQV" ‖ 0x02 ‖ nonce ‖ ciphertext ‖ tag`, the key salted
  `northnarrow-quarantine-v2`, the header and the vault id authenticated
  with the content, and `"format": 2` in the `.meta`. Entries written
  before (no `format`) are read as v1, as they were. A `.meta` naming a
  format the agent does not read, a header naming one, or a `.bin` whose
  format differs from its `.meta`'s is refused with that reason before
  anything is decrypted or written. The vectors of lab PR 230 and the v1
  vault fixture pass unchanged; the v2 record is pinned too.
- NN-L-IMP-001's copy-delete evidence counted, in a world-writable sticky
  directory that was the burst's own (`/tmp`, `/var/tmp`, `/dev/shm`), the
  copies of whoever owned them (lab PR 238, the residual of lab PR 232):
  another user's fresh copies of ciphertext there, or copies planted to
  have a benign job judged an encryptor, made the burst decisive. There,
  only the copies owned by the uid the burst ran as count now, the copy
  the record names included (checked on the file opened); an encryptor's
  copies are new files, its own. Ordinary directories, a `0777` share
  included, are unchanged.
- Rule shadowing (lab PR 236): NN-L-FIM-023 (systemd timer) was never
  reached behind NN-L-FIM-009 — both now match a `.timer`; a new
  `authorized_keys` under `/home` was NN-L-FIM-002's record and
  NN-L-FIM-004 was never recorded — FIM-004 (High) is now the primary rule,
  its kill held by the legacy ceiling until `enforce NN-L-FIM-004`; a large
  internal transfer was NN-L-NET-007's Medium and NN-L-NET-009's UDP sum
  never grew — NET-009 (High) is the primary rule and its UDP sum crosses
  100 MiB; R001 and R009 were silent on an exec that completed
  NN-L-CHAIN-007 late (lab PR 235) — the record names all three. Without a
  policy no event gets a stronger response than before.
- NN-L-CHAIN-007 (`/tmp` exec, credential read, egress) was missed when
  the exec record reached the engine after the read and the egress it
  preceded (lab PR 235; the CI flake of
  `chain_tmp_then_cred_then_egress_trips_chain_007` on Ubuntu 22.04):
  CHAIN-001 fired and CHAIN-007 never did. The exec now completes the
  chain on the kernel timestamps, as a late read already did (review 70).
- A `chmod u+s` of a watched file could go unrecorded as attribute drift
  (lab PR 229; the CI flake of `fim_chmod_setuid_records_attribute_drift`).
  The recompute task filled the drain's baseline cache only after the
  baseline row's fsync: a chmod in that window was compared with no
  baseline and recorded as `Modified`, with no mode. The cache now takes
  the entry before the row is written. The `inode_setattr` hook fires
  before the change lands: a drain that re-read the file first dropped
  the event as a no-op touch; the event now waits (up to 2 s) until a
  `stat` shows the change, then is checked as its writer's modification.
  A mode or owner change read with a content change is named on the
  `Modified` row (`attrs`), where it was dropped.
- The DNS attribution of a flow (`resolved_hostname`) depended on which of
  three tasks ran first (lab PR 229; the CI flake of
  `net_outbound_connect_records_flow_with_dns_attribution`): a close or a
  connect read before the DNS pump had read the query of the same process
  found no name. They now wait, at most 250 ms from the record, for a pass
  of the DNS pump begun after them; the pump feeds the cache a whole pass
  at a time and holds the events of a full bus in order instead of
  feeding it behind each send. Names asked through systemd-resolved's NSS
  module (`resolve` before `dns` in nsswitch.conf: Debian 13, Fedora) are
  attributed too: an optional uprobe on `libnss_resolve.so.2`
  (`_nss_resolve_gethostbyname4_r`, `…3_r`) reads them into the DNS cache
  only (no `DnsQuery` event; the DNS rules judge the queries on the wire).
  The Debian 13 expected failure of the CI gate is removed.
- `install.sh --upgrade` failed on Ubuntu 26.04 and rolled back (lab PR
  229): it ran `install -d` on the state directory before lifting the
  immutable flag the agent sets on it. GNU install leaves an existing
  directory's owner and mode alone when they match; uutils coreutils, the
  default on 26.04, sets them again, which an immutable directory refuses.
  The flag is now lifted first.
- NN-L-IMP-001's copy-delete evidence looked for the copies below and
  beside the burst's directory across a world-writable sticky directory
  (lab PR 232): a user's script with one plain copy in `/tmp/job` was
  decisive on another tree's fresh copies of ciphertext under the same
  suffix elsewhere in `/tmp` — anyone's, and plantable. The copy walk no
  longer goes below `/tmp`, `/var/tmp`, `/dev/shm` (`1777`) nor beside a
  directory in one; that directory's own copies and the trees of ordinary
  directories still count. The impact tests now work in a directory of
  their own inside their `TempDir`: one read another's `.locked` copies
  beside it in `/tmp` and failed on CI (PR 427).
- NN-L-FIM-010 named a rename's destination DIRECTORY, so a watched file
  renamed `x → x.locked` never matched, and a rename inside a watched data
  directory (seen as the directory's creation of the new name) was not
  looked at (lab PR 225). The kernel carries the new leaf
  (`FIM_RENAME_DEST_LEAF`); the drain names `dir/leaf`, falling back to the
  directory entry that holds the renamed inode; the rule reads the moved-in
  creation too, one verdict per rename. That moved-in match is new: its
  kill is held behind the per-rule response policy (off by default, a
  Critical record); the watched file's own rename kills as the rule always
  meant to.
- The port-53 exemption of NN-L-NET-008 and NN-L-CHAIN-002/005 ignored the
  protocol and the server (research defect D1): an implant in `/tmp` with
  its C2 on TCP/53 to its own server passed all three. It now covers only a
  flow to port 53 (UDP or TCP) of one of the host's configured resolvers
  (`nameserver` lines of `/etc/resolv.conf` and
  `/run/systemd/resolve/resolv.conf`, re-read when they change). That
  match is new, so its kill is held behind the per-rule policy (off by
  default): a record at the rule's severity.
- The transfer tools of `netflow-comm-allowlist` (`curl`, `wget`, `ssh`,
  `scp`, `sftp`, `rsync`, `git`) stay exempt from the network record and
  port rules for what they are, but no longer when their lineage holds a
  precursor (research defect D9): an exec from a staging directory or a
  staged image among the ancestors, a credential-store read, a canary
  trip, or a shell an exposed network service started — the
  `curl … | sh` of a dropper and the `ssh` of a web shell are judged like
  any other program (`Judgement::Revoked`, said in the reasoning). They
  were exempt before, so a kill there is held behind the per-rule policy
  (off by default): a record at the rule's severity.
- Exec quarantine at first sight, EXPERIMENTAL and off by default
  (capabilities C13, C12; lab PR 223; `docs/design/EXEC_QUARANTINE.md`).
  With `--exec-quarantine enforce` an executable never judged on the host,
  run from a guarded location (`/tmp`, `/var/tmp`, `/dev/shm`, a home
  directory, a world-writable directory, a memory-backed filesystem, a
  memfd, an unlinked file), is held by the kernel before its first
  instruction: `sched_process_exec` sends it `SIGSTOP` (`bpf_send_signal`,
  pending before the task returns to user mode in the new image); the LSM
  exec sensor classifies each binfmt pass. The agent opens the file the
  process runs (`/proc/<pid>/exe`, or a script by path, the inode checked),
  trusts a package's unmodified file (dpkg md5sums, rpm digests), has the
  file scanned, waits within the budget for the rule engine's verdict on the
  same exec (a rule kill lands on a held process: it never ran), then
  resumes it, or kills it and quarantines the file. No decision within the budget
  (`--exec-quarantine-budget-ms`, 2000) gets the default policy
  (`--exec-quarantine-on-expiry`, resume); a suspicious verdict gets
  `--exec-quarantine-on-suspicious` (resume). An identity judged once —
  `(dev, ino)` under the same ctime and size, resumed (or observed), for
  the agent's run — is not held again; a copy of content judged clean is
  resumed on its digest without a new record. A decision is a signed
  detection record `NN-L-EXECQ-001_FirstSightQuarantine`, except a resume on
  a known digest, a clean verdict that arrives after the default policy,
  and what the per-rule budget holds back
  (ATT&CK 20.0, lab PR 221's typed mapping: TA0002, T1204.002, T1059.x for
  a script, `mitre_version` set; field `execq`: verdict,
  SHA-256, reasons, decision, classes, held time); a guard that cannot
  start and a scanner loss are signed `subsystem_degraded` (one per cause
  per 10 min, repeats counted); processes a dead agent left held are
  resumed at the next boot that runs the guard (`exec_quarantine`
  `recovered_at_boot`). Fail-open: without the controller's heartbeat, with
  a full ring (`RING_DROPS[execq]`, a security ring) or a refused signal the
  kernel holds nothing; the execs a full ring or a refused signal let run
  are a signed `subsystem_degraded` with their counts, at most one per
  10 min; the kernel configuration is frozen. A detect-only
  agent observes. `nn-admin status --key` shows its state and counts
  (`execq_*`, appended after lab PR 222's `cow_guard`). New BTF offsets
  `INODE_I_CTIME_SEC_OFFSET` / `INODE_I_CTIME_NSEC_OFFSET` (optional; slots
  95 and 96, after lab PR 219's; the tracepoint, enum and hook argument
  slots move up by two).
- `northnarrow-scan`, the exec quarantine's scanner: a separate process the
  agent spawns as the system account `northnarrow-scan` (created by
  `install.sh`, removed by `uninstall.sh`; `CAP_SETUID`/`CAP_SETGID` added
  to the agent unit's bounding set), supervised and restarted under a
  backoff. It refuses root, sets `PR_SET_NO_NEW_PRIVS` and
  `PR_SET_DUMPABLE` 0, closes every other descriptor, caps processes,
  descriptors and memory, then installs a seccomp filter that kills it on
  any `open*`, `exec*`, `socket`, `clone`, `ptrace`, `bpf` or executable
  mapping: it reads only the descriptors the agent hands it over a
  `SOCK_SEQPACKET` pair (`SCM_RIGHTS`), its configuration from a sealed
  memfd. It computes SHA-256, checks the signed hash list and runs
  explainable ELF heuristics (UPX, high-entropy code, RWX segments, an
  unusual or missing interpreter, a stripped static binary, suspicious
  imports in a small binary; weights to a threshold, every reason in the
  record). Shipped in the tarball, the `.deb` and the `.rpm`, recorded in
  `install-manifest.json`, its binary inode-protected. YARA is not in this
  release: libyara is C, yara-x needs rustc 1.95 and a JIT the filter
  refuses; the `yara` feature is reserved (design §6).
- Overlay kind `execq-hashes` (`/etc/northnarrow/execq-hashes.local`,
  `block <sha256> [label]` / `allow <sha256> [label]`), signed and verified
  like every overlay (`nn-admin config overlay set execq-hashes`),
  MUTATE-protected with its signature.
- Lab check `deploy/lab/execq/execq-check.sh` (`nn-lab.sh execq-check`).
- Copy on first write: ransomware rollback for Linux (lab PR 222,
  EXPERIMENTAL, off by default; capabilities C19, C17;
  `docs/design/COPY_ON_FIRST_WRITE.md`). Before a writer whose trust is not
  established opens an existing file for writing in a protected scope, the
  agent copies the file while the open waits in a fanotify permission event
  (`FAN_OPEN_PERM`, `FAN_REPORT_TID`; answered `FAN_ALLOW` by the reader,
  the copier or a backstop — never denied, never waited on indefinitely: a
  copy within `event_budget_ms` (50 ms) + 25 ms of the reader reading the
  event, any other open once the reader has decided; a reader stalled 3 s
  closes the group and the kernel allows everything). No thread of the
  guard opens a journal file while holding a lock the reader takes, so a
  scope marked by mount or filesystem, its journal under the mark, does not
  make the guard wait on itself. The writer's open flags come from
  `/proc/<tid>/syscall` (the fanotify metadata has none; `openat2`, `io_uring`
  and anything unknown count as writes). Trust is by exec identity and
  ordered lineage (`AuthSessionTracker::lineage_identities`, new): a root
  package transaction, or a trusted writer — editors and `git`, plus the
  overlay's `trusted_writer` entries, by `ExecIdentity::is_client` — with no
  foreign ancestor; never by `comm`. The copy is a reflink (`FICLONE`: XFS,
  btrfs) or a bounded copy (`copy_file_range`, at most `copy_cap`, 16 MiB),
  into a root-only journal per scope, by default on the scope's filesystem
  (`<scope>/.northnarrow-cow`, registered in `PROTECTED_INODES`: MUTATE |
  NOCREATE on its directories, MUTATE | WRITE on `index.jsonl`), with a
  content index (path, inode, size, times, birth time, owner, SHA-256, writer
  and lineage), a byte budget per scope, LRU eviction that never evicts a copy
  used (taken or shared) in the last 15 min, and 24 h retention from last
  use. Restore: `nn-admin remediate ransomware [--pid <pid>] [--since <ts>]
  [--dry-run] --key <key>` (at least one; together, an entry meets both;
  `--since` alone restores every writer's earliest copy since then)
  (`OperationCode::RemediateRansomware` 26, `AdminMessage::RemediateRansomware{Request,Response}`
  appended at indices 56/57 after lab PR 217's signed unlock pair, the
  debug-only variants moving to 58/59, role `response-manage`), and on its own when the COMBAT ladder's
  NEUTRALIZE (new `CombatLadder::with_neutralize_hook`) or NN-L-FIM-010's kill
  neutralizes a tree a ransomware signal named, with `auto_restore = true`
  (default false; never in detect-only; NN-L-FIM-010's kill restores without
  COMBAT). One signed `cow_restore` audit row per file; a file someone else
  changed after the attack, as far as the guard saw (a write-open seen after
  the copy — kept in memory, the last 8 per inode, 0-byte files not copied
  — another inode or a reused inode number, a copy older than this run and a
  newer mtime), is not overwritten — the original is written beside it.
  Paths are reached with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`.
  Configuration is the signed overlay `cow-guard.local`
  (`OverlayKind::CowGuard`, 12; protected like the others); the drop-in
  `deploy/systemd/20-cow-guard.conf` (`install.sh --cow-guard`, known to
  self-integrity) adds `CAP_SYS_ADMIN`, `CAP_CHOWN`, `CAP_FOWNER`.
  `status --key` shows the guard (`StatusResponse::cow_guard`, appended
  after lab PR 219's `exploit_guard`, telemetry). A degradation is a signed
  `integrity_drift` (`subsystem_degraded`): per reason the first at once,
  then a summary at most every 10 min; through the guard's work queue, so a
  full queue can lose one. Not
  protected, and said so: files over the cap without reflink, writers
  already trusted, the journal against root when the anti-tamper hooks are
  off, descriptors opened before the guard watched (an `mmap` write is
  covered: its writable descriptor's open is seen), encryption into new
  files with unlink or rename-over. Microbenchmark `agent/examples/cow_bench.rs`;
  lab harness `deploy/lab/cow/cow-check.sh` with a benign simulator
  (`ransom-sim.py`).
- Every rule declares its MITRE ATT&CK tactics and techniques as data
  (lab PR 221, capability C16): `Rule::attack()` returns typed
  references (a `Tactic` enum, technique ids checked for shape when they
  compile) of ATT&CK Enterprise 20.0. All 93 rules the agent can record
  (lab PR 219's two, lab PR 223's NN-L-EXECQ-001, lab PR 224's three, lab
  PR 225's six and lab PR 226's four included) are mapped — 66 techniques
  and sub-techniques under 12 tactics — and a rule detection
  record now carries their ids in `mitre` (it was always empty on the rule
  path) and the version in a new `mitre_version` field
  (`"20.0"`). Records written before keep their bytes and still verify:
  the field is absent on them and on ADE records. The ids are pinned in
  `docs/detection/attack-enterprise-20.0.tsv`, extracted from MITRE's STIX
  bundle by commit and sha256 with the ATT&CK Terms of Use
  (`LICENSES/MITRE_ATTACK_ToU-20.0.md`, `NOTICES.md`); a test fails on a
  rule without a mapping, an id not in the list, an id revoked or
  deprecated in 20.0 (the T1562 family and T1070.002, which the pinned 20.0
  data replace with T1685, its sub-techniques and T1686) or a technique filed under a
  tactic it does not have. Ids the code named in prose and v20 revoked or contradicts were
  replaced in the mapping: NN-L-NET-021 (T1562.006 → T1685), NN-L-FIM-024
  (T1562.001 → T1685), NN-L-FIM-018/019 (T1070 → T1685.006), NN-L-FIM-021
  (T1543/T1556 → T1556.003), NN-L-IOU-001/002 (T1562 → T1106), NN-L-BPF-001
  (T1562 dropped, T1014 kept), R016 (T1622 → T1055.008); the revoked or
  wrong ids are gone from the reasoning text of NET-021, IOU-001/002,
  BPF-001 and R016 (FIM-024's stays: a test pins it). `cargo xtask
  attack-coverage` renders
  `docs/detection/ATTACK_COVERAGE.md` (technique → rules → sensor and
  ATT&CK data components → validation status, the V2 rows), an ATT&CK
  Navigator layer (`attack-navigator-layer.json`, layer format 4.5) and
  `docs/detection/RULE_CATALOGUE.md` (each rule's severities, responses,
  ATT&CK, what it observes, known false positives, how to test); a test
  holds the committed files to the generated ones. The anti-tamper
  honeypot guide names T1685.
- Exploit post-condition guard (lab PR 219, experimental; capabilities C12,
  C14). Whatever bug a local kernel exploit uses, it ends with a task that
  holds what it did not hold: root, capabilities, another user namespace,
  other namespaces or another root. The kernel makes those changes
  legitimately only through `commit_creds`, `switch_task_namespaces` and
  `set_fs_root`, on behalf of a few system calls; the guard flags a gain
  through no mechanism (a `struct cred` written in place) or through a
  mechanism on behalf of a call that never makes it (`commit_creds` from
  `ioctl`, `write`, `keyctl`, `bpf`, …), as NN-L-EPG-001 (credentials,
  T1068) or NN-L-EPG-002 (namespaces and root, T1611), Critical, signed,
  outside the engine, with the variant and the point that caught it. The
  allow-list is a table of mechanisms and system calls, never names; fully
  privileged tasks are not judged. Two variants (`--exploit-guard`,
  `NN_EXPLOIT_GUARD`): **lite**, the default, with no system-call hook —
  the mechanism hooks judge the call in progress (`pt_regs.orig_ax`), and a
  credential changed without a mechanism is caught at its first use (LSM
  `capable`, exec, `file_open` of a root-owned private file) against a
  per-task record in an LRU task map (keyed by `task_struct` address, the
  task's start time in the record against address reuse; deleted at exit;
  preallocated, so sized `min(pid_max, threads-max)` capped at 65536, or
  `--exploit-guard-tasks`). A record the map evicts is re-taken at the
  task's next hook, counted (in the status's untracked count, with the
  tasks a full map left untracked; a WARN at every rise and a signed
  `subsystem_degraded`, `exploit_guard_baseline_lost`, at most once per
  600 s; "task record(s) lost" in `nn-admin status --key`), and a
  re-taken credential that holds privilege is recorded as degraded
  evidence (NN-L-EPG-001 at High, never refused or killed): an eviction
  never makes an in-place write the new baseline in silence. The first
  build kept the record in BPF task storage, which the agent's aya 0.13
  cannot load: the agent refused to start on every kernel ("Unsupported
  map type found 29", lab, Debian 12); a unit test now fails on any map of
  the embedded object whose type aya 0.13.1's loader does not accept.
  **Strict**, opt-in, the comparison around every system call (`sys_enter`
  / `sys_exit`; its task map sized from `pid_max`, `--exploit-guard-tasks`,
  not preallocated, which needs 6.1: the agent checks the kernel version
  and below 6.1 strict is unavailable, a signed degradation); `off` is a
  weakening variable and a signed degradation.
  `--exploit-guard-response detect|enforce`: detect (default) records;
  enforce also sends SIGKILL from the hook, delivered before the task
  returns to user mode, and lite refuses the use (`-EPERM`)
  (`--detect-only` keeps detect). The posture trigger
  `ExploitPostcondition` is kernel evidence that needs corroboration while
  the guard is experimental. `nn-admin status --key` (the signed status)
  shows the variant, response and counters. The decision model is `common::epg`, the same code in the
  kernel programs and the unit tests; 17 new optional BTF offsets (slots
  78–94, later slots renumbered); a kernel missing one leaves the guard off
  and attested. Validation registry: `v2-rules.tsv` v3 (with lab PR 224's
  rows: 82 rows, sub-gate 28), `v2-techniques.tsv` v2 (TQ60 T1068),
  `v2-controls.tsv` v2. Lab:
  `deploy/lab/epg/` (negative suite, debug-build fault injection for both
  variants, microbenchmark modes `getppid` and `rdzero` in `nn-bench`).
  Design note: `docs/design/EXPLOIT_POSTCONDITION_GUARD.md`.
- The privileged suites run in GitHub Actions (Wave 4 Phase 2.1,
  capabilities C01, C29; lab PR 227). Until now CI only compiled them
  (`--no-run`) and they ran nowhere but the self-hosted lab.
  `.github/workflows/lab-vm.yml` boots one KVM guest per matrix entry on a
  GitHub-hosted `ubuntu-24.04` runner with `deploy/lab/nn-lab.sh` — the
  vendor's cloud image checked against its list, the guest's host key
  generated on the runner — syncs, builds and installs the tree under test
  in it and runs `test-ignored`: every privileged and `#[ignore]` suite, as
  root, single-threaded, as the lab's gate does. A pull request to `main`
  that touches a tree the suites are built or run from gets Ubuntu 24.04
  (6.8) and Ubuntu 22.04 (5.15); the nightly schedule and a manual dispatch
  run the lab's four guests (and Debian 12, 6.1; Debian 13, 6.12). On a
  pull request the job is informational (its own workflow, not a required
  check, `continue-on-error`); the nightly and a dispatch are the gate. A
  runner without a usable `/dev/kvm` boots nothing and reports "skipped: no
  KVM": a pass on a pull request, a failure on the nightly and a dispatch.
  No `pull_request_target`: a fork's pull request gets the read-only token
  and no secret.
  `NN_LAB_CI=1` is nn-lab.sh's CI mode: KVM only (whpx and tcg refused),
  every cargo build `--locked`, ssh in batch mode with keepalives, the tail
  of the guest's serial console when a boot fails; unset, the lab is
  unchanged, and `$CI` is never read. New sub-commands: `image-info` (the
  digest the vendor's signed list gives for its current image: the
  workflow's cache key) and `fetch-image` (the base image without a guest;
  one restored from the cache is checked against that list again and, in CI
  mode only, replaced when it is another image). `test-ignored` frames each
  of its five cargo runs with a start and an end line. `cargo xtask
  gate-summary` judges a run from its log: it passes only when every step
  succeeded, nothing failed to build, every cargo run finished, every
  failed test binary printed its summary (a crash or a kill does not) and
  every failed test is an expected one, and it writes `gate-summary.json`
  (suites, passed, failed, ignored, the expected failures, per kernel) and
  the job summary. `deploy/lab/expected-failures.tsv` lists the recorded
  follow-ups expected to fail on one guest — today Debian 13's DNS
  attribution under `nss-resolve` — counted in `failed`, shown with their
  outcome, and failing the run when they pass or do not run. `cargo xtask
  gate-report` turns a run's artefacts (`gh run download`) into a Markdown
  table to commit under `docs/validation/results/`; CI never pushes. A
  read-only token not left in `.git/config`, actions pinned by SHA, the
  credential check of external audit SUP-003 after the host build;
  `xtask/tests/lab_ci.rs` checks the workflow (path filters derived from the
  repository, the matrix, the pins and permissions, the policy above, the
  time bounds, KVM, the image cache, the evidence kept), the CI switches
  and the summary. `NN_LAB_IGNORED_SKIP` now logs what it leaves out, and
  the summary keeps that line as a note.
  `docs/integration-test-runbook.md`, "The CI VM gate", says how it relates
  to the self-hosted lab and what stays there.

### Changed
- The priority event bus replaces the one channel between the sensors and
  the event loop (lab PR 267, Wave 4 phase 2, R12a of the restructure plan;
  `docs/architecture/EVENT_BUS.md`). Every source — the nine ring pumps,
  the exploit guard's, the file-open sensor's, the FIM and network drains —
  sends into its class's queue: P0 tamper (`FsProtectDenial`,
  `BpfSyscall`, `ModuleLoad`, `SensorFlood`, `DefenderSignal`,
  `ExploitPostcondition`; 1,024, the sender waits 50 ms then drops), P1
  process (4,096, 10 ms), P2 file (8,192: a new `FileOpen` is dropped,
  every other file event waits as on the channel, review 75), P3 network
  (8,192, drop the new event); every `Event` variant placed by an
  exhaustive match. The event loop takes by strict priority with aging
  (one take by age after 64 that passed over a waiting lower queue), FIFO
  inside a queue: a flood of opens no longer holds the tamper records back,
  nor makes the kernel drop them (EXP-13). A tamper event taken ahead of
  queued execs hands them to the lineage and the rules first, so it is
  judged on the process tree of every exec that reached the bus before it.
  Per queue: events queued and dropped, depth and the most it held, the
  longest wait, the sends that waited, the takes by age, the latency from
  queue to decision (p50/p99/max), in `nn-admin status --key` with the loss
  counters of the eight stages of an event's path (1–3 the kernel ring, the
  kernel budget and the decoder, 4 the bus; 5–8 named, counted by R12b,
  R12c and R15). A drop is a WARN, a signed `event_bus_drop` row (P0 at the
  next 10 s sample, the other queues at most every 600 s, each row carrying
  every drop since the previous one, flushed at the stop) and, past 64 in a
  sample for P0–P2, the posture's `TelemetryLoss`, as a security ring's
  kernel drops. Ordering: a property test replays every golden case in
  every order that keeps each class's own order (all of them for 21 of the
  24 cases, 952 orders) and requires, for each rule and process, the same
  verdict and the same responses. It found two stores that depended on the
  order between classes, fixed: the lineage and the chains' ancestry tree
  learned an exec only when it was judged (an exec ingested twice, or after
  a newer one of its pid, now changes nothing), and the chain store let one
  chain keep another off a flow — each chain now answers a flow once, in
  any order, and a late exec's CHAIN-002 prefers the egress whose kill is
  not held at port 53. Golden: `shadow-chain007-late-exec` gains CHAIN-002
  on its late exec's line (the chain the flow has in kernel order; the
  responses are unchanged), and so do the two nn-admin matrix files that
  replay it; the matrix's full status shows the new lines. The unsigned
  status frame is one byte longer (the appended field's `None`). The
  DNS pump's outbox for a full channel (lab PR 229) is gone.
- Determinism seams: the signed chains' clock and the posture's switches
  per machine (lab PR 249, Wave 4 phase 2, before R08; no behaviour
  change). **Clock.** nn-evidence's writers read the time they stamp on a
  row through `nn_evidence::clock::Clock` — the host's, `SystemClock`
  (`Utc::now`, as before), unless given another: an audit row's `ts`
  (`AuditLog::open_with` with `AuditStamps`, which also carries the pid of
  the rows the writer signs about itself — `std::process::id()` by
  default; the ladder's and the trusted-installer window's rows read it
  with `AuditLog::self_pid`), a rotating log's terminators and manifest
  rows (`RotatingChainLog::open_with_clock`), the head anchor's snapshots
  (`Anchor::with_clock`), the time a refused COMBAT transition happened
  (`AuditEvidence::with_clock`); `open` and `new` keep the host's. The
  format is unchanged: given the times `main` wrote, the writers make the
  chain-pin fixtures of lab PR 241 again byte for byte, every file
  (`agent/tests/chain_format_clock.rs`; `chain_format_pin.rs` and the v1
  fixtures untouched). The posture golden replay opens its audit log with a
  fixed key, its own clock and the replayed agent's pid, and prints its
  signed rows whole — time, hashes, signature, pid — where it named them
  (`@TS@`, `#n`, `@SIG@`, `@AGENT_PID@`): the six golden files that hold
  signed rows changed in those fields only. **Switches.** The runtime value
  of `RANSOMWARE_COMBAT_WITHOUT_CORROBORATION` (`RANSOMWARE_DECISIVE`) and
  `KERNEL_MASS_WRITE` were process-wide: the posture reads the ransomware
  directive of the per-rule policy from the handle it is given
  (`PostureMachine::with_rule_policy`; the agent passes
  `rule_policy::global()`, the handle the engine reads and `nn-admin policy
  set` swaps; `TriggerType::confidence` takes the value), and the
  mass-write mode is the trigger detector's own
  (`PostureMachine::set_kernel_mass_write`, set by `main.rs` when the LSM
  file-open sensor is armed, as before);
  `posture_types::{ransomware_combat_without_corroboration,
  set_ransomware_combat_without_corroboration}` and
  `triggers::set_kernel_mass_write` are gone. NN-L-FIM-010's
  one-verdict-per-rename list is the rule's own (it was process-wide too:
  two engines in one process — parallel replays, tests — shared it). A new
  posture golden case, `ransomware-alone-combat-policy`, runs under
  `combat-without-corroboration NN-L-IMP-001` — ransomware alone to COMBAT,
  decisive and unlocked — beside the other cases.
- Wave 4 restructure, R00 — guardrails, no file moved (lab PR 239): a
  member reaches a repository file through `NN_REPO_ROOT`
  (`.cargo/config.toml` `[env]`, absolute) instead of a path relative to
  where the file sits (`include_str!("../../../configs/…")`,
  `CARGO_MANIFEST_DIR/..`; 37 files of the agent and the watchdog), so a
  module moved to another crate still builds; the repository tests read
  the workspace members from `cargo metadata` (the licence check, the Kani
  proof scan, the lab-vm path-filter scan, the journal-field scan of every
  member and the line guard wherever the daemon installs its subscriber);
  `xtask/tests/path_liveness.rs` fails on a workflow path filter that
  matches no tracked file, a `cargo kani` step whose package or harness is
  gone, a `-p`/feature of CI or the lab scripts that names nothing, a
  file the xtask tests name that does not exist, and a depth-relative path
  in a member; `docs/architecture/module-map.toml` maps every module of
  `agent/src` and `common/src` to its target crate, with the layers, and
  `xtask/tests/module_map.rs` keeps the layer violations from growing (77
  today: nn-core 53, nn-evidence 12, nn-admin 6, nn-linux 3, nn-proto 3);
  `[workspace.lints]` (the `cfg(kani)` declaration) shared by the members;
  `mk-tarball.sh` drops the unshipped SBOMs to depth 3. `lab-vm.yml` also
  starts on `fuzz/**` (the agent's seed test reads it; the old scan missed
  the `../fuzz` path). The eBPF object and the golden files are
  byte-identical to `main`'s, so are the watchdog and the scanner; the
  agent and nn-admin differ only in source line numbers (panic locations,
  log callsites) of the seven files whose embeds took more lines: same
  size, same `.text`.
- Wave 4 restructure, R01 — scaffolding (lab PR 239): the crates of the
  layered layout, empty, in `crates/`: nn-parse, nn-model, nn-proto,
  nn-evidence, nn-core (the pure ones), nn-linux and nn-admin — workspace
  fields and lints, `#![forbid(unsafe_code)]` but in nn-linux, members and
  `[workspace.dependencies]`; nothing depends on them yet. The layer gate
  `xtask/tests/workspace_layers.rs` holds the workspace to
  `docs/architecture/module-map.toml`: every dependency between members is
  one the layers allow (normal, build or dev), no cycle, the pure crates
  reach no OS interface (libc, nix, aya, procfs, tokio; `std::os`,
  `cfg(target_os)`), crate roots forbid `unsafe` where the map says, every
  member inherits the workspace lints. The new CI job `portable-core`
  checks the pure crates for aarch64 Linux, Windows and macOS (x86_64 and
  aarch64). The x86-64-v2 rustflags are the x86_64 Linux target's
  (`[target.x86_64-unknown-linux-gnu]`, a string so that
  `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS` still replaces them),
  no longer every target's: with `[build]`, an aarch64 build got
  `target-cpu=x86-64-v2` and a `neon` ABI warning. `lab-vm.yml` starts on
  `crates/**`. The shipped binaries, the eBPF object and the packages are
  the same as R00's.
- Wave 4 restructure, R03 — nn-proto (lab PR 240; before R02, so that
  nn-model, which depends on `common`, does not inherit its Unix-only
  `atomic_file`): `common`'s admin protocol (`wire::admin_protocol`),
  signed payloads (`wire::admin_signed_payload`), quorum (its Kani proof
  with it), shutdown marker and watchdog hold moved unchanged (`git mv`)
  to `crates/nn-proto`, with their dependencies and the `debug-trigger`
  feature, which the agent now forwards there (CI's wire-discriminant step
  and `kani.yml` run on `-p nn-proto`); `atomic_file` and `sd_notify` to
  `northnarrow-antitamper-bpf`, the Linux base of the agent and the
  watchdog. `common` cannot re-export them (they depend on it, and cargo
  refuses the cycle): the importers — the agent, the watchdog, the fuzz
  targets `admin_frame` and `shutdown_marker` — name the new crates, a
  path rewrite, and the moved files compile through `pub(crate)` shims at
  nn-proto's root (removed in R17). A new test pins five admin frames and
  a v1 envelope byte for byte as `main` encoded them (signed payloads and
  `PostureKind` inside); it passes before and after the move. The ratchet
  scan counts a reference to a crate of `crates/` by its name, so the
  nn-evidence → nn-proto arc of `verify_lines` and `canary::chain_lines`
  still counts: 77. The eBPF object is byte-identical to `main`'s; its
  stamp changes with `common`'s sources.
- Wave 4 restructure, R02 — nn-model and nn-parse (lab PR 240): `common`'s
  event model (`model.rs` → `crates/nn-model/src/event.rs`, its items at
  nn-model's root as they were at `common`'s), `posture_types`, `netaddr`
  and `log_escape` moved unchanged to nn-model; the std types of
  `common::wire` (`FimEvent`, `FileAttrChange`, `FileCapability`, `FimOp`,
  `FimOpDecodeError`, `TlsFingerprint`, `NetFlowEvent`, `FlowPhase`,
  `NetListenerEvent`) and their tests cut, as they were, into
  `nn_model::telemetry`; `dns_qname` and its Kani proofs to
  `crates/nn-parse` (`kani.yml`: `-p nn-parse`). nn-proto's one dependency
  in the repository is now nn-model. `common` is the kernel↔userland ABI
  (raw layouts and their name tables, BTF offsets, uapi constants, drop
  and fail-open slots, the exploit guard's model) and the exec
  quarantine's scanner protocol; it no longer depends on `serde_json`, and
  the watchdog and the fuzz crate no longer depend on it. The importers
  name nn-model and nn-parse (a path rewrite, `use` groups split by
  crate); `journal_fields`' source scan looks for
  `nn_model::log_escape::Escaped`. nn-model and nn-proto now hold code,
  and `portable-core` checks them for aarch64 Linux, Windows and macOS
  (they pass: `common` has no Unix-only module left). The ratchet stays at
  77: no reference it counts was to or from a moved module but the two
  nn-evidence → `admin_protocol` ones, which remain. Identity of the two
  steps against `main` 2e1438f (same path, the release job's flags): the
  eBPF object is byte-identical, its stamp's source hash moves with
  `common`'s sources; the tarball's 72 entries and the .deb's 79 paths and
  modes are the same; the golden replay and its files are unchanged, and
  the test list is `main`'s plus the frame pin. The binaries are not
  byte-identical, and cannot be after a move between crates: a crate's
  identity seeds symbol names and `TypeId`s, and the fat-LTO module is
  composed anew — `main` rebuilt with one unused optional dependency added
  to `common` already changes the scanner's layout and 2, 16 and 17
  functions of the watchdog, nn-admin and the agent. Function by function
  (names mapped, addresses dropped) 503 of 504, 2,429 of 2,468, 3,210 of
  3,330 and 7,217 of 7,408 are the same code, the rest LLVM's choices
  (inlining, constant propagation, which of identical bodies is kept,
  registers, `TypeId` constants); the text of `.rodata` differs only in
  the moved files' paths (panic locations), log-callsite line numbers and
  the stamp hash. nn-admin's `--events` help still says `common::Event`,
  so that no output changes.
- Wave 4 restructure, R06 — nn-parse (lab PR 242): the agent's TLS
  ClientHello parser (`net/tls_parser.rs` → `crates/nn-parse/src/tls.rs`,
  `git mv`, with its tests, the `crypto_vectors` JA3 pin and its Kani
  proof) and `net/dns_cache`'s reply parser (`parse_a_records`,
  `parse_aaaa_records` and the bounded walk, cut verbatim with their tests
  into `crates/nn-parse/src/dns_records.rs`) moved to nn-parse, which now
  holds every parser of the plan's §2.4 and takes md-5, sha2 and hex at
  the agent's versions and features. The cache and its state stay in the
  agent. Two lines of the parser changed: `x % 2 != 0` became
  `!x.is_multiple_of(2)` (the same for the divisor 2), which the
  workspace's clippy asks of nn-parse (the agent's SUP-015 exception kept
  the lint off there). The agent re-exports both at their old paths
  (`net::tls_parser`, `net::dns_cache::{parse_a_records,
  parse_aaaa_records}`), so the fuzz targets and seeds are unchanged (the
  shims go in R17). Pins added first, on `main`: the `tls_client_hello`
  seeds parse to the same fields, SNI, ALPN, JA3 input, JA3 MD5 and JA4;
  the `dns_records` seeds and regression to the same answers; a hostile
  corpus of each (every prefix and xorshift mutants: 6,559 ClientHello and
  4,354 DNS inputs) to the same outcome counts and the same SHA-256 over
  every rendering. They moved with the code and pass there unchanged.
  `kani.yml` proves the TLS cursor on `-p nn-parse` (path filter
  `crates/nn-parse/src/tls.rs`), without the agent's
  `--ignore-global-asm`. The ratchet stays at 77: the moved code named no
  module of the agent. Identity against `main` c7bb346 (same path, the
  release job's flags): the eBPF object and its stamp are byte-identical
  (`common` is untouched), so is the scanner; the tarball's 72 entries and
  the .deb's 79 paths and modes are the same; the golden replay, the 19
  `crypto_vectors` tests and the test list (3,006, the 48 moved tests
  found by name) are unchanged. No shipped binary links the moved parsers
  (nothing feeds them yet: `TLS_FINGERPRINT_PRODUCER` is false, the DNS
  parser has no observer). The others differ as nn-parse's new
  dependencies make them: `main` rebuilt with md-5, sha2 and hex added to
  nn-parse, no source changed, gives a watchdog byte-identical to this
  lot's (2 of 2,469 functions differ from `main`'s, both `TypeId`
  constants) and changes 11 functions of nn-admin and 24 of the agent the
  same way (`TypeId`s, which of identical bodies keeps its name); the move
  itself changes 2 more of nn-admin and 3 of the agent and keeps
  `RawVec<&[u8]>::grow_one` out of line: the growth of `Vec<&[u8]>`, which
  the parser's `alpn_values` shared with `RollbackFloor::scan` before.
  `.rodata` holds the same text.
- Wave 4 restructure, R04a/R04b — the evidence chain's ties to the agent
  cut, no file moved (lab PR 241): a test pins the signed chains' format
  first (`agent/tests/chain_format_pin.rs`: fixtures written by `main`
  c7bb346's code — audit rows, a rotating log with archives and manifest,
  a head anchor — verify in full, and this code writes `main`'s bytes for
  the same inputs). Then: the identity types the audit chain attests
  (`AgentIdentity`, `IdentitySource`) and the `integrity_drift` op are
  `audit`'s; the boot rows take the build facts by value (`AgentBuild`:
  version, features, BPF guard mode, from the new `build_info`, which
  holds `build_features` and `LAB_FEATURES`); the agent's signing key and
  its files leave for the new `keys` (plan: "AgentSigningKey si separa dal
  formato"), the writers sign through `chain_host::ChainSigner`; the
  agent's own list of chains (`ChainPaths`, the canary chains' checks,
  the anchoring and boot-verify tasks) leaves `chain_anchor` for the new
  `chains`; the build-time assertions holding the readers' line caps to
  the admin frame size (`MAX_FRAME_BODY`) go to `admin_socket`, which
  sees both crates (the two nn-evidence → nn-proto arcs); the chains'
  Linux file operations (`O_NOFOLLOW | O_NONBLOCK` opens, file and
  directory modes, `renameat2(RENAME_NOREPLACE)`, `pwrite`, the
  directory anchor) go behind `chain_host::ChainHost`, implemented by
  `chain_host_linux::LinuxHost` with the same calls, reached through the
  writers' key type and named by the readers (`boot_check::<H>`); the
  audit log's boot preflight (`access(2)`) leaves `audit` for
  `audit_preflight`; the chain tests run on a portable host, what is
  Linux about the chains is tested on the agent's; the detection log's
  records leave `detection_store` for `detection_payload` (mapped to
  nn-evidence); the core modules name the integrity op through `audit`;
  the open sensor's path text (cut and unread marks, an exact path, an
  unplaced path's device, mountinfo's escapes) leaves `sensors` for
  `path_text` (R04b).
- Wave 4 restructure, R05 — nn-evidence (lab PR 241): the agent's
  `chainlog`, `audit`, `chain_anchor`, `chain_tail`, `verify_lines`,
  `chain_host` and `canary::chain_lines` moved to `crates/nn-evidence`
  (`git mv`, 99-100 %), which is pure: no libc, no `std::os`,
  `#![forbid(unsafe_code)]`, checked by `portable-core` on the five
  targets. The agent keeps every path as a shim without a file (`lib.rs`,
  `canary/mod.rs`; removed in R17), the writers aliased with the agent's
  key as default, so callers, tests, fuzz targets and examples are
  unchanged; the ratchet learns shims (`[shims.agent]`). `anchored`
  stays in the agent (nn-linux): it is the Linux host's anchor. Also:
  `common::execq` (the exec quarantine's scanner protocol, lab PR 240's
  open item) moved to `nn_proto::execq` (the importers rewritten, the
  scanner depends on nn-proto, `common` drops postcard and hex), and
  `nn-admin policy test --events` names `nn_model::Event`. The ratchet
  goes from 77 to 54: nn-evidence 12 → 0, nn-core 53 → 40, nn-admin
  6 → 8 (its `chain verify` builds the agent's chain list, which names
  payloads of nn-linux modules), nn-linux 3, nn-proto 3. Identity
  against `main` c7bb346: the eBPF object is byte-identical (sha256
  2cfdde83…), its stamp's source hash moves with `common`; the golden
  replay, the wire pins (`encoded_frames_are_pinned`), the crypto vectors
  and the chain format pin are unchanged; the tarball's 72 entries and
  the .deb's 79 paths and modes are the same. The binaries are not
  byte-identical (a crate's identity seeds symbols and `TypeId`s, and
  rustc instantiates a generic function in each crate that uses it in a
  release build): function by function, names mapped and addresses
  dropped, the scanner is 478 of 479 the same (the `execq` decoder of
  its hash list), the watchdog 2,242 of 2,244 (two `TypeId` users),
  nn-admin 2,980 of 3,131, the agent 6,639 of 6,893; the rest is inlining
  at the new crate boundary, register allocation, `TypeId` constants and
  generic code made twice (the agent's `.text` +2.5 %, nn-admin's +2.5 %:
  serde_json's deserializers of the audit row, chrono's formatting,
  base64 — one copy per crate). Logging: the moved modules' events carry
  `nn_evidence::…` as their target, which the journal line does not show
  (`with_target(false)`); a `RUST_LOG` filter naming the agent's module
  paths no longer selects them.
- Wave 4 restructure, R07 — nn-core, part 1: the content lists (lab PR
  247): the generic `.v1` + `.local` list loader (`config/overlay.rs`), the
  FIM watched paths (`fim/paths_config.rs`), the credential canary renderer
  (`canary/templates.rs`) and the COMBAT management carve-out
  (`anti_tamper/combat_allow.rs`) moved to `crates/nn-core` (`git mv`,
  94–99 %), with the part of `config::overlay_auth` the loaders take
  (`Verified`, `content_sha256`, `read_overlay`, `ALLOW_UNSIGNED_ENV`,
  `MAX_OVERLAY_BYTES`, cut verbatim); nn-core keeps the agent's module paths
  (`nn_core::config::overlay`, …). nn-core stays pure: the open the content
  code made itself (`O_NOFOLLOW | O_NONBLOCK`, an `ELOOP` refused as a
  symbolic link — an overlay, a shipped `.v1`, an operator template) is the
  new `content_host::ContentHost`'s, implemented for the agent's
  `LinuxHost` by `content_host_linux` with the same flags, and the deploy's
  seed is still drawn from the OS RNG in the agent (`new_content_seed`).
  The agent keeps every path as a shim in the parent's `mod.rs` (removed in
  R17), the loaders that read a file bound there to `LinuxHost` under their
  names and signatures, so callers, tests, `fuzz_api` and the fuzz targets
  are unchanged. On the way: `overlay_auth`'s install half (`store`,
  `inode_key`: the atomic replace and inode protection of `config overlay
  set`) to `config::overlay_install`; the overlay check names the exec
  profile in `execpol::policy`; `net status`'s inactive-rules report from
  the blocklist to `net::blind_spots` (it reads the resolver's
  configuration). The ratchet goes from 54 to 52 (nn-core 40 → 38). Not
  moved, and why: the comm allowlists and the canary readers judge on
  `posture::lineage` (the allowlist also holds a kill through
  `decision::response_policy`), `escalation_allow` and `mass_write_overlay`
  are in `posture/`, the blocklist's loaders are called by the decision
  replay without a host (R08); the overlay gate verifies through
  `anti_tamper::admin_auth` and the rollback floor reads the agent's key,
  which are not below nn-core yet (§4.1 rule 3). Identity against `main`
  9de1923, same path, the release job's flags: the eBPF object (a clean
  rebuild of `main`'s) and its stamp are byte-identical (sha256 42afd5b6…
  at that path; stamp source c0365736…); the scanner and the watchdog are
  byte-identical, stripped and not; the tarball's 72 entries and the .deb's
  79 paths and modes are the same; the golden replays, the wire and chain
  format pins, the crypto vectors, the parser pins and the overlay-v1
  fixture pass unchanged; the test list is `main`'s (3,043 names; 44 now in
  nn-core, 9 moved within the agent). The agent (14,863,200 → 14,876,736
  bytes) and nn-admin (4,022,024 → 4,029,320) are not byte-identical, and
  cannot be after a move between crates: function by function, names mapped
  and addresses dropped, 7,555 of the agent's 7,614 functions and 3,441 of
  nn-admin's 3,463 are the same code; a control (`main` with the agent
  depending on nn-core and nn-core on its new crates, no source moved)
  already changes 14 and 6 of them (clap's `TypeId`s of the agent's enums,
  which of identical bodies keeps its name); the moves add generic code
  made a second time in nn-core (anyhow's message errors, `RawVec` growth,
  hex, base64: `.text` +0.14 %), inlining and register choices at the new
  crate boundary, and calls to folded bodies under another name. `.rodata`
  holds the same text but the moved files' paths and the callsite line
  numbers of the moved and edited files; the moved modules' tracing target
  is `nn_core::…` (not printed: `with_target(false)`).
- Wave 4 restructure, R08a — nn-core, part 2a: the posture, its lineage,
  the correlation buffer and the detection budget (lab PR 250). Moved to
  `crates/nn-core` (`git mv`, 84–100 %): the posture's state machine, its
  triggers, the COMBAT entry and the clock, the corroboration ledger, the
  state and the transitions, the lineage tracker, the stack exemption, the
  two operator overlays (`escalation_allow`, `mass_write_overlay`), the
  canary readers (they judge on the lineage), the correlation buffer and
  the detection budget; the open sensor's path text (`path_text`) to
  `crates/nn-model` first, as the posture reads it. nn-core stays pure:
  what the posture read from its host itself — the process table (`exe`,
  `status`, `stat`, `cgroup`, `loginuid`, `cmdline`, `mountinfo`,
  `ns/mnt`), the host's `/etc/subuid` and `/etc/passwd`, a directory's
  owner, the time suspended (`CLOCK_BOOTTIME` − `CLOCK_MONOTONIC`, read by
  `for_host`'s live checks), `CLOCK_MONOTONIC` and the clock tick — is the
  new `posture::host::PostureHost`'s, and what it consults in the agent's
  other modules — the rule engine's shapes the triggers share with the
  rules (NN-L-FIM-024's bait tamper, NN-L-EPG-001/002, R020's reverse
  shell, the staging directories), the per-rule policy, the
  trusted-installer window, the ransomware and security-tool judges, the
  unlock token — is `posture::host::PostureAgent`'s; both are implemented
  for the agent's `LinuxHost` by `posture_host_linux` with the calls the
  posture made, and the posture's types take the host as a type
  parameter. The budget's reporter task (tokio, the agent's audit log and
  detection sink) stays in the agent (`detection_report`). The agent keeps
  every path as a shim (removed in R17): `lib.rs`, `canary/mod.rs` and a
  new `posture.rs`, with the machine, the detector, the tracker and the
  exemption as aliases on `LinuxHost`; callers, `main.rs`, the admin
  socket, the ladder, the rules, the tests, the replays, the examples and
  the fuzz targets are unchanged. 252 tests moved with their code and run
  on a portable test host; the cross-module tests and the golden replay
  stay in the agent and read nn-core's test helpers through a
  dev-dependency feature (`test-util`; the legacy boolean release stays
  `cfg(test)`). The ratchet goes from 52 to 50 (nn-core 38 → 36). Not
  moved: the comm allowlists (`Judgement::apply`, which the rules call,
  holds a kill through the engine's response policy: R08b), the
  blocklists and the decision replay (R08b), the overlay gate and the
  rollback floor (after R04b and R09a). Identity against `main` 9e33fad,
  same path, the release job's flags: the eBPF object and its stamp are
  byte-identical (sha256 a4f7006f… at that path; stamp source
  c0365736…); the scanner is byte-identical; the watchdog (2,336,920 →
  2,337,080 bytes) has every one of `main`'s 2,469 functions the same
  code and one more copy of a `RawVec` growth body `main` has twice, which
  `path_text`'s move into nn-model alone gives (that commit builds the
  same watchdog byte for byte); the tarball's 72 entries and the .deb's 79
  paths and modes are the same; the golden replays (five runs), the wire
  and chain format pins, the crypto vectors, the parser pins and the
  overlay-v1 fixture pass unchanged; the test list is `main`'s (3,078
  names: 252 now in nn-core, R020's trigger test in the agent's
  `posture::tests`) and three tests of the Linux host. The agent
  (14,901,048 → 14,940,328 bytes) and nn-admin (4,029,280 → 4,029,840)
  are not byte-identical: function by function, names mapped and
  addresses dropped, 7,536 of the agent's 7,653 functions and 3,440 of
  nn-admin's 3,478 are the same code; a control (`main` with nn-core's new
  dependencies, no source moved) already changes 21 and 6 (clap's
  `TypeId`s, which of identical bodies keeps its name); the move adds
  inlining and register choices at the new crate boundary, the machine's
  `observe` kept out of `process_event` (+28,039 / −24,512 bytes), and
  the lineage's methods made in both the agent's library and its binary
  once generic (`.text` +35,376 bytes, +0.49 %). `.rodata` holds the same
  text but the moved files' paths, the callsite line numbers and the
  reporter's path; the moved modules' tracing target is `nn_core::…` (not
  printed: `with_target(false)`).
- Wave 4 restructure, R08b — nn-core, part 2b: the decision engine (lab
  PR 251). Moved to `crates/nn-core` (`git mv`, 65–100 %, most over
  85 %): the decision engine — the rules, the multi-match combination and
  its legacy ceiling, the signed per-rule policy and the response switches
  (lab PR 236), the offline replay that the golden replay and `nn-admin
  policy test` share, the rule catalogue's table, the ATT&CK mapping, the
  flow ledger, the chain rules' correlation store and ancestry tree — with
  the state its rules read: the comm allowlists, the FIM rules, the
  operator's blocklists, the DNS cache's state, the flow tracker, the
  netflow limiter, the host's resolvers, the ransomware tracker, the
  security-tool detector, the drift's classification and the canary
  detector (with the network canaries' addresses); the parts of a
  detection record the engine names (`Sensor`, `MitreAttack`,
  `Principal`) to `crates/nn-evidence`, the bait table and the
  trusted-installer window's vocabulary to nn-core first. nn-core stays
  pure: what the engine did on its host itself — `rpm -qf` through
  `trusted_bin` and the dpkg lists inside tokio's `block_in_place`, the
  host's view of a path (`/proc/1/root`), `/proc` for the ancestry tree
  and the per-rule policy's exemption facts, the files' samples, the
  trusted-installer window, the kernel's `DEFENDER_PIDS`, tokio's `Notify`
  of the DNS pump and of the flow tracker, the canary registry and access
  log (signed chains), `getifaddrs`, `stat(2)` — is the new
  `decision::host::DecisionHost`'s and `canary::host::CanaryHost`'s,
  implemented for the agent's `LinuxHost` by `decision_host_linux` and
  `canary_host_linux` with the calls the code made; the exemption facts
  (`ProcFacts`), the files' sampler (`FsSampler`), the pump's ingest
  (`net::dns_ingest`) and `stat_inode_key` stay with that host, behind the
  engine's traits. The posture reads the engine's shapes and per-rule
  policy itself (`PostureAgent` drops them). The agent keeps every path
  as a shim (removed in R17): `decision.rs`, `impact.rs`, `impair.rs` and
  inline modules for the comm allowlist, the limiter, the DNS cache, the
  flow tracker and the canary detector, with the engine, the stores, the
  trackers and the detectors as aliases on `LinuxHost`; callers are
  unchanged but for three list loaders in `main.rs` and the posture's
  golden replay, which name the host. 699 tests moved with their code and
  run on the portable test host; the tests that wire the agent's other
  modules stay in the agent (`decision/host_tests.rs`,
  `impact/host_tests.rs`, `impair/host_tests.rs`,
  `canary/detector_tests.rs`), with the golden replay, the validation
  registry and the catalogue's renderer; the rule catalogue and the
  validation matrix cite the moved tests at their new paths
  (`ATTACK_COVERAGE.md` and the Navigator layer unchanged). The ratchet
  goes from 50 to 33 (nn-core 36 → 19). Left for R08c: the COMBAT
  ladder's policy and traits, the response types and the executor's
  policy, the contract and bus skeletons. Identity against `main`
  55f0e97, same path, the release job's flags: the eBPF object and its
  stamp are byte-identical (sha256 7b9fa6d2… at that path; stamp source
  c0365736…); the scanner and the watchdog are byte-identical, stripped
  and unstripped; the tarball's 72 entries and the .deb's 79 paths and
  modes are the same; `posture_demo` prints the same lines; `nn-admin
  policy test` on the golden cases under four policies, with the shipped
  lists and without, as a table and as JSON, gives the same 402 outputs;
  the golden replays (five runs), the wire and chain format pins, the
  crypto vectors, the parser pins, the overlay-v1 fixture and the
  per-rule policy's format pass unchanged; the test list is `main`'s
  (3,081 names, 699 now in nn-core). The agent (14,939,576 → 15,035,960
  bytes) and nn-admin (4,029,840 → 4,086,576) are not byte-identical:
  function by function, names mapped and addresses dropped, 7,500 of the
  agent's 7,684 functions and 3,364 of nn-admin's 3,483 are the same
  code; a control (`main` with nn-core's new dependencies, no source
  moved) already changes 12 and 7 (clap's `TypeId`s, which of identical
  bodies keeps its name); the move adds inlining and register choices at
  the new crate boundary, the seams' functions, and the engine's code
  made and inlined in the agent's crates now that it is generic over the
  host (`.text` +83,104 bytes, +1.14 %; nn-admin +44,224, +1.36 %).
  `.rodata` holds the same text but the moved and new files' paths, the
  callsite names of the moved and edited files, the catalogue's cited
  test paths (compiled in, never printed) and literals grouped otherwise;
  the moved modules' tracing target is `nn_core::…` (not printed:
  `with_target(false)`).
- Wave 4 restructure, R08c — nn-core, part 2c: the COMBAT ladder and the
  executor's policy (lab PR 252). Moved to `crates/nn-core` (`git mv`,
  90–98 %): the COMBAT ladder — its three stages and their state machine,
  the jump-ahead, the attribution and its cap, the isolation gate, the
  worker and its queue, the stand-down — with its signed evidence
  (`AuditEvidence`, now over an audit log of any key), the offenders'
  identity (lab PR 245) and its tests; the executor's configuration and
  policy (`response::config`: the detect-only gate and the variables that
  switch it on, the quarantine's cap, the cgroup and nftables names). Cut
  to nn-core from the agent's files, verbatim: the traits of what the
  ladder drives and the outcomes they report (`CombatActuator`,
  `SoftBlock`, `NeutralizeReport`, `IsolateOutcome`; `ProtectedProcs`,
  `ProtectedReason`, `NoProtectedProcs`), the record of a stale COMBAT
  chain found at start (`StaleChain`, its signed entry, `attest`), and
  first the isolation's read-back vocabulary (`Family`, `FamilyOutcome`,
  `IsolationReport`). nn-core stays pure: the ladder held the agent's
  capture of a process (a pidfd and its start, `ProcRef`), now its host's
  (`combat::host::CombatHost` and `Capture`, implemented for `LinuxHost`
  by `combat_host_linux` with `ProcRef`'s own calls). What is Linux stays
  in the agent for nn-linux (R09): the production actuator
  (`SystemActuator`: the executor's kill, quarantine and per-PID egress
  block, the isolator, `/proc`), the production host-critical guard
  (`SystemProtectedProcs`: the live `/proc`), the stale chain's unsigned
  compatibility line, the executor and its actions. The posture names the
  engine's ransomware and security-tool judges itself (its machine and
  triggers take `DecisionHost`); `PostureAgent` keeps the
  trusted-installer window and the unlock token (R04b). The skeletons the
  priority bus (R12) and the signed sensor contract (R13) are built on,
  types only: `nn_model::{EventClass, ProcessKey}`, `nn_core::bus`
  (priorities, the envelope, the loss stages and counters) and
  `nn_core::contract` (a class's contract, its synchronous verdict and
  failure mode, truncations, a source's state). The agent keeps every
  path as a shim (removed in R17): a new `combat.rs`, with the ladder and
  its neutralize hook as aliases on `LinuxHost`, the evidence on the
  agent's key and `ProcRef` as the host's capture, and `response/mod.rs`;
  callers are unchanged but for the actuators of the posture's golden
  replay and of the ladder's host tests, which implement the trait on
  `LinuxHost`. 39 tests moved with their code and run on the portable test
  host (nn-core 995 → 1,034); the 11 that wire the agent's key, audit log,
  posture, actuator or a real process stay in the agent
  (`combat/host_tests.rs`, `combat/evidence_tests.rs`), and the Linux
  host's capture has a test of its own. The ratchet goes from 33 to 29
  (nn-core 19 → 15). Identity against `main` 3a1ee3e, same path, the
  release job's flags: the eBPF object and its stamp are byte-identical
  (sha256 5eab9218… at that path; stamp source c0365736…); the scanner and
  the watchdog are byte-identical, stripped and unstripped (nn-model's new
  types change nothing in it); the tarball's 72 entries and the .deb's 79
  paths and modes are the same; `posture_demo` prints the same lines;
  `nn-admin policy test` gives the same 402 outputs; the golden replays
  (five runs), the wire and chain format pins, the crypto vectors, the
  parser pins, the overlay-v1 fixture and the per-rule policy's format
  pass unchanged; the test list is `main`'s (3,081 names, 11 at a new path
  in the agent) and the capture's test. nn-admin keeps its size (4,086,576
  bytes) and is not byte-identical: function by function, names mapped and
  addresses dropped, 3,526 of its 3,527 functions are the same code
  (NN-L-EVA's `evaluate` no longer inlines the security-tool assessment)
  and its `.rodata` holds the same text. The agent (15,036,712 → 14,998,040 bytes)
  has 7,673 of its 7,744 functions the same code; no manifest changed, so
  the rest is the code's: the assessment kept out of line, called by the
  rule and the posture's triggers (`.text` −37,920 bytes, −0.52 %: the
  rule −15,172, the posture's `observe` −12,468 without the ransomware
  judge inlined), inlining and register choices where the moved code is
  instantiated now, and std's channel code of the ladder's queue and of
  the copy-on-write guard inlined otherwise. `.rodata` holds the same text
  but the callsite names of the moved and edited files, the stale chain
  record's path and tracing target, and literals grouped otherwise.
- Wave 4 restructure, R09a — nn-linux, part 1: the actuators, the
  self-defence, the agent's key and its Linux host (lab PR 253). Moved to
  `crates/nn-linux` (`git mv`, 98–100 %): the executor and its actions
  (`response`: kill, quarantine and its vault, the per-PID egress block,
  the throttle, the containment and its release, the capability
  preflight, `ProcRef`), the COMBAT ladder's production actuator, guard
  and stale chain's compatibility line (`combat::{actuator, protected,
  reconcile}`), the self-defence (`anti_tamper`: the LSM deny hooks and
  their kernel maps, the BPF guard, the BTF revalidation, the fail-open
  counters, the network isolator, the trusted-installer window, the
  admin key set with its challenge and its `UnlockToken`), the agent's
  signing key (`keys`), and the utilities they stand on (`agent_id`,
  `anchored`, `async_fd`, `atomic_file`, `bounded_cmd`, `fs_type`,
  `os_rng`, `runtime`, `trusted_bin`). The key's chains are written on
  the agent's `LinuxHost`, so the host moved with it, and the
  implementations of nn-core's and nn-evidence's host traits on it with
  the host (a trait of another crate on a type of another crate is
  implemented in neither): the chains', the content lists', the
  posture's, the decision engine's, the canary detector's and the
  ladder's, with what they name — the canary registry, its access log,
  this host's addresses and the read-forward set (R09b's "store dei
  canary" by the plan), the sampler of the host's files, the DNS pump's
  ingest with the cache carrying it, the security tools' kernel map
  (`impair::DefenderMap`, cut). `admin_auth` moved whole with
  `anti_tamper`: its token's mint is `pub(in crate::anti_tamper)` beside
  the isolator it unlocks, and stays that narrow; its role keywords went
  to nn-proto's `admin_quorum` first, its verification is R04b's still.
  Cut to nn-linux first: `self_integrity`'s op and jitter,
  `fim::attach`'s device number and inode key; the four items the
  moved code names of R09b's and R09c's modules. Seam: the network
  isolator holds the agent's signed-overlay gate through nn-core's
  `config::overlay_auth::Vouch` (the gate and the rollback floor stay in
  the agent: the plan sends them to nn-core with the content, after
  R04b). The tests that read the agent's own parts were cut into it
  first (`agent_id`'s scan of `main.rs`, the content host's three, the
  isolator's two with the gate). The agent keeps every path as a shim
  (removed in R17); callers, tests, replays, examples and the fuzz
  targets are unchanged. nn-linux forwards `debug-trigger` (the BPF
  guard observes in such a build, as before) and keeps its tests' doors
  behind `test-util`, a dev-dependency feature (no build of the binaries
  has it). `btf-matrix.yml`'s path filter, xtask's `lab_scripts.rs` and
  `path_liveness.rs` follow `anti_tamper`. The ratchet goes from 29 to
  26 (nn-proto 3 → 0: `admin_auth.rs` left the scanned tree with
  `anti_tamper`; its three references are nn-linux's own now, not cut).
  Identity against `main` 0e89772, same path,
  the release job's flags: the eBPF object is byte-identical (sha256
  a568d328… at that path), its stamp's source hash c0365736… →
  235e2fed… (a test and a comment of `common`: `bpf_cmd`'s scan for a
  second copy of a BPF command number reads `crates/` too, as the BPF
  rules and the self-defence's wrappers left the directories it listed;
  the agent embeds that hash); the scanner and the watchdog are byte-identical,
  stripped and unstripped; the tarball's 72 entries and the .deb's 79
  paths and modes are the same, the agent's SBOM lists nn-linux;
  `posture_demo` prints the same lines; `nn-admin policy test` on lab PR
  251's samples gives the same 402 outputs; the golden replays (five
  runs), the wire, chain and crypto pins, the parser pins, the overlay-v1
  fixture and the per-rule policy's format pass unchanged; the test list
  is `main`'s (3,082 names, 438 now nn-linux's, 6 at a new path in the
  agent). The agent (14,998,040 → 15,192,208 bytes) and nn-admin
  (4,086,576 → 4,129,480) are not byte-identical: function by function,
  names mapped and addresses dropped, 7,550 of the agent's 7,739
  functions and 3,476 of nn-admin's 3,527 are the same code; a control
  (`main` with nn-linux's dependencies, no source moved) already changes
  19 and 6 (clap's `TypeId`s, which of identical bodies keeps its name);
  from the control, the move adds a second copy of generic code
  instantiated in nn-linux as in the agent (the extra copies of an
  instantiation go from 736 to 953 in the agent, 360 to 434 in nn-admin:
  serde_json's deserializers and float parsers, anyhow's errors,
  tracing's field values, aya's error formatting, the audit log's
  `append` on the agent's key), inlining decisions at the new crate
  boundary (the canary stores' chain readers kept out of line, the row
  parsers inlined into them) and the gate's call through `Vouch`'s
  vtable: `.text` +157,632 bytes in the agent (+2.15 %), +31,808 in
  nn-admin (+0.97 %). `.rodata` holds the same text but the moved files'
  paths and the callsite names of the moved and edited files, the gate's
  `Debug` strings (its vtable keeps them), a panic of serde_json's map
  serializer no longer reachable where it is inlined, and literals
  grouped otherwise.
- Wave 4 restructure, R09b — nn-linux, part 2: the sensors, the eBPF
  object's embed, file integrity monitoring and the network drain (lab
  PR 254). Moved to `crates/nn-linux` (`git mv`, 96–100 %): the sensors
  (`sensors/*`: the embedded object and its boot preflight, the single
  loader that attaches every program and pumps every ring, the exec,
  file-open, DNS, connect-deny and exploit-guard sensors, the ring drops
  and the rejected records), the build script that embeds the object
  and refuses a stale one (`build.rs`, 97 %: it finds the repository
  through `NN_REPO_ROOT` now, ebpf-guard is nn-linux's build-dependency),
  file integrity monitoring whole (`fim/*`: the observers' attach, the
  drain and its drift log, the baseline, the honeypot baits, the
  recompute, the watched paths' loader; `attach.rs` onto R09a's cut of
  it), the network drain and the blind spots it reports
  (`net::{drain, blind_spots}`), and the decoys' path policy
  (`canary::path_policy`). The DNS record's decode left nn-model for the
  DNS sensor (`sensors::dns_sensor::{query_event, nss_query_name}`, the
  `From<&DnsQueryRaw> for Event` and its tests verbatim): it was
  nn-model's one use of nn-parse, which nn-model no longer depends on
  (the watchdog and the scanner, which reached nn-parse and md-5 through
  nn-model only, drop both from their dependency trees and SBOMs). The
  other decodes stay in nn-model: they need only nn-wire and the model,
  whose vocabulary maps ABI bytes nn-core's rules read, and moving them
  would rewrite every pump for no arc removed. Cut to nn-linux first,
  what the sensors name of the agent's `boot`: the typed phases and the
  attach permit (the permit's field is private to its module, so the
  sequence that alone gives it went too), the degradations' registry
  (`boot/degradation.rs`, moved whole) and the sensors' attach points
  the capability manifest lists; and `telemetry_probe::PROBE_DIR`. One
  seam: the loader writes the exec guards' kernel configuration
  (`execq::install`, `execpol::install`, lab PRs 223 and 226) at a fixed
  point of its load, and the guards stay in the agent — the loader is
  `SensorMultiplexer<G: ExecGuards>`, the agent's
  `exec_guards::AgentExecGuards` the block cut verbatim from the load,
  and the agent's `sensors::SensorMultiplexer` the loader on it (an
  alias): the same calls in the same order. The test that reads the
  agent's weakening list was cut into the agent first (`epg_tests.rs`);
  the admin-socket tests' stand-in for the kernel's watched inodes is
  behind nn-linux's `test-util`. The flow tracker's and the rules'
  gate's binding to the Linux host moved with the drain that names them
  (the agent's `net` re-exports them). The agent keeps every path as a
  shim (removed in R17); `main.rs`, the admin socket, the tests, the
  replays, the examples and the fuzz targets are unchanged. CI's
  ebpf-build runs the embed's map-type test where it lives
  (`-p nn-linux`; filtered on the agent it would have matched nothing
  and passed); path_liveness no longer exempts `agent/build.rs`. The
  staleness guard, proven end to end on `main` and on the lot's tree
  (a fresh object embeds; a stale closure, `common/` or `agent-ebpf/`
  edited, refuses "STALE eBPF OBJECT"; other bytes than the stamped
  ones refuse "DOES NOT MATCH ITS STAMP"; no stamp refuses "UNSTAMPED";
  no object builds the placeholder the boot preflight refuses): the
  same verdicts and the same messages but the script's path in their
  banner line. The ratchet goes from 26 to 22 (nn-linux 3 → 0: the
  sensors' references to `boot` left with them; nn-core 15 → 14: the
  agent's `net/mod.rs` names `LinuxHost` no more).
  Identity against `main` 482a956, both built in one temporary checkout
  (same path), the release job's commands: the eBPF object and its stamp
  are byte-identical (source hash 235e2fed…, `main`'s: `common/` and
  `agent-ebpf/` untouched, so the agent embeds `main`'s build hash).
  Through the moves the scanner and the watchdog stayed byte-identical;
  the decode's move makes them differ: nn-model dropped nn-parse, which
  changes its metadata hash, so the `TypeId`s of its types and the
  symbols' order — function by function the scanner's 504 are the same
  code and the watchdog's 2,468 of 2,470 (the two differ by the `TypeId`
  constants of nn-model's types), the stripped `.text` ±16 bytes of
  alignment; their SBOMs drop nn-parse and md-5. The tarball's 72
  entries and the .deb's 79 paths and modes are the same; `posture_demo`
  prints the same lines; `nn-admin policy test` on lab PR 251's samples
  gives the same 402 outputs; the golden replays (five runs), the wire,
  chain and crypto pins, the parser pins, the overlay-v1 fixture and the
  per-rule policy's format pass unchanged; the test list is `main`'s
  (3,082 names: 220 now nn-linux's, 7 at a new path — the weakening test
  in the agent, the DNS decode's six in the DNS sensor). The agent
  (15,192,112 → 15,276,256 bytes) and nn-admin (4,129,480 → 4,130,440)
  are not byte-identical: function by function (unstripped, names
  mapped, addresses dropped) 7,705 of the agent's 7,992 functions and
  3,528 of nn-admin's 3,604 are the same code; of the agent's 147 that
  differ, 105 call other callees (inlining at the new crate boundary:
  the loader, the drains, the FIM, generic code instantiated in
  nn-linux), 22 are scheduled or allocated otherwise, 14 differ in
  operands only (10 by clap's and tracing's `TypeId` constants), 5 names
  have several bodies; the unpaired are generic instantiations made in
  the other crate and code inlined on one side only (the exec guards'
  `install` and `fail`, out of line on `main`, inlined into
  `AgentExecGuards::install`): `.text` +81,872 bytes (+1.09 %) in the
  agent, +2,000 in nn-admin. `cargo doc`: 336 warnings, `main` 337.
- Wave 4 restructure, R09c — nn-linux, part 3: the hardening, the
  integrity checks and the systemd integration (lab PR 257). Moved to
  `crates/nn-linux` (`git mv`, 99–100 %): the systemd integration
  (`systemd_state`: what systemd reports the host as, over its private
  socket; `sd_notify`: the agent's `READY=1`), the install manifest's
  boot check (`install_manifest`), the hardening (`host_hardening`: the
  kernel and boot-chain checks of `nn-admin host-check`, the boot's
  warnings and the capability manifest; `process_hardening`: no core
  dump, no readable memory), the telemetry probe (`telemetry_probe`,
  onto R09b's cut of it), the self-integrity watcher (`self_integrity`,
  onto R09a's cut of it), the files around the agent's start and stop
  (`audit_preflight`, the shutdown marker's file I/O,
  `upgrade_rollback`) and the lab builds' probes (`sensor_feasibility`,
  `verifier_check`, behind the features they had, nn-linux's now, which
  the agent forwards). Cut first: the install manifest's test that reads
  the agent's fuzz fixture stays in the agent
  (`install_manifest_tests.rs`); the shipped COMBAT defaults' lookup
  (`shipped_default`) sits beside the rulesets it returns, in nn-linux's
  `anti_tamper::network_isolate` (the agent's overlay gate re-exports
  it). One seam: the watcher holds the agent's signed-overlay gate
  through nn-core's `Vouch` (R09a's, the network isolator's), which
  takes `is_signed` beside `verified`; `self_integrity::spawn` takes the
  `Arc` of any `Vouch`, so `main.rs` is unchanged. `systemd_state`'s
  padding reads `is_multiple_of` (the workspace lints; its callers pass
  4 and 8). The agent keeps every path as a shim (removed in R17);
  `main.rs`, the admin socket, the tests, the replays, the examples and
  the fuzz targets are unchanged; xtask's `operator_docs.rs` and
  `path_liveness.rs` read the checks' new path, `install.sh`'s comments
  name the new paths. The boot's deny self-test, BPF LSM gate, trust
  level and signed manifest stay in the agent (the plan's R11a and R13).
  The ratchet goes from 22 to 21: R09c's modules had no counted arc
  (nn-linux 0), and nn-admin's `detections` names the detections'
  default limit (`DEFAULT_DETECTIONS_LIMIT`, what `limit = 0` means on
  the wire) where it now is, nn-proto's `admin_signed_payload` (nn-admin
  8 → 7). Identity against `main` 8738784, both built in one temporary
  checkout (same path), the release job's commands: the eBPF object and
  its stamp are byte-identical (source hash 235e2fed…, `main`'s), the
  scanner and the watchdog byte-identical, stripped and unstripped; the
  tarball's 72 entries and the .deb's 79 paths and modes are the same;
  `posture_demo` prints the same lines; `nn-admin policy test` on lab PR
  251's samples gives the same 402 outputs; the golden replays (five
  runs), the wire, chain and crypto pins, the parser pins, the
  overlay-v1 fixture and the per-rule policy's format pass unchanged;
  the test list is `main`'s (3,082 names: 89 now nn-linux's, one at a
  new path — the fuzz fixture's test in the agent). The agent
  (15,276,288 → 15,282,760 bytes) and nn-admin (4,130,440 → 4,149,576)
  are not byte-identical: function by function (unstripped, names
  mapped, addresses dropped) 7,856 of the agent's 7,958 functions and
  3,555 of nn-admin's 3,580 are the same code; of the agent's 89 that
  differ, 72 call other callees (inlining at the new crate boundary: the
  watcher, the probe, the overlay read, generic code instantiated in
  nn-linux), 10 are scheduled or allocated otherwise, 5 differ in
  operands only (the watcher's task, whose state holds the gate as a
  `dyn Vouch`, a wider pointer), one name has several bodies; the
  unpaired are generic instantiations made in the other crate, code
  inlined on one side only (`jittered` out of line on `main`; the
  watcher's `collect_round` and the overlay read on `LinuxHost` out of
  line on the tip) and the one new function, the gate's
  `Vouch::is_signed`: `.text` +5,872 bytes (+0.08 %) in the agent,
  +16,848 (+0.51 %) in nn-admin (serde_json's generic code instantiated
  again in nn-linux for the install manifest). `.rodata`: the same text
  but the callsite lines of the edited files. On the lab guest (Ubuntu
  24.04) what the agent hashes and checks at boot gives `main`'s
  verdicts: every boot of the installed agent — the lot's 11, `main`'s
  7, the one `upgrade-check` made from `main` — verified its binaries
  and the embedded object against the install manifest ("checked=5") and
  signed the same capability manifest (the host hardening table
  included); the `tamper-check` cases are `main`'s, case by case (72 of
  75 OK, the same two known gaps and deviation), and so are the
  self-integrity findings over each run, kind by kind — an unsigned
  overlay is drift, a signed one is not (the gate's `is_signed` through
  `Vouch`).
- Wave 4 restructure, R10 — nn-admin: the operator client leaves the
  agent (lab PR 259). Moved to `crates/nn-admin` (`git mv`, 99 %): the
  agent's `admin_cli` (the library half: the Unix-socket transport, the
  signed requests, the readers and verifiers) and the logic of its
  `bin/nn_admin.rs` (clap's dispatcher, the rendering, the exit codes;
  nn-admin's `cli`). The `nn-admin` binary stays in the agent package, a
  shim of three lines that runs nn-admin's `main` on the agent's host
  (`CARGO_BIN_EXE_nn-admin`, the SBOMs, the release are unchanged).
  nn-admin depends on nn-proto, nn-evidence, nn-core and nn-model — not
  on nn-linux and not on the agent: the plan draws it beside nn-linux,
  both below the agent (§2.1), and the module map's rule for it has no
  nn-linux (the decision lab PR 239 left to R10). What it reads of the
  Linux host and of the agent goes through one seam of its own,
  `nn_admin::host::AdminHost`, which the agent implements
  (`admin_host::AgentAdminHost`): the host hardening checks
  (`host-check`, `status`'s summary line), the agent key's files (`audit
  verify`, `chain verify`), the agent's chains and where they lie under
  its state directory (`chain verify`), the overlay gate and its rollback
  floor (`config overlay status`, `policy show`), the loaders' checks of
  an overlay before it is signed (`config overlay set|sign`), the content
  the agent was built with, the offline engine on the Linux host
  (`policy test`); each method is the call the code made before, in the
  same place and order. Cut or moved first, bottom-up: the
  trusted-installer window's ceiling to nn-core's
  `anti_tamper::trusted_installer`; nn-admin's read of the identity file
  (`load_existing`, MAIN-010) from nn-linux's `agent_id` to nn-admin, the
  all-zero rule both reads take to nn-proto's `shutdown_marker`
  (`parse_minted_agent_id`); the OS CSPRNG (`os_rng`) from nn-linux to
  nn-evidence, below both; the overlay signature file and the gate's
  `Decision` to nn-core's `config::overlay_auth`. nn-admin's `--new-roles`
  parse names nn-proto's `admin_quorum`. The 12 tests of `admin_cli` that
  wire the agent's key, chains and loaders, and the 2 of `agent_id` that
  read both identity reads, were cut into the agent first
  (`admin_cli_tests.rs`, `agent_id_tests.rs`). `read_priv_key`'s owner
  check reads the effective uid through rustix's safe `geteuid` (nn-admin
  forbids unsafe code). The agent keeps `admin_cli`'s path as a shim
  (removed in R17); nn-admin declares `debug-trigger`, which the agent
  forwards. The ratchet goes from 21 to 14 (nn-admin 7 → 0).
  Identity against `main` 48228ad, both built in one temporary
  checkout (same path: the eBPF object carries its sources' absolute
  paths), the release job's commands: the eBPF object and its stamp are
  byte-identical (source hash 235e2fed…, `main`'s), the scanner and the
  watchdog byte-identical, stripped and unstripped; the tarball's 72
  entries and the .deb's 79 paths and modes are the same, the scanner's
  and the watchdog's SBOMs too, the agent's lists nn-admin;
  `posture_demo` prints the same lines; every `nn-admin` subcommand gives
  `main`'s bytes — a matrix of 1,964 cases (every help text, clap's
  errors, `init`, `verify-keys`, `host-check`, `audit read|verify`,
  `chain verify` on chain-pin-v1's log and every class of lab PR 256,
  `config overlay status|sign|set`, `policy show|set|test` — the 24
  golden cases and their events as two streams under the built-in
  defaults, the three golden candidates and a refused one, with the
  shipped lists and with none, as a table and as JSON —, every socket
  verb against a mock agent with its success, refusal and transport
  replies, the key and identity errors, closed pipes) gives the same
  stdout, stderr, exit status, files written and requests sent with
  `main`'s binary and the tip's, release and lab builds alike; the
  golden replays (five runs), the wire, chain and crypto pins, the
  parser pins, the overlay-v1 fixture and the per-rule policy's format
  pass unchanged; the test list is `main`'s (3,098 names: 44 now
  nn-admin's, 32 at a new path — admin_cli's 12 and agent_id's 2 in the
  agent, the dispatcher's 18 in nn-admin's `cli`). The agent
  (15,297,832 → 15,298,288 bytes) and nn-admin (4,160,520 → 4,218,272)
  are not byte-identical: function by function (unstripped, names
  mapped to the new crates and modules,
  addresses dropped) 7,007 of the agent's 7,030 functions and 2,991 of
  nn-admin's 3,170 are the same code. The agent's 23: clap's `TypeId`
  constants of its enums (its crate's dependencies changed), a call to a
  body of the same code under another name, the overlay gate's read
  calling nn-core's `sig_path` out of line; `.text` −48 bytes. nn-admin's
  179: 127 generic instantiations made both in nn-admin's library and in
  the binary's crate, where the dispatcher, generic over the host, is
  monomorphized (`Debug` of the admin messages, serde's
  deserializers), 33 inlining at the new crate boundary
  (`read_priv_key` calls rustix's `geteuid`), 14 scheduling, 5
  operands; unpaired, code inlined on one side only (`audit_read_into`
  into `run_audit_read`, the response verbs into the dispatcher;
  `run_init`, `print_capabilities`, `sig_path` out of line on the tip)
  and the seam's methods kept out of line: `.text` +42,144 bytes
  (+1.26 %). `.rodata` holds the same text but the moved files' paths,
  the callsite lines of the edited files and literals grouped otherwise.
  On the lab guest (Ubuntu 24.04) the lot's code passes `test-ignored`
  (76 suites, 84 passed), `policy-check` and `tamper-check` — `main`'s
  outcomes and verdicts, case by case (72 of 75 OK, the same two known
  gaps and deviation) —, `upgrade-check` from `main` passes, and the two
  nn-admin binaries against the live agent give the same bytes for 35
  commands (status, capabilities, net status signed and not, the readers,
  the verifiers, `policy test`, the error paths); every boot verified
  its binaries, nn-admin among them, against the install manifest.
- Wave 4 restructure, R11a — nn-agent: `main.rs` cut into typed phases
  (lab PR 261). The agent's start — `main.rs`'s `run`, 3,900 lines, with
  `process_event` and the helpers around them — is the library's now, in
  the plan's layout (§2.4: `main` → `boot/*`, `pipeline/*`,
  `run_loop.rs`, `shutdown.rs`): `boot/cli` (the command line),
  `logging`, `preflight`, `state`, `identity`, `integrity` (the checks
  before anything attaches, ending in the attach permit), `attach` (the
  attach and the deny self-test), `evidence` (the attest phase, the audit
  log's late binding, the rotating logs and detection stores), `policy`,
  `response`, `posture` (the machine and the COMBAT ladder), `fim`,
  `canary`, `net`, `admin`, `tasks`, `ready` (the capability manifest,
  READY); `pipeline/` (`process_event`, the host-stopping state);
  `run_loop.rs`; `shutdown.rs`. `boot::main` holds `main`'s one-shot
  modes and runtime, and `boot`'s `run` calls the phases in the order
  their code always ran; `main.rs` is the binary's shim. Each phase is a
  function that takes what the phases before it produced and returns a
  struct of what the ones after it read (`Preflight`, `StateReady`,
  `Identity`, `Integrity`, `Attached`, `SelfTested`, `Attested`,
  `Policy`, `Response`, `Posture`, `Combat`, `FimPaths`, `Stores`,
  `Canary`, `Tasks`, `Armed`, `Stopped`): the attach takes the
  `AttachPermit` only the integrity phase gets from
  `BootSequence::enter_attach`, the event loop takes the proof of READY
  only `ready::arm` makes, and only the identity phase builds an
  `Identity` (new unit test). No behaviour change: the phases' code is
  `run`'s, line for line and in its order, but 49 edits the signatures
  need (a `&x` of a value a phase now borrows, three `let mut` whose
  mutation is in a later phase) and the visibility a crate boundary
  needs; the library names itself as the binary did (`extern crate self
  as northnarrow_agent`, until R17). The history is kept (the plan's
  Appendix A): 21 `git mv` copies of main.rs merged beside it, trimmed
  one region at a time, so `git blame` and `git blame -C -C -M` of the
  new files reach the commits that wrote their lines — only the new glue
  is this lot's. The tests that read `main.rs` read the start's sources:
  the order test rebuilds the start in the order it runs and asserts what
  it asserted; the identity's read-once scan covers `boot/`, `pipeline/`,
  `run_loop.rs`, `shutdown.rs` and `main.rs`. xtask's state-isolation
  ratchet reads the agent's flags from `boot/cli.rs`; `btf-matrix.yml`'s
  filter names `boot/mod.rs` and `boot/preflight.rs`; the module map maps
  `pipeline`, `run_loop` and `shutdown` (ratchet 14, unchanged).
  The lot sits on lab PR 260 (`main` 45eaae3, merged while the lot was
  in the lab; the history regenerated on it): lab PR 260's step of the
  canary start — the trips the access log holds and the registry does
  not record, recorded before the detector runs — moved with the canary
  phase into `boot/canary.rs`, its 115 lines as lab PR 260 wrote them
  (plain `git blame` gives them to its commit).
  Identity against `main` 45eaae3, both built in one exported tree
  (the same path: the eBPF object carries its sources' absolute paths),
  the release job's commands: the eBPF object and its stamp are
  byte-identical (source hash 235e2fed…, `main`'s), the scanner and the
  watchdog byte-identical, stripped and unstripped; the tarball's 72
  entries and the .deb's 79 paths and modes are the same, the SBOMs too;
  `posture_demo` prints the same lines, and the agent's `--help`,
  `--version`, `--build-features` (release and lab build), `--btf-check`
  and a bad flag the same text; every `nn-admin` subcommand gives
  `main`'s bytes (lot 259's matrix, 1,964 cases, release and lab build);
  the golden replays (five runs), the wire, chain and crypto pins, the
  parser pins, the overlay-v1 fixture and the per-rule policy's format
  pass unchanged; the test list is `main`'s but the Cli's three tests at
  their new path (`boot::cli::tests`, in the library's tests) and the
  identity phase's new one (3,109 → 3,110 names). The agent (15,338,880
  → 15,182,136 bytes, `.text` −1.5 %) and nn-admin (4,218,272 →
  4,228,928) are not byte-identical: function by function (unstripped,
  names mapped to the new modules, addresses dropped) 6,408 of the
  agent's 6,784 paired functions are the same code — of the 376 that
  differ, 214 have another count of bodies (generic code the binary's
  crate instantiated beside the library's is the library's now: one copy
  fewer for most), 128 call other callees (inlining at the new crate
  boundary), 17 are scheduled otherwise, 17 differ in several bodies or
  operands —, 53 are the same code under another name (the tasks `run`
  spawned, its closures then, a phase's now), and the unpaired are `run`,
  its closures and their task harnesses (141) against the 23 phases,
  theirs (155), and code inlined or instantiated otherwise
  (`start_open_sensor` and lab PR 260's `record_unrecorded_trips` into
  their phases, the engine's `decide` out of line); nn-admin, which
  links the library, 3,135 of 3,188 (53: 34 another count of bodies, 17
  callees, 2 scheduling). Against `main` b8b55a9, before lab PR 260, the
  same functions differed in the same ways. `.rodata`: the same text but
  the 257 log callsites of the moved code, which name their new files
  (`event <file>:<line>`; 957 in all, as before), the new modules' paths
  (tracing's module path, not printed: the journal lines have no target)
  and the moved files' paths; the rest is laid out otherwise, each
  side's text found in the other's but 0.08 % of the characters
  (printable bytes of binary constants at the strings' edges).
  On the lab guest (Ubuntu 24.04), against `main` 45eaae3 on the same
  guest, the lot's code passes `test-ignored` (76 suites, 85 passed:
  `main`'s 85 tests, each with the same outcome) and `tamper-check` —
  `main`'s outcomes and verdicts, case by case (72 of 75 OK, the same
  two known gaps and deviation) —, and `upgrade-check` from `main`
  passes. Its boots and `main`'s (three each, and the upgrade's) log
  the same 204 lines in the same order once the values a boot changes
  are masked (pids, inodes, hashes, counts, durations, the detections
  check's moving window), 188 of them byte for byte; their signed rows
  are the same, row by row, and so is the capability manifest; every
  boot verified its binaries against the install manifest. A first
  round against `main` b8b55a9 gave the same, but C15 in `main`'s
  `tamper-check`: its 45 s cgroup freeze began a second after a round
  of the self-integrity watcher, whose next round came 10 to 15 s late,
  under its 15 s stall threshold — no finding; C15 alone, three times
  on each build, was OK every time.
- Wave 4 restructure, R11d — nn-agent: the admin socket cut into
  `admin/*`, one verification pipeline for its signed verbs (lab PR
  263). `admin_socket.rs` (10,134 lines) is the agent's `admin` module,
  in the plan's layout: `admin/transport` (the bind and the accept loop,
  the connection table, the peer's credentials and identity, the
  framing, the loop of one connection and one request's path,
  `serve_request`), `admin/verify` (the pipeline), `admin/audit` (the
  signed row of each request), `admin/handlers/*` (`dispatch` and the
  verbs, one file per family: unlock, shutdown, posture, keys, config,
  fim, installer, response, status, canary, net, detections, and the read
  verbs' tail) and `admin/tests`; `admin_socket` stays its path
  (`lib.rs`, until R17). Each of the 25 signed verbs carried its own copy
  of the verification around nn-linux's verify — the signatures
  collected, the verify called with its quorum, roles and operation, the
  error mapped (in two verbs by an inline copy of the mapper), the
  signers handed to the audit row, the extra matched again; now
  `verify::signed` alone verifies a request by its verb's rule, one table
  of operation, quorum and roles, writes the signers for the row and
  hands the handler a `Verified` request only it can make (the request,
  its extra typed, the matched keys and fingerprints, the token, the
  server's clock). The two rules that are not "n keys, each role" are the
  table's own: rotate-keys add needs one key while the one-key bootstrap
  is armed, the telemetry status either read role (its refusal names the
  signer). No reply and no audit row changed: a new table test drives
  every verb through every refusal of the verification — no challenge, a
  replay, the challenge spent, a bad signature, an unknown key, a missing
  role, no signature, one key twice, a time 120 s off, another install's
  id, another verb's payload or extra, nine signatures — and through the
  accepted and the rate-limited cases, and gives the same 478 replies and
  rows on `main` (the two fixes above aside). The history is kept (the
  plan's Appendix A): 19 `git mv` copies merged beside the file and
  trimmed one region at a time, so `git blame` of the parts reaches the
  commits that wrote their lines; for the tests, `git blame -w
  --ignore-revs-file .git-blame-ignore-revs` (new: the tests' dedent).
  Every `nn-admin` subcommand gives `main` 4444f20's bytes (lot 259's
  matrix, 1,964 cases, release and lab build); the wire, chain and
  crypto pins pass unchanged (nn-proto, `common` and the eBPF crates
  untouched), the golden replays too (five runs); the test list is
  `main`'s but the admin socket's 108 tests at their new path
  (`admin::`) and 9 new (3,110 → 3,119 names). On the lab guest (Ubuntu
  22.04), against `main` 4444f20 on the same guest, the lot's code
  passes `test-ignored` (76 suites, 85 passed: `main`'s 85 tests, each
  with the same outcome), `tamper-check` — `main`'s outcomes and
  verdicts, case by case (72 of 75 OK, the same two known gaps and
  deviation), its trusted-installer grants and signed overlay through
  the pipeline — and `policy-check` (the signed `policy set`), and
  `upgrade-check` from `main` passes; 41 nn-admin commands against the
  live agent — lab PR 259's, and the verification's refusals on the real
  socket: an unknown key, another install's id, the roles the lab key
  lacks, `shutdown` with one key (which nn-admin refuses before sending)
  — give the same output, exit status and signed rows from `main`'s
  agent and the lot's, with either build of nn-admin (the telemetry's
  counters, the times and the boot's manifest hash aside).
  After the independent review of the pull request: the bootstrap's
  1-of-N is tested end to end through the pipeline (armed, then spent;
  re-armed neither by a one-key admin.pub with a valid sentinel nor
  after the signed chain spent it; the gate's closed states), every
  verb against keys of every other role and of the default roles, the
  shutdown's quorum is the watchdog's constant (`SHUTDOWN_QUORUM`) in
  the table, the core has a test of the nonce binding, the rejection
  table is a golden file of `cargo xtask golden`
  (`agent/tests/golden/admin/expected`, `docs/validation/
  GOLDEN_REPLAY.md` §7), and no test reads or removes the host's
  bootstrap files any more.
- Wave 4 restructure, R11c — nn-agent: the global setters replaced by
  explicit handles (lab PR 264). The start wired what it made into deep
  code through process-wide statics that setters filled, and some
  instances kept their own state in statics every other instance of the
  process shared. Every `static` of the agent's code was inventoried
  (the agent and the crates it is built from, test code aside; the table
  is in the pull request) and classed: 48 were boot state handed on
  through a setter, or one phase's result read by a later one, or one
  instance's state the others shared — they are gone; 64 stay, one per
  process by their nature (the event loop's heartbeat, the one boot, the
  host's facts, the one eBPF object's state as the status reads it, the
  status totals, the signed degradations, state keyed by an instance's
  own path, per-thread scratch), each listed with why. Now explicit: the
  per-rule policy (one `PolicyHandle` the policy phase makes, read by the
  engine and the posture and swapped by `nn-admin policy set` through
  the admin socket's clone; it was `rule_policy::global()`); the audit
  log's late binding (the ring-drop and fail-open samplers, the exploit
  guard and its control, the FIM's watch-pressure attestation, the read
  verbs' unverified rows, the telemetry probe, the BPF guard's record of
  the object's own maps and links and its stop, each a handle the part
  hands the start); the boot's results (the anti-tamper attach's report,
  the trust level's measurements, the signed capability manifest, the
  ransomware tracker and the security-tool judge, the JA3 list's size);
  the load's plan (the exec, file-open and DNS sensors the command line
  chose, the exploit guard's task maps) and what it armed (the exec
  sensor's and the DNS sensor's modes, the sensors' attach points); the
  exec guards (an instance with their configuration and the kernel
  objects their install took); the copy-on-first-write guard, the
  quarantine's refusal of the agent's own files (in the executor's
  configuration), the deny self-test's own denial and the host's stop;
  and per instance: the overlay gate's configured paths, the canaries'
  read-forward set (the FIM drain's), the FIM drain's retry queues (the
  tests ran a thread-local copy). A new ratchet test
  (`xtask/tests/global_state.rs`) lists the statics that stay with their
  reasons and the start's calls into them, and fails on a new one. No
  behaviour changes: the same values reach the same readers at the same
  points of the start. A new test proves `policy set` still applies at
  once everywhere: a signed `config overlay set` through the admin
  pipeline, on one handle shared as the start shares it, gives R020 its
  kill back in the engine's next decision, the executor runs that kill,
  and the posture's next judgement takes the ransomware directive.
  The eBPF object, the watchdog, the scanner, the packages' contents
  and the SBOMs are `main`'s bytes; the wire, chain and crypto pins pass
  unchanged, the golden replays too (five runs); the test list is
  `main`'s and the 7 new (3,176 → 3,183 names). On the lab guest
  (Ubuntu 24.04), against `main` 118d504 on the same guest, the lot's
  code passes `test-ignored` (91 passed: `main`'s 91), `policy-check`
  (the signed `policy set` applied at once — the next event's tree
  killed — and at boot), `tamper-check` — `main`'s outcomes and
  verdicts, case by case (72 of 75 OK, the same two known gaps and
  deviation) — and `upgrade-check` from `main`; its boots log `main`'s
  lines and sign `main`'s rows; 41 nn-admin commands against the live
  agent — lab PR 263's, with the verification's refusals on the real
  socket — give the same output, exit status and signed rows from
  `main`'s agent and the lot's, with either build of nn-admin (the
  telemetry's counters, the times and the boot's manifest hash aside).
- The rest of the dependencies refreshed (Wave 4 Phase 2, D3a of the
  dependency plan; lab PR 237; supersedes Dependabot #433): nix 0.29 →
  0.31.3 (the agent; its 271 `nix::` sites compile unchanged) and
  `cargo update` of the three lockfiles, patch and minor only — 49
  entries in `Cargo.lock` (tokio 1.54.1, cc 1.9, bitflags 2.13, bytes
  1.12, syn 2.0.119 and 3.0.9, zerocopy 0.8.63, among others), 10 in
  `fuzz/Cargo.lock` (tokio and nix as in the root, the security crates
  locked alike), 9 in `agent-ebpf/Cargo.lock` (proc-macro and build
  crates; aya-build kept at 0.2.0). aya, aya-obj and the RustCrypto
  crates do not move; parking_lot 0.13 waits for the MSRV 1.95 lot. The
  MSRV stays 1.89. The eBPF object's code, maps, BTF and BTF.ext are
  byte-identical to `main`'s; only `.debug_str` differs (the crate
  hashes in mangled names). The CLI stub no longer depends on
  `northnarrow-common` and `anyhow`, which it did not use.
  `.github/dependabot.yml`: the grouped cargo entry covers `/` and
  `/fuzz` (`directories`), so its patch/minor PR moves the fuzz lockfile
  with the root one; an xtask test checks it.
- RustCrypto's next generation, in one step (Wave 4 Phase 2, D2 of the
  dependency plan; lab PR 234): sha2 0.11 (agent, common, ebpf-guard,
  scan), hkdf and hmac 0.13, aes-gcm 0.11, md-5 0.11, ed25519-dalek 3
  (its `std` feature is now `alloc`) and rand 0.10, which ed25519-dalek 3
  needs. One copy of each crate in `Cargo.lock` and `fuzz/Cargo.lock`
  (getrandom 0.4.3 in both); generic-array, getrandom 0.2, rand_chacha and
  ppv-lite86 left the graph. rand 0.10 has no `OsRng`: `agent/src/os_rng.rs`
  keeps one over rand's `SysRng` — every byte from the operating system's
  CSPRNG (getrandom: the `getrandom(2)` syscall, `/dev/urandom` after
  polling `/dev/random` as fallback), no userland generator in between, a
  panic if it fails, as before — for keys, nonces, challenges and seeds;
  the callers that handle the error (agent id, audit signing key, probe
  nonce) read `SysRng` itself, and the anti-tamper session nonce, drawn
  from `thread_rng`, now comes from the OS generator too. The vault's
  nonce is built from its 12-byte array and the `.meta` SHA-256 is
  `hex::encode`d (the same lowercase hex). The 20 vectors of lab PR 230
  pass unchanged; the fuzzer lock check also covers rand, rand_core,
  getrandom and md-5. Supersedes Dependabot #289 and #287.
- The eBPF programs are built with aya-ebpf 0.2.1 instead of 0.1.1 (lab
  PR 233, D1b of the Wave 4 phase 2 dependency plan; supersedes Dependabot
  #361): `helpers::gen` is now `helpers::generated` (56 calls in 11 files)
  and `RetProbeContext::ret` returns the value itself. Its build
  dependency aya-build stays at 0.2.0 in `agent-ebpf/Cargo.lock` (0.2.1
  needs rustc 1.98, the eBPF nightly is 1.93; Dependabot ignores it
  there); the nightly and bpf-linker 0.10.3 are unchanged. The generated
  code differs in 48 of the 96 BPF functions (among other things, kprobes
  read their arguments from the context instead of through
  `bpf_probe_read`), and the object still keeps the "Older verifiers"
  rules: the same `memset`/`memcmp` calls function for function, none in
  the exploit guard, exec or file-open programs, global functions with
  `u64` arguments only. Every program that loads with `main`'s object
  loads with this one on 5.15, 6.1, 6.8 and 6.12. Per program, the
  instructions the verifier processes move between −47 % (the TCP connect
  kprobes) and +16 % against `main`'s, and between −1.3 % and −0.1 % in
  total; the largest stays at 48 % of the 1M limit
  (`docs/validation/results/verifier-2026-10-22-aya-ebpf-0.2.md`).
- aya 0.13.1 → 0.14.0 in userland, with aya-obj 0.2.1 → 0.3.0 (lab PR 231,
  Wave 4 phase 2, D1a; supersedes Dependabot #363). aya-log is removed
  instead of bumped: the eBPF object has no `AYA_LOGS` map, so its init
  failed at every start with a debug line, and nothing else used it. The
  loader follows 0.14's API with the same effect: `map_max_entries` for the
  exploit guard's task maps, `default_map_pin_directory` for the pin root
  (maps pinned by name under it, an existing pin reused). The BPF guard's
  `map_data` covers the nine new `Map` variants, and the map types the
  embedded object is held to are re-read from 0.14's `parse_map`: 29, up
  from 20, still without task storage. The kernel side (aya-ebpf 0.1.1) is
  unchanged, and the eBPF object is byte-identical to `main`'s. Both
  lockfiles lose aya-log, aya-log-common, thiserror 1, core-error,
  num_enum and allocator-api2, and take object 0.39.1 (from 0.36) and
  foldhash 0.2; `Cargo.lock` also loses windows-sys 0.52/0.59, and
  `fuzz/Cargo.lock` hashbrown 0.15. The MSRV stays 1.89. Detection,
  response and the programs the kernel loads do not change. One memory
  fix comes with the bump: aya-obj 0.3's `BtfType` is 72 bytes (48 in
  0.2.1), and glibc kept the pages that the boot's vmlinux BTF parses
  freed. The perf gate measured the idle agent 17 MB larger than `main`
  on the same guest (`agent_rss_idle_kib` +47.5 %, `agent_rss_load_kib`
  +37.7 %, both REGRESSION). The agent now calls `malloc_trim(0)` once
  after READY (`boot::release_boot_heap`, glibc only), which returns only
  free memory. Lab: the eBPF object (sha256 `243a806b…`) and every
  program's verifier result and count are the same as `main`'s on 5.15,
  6.1, 6.8 and 6.12. The agent reaches L3 with no degradation on all
  four. On 24.04 the upgrade from `main` passes, the privileged suites
  pass (80 passed, 0 failed) and the perf gate reports 0 regressions
  against the committed baseline.
- The ADE is a consultant: a model verdict that names a response (Kill,
  KillTree, Quarantine, BlockNetwork, Isolate) is recorded as a
  recommendation — a detection with the model's reasoning, response
  "advisory: … recommended by the model, not executed" — and nothing runs.
  The model reads strings an attacker writes; responses stay with the
  deterministic rules and the COMBAT ladder. `NN_ADE_ENFORCE=1` lets the
  verdicts act again and is reported as a weakening in the signed chain.
  (Superseded by the removal of the advisor, lab PR 214: see Removed.)

### Documentation

- The `.rpm` signing key exists (external audit NN-AUD-199, the
  maintainer's residual): its public half is committed at
  `deploy/release/RPM-GPG-KEY-northnarrow.asc` — `NorthNarrow RPM
  signing`, RSA 4096, signing only, expires 2028-10-16, fingerprint
  `BBBB EB6F 5566 A1CE 99AE  8379 C66A E018 C172 7C8D` — and published in the README and the operator guide (§6); the
  private half is in the `release-signing` environment. The next `v*` tag
  ships a signed `.rpm` instead of stopping at `rpm-sign`.

- The external audit tracker gets its Wave 3 table
  (`docs/audit/EXTERNAL_AUDIT_16f7563.md`): the 188 Low and 21
  Informational findings re-checked against `main` at `b9bf4d5` — 14
  already fixed by Waves 0–2 (with their lab PR), 30 in part, 5 obsolete,
  10 declined with the reason, 180 to fix in lots; NN-AUD-299 fixed with
  lab PR 166. Seven follow-ups found in the lab since lab PR 162 are added
  to "Follow-ups found in the lab": journal line injection (taken with
  NN-AUD-413), DNS attribution on `nss-resolve` hosts, a `tcp_close` ring
  burst, short-lived staging payloads that end before their verdict, the
  unhooked `file_ioctl_compat`, NN-L-NET-001 judging a flow at its close,
  `nn-admin` aborting on a closed pipe.
- The documentation follows the remediation of the external audit of
  `16f7563` (Waves 0–2) and the advisory ADE. README: the model's role
  (it recommends, the rules and the COMBAT ladder respond), what is
  verified today (76 rules, 16 deny hooks, the anti-tamper suite, the
  kernels from 6.9 not verified), the audit's status, the install checks
  (`--source-tree`, `--allow-manifest-only`, the boot-time check) and the
  supply chain (actions pinned by SHA, attestations bound to the release
  workflow at a `v*` tag, the `.rpm` signed on tag builds with its public
  key and fingerprint published with the first signed release, the `.deb`
  checked by attestation). New
  `docs/operator/UPGRADE_NOTES_AUDIT_16f7563.md`: the changes of
  behaviour and the regressions of `[Unreleased]` grouped for an operator,
  each with its finding and lab PR, linked from the install guide (whose
  §6.1 now says the rpm key is still to come) and the README. The tracker gains a summary per wave, the method and a section
  of follow-ups found in the lab (`inode_setattr` on 6.9+,
  NN-L-CANARY-003 and NN-L-NET-003 unable to fire, FIM-024 and the
  posture, `FLOW_SOCK_MAP`, the single ADE slot, no `nft` on Debian 12, an
  unexplained missing R001, the measurements owed on a model host).
  `docs/ADE_DOCTRINE.md` and the Article 13 dossier describe the advisory
  ADE, the prompt window, sanitization and context selection, the pinned
  RAG corpus and the one-slot limit; `ROADMAP.md`, `SECURITY.md`,
  `docs/CLAUDE_BRIEFING.md`, `docs/operator/KERNEL_COMPATIBILITY.md`
  (6.9+ and `nft`) and `docs/validation/README.md` (the Critical
  sub-gate) are brought up to date. No change to the agent.

### Removed
- The on-host LLM advisor (Wave 4, lab PR 214): the ADE (`agent/src/ade`,
  the Foundation-Sec-8B GGUF model the agent ran on the execs no rule
  matched), its RAG knowledge base (`agent/src/rag`, `cargo xtask rag-kb`,
  `docs/kb-sources/`, `target/kb`, the ATT&CK and Sigma licence texts of
  `LICENSES/`), the XAI explanations (`agent/src/xai`, `common::xai_types`,
  the never-written `explanation` field of a detection, the `BUILD_SHA`
  stamp only they read), `common::{ade_types, rag_types}`, the vendored
  `candle-core` and its `[patch.crates-io]`, every model and tokenizer
  dependency (candle-core/-nn/-transformers, tokenizers, tantivy, num_cpus
  in the agent; ureq, sha2, flate2, tar and serde in xtask), the system
  prompts of `dataset/`, the examples `ade_attacks`, `ade_demo`,
  `ade_smoke`, `ade_with_rag`, `bench_threads`, `rag_demo` and `diag_hw`,
  `cargo xtask ade-demo`, the `ade_verdict` and `ade_preparse` fuzz targets
  with their seeds and regressions, the `ade-build` and `ade-unit-test` CI
  jobs, the advisory exceptions of lru and paste (RUSTSEC-2026-0253,
  RUSTSEC-2026-0002, RUSTSEC-2024-0436: those crates left both lockfiles),
  the posture's modulation of model verdicts, the correlated-context
  selection of the prompt, the NOTICES.md sections of that material, and
  `docs/ADE_BACKEND_NOTES.md`, `docs/PERFORMANCE_THREADS.md` and the
  Article 13 dossier. Why: a multi-GB model inside the root agent process,
  fed with strings an attacker writes, was the largest attack surface of
  the agent; its accuracy was never measured; it cost gigabytes of RAM on a
  server (about 7 GB of peak RSS); mature EDRs keep on-host detection
  deterministic, and an AI assistant, if any, belongs off the enforcement
  path (a future analyst assistant on the backend). Detection stays
  deterministic: rules, correlation, posture and COMBAT; an exec no rule
  matches gets no detection, as on every host without the model, which no
  release shipped. **Upgrade:** the flags `--no-ade`, `--ade-model`,
  `--ade-timeout`, `--ade-prompt`, `--ade-threads` and the variables
  `NN_ADE_ENFORCE`, `NN_ADE_ALLOW_MOCK`, `NN_ADE_RAG_ENABLED`,
  `NN_ADE_RAG_INDEX_DIR`, `NN_ADE_RAG_JSONL_DIR`, `NN_ADE_TOKENIZER` are
  accepted and ignored, one WARN each at start naming it
  (`agent/src/removed_settings.rs`); the two weakening variables among them
  are no longer reported by the self-integrity check; `install.sh` names a
  leftover `/var/lib/northnarrow/models/` and leaves it; detection records
  the advisor wrote still decode and chain-verify, byte for byte
  (`DetectionPath::Ade`, `AdvisorAction`). The unit's memory limits are
  unchanged until the lab measures the agent's RSS without the model.
  `docs/operator/UPGRADE_NOTES_WAVE4.md` is new; the design documents of
  the advisor are marked historical. `Cargo.lock` and `fuzz/Cargo.lock`
  lose about 150 packages each; no locked version changed (cargo's own
  pruning, no `cargo update`). The validation registry keeps the Critical
  FIM rules of design §13 Q1 as its own list (they came from the advisor's
  templates).

### Fixed
- Transactional upgrade with rollback, and blocking provenance verification
  (capabilities C27, C28; static review of `baf4c25` P0 C-45 / G-07 / TD-09,
  App.D C-46, G-36; lab PR 220).
  - **`install.sh --upgrade` is a transaction.** It stopped the units,
    dropped the pins and overwrote binaries, units and configuration with
    no copy, no trap and no health check: a failure halfway (the binaries
    replaced and not the units, a new agent that does not start) left the
    host without a working agent. Before anything is stopped, every file the
    run may create or replace — the binaries, the units, the Debian drop-in,
    the journald config, the install manifest, the `.v1` lists, the overlay
    template, the control-surface files, the canary templates, the overlay
    signatures it may add — is copied (`cp -a`) into
    `/var/lib/northnarrow-upgrade/<time>-<pid>/`, and the files that do not
    exist yet are listed; a backup that fails is a refusal with nothing
    stopped. Binaries, units and the manifest are staged next to the
    installed ones and switched by `rename(2)`. After the restart the units
    must pass a health check (60 s, `HEALTH_TIMEOUT`): both active (Type=
    notify), the agent's own `anti-tamper: all LSM hooks attached` event
    with every deny hook, read as an event of the unit's main process
    (`_SYSTEMD_UNIT`, `_PID`, `_TRANSPORT=stdout`, the whole line — a file
    named like it in another event is not it), its pid file and an answer on
    its admin socket, the watchdog's own PROTECTED_PIDS registration with
    its main pid; a deny-hook shortfall fails, a missing observe hook is a
    WARNING. Any failure after the stop (an EXIT trap, Ctrl-C included)
    rolls back: the new units stopped through the new agent's own window
    (the same `--grant-key`, now required by `--upgrade` over running units,
    checked before anything is stopped), the previous files renamed back
    byte for byte — checked against the SHA-256 taken before the stop — and
    the new ones removed, the previous units started and
    checked, exit 3 with the stage and the reason on stderr and at
    `auth.err` (tag `northnarrow-install`). A unit that does not start is
    reported at the stage `health_check` (the start itself is not checked).
    Exit 4 (`auth.crit`) when the rollback cannot finish: below, or a
    restored file that is not the one backed up, or a restored version that
    fails its own health check (no `rollback.sh` then). The audit chain and the chain
    logs are not rolled back. A unit the stop did not reach now stops the
    run before its pin root goes.
  - **The previous agent signs the rollback.** Before restarting it,
    install.sh leaves `/run/northnarrow/upgrade-rolled-back.json`; the agent
    records it at its boot as an `upgrade_rolled_back` row (stage, reason,
    both versions, the transaction, `reported_by: install.sh`, its own
    version) and removes it (`agent/src/upgrade_rollback.rs`: read without
    following a link, root's, not writable by others, 4 KiB, strings only,
    200 characters, controls as `?`; anything else recorded as `failure:
    marker refused (…)`). install.sh reads the row back and names it; an
    agent older than the marker is reported as such and the marker removed.
  - **When the new hooks block the rollback** (a new agent that pinned them
    and died, or that does not answer on its socket), install.sh starts it
    once more for its window and otherwise stops with exit 4 (`auth.crit`)
    and `rollback.sh` in the transaction directory: after `systemctl
    disable` of both units and a reboot it restores the files, enables and
    starts the previous units and checks them. `uninstall.sh --purge`
    removes `/var/lib/northnarrow-upgrade`.
  - **Provenance verification blocks.** A release tree installed as
    `checksums` with an unsigned `SHA256SUMS` when the attestation failed or
    no verifier was there (`--require-attestation` was opt-in). A release
    tree now installs only at `attested`; a failed `gh attestation verify`
    (its last lines shown), no tarball, or no verifier is a refusal. The tree
    must also be the tarball's: its `MANIFEST.sha256` is compared with the
    one inside the tarball (a tree edited after extraction, manifest
    rewritten, passed every check). `--allow-unverified` accepts less — for
    the lab and development — and covers a source tree as `--source-tree`
    does; `--allow-manifest-only` is its former name. Each override is a
    WARNING, a line at `auth.warning`, `verify_override` (and
    `attestation.failure`) in the install manifest; `nn-admin host-check`
    now warns on `checksums` too. `--require-attestation` is the default
    (`REQUIRE_ATTESTATION=1` in install.sh, cleared only by
    `--allow-unverified` or `--no-verify`; the flag with either: exit 2).
    cosign verifies only with an offline bundle (`--attestation`); that path
    has no automated test. The lab keeps
    `--source-tree`; `release-check` expects the refusal of a CI run's
    tarball, then installs it with `--allow-unverified`.
  - **Packages report an unhealthy upgrade.** The configure step runs the
    same health check on the units it restarted: the `.deb` `postinst`
    fails (dpkg: half-configured), the `.rpm` checks in a new `%posttrans`
    (`install.sh --package-verify`, after the whole transaction) and fails
    it; the restart list stays for `dpkg --configure -a`. Neither package
    manager restores the previous version at that point; what each one can
    roll back is in `docs/operator/INSTALL_UPGRADE_UNINSTALL.md` §6.2. The
    release workflow's smoke test counts five rpm scriptlets.
  - Tests: `xtask/tests/install_scripts.rs` runs install.sh whole against
    stub `systemctl`, `journalctl` and fake agents that keep the
    anti-tamper's rules — a health check that fails rolls back byte for
    byte (mode and mtime) and restarts the previous agent, which signs the
    record; a failure at each stage (programs that do not unload, a unit
    rename that fails after the binaries were switched, `daemon-reload`, a
    unit that does not start (reported at `health_check`), a deny-hook
    shortfall, a forged health line); the pinned-and-dead
    agent finished by `rollback.sh`; an unattested release refused without
    the flag, the flag logged; the tree not from its tarball; the package
    configure and verify steps. `agent/src/upgrade_rollback.rs` tests the
    marker against install.sh's writer.
- Wave 4, boot integrity: checks before the attach, the deny self-test,
  signed degradations, a trust level and a capability manifest (external
  review G-09, G-11, G-12, AR-09, P0 C-13, P0 C-14; capability program C01,
  C23; lab PR 218; `docs/operator/BOOT_INTEGRITY.md`). Without `bpf` in the
  active LSM list (`/sys/kernel/security/lsm`, Ubuntu's default) every deny
  hook attached and none ran, behind one WARN. **Decision:** such a start is
  refused before anything attaches (exit 78) unless
  `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`, the degraded-mode opt-in of the
  deny-hook shortfall (trust level L0); a signed `subsystem_degraded`
  (`source: bpf_lsm`) either way, and a refusal adds `agent_boot`
  `refused` with `refused_by` naming the gate (`install_manifest` for the
  manifest refusal of lab PR 21). Detect-only does not change it; an
  unreadable list is left to the self-test. Right after the attach a child
  of the agent's binary (`--deny-self-test`, hidden) sends `SIGURG` to the
  agent and must get `EPERM` from `task_kill`: a delivered signal (hooks
  attached, not run) refuses the start the same way (`refused_by:
  deny_self_test`), an unmeasured one is signed (L1); the self-test's own
  denial — its pid, signal, target and a kernel timestamp between spawn and
  reap — is taken before the posture (no COMBAT, no NN-L-AT-001). The
  capability, install-manifest and audit checks ran after the eBPF programs
  were loaded, attached and pinned: they now run in a preflight phase (the
  audit log's writability by an open for append that writes nothing), in
  typed phases — `boot::BootSequence` (preflight, attach, self-test, attest,
  subsystems, run), a step out of its phase or a phase left incomplete
  stops the start, and `SensorMultiplexer::start_with_net` /
  `attach_anti_tamper` take an `AttachPermit` only `enter_attach` gives; a
  test holds `main.rs`'s order. The audit log opens right after the
  self-test, before the blocklists and the rule engine. When the netflow log
  cannot be opened the network drain no longer stays off for the boot (TCP,
  UDP and listeners blind): it runs without the log, signed (`net_drain`).
  Every degradation goes through one registry (`boot::degradation`):
  signed at once when its finder holds the audit log, at the log's open
  for the earlier ones, otherwise within 15 s (60 s bound), and listed by
  `nn-admin status --key`; new records for the exec sensor on
  `sys_enter_execve`, the file-open sensor on `sys_enter_openat` (its four
  fallbacks and the tracepoint mode), `udp_v6_send_skb` and `udpv6_sendmsg`
  not attached, io_uring without its tracepoints, the netflow and listener
  logs, the self-test. Trust levels: L3 every mandatory deny hook attached
  and self-tested, `bpf` active, enforcing, nothing degraded; L2 the same
  with a degradation or detect-only; L1 a deny hook missing or the
  self-test inconclusive; L0 no enforcement. A capability manifest (kernel,
  BTF, LSMs, deny hooks, self-test, each sensor's attach point, host
  hardening, degradations, level) is signed at every boot as a
  `capability_manifest` audit row, read with `nn-admin capabilities --key`.
  The status reply appends `trust_level`, `trust_reasons`, `degradations`
  and `capability_manifest` after lab PR 215's and 217's fields, which
  follow lab PR 207's (telemetry: the signed verb only). Alternatives not taken: a variable of its own for the missing
  `bpf` (one more weakening switch; the opt-in already means "below the
  expected protection" and is a signed `weakening_env`); per-hook
  self-tests (one hook proves the kernel runs the agent's LSM programs;
  per-hook checks are a follow-up); the full split of `main()` into one
  function per phase (follow-up: the permit and the sequence fix the order
  now).
  **Regressions / changes:** a host without `bpf` in its active LSMs no
  longer starts the agent (exit 78), an upgraded one included — add `bpf`
  (`KERNEL_COMPATIBILITY.md`) or set the opt-in; `install.sh` says so. A
  refusal before the attach is signed only when the early registration in
  the pinned `PROTECTED_PIDS` worked (otherwise the previous hooks close the
  key: the journal keeps it). The boot's signed rows change order
  (`agent_boot` before the blocklist records) and gain
  `subsystem_degraded` rows with `source`, one `capability_manifest` row,
  `refused_by` on a refused `agent_boot`. One exec of the agent's binary per
  boot (the self-test child). An `nn-admin` of this PR cannot read an older
  agent's status reply (as before: upgrade the agent first).
  Tests: `boot` `no_attach_permit_before_every_preflight_check`,
  `a_check_after_the_attach_is_refused`,
  `phases_cannot_be_skipped_or_repeated`,
  `phases_are_in_order_and_each_step_in_one_phase`,
  `main_runs_the_phases_in_order`, `main_runs_the_net_drain_without_its_log`;
  `boot::lsm` `a_missing_bpf_lsm_refuses_unless_opted_in`,
  `bpf_is_found_anywhere_in_the_list`,
  `an_unreadable_list_is_left_to_the_self_test`; `boot::deny_selftest`
  `exit_statuses_map_to_outcomes`, `only_the_self_tests_own_denial_is_taken`,
  `a_not_denied_signal_is_an_anti_tamper_record`,
  `the_parent_reads_the_childs_status`; `boot::degradation`
  `every_report_is_signed_once_and_listed`,
  `a_record_without_a_source_keeps_the_old_shape`,
  `without_an_audit_log_reports_are_kept_unsigned`,
  `past_the_cap_reports_are_counted`; `boot::trust` (L3, L2, L1, L0, order);
  `boot::manifest` `the_manifest_is_a_signed_row_of_the_audit_chain`,
  `a_later_note_moves_a_sensor`; `audit`
  `the_audit_preflight_writes_nothing_and_finds_an_unwritable_log`,
  `a_refused_boot_names_its_gate`; `anti_tamper`
  `the_deny_report_counts_hooks_and_names_every_gap`; `net::drain`
  `flows_reach_the_rules_without_the_netflow_log`; `admin_protocol`
  `a_lab207_nn_admin_reads_a_lab218_status_reply`,
  `a_lab218_nn_admin_cannot_read_a_lab207_status_reply`,
  `the_trust_level_and_degradations_are_withheld_from_the_public_status`;
  `nn-admin` `status_shows_the_trust_level_and_the_degradations`,
  `capabilities_prints_the_signed_manifest`; `agent_id`
  `the_agent_reads_its_identity_once` follows the refusal helper. On the
  starting tree: the order assertions (capabilities and install manifest
  before `start_with_net`) and the drain one, run against its `main.rs`,
  fail (`caps::boot_gate(` after the attach; the drain spawned only with
  the netflow log); the other tests call types and functions new in this
  lot and do not compile there. Host: `cargo xtask build-ebpf --release`,
  `cargo fmt`, the three clippy runs (`--workspace --all-targets`, the
  agent with `test-privileged,debug-trigger`, `posture_demo`) clean,
  2,825 passed, 0 failed (one earlier full run lost
  `admin_socket::tests::force_posture_records_the_state_it_left`, a journal
  capture this lot does not touch; it passes alone and in the two later
  runs).
- Truthful COMBAT outcomes: what an unlock, a NEUTRALIZE and an ISOLATE
  report and record is now the state of the host (capabilities C17, C18;
  static review of `baf4c25` P0 C-30, C-32, C-35, G-02, G-03, TD-07, TD-11;
  the NN-AUD-243 residue; lab PR 217).
  - **Unlock.** A release whose iptables teardown failed was answered
    `Success` and recorded "success": the release hook returned nothing and
    ran after the posture had already been written ALERTED. The hook now
    returns what the tables hold after the teardown, read back per family
    (`iptables -S` / `ip6tables -S`: neither the `NORTHNARROW_COMBAT` chain
    nor a jump into it), and runs before the posture changes; the posture
    leaves COMBAT only after a verified release. A failure is answered
    `AdminResult::ActionFailed` with the reason and the per-family state
    (`nn-admin unlock` exit 9), the posture stays COMBAT, and the audit row
    is `failure: release_failed (…)`. The same for `force-posture` out of
    COMBAT. An unlock outside COMBAT runs the teardown and the read-back
    without touching the ladder — lifting a stale chain the boot teardown
    could not remove (the boot state now follows the table read back) —
    and is idempotent when the tables read back clear.
  - **Signed unlock.** `unlock` is a `SignedPayload` with
    `OperationCode::Unlock` (challenge, time, `agent_id`, 1-of-N, role
    `unlock`), like every other admin operation — new wire variants
    `SignedUnlockRequest` / `SignedUnlockResponse`, appended before the
    debug-only ones (indices 54/55, after lab PR 216's `LoopProgress`
    pair; lab PR 222's `RemediateRansomware` pair follows at 56/57, and the
    debug-only variants move to 58/59) — and its audit row names the signer (`key_fp`, it was
    empty). The legacy signature over the bare nonce is refused,
    `UnlockResult::LegacyProtocolRefused` (appended), audited as `failure:
    legacy_protocol_refused`. Decision: refused outright, no compatibility
    flag — a flag would be a downgrade switch on the one operation that
    lifts the isolation, and `nn-admin` ships in the same release as the
    agent. `nn-admin unlock` gains `--agent-id-file` (default
    `/etc/northnarrow/agent_id`).
  - **NEUTRALIZE** stopped at the first offender it could not contain: the
    others were neither killed nor had their binary quarantined. Every
    offender is now handled, and one signed `combat_outcome` row (stage
    NEUTRALIZE) lists each one's kill and quarantine outcome and the
    host-critical ones spared; `result` is `success` only when all are
    contained.
  - **ISOLATE** was marked done before it ran, its failure only logged and
    never retried. `NetworkIsolator::engage` returns the per-family
    read-back; the stage reads ISOLATE only once IPv4 is isolated; each
    attempt's outcome is a signed `combat_outcome` row (stage ISOLATE, per
    family); an attempt that left a family not isolated is retried after
    5 s and 10 s, three attempts per episode.
  - **Isolation state per IP family.** One flag covered IPv4 and IPv6 and
    was true with IPv6 open. The isolator keeps a flag per family, set and
    cleared only from the tables read back after an engage or a release
    (isolated: the chain reaches its DROP and INPUT and OUTPUT jump into
    it; a chain left without its jumps is a failed release, not an
    isolation); the status reply carries both (`network_isolation_v4` /
    `_v6`, appended, public; `network_isolation_engaged` is either), and
    `nn-admin status` prints them. Every `iptables`, `ip6tables` and `nft` invocation
    is waited for at most 10 s, then killed (`bounded_cmd`).
  - Compatibility: an older `nn-admin` cannot decode the new replies
    (`LegacyProtocolRefused`, `ActionFailed`) and exits 5 — never a
    success; this `nn-admin` cannot unlock an agent older than lab PR 217
    (the agent closes the connection; exit 5 says to use that agent's
    `nn-admin`), and, as with every status field appended since lab PR 193,
    cannot read its `status`. The watchdog's ping reads the two leading
    status fields only and is unaffected. `docs/operator/COMBAT_RECOVERY.md`
    §3.
- Wave 4, capability C23 (anti-tamper and self-defence): supervision fails
  visibly, and both daemons are hardened (static review of `baf4c25`:
  C-43, C-44, G-05, G-06, TD-08, TD-10; lab PR 216). **Exit statuses:**
  when the wait on the agent's pidfd failed, the watchdog's restart loop
  ended, `run()` returned `Ok` and the process exited 0 — which the unit's
  `Restart=on-failure` does not restart: the agent ran on unsupervised,
  with an `info` line as the only trace. Every failure now exits with a
  status of its own (`ExitReason`: 10 hardening, 11 no verified agent, 12
  pidfile, 13 respawn backend, 14 `READY=1`, 15 signal handlers, 20 the
  pidfd wait; 0 only for a stop it was told to make) after a
  `watchdog_exit` record the agent signs. **Unit:** `Restart=always` with
  `RestartPreventExitStatus=0` (a death by SIGHUP was a clean stop),
  backoff 2 s → 60 s (`RestartSteps=`, systemd 254+) and no start limit
  (`StartLimitIntervalSec=0`): the watchdog never stays down, each failed
  run visible through `watchdog_exit` and `watchdog_gone`. `OnFailure=`
  covers what fails the unit itself: the new
  `northnarrow-watchdog-failed.service`, which runs
  `northnarrow-watchdog --record-unit-failure` and records
  `watchdog_failed` with systemd's `MONITOR_*` result (installed,
  packaged, protected and drop-in-checked like the other units). The agent
  signs `watchdog_gone` when the watchdog it verified no longer runs.
  **Stuck recovery:** a failed recovery was handled as a death — evicted
  from `PROTECTED_PIDS`, pidfile removed, respawn — with the agent maybe
  alive, and it re-registers its pid only at its start; the eviction even
  came before the SIGKILL. The verdict is now the agent's own pidfd: only a
  confirmed exit is evicted (after it), a live agent keeps its protection
  and its pidfile and stays supervised (`stuck_recovery_failed`,
  `DEGRADED` status), and the wait after SIGKILL is bounded (10 s).
  **Liveness:** the STATUS ping was answered by the admin socket's task,
  which runs beside the event loop; the ping now also reads the loop's
  round count (new unsigned `LoopProgress` request, indices 52/53), and
  three answers in a row without a round since the one before (90 s or
  more) are a stuck agent (`event_loop_stalled`, then recovery). An agent older than the request
  closes the connection and is pinged as before. **Hold:** still no
  respawn loop, but bounded and visible — a `STATUS=` line with its
  length and next retry, an ERROR every 10 minutes, one retry after 10,
  20, 40 minutes and then hourly (`hold_retry`; it supersedes WDG-004's
  "only an operator starts the agent again"), its end recorded
  (`hold_ended`). **Hardening:** the agent is not dumpable
  (`PR_SET_DUMPABLE` 0, `RLIMIT_CORE` 0 at its start; the watchdog
  already was), both units set `LimitCORE=0` and an explicit
  `TimeoutStartSec=` (agent 180 s, watchdog 60 s, above its own 30-s
  deadline), `/run/northnarrow` is 0700 whoever creates it (install.sh
  made it 0755; the watchdog unit and the handler declare the runtime
  directory too, the watchdog creates a missing one 0700). Tests: exit
  statuses and their records, a real failed pidfd wait, the recovery
  verdict on a live and a SIGINT-ignoring process, the loop-stall tracker
  and the two-frame ping, the hold schedule, the unit contract (with an
  offline `systemd-analyze verify` of the three units), install.sh's
  0700 and the handler's shipping.
- BPF self-defence: the `bpf` command numbers and the deny hooks' fail-opens
  (capability C23, Wave 4, lab PR 215; from the static review of `baf4c25`,
  P0 C-02 / G-01 / TD-03, not in the audit tracker). The `bpf` LSM hook had
  its own copy of the uapi `enum bpf_cmd` numbers, with
  `BPF_LINK_GET_FD_BY_ID = 31`; the uapi value is 30, and 31 is
  `BPF_LINK_GET_NEXT_ID` (counting the enumerators by hand gives 31, because
  `BPF_PROG_RUN = BPF_PROG_TEST_RUN` takes no number of its own). A handle
  on one of the agent's links taken by id (`bpftool link show id N`, the
  first step of `bpftool link detach id N`) was therefore granted in enforce
  mode and left no record, in either mode. The enumeration `bpftool link
  list` steps through (`LINK_GET_NEXT_ID`) was refused when it started from
  one of the agent's link ids, and recorded as an anti-tamper denial
  (NN-L-AT-001, posture COMBAT) although it gives no handle. `bpf_cmd_name`
  repeated the 31, so the real handle by id was "other" in the records, the
  ADE context and the XAI evidence. Detaching or updating a hook stayed
  impossible: the detach/update deny (EBPF-010) reads the link from the fd,
  and the kernel refuses both on these link types. **Fix:** every `bpf_cmd`
  number is defined once, in `common/src/bpf_cmd.rs` (`no_std`, compiled by
  the eBPF programs and the agent): the hook, `bpf_cmd_name`, the BPF rules
  and the agent's `OBJ_GET` and `MAP_FREEZE` wrappers read it, and the
  hook's set of observed commands is `bpf_cmd::observed`, which the host
  tests check (no `*_GET_NEXT_ID` in it). Tests: every number against the
  build host's `/usr/include/linux/bpf.h` (a parser that follows C's enum
  rules, aliases included) and against `enum bpf_cmd` in the running
  kernel's BTF; with 31 put back both fail and name it. A source scan fails
  when anything else in the tree defines one of these numbers as a constant
  (on the starting tree it lists 22 such constants; the 23rd copy, the match
  in `bpf_cmd_name`, fails the names test). Now in enforce mode `bpftool
  link show id N` on one of the agent's links is refused and recorded
  (`deny=bpf_link`); the enumeration is neither refused nor recorded.
  `bpftool link list` as a whole still takes a handle by id on every link it
  prints, so in enforce mode it lists the host's other links and stops at
  the first NorthNarrow link with one recorded denial, like `bpftool map
  show` (the documented trade-off; before, it stopped one link later, at the
  refused enumeration). **Fail-opens counted:** a deny hook that could not
  read what it needs to decide let the operation through and left no trace
  (`Err(_) => return 0` in `task_kill`, `ptrace_access_check`, the inode,
  file and xattr hooks, the map guard, the `bpf` hook's link checks). Each
  of the 20 hooks now has a slot in a new per-CPU map, `DENY_FAIL_OPEN`
  (`common/src/fail_open.rs`, append-only). A failed read, an unknown
  argument position, an unreadable `OBJ_GET` path and a link the
  detach/update deny cannot read bump it; a NULL the kernel holds there (a
  negative dentry, an fd that names no link) does not. The agent reads it
  every 10 s, logs `deny hook FAILED OPEN` at WARN, writes a signed
  `deny_fail_open` audit entry (the first of a hook at once, then at most
  one per hook every 10 minutes carrying every fail-open since the previous
  entry), and reports `deny_fail_open_total` / `deny_fail_open` in the
  signed `status` (`nn-admin status --key`: `deny fail-open : 0`; "not
  counted" when the object exports no counters, which is also a signed
  `subsystem_degraded`). The posture is not raised: a fail-open says a hook
  could not decide, not that someone tried something. The map is one of the
  agent's own, so the BPF guard refuses write handles on it (tamper-check
  C43 asks for one). Lab: `anti-tamper.sh` C63 (a handle by id on one of the
  agent's links: refused and recorded in enforce mode, granted and
  NN-L-BPF-002 in observe mode) and C64 (`LINK_GET_NEXT_ID` from each of the
  agent's link ids and a walk from 0: allowed, no `deny=bpf_link` and no
  NN-L-BPF-002), through new modes of the link probe (`--own` reads the
  agent's link ids from `OWN_BPF_IDS` with read-only handles,
  `--handle-by-id`, `--next-from`; its numbers come from `<linux/bpf.h>`);
  `--selftest` checks the id parser and the probe's argument handling. The
  enforce-mode privileged e2e
  (`bpf_guard_enforce_refuses_protected_pids_write`) also asserts the handle
  by id refused with `EPERM` and `op=bpf_link` in the log, and the
  enumeration from each of the agent's link ids not refused. **Regression:**
  the two status fields are appended after lab PR 207's: an `nn-admin` of
  this release cannot read an older agent's status (exit 5); upgrade the
  binaries together (the watchdog's ping reads the two leading fields only
  and is not affected). Operator guide §3.2, §3.3 (links) and §3.5
  corrected: the guide said every handle by id on the agent's links was
  refused, which was not so.
- External audit, Wave 3, the status split and correlation chain retention
  (Low ASK-009 NN-AUD-237, NETR-014 NN-AUD-297; lab PR 213). Two product
  decisions, taken as the triages recommend, the conservative way that
  keeps what works. ASK-009: `status` was served without a signature or a
  record and, since the audit, also gave the ring drops and rejected
  records, the netflow pacing and evictions, `FLOW_SOCK_MAP`, the inactive
  network rules, detect-only, the COMBAT evidence gaps and the
  encrypted-flow counts — with the agent's maps closed to root by the BPF
  guard, the easy feedback of a ring flood. **Decision:** the unsigned
  `status` keeps what the watchdog and COMBAT recovery read (the posture,
  the isolation, the last admin action, the COMBAT stage and lock) and
  sends `None` for the rest (same shape, `StatusResponse::public`); the
  rest comes from a new signed verb, `TelemetryStatusRequest` (op 25,
  appended before the debug-only variants), 1-of-N, `audit-read` or
  `telemetry-read` (`triage` and `all` imply it), one `telemetry_status`
  audit row per request without the counters. `nn-admin status --key` and
  `nn-admin net status --key` use it; without a key `status` prints the
  public fields and a line saying the telemetry is withheld and how to read
  it, `net status` that line only, and `--json` gains `telemetry_signed`.
  The unsigned polling is recorded: one signed `status_polled` row per peer
  (uid and the comm it gives itself) per hour, at its first request, with
  the count of its previous hour; the registered watchdog is left out by
  the pid the agent verified (pidfile, executable, start time: the one it
  puts in `PROTECTED_PIDS`), never by comm; 64 peers are tracked, the rest
  share one window. The watchdog's ping is still the unsigned `Status` and
  still judges latency only, but reads just the reply's variant and its two
  leading fields (`decode_status_liveness`): it no longer depends on the
  fields appended to the status, and a watchdog newer than the agent reads
  an older agent's reply (the known follow-up, closed for the watchdog).
  `deploy/lab/soak/sample.sh` reads the drops with the lab's key; a sample
  it could not read is left empty and `nn-lab.sh soak report` fails the run
  (it wrote 0). Alternatives not taken: `telemetry-read` alone (the
  triage's wording) — the default allowlist and the key `install.sh`
  bootstraps hold `audit-read`, not it, and adding it takes a `rotate-keys`
  quorum the install key cannot sign: every existing install and the lab
  soak would have lost the counters, which are no more than what an
  `audit-read` key reads in the signed audit log; detect-only left public —
  it tells a local root whether a kill will follow (the signed `agent_boot`
  entry and `--key` keep it for the operator); one row per unsigned request
  — the watchdog pings every few seconds. NETR-014: every chain precursor
  expired after 300 s, so a credential read or a canary trip followed by an
  egress five minutes later gave nothing. **Decision:** retention per
  precursor kind — a credential read and a canary trip are kept 30 minutes,
  a staging-directory exec and a `sudo`/`su` 300 s as before; CHAIN-001,
  -003, -004 and -006 grade by age: within 300 s the Critical
  `KillProcessTree` verdict, unchanged; from 300 s to 30 min one **High
  `Log`** record per precursor (no response, no COMBAT; its reasoning gives
  the age). CHAIN-002, -005, -007 (whose first step is the staging exec)
  and -008, and the review-70 late completions, keep 300 s; the 4096-process
  and 16-precursor caps are unchanged; the netflow limiter keeps evaluating
  a process whose read could still give its record, not once it has.
  Alternative not taken: the Critical kill for the whole 30 minutes (the
  triage's risk: a backup client or an agent-style helper killed up to 30
  minutes after it read its own credentials, with no false-positive
  baseline yet). The triage's one-hour false-positive baseline on Ubuntu
  24.04 is owed to the lab before merge.
  **Regressions / changes:** an unsigned `nn-admin status` no longer prints
  `response mode`, `combat evidence`, `ringbuf drops` and `ringbuf
  rejected` (`--json`: `null`), and `nn-admin net status` without `--key`
  prints one line (exit 0): a script or monitor that reads them needs
  `--key` with an `audit-read` key, one `telemetry_status` audit row per
  call; the audit log gains at most one `status_polled` row per polling
  peer per hour. An `nn-admin` older than this agent reads its unsigned
  status (same shape) and shows the withheld counters as absent; this
  `nn-admin --key` against an older agent fails (exit 5: no such verb), and
  a newer `nn-admin` still cannot decode an older agent's status. In
  `debug-trigger` builds the two debug-only variants move from 50/51 to
  52/53: build the lab's `nn-admin` and agent together. A credential read
  (FIM-watched store, not wide-coverage) or a canary trip followed by an
  egress 5 to 30 minutes later now draws one High record and a `VERDICT
  (rule)` WARN where nothing was; within 300 s nothing changes; such a
  process's flows skip the netflow pacing for up to 30 minutes instead of 5
  until its record is given.
- External audit, Wave 3, operator-facing correctness (Low ASK-015
  NN-AUD-241, AUT-007 NN-AUD-247, AUT-013 NN-AUD-250, MAIN-016 NN-AUD-258,
  EVD-016 NN-AUD-279; Info ASK-018 NN-AUD-424; lab PR 212). ASK-015: a
  production `force-posture` logged the state it entered as `from`
  (`from=Observing to=Observing` when it left COMBAT) and its audit row
  had only the target. The posture machine returns the state it left, read
  under the transition's lock (`ForceOutcome`); the journal line names it
  and the row's `extra` gains `"from"` when the force was applied (a
  refused force changed nothing and has none). ASK-018: `nn-admin
  detections --path` matched the process name (`comm`) only, so `--path
  /usr/bin/curl` found nothing; a record is now kept when its executable
  (`exe`), its file (`file`) or its `comm` contains the text — a superset
  of before, no wire change, and the help says so. AUT-013: `rotate-keys
  add --new-roles unlock,,audit-read` skipped the empty entry the agent
  refuses in `admin.pub`; the list goes through the agent's parser and is
  refused with its words (spaces around an entry are still trimmed).
  AUT-007: the help of `shutdown` and `rotate-keys` said both signers need
  the role; the agent asks it of one, the co-signer may be any installed
  key (design §3.3). The help, `admin_cli` and design §3.3/Appendix B say
  so and ask that every installed key be kept as a control credential;
  requiring the role of each signer is declined (installs whose co-signer
  carries the default `unlock,audit-read` would stop working). MAIN-016:
  the agent's `READY=1` and the watchdog's `READY=1`/`STATUS=` were sent
  to `$NOTIFY_SOCKET` as a path, so an abstract socket (`@name`) never got
  them and a `Type=notify` start would time out. One sender shared by both
  (`common::sd_notify`) sends to `/path` and to `@name`, reads a value that
  is not UTF-8 instead of taking it as unset (nothing was sent, and
  nothing said so), and refuses any other value (`vsock:`, a relative
  path) with an error. EVD-016: no code change, the residual is recorded:
  the install manifest is not signed (`install.sh` writes it on the host,
  so a release signature cannot cover it); recording its SHA-256 in
  `agent_boot` stays a later option.
- External audit, Wave 3, lab and range host safety (Low LAB-019 NN-AUD-409,
  LAB-022 NN-AUD-412, LAB-025 NN-AUD-415, LAB-027 NN-AUD-417; lab PR 211).
  The lab and range scripts no longer harm the host they run on. LAB-025:
  every connection `nn-lab.sh` made to a guest (ssh, rsync, scp) took any
  host key, so whatever listened on the forwarded `127.0.0.1` port while
  the guest was down — another user's process, a forwarder to another
  guest — was taken for the guest, and `sync` sent it the tree. Each guest
  now has its own `known_hosts` (alias `nn-lab-<guest>`, ed25519 only, the
  lab key only offered), checked strictly from the first connection: `up`
  generates a new guest's host key and injects it through cloud-init
  (`ssh_keys:` in the four templates; the private half only in the
  user-data and seed, 0600), so nothing is trusted on first use; a guest
  whose disk predates this has its key recorded once by `up`, and only
  while the port is served by the guest's own QEMU (its pid file) or whpx
  forwarder unit (`ss -ltnp`, before and after the scan);
  `nn-lab.sh trust-host-key` records the running guest's key again on
  purpose. Without a recorded key nothing connects and the command says
  so; a key that is not the guest's is reported as such, not as "not
  running"; `down` refuses rather than leave the guest to be killed;
  `destroy` forgets the key. rsync's `-e "ssh ${SSH_OPTS[*]}"` broke on a
  space in a path: the options are quoted for rsync now. LAB-022:
  `open-sensor-check.sh` overwrote `~/.aws/credentials` and `rm -rf`-ed
  `~/.aws` wherever it ran. It refuses a host that is not a lab guest
  (`/var/lib/nn-lab-provisioned`) unless `NN_TEST_DISPOSABLE_HOST=1`, moves
  an existing `~/.aws` (never followed if a link) aside and puts it back at
  the end of the step and on every way out (error, Ctrl-C, TERM, HUP, a
  closed pipe), removes only its own fixture, and stops before touching
  anything when a previous run left `~/.aws.nn-open-sensor`. LAB-019: the
  superseded range teardown (`docs/adversarial/scripts/07_teardown.sh`)
  printed "disks kept0" for `KEEP_DISKS=0` and deleted them, nothing under
  `FORCE=1`, and deleted for any other value; `KEEP_DISKS` is 0 or 1, the
  printed line, the prompt and the branch say the same, and a hard disk
  outside its VM's folder stops the teardown before anything is powered
  off. LAB-027: `deploy/adversarial/bootstrap-target-prod.sh` built
  whatever the tree held, through the build user's login profiles, and
  installed it as root with no record. Before step 1 stops anything it
  now refuses a dirty tree (untracked files included; `NN_ALLOW_DIRTY_TREE=1`
  is recorded), a HEAD other than `NN_EXPECT_COMMIT`, cargo configuration
  git does not see, and a tree or parent directory not the build user's
  or writable by others; the build runs with a clean environment and an
  explicit `BUILD_PATH`; `/root/range-provenance.txt` records the commit,
  the tree's state and the sha256 of the three installed binaries, each
  checked equal to the build. Tests: `xtask/tests/lab_host_safety.rs` (16;
  all fail on the starting scripts).
  **Regressions / changes:** an existing guest has no recorded host key:
  run `nn-lab.sh up` (also on a running guest) or `nn-lab.sh trust-host-key`
  once per guest; a guest recreated by an older `nn-lab.sh` needs
  `trust-host-key`. `open-sensor-check` exits 2 off a lab guest. The range
  bootstrap needs a committed tree (or the recorded override).
- External audit, Wave 3, BTF matrix downloads and release governance (Low
  SUP-013 NN-AUD-398, SUP-014 NN-AUD-399, SUP-021 NN-AUD-405, SUP-024
  NN-AUD-408; lab PR 210). The BTF matrix fed third-party blobs to the
  product's BTF parser as the archive's moving `main` served them, and a
  release could start from any `v*` tag and overwrite published assets.
  SUP-014: `deploy/btf-matrix/blobs.sha256` pins one BTFHub archive commit
  (`ed9772c5dd12`, the archive's head of 2026-10-01) and the sha256 of each
  of the nine archives (the kernels the weekly run already used).
  `run.sh` downloads them at that commit only (`https` only, 64 MiB at
  most) and checks the digest before anything opens the file; a cached
  copy is checked again at every run (one that no longer matches is
  deleted and downloaded again), and nothing that fails a check is left in
  the cache. The archive must hold exactly one regular file,
  `<kernel>.btf`, read through `tar -O` (no member name, owner, mode or
  link from the archive reaches the disk; 512 MiB at most).
  `run.sh --refresh [COMMIT]` lists the archive (default: its head,
  resolved to a commit), refuses names outside `[A-Za-z0-9._+-]`, checks
  the newest non-cloud blobs the same way and prints a new `blobs.sha256`
  for a bump PR. The workflow's blob cache is keyed by that file and is no
  longer restored from any `btfhub-blobs-` key. SUP-013: a distro/version
  of `expected.tsv` left without a blob (none pinned, or none in a
  refreshed listing) was a green `n/a` row; it is now a REGRESSION row and
  fails the run. SUP-021: `GITHUB_TOKEN` was on curl's command line; the
  matrix now calls no API and gets no token, and `--refresh` passes the
  token in a header curl reads from a file descriptor (or lets `gh` use
  its own). `deploy/btf-matrix/run-test.sh` tests all of this offline (stub
  curl, gh and agent, a local directory as the archive), in the CI test
  job and before each matrix run. SUP-024: a new `verify-tag` job runs
  first on a tag, and `package` — hence every later job — waits for it:
  the tag must be annotated, name itself, point to the commit built and
  carry an SSH signature that `git verify-tag` accepts against
  `.github/allowed_signers` (`.github/scripts/verify-release-tag.sh`,
  whose selftest runs on throwaway keys). Publishing moved out of `sign`
  into a `publish` job (tags only, `release-signing` environment,
  `contents: write` and nothing else), so no job holds both
  `contents: write` and the OIDC token; it creates the release as a draft,
  refuses a release that already has assets, uploads without `--clobber`
  and publishes the draft last. CONTRIBUTING.md says how a tag is signed
  and checked. Two-person review (CODEOWNERS) stays declined while there
  is one maintainer.
  **Regressions / changes:** `.github/allowed_signers` lists no key yet, so
  every tag stops at `verify-tag`, before any build, until the maintainer
  adds the public half of a tag-signing SSH key (upgrade notes §9); an
  OpenPGP-signed tag is refused. Publishing a release again needs its
  deletion first. Kernels archived after the pin reach the weekly matrix
  only through a bump PR. `run.sh` takes its distro/version list from
  `expected.tsv` (the `KERNELS` array is gone) and gains `--pins`,
  `--expected`, `--no-host` and `--refresh`.
- External audit, Wave 3, operator documentation and compliance (Low
  DEP-013 NN-AUD-385, DEP-018 NN-AUD-390, DEP-021 NN-AUD-441, SUP-019
  NN-AUD-403, SUP-020 NN-AUD-404, LAB-028 NN-AUD-444 guard; lab PR 209).
  DEP-013: the grub step that the install banner, the install guide and the
  kernel guide sent operators to (`docs/TAPPA7_PREREQ.md`) wrote a fixed
  `lsm=` list taken from one Ubuntu host; `lsm=` replaces the kernel's own
  list, so a RHEL-family host would have rebooted without SELinux.
  `docs/operator/KERNEL_COMPATIBILITY.md` now has "Enabling the `bpf`
  LSM": the list is the `lsm=` the kernel was booted with, or else
  `CONFIG_LSM`, plus `bpf`; a module running now that the list leaves out
  stops the procedure; an `lsm=` already in the grub configuration is
  edited, never doubled; `update-grub` through a drop-in on Debian and
  Ubuntu, `grubby` on the RHEL family; after the reboot the running list
  must differ by `bpf` alone, with SELinux enforcing or AppArmor on as
  before; and how to undo it. The banner, the guides, the README, the
  integration runbook and the `nn-admin host-check` hint point there, and
  say never to write a fixed list. DEP-018: the banner and four guides
  named documents the release does not ship (`docs/TAPPA7_PREREQ.md`, the
  design notes, the audit tracker, `docs/PERFORMANCE.md`,
  `../../CHANGELOG.md`): each now names a guide, a file at the release's
  root, or a `https://github.com/northnarrow/northnarrow-new/blob/main/…`
  URL; for the overlay formats the banner points to the headers of the
  shipped lists and to the install guide's §3.6, and it says where a
  package puts the guides. DEP-021: `docs/TAPPA7_PREREQ.md` is marked as a
  dated historical record: SIGQUIT, "allowed" in its May table, is denied
  like every signal outside a trusted-installer window; the comparison
  with a competitor is gone. SUP-019: `NOTICES.md` paraphrased the ATT&CK
  designation without its year and justified the LOLBAS exclusion by a
  "proprietary distribution" the Apache-2.0 tree does not have. It now
  says which files are under which terms (NorthNarrow's own code under
  Apache-2.0; the ATT&CK and Sigma content; the vendored candle-core, MIT
  OR Apache-2.0, modified; the crates' licences; the eBPF object's own
  `Dual MIT/GPL` declaration), quotes the designation verbatim, and
  records the model the release does not distribute
  (Foundation-Sec-8B-Reasoning: its source, no pin, the Llama 3.1 Community License for the
  Llama 3.1 part and Apache-2.0 for Cisco's changes, what an operator who
  installs or passes it on takes on). `cargo xtask rag-kb` writes only its
  own block of the file now, with the designation read from the pinned
  Terms of Use. The licence field stays `Apache-2.0`, the licence of
  `LICENSE`, with a comment that points to NOTICES. SUP-020: `SECURITY.md`
  states a support period (a `0.0.x` tag is supported until the next tag),
  the procedure for CRA Article 14 once it applies (24 hours, 72 hours, 14
  days or one month, ENISA's single reporting platform, the users told
  through an advisory), and a 90-day embargo limit; `.well-known/security.txt`
  (RFC 9116) names GitHub Security Advisories, the only channel (no e-mail
  address is published yet), and the policy. LAB-028, the guard: a
  registry test fails when the V2 sweep document loses its HALT while
  matrix.md has no data row or no run directory exists, and when a row
  cites a run directory that is not there or has no `SHA256SUMS`; the
  campaign itself is still to run.
  **Regressions / changes:** step 4 of the install banner and the
  `host-check` hint for `bpf_lsm` read differently; `cargo xtask rag-kb`
  refuses a `NOTICES.md` without its block markers (and writes nothing);
  `.well-known/security.txt` expires on 2027-10-01 and a repository test
  fails from that day until it is renewed.
- External audit, Wave 3, developer tooling hygiene (Low WDG-016
  NN-AUD-365, WDG-018 NN-AUD-367, WDG-R02 NN-AUD-368, WDG-R10 NN-AUD-376,
  WDG-R11 NN-AUD-377, WDG-R16 NN-AUD-439; lab PR 208). The developer
  examples and tools hold no trap. WDG-R02: `PostureMachine::admin_release_combat`,
  the bool stub that leaves COMBAT without a signed token (no release hook,
  no admin action recorded), was public API under the `posture-demo`
  feature; it is a `#[cfg(test)] pub(crate)` helper of the unit tests now.
  `examples/posture_demo` no longer calls it: it reached ENGAGED only since
  POS-015 made a plain `/tmp` exec an ENGAGED-tier signal, so its release
  would have panicked on `NotInCombat`; it now reaches a locked COMBAT on a
  kernel anti-tamper denial, shows that decay does not leave it a day
  later, and ends there (the way out is `nn-admin unlock`). WDG-016: the
  unshipped `northnarrow` CLI stubs printed "Not implemented yet" on
  stdout and exited 0; they say on stderr that nothing was done and exit
  69 (`EX_UNAVAILABLE`), naming `nn-admin`. WDG-018: `cargo xtask run`
  started the agent with `sudo -E` (the developer's whole environment,
  `NN_AUDIT_ALLOW_UNWRITABLE` and the other `NN_*` variables the agent
  reads included, handed to root) and `to_str().unwrap()` on its path; it
  passes `--preserve-env=RUST_LOG --` and the path as an `OsStr`.
  WDG-R10: `ade_smoke` defaulted its model to a developer's home; it takes
  `ADE_MODEL`, else `AdeConfig::DEFAULT_MODEL_PATH`, and the test
  fixtures with that home (`posture/triggers.rs`, `lineage.rs`, and lab PR
  198's in `mass_write_overlay.rs`) use `/home/alice`. WDG-R11: `verify_chainlog` documented `sudo cargo
  run`, which compiles and runs the dependency graph's build scripts as
  root; it is built as the developer and only its binary runs under
  `sudo`, and its doc points to `nn-admin chain verify --log fim-drift
  --agent-pubkey` for an off-host key (WDG-013's residual: the example
  itself still trusts the host's published half). WDG-R16: `diag_hw` and
  `docs/PERFORMANCE_HARDWARE.md` keep a host's report with the host's
  records; the document holds the reference host only. Two repository
  lints (`xtask/tests/repository_hygiene.rs`) keep it so: no `/home/<name>`
  or `/Users/<name>` outside a list of fixture names in the sources,
  scripts and configuration (Markdown excluded), and no `cargo` under
  `sudo` in `agent/examples` and `docs/operator` (a lab note of
  `KERNEL_COMPATIBILITY.md` reworded).
  **Regressions / changes:** `northnarrow <cmd>` exits 69 instead of 0;
  `cargo xtask run` keeps only `RUST_LOG` across `sudo`; `ade_smoke`'s
  default model path is `/var/lib/northnarrow/models/…`; the posture demo's
  output ends in COMBAT. The `posture-demo` feature compiles nothing into
  the agent any more and only builds the demo (kept: the demo's
  `ProcessSpawn` builds again once lab PR 187's two fields reach it).
  Tests: `cli/tests/stubs.rs` (1), `xtask` `agent_command` (2),
  `xtask/tests/repository_hygiene.rs` (3); on the starting tree the CLI
  test and the two lints fail (exit 0; the developer's home in six lines;
  `sudo cargo run`), the `agent_command` tests do not compile (new item).
- External audit, Wave 3, network blind spots and drain consistency (Low
  NET-017 NN-AUD-335, NET-020 NN-AUD-434 part (3); lab PR 207). NET-017:
  the agent never said what its network rules cannot see. The DNS rules
  (NN-L-NET-002, -004, -005, -014) read the queries sent to UDP/53 and
  nothing else; they are now declared blind where they are, without
  inspecting the traffic (`net/blind_spots.rs`). The drain counts the
  netflow rows to TCP/853 (DNS over TLS), split into the local resolver's
  (systemd-resolved, unbound, stubby…, by image, never by comm) and the
  other processes' (which resolve names past the resolver whose queries
  the rules read), and the rows to UDP/443 (QUIC, whose TLS handshake no
  fingerprint reader can see); `nn-admin net status` prints them with
  what they mean, and says DNS over HTTPS is not counted (HTTPS to a
  resolver looks like any web traffic). When systemd-resolved's
  `DNSOverTLS=` is `yes` or `opportunistic` — read from `resolved.conf`
  and its drop-ins as resolved reads them (the first main file of `/etc`,
  `/run`, `/usr/local/lib`, `/usr/lib`; drop-ins by name, a higher
  directory hiding a lower one, a `/dev/null` link masking; the last valid
  `[Resolve]` assignment wins, an empty one resets), files capped at 64
  KiB, a FIFO or device skipped without blocking — `net status` lists
  "NN-L-NET-002/004/005/014 (DNS): blind to the local resolver's upstream"
  with the file, and the agent says so in a WARN at boot. The setting is
  read again at each status request, so the list follows a change without
  a restart. Not covered, and said in the code: per-link DoT (networkd,
  NetworkManager, `resolvectl dnsovertls`), which the TCP/853 count still
  shows; ECH (with the ClientHello producer, BUG-025). NET-020 (3): the TCP
  close decoded the kernel's comm with `from_utf8_lossy` and trimmed only
  the trailing NULs, while the connect, UDP and listener paths stop at the
  first NUL, so `curl\0Xvil` (a byte left after a shorter
  `PR_SET_NAME`) gave the TCP row and its journal line another name than
  the other rows, and the comm allowlist saw either. Every branch now
  decodes once, up to the first NUL; with lab PR 202's part (2),
  NN-AUD-434 is closed.
  **Regressions / changes:** the `status` reply gains three trailing
  fields (`net_dot_rows_total`, `net_dot_rows_resolver`,
  `net_quic_rows_total`, after lab PR 193's): an older `nn-admin` or
  watchdog reads a newer agent's reply, but a newer `nn-admin` or watchdog
  cannot decode an older agent's (postcard has no field count; a known
  follow-up): upgrade them together. `nn-admin net status` prints three
  more lines and its `--json` three more keys; `net_inactive_rules` can
  hold a second entry; a TCP row's `comm` can be shorter than before for a
  comm with bytes after its NUL.
- External audit, Wave 3, lab verdict integrity (Low LAB-020 NN-AUD-410,
  LAB-024 NN-AUD-414, LAB-026 NN-AUD-416; lab PR 206). The lab's verdicts
  are what it saw. LAB-020: `nn-lab.sh upgrade-check` passed with seven of
  the new agent's own LSM programs, against 16 deny hooks plus the
  observers. It now wants the new agent's own health line (`anti-tamper:
  all LSM hooks attached`, `deny_attached` equal to `deny_expected`, at
  least the 16 of `DENY_HOOKS`; an xtask test keeps the two numbers equal),
  no fewer own LSM programs than before the upgrade (an observer lost fails
  too) nor than the deny hooks, and no anti-tamper `subsystem_degraded`
  signed at the upgraded boot (a start under
  `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`, a missing observe hook; other degraded
  records are printed). The line is read with
  `deploy/lab/lib/lab-records.py` (`python3 -I`, as the lab user, on what
  `sudo journalctl -o json` gives it): an event journald attributes to the
  unit's own stdout and to the agent's pid, with the text at the start of
  its message, never a match anywhere in a line — any user can make the
  agent log a file name that holds the line, and `release-check.sh`'s greps
  counted one. The same helper reads `release-check`'s three agent lines and
  the anti-tamper suite's state lines: the BPF guard mode, an open
  trusted-installer window, C11's drop-in registration and C38's watchdog
  registration (a file named "… watchdog PID registered in PROTECTED_PIDS
  pid=<n>" made C38 pass, and `pid=12` matched `pid=1234`). LAB-024: no
  guest template set `lockdown=`, so C27 never ran and left no row.
  `NN_LAB_LOCKDOWN=integrity nn-lab.sh up` boots a separate guest of the
  distro (its own disk, seed, reports and ssh port, the distro's + 1000, on
  the distro's base image) with `lockdown=integrity` added to the `lsm=`
  line of the four templates (`__NN_LAB_KARGS__`; a template without it is
  refused), and `check` fails on it when the kernel is not locked down.
  Without lockdown C27 is a listed KNOWN GAP; its `finit_module` number is
  the machine's (x86_64 313, arm64 273; elsewhere a not-run deviation),
  where it was 313 everywhere. C17 left no row without kexec-tools, which no
  template installs: it then loads the running kernel with
  `kexec_file_load(2)` itself (the agent refuses both calls, review 82), and
  an image that did load is unloaded, by the trap too. LAB-026: the nightly
  ran none of the security checks; `tamper-check`, `pkgmgr-check`,
  `open-sensor-check`, `fim-reuse-check`, `btrfs-check` and `overlay-check`
  run after `install` (each starts the units it finds stopped;
  `pkgmgr-check` gave up), a step that says N/A reads N/A and a NOT RUN
  fails whatever its exit status, and the report gives each step's verdict
  lines (the anti-tamper rows that are a deviation, a known gap or N/A) and
  the guest's lockdown. `anti-tamper.sh --only` without a value ran every
  case, the destructive ones too, and an id that names no case printed OK:
  it takes case ids only, each must end up as a row, and a run that leaves
  a case out does none of its setup or cleanup (the drop-in removals and
  three `daemon-reload` of C11, C12 and C25, C13's `/mnt/nn-bpf2`, C18's
  `oom_score_adj` write, the probe builds, C34's fresh agent binary, C49's
  file in `/etc`); a probe that did not build is a row only for the cases
  selected, and C43 is listed with C34-C37. The restores hold or fail the
  run: C11's drop-in gone (and its directory when the case made it), C12's
  runtime `MemoryMax` taken back with a `daemon-reload` (`--only C12` left
  the 4G cap in force) and the unit's `MemoryMax` and the cgroup's
  `memory.max` as found, C25's unit back at the installed path, C18's value
  written back to the same process (pid and start time; it wrote -500 when
  it could not read the value) and read back, by the trap too, and
  `/mnt/nn-bpf2` removed. C15 and C16 are rows when they cannot run, and C30
  a deviation when bpftool cannot dump the map (`0 → 0` passed). `nn-lab.sh
  help` printed lines 2–36 of a header that ran to line 65 (it stopped at
  `uninstall-check`); it prints the header to its end. Tests: `xtask/tests/lab_scripts.rs` (10; all fail on the
  starting scripts), `anti-tamper.sh --selftest` 64 checks (40 before),
  `lab-records.py --selftest` 7.
- External audit, Wave 3, ADE measurement and output parser (Low WDG-012
  NN-AUD-361, WDG-017 NN-AUD-366, WDG-R03 NN-AUD-369, WDG-R12 NN-AUD-378,
  WDG-R13 NN-AUD-379, WDG-R14 NN-AUD-380, WDG-R15 NN-AUD-438; lab PR 205).
  Parser (WDG-R14): `VerdictParser` stripped a `<think>` reasoning block
  wherever the marker appeared, so a verdict that quoted a file name such
  as `/tmp/<think>x</think>.bin` lost its head, or read as a block left
  open, and folded to an Escalate Tier1 (noise, never a bypass). A block
  is now the model's reasoning only when it opens before the first `{` of
  the output, as the streaming detector reads it; a marker inside the
  object is text (`docs/ADE_BACKEND_NOTES.md`, upgrade notes §7).
  `ade_attacks` (WDG-017, WDG-R13, WDG-R14): every `Allow`
  is FOOLED whatever its confidence (one at 0.70 or below counted as
  PARTIAL, and the "BLOCKED+PARTIAL success rate" counted it as
  defended); BLOCKED, PARTIAL and FOOLED are reported apart, never
  summed; B4 says the 120-char comm it sends (it announced 5,000), F2 the
  200 repetitions it sends (it announced 1,000); a category H of four
  cases aimed at the output pre-parser (44 attacks); each line and the
  report say which layer answered (the model, the sanitizer before it, a
  malformed output's fail-closed Escalate, a prompt over the window), and
  the refused outputs are printed (first 400 characters). `ade_with_rag`
  (WDG-012, WDG-R03): without a model the stub is an empty file in a
  temporary directory, never at the configured path (run as root it left
  a 0-byte file where the production model belongs); the example prints
  the prompt delta (`assembled_prompt`) and exits 1 unless the two prompts
  differ by exactly the `RAG_CONTEXT:` block; with a model both engines
  share the real backend (it always pinned the mock, which never reads
  the prompt), and on the mock the verdict diff is declared void.
  `bench_threads` (WDG-R12): it printed `avg_tok_per_sec`, the token cap
  times the runs over the time; it reports milliseconds per evaluation
  and evaluations/s, how many outputs closed a verdict before the cap and
  the worker count candle used (a result at another count is discarded),
  refuses a mock run, and kills a subprocess after (runs + 1) × the
  engine timeout plus 300 s (the wait had no bound); the promised mock
  fallback is gone from its comment and from `docs/PERFORMANCE_THREADS.md`.
  `ade_demo` (WDG-R15): its comment and `cargo xtask ade-demo`'s help no
  longer promise a hermetic, deterministic mock run; the final
  p50/p95/p99 name their backend, and a mock run says that it measures
  nothing. The four examples carry tests run by `cargo test --workspace`
  (`[[example]] … test = true`).
- External audit, Wave 3, chain pre-image v3 (Low EVD-007 NN-AUD-273,
  EVD-008 NN-AUD-274, EVD-023 NN-AUD-427; lab PR 204). One agent key signs
  every chain. EVD-008: the rotating logs (detections, status events,
  netflow, FIM drift) hashed every line, data line, terminator or manifest
  row, as `SHA-256(prev_hash ‖ json)`, the same for every log: a line or a
  whole manifest moved from one log to another whose payload has the same
  shape verified there. Every line the agent now writes is format v3
  (`chainlog::CHAINLOG_FMT_V3`, `fmt_ver` 3 in the line, the terminator's
  `rotate` and the manifest entry), signed over `SHA-256(domain ‖ prev_hash
  ‖ json)` with `domain` = `northnarrow/chainlog/<log>/<line type>/v3\0`
  (`chain_domain`; `<log>` from the payload type, `ChainPayload::KIND`:
  `detections`, `status_events`, `netflow`, `fim_drift`; `<line type>`
  `data`, `terminator`, `manifest`); the verifiers dispatch on `fmt_ver` in
  `verify_log_set`, `verify_recent`, `line_is_genuine`, the manifest checks
  and the tail check at open. This is the per-chain tag lab PR 197 left for
  the rotating logs (FIMP-013). EVD-007: the verifiers hashed the decoded
  line, so a key the type does not have, another key order, spaces or an
  escaped spelling decoded to the same line and verified — the signature
  covered the modelled fields, not the bytes on disk. A v3 line, and a
  numbered row (`seq`) of `audit.log` and the canary chains, must be byte
  for byte its own re-serialisation: `LogSetError::NonCanonicalLine`,
  `AuditVerifyError::NonCanonical`, `ChainVerifier::push_line`; at open a
  canary row in that state is not applied, an access row not continued
  from, and no such line is a head. Lines and rows from before keep the
  check they were written under and are counted (`legacy_lines`,
  `non_canonical_legacy`, named in `nn-admin chain verify`'s summary); once
  a log or manifest holds a v3 line, a later line in the old format is
  refused (`LegacyAfterV3`); an unknown `fmt_ver` is named, not hashed.
  EVD-023: the pre-image rule (`entry_hash` and `agent_sig` empty) was a
  `debug_assert!` in `audit::compute_entry_hash`, the canary chains, the
  FIM baseline and the listener log, and nothing in `chain_digest`: a
  release build hashed a row that still carried them. It is an error in
  every build (`chain_anchor::check_unsealed`, the frame check of
  `chain_digest`). Found by the new round-trip test: `serde_json`'s default
  float parser lands one ULP off some 17-digit floats, so a detection whose
  `confidence` (or an audit row whose `extra`) held one did not recompute
  its own hash; the agent builds `serde_json` with `float_roundtrip`.
  **Regressions / compatibility:** no line on disk changes, the v1/v2
  lines and the rows without `seq` verify byte for byte as before (frozen
  v2 and v3 vectors, a 0.0.1-shaped set upgraded in the tests); new lines
  are v3. An `nn-admin` older than the agent reports each rotating log with
  v3 lines `BROKEN` (`entry_hash mismatch`, exit 8): upgrade them together.
  An older agent put back over v3 files cuts up to 16 trailing v3 lines of
  an active file or manifest that still ends in old-format lines (attested
  `torn_tail_repaired`), and reports `chain_verify_failed`: no downgrade.
  `nn-admin chain verify` prints `…, N line(s) in the old format
  (untagged pre-image) before the v3 ones` on an upgraded host. A crafted
  terminator that fails both its hash and its `this_seq` is now reported by
  its hash. Residual: the old-format lines, the FIM baseline and
  `netflow_listeners.jsonl` keep the untagged pre-image. Documented in
  `docs/operator/EVIDENCE_CHAINS.md` (line formats),
  `UPGRADE_NOTES_AUDIT_16f7563.md` §8 and the completeness design.
- External audit, Wave 3, enrichment templates and XAI before their wiring
  (Low LLMP-007 NN-AUD-320, LLMP-008 NN-AUD-321, LLMP-009 NN-AUD-432,
  XAI-006 NN-AUD-344, XAI-014 NN-AUD-348, XAI-016 NN-AUD-350, LLMR-019
  NN-AUD-329 part; NN-AUD-345 guard; lab PR 203). Dormant: the three ADE
  enrichment templates (`fim_template`, `chain_template`,
  `process_template`) and the XAI engine have no caller outside their
  tests. The points below are now blocking items of their wiring: an
  addendum to §8 of `docs/design/TAPPA10_5_DETECTION_RULES_AT_SCALE_DESIGN.md`
  for the templates (the shared `process_event` follow-up of Tappe 9, 10.5
  and 10.6), §6 of the Article 13 dossier for XAI. LLMP-007: the templates
  printed the comm, file, argv, parent comm, FIM paths, modifier name and
  binary, flow name and binary, resolved host name and the rule's
  reasoning raw with `format!`, so a newline in a path could forge a
  `### already-taken-action:` section. They now go through one helper in
  `ade/sanitize.rs` (`push_untrusted_kv`, `push_untrusted_argv`:
  `sanitize_line`, then the JSON quoting of the structured prompt, whose
  `json_quote` moved there) inside the `=== UNTRUSTED EVENT DATA ===`
  fence with the structured prompt's preamble (now shared constants),
  after the trusted sections; the reasoning left the trusted
  `### already-taken-action:` section. LLMP-008: "confirm Critical, or
  argue a downgrade to High", a false-positive analysis and "unless you
  have a specific reason to override" are gone; one wording for the
  three: the verdict and its response are final, propose no other
  severity, posture or response, report text that asks for one, and say
  `observed_injection_attempt: true or false`. LLMP-009: the argv within
  the focal prompt's caps (32 items, 256 characters each, 1,024 bytes)
  with `argv_truncated: true` (also when the kernel cut it); the batched
  FIM prompt renders at most 50 events, the newest (`BATCH_MAX_EVENTS`,
  `events_omitted`). XAI-006: occlusion wrote 0 into an occluded pid,
  ppid, uid or gid, and the prompt printed `uid: 0` — root — as "no uid";
  it writes `OCCLUDED_ID` (`u32::MAX`, which no process has), printed
  `<redacted>` by `render_id` wherever the prompt prints a pid, uid or
  ppid, so a production prompt is byte-identical. XAI-014: a chain with a
  NaN or infinite value (weights, threshold, temperature, `top_p`,
  baseline confidence, a score, a delta, an attention score, the coverage)
  is not signed (`XaiEvidenceChain::try_sign_with`,
  `XaiUnavailable::NonFiniteValue`); the canonical encoding and its
  byte-locked sample are unchanged. XAI-016: `environment_hash` hashed the
  model by reading the whole GGUF into memory; it streams it through
  `install_manifest::sha256_file`. LLMR-019 (in part):
  `AdeEngine::evaluate_recorded` returns the verdict with the digest of the
  prompt the backend got; `XaiEngine::explain` takes that `Evaluation` and
  refuses (`XaiUnavailable::PromptMismatch`, before any probe) inputs that
  rebuild another prompt — it signed a chain over the rebuilt one. Left
  for the wiring: the caller passing the evaluated event and context and
  keeping the digest until it explains. XAI-007 (NN-AUD-345, declined as
  filed): a guard test that the prompt renders neither the real argv nor
  the parent's name.
  **Regressions / changes:** the enrichment templates' byte format changes
  (quoted values, the fence, the reasoning moved, the new question; no
  consumer); `XaiEngine::explain` takes an `Evaluation` instead of an
  `AdeVerdict` (no caller outside tests); an occluded identifier reads
  `<redacted>` in the occluded prompt instead of `0`.
- External audit, Wave 3, TLS and DNS parser conformance (Low NET-007
  NN-AUD-330, NET-008 NN-AUD-331, NET-013 NN-AUD-332, NET-014 NN-AUD-333,
  NET-015 NN-AUD-334, NET-018 NN-AUD-336, NET-020 NN-AUD-434 part (2); lab
  PR 202). Latent: no sensor captures a ClientHello in this build
  (BUG-025, `TLS_FINGERPRINT_PRODUCER` is false) and the DNS response
  parser has no production caller, so nothing the agent records changes
  today; the producer that lands on this code inherits conforming parsers.
  `net/tls_parser.rs`: NET-007, the GREASE test `(v & 0x0F0F) == 0x0A0A`
  accepted 256 values; it is RFC 8701's sixteen (both bytes equal, low
  nibble `A`), so `0x1A2A` or `0x3AFA` stay in JA3/JA4 as in the
  reference tools. NET-008, JA4: no server_name extension is `i` (it was
  `n`, which the specification does not have), and the `d` is the
  extension's presence; without signature algorithms the extension-hash
  input has no `_` (checked against the specification's vector
  `6d807ffa2a79`). Found while checking against the reference: the
  signature algorithms are GREASE-filtered, the ALPN pair reads the first
  protocol name's raw bytes (a non-UTF-8 name was skipped, so the next
  one was used) and prints a byte outside ASCII as `9`, like both FoxIO
  implementations (the specification's text
  asks for a hex form that neither prints; we follow the
  implementations, which make the feeds), a `supported_versions`
  extension without a usable value is `00` instead of the legacy
  version, and DTLS version codes give `00` on TCP as in the reference;
  JA3 reads the last repeated supported_groups / ec_point_formats, as
  `ja3.py` does. NET-013 and NET-020 (2): the cipher list must fit in
  the message before anything is sized from it (the dead `> u16::MAX`
  check is gone); the `u16` list readers are sized by their bytes and a
  list longer than its extension is empty. NET-014: the SNI is canonical
  at the parser (ASCII lower case, trailing dot removed, labels of 1 to
  63 letters, digits or hyphens, at most 253 bytes); anything else,
  two host names, or a list that does not fill its extension is
  `Sni::NonConforming` (`sni()`), so a non-conforming name is a flag, not
  a string of up to 65,535 bytes of the peer's choosing, and reads stay
  inside the declared list. The flag reaches the netflow row with the
  producer: no row carries a fingerprint today, and adding it is a wire
  change. NET-018: the handshake message is reassembled from consecutive
  handshake records by their lengths and bounded by its own length, so a
  ClientHello split over records fingerprints as the unsplit one and
  bytes after the message (in its record or after it) are not read as
  extensions; `parse_client_hello_outcome` returns `Complete`,
  `Incomplete` (a well-formed beginning cut by the end of the buffer) or
  `Invalid` (another record type before the message ends, a record
  version that is not 3.x, an empty record or one over 2^14 bytes, not a
  ClientHello, bytes after the extensions block inside the message).
  `net/dns_cache.rs`, NET-015 and NET-013: `skip_name` refuses the
  reserved length prefixes `01` and `10` (so a label over 63 bytes), a
  name over 255 octets and a compression pointer outside the message;
  the bounds are `n > remaining()`; the answer vector is sized by what
  the message can hold (`answer_capacity`), not `ancount` (a 12-byte
  header reserved over a megabyte). The response parser is kept, not
  deleted: the `dns_records` fuzz target uses it. Reference vectors, none
  computed by our code: eleven ClientHellos of our own, built in the
  tests from explicit fields (a Firefox-like TLS 1.3 hello with and
  without SNI, a TLS 1.2 hello with ALPN h2, Chrome-like hellos with
  GREASE everywhere, with GREASE in signature_algorithms and with a
  first ALPN name outside ASCII, values shaped like GREASE, repeated
  curve extensions, a hello without SNI or cipher, the two JA3 README
  hellos; the SHA-256 of each is pinned), whose JA3 and JA4 come from
  the reference tools run locally on those bytes (salesforce/ja3
  `python/ja3.py` at `502cc63` with dpkt 1.9.8; FoxIO-LLC/ja4
  `python/ja4.py`, the BSD 3-Clause JA4 TLS implementation, at
  `c6469a7` with tshark 4.2.2); the JA4 specification's worked example
  and its no-signature-algorithms vector (JA4.md, BSD 3-Clause); the two
  JA3 README vectors. No code or data of either project is in the
  repository. On the starting code the JA4 of eight of the eleven
  differed from the reference (among them GREASE in
  signature_algorithms, and the non-ASCII ALPN printed `h1` for `99`)
  and the JA3 of the GREASE-shaped one.
  **Regressions / changes:** none at runtime (no producer). For the
  producer: JA4 strings change where listed (`i` for `n`, signature
  algorithm GREASE, ALPN bytes, the hash without signature algorithms,
  `00` versions), JA3 keeps non-GREASE `0x?A?A` values; `extract_sni`
  returns the lower-case form and `None` for a non-conforming name; a
  buffer that ends inside a ClientHello no longer parses as a shorter
  TLS 1.0 hello; a DNS response with a reserved label prefix, a name over
  255 octets or a pointer outside the message yields no address. Tests:
  `grease_filter_matches_rfc8701_exactly`,
  `ja3_keeps_values_shaped_like_grease_that_are_not`,
  `ja3_matches_the_salesforce_readme_vectors`,
  `reference_vectors_are_the_bytes_the_tools_read`,
  `ja3_matches_the_reference_on_our_client_hellos`,
  `ja4_matches_the_reference_on_our_client_hellos`,
  `ja4_matches_the_specification_example`,
  `ja4_extension_hash_omits_the_separator_without_signature_algorithms`,
  `ja4_uses_i_when_sni_is_absent`,
  `ja4_marks_d_for_a_present_but_nonconforming_sni`,
  `ja4_alpn_pair_follows_the_reference_implementations`,
  `sni_is_canonicalised_and_bounded`,
  `sni_reads_stay_inside_the_declared_list`,
  `overlong_extension_lists_give_empty_lists`,
  `ja3_reads_the_last_repeated_curve_extension_like_the_reference`,
  `fragmented_client_hello_yields_the_same_ja3`,
  `trailing_bytes_are_not_parsed_as_extensions`,
  `every_prefix_of_a_client_hello_is_incomplete`,
  `a_broken_record_layer_or_message_is_invalid`,
  `overlong_cipher_list_is_rejected`, `mutated_client_hellos_never_panic`;
  `reserved_label_prefix_is_rejected`, `label_over_63_is_rejected`,
  `answer_name_pointers_must_point_inside_the_message`,
  `huge_ancount_in_a_short_packet_allocates_little`;
  `parse_truncated_packet_returns_none_no_panic` now asserts `None` for
  every strict prefix.
- External audit, Wave 3, engine composition and the release build (Info
  PROC-014 NN-AUD-429, Low PROC-015 NN-AUD-302; lab PR 201). PROC-014:
  `default_rules()`, the rule set the engine tests build, lacked the
  io_uring (NN-L-IOU-001/002) and BPF (NN-L-BPF-001/002) rules that only
  the production builder `default_rules_with_net` registered, so no engine
  test saw them and nothing held the two builders to one composition. Both
  families are now in `default_rules()` too, over its empty process
  allowlist (their built-in known programs still apply), at the production
  builder's place (after R018, before FIM): 77 rules under 76 ids.
  `production_engine_pins_all_rule_ids` builds the engine as `main.rs`
  does, over empty operator state, and requires the id sequence of
  `default_rules()`, which `default_engine_pins_all_seventy_six_rule_ids`
  pins; `both_builders_keep_the_family_order` pins the order of the
  families (the chains that observe first, the process rules in
  `spawn_rules` order, R018, io_uring, BPF, FIM, canary, net, CHAIN-008
  last) and the process rules' precedence;
  `io_uring_and_bpf_events_reach_their_rules_in_both_engines` sends the
  four rules their events. PROC-015 (what remained): a `demo-tappa5` build
  refuses to start in enforcement unless `NN_ALLOW_DEMO_RULES=1`
  (`decision::engine::demo_rules_gate`, checked once detect-only is
  resolved, before any response runs; detect-only starts), and the
  variable is a weakening variable (`WEAKENING_ENV`: a signed
  `integrity_drift` in a demo build, the only one that reads it). The demo
  engine is the production engine with R901..R904 put first
  (`RuleEngine::with_demo_tappa5_first`), no longer the demo rules over
  `default_rules()`, which has no operator blocklist or allowlist.
  `--build-features` and the signed `agent_boot` entry name `posture-demo`
  too (`audit::LAB_FEATURES`); `agent/tests/build_features_cli.rs` holds
  that list to the `[features]` of `agent/Cargo.toml` (every feature
  named, `default = []`). `release.yml`: a package-job step, "No lab
  feature in the released binaries", extracts the tarball, the .deb and
  the .rpm and fails unless each `northnarrow-agent --build-features`
  prints `none` and each `nn-admin --help` lists no `debug` subcommand,
  before the artefacts are uploaded;
  `xtask/tests/supply_chain.rs::the_release_build_carries_no_lab_feature`
  requires that step, after the packaging and before the upload, and a
  release build that passes no cargo feature.
  **Regressions / changes:** an engine built from `default_rules()` (the
  engine and ADE tests) also records io_uring and BPF events (Log only);
  tests that count its rules count 77; a `demo-tappa5` agent started
  without `--detect-only`, `NN_DETECT_ONLY` or `NN_ALLOW_DEMO_RULES=1`
  exits at start with the reason, and one that starts runs the operator's
  blocklists and allowlists, the io_uring and BPF rules included; a
  `posture-demo` build's `--build-features` prints `posture-demo` (the
  range bootstrap refuses it, as anything but `none`); the release job
  installs `cpio`.
- External audit, Wave 3, fuzz targets that can fail and fuzzing/proofs as
  PR gates (Low WDG-014 NN-AUD-363, WDG-R04 NN-AUD-370, WDG-R05 NN-AUD-371,
  WDG-R06 NN-AUD-372, WDG-R07 NN-AUD-373, WDG-R08 NN-AUD-374, WDG-R09
  NN-AUD-375, SUP-018 NN-AUD-402, SUP-023 NN-AUD-407; lab PR 200). The fuzz
  targets mostly asserted "no panic", and several could not reach what
  they claimed to test. Every target now asserts what its parser promises
  (`fuzz/README.md` lists the property of each), so a wrong answer fails
  as a crash does. WDG-R05: the `install_manifest` target passed
  `/proc/self/exe`, which never runs from a manifest's `bin_dir`, so every
  input ended "not applicable" before any hash; it now checks against a
  fixed fixture directory (`fuzz_api::install_manifest_check_in_dir`) and
  asserts that `Verified` means every recorded hash matches. The harness
  showed an agent defect: the boot check hashed `bin_dir.join(name)` for
  any key of the manifest's `files` map, and a join with an absolute name
  drops `bin_dir` (`/dev/zero` hung the boot check, `../` reached any
  file); only the four names `install.sh` records are compared now, any
  other is a mismatch and is never opened (`RECORDED_NAMES`). WDG-R04: new
  `ade_verdict` and `ade_preparse` targets on the ADE model output (an
  accepted verdict meets the schema rules a response relies on and parses
  again from its own JSON; the pre-parser is a separate function,
  `preparse`). WDG-R07: `dns_records` also drives `decode_dns_qname` and
  checks that the name reads back as the wire labels byte for byte, with
  unit tests for a self-pointer, a 128-pointer chain, a label past the
  buffer and 255 bytes without a root label. WDG-R08: the TLS target
  computes JA3 and JA4 on every accepted hello and checks their shape,
  with zero-cipher, zero-extension, empty-ALPN and 4,096-extension tests.
  WDG-014: a `shutdown_marker` target runs the watchdog's marker check
  against a fixture (`fuzz_api`): a marker it honours must carry a
  shutdown the fixture keys signed, at most the signature cap, two signers
  with the `shutdown` key, and must be refused as a replay. AUT-011
  (NN-AUD-249, declined) gets the pin its triage offered:
  `decode_cbor_rejects_deeply_nested_input` (10,000 nested arrays are
  ciborium's `RecursionLimitExceeded`), and the marker target replays such
  a payload. WDG-R09: `canary_template` and `install_manifest` wrote
  `$TMPDIR/nn-fuzz-*-<pid>` with `fs::write` and never removed it; one
  private `tempfile` directory per process, files created exclusively,
  removed at exit. SUP-018 / WDG-R06: committed seeds for every target
  (`fuzz/seeds/<target>/`, checked by `fuzz_api::tests` to reach the
  assertions) and inputs of fixed bugs (`fuzz/regressions/<target>/`,
  each failing its target with the fix reverted); the CI fuzz job replays
  both with `-runs=0` and a 25 s timeout, then smokes from a corpus
  cached between runs and the seeds; an xtask test requires seeds for
  every `[[bin]]`. SUP-023: `kani.yml` runs on the pull requests that
  touch a proved file (`tls_parser.rs`, `admin_quorum.rs`, and the DNS
  name walk, moved out of `model.rs` into `common/src/dns_qname.rs` so
  that edits to the event model do not start it), keeps its weekly run,
  and runs the `qname_wire_end` proof, which no workflow ran; an xtask
  test keeps the path filter equal to the files with a proof and checks
  that every harness runs.
  **Regressions / changes:** an install manifest whose `files` map holds
  a name other than `northnarrow-agent`, `northnarrow-watchdog`, `nn-admin`
  or `ebpf_object` is a mismatch, fatal at boot unless
  `NN_ALLOW_UNVERIFIED_BINARY=1` (`install.sh` writes exactly these four);
  the CI fuzz job takes a few seconds longer (the replays); `kani.yml`
  adds minutes of CI to the pull requests that touch the three proved
  files; `QnameLabels`, `decode_dns_qname` and `qname_wire_end` live in
  `common::dns_qname`, re-exported at the crate root as before.
- External audit, Wave 3, RAG retrieval (Low XAI-008 NN-AUD-346, XAI-012
  NN-AUD-347, XAI-019 NN-AUD-435; lab PR 199). Dormant: RAG runs only with
  `NN_ADE_RAG_ENABLED` set, off by default; these points, with Wave 2's
  corpus pinning (lab PR 145), are now blocking items of the §13
  default-flip checklist (an addendum below the owner's eight points in
  `docs/TAPPA6_9_7_RAG_KB_PLAN.md`). XAI-008: on the BM25 path the scores
  are divided by the top hit's before the `min_similarity` floor, so the
  top hit was always 1.0 and always kept, whatever it shared with the
  query. The top hit must now carry at least one in four of the query's
  distinct terms (in its title, author or content, analysed as the index
  does; `COVERAGE_ONE_IN`, `required_terms`, `matched_terms`), else the
  result is empty. The triage proposed one in three: on the pinned corpus
  that emptied the golden query "xmrig miner pool stratum", whose hits
  ("Linux Crypto Mining Pool Connections" first) are relevant and each
  share one of its four terms, and the suite fell to 27/30. `RagQuery`
  is unchanged, so `min_similarity: 0.0` still means the 0.15 default:
  the golden suite, the end-to-end format test and three unit tests that
  meant "no floor" measured with 0.15; they pass `f32::MIN_POSITIVE`, as
  the `RagQuery` doc now says. XAI-012: three `TermQuery` per analysed
  term, without a limit; the terms are now deduplicated in first-seen
  order, then cut at 32 (`MAX_QUERY_TERMS`, at most 96 clauses), and the
  query text is not truncated (it would cut a path). The
  `build_rag_query` doc promised "under ~120 chars", which nothing
  enforced; it says what bounds the query. XAI-019: `SecTokenStream`
  stops its cursor at the end and clamps `token()` / `token_mut()` (an
  empty token for an empty text): a read past the end returns a token
  instead of panicking. XAI-003 (NN-AUD-343, obsolete since lab PR 145,
  the triage's one line): the field lookup in `bm25_query` returns an
  error instead of `unwrap()`. On `target/kb` (970 documents): golden
  28/30 before and after, the same two failures; retrieve p50 95–99 µs
  before, 102–106 µs after, p95 120–130 µs before, 127–131 µs after
  (budget 50 ms).
  **Regressions / changes:** a query whose top BM25 hit carries less than
  a quarter of its distinct terms gets no RAG block (none of the 30
  golden queries, none of 30 production-shaped ones measured); a word
  repeated in a query counts once, so the ranking of such queries changes
  (two golden queries reorder below their wanted ids, which stay); the
  golden suite runs without the relative floor (28/30 with it or
  without).
- External audit, Wave 3, posture overlay validation (Low POS-010
  NN-AUD-306, POS-011 NN-AUD-307; lab PR 198). The two signed overlays
  that widen a posture exemption are checked for breadth, not only for
  shape: a signature proves who wrote an entry, not that it is narrow.
  POS-010 (the part left after Tappa 10.8 and LLMR-013):
  `mass-write-carveout.local` accepted any absolute prefix, `/` included,
  and logged an INFO count, so a signed typo switched the ransomware arm
  off. An entry is refused (WARN `mass-write overlay: entry REFUSED — not
  applied`, with the path, the line and a reason that names it; the rest
  of the file applies) when, its repeated `/` folded, it is `/`, has a
  `.` or `..` component, is a top-level directory (`/home`, `/root`,
  `/srv`, `/var`, `/tmp`, `/media`, `/mnt`, `/data`, `/opt`, `/usr` are
  named as data roots; any other is refused too), is a whole user's tree
  (`/home/<user>`, `/run/user/<uid>`), or covers `/var/tmp`, `/dev/shm`
  or `/run/user`, the shared trees the arm counts on purpose. An entry
  without its final `/` is judged as the name prefix the posture matches
  (`/home/al`, `/var/t`). What is accepted is one WARN (`ransomware-shape
  detection is OFF under these carve-outs`, the name-prefix entries
  listed apart), said once: `main.rs` parsed the overlay twice (the
  sensor and the posture), now once. An accepted entry's repeated `/` is
  folded (the posture compares it with kernel paths). POS-011:
  `escalation-allow.local` accepted the comm `*` with `0.0.0.0/0`, with
  no warning; any `/0` network is refused, and the comm `*` (any
  process) with a network wider than /16 (IPv4) or /32 (IPv6); `exfil *
  140.82.112.0/20 443` stays. Refusals carry their line (`line N: …`) and
  quote the entry. Both checks are the loaders' own, so `nn-admin config
  overlay set` and `sign` refuse such a file, naming the line and the
  entry (`validate_content` called a copy of the mass-write rules; it
  now calls the loader's `parse_text`). Found while doing it: the kernel
  file-open sensor placed a carve-out with `metadata`, which follows
  links, at boot and at every refresh (a minute), so a user who replaced
  the directory of a signed carve-out in their home (`~/.claude/`) with
  a link to `~` or `/` moved the carve-out onto that tree. A carve-out is
  now walked from `/` one component at a time (`O_PATH | O_NOFOLLOW`,
  each checked on its own fd); a link on the way refuses it (WARN
  `file-open sensor: mass-write carve-out NOT applied — a symbolic link
  on its path`, once per new refusal) and that tree is counted.
  **Regressions:** an entry of these shapes in an overlay signed before
  stops applying (the overlay loads, the entry is a WARN at boot), so the
  writes or connections it exempted count again, and `config overlay
  set|sign` refuses the file until the entry is narrowed; a carve-out
  reached through a symbolic link (`/var/run/…`, a tool directory that is
  a link) no longer applies in the kernel sensor (it never matched in
  tracepoint mode): list the directory it points to; journal searches
  for `mass-write overlay: load complete` (now only when nothing is
  added) and `escalation-allow: skipping malformed entry` (now `entry
  REFUSED — not applied`). Upgrade notes §6. Tests: `mass_write_overlay`
  `root_and_data_roots_are_rejected` (the triage's overlay keeps only
  `/var/lib/devtool/cache/`), `too_broad_entries_are_refused_by_name`
  (19 shapes, the entry and the line named), `narrow_entries_still_load`
  (the BUG-017 dev-host overlay, `/srv/build/`, tool directories below
  the shared trees); `triggers`
  `a_refused_carveout_leaves_the_mass_write_arm_on` (a burst in
  `/home/alice/Documents` still raises ConfirmedIntrusion);
  `escalation_allow` `wildcard_with_default_route_is_rejected`,
  `narrow_wildcard_entry_still_parses`; `overlay_auth`
  `content_validation_uses_the_loader_rules` (extended); `open_sensor`
  `a_carveout_never_follows_a_symlink`. Two existing loader tests used
  `/ok/` and `/keep/`, now refused: `/ok/dir/`, `/keep/me/`.
- External audit, Wave 3, FIM pipeline and signed-chain hygiene (Low
  FIMR-015 NN-AUD-289, FIMR-016 NN-AUD-290, FIMP-012 NN-AUD-291, FIMP-013
  NN-AUD-292, FIMP-014 NN-AUD-293; lab PR 197). FIMP-012: the FIM drain
  decoded the name of a file dropped into a watched directory lossily
  (U+FFFD for each byte that is not UTF-8), a name no file has: the new
  file was never watched (its later in-place edits went unseen) and its
  drift row named a file that does not exist. The name is kept as bytes:
  a UTF-8 name is itself, backslashes included; any other is spelled with
  `\xNN` for those bytes and `\\` for a backslash (`/etc/cron.d/x\xff`), so
  distinct names stay distinct, and the drain stats, hashes, enrolls and
  sweeps the file by its bytes (a UTF-8 file spelled like the escape is the
  one under that name). An empty leaf, `.` and `..` are refused. FIMP-014:
  `DriftRateLimiter` held a `std::sync::Mutex` locked with `.expect("…
  poisoned")`, against its own note: a panic under the lock made every
  later drift panic (`panic = "abort"`). It is a `parking_lot::Mutex`.
  FIMP-013 (the strict half): the agent's chain verifiers — audit log,
  rotating logs (detections, status events, netflow, FIM drift, their
  terminators and manifests), FIM baseline, canary registry and access
  log, the head anchor — checked signatures with Ed25519 `verify`, which
  accepts a signature valid for any message under a small-order public
  key. They use `verify_strict`; the admin path already did. Every row the
  agent signed passes; no row, field or pre-image changed, and every
  existing v1 row verifies as before. FIMR-015: the bait paths were a list
  in `fim::rules` and their contents a `match` in `fim::honeypot`, paired
  by a test, and the boot sweep took a bait without a template with
  `.expect` (a panic). One table, `honeypot::BAITS` (path, content);
  `HONEYPOT_PATHS` is derived from it. FIMR-016 (the S part): the ten
  templates shared one warning line and `last_modified=2026-02-15T09:30:00Z`,
  which a bait restored by the sweep contradicted with its fresh mtime. The
  templates' comment lines now differ and their `last_modified=` is empty;
  `install.sh` (`install_bait`) and the sweep (`render_bait`) fill it with
  the time of the write, UTC to the second, and set the file's mtime to
  that second. A reinstall leaves a file that holds its template, the date
  line aside, alone (BUG-020's skip). Not in this lot: the per-chain domain
  tag and row format v2 of FIMP-013 (the rotating logs, the FIM baseline
  and drift log still hash `prev ‖ row` untagged; a format change with
  `nn-admin` and the chain documentation, its own PR), and the L part of
  FIMR-016 (per-install bait names, a product decision). **Regressions /
  notes:** drift rows and FIM detections name a file whose name is not
  UTF-8 with `\xNN` (it read `�`); the ten control-surface files are
  rewritten once by the first upgrade (inside the trusted-installer window
  `install.sh --upgrade --grant-key` opens) and then carry their own date —
  a byte-for-byte comparison with `configs/honeypot-baits/*` must leave the
  `last_modified=` line out; a verifier given a small-order
  `--agent-pubkey` reports the chain broken at its first row. Documented
  in `docs/operator/EVIDENCE_CHAINS.md`, `anti-tamper-honeypots.md` §3 and
  `UPGRADE_NOTES_AUDIT_16f7563.md` §§1, 4, 8.
- External audit, Wave 3, open-sensor and DNS userland (Low SNS-004
  NN-AUD-352, SNS-010 NN-AUD-353, SNS-011 NN-AUD-354, SNS-014 NN-AUD-357,
  SNS-015 NN-AUD-436; lab PR 196). The userland half of the file-open
  sensor and of the DNS sensor puts each event where it happened, and its
  WARNs say what is true. No eBPF program changes. SNS-004: the mount table
  that puts a record's mount-relative path on its mount point was re-read
  on a miss only; a tmpfs unmounted and another mounted elsewhere reuses
  the anonymous device and root inode, and on a quiet host the new
  filesystem's files kept the old mount point. The open `mountinfo` is now
  polled (`POLLPRI`, no wait) at every lookup and the table re-read after a
  change (at most every 2 s; until then a hit is answered only while a
  `stat()` of its mount point still shows that root, else the path is
  unplaced, `mnt[maj:min:ino]/…`), and in any case when it is 30 s old
  (the module-load pump uses the same table). SNS-010: home trees (the
  `TREE_HOME` checks for `Login Data`, `logins.json`, `key4.db`,
  `*.kdbx`, …) were `/root` and uid 1000–65533 only; now uid 0's declared
  home and every account's home, except the overflow uids (65534,
  4294967294, 4294967295, any `nobody`) and shared system directories
  (`/`, `/nonexistent`, `/var/lib`, `/var/mail`, `/usr/share`, … exactly;
  anything under `/bin`, `/etc`, `/dev`, `/proc`, `/usr/lib`,
  `/var/empty`, …), judged on the declared path and on the path it
  resolves to. SNS-011: the generation bump read 0 on a map error and
  wrote 1, taking the generation back; a read error is now an error
  (nothing written, the rule write reports `generation_failed`, degraded),
  and the value written is the later of the slot and this process's last
  write (serial order) plus one, never 0; a concurrent kernel bump that
  merges with it is documented as harmless. SNS-014: the DNS pump read
  `/proc/<pid>/exe` when it drained the record, so a process that took the
  pid since (or the image the sender executed since) named the sender;
  the lineage tracker now answers for the sender only
  (`AuthSessionTracker::image_at`: its cached exec when it ran no later
  than the query, else `/proc/<pid>/exe` when the process `/proc` shows
  started no later than it, field 22 read after the last `)`), and an
  unconfirmed sender is unnamed — a non-forwarder for NN-L-NET-004/-014,
  as before on a miss. SNS-015: the comments that called `FS_PROTECT_EVENTS`
  still pinned ("Do not unpin") and cited BUG-024 as live are rewritten;
  the reject WARN no longer names BUG-024 as a cause. NN-AUD-355 (declined,
  the boot is already fail-closed): the `BTF_OFFSETS map NOT armed` WARN
  now says why and what the start does next (with the net sensor it fails
  at the latest at the `tcp_close` fexit; without it `attach_anti_tamper`
  refuses unless `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`; with BTF present, that
  nothing was resolved before this load). **Regressions / changes:** more
  home trees, so NN-L-FIM-015/-016 can report a credential-store name read
  in a service account's home (Jenkins, GitLab Runner, PostgreSQL); a
  file-open path right after a remount may read `mnt[…]/…` for up to 2 s
  instead of the old mount point; the reject WARN and the unarmed-BTF WARN
  have new texts (same first words); a DNS sender whose start or exec
  `/proc` shows after the query is unnamed. Also: the `posture_demo`
  example builds again (its `ProcessSpawn` lacked `argv_truncated` and
  `filename_truncated`, added by lab PR 187). Tests: `open_sensor` +6
  (and `home_roots_read_every_account_s_own_home` replaces
  `home_roots_reads_regular_accounts_only`), `lineage` +2, `multiplexer`
  +3; on the starting tree they do not compile (new items), and with the
  old logic put back 8 of them fail.
- External audit, Wave 3, privileged test assertions (Low TST-013
  NN-AUD-419, TST-014 NN-AUD-420, TST-015 NN-AUD-421, TST-016 NN-AUD-422,
  TST-017 NN-AUD-423; lab PR 195). The privileged suites now prove what
  they claim, and their guards check their own cleanup. TST-016:
  `exec_sensor_live` passed on any `echo` exec on the host
  (`comm == "echo"`); its test (renamed
  `the_canary_exec_is_observed_with_its_pid_parent_and_argv`) wants the
  record of the canary itself: its pid, this test process as the parent
  (`real_parent->tgid`, read with this kernel's BTF offsets, lab PR 187)
  and `northnarrow-canary` in argv, within 3 s, and lists every `echo`
  it saw when it fails. TST-013: five JSONL readers dropped what did not
  parse (`filter_map(… .ok())` in the canary, FIM, network and
  detection-at-scale suites, and `common::jsonl_rows`, which
  `wait_jsonl_row`, `records_of`, `exec_barrier`, the response and the
  honeypot suites use), and the FIM suite counted any non-blank line as a
  row. One reader now, `common::read_jsonl_strict` (`parse_jsonl_strict`
  for bytes): every newline-terminated line must be one JSON value (an
  empty line included) or the test fails naming the file, the line number
  and its first 200 bytes; only an unterminated last line, a write in
  progress, waits; a file that does not exist yet has no rows. It checks
  the framing, not the schema: rows of other kinds or other processes are
  kept for the callers to filter. TST-014: `EniIptablesGuard`'s Drop
  discarded every status, removed one jump per base chain (a duplicated
  jump survived and `-X` failed) and never looked at the result, and
  `is_clean()` called a host where iptables could not run "clean"
  (nobody called it; deleted). Drop now repeats `-D <base> -j <chain>`
  while iptables deletes one (at most 16), flushes and deletes the chain,
  on the v4 table and on the v6 one the agent's COMBAT also writes
  (BUG-031; v6 only where `ip6tables` is installed), then reads each table
  back (`iptables -S`; `nft list table` when iptables-nft calls the table
  "incompatible"; a kernel without the table has nothing in it) and fails
  the test, naming what is left and how to remove it, when the chain or a
  jump to it remains or a table cannot be read (only printed when the
  test is already failing). TST-017: `install_to_priv_bin` existed in six
  suites, and two ran the agent from `target/` under the user's home:
  `privileged_map_pin` (with an `--admin-pub` that was never created, so
  it checked an agent without its admin socket) and `fim_privileged_e2e`.
  `common::install_to_priv_bin` / `install_bin_at` / `InstalledBin` are
  shared (through `/usr/bin/sudo` by its absolute path; a failed removal
  fails the test); map_pin and the FIM suite run the installed copy,
  map_pin creates `admin.pub` with `nn-admin init`, and the FIM fixture
  stops its agent before its tempdir goes (`impl Drop`, lab PR 163's
  lesson; its fields dropped the tempdir first). New
  `privileged_e2e::agent_without_admin_pub_starts_degraded_and_says_so`:
  an agent without `admin.pub` logs the ERROR line, opens no socket, runs
  on, and its audit chain holds a signed `subsystem_degraded` whose detail
  starts "admin socket disabled" (`at_boot`, `agent-self`) and verifies
  with `nn-admin audit verify`. TST-015: the runbook said "9 tests
  passing, 2 ignored" for a suite of ten with none ignored, and named one
  of twelve privileged suites. `nn-lab.sh test-e2e` now counts each suite
  (`deploy/lab/lib/suite-count.sh`): the tests `cargo test -- --list`
  names must equal the passed count of the run's one `test result:` line,
  with nothing failed, ignored or filtered out (a suite built without its
  feature lists none and fails); it prints `count ok: …` or `FAIL: …`
  (collected by the nightly report), runs all three suites and fails the
  step when any does (standalone it stopped at the first failure; in the
  nightly the step had only the last suite's status).
  `NN_LAB_E2E_TEST_ARGS` adds libtest arguments to the runs, not the
  listing (`--skip e2e_status_no_admin_action_initially` must fail it).
  The runbook drops its counts, lists every privileged suite (features,
  how it runs, what it needs, the `nn-lab.sh` step) and its "Future work"
  no longer says a missing `admin.pub` "produces a WARN". Tests:
  `fixture_selftest` `a_malformed_line_fails_the_read_naming_its_number_and_bytes`,
  `a_partial_last_line_is_a_write_in_progress_not_a_row`,
  `rows_of_any_shape_are_kept_and_an_empty_line_is_not_one`,
  `a_long_malformed_line_is_shown_cut_at_200_bytes`,
  `a_missing_file_has_no_rows_and_a_file_is_read_strictly`,
  `reading_a_file_with_a_malformed_line_panics`,
  `iptables_listing_leftovers_are_the_chain_and_every_jump_to_it`,
  `nft_listing_leftovers_are_the_chain_and_every_jump_to_it`
  (unprivileged, in `cargo test --workspace`); ignored, root and iptables:
  `iptables::iptables_guard_removes_every_duplicate_jump`,
  `iptables::iptables_guard_fails_the_test_when_the_chain_stays`;
  `deploy/lab/lib/suite-count-test.sh` (15 cases, no VM). On the starting
  tree the new unit tests do not compile (new items); with the old
  lenient reader put back in `parse_jsonl_strict`, 5 of the 6 reader tests
  fail (the missing-file one passes on both). The two guard tests fail
  with the old Drop (the second INPUT jump and the chain survive; no
  panic), the exec test without the canary's own exec, the new e2e
  without the `attest_degraded` call. Host: `cargo fmt`, both clippy runs
  (`--workspace --all-targets`, the agent with
  `test-privileged,debug-trigger`) clean, 2,504 passed, 0 failed.
- External audit, Wave 3, install and uninstall scripts (Low DEP-012
  NN-AUD-384, DEP-016 NN-AUD-388, DEP-020 NN-AUD-440; lab PR 194).
  DEP-016: `install.sh` looked the tarball up in `SHA256SUMS` with
  `grep -E " \*?<name>$"`, the name as a pattern: its dots matched any
  character, so the line of a look-alike file listed first
  (`northnarrow-1X2.3-…`) was taken for `northnarrow-1.2.3-…` and the
  install was refused (a spurious REFUSED, never a bypass: the hash is
  still compared), and a name with a `+` was never found. `sums_expected
  NAME FILE` compares the second field as a string (a leading `*` removed,
  `awk`, run by the test with the shell's own `awk`, mawk included); a
  name listed with two different checksums is refused (the first line was
  used) and an unreadable file is named. DEP-020: with both units inactive
  and the pin root of the last agent still there, the branch that should
  open the trusted-installer window required an active agent — never true
  there — so `--grant-key` was ignored and `install.sh --upgrade
  --grant-key` ended in "PROTECTED". A pin root nothing protects is
  removed; a protected one, with the key: the installed agent is started
  (its unit only), its admin socket awaited (30 s), the window opened, the
  agent stopped again on the normal path (stop, purge, drain) and left out
  of the units to restart and of the package's restart list, so the units
  end as they were; without a key nothing is started and both ways out are
  named (`--grant-key`; disable, reboot, re-run, enable). A failed start,
  a refused grant (the agent keeps running, said so) or a socket that does
  not appear are explicit failures. The same case in `uninstall.sh` (the
  same text, one block both scripts carry, kept equal by a test), before
  anything is disabled; not under `--package`. `uninstall.sh` also
  disabled each unit before stopping it: on a protected host without the
  window the stop was refused, the units stayed running but disabled, and
  the script stopped at the pin root. It stops both now, disables them
  once both are stopped, and otherwise exits 1 with nothing disabled or
  removed. DEP-012, the part left after lab PR 96: an install older than
  it wrote the bootstrap private key to `/etc/northnarrow/admin.key`, which
  an uninstall without `--purge` keeps; the summary named only
  `/root/northnarrow-admin.key`. It names both (`kept_report`), and
  `--purge` says it removes the legacy one. `install.sh` takes
  `BPFFS_ROOT` like `uninstall.sh`; `uninstall.sh --help` prints the whole
  usage, `--grant-key` included. New `xtask/tests/install_scripts.rs` (12
  tests: the two blocks, and the stop sections of both scripts under bash
  with stub `systemctl`, `rm` refusing the pin root until the stub
  `nn-admin` opens the window, `bpftool` and `sleep`). **Regression:** a
  `SHA256SUMS` with two different lines for the tarball is refused;
  `uninstall.sh` without `--grant-key` on a running, protected host exits
  1 at the stop instead of at the pin root, with the units still enabled;
  its log reads `stopping <unit>` and `disabling <unit>` (was `stopping +
  disabling <unit>`); on stale protected pins with `--grant-key`, the audit
  chain gets an `agent_boot` and an `agent_stop` of the agent started for
  the window.
- External audit, Wave 3, response honesty and status (Low CMB-018
  NN-AUD-310, CMB-020 NN-AUD-311, CMB-027 NN-AUD-318; lab PR 193).
  CMB-020: the detect-only branches of `block_outbound_for_pid`,
  `throttle_pid` and `quarantine_handle` (which `quarantine_process_binary`
  calls) answered `Blocked`, `Throttled` with the three limits, and
  `Quarantined { vault_id: "dry-run" }` — a containment that never
  happened, counted as done by whoever read it. They answer
  `WouldExecute`, as the dispatcher and `Executor::quarantine_handle`
  already did before them (which is why no agent path reached them: a
  library-level fix, nothing changes on a host). CMB-027, the triage's fix
  and not the audit's fail-closed (holding ISOLATE until the audit log can
  be written would let whoever breaks the log — fills its filesystem —
  prevent the containment): `LadderEvidence::record_stage` returns
  `Result<(), Unrecorded>` and the ladder checks it at its five call sites.
  A stage transition the audit log refuses is logged whole at ERROR
  (`COMBAT stage transition NOT in the signed audit log — enforcement
  proceeds`, with from, to, trigger, offenders and reason), and the ladder
  carries on; `AuditEvidence` keeps it in a bounded queue (64) and writes
  it, in order and before any newer transition, at the next append or at
  the stand-down, as a `combat_stage` row with `deferred: true` and
  `occurred_at` (when it happened); a transition dropped from the full
  queue is counted, and the next row written says `transitions_lost: N`.
  Without an audit log (`NN_AUDIT_ALLOW_UNWRITABLE=1`) every transition
  is counted as unrecorded (it was silent). CMB-018: `nn-admin status`
  shows `response mode` — `enforcing`, or `DETECT-ONLY (<source>)` with
  `--detect-only` or the variable's `NAME=value`, as the signed
  `agent_boot` entry records it — and `combat evidence`: complete, or the
  transitions not written when they happened since boot, how many are
  queued, how many were dropped; `--json` gains `detect_only`,
  `detect_only_source`, `combat_evidence_unrecorded`,
  `combat_evidence_pending`, `combat_evidence_dropped`. `StatusResponse`
  gains these five fields at its end (`#[serde(default)]`); no
  `AdminMessage` variant is added, the discriminants are unchanged. Found
  while adding them: postcard carries no field count, so `serde(default)`
  never fills a trailing field an older agent did not send — the "`None`
  from an agent older than the field" notes of `StatusResponse` (since
  Tappa 10.8) hold only for an older `nn-admin` reading a newer agent; the
  struct's doc says so and two tests pin both directions.
  **Regressions / changes:** `nn-admin status` prints two more lines and
  its JSON five more keys; an `nn-admin` newer than the agent cannot
  decode the agent's `status` reply (a decode error, as with every field
  added to it since Tappa 10.8), and neither can a watchdog newer than
  the agent, whose ping decodes the same reply and then counts as failed —
  upgrade the binaries together; an `nn-admin` or a watchdog older than
  the agent reads the reply without the new fields;
  a COMBAT audit append failure is an ERROR line naming the whole
  transition (a WARN `failed to append COMBAT stage transition to audit
  log` before): update journal searches; `combat_stage` rows can carry
  `deferred`, `occurred_at` and `transitions_lost` (inside `extra`: an
  older `nn-admin` verifies them); library API: `record_stage` returns a
  `Result`, `LadderEvidence` gains `retry_pending` and `counts`,
  `CombatLadder` gains `evidence_counts`, `ResponseAdminState` gains
  `detect_only_source` and `combat_evidence`, and the three module
  functions return `WouldExecute` in detect-only.
- External audit, Wave 3, signed-request verification (Low ASK-017
  NN-AUD-243, AUT-001 NN-AUD-244, AUT-005 NN-AUD-245, AUT-006 NN-AUD-246;
  lab PR 192). AUT-001: the live verify of a signed request compared only
  the payload's `op` tag with the request, while the dispatchers read its
  `extra`; the two are encoded independently, so a payload pairing the
  `shutdown` tag with an `unlock` extra, signed by two `shutdown` keys,
  verified, and `dispatch_shutdown` wrote the marker on a 30 s grace nobody
  signed (`_ => 30`, under a comment saying the invariant was enforced
  upstream). `admin_signed_payload::check_op` (the tag is the request's
  operation, the extra that operation's) is now the one check every
  verifier runs first — live requests, stored overlay signatures,
  `admin_signed_payload::verify` — refused as `UnknownOperation` (counted
  against the connection) before any Ed25519 work, the journal line naming
  the extra's operation; the shutdown fallback refuses, and the two
  comments that claimed the check are corrected. Latent: `nn-admin` always
  builds matching payloads. AUT-005: only the 64 KiB frame bounded the
  signatures of one submission (about 1,000, each checked against every
  key, a quadratic tally, and a quorum shortfall is not counted):
  `admin_quorum::MAX_SUBMITTED_SIGNATURES` = 8, enforced inside
  `match_signatures` (no caller can skip it) and checked first by the
  agent's three verify paths and by the watchdog's marker verify. Over it:
  `InvalidSignature` on the wire, counted (`AdminAuthError::
  TooManySignatures`, journal reason `too_many_signatures`), and
  `Rejection::TooManySignatures` for a marker, before its signatures are
  decoded. The cap is 8, not the triage's 16: the Kani proof of the quorum
  rule now covers every submission length up to the cap (it stopped at 4),
  and at 16 it outgrew a CI runner (over 20 minutes and 16 GB before it was
  stopped; at 8, 5 minutes and 7 GB). AUT-006: `rotate-keys revoke`
  dropped every `admin.pub` line whose 4-byte fingerprint matched, so with
  two keys sharing it both went, and `add` refused a different key with a
  colliding fingerprint as "already present". Revoke now refuses a
  fingerprint that names two different keys (`RotateKeysError::
  AmbiguousFingerprint`, the file byte for byte as it was; the lines of one
  key listed twice still all go), and add tells the same key (its 32 bytes,
  `KeyAlreadyPresent`) from a collision (`FingerprintCollision`); both stay
  `InvalidSignature` on the wire, named in the `admin.rotate_keys` journal
  line and listed in `nn-admin`'s message. ASK-017: a verified `unlock`
  whose COMBAT release failed for any reason but "not in COMBAT" was
  answered — and recorded — as `Success`; it is `InvalidSignature` with an
  ERROR, so the audit row says `failure` (unreachable today: the release
  refuses only `NotInCombat`; what the release hook does with the token
  stays unobservable). **Regressions / changes:** the wire format, every
  existing signature and every `nn-admin` verb are unchanged; a submission
  of more than 8 signatures is refused (no in-repo client sends more than
  two), and the watchdog refuses a marker carrying more (the agent never
  writes one); a revoke of a fingerprint two different keys share removes
  nothing, and adding a colliding key is reported as a collision (exit 2,
  as before) — reachable only with a crafted collision; the exit-2 message
  of `rotate-keys` lists the new refusals; `SignedPayloadError::
  UnexpectedOperation`, `AdminAuthError::TooManySignatures`,
  `RotateKeysError::{FingerprintCollision, AmbiguousFingerprint}` and
  `Rejection::TooManySignatures` are new, and `admin_quorum::
  match_signatures` returns a `Result`. Upgrade notes §3, design §3.3,
  §6.3 and §7.2.
- External audit, Wave 3, ADE runtime hygiene (Low LLMP-005 NN-AUD-319,
  LLMP-010 NN-AUD-322, LLMR-009 NN-AUD-325, LLMR-018 NN-AUD-328, LLMR-020
  NN-AUD-433, XAI-017 NN-AUD-351; lab PR 191). LLMR-009: the ADE load set
  `RAYON_NUM_THREADS` with `std::env::set_var` inside `#[tokio::main]`,
  with the runtime's workers and the logging already running — a write of
  the environment racing their reads, undefined behaviour, under a comment
  that called the point race-free. The agent's `main` is a plain function:
  it parses the command line, runs the early exits, pins the variable
  while its thread is the process's only one (checked in
  `/proc/self/status`, no runtime current; otherwise nothing is written
  and a WARN says so), then builds the runtime `#[tokio::main]` built
  (multi-thread, every driver) and runs the agent in it. Same value and
  rule as before (`--ade-threads`, else physical cores − 1; an operator's
  variable wins), set when the ADE may load (not `--no-ade`, a file at the
  model path); the ADE load now only says the count, a WARN when nothing
  pinned it. The variable stays (candle-core reads it again at every
  kernel split; a pool sized by rayon's builder alone would leave candle
  splitting for every logical CPU). The `ade_demo` and `ade_attacks`
  examples pin the same way. LLMP-010, wider than reported: the streaming
  detector that stops the decode at the verdict's close took a `}` before
  the object to depth -1 for good, and a `"` there switched string mode
  on, so that with an odd count of quotes the object never closed: the
  decode ran to `max_output_tokens` (cost only, bounded by the timeout).
  It also counted braces in the model's `<think>` block: a balanced `{ … }`
  in the reasoning stopped the decode before `</think>`, and the parser
  refused the output — a malformed-output Escalate for a verdict the model
  had not written yet. The detector reads the stream as the parser reads
  the output: a `<think> … </think>` block first (markers split across
  tokens matched), every character before the first `{` ignored, the depth
  saturating at 0; it keeps no copy of the output (the unread `buffer` is
  gone). LLMP-005: `recommended_action.action` was never checked against
  `verdict`; nothing decides on it, but a model's `Kill` under an `Alert`
  was kept as it was: the engine aligns it on the verdict (a debug line
  when they differed), and the parser's two dead statements are gone.
  LLMR-018: the mock fallback (`NN_ADE_ALLOW_MOCK=1` only) stamped the
  configured GGUF's stem and `Q4_K_M` as model and quantization in its
  verdicts; it says `mock-deterministic` and `none`. LLMR-020: the candle
  warmup marked itself done before its forward pass ran; it is done once
  the pass succeeded, and the constant, uncalled `AdeEngine::is_ready` is
  removed. XAI-017: `CorrelationBuffer::new(0)` never evicted; the
  capacity is at least 1 and a push evicts while the buffer is full (the
  agent's buffer is the 1,000-event default). Prompts and scores are
  unchanged. **Regressions / changes:** the journal line `ADE rayon worker
  count pinned via RAYON_NUM_THREADS` comes at the start of the boot, not
  at the ADE load, and is written when the ADE may load even if the
  memory check then keeps it off; an operator's `RAYON_NUM_THREADS` is
  said at INFO (it was DEBUG); a tokio runtime that cannot be built ends
  `main` with an error instead of a panic; on a model host the decode
  stops sooner after prose with quotes or braces, and a reasoning block
  with braces gives the model's verdict instead of a malformed-output
  Escalate (not measured on a model host); the mock fallback's verdicts
  carry `mock-deterministic` / `none`; `AdeEngine::is_ready`,
  `StreamingJsonDetector::buffer` and `CandleBackend::configure_threads`
  are gone from the library API.
- External audit, Wave 3, verifiers and forensic tools on bad input (Low
  MAIN-014 NN-AUD-256, EVD-017 NN-AUD-280, EVD-022 NN-AUD-283; lab PR
  190). EVD-017: a sealed archive without its terminator line (an empty
  `<log>.000001` is enough) made `verify_log_set` hit an `expect`, which
  `nn-admin chain verify` reaches since lab PR 160: the command aborted
  (`panic = "abort"`) before it reported any chain. It is
  `LogSetError::ArchiveWithoutTerminator { file, seq }`, that chain's
  `BROKEN` line, and every other chain and the anchor are still reported.
  MAIN-014: `nn-admin audit read` stopped at the first line that is not
  an audit row (exit 1) and every row after it went unseen; it prints
  every row, names each skipped line on stderr with its number (the first
  100, then the count) and exits 8. `audit verify` turned such a line
  into an I/O-style error (exit 1); it is a broken chain, exit 8, `line N:
  not an audit row (…); K row(s) verified before it`
  (`AuditVerifyError::UnreadableLine`). Both verifiers of the audit chain
  run one pass through `audit::ChainVerifier` (`verify_chain` is a
  wrapper over it, `verify_chain_file` streams a file, `--expect-head` and
  `--min-seq` folded in): `audit verify` kept every row and read the file
  a second time, `chain verify` read it whole; a 128 MiB chain now
  verifies at a 10 MiB peak RSS (265 MiB before). The full verifiers, the
  rotating logs' manifests and `audit read` read through one bounded line
  reader (`verify_lines`: 16 MiB a line, a longer one consumed and
  reported, never buffered; a line that is not UTF-8 named, not an
  error), and `verify_one_file` keeps the end offsets the manifest
  checkpoints name instead of every line's. EVD-022: an archive name is
  accepted when it is the canonical spelling of its seq (six digits with
  zeros, or up to 19 without a leading zero), so archives from seq
  1,000,000 on are listed, evicted, verified and read; the evicted-prefix
  check walks the manifest's rows instead of every seq below the earliest
  archive. Format: no writer changed; existing rows and archives verify
  byte for byte as before (same pre-images; the slice and file verifiers
  agree on every kind of break, tested). Changes for readers, declared:
  `audit read` exits 8 (was 1) on a log with lines that are not rows and
  prints the rows after them; `audit verify` exits 8 (was 1) on such a
  line; a line over 16 MiB is reported as damaged (no row the agent
  writes comes near it); `chain verify` names a bad audit line with the
  new text; an older `nn-admin` does not see archives past seq 999,999
  (reached only after a million rotations). Exit codes:
  `docs/operator/EVIDENCE_CHAINS.md` ("Exit codes of the verifiers") and
  the `nn-admin` header, which now lists 8.
- External audit, Wave 3, anti-tamper bootstrap trust and honest health
  (Low ATP-007 NN-AUD-260, ATP-015 NN-AUD-263, ATP-016 NN-AUD-264,
  ATP-017 NN-AUD-265, EBPF-016 NN-AUD-267, EBPF-020 NN-AUD-271; lab PR
  189). ATP-007, worse than reported: `ensure_state_dir` created, stat-ed,
  chmodded and chowned `/var/lib/northnarrow` by path, so a symbolic link
  planted there by a root before the agent started gave its target mode
  0700, owner root and — since lab PR 152 — the state directory's NOCREATE:
  a link to `/etc` would have refused every new file in `/etc` outside a
  trusted-installer window. The agent now refuses to start when the state
  directory, or one of its own entries in it (`quarantine`,
  `quarantine/vault`, `detections`, the chain logs), is a link — checked
  first thing at boot, before any bootstrap writes there, and again by the
  attach — naming the link and pointing to a bind mount; the directory is
  opened `O_NOFOLLOW | O_DIRECTORY` and repaired on the descriptor
  (`fchmod`, `fchown`), and the key registered is that descriptor's
  `fstat`. The same class elsewhere: the bpffs pin root as a link is not
  chmodded, pinned into or registered (`pin_root_refusal`), the
  `/etc/northnarrow` and unit drop-in directories as links are not
  registered, and each refuses the start as a failed step; the agent's
  files are keyed with `lstat` (a `fim_baseline.jsonl -> /etc/passwd`
  write-denied `/etc/passwd`). ATP-016: the health line subtracted every
  failure entry from the expected hooks, so an FS bootstrap failure (13
  deny hooks absent) read "15 of 16 attached"; missing hooks and failed
  steps that are not hooks are now kept apart (`DenyHealth`), a bootstrap
  failure counts every FS deny hook (and the optional ones the kernel has)
  — "3 of 16" — a BPF guard that refuses nothing counts once, and the
  `DENY HOOK SHORTFALL` line carries `missing=` and `infra_failed=`; the
  fail-closed decision is unchanged. A start under
  `NN_ANTI_TAMPER_ALLOW_DEGRADED=1` and missing observe hooks are now a
  signed `subsystem_degraded` each, with what is missing. ATP-017: every
  `link_*` entry of the pin root went into the 64-entry `OWN_PIN_NAMES`,
  so 64 planted names refused the start and a planted name equal to
  another product's pin denied that product's `OBJ_GET`; only pins whose
  link runs one of the agent's programs are registered, every other one is
  a WARN and a signed `integrity_drift` (`foreign_pin`), neither registered
  nor removed. EBPF-016: on overlayfs, FUSE and NFS the agent cannot vouch
  that `stat()` and the hooks see the same `(dev, ino)`, and a mismatch was
  silent both ways; every protected or watched path is checked with
  `statfs()`, and a boot with any on such a filesystem logs a WARN and one
  signed `subsystem_degraded` (`reason: inode_identity_unverified`, the
  filesystems, counts, first paths); `KERNEL_COMPATIBILITY.md` documents
  the limit, and `nn-lab.sh overlay-check` (modelled on `btrfs-check`)
  fails on silence. EBPF-020: `attach_lsm`, which adopted any pinned link
  that re-opened, and `fresh_attach_and_pin`, its only user, are removed
  from `antitamper-bpf` and its re-export; `reattach_fresh` is the one
  pinned LSM attach. ATP-015: the doc comments of the observer
  register/evict say where the no-bpffs mode is logged and that evict has
  nothing to withdraw. No eBPF program changes. **Regressions / changes:**
  an install whose state directory is a symbolic link does not start (use
  a bind mount; upgrade notes §2), and neither does one whose
  `/etc/northnarrow`, unit drop-in directory or bpffs pin root is a link;
  the `DENY HOOK SHORTFALL` line has two new fields and the refusal reads
  "N of M deny hooks attached and armed; missing: …; K protection step(s)
  failed: …"; a degraded start, missing observe hooks, foreign `link_*`
  pins and paths on overlayfs, FUSE or NFS each add signed records (a host
  with an overlay root gets one at every boot); `attach_lsm` and
  `fresh_attach_and_pin` are no longer part of `antitamper-bpf`.
- Lab follow-ups of lab PRs 176 and 180, and nn-admin on a closed pipe
  (lab PR 188). A stale `NORTHNARROW_COMBAT` chain torn down at start was
  signed (`combat_reconcile`), but its compatibility line in
  `/var/lib/northnarrow/combat-audit.jsonl` was refused with EPERM
  whenever the file did not exist: it was written at the teardown, and
  the state directory is `chattr +i` from one run to the next, which
  refuses a new entry to everyone. The line is now written once the state
  directory's protection is set up, an existing file appended as before,
  a missing one created `0600` with the directory's `+i` lifted for that
  moment and put back, as for the agent's other state files. The COMBAT isolation
  trusted any `iptables-restore` that exited 0: root could point the
  `iptables-restore` link or its `/etc/alternatives` entry at another
  root-owned system binary (`/usr/bin/true`), and COMBAT logged "network
  isolated" with nothing applied. After the restore the agent reads the
  table back (`iptables -S`): the chain must reach its catch-all DROP (no
  unconditional ACCEPT or RETURN ahead of it) and INPUT, OUTPUT and the
  ruleset's FORWARD must jump into it; otherwise an ERROR "COMBAT:
  isolation NOT in place …" naming the restore binary and the gaps, the
  engage fails ("COMBAT isolate failed") and `nn-admin status` says
  `network_isolation_engaged: false`. The v6 leg is read back too and
  stays best-effort (a WARN, v4 kept). `fim-paths.v1` watches
  `/usr/sbin/iptables-restore` and `/usr/sbin/ip6tables-restore`, and
  with them each link and `/etc/alternatives` entry up to the target, so
  re-pointing one is NN-L-FIM-001 drift (Critical, KillProcessTree; Log
  Low inside a package transaction, as for every system binary). `nn-admin`
  aborted (exit 134, a panic message) when its stdout was a pipe closed
  early (`nn-admin status | grep -m1 …`): every line it prints goes
  through one writer, and a closed stdout or stderr ends the command
  quietly with 141 (128 + SIGPIPE), `audit read` included. **Regressions /
  changes:** a host whose `iptables-restore` exits 0 without applying the
  ruleset is no longer reported isolated; an engage whose read-back finds
  the table emptied clears the isolated state; the shipped `fim-paths.v1`
  changed (`install.sh` replaces the previous copy; run `nn-admin fim
  baseline` so the two new paths have a baseline row — until then each
  change of their target is drift without a baseline); an admin's own
  `update-alternatives --set iptables …` outside a package transaction
  is NN-L-FIM-001 on the two links, as it already was on
  `/usr/sbin/iptables`; `nn-admin … | head` exits 141 instead of 134.
- External audit, Wave 3, kernel record fidelity (Low EBPF-017
  NN-AUD-268, EBPF-019 NN-AUD-270, EBPF-021 NN-AUD-272, EBPF-022
  NN-AUD-426; lab PR 187). EBPF-021: the exec record keeps the first 511
  bytes of the command line and the first 256 of the caller's path, and
  said nothing when it cut them: filler options (`socat -d -d … TCP:…
  EXEC:/bin/sh`) pushed the argument a rule decides on past the cut and
  the argv looked whole, so the distribution's socat read as a relay
  (Log High) instead of a shell (killed). The kernel now marks both in
  the first byte of `ProcessSpawnRaw`'s former pad, `trunc_flags`
  (`wire::spawn_trunc`: argv longer than 512 bytes or unread, path longer
  than 256 bytes with its NUL; size 1,400 and every offset unchanged, an
  older object leaves it 0), decoded into `Event::ProcessSpawn {
  argv_truncated, filename_truncated }` (serde default `false`: an older
  record reads as "not known to be cut"). R006 does not classify a
  distribution socat whose argv is cut and whose part kept runs no shell
  as a relay: Log at Critical, the severity of one that runs a shell,
  with the cut named; R013, R015 and R017, whose argv only enriches the
  reasoning, and R006's kill name the cut too. A cut caller's path is
  never normalised lexically into the image path (what followed the cut
  may climb out of any prefix): the running image names it. An executable
  path component of 31 bytes, possibly cut by the kernel's read, ends in
  `…`, as the file-open sensor's do since lab PR 137. EBPF-017: the
  budget of task-denial records (refused signals and ptrace attaches on a
  protected pid) was one `Array` read, changed and written from every
  CPU, and a record over it left no count; it is per CPU (50 a second per
  CPU), and a record held back is counted in a new `RING_DROPS` slot,
  `task_denial_rate` (18, appended; 19 slots), a security ring: journal
  WARN, signed `ringbuf_drop`, `TelemetryLoss` past 64 in a sample. The
  deny never depended on the record. EBPF-019: the WARN for a TCP close
  with a kernel correlator and no pending flow logged the whole
  correlator, whose second half is the socket's kernel address; it logs
  `corr_start_ns`, the connect's timestamp half. EBPF-022: the empty
  `else` blocks and stale "marker" comments of `inode_protect.rs`, the
  unused flag of the FIM rename observer, and `module_load.rs`'s "256
  bytes" (512) are gone; `kdbx_suffix` scans from position 0, so a file
  named `.kdbx` is a credential leaf (now in `common`, tested); the eBPF
  profiles say `debug = 2` and `cargo xtask build-ebpf` refuses an object
  without `.BTF`; the compatibility matrix's counts are dated. eBPF:
  `sched_process_exec` 512 → 524 BPF instructions,
  `fim_file_open_sensor` 2,148 → 2,153 (the bounded `.kdbx` scan runs one
  more step), `task_kill` and `ptrace_access_check` the same size; no
  loop added. **Regressions / changes:** a distribution socat with a
  command line over 511 bytes and no shell address in that part is a
  Critical record (High before); a cut argv ends the reasoning of R006,
  R013, R015 and R017 with `[argv truncated at 511 bytes: arguments past
  the cut were not seen]`; on N CPUs up to 50 × N task-denial records a
  second reach the 64 KiB ring (3,200 on 64 CPUs); a burst of refused
  signals or ptrace attaches shows `task_denial_rate` in `nn-admin
  status`, a signed `ringbuf_drop` and an ALERTED `TelemetryLoss` (the
  first denial already locked COMBAT); the journal field `corr_id` of "TCP
  close had a kernel flow id but no pending flow" is `corr_start_ns`
  (update searches); an executable path with a component of exactly 31
  bytes reads with `…`, so an allowlist or canary path naming such a file
  no longer equals the kernel's path (a canary still matches the caller's
  string); when the process is gone before its exec is read, a cut
  caller's path is left as the caller passed it instead of normalised.
  CI found what the new `.BTF` check is for: its workflow-wide
  `RUSTFLAGS: -D warnings` replaced the eBPF target's rustflags of
  `agent-ebpf/.cargo/config.toml` (`-C debuginfo=2`, `--btf`), so the
  CI-built object had no `.BTF` (the release workflow sets no global
  RUSTFLAGS, its objects were whole); `xtask build-ebpf` now drops
  `RUSTFLAGS` and `CARGO_ENCODED_RUSTFLAGS` from the nested eBPF build.
- External audit, Wave 3, network rule state (Low NETR-012 NN-AUD-295,
  NETR-015 NN-AUD-298, NETR-016 NN-AUD-428; lab PR 186). NETR-015:
  NN-L-NET-006 and -019 left alone every listener on 22, 53, 80, 443,
  8080 and 8443 before judging it, so any process of any user serving
  8080 or 8443 — a binary from `/tmp` or a home, `python3 /tmp/x.py` —
  was never recorded. A common port now exempts a listener only when its
  program is one a root-owned tree installed: the executable (from the
  process lineage, else `/proc`; the listener record names none) and, for
  an interpreter, the script it runs, by an absolute path, in `/usr`,
  `/opt`, `/snap`, `/bin`, `/sbin`, `/lib`, `/lib64` or `/nix/store`.
  nginx, sshd, systemd's socket units or systemd-resolved stay quiet on
  their ports; any other program is judged as on any other port (the comm
  allowlist, then a Medium record), and the reasoning names the port. The
  audit's other half, 443 among NN-L-NET-010's C2 ports, is declined: that
  rule kills, so it would kill every client outside the comm allowlist;
  C2 over 443 is answered by -001/-002, -008, -013 and the chains.
  NETR-012: the DNS name-shape dedup hashed names with
  `DefaultHasher::new()`, whose keys are fixed, so a name that collides
  with another could be computed offline and have its verdict dropped as
  a repeat; and it swept its whole map on every suspicious query, with no
  bound but the 2 s window. The hash (NN-L-NET-014's corroboration keys
  too) is SipHash keyed once per process; the map is swept every 256
  calls, a lookup compares the stored time (a pair past the window never
  suppresses a verdict), and at 4,096 pairs the one fired least recently
  goes. NETR-016: since lab PR 140, -014 runs before -004; when -014
  dropped a lookup's repeated leg (the AAAA, a retry, the resolver's
  forwarded leg) as a duplicate, the first-match engine handed it to
  -004, which recorded it — two records per lookup of a long name with a
  high-entropy label. The two rules now share one dedup window, so a
  lookup gives one verdict from the family, and their documentation
  describes the current order. NETR-011 (fixed in lab PR 140) gains the
  audit's case as a test. **Regressions / changes:** a listener on 22,
  53, 80, 443, 8080 or 8443 whose program lies outside those trees, is a
  module run with `-m` or an inline program, or whose executable cannot
  be read (it exited first) is a Medium record (NN-L-NET-019 on a
  wildcard address, -006 otherwise) and moves the posture to ALERTED — a
  developer server on 8080 (`python3 -m http.server`, node under
  `~/.nvm`) included, as on 8000 or 3000 before; the comm allowlist
  cannot exempt such a program (its entries name system-tree programs);
  -006/-019 reasoning on a common port reads `on port 8080, a common
  service port, from a program not installed in a root-owned system
  tree …`; a long high-entropy DNS name gives one record (NN-L-NET-014)
  per lookup where it gave two; the qname hash changes at every agent
  start (in-memory state only).
- External audit, Wave 3, agent identity (Low MAIN-009 NN-AUD-251,
  MAIN-010 NN-AUD-252, EVD-020 NN-AUD-282; lab PR 185). MAIN-009: the
  agent read `/etc/northnarrow/agent_id` twice at boot — before the attach
  for the overlay gate, after it for the audit log, the chains and the
  admin plane — and each read fell back with a WARN to the all-zero id,
  the one the test fixtures sign with, when the file could not be used.
  Now one read (`agent_id::resolve`) feeds all of them; a file that
  cannot be used (corrupted, all zeros, unreadable, a mint that cannot be
  written) gives a per-boot random id, never written: an ERROR, and a
  signed `integrity_drift` `subsystem_degraded` naming the reason and the
  id once the audit log is open. Nothing signed for another install or
  for zero verifies; signed admin requests and overlays made for the
  install's id are refused for that boot (the legacy unlock does not bind
  the id); one signed for the per-boot id — the `agent_id` of that boot's
  audit rows, in a file passed with `--agent-id-file` — opens the
  trusted-installer window that repairs the file. An all-zero `agent_id`
  on disk is corruption. EVD-020: a missing `agent_id` was minted and
  written with an INFO line only, and its rename was not synced. The mint
  now goes through `atomic_file::replace` (`.agent_id.tmp` removed, never
  followed, mode on the descriptor, file and directory synced: a
  leftover `agent_id.tmp` no longer blocks it), and the boot signs it:
  `agent_id_minted` (the file, the id, the id the chain's last row
  carried). An id other than the one the audit chain's last row carries
  — the file removed and minted again, replaced, or unusable while the
  agent was not running — is an ERROR (`AGENT IDENTITY CHANGED`) and a
  signed `integrity_drift` `agent_id_changed` with `from`, `to` and
  `source` (`loaded`, `minted`, `unavailable`), written with the agent key
  that signed the rows before it, ahead of the boot's `agent_boot` (a
  refused boot records it too). MAIN-010: 21 `nn-admin` paths and `config
  overlay status` read the id with the agent's `load_or_bootstrap`, which
  minted and wrote one when the file was missing: a read-only command run
  before the agent's first start created the identity the agent then
  adopted without a trace, and `config overlay sign` signed an overlay
  for it. They now use `agent_id::load_existing`: "agent_id not found at
  …: the agent creates it at its first start", and nothing is created.
  Format: no field changes; the new rows are ordinary numbered rows (op
  `agent_id_minted`, `integrity_drift` kind `agent_id_changed`), existing
  rows keep their bytes and verify, and an `nn-admin` older than the
  agent verifies the new rows too (unlike lab PRs 160 and 179, nothing
  changes for older readers). **Regressions / changes:** `nn-admin` run
  before the agent's first start fails (exit 5) instead of minting
  `agent_id`; overlays can no longer be signed before it unless
  `agent_id` is pre-seeded (32 hex characters and a newline, mode 0644);
  the first start after `agent_id` is deliberately removed, replaced or
  restored from a backup reports `agent_id_changed` once (intended); a
  host whose `agent_id` is all zeros, or unusable, boots on a per-boot id
  and refuses zero-id signed requests; a restart under the previous
  instance's pinned hooks whose early registration failed (EBPF-015) and
  whose `agent_id` is missing cannot mint it and boots on a per-boot id
  (the old second read minted it after the attach).
- External audit, Wave 3, units and package hooks (Low DEP-005 NN-AUD-381,
  DEP-010 NN-AUD-382, DEP-014 NN-AUD-386, DEP-017 NN-AUD-389; lab PR 184).
  DEP-014: the watchdog's unit kept `CAP_SYS_ADMIN` "for the historical
  bpf(2) shape"; nothing it does needs it — opening the pinned maps,
  claiming its role slot and the `PROTECTED_PIDS` insert/delete are
  `bpf_capable()` (CAP_BPF from 5.8, the floor), and the respawn's
  `systemctl start` is authorised by uid 0 on systemd's private socket,
  which carries no capabilities. The bounding set is `CAP_BPF
  CAP_SYS_PTRACE`. DEP-005: `MemoryMax=11G` with `OOMScoreAdjust=-500` on a
  host with no more memory than that: the cap cannot bind, and a leaking
  agent would outlive sshd and the workload. The sizes stay absolute
  (the self-integrity check cannot compare `N%` with the cgroup and would
  drop the expectation; a test now keeps every limit the units set
  understood); instead, at start, an agent in its unit's cgroup whose
  `memory.max` is at or above `MemTotal` raises its own `oom_score_adj`
  to 0 (raising needs no capability) with a WARN, and the limits round
  expects 0 on such a host, -500 elsewhere. DEP-017: the agent's unit sets
  `LogRateLimitIntervalSec=30s` / `LogRateLimitBurst=50000` — journald's
  default of 10000 per 30 s dropped the rest of a burst, the
  `chain head anchored` lines forwarded off the host included — bounded,
  not 0, with the namespace capped at 1 GiB; the journald config says why
  it sets neither a rate limit nor `Seal=`, and EVIDENCE_CHAINS.md how to
  seal the journal with `journalctl --setup-keys`. DEP-010: the `.deb`
  rollback (postinst `abort-upgrade|abort-remove|abort-deconfigure`,
  postrm `abort-install|abort-upgrade`) started the stopped units with
  `|| true` and exited 0 whatever came back; the two hooks share one
  `restart_stopped` (a test keeps the copies equal), which checks
  `systemctl is-active` after the starts, names every unit left down on
  stderr and at `auth.err` (`northnarrow-pkg`), keeps the restart list
  and fails the hook. The lab's tamper case C18 puts back the agent's own
  `oom_score_adj` instead of -500. **Regressions / changes:** a failed
  rollback that leaves a unit down is a failed package operation, the
  package half-installed; on hosts up to 11 GiB of `MemTotal` (the 8 GiB
  lab guests included) the agent runs at `oom_score_adj` 0, an ordinary
  OOM candidate the watchdog respawns, and an install that kept -500
  there is a `limit_unexpected` finding; an agent log burst can take
  50000 lines per 30 s of the namespace; the watchdog's `exec` backend
  inside its unit (unsupported) loses `CAP_SYS_ADMIN` too. Not changed:
  `rpm` has no rollback scripts; `nn-admin host-check` gets no memory line
  (the triage's WARN would be permanent on every small host, with no fix
  for the operator).
- External audit, Wave 3, dependency advisory policy (Low SUP-007
  NN-AUD-393, SUP-008 NN-AUD-394, SUP-009 NN-AUD-395, SUP-010 NN-AUD-396,
  SUP-011 NN-AUD-443; lab PR 183). The RustSEC job failed on
  vulnerabilities only: `unsound` and `unmaintained` advisories were
  warnings that ci.yml said Dependabot tracked — it fails no build and
  bumps the manifests' own dependencies only — and nothing recorded why
  the five on today's lockfiles were let through. The audit job now runs
  `cargo audit --deny unsound --deny unmaintained` on the three
  lockfiles, and the new `.cargo/audit.toml` denies the same, so a local
  `cargo audit` from the repository root gives the CI verdict. An advisory that cannot be fixed
  is a recorded exception there: the ID with the crate and the locked
  version it was reasoned about, why it cannot be reached or has no fix,
  an owner, the event that reopens it, the day it was recorded and an
  expiry at most 184 days later; a new step of the audit job
  (`.github/scripts/check-audit-exceptions.sh`, on the daily schedule
  too) fails once an expiry has passed. Accepted until 2027-01-20: lru
  0.12.5, RUSTSEC-2026-0253 and RUSTSEC-2026-0002 (SUP-008/009: only
  tantivy 0.25.0 depends on it, with `usize` keys and no `iter_mut`; the
  fixed releases are beyond its `^0.12`, and the release profile aborts
  on panic); paste 1.0.15, RUSTSEC-2024-0436 (SUP-011: archived, a
  build-time proc-macro of the candle/tokenizers chain); and
  unsafe-libyaml 0.2.11, RUSTSEC-2024-0449, found by the new gate
  (published 2026-10-12, after the triage): archived, reached only
  through xtask's `serde_yaml_ng`, which parses the committed workflows
  and the sha256-pinned Sigma tarball; moving xtask to a YAML parser in
  safe Rust is a follow-up. SUP-010: memmap2 0.9.10 → 0.9.11 in
  `Cargo.lock` (RUSTSEC-2026-0186; `fuzz/Cargo.lock` had it already),
  lockfile only. **Regressions / changes:** a newly published unsound or
  unmaintained advisory turns the audit job red, on the daily run of an
  unchanged `main` too, until it is fixed or recorded; from 2027-01-21
  the job is red until the four exceptions are re-checked and recorded
  again, or dropped; a tantivy, candle or tokenizers bump that moves lru
  or paste off the recorded version fails `xtask/tests/supply_chain.rs`
  until the entry is dropped or rewritten; a bump of one of 27 security
  crates (tokio, serde, serde_json, postcard, ciborium, the signature and
  hash crates, libc, nix, aya, object, procfs, tantivy, candle-core,
  tokenizers, safetensors, memmap2, lru, paste) must land in `Cargo.lock`
  and `fuzz/Cargo.lock` alike, or the same test file fails.
- External audit, Wave 3, ADE prompt inputs (Low LLMP-012 NN-AUD-323,
  LLMP-014 NN-AUD-324, LLMR-011 NN-AUD-326; lab PR 182). The trusted block
  of every ADE prompt (`=== TRUSTED CONTEXT (issued by NorthNarrow,
  immutable) ===`) printed the hostname, the kernel release and
  `/etc/machine-id` as they were read, only trimmed: `sethostname(2)`
  takes any 64 bytes, a newline included, and the machine id was read
  whole, so root could end the block and add its own "trusted" lines or
  sections. `HostContext::discover` now makes each one sanitized line
  (`ade::sanitize::sanitize_line`, over the event sanitizer: control
  characters, NEL and the Unicode line separators as `?`, zero-width and
  bidi characters dropped, chat-template tokens masked, `===` neutralised)
  of at most 64 characters, `unknown` when nothing is left; the machine id
  is 32 lowercase hex characters, read through a 64-byte window, or
  `unknown`. The prompt sanitizes every trusted-context line again when it
  prints it (`host_role` and the language included), and the XAI
  `environment_hash` takes its hostname from the same function (its
  `canonical_hostname` was a second raw read). LLMR-011, the part left
  after lab PR 145: a RAG title goes through the same line sanitizer,
  capped at 160 characters, before the period rule, and the retrieval
  query is built from the sanitized event (`build_rag_query`, which
  replaces `build_rag_query_from_event`). LLMP-012: the unhardened
  `ade::prompt::build_event_prompt`, with no caller but its own tests, is
  removed with its helpers. Clean values print byte for byte as before: a
  whole prompt is pinned as the previous code rendered it, and every title
  of the pinned corpus (36 seed titles, the 934 of the pinned dumps) renders
  as before. **Regressions / changes:** a host whose `/etc/machine-id` is
  not 32 lowercase hex characters (`uninitialized`, upper case, anything
  else) has `unknown` as host id in the prompt, the XAI snapshot and the
  verdict metadata; a hostname or kernel release with a control character,
  a line separator or `===` is shown neutralised (and the XAI
  `environment_hash` changes with it); a path longer than 256 characters
  is cut in the RAG query as it already was in the prompt. Nothing an
  operator sees changes on a host with clean values.
- External audit, Wave 3, COMBAT guard and self-protection (Low CMB-022
  NN-AUD-313, CMB-024 NN-AUD-315, CMB-025 NN-AUD-316, CMB-028 NN-AUD-431;
  lab PR 181). CMB-022: the COMBAT guard took an unreadable
  `/proc/<pid>/exe` for "not protected". Without `CAP_SYS_PTRACE` (a
  drop-in narrowing the unit's bounding set) the kernel refuses that link
  for every process of another uid, every non-dumpable one and every root
  process holding a capability the agent lacks — sshd and the watchdog
  among them — so there the ladder would kill or net-cut the SSH service.
  The audit's "unreadable means protected" is not what was done (any
  process could buy immunity with `PR_SET_DUMPABLE=0` and push the ladder
  to ISOLATE): an unreadable executable is spared only on an anchor the
  process cannot forge — the watchdog slot's PID with its verified start
  time, or real uid 0 in an SSH unit (`ssh.service`, `sshd.service`,
  `ssh@`/`sshd@` instances) or in `northnarrow-watchdog.service` of the
  system manager (`/system.slice/…`, never a unit a user's manager
  named); any other PID is fair game. A WARN at most once a minute says
  which way each went (`COMBAT guard: /proc/<pid>/exe unreadable`, with
  the anchor and the count held back). CMB-028: the capability preflight
  reads the effective set with `capget(2)`, `CapEff` of
  `/proc/thread-self/status` as the cross-check (where they differ, only
  what both report counts); a set readable neither way refuses the start
  in enforcement, as a missing `CAP_KILL` does. Every other missing
  capability is, in enforcement, an ERROR (`capability preflight: CAP_…
  missing from the effective capability set: … unavailable`) and a signed
  `subsystem_degraded` at each boot — `CAP_SYS_PTRACE` names what it takes
  (quarantine targets, lineage, the watchdog's verification, the COMBAT
  guard's exe check, `/proc/1/root`); in detect-only a WARN. The
  `CAP_NET_ADMIN` text names the nft egress block next to
  iptables/ip6tables-restore. CMB-024: the quarantine's read is bounded
  by `quarantine_max_bytes` as its size check was — a file that grew in
  between (a running script) is refused (`TooLarge`, nothing vaulted or
  removed); `size_bytes` is what was read. CMB-025: besides the default
  install paths, the quarantine (and `nn-admin response restore` as a
  destination) refuses the agent's own files where this host keeps them,
  set once at boot: the running binary and its `northnarrow-*` /
  `nn-admin*` siblings, `--watchdog-exe`, the master key, the vault and
  the containment record (an INFO line lists them); `/opt` is not denied
  wholesale. Lab builds (`debug-trigger`) answer the PIDs written to
  `/run/northnarrow/debug-protected-query` with the guard's decision.
  **Regressions / changes:** an agent in enforcement whose capability set
  can be read neither by `capget(2)` nor from procfs no longer starts
  (WARN before; `--detect-only` still starts); a missing capability other
  than `CAP_KILL` is an ERROR and a signed `subsystem_degraded` at every
  boot in enforcement (a WARN `capability missing from effective set`
  before — update journal searches); without `CAP_SYS_PTRACE`, root
  processes of the SSH and watchdog units whose executable cannot be read
  are spared (skipped, the ladder escalating as for any spared offender)
  where they were killed; a binary that grows past the maximum while it is
  read is no longer quarantined; a vault entry's `size_bytes` is the bytes
  read; restore refuses the agent's own files as destinations.
- External audit, Wave 3, unit and mount tampering (Low MAIN-013
  NN-AUD-255, MAIN-015 NN-AUD-257, EVD-011 NN-AUD-276, EVD-014 NN-AUD-277;
  lab PR 180). The self-integrity check looked for the agent's drop-ins in
  8 of the 13 directories of systemd's unit search path: a `.conf` under
  `/etc/systemd/system.attached/northnarrow-agent.service.d/` (or
  `/run/systemd/system.attached`, or a generator directory) changed the
  unit at the next `daemon-reload` — `ExecStart=`, `Environment=` (lab PR
  176's `PATH` included), `CapabilityBoundingSet=` — and no round saw it.
  The drop-ins are now read from the one list the unit copies were already
  read from, the whole search path (a directory reached by two spellings
  counts once); the shipped Debian drop-in is still accepted only at its
  path and with its content. EVD-014: a round that could not read
  `/proc/1/mountinfo` checked no mount and said nothing; it now reads the
  agent's own namespace (`/proc/self/mountinfo`, where the unit's own
  `ReadWritePaths=` binds are not findings), and when neither can be read
  it records `mountinfo_unreadable` (ERROR, signed `integrity_drift`)
  while that lasts. The mount check also matched only mount points at or
  below the protected paths: a tmpfs over `/var/lib`, a bind over `/etc`
  or `/usr/local/bin`, a second bpffs stacked on `/sys/fs/bpf` hid the
  state directory, the configuration and the unit files, the binaries or
  the pins from the operator, `nn-admin` and the agent's next start,
  unseen. Each watched path's mount chain is now recorded at the agent's
  start (`mount_round`); a mount laid since over a directory above one is
  `mount_over_protected` ("… hides …"), and a mount it resolved through
  that is gone `protected_mount_gone`. MAIN-013: a stale
  `NORTHNARROW_COMBAT` chain torn down at start was recorded only in the
  unsigned `combat-audit.jsonl`, opened by its literal path with the
  default mode; the outcome is now kept until the audit log is open and
  signed there (`integrity_drift`, kind `combat_reconcile`, result
  `repaired` with `rules_torn_down`, or `failed` when the chain could not
  be checked or torn down and the host may still be isolated — not when
  there is no trusted iptables to check with); the jsonl line stays,
  written through the anchored state directory, `O_NOFOLLOW`, a FIFO or
  any other non-regular file refused without waiting, created `0600`.
  MAIN-015: `anchored::anchor` returned the unanchored path in silence when
  a parent could not be opened, switching off the mount-diversion
  protection for that log; that is now an ERROR once per directory (a
  missing parent stays silent); the cap the audit proposed is declined
  (every caller anchors a fixed path from the command line, now
  documented). **Regressions / changes:** drop-ins in the newly read
  directories are `unit_dropin` findings (stock Ubuntu 22.04/24.04 and
  Debian 12/13 keep none there for the agent's units); a mount laid over
  a directory above the agent's paths after its start is reported even
  when it is the host's own (a late remote `/var/lib`, an automount on
  `/usr/local`) until the agent restarts with it in place; mounts present
  at the start are not judged by the new check (the check on the paths
  themselves still runs at boot); new signed kinds `mountinfo_unreadable`,
  `protected_mount_gone`, `combat_reconcile`; `combat-audit.jsonl` is
  created `0600` (an existing file keeps its mode, `install.sh` already
  closes it).
- External audit, Wave 3, admin socket peers and request cost (Low
  ASK-005 NN-AUD-236, ASK-012 NN-AUD-238, ASK-013 NN-AUD-239, ASK-014
  NN-AUD-240, EVD-010 NN-AUD-275; lab PR 179). The admin socket's only
  gate was its mode 0600: `SO_PEERCRED` fed the audit fields alone, a
  failed `getsockopt` was recorded as uid 0 and the returned length was
  not checked, so a socket or directory whose mode had been widened served
  any local user (`status` and its drop counters, challenges, the
  unauthenticated plumbing). The accept loop now checks the peer before it
  gets a slot: uid 0, or the agent's own euid (the same in production),
  is served; another uid, credentials that cannot be read or a short
  reply is closed without a reply, an ERROR at most every 10 s and one
  signed `integrity_drift` `admin_socket_foreign_peer` per 10 minutes
  (with the count of the others). ASK-013: `client_comm` is the name the
  peer gave itself; rows of admin operations now also carry
  `client_exe`, `/proc/<pid>/exe`, and the triage status events
  `principal_exe`, both read while a pidfd on the peer (`SO_PEERPIDFD`
  from 6.5, `pidfd_open` before) shows it alive — a peer gone by then is
  `<exited>`, not whatever holds its pid. ASK-005: each request's work
  (the bounded reads, the per-row signature checks, the chain appends,
  the audit row's fsync under its mutex) runs through `block_in_place`
  (the FIM drain's helper, moved to `crate::runtime`) instead of holding
  a runtime worker; the reply still follows its audit row, one request
  at a time per connection. EVD-010: `detections` kept every matching
  record of a file with its raw line before cutting; the collector now
  keeps the newest `limit` (`limit` + 1,000 with the agent key) in a
  bounded heap, same rows returned. ASK-014: the stop-time unlink of the
  socket uses `lstat` + `unlink` (a dangling link was left behind; the
  bind at start was fixed in lab PR 170). **Regressions / changes:** a
  non-root process can no longer use the admin socket even if its mode
  is widened (root, `sudo nn-admin`, the watchdog unaffected); a
  descriptor passed on by a root process keeps root's credentials (the
  check is on who connected); new rows carry `client_exe` /
  `principal_exe`, which an `nn-admin` older than the agent reports as a
  broken row (as with lab PR 160's `seq`; upgrade the binaries together);
  rows written before keep their bytes and verify; new signed kind
  `admin_socket_foreign_peer`.
- External audit, Wave 3, deception readers and deploy inputs (Low DEC-012
  NN-AUD-337, DEC-015 NN-AUD-340, DEC-016 NN-AUD-341, DEC-017 NN-AUD-342;
  lab PR 178). One complete line that is not UTF-8 in `canaries.jsonl` or
  `canary_access.jsonl` still switched deception off at boot: the readers'
  `BufRead::lines()` returned `InvalidData`, the `?` failed the open, and
  the agent logged "canary registry open failed" and ran with no canary
  armed and no trip recorded — the DEC-006 skip of lab PR 90 covered only
  a line that did not parse. The lines had no cap either: a multi-GiB line
  was read into memory at boot. Both chains now go through one bounded
  reader (`canary::chain_lines`): a line is at most 1 MiB (every row the
  agent writes is far below, its operator strings coming from one signed
  64 KiB admin frame; the writers refuse a longer row rather than write
  one the next boot would skip), a longer one is consumed to its newline
  without being stored, and a line over the cap or not UTF-8 is skipped
  and counted like a malformed one (the signed `chain_lines_unreadable`
  at boot); the rows after it are applied. An operator credential template
  is read without following a link at its name, without blocking on a
  FIFO, from a regular file of at most 64 KiB (`MAX_TEMPLATE_BYTES`): the
  templates are write-allowed at run time by design, so one grown in place
  — or a missing family's file created as a link to `/dev/zero` — was read
  without limit by the next `canary deploy`; a template there but refused
  is `TemplateRead`, the deploy (or refresh) refused and the file named,
  never a silent fall-back to the built-in one. Any `{{` left after the
  substitution is `UnresolvedPlaceholder` (an unclosed `{{tenant_id`
  passed and went into the decoy), with the name shown escaped and at most
  32 characters; an azure, gcp or docker decoy must parse as JSON
  (`MalformedOutput`). A File / Credential canary path is checked for
  control characters and a length under `PATH_MAX`, then normalised (`//`
  and a trailing `/` folded) before the deny prefixes are matched, and the
  deploy writes, records and watches that normal form: `//lib32/x` missed
  `/lib32/`, and on a host without `/lib32` the write created the
  directory. A test now pins `accessor_exe` (NN-AUD-339, fixed in lab PR
  99). **Regression:** an operator template over 64 KiB, a symbolic link
  or a non-regular file at a template's name, a template with a literal
  `{{`, or a JSON family's template that does not render JSON now refuses
  the deploy and the refresh of that family, naming the file; a canary
  path with a control character or of `PATH_MAX` bytes or more is refused,
  and one written with `//` is recorded under its normal form.
- External audit, Wave 3, process rule precision (Low PROC-012
  NN-AUD-300, PROC-013 NN-AUD-301; lab PR 177). R015 (an encoder:
  `base64`, `xxd`, `openssl`) and R016 (a debugger: `gdb`, `strace`,
  `ltrace`) judge an exec by a service account, and their class stopped
  at uid 1000: `nobody` (65534) and the transient accounts of systemd's
  `DynamicUser=yes` units (61184..65519), service accounts both, were
  never judged — a web shell under a `nobody` worker decoding its payload
  with `base64 -d` drew no record. One helper, `is_service_uid`
  (`decision/rules/mod.rs`), is now the class of both rules: 1..999,
  65534 and 61184..65519. Root, the human accounts (1000..60000, and
  systemd-homed's 60001..60513) and the container ranges stay out: a
  rootless container's sub-uids (`/etc/subuid`, 100000 and up by
  default) belong to the user who owns the range, who can become any of
  them (`podman unshare`), and from the host's uid alone a container's
  daemon is not told apart from its root or its users (systemd-nspawn's
  524288 and up likewise). R008 (an executable in a hidden directory of a
  home) exempted the whole of `~/.cache/` and `~/.config/`, so a binary
  dropped in `~/.cache/<anything>/`, or in the user's persistence
  directories `~/.config/systemd/` and `~/.config/autostart/`, drew no
  record; its comment said "filename contains" where the code matches a
  prefix of the path relative to `/home/<user>/`. Under those two only the
  directories of named tools that run their own executables there are
  exempt now, each with its reason in the code: `.cache/go-build/` (Go
  1.24's `go run` and `go tool`), `.cache/bazel/`, `.cache/bazelisk/`,
  `.cache/ms-playwright/`, `.cache/puppeteer/`, `.cache/Cypress/`,
  `.cache/selenium/`, `.cache/pre-commit/`, `.cache/uv/`,
  `.cache/pypoetry/virtualenvs/`, `.cache/yay/`, `.cache/paru/`,
  `.cache/coursier/arc/`, `.cache/JetBrains/RemoteDev/`, the
  `User/globalStorage/` of the VS Code family under `.config/` (`Code`,
  `Code - OSS`, `VSCodium`, `Cursor`) and `.config/coc/extensions/`; the
  comment describes the prefix match. The other entries (`.cargo/bin/`,
  `.local/bin/`, `.npm/`, …) are unchanged, and R008 still judges the file
  the kernel executed (review 61): a script is judged by its interpreter.
  The three rules only record (Log, Medium); nothing more is killed.
  **Regressions:** a native executable another tool keeps and runs under
  `~/.cache/` or `~/.config/` — Sublime Text's language servers in
  `~/.cache/sublime-text/`, NixOS's `appimage-run` in
  `~/.cache/appimage-run/`, an editor of the VS Code family not listed —
  draws an R008 record at each run, and R008 has no operator allowlist; a
  daemon running as `nobody` or as a `DynamicUser=` account that runs one
  of the six tools draws an R015 or R016 record (an entry in the signed
  `process-comm-allowlist.local` exempts the program).
- External audit, Wave 3, COMBAT isolation integrity (Low ATP-006
  NN-AUD-259, ATP-014 NN-AUD-262; lab PR 176). COMBAT's isolation ran
  `iptables-restore`, `iptables` and their v6 pair by bare name, searched
  on the `PATH` the agent inherited: the unit set none, and systemd's
  default for a service starts with `/usr/local/sbin:/usr/local/bin`,
  which the FIM list does not watch and the anti-tamper hooks leave open
  (lab PR 152). An `iptables-restore` planted there that exits 0 turned
  every COMBAT isolation into a no-op the agent logged as "network
  isolated". The same held for `nft` (the per-process egress block, the
  retired blackout's cleanup) and `rpm` (R018's module provenance: one
  that exits 0 made every module file "packaged"). A shared helper
  (`trusted_bin`) now looks a binary up in `/usr/sbin`, `/usr/bin`,
  `/sbin` and `/bin` only, whatever `PATH` says, follows its links
  (`/etc/alternatives`) to the real file, and runs that file — with
  `argv[0]` the name, which a multi-call `xtables-nft-multi` needs — only
  when it lies in one of those directories, is an executable regular file
  owned by root that nobody else can write, in directories root owns and
  nobody else can write, from `/` down. A refused copy gives way to the
  next directory's, with a WARN. Without a trusted one the step fails as a
  missing binary did: the engage errors, `nft` is the recorded failure
  (`ENOENT`, "is nftables installed?"), R018 judges as without a package
  database. The boot names the files the isolation will run (`COMBAT
  isolation binaries`) or logs an ERROR when there is no trusted
  `iptables`; the "network isolated" line names `restore_bin`.
  `nn-admin host-check`, the boot's `nft` check and `install.sh` look for
  `nft` the same way. Both units set
  `Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin` (defence in depth for
  anything they start). NN-AUD-259: after a successful restore `engage()`
  returned the v4 jump dedup's error before recording the isolation — the
  host was isolated while `nn-admin status` said
  `network_isolation_engaged: false` and the ladder logged "COMBAT isolate
  failed". The state is recorded as soon as the restore succeeds; a failed
  dedup is an ERROR (the duplicate jump isolates too), not a failed
  engage, as the v6 mirror already did. The release removes every jump
  into the chain, one `-D` per jump `iptables -S` lists: with a duplicate
  left, its single `-D` per base chain let `-X` fail after the flush had
  put the host back on the network, still reported isolated.
  **Regressions:** an `iptables`, `ip6tables`, `nft` or `rpm` present only
  under `/usr/local` (or anywhere outside the four directories) is no
  longer run — the isolation fails (ERROR at boot, failed STAGE 3), the
  egress block records its failure, `install.sh` refuses the host without
  `--without-nftables`, R018 has no rpm provenance; a binary or directory
  in the chain that is not root's, or that group or others can write, is
  refused the same way. What the agent and the watchdog start no longer
  has `/usr/local` on its `PATH`.

- Dependencies: `tokio` 1.53.3 and `serde_json` (Dependabot's `rust-minor`
  group, PR #362, which failed CI). tokio 1.53.3 deprecates
  `AsyncFd::new`, `try_new`, `with_interest` and `try_with_interest` as
  unsound (tokio#8587: nothing required the fd to stay open while the
  `AsyncFd` lived); the agent's sensors registered their ring buffers
  with `AsyncFd::new` in nine places and `-D warnings` stopped the build.
  They go through `async_fd::register`, the one place the agent states
  the contract `AsyncFd::register` asks for (the ring buffer owns its fd,
  the `AsyncFd` owns the ring buffer); the watchdog's two pidfd
  registrations use `register_with_interest` with the same justification.
  Behaviour unchanged (`new` called `register`).
- Lab follow-up, 32-bit ioctls through `file_ioctl_compat` (lab PR 174).
  Since kernel 6.8 (upstream f1bb47a31dff, also in the stable releases
  6.7.3, 6.6.15, 6.1.76, 5.15.149 and 5.10.210) the `ioctl(2)` of a 32-bit
  process goes through the LSM hook `file_ioctl_compat` instead of
  `file_ioctl`, and the agent had no program on it: there a 32-bit
  `chattr` (`FS_IOC32_SETFLAGS`, `FS_IOC_FSSETXATTR`) of a protected file
  was not refused. A deny program on the new hook
  (`protected_ioctl_compat_deny`) is the `file_ioctl` deny: the same
  commands, the same identity and trusted-installer-window checks, the
  same `op=ioctl` denial record. It is an optional deny hook, like the ACL
  ones of 6.2: attached where the kernel's BTF has
  `bpf_lsm_file_ioctl_compat`, and then counted among the expected deny
  hooks (`deny_expected` one more: 19 on 6.8 and 6.12, 17 on 6.1.76+ and
  5.15.149+), so a kernel that has the hook but does not attach it is a
  deny-hook shortfall; without it nothing is attached and the count is
  unchanged (the compat syscall goes through `file_ioctl` there). The
  hook's `struct file *` argument is checked at boot like the other fixed
  ones (29), the boot's prototype line lists the optional deny hooks, and
  `--btf-check` prints an `optional` line for each, present or absent.
- Lab follow-up, package-manager mediation bound to a real transaction
  for the network, chain, R009 and posture consumers (lab PR 175). Lab PR
  173 bound the FIM rules' package carve-out to a transaction and left the
  other consumers on the lineage predicate (`is_system_daemon_mediated`: a
  `mandb` or a package manager anywhere among the ancestors, whoever ran
  it, for as long as the descendant lived). `mandb` is not set-id: a user
  ran it with `LD_PRELOAD`, had it fork a program from `/tmp` that called
  out, and NN-L-NET-008 recorded the flow (Log) instead of killing the
  process, NN-L-CHAIN-002/005/007 gave no verdict, and a crontab, a staged
  payload or a mass rewrite of the user's files forked the same way raised
  no `PersistenceMechanism` and no `ConfirmedIntrusion`; under a root
  `mandb`, a root exec from `/tmp` was R009's Log, which kept R001,
  evaluated after it, from killing it. NN-L-NET-008, the chains' package
  carve-out, R009's sanction and the posture's persistence, staging-exec
  and mass-write arms now use the FIM rules' transaction
  (`AuthSessionTracker::in_package_transaction`), at the event's own time
  (the connect, the exec, the write). Found while fixing, and fixed for the
  FIM rules too: no package manager is set-id either, so a user's
  `dpkg --version` run with `LD_PRELOAD` forked what it liked inside lab PR
  173's transaction, and an image a user builds (rootless Podman) brings
  its own `/usr/bin/dpkg`. A transaction is now a package manager proper
  the kernel executed as root: the exec event's real uid, a host uid, or
  the real uid of `/proc/<pid>/status` for a package manager that predates
  the agent — as the ring-drop exemption (SNS-009) already required.
  `mandb` keeps one exemption, from the mass-write arm: its own writes as
  root or a system account (uid 999 or below: man-db's timer runs it as
  `man` on Debian and Ubuntu, as root on Fedora), not what it forks and
  not a user's own `mandb`. A package manager a user runs (a rootless
  `podman build`'s `dnf` or `apt`) is exempt from the posture's mass-write
  and persistence arms for what it writes in that user's container storage
  only (`is_user_container_storage_write`): a path the kernel placed under
  `<dir>/.local/share/containers/` or `<dir>/.local/share/lxc/` whose marker
  directory the user (or the owner of the `/etc/subuid` range of the uid)
  owns, `/run/user/<uid>/containers/` or a `/var/lib/lxc/<name>/` the user
  owns; or, for a path on a filesystem no host mount shows, cut by the
  walk or given by the caller (tracepoint mode), a process in a mount
  namespace of its own whose root is an overlay with its layers in that
  storage — and, for an unplaced path, on that overlay. An event without
  a time is judged when it is read. **Regressions:** a package manager not
  executed by the host's root (rootless Podman, unprivileged LXC or LXD)
  is no transaction for the rules, and for the posture outside that
  user's container storage: its writes to the user's home, a bind-mounted
  directory or the host's paths count and can raise `ConfirmedIntrusion`
  or `PersistenceMechanism`; an LXD storage pool (root's) and Podman
  storage moved elsewhere (`storage.conf`) or under `fuse-overlayfs` are
  not recognised; a process a transaction left behind that calls
  out from a staging directory, executes from a user path as root, writes
  a persistence path or rewrites many files more than 30 s after the
  package manager was last seen running (60 s after its exec if never
  seen) is judged like any other; a user's own `mandb` that rewrites many
  files raises `ConfirmedIntrusion`.
- External audit, Wave 3, FIM rules (Low FIMR-010 NN-AUD-284, FIMR-011
  NN-AUD-285, FIMR-014 NN-AUD-288, FIMR-012 NN-AUD-286, FIMR-013
  NN-AUD-287; lab PR 173). The FIM rules' package carve-out (review 49: a
  write by dpkg, rpm, dnf or their children recorded at Low, not killed)
  counted `mandb` as a package manager. `mandb` is not set-id, so any user
  runs it with `LD_PRELOAD` and has it fork `crontab`: that user's crontab
  install was Log + Low instead of NN-L-FIM-007's High + KillProcess. The
  carve-out, and the drain's rate limiter, which paces only a package
  transaction's drift, now trust the package managers proper
  (`PACKAGE_MANAGER_EXES`: the list without `mandb`; the executable the
  kernel ran, never `comm`) during their transaction only: the nearest one
  in the writer's lineage runs now as the process the cache recorded, or
  was last seen running (by a lineage walk; there is no exit feed) at most
  30 s before the write, or — a short `dpkg -i` never seen running — was
  executed at most 60 s before it. A process a finished transaction left
  behind is judged like any other. The posture's triggers keep the wider
  list (`mandb` rebuilds its caches in bulk). NN-L-FIM-007 coalesced every
  cron write of one process in one cron directory for 2 s, so a second
  drop-in drew no verdict: it now coalesces one edit, told by the file.
  The FIM event carries the inode of the file it is about (`file_key`,
  with `is_dir` for a watched directory's own event and `moved_in` for a
  child renamed into one; optional on the wire, absent from rows written
  before), a temporary file renamed into place keeps its inode, and two
  drop-ins are two verdicts whatever their names; `crontab -e` stays one
  verdict in each order the drain can read its files. A file entry of the
  cron list matches only itself: `/etc/crontab.bak` no longer fires as
  `/etc/crontab`. NN-L-FIM-011..014 fire on a cloud credential file
  replaced by a rename over it, truncated by path, chmod'ed or chown'ed
  (`Modified`, `AttrChanged`), not only on an open; the cloud's own CLI
  stays exempt. NN-L-FIM-010 matches the ransomware extensions in any case
  (`.LOCKED`, `.Crypted`). **Regressions:** a write by a maintainer
  script's descendant more than 30 s after its package manager was last
  seen running (more than 60 s after its exec if never seen) gets the
  rule's full verdict; an editor that saves a new inode at each save
  within 2 s gives one NN-L-FIM-007 verdict per inode; an in-place edit of
  a watched cloud credential file by another program gives two High
  verdicts (the open, then the change).
- External audit, Wave 3, posture corroboration (Low POS-008 NN-AUD-305,
  POS-006 NN-AUD-303, POS-007 NN-AUD-304; Informational POS-013
  NN-AUD-430; lab PR 172). The COMBAT corroboration ledger kept one FIFO
  of 64 signals for every scope: since the ledger was scoped (lab PRs 141
  and 161) an unprivileged user running `nc` in a loop — each exec an
  `ExploitAttempt` recorded at ENGAGED — pushed another actor's evidence
  out of it, a root change that locks COMBAT included, and that actor's
  next signal stayed at ENGAGED. Each scope now has a bound of its own (16
  entries) and the ledger one of 256. A repeat of a signal (the same
  trigger, evidence class, privilege and pending writer) refreshes its
  entry instead of adding one, so a flood is one entry; above a scope's
  bound its own least useful entry goes (a change still waiting for its
  writer, then an ordinary signal, a privileged one last); when the
  ledger is full the entry goes from the actor holding the most, where
  every scope below `/user.slice/user-<uid>.slice` is that user's (a flood
  split over containers, or cgroups of one's delegated subtree named like
  them, is charged to one actor) and a unit's sub-cgroups are the unit's;
  a WARN says so once per episode. The correlation windows of the
  posture triggers (`within`) counted any event stamped after the focal
  one, however much later (the buffer holds 1,000 events of any age): the
  window is now the same on both sides. A service uid (1..999) reading
  `/etc/shadow`, `/etc/gshadow` or `/etc/sudoers` raised nothing (every
  uid below 1000 was dropped first): the read now raises
  `SensitiveFileAccess` (ALERTED) when the reader is a shell, an
  interpreter (`php-fpm` included) or a generic file tool, judged by the
  file the kernel executed and never by `comm`, an image outside a system
  tree, or a process the agent cannot place; a daemon reading with its
  own binary and the auth stack's own read stay quiet, and so do
  `/etc/passwd` and `/etc/login.defs`; root is unchanged.
  `PostureMachine::admin_release_combat(bool)`, which leaves COMBAT
  without the release hook or an admin record, is compiled only for the
  tests and the new `posture-demo` feature, which `examples/posture_demo`
  requires (CI runs clippy on it). **Regressions:** a service-uid process
  in group `shadow` that reads the credential files with a shell, an
  interpreter or a tool (a backup script, an application checking
  passwords against `/etc/shadow` itself) raises ALERTED; an event stamped
  more than a window after the focal one no longer counts toward its
  correlation; `cargo run --example posture_demo` needs
  `--features posture-demo`.
- External audit, Wave 3, CI and build integrity (Low SUP-004 NN-AUD-392,
  SUP-016 NN-AUD-401, SUP-022 NN-AUD-406, SUP-012 NN-AUD-397, SUP-015
  NN-AUD-400, and the scheduled advisory check left over from SUP-006
  NN-AUD-204; lab PR 171). `ci.yml` and `kani.yml` gave their jobs the
  repository's default token: every workflow now starts at
  `contents: read`, only release.yml's `sign` job may write, and no
  checkout leaves the token in `.git/config` for the build scripts of the
  dependency tree. No CI or release build was `--locked`, so a manifest
  change was resolved again on the runner while `cargo audit` checked the
  committed lockfile: every cargo build, test, clippy and check is locked,
  `cargo xtask` takes `--locked` and passes it to its nested builds
  (agent-ebpf included), and the fuzz and Kani jobs, whose tools have no
  such flag, check their lockfile first and fail if it changed.
  `fuzz/Cargo.lock` was already out of step with the agent's manifests
  (procfs 0.17, no fancy-regex 0.14 — CI resolved it again on every run)
  and is brought up to date. Cache restore keys no longer fall back to any
  job's cache (`<os>-cargo-`). The cache prune script passed — "0 crates",
  exit 0 — when `cargo metadata` failed, leaving restored workspace
  artifacts in place: it now fails. `rust-toolchain.toml` pins Rust 1.99.0
  (the release the last green CI used) instead of `stable`, every
  workflow installs that pin, and Dependabot proposes the next release.
  `rust-version` claimed 1.83 while `uuid 1.28.0` needs 1.89: it is 1.89
  (the whole workspace, all targets, checks with 1.89.0), a new `msrv` CI
  job builds with it, and a test fails when a locked dependency needs a
  newer rustc (clippy, which reads that value, now proposes
  `is_multiple_of` in the agent; that lint is allowed there until the
  rewrite). `ci.yml` runs daily for the advisory job alone. New tests
  in `xtask/tests/supply_chain.rs`. **Regression:** a PR that changes a
  `Cargo.toml` must commit the updated `Cargo.lock`, `fuzz/Cargo.lock`
  and, for that crate, `agent-ebpf/Cargo.lock`, or CI fails; a new Rust
  release reaches CI, release and lab builds only through a reviewed bump
  of `rust-toolchain.toml` (the first build on a host downloads the pinned
  toolchain); each CI job installs the pinned toolchain (about a minute)
  and the first runs after this change build with colder caches.
- External audit, Wave 3, watchdog supervision (Low WDG-007 NN-AUD-358,
  WDG-010 NN-AUD-360, WDG-008 NN-AUD-359, WDG-015 NN-AUD-364,
  Informational WDG-019 NN-AUD-437; lab PR 170). Root could `rm
  /run/northnarrow/admin.sock` (the directory is outside the inode deny
  set) and then freeze the agent's cgroup: the watchdog read the missing
  socket as "never came up", so the STATUS ping — what recovers a frozen
  agent — never failed again, and `nn-admin` was dead until the next agent
  start. The watchdog now remembers whether the agent it supervises
  answered. A socket that never came up is still never a hang (the
  2026-10-08 restart loop stays closed); one gone after an answer is
  reported on the second ping 30 s later (ERROR on `watchdog.tamper`, a
  `watchdog.hold` line with reason `admin_socket_vanished` that the agent
  signs as `integrity_drift` `admin_socket_vanished`, after its recovery
  when it was frozen) and recovered on the third (SIGINT, 5 s, evict and
  SIGKILL, respawn). "Nothing listens" now also covers ECONNREFUSED and
  ENOTDIR (a stale socket, a file or a directory at the path), which
  counted as a hang; the answer must come from the supervised pid
  (`SO_PEERCRED`), so a process that binds the path in the agent's place
  is not an answer; nothing is pinged between an agent's death and the
  next one. The agent records its socket's device and inode and looks at
  the path every 10 s: a socket removed or replaced is a signed
  `integrity_drift` (`admin_socket_removed`, at most one per 10 minutes,
  with the count of the others) and is bound again at once, so a healthy
  agent answers before the watchdog counts anything. Its bind removes
  what sits at the path without following a link (a dangling link at the
  name made `bind` fail), creates a missing parent 0700 and sets 0600
  through an `O_PATH | O_NOFOLLOW` descriptor; it stops at shutdown, after
  the agent's own unlink. WDG-015: the agent's and the watchdog's pidfiles
  are written with the AUT-003 writer, moved to `common::atomic_file`
  (the temporary name removed, created `O_CREAT | O_EXCL`, renamed, the
  directory synced); `watchdog.pid.tmp` and `agent.pid.tmp.<pid>` were
  opened through a link planted at the name by the processes the hooks
  trust. WDG-008 (exec backend, non-systemd hosts): the argv captured from
  `/proc` is kept at `/run/northnarrow/agent.argv` (0600; read back only
  as a regular file of the watchdog's user closed to others) and used
  when a later watchdog start cannot read `/proc`, with argv[0] the
  verified binary; that fallback, or the minimal one when there is no
  record, is a `respawn_argv_degraded` record the agent signs — not the
  refusal to start the audit proposed, which would leave such a host with
  no respawn at all. WDG-010 (exec backend): an exited agent the watchdog
  started is collected through its pidfd (`waitid(P_PIDFD, WEXITED |
  WNOHANG)`; ECHILD for an agent systemd started) — each respawned agent
  stayed a zombie child. WDG-019: the comment of the pidfile retry loop
  says what it does (every error retried to the deadline; EACCES on
  `/proc/<pid>/exe` is transient by design, WDG-003) — no change of
  behaviour. **Regressions / changes:** a running agent that cannot bind
  its socket again (a directory planted at the path) is restarted once by
  the watchdog about 90 s later — its successor then runs without admin
  plane, as before, and is not restarted again; an agent with no admin
  plane that leaves a stale socket file behind is no longer restarted
  every minute; the temporary pidfiles are `.agent.pid.tmp` and
  `.watchdog.pid.tmp`; the watchdog's absent-socket WARN no longer says
  "(ENOENT)"; exec-backend hosts gain `/run/northnarrow/agent.argv`; new
  signed kinds `admin_socket_removed`, `admin_socket_vanished`,
  `respawn_argv_degraded`. Found by the watchdog's new e2e and fixed here, ASK-016 (Low
  NN-AUD-242): the two `debug-trigger` variants of `AdminMessage` sat in
  the middle of the enum and shifted the postcard discriminant of every
  variant after them, so a `debug-trigger` build (the lab's agent) and a
  build without it (the e2e's watchdog) misread each other's frames — the
  watchdog decoded the agent's `StatusResponse` as another variant and
  never saw a ping answered. They are the last variants now (production
  discriminants unchanged), a test pins the production ones in both
  feature sets, and CI runs it with `debug-trigger`.
- External audit, Wave 3, evidence files and the telemetry probe (Low
  EVD-019 NN-AUD-281, EVD-015 NN-AUD-278; lab PR 169): `audit.log` and
  `chain_heads.json` were `0644` in the world-readable `/etc/northnarrow`,
  so any local user read the key fingerprints, the callers' pid/uid/comm,
  the drift details and which sensor was in a `telemetry_gap`. They are
  created `0640` now (root and the file's group); the chain logs under
  `/var/lib/northnarrow` (detections, status events, netflow and its
  listeners, FIM baseline and drift, the canary chains, archives and
  manifests), closed until now only by the directory's `0700`, are
  created `0600`. `install.sh` closes the existing files on install,
  `--upgrade` and the packages' configure step, with the units stopped
  and the pins dropped, and `--audit-group GROUP` (`NN_AUDIT_GROUP`)
  gives the two `/etc` files an existing group for a log shipper, kept by
  later upgrades. The telemetry probe's DNS datagram to `127.0.0.1:53`
  was a recursive query whose name carried the agent's pid and the
  clock, and a forwarding resolver on the host passed it upstream every
  minute: the nonce is 64 random bits, and the datagram is flagged as a
  response (`QR` set, `RD` clear), which a resolver drops instead of
  answering or forwarding; both DNS sensors read only the name, so the
  probe still sees `dns`. `MSG_PROBE`, proposed in triage, is not used:
  the kernel then builds no buffer (`ip_make_skb` returns none on 5.15,
  6.1, 6.8 and 6.12), `udp_send_skb`, where the default sensor reads, is
  never reached, and every round would be a DNS telemetry gap.
  **Regression:** a reader of `audit.log` or `chain_heads.json` that does
  not run as root (a log shipper, a script without `sudo`) gets `EACCES`
  until it has the `--audit-group` group; a listener on `127.0.0.1:53`
  now receives the probe as a response (flags `0x8000`) with a random
  first label.
- External audit, Wave 3, the shipped default lists on disk (Low
  NN-AUD-327 LLMR-015, wider than reported; lab PR 168): the five `.v1`
  lists in `/etc/northnarrow` (`fim-paths`, `netflow-blocklist`,
  `netflow-ja3-blocklist`, `process-comm-allowlist`,
  `netflow-comm-allowlist`) were applied as they stood on disk, read
  through a link and blocking on a FIFO, and `install.sh` never replaced
  one that existed — `--upgrade` and the packages' configure step
  included. An upgraded host kept the lists of its first install: one
  installed before lab PR 78 still killed processes talking to
  `100.64.0.0/10` (CGNAT, Tailscale, EKS) or `198.18.0.0/15` (VPN
  clients) through NN-L-NET-001 (KillProcessTree). An offline edit — an
  exemption added to an allowlist, a watched path or a blocked range
  removed — took effect at the next boot without a word. The agent now
  applies the copy it was built with: the file when it is that copy byte
  for byte; over the copy an earlier release shipped (SHA-256 tables from
  the history of `configs/`, `EARLIER_*_SHA256`) the built-in one, with a
  WARN; over anything else the built-in one, with an ERROR and a signed
  `integrity_drift` (`default_list_modified`, file and both SHA-256) at
  every boot (`OverlayGate::report_default_modified`). The file is read
  like an overlay (no link, no FIFO, at most 4 MiB); a link or a FIFO is
  unavailable (`default_list_unavailable`, built-in copy).
  `NN_OVERLAY_ALLOW_UNSIGNED=1`, the escape hatch of the unsigned
  overlays, applies an edited list anyway, still recorded. `install.sh`
  (`install_shipped_v1`; its `SHIPPED_V1_EARLIER` is the agent's table,
  checked equal by a unit test, and each built-in copy's SHA-256 is
  pinned) installs the shipped list over a missing, current,
  earlier-shipped or non-regular one; an edited one is kept as
  `<list>.v1.operator`, the
  shipped list installed, and a WARNING prints the difference with the
  `nn-admin config overlay set <list>` command that carries it into the
  signed `.local` overlay. `nn-lab.sh upgrade-check` checks the five lists
  after the upgrade. The privileged e2e fixtures, which write their own
  lists, start the agent with `NN_OVERLAY_ALLOW_UNSIGNED=1`.
  **Regression:** a `.v1` edited by hand is no longer applied, from the
  first boot of this agent or the upgrade that installs it: move the
  change into the list's signed `.local` overlay (`install.sh` keeps the
  edited file as `.v1.operator` and prints the difference). A `.v1` that
  is a symbolic link is not followed.
- External audit, Wave 3, journal line injection (Low NN-AUD-413 LAB-023,
  and the cross-cutting finding of the Wave 3 triage; lab PR 167). The
  agent logged values another user names with `%` (Display) —
  `target_filename`, `filename`, `comm`, the rule's `reasoning`, DNS
  names — and tracing-subscriber 0.3 escapes neither `\n` nor `\r`: any
  local user could run a file in `/tmp` named `x\nANTI-TAMPER DENIAL …
  op=signal` and the journal showed a whole entry the agent never wrote.
  The new `common::log_escape` has two layers. `Escaped` renders such a
  value: as it is when plain (`comm=bash`, `path=/etc/passwd`), quoted
  logfmt-style with `\n`, `\r`, `\t`, `"`, `\` and the controls escaped
  when it holds a space, `"`, `=`, `\` or a control, so it can neither end
  the line nor pass for another field; every such field of the agent goes
  through it (comm of any process, the files it runs, opens or writes, FIM
  paths and symlink hops, DNS query names, canary names, rule and model
  reasoning, the quarantined binary, a contained process's cgroup, the
  admin socket peer). `OneLine`, the writer of the agent's and the
  watchdog's fmt layer, writes every event as one line whatever it holds
  (an error quoting a path, a `format!` message): each control byte but
  the final newline escaped (`\n`, `\xNN`), a line over 16 KiB cut below
  journald's `LineMax`. The test `journal_fields` formats a VERDICT line
  with a forged name and checks it stays one line, and scans the agent's
  and watchdog's sources: a new `%` on one of those field names without
  `Escaped` fails it. Lab side: `anti-tamper.sh` built a case's evidence
  from journal text (`ANTI-TAMPER DENIAL .*op=`, `VERDICT (rule) rule=`
  anywhere in a line); it now reads the signed records with `python3 -I`
  — the NN-L-AT-001 detections after line d0 (rule ids and the refused
  operation, `deny=<op>`), the audit ops — and keeps the journal only for
  `errors=`, counted on the agent unit's own stdout entries by their level
  field. NN-L-AT-001 records name the refused operation in a new optional
  `operation` field (absent on other records, so existing records keep
  chain-verifying). **Regressions / format changes:** the journal lines of
  the agent and the watchdog carry no ANSI colour codes any more (they are
  kept on a terminal); a value holding a separator is quoted — `reasoning`
  on `VERDICT` lines always is (`reasoning="…"`); a control character in
  any line reads `\n`, `\x07`; a line over 16 KiB ends in `[cut: N more
  bytes]`. The suite's evidence column reads `deny=signal×1` (from
  detections) where it read `op=signal×1` (from the journal), its journal
  part only `errors=`, and C24 checks the store (`config_overlay_set`)
  and no `unauthorized_overlay` at the restart in `audit.log` (the store
  raises the rollback floor, so the boot writes no
  `config_overlay_accepted`). An `nn-admin` older than the agent reports NN-L-AT-001 records
  with `operation` as broken (upgrade the three binaries together).

- Dependencies: `zip` 9.0.4 instead of 7.2.0 (RUSTSEC-2026-0367,
  RUSTSEC-2026-0368, RUSTSEC-2026-0369: `ZipArchive::extract` kept
  SUID/SGID bits, applied the archive's Unix permissions and followed
  symbolic links out of the target directory). The agent's only user is
  the vendored `candle-core` (its `.npz`/`.pth` readers, which read entries
  in memory and never extract), so the paths were not reachable; the
  advisories failed `cargo audit` all the same. Three lines of
  `vendor/candle-core/src/{npy,pickle}.rs` follow zip 9's `Result` entry
  names, marked "NorthNarrow" like the patch's other changes. The fuzz
  harness now builds the same patched `candle-core` as the agent (it built
  crates.io's, with Oniguruma and zip 7).
- Lab follow-ups, LSM hook prototypes and `FLOW_SOCK_MAP` (lab PR 164).
  From kernel 6.9 `inode_setattr` takes `struct mnt_idmap *` before the
  dentry, and the anti-tamper setattr deny and the FIM setattr observer
  read argument 0 as the dentry: there `chmod`, `chown` and `truncate` of
  a protected file were not refused, nor seen by FIM on a watched one.
  The agent now reads the hook's prototype from the running kernel's BTF
  (`bpf_lsm_inode_setattr`) and hands the dentry's position to the
  programs through `BTF_OFFSETS`. The same check found that on 5.7 to
  5.11 (5.10 LTS) `inode_setxattr` and `inode_removexattr` start with the
  dentry, where the xattr deny read argument 1; their positions are
  resolved the same way. A prototype of another shape is never guessed:
  the programs on that hook are not attached (a deny-hook shortfall, which
  refuses the start unless `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`; a FIM
  coverage shortfall) and a signed `subsystem_degraded` says why. The 28
  other pointer arguments the LSM programs read at a fixed position are
  checked against the running kernel's prototypes at boot and by
  `--btf-check`, whose summary counts them. **Regression:** a kernel
  whose hook prototype moved an argument the agent reads at a fixed
  position no longer starts (exit 78, like a missing field).
  `FLOW_SOCK_MAP`, the kernel's connect→close socket map, holds 65,536
  sockets, the userland flow tracker's capacity (it held 4,096 and beyond
  that forgot long sessions, whose close was never recorded): about 5.5
  MiB of kernel memory, preallocated (was 0.34 MiB). `nn-admin net status`
  (text and `--json`) shows how many sockets the map holds without their
  close and how many it forgot at least. The lab gains a Debian 13 guest
  (kernel 6.12, `NN_LAB_DISTRO=debian13`, ssh port 2722).
- Two follow-ups found in the lab (lab PR 162). The ADE judged every exec
  under its parent's name: for each exec the `ExecCheck` (before the new
  image runs, with the parent's comm) took the only evaluation slot and
  the child's `ProcessSpawn` was counted and dropped, so a `lockbit-*`
  binary was never evaluated. The model is now shown the `ProcessSpawn`;
  an `ExecCheck` that no spawn follows within 2 s (an exec that did not
  complete, or a lost spawn event) still goes to it on its own, and the
  rules see both as before. A tamper of an anti-tamper control-surface
  file (NN-L-FIM-024: `kill_switch.conf`, `pause.flag`, …) left the
  posture where it was although the rule and its documentation said
  COMBAT: no posture trigger read FIM events. It now raises the decisive
  `ControlSurfaceTamper` trigger (a locked COMBAT, the tampering process
  named as the offender), on the rule's own match and with its
  exemptions (the agent and the watchdog); inside a trusted-installer
  window the rule still kills and records, and the posture is not
  raised. On an installed host the `/etc/northnarrow` baits are under the
  FS deny, whose `AntiTamperDenial` already raised COMBAT; the
  `/run/northnarrow` baits are not, and their tamper left the posture in
  OBSERVING.
- Lab follow-ups, network canaries and NN-L-NET-003 (lab PR 163):
  NN-L-CANARY-003 could not fire — nothing consulted the network
  canaries, so no Network canary ever tripped. A network canary is now a
  decoy destination: a local process connecting to its address and port
  (`nn-admin canary deploy network --bind-addr --bind-port`; `0.0.0.0` /
  `::` is the port at any address of this host) trips it, reported by the
  connect kprobe at the start of the connect — the signed access row with
  `first_trip`, the registry's `trip` row and NN-L-CANARY-003 (Critical,
  KillProcessTree on the connecting process). The agent opens no
  listener: a connection from another host, a UDP datagram and the lure
  of a port `ss -tlnp` shows are not covered (deception design §5.4). The
  close of the trip's connection is recorded in the netflow log and not
  judged again (NN-L-CHAIN-003 answered the same access a second time). A
  network canary deploy is refused when its address is not an IP
  address, its port is 0, or a listener on this host serves the port
  (its clients would trip it). V2 campaign: `v2-rules.tsv` version 2 —
  NN-L-NET-003 (no TLS fingerprint producer, BUG-025) leaves the Critical
  sub-gate until BUG-025 and stays in the denominator; the sub-gate holds
  25 rules, NN-L-CANARY-003 among them with a privileged e2e.
- Lab follow-up, the rules that kill an exec whose executable is the
  payload itself kill its process tree (lab PR 166). A root dropper run
  from `/tmp` that forked at once and waited in `pause()` was killed by
  R009, which runs ahead of R001 (hence no R001 verdict in the lab), but
  `KillProcess` reached the parent only: the child, forked before the
  kill, ran on under init with the image from `/tmp`, and a child that
  never execs draws no verdict of its own. R001, R002, R003, R009, R010
  and R017 now answer with `KillProcessTree`, and so does R006 (the shell
  that `socat EXEC:` runs is its child). R011, R012 and R013, which
  outrank R001..R003 (PROC-009), do the same for a copy run from `/tmp`,
  `/var/tmp` or `/dev/shm` — a dropper named `insmod` kept its children —
  and keep `KillProcess` for the tool anywhere else. The tree kill is the
  one R004 and R007 use: a cgroup of its own, every member checked by
  identity, the host-critical guard for each pid, descendants only, and
  the record names what it did (`KillProcessTree (partial: …)`); its
  cgroup is now frozen as soon as the root is inside, before the walks
  that move the descendants, so the root can neither exit nor fork
  meanwhile (the freezer, not SIGSTOP: a `sudo` stops itself when its
  command stops, and in the lab stayed stopped once the command was
  killed). A short-lived payload copied to `/tmp` (`unshare --version`,
  `bash -c 'exit 0'`) can end before its verdict whichever kill answers
  it: in the lab it did on `main` too (3 of 4 runs under `KillProcess`),
  while the same binary run from a home directory was killed 4 of 4 —
  the extra latency of a staging exec is upstream of the rules (a
  follow-up). The exemptions are unchanged: the allowlist judged on the executed file,
  R009's administrator sessions and package transactions (PROC-007), the
  trusted actors (PROC-008), R006's record of the distribution's `socat`.
  New privileged e2e `tmp_dropper_forked_child_dies_with_it` (as root and
  as `nobody`); `tmp_exec_kill_hits_the_offender_only` now requires the
  tree kill. **Regression:** these rules kill more processes, all of them
  descendants of the exec: the children a payload forked, the shell of a
  `socat EXEC:`, and the children a process already had when it executed
  the payload in place (`exec /tmp/x` from a shell with background jobs).
  Its parent and siblings are never touched.
  With it, external audit NN-AUD-299 (PROC-011, Wave 3, Low): R017
  killed every shell outside `/bin` and `/usr/bin` — a `bash` an
  administrator installed in `/usr/local/bin`, run as a login shell or by
  `#!/usr/bin/env bash` with `/usr/local/bin` first in `PATH`. The trees
  only root can write where a shell is installed (`/usr/local/bin`,
  `/usr/sbin`, `/sbin`, `/nix/store`) are exempt too; `/opt`, a home and
  the staging directories still fire.
- Lab follow-up, nftables (lab PR 165): the per-process outbound block (a
  BlockOutbound verdict, the COMBAT soft egress block of INVESTIGATE) is
  an nftables rule applied with `nft`, and nothing in the install chain
  asked for it — on Debian 12's cloud image, which ships without it, the
  block failed at the first offender. The `.deb` pre-depends on
  `nftables` (dpkg refuses before the pre-unpack hook stops a running
  agent; `apt-get install ./<deb>` pulls it in) and the `.rpm` requires
  it; neither enables `nftables.service` or loads a ruleset.
  `install.sh` installs no system package: on a host without `nft` it
  refuses before changing anything (an `--upgrade` included) and names
  the command, or goes on with `--without-nftables`, recorded in
  `install-manifest.json` (`prerequisite_overrides`) and named by
  `nn-admin host-check`; in `--package-configure` a missing `nft` is a
  warning. At boot the agent looks for `nft` on its own `PATH` and, when
  it is missing, logs an ERROR and records one signed
  `subsystem_degraded` ("block_outbound unavailable: nft missing"). The
  host-check line stays a WARN, like every check of that table (exit 2
  already marks the host), now also searching `/usr/local`. The lab
  guests install `nftables` (templates; `nn-lab.sh up` and `install`
  for guests provisioned before), `pkg-check` checks the dependency, the
  range bootstrap and the release workflow's package smoke test check it
  too. **Regression:** `install.sh` on a host without `nft`, a scripted
  `--upgrade` included, needs `nftables` installed or
  `--without-nftables`; a bare `dpkg -i` / `rpm -U` of the package needs
  `nftables` installed first.
- External audit, Wave 2, range bootstrap and lab verdict integrity
  (Medium LAB-006, LAB-018, LAB-016, LAB-017, LAB-011, LAB-014): the
  bootstrap refuses a lab-featured binary (`--build-features`), stops on
  a failed FIM baseline or canary deploy and checks baseline, canary,
  passwordless sudo and a decodable CapEff; the t713 reproducer, the
  btrfs and inode-reuse checks and the anti-tamper suite report a case
  that did not run as NOT RUN / DEVIATION (N/A only when the kernel lacks
  the feature); the soak FAILs on a dead agent, a missing watchdog, a map
  at 90 % and ring drops; `verify-isolation.sh` gates the range's
  snapshots on an adapter allowlist and in-guest probes.
- External audit, Wave 2, privileged fixture hygiene (Medium TST-011,
  TST-012, TST-009): the two iptables self-tests of the shared fixture
  module ran in each of the eight test binaries that include it, and the
  clean-state one first deleted the production `NORTHNARROW_COMBAT` chain
  and its INPUT jump, whoever owned them. They are in one binary,
  `fixture_selftest`, and refuse to start while a NorthNarrow agent or
  watchdog runs or when the chain exists. The honeypot e2e suite rewrites
  the real bait files (the agent has no flag to move them): it overwrote
  and deleted the baits of an installed, stopped agent without putting
  them back, and removed the pin root first. It now refuses to run
  without root, outside an nn-lab guest (`/var/lib/nn-lab-provisioned`,
  written by the lab's cloud-init) unless `NN_TEST_DISPOSABLE_HOST=1`,
  and while an agent or watchdog runs; it records each bait's content,
  mode, owner and mtime, and when a test ends, pass or fail, puts back
  every bait that existed and checks it; it no longer touches the pin
  root. The map-pin restart test counted every LSM program on the host
  against `>= 7` while the agent attaches nine deny hooks: it now reads
  the agent's own pins for each hook of the new `anti_tamper::DENY_HOOKS`
  (an LSM program and its link pinned, task_kill and ptrace bound to
  the pinned `PROTECTED_PIDS`, the same objects after the agent exits, a
  fresh program for every hook after the restart) and the agent's
  `deny_attached=N deny_expected=N` line (sixteen deny hooks with lab PR
  152, plus the ACL hooks on 6.2 and later). No change to the agent's
  behaviour.
- External audit, Wave 2, evidence completeness (Medium EVD-002, EVD-003,
  EVD-009, DEC-018): a signed chain proved its rows were not changed, not
  that none were removed. `audit.log` or a canary chain cut at its end, or
  deleted and restarted, verified; an emptied or deleted active file of a
  rotating log passed `verify_log_set`; nothing verified a chain in
  production (the canary chains were only parsed at open — an unsigned
  `Burn` row retired a canary — and `nn-admin detections` served any
  well-formed line); the chains shared one key with no domain separation.
  Now rows of `audit.log` and the canary chains carry their position
  (`seq`) and a per-chain domain tag in their hash; the rotating logs
  checkpoint their active file in their signed manifest; the heads of all
  chains are anchored in the signed `/etc/northnarrow/chain_heads.json`
  (at start, every 5 minutes, at stop; each also an INFO `chain.head`
  journal line). Every start compares the files with them before anything
  opens and reports a cut, emptied, deleted or rewritten chain as an ERROR
  and a signed `integrity_drift` (`chain_truncated`, …); a cut audit chain
  also resets the overlay rollback floor and closes the one-key bootstrap.
  The canary registry verifies every row at open (one that fails is not
  applied), the access log its last 256; the rotating logs' last 4 MiB are
  verified in the background (`chain_verify`); `nn-admin detections` leaves
  out rows that do not verify. New: `nn-admin chain verify` (every chain in
  full, against the anchor; exit 8) and `nn-admin audit verify
  --expect-head/--min-seq`. Existing chains keep verifying unchanged and
  are numbered from their current length; the switch is recorded
  (`chain_numbering_started`). **Regression:** an `nn-admin` older than
  the agent reports numbered rows as broken; downgrading the agent is not
  supported. Runbook: `docs/operator/EVIDENCE_CHAINS.md`.
- External audit, Wave 2, new entries in the agent's directories (Medium
  EBPF-015): the filesystem deny refused removing or renaming an entry of
  `/etc/northnarrow`, the state directory or the pin root, not adding one —
  root could drop a decoy overlay or a second key file beside the protected
  ones, plant a pin, add a drop-in to the agent's unit (Debian), and set or
  remove extended attributes of any protected file. A new file, link,
  symlink, FIFO or directory in those directories, and any extended
  attribute or (6.2+) ACL change but `security.selinux`, are now refused
  outside a trusted-installer window and recorded (`op=create`, `mkdir`,
  `mknod`, `symlink`, `link`, `xattr`). A restarted agent registers itself
  before it recreates a missing file or map pin. **Regression:** an overlay
  dropped into `/etc/northnarrow` by hand, `systemctl edit
  northnarrow-agent` on a Debian host and `nn-admin config overlay sign`
  writing its `.sig` there now need a window; overlays go through
  `nn-admin config overlay set`.
- External audit, Wave 2, posture scope of containers (Medium POS-005,
  completed): a rootless container (Podman, rootless Docker) runs with the
  login uid of the user who started it, so two containers of one user, or
  a container and that user's shell, still shared one corroboration scope
  and reached COMBAT together. A container is now an actor of its own
  whoever started it — Podman, Docker, containerd and CRI-O scopes,
  rootful or rootless, and the cgroupfs paths of Docker and Kubernetes —
  and the units of a systemd running inside one belong to it; a container
  whose init has exited is placed through its conmon. On a cgroup v1 host
  the most specific of systemd's hierarchy and the cpu, memory and pids
  controllers places a process (a rootless container there has no cgroup
  of its own and stays in its user's scope). **Detection change:** an
  attacker in a login session who runs part of an attack in a container
  they start splits the evidence — the halves no longer corroborate; two
  signals inside one container still do.
- External audit, Wave 2, admin socket connections and roles (Medium
  ASK-002, ASK-003, ASK-004, ASK-010, ASK-011): the admin socket's accept
  loop ended on any `accept()` error — an EMFILE, which a root process
  holding a few hundred idle connections could cause, left the agent
  without unlock, shutdown or key rotation until a restart — and it served
  any number of connections, each waiting on its peer for ever. A
  transient accept error (EMFILE, ENFILE, ENOBUFS, ENOMEM, ECONNABORTED,
  EINTR) now backs off and retries; at most 32 connections are served at
  once, a full table closing the one that has waited longest on its peer;
  a peer gets 10 s to send each request and 5 s to take each reply; if the
  loop still ends, an ERROR and a signed `subsystem_degraded`. The
  challenge was one slot for the whole agent: any client asking for one
  broke a concurrent `unlock`, `shutdown` or `trusted-installer-grant`
  (`NonceMismatch`), a polling dashboard included, and three bad
  signatures from anyone blocked every client for five minutes. The
  challenge and the failure count now belong to the connection: the third
  failed signature on a connection is answered `RateLimited` and the
  connection closed; other connections are not affected. A key with only
  `force-posture` could leave COMBAT and release the isolation like
  `unlock`: leaving COMBAT now also needs a signer holding `unlock`
  (`RoleDenied`, posture untouched); forcing COMBAT is unchanged.
  `rotate-keys add` gave the new key whatever roles it was asked for — a
  `rotate-keys`-only quorum, or the bootstrap key alone, could mint an
  `all` key: each role of the new key must now be held by a signer (`all`
  only by a signer holding `all`; an omitted list counts as
  `unlock,audit-read`), else `RoleDenied` and `admin.pub` untouched.
  **Regression:** a `force-posture`-only key can no longer leave COMBAT
  (use `nn-admin unlock`, or add `unlock` to the key); a key holding only
  `rotate-keys` can no longer add keys with roles it lacks
  (COMBAT_RECOVERY §1.1); a client must send its signed request on the
  connection that fetched the challenge, within 10 s (every nn-admin verb
  does).
- External audit, Wave 2, validation methodology (Medium LAB-012, LAB-013,
  TST-019): the adversarial campaign's coverage gates could not fail — a
  miss triaged after the run as N/A or as a sensor gap left the
  denominator — ATT&CK coverage had no definition, and the "100 % on the
  Critical tier" sub-gate had nothing behind it. Before the campaign runs,
  its denominator is frozen in `docs/validation/v2-rules.tsv` (77 rules:
  the 76 the production engine loads and NN-L-AT-001), with the technique
  rows (`v2-techniques.tsv`, the techniques without a rule included, each
  with its expected outcome) and one evasion row and one benign control
  per family (`v2-controls.tsv`). `matrix.md` records the version and
  sha256 of each and the gate formulas: a miss is a FAIL whatever its
  triage class, a rule never run counts against the headline, technique
  coverage is reported apart. The Critical sub-gate holds the rules the
  design's Q1 names and every other rule that can issue a Critical verdict
  (26), and `matrix.md` says where each one's proof lives today, and
  `no proof` where there is none: none has campaign proof yet, 15 have
  unit tests only, and NN-L-NET-003 and NN-L-CANARY-003 cannot fire on the
  agent as built (no TLS fingerprint is captured, nothing produces a
  Network canary trip). Unit tests hold the registry to the shipped
  rules and the recorded hashes to the files. The range bootstrap
  expected 69 rules; it now takes the count from the registry (76). No
  change to the agent.
- External audit, Wave 2, anti-tamper suite correctness and coverage
  (Medium LAB-003, LAB-004, LAB-005, LAB-007): `tamper-check` could kill
  its own session: C02 signalled whatever `systemctl show -p MainPID`
  printed, `kill -9 0` when the watchdog was down, and later cases reused
  a PID read once from a possibly stale pidfile. Every signal now goes to
  a process checked by comm and start time, through a pidfd; a watchdog or
  agent that is not there reads "target absent", a deviation. A case's
  outcome was the English text of its error: the run is in the C locale,
  the helpers report the errno, and a refusal counts as "denied" only if
  the end state held too (same process alive and running, same inode,
  file not shrunk, pins kept, `+i` kept): `rm -rf` of the pins that
  removes some of them is "partial". The mounts over `/etc/northnarrow`
  and `/sys/kernel/btf` are undone by a trap on exit, Ctrl-C, a lost
  session or an `umount` that failed; one left after its case fails and
  stops the run. New cases: the seven other signals from a root shell
  (C55a-g), a binary replaced by rename or unlink (C56a-b), audit.log
  truncated and detections.jsonl emptied (C57a-b), a renamed module tool
  (C58, R018 expected), write/unlink/rename through io_uring (C59a-c), a
  runtime mask of the watchdog (C60, reported as `unit_shadowed`),
  PROTECTED_PIDS across a restart (C61, observe builds); the journal
  vacuum is listed as a known gap (C57c). `anti-tamper.sh --persistence`
  checks the hooks, pins and `+i` after a reboot (C62a-e), and
  `--selftest` checks the helpers without root. **Regression:** the run
  deletes the agent journal namespace's archived files (C57c).
- External audit, Wave 2, lab host hygiene and lab supply chain (Medium
  LAB-008, LAB-009, LAB-002, LAB-015; Low LAB-010): lab scripts that run as
  root on a guest worked at fixed paths under `/tmp` and `/var/tmp` that any
  user can create first: the overhead benchmark truncated whatever the
  entries of `/var/tmp/nn-bench` pointed to, `pkg-check` and `pkgmgr-check`
  installed packages from a directory another user could own, and the
  anti-tamper suite bound a `/tmp` directory over `/etc/northnarrow` (C14)
  and signed a `/tmp` file as an overlay with the lab key (C24). They now
  work in directories `mktemp` creates (one user's, unpredictable names);
  `nn-bench` refuses a work directory that is a link or open to other users
  and does not follow links. The base images came from "current"/"latest"
  URLs over plain `curl`, unchecked: `up` now checks each download against
  the vendor's signed list (Ubuntu, AlmaLinux: keys pinned by fingerprint;
  Debian signs none of its current cloud images: HTTPS only, recorded as
  such), records the digest next to the image, and layers a new guest only
  on an image that still matches it; `nn-lab.sh verify-image` checks an
  image downloaded earlier against the lists the vendor still publishes.
  The guests' rustup comes from a pinned `rustup-init` checked against its
  pinned SHA-256 instead of `curl | sh`; the range's Sliver from Kali's apt
  repository instead of `curl | sudo bash`; the Atomic Red Team pin is
  fetched or the provisioning stops (a failed checkout used to be
  ignored), and the installed versions are written down. `release-check`
  passed `SHA256SUMS` when any listed file matched and extracted the
  tarball as root with its owners and modes; it now checks the tarball's
  own line before extracting plain files. The lab added roles to every key
  in `admin.pub` (an unanchored `sed` inside a window, another after a
  reboot with nothing protecting the file); it no longer edits `admin.pub`,
  and a guest where no key has `trusted-installer` is refused, to be
  recreated. The Tappa 7 debug script under `docs/debug/` (it detached
  every LSM link on the host and left the state directory damaged) is
  deleted. **Regression:** a new base image needs `gnupg` and `gpgv` on the
  host and, once, the vendor's key from the network; an image downloaded
  before is used with a warning until `verify-image` records it; a guest
  installed before the `trusted-installer` role must be recreated.
- External audit, Wave 2, response and detection assertions (Medium
  TST-018, TST-005, TST-008, TST-006): a detection record named the
  response's action even when it did not happen — a kill that found the
  process already gone, was refused (a protected process), denied or
  failed read `"response":"KillProcess"`, like one that landed. The bare
  action name now means it was carried out; otherwise the outcome follows
  it: `KillProcess (already gone)`, `KillProcessTree (refused: <reason>)`,
  `KillProcess (permission denied)`, `Quarantine (failed: <error>)`, and
  `KillProcessTree (partial: 1 not killed, 1 spared)` for a tree killed in
  part. The action stays the first word, so readers that key on it still
  find it; `suppressed (detect-only)` and `none` are unchanged, and records
  already written keep their text. The privileged e2e now check who the
  response hits: a new suite runs an enforcing agent and asserts that a
  `/tmp` offender is named by its record and dies by SIGKILL while a
  same-named sibling runs on; the honeypot tests assert one signed record
  (Critical, KillProcessTree carried out, the tamperer as principal) and
  the death of the tamperer and its child, where three unrelated
  substrings of the log passed before (`COMBAT` matched the boot banner);
  the uncommon-port listener test asserts its NN-L-NET-006 record; and
  absence checks wait for a barrier through the same pipeline (an exec, a
  FIM write, a settled row count) instead of a fixed sleep.
- External audit, Wave 2, the anti-tamper proved in enforce mode (Medium
  TST-001, TST-002, TST-010, LAB-001): every privileged fixture stops its
  agent by evicting it from `PROTECTED_PIDS` with bpftool, which only a
  test build's observing BPF guard allows, and no test showed the
  production guard refusing it. A new e2e runs the guard in enforce mode
  and asserts that root's eviction and `kill -9` are refused and recorded,
  that the fixtures' teardown then fails and says why, and that the signed
  shutdown stops the agent. That teardown used to ignore a failed eviction
  and a refused signal and leave the agent running: it now fails the test,
  sends no signal it knows will be refused, and no agent is started when
  `bpftool` does not run (on an Ubuntu 22.04 lab guest without
  `linux-tools-$(uname -r)` the refused signal sent the agent into COMBAT;
  it killed the test runner, then the next test binaries). The runbook's
  respawn test no longer publishes the eviction recipe (`systemctl kill`
  inside a trusted-installer window instead), `nn-lab.sh respawn-check`
  fails where it warned when a root `kill -9` or an out-of-window
  `systemctl kill` succeeds, the lab installs and checks the guest's
  bpftool before the test suites, and `docs/verify-2b.sh`, whose normal
  stop was the eviction, is retired.
- External audit, Wave 2, agent start and watchdog respawn; RAG and ADE
  tooling (Medium DEP-004, WDG-009, WDG-011, WDG-R01): the agent unit's
  bpffs pre-flight was a `ConditionPathIsMountPoint`. Without bpffs at
  `/sys/fs/bpf` systemd skipped the agent and reported its start job done
  — "inactive (dead)", nothing in `systemctl --failed` — and the
  watchdog's `systemctl start --no-block` succeeded the same way. It is now
  `ExecStartPre=/usr/bin/mountpoint -q /sys/fs/bpf`: the unit fails
  (`Result: exit-code`), is listed by `systemctl --failed` and the system
  reads degraded (an `AssertPathIsMountPoint`, the audit's proposal, fails
  the start job but leaves the unit inactive). Every watchdog hold — a start that brought no agent back within 30 s, a failed
  `systemctl start`, the restart ceiling — is recorded with the unit's
  systemd state at `/run/northnarrow/watchdog.hold`, and the agent signs
  it as an `integrity_drift` (`watchdog_hold`) at its next start; it was a
  journal line only. **Regression:** a host without bpffs shows a failed
  agent unit instead of a skipped one, and a host without
  `/usr/bin/mountpoint` (util-linux) cannot start the agent. The watchdog ran `systemctl start`
  on its runtime's only thread, so a busy PID 1 stopped the STATUS ping and
  every timer for up to the D-Bus timeout, and after any stall the ping
  interval fired its missed ticks back to back: "two timeouts 60 s apart"
  could be two pings 2 s apart. The respawn now runs on the blocking pool,
  a stop request is honoured while it runs, missed ping ticks are delayed,
  and the fallback argv no longer re-reads `/proc/<pid>/exe` in a 60 s
  blocking sleep. `cargo xtask rag-kb` parsed what it downloaded or found
  in `--mirror` unchecked, fetched the ATT&CK bundle and licence by tag and
  the DRL licence from `master`, and labelled the commit-pinned Sigma
  tarball `master`. Every input is now fetched by commit and must match a
  pinned SHA-256 before it is parsed, in both modes; `provenance.json`
  records `input_sha256`; a rebuild whose dumps differ from the committed
  anchors writes nothing unless `--update-anchors`. The anchors were
  rebuilt from the verified inputs: the dumps are byte-identical; the Sigma
  `pin` is now its commit, so `kb_index_hash` changed (`4d335aed…` →
  `b6cd7d32…`). `ade_attacks` with `NN_ADE_ALLOW_MOCK=1` and a model that
  did not load scored the mock backend, which never reads the prompt
  (100 %): it now exits non-zero naming the mock, and the report names the
  backend next to the rate.
- External audit, Wave 2, install integrity fails closed (Medium DEP-007,
  DEP-009, DEP-006): `install.sh` stepped its release checks down on its
  own — a tree without `MANIFEST.sha256` installed as a "source tree", so
  removing that one file from an altered release switched every check off.
  A tree without it is now refused unless `--source-tree` is given, and a
  tree vouched for only by its own `MANIFEST.sha256` (no tarball +
  `SHA256SUMS`, no attestation) unless `--allow-manifest-only`; the flag is
  recorded in `install-manifest.json` (`verify_override`), and a new
  `nn-admin host-check` line warns below `checksums` (`package` included).
  At boot a deleted install manifest switched the binary integrity check
  off where an edited one refused the boot: once the signed audit chain
  holds a verified boot of this install, a missing manifest refuses the
  boot too (exit 78, `agent_boot` refused, `NN_ALLOW_UNVERIFIED_BINARY=1`
  for a development host). The upgrade and uninstall drain waited for no
  LSM program at all on the host, so a second BPF-LSM product made them
  give up with the agent already stopped; the agent now lists its own
  program ids in `/run/northnarrow/bpf-own-ids` and the scripts wait for
  exactly those (an agent older than the list: the old count, naming what
  is left). **Regression:** a scripted install from a source tree needs
  `--source-tree` (the lab and the range bootstrap pass it); an extracted
  release without its tarball and `SHA256SUMS` needs `--tarball`/`--sums`
  or `--allow-manifest-only`; a host restored without its install manifest
  does not start until `install.sh` runs again.
- External audit, Wave 2, release trust chain and CI supply chain (Medium
  SUP-001, SUP-002, SUP-005, SUP-017, DEP-008): an attestation check
  accepted any ref, so the artefacts of a `workflow_dispatch` run on a
  branch verified like a release. install.sh (gh and cosign), README, the
  operator guide and the tarball's README-RELEASE now require the release
  workflow at a `v*` tag (`--cert-identity-regex '…release\.yml@refs/tags/v'`,
  `--deny-self-hosted-runners`). Every GitHub action is pinned by commit
  SHA with its version as a comment, and cargo-cyclonedx (which writes the
  attested SBOM) and cargo-fuzz by version; a test fails on a tag-pinned
  action or an unpinned `cargo install`. `.cargo/config.toml` defaults to
  `target-cpu=x86-64-v2`: `native` tied any build copied to another host to
  the build CPU (SIGILL elsewhere) and is now an explicit opt-in. The
  `.rpm` is signed on a tag by its own job with a key from a tag-restricted
  environment, checked against the public key committed at the tag, and
  verified (`rpm -K`) before it is attested; `rpm --import` + `rpm -K` or
  dnf with `localpkg_gpgcheck=1` check it on the host. The `.deb`, which
  dpkg and apt do not verify per file, is checked with the tag-bound
  attestation before `dpkg -i` (operator guide §6.1); `dpkg --verify` and
  `rpm -V` are no longer presented as an integrity check of the package's
  origin. **Regression:** the artefacts of a dispatch run on a branch no
  longer pass install.sh's attestation step (`--require-attestation`
  refuses them); dev, lab and range builds decode with candle at the
  x86-64-v2 ISA unless they opt into native; a tag release fails at
  `rpm-sign` until the maintainer has created the rpm signing key.
- External audit, Wave 2, C code in the agent (Medium MAIN-006): the ADE
  tokenizer split every prompt — strings the observed processes chose —
  with Oniguruma, a C regex library (`onig_sys`), inside the root agent,
  against the no-C rule the same manifest applied to zstd. Asking
  `tokenizers` for `fancy-regex` was not enough: candle-core 0.10 requires
  its `onig` feature, and with both on, tokenizers uses Oniguruma.
  candle-core 0.10.2 is now patched (`vendor/candle-core`: the crates.io
  package, its tokenizers dependency asking for `fancy-regex`) and the
  backend is `fancy-regex` (Rust). A golden test recorded with Oniguruma
  first (Unicode, every whitespace class, long argv, DNS names, an
  ADE-shaped prompt, hostile runs) gives the same pieces and token ids; a
  full prompt tokenizes in about 7.5 ms instead of 6. A CI step fails when
  `onig_sys` or `zstd-sys` enters the agent's dependency graph. AUT-009:
  the rollback-floor residual (a log cut inside a UTF-8 character emptying
  the floor for a boot) was already gone with LLMR-014; two tests pin it.
- External audit, Wave 2, lab and build tooling (Medium SNS-003, EBPF-014):
  the sensor-feasibility runner of lab builds (`--sensor-feasibility`,
  feature `test-privileged`) ran as root on fixed names in world-writable
  directories: it removed and re-created `/var/tmp/nn-feasibility`, wrote
  its fixtures there and copied `/usr/bin/true` to
  `/dev/shm/nn-feasibility-true`, then executed that copy, so a local user
  who prepared those names could have root run their file. Each run now
  works in fresh `mkdtemp` directories (0700, `<base>/nn-feasibility.XXXXXX`
  and `/dev/shm/nn-feasibility.XXXXXX`; `NN_FEASIBILITY_BASE` kept),
  creates every file with `O_CREAT|O_EXCL|O_NOFOLLOW`, checks each file it
  is about to execute (regular, owned by root, the expected link count, a
  named copy writable by root only), and never touches the old names. The
  eBPF build stamp recorded only the source hash, so an object rebuilt
  outside `cargo xtask` from the same sources (other flags, another
  toolchain, an IDE) or replaced after the stamp was embedded as fresh.
  The stamp (`nn-ebpf-buildhash-v2`) now also holds the SHA-256 of the
  object xtask built, and `agent/build.rs` refuses an object whose bytes
  differ. **One forced rebuild:** a stamp written before this change reads
  as absent and the agent build stops on "UNSTAMPED eBPF OBJECT" until
  `cargo xtask build-ebpf` (or `cargo xtask build --release`) runs once.
- External audit, Wave 2, RAG corpus integrity and provenance (Medium
  XAI-001, XAI-009, XAI-002, XAI-010, XAI-018; dormant while
  `NN_ADE_RAG_ENABLED` is off): the RAG canary indexed every `*.jsonl` in
  its directory, unchecked, into the trusted part of the ADE prompt; an
  empty or missing directory gave RAG on the ~36 built-in seed notes,
  logged as "RAG enabled"; and an index on disk was opened whenever its
  marker file, forgeable by whoever could write there, matched. The
  agent now embeds
  `docs/kb-sources/kb_index.json`, which names each canonical dump with its
  SHA-256 (`cargo xtask rag-kb` writes the names), and starts RAG only when
  the directory holds exactly those dumps, byte for byte; otherwise it
  runs without RAG, with a WARN and a signed `subsystem_degraded` naming
  the cause. The index is built in memory at every start (about 0.4 s);
  `NN_ADE_RAG_INDEX_DIR` is ignored with a WARN. The XAI `environment_hash`
  now includes the loaded corpus fingerprint (an empty field with RAG
  off). The Article 13 dossier §8 no longer claims that the signed chain
  commits every retrieved snippet: the prompt carries only the titles and
  Sigma severities, and which documents were retrieved is covered only in
  part until the Tappa 13 log; a new §9 records that the ADE is advisory.
  **Regression:** a knowledge-base update needs an agent release.
- External audit, Wave 2, correlation context and XAI readiness (Medium
  XAI-004, XAI-013, XAI-005, XAI-011): the focal event sat in its own
  correlated context — the agent pushed a copy into the buffer and excluded
  it by address, which never matched — so the model read it twice, once as
  untrusted correlated data. The copy is now excluded (same variant, pid
  and timestamp; the ExecCheck of the same exec stays). About 20 unrelated
  events in the 30 s window (DNS queries) pushed a precursor of the same
  process, parent or file out of what the model saw: up to half of the 20
  correlated slots now go to events sharing a key with the focal one,
  within 5 minutes, before nearby events; an event left out for its
  injection score takes no slot; the 4 KiB block cap and the model-window
  fit drop nearby events before keyed ones. The selection runs on the ADE
  evaluation's task, not on the event loop. XAI (not wired yet): the
  preflight refused every ProcessSpawn with 4 or more correlated events;
  the bounded-K cap now adapts to the budget (20 correlated events: K = 4,
  a Degraded chain) and is recorded in `method.max_units`, and only the
  correlated events the prompt renders are units. An event ADE keeps from
  the model (injection score, a prompt over the window) no longer yields a
  signed "Complete" chain of zero deltas over the hash of an empty prompt:
  it is refused before any probe. **Regression:** the model sees a
  different correlated context (at most 20 events, keyed first).
- External audit, Wave 2, deception content and state (Medium DEC-007,
  DEC-008, DEC-010, DEC-011): what the decoys held told an attacker what
  they were — the credential templates said "Canary credential — DO NOT
  USE. NorthNarrow XDR", used `northnarrow.io` names and
  `NORTHNARROW_API_TOKEN`, a File canary was three comment lines naming the
  product, the operator key and the rule — so one `grep -ri northnarrow`
  found every decoy on every host. The templates are now neutral (no
  comment, Docker Hub and ghcr.io entries, `API_TOKEN`, `azure-cli-<date>`,
  a generated GCP project id) and a File canary holds 512 to 4095 bytes
  derived from its seed. `install.sh` replaces an installed template that
  is byte-identical to the one an earlier release shipped, keeps an edited
  one (with a WARNING if it still names the product) and installs them
  0640 in a 0750 directory; the agent does not use a shipped template of an
  earlier release it still finds. The content was rendered from the
  operator key fingerprint and the path: the fingerprint was printed into
  the azure, gcp and docker decoys and every host got the same credential
  for the same path. Each deploy now draws a random 32-byte seed, recorded
  in the registry with the SHA-256 of the bytes written, and `nn-admin
  canary refresh` writes the decoy again from a new seed (in place, the
  same inode), recorded too; a refresh whose decoy cannot be written or
  watched is refused. At boot each decoy is compared with its record: one
  modified, removed or replaced (a link, a FIFO) while the agent was down
  used to be re-armed in silence; it is now an ERROR and, when its state
  changed, a signed `integrity_drift` (`canary_decoy_tampered` or
  `canary_decoy_missing`) and a `decoy_check` row that `nn-admin canary
  list` shows; only a regular file is watched. A trip lived in memory only:
  every restart re-armed the response for a canary already tripped. It is
  now a signed `trip` row naming the access row (that hash was always
  empty), read back at boot. **Regression:** a tripped canary stays tripped
  (recorded, not responded to) across restarts until `nn-admin canary
  refresh`, as the design's manual refresh intends. Decoys deployed before
  keep their content, which names the product, and cannot be checked
  beyond their presence (a WARN at boot): refresh them, or burn and
  deploy again. Reading a decoy trips it: `nn-admin canary list` is the
  inventory. An older agent (downgrade) skips `trip` and `decoy_check`
  rows as unreadable, re-arms tripped canaries, and chains its next row
  to the last row it could read, which an off-host check of the registry
  then reports as broken.
- External audit, Wave 2, DNS attribution identity (Medium NET-016,
  NET-006): a connect took the last name its PID had asked for in the
  past 300 s, whoever held the PID then. A process that inherited the PID
  of one that resolved a `.onion` name — and that resolves through
  Varlink, or connects to a bare address — was recorded in the signed
  netflow row with that name and killed by NN-L-NET-002. The connect pump
  now reads the connecting process's start (the exec's from the spawn
  cache, else `/proc` less the host's suspended time), the row carries it
  (`proc_start_ns`), and only the queries made since count. A forwarded
  DNS leg went to the newest PID that had sent the same name, compared
  case-sensitively and wherever it was sent: a process could choose whom
  NN-L-NET-014's kill named. The originator must now have asked a loopback
  stub resolver, the name matches ignoring case, and two such processes
  are an ambiguous attribution — logged, not acted on.
- External audit, Wave 2, netflow drain throughput and honest coverage
  (Medium NET-019, NET-012, NET-009): every TCP close was written to
  `netflow.jsonl` with its own fsync and handed to the rules before the
  next record was read, so one user's loop of short connections made the
  kernel drop closes, other users' among them. Rows are now committed
  together, one fsync at most every 100 ms (a crash of the host can lose
  the last 100 ms, or tear the last row, which the next open cuts and
  attests); the listener log too. The rows handed to the rules are paced
  per uid (1,000, then 200 a second); a row held back is still written,
  with `"decision_engine_skipped": true`, and is never one a killing rule
  could match (NN-L-NET-001, -002, -003, -008, -010, -018) or one of a
  process with a chain precursor, which keeps NN-L-CHAIN-* complete. The
  flow tracker scanned up to 65,536 pending connects on every close and,
  when full, evicted the oldest — the long session; a close is now O(1)
  and the eviction takes the oldest connect of the process holding the
  most, and a row built at close names its executable. No sensor
  produces TLS fingerprints yet (BUG-025): a JA3 list with entries is now
  an ERROR and a signed `subsystem_degraded` at boot instead of silent
  coverage, the shipped `netflow-ja3-blocklist.v1` says NN-L-NET-003 is
  inactive, and the new `nn-admin net status` shows the rows held back,
  the evictions, the network rings' drops and the inactive rules.
- External audit, Wave 2, posture scope and exemptions (Medium POS-005,
  POS-015, POS-009): every process without a login uid — each service,
  each container, a process already gone — shared one corroboration
  scope, and with it the lock: puppet or salt rewriting a unit file locked
  a COMBAT that any other service or container then corroborated. Such a
  process is now scoped by the systemd unit or container its cgroup names
  (read, for an event that raised a trigger, from the process or its
  nearest running ancestor); a signal that cannot be placed is recorded
  but corroborates nothing and locks nothing, and root's change locks
  COMBAT only when its own actor's evidence pairs with it. One exec from
  `/tmp`, `/var/tmp` or `/dev/shm` was a COMBAT-tier signal: a build's
  `conftest`, then an upload from the same session, reached COMBAT. It now
  raises `StagingExec` (ENGAGED, never corroboration), and
  `ConfirmedIntrusion` only when the file was unlinked or a memfd as it
  ran, or the same process crossed the mass-write threshold within a
  minute — never under a package manager. The watchdog's exemption from
  posture triggers was a PID compare refreshed every 30 s: it now ends
  with the process verified (its start time), and a kernel denial from the
  watchdog's PID is raised; the agent's own PID stays exempt.
  **Detection change:** a plain staged binary followed by another signal
  from the same session stays at ENGAGED (R001..R003 still kill the
  exec). Scoping login sessions by workload too waits for the
  workload-context design (steps 1–2).
- External audit, Wave 2, open-sensor path and classification fidelity
  (Medium SNS-005, SNS-006, SNS-007, EBPF-011): a writer that forked a
  fresh worker every few files never reached the mass-write threshold,
  which was counted per process. A second window per cgroup
  counts overwrites (existing files of 4 KiB or more) of processes that
  rewrote at least three, with a threshold of 40 a minute; its crossing is
  file-system evidence that needs corroboration, and a build (one process
  per output) never enters it. The classification walk goes 16 directories
  up (was 8) and says when it stopped short. A path under a filesystem
  root the agent cannot place reads `mnt[<dev>:<ino>]/…` instead of a host
  path, a path component cut at 31 bytes ends in `…` and an unreadable one
  is `?`; for such paths the posture uses the kernel's class of the file,
  so a kernel-classed write there no longer goes unnoticed. The open
  sensor's rules are written past a full map — stale rules removed first,
  the posture's own paths before homes and runtime directories, the cache
  generation always bumped — with an ERROR and one signed
  `subsystem_degraded` when some do not fit; the maps hold 4096 inode
  rules (was 1024). The sensor's program now verifies on 5.15 in about
  460,000 instructions (was 834,000): the record writer and the counts are
  global BPF functions.
- External audit, Wave 2, process and canary rule coverage (Medium
  PROC-009, PROC-010, PROC-008, NETR-006): the first rule to match wins,
  and records ran ahead of kills — a shell in a hidden home directory was
  recorded, not killed; a staging-dir process reaching port 21 or an
  internal host was recorded; a DNS tunnel with names over 60 characters
  never reached its kill. Every rule that kills now comes first, and the
  specific tool rules come before the staging ones: `/tmp/insmod` is R011
  (High, T1547.006), not R001 (Medium). R007 killed the tree of any
  process whose name contained a miner's (`xmrig-cleanup`), and R006
  every `socat`, the distribution's included: both take the process
  allowlist; R007 kills an exact miner name (in the process name or the
  executed file's) and records a name that only contains one; R006
  records the distribution's `socat` unless it runs a shell. The shipped
  process allowlist names package managers and configuration management,
  but the rules judged only the program run, so it never applied: a root
  exec of a system-tree tool under one of them (DKMS running `modprobe`
  under apt) is now recorded, not killed. A canary accessed in a way its
  type does not expect — a File decoy's path executed — got no verdict
  and was burned; any access now answers. **Regression:** rule ids and
  severities change for these cases, a miner renamed `xmrig-something`
  and the distribution's `socat` relaying to anything but a shell are only
  recorded, and the engine holds R007 twice (73 rules, 72 ids).
- External audit, Wave 2, admin read verbs (Medium ASK-006, ASK-007,
  ASK-008): `fim report`, `net flows` and `canary list` read the active
  file from its start and stopped at half a frame, so past about fifty rows
  they answered with the OLDEST rows, and no verb opened a rotated archive:
  a flood of connections from any user hid the newest flows from
  `net flows`. They now answer the newest rows first, from the active file
  then the archives, within the same budget; `truncated` means older rows
  were left out. The read is bounded per file and per request and opens
  only regular files, without following a symlink. `fim report` and
  `net flows` read the built-in paths whatever `--fim-drift-file` and
  `--netflow-file` said; they read the configured files now.
  `net listeners`, `net fingerprint` and `net resolve` answered Success with
  nothing, without reading anything: `net listeners` lists the listener log
  (listen events, not a snapshot of open sockets), `net fingerprint` the
  netflow rows of that flow (`ja3`/`ja4`/`sni` null: the TLS capture is not
  wired yet), `net resolve` the hostname of the newest retained flow to
  that address; a malformed address or flow id is refused. **Regression:**
  `fim report`, `canary list`, `net flows` and `net listeners` print the
  newest row first — a script that read the first line as the oldest must
  read the last.
- External audit, Wave 2, inputs trusted but forgeable (Medium ATP-010,
  ATP-005, SNS-002): the tracepoint field offsets came from whatever was
  mounted at `/sys/kernel/tracing` — a tmpfs over it, or a file bound over
  one `format`, chose where the exec, open and io_uring tracepoint sensors
  read, silently. A root and each file are now used only on tracefs; a
  field must have the width the sensor reads, lie past the common header
  and end within 512 bytes; a field missing from the io_uring submit event
  now tries its other name. A field left on its compiled offset is a
  signed `subsystem_degraded`, and a mount over or under the tracefs roots
  a signed `integrity_drift` (`tracefs_mount`). The COMBAT carve-out took
  any prefix: `10.0.0.0/0`, a typo for `/8`, spared every address and
  COMBAT isolated nothing. A line wider than /8 (IPv4) or /48 (IPv6), or
  naming the unspecified or a multicast address, is now skipped with a
  WARN and refused by `config overlay set|sign`; with the overlay gate, a
  carve-out file missing at a check is no longer read unsigned a moment
  later. **Regression:** a signed carve-out with such a line loses that
  line at the next COMBAT engage; `nn-admin config overlay status` names
  it. A `.` inside a DNS label read as a separator, so one label passed for
  several or spelled a well-known host: query names now use RFC 4343
  escapes (`\046`, `\092`, `\DDD` for unprintable bytes, which were all
  `?`); ordinary names are unchanged.
- External audit, Wave 2, FIM watch set (Medium FIMP-007, FIMP-008,
  FIMP-010, FIMP-009): the FIM drain's retry queues had no cap and no
  de-duplication, and their pass (one `stat` per entry, under a lock, on a
  runtime worker) ran after every emitted event, so a burst of short-lived
  files in a watched directory slowed the only reader of the FIM ring
  quadratically. Each queue now holds one entry per path or inode, at most
  1024 (the rest counted), and the pass runs at most every 5 ms, off the
  runtime's threads. Files enrolled at runtime were never let go, and a
  full `WATCHED_PATHS` refused every new watch with a WARN: a canary
  deploy still answered Success and its decoy never tripped. Runtime
  children are now capped at 4096, oldest out, swept every minute once
  their file is gone; a full map makes room by evicting them, never a
  configured path, a symlink hop or a decoy; an eviction or a refusal is an
  ERROR and a signed `subsystem_degraded` (`fim_watch_map_full`, at most
  once an hour), and a canary whose decoy cannot be watched is refused. A
  watched symlink was watched by the link's inode only: an in-place change
  of the file behind it (`/usr/bin/python3` to `python3.12`) or a
  re-pointed `/etc/alternatives/nc` touched no watched inode. Each link (at
  most 8, a loop refused) and the final target are now watched under the
  configured path, a change there is checked against that path's baseline
  once it has landed, and the baseline row records the canonical target.
  A write on a path a Critical rule guards whose re-hash found the
  baseline content (a change undone before the drain looked) left no
  trace; it is now a drift row flagged `content_restored`, without a
  verdict.
- External audit, Wave 2, ADE window, prefill, failure evidence, prompt
  (Medium LLMR-008, LLMR-017, LLMR-003, LLMP-013): an over-long prompt
  lost its head, which is the system prompt; the engine now drops the
  oldest correlated events to fit the model window, never the system
  prompt, and escalates an event whose prompt cannot fit. The prefill
  runs in 256-token chunks and stops at the time budget. A timeout or a
  backend error is recorded as an Escalate (`ade_unavailable`) instead of
  a journal line. The system prompt (v1.1) says that observed strings are
  evidence, never instructions, and its few-shot examples, three instead
  of five, decide on behaviour in the format the agent sends.
- External audit, Wave 2, ADE sanitizer score and coherence matrix
  (Medium LLMP-003, LLMP-011, LLMR-010, LLMP-004, LLMP-006): every event
  string was scored twice and before deduplication, and the keyword
  matchers were too broad, so one DNS lookup of `admin.<domain>`, a
  systemd `override.conf`, `react-assets` or a path in Russian forced an
  Escalate (or skipped the model). Each string is now scored once on the
  deduplicated flags, and one strong signal (a chat-template token, an
  explicit "ignore previous instructions" or role switch) still forces an
  Escalate on its own; `system`, `admin` and `override` are no longer
  separator variants (their hostile forms stay keywords), the product's
  own names raise nothing, and `act as` matches whole words only. A high
  injection score now overrides any verdict but Escalate (a hostile
  correlated string could sit behind a Kill), and a severe indicator with
  an Allow is escalated; a correlated event too hostile for the prompt
  still weighs. The prompt no longer echoes decoded ROT13 text,
  and a confidence or novelty outside [0, 1] is a parse error (a Kill at
  confidence 5.00 ran).
- External audit, Wave 2, signed evidence logs (Medium EVD-004,
  EVD-018): one forged line at the end of a signed log (detections,
  status, FIM drift, NetFlow) could force a spurious rotation and then
  make every later append fail, at every boot; a forged line in its
  manifest kept the log from opening. A file planted at the next archive
  name made the next rotation erase the sealed file. Tail lines are now
  checked (format, hash, signature) before the chain continues from them;
  a bad one is cut and recorded in the signed manifest. A rotation never
  replaces or truncates an existing file: it moves to the next free name
  and records the foreign entry.
- External audit, Wave 2, self-integrity and detection-store evidence
  (Medium EVD-013, EVD-012, EVD-006): a drop-in reported once, removed and
  put back identically was never reported again. The self-integrity check
  now records a finding that goes away (`integrity_drift_cleared`, signed)
  and reports it again when it comes back (at most once per 10 minutes,
  with the count), capped at 64 findings per kind per round. Limits that
  appear or vanish are drift, the agent's cgroup is checked, and when the
  agent runs as its unit the first round compares the limits with the
  unit's values (`limit_unexpected`), so a limit changed in the first 15 s
  is no longer taken as normal. A full detection queue drops the lowest
  severity logged-only record first, and drops are recorded in a signed
  `detections_dropped` audit entry per minute.
- External audit, Wave 2, kernel telemetry loss (Medium EBPF-009,
  EBPF-013): holding 4096 watched files open for write filled the FIM
  write-marker map, and the next in-place rewrite of a watched file left
  no `Modified` event and no counter. The map now matches the watch set
  and a refused marker is counted (`fim_dirty_full`). An unprivileged loop
  of `listen()` or `io_uring_setup()` could push other processes' listener
  and ring-creation records out of their ring: both now have DNS's
  per-process and per-user record budgets (64, then 128/s per process),
  the excess is counted (`listen_rate`, `io_uring_rate`) and carried by
  the process's next record, and the new NN-L-NET-021 names the process
  that floods.
- External audit, Wave 2, telemetry loss (Medium SNS-001, SNS-008,
  SNS-009): a ring-buffer pump that died went unnoticed — the agent kept
  running blind on that sensor. Every telemetry task is now watched: one
  that ends is recorded in the signed audit log, the agent stops
  (`sensor_pump_exited`, non-zero exit) and the watchdog restarts it.
  Malformed records of the open sensor are counted and shown by `nn-admin
  status` (`ringbuf rejected`), like every other ring's. A security ring
  losing more than 64 events in 10 s raises the posture to ALERTED
  (`TelemetryLoss`, never corroboration for COMBAT; not during a package
  transaction or a trusted-installer window), and an unreadable drop
  counter keeps its last value instead of reading as zero.
- A build rewriting its own outputs (`cargo build`: fingerprints,
  timestamps, `.d` files) was counted as encryption in place: with another
  alert in the session it reached COMBAT, which killed cargo and
  quarantined `cargo` and `rustc`. An overwrite counts only for an existing
  file of at least 4 KiB (its size read at open).
- External audit, Wave 2, network rule state and addressing (Medium
  NETR-005, NETR-007, NETR-008): NN-L-NET-008 (outbound from a staged
  binary) never fired — no flow row carried the process's executable. The
  image is now named at connect time (lineage cache, `/proc` as fallback,
  a deleted image included), so a dropper's forked child that never execs
  is killed when it calls out; NET-008, CHAIN-002/005/007 and the posture's
  exec arm share one staging set (`/tmp`, `/var/tmp`, `/dev/shm`), with a
  package transaction's processes recorded, not killed. NN-L-NET-007/018
  treat IPv6 unique-local and link-local peers as internal: SMB, RDP, WinRM
  or VNC over them now draws the same verdict as over RFC 1918. The DNS
  burst, beacon and DNS-tunnel windows have hard caps in O(1) per event —
  before, a connection or DNS spray by any user grew them for up to an hour
  with a full scan per event, and a spray of 4096 parent domains switched
  off NN-L-NET-014's tunnel kill for every other process. At a cap the
  least recently updated key goes (a beacon's or a tunnel's keys last),
  counted and warned about; a process reaching more than 256 destinations
  in an hour is held to its own quota.
- External audit, Wave 2, bounded correlation state (Medium NETR-004,
  NETR-009, NETR-010): the chain rules' correlation store now holds a hard
  cap of 4096 processes in O(1) per insert — before, every new process above
  it cost a full scan under the engine's lock, so any user could stall the
  rule engine with a loop of execs. Processes holding only a `sudo`/`su`
  precursor are evicted first; losing a blocking chain's precursor is
  counted and warned about. Precursors and lineage now follow the process
  incarnation (its start time), so a process that inherits a recycled PID no
  longer inherits the old holder's precursors or ancestors (a wrong
  `KillProcessTree`). The ancestry tree keeps live processes under a flood
  of short-lived ones (second-chance eviction against `/proc`, 65,536
  edges), and counts and warns when it must drop a live one.
- A TCP flow closed abortively (RST, `SO_LINGER` 0) was recorded with
  source port 0: the close probe read the port after the kernel had
  released it. It now falls back to the socket's `inet_sport` (a new
  BTF-revalidated offset).
- External audit, Wave 2, undoing a response (Medium CMB-016, Low CMB-026):
  three signed admin verbs, run by the agent and recorded in the signed
  audit log. `nn-admin response status` (`audit-read`) lists the contained
  processes, the quarantine vault and the COMBAT stage; `response release
  --pid` and `response restore --vault-id [--to]` need the new
  `response-manage` role, never granted by default. A release goes back to
  the cgroup the process came from, by the containment record; a restore
  checks the vault id (32 hex digits) and the SHA-256 recorded at capture,
  creates a new file (mode 0600, never over an existing file or through a
  link, never under a protected prefix, the directory must exist) and keeps
  the vault entry — before, restore took any id as a path fragment and
  overwrote whatever the destination named. `nn-admin status` shows the
  COMBAT stage and whether COMBAT is locked.
- External audit, Wave 2, containment state and recovery (Medium CMB-010,
  CMB-017, CMB-013, CMB-015): a released process goes back to its systemd
  unit (recorded when it was contained), never to the root cgroup — before,
  it left its unit's accounting and limits for good; an agent restart
  reconciles the record. A corrupt quarantine index is rebuilt from the vault instead of
  being replaced by an empty one, and every quarantine, containment and
  release is in the signed audit log. The throttle reports the limits it
  actually set and does not move a process when it could set none. The
  carve-out docs describe IPv6 isolation as it is.
- External audit, Wave 2, process identity in kills (Medium CMB-004,
  CMB-019): a kill could reach a process that had taken the PID of an
  offender since it was attributed; the COMBAT ladder and the rule and ADE
  verdicts now capture the process (a pidfd and its start time, checked
  against what the event says about it) and signal it through the pidfd. A tree that keeps forking is no longer killed from a
  one-time snapshot that misses its new children: it is moved into a
  cgroup of its own, frozen and killed as a whole. The agent raises its
  open-files limit at start (a large episode holds one pidfd per offender).
- External audit, Wave 2, the COMBAT ladder's execution model (Medium
  CMB-007, CMB-011, CMB-012, CMB-014; CMB-010 stop-gap): the ladder's side
  effects — `nft`, cgroup writes, kills, quarantine, iptables — ran on the
  event loop, so no sensor event was read while a large tree was
  neutralized; they now run in order on a worker thread. A stand-down waits
  for a step already under way, so an isolation decided just before an
  admin unlock no longer lands after the release. A forking offender costs
  one `nft` run per episode, and a tree past 1 024 processes escalates. A
  soft egress block that did not take effect (no `nft`) is recorded and
  shortens INVESTIGATE to 10 s; `nn-admin host-check` reports a host
  without `nft`. The stand-down releases only processes it blocked and
  that are still the same process in the blocked scope.
- External audit, Wave 2, the variables that weaken the agent (Medium
  MAIN-008, MAIN-004, MAIN-007): `NN_DETECT_ONLY=yes` (or `true`) switched
  the response off without the integrity finding `=1` gets, and detect-only
  also let the agent run without a writable audit log — the audit gate now
  needs its own override (`NN_AUDIT_ALLOW_UNWRITABLE=1`), and `agent_boot`
  records where detect-only came from. The evidence logs' rotation caps
  read from the environment have a 1 MiB floor and every override is
  logged and reported; the mock ADE backend and a telemetry probe switched
  off or thinned out are reported too. A drain loop that ends is an ERROR
  and a signed `subsystem_degraded` record.
- External audit, Wave 2, the overlays' rollback floor (Medium LLMR-014):
  the newest accepted signature of each overlay was read from `audit.log`
  as plain JSON, and a missing log gave no floor — removing the log
  offline brought a retired, once legitimately signed exemption back. The
  floor now comes from the chain the agent verifies, anchored so that a
  boot checks only the new entries; a log that is gone or does not verify
  resets it, recorded in the signed chain: no overlay signed before the
  reset is loaded until it is signed again.
- External audit, Wave 2, the signed overlays (Medium LLMR-013, LLMR-016):
  what the agent applies is the overlay it verified — the loaders, and
  COMBAT at every engage, read the file a second time, so a root process
  able to pause the agent's reads could get unsigned content applied. An
  overlay is no longer read through a link, and a FIFO in its place no
  longer stops the agent's boot. A shipped default list that cannot be
  read gives way to the copy built into the agent, recorded in the signed
  audit log.
- External audit, Wave 2, the admin key files (Medium AUT-003, AUT-004,
  MAIN-005, AUT-002): a link planted in `/etc/northnarrow` no longer makes
  the agent write through it when it replaces `admin.pub` or a signed
  overlay — a key rotation could truncate the audit log. A malformed line
  in `admin.pub` costs its own key, recorded, instead of the admin socket.
  `nn-admin verify-keys` accepts the `admin.pub` install.sh writes and
  shows each key's roles; the CLI refuses an admin private key others can
  read.
- External audit, Wave 2, the trusted-installer window (Medium ATP-003,
  ATP-012): the window ends at its deadline in the kernel itself — before,
  a host whose events had stopped kept every protected file, the kexec
  refusal and the pin root's protection open until something reached the
  agent. The agent closes and records it on time, and a close that failed
  is recorded as failed.
- External audit, Wave 2, the filesystem deny (Medium EBPF-008, ATP-008):
  root could clear the immutable flag of the state directory, or make
  `audit.log` append-only to the agent, through the fsxattr interface
  (`xfs_io -c 'chattr -i'`): the deny let it through, and the number it
  held for that ioctl was none. The shipped `.v1` lists (the netflow and
  JA3 blocklists, the comm allowlists) can no longer be appended to; they
  are tuned through their signed `.local` overlays.
- External audit, Wave 2, the BPF guard (Medium ATP-013, ATP-009,
  EBPF-004): the agent's ring buffers and drop counters are guarded like
  its other maps — a root process could take a writable handle on each,
  enough to silence a sensor, the anti-tamper denials included. The
  kernel-offset table is frozen once armed. A production agent whose
  guard only observes counts it as a missing deny hook, and the signed
  boot entry records the build's test features and the guard's mode.
- External audit, Wave 2, file integrity (Medium TST-004, FIMR-007, FIMR-008,
  FIMR-009, FIMP-011): a change of a watched file's permissions, owner or
  group is drift of its own — a set-uid bit, or write for others, on a
  system binary is treated as a rewrite of it; `chmod o+r /etc/shadow` as
  a change of it. sshd's `.ssh/authorized_keys2` and
  `/etc/ssh/authorized_keys` are judged like `.ssh/authorized_keys`. The
  control-surface files the agent re-creates at boot are watched at once
  (after a reboot the runtime ones were not), restored without following
  a link, and a removal within one boot is recorded in the signed audit
  log. File monitoring that attached nothing is recorded there too.
- External audit, Wave 1, kernel module loads (High PROC-005): a module file
  under /lib/modules that no package installed and DKMS did not build is no
  longer "standard": loaded by an unexpected loader it is killed like one
  from /tmp. A module on another mount is placed on its mount point (it
  could pass for /lib/modules), and a path component that is not UTF-8 no
  longer disappears.
- External audit, Wave 1, the tracepoint fallback (High POS-004): when the
  file-open sensor runs on the `openat` tracepoint, an open's path is the
  caller's own string, read before any permission check. A refused open of
  a persistence or critical path no longer counts as a COMBAT-tier signal
  (it alerts), and a path through `/proc/self/cwd` or `..` no longer
  escapes the mass-write count.
- External audit, Wave 2, the advisory gate (Medium SUP-006): `cargo audit`
  checks every lockfile — the fuzz harness and the eBPF crate were never
  audited — and runs as a plain step with a read-only token; the action it
  replaces failed pull requests that had found nothing.
- External audit, Wave 1, the evidence signing key (High EVD-001): the
  agent's private signing key can no longer be read by root (or anyone
  outside the agent); its public half is published at
  `/etc/northnarrow/agent.sig.pub`, which `nn-admin audit verify` reads.
  **Note:** a backup of `/etc` gets `EPERM` on `agent.sig.key` (recorded,
  ALERTED); the key is not meant to leave the host.
- External audit, Wave 1, the release pipeline (High SUP-003): building and
  signing are separate jobs. The job that compiles the dependency tree has
  a read-only token, not persisted, and cannot request the signing token;
  the job that attests and publishes compiles nothing.
- External audit, Wave 1, the ADE model (High LLMR-004): the model and its
  tokenizer are loaded only when root owns them and every directory above
  them, closed to others; the default location moved from a user's home to
  `/var/lib/northnarrow/models/`. **Upgrade note:** move a model kept
  elsewhere there (or pass `--ade-model` to a root-owned location), or the
  agent runs on its rules alone. The ADE's system prompt is built into the
  agent (an installed agent never found the relative path it read). A model
  that fails to load leaves the ADE off instead of falling back to the mock
  backend, which judged by process names (LLMR-005); `NN_ADE_ALLOW_MOCK=1`
  brings the mock back for demos.
  agent (an installed agent never found the relative path it read).
  agent runs on its rules alone.
- External audit, Wave 1, DNS (High NET-004, EBPF-006): the cache of recent
  DNS queries is bounded in total (about 20 MiB at worst; it could grow
  past a gigabyte); a flood evicts the flooder's queries first. The DNS
  sensor's degraded mode (query names read from the sender's memory, on
  kernels where the socket-buffer programs cannot attach) is recorded in
  the signed audit log.
- External audit, Wave 1, a second network isolation (High CMB-006): an ADE
  `Isolate` verdict no longer cuts the host off the network through an
  nftables blackout of its own (no management carve-out, no release, not
  in `status`). Host-wide isolation is the COMBAT ladder's alone; the
  verdict kills the process tree it names. An older agent's leftover
  chains are removed at start.
- External audit, Wave 1, file integrity (High FIMR-004, FIMR-005,
  FIMP-003, FIMP-004):
  - A watched file replaced by renaming another over it (how installers
    and rootkits swap a binary, a PAM module, a unit) is now judged like a
    modification: the new file checked against the baseline, attributed to
    the process that renamed it. Before, only the rename was recorded.
  - A change to a path a Critical rule guards (system binaries, kernel
    and PAM modules, `ld.so.preload`, the baits) is never throttled.
  - One large watched file can no longer stall the FIM pipeline: a burst
    of changes to a 256 MiB file used to block the agent until the
    watchdog killed and restarted it, losing other files' changes.
  - A path added to the signed `fim-paths` overlay and re-baselined with
    `nn-admin fim baseline` is watched at once, without a restart.
- External audit, Wave 1, posture lineage (High POS-002, POS-003):
  - Ransomware run from an SSH, desktop or cron session no longer goes
    unseen: every process of a session was exempt from the mass-write
    trigger. A session's new files (a build, a clone, an archive, a
    browser's cache) still do not count; its rewrites of existing files —
    encryption in place, told apart by the kernel — do. A credential-file
    read is exempt only for the authentication program itself (sudo, su,
    unix_chkpwd, …) or its direct child, not for the whole session.
  - A process can no longer borrow sudo's (or a package manager's)
    exemption by forking its payload and then executing sudo, which needs
    no password to be seen, nor through the pid of an exited parent: an
    ancestor counts only if it ran the program before the process below
    it was forked.
- External audit, Wave 1, the quarantine (High CMB-001):
  - The agent vaults and removes the file a process ran — held open from
    `/proc/<pid>/exe`, removed only after the name is checked to still be
    that inode — never whatever its path leads to by the time the
    quarantine runs. A user could swap a directory of their own binary's
    path for a symlink and have the agent (root) delete any file.
  - Found in the lab: on a fresh install no quarantine completed — the
    vault directory was created on first use, inside the immutable state
    directory (EPERM). The agent now creates it at start.
- External audit, Wave 1, canaries (High DEC-004, DEC-005):
  - A canary kills on its first access only; later accesses are recorded
    (every access stays in the signed canary access chain). Before, every
    read of a tripped canary killed again.
  - A File or Credential canary read by a backup, anti-malware, indexing or
    sync program (restic, borg, clamd, tracker, syncthing, …: told by the
    executable the kernel ran) is recorded, not killed. A backup that runs
    a generic tool (`tar`, `rsync`) is added by the operator in the new
    signed overlay `canary-readers.local`.
- External audit, Wave 1, the agent's BPF links (High EBPF-010):
  - Detaching or replacing one of the agent's links is refused to any
    process but the agent and the watchdog, by the link the fd names —
    however the handle was obtained. The supported kernels refused both on
    the agent's link types already (EOPNOTSUPP / EINVAL in the lab); the
    agent no longer depends on it.
  - A link handle through a pin path padded past the hook's buffer is
    denied like the plain path (it went through in enforce mode).
  - Pin names are matched by a hash of the path's final component: the
    previous byte-by-byte key made the `bpf()` observer fail the kernel's
    verifier once the deny was added (it would have run without it).
- External audit, Wave 1, kills on everyday shapes (High FIMR-006, NETR-002):
  - A file created in a watched directory under `/home` (or `/tmp`,
    `/var/tmp`, `/dev/shm`) no longer kills the process tree and moves the
    host to COMBAT (NN-L-FIM-002): it is recorded. A watched binary
    hardlinked there is still killed.
  - Resolving a long DNS name no longer kills the resolving process
    (NN-L-NET-004 and NN-L-NET-014 — S3 buckets, CDN, load balancers,
    Kubernetes names): a name over 60 characters, or one high-entropy
    label, is recorded. The kill is for a tunnel's shape: 8 distinct
    high-entropy labels under one parent domain from one process within a
    minute.
    (NN-L-NET-004 — S3 buckets, CDN, load balancers, Kubernetes names): a
    name over 60 characters is recorded; encoded labels stay NN-L-NET-014's.
- External audit, Wave 1, the bootstrap admin key as a standing bypass (High
  DEP-001):
  - The package hooks no longer pick up the admin key left on the host on
    their own: an upgrade or removal opens the trusted-installer window only
    with the key in `NN_GRANT_KEY` (or one the operator opened first).
    Before, every `apt upgrade` suspended the anti-tamper with
    `/etc/northnarrow/admin.key` if it was still there.
  - A fresh install writes the bootstrap private key to
    `/root/northnarrow-admin.key` (`--admin-key-out` to choose; never under
    `/etc/northnarrow` or `/var/lib/northnarrow`, where backups, etckeeper
    and tooling would pick it up). `uninstall.sh --purge` removes it.
  - While an admin private key sits at either location, `nn-admin
    host-check` reports `WARN admin_key` and the agent records
    `admin_key_on_host` in the signed audit chain (`integrity_drift`).
- External audit, Wave 1, the agent's own binaries as a way around the BPF
  self-defence (High EBPF-002):
  - The guard on the agent's maps and links exempted any process running
    one of the agent's executables (agent, watchdog, `nn-admin`). Root could
    preload its own library into one of them: in the lab, `nn-admin`, a
    second agent and a second watchdog each got a write handle on
    `PROTECTED_PIDS` and a handle on the task_kill hook's link (enough to
    detach it). Now only the successor of an agent or a watchdog that
    exited may open the maps before it is a protected pid — while no live
    process holds that role (tracked in the kernel: the slot empties when
    the process exits), from its main thread, in its first minute. No
    process gets a link handle, `nn-admin` is not exempt at all, and a
    process running the agent's or the watchdog's binary cannot be ptraced
    before it registers.
  - The agent no longer protects a second watchdog that the pidfile names
    while the registered one still runs.
- External audit, Wave 1, systemd as a way around the anti-tamper (High
  EBPF-001):
  - The task_kill hook let PID 1 deliver any signal to the agent and the
    watchdog for the agent's whole life (BUG-010's `KILL_OVERRIDE`, armed
    at boot). systemd only relays root's request: `systemctl stop` of both
    units ended them in 0.6 s and nothing respawned them, `systemctl kill
    -s SIGKILL` killed the agent. PID 1 now passes only under a grant the
    agent writes when a signed trusted-installer window opens — the stop
    signals, until the window ends, under this boot's session nonce — or
    as `systemd-shutdown`, the last stage of a shutdown, recognised by its
    comm and its executable.
  - The units refuse a manual stop (`RefuseManualStop=yes`; without it
    systemd ignored the EPERM and reported the units dead while they ran)
    and never start a second instance beside a running one
    (`SendSIGKILL=no`). Maintenance takes the window and `systemctl kill
    -s SIGTERM`; `install.sh`, `uninstall.sh` and the lab do so.
  - A refused signal relayed by systemd is a signed detection (NN-L-AT-001,
    "on behalf of a `systemctl stop` / `kill` / `restart`") and raises the
    posture to ENGAGED (`RelayedTamperAttempt`), not COMBAT: init is never
    an offender (in the lab, the first refused `systemctl kill` made init
    the offender, which the ladder could only contain by isolating the
    host). While systemd reports the host as stopping — asked over its
    private socket, served by PID 1 — the refusal is expected, the ladder
    stands down and the posture stops escalating; the agent runs, and
    detects, until `systemd-shutdown`, and records `agent_stop` with reason
    `system_shutdown`.
- Found while verifying it in the lab:
  - Stopping `systemd-journald@northnarrow` aborted both the agent and the
    watchdog (the log writer reported the broken pipe with an `eprintln!`
    that panicked, and `panic = "abort"`), so every reboot ended the agent
    with SIGABRT and five stops in a minute would have tripped the
    watchdog's ceiling. A lost log line no longer costs the process.
  - The mass-write counter (the ransomware shape) counted write-opens of
    device nodes: `> /dev/null` in a script loop, systemd writing
    `/dev/console` at shutdown. It counts regular files only (files in
    `/dev/shm` still count).
- External audit, Wave 1, bootstrap gate and unit drop-in (High ATP-004,
  DEP-002):
  - The one-time relaxation that lets a one-key install add its second
    key with one signature (`rotate-keys add`, BUG-013) was decided on
    files root can write: `admin.pub` as it read at the request, a
    sentinel, and the install nonce the sentinel is computed from. After
    a second key was added, a root process could show the agent a
    one-key `admin.pub` again — rewritten before a restart, or
    bind-mounted over the file while it ran — with a sentinel recomputed
    from the readable nonce, and add a key of its own with one
    signature. The gate now counts the keys the agent has loaded, not the
    file, and is closed for good once the signed audit chain records a
    successful `rotate-keys add`.
  - `install.sh`'s Debian drop-in
    (`northnarrow-agent.service.d/10-debian-perf-paranoid.conf`) was
    neither protected nor checked: the integrity check skipped it by
    path. A root process could add `ExecStart=`, `Condition…=` or
    `Environment=` lines to it and stop or weaken the agent at its next
    start, unreported. The drop-in directory and file join the protected
    binary/unit set (writes, unlink and rename denied); the content ships
    as `deploy/systemd/10-debian-perf-paranoid.conf`, and the integrity
    check passes the drop-in only while it matches that file byte for
    byte.
- External audit, Wave 1, COMBAT rulesets (High ATP-001, DEP-003): the
  files that decide what COMBAT isolates — `combat-rules.v4`,
  `combat-rules.v6` and the management carve-out `combat-allow.cidrs` —
  were protected by file permissions only, re-read at every isolation and
  never signed. A root process could rewrite the rulesets so COMBAT dropped
  nothing, delete them so isolation failed, or add its own network to the
  carve-out, while the agent still logged "network isolated".
  - They are now applied only as shipped (the content the agent was built
    with) or with an admin signature (`config-manage`) for their exact
    content — the signed-overlay mechanism, with three new kinds
    (`combat-rules-v4`, `combat-rules-v6`, `combat-allow`). Anything else,
    or a missing file, makes COMBAT apply the built-in content; the
    refusal is an ERROR and a signed `integrity_drift` entry.
  - A signed ruleset must still isolate (filter table, the COMBAT chain and
    its DROP, the INPUT and OUTPUT jumps, COMMIT); a signed carve-out must
    parse whole.
  - The files and their signatures join the protected `/etc/northnarrow`
    set (unlink, rename and attribute changes denied), and the periodic
    integrity check reports one that differs from the shipped content
    without a signature, before COMBAT ever needs it.
  - Operators store a carve-out with `nn-admin config overlay set
    combat-allow --file <cidrs> --key <key>`; `install.sh --upgrade` adopts
    one edited by hand under an earlier release with the grant key.
- External audit, Wave 1, FIM availability (High MAIN-003, FIMR-001,
  FIMP-001):
  - The FIM sensors, the file-open sensor, the drain and every FIM rule
    were started only if the baseline database opened: one malformed line
    in `fim_baseline.jsonl` switched FIM off for the boot. They now start
    regardless; without the database only a new baseline cannot be
    recorded, and that is written to the signed audit chain
    (`subsystem_degraded`). A torn last write of the baseline is repaired
    and a malformed line skipped, as for the other chain logs.
  - The drain dropped "no-op" changes against baseline rows it never
    verified: a forged row giving a watched file the hash of its
    backdoored content hid every later change. Only the verified suffix of
    the chain (signature, recomputed hash, link to the previous row) may
    now silence an event; rows before a break report every change until a
    new signed baseline, and the break is recorded.
  - One invalid line in `fim-paths.v1` (or any shipped list) emptied the
    whole list — FIM watched nothing. The line is skipped and reported;
    an empty watch list is an ERROR and a signed record. `fim-paths.v1`
    is now write-denied like `install-manifest.json` (install.sh writes it
    with the pins purged); `fim-paths.local` stays MUTATE-only and
    signature-gated.
- External audit, Wave 1, chain logs cut short (High EVD-005, NET-003,
  DEC-006): one write interrupted by a crash or a power loss no longer
  switches a subsystem off.
  - A torn last line of `audit.log` kept the agent from starting again in
    enforce mode ("Refusing to run unaudited", lab: Ubuntu 22.04). The
    fragment is cut off — or given its missing newline when it is a whole
    entry — and the repair is recorded in the signed chain
    (`chain_tail_repaired`, with the dropped bytes' SHA-256). A bad line
    before the end still refuses the log, untouched; no repair ever
    empties a chain.
  - A torn `netflow_listeners.jsonl` kept the network drain from starting
    at every later boot, so no network rule saw a flow. The listener log
    is repaired the same way, and if it still cannot be opened, flows and
    listener events reach the rules anyway — only that log is not
    written.
  - One unreadable line in the canary registry or access log switched
    deception off ("rule engine sees no CanaryTripped events"). The line
    is skipped and reported (`integrity_drift`, `chain_lines_unreadable`);
    the readable canaries stay deployed and watched.
- External audit, Wave 1, identity of the protected processes (High
  MAIN-001, ATP-002, WDG-002, WDG-003):
  - The agent put whatever pid `/run/northnarrow/watchdog.pid` named into
    PROTECTED_PIDS: in the lab a root `sleep` copied as
    `northnarrow-watchdog` became unkillable (`kill -9` from root: EPERM).
    It now protects only a pid verified to run the installed watchdog
    binary, re-checked every 30 s.
  - Entries a previous agent left in the pinned map were kept while their
    process merely called itself `northnarrow-wat`; they are now kept only
    while they run the agent's or the watchdog's executable.
  - The watchdog took the agent pidfile at its word: in the lab it watched
    a `sleep` as the agent. It now verifies the process runs the agent
    binary (pidfd first, then the executable's device and inode) before
    it protects it, signals it or copies its command line, and signals
    through the pidfd. The unit gains CAP_SYS_PTRACE for that check.
  - A "stuck" signal buffered while the agent was dying could SIGINT,
    evict and SIGKILL the healthy agent that replaced it. Signals now name
    the agent they were raised against and are dropped for any other.
- External audit, Wave 1, authorised shutdown (High EVD-021, WDG-001,
  TST-003):
  - Any root process could switch NorthNarrow off for good: the watchdog
    stood down — no respawn, exit 0 — for any file at
    `/run/northnarrow/agent.shutdown_authorised` with a 64-hex hash and
    a future deadline. In the lab, such a file and a `systemctl stop` of
    the agent left both agent and watchdog off.
  - The marker now carries the shutdown the admin quorum signed and the
    exiting agent's pid, and the watchdog verifies it against
    `admin.pub` as the agent did: quorum and role, this install, signed
    while that agent ran and recently, not honoured before. Anything
    else is refused: the agent is respawned, and the agent records the
    refusal in its signed audit chain (`shutdown_marker_rejected`).
  - The agent wrote the marker through a temporary file that followed a
    symlink; it is now created exclusively, never through a link.
  - New privileged tests cover both halves: a forged marker brings the
    agent back, a quorum-signed one stands the watchdog down.
- External audit, Wave 1, allowlists on exec identity (High LLMR-012;
  the NETR-003 class swept across the remaining rules):
  - A process could silence the io_uring and BPF rules by naming itself
    like a known program: in the lab, the io_uring probe built as
    `nginx` read a file and connected through a ring, and python renamed
    `systemd` with `prctl(PR_SET_NAME)` loaded a BPF program, with no
    verdict. The rules' known programs and the operator allowlist are
    now judged on the executable the kernel ran, inside a root-owned
    system tree. The same now holds for R011–R017.
  - The allowlists keep working as written: an entry of 15 characters,
    the length the kernel cuts a process name to, also matches the
    longer program it was cut from (`unattended-upgr`,
    `systemd-network`). `systemd-udevd` is recognised as `udevadm`, the
    file it links to.
  - When the executable cannot be read (the process exited first), a
    verdict for a process named like an allowlisted program is recorded,
    not acted on.
- External audit, Wave 1, process rules (High PROC-002, PROC-003,
  PROC-004, PROC-007):
  - Without the kernel-resolved path (tracepoint mode), a relative
    `./payload` from /tmp or `/usr/bin/../../tmp/x` slipped past the exec
    rules; the fallback path is now normalised or read from the process.
  - A kernel module loaded from a directory nested deeper than 16 levels
    got an alert instead of the kill; it is now killed, and an unreadable
    path raises a High alert.
  - R009 no longer kills root scripts run from a home or /tmp in an
    administrator's sudo session at a terminal, nor package scriptlets;
    it records them. Other root execs from those paths are still killed.
- External audit, Wave 0, anti-tamper (High EBPF-003, WDG-004):
  - A single write to the pinned ptrace override map lifted the agent's
    ptrace protection until the next reboot. The override now needs the
    current session's nonce and is cleared at every start.
  - When the agent kept dying (tamper suspected) the watchdog exited
    quietly, leaving neither agent nor watchdog. It now stays up, reports
    the degraded state to systemd, and resumes once the agent is started
    again.
- External audit, Wave 0, detection (High FIMP-002, FIMP-005, FIMP-006,
  NETR-001, DEC-003):
  - A watched symlink pointing at a FIFO froze file integrity
    monitoring for good; one pointing at a device read forever.
  - After `mv` of a watched file, edits to the moved copy were reported
    under the watched name, and could get the editor killed.
  - When the drift log could not be written, the FIM rules never saw
    the change. They now always do, and the lost evidence is reported.
  - A credential file opened by its own application (a keyring, a
    browser profile) and a network flow by the same process drew a
    KillProcessTree; such opens are reported only, as designed.
  - File canaries never worked once deployed by the installed agent:
    writing the decoy failed on its read-only sandbox, the decoy was never
    watched by the kernel, and after a restart its reads were dropped.
    Decoys are now written through the host's view without following a
    symlink anywhere on the way, watched from deploy to burn, and watched
    again at every boot (High DEC-001, DEC-002 from Wave 1).
- External audit, Wave 0, COMBAT response (High CMB-002, CMB-005, and
  CMB-003 from Wave 1):
  - NEUTRALIZE reported a threat contained when the root of its tree
    died but descendants lived on, or when the tree walk stopped at its
    limit. Every descendant now counts.
  - The guard that spares sshd and the agent's watchdog applied only to
    the tree walk; a rule's KillProcess, or a Quarantine, BlockOutbound
    or Throttle verdict, ignored it. It now covers every action on a
    process.
  - The guard spared any process running the sshd binary, which any
    user can run. It now spares the SSH service: sshd as root in an SSH
    unit.
- External audit, Wave 0, LLMR-002 (Critical): any user could blind the
  agent by running unknown binaries in a loop. Each one sent to ADE held
  the event loop for up to the inference timeout, and the kernel dropped
  events meanwhile; a timed-out generation also kept running for up to
  two minutes. ADE now evaluates on its own task, one exec at a time
  (the others are judged by the rules only and counted), and a timeout
  stops the generation.
- External audit, Wave 0, POS-001 (Critical): any local user could put
  the host in a locked COMBAT — network isolation, with no way out but a
  signed release — with two cheap heuristics, such as twenty HTTPS
  connections and then three internal SSH connections. Signals now
  corroborate only across kinds of evidence (network, execution, file
  system, kernel). A COMBAT reached on heuristics alone contains threats
  at the process level, never isolates, and decays after 30 quiet
  minutes. Isolation needs a locked COMBAT: a kernel-adjudicated denial,
  root changing a system file outside an administrator's session, or an
  administrator's order.
- External audit, Wave 0, LLM (Critical LLMP-002, High LLMP-001,
  LLMR-001, LLMR-006):
  - The correlated events reached the model raw, inside the prompt's
    trusted block, and a line break in a file name could forge a prompt
    section. They are now sanitized and untrusted, and every untrusted
    string is printed as a JSON string.
  - Model output with a multi-byte character at byte 4096 crashed the
    agent when an escalation kept it.
  - A low-confidence `KillTree` ran because the verifier answered
    "inconclusive". Below its floor every destructive action is refused,
    and an inconclusive check escalates.
- External audit, Wave 0, PROC-001 (Critical): a fileless (memfd)
  exec escaped R004 when its parent named itself `systemd` and its
  `argv[0]` ended in `/systemd-executor`. With the exec sensor's
  identity R004 now judges what the kernel executed: a memfd, or an
  unlinked file reached through an fd. systemd's launch of every unit (a
  real file) is no longer something to exempt. Without the identity,
  the exemption needs `argv[0]` exactly and a systemd parent by
  identity, never by name.
- External audit, Wave 0, network (Critical NET-001 and NET-010, High
  EBPF-007, NET-002, NET-005, NET-011):
  - A dual-stack IPv6 socket reaching an IPv4 address (`::ffff:a.b.c.d`)
    slipped past the IP blocklist and the posture's internal and loopback
    checks. Addresses are now canonical wherever they are decoded.
  - A process could silence the network rules by naming itself like an
    allowlisted program (`prctl(PR_SET_NAME)`). The allowlist is now
    judged on what the kernel executed; when that cannot be read, the
    verdict is recorded instead of acted on.
  - UDP sent from port 53 to anything but a local client was dropped by
    the kernel sensor. It is now reported, aggregated per client address
    for a DNS server.
  - One malformed line emptied a whole blocklist at load; now only that
    line is dropped.
  - A DNS query issued after a connect hid the hostname the connect was
    attributed to.
  - The shipped blocklist held CGNAT (`100.64.0.0/10`) and benchmarking
    (`198.18.0.0/15`) space, which Tailscale, EKS and VPN clients use,
    on a rule that kills the process tree.
- A file capability granted by any route other than the `setcap` program
  (a direct `setxattr`, `cp --preserve=xattr`, `tar --xattrs`) drew no
  verdict (review 86, High). In the lab a user read `/etc/shadow`
  through a copy of `cat` given `cap_dac_read_search`. The agent now
  watches `security.capability` on every file (LSM
  `inode_post_setxattr`). The new rule NN-L-FIM-025 strips the capability
  again, Critical for a root-equivalent one. Package-manager installs and
  interactive admin sessions keep theirs. The unit's capability bounding
  set gains `CAP_SETFCAP` for the strip.
- The COMBAT ladder's NEUTRALIZE never quarantined the offender's binary
  (review 87, High). It looked the binary up after the kill, when it was
  already gone, and under the unit's read-only sandbox the unlink failed
  while the outcome still claimed success. NEUTRALIZE now reads the
  binary before the kill. File-changing responses reach the host's view
  of the file through `/proc/1/root`, and a quarantine that leaves the
  binary in place is reported as failed.
- An account tool was killed after it wrote `/etc/passwd`, `/etc/shadow`
  or `/var/log/lastlog` (review 83). On AlmaLinux 9 `useradd` was killed
  for resetting the new uid's `lastlog` entry and created no account. On
  Ubuntu `useradd` run without a terminal left an account with no group
  and no home. A user changing their own password with `passwd` was
  killed the same way. Writes by the account tools (shadow-utils,
  libuser, `systemd-sysusers`), told by what the kernel executed, are now
  recorded: at Low for a user's own change, else at the rule's severity.
- A process could read cloud, browser, password-manager and GPG
  credentials, or write `wtmp`, `btmp` and `lastlog`, with no detection
  by giving itself a legitimate client's name (review 85, High):
  `prctl(PR_SET_NAME, "aws")` was enough. The rules now recognise a
  client by what the kernel executed: its exe, or the script an
  interpreter runs, inside a root-owned system tree. They also recognise
  gcloud, the Azure CLI and AWS CLI v1, which run as `python3`. A client
  reading another user's credentials is no longer exempted.
- An administrator's `sudo` edit of a watched configuration, cron, unit or
  timer file killed the command or the editor (review 52). `sudo useradd`
  was killed after writing `/etc/passwd` and left an account with no group
  or home. Two such edits in one session also put the host in COMBAT,
  whose ladder then killed the writer. Writes from an interactive sudo/su
  session (login uid and terminal) to these files are now recorded at the
  rule's severity. They raise the posture without corroborating each
  other. Services, jobs, commands run without a terminal and root
  processes with no sudo/su above them keep the kill.
- Root could boot a kernel without the agent through kexec (review 82,
  High): on AlmaLinux 9, `kexec -l` succeeded with the agent running. The
  agent now refuses every kexec image load outside the trusted-installer
  window and records it as an anti-tamper denial; its unit starts after
  `kdump.service`, so kdump keeps loading its crash kernel at boot.
- Sealed chain-log archives and their manifests could be altered by root
  after an agent restart (review 81, High): only the active files were
  protected again at start, and the manifest never was. The agent now
  protects every retained archive and manifest at start and the manifest
  at each rotation.
- An evicted log archive left its inode protected until the next agent
  start (review 80): when the filesystem reused the number for an
  unrelated file, that file could not be written or removed and each try
  was an anti-tamper detection. The agent now releases an archive's inode
  before evicting it.
- The TCP close sensor sent a record for every passive socket (listeners,
  accepted peers) that the agent then dropped, so inbound connections
  could fill the ring the outbound flow closes need; and a close lost to a
  full ring left a stale entry that misattributed a later socket's close
  (review 79, part). Only sockets the connect sensor recorded are reported
  now. Still open: a loop of outbound connects can still overflow the flow
  rings (design pending).
- Detections held back by the per-rule budget (review 75) were reported
  only as a count, so a flood of one rule could hide which file another
  detection of that rule was about. The held report (journal and signed
  audit entry) now names up to eight distinct subjects per rule and uid.
- An unprivileged loop of DNS queries could hide a DNS tunnel (review 78,
  High). The DNS sensor recorded every datagram into one ring: a loop of
  benign queries lost half of the records and took more than a CPU of the
  agent, and a tunnelling-shaped query in the middle evaded NN-L-NET-004
  one time in three. The kernel now gives each process and each user a DNS
  budget; queries over it are not recorded but counted on the process's
  next record, and the new NN-L-NET-020 reports the process that floods.
  The local resolvers are exempt.
- A file detection did not say which file it was about (review 77). The
  record of a cron drop-in named the writer but not the drop-in; records
  carried a path only for exec detections. Detection records now have a
  `file` field for the file sensors (FIM drift, file open, mass write,
  module load).
- Root could switch off the FIM kill rules for a minute at a time (review
  76, High). The drift events handed to the rules were paced by host-wide
  buckets (50 created and 100 modified files per minute, whoever wrote
  them). After 60 throwaway files in `/etc/cron.d`, a real cron drop-in
  was only logged: NN-L-FIM-007 never ran and its writer was not killed.
  The buckets now pace only package-manager writes, the upgrade noise they
  were meant for; every other write reaches the rules.
- An unprivileged loop of reads disabled the FIM kill rules and erased
  detection records (review 75, High). Every open of the user's own
  credential file, or of a world-readable sensitive file such as
  `/etc/passwd`, sent a record to a kernel ring and a verdict to the journal
  and the detection store. Two `open()` loops lost 94 % of the open-sensor
  ring and kept the agent's event channel full; the FIM drain then dropped
  the drift events it could not queue, so a root process writing a cron
  drop-in was not killed. journald suppressed 400k agent lines, and the
  store's queue evicted the records of real kills. Now the kernel drops a
  task's repeated reads of a file within one second, the FIM drain waits
  for room instead of dropping, detections are logged and stored within a
  per-rule, per-uid budget (every verdict is still acted on; the rest are
  counted and reported), and a full queue evicts logged-only records first.
- NN-L-NET-009 (more than 100 MiB sent) never fired for UDP (review 74,
  High). The flow tracker emits one UDP row per kernel record, at most
  about 1 MiB, so no row reached the threshold: 150 MB sent over UDP in
  0.6 s went unflagged. NET-009 now sums the UDP rows of a (process,
  destination) over 10 minutes.
- An unprivileged UDP burst could erase every network flow record (review
  73, High). A connected UDP socket emitted one record per `send()` into the
  ring the TCP closes share. One process sending 146k datagrams/s lost 1.45
  million records in 10 s, TCP flows included. UDP sends are now aggregated
  in the kernel per destination: one record per second, or per MiB, carrying
  the bytes sent. UDP records also have their own ring.
- An unprivileged shell loop could blind the exec rules (review 72, High).
  For every event, the agent cloned its ring of up to 1,000 recent events to
  hand the posture triggers a slice. Under an exec burst (four `cat` loops,
  about 2,000 execs/s) that was a full CPU on Ubuntu 24.04. On Ubuntu 22.04
  and Debian 12 the exec rings overflowed, so the execs in the burst,
  including a hidden payload, reached no rule. The triggers now read the
  ring in place: the agent's CPU per exec drops from about 520 µs to 80 µs.
- A credential theft could be reported only as a `/tmp` C2 connection
  (review 70). CHAIN-007 (`/tmp` exec → credential read → egress) and
  CHAIN-001 checked their precursors only when the egress arrived. A
  credential read processed after the connect it preceded (it comes
  through another ring) left both silent: CHAIN-002 killed the tree but
  did not name the theft (lab, Ubuntu 22.04). A late read now completes
  the chain with the egress it preceded.
- The agent wrote every exec and every network flow to the journal at INFO
  (review 71). On a busy host journald then rate-limited the agent, which
  lost other lines too, and every command line on the host (with any
  secret in its arguments) was copied into the journal. Both lines are now
  DEBUG; the records stay in the detection store and the signed netflow
  log.
- An agent start could lose events in its first seconds (review 69). Until
  the LSM file-open sensor took over, the `sys_enter_openat` tracepoint sent
  every open of the host to the agent's event channel, which nothing reads
  before the boot sequence ends. The channel filled, every sensor waited
  behind it, and the file-open ring overflowed: up to 1,018 records lost on
  the lab. The tracepoint now stays inert in the default mode until it is
  needed (`--file-open-sensor tracepoint`, or as the fallback).
- UDP datagrams to IPv6 destinations left no flow row (review 68, High).
  The N2 UDP program was attached to `udp_sendmsg` only, so a QUIC-like
  beacon or raw-UDP exfiltration over IPv6 was invisible to the flow
  rules. It is now attached to `udpv6_sendmsg` too. An IPv4-mapped
  destination still gives one row, not two.
- DNS tunnelling could escape NET-004/-005/-014 (reviews 66, 67, High).
  The DNS sensor read the query name from user memory before the kernel
  copied it, and saw IPv4 only. On the lab, a tunnelling-shaped name ran
  untouched when it was sent in any of these ways:
  - to an IPv6 resolver (`[::1]:53`);
  - from a page the process had not touched yet (the name read as empty);
  - with a zero byte inside its first label (the name was cut there).
  The sensor now reads the kernel's copy, IPv4 and IPv6, and all three are
  killed. A query whose name does not end in the copy's linear data (sent
  in pieces, with UDP GSO or zero copy) is recorded by NET-004 (Log).
- The exec kill rules could be evaded with a relative path (review 61,
  High). They matched the string the caller passed to `execve`, so
  `cd /tmp && ./payload` ran with no detection while `/tmp/payload` was
  killed (lab, Debian 12). A symlink, `..` or `execveat` with a directory
  fd did the same, and a memfd behind a symlink escaped R004. R001, R002,
  R003, R008, R009, R010, R013's and R017's exemptions, CHAIN-002, the
  posture's `/tmp` arm, process canaries and the auth-lineage tracker now
  read the file the kernel executed, and R004 also fires on the kernel's
  memfd flag.
- Review 64's fix had no effect (review 65, High). `cargo xtask build`
  dropped every `CARGO_*` variable before building, including the release
  job's `x86-64-v2` override. A release built on a runner with AVX-512 still
  died with SIGILL on CPUs without it (seen on PR #223's tarball). xtask now
  passes per-target settings on to the nested build. The release job also
  starts the binaries on an emulated `x86-64-v2` CPU
  (`qemu-x86_64 -cpu Nehalem`).
- Release binaries could die with SIGILL at start (review 64, High). The
  workspace builds with `target-cpu=native`, and the release workflow did
  not override it, so a release built on a GitHub runner with AVX-512 used
  AVX-512 and did not run on CPUs without it (the lab's guests, many
  servers). Releases now target `x86-64-v2`.
- The agent stopped starting after about 41 restarts in one uptime
  (review 63, High). Every boot added the inodes it protects to the
  pinned `PROTECTED_INODES` map (23 per restart on the lab, mostly the
  re-created bpffs pins) and never removed the earlier boots' keys; at
  1024 entries an insert failed and the agent refused to start with a
  missing protection. The boot now removes every key it did not register
  itself, after registering its own, and `tamper-check` checks that one
  more restart does not grow the map.
- After an agent restart, kill -9 and ptrace attempts on the agent were
  still refused but left no evidence (review 62). The two hooks emit on the
  anti-tamper ring, yet reused the previous boot's pinned program, bound to
  a ring no one read any more. They are now reattached fresh every boot,
  like the file-protection hooks, and `tamper-check` repeats the kill and
  ptrace cases after its restarts.
- `nn-lab.sh tamper-check` left its overlays in `/etc/northnarrow`, and
  C24's was signed, so its `+backupd` exemption stayed in force on the
  lab guest. The e2e fixtures' agents then logged it as an unauthorised
  overlay, and `audit_verify_e2e` failed on its entry count (Ubuntu
  22.04). The check now purges the pins, removes the overlays and
  restarts the units.
- `nn-lab.sh sync` could leave the lab guest building stale code. rsync
  kept the host's file times, so sources synced from another checkout or
  worktree could be older than the guest's last build. cargo then kept
  the old crate: the build failed, or linked the previous code. Files are
  now compared by content, and a changed file takes the guest's clock.
- Every file operation on the host went through a global kernel lock
  (review 56). 45 `bpf_printk` diagnostic markers from a 2026-05
  investigation were still in the anti-tamper LSM programs: one per
  `file_open`, up to five per write-open, and more on every unlink,
  rename, setattr and ioctl. `bpf_trace_printk` serialises on one spinlock
  and writes the trace buffer, and its "trace_printk() … unsafe for
  production" banner appeared on every agent host. All are removed.
  Overhead benchmark on Ubuntu 24.04, 3 rounds: open throughput loss
  falls from 38.5 % to 31.9 %, write-open from 48.8 % to 25.6 %.
- FIM killed unrelated processes after a watched file was deleted
  (review 57). A file dropped in a watched directory is watched by its
  inode, and deleting the file left the inode number watched, even across
  agent restarts. ext4 hands that number to the next new file, so a
  compiler's temporary file in `/tmp` was killed as a "cron drop-in". A
  deleted file's inode is now forgotten, and stale keys are cleared at
  boot. The enrollment of dropped files itself often failed (review 58):
  it ran before the file existed at its final path. It is now retried
  for two seconds. `nn-lab.sh fim-reuse-check` covers both.
- On btrfs, FIM and the anti-tamper file protection saw nothing (review
  55). Userland keys watched and protected files by `(dev, ino)` from
  `stat()`, which on btrfs reports the subvolume's device. The eBPF hooks
  looked them up with the superblock's device, so no key ever matched.
  FIM missed every file on btrfs, the deny hooks protected none of them,
  the BPF guard's exemption for the agent's own executables never applied,
  and nothing warned. The eBPF side now reports the device as `stat()` does
  (`BTRFS_I(inode)->root->anon_dev` for btrfs inodes). The offsets come
  from the btrfs module's BTF, which the resolver now reads as split BTF
  on top of vmlinux. `nn-lab.sh btrfs-check` reads a watched credential
  file on the root filesystem and on a btrfs subvolume; NN-L-FIM-011 must
  fire both times. Before the fix it fired only for the root filesystem.
- Without the kernel BTF (`/sys/kernel/btf/vmlinux`) the anti-tamper
  attach only logged a WARN and skipped every LSM hook, outside the
  fail-closed check that refuses to start on a missing deny hook. Only the
  network sensor's own BTF load kept such an agent from running. The
  no-BTF case now takes the same fail-closed path
  (`NN_ANTI_TAMPER_ALLOW_DEGRADED=1` is the only way to start degraded),
  and a mount that hides `/sys/kernel/btf` while the agent runs is
  reported as `integrity_drift` (review 53).
- A copy of the agent's unit in an earlier directory of systemd's load
  path replaced the installed unit at the next `daemon-reload` without any
  evidence. The tmpfs `/run/systemd/transient` and `system.control`
  outrank even `/etc/systemd/system`, and both are outside the FIM watch.
  The integrity check now reports every second copy of the units as an
  `integrity_drift` entry of kind `unit_shadowed`, `systemctl mask`
  included.
- The FIM rules killed the package manager. dpkg was killed while it
  installed or removed any package that ships a systemd unit or timer, a
  cron drop-in, a PAM module or a setuid binary, which left packages
  half-installed (`apt-get install --reinstall rsync` failed). Writes made
  by dpkg, rpm, dnf/yum, microdnf or PackageKit, or by the maintainer
  scripts they run, are now recorded as Low log-only detections instead of
  killed. The package manager is recognised by the kernel-resolved
  executable of the writer's lineage, never by process name.
- NN-L-CHAIN-008 (sudo/su, then network) killed legitimate admin work: any
  network flow of a descendant of `sudo` or `su` within 5 minutes drew a
  Critical `KillProcessTree`, `sudo apt-get update` and loopback traffic
  included. The rule is now informational (Medium, log only), ignores
  loopback destinations and is evaluated after every other rule, so it
  never hides a blocking verdict on the same flow.
- NN-L-FIM-019 killed systemd's getty start-up child, which writes the
  login record under the name `(agetty)`: after a reboot both console
  gettys hit their start limit and the host had no console login. The
  login-record rules (FIM-018/019) now accept systemd's pre-exec name and
  the `systemd-update-utmp` and `sshd-session` writers.
- The mass-write posture trigger logged its WARN on every event while a
  steady writer kept the threshold crossed (one line per second for 24 h
  on the first soak); the line is now emitted once per pid per window.
  Detection and posture behaviour are unchanged.
- Memory leak in the DNS attribution cache: the per-pid map was never
  pruned of dead pids, so every short-lived process that resolved a name
  grew the agent by a few hundred bytes for the life of the process
  (~1 MB/h on the first 24 h soak). Stale pids are pruned by TTL and the
  map is capped at 4096 distinct pids.
- Lab soak sampler counts WARN/ERROR lines by text in the `northnarrow`
  journal namespace (tracing output has journald priority 6, so the
  priority filter counted nothing); `soak start` passes `SOAK_*_PER_S`
  rates through to the generator.
- RHEL 9 family (AlmaLinux 9 / 5.14 el9): the vendor tracepoint header
  shifts `sched_process_exec.filename` by 4 bytes; the exec sensor read an
  empty filename on every exec and R017 killed every shell. Tracepoint
  field offsets are now resolved from tracefs at boot (4 new `BTF_OFFSETS`
  slots), and the "non-standard path" rules (R017, R013) never fire on an
  empty filename.
- Short-lived TCP flows (connect and close within the pipeline latency:
  loopback probes, scanners, reverse-shell attempts) produced no netflow
  row and could silence CHAIN-007; the close now synthesises the row when
  it overtakes its connect.
- Debian-family hosts: the hardened agent unit could not attach its
  tracepoint/kprobe sensors (`perf_event_open` EACCES: Debian's
  `perf_event_paranoid=3` patch demands `CAP_SYS_ADMIN`); `install.sh`
  adds a drop-in with that capability on those hosts only, and the attach
  error explains the condition.
- Kernel 5.15 (Ubuntu 22.04): the eBPF object was rejected by the older
  verifier (`memset` subprogram call on ring-buffer entries; variable-length
  read into uninitialised stack; `Option` payload read before its
  discriminant in the FIM rename hook). Entries are zeroed inline, such
  reads land in the ring-buffer entry, the rename destination is a plain
  key; the agent now loads on 5.15 with every program and all 8 FIM hooks
  attached (DNS QNAME via `ITER_IOVEC` only — degraded, not refused).
- e2e fixtures (agent and watchdog): teardown signalled only the `sudo`
  pid and relied on the relay; sudo 1.9.9 does not relay from its own
  process group, so suites hung on 22.04. The whole subtree is now
  signalled, with a bounded wait. The map-pin test accepts the 15-byte
  kernel program name printed by older bpftool.

- FIM e2e suite: the credential-read test asserted a drift row that
  BUG-012 v2 deliberately never writes; it now asserts the
  `NN-L-FIM-011_AwsCredsRead` detection record and the empty drift log.
  The lab's `test-e2e` step runs the FIM suite (it ran nowhere before).

### Added
- Lab without `/dev/kvm` (`deploy/lab/nn-lab.sh`, `NN_LAB_ACCEL=whpx|tcg`):
  WSL exposes no nested virtualization on AMD hosts since Windows
  KB5127648 (microsoft/WSL#41918). `whpx` runs the guests in QEMU for
  Windows on the Windows hypervisor, next to WSL, at full speed — disks in
  `C:\nn-lab\<distro>`, ssh forwarded on the WSL-facing address only and
  mapped to `127.0.0.1:<port>` by a socat user unit, so every sub-command and
  probe works unchanged; a guest reboot (WHPX hangs on a reset) ends QEMU
  and `up` starts it again. `tcg` is software emulation in WSL.
- DNS sensor on the socket buffer (Tappa 10.9 step 3). Kprobes on
  `udp_send_skb` and `udp_v6_send_skb` read the query from the buffer the
  kernel sends: the destination from the flow, and the name from the
  kernel's copy of the payload. Userland walks the labels, so a zero byte
  inside a label no longer cuts the name. `udp_sendmsg` is no longer
  attached for DNS; `--dns-sensor sendmsg` (or `NN_DNS_SENSOR`) keeps it
  for one soak cycle. `DnsQuery` gains `qname_partial`. Eight optional BTF
  slots (`sk_buff.{head,tail,transport_header,data_len}`,
  `flowi4.{daddr,uli}`, `flowi6.{daddr,uli}`). `nn-lab.sh
  dns-sensor-check` verifies it end to end.
- Exec sensor on LSM `bprm_check_security` (Tappa 10.9 step 2). For each
  binfmt pass (a `#!` script: the script, then its interpreter) it reads
  the file the kernel opened. It records `(dev, ino)`, whether the file is
  on a memory-backed filesystem, is a memfd or is unlinked, and its path
  rebuilt from the dentry up to the exec'ing task's root (containers and
  chroots keep their own view). The path walk is a global BPF function,
  verified on its own. The first pass's identity is handed to the
  post-exec `ProcessSpawn`, and `ExecCheck` now carries kernel data (and
  a real `ppid`). `sys_enter_execve` is no longer attached;
  `--exec-sensor tracepoint` (or `NN_EXEC_SENSOR`) keeps it for one soak
  cycle. The exec ring grows to 1 MiB for the larger records.
  `nn-lab.sh exec-sensor-check` verifies it end to end.
- File-open sensor on LSM `file_open` (Tappa 10.9 step 1). The FIM
  `file_open` observer now also classifies every open in the kernel, and
  only the opens a rule reads reach userland:
  - sensitive files, and writes to critical or persistence files and trees;
  - the telemetry probe directory;
  - credential stores found by name in every home (review 54);
  - one `Event::MassWrite` per process crossing 20 write-opens in 60 s,
    instead of every open.

  `sys_enter_openat` is detached once the sensor is armed, so the path is
  the one the kernel opened (no time-of-check gap) and opens through
  `io_uring` are seen. A relative path, a directory fd or a symlink no
  longer slips past the posture's file triggers (review 60, High). Directory classes are cached; a directory rename
  invalidates the cache and `rmdir` drops the removed directory's entry.
  Paths are rebuilt from the mount table.
  `--file-open-sensor tracepoint` (or `NN_FILE_OPEN_SENSOR`) keeps the old
  sensor for one soak cycle. Credential-store opens in homes outside the
  watch list are reported; the reader is killed only when it is a non-root
  user other than the file's owner and holds no DAC capability on the host
  (design Q8): the owner's own tools and root's backups are not.
  The posture's path lists are prefixes and the kernel classifies by
  directory, so `/etc/ssh/sshd_config.d/` is now listed: the
  `/etc/ssh/sshd_config` prefix used to cover sshd's drop-ins.
  Mass-write carve-outs are directory trees, with or without the final
  `/`. If the verifier refuses the sensor, FIM keeps its plain observer
  and the agent stays on `sys_enter_openat`.
  `nn-lab.sh open-sensor-check` verifies it end to end on Ubuntu 24.04
  (6.8), Ubuntu 22.04 (5.15) and Debian 12 (6.1). On the 6.8 lab guest
  the open benchmark loses 28.2 % instead of 31.9 %, and the agent's own
  CPU per open drops from 6.4 µs to almost nothing (design §10.6, Q7).
- `nn-lab.sh sensor-feasibility [BASE]`, step 0 of the Tappa 10.9 sensor
  attach points. A lab build of the agent (`--sensor-feasibility`, feature
  `test-privileged`) loads throw-away probes on the attach points the
  design proposes and exercises them from its own process. The probes are
  LSM `file_open` with the parent-directory, name and ancestor tables and
  the in-kernel write counter; LSM `bprm_check_security`; and the DNS
  payload read from the socket buffer by a `kretprobe` on
  `ip_make_skb`/`ip6_make_skb` and a `kprobe` on `udp_send_skb`. All 18
  properties hold on 6.8, 6.1 and 5.15. Among them: every record names the
  inode the open returned while another thread swaps the name, and an
  `execveat` of a memfd is seen. The run on btrfs found review 55. The
  probes ship in the shared eBPF object but the agent never loads them;
  their maps take about 70 KiB until step 1 replaces them. With
  `NN_FEASIBILITY_BENCH=<opens>` it also measures the cost per open. On
  6.8, an empty LSM program adds 147 ns, today's FIM observer 427 ns, and
  the full observer 1 587 ns (−34 %). The full checks cannot therefore run
  on every open: step 1 caches the classification per directory.
- Kani proof of the admin multi-signature rule. `verify_quorum` and
  `verify_signed_payload_quorum` now share `quorum_decision`, the tally of
  distinct keys, threshold and role check separated from the signature
  checks, and Kani proves it accepts only when enough distinct keys matched
  and every required role is carried by one of them (weekly job). A
  threshold of 0 was refused only by a `debug_assert`; the rule now uses
  `max(threshold, 1)` in every build.
- `nn-lab.sh release-check DIR`: the release tarball CI built and attested
  (`gh run download`), installed and verified on a guest. It checks
  SHA256SUMS, that the binaries run on the guest's glibc, `install.sh`'s
  tree and tarball verification (provenance `checksums`), the boot-time
  binary integrity check, every deny hook, the telemetry probe and one
  detection. It passes on Ubuntu 24.04, Ubuntu 22.04 and Debian 12.
- Fuzz targets `combat_allow` and `canary_template`: the COMBAT management
  carve-out (allow-file text, generated ACCEPT lines, splice into the
  operator ruleset) and the operator canary templates. Besides "never
  panics", `combat_allow` asserts that no allow-file content can inject an
  `iptables-restore` line other than an ACCEPT for one validated address.
- `tamper-check` with kernel lockdown: kexec (C17) is a required refusal
  when lockdown is active instead of a known gap, and C27 loads a module
  whose signature was stripped through a bare `finit_module`. Verified on
  Ubuntu 22.04 with `lockdown=integrity`: the agent runs unchanged, both
  are refused by the kernel, and R018 still records the module attempt.
  `nn-admin host-check` reports module signing as enforced when lockdown
  is in integrity or confidentiality mode, which refuses unsigned modules
  whatever `module.sig_enforce` says.
- Distribution packages: `northnarrow_<ver>-<rel>_amd64.deb` and
  `northnarrow-<ver>-<rel>.x86_64.rpm`, built by
  `deploy/release/mk-packages.sh` with dpkg-deb and rpmbuild only, and
  published, checksummed and attested with the tarball. Their scripts run
  `install.sh` / `uninstall.sh` in new package modes (`--package-stop`,
  `--package-configure`, `--package`). Installing over an `install.sh`
  install migrates it; upgrade and removal go through the
  trusted-installer window (`NN_GRANT_KEY`) and stop cleanly without it;
  the first install starts nothing. Lab: `nn-lab.sh pkg-check`.
- Package install layout: `install.sh` and `uninstall.sh` accept
  `BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system` and rewrite the units
  for `BIN_DIR`. The agent protects the binaries and units of both layouts
  and finds the watchdog next to its own executable, so `--watchdog-exe`
  is now optional. Prerequisite for `.deb`/`.rpm` packages (review 26).
- Overhead benchmark (`nn-lab.sh overhead [ROUNDS]`): the agent off and on,
  alternated, over four worst-case micro-workloads (open, open + write,
  exec, loopback connect); the report gives the median throughput lost and
  the agent's own CPU per workload. Runbook section "Overhead (agent off
  vs on)".
- Host hardening checks (`nn-admin host-check [--json]`, summary in
  `nn-admin status`, one WARN per gap at agent boot, table at the end of
  `install.sh`): BPF LSM, kernel lockdown, unprivileged BPF, module
  signature enforcement, Secure Boot, IMA, kexec, single bpffs mount —
  the host settings that keep root from rewriting the kernel at runtime,
  which is the only way around the anti-tamper.
- Kani model checking (`.github/workflows/kani.yml`, weekly): the TLS
  ClientHello `Cursor` and the DNS name walk (`QnameLabels`, split out of
  `decode_dns_qname` without behaviour change) are proved in bounds for
  every input of a bounded size. The first proof found the cursor's bound
  check `pos + n > len` wrapping for a huge `n` in release builds; it is
  now saturating.
- Signed operator overlays: the agent loads a `*.local` overlay
  (allowlists, blocklists, FIM paths, posture carve-outs) only if
  `<overlay>.sig` proves that a key with the new `config-manage` role signed
  its exact content, for this `agent_id`, and not earlier than the last
  accepted signature (rollback guard from the audit chain); otherwise it
  boots on the shipped defaults for that list and records an
  `unauthorized_overlay` integrity finding. `nn-admin config overlay
  set|sign|status`; `install.sh` bootstraps the key with `config-manage`
  and `--upgrade` adopts existing overlays with `--grant-key`; the posture
  overlays and the `.sig` files join the protected set; escape hatch
  `NN_OVERLAY_ALLOW_UNSIGNED=1` (reported). Closes the gap found by
  tamper-check C19.
- Adversarial anti-tamper check, second part: `cgroup.kill` on the agent's
  unit (C20), an exec flood hiding an exec from `/tmp` (C21) and an
  io_uring probe that opens, reads and connects through a ring with no
  openat/connect syscall (C22, `deploy/lab/adversarial/iouring-probe.c`, raw
  syscalls) — 23 cases, all with signed evidence on 6.8 and 5.15. Kills that
  nothing can refuse are now evidence: every run writes `agent_stop` with the
  reason it left its event loop, and every `agent_boot` says how the previous
  run ended (`previous_run`: none / clean / abrupt; review 46). The four
  remaining append-by-path logs (FIM baseline, canary registry and access
  log, listener log) also write through a directory fd (review 44).
- Adversarial anti-tamper check (`nn-lab.sh tamper-check`,
  `deploy/lab/adversarial/anti-tamper.sh`): 20 cases (signals, ptrace,
  protected files and pins, BPF maps/links/programs, unit drop-ins,
  `set-property`, bpffs and bind mounts, cgroup freeze, module load,
  `oom_score_adj`, config overlays), each with expected outcome and the
  evidence it must leave in the signed chain logs. Found and fixed:
  `OWN_BPF_IDS` collisions between map/program/link ids (review 40),
  silent signal/ptrace denials — now `op=signal`/`op=ptrace` records and
  detection NN-L-AT-001 for every anti-tamper denial (41), silent
  systemd/kernel tampering — now a self-integrity check every 30 s ±20 %
  with `integrity_drift` audit entries, `OOMScoreAdjust` in both units
  (42), the telemetry probe tripping NN-L-NET-004 (43), and the signed
  logs being divertible by a bind mount over their directory — every log now
  writes through a directory fd taken when it is opened (44). Ring-buffer
  losses are signed audit entries (`ringbuf_drop`); the telemetry probe
  and the link self-check run with ±20 % jitter.
- Telemetry probe: every 60 s the agent runs a child of its own binary
  (`--telemetry-probe <nonce>`, hidden) that produces one known event per
  probed sensor — exec, file open of `/run/northnarrow/probe/<nonce>`, DNS
  query for `<nonce>.probe.northnarrow.invalid` to 127.0.0.1:53 — and
  checks each reaches the pipeline within 5 s; a silent sensor is an
  `ERROR TELEMETRY GAP` and a signed audit entry (`telemetry_gap`, then
  `telemetry_restored`), coverage as a product function.
  `NN_TELEMETRY_PROBE_SECS=0` disables it.
- BPF self-defence, second half: the `bpf` LSM hook now DENIES (enforce
  mode) a handle to one of the agent's own links to a foreign process, by id
  (`LINK_GET_FD_BY_ID`) and through the pin (`OBJ_GET` whose final path
  component is one of our `link_*` pins) — the two routes to `bpftool link
  detach`; denial `operation=bpf_link` in the audit chain and the posture
  ladder. Own ids are kept with their kind (map / program / link live in
  separate kernel id spaces; before, a foreign map with the id of one of our
  programs would have been write-denied). Link self-check every 10 s: a
  registered link missing — checked through the agent's own fds and pins,
  no `CAP_SYS_ADMIN` — is an ERROR and a signed audit entry
  (`bpf_link_missing`), in every mode. Review entry 39 (High): the pin root
  `/sys/fs/bpf/northnarrow` and every pin are now in the protected-inode
  set, so `systemctl stop` + `rm -rf` of the pins no longer drops the
  hooks; the trusted-installer window is the authorised purge —
  `install.sh --upgrade --grant-key <key>` / `uninstall.sh --grant-key
  <key>` open it, the bootstrapped admin key carries the role
  (`unlock,audit-read,trusted-installer`), and the lab migrates guests
  installed with an older key once (units disabled across a VM restart).
- BPF self-defence, first half: LSM hook `bpf_map` denies any write handle
  on the agent's own maps (ids registered after load) to processes that
  are not the agent or the watchdog — `bpftool map update/delete` against
  `PROTECTED_PIDS` now fails with EPERM and lands in the audit chain as an
  anti-tamper denial (`bpf_map`); read-only handles stay allowed, but
  `bpftool` always asks for RDWR, so in enforce mode `map show/dump` on the
  agent's maps fail too (read the state with `nn-admin status`). LSM hook
  `bpf`
  observes program loads, attaches, link create/update/detach, BTF loads
  and handles-by-id on the agent's maps/links by foreign processes
  (`Event::BpfSyscall`, one record per pid per command per second); rules
  `NN-L-BPF-001_BpfProgramLoaded` (Medium, Log; known tooling exempt) and
  `NN-L-BPF-002_BpfForeignHandleOrDetach` (High, Log). Observe mode (no
  deny) in `debug-trigger` builds and with `NN_BPF_DEFENSE_OBSERVE=1`; the
  guard counts as a ninth deny hook in the fail-closed LSM health. Seven new
  BTF offset slots (`bpf_map`, `bpf_prog`, `bpf_prog_aux`, `mm_struct.exe_file`
  for the exe-inode exemption that lets a restarting watchdog register itself).
- io_uring sensor — the asynchronous I/O channel syscall-centric sensors
  miss: tracepoints `io_uring_create` and `io_uring_submit_{req,sqe}`
  (name resolved per kernel), submissions aggregated per pid in kernel by
  opcode class (file open, file read/write, network connect, network
  send/recv, filesystem mutation) and emitted on a new class or once per
  second; `Event::IoUring`; rules `NN-L-IOU-001_IoUringRingCreated` (Low,
  Log: baseline of ring creators outside the allowlist) and
  `NN-L-IOU-002_IoUringFileAndNetwork` (High, Log: file and network I/O
  through rings from the same unlisted process — the RingReaper shape).
  Known io_uring servers (qemu, nginx, postgres, mariadb, mysql, redis,
  node, fio, systemd-journal) and the process comm allowlist are exempt.
  Five new `BTF_OFFSETS` tracepoint slots; a kernel without
  `CONFIG_IO_URING` degrades with a WARN.
- Ring-buffer drop accounting: every eBPF producer bumps a per-ring
  counter (`RING_DROPS` per-CPU map, 11 rings) when its reservation
  fails; the agent samples it every 10 s, logs each increase at WARN with
  the ring's name, and `nn-admin status` shows the total and the per-ring
  breakdown (`ringbuf_drops_total`, `ringbuf_drops` in `--json`). Before,
  only the exec ring counted and nothing read it.
- Fuzzing (`fuzz/`, cargo-fuzz): eight libFuzzer targets over every
  parser that consumes attacker-shaped bytes — admin socket frames, TLS
  ClientHello and DNS payloads from the kernel rings, the BTF blob,
  tracefs `format` files, role lists, chain-log lines, the install
  manifest. The `fuzz` CI job builds every target and runs each for a
  short smoke on every PR; a crash artefact fails the job.
- Supply chain, install-time and runtime halves: `install.sh` verifies the
  extracted tree (`MANIFEST.sha256`, now shipped in the tarball), the
  tarball against `SHA256SUMS` and the SLSA provenance attestation (gh or
  cosign, bound to this repository's release workflow;
  `--require-attestation`, `--no-verify`), and records the level reached
  plus the hashes of every installed binary and of the eBPF object in
  `/etc/northnarrow/install-manifest.json`. The agent re-verifies those
  hashes at every boot and refuses to start on a mismatch
  (`NN_ALLOW_UNVERIFIED_BINARY=1` to override); the `agent_boot` audit
  entry carries `binary_integrity` and `install_provenance`.
- Lab: fourth guest AlmaLinux 9 (`NN_LAB_DISTRO=alma9`, kernel 5.14 el9,
  SELinux enforcing, port 2622) — verified end to end; the compatibility
  matrix records it.
- `BTF matrix` workflow + `deploy/btf-matrix/run.sh`: computed
  kernel-compatibility matrix over the BTFHub archive (newest non-cloud
  kernel per distro/version, `--btf-check` verdicts, BPF LSM floor),
  compared with a baseline (`expected.tsv`); on PRs touching the offset
  tables, weekly, and on demand. Verdicts recorded in
  `KERNEL_COMPATIBILITY.md`.
- `northnarrow-agent --btf-check <btf>`: offline compatibility verdict
  (SUPPORTED / SUPPORTED (degraded) / NOT SUPPORTED) for any kernel BTF;
  optional offsets (the `iov_iter` family behind DNS QNAME decoding)
  degrade the sensor instead of refusing the boot. Lab: third guest
  `ubuntu2204` (kernel 5.15), verified end to end.
- Multi-kernel, level 1: kernel struct offsets are resolved from the
  running kernel's BTF at boot and published to the eBPF programs through
  the `BTF_OFFSETS` map before any hook attaches (compiled-in values are
  only the fallback); `iov_iter` alternative paths (≤ 6.3) and the
  `ITER_UBUF` enumerator resolved by name. Debian 12 / kernel 6.1 now
  runs the full e2e suites (agent 6/6, watchdog 4/4); a field absent on
  the running kernel still refuses the boot (BUG-036, exit 78).
- Lab: second guest Debian 12 (`NN_LAB_DISTRO=debian12`, kernel 6.1) with
  its own disk, port and reports; `docs/operator/KERNEL_COMPATIBILITY.md`
  records the verified matrix. Finding: the agent refuses to start on 6.1
  (20 of 41 compiled-in BTF offsets differ — fail-closed as designed);
  runtime offsets tracked as review entry 27.
- Release workflow on tags `v*`: locked build, release tarball consumed by
  `install.sh` unchanged, CycloneDX SBOM, `SHA256SUMS`, SLSA build
  provenance attestation (`gh attestation verify`); dry run on packaging
  PRs. `deploy/release/mk-tarball.sh` builds the same tree locally.
- `install.sh --upgrade`: in-place upgrade of a running install (stops
  watchdog → agent, drains the LSM programs, replaces, restarts; keys,
  agent_id, audit chain and chain logs preserved). Without the flag the
  script now refuses when the units are active instead of failing halfway
  with `Operation not permitted`.
- `deploy/uninstall.sh` (`--purge`, `--yes`): ordered removal that the
  anti-tamper layer allows; keeps `/etc/northnarrow` and
  `/var/lib/northnarrow` unless purged.
- Lab: `nn-lab.sh upgrade-check` / `uninstall-check`, both in the nightly.
- `docs/operator/INSTALL_UPGRADE_UNINSTALL.md`.

### Fixed
- Lab/test only: `privileged_map_pin` and the watchdog 3-cycle respawn
  e2e evict the agent from PROTECTED_PIDS before signalling it (the
  `task_kill` deny-by-default policy refuses a bare SIGQUIT/SIGKILL);
  two illustrative doctests re-fenced as text.

## [0.0.1] - 2026-10-09

Tag `v0.0.1-tappa9.0`: everything up to Tappa 9.0 plus the 2026-10-08/09
hardening round (PR #145, #155–#170). All High/Medium findings of
`docs/audit/NN_BUG_AUDIT_2026-06-09.md` and
`docs/audit/NN_REVIEW_2026-10-08.md` closed and verified on the QEMU lab
guest (kernel 6.8, BPF-LSM).

### Security / safety
- RAG release gates (golden ≥ 90 %, latency, e2e format) fail fast when
  `target/kb` is missing instead of silently benchmarking the built-in
  seed; the lab ships the corpus and reports 28/30 = 93.3 % on the real
  ATT&CK + Sigma dumps (the earlier 36.7 % was the seed-only artefact).
- `nn-admin rotate-keys add --new-roles` accepts every role keyword the
  agent understands (`canary-manage`, `fim-manage`, `net-read`,
  `triage`, …), not only the legacy five: least-privilege keys for
  canary/FIM operators can now be granted from the CLI instead of
  hand-editing `admin.pub` or granting `all`. The install-bootstrapped
  key's roles (`unlock,audit-read` only) are documented in
  `docs/operator/COMBAT_RECOVERY.md` §1.1.
- An orphan TCP close (no pending flow) is logged at WARN with the
  5-tuple instead of silently dropped at debug.
- The outbound UDP sensor now observes unconnected `sendto()` traffic
  (destination read from `msghdr->msg_name`), rate-limited kernel-side
  to one netflow row per `(pid, destination)` per second. Before, only
  connected UDP sockets produced a row: QUIC-like beacons and raw-UDP
  exfil through an unconnected socket were invisible.
- Boot-time audit self-check: a signed `agent_boot` entry is appended at
  startup; an unwritable audit log is fatal in enforcement mode
  (`NN_AUDIT_ALLOW_UNWRITABLE=1` to override, detect-only warns).
- Posture corroboration ledger is scoped per login session (`loginuid`
  of the owning pid; host-level activity is its own scope): a weak
  ENGAGED-tier signal from one user/container no longer corroborates a
  blunt COMBAT-tier signal from an unrelated one into a host-wide COMBAT.
- Audit Medium round: TCP netflow rows and `flow_id` carry the real
  source address/port (close-time), not `0.0.0.0:0`; the COMBAT
  kill-tree spares host-critical descendants (sshd, watchdog) via the
  ladder guard; the `detections/` chain logs are in PROTECTED_INODES;
  mass-write ignores a session's own `/run/user/<uid>/` writes only;
  `nn-admin detection-set-status` reports a persistence failure (exit
  10) distinctly from "not found" (exit 9).
- `/etc/northnarrow` directory inode is now in PROTECTED_INODES
  (mutation-denied): the config tree can no longer be renamed or removed
  from under the agent by a root process outside PROTECTED_PIDS.
- Canary deploy enforces a path policy (no system trees, no `/run`, no
  NorthNarrow state/config, no `..`, no symlink escape, `O_NOFOLLOW`
  write): a leaked admin key can no longer write root-owned files at
  arbitrary paths through `nn-admin canary deploy`.
- Anti-tamper `task_kill` hook is deny-by-default: every userspace signal
  towards a protected pid is refused (previously only SIGKILL/SIGTERM, so
  `kill -INT/-HUP/-QUIT/-STOP` from root stopped or froze the agent).
  Allowed: signal 0, self-signals, signals between protected pids
  (watchdog ↔ agent) and PID 1 with the armed nonce. The watchdog now
  registers its own pid in PROTECTED_PIDS at boot (design §7.1; before,
  it was protected only if its pidfile pre-dated the agent's start).
- R004 (fileless exec) also matches `/dev/fd/N` (what glibc's `fexecve`
  really passes) and `/memfd:` pseudo-paths; previously a memfd exec on
  Ubuntu 24.04 was undetected.
- File canaries deployed at arbitrary paths trip again on READ: the FIM
  drain's BUG-012 v2 gate now forwards `Opened` events for canary inodes
  (published by the K3 index rebuild) to the rule engine.
- Watchdog respawn v2 (`docs/design/WATCHDOG_RESPAWN_V2_DESIGN.md`): a
  crashed agent is restarted with `systemctl start` under its own unit
  (full ExecStart argv, own cgroup/caps/ProtectHome) instead of as a
  fork-exec child of the watchdog's 64 MiB / 2-cap sandbox. `BindsTo=`
  removed from the watchdog unit; `StartLimitIntervalSec=0` on the agent
  unit. New flags `--respawn-backend {auto,systemd,exec}` and
  `--agent-unit`. Closes `watchdog-respawn-1` and `combat-avail-1`.
- Audit Beta-blockers closed: `abi-modpath-1` (module path sensor now
  keeps 16 components and flags truncation; R018 never auto-kills on an
  unverifiable prefix), `posture-1` (two blunt COMBAT-tier signals in one
  round cap at ENGAGED), `ebpf-lsm-1` (LSM deny-hook attach shortfall is
  fail-closed: the agent refuses to start unless
  `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`). `at-authz-2` was already closed by #142.
  **Wire change:** `ModuleLoadRaw` grows from 312 to 568 bytes (eBPF and
  userland from the same `common` crate — rebuild both).
- `CAP_KILL` added to the agent's `CapabilityBoundingSet`; without it
  KillProcess could only signal root-owned targets. New boot preflight
  (`response/caps_preflight.rs`) refuses to start in enforcement mode when
  `CAP_KILL` is missing and logs any other missing capability.
- `kill_process_tree` refuses PID 0/1 as a root before walking `/proc`
  (PID 0's children are init + kthreadd, i.e. the whole host) and never
  yields PID 1/2 as descendants.
- Quarantine refuses to vault + unlink binaries under system prefixes
  (`/usr/bin`, `/usr/lib`, `/etc`, `/boot`, …) and NorthNarrow's own paths.
- Posture: the corroboration ledger is cleared on every COMBAT release
  path (audit `posture-2`).
- NN-L-NET-005 / NN-L-NET-013 stateful windows evict idle keys (audit
  `catchall-1`, unbounded memory growth on a long-lived agent).

### Fixed
- Agent unit: `/etc/northnarrow` added to `ReadWritePaths` — under
  `ProtectSystem=strict` the installed agent could not append its own
  signed audit log (EROFS) nor bootstrap `agent_id`/`agent.sig.key`.
- Agent unit: `RuntimeDirectoryPreserve=yes` — a respawn-v2 restart no
  longer wipes `/run/northnarrow` (watchdog pidfile, shutdown marker,
  honeypot baits).
- `install.sh` now ships `combat-rules.v4/.v6` from `configs/` (missing
  ruleset = no NetworkIsolator = admin socket silently absent = watchdog
  stuck-recovery restart loop) and lifts `chattr +i` on the state dir
  for upgrades. The agent logs an ERROR when the ruleset is missing.
- CI: `cargo fmt`, `cargo clippy -D warnings` and the `test` job are green
  again; `ade-build` no longer runs out of disk on the hosted runner;
  `ebpf-build` pins `bpf-linker 0.10.3` (0.11 needs a system LLVM 21+).
- Test flake `anti_tamper::network_isolate::release_is_idempotent`
  (ETXTBSY race on the mock `iptables-restore` script).
- Dependencies: `rustls` 0.23.45 (RUSTSEC-2026-0285), `crossbeam-epoch`
  0.9.21 (RUSTSEC-2026-0204).

### Added
- `deploy/lab/nn-lab.sh`: QEMU/KVM Ubuntu 24.04 lab guest (kernel 6.8,
  `lsm=…,bpf`) with sync/build/test-e2e/test-ignored/install/respawn-check
  sub-commands; runs from WSL2 with nested virtualization.
- `cargo audit` CI job, Dependabot (cargo + GitHub Actions), `SECURITY.md`.

## [0.0.1] — 2026-06-10

Tappe 0–9.0 as described in `ROADMAP.md`: eBPF sensors, rule engine,
response executors, local ADE (candle), posture machine, anti-tamper
(BPF-LSM + watchdog), signed admin channel, detection store.
