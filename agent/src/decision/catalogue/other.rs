//! The canary, chain, io_uring, BPF, anti-tamper, exploit guard and security-tool
//! rules.

use nn_model::{ResponseAction, Severity};

use super::RuleDoc;
use crate::detection_payload::Sensor;

pub(super) const DOCS: &[RuleDoc] = &[
    // ── deception canaries ──────────────────────────────────────────
    RuleDoc {
        id: "NN-L-CANARY-001_FileAccess",
        severities: &[Severity::Critical, Severity::High, Severity::Low],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Canary, Sensor::File, Sensor::Exec],
        data_components: &["DC0055", "DC0032"],
        observes: "An open (or an exec) of a File canary, a decoy file the operator deployed \
                   with `nn-admin canary deploy file`, matched by inode against the signed \
                   canary registry before the rule engine runs.",
        false_positives: "No workflow reads a decoy, but a program that reads whole trees \
                          (backup, anti-malware, indexer, sync: the built-in canary readers \
                          and the signed canary-readers.local) is recorded High, not killed \
                          (external audit DEC-005); every access after the first trip is a \
                          Low record (DEC-004).",
        how_to_test: "Deploy a File canary (`nn-admin canary deploy --name t --key <key> file \
                      --path /root/aws_keys_old.txt`) and `cat` it from a shell: the shell's \
                      tree is killed, the posture goes to COMBAT.",
        tests: &[
            "agent/src/decision/rules/canary.rs::canary001_fires_on_file_canary_file_open",
            "agent/src/decision/rules/canary.rs::a_reader_of_whole_trees_is_recorded_not_killed",
            "agent/tests/canary_privileged_e2e.rs::file_canary_open_triggers_canary_tripped_event_and_combat",
        ],
        attack_note: "The technique is what the intruder did: read a file found on the host \
                      (T1005). A decoy named for credentials is NN-L-CANARY-004's \
                      (T1552.001).",
    },
    RuleDoc {
        id: "NN-L-CANARY-002_ProcessExec",
        severities: &[Severity::Critical, Severity::Low],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Canary, Sensor::Exec],
        data_components: &["DC0032"],
        observes: "An exec of a Process canary, a decoy helper binary the operator deployed \
                   with `nn-admin canary deploy process`, matched by path against the signed \
                   canary registry.",
        false_positives: "No workflow runs the decoy (operators use nn-admin); an exec after \
                          the first trip is a Low record (DEC-004).",
        how_to_test: "Deploy a Process canary (`nn-admin canary deploy --name t --key <key> \
                      process --path /usr/local/bin/sysadmin-helper --fake-arg0 helper`) and \
                      run it: the caller's tree is killed.",
        tests: &[
            "agent/src/decision/rules/canary.rs::canary002_fires_on_process_canary_exec",
            "agent/tests/canary_privileged_e2e.rs::process_canary_exec_triggers_canary_tripped_event_and_combat",
        ],
        attack_note: "Weak mapping: no ATT&CK technique names running a decoy. The decoy is \
                      found by enumerating a binary directory (T1083, design appendix B: `ls \
                      /usr/local/bin` then exec something interesting); the exec itself is \
                      what the rule sees.",
    },
    RuleDoc {
        id: "NN-L-CANARY-003_NetworkConnect",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::Canary, Sensor::Network],
        data_components: &["DC0082"],
        observes: "A TCP connect by a local process (the connect kprobe) to a Network canary's \
                   address and port, a destination no legitimate process uses.",
        false_positives: "The operator's own scanner or monitoring check that probes the \
                          canary's port trips it; a deploy is refused when a listener on the \
                          host would receive the canary's connections. Every connect kills; a \
                          connection from another host is not seen.",
        how_to_test: "Deploy a Network canary (`nn-admin canary deploy --name t --key <key> \
                      network --bind-addr 127.0.0.1 --bind-port 4444`) and connect to it from \
                      a shell (`bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444'`).",
        tests: &[
            "agent/src/decision/rules/canary.rs::canary003_fires_on_network_canary_connect",
            "agent/src/canary/detector.rs::a_network_canary_trip_draws_canary_003_on_the_connector",
            "agent/tests/canary_privileged_e2e.rs::network_canary_connect_trips_canary_003_and_kills_the_connector",
        ],
        attack_note: "A port scan of the host finds the decoy (T1046); a decoy destination \
                      planted in a configuration file, a hosts entry or an ssh config is a \
                      remote service the intruder tries to reach (T1021).",
    },
    RuleDoc {
        id: "NN-L-CANARY-004_CredentialRead",
        severities: &[Severity::Critical, Severity::High, Severity::Low],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Canary, Sensor::File, Sensor::Exec],
        data_components: &["DC0055", "DC0032"],
        observes: "A read of a Credential canary, a decoy credential file (aws, azure, gcp, \
                   docker or generic family, format-valid and authenticating nowhere) the \
                   operator deployed with `nn-admin canary deploy credential`.",
        false_positives: "Legitimate cloud CLIs read the real credentials, not the decoy; a \
                          reader of whole trees is recorded High, not killed (DEC-005), and an \
                          access after the first trip is a Low record (DEC-004).",
        how_to_test: "Deploy a Credential canary (`nn-admin canary deploy --name t --key <key> \
                      credential --path /root/.aws/credentials.bak --cred-family aws`) and \
                      `grep -r AKIA /root` from a shell.",
        tests: &[
            "agent/src/decision/rules/canary.rs::canary004_fires_on_credential_canary_read",
            "agent/src/decision/rules/canary.rs::a_later_access_to_a_tripped_canary_is_recorded_not_killed",
        ],
        attack_note: "",
    },
    // ── correlation chains ──────────────────────────────────────────
    RuleDoc {
        id: "NN-L-CHAIN-001_CredReadThenEgress",
        severities: &[Severity::Critical, Severity::High],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Network, Sensor::File],
        data_components: &["DC0078", "DC0055"],
        observes: "An outbound flow from a process that read a FIM-watched credential store \
                   (a browser's, a password manager's database, a GPG keyring) within 300 s: \
                   Critical kill; within 30 minutes, one High record (NETR-014).",
        false_positives: "A browser or password manager whose store the operator added to the \
                          FIM watch list, syncing within the window. Reads seen only through \
                          the open sensor's wide coverage of the homes are not a precursor \
                          (NETR-001).",
        how_to_test: "With a browser credential file (`Login Data`) in the FIM watch list, \
                      one process reads it and connects out (loopback counts); run the agent \
                      in detect-only mode, since NN-L-FIM-015 acts on the read first.",
        tests: &[
            "agent/src/decision/rules/chain.rs::chain001_fires_on_cred_read_then_egress",
            "agent/src/decision/rules/chain.rs::an_aged_read_is_recorded_once",
        ],
        attack_note: "The credential stores of the precursor are those of NN-L-FIM-015, -016 \
                      and -017 (T1555.003, T1555.005, T1552.004); the egress is read as \
                      exfiltration over the process's own channel (T1041).",
    },
    RuleDoc {
        id: "NN-L-CHAIN-002_TmpExecThenEgress",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::Network, Sensor::Exec],
        data_components: &["DC0078", "DC0032"],
        observes: "An outbound flow (at its connect, while it is open, at its close), other \
                   than one to port 53 of a configured resolver, from a process whose image \
                   is in a staging directory (/tmp, /var/tmp, /dev/shm), within 300 s of its \
                   exec. To port 53 of a server that is no configured resolver — a match new in lab PR 224, \
                   which exempts only the host's resolvers — the kill is held behind the \
                   per-rule response policy (off by default): recorded at the same severity. \
                   It also completes when the exec record is processed after the flow (lab \
                   PR 244), judged on the kernel timestamps.",
        false_positives: "An installer or a test binary run from a temporary directory that \
                          talks to the network. A process of a package transaction is spared \
                          (NETR-008, lab PR 175); its flow falls to NN-L-NET-008.",
        how_to_test: "Run from /tmp a helper that connects out as its first act (the e2e \
                      compiles one, which wins the race against R001's kill), or run the \
                      agent in detect-only mode and `cp /usr/bin/curl /tmp/c && /tmp/c \
                      http://127.0.0.1:8080/`.",
        tests: &[
            "agent/src/decision/rules/chain.rs::chain002_fires_on_tmp_exec_then_nondns_egress",
            "agent/src/decision/rules/chain.rs::chain002_completes_when_the_exec_is_processed_after_the_egress",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::chain_tmp_exec_then_egress_trips_chain_002",
        ],
        attack_note: "T1059 and T1571 as the design and the V2 technique rows (TQ18, TQ55) \
                      have them. The image need not be an interpreter, and the trigger is any \
                      port but 53, so a payload calling home on 443 (T1071) fires it too, \
                      which the mapping does not claim.",
    },
    RuleDoc {
        id: "NN-L-CHAIN-003_CanaryThenEgress",
        severities: &[Severity::Critical, Severity::High],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Network, Sensor::Canary],
        data_components: &["DC0078", "DC0055", "DC0032", "DC0082"],
        observes: "An outbound flow from a process that tripped a deception canary (any \
                   NN-L-CANARY type) within 300 s: Critical kill; within 30 minutes, one High \
                   record (NETR-014). The connection a network canary trip is (its connect, \
                   answered by NN-L-CANARY-003) is not an egress after it: no row of it \
                   completes the chain, in whatever order its connect and close arrive (lab \
                   PR 246).",
        false_positives: "Every trip is a precursor, including one the canary rule only \
                          records: a reader of whole trees (a backup client) that reads a \
                          canary and then uploads within 300 s draws the Critical verdict.",
        how_to_test: "Deploy a File canary, then from one process read it and connect out \
                      (`python3 -c` opening the decoy, then a socket); run the agent in \
                      detect-only mode, since NN-L-CANARY-001 kills the reader first.",
        tests: &[
            "agent/src/decision/rules/chain.rs::chain003_fires_on_canary_then_egress",
            "agent/src/decision/rules/chain.rs::chain003_records_an_aged_trip_without_killing",
            "agent/src/canary/detector.rs::the_trips_own_connection_draws_no_chain_verdict_in_any_order",
        ],
        attack_note: "The precursor's technique depends on the canary type (see \
                      NN-L-CANARY-001..004); the chain itself is evidence of exfiltration.",
    },
    RuleDoc {
        id: "NN-L-CHAIN-004_CrossPidCredExfil",
        severities: &[Severity::Critical, Severity::High],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Network, Sensor::File, Sensor::Exec],
        data_components: &["DC0078", "DC0055", "DC0032"],
        observes: "An outbound flow from a process whose ancestor (not itself) read a \
                   FIM-watched credential store: within 300 s Critical kill, within 30 \
                   minutes one High record. The ancestry comes from the exec sensor.",
        false_positives: "As NN-L-CHAIN-001, through a child: a browser or password manager \
                          whose watched store was read by the parent and whose helper process \
                          syncs.",
        how_to_test: "A parent reads a FIM-watched `Login Data` file (NN-L-FIM-015 kills the \
                      parent only) after forking a child that connects out afterwards; the \
                      e2e does exactly this.",
        tests: &[
            "agent/src/decision/rules/chain.rs::chain004_cross_pid_cred_exfil_fires",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::chain_cred_read_parent_then_descendant_egress_trips_chain_004",
        ],
        attack_note: "As NN-L-CHAIN-001.",
    },
    RuleDoc {
        id: "NN-L-CHAIN-005_CrossPidTmpC2",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::Network, Sensor::Exec],
        data_components: &["DC0078", "DC0032"],
        observes: "An outbound flow (at its connect, while it is open, at its close), other \
                   than one to port 53 of a configured resolver, from a process whose ancestor \
                   (not itself) was executed from a staging directory within 300 s. To port 53 of a server that is no configured resolver — a match new in lab PR 224, \
                   which exempts only the host's resolvers — the kill is held behind the \
                   per-rule response policy (off by default): recorded at the same severity.",
        false_positives: "As NN-L-CHAIN-002, through a child (an installer run from /tmp whose \
                          helper downloads); a package transaction is spared.",
        how_to_test: "A program run from /tmp forks a child that connects out to a port other \
                      than 53; the e2e builds one.",
        tests: &[
            "agent/src/decision/rules/chain.rs::chain005_cross_pid_tmp_c2_fires",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::chain_tmp_parent_then_descendant_egress_trips_chain_005",
        ],
        attack_note: "As NN-L-CHAIN-002.",
    },
    RuleDoc {
        id: "NN-L-CHAIN-006_CrossPidCanaryExfil",
        severities: &[Severity::Critical, Severity::High],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Network, Sensor::Canary, Sensor::Exec],
        data_components: &["DC0078", "DC0055", "DC0032", "DC0082"],
        observes: "An outbound flow from a process whose ancestor (not itself) tripped a \
                   deception canary: within 300 s Critical kill, within 30 minutes one High \
                   record.",
        false_positives: "As NN-L-CHAIN-003, through a child: a backup client that reads a \
                          canary and hands the upload to a helper process.",
        how_to_test: "A process forks a daemonised grandchild, then trips a File canary; the \
                      grandchild connects out afterwards (the e2e's recipe).",
        tests: &[
            "agent/src/decision/rules/chain.rs::cross_pid_chains_grade_by_age",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::chain_canary_trip_parent_then_descendant_egress_trips_chain_006",
        ],
        attack_note: "As NN-L-CHAIN-003.",
    },
    RuleDoc {
        id: "NN-L-CHAIN-007_TmpCredExfilSequence",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::Network, Sensor::Exec, Sensor::File],
        data_components: &["DC0078", "DC0032", "DC0055"],
        observes: "One process executed from a staging directory, then read a FIM-watched \
                   credential store, then opened an outbound flow, all within 300 s; it also \
                   completes when the read is processed after the flow (review 70).",
        false_positives: "A program run from /tmp that reads a watched credential store and \
                          talks to the network; a package transaction is spared.",
        how_to_test: "In detect-only mode, a binary run from /tmp reads a FIM-watched \
                      `Login Data` file and connects out (the e2e is ignored as flaky, \
                      T10.6.2: the same-PID kills race).",
        tests: &[
            "agent/src/decision/rules/chain.rs::chain007_three_step_sequence_fires",
            "agent/src/decision/rules/chain.rs::chain007_completes_when_the_read_is_processed_after_the_egress",
        ],
        attack_note: "The steps of NN-L-CHAIN-002 (T1059) and NN-L-CHAIN-001 (T1555.003, \
                      T1555.005, T1552.004, T1041).",
    },
    RuleDoc {
        id: "NN-L-CHAIN-008_CrossPidPrivEscExfil",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Network, Sensor::Exec],
        data_components: &["DC0078", "DC0032"],
        observes: "An off-host outbound flow (not loopback, not unspecified) from a descendant \
                   of a `sudo` or `su` exec within 300 s. Registered last, so its Log verdict \
                   never shadows a blocking rule on the same flow.",
        false_positives: "Routine administration: `sudo apt-get update`, configuration \
                          management with `become: sudo`, any sudo'd tool that reaches the \
                          network. Hence Medium and Log only.",
        how_to_test: "`sudo curl -s http://example.org/ >/dev/null` from a login shell.",
        tests: &[
            "agent/src/decision/rules/chain.rs::chain008_cross_pid_privesc_exfil_fires",
            "agent/src/decision/rules/chain.rs::chain008_is_informational_log_not_kill",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::chain_privesc_then_descendant_egress_trips_chain_008",
        ],
        attack_note: "T1548, not T1548.003 (Sudo and Sudo Caching): `su` is a precursor too. \
                      The precursor is any use of sudo or su, not an abuse of it.",
    },
    // ── io_uring ────────────────────────────────────────────────────
    RuleDoc {
        id: "NN-L-IOU-001_IoUringRingCreated",
        severities: &[Severity::Low],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::IoUring],
        data_components: &["DC0021"],
        observes: "The creation of an io_uring ring by a process outside the known io_uring \
                   users and the process allowlist, judged on the executable the kernel ran: \
                   the baseline of who uses io_uring on the host.",
        false_positives: "Any legitimate io_uring user not yet listed (a database, QEMU, \
                          nginx, a liburing tool, a libuv runtime such as Node 20 or later); \
                          add it to process-comm-allowlist.local.",
        how_to_test: "anti-tamper.sh case C22 builds a probe that opens and reads \
                      /etc/hostname and connects to 127.0.0.1:9 through one ring \
                      (`kernel.io_uring_disabled` must be 0).",
        tests: &[
            "agent/src/decision/rules/iouring.rs::ring_creation_logs_unlisted_and_exempts_known_and_allowlisted",
            "deploy/lab/adversarial/anti-tamper.sh::case C22",
        ],
        attack_note: "The reasoning text named T1562 (Impair Defenses), revoked in ATT&CK v19, \
                      until lab PR 221 (its successor T1685 is disabling or tampering with a \
                      tool, which a ring does not do). io_uring does I/O outside the \
                      syscalls the open, exec and connect sensors hook: calling a kernel interface directly to sidestep \
                      hooked APIs is T1106.",
    },
    RuleDoc {
        id: "NN-L-IOU-002_IoUringFileAndNetwork",
        severities: &[Severity::High],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::IoUring],
        data_components: &["DC0021"],
        observes: "A process outside the allowlist that has driven both file I/O (open or \
                   read/write) and network I/O (connect or send/recv) through io_uring rings; \
                   once per process, on the record that completes the pair.",
        false_positives: "A legitimate io_uring server not in the allowlist that serves files \
                          over the network (a proxy, a database, a Node service).",
        how_to_test: "anti-tamper.sh case C22 (the same probe as NN-L-IOU-001: openat, read \
                      and connect through one ring).",
        tests: &[
            "agent/src/decision/rules/iouring.rs::file_and_network_fires_once_on_the_completing_record",
            "deploy/lab/adversarial/anti-tamper.sh::case C22",
        ],
        attack_note: "As NN-L-IOU-001 (T1106). The file-and-network pairing is the shape of \
                      an implant's collection and exfiltration (T1005, T1041), whose content \
                      the rule does not see; those are not claimed.",
    },
    // ── BPF ─────────────────────────────────────────────────────────
    RuleDoc {
        id: "NN-L-BPF-001_BpfProgramLoaded",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::AntiTamper],
        data_components: &["DC0021"],
        observes: "A bpf() program load, attach or link creation by a process outside the \
                   known BPF tooling and the process allowlist (the `bpf` LSM observer), \
                   judged on the executable the kernel ran.",
        false_positives: "BPF tooling not in the list: bpftool, bpftrace, BCC tools, an \
                          observability or security agent; add it to \
                          process-comm-allowlist.local.",
        how_to_test: "`bpftool feature probe kernel` loads test programs (anti-tamper.sh \
                      case C10).",
        tests: &[
            "agent/src/decision/rules/bpf.rs::program_load_by_unlisted_logs_medium_and_known_tooling_is_exempt",
            "deploy/lab/adversarial/anti-tamper.sh::case C10",
        ],
        attack_note: "A kernel-resident program from an unknown loader is the eBPF rootkit \
                      shape (T1014). The reasoning text also named T1562, revoked in v19, \
                      until lab PR 221; a program that blinds a sensor would be T1685, which a load alone does \
                      not show.",
    },
    RuleDoc {
        id: "NN-L-BPF-002_BpfForeignHandleOrDetach",
        severities: &[Severity::High],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::AntiTamper],
        data_components: &["DC0021"],
        observes: "A handle taken by id to one of the agent's own BPF maps, programs or links, \
                   a write handle on an agent map (observe mode), or a program or link detach \
                   by a process outside the known BPF tooling.",
        false_positives: "A detach by tooling not in the list (a container runtime or CNI not \
                          listed). A handle to the agent's own objects is never exempt: an \
                          administrator's `bpftool map dump` of them is recorded too.",
        how_to_test: "`bpftool map update pinned <pins>/PROTECTED_PIDS key 1 0 0 0 value 1` \
                      (anti-tamper.sh case C08) or `bpftool link show pinned` (C09): observe \
                      mode records this rule, enforce mode denies the handle (NN-L-AT-001).",
        tests: &[
            "agent/src/decision/rules/bpf.rs::own_object_handle_is_high_even_for_known_tooling",
            "deploy/lab/adversarial/anti-tamper.sh::case C08",
        ],
        attack_note: "",
    },
    // ── anti-tamper ─────────────────────────────────────────────────
    RuleDoc {
        id: "NN-L-AT-001_AntiTamperDenial",
        severities: &[Severity::High],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::AntiTamper],
        data_components: &["DC0035", "DC0061", "DC0040", "DC0055", "DC0021"],
        observes: "Every action on the agent an anti-tamper LSM hook refused: a signal to a \
                   protected pid, a ptrace or /proc/<pid>/mem access, a write, unlink, rename \
                   or new entry in its protected files, a handle to its BPF maps or links, a \
                   kexec load, a read of its signing key. Issued by process_event outside the \
                   engine.",
        false_positives: "An administrator's `systemctl stop` or `kill` of the agent, or an \
                          upgrade, outside a trusted-installer window; a debugger or \
                          `strace -p` on the agent. The kernel refused the action either way; \
                          the record is Log only.",
        how_to_test: "`kill -9` the agent from a root shell (anti-tamper.sh case C01) or read \
                      /proc/<agent>/mem (case C03): the record names the refused operation \
                      (deny=signal, deny=ptrace).",
        tests: &[
            "agent/src/decision/rules/anti_tamper.rs::every_denial_kind_is_a_high_log_verdict",
            "deploy/lab/adversarial/anti-tamper.sh::case C01",
            "deploy/lab/adversarial/anti-tamper.sh::case C03",
        ],
        attack_note: "Killing, stopping or rewriting the sensor is T1685. A ptrace or \
                      /proc/<pid>/mem access on the agent is the injection attempt the V2 rows \
                      TQ13 and TQ15 expect denied (T1055.008, T1055.009); a read of the \
                      signing key is T1552.004.",
    },
    // ── exploit post-condition guard (lab PR 219, experimental) ─────
    RuleDoc {
        id: "NN-L-EPG-001_CredentialPostcondition",
        severities: &[Severity::Critical, Severity::High],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::ExploitGuard],
        data_components: &["DC0034", "DC0021"],
        observes: "A task that was not fully privileged holding a uid, a gid, a capability or \
                   another user namespace that no commit_creds made, or that commit_creds made \
                   on behalf of a system call that never makes that change: the post-condition \
                   of a kernel exploit, whatever its bug. Lite (default) judges the mechanism on \
                   the call in progress and a credential changed without one at its first use \
                   (capable, exec, a root-private open); strict compares around every system \
                   call. High, Log only: lite's degraded evidence, a task whose record the LRU \
                   task map evicted, re-taken holding uid or gid 0 or a capability that no \
                   mechanism is known to have given. Issued by process_event outside the engine.",
        false_positives: "None expected from the legitimate transitions (sudo, su, newgrp, \
                          setpriv, capsh, unshare, rootless and rootful containers, \
                          systemd-run --uid, cron): the guard allows by mechanism, not by \
                          name, and lite compares real_cred so overlayfs's override_creds is \
                          not a change. Experimental: detect by default; enforce kills in \
                          kernel (lite also refuses the use). The High degraded evidence fires \
                          for legitimate privileged tasks too when the lite task map evicts \
                          (a host above its size, or a task flood; counted and attested).",
        how_to_test: "On a debug build, `epg-check.sh inject capable detect` (lite) or `inject \
                      getppid detect` (strict; the agent refuses strict below Linux 6.1): the \
                      injected anomaly is recorded, the record naming the probe (comm \
                      nn-epg-probe) and, in its response, the point that caught it (the \
                      journal's VERDICT line says LAB INJECTION); `negative` runs the \
                      legitimate transitions and expects no record.",
        tests: &[
            "agent/src/decision/rules/epg.rs::credential_write_in_detect_mode_is_a_critical_log",
            "agent/src/decision/rules/epg.rs::enforce_kill_is_recorded_as_a_kernel_kill",
            "agent/src/decision/rules/epg.rs::a_lost_baseline_is_degraded_evidence",
            "deploy/lab/epg/epg-check.sh::inject",
        ],
        attack_note: "Exploitation for Privilege Escalation (T1068) by its result: the rule \
                      sees the credentials an exploit leaves, not the exploit.",
    },
    RuleDoc {
        id: "NN-L-EPG-002_NamespaceRootPostcondition",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::ExploitGuard],
        data_components: &["DC0034", "DC0021"],
        observes: "A task's nsproxy, fs_struct or filesystem root replaced with no mechanism, \
                   or by a mechanism on behalf of a call that never switches them: the \
                   post-condition of a container or namespace escape through the kernel. \
                   Issued by process_event outside the engine.",
        false_positives: "As NN-L-EPG-001: setns, unshare, chroot, pivot_root and the container \
                          runtimes are the mechanisms the guard allows.",
        how_to_test: "As NN-L-EPG-001 (`epg-check.sh negative`; the injection exercises the \
                      record path of both rules).",
        tests: &[
            "agent/src/decision/rules/epg.rs::namespace_escape_is_epg_002",
            "deploy/lab/epg/epg-check.sh::negative",
        ],
        attack_note: "Escape to Host (T1611) by its result; a credential gain in the same \
                      call is NN-L-EPG-001's.",
    },
    // ── security tools switched off (lab PR 225, CM-18) ─────────────
    RuleDoc {
        id: "NN-L-EVA-001_SecurityServiceStopped",
        severities: &[Severity::High, Severity::Low],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "A listed security tool's unit stopped, disabled, masked or killed \
                   (`systemctl stop/disable/mask/kill`, `service … stop`, `invoke-rc.d`, \
                   `update-rc.d`, `chkconfig`, `rc-service`, `rc-update`, `/etc/init.d/<name> \
                   stop`); the tools are the shipped list `security-tools.v1`.",
        false_positives: "Low in a package transaction, an administrator's interactive session \
                          or under a configuration-management actor, and — for the agent's own \
                          units only — a stop or restart inside a valid signed trusted-installer \
                          window (the record's `sanction` names its key id and deadline; the \
                          posture does not move). Another tool stopped inside the window, or the \
                          agent's units outside it or after it expired, stay High. Asked by a \
                          program run from a staging directory or a deleted executable, the kill \
                          of that program's tree is held behind the per-rule response policy \
                          (off by default, new in lab PR 225): a High record.",
        how_to_test: "`ransom-check.sh` MS-25: `systemctl stop auditd` (auditd installed).",
        tests: &[
            "agent/src/decision/rules/evasion.rs::eva_rules_record_the_ms25_commands",
            "agent/src/decision/rules/evasion.rs::eva_kills_a_staged_script_that_asks",
            "agent/src/decision/rules/evasion.rs::eva_001_inside_the_installer_window_is_low_for_the_agents_own_units_only",
            "agent/src/impair/tests.rs::a_valid_window_sanctions_a_stop_or_restart_of_the_agents_own_units",
            "agent/src/impair/tests.rs::an_expired_window_sanctions_nothing",
            "agent/src/impair/tests.rs::a_valid_window_never_sanctions_another_tool",
            "deploy/lab/malsim/ransom-check.sh::MS-25",
        ],
        attack_note: "T1685 for a tool, T1685.004 for the audit system, T1686 for the \
                      firewall; the record's reasoning names the one of its tool.",
    },
    RuleDoc {
        id: "NN-L-EVA-002_SecurityToolSwitchedOff",
        severities: &[Severity::High, Severity::Low],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "A listed tool switched off by its own command: `auditctl -e 0` and `-D`, \
                   `ufw disable`, `setenforce 0`, `nft flush ruleset`, `iptables -F`, \
                   `aa-teardown`, cloud-agent uninstallers.",
        false_positives: "As NN-L-EVA-001. One record per command and process tree (the \
                          children of one parent) within 10 s: `ufw disable` runs dozens of \
                          `iptables -F` through `ufw-init`; the repeats are counted \
                          (`detections_held`, the next record's `suppressed_before`), never on \
                          the kill path.",
        how_to_test: "`ransom-check.sh` MS-25: `auditctl -e 0`, `ufw disable`.",
        tests: &[
            "agent/src/decision/rules/evasion.rs::eva_rules_record_the_ms25_commands",
            "agent/src/decision/rules/evasion.rs::eva_002_coalesces_the_iptables_calls_of_one_ufw_disable",
            "agent/src/detection_budget.rs::coalesced_repeats_are_counted_without_spending_the_budget",
            "deploy/lab/malsim/ransom-check.sh::MS-25",
        ],
        attack_note: "As NN-L-EVA-001.",
    },
    RuleDoc {
        id: "NN-L-EVA-003_SecurityToolKilled",
        severities: &[Severity::High, Severity::Low],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::AntiTamper, Sensor::Exec],
        data_components: &["DC0021", "DC0032"],
        observes: "A stop or end signal to a listed tool's process: on `task_kill` \
                   (`DEFENDER_PIDS`, filled at boot and from the tools' execs, and from \
                   `/proc` scans after each for the daemon it forks; reported, never \
                   refused — a shell's builtin `kill` included), or a `kill`, `pkill`, \
                   `killall` exec.",
        false_positives: "As NN-L-EVA-001; a service manager's own stop of a unit it restarts.",
        how_to_test: "`ransom-check.sh` MS-25: `kill -STOP` of auditd from a shell.",
        tests: &[
            "agent/src/decision/rules/evasion.rs::eva_rules_record_the_ms25_commands",
            "agent/src/impair/tests.rs::a_forking_daemons_own_pid_is_registered_after_its_exec",
            "deploy/lab/malsim/ransom-check.sh::kill -STOP of auditd",
        ],
        attack_note: "As NN-L-EVA-001.",
    },
    RuleDoc {
        id: "NN-L-EVA-004_SecurityToolConfigChanged",
        severities: &[Severity::High, Severity::Low],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0061"],
        observes: "A listed tool's configuration file changed (the files `security-tools.v1` \
                   names, watched by FIM).",
        false_positives: "As NN-L-EVA-001: a package upgrade or an administrator's edit is \
                          Low.",
        how_to_test: "`ransom-check.sh` MS-25: an edit of auditd's configuration.",
        tests: &[
            "agent/src/decision/rules/evasion.rs::eva_rules_record_the_ms25_commands",
            "deploy/lab/malsim/ransom-check.sh::MS-25",
        ],
        attack_note: "As NN-L-EVA-001.",
    },
];
