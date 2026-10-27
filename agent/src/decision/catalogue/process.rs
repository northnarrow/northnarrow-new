//! The process rules (R001..R018).

use nn_model::{ResponseAction, Severity};

use super::RuleDoc;
use crate::detection_payload::Sensor;

pub(super) const DOCS: &[RuleDoc] = &[
    RuleDoc {
        id: "R001_ExecFromTmp",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of a file under `/tmp/`, judged on the file the kernel executed \
                   (a relative path, a symlink or `..` resolves to it).",
        false_positives: "An installer or a build that runs what it unpacked in `/tmp` is \
                          killed: the rule's whitelist is empty and the process allowlist does \
                          not apply. A root exec in an administrator's sudo/su session or a \
                          package transaction is R009's Low record instead (R009 runs first).",
        how_to_test: "As an unprivileged user: `cp /bin/true /tmp/nn-r001 && /tmp/nn-r001`. \
                      Run as root it is R009's verdict.",
        tests: &[
            "agent/src/decision/rules/r001_exec_from_tmp.rs::fires_on_exec_from_tmp",
            "agent/tests/response_privileged_e2e.rs::tmp_dropper_forked_child_dies_with_it",
            "deploy/lab/exec-sensor/exec-sensor-check.sh::R001_ExecFromTmp",
        ],
        attack_note: "No technique is \"execution from a staging directory\": T1059 follows \
                      design §7.1 and V2 row TQ18 (the script or shell a dropper runs). A \
                      native payload is evidence of the Execution tactic, not of an \
                      interpreter.",
    },
    RuleDoc {
        id: "R002_ExecFromDevShm",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of a file under `/dev/shm/`, the memory-backed shared directory, \
                   judged on the file the kernel executed.",
        false_positives: "Rare: few programs execute from `/dev/shm`. Nothing exempts one that \
                          does.",
        how_to_test: "As an unprivileged user: `cp /bin/true /dev/shm/nn-r002 && \
                      /dev/shm/nn-r002` (a host that mounts `/dev/shm` noexec refuses the \
                      exec before the rule sees it).",
        tests: &[
            "agent/src/decision/rules/r002_exec_from_dev_shm.rs::fires_on_dev_shm",
            "agent/src/decision/rules/r002_exec_from_dev_shm.rs::r002_kills_the_process_tree",
        ],
        attack_note: "T1027.011 names `/dev/shm` as fileless storage; T1059 as for R001.",
    },
    RuleDoc {
        id: "R003_ExecFromVarTmp",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of a file under `/var/tmp/`, the temporary directory that survives \
                   a reboot, judged on the file the kernel executed.",
        false_positives: "A package scriptlet or an installer that runs from `/var/tmp` as an \
                          unprivileged user is killed; run as root in a package transaction \
                          or an administrator's session it is R009's Low record.",
        how_to_test: "As an unprivileged user: `cp /bin/true /var/tmp/nn-r003 && \
                      /var/tmp/nn-r003`.",
        tests: &[
            "agent/src/decision/rules/r003_exec_from_var_tmp.rs::fires_on_var_tmp",
            "agent/src/decision/rules/r003_exec_from_var_tmp.rs::r003_kills_the_process_tree",
        ],
        attack_note: "T1059 as for R001.",
    },
    RuleDoc {
        id: "R004_ExecFromProcSelfFd",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "A fileless exec: with the exec sensor's identity, a memfd, or an unlinked \
                   file reached through a descriptor; without it (tracepoint mode), an exec \
                   path of the form `/proc/self/fd/N`, `/proc/<pid>/fd/N`, `/dev/fd/N` or \
                   `/memfd:`.",
        false_positives: "systemd-executor's launch of every unit (systemd 254 and later) is \
                          exempt on what the kernel executed and on a systemd parent. Another \
                          program that re-executes itself from a memfd (older runc versions \
                          do, to protect their binary) is killed: nothing else is exempt.",
        how_to_test: "`python3 -c 'import os; fd = os.memfd_create(\"x\"); \
                      os.write(fd, open(\"/bin/true\", \"rb\").read()); \
                      os.execv(\"/proc/self/fd/%d\" % fd, [\"x\"])'`.",
        tests: &[
            "agent/src/decision/rules/r004_exec_from_proc_self_fd.rs::fires_on_proc_self_fd",
            "agent/src/decision/rules/r004_exec_from_proc_self_fd.rs::\
             fires_on_a_memfd_whatever_path_reached_it",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::\
             process_memfd_fileless_exec_trips_r004",
            "deploy/lab/exec-sensor/exec-sensor-check.sh::R004_ExecFromProcSelfFd",
        ],
        attack_note: "T1620: an anonymous (memfd) or unlinked file executed through a \
                      descriptor is a payload with no file on disk.",
    },
    RuleDoc {
        id: "R005_NetcatExec",
        severities: &[Severity::High],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "An exec whose `comm` is a netcat (`nc`, `ncat`, `netcat`, `nc.openbsd`, \
                   `nc.traditional`), recorded only.",
        false_positives: "Administrators and scripts use netcat for port checks and file \
                          transfers; every such exec is recorded (Log), none is acted on. The \
                          name is the process's own: a renamed copy is not seen.",
        how_to_test: "`nc -z 127.0.0.1 22` (any netcat invocation).",
        tests: &["agent/src/decision/rules/r005_netcat_exec.rs::fires_on_each_netcat_alias"],
        attack_note: "T1095 for netcat's use as a raw TCP/UDP channel (a reverse or bind \
                      shell); the rule sees the name only, not the connection.",
    },
    RuleDoc {
        id: "R006_ReverseShellTooling",
        severities: &[Severity::Critical, Severity::High],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "An exec named like offensive tooling (`socat`, `msfvenom`, `meterpreter`, \
                   `sliver`, `havoc`). The distribution's `socat` is recorded unless one of \
                   its addresses runs a shell (`EXEC:`, `SYSTEM:`, `SHELL:`), and recorded at \
                   Critical when the kernel cut its argv.",
        false_positives: "A `socat` from `/usr/bin`, `/bin`, `/usr/sbin` or `/sbin` used as a \
                          relay is recorded (Log, High), not killed; a build of it elsewhere is \
                          killed unless allowlisted in `process-comm-allowlist`, which is \
                          judged on what the kernel executed.",
        how_to_test: "`cp /bin/sleep /tmp/sliver && /tmp/sliver 5` (killed); `socat -V` \
                      (the distribution's socat, recorded).",
        tests: &[
            "agent/src/decision/rules/r006_reverse_shell_tooling.rs::fires_on_each_offsec_tool",
            "agent/src/decision/rules/r006_reverse_shell_tooling.rs::\
             r006_system_socat_is_recorded_a_copy_is_killed",
            "agent/src/decision/rules/r006_reverse_shell_tooling.rs::\
             r006_system_socat_running_a_shell_is_killed",
        ],
        attack_note: "The tools are C2 frameworks and a relay: T1095 for the raw TCP channel, \
                      T1059.004 for the shell `socat EXEC:` runs. The rule sees the name and \
                      argv, not the traffic; a renamed tool evades it.",
    },
    RuleDoc {
        id: "R007_CryptoMiner",
        severities: &[Severity::Critical, Severity::High],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "An exec whose `comm`, or the basename of the file the kernel executed, is a \
                   miner's name (`xmrig`, `cpuminer`, `minerd`, `ccminer`, `ethminer`, \
                   `phoenixminer`), any case: killed. A name that only contains one is \
                   recorded, from a second registration after every process rule that kills.",
        false_positives: "A cleanup or monitoring tool named after a miner (`xmrig-cleanup`) is \
                          recorded, not killed; a benchmark run of a real miner is killed \
                          unless allowlisted in `process-comm-allowlist`.",
        how_to_test: "`cp /bin/sleep ~/xmrig && ~/xmrig 5` (killed); \
                      `cp /bin/sleep ~/xmrig-check && ~/xmrig-check 5` (recorded).",
        tests: &[
            "agent/src/decision/rules/r007_crypto_miner.rs::fires_on_known_miner_comms",
            "agent/src/decision/rules/r007_crypto_miner.rs::r007_substring_only_is_recorded",
        ],
        attack_note: "T1496.001 Compute Hijacking, v20's sub-technique for mining. By name \
                      only: the CPU and pool connections of a renamed miner are not judged \
                      here.",
    },
    RuleDoc {
        id: "R008_HiddenHomeBinary",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of a native file under a dot-directory of a home \
                   (`/home/<user>/.<dir>/`), outside the toolchain directories the rule \
                   lists; recorded only.",
        false_positives: "Toolchains and tools that run their own downloads are exempt by \
                          directory (`.cargo/bin`, `.local/bin`, `.rustup`, `.nvm`, the named \
                          caches under `.cache` and `.config`); another one is recorded.",
        how_to_test: "`mkdir -p ~/.nn-r008 && cp /bin/true ~/.nn-r008/x && ~/.nn-r008/x`.",
        tests: &[
            "agent/src/decision/rules/r008_hidden_home_binary.rs::fires_on_unknown_dot_directory",
            "agent/src/decision/rules/r008_hidden_home_binary.rs::autostart_dir_is_never_exempt",
        ],
        attack_note: "T1564.001: only the hiding is observed, not the persistence a hidden \
                      binary may serve.",
    },
    RuleDoc {
        id: "R009_RootExecFromUserPath",
        severities: &[Severity::High, Severity::Low],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "An exec by uid 0 of a file under `/home/`, `/tmp/` or `/var/tmp/`, judged on \
                   the file the kernel executed.",
        false_positives: "An administrator's sudo/su session at a terminal and a package \
                          transaction (a package manager run by root whose run covers the exec) \
                          are recorded at Low, not killed. Root automation outside both (a \
                          root cron job or a configuration-management run that executes a file \
                          from a home or `/tmp`) is killed.",
        how_to_test: "`cp /bin/true /tmp/nn-r009 && sudo systemd-run --wait /tmp/nn-r009` \
                      (root, outside a terminal session).",
        tests: &[
            "agent/src/decision/rules/r009_root_exec_from_user_path.rs::fires_on_root_in_user_path",
            "agent/src/decision/rules/r009_root_exec_from_user_path.rs::\
             sudo_session_at_a_terminal_is_recorded_not_killed",
            "agent/tests/response_privileged_e2e.rs::tmp_dropper_forked_child_dies_with_it",
        ],
        attack_note: "The rule sees the result, root executing a file a user can write, not \
                      the means: T1548 (an abused setuid binary or sudo rule) and T1068 (an \
                      exploit) are the escalations it is evidence of.",
    },
    RuleDoc {
        id: "R010_BinaryInWebroot",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of a file under a web server's document root (`/var/www/`, \
                   `/srv/www/`, `/usr/share/nginx/html/`, `/var/lib/nginx/`, \
                   `/var/lib/apache2/`), judged on the file the kernel executed.",
        false_positives: "A CGI program installed under one of these roots is killed; nothing \
                          exempts it. Interpreted pages (PHP) run their interpreter from \
                          `/usr/bin` and do not match.",
        how_to_test: "`sudo install -m 755 /bin/true /var/www/nn-r010 && /var/www/nn-r010`.",
        tests: &[
            "agent/src/decision/rules/r010_binary_in_webroot.rs::fires_on_each_webroot",
            "agent/src/decision/rules/r010_binary_in_webroot.rs::r010_kills_the_process_tree",
        ],
        attack_note: "",
    },
    RuleDoc {
        id: "R011_KernelModuleTooling",
        severities: &[Severity::High],
        actions: &[
            ResponseAction::KillProcessTree,
            ResponseAction::KillProcess,
            ResponseAction::Log,
        ],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of `insmod`, `modprobe` or `kmod` whose parent is not a kernel \
                   thread (`PF_KTHREAD`, read by the sensor). A copy run from a staging \
                   directory is killed with its tree, the tool elsewhere alone.",
        false_positives: "Kernel-driven loads (a kworker's modprobe at boot or hot-plug) are \
                          exempt. A root exec of the system's tool under a trusted actor of \
                          `process-comm-allowlist` (DKMS under apt or dpkg) is recorded, not \
                          killed; an administrator's manual `modprobe` is killed unless the \
                          tool itself is allowlisted.",
        how_to_test: "`sudo modprobe dummy` (anti-tamper.sh case C16).",
        tests: &[
            "agent/src/decision/rules/r011_kernel_module_tooling.rs::fires_on_kmod_tooling",
            "agent/src/decision/rules/r011_kernel_module_tooling.rs::\
             kmod_tool_under_apt_is_recorded_not_killed",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::\
             process_kernel_module_tooling_trips_r011",
            "deploy/lab/adversarial/anti-tamper.sh::case C16",
        ],
        attack_note: "The tool's exec, not the load itself (R018).",
    },
    RuleDoc {
        id: "R012_SetcapTooling",
        severities: &[Severity::High],
        actions: &[
            ResponseAction::KillProcessTree,
            ResponseAction::KillProcess,
            ResponseAction::Log,
        ],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of `setcap`, which grants file capabilities; a capability spec in \
                   argv is named in the reasoning. A copy run from a staging directory is \
                   killed with its tree.",
        false_positives: "A provisioning tool that sets capabilities is killed unless `setcap` \
                          is allowlisted in `process-comm-allowlist`; under a trusted actor (a \
                          package manager) the system's `setcap` is recorded. A capability set \
                          by any other route is NN-L-FIM-025's.",
        how_to_test: "`setcap` with no argument (the exec alone fires it).",
        tests: &[
            "agent/src/decision/rules/r012_setcap_tooling.rs::fires_on_setcap",
            "agent/src/decision/rules/r012_setcap_tooling.rs::\
             r012_staged_copy_kills_the_process_tree",
        ],
        attack_note: "File capabilities have no sub-technique of their own (T1548.001 is \
                      setuid and setgid): the parent technique.",
    },
    RuleDoc {
        id: "R013_NamespaceEscapeTooling",
        severities: &[Severity::High],
        actions: &[
            ResponseAction::KillProcessTree,
            ResponseAction::KillProcess,
            ResponseAction::Log,
        ],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of `nsenter`, `unshare` or `runc` from outside `/usr/bin`, `/bin`, \
                   `/usr/sbin` and `/sbin`; host-escape flags in argv (`-t`, `--mount`, \
                   `--privileged`, `--net=host`) are named in the reasoning.",
        false_positives: "A container runtime that runs its own `runc` from a non-standard \
                          path (a bundled runtime under `/var/lib` or `/opt`) is killed until \
                          `runc` is allowlisted in `process-comm-allowlist` \
                          (`docs/operator/CONTAINER_HOST_DEPLOY.md`). An empty exec path never \
                          fires.",
        how_to_test: "`cp /usr/bin/unshare ~/unshare && ~/unshare --help`.",
        tests: &[
            "agent/src/decision/rules/r013_namespace_escape_tooling.rs::\
             fires_on_escape_tool_from_nonstandard_path",
            "agent/src/decision/rules/r013_namespace_escape_tooling.rs::\
             r013_staged_copy_kills_the_process_tree",
        ],
        attack_note: "The tool's exec from an odd place is the escape attempt's shape; the \
                      escape itself (a write to the host's namespaces) is not observed.",
    },
    RuleDoc {
        id: "R014_AtBatchScheduling",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of `at` or `batch`, with the time spec from argv; recorded only.",
        false_positives: "Administrators schedule one-shot jobs routinely; every one is \
                          recorded, none acted on. `process-comm-allowlist` silences it.",
        how_to_test: "`echo true | at now + 1 minute` (the `at` package installed).",
        tests: &["agent/src/decision/rules/r014_at_batch_scheduling.rs::fires_on_scheduling_tool"],
        attack_note: "Execution and Persistence, the two tactics of T1053.002 a one-shot job \
                      serves; the job's own run later is an ordinary exec.",
    },
    RuleDoc {
        id: "R015_EncodingToolingServiceUid",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of `base64`, `xxd` or `openssl` by a service account (uid 1..999, \
                   `nobody`, systemd's `DynamicUser=` range); decode or cipher flags in argv \
                   are named. Recorded only.",
        false_positives: "A daemon that legitimately shells out to `openssl` (a certificate \
                          renewal under a service account, a backup script) is recorded; \
                          `process-comm-allowlist` silences it. Root and human users are out of \
                          scope.",
        how_to_test: "`sudo -u nobody base64 /etc/hostname`.",
        tests: &[
            "agent/src/decision/rules/r015_encoding_tooling_service_uid.rs::\
             fires_on_encoder_by_service_uid",
            "agent/src/decision/rules/r015_encoding_tooling_service_uid.rs::\
             nobody_is_service_class",
        ],
        attack_note: "T1027 for an encode, T1140 for a decode (`base64 -d`), T1132 as V2 row \
                      TQ29: the rule sees the encoder's exec, not the data or the channel.",
    },
    RuleDoc {
        id: "R016_DebuggerServiceUid",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of `gdb`, `strace` or `ltrace` by a service account (the class of \
                   R015); an attach to a live process (`-p`, `--pid`) is named. Recorded \
                   only.",
        false_positives: "A crash handler or a CI runner under a system account that runs a \
                          debugger is recorded; `process-comm-allowlist` silences it. Root and \
                          human users are out of scope.",
        how_to_test: "`sudo -u nobody gdb --version` (gdb installed).",
        tests: &[
            "agent/src/decision/rules/r016_debugger_service_uid.rs::\
             fires_on_debugger_by_service_uid",
            "agent/src/decision/rules/r016_debugger_service_uid.rs::\
             argv_attach_pid_enriches_reasoning",
        ],
        attack_note: "The rule's prose named T1622 (Debugger Evasion) until lab PR 221: a \
                      payload detecting a debugger, not running one. What it observes is a ptrace tracer started \
                      by a service account, the tool of T1055.008; a service account traces \
                      only its own processes, so Stealth, not Privilege Escalation. The \
                      ptrace call itself is not seen (V2 row TQ14 stays a known gap).",
    },
    RuleDoc {
        id: "R017_ShellFromNonstandardPath",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of a shell (`comm` `sh`, `bash` or `dash`) from outside the \
                   root-only shell directories (`/bin`, `/usr/bin`, `/usr/local/bin`, \
                   `/usr/sbin`, `/sbin`, `/nix/store`); an inline `-c` payload and the parent \
                   are named.",
        false_positives: "A shell bundled under `/opt` or in a home (a vendored busybox, a \
                          conda environment) is killed unless allowlisted in \
                          `process-comm-allowlist`; under a trusted actor the record replaces \
                          the kill. An empty exec path never fires.",
        how_to_test: "`cp /bin/sh ~/sh && ~/sh -c true`.",
        tests: &[
            "agent/src/decision/rules/r017_shell_from_nonstandard_path.rs::\
             fires_on_shell_from_nonstandard_path",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::\
             process_shell_from_nonstandard_path_trips_r017",
        ],
        attack_note: "",
    },
    RuleDoc {
        id: "R018_KernelModuleLoad",
        severities: &[Severity::Critical, Severity::High, Severity::Medium],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::ModuleLoad],
        data_components: &["DC0031"],
        observes: "A kernel module load (`finit_module`, `init_module`) at the LSM hooks. \
                   Killed: a file outside `/lib/modules`, a path deeper than any module \
                   directory, or a file under it that no package installed and DKMS did not \
                   build, loaded by an unexpected loader. Recorded: a legacy `init_module` \
                   (High), an unreadable path (High), a standard module by an unexpected \
                   loader (Medium).",
        false_positives: "Kernel-driven loads are exempt, and so are `systemd-udevd`, \
                          `systemd-modules-load` and `kmod` (loader or parent) for a module in \
                          a module directory. An administrator who loads a module from a build \
                          directory (`insmod ~/driver.ko`) is killed.",
        how_to_test: "Copy an in-tree module out of the module tree, decompressed, and \
                      `insmod` it from `/tmp` (Critical); `exec -a modprobe` of a renamed \
                      loader for a standard module (anti-tamper.sh case C58, Medium).",
        tests: &[
            "agent/src/decision/rules/r018_kernel_module_load.rs::\
             fire_nonstandard_path_is_critical_killtree",
            "agent/src/decision/rules/r018_kernel_module_load.rs::\
             fire_stdpath_unexpected_loader_is_medium_log",
            "deploy/lab/adversarial/anti-tamper.sh::case C58",
        ],
        attack_note: "",
    },
    // ── a shell on a network socket (lab PR 224, CM-03) ─────────────
    RuleDoc {
        id: "R020_ShellWithSocketStdio",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032", "DC0082"],
        observes: "A shell or interpreter, by exec identity, whose stdin/stdout is an outbound \
                   inet socket (the reverse shell), or an accepted one not handed over by an \
                   inetd-style launcher (the bind shell), or whose parent's stdio is an \
                   outbound socket (the pty-wrapped reverse shell): `sched_process_exec` \
                   reads the new image's fds 0..2 and its parent's. Critical, recorded, \
                   posture ConfirmedIntrusion; the kill of the tree (`KillProcessTree`) is \
                   held behind the per-rule response policy, off by default (a new rule of \
                   lab PR 224).",
        false_positives: "inetd-style services (PID 1 socket activation, inetd, xinetd, \
                          tcpserver), exempt by the launcher's identity; the process allowlist \
                          by identity. Without the optional BTF offsets the stdio is not read \
                          and the rule cannot fire.",
        how_to_test: "`net-check.sh --only MS06`: bash on a /dev/tcp socket, and the Python \
                      pty reverse shell (MS06B), to a loopback listener.",
        tests: &[
            "agent/src/decision/rules/r020_shell_with_socket_stdio.rs::\
             a_shell_on_an_outbound_socket_is_a_critical_reverse_shell",
            "agent/src/decision/rules/r020_shell_with_socket_stdio.rs::\
             a_pty_wrapped_reverse_shell_fires_on_the_shell",
            "deploy/lab/malsim/net-check.sh::MS06",
        ],
        attack_note: "The shell (T1059.004) and its raw channel (T1095), as R006 maps the \
                      tools that set one up.",
    },
    // ── exec quarantine (lab PR 223, experimental, off by default) ──
    RuleDoc {
        id: "NN-L-EXECQ-001_FirstSightQuarantine",
        severities: &[
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ],
        actions: &[
            ResponseAction::Quarantine,
            ResponseAction::KillProcess,
            ResponseAction::Log,
        ],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032", "DC0059"],
        observes: "With --exec-quarantine: an executable never judged before, run from a \
                   guarded location (/tmp, /var/tmp, /dev/shm, a home or world-writable \
                   directory, a memfd, an unlinked file), held by the kernel before its first \
                   instruction (enforce) and judged by the confined scanner (signed hash list, \
                   ELF and script heuristics) and the rules; resumed, or killed and \
                   quarantined. Recorded by the guard's controller, one record per decision.",
        false_positives: "A build or a test suite running new binaries from a home or /tmp: \
                          judged once per identity, resumed when clean (cached), and the \
                          default policy resumes on an expired budget; a suspicious verdict \
                          resumes unless --exec-quarantine-on-suspicious kill.",
        how_to_test: "On a lab guest, `nn-lab.sh execq-check`: copies of /usr/bin/true and \
                      /usr/bin/ls are resumed and cached, the block-listed marker binary is \
                      killed before it writes its marker and quarantined.",
        tests: &[
            "agent/src/execq/controller/tests.rs::a_blocklisted_binary_is_killed_and_quarantined",
            "agent/src/execq/controller/tests.rs::\
             a_clean_new_binary_is_resumed_cached_and_recorded_once",
            "deploy/lab/execq/execq-check.sh::execq check: PASS",
        ],
        attack_note: "User Execution: Malicious File (T1204.002) for what it holds; a script \
                      also names its interpreter's technique (T1059.004, .006, .007, or T1059), \
                      per record.",
    },
    // ── exec policy (lab PR 226, experimental, off by default) ──────
    RuleDoc {
        id: "NN-L-EXECPOL-001_StagingExecDenied",
        severities: &[Severity::High, Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "With --exec-policy: an exec of a file in a staging class (memfd, a deleted \
                   file, /dev/shm, /tmp… per the profile's table) by a caller of a lineage \
                   tier (admin, session, service) the table denies: refused with EACCES \
                   before the exec's point of no return (enforce, High) or recorded as \
                   \"would deny\" (audit, Medium). Recorded by the policy's controller.",
        false_positives: "The desktop profile allows a login session's own staging locations \
                          (AppImage, build trees); `exempt` lines of the signed \
                          exec-policy.local; audit mode first.",
        how_to_test: "`nn-lab.sh malsim-exec-check`: MS-01 (a copy of id in /dev/shm run \
                      from a service) refused in enforce, recorded in audit.",
        tests: &[
            "agent/src/execpol/record.rs::a_denied_exec_is_one_high_record",
            "agent/src/execpol/record.rs::memfd_and_deleted_techniques",
            "deploy/lab/malsim/exec-check.sh::MS-01",
        ],
        attack_note: "Per record: T1620 for a memfd or a deleted file (and T1070.004 for the \
                      deletion), T1204.002 for a staging location, T1564.001 for a hidden \
                      name on the way.",
    },
    RuleDoc {
        id: "NN-L-EXECENV-001_PreloadFromStaging",
        severities: &[Severity::High, Severity::Medium, Severity::Low],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "A loader variable at exec (`LD_PRELOAD`, `LD_AUDIT`) naming a staging \
                   path: refused (enforce) or recorded; a set-id target is recorded (the \
                   kernel sets AT_SECURE and the loader ignores it).",
        false_positives: "A developer's own preload from a build tree in a session (Low).",
        how_to_test: "`nn-lab.sh malsim-exec-check`: MS-32, LD_PRELOAD of a no-op library \
                      from /tmp into a service.",
        tests: &[
            "agent/src/execpol/record.rs::the_preload_record",
            "deploy/lab/malsim/exec-check.sh::MS-32",
        ],
        attack_note: "",
    },
    RuleDoc {
        id: "NN-L-EXECENV-002_ExecEnvironmentTrick",
        severities: &[
            Severity::Critical,
            Severity::Medium,
            Severity::Low,
        ],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The environment of an exec, recorded: `GLIBC_TUNABLES` at a set-id \
                   target (Critical in the shape of CVE-2023-4911), a library path into \
                   staging for a service or root, shell history disabled.",
        false_positives: "History disabled by a user's own shell configuration (Low, repeats \
                          held back).",
        how_to_test: "Run `su` with `GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=A` \
                      on a lab guest with the exec policy on.",
        tests: &["agent/src/execpol/record.rs::tunables_history_and_library_path"],
        attack_note: "Per record: T1068 for the set-id exploit's environment, T1574.006 for \
                      the library path, T1070.003 for the history.",
    },
    RuleDoc {
        id: "NN-L-EXECENV-003_ExecMappingFromStaging",
        severities: &[Severity::High, Severity::Medium, Severity::Low],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "An executable mapping (`mmap_file` with PROT_EXEC) of a file in a staging \
                   class: refused (enforce) or recorded.",
        false_positives: "JIT runtimes mapping their own caches from a session's temporary \
                          directory (recorded, Low).",
        how_to_test: "`dlopen` a library copied to /tmp from a service, with the exec policy \
                      on.",
        tests: &["agent/src/execpol/record.rs::a_mapping_record"],
        attack_note: "T1620 is added for a memfd or a deleted file.",
    },
];
