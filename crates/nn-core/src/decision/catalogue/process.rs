//! The process rules (R001..R018).

use nn_model::{ResponseAction, Severity};

use super::RuleDoc;
use crate::detection_payload::Sensor;

pub(super) const DOCS: &[RuleDoc] = &[
    RuleDoc {
        id: "R001_ExecFromTmp",
        severities: &[Severity::High, Severity::Medium],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of a file under `/tmp/`, judged on the file the kernel executed \
                   (a relative path, a symlink or `..` resolves to it).",
        false_positives: "Lot 283b: a person's exec (an account from `UID_MIN` up with a \
                          login shell) — `go test`'s binaries, `go run`, an AppImage, a build \
                          that runs what it unpacked in `/tmp` — is recorded at High below \
                          COMBAT, killed in COMBAT or under a signed `enforce`. A system \
                          account's exec (below `UID_MIN`, or a `nologin` shell: `www-data`, \
                          `postgres`, `nobody`) is killed in every posture: the whitelist is \
                          empty and the process allowlist does not apply. A root exec is \
                          R009's (R009 runs first; R001's kill of it waits for COMBAT).",
        how_to_test: "As a system account: `sudo -u www-data sh -c 'cp /bin/true /tmp/nn-r001 \
                      && /tmp/nn-r001'` (killed); as the lab user, the same is recorded at High. \
                      Run as root it is R009's verdict.",
        tests: &[
            "crates/nn-core/src/decision/rules/r001_exec_from_tmp.rs::fires_on_exec_from_tmp",
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
            "crates/nn-core/src/decision/rules/r002_exec_from_dev_shm.rs::fires_on_dev_shm",
            "crates/nn-core/src/decision/rules/r002_exec_from_dev_shm.rs::r002_kills_the_process_tree",
        ],
        attack_note: "T1027.011 names `/dev/shm` as fileless storage; T1059 as for R001.",
    },
    RuleDoc {
        id: "R003_ExecFromVarTmp",
        severities: &[Severity::High, Severity::Medium],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of a file under `/var/tmp/`, the temporary directory that survives \
                   a reboot, judged on the file the kernel executed.",
        false_positives: "As R001 (lot 283b): a person's exec from `/var/tmp` is recorded at \
                          High below COMBAT; a system account's (a package scriptlet run as \
                          one) is killed; run as root in a package transaction or an \
                          administrator's session it is R009's Low record.",
        how_to_test: "As an unprivileged user: `cp /bin/true /var/tmp/nn-r003 && \
                      /var/tmp/nn-r003`.",
        tests: &[
            "crates/nn-core/src/decision/rules/r003_exec_from_var_tmp.rs::fires_on_var_tmp",
            "crates/nn-core/src/decision/rules/r003_exec_from_var_tmp.rs::r003_kills_the_process_tree",
        ],
        attack_note: "T1059 as for R001.",
    },
    RuleDoc {
        id: "R004_ExecFromProcSelfFd",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "A fileless exec: a memfd or an unlinked file (an `O_TMPFILE`, a file \
                   opened then deleted), whatever path reached it (lot 310: \
                   `/proc/thread-self/fd/N`, `/proc/<pid>/task/<tid>/fd/N`, `/dev/stdin`, a \
                   relative path, a symlink, `/proc/<pid>/exe` alike), judged on the executed \
                   file's identity: the exec sensor's in LSM mode; in tracepoint mode the \
                   exec pump's read of `/proc/<pid>/exe` while the process lives, else its \
                   path, read by the posture's one reader of a `/proc` link \
                   (`/proc/<pid>[/task/<tid>]/fd/N`, `map_files/`, `/dev/fd/N`, `/dev/std*`, \
                   `/proc/<pid>/root/…` chains, `..` folded) or `/memfd:`.",
        false_positives: "systemd-executor's launch of every unit (systemd 254 and later) is a \
                          linked file, not fileless; after a systemd upgrade PID 1 launches \
                          from the old, unlinked executor until its re-exec, exempt by that \
                          file's identity: a copy the host's PID 1 holds by that identity \
                          alone (an inode no user can reach); the packaged file at its \
                          install path or a copy a genuine user manager holds (its image the \
                          packaged manager's, in PID 1's mount namespace) for the first exec \
                          of a process PID 1 or such a manager forked (the kernel's record \
                          at sched_process_fork, never the parent at exec time) — re-read \
                          every 10 s and replaced, never by its name or `argv[0]`. A \
                          process re-executing the very image its parent runs \
                          (`/proc/self/exe` after an upgrade unlinked it: Chromium's \
                          children, Docker's `reexec`) is not fileless when that image was \
                          executed from a directory only root can write, in PID 1's mount \
                          namespace (parents running at the agent's start included); a \
                          user's dropped binary that unlinks and re-executes itself is \
                          killed. Another program that re-executes itself from a memfd \
                          (older runc versions do, to protect their binary), or that execs a \
                          file at the instant an upgrade unlinks it, is killed: nothing else \
                          is exempt.",
        how_to_test: "`python3 -c 'import os; fd = os.memfd_create(\"x\"); \
                      os.write(fd, open(\"/bin/true\", \"rb\").read()); \
                      os.execv(\"/proc/self/fd/%d\" % fd, [\"x\"])'`.",
        tests: &[
            "crates/nn-core/src/decision/rules/r004_exec_from_proc_self_fd.rs::fires_on_proc_self_fd",
            "crates/nn-core/src/decision/rules/r004_exec_from_proc_self_fd.rs::\
             fires_on_a_memfd_whatever_path_reached_it",
            "crates/nn-core/src/decision/rules/r004_exec_from_proc_self_fd.rs::\
             bug88_other_spellings_the_report_fix_still_misses",
            "crates/nn-core/src/decision/rules/r004_exec_from_proc_self_fd.rs::\
             a_dropped_binary_that_unlinks_and_reexecutes_itself_is_killed",
            "crates/nn-core/src/decision/rules/r004_exec_from_proc_self_fd.rs::\
             the_executor_is_a_child_s_first_exec",
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
        tests: &["crates/nn-core/src/decision/rules/r005_netcat_exec.rs::fires_on_each_netcat_alias"],
        attack_note: "T1095 for netcat's use as a raw TCP/UDP channel (a reverse or bind \
                      shell); the rule sees the name only, not the connection.",
    },
    RuleDoc {
        id: "R006_ReverseShellTooling",
        severities: &[Severity::Critical, Severity::High],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "An exec of offensive tooling (`socat`, `msfvenom`, `meterpreter`, \
                   `sliver`, `havoc`), by its `comm` or the kernel's executed file (a link \
                   under another name). The distribution's `socat` — placed by the kernel's \
                   executed file, never the caller's string — is recorded unless one of its \
                   addresses runs a shell (lot 313: each address of a dual `a!!b` or a chain, \
                   read as socat's lexer reads it — `\\` and quotes dropped; `SYSTEM:` and \
                   `SHELL:` always; `EXEC:` past `env` (`-S` too), `setsid`, `nohup`, \
                   `stdbuf`, `timeout`, `sudo -i`, `su`, `chroot`, the dynamic loader and the \
                   like, a shell, `script`, or an interpreter running inline code), and \
                   recorded at Critical when the kernel cut its argv. A shell or an \
                   interpreter (by identity) that socat starts, directly or through a launcher \
                   that forks, is killed too: what an address ran, whatever its spelling.",
        false_positives: "A `socat` from `/usr/bin`, `/bin`, `/usr/sbin` or `/sbin` used as a \
                          relay is recorded (Log, High), not killed; a build of it elsewhere is \
                          killed unless allowlisted in `process-comm-allowlist`, which is \
                          judged on what the kernel executed. Lot 313: a `SYSTEM:` address \
                          runs `/bin/sh -c` and is killed whatever its command (a test \
                          harness's `SYSTEM:'echo …'` server too), and so is a shell or an \
                          interpreter socat starts (`EXEC:python3 /srv/app.py`): allowlist \
                          socat by identity where a harness needs one.",
        how_to_test: "`cp /bin/sleep /tmp/sliver && /tmp/sliver 5` (killed); `socat -V` \
                      (the distribution's socat, recorded); `socat TCP:127.0.0.1:9 \
                      STDIO!!EXEC:/bin/sh` (killed).",
        tests: &[
            "crates/nn-core/src/decision/rules/r006_reverse_shell_tooling.rs::fires_on_each_offsec_tool",
            "crates/nn-core/src/decision/rules/r006_reverse_shell_tooling.rs::\
             r006_system_socat_is_recorded_a_copy_is_killed",
            "crates/nn-core/src/decision/rules/r006_reverse_shell_tooling.rs::\
             r006_system_socat_running_a_shell_is_killed",
            "crates/nn-core/src/decision/rules/r006_reverse_shell_tooling.rs::\
             bug112_dual_address_running_a_shell_is_killed",
        ],
        attack_note: "The tools are C2 frameworks and a relay: T1095 for the raw TCP channel, \
                      T1059.004 for the shell `socat EXEC:` runs. The rule sees the name and \
                      argv, not the traffic; a renamed copy of a tool evades it.",
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
            "crates/nn-core/src/decision/rules/r007_crypto_miner.rs::fires_on_known_miner_comms",
            "crates/nn-core/src/decision/rules/r007_crypto_miner.rs::r007_substring_only_is_recorded",
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
            "crates/nn-core/src/decision/rules/r008_hidden_home_binary.rs::fires_on_unknown_dot_directory",
            "crates/nn-core/src/decision/rules/r008_hidden_home_binary.rs::autostart_dir_is_never_exempt",
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
        false_positives: "An administrator's sudo/su session at a terminal, a package \
                          transaction (a package manager run by root whose run covers the exec) \
                          and the process tree of the installer a trusted-installer window was \
                          granted to (by lineage from that process, after the grant, while the \
                          window is open: install.sh, uninstall.sh) are recorded at Low. Root \
                          automation outside them (a root cron job, a configuration-management \
                          run or a CI job that executes a file from a home or `/tmp`, the \
                          installer's own exec) is recorded at High; the kill of its tree runs \
                          only in COMBAT, or in every posture under a signed `enforce R009` \
                          (lot 278).",
        how_to_test: "`cp /bin/sleep /tmp/nn-r009 && sudo systemd-run --wait /tmp/nn-r009 1` \
                      (root, outside a terminal session): a High record, the kill held below \
                      COMBAT.",
        tests: &[
            "crates/nn-core/src/decision/rules/r009_root_exec_from_user_path.rs::fires_on_root_in_user_path",
            "crates/nn-core/src/decision/rules/r009_root_exec_from_user_path.rs::\
             sudo_session_at_a_terminal_is_recorded_not_killed",
            "crates/nn-core/src/decision/rules/r009_root_exec_from_user_path.rs::\
             the_installer_s_own_tree_is_recorded_inside_its_window",
            "crates/nn-core/src/decision/posture_floor.rs::r009_kills_in_combat_only",
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
            "crates/nn-core/src/decision/rules/r010_binary_in_webroot.rs::fires_on_each_webroot",
            "crates/nn-core/src/decision/rules/r010_binary_in_webroot.rs::r010_kills_the_process_tree",
        ],
        attack_note: "",
    },
    RuleDoc {
        id: "R011_KernelModuleTooling",
        severities: &[Severity::High, Severity::Medium, Severity::Low],
        actions: &[
            ResponseAction::KillProcessTree,
            ResponseAction::KillProcess,
            ResponseAction::Log,
        ],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The exec of `insmod`, `modprobe` or `kmod` whose parent is not a kernel \
                   thread (`PF_KTHREAD`, read by the sensor), judged on its command line's \
                   syntax and on what the exec pump reads at the exec (lot 279). Killed: \
                   `insmod`; a `modprobe` argument with a `/` or a `.ko*` suffix; \
                   `-C`/`-d`/`-S`/`--force*`/`-o`/`--remove-holders`/`--remove-dependencies` \
                   (and their abbreviations); any argument starting with `-` after the first \
                   module name; a `kmod` command that is not `help`/`list`/`static-nodes`/the \
                   version; a program that is not the system's tool (its path; its device and \
                   inode not those of the file `/usr/bin/kmod` resolves to; `/usr/bin/kmod` \
                   and `/bin/kmod` two different files), of another mount namespace; \
                   `MODPROBE_OPTIONS`, `LD_PRELOAD`, `LD_AUDIT` or `LD_LIBRARY_PATH` in its \
                   environment (read: killed even if the process has since exited — \
                   evidence; a leader that exited while a thread runs on is read through that \
                   thread, refused when none is read whole), a running process's environment \
                   not read, over 1 MiB, an unknown \
                   start; an argv not read whole. Recorded \
                   otherwise: the system's tool by module name, nothing moved or forced — no \
                   `modprobe.d` or index is read, what the names load is the kernel's to judge \
                   (its signature policy; R018's verdict on the load it reports, after it, \
                   where R018 gives one) — Low when run by root with its environment read \
                   clean (lot 290; High before: a lab round left 369 such lines), Medium \
                   when run by root but exited before its environment could be read (lot \
                   340: a module already loaded or built in), High otherwise. A process that \
                   had exited before its environment \
                   could be read is recorded, its environment not verified (its kill would \
                   reach no one): the environment's check is best effort for a short-lived \
                   `modprobe`. A copy run from a staging directory is killed with its tree, \
                   the tool elsewhere alone. Lot 285: a child of the module tool (the command \
                   of a `modprobe.d` `install`/`remove` directive, `/bin/sh -c …`) is recorded \
                   (Medium).",
        false_positives: "Kernel-driven loads (a kworker's modprobe at boot or hot-plug) are \
                          exempt. The container runtimes', kube-proxy's and an administrator's \
                          `modprobe <name>` are recorded, not killed (lot 279), and so is a \
                          root exec of the system's tool under a trusted actor of \
                          `process-comm-allowlist` (DKMS under apt or dpkg); in an initramfs \
                          build (the packaged `update-initramfs`, `mkinitramfs` or `dracut` run \
                          by root, read by the exec pump; lot 287), the hook `kmod` and \
                          modprobe's dry runs (`--show-depends`, `--dry-run`, `-S` beside them) \
                          are recorded too. Killed still: an administrator's `insmod` of a built \
                          module, a `modprobe -S` that may load, a quiet probe written \
                          `modprobe <name> -q`, a module parameter with a `/`, a `modprobe` run \
                          from a shell whose environment sets `LD_LIBRARY_PATH` (or \
                          `LD_PRELOAD`, `LD_AUDIT`), and every module tool's exec on a host \
                          whose `/usr/bin/kmod` and `/bin/kmod` are two different files.",
        how_to_test: "`sudo modprobe dummy` (recorded; anti-tamper.sh case C16); \
                      `deploy/lab/malsim/kmod-check.sh` (the benign corpus recorded, the \
                      malicious shapes killed).",
        tests: &[
            "crates/nn-core/src/decision/rules/r011_kernel_module_tooling.rs::fires_on_kmod_tooling",
            "crates/nn-core/src/decision/rules/r011_kernel_module_tooling.rs::\
             modprobe_by_name_is_recorded_not_killed",
            "crates/nn-core/src/decision/rules/r011_kernel_module_tooling.rs::\
             a_plain_root_modprobe_is_low_and_the_suspicious_keep_high",
            "crates/nn-core/src/decision/rules/r011_kernel_module_tooling.rs::\
             what_the_command_line_names_is_killed",
            "crates/nn-core/src/decision/rules/r011_kernel_module_tooling.rs::\
             r011_records_the_children_of_modprobe",
            "crates/nn-core/src/decision/rules/r011_kernel_module_tooling.rs::\
             what_the_exec_pump_read_is_judged",
            "crates/nn-core/src/decision/rules/r011_kernel_module_tooling.rs::\
             an_exec_whose_process_exited_before_its_environment_was_read_is_recorded_noting_it",
            "crates/nn-core/src/decision/rules/r011_kernel_module_tooling.rs::\
             kmod_tool_under_apt_is_recorded_not_killed",
            "crates/nn-linux/src/sensors/kmod_exec.rs::\
             the_environment_is_read_from_the_exec_s_process",
            "crates/nn-linux/src/sensors/kmod_exec.rs::\
             a_running_process_s_unreadable_environment_is_refused_an_exited_one_s_is_not",
            "crates/nn-linux/src/sensors/kmod_exec.rs::what_was_read_is_judged",
            "crates/nn-linux/src/sensors/kmod_exec.rs::\
             a_leader_that_exited_while_its_thread_runs_has_not_exited",
            "crates/nn-linux/src/sensors/kmod_exec.rs::\
             a_relay_of_threads_after_its_leader_exited_is_never_an_exit",
            "crates/nn-linux/src/sensors/kmod_exec.rs::\
             the_program_is_the_system_s_tool_by_device_and_inode",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::\
             process_kernel_module_tooling_trips_r011",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::\
             r011_records_a_packaged_modprobe_and_kills_an_insmod_from_tmp",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::\
             r011_records_a_name_and_kills_a_moved_tree_or_modprobe_options",
            "deploy/lab/adversarial/anti-tamper.sh::case C16",
        ],
        attack_note: "The tool's exec, judged on its syntax and its environment; the load \
                      itself is the kernel's to judge, and R018's after it.",
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
            "crates/nn-core/src/decision/rules/r012_setcap_tooling.rs::fires_on_setcap",
            "crates/nn-core/src/decision/rules/r012_setcap_tooling.rs::\
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
        false_positives: "Lot 283b: a container runtime's own `runc` from a non-standard path \
                          (k3s' `/var/lib/rancher/k3s/data/<hash>/bin/runc`, a bundle under \
                          `/opt`) is recorded at High, its kill held behind a switch a signed \
                          `enforce` turns on; allowlisting `runc` in `process-comm-allowlist` \
                          silences it (`docs/operator/CONTAINER_HOST_DEPLOY.md`). A copied \
                          `nsenter` or `unshare` is killed. An empty exec path never fires.",
        how_to_test: "`cp /usr/bin/unshare ~/unshare && ~/unshare --help`.",
        tests: &[
            "crates/nn-core/src/decision/rules/r013_namespace_escape_tooling.rs::\
             fires_on_escape_tool_from_nonstandard_path",
            "crates/nn-core/src/decision/rules/r013_namespace_escape_tooling.rs::\
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
        tests: &["crates/nn-core/src/decision/rules/r014_at_batch_scheduling.rs::fires_on_scheduling_tool"],
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
            "crates/nn-core/src/decision/rules/r015_encoding_tooling_service_uid.rs::\
             fires_on_encoder_by_service_uid",
            "crates/nn-core/src/decision/rules/r015_encoding_tooling_service_uid.rs::\
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
            "crates/nn-core/src/decision/rules/r016_debugger_service_uid.rs::\
             fires_on_debugger_by_service_uid",
            "crates/nn-core/src/decision/rules/r016_debugger_service_uid.rs::\
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
            "crates/nn-core/src/decision/rules/r017_shell_from_nonstandard_path.rs::\
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
        observes: "A kernel module load (`finit_module`, `init_module`) at the LSM hooks, judged \
                   IN THE KERNEL by the file (lot 285): a file of the running kernel's tree that \
                   a verified package installed or DKMS built, unchanged since boot or written \
                   since inside a package transaction, or named by a signed `module-allow`, \
                   loads; any other file and every `init_module` buffer are refused outside a \
                   signed trusted-installer window in the deny mode (the default), let through \
                   in the record mode (`alert R018`). A DKMS or akmods build in \
                   `updates/dkms/` or `extra/` whose content is the registered build (DKMS's \
                   copy, the package's digest), written since boot outside a recognised package \
                   transaction (dnf's and yum's scripts recognised by the file their exec \
                   named), is let through and recorded High under every policy but `enforce \
                   R018`, which refuses it; a file of those directories nothing vouches for is \
                   refused. Who loads is not asked. Killed: a file outside `/lib/modules` or \
                   deeper than any module directory, refused or not. Recorded: any other \
                   untrusted file or buffer, an unattested DKMS or akmods build (High), a load \
                   a window or an opt-out let through (Medium); a load the kernel did not judge \
                   (the agent's first seconds) by the path and the package database — a path \
                   with a component the sensor read only in part (31 bytes, marked …) is \
                   unverifiable, High (lot 292).",
        false_positives: "None measured on the benign corpus (lot 285: udev's and the services' \
                          loads, docker's, k3s', a DKMS build under apt). A module built by \
                          hand outside the DKMS and akmods directories (`make \
                          modules_install`), a vendor's installer outside the package manager \
                          and a module of the tree written after boot before the agent started \
                          are refused until a signed `module-allow <module>` (or the next boot); \
                          a registered DKMS or akmods build written outside a package \
                          transaction (a root shell's `dkms install`, `akmods` at boot) is let \
                          through, recorded High; an administrator who loads a module from a \
                          build directory (`insmod ~/driver.ko`) is refused and killed.",
        how_to_test: "Copy an in-tree module to `/tmp` and `insmod` it: refused (EPERM), \
                      Critical, the loader killed; a renamed loader of a trusted module \
                      (anti-tamper.sh case C58) loads with no record, its copy in `/tmp` \
                      (C58b) is refused.",
        tests: &[
            "common/src/module_judge.rs::an_untrusted_module_file_outside_the_tree_is_denied",
            "agent/src/module_trust/scan.rs::a_copy_of_a_trusted_module_in_tmp_is_denied",
            "common/src/module_judge.rs::\
             a_trusted_module_modified_after_boot_is_denied_outside_a_window",
            "common/src/module_judge.rs::init_module_from_memory_is_denied",
            "agent/src/module_trust/scan.rs::a_dkms_module_under_a_package_transaction_is_allowed",
            "crates/nn-core/src/decision/rules/r018_kernel_module_load.rs::\
             a_signed_per_module_opt_out_is_allowed_and_recorded",
            "crates/nn-core/src/decision/rules/r018_kernel_module_load.rs::\
             r018_comm_allowlist_removed",
            "crates/nn-core/src/decision/rules/r018_kernel_module_load.rs::\
             fire_nonstandard_path_is_critical_killtree",
            "crates/nn-core/src/decision/rules/r018_kernel_module_load.rs::\
             a_cut_component_is_not_the_packaged_module_it_starts_like",
            "deploy/lab/adversarial/anti-tamper.sh::case C58",
        ],
        attack_note: "",
    },
    // ── a shell on a network socket (lab PR 224, CM-03) ─────────────
    RuleDoc {
        id: "R020_ShellWithSocketStdio",
        severities: &[Severity::Critical, Severity::High],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032", "DC0082"],
        observes: "A shell or interpreter, by exec identity (lot 313: a copy of an installed \
                   shell or interpreter under any name, found by the exec pump's bounded \
                   content check; an installed one by its device and inode; else the executed \
                   file's name; busybox by the program its argv names, `busybox sh`, `-sh`; \
                   the program the dynamic loader runs, `ld.so /bin/bash`), whose \
                   stdin/stdout is an outbound \
                   inet socket (the reverse shell), or an accepted one not handed over by an \
                   inetd-style launcher (the bind shell), or whose parent's stdio is an \
                   outbound socket (the pty-wrapped reverse shell): `sched_process_exec` \
                   reads the new image's fds 0..2 and its parent's. Critical, recorded, \
                   posture ConfirmedIntrusion; the kill of the tree (`KillProcessTree`) is \
                   held behind the per-rule response policy, off by default (a new rule of \
                   lab PR 224). Lot 313: an exec of a user-writable image on such a socket \
                   whose content check the exec pump's budget skipped is recorded High, \
                   \"identity unverified\".",
        false_positives: "inetd-style services (PID 1 socket activation, inetd, xinetd, \
                          tcpserver), exempt by the launcher's identity; the process allowlist \
                          by identity. Without the optional BTF offsets the stdio is not read \
                          and the rule cannot fire.",
        how_to_test: "`net-check.sh --only MS06`: bash on a /dev/tcp socket, and the Python \
                      pty reverse shell (MS06B), to a loopback listener.",
        tests: &[
            "crates/nn-core/src/decision/rules/r020_shell_with_socket_stdio.rs::\
             a_shell_on_an_outbound_socket_is_a_critical_reverse_shell",
            "crates/nn-core/src/decision/rules/r020_shell_with_socket_stdio.rs::\
             a_pty_wrapped_reverse_shell_fires_on_the_shell",
            "crates/nn-core/src/decision/rules/r020_shell_with_socket_stdio.rs::\
             n1_a_renamed_copy_of_a_shell_is_a_shell",
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
        severities: &[Severity::High, Severity::Medium, Severity::Low],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "With --exec-policy: an exec of a file in a staging class (memfd, a deleted \
                   file, /dev/shm, /tmp… per the profile's table) by a caller of a lineage \
                   tier (admin, session, service) the table denies: refused with EACCES \
                   before the exec's point of no return (enforce, High) or recorded as \
                   \"would deny\" (audit, Medium). Recorded by the policy's controller. Lot \
                   325: with the exec guards' per-task buffers full (a flood of execs in \
                   flight) an exec is judged without its walk — a protected target refused, \
                   every other exec let through and recorded (Low).",
        false_positives: "The desktop profile allows a login session's own staging locations \
                          (AppImage, build trees); `exempt` lines of the signed \
                          exec-policy.local; audit mode first.",
        how_to_test: "`nn-lab.sh malsim-exec-check`: MS-01 (a copy of id in /dev/shm run \
                      from a service) refused in enforce, recorded in audit.",
        tests: &[
            "agent/src/execpol/record.rs::a_denied_exec_is_one_high_record",
            "agent/src/execpol/record.rs::memfd_and_deleted_techniques",
            "agent/src/execpol/record.rs::an_exec_judged_without_its_walk_is_recorded",
            "deploy/lab/malsim/exec-check.sh::MS-01",
        ],
        attack_note: "Per record: T1620 for a memfd or a deleted file (and T1070.004 for the \
                      deletion), T1204.002 for a staging location, T1564.001 for a hidden \
                      name on the way.",
    },
    RuleDoc {
        id: "NN-L-EXECENV-001_PreloadFromStaging",
        severities: &[
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "A loader variable at exec (`LD_PRELOAD`, `LD_AUDIT`) naming a staging \
                   path: refused (enforce) for the tiers whose rule denies, a set-id target \
                   as any other (lot 318: the policy does not count on AT_SECURE), or \
                   recorded; a set-id target recorded says whether the loader ignores the \
                   entry (the exec changes the credentials: AT_SECURE) or honours it (root \
                   running a set-uid-root file changes none). Lot 325: every variable is \
                   read (it was the first 64) and every occurrence judged; the new image's \
                   environment, the kernel's own copy, is read again past the exec's point \
                   of no return — an entry seen only there is the environment changed after \
                   the copy, and the image is killed before its first instruction where the \
                   tier refuses it (Critical).",
        false_positives: "A developer's own preload from a build tree in a session (Low).",
        how_to_test: "`nn-lab.sh malsim-exec-check`: MS-32, LD_PRELOAD of a no-op library \
                      from /tmp into a service.",
        tests: &[
            "agent/src/execpol/record.rs::the_preload_record",
            "agent/src/execpol/record.rs::a_preload_seen_only_in_the_kernel_s_copy_is_the_environment_changed",
            "deploy/lab/malsim/exec-check.sh::MS-32",
        ],
        attack_note: "",
    },
    RuleDoc {
        id: "NN-L-EXECENV-002_ExecEnvironmentTrick",
        severities: &[
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
        ],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Exec],
        data_components: &["DC0032"],
        observes: "The environment of an exec, recorded: `GLIBC_TUNABLES` at a set-id \
                   target (Critical in the shape of CVE-2023-4911), a library path into \
                   staging for a service or root, shell history disabled; an environment \
                   the exec sensor could not read whole (High: its loader variables \
                   were not judged); lot 325: one the scan could not finish, more \
                   variables than any the kernel accepts, or a loader variable's value \
                   longer than the check reads (High; refused at a protected or set-id \
                   target).",
        false_positives: "History disabled by a user's own shell configuration (Low, repeats \
                          held back).",
        how_to_test: "Run `su` with `GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=A` \
                      on a lab guest with the exec policy on.",
        tests: &[
            "agent/src/execpol/record.rs::tunables_history_and_library_path",
            "agent/src/execpol/record.rs::an_environment_not_read_whole_is_one_high_record",
            "agent/src/execpol/record.rs::an_environment_the_scan_could_not_finish_is_one_high_record",
            "agent/src/execpol/record.rs::a_loader_value_longer_than_its_capture_is_not_judged_whole",
        ],
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
