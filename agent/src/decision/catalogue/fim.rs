//! The file integrity and file access rules (NN-L-FIM-001..025).

use common::{ResponseAction, Severity};

use super::RuleDoc;
use crate::detection_store::Sensor;

pub(super) const DOCS: &[RuleDoc] = &[
    RuleDoc {
        id: "NN-L-FIM-001_SystemBinaryModified",
        severities: &[Severity::Critical, Severity::Low],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0061", "DC0059"],
        observes: "A rewrite of a watched file under /bin, /sbin, /usr/bin, /usr/sbin or /usr/lib, \
            or a permission or ownership change there that hands out power over it (a set-id bit, \
            write for group or others, a new owner).",
        false_positives: "Package upgrades rewrite these files: a write inside a package \
            transaction (dpkg, rpm or dnf lineage, kernel-resolved) is recorded at Low. A change \
            that only takes power away (chmod u-s) draws no verdict. A hand-built `make install` \
            into /usr is killed.",
        how_to_test: "`sudo chmod g+w /usr/bin/curl` (a watched binary), then `sudo chmod g-w \
            /usr/bin/curl`; expect Critical, KillProcessTree aimed at chmod.",
        tests: &[
            "agent/src/fim/rules.rs::fim001_fires_on_system_binary_modified",
            "agent/src/fim/rules.rs::a_set_uid_bit_on_a_system_binary_is_killed_its_removal_is_not",
            "agent/src/fim/rules.rs::package_manager_writes_are_logged_not_killed",
        ],
        attack_note: "T1554 for a rewritten binary, T1548.001 for a set-id bit granted on one. A \
            supply-chain compromise (T1195) happens upstream; the host sees the file change.",
    },
    RuleDoc {
        id: "NN-L-FIM-002_NewSuidBinary",
        severities: &[Severity::Critical, Severity::Medium, Severity::Low],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0039"],
        observes: "A hard link, in /tmp, /var/tmp, /dev/shm or /home, to a watched inode (the \
            kernel reports a link only when its source is watched, such as a setuid-root system \
            binary): Critical. A file created in a watched directory there is recorded (Medium, \
            Log): the hook carries no mode bits.",
        false_positives: "Files that browsers, GnuPG or SDKs create in watched home paths are only \
            recorded (external audit FIMR-006). A link made inside a package transaction is \
            recorded at Low.",
        how_to_test: "`sudo ln /usr/bin/passwd /var/tmp/nn-link` (on the filesystem of /usr), then \
            `sudo rm /var/tmp/nn-link`; expect Critical, KillProcessTree aimed at ln.",
        tests: &[
            "agent/src/fim/rules.rs::fim002_kills_a_watched_inode_linked_into_a_user_writable_dir",
            "agent/src/fim/rules.rs::fim002_records_a_file_created_in_a_watched_user_writable_dir",
        ],
        attack_note: "T1548.001: a setuid binary kept under a name a user controls. The rule does \
            not see a set-id bit itself; NN-L-FIM-001 and NN-L-FIM-025 do.",
    },
    RuleDoc {
        id: "NN-L-FIM-003_SensitiveConfigModified",
        severities: &[Severity::High, Severity::Low],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0061", "DC0059"],
        observes: "A rewrite of /etc/passwd, /etc/shadow, /etc/sudoers, /etc/ssh/sshd_config, \
            /etc/pam.d/sshd or /etc/pam.d/sudo, or a permission or ownership change of one that \
            grants power or exposes its content (chmod o+r /etc/shadow).",
        false_positives: "Account administration writes these files. An account tool (passwd, \
            useradd, chpasswd, systemd-sysusers and the rest, by kernel-resolved exe) is recorded, \
            at Low when a non-root user ran it; a write in an administrator's interactive sudo or \
            su session is recorded at High; a package transaction at Low. A \
            configuration-management run without a terminal is killed.",
        how_to_test: "`sudo systemd-run --wait chmod o+r /etc/shadow`, then `sudo chmod o-r \
            /etc/shadow` (systemd-run: no terminal, so the interactive-admin carve-out does not \
            apply); expect High, KillProcess.",
        tests: &[
            "agent/src/fim/rules.rs::fim003_fires_on_sensitive_config_modified",
            "agent/src/fim/rules.rs::shadow_made_readable_by_others_is_a_sensitive_change",
            "agent/src/fim/rules.rs::account_tools_are_recorded_not_killed",
        ],
        attack_note: "One technique per file: passwd and shadow are T1098 (an account changed) and \
            T1136.001 (a local account added), the two PAM files T1556.003, sudoers T1548.003; \
            sshd_config has none of its own. A read of shadow (T1003.008) is not this rule's: it \
            fires on a write or a permission change.",
    },
    RuleDoc {
        id: "NN-L-FIM-004_AuthorizedKeysModified",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcess],
        sensors: &[Sensor::File],
        data_components: &["DC0061", "DC0039", "DC0059"],
        observes: "A new or edited file sshd reads public keys from (~/.ssh/authorized_keys, \
            ~/.ssh/authorized_keys2, /etc/ssh/authorized_keys, /etc/ssh/authorized_keys/<user>), \
            or one handed to another owner or made writable by group or others.",
        false_positives: "No carve-out: an administrator adding a key by hand or with ssh-copy-id \
            is killed after the write (the key stays). fim-paths.v1 watches root's files and \
            /etc/ssh's; a user's home needs an entry in fim-paths.local.",
        how_to_test: "`echo ssh-ed25519 AAAA nn-test | sudo tee -a /root/.ssh/authorized_keys` \
            (the file must exist when the agent starts); expect High, KillProcess aimed at tee. \
            Remove the line afterwards.",
        tests: &[
            "agent/src/fim/rules.rs::fim004_fires_on_authorized_keys_modified",
            "agent/src/fim/rules.rs::fim004_fires_on_authorized_keys2_and_etc_ssh_forms",
            "agent/src/fim/rules.rs::an_authorized_keys_file_handed_to_another_owner_fires",
        ],
        attack_note: "A new authorized_keys file created in a watched directory under /home is \
            recorded by NN-L-FIM-002 (Medium, Log), which the engine evaluates first; an edit of \
            an existing one, and any write under /root or /etc/ssh, is this rule's.",
    },
    RuleDoc {
        id: "NN-L-FIM-005_LogTruncated",
        severities: &[Severity::High],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0061"],
        observes: "A rewrite of a watched file under /var/log or /var/audit (fim-paths.v1: \
            auth.log, secure, syslog, messages, kern.log, audit/audit.log); the drift record says \
            whether it shrank. wtmp, btmp and lastlog are left to NN-L-FIM-018 and -019.",
        false_positives: "Logrotate and any other writer of a watched log fire it, which is why it \
            only records. rsyslogd's own append (its exe, the syslog uid, the file grown) is \
            exempt; its truncation is not.",
        how_to_test: "`echo nn-test | sudo tee -a /var/log/syslog` (/var/log/messages on the RHEL \
            family), a writer other than rsyslogd; expect High, Log.",
        tests: &[
            "agent/src/fim/rules.rs::fim005_fires_on_log_modification_but_logs_only",
            "agent/src/fim/rules.rs::fim005_rsyslogd_truncation_still_fires",
            "agent/src/fim/rules.rs::fim005_non_rsyslogd_writer_still_fires",
        ],
        attack_note: "T1685.006 (Clear Linux or Mac System Logs), which ATT&CK v19 made of \
            T1070.002, now revoked. A write to the Linux audit log is also T1685.004; the rule \
            does not tell it from another log.",
    },
    RuleDoc {
        id: "NN-L-FIM-006_OperatorBinaryModified",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0061"],
        observes: "A rewrite of a watched file under /usr/local/bin, /usr/local/sbin or /opt.",
        false_positives: "Every upgrade of locally installed software fires it, hence a Medium \
            record only. fim-paths.v1 watches none of these paths: the rule sees what the operator \
            lists in fim-paths.local.",
        how_to_test: "Add an existing file, /usr/local/bin/nn-test, to \
            /etc/northnarrow/fim-paths.local, restart the agent, then `echo x | sudo tee -a \
            /usr/local/bin/nn-test`; expect Medium, Log.",
        tests: &["agent/src/fim/rules.rs::fim006_fires_on_operator_binary_modified"],
        attack_note: "T1554, as NN-L-FIM-001, for the binaries outside the distribution's trees.",
    },
    RuleDoc {
        id: "NN-L-FIM-007_CronDropInCreated",
        severities: &[Severity::High, Severity::Low],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0039", "DC0061"],
        observes: "A new or rewritten cron entry: a file under /etc/cron.d, /etc/cron.hourly, \
            /etc/cron.daily, /etc/cron.weekly, /etc/cron.monthly or /var/spool/cron, or \
            /etc/crontab itself. The several events of one crontab install or editor save draw one \
            verdict; a second drop-in by the same process draws another.",
        false_positives: "A package transaction is recorded at Low, and a write in an \
            administrator's interactive sudo or su session (`sudo crontab -e`) at High. A user's \
            own `crontab -e` is killed after the write (the entry stays).",
        how_to_test: "`sudo systemd-run --wait cp /dev/null /etc/cron.d/nn-test`, then remove the \
            file; expect High, KillProcess aimed at cp.",
        tests: &[
            "agent/src/fim/rules.rs::fim007_fires_on_cron_dropin_created_or_modified",
            "agent/src/fim/rules.rs::fim007_two_distinct_dropins_fire_twice",
            "agent/src/fim/rules.rs::package_manager_writes_are_logged_not_killed",
        ],
        attack_note: "Persistence only: a drop-in under /etc/cron.d already needs root, and a \
            user's crontab runs as that user.",
    },
    RuleDoc {
        id: "NN-L-FIM-008_KernelModuleModified",
        severities: &[Severity::Critical, Severity::Low],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0039", "DC0061"],
        observes: "A new or rewritten file under /lib/modules: a dropped or modified .ko.",
        false_positives: "Kernel and DKMS package transactions write here and are recorded at Low; \
            a module built and installed by hand (`make modules_install`) is killed.",
        how_to_test: "`sudo touch /lib/modules/$(uname -r)/nn-test.ko`, then remove it; expect \
            Critical, KillProcessTree aimed at touch.",
        tests: &[
            "agent/src/fim/rules.rs::fim008_fires_on_kmod_modified",
            "agent/src/fim/rules.rs::bug022_created_kmod_and_truncated_suffix_rules_fire",
        ],
        attack_note: "The file on disk; R018_KernelModuleLoad sees the load. T1014 because a \
            dropped module is the usual vehicle of a kernel rootkit; the rule does not see what \
            the module does.",
    },
    RuleDoc {
        id: "NN-L-FIM-009_SystemdUnitDropped",
        severities: &[Severity::High, Severity::Low],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0039", "DC0061"],
        observes: "A new or rewritten file under /etc/systemd/system, /lib/systemd/system or \
            /usr/lib/systemd/system: a unit or a drop-in, a .timer included.",
        false_positives: "Package transactions are recorded at Low; `sudo systemctl edit` and \
            other writes in an interactive sudo or su session at High; the agent's own units, \
            written while the operator's trusted-installer window is open, at Low.",
        how_to_test: "`sudo systemd-run --wait cp /dev/null /etc/systemd/system/nn-test.service`, \
            then remove it; expect High, KillProcess aimed at cp.",
        tests: &[
            "agent/src/fim/rules.rs::fim009_fires_on_systemd_unit_dropped_or_modified",
            "agent/src/fim/rules.rs::fim009_downgrades_own_unit_under_open_window",
        ],
        attack_note: "/etc/systemd/user is watched but not among the rule's directories: a user \
            unit there draws no verdict. A .timer here is recorded as this rule, which the engine \
            evaluates before NN-L-FIM-023.",
    },
    RuleDoc {
        id: "NN-L-FIM-010_RansomwareExtensionRename",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::File],
        data_components: &["DC0061"],
        observes: "A watched file renamed to, or from, a name ending in one of 19 ransomware \
            marker extensions (.locked, .crypted, .encrypted, .lockbit, .conti, ...; any case). \
            Lab PR 225 also reads a rename inside a watched directory, seen as the \
            directory's new entry: that match is new, so its kill is held behind the \
            per-rule response policy (off by default) — a Critical record.",
        false_positives: "An operator renaming a file to one of these names is killed; .lock, \
            .tmp, .bak and editor swap files are not on the list. Only watched files are seen.",
        how_to_test: "Add an existing scratch file, /srv/nn-test/report.txt, to \
            /etc/northnarrow/fim-paths.local, restart the agent, then `sudo mv \
            /srv/nn-test/report.txt /srv/nn-test/report.txt.locked`; expect Critical, \
            KillProcessTree aimed at mv.",
        tests: &[
            "agent/src/fim/rules.rs::fim010_fires_on_renamed_to_ransomware_extension",
            "agent/src/fim/rules.rs::fim010_matches_extension_case_insensitively",
            "agent/src/fim/rules.rs::fim010_moved_in_is_held_and_does_not_hide_the_files_rename",
        ],
        attack_note: "Encryption in place, without a rename, has no rule (v2-techniques.tsv TQ32).",
    },
    RuleDoc {
        id: "NN-L-FIM-011_AwsCredsRead",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0055", "DC0061", "DC0059"],
        observes: "An open (read or write) of ~/.aws/credentials or ~/.aws/config, or a change \
            that never opens it: the file replaced by a rename over it, truncated, or its mode or \
            owner changed.",
        false_positives: "The AWS CLI (aws, aws-cli; told by the kernel-resolved exe, not comm) is \
            exempt unless it reads another user's file. An open found only by the file-open \
            sensor's credential names (a home outside the watch list) is recorded, not killed, \
            unless a non-root user other than the owner read it; any other reader of a watched \
            path, a backup tool included, is killed.",
        how_to_test: "With /root/.aws/credentials in place when the agent starts: `sudo cat \
            /root/.aws/credentials`; expect High, KillProcess aimed at cat. The lab probe reads a \
            file in a home outside the watch list and expects High with action Log.",
        tests: &[
            "agent/src/fim/rules.rs::fim011_fires_on_aws_cred_read_by_unknown_process",
            "agent/src/fim/rules.rs::fim011_fires_on_replaced_credentials",
            "agent/tests/fim_privileged_e2e.rs::fim_subprocess_open_aws_creds_records_opened_event",
            "deploy/lab/open-sensor/open-sensor-check.sh::NN-L-FIM-011_AwsCredsRead",
        ],
        attack_note: "",
    },
    RuleDoc {
        id: "NN-L-FIM-012_AzureCredsRead",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0055", "DC0061", "DC0059"],
        observes: "An open (read or write) of a file under ~/.azure, or a change that never opens \
            it: the file replaced by a rename over it, truncated, or its mode or owner changed.",
        false_positives: "The Azure CLI (az, or a program under /opt/az; told by the \
            kernel-resolved exe, not comm) is exempt unless it reads another user's file. An open \
            found only by the file-open sensor's credential names (a home outside the watch list) \
            is recorded, not killed, unless a non-root user other than the owner read it; any \
            other reader of a watched path, a backup tool included, is killed.",
        how_to_test: "With a file under /root/.azure in place when the agent starts: `sudo cat \
            /root/.azure/azureProfile.json`; expect High, KillProcess aimed at cat.",
        tests: &[
            "agent/src/fim/rules.rs::fim012_fires_on_azure_cred_read_by_unknown_process",
            "agent/src/fim/rules.rs::own_clients_are_told_by_their_exec",
        ],
        attack_note: "",
    },
    RuleDoc {
        id: "NN-L-FIM-013_GcpCredsRead",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0055", "DC0061", "DC0059"],
        observes: "An open (read or write) of the gcloud credential stores under ~/.config/gcloud \
            (credentials.db, access_tokens.db, application_default_credentials.json, \
            legacy_credentials/), or a change that never opens it: the file replaced by a rename \
            over it, truncated, or its mode or owner changed.",
        false_positives: "The Google Cloud CLI (gcloud, gsutil, bq; told by the kernel-resolved \
            exe, not comm) is exempt unless it reads another user's file. An open found only by \
            the file-open sensor's credential names (a home outside the watch list) is recorded, \
            not killed, unless a non-root user other than the owner read it; any other reader of a \
            watched path, a backup tool included, is killed.",
        how_to_test: "With /root/.config/gcloud/credentials.db in place when the agent starts: \
            `sudo cat /root/.config/gcloud/credentials.db`; expect High, KillProcess aimed at cat.",
        tests: &[
            "agent/src/fim/rules.rs::fim013_fires_on_gcp_cred_read_by_unknown_process",
            "agent/src/fim/rules.rs::own_clients_are_told_by_their_exec",
        ],
        attack_note: "",
    },
    RuleDoc {
        id: "NN-L-FIM-014_DockerCredsRead",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0055", "DC0061", "DC0059"],
        observes: "An open (read or write) of ~/.docker/config.json or \
            /var/lib/docker/credentials.json, or a change that never opens it: the file replaced \
            by a rename over it, truncated, or its mode or owner changed.",
        false_positives: "The Docker CLI (docker, dockerd, containerd; told by the kernel-resolved \
            exe, not comm) is exempt unless it reads another user's file. An open found only by \
            the file-open sensor's credential names (a home outside the watch list) is recorded, \
            not killed, unless a non-root user other than the owner read it; any other reader of a \
            watched path, a backup tool included, is killed. Docker CLI plugins that run as their \
            own executables (docker-compose, docker-buildx) are not on the client list.",
        how_to_test: "With /root/.docker/config.json in place when the agent starts: `sudo cat \
            /root/.docker/config.json`; expect High, KillProcess aimed at cat.",
        tests: &[
            "agent/src/fim/rules.rs::fim014_fires_on_docker_cred_read_by_unknown_process",
            "agent/src/fim/rules.rs::own_clients_are_told_by_their_exec",
        ],
        attack_note: "",
    },
    RuleDoc {
        id: "NN-L-FIM-015_BrowserCredsAccessed",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0055", "DC0061"],
        observes: "A read or write of a browser's stored logins (Chrome, Chromium, Edge, Brave: \
            Login Data; Firefox: logins.json, key4.db, key3.db, signons.sqlite) by a process other \
            than a browser.",
        false_positives: "The browsers on the client list (chrome, chromium, firefox, brave, \
            msedge, opera, vivaldi; kernel-resolved exe) are exempt; profile backup and sync tools \
            are not. An open found only by the file-open sensor's credential names (a home outside \
            the watch list) is recorded, not killed, unless a non-root user other than the owner \
            read it; any other reader of a watched path, a backup tool included, is killed.",
        how_to_test: "With /root/.config/google-chrome/Default/Login Data in place when the agent \
            starts: `sudo cp '/root/.config/google-chrome/Default/Login Data' /tmp/`; expect High, \
            KillProcess aimed at cp.",
        tests: &[
            "agent/src/fim/rules.rs::d3_fim_rules_table",
            "agent/src/fim/rules.rs::own_clients_are_told_by_their_exec",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::fim_browser_cred_access_trips_fim_015",
        ],
        attack_note: "",
    },
    RuleDoc {
        id: "NN-L-FIM-016_PasswordManagerDbAccessed",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0055", "DC0061"],
        observes: "A read or write of a KeePass database (*.kdbx) or of the pass store \
            (~/.password-store) by a process other than a password manager.",
        false_positives: "KeePassXC, KeePass, pass and gopass are exempt by kernel-resolved exe or \
            script; a program a password manager runs as a separate executable (gpg decrypting a \
            pass entry) is not. An open found only by the file-open sensor's credential names (a \
            home outside the watch list) is recorded, not killed, unless a non-root user other \
            than the owner read it; any other reader of a watched path, a backup tool included, is \
            killed.",
        how_to_test: "With a file under /root/.password-store in place when the agent starts: \
            `sudo cat /root/.password-store/nn-test.gpg`; expect High, KillProcess aimed at cat.",
        tests: &[
            "agent/src/fim/rules.rs::d3_fim_rules_table",
            "agent/src/fim/rules.rs::own_clients_are_told_by_their_exec",
        ],
        attack_note: "",
    },
    RuleDoc {
        id: "NN-L-FIM-017_GpgKeyringAccessed",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0055", "DC0061"],
        observes: "A read or write of any file under ~/.gnupg by a process outside the GnuPG \
            toolchain (gpg, gpg2, gpg-agent, gpgsm, gpgconf, dirmngr, keyboxd, scdaemon, \
            gpg-connect-agent).",
        false_positives: "Programs outside that toolchain that read the keyring (backup tools, \
            other OpenPGP implementations) fire it. An open found only by the file-open sensor's \
            credential names (a home outside the watch list) is recorded, not killed, unless a \
            non-root user other than the owner read it; any other reader of a watched path, a \
            backup tool included, is killed.",
        how_to_test: "With /root/.gnupg in place when the agent starts: `sudo cat \
            /root/.gnupg/pubring.kbx` (any file there); expect High, KillProcess aimed at cat.",
        tests: &[
            "agent/src/fim/rules.rs::d3_fim_rules_table",
            "agent/src/fim/rules.rs::own_clients_are_told_by_their_exec",
        ],
        attack_note: "T1552.004 (Private Keys): the rule fires on any file there, public keyrings \
            included.",
    },
    RuleDoc {
        id: "NN-L-FIM-018_LastlogTampered",
        severities: &[Severity::High, Severity::Low],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0061"],
        observes: "A rewrite of /var/log/lastlog by a process outside the login machinery.",
        false_positives: "The login machinery (login, sshd, sshd-session, systemd-logind, \
            systemd-update-utmp, getty and agetty, display managers, su, sudo, lastlog) is exempt \
            by kernel-resolved exe. An account tool (useradd resetting a new uid's entry) is \
            recorded, at Low when a non-root user ran it.",
        how_to_test: "`printf x | sudo dd of=/var/log/lastlog oflag=append conv=notrunc` (a lab \
            guest: it appends a byte); expect High, KillProcess aimed at dd.",
        tests: &[
            "agent/src/fim/rules.rs::d3_fim_rules_table",
            "agent/src/fim/rules.rs::account_tools_are_recorded_not_killed",
        ],
        attack_note: "T1685.006: ATT&CK lists the login records among the system logs (T1070.002, \
            revoked in v19). The reasoning text names T1070.",
    },
    RuleDoc {
        id: "NN-L-FIM-019_WtmpBtmpTampered",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcess],
        sensors: &[Sensor::File],
        data_components: &["DC0061"],
        observes: "A rewrite of /var/log/wtmp or /var/log/btmp by a process outside the login \
            machinery.",
        false_positives: "The login machinery (login, sshd, sshd-session, systemd-logind, \
            systemd-update-utmp, getty and agetty, display managers, su, sudo, lastlog) is exempt \
            by kernel-resolved exe. Another program that writes login records through the utmp API \
            (a terminal multiplexer's helper) is killed.",
        how_to_test: "`printf x | sudo dd of=/var/log/btmp oflag=append conv=notrunc` (a lab \
            guest: it appends a byte); expect High, KillProcess aimed at dd.",
        tests: &[
            "agent/src/fim/rules.rs::d3_fim_rules_table",
            "agent/src/fim/rules.rs::own_clients_are_told_by_their_exec",
        ],
        attack_note: "T1685.006, as NN-L-FIM-018; the reasoning text names T1070.",
    },
    RuleDoc {
        id: "NN-L-FIM-020_ShellHistoryCleared",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0040", "DC0061"],
        observes: "A watched .bash_history or .zsh_history deleted or renamed.",
        false_positives: "Users and administrators clearing their own history (rm \
            ~/.bash_history), and history tools that rotate the file by a rename; hence a Medium \
            record only.",
        how_to_test: "`sudo touch /root/.bash_history` before the agent starts, then `sudo mv \
            /root/.bash_history /root/.bash_history.nn` and back; expect Medium, Log.",
        tests: &["agent/src/fim/rules.rs::d3_fim_rules_table"],
        attack_note: "A truncation in place, `history -c` and `unset HISTFILE` (also T1070.003) \
            draw no verdict: only a deletion or a rename.",
    },
    RuleDoc {
        id: "NN-L-FIM-021_PamModuleModified",
        severities: &[Severity::Critical, Severity::Low],
        actions: &[ResponseAction::KillProcessTree, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0039", "DC0061"],
        observes: "A new or rewritten .so under a watched security/ directory (/lib/security, \
            /usr/lib/security and the x86_64-linux-gnu ones), or a file there whose name \
            overflowed the kernel's buffer.",
        false_positives: "PAM package updates are recorded at Low. fim-paths.v1 does not watch \
            /usr/lib64/security (the RHEL family's): a module dropped there is not seen unless \
            fim-paths.local adds it.",
        how_to_test: "`sudo cp /usr/lib/x86_64-linux-gnu/security/pam_permit.so \
            /usr/lib/x86_64-linux-gnu/security/pam_nntest.so` (Debian, Ubuntu), then remove it; \
            expect Critical, KillProcessTree aimed at cp.",
        tests: &[
            "agent/src/fim/rules.rs::d3_fim_rules_table",
            "agent/src/fim/rules.rs::bug022_created_kmod_and_truncated_suffix_rules_fire",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::fim_pam_module_modify_trips_fim_021_combat",
        ],
        attack_note: "T1556.003 for both the backdoor (persistence) and the credential harvest; \
            the reasoning's T1543 is not the behaviour. A rewrite of an existing module under \
            /usr/lib is evaluated by NN-L-FIM-001 first and recorded as that rule (same response, \
            T1554).",
    },
    RuleDoc {
        id: "NN-L-FIM-022_LdSoPreloadModified",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::File],
        data_components: &["DC0039", "DC0061"],
        observes: "/etc/ld.so.preload created or rewritten.",
        false_positives: "No carve-out, not even for the package manager: no mainstream package \
            ships the file. A host that preloads a library system-wide on purpose (an allocator, a \
            debugging shim) fires it on every change.",
        how_to_test: "The path must exist when the agent starts (an absent watch-list path is \
            skipped): create an empty /etc/ld.so.preload with the agent stopped, start it, then \
            `echo | sudo tee /etc/ld.so.preload`; expect Critical, KillProcessTree aimed at tee. \
            Remove the file afterwards.",
        tests: &[
            "agent/src/fim/rules.rs::d3_fim_rules_table",
            "agent/src/fim/rules.rs::ld_so_preload_is_not_carved_out",
        ],
        attack_note: "T1574.006 under Execution and Stealth, its two v20 tactics (v19 took it out \
            of Persistence). On a host without the file the first creation is not seen: \
            fim::attach::populate_watched_paths skips a path that does not exist, and /etc is not \
            watched as a directory.",
    },
    RuleDoc {
        id: "NN-L-FIM-023_SystemdTimerCreated",
        severities: &[Severity::High, Severity::Low],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0039", "DC0061"],
        observes: "A new or rewritten .timer unit under /etc/systemd/system, /lib/systemd/system \
            or /usr/lib/systemd/system (or a file there whose name overflowed the kernel's \
            buffer).",
        false_positives: "Package transactions are recorded at Low, writes in an interactive sudo \
            or su session at High.",
        how_to_test: "`sudo systemd-run --wait cp /dev/null /etc/systemd/system/nn-test.timer`: \
            one record naming NN-L-FIM-009 (primary: same severity and action, registered \
            first) and this rule among its matches (lab PR 236, multi-match).",
        tests: &[
            "agent/src/fim/rules.rs::d3_fim_rules_table",
            "agent/src/fim/rules.rs::bug022_created_kmod_and_truncated_suffix_rules_fire",
            "agent/src/decision/tests.rs::shadow_fim023_fires_with_fim009_on_a_timer",
        ],
        attack_note: "NN-L-FIM-009 (T1543.002) matches the same writes; until lab PR 236 it \
            shadowed this rule in the engine's first-match order. Now both are matches of one \
            record, whose ATT&CK field carries T1543.002 and T1053.006.",
    },
    RuleDoc {
        id: "NN-L-FIM-024_AntiTamperHoneypotModified",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::File],
        data_components: &["DC0039", "DC0061", "DC0040", "DC0059"],
        observes: "Any change (create, write, delete, rename, chmod or chown) of one of the ten \
            control-surface bait files under /etc/northnarrow, /var/lib/northnarrow and \
            /run/northnarrow, whose names offer a way to disable the agent; the agent never reads \
            them. Its own writes are not judged.",
        false_positives: "None expected: no operator workflow writes them. A \
            configuration-management run that resets /etc/northnarrow wholesale (rsync --delete) \
            fires it.",
        how_to_test: "`sudo rm /etc/northnarrow/kill_switch.conf` (the e2e's case; the agent \
            recreates the file at its next start); expect Critical, KillProcessTree aimed at rm.",
        tests: &[
            "agent/src/fim/rules.rs::fim024_fires_on_every_honeypot_path",
            "agent/src/fim/rules.rs::fim024_fires_on_create_delete_rename_too",
            "agent/tests/honeypot_tamper_e2e.rs::delete_kill_switch_conf_trips_fim024_and_kills_the_tamperer",
        ],
        attack_note: "T1685 (Disable or Modify Tools), which replaced T1562.001 in ATT&CK v19; the \
            reasoning text, pinned by a test, still names T1562.001.",
    },
    RuleDoc {
        id: "NN-L-FIM-025_FileCapabilityGranted",
        severities: &[Severity::Critical, Severity::High, Severity::Medium, Severity::Low],
        actions: &[ResponseAction::StripFileCapability, ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0059"],
        observes: "A file capability (security.capability) stored on any file, by any route \
            (setcap, setxattr, cp --preserve=xattr, tar --xattrs), seen by the file-open sensor's \
            inode_post_setxattr hook. Critical for a root-equivalent capability (setuid, setgid, \
            dac_override, dac_read_search, fowner, chown, sys_admin, sys_ptrace, sys_module, \
            sys_rawio, setfcap, bpf), else High; the response removes it.",
        false_positives: "Packages install files with capabilities (ping, newuidmap, dumpcap): \
            recorded at Low and kept. A grant in an interactive sudo or su session, or while the \
            trusted-installer window is open, is recorded and kept; a namespaced capability (a \
            rootless container build) is recorded at Medium.",
        how_to_test: "`cp /usr/bin/python3 /tmp/nn-py && sudo systemd-run --wait setcap \
            cap_setuid+ep /tmp/nn-py`; `getcap /tmp/nn-py` then prints nothing; expect Critical, \
            StripFileCapability.",
        tests: &[
            "agent/src/fim/rules.rs::fim025_strips_a_granted_capability",
            "agent/src/fim/rules.rs::fim025_keeps_a_grant_inside_the_trusted_installer_window",
            "agent/src/fim/rules.rs::fim025_package_manager_and_interactive_admin_keep_the_capability",
        ],
        attack_note: "T1548: ATT&CK has no sub-technique for Linux file capabilities (T1548.001 is \
            the set-id bits).",
    },
    // ── ransomware, decisive (lab PR 225, CM-16) ────────────────────
    RuleDoc {
        id: "NN-L-IMP-001_RansomwareEncryption",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0061", "DC0039", "DC0040"],
        observes: "Two of four shapes of one actor's file activity within 120 s: existing \
                   files rewritten (the mass-write overwrite counter), ciphertext-like content \
                   left behind (entropy sampled in userland), a burst of renames to one new \
                   extension (or encrypted copies under an extension appended to the names of \
                   the originals deleted, the copies themselves sampled), deletion of originals \
                   after new files were written. Critical, \
                   recorded; the kill of the actor's tree (`KillProcessTree`) and the posture's \
                   COMBAT without corroboration are held behind the per-rule response policy, \
                   off by default (new in lab PR 225): the posture's RansomwareEncryption needs \
                   corroboration, ENGAGED alone, never locked.",
        false_positives: "Writers trusted by exec identity, package ownership and lineage, never \
                          by name: a root package transaction, or a packaged program with no \
                          foreign program in its lineage (rsync, tar, git, compilers, backup \
                          agents, databases), never counts. Copy-then-delete by anyone else — \
                          `mv` across filesystems, `rsync --remove-source-files`, a package \
                          unpack, compiler temporaries, an editor's safe write, `git gc`, log \
                          rotation with compression — is one shape (the deletions): no copy \
                          under an appended extension beside the deleted original, or copies \
                          that are plain, compressed or another known format. A user's own \
                          script encrypting 20 files a minute into copies with no known \
                          format header and deleting the originals (`openssl enc`, `ccrypt`) \
                          is recorded.",
        how_to_test: "`ransom-check.sh` MS-23: the benign simulator (`ransom-sim.py`, \
                      /srv/nn-malsim only), in place and copy-delete, draws the Critical \
                      record (its kill held: the simulator finishes) and the posture reaches \
                      ENGAGED; tar, rsync, git checkout, an apt install and the simulator's \
                      own script compressing or moving its files then deleting them draw no \
                      record.",
        tests: &[
            "agent/src/decision/rules/impact.rs::imp001_kills_the_actors_tree_on_two_shapes",
            "agent/src/impact/tests.rs::copy_delete_beside_fresh_originals_is_decisive",
            "agent/src/impact/tests.rs::benign_copy_delete_shapes_are_not_decisive",
            "deploy/lab/malsim/ransom-check.sh::MS-23",
        ],
        attack_note: "Data Encrypted for Impact (T1486) by the shape of the writes, not by a \
                      ransom note or a known family.",
    },
    RuleDoc {
        id: "NN-L-IMP-002_RenameExtensionBurst",
        severities: &[Severity::High],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::File],
        data_components: &["DC0061"],
        observes: "A burst of renames to one new extension, of an encryptor's shape, by one \
                   actor, alone (with a second shape it is NN-L-IMP-001).",
        false_positives: "Bulk renames by trusted writers (by identity and lineage); a user's \
                          own batch rename of many files to one extension is recorded.",
        how_to_test: "From ONE process — the counter is per process, and a shell loop of \
                      `mv` is one process per file — rename 20 regular files of 4 KiB or \
                      more to `.locked`, with the LSM file-open sensor armed and no other \
                      shape: `python3 -c 'import glob,os; [os.rename(f, f + \".locked\") \
                      for f in glob.glob(\"/srv/nn-test/*\")]'`.",
        tests: &["agent/src/decision/rules/impact.rs::imp002_records_a_lone_rename_burst"],
        attack_note: "",
    },
];
