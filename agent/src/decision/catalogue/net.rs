//! The network rules (NN-L-NET-*).

use common::{ResponseAction, Severity};

use super::RuleDoc;
use crate::detection_store::Sensor;

pub(super) const DOCS: &[RuleDoc] = &[
    RuleDoc {
        id: "NN-L-NET-001_OutboundToBlockedIp",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::Network],
        data_components: &["DC0082", "DC0078"],
        observes: "A finished outbound flow whose destination address is in the operator's \
                   netflow blocklist (`/etc/northnarrow/netflow-blocklist.{v1,local}`, \
                   addresses and CIDRs). Never held back by the netflow rate limiter.",
        false_positives: "Only as good as the blocklist: an entry that covers a shared address \
                          (a CDN, a cloud load balancer) kills every client of it. The shipped \
                          list is empty.",
        how_to_test: "Add an address the guest can reach (the lab host's bridge address) to \
                      `netflow-blocklist.local`, restart the agent, then connect to it from a \
                      throwaway shell: `sh -c 'curl -s --max-time 3 http://<address>/'`. The \
                      shell's tree is killed.",
        tests: &["agent/src/decision/rules/net.rs::net_001_fires_on_blocklist_match"],
        attack_note: "An indicator match: the destination, not the protocol, is the signal. \
                      Mapped to the two C2 channel techniques a flow to a known C2 address is \
                      an instance of (an application protocol, T1071, or raw TCP/UDP, T1095); \
                      the flow's protocol is not inspected.",
    },
    RuleDoc {
        id: "NN-L-NET-002_OutboundToBlockedTld",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcess],
        sensors: &[Sensor::Network],
        data_components: &["DC0082", "DC0085"],
        observes: "An outbound flow whose process last looked up (within 5 minutes, same \
                   process) a name under `.onion` or `.bit`: the DNS cache names the flow's \
                   destination from the process's own query.",
        false_positives: "A Tor or Namecoin user on the host. A flow to an IP literal, or one \
                          whose name lookup the DNS sensor did not see, cannot fire it.",
        how_to_test: "From one process, look up a `.onion` name (the resolver's NXDOMAIN is \
                      enough: the sensor records the query), then connect anywhere within 5 \
                      minutes: `python3 -c $'import socket, contextlib\\nwith \
                      contextlib.suppress(OSError): socket.getaddrinfo(\"nn-test.onion\", \
                      80)\\nsocket.create_connection((\"<peer>\", 80))'` (bash). The process \
                      is killed.",
        tests: &[
            "agent/src/decision/rules/net.rs::net_002_fires_on_onion_tld",
            "agent/src/decision/rules/net.rs::net_002_no_hostname_no_fire",
        ],
        attack_note: "`.onion` is Tor, T1090.003 Multi-hop Proxy. `.bit` (Namecoin) names \
                      have no ATT&CK technique of their own and are not mapped separately.",
    },
    RuleDoc {
        id: "NN-L-NET-003_BadJa3",
        severities: &[Severity::Critical],
        actions: &[ResponseAction::KillProcessTree],
        sensors: &[Sensor::Network],
        data_components: &["DC0085"],
        observes: "An outbound flow whose TLS ClientHello fingerprint (JA3) is in the operator's \
                   JA3 blocklist (`netflow-ja3-blocklist.{v1,local}`).",
        false_positives: "A JA3 hash names a TLS library and its settings, not a program: an \
                          entry shared by a common client (a language runtime's default TLS \
                          stack) kills every program built on it.",
        how_to_test: "Cannot be exercised on a guest: no sensor fills a flow's TLS fingerprint \
                      until BUG-025 (`FlowTracker::attach_tls` has no caller), so the rule \
                      cannot fire. The unit test gives the flow a fingerprint directly.",
        tests: &["agent/src/decision/rules/net.rs::net_003_fires_on_ja3_blocklist_match"],
        attack_note: "TLS C2 is T1573.002 (ATT&CK classes SSL/TLS as asymmetric cryptography). \
                      Inactive until BUG-025: out of the V2 Critical sub-gate, still in its \
                      denominator.",
    },
    RuleDoc {
        id: "NN-L-NET-004_SuspiciousDnsQname",
        severities: &[Severity::High, Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Network],
        data_components: &["DC0085"],
        observes: "A DNS query for a name over 60 characters (Medium), or one whose name does \
                   not end in the kernel's linear copy of the datagram — sent in pieces, with \
                   UDP GSO or zero copy, or not DNS at all (High). Recorded, never killed; a \
                   forwarded leg is attributed to the process that asked the local stub.",
        false_positives: "Long legitimate names (object-storage buckets, CDN and load-balancer \
                          names, Kubernetes service FQDNs, ACME challenges) are recorded: \
                          external audit NETR-002 took the kill away for that reason. The \
                          local resolvers are never the target (FP-3), and one lookup's legs \
                          give one record (FP-5, shared with NN-L-NET-014).",
        how_to_test: "Look up a name over 60 characters whose first label is under 25: `dig \
                      aaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbbbbbb.cccccccccccccccccccc.example.com`. \
                      `deploy/lab/dns-sensor/dns-sensor-check.sh` does it, and the name sent in \
                      pieces, with its own sender.",
        tests: &[
            "agent/src/decision/rules/net.rs::net_004_records_a_long_qname",
            "agent/src/decision/rules/net.rs::net_004_logs_a_partial_name",
            "deploy/lab/dns-sensor/dns-sensor-check.sh::NN-L-NET-004_SuspiciousDnsQname",
        ],
        attack_note: "Length alone is the shape of a DNS tunnel (T1071.004), not proof of one; \
                      the encoded label is NN-L-NET-014's.",
    },
    RuleDoc {
        id: "NN-L-NET-005_DnsTxtNullBurst",
        severities: &[Severity::High],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Network],
        data_components: &["DC0085"],
        observes: "More than 50 DNS queries of type TXT or NULL from one process within 60 \
                   seconds, the record types DNS tunnels carry their payload in. Forwarded legs \
                   of the local resolvers are not counted.",
        false_positives: "Mail and anti-spam software checking SPF, DKIM and DMARC records in \
                          bulk, and service discovery over TXT. A burst asked through \
                          Varlink/nss-resolve (no stub query of the originator) is not counted \
                          at all (documented gap).",
        how_to_test: "Send 60 TXT lookups from one process: `for i in $(seq 60); do echo \
                      \"nn$i.example.com TXT\"; done > /tmp/q; dig -f /tmp/q +short +tries=1 \
                      +time=1`.",
        tests: &[
            "agent/src/decision/rules/net.rs::net_005_fires_on_txt_burst_over_threshold",
            "agent/src/decision/rules/net.rs::\
             fp3_005_skips_forwarded_leg_but_fires_on_originator",
        ],
        attack_note: "",
    },
    RuleDoc {
        id: "NN-L-NET-006_UncommonListener",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Network],
        data_components: &["DC0021"],
        observes: "A new TCP listener on a port outside 22, 53, 80, 443, 8080 and 8443 — or on \
                   one of them from a program not installed in a root-owned system tree — by a \
                   process outside the netflow comm allowlist. A wildcard bind is \
                   NN-L-NET-019's.",
        false_positives: "Developer servers, test fixtures and user services that listen on \
                          high ports; the netflow comm allowlist (judged on the executed \
                          program, not on `comm`) answers the known daemons.",
        how_to_test: "Listen on loopback on an uncommon port from `python3`: `python3 -m \
                      http.server 18080 --bind 127.0.0.1`.",
        tests: &[
            "agent/src/decision/rules/net.rs::\
             net_006_fires_on_uncommon_port_non_allowlist_comm",
            "agent/tests/net_privileged_e2e.rs::net_listener_on_uncommon_port_records_event",
        ],
        attack_note: "A bind shell or a backdoor listener has no ATT&CK technique of its own; \
                      mapped to T1571 as the code names it. The protocol served on the port is \
                      not seen.",
    },
    RuleDoc {
        id: "NN-L-NET-007_Rfc1918FromUnusualProc",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Network],
        data_components: &["DC0082", "DC0078"],
        observes: "An outbound flow to an internal address (RFC 1918, IPv6 unique-local or \
                   link-local) from a process outside the netflow comm allowlist, on any port.",
        false_positives: "Any internal client the allowlist does not name: monitoring agents, \
                          a developer's tools reaching a staging host, internal package \
                          mirrors. The four lateral-movement ports are NN-L-NET-018's.",
        how_to_test: "From `python3`, connect to a port an RFC 1918 host on the lab network \
                      serves (not 445, 3389, 5985 or 5900): `python3 -c 'import socket; \
                      socket.create_connection((\"<internal peer>\", 8000), timeout=3)'`.",
        tests: &[
            "agent/src/decision/rules/net.rs::net_007_fires_on_rfc1918_non_allowlist",
            "agent/src/decision/rules/net.rs::net_007_fires_on_link_local",
        ],
        attack_note: "Evidence of internal reach, not of a protocol: a remote service (T1021) \
                      or a scan of internal services (T1046) draw it alike; the rule sees one \
                      flow at a time and does not tell them apart.",
    },
    RuleDoc {
        id: "NN-L-NET-008_OutboundFromTmpExec",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::Network, Sensor::Exec],
        data_components: &["DC0082", "DC0078", "DC0034"],
        observes: "An outbound flow to a port other than 53 from a process whose image lies in \
                   `/tmp`, `/var/tmp` or `/dev/shm` (named at connect time from the spawn \
                   cache or `/proc`). A process of a root package transaction is recorded \
                   (Log), not killed.",
        false_positives: "Installers and self-extracting archives that run a helper from a \
                          staging directory and call out; package-manager transactions are \
                          carved out. A staged exec followed by egress within 5 minutes is \
                          NN-L-CHAIN-002/005's (they run first).",
        how_to_test: "In detect-only (R001 would kill the exec first), run a copy of `python3` \
                      from `/tmp` that connects more than 5 minutes after its exec, when the \
                      chain precursor is gone: `cp /usr/bin/python3 /tmp/nn-py; /tmp/nn-py -c \
                      'import socket,time; time.sleep(330); \
                      socket.create_connection((\"<peer>\", 80))'`.",
        tests: &[
            "agent/src/decision/rules/net.rs::net_008_fires_on_tmp_exec_outbound",
            "agent/src/decision/rules/net.rs::net_008_covers_every_staging_directory",
            "agent/src/decision/rules/net.rs::net_008_spares_a_package_transaction",
        ],
        attack_note: "A staged payload calling out is mapped to its likeliest purpose, \
                      fetching the next stage (T1105); the flow's protocol is not seen, and a \
                      staged payload's C2 channel draws the rule as well.",
    },
    RuleDoc {
        id: "NN-L-NET-009_ByteAnomaly",
        severities: &[Severity::High],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Network],
        data_components: &["DC0078"],
        observes: "A flow that sent more than 100 MiB, or UDP rows to one destination summing \
                   past 100 MiB within 10 minutes, from a process outside the netflow comm \
                   allowlist.",
        false_positives: "Backups, uploads, container image pushes and file sync by programs \
                          the allowlist does not name (`rsync`, `scp`, `git`, `curl` and the \
                          container runtimes are in it).",
        how_to_test: "Send 120 MiB from `python3` to a listener on the lab host (`nc -l 9000 > \
                      /dev/null` there): `python3 -c 'import socket; s = \
                      socket.create_connection((\"<peer>\", 9000)); s.sendall(bytes(120 << \
                      20))'`.",
        tests: &[
            "agent/src/decision/rules/net.rs::\
             net_009_fires_on_large_flow_from_non_allowlist",
            "agent/src/decision/rules/net.rs::net_009_sums_udp_rows_per_destination",
        ],
        attack_note: "Volume only: whether the channel is the C2 channel (T1041) or another \
                      protocol (T1048) is not seen, so both are named.",
    },
    RuleDoc {
        id: "NN-L-NET-010_OutboundToHighRiskC2Port",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::Network],
        data_components: &["DC0082", "DC0078"],
        observes: "An outbound flow to port 4444 (Metasploit's default), 1080 (SOCKS), 6667 or \
                   6697 (IRC) or 9001 (Tor relays) from a process outside the netflow comm \
                   allowlist. A process named like an allowlisted program whose executable \
                   could not be read is recorded (Log), not killed.",
        false_positives: "IRC clients, SOCKS proxies and Tor run by a user, and services that \
                          happen to use these ports; 443 is deliberately not in the set (the \
                          rule kills).",
        how_to_test: "With a listener on port 4444 of the lab host, connect from `python3`: \
                      `python3 -c 'import socket; socket.create_connection((\"<peer>\", 4444), \
                      timeout=3)'`. The process is killed.",
        tests: &[
            "agent/src/decision/rules/net.rs::net_010_fires_on_c2_port_non_allowlist",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::\
             net_outbound_high_risk_c2_port_trips_net_010",
        ],
        attack_note: "4444 and 6667/6697 are C2 on a non-standard port (T1571); 1080 SOCKS and \
                      9001 Tor are proxies (T1090; 9001 is the multi-hop T1090.003).",
    },
    RuleDoc {
        id: "NN-L-NET-011_PlaintextCredService",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Network],
        data_components: &["DC0082", "DC0078"],
        observes: "An outbound flow to FTP (21) or Telnet (23) from a process outside the \
                   netflow comm allowlist: credentials sent in clear.",
        false_positives: "Legacy FTP transfers and Telnet sessions to network equipment in \
                          environments that still use them; hence Log, not a kill.",
        how_to_test: "With a listener on port 21 of the lab host, connect from `python3`: \
                      `python3 -c 'import socket; socket.create_connection((\"<peer>\", 21), \
                      timeout=3)'`.",
        tests: &["agent/src/decision/rules/net.rs::net_011_fires_on_plaintext_port_non_allowlist"],
        attack_note: "The rule's concern is credentials in clear, which ATT&CK does not name as \
                      a host behaviour. FTP is mapped as an application-layer C2 protocol \
                      (T1071.002), Telnet as a remote service (T1021, which has no Telnet \
                      sub-technique); FTP used for exfiltration (T1048.003) is not told apart.",
    },
    RuleDoc {
        id: "NN-L-NET-013_Beacon",
        severities: &[Severity::High],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Network],
        data_components: &["DC0078", "DC0082"],
        observes: "Outbound flows from one process to one destination at regular intervals: \
                   at least 4 of them, a mean interval of a second or more and a coefficient \
                   of variation of 0.15 or less, within an hour.",
        false_positives: "Pollers, health checks, metrics exporters and update checkers not in \
                          the netflow comm allowlist (`chronyd`, `ntpd`, `node_exporter` are).",
        how_to_test: "From one process, connect to the same address every 5 seconds: \
                      `python3 -c 'import socket, time; \
                      [(socket.create_connection((\"<peer>\", 80)).close(), time.sleep(5)) \
                      for _ in range(6)]'`.",
        tests: &["agent/src/decision/rules/net.rs::net_013_fires_on_low_jitter_periodic_flow"],
        attack_note: "The timing is the signal: a C2 beacon over an application protocol \
                      (T1071) or a scheduled transfer (T1029).",
    },
    RuleDoc {
        id: "NN-L-NET-014_DnsTunnelEntropy",
        severities: &[Severity::High, Severity::Medium],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::Network],
        data_components: &["DC0085"],
        observes: "A DNS query whose first label is 25 characters or more with a Shannon \
                   entropy of 3.8 bits per character or more. One such label is recorded \
                   (Medium); 8 distinct ones under one parent domain from one process within a \
                   minute kill it (High). A forwarded leg with no attributable originator is \
                   recorded only.",
        false_positives: "A long varied name of words (`my-company-prod-backups-archive`) \
                          reaches the threshold and is recorded; the kill needs a tunnel's \
                          volume of distinct labels (NETR-002). The local resolvers are never \
                          the target (FP-3).",
        how_to_test: "Look up 8 random base32 labels under one parent from one process: `for i \
                      in $(seq 8); do echo \"$(head -c 20 /dev/urandom | base32 | tr -d = | tr \
                      A-Z a-z).nn-tunnel.example.com\"; done > /tmp/q; dig -f /tmp/q +short`. \
                      `dig` is killed; one label alone is recorded.",
        tests: &[
            "agent/src/decision/rules/net.rs::\
             net_014_kills_a_tunnel_of_distinct_labels_under_one_parent",
            "agent/src/decision/rules/net.rs::net_014_records_a_single_high_entropy_label",
        ],
        attack_note: "DNS tunnelling carries C2 or exfiltrated data alike; the rule cannot tell \
                      them apart and is mapped to the DNS channel (T1071.004) only.",
    },
    RuleDoc {
        id: "NN-L-NET-018_Rfc1918LateralPort",
        severities: &[Severity::High],
        actions: &[ResponseAction::KillProcess, ResponseAction::Log],
        sensors: &[Sensor::Network],
        data_components: &["DC0082", "DC0078"],
        observes: "An outbound flow to an internal address (RFC 1918, IPv6 unique-local or \
                   link-local) on 445 (SMB), 3389 (RDP), 5985 (WinRM) or 5900 (VNC) from a \
                   process outside the netflow comm allowlist. A process named like an \
                   allowlisted program whose executable could not be read is recorded (Log).",
        false_positives: "Administration clients (`smbclient`, RDP and VNC viewers) and \
                          monitoring of Windows hosts from this one, when not in the allowlist. \
                          SSH (22) is not watched (V2 row TQ04, a known gap).",
        how_to_test: "With a listener on port 445 of an RFC 1918 lab host, connect from \
                      `python3`: `python3 -c 'import socket; \
                      socket.create_connection((\"<internal peer>\", 445), timeout=3)'`. The \
                      process is killed.",
        tests: &[
            "agent/src/decision/rules/net.rs::\
             net_018_fires_on_rfc1918_lateral_port_non_allowlist",
            "agent/src/decision/rules/net.rs::net_018_fires_on_ula_lateral_port",
        ],
        attack_note: "One sub-technique per watched port; the port, not the protocol spoken \
                      on it, is what the rule sees.",
    },
    RuleDoc {
        id: "NN-L-NET-019_WildcardListener",
        severities: &[Severity::Medium],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Network],
        data_components: &["DC0021"],
        observes: "A new TCP listener bound to the wildcard address (`0.0.0.0` or `::`) on an \
                   uncommon port — or on a common one from a program not installed in a \
                   root-owned system tree — by a process outside the netflow comm allowlist: \
                   the port is reachable from other hosts.",
        false_positives: "Developer servers and user services that bind all addresses by \
                          default (`python3 -m http.server`, test fixtures); the allowlist \
                          answers the known daemons.",
        how_to_test: "Listen on all addresses on an uncommon port: `python3 -m http.server \
                      18080`.",
        tests: &[
            "agent/src/decision/rules/net.rs::\
             net_019_fires_on_wildcard_uncommon_port_non_allowlist",
            "agent/tests/detection_rules_at_scale_privileged_e2e.rs::\
             net_wildcard_listener_trips_net_019",
        ],
        attack_note: "As NN-L-NET-006: a backdoor listener has no technique of its own; T1571 \
                      as the code names it.",
    },
    RuleDoc {
        id: "NN-L-NET-020_DnsQueryFlood",
        severities: &[Severity::High],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Network],
        data_components: &["DC0078"],
        observes: "A process, or a user across its processes, sent at least 256 DNS queries \
                   beyond the kernel's DNS budget within 10 seconds (64, then 128 per second, \
                   per process; 2,048, then 1,024 per second, per user). Queries over the \
                   budget are not recorded, so the DNS rules never judge them.",
        false_positives: "DNS benchmarking and bulk resolution (crawlers, mail servers); the \
                          local resolvers' users are exempt in the kernel.",
        how_to_test: "Send 3,000 queries from one process as fast as it can: `python3 -c \
                      'import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); \
                      q = bytes.fromhex(\"1234010000010000000000000765\
                      78616d706c6503636f6d0000010001\"); [s.sendto(q, (\"127.0.0.53\", 53)) \
                      for _ in range(3000)]'` (a query for `example.com`).",
        tests: &[
            "agent/src/decision/rules/net.rs::\
             net_020_sums_held_queries_per_process_and_window",
            "agent/src/decision/rules/net.rs::net_020_user_budget_is_summed_per_user",
        ],
        attack_note: "The queries held back were not judged: the rule reports the volume a DNS \
                      tunnel (T1071.004) could hide in, not their content.",
    },
    RuleDoc {
        id: "NN-L-NET-021_SensorRecordFlood",
        severities: &[Severity::High],
        actions: &[ResponseAction::Log],
        sensors: &[Sensor::Network, Sensor::IoUring],
        data_components: &["DC0021"],
        observes: "A process, or a user across its processes, made at least 256 `listen()` or \
                   `io_uring_setup()` calls beyond the kernel's record budget for that sensor \
                   within 10 seconds (64, then 128 per second, per process; 512, then 256 per \
                   second, per user): a flood that can push other processes' records out of \
                   the shared kernel ring.",
        false_positives: "Test suites and servers that create and close many listening sockets \
                          or rings in a tight loop.",
        how_to_test: "Open and close 2,000 listeners from one process: `python3 -c 'import \
                      socket; [socket.create_server((\"127.0.0.1\", 0)).close() for _ in \
                      range(2000)]'`. The listeners recorded within the budget also draw \
                      NN-L-NET-006.",
        tests: &[
            "agent/src/decision/rules/net.rs::\
             net_021_names_the_listen_flooder_once_per_window",
            "agent/src/decision/rules/net.rs::net_021_sums_per_sensor_and_user",
        ],
        attack_note: "The code named T1562.006 Indicator Blocking, revoked in v19, until lab \
                      PR 221; its replacement T1685 Disable or Modify Tools (Defense \
                      Impairment) covers blocking the telemetry a sensor collects.",
    },
];
