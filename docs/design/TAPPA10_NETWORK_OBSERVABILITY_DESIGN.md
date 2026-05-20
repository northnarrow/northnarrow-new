# Tappa 10 — Network Observability Design

**Status:** RFC RESOLVED 2026-05-19 (§13 — all 10 owner-accepted
decisions documented in-place). N1 implementation sequenced AFTER
the Tappa 9.5 K1-K8 sprint per the project SHIP order
(T9 ✅ → T9.5 → T10).
**Author:** Claude Code (architecture), pending owner sign-off.
**Date:** 2026-05-20.
**Prerequisite track:** Tappa 4 (multi-sensor BPF multiplexer),
Tappa 6 (ADE), Tappa 7 (anti-tamper LSM + watchdog), Tappa 8
(signed admin overrides + audit chain), Tappa 9 (FIM) are all
SHIPPED. Tappa 10 builds on five existing layers:

- The `tcp_v4_connect` + `tcp_v6_connect` + `udp_sendmsg` kprobes
  already attached in `agent/src/sensors/multiplexer.rs` (Tappa 4 —
  `TcpConnectRaw` + `DnsQueryRaw` ringbuf events flow today).
- The `CorrelationBuffer` in `agent/src/correlation/mod.rs` —
  Tappa 10 extends with network-specific correlation passes
  (flow ↔ DNS ↔ process spawn) rather than introducing a new
  buffer.
- The Tappa 6 ADE pipeline (`AdeEngine::evaluate`) — Tappa 10
  routes anomalous network flows through the same prompt
  envelope that Tappa 9 §8.1 defined for FIM.
- The Tappa 8 B1 chained audit log primitives — Tappa 10's
  NetFlow audit chain reuses `BaselineDb`-shape rotation.
- The Tappa 9 polish-#4 `AdeFimRateLimiter` shape (§13 Q9
  tiered cap) — Tappa 10 ports the same 10/min + 1/min
  hierarchical bucket for NetFlow-driven ADE prompts.

This doc is reviewable as a PR. All §13 RFC items resolved
2026-05-19; implementation begins at N1 once the Tappa 9.5
K1-K8 sprint completes (project SHIP order).

---

## 1. Purpose & scope

**Network Observability is the second customer-visible Phase 1
detection feature after FIM.** Competitors (Carbon Black,
CrowdStrike Falcon, SentinelOne, Wazuh) all ship "outbound
connection telemetry" as table stakes — operators expect to
answer "what processes called home over the last 24 hours, to
where, and what does each conversation look like". NorthNarrow
must match this baseline AND deliver a differentiated capability
in TLS fingerprinting + sovereign-local behavioural analysis
(no SaaS dependency for JA3/JA4 lookups).

The Tappa 10 scope:

1. **NetFlow primitives.** Build on Tappa 4's existing TCP +
   DNS kprobes by adding (a) a userland flow-tracking layer
   that groups `connect → accept → close` into single
   `NetFlowEvent` records, (b) UDP outbound observation
   (currently only DNS), (c) listener tracking (`inet_csk_listen`)
   so operators see "what ports the host opens".
2. **DNS-to-flow correlation.** Maintain a per-process DNS
   resolution cache (`dst_ip → qname, qtype, ts`) keyed by
   `(pid, dst_ip)` so a NetFlow record carries the originally-
   resolved hostname (not just the IP). Closes the "192.0.2.1
   means nothing" operator-experience gap.
3. **JA3 / JA4 TLS fingerprinting** (post-handshake). Userland
   parser reads the ClientHello bytes from the connect-side
   socket buffer, computes the standard fingerprint forms,
   attaches to the NetFlow record. NO payload decryption —
   metadata-only.
4. **9 detection rules** (NN-L-NET-001 through NN-L-NET-009)
   that classify network events into decision-engine verdicts:
   outbound to high-risk port, DNS for known-bad TLD, JA3
   match against threat-actor fingerprint, suspicious DNS
   tunnelling shape, etc.
5. **ADE handoff for High/Critical NetFlow events** — same
   tiered cap (10 individual + 1 batched overflow) as the
   FIM C9 ADE template (port the `AdeFimRateLimiter` shape
   verbatim for consistency).
6. **`nn-admin net` CLI surface.** `nn-admin net flows`,
   `nn-admin net listeners`, `nn-admin net resolve <ip>` (DNS
   cache lookup), `nn-admin net fingerprint <flow_id>` (JA3/4
   detail).
7. **Panopticon preparation** — chained, signed `netflow.jsonl`
   audit log + raw-packet capture PRIMITIVE (capacity to
   reserve N bytes per flow for forensic replay), but the
   FULL packet-capture daemon is deferred to **Tappa 11.5**.
   Tappa 10 ships the on-disk audit format + the kernel-side
   trigger; Tappa 11.5 wires the user-space pcap writer +
   the rolling-retention manager.

### 1.1 Out of scope for Tappa 10

- **Full packet capture / pcap retention** (Panopticon) —
  Tappa 11.5. Tappa 10 ships the trigger + on-disk envelope
  but no pcap writer task.
- **TLS payload decryption** (MITM CA injection, ssl_keylog
  side-channel ingestion) — never (sovereign / privacy red
  line per Tappa 0 charter).
- **HTTP/2 + HTTP/3 / QUIC parsing** (header introspection) —
  V1.1 differentiation; HTTP-over-TCP can be heuristically
  classified by port + JA3 shape in V1.0.
- **Active port scanning of the host** (security-posture
  baseline) — V1.1; Tappa 10 only observes existing
  listeners.
- **Centralised threat-intel feeds** (real-time C2 IP
  blocklist updates) — Tappa 13 SaaS-Backend; Tappa 10
  ships an OPERATOR-CURATED static list in
  `/etc/northnarrow/netflow-blocklist.v1`.

### 1.2 Threat model

The attacker has executed code on the host (typically via the
Tappa 2/3 execution-monitor sensors having missed something OR
the operator having explicitly allowed an exec) and is now
attempting to:

- **Establish C2** — TCP connect to attacker-controlled
  infrastructure, often over ports 443/8443/53 to blend with
  legitimate traffic.
- **DNS tunnel** — exfiltrate data over abnormally large /
  fast DNS queries (Cobalt Strike DNS beacon shape).
- **Lateral movement** — connect to internal hosts on
  unusual ports (SMB, RDP, WinRM) from a process that
  shouldn't normally do so.
- **Exfiltrate** — large outbound transfer to an unusual
  destination over a normally-quiet flow.

Tappa 10 does NOT prevent the network operation at the syscall
level (Tappa 5's `BlockOutbound` + `FullNetworkIsolation`
response actions are the prevention layer for specific verdicts;
the LSM hook layer is FIM-only). Tappa 10 *observes*, *classifies*,
and *surfaces* network behaviour to the operator + ADE within
seconds.

The chained on-disk NetFlow audit log is protected by Tappa 7
LSM + Tappa 9 C7 STATE_PROTECTED_FILES (see §10 — adds
`netflow.jsonl` + `netflow_listeners.jsonl` to the existing
list).

---

## 2. Current state inventory (IMPLEMENTED vs TODO)

### 2.1 IMPLEMENTED

- `TcpConnectRaw` wire type + `tcp_v4_connect` + `tcp_v6_connect`
  kprobes (Tappa 4 — `agent-ebpf/src/tcp_connect.rs`,
  `common/src/wire/mod.rs:131`). Events flow through the
  multiplexer's `tcp_connect` pump into `Event::TcpConnect`
  consumers today.
- `DnsQueryRaw` wire type + `udp_sendmsg` kprobe filtered to
  dest port 53 (Tappa 4 — `agent-ebpf/src/dns_query.rs`).
  Userland decodes the label-encoded QNAME to dotted notation
  in the multiplexer pump.
- `CorrelationBuffer` (Tappa 6 — `agent/src/correlation/mod.rs`)
  — generic time-windowed event ring; `get_correlated(focal,
  lookback_ns, max_hits)` returns events within the window.
  Tappa 10 reuses this for the DNS-to-flow lookup.
- Tappa 5 response actions: `BlockOutbound`,
  `FullNetworkIsolation`, `ThrottleProcess`,
  `Quarantine`. Tappa 10's rule layer emits these as the
  network-side verdicts.
- Tappa 9 C9 `AdeFimRateLimiter` + `OverflowBuffer` shape
  (Tappa 9 polish #4) — Tappa 10 ports verbatim as
  `AdeNetRateLimiter` (separate per-domain bucket; same
  10/min + 1/min envelope per §13 Q9).
- Tappa 8 B1 chained audit log primitives — Tappa 10's
  `netflow.jsonl` chain uses the same `prev_hash` /
  `entry_hash` / `agent_sig` triple.

### 2.2 TODO (gaps this design addresses)

- **No NetFlow correlation layer.** Each TCP connect today
  emits a single `Event::TcpConnect`; there's no grouping
  into a flow (connect + close, byte counts, duration).
- **No DNS-to-flow attribution.** A subsequent
  `Event::TcpConnect` to 1.2.3.4 doesn't know that 0.5s
  earlier the same PID resolved `evil.example.com → 1.2.3.4`.
- **No JA3/JA4 fingerprinting.** No userland TLS handshake
  parser exists.
- **No listener tracking.** Operators can't answer "what
  ports does this host listen on" without shelling out to
  `ss -tlnp`.
- **No outbound UDP observation** (besides DNS). Cobalt
  Strike DNS-tunnelling shape needs UDP-payload-size
  histograms; today we only see "DNS query for X".
- **No network rules.** The decision engine has 24 rules
  (R001..R010 + NN-L-FIM-001..014); none match
  `Event::TcpConnect`, `Event::DnsQuery`, or the new
  `Event::NetFlow` Tappa 10 introduces.
- **No `nn-admin net` CLI.** Operators can't query
  flows / listeners / DNS cache via the admin socket.
- **No `netflow.jsonl` audit chain.**

### 2.3 Test surface that already exists

- `agent-ebpf/src/tcp_connect.rs::tests` — kprobe-decision
  unit tests; Tappa 10 will add parallel listener-tracking
  tests.
- `agent-ebpf/src/dns_query.rs::tests` — QNAME-decode +
  port-filter; reused for the UDP-outbound observation
  Tappa 10 adds.
- `agent/src/correlation/mod.rs::tests` — time-windowed
  event correlation primitives Tappa 10's DNS-to-flow
  pass extends.
- `agent/tests/privileged_e2e.rs` — the PHASE_D_003
  `install_to_priv_bin` + `R009`-avoidance pattern (now
  shipped on every agent priv-e2e per Tappa 9 polish #1) is
  reusable for the Tappa 10 network-e2e tests.
- `agent/src/ade/fim_template.rs::AdeFimRateLimiter` + tests
  — Tappa 10's `AdeNetRateLimiter` is a near-copy with
  domain-specific naming. Test patterns port verbatim.

---

## 3. Architecture

```text
                  ┌──────────────────────────────────┐
                  │  Operator workstation            │
                  │  (nn-admin net {flows|listeners| │
                  │             resolve|fingerprint})│
                  └──────────────┬───────────────────┘
                                 │  Unix socket
                                 │  (signed AdminMessage, Tappa 8)
                  ┌──────────────▼───────────────────┐
                  │  agent/src/admin_socket.rs       │
                  │  + dispatch_net_flows etc.       │
                  └──────┬──────────────┬────────────┘
                         │              │
        ┌────────────────▼──┐  ┌────────▼──────────┐
        │ agent/src/net/    │  │ agent/src/audit.rs│
        │ flow_tracker.rs   │  │ (Tappa 8 B1)      │
        │   correlate_flow()│  │ Reused for the    │
        │   resolve_dns()   │  │ netflow chain.    │
        └────────┬──────────┘  └───────────────────┘
                 │
                 │ writes
                 ▼
        ┌───────────────────────┐
        │ /var/lib/northnarrow/ │
        │   netflow.jsonl       │  ← Tappa 7 LSM-protected
        │   netflow_listeners.  │  ← Tappa 7 LSM-protected
        │     jsonl             │
        └───────────────────────┘
                 ▲
                 │ append-on-close
                 │
        ┌────────┴──────────┐
        │ agent/src/net/    │   Drains TCP_CONNECT_EVENTS,
        │ drain.rs          │   DNS_QUERY_EVENTS, +new ringbufs;
        │   drain_loop()    │   builds NetFlowEvent;
        └────────┬──────────┘   classifies via NN-L-NET-*;
                 │                emits Event::NetFlow.
                 ▼
        ┌───────────────────┐
        │ Decision engine   │
        │ (Tappa 2 rules    │   NN-L-NET-001..009 + ADE for
        │  + ADE for high/  │   Critical/High.
        │  critical)        │
        └───────────────────┘

   ┌──────────────────────────────────────────────────┐
   │ Kernel BPF programs                              │
   │                                                  │
   │  (existing Tappa 4) tcp_v4_connect  → TCP_CONNECT│
   │  (existing Tappa 4) tcp_v6_connect  →   _EVENTS  │
   │  (existing Tappa 4) udp_sendmsg     → DNS_QUERY_ │
   │                                       EVENTS    │
   │                                                  │
   │  (NEW Tappa 10):                                 │
   │    inet_csk_listen      → NET_LISTEN_EVENTS      │
   │    udp_sendmsg_v6       → DNS_QUERY_EVENTS       │
   │      (extends Tappa 4's v4-only sensor)          │
   │    tcp_close            → NET_FLOW_CLOSE_EVENTS  │
   │      (emits byte-counters + duration on close)   │
   │                                                  │
   │  Maps: NET_LISTEN_EVENTS, NET_FLOW_CLOSE_EVENTS, │
   │        FLOW_SOCK_MAP (sk → flow_id).             │
   │                                                  │
   │  Observation-only — NEVER returns -EPERM. Tappa  │
   │  5 BlockOutbound + FullNetworkIsolation use the  │
   │  existing iptables-restore path; Tappa 10 doesn't│
   │  change that.                                    │
   └──────────────────────────────────────────────────┘
```

Tappa 10 introduces a **flow-tracker** layer in userland that
groups the kernel's per-event TcpConnectRaw + tcp_close into
single `NetFlowEvent` records. The existing CorrelationBuffer
becomes the DNS-resolution cache; the new flow_tracker.rs is
the per-flow state machine.

---

## 4. Data model

### 4.1 `NetFlowEvent` (userland decoded shape, common::wire)

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetFlowEvent {
    /// Monotonic-clock ns since boot — connect time.
    pub start_ns: u64,
    /// End time (close, or 0 if still open at observation).
    pub end_ns: u64,
    /// Five-tuple.
    pub family: u8,       // AF_INET or AF_INET6
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub proto: u8,        // IPPROTO_TCP or IPPROTO_UDP
    /// Process identity at connect time.
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: Option<String>,  // /proc/<pid>/exe at connect
    /// Byte counters (from tcp_close kprobe).
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    /// Tappa 10 DNS-attribution — the QNAME that resolved to
    /// `dst_addr` within the §6 correlation window. `None` if
    /// the connection went to an IP literal or the DNS cache
    /// missed.
    pub resolved_hostname: Option<String>,
    /// Tappa 10 JA3/JA4 — populated post-handshake (TLS only).
    pub tls_fingerprint: Option<TlsFingerprint>,
    /// Per-flow stable ID — `SHA-256(start_ns || five_tuple ||
    /// pid)[..16]` — operators reference flows by this in
    /// `nn-admin net fingerprint <flow_id>`.
    pub flow_id: String,
}
```

### 4.2 `TlsFingerprint`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFingerprint {
    /// JA3 — `MD5(client_version,ciphers,extensions,curves,
    /// curve_formats)`. Standard hex form.
    pub ja3: String,
    /// JA3 raw input string (the comma-separated tuple before
    /// MD5). Operator visible in `nn-admin net fingerprint`
    /// for debugging unknown fingerprints.
    pub ja3_raw: String,
    /// JA4 — `<protocol>_<version>_<cipher_count>_<extension_count>_
    /// <alpn>_<sha256_of_extensions>`. Newer standard
    /// (FoxIO / Salesforce, 2023) with better resistance to
    /// extension-reordering evasion.
    pub ja4: String,
    /// SNI server name (from ClientHello extension 0). `None`
    /// when no SNI extension OR when extracting failed.
    pub sni: Option<String>,
    /// ALPN protocol list (h2, http/1.1, …).
    pub alpn: Vec<String>,
}
```

### 4.3 `NetListenerEvent`

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetListenerEvent {
    pub timestamp_ns: u64,
    pub family: u8,
    pub bind_addr: IpAddr,
    pub bind_port: u16,
    pub proto: u8,
    pub pid: u32,
    pub uid: u32,
    pub comm: String,
    pub exe: Option<String>,
}
```

### 4.4 `NetFlowEntry` (on-disk JSONL row)

Persisted to `/var/lib/northnarrow/netflow.jsonl` (Tappa 7 LSM-
protected). Same hash-chain + signature shape as the Tappa 8
audit log + Tappa 9 baseline/drift chains so verification reuses
the existing primitives. Schema:

```json
{
  "ts": "2026-05-21T08:14:02.123456Z",
  "flow_id": "9f3c...",
  "start_ns": 12345678,
  "end_ns": 12349999,
  "five_tuple": "192.0.2.10:54321 -> 1.2.3.4:443 (TCP)",
  "pid": 8888, "uid": 0, "comm": "curl",
  "bytes_sent": 1234, "bytes_recv": 5678,
  "resolved_hostname": "example.com",
  "ja3": "abc123...", "ja4": "t13d1517h2...",
  "sni": "example.com",
  "verdict_rule_id": "NN-L-NET-001_OutboundToBlockedTld",
  "verdict_severity": "High",
  "agent_id": "1f8a...",
  "prev_hash": "abc...",
  "entry_hash": "def...",
  "agent_sig": "..."
}
```

---

## 5. BPF program list

### 5.1 Existing (Tappa 4)

| Program | Hook | Trigger |
|---|---|---|
| `tcp_v4_connect` | kprobe | TCP IPv4 connect entry |
| `tcp_v6_connect` | kprobe | TCP IPv6 connect entry |
| `udp_sendmsg` (DNS-filtered) | kprobe | UDP send to dest port 53 |

### 5.2 New (Tappa 10)

| Program | Hook | Trigger |
|---|---|---|
| `inet_csk_listen` | kprobe | TCP listen() syscall — emits `NetListenerEvent` |
| `tcp_close` | kprobe | TCP close() — emits byte counters via `FLOW_SOCK_MAP` lookup |
| `udp_sendmsg_outbound` | kprobe | UDP send to non-53 dest — emits abbreviated flow record |
| `tcp_data_capture_trigger` (V1.0 PRIMITIVE) | kprobe | Per-flow first-N-bytes capture into `PACKET_CAPTURE_RB`; user-space writer is Tappa 11.5 |

Each new program follows the Tappa 4 pattern: reserve a slot in
its dedicated ringbuf, populate the wire struct, submit. Verifier
complexity stays under aya 0.13's 1M-instruction limit per
program (the Tappa 4 existing ones are well under).

### 5.3 Resource budget

- `NET_FLOW_CLOSE_EVENTS`: 256 KiB ringbuf (~3000 events/s burst
  capacity — typical web workload generates ~50 conn/s, busy
  hosts ~500/s).
- `NET_LISTEN_EVENTS`: 64 KiB ringbuf (listener changes are
  rare events — daemon startup + occasional rebinds).
- `FLOW_SOCK_MAP`: LRU HashMap, **4096 entries**, key = sk
  ptr u64, value = flow_id u128. Bounds the per-flow state
  the kernel side carries.
- `PACKET_CAPTURE_RB`: 1 MiB ringbuf (V1.0 PRIMITIVE only;
  Tappa 11.5 writer reads + rotates).
- Per-program verifier complexity: ~80 instructions each
  (lookup + reserve + memcpy + submit).

---

## 6. Userland: drain + correlation + JA3/JA4

### 6.1 Flow tracker

`agent/src/net/flow_tracker.rs::FlowTracker`:
- Maintains a `HashMap<flow_id, FlowInProgress>` keyed by
  the per-flow stable ID from §4.1.
- On `Event::TcpConnect`, creates a `FlowInProgress` with
  start timestamp + connect-side metadata + a placeholder
  for end/byte-counters/fingerprint.
- On `tcp_close` event (from new BPF), looks up by sk ptr in
  `FLOW_SOCK_MAP`, finalises the flow with byte counters,
  emits one `NetFlowEvent` to the bus.
- On `Event::DnsQuery`, populates the DNS resolution cache
  (next subsection).
- TTL: a `FlowInProgress` that's been open >24h gets emitted
  with `end_ns = 0` (long-lived flow); subsequent close
  emits a SECOND entry with proper byte counters. This is
  intentional — operators see long-lived flows even before
  they close (SSH sessions, persistent C2 beacons).

### 6.2 DNS resolution cache

`agent/src/net/dns_cache.rs::DnsResolutionCache`:
- `HashMap<(pid, IpAddr), (qname, qtype, ts_ns)>` — keyed by
  the PID that issued the resolution (so cross-process
  cache misses don't pollute attribution).
- TTL: 5 minutes (matches typical OS resolver cache TTL).
- On `Event::DnsQuery`, parses the qname, awaits the
  response correlation (the response carries the resolved
  IPs; we observe DNS RESPONSES via the same `udp_recvmsg`
  pattern — a new BPF program in V1.1 or a libpcap-style
  userland sniffer; for V1.0 we use the simpler approach of
  populating the cache from RESPONSE-LESS query intent +
  letting the subsequent connect carry the dest IP that we
  back-correlate to the most-recent same-PID DNS query).
- On `NetFlowEvent` construction, look up
  `(pid, dst_addr)` → `qname` and populate
  `resolved_hostname`.

### 6.3 JA3 / JA4 fingerprinting

`agent/src/net/tls_parser.rs`:
- Triggered by the new `tcp_data_capture_trigger` BPF
  program — first 4096 bytes of each new TCP flow get
  copied to userland (capture primitive). For TLS, this
  includes the ClientHello.
- Userland parses the ClientHello structure (TLS RFC 5246
  §7.4.1.2): version, cipher_suites list, extensions list,
  supported_groups (curves), ec_point_formats.
- JA3 hash: `MD5(version,ciphers_sep_dash,extensions_sep_dash,
  curves_sep_dash,formats_sep_dash)` with field separators
  per the canonical JA3 spec.
- JA4 hash: per the FoxIO/Salesforce JA4 spec (newer,
  resistant to extension reordering).
- SNI extracted from extension 0; ALPN list from extension
  16. Both populate `TlsFingerprint` for operator
  visibility.
- 100% Rust parser — no `tls-parser` crate dep (the parsing
  is trivial; pulling a crate for ~200 lines of bit-level
  reading violates Tappa 0's "minimal dep" charter). The
  test suite includes ClientHello fixtures from real
  browsers + curl + known malware samples.

### 6.4 Storage protection

Two new files join the Tappa 9 C7 `STATE_PROTECTED_FILES`
under `/var/lib/northnarrow/`:

- `netflow.jsonl`
- `netflow_listeners.jsonl`

Same LSM caller-side exemption (PROTECTED_PIDS) means the
agent can append while every other root caller is denied.

### 6.5 NetFlow rate-limiting

Storm protection between the flow_tracker and the decision
engine, implemented as a **hierarchical token-bucket per
verdict tier** (same shape as Tappa 9 §6.5):

| Severity tier | Default rate | Configurable |
|---|---|---|
| Critical | **NO LIMIT** | No |
| High | 200 events / minute | Yes (`net.rate_limit.high_per_min`) |
| Medium | 1000 events / minute | Yes |

When a tier's bucket is exhausted, the flow_tracker:

1. **Always appends the `NetFlowEntry` to `netflow.jsonl`** —
   evidence preservation, same lock-in as FIM §6.5.
2. **Sets `decision_engine_skipped: true`** on the
   persisted entry.
3. **Skips the `Event::NetFlow` emission** to the decision
   engine for the suppressed event.
4. **Logs once per bucket-exhaustion window.**

`nn-admin net status` surfaces the current bucket state.

---

## 7. Detection rules — NN-L-NET-001 through NN-L-NET-009

Port + extension reference: the legacy M13.1-3 code shipped a
single rule (`net.outbound_to_unusual_port`). Tappa 10's set
is a refinement informed by EDR-vendor parity research +
recent IR-report TTPs.

| ID | Title | Match | Severity | Action |
|---|---|---|---|---|
| **NN-L-NET-001** | Outbound to operator-blocked IP/CIDR | dst_addr in `netflow-blocklist.v1` | Critical | KillProcessTree + posture→COMBAT |
| **NN-L-NET-002** | Outbound to operator-blocked TLD | resolved_hostname ends with blocked TLD (`.onion`, `.bit`) | High | KillProcess + posture→ENGAGED |
| **NN-L-NET-003** | JA3 match against operator-curated threat-actor list | `tls_fingerprint.ja3 ∈ blocklist` | Critical | KillProcessTree + posture→COMBAT |
| **NN-L-NET-004** | Suspicious DNS qname (long subdomains, base64 shape) | qname > 60 chars OR matches base64 regex | High | KillProcess + posture→ENGAGED |
| **NN-L-NET-005** | DNS qtype TXT/NULL burst (tunnelling shape) | >50 TXT/NULL queries from same PID in 60s | High | posture→ENGAGED + log |
| **NN-L-NET-006** | New listener on uncommon port | port ∉ {22, 53, 80, 443, 8080, 8443} AND comm ∉ allowlist | Medium | posture→ALERTED |
| **NN-L-NET-007** | Outbound to internal-RFC1918 from unusual process | dst_addr in 10/8, 172.16/12, 192.168/16 AND comm ∉ allowlist (`ssh`, `curl-internal`, …) | Medium | posture→ALERTED |
| **NN-L-NET-008** | Outbound from `/tmp/` exec to non-resolver | exe under `/tmp/` AND dst_port ∉ {53} | High | KillProcess + posture→ENGAGED |
| **NN-L-NET-009** | Flow byte-count anomaly | bytes_sent > 100 MiB on a single flow from non-allowlisted comm | High | posture→ENGAGED + log |

Each rule has the same structure as the existing FIM
NN-L-FIM-001..014 rules: a `match_event(&Event) -> Option<Verdict>`
method that inspects `Event::NetFlow(NetFlowEvent)` /
`Event::DnsQuery(DnsQueryEvent)` /
`Event::NetListener(NetListenerEvent)`.

**Cross-cutting rule note (Q4 lock-in port from Tappa 9):**
every `Critical`-severity rule above is **never throttled by
§6.5's NetFlow rate limiter**. NN-L-NET-001 (operator-blocked
IP) and NN-L-NET-003 (JA3 threat-actor match) fire on every
event regardless of bucket state — the events they catch are
documented C2 indicators and must not be suppressible.

---

## 8. ADE handoff

`severity = Critical` AND `severity = High` NetFlow events
route to the LLM second-brain per the existing Tappa 6 ADE
pipeline. The ADE prompt template — `agent/src/ade/net_template.rs`
(NEW; mirrors Tappa 9 C9 `fim_template.rs`) — carries:

- `NetFlowEvent` JSON
- The firing `Verdict`
- The DNS resolution history for the same PID (last 10
  resolutions in the last 5 minutes)
- The process spawn ancestry (parent + grandparent comm)

The LLM is asked to:

- Cross-reference recent process exec + file modifications
  (any Tappa 9 FIM events from the same PID?).
- Assess attack stage (initial access / persistence / C2 /
  exfil).
- Recommend next investigation steps (related IoCs to
  block, additional comms to watch).

`severity = Medium` / `Low` events stay in the deterministic-
rule path — same gate the rest of Tappa 6 + Tappa 9 use to
avoid LLM cost on low-severity events.

### 8.1 ADE prompt cost ceiling (port from §13 Q9)

Same tiered cap as Tappa 9 C9 FIM:

- **10 individual ADE prompts / minute** — one per Critical/
  High NetFlow event until the cap.
- **1 batched overflow prompt / minute** — fired when the
  individual cap is exhausted; correlation question
  ("multi-stage attack or independent events?").

Upper bound: **11 ADE calls / minute** in the NetFlow domain
(separate from the FIM 11/min — two domains, two budgets).
The DETERMINISTIC rule path is **never throttled by the ADE
cap** — it fires on every Critical/High event regardless of
whether ADE saw the event individually or in the batch.
`AdeNetRateLimiter` lives in `agent/src/ade/net_template.rs`
alongside the prompt builder (mirrors the Tappa 9 FIM
layout).

---

## 9. Wire protocol

NEW `AdminMessage` variants for the operator CLI. Each
appends LAST to preserve every prior variant's postcard
discriminant (per the §A7 wire-stability rule already in
force across Tappa 8 + Tappa 9):

- `AdminMessage::NetFlowsRequest(NetFlowsRequest)` —
  authorised by `Role::NetRead = 8` (NEW). 1-of-N
  signed-payload (workflow op per §13 Q6 of Tappa 9).
- `AdminMessage::NetFlowsResponse(NetFlowsResponse)` —
  carries the chained JSONL body + truncation flag (same
  shape as `FimReportResponse`).
- `AdminMessage::NetListenersRequest` /
  `NetListenersResponse` — read-only listener snapshot.
- `AdminMessage::NetResolveRequest(NetResolveRequest)` /
  `NetResolveResponse` — DNS cache lookup for an IP.
- `AdminMessage::NetFingerprintRequest(NetFingerprintRequest)`
  / `NetFingerprintResponse` — per-flow JA3/JA4 + raw
  ClientHello bytes (operator forensic detail).

New `OperationCode::NetFlows = 10`,
`OperationCode::NetListeners = 11`,
`OperationCode::NetResolve = 12`,
`OperationCode::NetFingerprint = 13`. New `Role::NetRead = 8`,
`Role::NetManage = 9` (the latter authorises future V1.1 ops
like `nn-admin net add-blocklist <ip>`).

The CLI flows mirror `nn-admin fim` exactly: challenge →
SignedPayload → submit → reply.

---

## 10. Systemd / deploy

No new systemd units. The NetFlow drain loop runs inside the
agent's existing tokio runtime (one new `tokio::spawn` in
`main.rs`, spawned post-attach alongside the existing sensor
pumps + Tappa 9 FIM drain).

Install changes (`deploy/install.sh` additions):

1. Bootstrap `/var/lib/northnarrow/netflow.jsonl` +
   `netflow_listeners.jsonl` as zero-byte placeholders
   (same shape as Tappa 9 C7's `fim_baseline.jsonl`).
2. Drop the curated default blocklist at
   `/etc/northnarrow/netflow-blocklist.v1` — operator-
   readable, agent-readable; format mirrors `fim-paths.v1`
   (one IP/CIDR per line, `#` comments). V1.0 ships with an
   empty file + a documentation comment ("operator
   populates from threat-intel feeds; see runbook").
3. `STATE_PROTECTED_FILES` extends to cover the two new
   netflow logs.
4. `ETC_PROTECTED_FILES` extends to cover
   `netflow-blocklist.v1` + the operator overlay
   `netflow-blocklist.local`.

The default JA3/JA4 fingerprint blocklist
(`/etc/northnarrow/netflow-ja3-blocklist.v1`) ships EMPTY
in V1.0 — the file is provisioned, but populating it
requires threat-intel curation that's out of Tappa 10
scope. Operators with EDR-vendor fingerprint exports drop
them into the `.local` overlay.

---

## 11. Testing strategy

### 11.1 Unit tests

- `agent-ebpf/src/net_listen.rs::tests` — kprobe decision
  unit tests for inet_csk_listen (~6 tests).
- `agent-ebpf/src/tcp_close.rs::tests` — sk-ptr lookup +
  byte-counter capture (~6 tests).
- `agent/src/net/flow_tracker.rs::tests` — connect→close
  state machine + long-lived-flow TTL + DNS attribution
  (~15 tests).
- `agent/src/net/dns_cache.rs::tests` — PID-keyed cache +
  TTL expiry + cross-PID isolation (~6 tests).
- `agent/src/net/tls_parser.rs::tests` — ClientHello
  fixtures from curl / firefox / chrome / java keytool +
  known-bad samples (Cobalt Strike default JA3) (~12
  tests).
- `agent/src/decision/rules/net.rs::tests` — one positive
  + one negative test per rule, plus path-/port-allowlist
  edge cases (~22 tests total).

### 11.2 Privileged e2e

Three privileged tests reusing the PHASE_D_003
`install_to_priv_bin` pattern (now ubiquitous post-Tappa 9
polish #1):

1. `net_outbound_connect_records_flow_with_dns_attribution`
   — spawn agent, resolve `localhost`, connect to 127.0.0.1
   on port 22 (SSH banner), close, verify `netflow.jsonl`
   row with `resolved_hostname = "localhost"`.
2. `net_ja3_fingerprint_extracted_on_tls_handshake` —
   spawn agent, `openssl s_client -connect example.com:443`,
   close, verify `netflow.jsonl` row with non-empty
   `ja3` + `sni = "example.com"`.
3. `net_listener_on_uncommon_port_records_event` —
   spawn agent, `nc -l 12345` for 1s, kill, verify
   `netflow_listeners.jsonl` row with `bind_port = 12345`
   AND the matching NN-L-NET-006 rule fires.

---

## 12. Effort estimate — commit-by-commit plan

Numbered against the §2.1/§2.2 inventory. Re-uses existing
`agent-ebpf`, `agent/src/correlation/`, `agent/src/audit.rs`,
`agent/src/admin_socket.rs` infrastructure. Estimated commit-
by-commit; total **~35–45 hours**.

| # | Title | Scope | Est. (h) |
|---|---|---|---|
| **N1** | `feat(common): NetFlowEvent + NetListenerEvent + TlsFingerprint wire types + Role::NetRead/NetManage + OperationCode::Net* additions` | New wire types + role/op-code additions. Tests: 6 (round-trip + variant ordering + role parse). | 3 |
| **N2** | `feat(agent-ebpf): inet_csk_listen + tcp_close + udp_sendmsg_outbound BPF programs + FLOW_SOCK_MAP + NET_LISTEN_EVENTS + NET_FLOW_CLOSE_EVENTS ringbufs` | New BPF programs alongside Tappa 4's connect kprobes. Tests: 8 (decision tests + verifier-passes assertion). | 6 |
| **N3** | `feat(agent): net/flow_tracker.rs — connect→close state machine + per-flow stable ID + emit Event::NetFlow` | Pure userland tracker. Tests: 15. | 5 |
| **N4** | `feat(agent): net/dns_cache.rs — PID-keyed DNS resolution cache + 5-minute TTL + flow attribution` | Built on existing CorrelationBuffer. Tests: 6. | 3 |
| **N5** | `feat(agent): net/tls_parser.rs — JA3 + JA4 + SNI + ALPN extraction from ClientHello (100% Rust, no tls-parser dep)` | Bit-level parser + fixture suite. Tests: 12. | 5 |
| **N6** | `feat(decision): 9 net rules NN-L-NET-001..009 + blocklist parser + posture transitions` | One rule per category. Tests: 22 (per-rule + edges). | 6 |
| **N7** | `feat(admin_cli): nn-admin net flows / listeners / resolve / fingerprint subcommands + signed-payload wiring + audit emission` | CLI surface + dispatch_net_*. Mirrors Tappa 9 C6 audit CLI pattern. Tests: 10. | 5 |
| **N8** | `feat(deploy): default netflow-blocklist.v1 + install.sh bootstrap + LSM widening of netflow.jsonl + netflow_listeners.jsonl + ETC widening for netflow-blocklist.v1` | ~empty V1.0 blocklist + install.sh changes + STATE/ETC_PROTECTED_FILES extensions. Tests: 6. | 3 |
| **N9** | `test(privileged_e2e): outbound flow w/ DNS attribution + JA3 extraction + uncommon-port listener detection` | New `agent/tests/net_privileged_e2e.rs` file. Reuses install_to_priv_bin. Tests: 3 privileged. | 4 |
| **N10** *(optional)* | `feat(ade): NetFlow ADE prompt template + AdeNetRateLimiter + integration` | Tappa 6 ADE integration for Critical+High NetFlow events (mirrors Tappa 9 C9). Tests: 8. | 5 |
| | **TOTAL** | | **~40–45 hours** ≈ 1.5–2 working weeks with CC pair-programming (N10 optional pushes to upper end). |

Phase-1 ships at N9 (CLI + detection + audit-grade reporting +
JA3/JA4 fingerprinting). N10 is the ADE enrichment alongside
Tappa 9 C9 — completes the LLM-context story across both FIM
and Network domains.

---

## 13. RFC resolutions

All 10 RFC items resolved 2026-05-19 (owner-accepted engineering
recommendations). N1 implementation unblocked, sequenced AFTER
the Tappa 9.5 K1-K8 sprint per project SHIP order. Each block
below: **Decision**, **Rationale**, **Implementation note**
(where in this doc / commit plan the decision manifests),
**Reversibility cost**.

### Q1 — JA3/JA4 collection scope

- **Decision:** COMPUTE FOR EVERY TLS FLOW in V1.0. No
  sampling, no per-process opt-in.
- **Rationale:** modern hosts process ~50 TLS handshakes/s
  peak; the JA3 parser runs in <100 µs per flow (MD5 +
  malloc-free reads). Total CPU budget < 0.5% on a busy
  host. Sampling complicates rule logic (rules expect
  fingerprints present); opt-in degrades the threat-
  hunting use case.
- **Implementation note:** §6.3 + N5 `tls_parser.rs`
  unconditional per-flow extraction. CPU budget verified
  in the N5 unit-test microbenchmark suite.
- **Reversibility:** easy (add a sample-rate knob if
  real-world CPU profiling shows pain; data model
  unchanged).

### Q2 — Packet capture primitive activation

- **Decision:** DORMANT in V1.0. The first-N-bytes BPF
  trigger compiles into the agent-ebpf object but is NOT
  attached — Tappa 11.5 attaches the kprobe alongside its
  user-space pcap writer in one atomic commit.
- **Rationale:** an active trigger with no consumer wastes
  ringbuf memory + adds verifier surface for no operator-
  visible value. Coupling the attach to the writer commit
  keeps the wire surface honest.
- **Implementation note:** §1.1 OUT OF SCOPE + §5.2 N2
  builds the program; main.rs N3 does NOT call its attach
  helper.
- **Reversibility:** easy (Tappa 11.5 just adds the
  attach + the writer; no V1.0 data-format commitment to
  honour).

### Q3 — DNS-to-flow attribution time window

- **Decision:** 5 minutes default TTL. Operator-tunable in
  V1.1 via `net.dns_cache_ttl_secs` in
  `/etc/northnarrow/config.toml`.
- **Rationale:** matches typical OS-resolver cache TTL
  (glibc nscd, systemd-resolved). 1 minute loses long-
  lived-flow attribution (browser-tab scenarios);
  30 minutes pollutes attribution when a process reuses
  an IP that resolved differently earlier.
- **Implementation note:** §6.2 + N4 `dns_cache.rs`
  `DnsResolutionCache::DEFAULT_TTL_SECS = 300`.
- **Reversibility:** easy (runtime-tuneable; default
  change doesn't break the wire format).

### Q4 — NetFlow rate-limiting tiers + caps

- **Decision:** PER-FLOW to audit chain (always) + HIERARCHICAL
  TOKEN-BUCKET on `Event::NetFlow` emission to the decision
  engine. Defaults: Critical **NO LIMIT**, High **200/min**,
  Medium **1000/min**. Suppressed events get
  `decision_engine_skipped: true` on the persisted entry.
- **Rationale:** same shape as Tappa 9 §13 Q4 — per-flow
  evidence preservation is non-negotiable; per-tier
  buckets protect the decision engine from web-browse
  flow volume (100+ flows/minute) without losing visibility.
  Critical-uncapped lock-in mirrors NN-L-FIM-001 + NN-L-FIM-010
  precedent (documented attack patterns must not be
  suppressible).
- **Implementation note:** §6.5 + N6 NN-L-NET-001/003
  Critical rules tagged "never throttled" in their match
  predicates; N3 flow_tracker implements the bucket
  between diff and emit.
- **Reversibility:** medium —
  `decision_engine_skipped: true` field commits to disk;
  bucket parameters are runtime-tuneable.

### Q5 — Operator blocklist format

- **Decision:** BARE FLAT LIST per file. Two files:
  `netflow-blocklist.v1` (IPs/CIDRs) +
  `netflow-ja3-blocklist.v1` (JA3 hashes). Each one entry
  per line, `#` comments, blanks ignored. Operator overlay
  via `.local` with `+entry` / `-entry` prefixes
  (Tappa 9 §13 Q7 precedent verbatim).
- **Rationale:** mirrors the Tappa 9 C7 `fim-paths.v1`
  shipping shape — no new YAML dep on the agent crate,
  operators inspect with `cat` + edit with `vi`. Same
  parser, same overlay semantics, same boot-WARN-on-
  disabled-default lock-in.
- **Implementation note:** §10 + N6 blocklist parser
  (reuses the Tappa 9 C7 `paths_config.rs` shape
  verbatim).
- **Reversibility:** easy (V1.1 can add a structured
  format alongside; flat format stays as the simple
  on-disk shape).

### Q6 — Listener tracking scope

- **Decision:** TRACK EVERY listener (every
  `inet_csk_listen` syscall). The chain captures all;
  the rule layer NN-L-NET-006 filters via comm + port
  allowlist, not via TTL.
- **Rationale:** historical visibility matters (post-
  incident: "did a listener appear in the 30 minutes
  before the C2 connect?"); TTL filtering at capture
  time discards forensic signal. Rule-side filtering
  keeps the operator-tunable comm/port allowlist
  authoritative.
- **Implementation note:** §5.2 + N2 `inet_csk_listen`
  BPF emits unconditionally; N6 NN-L-NET-006 rule does
  the allowlist filter.
- **Reversibility:** easy (V1.1 can add a "persistent
  listener only" filter as a rule-side option).

### Q7 — TLS handshake parser dependency

- **Decision:** HAND-ROLL the ClientHello bit-reader.
  No `tls-parser` / `rustls-*` crate dep.
- **Rationale:** the parsing surface is ~200 lines
  (RFC 5246 §7.4.1.2 short and stable; TLS 1.3
  ClientHello is a superset of V1.0 inputs). Pulling a
  crate violates Tappa 0's "minimal dep" charter; JA3/JA4
  hash inputs are exactly the fields the standard JA3
  spec lists — no parser-crate flexibility needed.
- **Implementation note:** §6.3 + N5 `tls_parser.rs`
  hand-rolled with comprehensive fixture suite (curl /
  firefox / chrome / java keytool + known-bad samples).
- **Reversibility:** medium (a parse-bug fix may take a
  follow-up commit; fixture-up-front mitigates).

### Q8 — NetFlow chain rotation policy

- **Decision:** V1.0 KEEPS FULL CHAIN. V1.1 ships signed
  `nn-admin net rotate` op with chain-of-chains
  continuation (same shape as Tappa 8 §14 Q9 audit-rotate
  + Tappa 9 §13 Q8 baseline-rotate + Tappa 9.5 §12 Q8
  canary-rotate).
- **Rationale:** a 1000-flow/day host generates ~30 MB
  per month; chains stay manageable for ~6 months. V1.1
  rotate joins the V1.1 rotation set across all four
  chained-audit primitives.
- **Implementation note:** no V1.0 implementation work;
  documented as deferred follow-up.
- **Reversibility:** easy (V1.1 rotate is additive; un-
  rotated chains stay verifiable forever).

### Q9 — ADE prompt cost ceiling

- **Decision:** PORT VERBATIM the Tappa 9 §13 Q9 tiered
  cap. 10 individual prompts / minute + 1 batched
  overflow prompt / minute, per domain. Total ADE call
  budget across FIM + NetFlow domains = **22 calls/minute**
  worst case (11 each).
- **Rationale:** same operational signal-density
  trade-off Tappa 9 C9 already locked in. Two separate
  domains = two separate budgets; cross-domain
  attribution is V1.1+.
- **Implementation note:** §8.1 + N10 (optional)
  `ade/net_template.rs` mirrors `agent/src/ade/fim_template.rs::AdeFimRateLimiter`
  + `OverflowBuffer` shape verbatim. Domain-scoped
  naming (`AdeNetRateLimiter`) keeps the budget
  separation explicit.
- **Reversibility:** easy (runtime-tuneable per domain;
  batched-overflow disabled by setting overflow cap to
  0 per Tappa 9 precedent).

### Q10 — SNI persistence in fingerprint chain

- **Decision:** PERSIST SNI in `netflow.jsonl` rows. No
  strip mode in V1.0.
- **Rationale:** the chain is LSM-protected (Tappa 7 +
  Tappa 9 C7 STATE_PROTECTED_FILES coverage), operator-
  only-readable, and SNI is already in-band on the wire
  (any threat actor with a tap sees it pre-encrypted).
  Stripping would degrade `nn-admin net resolve` +
  `nn-admin net fingerprint` operator utility for no
  real privacy gain.
- **Implementation note:** §4.2 `TlsFingerprint.sni:
  Option<String>` field carries through to the on-disk
  row + the wire response.
- **Reversibility:** easy (V1.1 can add an opt-in strip
  mode; rotation invalidates the historical chain).

### Cross-cutting consistency (lock-ins captured above)

1. **Q1 (per-flow JA3) + Q7 (hand-rolled parser)** → §6.3
   + N5 pull in zero extra workspace deps; CPU budget
   verified in N5 unit-test microbenchmarks. The whole
   TLS-fingerprinting path is dependency-free Rust.
2. **Q3 (5-min TTL) + Q6 (track every listener)** → both
   compound the `DnsResolutionCache` + listener-table
   memory footprint; bounded by §5.3 capacity caps + the
   per-process-PID-keyed shape.
3. **Q4 (Critical uncapped) + Q9 (ADE tiered cap)** →
   deterministic rule path always fires; ADE enrichment
   throttled by the same shape as Tappa 9 C9 (port
   verbatim). Two domains, two budgets.
4. **Q5 (flat blocklist) + Q7 (hand-rolled parser)** →
   keeps the V1.0 deploy surface dependency-free;
   install.sh ships an empty blocklist (operator
   populates) + a non-empty cipher-suite table for
   the parser.
5. **Q2 (dormant pcap trigger) + Tappa 11.5** → Tappa 10's
   on-disk schema is forward-compatible (pcap_ref field
   as `Option<String>` populated by Tappa 11.5). N2
   compiles the program; main.rs N3 holds off on the
   attach.

---

## Appendix A — Cross-references

- Tappa 4 multiplexer — `agent/src/sensors/multiplexer.rs`
  (existing TCP + DNS kprobes + pump pattern Tappa 10
  extends).
- Tappa 6 ADE — `agent/src/ade/` (LLM evaluate path Tappa 10
  routes Critical+High NetFlow events through).
- Tappa 7 task 5 — `agent/src/anti_tamper/filesystem.rs`
  (STATE_PROTECTED_FILES + ETC_PROTECTED_FILES Tappa 10
  extends with netflow files).
- Tappa 8 §9 — `agent/src/audit.rs` chain primitives the
  netflow chain reuses.
- Tappa 9 C7 — `docs/operator/TAPPA9_FIM_TRUST_MODEL.md`
  (TOFU + Q7 overlay model Tappa 10's blocklist follows).
- Tappa 9 C9 — `agent/src/ade/fim_template.rs`
  (`AdeFimRateLimiter` + `OverflowBuffer` shape Tappa 10
  ports as `AdeNetRateLimiter`).
- Old-repo commits `M13.1-3` — Phase-1 network sensors in
  the pre-NorthNarrow codebase; Tappa 10 NN-L-NET-001..009
  are the renamed + refined ports.

## Appendix B — Threat-model recap

| Attack | Detection layer |
|---|---|
| Outbound C2 to attacker-controlled IP | NN-L-NET-001 (blocklist match, Critical) |
| C2 over Tor hidden service | NN-L-NET-002 (`.onion` resolved hostname, High) |
| Cobalt Strike default JA3 fingerprint | NN-L-NET-003 (JA3 blocklist match, Critical) |
| DNS tunnelling (long encoded subdomains) | NN-L-NET-004 (qname > 60 chars / base64 shape, High) |
| DNS over TXT records (Cobalt DNS beacon) | NN-L-NET-005 (TXT/NULL burst, High) |
| Reverse shell listener on uncommon port | NN-L-NET-006 (uncommon port + non-allowlist comm, Medium) |
| Lateral movement to internal subnet | NN-L-NET-007 (RFC1918 dst from unusual process, Medium) |
| C2 from a `/tmp/` payload | NN-L-NET-008 (exe under /tmp/ + non-DNS port, High) |
| Large-byte exfil | NN-L-NET-009 (>100 MiB single-flow, High) |

Every attack in the table is detected within seconds of the
network operation completing (close-side for TCP; per-query for
DNS; first-flow for JA3), with `severity = High` or `Critical`
events routing to ADE for contextual analysis. The agent's
deterministic rule fires the kill + posture transition
regardless of ADE verdict — the LLM is enrichment, not a
gate.
