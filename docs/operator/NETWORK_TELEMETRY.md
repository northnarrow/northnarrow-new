# Network telemetry and "no DNS, no connect"

Lot 275 (capability C07, level 1 → 2) adds three sources of network
telemetry to the outbound connects, flows, listeners and DNS queries the
agent already recorded, and one rule that reads them, NN-L-NET-028. This
guide says what each source records, what it costs, what the rule judges
and how an operator tunes it. The sources' terms are in
[SENSOR_CONTRACT.md](SENSOR_CONTRACT.md) (`net_inbound`, `dns_answer`,
`tls_hello`); the per-rule policy that holds the rule's kill is in
[RULE_POLICY.md](RULE_POLICY.md).

## 1. Inbound connections (`net_inbound`)

- **What:** every TCP connection a process takes with `accept()` (an fexit
  on `inet_csk_accept`, in the accepting process's context), and its close
  (`tcp_close`). Each is an `Event::NetInbound` row with the attribution an
  outbound flow has: the accepting process (pid, uid, comm, the image the
  kernel executed, its start), the peer that connected (`src_*`), the local
  listener's end (`dst_*`); at the close the byte counters, the close
  reason (`sk_err`) and the canonical flow id.
- **Where:** the closed rows go to the signed netflow log
  (`/var/lib/northnarrow/netflow.jsonl`) with `"inbound": true`; an
  outbound row carries no such field (rows written before read the same).
  The rules of outbound flows do not read these rows.
- **Kernels:** `inet_csk_accept` has four parameters up to 6.9 and two from
  6.10; the agent reads the count from the kernel's BTF and loads the
  program built for it. A count no program is built for leaves the source
  off, signed (`net_inbound`).
- **Budget:** 256 accepts at once, then 512 a second, per accepting
  process; 2,048, then 1,024 a second, per user. An accept over it is not
  recorded (nor its close), counted in `inbound_rate`, and the process's
  next record carries the count (`SensorFlood`, NN-L-NET-021).
- **Limits:** the accepted sockets are kept in an LRU map of 65,536; past
  it (more connections accepted and open at once) the oldest entry goes,
  not counted, and that connection's close is not recorded (review of
  #495, N4).

## 2. DNS responses (`dns_answer`)

- **What:** every datagram a process receives from port 53 (an fexit on
  `udp_recvmsg` and `udpv6_recvmsg`), read from the receiver's own buffer
  once the kernel copied it there, up to 512 bytes. The parse worker
  decodes it (the core parses no DNS bytes, [WORKERS.md](WORKERS.md)): the
  question, the response code, the A, AAAA and CNAME records with their
  TTLs. Each is an `Event::DnsAnswer`.
- **Who receives what:** on a host whose `/etc/resolv.conf` names a stub
  resolver (Ubuntu's `127.0.0.53`), the application receives the stub's
  answer itself; on a host whose NSS asks systemd-resolved over varlink
  (`hosts: … resolve …`, Debian 13), systemd-resolved receives the upstream
  answer, and the name the application asked is the DNS query sensor's
  `dns_nss` record — the agent joins the two by name.
- **Budget:** 64 responses at once, then 128 a second, per process; 2,048,
  then 1,024 a second, per user; the local resolvers' users exempt (as for
  the queries). Held responses are counted (`dns_answer_rate`) and carried
  by the next record. One user's burst (2,048 records of 576 bytes) is more
  than the ring holds (512 KiB, about 910): the ring's losses are counted
  (`dns_answer`), as the DNS query ring's are. Either loss makes
  NN-L-NET-028's evidence unknown for every process for 5 minutes (review
  of #495, N3 and D3).
- **Not seen:** DNS over TCP, DNS over TLS or HTTPS (a browser's own DoH, a
  resolver configured `DNSOverTLS=yes` upstream), a response longer than
  512 bytes past the cut, or than the receiver's buffer (its first records
  are read; it says `truncated`, as for a response with the server's TC
  bit or a malformed record).
- **A size probe** (`recv(fd, NULL, 0, MSG_PEEK|MSG_TRUNC)`, as systemd's
  resolver asks a datagram's length): a record with nothing read
  (`unread`), its receiver's lineage noted as held — the resolver's, whose
  own connects go to the configured resolvers, not judged (the second
  review of #495, R4).
- **Kernels:** `udp_recvmsg` lost its `noblock` parameter in 5.19: six
  parameters before, five after, read from the BTF as for the accept.

## 3. TLS ClientHello fingerprints (`tls_hello`)

- **What:** the first send of every outbound TCP flow (an fentry on
  `tcp_sendmsg`; the connect kprobes mark the socket) when it is a TLS
  handshake record carrying a ClientHello, copied from the sender's buffer
  up to 4,096 bytes. The parse worker computes its JA3, JA4, SNI and ALPN.
  Each is an `Event::TlsClientHello`; the fingerprint is also attached to
  the flow, so its open-flow snapshots and its closed row in the netflow
  log carry `ja3`, `ja4` and `sni`.
- **Rule:** NN-L-NET-003 judges the hello: a JA3 or a JA4 in the
  operator's signed `netflow-ja3-blocklist.local` (one fingerprint a line,
  either form; list a client's JA4 when it permutes its extensions, as
  Chrome does from 108: its JA3 varies). **Medium, recorded, never acted
  on** (R6 of the external review of 04/11): a fingerprint is an attribute
  of the TLS stack — a library and its settings — not a program's
  identity; every program on the same stack shares it, and the fingerprint
  alone finds 6.82 % of malware against 88.68 % with the destination
  (Anderson & McGrew). The record says so. The per-rule policy refuses
  `enforce NN-L-NET-003` until the rule has a second predicate, a
  destination or an executable ([RULE_POLICY.md](RULE_POLICY.md) §2).
- **Budget:** 64 hellos at once, then 32 a second, per process; 512, then
  256 a second, per user (`tls_rate`).
- **Limits:** the bytes are user memory read when the send begins (a
  sender can rewrite them meanwhile, as it can shape its hello like another
  client's); a hello sent with the connect (TCP Fast Open) is not seen; a
  hello over 4,096 bytes, or split over several sends, is `incomplete`, no
  fingerprint. The connected sockets awaiting their first send are kept in
  an LRU map of 65,536: a flood of connects that never send evicts the
  oldest marks, not counted, and those flows' hellos are not seen (review
  of #495, N4; NN-L-NET-003 only records). One user's burst (512 hellos of
  4,176 bytes) is more than the 1 MiB ring holds (about 250): losses
  counted (`tls`). NN-L-NET-003 records each listed hello, with no
  deduplication (N8).

## 4. NN-L-NET-028 — "no DNS, no connect"

Legitimate software nearly always looks a name up before it connects; an
implant often carries an address in its code. NN-L-NET-028 records a TCP
connect, or a UDP send, to a **public** address the DNS evidence does not
bind to the process or an ancestor: no DNS response the lineage received
(a datagram from port 53, of the question's chain only) named the address,
and no response a **system resolver** received for a name the lineage asked
did. A system resolver is its executable — `systemd-resolved`, `dnsmasq`,
`nscd`, `unbound`, `named`, `pdns_recursor` or `kresd`, at its path in the
system tree — run by one of the host's resolver users (the dedicated
accounts the DNS budgets exempt; never root), in the host's mount
namespace, where that path names the host's file (the second review of
#495, R1: a path alone is never an identity — a container's
`/usr/sbin/dnsmasq` is not one). Never a process name: any other
process's response binds that process only. Where no resolver is
recognized (nscd as root, dnsmasq as `nobody`), the askers stay unknown:
fail-safe.

- **Verdict:** Medium when nothing bound the address, Low when only a
  system resolver's response for another lineage named it (a shared CDN
  address). Once per process and destination every 10 minutes. Its
  response, `KillProcess`, is **held** behind the per-rule policy: the
  verdict is `Log`, and the policy refuses `enforce NN-L-NET-028` for now
  (review of #495: an answer can be missing for benign reasons the agent
  cannot see — [RULE_POLICY.md](RULE_POLICY.md) §2).
- **Per lineage:** a binding is `(process, address)`, made when a response
  names the address to the process that received it, or — a system
  resolver's response — to a process that asked for its name (within 10 s,
  or later from the host's table of names, CNAME chains followed). Only the
  records of the question's chain count (its name, its CNAMEs' targets);
  any other record of a response is ignored. It lasts for the name's TTL (at least 300 s, at most a day),
  then 2 hours past each use: a daemon that resolved its peers once keeps
  them while it uses them. A process's ancestors count; a sibling does not.
- **Not judged (no record):**
  - a destination that is not public: loopback, RFC 1918, unique-local,
    link-local, CGNAT, multicast, broadcast, `0/8`, `240/4`, `198.18/15`
    (the documentation ranges are judged public);
  - the configured resolvers (`nameserver` lines of `/etc/resolv.conf` and
    of systemd-resolved's upstream `resolv.conf`);
  - an address of the signed allowlist `nodns-allow.local` (§5);
  - what the agent cannot judge (`unknown`): a process older than the DNS
    response sensor (it may have resolved before the sensor watched); a
    process whose start is not known, for a binding it holds; a name the
    lineage asked whose response was never seen whole (systemd-resolved
    answering from a cache older than the agent, or speaking DNS over TLS
    upstream; a response cut at 512 bytes, with the server's TC bit or a
    malformed record); DNS records of the lineage held back by its budget;
    **for every process, for 5 minutes** after a DNS record the parse
    worker could not decode, a user's DNS records held back, or a DNS ring
    or budget that lost records; a connect judged before the DNS pumps had
    read the records made before it; the DNS response sensor not running.
    A DNS flood therefore blinds the rule for a while (the floods
    themselves are NN-L-NET-020's records); it never alerts — and it shows
    (the second review of #495, R2): each loss of coverage for every
    process, and each connect judged before the DNS pumps caught up, is a
    signed `nodns_coverage_lost` row of the audit log (its `cause` —
    `undecoded`, `user_held`, `dns_losses`, `barrier` — and the `pid` and
    `uid` that caused it when known; at most one a cause every 5 minutes),
    and every beat of the heartbeat carries the rule's judgements by
    outcome and unknown reason (`nodns`, [HEARTBEAT.md](HEARTBEAT.md)). A
    burst of queries then a literal-IP connect leaves at least the row
    "NN-L-NET-028 blinded by `user_held`" or `dns_losses`.
  - **Severity, measured against the review's rules** (R5): `Low` comes
    only from a system resolver's response for another lineage; an address
    handed between processes outside a lineage, when no recognized resolver
    answered for it within its hold, is `Medium`.
- **"IP in the name":** an address its own name spells (`1-2-3-4.nip.io`,
  `1.2.3.4.sslip.io`, its hexadecimal form) binds nothing: such a name is a
  connect to that address.
- **What it does not catch:** a C2 behind a domain (it is pushed into the
  DNS records, where the DNS rules and the blocklists see it), a process
  that resolves for itself outside the system resolver (DoH, a resolver of
  its own), a C2 at an address some ancestor resolved.

## 5. Tuning

- **The signed allowlist** `/etc/northnarrow/nodns-allow.local`: one
  address or CIDR block a line (`203.0.113.7`, `198.51.100.0/24`,
  `2001:db8:1::/48`), `#` comments, at most 4,096 entries, no block wider
  than /8 (turn the rule off instead). Any bad line refuses the file. It is
  read at the agent's start, only when signed:

  ```
  nn-admin config overlay set nodns-allow --file nodns-allow.local --key <admin key>
  ```

  then restart the agent. The file and its signature are protected like the
  other overlays.
- **The per-rule policy** (`rule-policy.local`, [RULE_POLICY.md](RULE_POLICY.md)):
  `off NN-L-NET-028` drops it, `audit NN-L-NET-028` records without
  counting, `exempt NN-L-NET-028 exe <path> sha256 <hex>` (or `uid`,
  `unit`) spares one program. `enforce NN-L-NET-028` is refused (a policy
  you sign with it is refused; one signed before is applied with the line
  as `alert`, a signed degradation): its kill stays held.
- **False positives measured** (lot 275's lab, `deploy/lab/malsim/nodns-fp.sh`;
  again on 6.8 after both reviews of #495 — the system resolver by its
  executable, its user and the host's mount namespace, `Low` only from it:
  none, every workload rc 0;
  every NN-L-NET-028 record of a workload's window counted, also under
  another rule's record of the same event): **none** on Ubuntu 24.04 (6.8)
  and 22.04 (5.15) over `apt-get update` and a download-only install, 40
  parallel HTTPS fetches over 12 hosts and `wget -p` of a page, 30 s of
  `systemd-timesyncd`, a `git clone` over HTTPS, `apt-get download` from
  the mirror, a rootful and a rootless podman container fetching over
  HTTPS, and lookups through the configured resolver (stub `127.0.0.53`,
  `hosts: files dns`). On 22.04 two of them did not complete, for causes
  outside this rule: the `git clone`'s HTTPS helper died of `SIGILL` in
  libgnutls on the guest's virtual CPU (after its connect, which was
  judged), and the rootful container did not start (R011 killed the
  `modprobe` podman ran). Not measured: `nss-resolve` hosts, Docker, a
  resolver other than systemd-resolved, browsers.
- **Expected false positives** (by design, not measured): clients that
  resolve outside the system resolver (DoH, a resolver of their own);
  peers configured by address (NTP servers, database replicas, mirrors by
  IP); rootless container networking whose helper (`slirp4netns`, `pasta`)
  connects for a container that resolved inside its own namespace; a
  container on Docker's default bridge whose resolvers fall back to public
  ones (8.8.8.8: its processes' UDP sends to port 53 are judged, and the
  answers they receive bind only themselves — review of #495, N5); a
  response a process received from a resolver it runs itself that is no
  system resolver. Load tools that connect to literal addresses draw it
  too: the lab's EXP-13 probe does, by design. A DNS ring's overflow, or
  records held back by a budget, no longer draws it: the evidence is then
  unknown for every process for 5 minutes.

## 6. What it costs

Each source's programs run on hot paths: `tcp_sendmsg` (every TCP send: one
map lookup that misses after a flow's first send), `udp_recvmsg` (every UDP
receive: the return value's test, the source address read and its port
compared), `inet_csk_accept` (every accept). Measured in lot 275's lab
(`nn-lab.sh overhead 3`, medians of 3 rounds, throughput lost with the agent
running, every source on; Ubuntu 24.04 / 22.04 guests):

| workload | 6.8: main | 6.8: lot 275 | 5.15: main | 5.15: lot 275 |
|---|---|---|---|---|
| `udp` (64-byte sends, each received) | +17.1 % | +22.8 % | +5.4 % | +23.1 % |
| `udprecv` (a loopback datagram received) | — | +20.9 % | — | +22.6 % |
| `tcpsend` (64-byte sends on one connection) | — | +1.9 % | — | +2.8 % |
| `connect` (connect, accept, close) | +11.7 % | +15.0 % | −8.4 % | +15.2 % |
| `dns` (queries sent) | +16.5 % | +10.5 % | +2.3 % | +16.1 % |

The UDP receive path is where the cost is: every receive runs the DNS
response program. Before the review of #495 it read the source's pointer,
family, port and address before the port's test; from then the family and
the port in one read and the address only for port 53. The figures above
are from before. After it (lab round 5, Ubuntu 24.04; the same figures are
the sensor contract's overhead entries, in the signed manifest):

| program | per call (`run_time_ns / run_cnt`, BPF stats on) | the workload with the agent on (stats off, medians of 3) |
|---|---|---|
| `dns_answer` (`udp_recvmsg`) | about 128 ns a receive from another port (88 ns a call with an empty receive between; 5.15: about 44 ns) | `udprecv` +20.6 %, `udp` +19.7 % |
| `tls_hello` (`tcp_sendmsg`) | about 121 ns a send | `tcpsend` +9.9 % |
| `net_inbound` (`inet_csk_accept`) | about 666 ns an accept | `connect` +5.9 % |

`deploy/lab/overhead/prog-cost.sh` measures the first column. The workloads
`udprecv` and `tcpsend` are new with this lot (no `main` figure). The
rounds are noisy (`connect` on 22.04's `main` run reads −8.4 %); the
per-run reports are in the capability program's lot 275 note.

