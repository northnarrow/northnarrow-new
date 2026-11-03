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
  by the next record.
- **Not seen:** DNS over TCP, DNS over TLS or HTTPS (a browser's own DoH, a
  resolver configured `DNSOverTLS=yes` upstream), a response longer than
  512 bytes past the cut (its first records are read; it says
  `truncated`).
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
- **Rule:** NN-L-NET-003 (a JA3 in the operator's signed
  `netflow-ja3-blocklist.local`) judges the hello, Critical. Its kill
  (`KillProcessTree`) is held behind the per-rule policy: no fingerprint
  was produced before this lot, so every match it makes is new (the
  decision of 21/10/2026); `enforce NN-L-NET-003` gives it back.
- **Budget:** 64 hellos at once, then 32 a second, per process; 512, then
  256 a second, per user (`tls_rate`).
- **Limits:** the bytes are user memory read when the send begins (a
  sender can rewrite them meanwhile, as it can shape its hello like another
  client's); a hello sent with the connect (TCP Fast Open) is not seen; a
  hello over 4,096 bytes, or split over several sends, is `incomplete`, no
  fingerprint.

## 4. NN-L-NET-028 — "no DNS, no connect"

Legitimate software nearly always looks a name up before it connects; an
implant often carries an address in its code. NN-L-NET-028 records a TCP
connect, or a UDP send, to a **public** address that the process and its
ancestors did not resolve through the system resolver: no DNS response the
lineage received named the address, and no name it asked for resolved to
it.

- **Verdict:** Medium when no process on the host resolved the address,
  Low when only another process did (a shared CDN address, an address
  handed over between processes). Once per process and destination every
  10 minutes. Its response, `KillProcess`, is **held** behind the per-rule
  policy, off by default: the verdict is `Log`. `enforce NN-L-NET-028` in
  the signed `rule-policy.local` gives the kill back.
- **Per lineage:** a binding is `(process, address)`, made when a response
  names the address to a process that received it or asked for its name
  (within 10 s, or later from the host's table of names, CNAME chains
  followed). It lasts for the name's TTL (at least 300 s, at most a day),
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
    name the lineage asked whose response was never seen (systemd-resolved
    answering from a cache older than the agent, or speaking DNS over TLS
    upstream); DNS records of the lineage held back by the kernel's
    budgets; for 5 minutes after a DNS record the parse worker could not
    decode; the DNS response sensor not running.
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
  `unit`) spares one program; `enforce NN-L-NET-028` arms the held kill.
- **Known false positives** (measured on the lab's workloads, lot 275 —
  the capability program (https://github.com/northnarrow/northnarrow-new/blob/main/docs/roadmap/CAPABILITY_PROGRAM.md)): clients that resolve outside the
  system resolver; peers configured by address (NTP servers, database
  replicas, mirrors by IP); rootless container networking whose helper
  (`slirp4netns`, `pasta`) connects for a container that resolved inside its
  own namespace; a ring overflow of the DNS sensors (counted in `dns`,
  `dns_answer`) that lost a response.

## 6. What it costs

Each source's programs run on hot paths: `tcp_sendmsg` (every TCP send: one
map lookup that misses after a flow's first send), `udp_recvmsg` (every UDP
receive: the return value's test and the source port), `inet_csk_accept`
(every accept). The lab's measurements with the three sources on, against
`main`, are in the capability program (https://github.com/northnarrow/northnarrow-new/blob/main/docs/roadmap/CAPABILITY_PROGRAM.md) (lot 275) and, per
source, in the capability manifest's terms.
