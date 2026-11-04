# The export of the signed chains (OCSF, JSONL, syslog over TLS)

Lot 276 (capability C21, the minimal signed export; R15's first step). The
agent's signed chains leave the host as OCSF 1.9.0 records — to rotating
JSONL files, and to a syslog receiver over TLS (RFC 5425) — each record
carrying its signed row, so a receiver checks it with the agent's public
key alone. **Off by default**: a signed `export.local` turns it on.

The design: [the process model](https://github.com/northnarrow/northnarrow-new/blob/main/docs/architecture/PROCESS_MODEL.md)
§11; the workers: [`WORKERS.md`](WORKERS.md).

## 1. What is exported

| Chain (`chain =`) | File on the host | OCSF 1.9.0 class(es) |
|---|---|---|
| `detections` | `/var/lib/northnarrow/detections/detections.jsonl` (+ archives) | Detection Finding (2004); a detection of the exec sensor also its Process Activity (1007, Launch) |
| `actions` | `/var/lib/northnarrow/detections/actions.jsonl` | Remediation: Process (7003), File (7002), Network (7004) or the generic Remediation Activity (7001); run markers and overflows a Base Event (0) |
| `fim_drift` | `/var/lib/northnarrow/fim_drift.jsonl` | File System Activity (1001) |
| `netflow` | `/var/lib/northnarrow/netflow.jsonl` | Network Activity (4001, Traffic) |
| `canary_access` | `/var/lib/northnarrow/canary_access.jsonl` | File System Activity (1001, Open), Process Activity (1007) or Network Activity (4001, Open) by the canary's kind |

The mapping, row by row:

| Row | Class / activity | What it carries |
|---|---|---|
| detection | 2004 Detection Finding / Create | `finding_info` (uid `<agent>/detection/<id>`, title, `types`, `analytic` Rule with the rule's id and name, `attacks` from its ATT&CK ids, version), `evidences` (the process; the file; the destination of a network detection), `actor.process`, `severity_id` (Low 2 … Critical 5), `status_id` (Open → New, Acknowledged/Investigating → In Progress, Resolved → Resolved, FalsePositive → Other), `confidence_score`, `is_alert` |
| detection of the `Exec` sensor | + 1007 Process Activity / Launch | the process, its parent as `actor` |
| action `intent` | 7003 / 7002 / 7004 / 7001 by its response (`Kill*` Evict, `Quarantine` Isolate, `StripFileCapability` Harden, `BlockOutbound`/`Isolate` Isolate, `Release` Restore, `Throttle` Other) | `command_uid` `<run>/<action>`, the target (process pid, file, connection direction), `remediation.desc` (why), status Other "intended" |
| action `outcome` | the class of its intent (7001 when the worker has not seen it) | status Success / Failure / Partial / Other (would execute, not run) / Error (abandoned), `status_detail`, `duration`; `metadata.correlation_uid` shared with its intent, the intent's row named in `unmapped.northnarrow.intent_row` |
| action `interrupted` | its intent's class | status Error: the agent stopped between the intent and its outcome |
| action `overflow`, `stalled`, `run_started`, `run_ended` | 0 Base Event / Other | the row as `raw_data` |
| FIM drift | 1001 / by its op: Modified Update, Created/Linked Create, Deleted Delete, Renamed Rename, Opened Open, CapabilitySet Set Security, AttrChanged Set Attributes | the file (path, SHA-256 of its new content), the modifier as `actor.process` |
| netflow | 4001 / Traffic | `src_endpoint`, `dst_endpoint` (its resolved name), `connection_info` (protocol, IP version), `traffic` (bytes in, out), `duration`, status by its close; JA3, JA4, SNI in `unmapped.northnarrow` |
| a row that does not parse, or of a kind not known | 0 Base Event / Other | its bytes as `raw_data` (nothing a chain holds is dropped by the mapping) |

Every record has `metadata` (`version` 1.9.0, `profiles` `["host"]`, the
product, `uid` `<agent_id>/<chain>/<file>/<line>[/1]`, `log_name` the
chain), `device` (the host's name, the agent's id), and:

- `raw_data`: **the signed row, verbatim** (the line as on disk);
- `unmapped.northnarrow.row`: its place — `chain`, `file` (the archive
  number; the active file's is the number it will take; 0 for the flat
  canary chain), `line` (from 1), `end` (the byte its line ends at) — its
  links `prev_hash`, `entry_hash`, whether the export worker verified it
  (`verified`), and on the first row after a rotation the terminator that
  sealed the file before (`rotate`, verbatim).

The schema is pinned: `crates/nn-export/ocsf/ocsf-1.9.0.json` (the classes'
JSON Schema and their enumerations' captions as schema.ocsf.io serves them
for 1.9.0 with the `host` profile, each download's SHA-256 recorded;
`crates/nn-export/tests/ocsf_vendor.py` rebuilds it). Every record the mapping writes is validated
against it by the tests (`nn_export::schema`).

## 2. Turning it on

`/etc/northnarrow/export.local`, signed like every overlay (a key with
`config-manage`; `docs/operator/RULE_POLICY.md` §2 for the signing flow):

```text
enabled = true
chain = detections          # repeated; none named: all five
chain = actions
start = end                 # end: the rows written from now | oldest: every row the chain holds
file = on                   # the JSONL files
file_max_bytes = 64MiB      # each file, 1MiB..1GiB
file_max_files = 4          # 1..32, the active file with them
syslog = 192.0.2.10:6514    # an IP and a port — the worker resolves no name
syslog_server_name = siem.example.org   # its certificate's name (default: the IP)
syslog_ca = /etc/northnarrow/export-ca.pem
syslog_ca_sha256 = <64 hex> # sha256sum of that file: the signed text pins the CA
syslog_facility = 13        # 0..23 (13: log audit)
```

The CA file goes into `/etc/northnarrow`, which the agent protects: copy
it inside a trusted-installer window (outside one the copy is refused,
`Operation not permitted`), then sign and set the text that pins it:

```
sudo nn-admin trusted-installer-grant --key ops.key --window-secs 60
sudo install -m 0644 receiver-ca.pem /etc/northnarrow/export-ca.pem
sha256sum /etc/northnarrow/export-ca.pem      # → syslog_ca_sha256
nn-admin config overlay sign export --file export.local --key ops.key   # offline
sudo nn-admin config overlay set export --file export.local --key ops.key
```

It takes effect at the agent's next start (as every overlay but the rule
policy). An unknown key, a value out of its bounds, a syslog sink without
its CA, a CA file whose SHA-256 is not the one the text pins: the export
**fails** (a signed degradation `export: configured, failed: …`), and
nothing is exported. A file whose signature does not verify: **refused**
(the gate's `unauthorized_overlay` row, and `export: configured, refused`).

## 3. How it runs

- The **core** (root) reads its chains on a thread of its own (`nn-export`,
  no capability, `nice` 10 — never the decision thread, never a lock of the
  evidence writers'), row after row after each sink's cursor, verbatim. It
  parses nothing of a row but its seal's hashes.
- The **export worker** — the agent's binary as `northnarrow-worker`,
  sandboxed (§5) — verifies each row with the agent's public key, maps it to
  OCSF, writes it to its sink and says which rows are delivered.
- The core moves each sink's **cursor** past the delivered rows only, and
  writes the cursors (`/var/lib/northnarrow/detections/export-cursors.json`,
  atomically, at most every 2 s and at the stop). **At least once**: after a
  receiver's outage, a worker's restart or the agent's, the rows after the
  cursor are sent again; a receiver deduplicates by `metadata.uid` (or by
  chain, file and line).

**Delivered** means: for the file sink, written and `fdatasync`ed; for
syslog — which has no acknowledgement of its own — every byte of the row's
records acknowledged by the receiver's TCP (`SIOCOUTQ`), and the connection
still up one second later (the *settle*). A receiver that stops with bytes
it has not read resets the connection (its kernel answers a close with
unread data by `RST`): every row that had not settled is written again. The
loss this cannot see: a receiver process that read the bytes and lost them
(a crash before it wrote them) after the settle, or one that kept the
connection open without reading for longer than the settle and then died.

**A slow, silent or hostile receiver costs the agent nothing but the
export's own thread**: each request to the worker has a budget (1 s); the
worker never blocks on the network (non-blocking sockets, `ppoll`), keeps
at most 1 MiB of records in flight, drops a connection on which nothing was
acknowledged for 30 s, a handshake not done in 10 s, a receiver that sends
application data; a sink that fails backs off (1, 2, 4 … 60 s). One
connection carries at most 64 MiB, then a fresh one takes over.

The JSONL files: `/var/log/northnarrow/export/export.jsonl`, rotated to
`export.jsonl.1` … once it would pass `file_max_bytes`, the oldest removed:
at most `file_max_files × file_max_bytes` on disk. The directory is the
worker account's (0750; a shipper reads it as root, or is given the group).
A shipper behind the rotation misses what rotated out: the chains are the
record, the files the bound.

## 4. What you see

```
$ sudo nn-admin export status --key ops.key
export: on
  config: on · chains detections,actions · start end · file (4 × 64 MiB), syslog 192.0.2.10:6514 (siem.example.org)
  config sha256: 5e1f…
  ocsf 1.9.0 · worker ready · port pinned yes · stage 8 lost 0
  sink file /var/log/northnarrow/export: up · 1204 row(s), 1612 record(s), 0 unverified, 0 fault(s), 0 lost · last …
    detections: cursor 3/112 · 0 in flight · 0 byte(s) behind · 0 lost
  sink syslog 192.0.2.10:6514 (siem.example.org): down (connect: Connection refused) · …
    detections: cursor 3/80 · 0 in flight · 9811 byte(s) behind · 0 lost
```

(`--json` for the same as JSON.) And:

- **stage 8** of the loss counters (`nn-admin status --key`, the signed
  `telemetry_loss` rows, every beat's `loss`): the rows the export can no
  longer deliver — a chain's archive evicted before a sink read it (its
  rows, from the chain's manifest: a lower bound, the manifest's count of a
  file being its last run's rows when the file spans an agent restart; the
  `export_state` note names the files), a row longer than a request
  carries (48 KiB). A verifier says `LOSS … stage 8 (export)`.
- the signed **`export_state`** rows of the audit log: at the start (the
  configuration's hash, the chains, the sinks, the cursors), at a sink's
  change of state (a worse one at once, a better one at most once a minute),
  at a chain moved under a cursor (`note`: evicted, `cursor_gone`,
  `cursor_ahead`, `oversize`), at the stop (each sink's counts, the
  cursors).
- the **capability manifest**'s `export` (state, chains, sinks, the
  configuration's hash, the port pin as measured); its changes signed as
  `capability_manifest_change`.
- each **beat**'s `export` (state, each sink's state, rows, bytes behind):
  `nn-admin heartbeat watch` says `DEGRADED` when the export is not `on` or
  a sink `failed`. A sink `down` is the receiver's: its rows wait in the
  chains (and stage 8 counts what they lose).

## 5. The export worker's sandbox

The parse worker's (`WORKERS.md` §3) with what its sinks need, no more:

- **Landlock, layer 1** (at its start): every filesystem right handled, one
  rule — read, list, write, create, remove, truncate regular files beneath
  `/var/log/northnarrow/export` (`fs_rules` in the manifest's `workers`).
  Signals and abstract sockets scoped (ABI ≥ 6).
- **Landlock, layer 2** (after its setup told it the receiver): TCP connect
  allowed to the receiver's **port** only — measured (a connect to another
  port refused with `EACCES`) and required by the core where the kernel's
  Landlock handles TCP (ABI ≥ 4: Ubuntu 24.04, Debian 13); the manifest says
  `port_pinned`. Landlock pins ports, not addresses; the address is the
  configuration's, the worker's code connects nowhere else. On ABI < 4
  (Ubuntu 22.04, Debian 12) no kernel layer pins its connects: the seccomp
  filter still allows TCP sockets only.
- **seccomp**: the parse worker's calls; `socket` (TCP over IPv4 or IPv6,
  non-blocking, close-on-exec, nothing else), `connect`, `ppoll`,
  `getsockopt(SO_ERROR)`, `ioctl(SIOCOUTQ)`, `sendto`/`recvfrom` with no
  address on a descriptor above its channel; `openat` with exactly the
  sink's flags (append, create, no link followed), `write` above the
  channel, `lseek`, `fdatasync`, `renameat2`, `unlinkat`; the three Landlock
  calls (for layer 2: a layer only takes rights away). No `exec`, no
  process, no UDP, no UNIX socket by path, no `ptrace`, no `bpf`.
- 16 descriptors, 512 MiB of address space, no process, no core.

It holds no key of the agent's: it verifies rows with the public key the
core hands it. It reads no chain (root's, 0600 in 0700 directories) and
writes no cursor: the core does both.

## 6. Checking what arrived (the receiver's side)

```
nn-admin export verify --agent-pubkey-file agent.sig.pub --file received.jsonl
```

reads records — the JSONL files' lines, or a syslog receiver's messages one
a line (an RFC 5424 header before the record, its RFC 5425 length too if it
kept the frames) — and checks:

- each record's `raw_data` is a row signed by the agent's key (the chain's
  domain, the hash recomputed from the row's bytes, the signature strict),
  and its `entry_hash` the one the record names. The row's format is read
  as the chain log reads it: `fmt_ver` 3 under the chain's domain, none or
  up to 2 (rows an older agent wrote, still in the archives) without it, a
  later one refused as a format this reader does not know;
- each chain's rows, in their order, link: a row's `prev_hash` is the row
  before it's `entry_hash`; across a rotation through the terminator the
  first row of the next file carries;
- a record delivered twice is counted (`duplicates`), not refused.

Exit 0 (`OK`), 13 a row that does not verify (`TAMPERED`), 11 a chain that
does not follow (`BROKEN`: rows missing — an export that was off, a gap the
agent's stage 8 counted, or rows taken out on the way), 2 lines that are no
record, or no record at all (`EMPTY`: an empty capture proves nothing). The agent's public key: `/etc/northnarrow/agent.sig.pub` on the host,
copied off it once.

## 7. The TLS stack and its dependencies

rustls with the RustCrypto provider (`rustls-rustcrypto`) — the founder's
decision: TLS in Rust only (aws-lc-rs is C; ring has C and assembly),
accepting a younger provider. Both pinned exactly (`=0.23.46`,
`=0.0.2-alpha` in `crates/nn-export/Cargo.toml`): they move only by a
reviewed edit. rustls is built without its defaults (no aws-lc-rs, no TLS
1.2, no logging), the provider without TLS 1.2.

The worker narrows the provider (`nn_export::tls::provider`): TLS 1.3, its
three suites, **X25519 only**, no client certificate and a key provider
that loads no private key (`NoKeys`), the receiver's chain checked by
rustls' own WebPKI verifier against the pinned CA bundle: rustls'
`with_root_certificates` builds its `WebPkiServerVerifier`, on rustls'
rustls-webpki 0.103.16 (`verify_for_usage`, then the name); the provider's
only part in it is its signature algorithms. The
provider's release (April 2024) is built on the RustCrypto generation of
that time, which the workspace had moved past: it brings its own copies
(sha2 0.10, p256 0.13, rsa 0.9, rustls-webpki 0.102 …). `cargo audit`
reports eight advisories in them, each recorded in `.cargo/audit.toml`
with why it is not reached here and a test that holds the narrowing:

| Advisory | Crate | Why not reached |
|---|---|---|
| RUSTSEC-2026-0049, -0098, -0099, -0104, -0382 | rustls-webpki 0.102.8 | the provider takes its `alg_id` constants only; certificates are verified by rustls' rustls-webpki 0.103.16 (patched) |
| RUSTSEC-2023-0071 (Marvin) | rsa 0.9.10 | RSA private-key operations only; the worker holds no RSA key, it verifies signatures (public data) |
| RUSTSEC-2026-0387 | crypto-bigint 0.5.5 | timing on secrets: P-256 and P-384 key exchange are removed (X25519 only, curve25519-dalek 4.1.3), no ECDSA key is held; ECDSA verification runs on public data |
| RUSTSEC-2024-0436 | paste 1.0.15 (unmaintained) | a procedural macro of the provider's: compile time only |

Licences: rustls (Apache-2.0 OR ISC OR MIT), rustls-webpki (ISC),
rustls-pki-types (MIT OR Apache-2.0), untrusted (ISC),
rustls-rustcrypto and the RustCrypto crates (MIT OR Apache-2.0),
num-bigint-dig (MIT/Apache-2.0); all permissive and compatible with the
agent's Apache-2.0. The lockfiles change by the new crates (Cargo.lock,
fuzz/Cargo.lock): the lot's note lists them.

## 8. Limits (what is open)

- The configuration takes effect at the next start (no reload).
- Syslog's delivery is the receiver's TCP plus the settle (§3): no
  application acknowledgement — RELP, or OTLP with its own, is later
  (R15's rest). A receiver that keeps its session up but has not read
  what its kernel acknowledged — it never reads, or reads slowly — and
  dies more than a second later loses those bytes (at most its receive
  buffer): the export counted the rows delivered. The lab measures it
  (`export-guest.sh` phases `slow` and `stall`): the rows lost are only
  rows written while that receiver held the connection (lot 276's lab,
  round 4: of 47 rows written while it held it, 42 lost on Ubuntu 26.04
  and 28 on Debian 12 behind a receiver reading 512 bytes a second; of 46,
  43 and 31 behind one that never read). Reading the peer's advertised window
  (`TCP_INFO`'s `tcpi_snd_wnd`, recent kernels) could hold such rows back
  until the receiver read them; RELP's acknowledgement would on all.
- No client certificate (mTLS): the receiver is authenticated, the agent
  is by its signed rows only.
- Landlock pins the port, not the address; below ABI 4 nothing in the
  kernel pins the worker's connects (a per-role address pin in the BPF LSM
  `socket_connect` hook would, on every kernel).
- The worker's own flows to its receiver are judged by the agent's network
  rules like any process's (NN-L-NET-007 alerts on an internal receiver):
  exempting the export worker's pid to its configured receiver is a
  follow-up.
- Not exported: the audit log, the status events, the heartbeat (which has
  its own verifier, `HEARTBEAT.md`), the netflow listeners, the FIM
  baseline.
- The receiver's check proves each row is the agent's and its chain
  continuous from the first row it saw; that the agent is honest is the
  heartbeat's and the off-host anchor's matter (R16).
