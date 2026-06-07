# Finding: NN-L-NET-004 attributes forwarded DNS to the resolver, not the originator (FP-3)

> FP numbering follows `docs/validation/DETECT_ONLY_VALIDATION_2026-06-05.md` in list order:
> FP-1 = NN-L-FIM-005 rsyslogd (commit `171018a`), FP-2 = mass-write/npm (`353199d`),
> **FP-3 = this (NN-L-NET-004)**, FP-4 = NN-L-FIM-007 dedup.

- **Status:** REPORT-ONLY — analysis + proposal. **No rule/attribution code changed.** Needs Fortunato's architectural sign-off (the fix touches the DNS event shape + a new attribution path).
- **Date:** 2026-06-07
- **Branch:** `benchmark/cc-t7-13-fix`
- **Severity of the FP:** **High.** The rule's action is `KillProcess`; mis-attributed to the local forwarder it would `SIGKILL` `systemd-resolved` (pid 673 on the dev host) → **host-wide DNS outage.** The forwarder is **not** in any kill-protection set (see §4), so the outage is real, not hypothetical.
- **Scope note:** the same attribution flaw affects all three DnsQuery-sourced rules — **NN-L-NET-004** (qname shape, `KillProcess`), **NN-L-NET-014** (qname entropy, `KillProcess`), and **NN-L-NET-005** (TXT/NULL burst, `Log`). 004/014 are the dangerous ones (they kill); 005 mis-counts under the forwarder's PID. A fix should be designed for the family, not just -004.

---

## 1. The false positive

A DGA-shaped / base64-shaped DNS qname issued by some workload is attributed to the **local forwarding stub resolver** (`systemd-resolved`, pid 673) rather than to the **process that actually issued the lookup** (the "originator"). On a kill action this takes out the host's DNS.

The dev host runs the standard Ubuntu/Debian split-resolver layout — `systemd-resolved` listening on the loopback stub `127.0.0.53:53`, confirmed by the COMBAT isolation ruleset which explicitly preserves it:

```
agent/src/response/network_isolation.rs:113
  "add rule inet {table} isolation_output ip daddr 127.0.0.53 udp dport 53 accept comment \"NN-iso local-DNS\"\n",
```

---

## 2. Attribution path, end to end (what PID is recorded today)

### 2.1 Kernel sensor — `agent-ebpf/src/dns_query.rs`

The sensor is a **kprobe on `udp_sendmsg` filtered to destination port 53**. It records the PID of **whoever calls `udp_sendmsg`**, i.e. the current task at the moment the datagram is sent:

```
agent-ebpf/src/dns_query.rs:149-155
  let pid_tgid = bpf_get_current_pid_tgid();
  ...
  (*raw_ptr).pid = (pid_tgid >> 32) as u32;     // TGID = process PID of the *sender*
  ...
  (*raw_ptr).family = dest.family;
  (*raw_ptr).timestamp_ns = bpf_ktime_get_ns();
  // dns_server = the destination resolver address (loopback stub OR upstream)
```

It also copies the destination resolver into `dns_server` (`dest_from_msg_name` / `dest_from_sock`) and the label-encoded QNAME. **The recorded PID is the UDP sender — not the lookup originator.**

### 2.2 The two ways a lookup reaches the wire — only one carries the originator's PID

| Path | Who sends the UDP/53 datagram the kprobe sees | Recorded `pid` | Recorded `dns_server` |
|------|-----------------------------------------------|----------------|-----------------------|
| **(A) Direct, no forwarder** — `/etc/resolv.conf` points straight at an upstream (e.g. `8.8.8.8`) | the originator itself | **originator** ✅ | non-loopback upstream |
| **(B) Stub-listener** — glibc `nss-dns` reads `127.0.0.53` from `resolv.conf` | the originator sends to `127.0.0.53`; **then** `systemd-resolved` sends the *upstream* query | **two events:** originator→stub (✅) **and** resolver→upstream (❌ pid 673) | loopback `127.0.0.53` (orig) / upstream (resolver) |
| **(C) Varlink / `nss-resolve`** — `nsswitch.conf hosts: … resolve …` | the originator talks to `systemd-resolved` over a **Unix socket** (`/run/systemd/resolve/io.systemd.Resolve`) — **no UDP/53 from the originator at all**; only the resolver's upstream query hits the wire | **only** resolver→upstream (❌ pid 673) | upstream |

So the FP arises in **(B)** (a spurious *second* verdict on pid 673, alongside the correct one on the originator) and, more insidiously, in **(C)** (the **only** observed event is attributed to pid 673 — the originator is invisible to this sensor).

### 2.3 Userland pump — `agent/src/sensors/multiplexer.rs`

`pump_dns_query` decodes `DnsQueryRaw → Event::DnsQuery` and feeds the DNS cache, verbatim from the raw PID:

```
agent/src/sensors/multiplexer.rs:582-600
  Ok(raw) => {
      let event = Event::from(raw);             // model.rs:444 — pid/comm/dns_server preserved
      if let (Some(cache), Event::DnsQuery { pid, query_name, query_type, timestamp_ns, .. }) = ... {
          cache.on_dns_query(*pid, query_name.clone(), *query_type, *timestamp_ns);  // PID-keyed
      }
      tx.send(event)...
  }
```

`Event::DnsQuery` (common/src/model.rs:108-117) carries `pid, uid, comm, query_name, query_type, dns_server, family, timestamp_ns`. **The destination resolver (`dns_server`) survives to the rule layer** — see the From impl at `common/src/model.rs:444-461`.

### 2.4 The rule — `agent/src/decision/rules/net.rs`

NN-L-NET-004 matches purely on qname shape and emits a verdict whose `event_pid` is the raw event PID:

```
agent/src/decision/rules/net.rs:469-509
  let Event::DnsQuery { pid, comm, query_name, timestamp_ns, .. } = event else { return None };
  ... // long/base64 shape test
  Some(net_verdict(self, ResponseAction::KillProcess, Severity::High, reason,
                   *pid, comm.clone(), *timestamp_ns))   // *pid = the UDP sender = forwarder in (B)/(C)
```

The rule **does not** consult `dns_server`, nor any allowlist — it is **not** comm-gated. (NN-L-NET-005 at :540 and NN-L-NET-014 at :1110 take `*pid` the same way.)

### 2.5 Response — `agent/src/main.rs` → executor

```
agent/src/main.rs:2303-2320
  if let Some(verdict) = engine.evaluate(&event) { ...
      let target_pid = verdict.event_pid;                 // 673
      exec.execute(action, target_pid)                    // KillProcess(673)
```

**Net effect:** `KillProcess` against `systemd-resolved`.

---

## 3. Why existing guards do NOT save it

- **Executor protected set is tiny:** `agent/src/response/executor.rs:47-51` seeds only `{0, 1, 2, own_pid}`. `systemd-resolved` is killable.
- **COMBAT host-critical guard doesn't cover it, and isn't on this path anyway:** `agent/src/combat/protected.rs` protects only `{init, agent, watchdog, sshd}` (by kernel-resolved exe), and it gates the **COMBAT ladder**, not the direct rule→executor `KillProcess` path NN-L-NET-004 uses.
- **The comm allowlist doesn't apply:** `systemd-resolve` *is* in `NETFLOW_COMM_ALLOWLIST_DEFAULTS` (net.rs:97-122), but that list is consulted **only** by the comm-gated NET rules (006/007/009/010/011/013/018/019). NN-L-NET-004/005/014 ignore it. So "just add the resolver to the allowlist" is a **non-fix** for these rules as architected.

---

## 4. What data is available to identify the originator

1. **`dns_server` (already on the event).** Distinguishes a query sent to a **loopback stub** (`127.0.0.0/8`, `::1`) from one sent to a **non-loopback upstream**. A loopback-destined query is the originator's own; a non-loopback query *from a resolver process* is a forwarded leg. (Necessary but not sufficient on its own — see the direct case (A), where a non-loopback query *is* the originator.)
2. **Kernel-resolved `/proc/<pid>/exe` of the sender (NOT yet on the event).** The robust discriminator for "is this PID a forwarder": exe ∈ {`/usr/lib/systemd/systemd-resolved`, `/usr/sbin/named`, `/usr/sbin/unbound`, `/usr/sbin/dnsmasq`, `dnscrypt-proxy`, …}. **Must be exe, never `comm`** — `comm` is `prctl(PR_SET_NAME)`-spoofable, and here a comm check would grant kill-*immunity*, so an attacker could set `comm=systemd-resolve` to dodge the kill (the exact bypass `combat/protected.rs` and `posture/lineage.rs` are built to avoid). The FIM drain already resolves writer exe this way (`resolve_pid_exe`, drain.rs:914) — the same best-effort `/proc` read can be added to the DNS pump.
3. **The PID-keyed DNS cache (`agent/src/net/dns_cache.rs`).** It already records **every** observed query keyed by the *issuing* PID, with a 300 s TTL (`on_dns_query` / `lookup_for_connect`). In case (B) the originator's stub query is in the cache **under the originator's PID** with the same qname. The cache as written only supports *forward* lookup (`pid → recent qname`); reverse correlation (`qname → originator pid`) needs a small secondary index (see §5).

---

## 5. Proposal (for sign-off — not shipped)

**Primary discriminator: the sender's kernel-resolved exe, not its comm; `dns_server` corroborates.**

### Approach 1 — Forwarder-aware attribution with originator back-correlation *(recommended)*

1. **Add `exe: Option<String>` to `Event::DnsQuery`**, resolved best-effort in `pump_dns_query` (mirror `resolve_pid_exe` from the FIM drain). A miss → `None` → treat as a normal (non-forwarder) sender (fail toward today's behaviour).
2. **Classify each DnsQuery as originator-issued vs forwarded** at the rule layer (a shared helper for -004/-005/-014):
   - sender exe ∈ known-resolver set **→ forwarded leg**;
   - else **→ originator-issued** (covers direct case (A) and the originator's own stub query in (B)).
3. **For an originator-issued query:** behave exactly as today — attribute + `KillProcess` on the sender PID. (No regression for the no-forwarder host.)
4. **For a forwarded leg that trips the qname predicate:** **never act on the resolver.** Instead **back-correlate** via the DNS cache to find the originator — the most-recent *other* PID that issued the same qname within a tight window (≤ ~2 s, not the full 300 s TTL — see §6.6):
   - **found →** emit the verdict attributed to the **originator** PID (correct kill target);
   - **not found** (case (C), cache miss, or the host is itself a LAN resolver) → **downgrade to `Log`/ALERTED**, naming the qname and recording that the originator is unattributable. **Never `KillProcess` the forwarder.**
5. **Cache change to enable step 4:** add a secondary `qname → (pid, ts_ns)` index to `DnsCache` (or iterate the existing per-PID deques). This is the natural extension of the cache's own documented V1.1 direction.

This keeps detection (the suspicious qname is always surfaced) while removing the catastrophic mis-kill, and it correctly attributes in case (B).

### Approach 2 — Originator capture at the stub *(heavier; defer)*

Attribute the originator at the point its lookup reaches the resolver: peer-credential capture on the stub UDP socket, and Varlink/Unix-socket instrumentation for case (C). This is the only way to attribute case (C) to a process, but it needs a **new sensor** (UDP to `127.0.0.53` has no connected peer creds readily available; Varlink needs socket-level hooking). Larger surface — out of scope for a tuning pass.

### Approach 3 — Minimal availability stop-gap *(interim, if a hotfix is needed before Approach 1)*

Add the known-resolver **exes** to the kill-protection set (and/or downgrade -004/-014 to `Log` when the sender exe is a resolver). Immediately removes the mis-kill; **loses** originator attribution in case (B) (we *could* have attributed there) and does nothing for -005's per-PID burst mis-count. Acceptable as a band-aid, not the real fix.

---

## 6. Residual gaps / false-negative analysis

1. **Case (C) Varlink/`nss-resolve` originator is unattributable.** No UDP/53 from the originator ⇒ nothing to correlate ⇒ Approach 1 falls back to `Log`. The malicious qname is still surfaced, but **no process is auto-killed at the DNS layer**. Compensating controls: the subsequent connect may still trip the NetFlow rules (byte-anomaly -009, beacon -013, blocked-IP/JA3 -001/-003), and the qname alert still fires. **Residual FN:** an exfiltrator using `nss-resolve` is not auto-killed on the DNS signal alone. Only Approach 2 closes this.
2. **Cached resolutions.** If the stub answers from cache, there's **no** upstream query ⇒ **no forwarder event** ⇒ no FP at all; and the originator's stub query (case B) is still observed + correctly attributed. DGA names are essentially never cache hits, so this is moot in practice.
3. **Shared-qname ambiguity.** If two local PIDs issue the *same* qname inside the correlation window, "most-recent wins" could mis-attribute. For -004/-014's by-definition-rare DGA/base64/high-entropy qnames this collision is negligible; for the merely-long benign case the action is a softer `Log` anyway.
4. **Originator already exited.** A short-lived dropper that resolved then died before the forwarder's upstream query drained: the cache entry (and thus the attribution string) is still correct, but the kill no-ops on the reaped PID. Acceptable (PID may also be reused — the kill must keep the executor's existing PID-floor/own-PID guards).
5. **Host acting as a LAN resolver** (this box runs `dnsmasq`/`bind` serving other hosts). The "originator" is a **remote** client with no local PID; back-correlation correctly finds nothing → `Log`, never kill the resolver. Correct by construction.
6. **Correlation-window tuning.** The forwarder's upstream query and the originator's stub query are ~microseconds apart, far inside any window. But the cache TTL is 300 s with most-recent-wins, so a **stale** same-qname entry from an earlier unrelated PID is a theoretical mis-attribution source — hence the **tight ≤2 s** back-correlation window in step 4 rather than the full TTL.
7. **TCP DNS / DoT / DoH are unobserved (pre-existing, not introduced here).** The kprobe only sees `udp_sendmsg`. A forwarder configured with `DNSOverTLS=yes` emits **no** upstream UDP/53 ⇒ no forwarder event (no FP) but the upstream leg is invisible; the originator's UDP/53 stub query (case B) is still seen. Large TCP responses (`TC` bit retried over TCP) and DoH-from-the-app are entirely outside this sensor.
8. **IPv6 + full loopback range.** The loopback check must cover `127.0.0.0/8` (not just `.53`) and `::1`; some stubs also bind `::1`.
9. **`extract_qname` only handles `ITER_UBUF`** (dns_query.rs:342) — `ITER_IOVEC` sendmsg leaves the qname empty (`qname_len=0`). Such events can't trip the content rules at all (a separate pre-existing coverage gap, orthogonal to attribution).

---

## 7. Suggested ordering for the fix (when greenlit)

1. Add `exe` to `Event::DnsQuery` + resolve it in `pump_dns_query` (reuse `resolve_pid_exe`).
2. Add a known-resolver-exe set + an `is_forwarded_leg(event)` helper shared by -004/-005/-014.
3. Add the `qname → (pid, ts)` reverse index to `DnsCache` and an `originator_for(qname, now, window)` lookup.
4. Re-route -004/-014 (and fix -005's counting) through forwarder-aware attribution: originator-issued → act on sender; forwarded → back-correlate or `Log`.
5. Unit tests: direct (A) still kills sender; stub (B) attributes to originator + suppresses the resolver verdict; Varlink (C) → `Log`, never kills the resolver; LAN-resolver → `Log`; loopback range + `::1`; stale-window non-correlation.

All of the above is **detect-only / attribution-quality** — no change to true-positive *behaviour* (a real originator is still killed), only to *who* is named. No COMBAT/ladder/enforcement changes.
