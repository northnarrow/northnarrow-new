# External security audit of commit 16f7563 — remediation tracker

An external audit of commit `16f7563` (2026-10-12, the merge of #224)
reported 444 findings, each with a proposed fix and a regression test
(6 Critical, 70 High, 159 Medium, 188 Low, 21 Informational), and 234
hardening improvements. Its remediation plan groups them in waves:

- **Wave 0** (0–2 weeks): every Critical, and the High findings with a
  small fix.
- **Wave 1** (2–8 weeks): the remaining High findings.
- **Wave 2** (2–4 months): the Medium findings.
- **Wave 3** (continuous): Low and Informational.

The report itself lives with the repository owner. This file tracks what
was done about each finding, so that a reader of the repository can see
the status without it. Each finding is re-checked against the current
code before it is fixed: the audit predates PRs #225 onward, and some
code it cites has changed since. A fix follows the plan's rule: a failing
regression test first, then the fix, then the privileged suites on at
least two supported kernels (6.8 and 5.14/5.15).

Status: `open`, `fixed (lab PR N)`, `already fixed (PR)`, or
`declined (reason)`.

## Wave 0

| ID | Audit ref | Severity | Area | File | Status |
|---|---|---|---|---|---|
| NN-AUD-001 | PROC-001 | Critical | Process rules | `agent/src/decision/rules/r004_exec_from_proc_self_fd.rs` | fixed (lab PR 79) |
| NN-AUD-002 | POS-001 | Critical | Posture | `agent/src/posture/mod.rs` | fixed (lab PR 80) |
| NN-AUD-003 | LLMP-002 | Critical | LLM prompts | `agent/src/ade/structured_prompt.rs` | fixed (lab PR 81) |
| NN-AUD-004 | LLMR-002 | Critical | LLM runtime | `agent/src/ade/mod.rs` | fixed (lab PR 82) |
| NN-AUD-005 | NET-001 | Critical | Network | `agent/src/net/blocklist.rs` | fixed (lab PR 78) |
| NN-AUD-006 | NET-010 | Critical | Network | `configs/netflow-comm-allowlist.v1` | fixed (lab PR 78) |
| NN-AUD-016 | EBPF-003 | High | eBPF kernel | `agent-ebpf/src/ptrace_check.rs` | open |
| NN-AUD-018 | EBPF-007 | High | eBPF kernel | `agent-ebpf/src/udp_sendmsg_outbound.rs` | fixed (lab PR 78) |
| NN-AUD-030 | FIMP-002 | High | FIM pipeline | `agent/src/fim/baseline.rs` | open |
| NN-AUD-033 | FIMP-005 | High | FIM pipeline | `agent/src/fim/drain.rs` | open |
| NN-AUD-034 | FIMP-006 | High | FIM pipeline | `agent/src/fim/drain.rs` | open |
| NN-AUD-035 | NETR-001 | High | Net rules | `agent/src/decision/rules/chain.rs` | open |
| NN-AUD-047 | CMB-002 | High | Combat response | `agent/src/combat/actuator.rs` | open |
| NN-AUD-049 | CMB-005 | High | Combat response | `agent/src/response/executor.rs` | open |
| NN-AUD-051 | LLMP-001 | High | LLM prompts | `agent/src/ade/sanitize.rs` | fixed (lab PR 81) |
| NN-AUD-052 | LLMR-001 | High | LLM runtime | `agent/src/ade/escalate.rs` | fixed (lab PR 81) |
| NN-AUD-054 | LLMR-006 | High | LLM runtime | `agent/src/ade/dual_verify.rs` | fixed (lab PR 81) |
| NN-AUD-056 | NET-002 | High | Network | `agent/src/net/blocklist.rs` | fixed (lab PR 78) |
| NN-AUD-059 | NET-005 | High | Network | `agent/src/net/dns_cache.rs` | fixed (lab PR 78) |
| NN-AUD-060 | NET-011 | High | Network | `configs/netflow-blocklist.v1` | fixed (lab PR 78) |
| NN-AUD-063 | DEC-003 | High | Deception | `agent/src/canary/read_forward.rs` | open |
| NN-AUD-070 | WDG-004 | High | Watchdog tooling | `watchdog/src/main.rs` | open |

## Notes on the fixes

- **NN-AUD-005 (NET-001), lab PR 78.** A dual-stack `AF_INET6` socket
  reaching an IPv4 peer reports it as `::ffff:a.b.c.d`. Every consumer
  compared that form with IPv4 entries and never matched. The address is
  now canonical where it is decoded (`common::netaddr`). That covers the
  netflow drain, the multiplexer, the posture's internal/loopback
  checks, the escalation allowlist and the log rendering. The blocklist
  also canonicalises both sides when it compares. Lab, Ubuntu 24.04 and
  22.04: a dual-stack connect to `::ffff:192.0.2.1` drew NN-L-NET-001
  (KillProcessTree); it drew nothing before.
- **NN-AUD-006 (NET-010), lab PR 78.** The network rules' allowlist is
  judged on exec identity (`CommAllowlist::judge`, the review-85
  mechanism), never on `comm`. When the identity cannot be read
  (the process exited before its exec event was), an allowlisted `comm`
  turns the verdict into a recorded Log rather than suppressing it or
  acting on it. NN-L-NET-009's UDP sum and NN-L-NET-013's beacon window
  judge only when they would fire. Lab: python renamed `curl` connecting
  to port 4444 drew NN-L-NET-010 (KillProcess) with
  `[named 'curl', an allowlisted program, but the kernel ran something else]`;
  it was suppressed before.
- **NN-AUD-018 (EBPF-007), lab PR 78.** Only a DNS server's answers to a
  local client stay out of the UDP sensor. Other sends from port 53 are
  flows, aggregated per client address when they go to a remote client.
  Lab: a socket bound to `<host>:53` sending to `192.0.0.9:4444` reached
  userland (NN-L-NET-010); the kernel dropped it before.
- **NN-AUD-056 (NET-002), lab PR 78.** At load, a malformed line in the
  IP or JA3 blocklists, or in their overlays, drops that line with a
  WARN, not the whole list. The validation of an overlay before signing
  stays strict.
- **NN-AUD-059 (NET-005), lab PR 78.** The DNS back-correlation returns
  the newest query at or before the connect. A later query by the same
  process no longer hides it.
- **NN-AUD-060 (NET-011), lab PR 78.** `100.64.0.0/10` (CGNAT: Tailscale,
  EKS, ISP space) and `198.18.0.0/15` (VPN and SD-WAN clients) are out of
  the shipped blocklist, which feeds a KillProcessTree rule.
- **NN-AUD-001 (PROC-001), lab PR 79.** R004's systemd-executor
  exemption trusted the parent's `comm` (`prctl`) and any `argv[0]`
  ending in `/systemd-executor` (the caller's choice).
  - **With the exec sensor's identity** (LSM mode, the default), R004
    has no exemption: what the kernel executed decides. Fileless code is
    a memfd, or an unlinked file (O_TMPFILE) reached through an fd. A
    real file reached through an fd is not fileless; the other rules
    judge it on its canonical path. One exception: systemd's own
    `systemd-executor` left unlinked by an upgrade, which PID 1 keeps
    launching units from.
  - **Tracepoint mode** keeps the path heuristic. Its exemption now
    needs `argv[0]` to be an install path exactly and a systemd parent:
    PID 1, or a `systemd --user` manager by exec identity, never by
    `comm`.
  - **A regression caught in the lab, before the PR.** A first version
    kept the exemption in LSM mode and required the executor's path to
    lack the `TASK_ROOT` flag. The exec sensor sets that flag for every
    process on the root filesystem. On Ubuntu 24.04 (systemd 255) R004
    then killed every unit start, the watchdog included — the regression
    the audit warned about.
  - **Lab.** Ubuntu 24.04 (systemd 255): units started with `systemd-run`
    drew no verdict; a memfd exec'd by a parent renamed `systemd`, with
    `argv[0]` set to the executor's path, drew R004 (KillProcessTree)
    and was killed. Ubuntu 22.04: the same forged exec was killed;
    before, it was exempt.
- **NN-AUD-003 (LLMP-002) and NN-AUD-051 (LLMP-001), lab PR 81.** The
  model read up to twenty correlated events, raw, inside the block the
  prompt calls trusted and immutable. Their names, paths and DNS queries
  are chosen by the processes observed. A LF, CR or TAB in a file name
  also passed the sanitizer, and a single LF could close the untrusted
  block and open a forged one.
  - The correlated events are sanitized like the focal one and printed
    in their own untrusted block, newest first, capped at 4 KiB. An
    event whose own score would have kept it from the model is left out
    and counted in the prompt.
  - Every untrusted string is printed as a JSON string literal, so no
    value can end its line. TAB, LF and CR count as non-printable. The
    prompt's section delimiter (`===`) inside an untrusted string is
    broken up and raises its own flag.
  - The sanity check weighs the correlated events' injection score with
    the focal event's.
- **NN-AUD-052 (LLMR-001), lab PR 81.** The raw model output kept in an
  escalation was cut at byte 4096 with a slice. A multi-byte character
  across the cut panicked, and with `panic = "abort"` that stopped the
  agent. The cut now falls on a character boundary.
- **NN-AUD-054 (LLMR-006), lab PR 81.** Below its confidence floor a
  `KillTree` came back `Inconclusive`, which the engine executed, while
  a `Kill` at the same confidence was refused. Below the floor every
  destructive action is now refused (KillTree 0.85, Kill and Quarantine
  0.70, BlockNetwork and Throttle 0.60), and an `Inconclusive` from any
  verifier is escalated, never executed.
- **Lab, for the LLM fixes (PR 81).** The lab guests carry no model (the
  8B GGUF does not fit the guests' memory and CPU budget), so ADE runs in
  rule-only mode there. The prompt builder, the sanitizer and the
  verifier are pure code; they are covered by unit tests and by
  end-to-end `evaluate` tests over scripted backends.
- **NN-AUD-002 (POS-001), lab PR 80.** Two heuristic signals of
  different trigger types corroborated each other into a locked COMBAT,
  and every heuristic is cheap for an unprivileged user. An update's
  twenty HTTPS connections followed by three internal SSH sessions
  reached COMBAT. Its ladder could then isolate the host, and only a
  signed release ended it.
  - **Corroboration needs two kinds of evidence**: network, execution,
    file system, kernel. The mass-write arm of ConfirmedIntrusion counts
    as file system, so snapd's state rewrite and its unit write (the
    2026-06-02 self-lock) are one kind.
  - **COMBAT on heuristics alone is unlocked.** The ladder contains at
    the process level, refuses ISOLATE (a signed audit entry says why)
    and the posture decays to ENGAGED after 30 minutes without a new
    escalation signal. The ladder stands down with it.
  - **COMBAT is locked** — isolation allowed, no decay, signed release —
    on a kernel-adjudicated denial, on root changing a system file
    outside an administrator's session, or when an administrator forces
    it. An isolation refused earlier in the episode runs as soon as
    COMBAT locks.
  - **Where this departs from the audit's fix.** It proposed that no two
    signals an unprivileged user can forge corroborate. The only signal
    such a user cannot forge (AntiTamperDenial) reaches COMBAT alone, so
    the corroboration path would have been dead. Here the kind of
    evidence gates COMBAT, and privilege gates isolation.
  - **Lab, Ubuntu 24.04 (6.8) and AlmaLinux 9 (5.14).** The exfiltration
    burst and the internal SSH fan-out each raised ENGAGED, in either
    order, and together stayed there. A binary run from /tmp, then an
    exfiltration burst through an `ssh -D` tunnel from the same session,
    reached COMBAT with `locked=false`. On 24.04 the offender was the
    session's sshd, which the ladder spares; it escalated to ISOLATE and
    refused it, and the host stayed reachable. Before the fix, that
    sequence isolated the host. On AlmaLinux (OpenSSH 9.9, sessions run
    `sshd-session`) the offender was killed and contained, with no
    isolation. On 24.04, thirty minutes after the last signal, the
    unlocked COMBAT decayed to ENGAGED and the ladder stood down. In a
    new episode, after the refused isolation, root's attempt to delete
    the agent binary was denied by the kernel; COMBAT locked, and the
    next ladder tick isolated the host. The signed audit log shows the
    refusal at 00:37:07 and the isolation at 00:37:24, "COMBAT since
    locked on non-heuristic evidence".
- **NN-AUD-004 (LLMR-002), lab PR 82.** The event loop awaited every ADE
  evaluation inline. An exec that no rule matched held every sensor's
  channel for up to the inference timeout (15 s), and the kernel ring
  buffers dropped what arrived meanwhile: any user could keep the agent
  blind by running unknown binaries in a loop. The timeout did not stop
  the generation either. Dropping the handle of a blocking task leaves
  it running, so it kept the model's weights up to the backend's own
  120 s budget, and the next evaluations queued behind it and timed out
  in turn.
  - The evaluation and the response to its verdict run on their own
    task (`AdeSlot`). One runs at a time; an exec that arrives while one
    runs is judged by the rules only, counted, and the count is logged
    once a minute. The event loop never waits on the model.
  - On timeout the engine stops the generation at its next token and
    reports the timeout once the backend is free. The backend's budget
    is the engine's timeout.
  - Tests: an evaluation that never ends refuses fifty more at once,
    without waiting, and frees the slot when it ends; an endless
    generation stops when the timeout fires, and the timeout is
    reported after it stopped.
  - Lab (Ubuntu 22.04): the agent run by hand with ADE on a placeholder
    model (candle refuses it; the mock backend answers). Forty unknown
    execs in a burst: the first was evaluated (VERDICT (ADE)), the others
    were counted as skipped ("ADE busy"), and an exec from /tmp right
    after still drew R001 at once. The privileged suite passed (55/55).
