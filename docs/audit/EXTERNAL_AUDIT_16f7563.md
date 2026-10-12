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
| NN-AUD-002 | POS-001 | Critical | Posture | `agent/src/posture/mod.rs` | open |
| NN-AUD-003 | LLMP-002 | Critical | LLM prompts | `agent/src/ade/structured_prompt.rs` | open |
| NN-AUD-004 | LLMR-002 | Critical | LLM runtime | `agent/src/ade/mod.rs` | open |
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
| NN-AUD-051 | LLMP-001 | High | LLM prompts | `agent/src/ade/sanitize.rs` | open |
| NN-AUD-052 | LLMR-001 | High | LLM runtime | `agent/src/ade/escalate.rs` | open |
| NN-AUD-054 | LLMR-006 | High | LLM runtime | `agent/src/ade/dual_verify.rs` | open |
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
