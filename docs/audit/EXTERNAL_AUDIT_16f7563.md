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
| NN-AUD-016 | EBPF-003 | High | eBPF kernel | `agent-ebpf/src/ptrace_check.rs` | fixed (lab PR 85) |
| NN-AUD-018 | EBPF-007 | High | eBPF kernel | `agent-ebpf/src/udp_sendmsg_outbound.rs` | fixed (lab PR 78) |
| NN-AUD-030 | FIMP-002 | High | FIM pipeline | `agent/src/fim/baseline.rs` | fixed (lab PR 84) |
| NN-AUD-033 | FIMP-005 | High | FIM pipeline | `agent/src/fim/drain.rs` | fixed (lab PR 84) |
| NN-AUD-034 | FIMP-006 | High | FIM pipeline | `agent/src/fim/drain.rs` | fixed (lab PR 84) |
| NN-AUD-035 | NETR-001 | High | Net rules | `agent/src/decision/rules/chain.rs` | fixed (lab PR 84) |
| NN-AUD-047 | CMB-002 | High | Combat response | `agent/src/combat/actuator.rs` | fixed (lab PR 83) |
| NN-AUD-048 | CMB-003 | High | Combat response | `agent/src/combat/protected.rs` | fixed (lab PR 83; Wave 1, taken with NN-AUD-049) |
| NN-AUD-049 | CMB-005 | High | Combat response | `agent/src/response/executor.rs` | fixed (lab PR 83) |
| NN-AUD-051 | LLMP-001 | High | LLM prompts | `agent/src/ade/sanitize.rs` | fixed (lab PR 81) |
| NN-AUD-052 | LLMR-001 | High | LLM runtime | `agent/src/ade/escalate.rs` | fixed (lab PR 81) |
| NN-AUD-054 | LLMR-006 | High | LLM runtime | `agent/src/ade/dual_verify.rs` | fixed (lab PR 81) |
| NN-AUD-056 | NET-002 | High | Network | `agent/src/net/blocklist.rs` | fixed (lab PR 78) |
| NN-AUD-059 | NET-005 | High | Network | `agent/src/net/dns_cache.rs` | fixed (lab PR 78) |
| NN-AUD-060 | NET-011 | High | Network | `configs/netflow-blocklist.v1` | fixed (lab PR 78) |
| NN-AUD-061 | DEC-001 | High | Deception | `agent/src/admin_socket.rs` | fixed (lab PR 84; Wave 1, taken with NN-AUD-063) |
| NN-AUD-062 | DEC-002 | High | Deception | `agent/src/canary/path_policy.rs` | fixed (lab PR 84; Wave 1, taken with NN-AUD-063) |
| NN-AUD-063 | DEC-003 | High | Deception | `agent/src/canary/read_forward.rs` | fixed (lab PR 84) |
| NN-AUD-070 | WDG-004 | High | Watchdog tooling | `watchdog/src/main.rs` | fixed (lab PR 85) |

## Wave 1

| ID | Audit ref | Area | Effort | Status |
|---|---|---|---|---|
| NN-AUD-007 | ASK-001 | Admin socket | M | fixed (lab PR 84, with NN-AUD-062) |
| NN-AUD-008 | MAIN-001 | Agent main | M | fixed (lab PR 89) |
| NN-AUD-009 | MAIN-002 | Agent main | M | fixed (lab PR 82, as NN-AUD-004) |
| NN-AUD-010 | MAIN-003 | Agent main | M | fixed (lab PR 91) |
| NN-AUD-011 | ATP-001 | Anti-tamper | M | fixed (lab PR 92) |
| NN-AUD-012 | ATP-002 | Anti-tamper | M | fixed (lab PR 89) |
| NN-AUD-013 | ATP-004 | Anti-tamper | M | fixed (lab PR 93) |
| NN-AUD-014 | EBPF-001 | eBPF kernel | M | fixed (lab PR 94) |
| NN-AUD-015 | EBPF-002 | eBPF kernel | M | fixed (lab PR 95) |
| NN-AUD-017 | EBPF-006 | eBPF kernel | M | already fixed (lab PR 57); attested (lab PR 104) |
| NN-AUD-019 | EBPF-010 | eBPF kernel | M | fixed (lab PR 97) |
| NN-AUD-020 | EVD-001 | Evidence logs | L | fixed (lab PR 107) |
| NN-AUD-021 | EVD-005 | Evidence logs | M | fixed (lab PR 90) |
| NN-AUD-022 | EVD-021 | Evidence logs | M | fixed (lab PR 88) |
| NN-AUD-023 | FIMR-001 | FIM rules | M | fixed (lab PR 91) |
| NN-AUD-024 | FIMR-002 | FIM rules | M | fixed (lab PR 75, review 85) |
| NN-AUD-025 | FIMR-003 | FIM rules | M | fixed (lab PR 75, review 85) |
| NN-AUD-026 | FIMR-004 | FIM rules | M | fixed (lab PR 102) |
| NN-AUD-027 | FIMR-005 | FIM rules | M | fixed (lab PR 102) |
| NN-AUD-028 | FIMR-006 | FIM rules | L | fixed (lab PR 98) |
| NN-AUD-029 | FIMP-001 | FIM pipeline | M | fixed (lab PR 91) |
| NN-AUD-031 | FIMP-003 | FIM pipeline | M | fixed (lab PR 102) |
| NN-AUD-032 | FIMP-004 | FIM pipeline | M | fixed (lab PR 102) |
| NN-AUD-036 | NETR-002 | Net rules | M | fixed (lab PR 98) |
| NN-AUD-037 | NETR-003 | Net rules | M | fixed (lab PR 78, with NN-AUD-006) |
| NN-AUD-038 | PROC-002 | Process rules | M | fixed (lab PR 86) |
| NN-AUD-039 | PROC-003 | Process rules | M | fixed (lab PR 86) |
| NN-AUD-040 | PROC-004 | Process rules | M | fixed (lab PR 86) |
| NN-AUD-041 | PROC-005 | Process rules | L | fixed (lab PR 109) |
| NN-AUD-042 | PROC-007 | Process rules | M | fixed (lab PR 86) |
| NN-AUD-043 | POS-002 | Posture | M | fixed (lab PR 101) |
| NN-AUD-044 | POS-003 | Posture | M | fixed (lab PR 101) |
| NN-AUD-045 | POS-004 | Posture | L | fixed (lab PR 108) |
| NN-AUD-046 | CMB-001 | Combat response | M | fixed (lab PR 100) |
| NN-AUD-048 | CMB-003 | Combat response | M | fixed (lab PR 83, with Wave 0) |
| NN-AUD-050 | CMB-006 | Combat response | M | fixed (lab PR 103) |
| NN-AUD-053 | LLMR-004 | LLM runtime | M | fixed (lab PR 105) |
| NN-AUD-055 | LLMR-012 | LLM runtime | M | fixed (lab PR 87) |
| NN-AUD-057 | NET-003 | Network | M | fixed (lab PR 90) |
| NN-AUD-058 | NET-004 | Network | M | fixed (lab PR 104) |
| NN-AUD-061 | DEC-001 | Deception | M | fixed (lab PR 84, with Wave 0) |
| NN-AUD-062 | DEC-002 | Deception | M | fixed (lab PR 84, with Wave 0) |
| NN-AUD-064 | DEC-004 | Deception | M | fixed (lab PR 99) |
| NN-AUD-065 | DEC-005 | Deception | M | fixed (lab PR 99) |
| NN-AUD-066 | DEC-006 | Deception | L | fixed (lab PR 90) |
| NN-AUD-067 | WDG-001 | Watchdog tooling | M | fixed (lab PR 88) |
| NN-AUD-068 | WDG-002 | Watchdog tooling | M | fixed (lab PR 89) |
| NN-AUD-069 | WDG-003 | Watchdog tooling | M | fixed (lab PR 89) |
| NN-AUD-071 | WDG-005 | Watchdog tooling | M | fixed (lab PR 85, with NN-AUD-070) |
| NN-AUD-072 | DEP-001 | Deploy | M | fixed (lab PR 96) |
| NN-AUD-073 | DEP-002 | Deploy | M | fixed (lab PR 93) |
| NN-AUD-074 | DEP-003 | Deploy | M | fixed (lab PR 92, with NN-AUD-011) |
| NN-AUD-075 | SUP-003 | Supply chain | M | fixed (lab PR 106) |
| NN-AUD-076 | TST-003 | Privileged tests | M | fixed (lab PR 88) |

## Wave 2

The Medium findings. Each was re-checked against `main` at `19926ae`
(2026-10-13) before it was scheduled: six had been fixed by earlier
changes (marked "already fixed"), and the checks found adjacent defects
the audit did not report, noted with the fix that takes them.

| ID | Audit ref | Area | Effort | Status |
|---|---|---|---|---|
| NN-AUD-077 | ASK-002 | Admin socket | M | open |
| NN-AUD-078 | ASK-003 | Admin socket | M | open |
| NN-AUD-079 | ASK-004 | Admin socket | M | open |
| NN-AUD-080 | ASK-006 | Admin socket | M | open |
| NN-AUD-081 | ASK-007 | Admin socket | S | open |
| NN-AUD-082 | ASK-008 | Admin socket | S | open |
| NN-AUD-083 | ASK-010 | Admin socket | S | open |
| NN-AUD-084 | ASK-011 | Admin socket | M | open |
| NN-AUD-085 | AUT-002 | Admin auth | S | fixed (lab PR 115) |
| NN-AUD-086 | AUT-003 | Admin auth | S | fixed (lab PR 115) |
| NN-AUD-087 | AUT-004 | Admin auth | S | fixed (lab PR 115) |
| NN-AUD-088 | AUT-009 | Admin auth | M | open |
| NN-AUD-089 | MAIN-004 | Agent main | S | fixed (lab PR 118) |
| NN-AUD-090 | MAIN-005 | Agent main | S | fixed (lab PR 115) |
| NN-AUD-091 | MAIN-006 | Agent main | M | open |
| NN-AUD-092 | MAIN-007 | Agent main | M | narrowed, residual fixed (lab PR 118) |
| NN-AUD-093 | MAIN-008 | Agent main | S | fixed (lab PR 118) |
| NN-AUD-094 | ATP-003 | Anti-tamper | S | fixed (lab PR 114) |
| NN-AUD-095 | ATP-005 | Anti-tamper | S | open |
| NN-AUD-096 | ATP-008 | Anti-tamper | M | fixed (lab PR 113) |
| NN-AUD-097 | ATP-009 | Anti-tamper | S | fixed (lab PR 112) |
| NN-AUD-098 | ATP-010 | Anti-tamper | M | open |
| NN-AUD-099 | ATP-012 | Anti-tamper | S | fixed (lab PR 114) |
| NN-AUD-100 | ATP-013 | Anti-tamper | S | fixed (lab PR 112) |
| NN-AUD-101 | EBPF-004 | eBPF kernel | M | fixed (lab PR 112) |
| NN-AUD-102 | EBPF-008 | eBPF kernel | S | fixed (lab PR 113) |
| NN-AUD-103 | EBPF-009 | eBPF kernel | S | open |
| NN-AUD-104 | EBPF-011 | eBPF kernel | M | open |
| NN-AUD-105 | EBPF-013 | eBPF kernel | M | open |
| NN-AUD-106 | EBPF-014 | eBPF kernel | S | open |
| NN-AUD-107 | EBPF-015 | eBPF kernel | M | open |
| NN-AUD-108 | EVD-002 | Evidence logs | L | open |
| NN-AUD-109 | EVD-003 | Evidence logs | M | open |
| NN-AUD-110 | EVD-004 | Evidence logs | M | open |
| NN-AUD-111 | EVD-006 | Evidence logs | M | open |
| NN-AUD-112 | EVD-009 | Evidence logs | M | open |
| NN-AUD-113 | EVD-012 | Evidence logs | S | open |
| NN-AUD-114 | EVD-013 | Evidence logs | M | open |
| NN-AUD-115 | EVD-018 | Evidence logs | S | open |
| NN-AUD-116 | FIMR-007 | FIM rules | S | fixed (lab PR 111) |
| NN-AUD-117 | FIMR-008 | FIM rules | M | fixed (lab PR 111) |
| NN-AUD-118 | FIMR-009 | FIM rules | S | fixed (lab PR 111) |
| NN-AUD-119 | FIMP-007 | FIM pipeline | S | open |
| NN-AUD-120 | FIMP-008 | FIM pipeline | M | open |
| NN-AUD-121 | FIMP-009 | FIM pipeline | M | open |
| NN-AUD-122 | FIMP-010 | FIM pipeline | M | open |
| NN-AUD-123 | FIMP-011 | FIM pipeline | S | fixed (lab PR 111) |
| NN-AUD-124 | NETR-004 | Net rules | S | open |
| NN-AUD-125 | NETR-005 | Net rules | M | open |
| NN-AUD-126 | NETR-006 | Net rules | S | open |
| NN-AUD-127 | NETR-007 | Net rules | S | open |
| NN-AUD-128 | NETR-008 | Net rules | S | open |
| NN-AUD-129 | NETR-009 | Net rules | M | open |
| NN-AUD-130 | NETR-010 | Net rules | M | open |
| NN-AUD-131 | PROC-006 | Process rules | M | already fixed (lab PR 87, with NN-AUD-055) |
| NN-AUD-132 | PROC-008 | Process rules | S | open |
| NN-AUD-133 | PROC-009 | Process rules | S | open |
| NN-AUD-134 | PROC-010 | Process rules | S | open |
| NN-AUD-135 | POS-005 | Posture | M | open |
| NN-AUD-136 | POS-009 | Posture | M | open |
| NN-AUD-137 | POS-015 | Posture | M | open |
| NN-AUD-138 | CMB-004 | Combat response | L | open |
| NN-AUD-139 | CMB-007 | Combat response | M | open |
| NN-AUD-140 | CMB-008 | Combat response | M | already fixed (lab PR 77; lab PR 100, with NN-AUD-046) |
| NN-AUD-141 | CMB-009 | Combat response | S | already fixed (lab PR 103, with NN-AUD-050) |
| NN-AUD-142 | CMB-010 | Combat response | M | open |
| NN-AUD-143 | CMB-011 | Combat response | M | open |
| NN-AUD-144 | CMB-012 | Combat response | M | open |
| NN-AUD-145 | CMB-013 | Combat response | S | open |
| NN-AUD-146 | CMB-014 | Combat response | S | open |
| NN-AUD-147 | CMB-015 | Combat response | S | open |
| NN-AUD-148 | CMB-016 | Combat response | M | open |
| NN-AUD-149 | CMB-017 | Combat response | S | open |
| NN-AUD-150 | CMB-019 | Combat response | M | open |
| NN-AUD-151 | LLMP-003 | LLM prompts | S | open |
| NN-AUD-152 | LLMP-004 | LLM prompts | S | open |
| NN-AUD-153 | LLMP-006 | LLM prompts | S | open |
| NN-AUD-154 | LLMP-011 | LLM prompts | S | open |
| NN-AUD-155 | LLMP-013 | LLM prompts | M | open |
| NN-AUD-156 | LLMR-003 | LLM runtime | S | open |
| NN-AUD-157 | LLMR-005 | LLM runtime | M | already fixed (lab PR 105, with NN-AUD-053) |
| NN-AUD-158 | LLMR-008 | LLM runtime | M | open |
| NN-AUD-159 | LLMR-010 | LLM runtime | S | open |
| NN-AUD-160 | LLMR-013 | LLM runtime | M | fixed (lab PR 116) |
| NN-AUD-161 | LLMR-014 | LLM runtime | M | fixed (lab PR 117) |
| NN-AUD-162 | LLMR-016 | LLM runtime | S | fixed (lab PR 116) |
| NN-AUD-163 | LLMR-017 | LLM runtime | M | open |
| NN-AUD-164 | NET-006 | Network | M | open |
| NN-AUD-165 | NET-009 | Network | L | open |
| NN-AUD-166 | NET-012 | Network | M | open |
| NN-AUD-167 | NET-016 | Network | M | open |
| NN-AUD-168 | NET-019 | Network | L | open |
| NN-AUD-169 | DEC-007 | Deception | S | open |
| NN-AUD-170 | DEC-008 | Deception | M | open |
| NN-AUD-171 | DEC-009 | Deception | S | already fixed (lab PR 84, with NN-AUD-062) |
| NN-AUD-172 | DEC-010 | Deception | M | open |
| NN-AUD-173 | DEC-011 | Deception | M | open |
| NN-AUD-174 | DEC-018 | Deception | L | open |
| NN-AUD-175 | XAI-001 | XAI and RAG | M | open |
| NN-AUD-176 | XAI-002 | XAI and RAG | M | open |
| NN-AUD-177 | XAI-004 | XAI and RAG | S | open |
| NN-AUD-178 | XAI-005 | XAI and RAG | M | open |
| NN-AUD-179 | XAI-009 | XAI and RAG | S | open |
| NN-AUD-180 | XAI-010 | XAI and RAG | S | open |
| NN-AUD-181 | XAI-011 | XAI and RAG | S | open |
| NN-AUD-182 | XAI-013 | XAI and RAG | M | open |
| NN-AUD-183 | XAI-018 | XAI and RAG | S | open |
| NN-AUD-184 | SNS-001 | Sensors | M | open |
| NN-AUD-185 | SNS-002 | Sensors | S | open |
| NN-AUD-186 | SNS-003 | Sensors | M | open |
| NN-AUD-187 | SNS-005 | Sensors | S | open |
| NN-AUD-188 | SNS-006 | Sensors | M | open |
| NN-AUD-189 | SNS-007 | Sensors | M | open |
| NN-AUD-190 | SNS-008 | Sensors | S | open |
| NN-AUD-191 | SNS-009 | Sensors | M | open |
| NN-AUD-192 | WDG-006 | Watchdog tooling | S | already fixed (lab PR 89, with NN-AUD-069) |
| NN-AUD-193 | WDG-009 | Watchdog tooling | M | open |
| NN-AUD-194 | WDG-011 | Watchdog tooling | S | open |
| NN-AUD-195 | WDG-R01 | Watchdog tooling | S | open |
| NN-AUD-196 | DEP-004 | Deploy | S | open |
| NN-AUD-197 | DEP-006 | Deploy | M | open |
| NN-AUD-198 | DEP-007 | Deploy | M | open |
| NN-AUD-199 | DEP-008 | Deploy | M | open |
| NN-AUD-200 | DEP-009 | Deploy | M | open |
| NN-AUD-201 | SUP-001 | Supply chain | S | open |
| NN-AUD-202 | SUP-002 | Supply chain | S | open |
| NN-AUD-203 | SUP-005 | Supply chain | S | open |
| NN-AUD-204 | SUP-006 | Supply chain | S | fixed (lab PR 110) |
| NN-AUD-205 | SUP-017 | Supply chain | S | open |
| NN-AUD-206 | LAB-001 | Lab scripts | M | open |
| NN-AUD-207 | LAB-002 | Lab scripts | L | open |
| NN-AUD-208 | LAB-003 | Lab scripts | S | open |
| NN-AUD-209 | LAB-004 | Lab scripts | L | open |
| NN-AUD-210 | LAB-005 | Lab scripts | M | open |
| NN-AUD-211 | LAB-006 | Lab scripts | S | open |
| NN-AUD-212 | LAB-007 | Lab scripts | S | open |
| NN-AUD-213 | LAB-008 | Lab scripts | M | open |
| NN-AUD-214 | LAB-009 | Lab scripts | M | open |
| NN-AUD-215 | LAB-010 | Lab scripts | S | open |
| NN-AUD-216 | LAB-011 | Lab scripts | M | open |
| NN-AUD-217 | LAB-012 | Lab scripts | M | open |
| NN-AUD-218 | LAB-013 | Lab scripts | L | open |
| NN-AUD-219 | LAB-014 | Lab scripts | S | open |
| NN-AUD-220 | LAB-015 | Lab scripts | S | open |
| NN-AUD-221 | LAB-016 | Lab scripts | S | open |
| NN-AUD-222 | LAB-017 | Lab scripts | M | open |
| NN-AUD-223 | LAB-018 | Lab scripts | S | open |
| NN-AUD-224 | TST-001 | Privileged tests | M | open |
| NN-AUD-225 | TST-002 | Privileged tests | S | open |
| NN-AUD-226 | TST-004 | Privileged tests | S | fixed (lab PR 111) |
| NN-AUD-227 | TST-005 | Privileged tests | M | open |
| NN-AUD-228 | TST-006 | Privileged tests | M | open |
| NN-AUD-229 | TST-008 | Privileged tests | S | open |
| NN-AUD-230 | TST-009 | Privileged tests | M | open |
| NN-AUD-231 | TST-010 | Privileged tests | S | open |
| NN-AUD-232 | TST-011 | Privileged tests | S | open |
| NN-AUD-233 | TST-012 | Privileged tests | M | open |
| NN-AUD-234 | TST-018 | Privileged tests | L | open |
| NN-AUD-235 | TST-019 | Privileged tests | M | open |

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
- **NN-AUD-047 (CMB-002), lab PR 83.** NEUTRALIZE judged a killed tree
  by its root alone. A descendant still running — not killed, spared by
  the host-critical guard, or beyond the 1000-descendant walk, which
  stopped silently — left the episode "verified contained". Every
  descendant now counts, the walk reports where it stopped
  (`TreeTruncated`), and the reason names the cause. An uncontained
  tree escalates like any uncontainable offender; isolation still needs
  a locked COMBAT (NN-AUD-002).
- **NN-AUD-049 (CMB-005) and NN-AUD-048 (CMB-003), lab PR 83.** The
  host-critical guard (the agent's stack, the SSH service) was consulted
  only by the kill-tree walk: a rule's KillProcess, or a Quarantine,
  BlockOutbound or Throttle verdict, could take down sshd or the
  watchdog. It now applies to every action on a process. That would
  have widened a hole: the guard spared *any* process running
  `/usr/sbin/sshd`, a binary any user can run, on a high port, to earn
  immunity. NN-AUD-048 is therefore taken with it, ahead of Wave 1:
  - sshd is spared only as root inside an SSH unit of systemd
    (`ssh.service`, `sshd.service`, socket-activated `ssh@`/`sshd@`);
  - with no systemd unit in the cgroup path, exe and uid 0 still decide;
  - a session's own processes run in the session's scope and are not
    spared — when one is the offender, killing it is the containment.
    OpenSSH 9.8 and later run sessions as `sshd-session` anyway; on
    Ubuntu 24.04 (OpenSSH 9.6) they ran `/usr/sbin/sshd` and were
    spared.
  - Lab, Ubuntu 24.04: a binary run from /tmp, then an exfiltration
    burst through an `ssh -D` tunnel. Before, the tunnel's sshd (uid
    1000, in the session's scope) was spared and the ladder escalated to
    ISOLATE (refused since NN-AUD-002). Now NEUTRALIZE killed it and the
    threat was contained without isolation. The SSH service kept
    accepting connections, and the quarantine refused `/usr/sbin/sshd`
    (a protected system prefix).
- **NN-AUD-030 (FIMP-002), lab PR 84.** The baseline hashed a watched
  symlink's target without checking its type. A link to a FIFO blocked
  the open for good, and with it the drain, which holds the drift
  database: FIM went blind, silently. A link to `/dev/zero` never reached
  EOF. A link to anything but a regular file now yields the link row
  only. The hash opens non-blocking and refuses a non-regular file, or
  one over 512 MiB.
- **NN-AUD-033 (FIMP-005), lab PR 84.** A watched file renamed away kept
  resolving to the watched path. `mv authorized_keys authorized_keys.bak`
  followed by an edit of the copy was reported as a change to
  `authorized_keys`, and its rule killed the editor. Once the rename
  lands, the moved inode is forgotten and whatever now lives at the path
  is watched — a file renamed over it included. The hook fires before
  the rename, so a drain that runs first retries for two seconds.
- **NN-AUD-034 (FIMP-006), lab PR 84.** A drift log that could not be
  written (disk full, a rotation or protection fault) made the drain
  return before the event reached the rules, silencing every FIM rule
  at once. The event now always goes out. Evidence that could not be
  recorded is reported at ERROR, once a minute with a count.
- **NN-AUD-035 (NETR-001), lab PR 84.** Review 54 decided that a
  wide-coverage credential open (any home's keyring, browser or
  password store) is reported, never acted on: the owner application
  opens it, and so does a backup. The chain rules ignored that and
  recorded it as the CredRead precursor, so the next flow of the same
  process drew KillProcessTree. They now skip wide-coverage opens; the
  FIM rules still log them.
- **NN-AUD-061 (DEC-001), NN-AUD-062 (DEC-002) and NN-AUD-063 (DEC-003),
  lab PR 84 — file canaries, end to end.** In the lab no file canary
  deployed at runtime ever tripped; three defects stacked up, and a
  fourth the audit did not list.
  - *The decoy was never watched* (DEC-001). Only the FIM path list
    filled the kernel's `WATCHED_PATHS`, so the kernel emitted nothing for
    a decoy outside it, and the drain would have dropped an event for an
    inode it could not name. The privileged e2e hid it by listing its
    decoys in `fim-paths.v1`. A deploy now watches the decoy's inode
    (`FimWatch`, the drain's own handles), a burn stops, and every boot
    watches the registry's decoys again — the FIM boot keeps only what it
    registers.
  - *The write could be redirected* (DEC-002). The path was checked, then
    re-resolved by `create_dir_all` and an open that refused a symlink
    only as the last component. A user owning a directory on the way
    could swap in a symlink in between. The decoy is now written by a
    walk from the root, `O_NOFOLLOW` on every component, with missing
    directories made by `mkdirat` inside the walk, and must be a regular
    file.
  - *The installed agent could not write a decoy at all.* The unit's
    `ProtectSystem=strict` and `ProtectHome=read-only` make every decoy
    location read-only in its namespace: each deploy failed with EROFS.
    The walk starts at the host's root as PID 1 sees it (`/proc/1/root`),
    as the quarantine and capability responses do (reviews 86 and 87).
  - *After a restart, reads were dropped* (DEC-003, below).
  - Lab, Ubuntu 22.04, installed agent: a deploy under `/home/nn` now
    succeeds; a `cat` of the decoy drew CANARY TRIPPED and NN-L-CANARY-001,
    and so did one after `systemctl restart northnarrow-agent` (the boot
    reported `read_forward=1`). Before: the deploy failed with EROFS, and
    a decoy in place never tripped.
- **Lab for NN-AUD-033 and NN-AUD-035 (Ubuntu 22.04).** `mv
  /etc/hosts.allow` away and an edit of the moved copy drew no event
  under `/etc/hosts.allow`; moved back, the file was watched again and
  its changed content reported (`FIM DRIFT … op=Created`). A process that
  read `~/.gnupg/private-keys-v1.d/…` and then opened a flow drew
  NN-L-FIM-017 at Log, and no CHAIN-001.
- **NN-AUD-063 (DEC-003), lab PR 84.** The boot rebuilt the canary
  indexes with no inode resolver. The read-forward set came out empty,
  and the FIM drain dropped every read of a file canary until an
  operator deployed, burned or refreshed one. Boot and admin now share
  one rebuild (`CanaryIndexes::rebuild_live`). The boot log reports the
  read-forward count, and warns when a file canary's decoy is missing.
- **NN-AUD-016 (EBPF-003), lab PR 85.** Of the three pinned override
  maps, `PTRACE_OVERRIDE` alone was neither tied to the session nonce nor
  zeroed at boot, and its hook accepted any non-zero value. One write to
  the pinned map lifted the ptrace protection of every later agent until
  a reboot: its memory became readable, a debugger attachable, and the
  hook returned before recording anything. It now opens only on this
  boot's session nonce, like `KILL_OVERRIDE` and `FS_PROTECT_OVERRIDE`,
  and the agent zeroes and pins it at boot, before the hooks attach. A
  failure there counts as a deny shortfall. Lab, Ubuntu 24.04: the hook
  loads with the compare, the pinned map reads 0 after boot, and root
  opening `/proc/<agent>/mem` gets EPERM, recorded as an `op=ptrace`
  denial.
- **NN-AUD-070 (WDG-004), lab PR 85.** Past the restart ceiling (five
  respawns in sixty seconds, "tamper suspected"), or when a respawn
  failed, the watchdog exited 0. Its unit's `Restart=on-failure`
  neither restarted it nor marked it failed: agent and watchdog were
  gone, with one journal line as the only trace. It now holds instead.
  It stays alive and protected, reports `DEGRADED` to systemd
  (`systemctl status` shows why), and respawns nothing. Once an operator
  starts the agent again, it supervises it with a fresh restart window.
  Lab, Ubuntu 24.04: the new privileged e2e killed every respawned agent
  until the ceiling tripped; the watchdog stayed alive and respawned
  nothing; an agent started by hand was supervised again (killed, it was
  respawned). The watchdog's privileged e2e had never run in the lab
  gate — they are gated by a feature, not `#[ignore]`, and `test-ignored`
  compiled them out — so `nn-lab.sh test-ignored` now runs them too (5/5).
- **NN-AUD-038 (PROC-002) and NN-AUD-039 (PROC-003), lab PR 86.** Since
  Tappa 10.9 the exec rules judge the path the kernel resolved from the
  executed file's dentry (canonical, symlinks resolved), which closes
  both findings where the LSM exec sensor runs — the default. Without it
  (tracepoint mode, or a file the sensor could not place) the rules fell
  back on the string passed to `execve`: a relative `./payload` run from
  /tmp matched no staging rule, and `/usr/bin/../../tmp/nsenter` passed
  R013/R017's standard-prefix exemption. That fallback is now the string
  resolved lexically (`.`, `..`, `//`) when it is absolute, and the
  running image's path when it is relative. The caller's string is kept
  as evidence.
- **NN-AUD-040 (PROC-004), lab PR 86.** R018's only autonomous response
  (Critical, KillProcessTree for a module loaded from outside
  /lib/modules) was turned into a Medium alert by any truncated path,
  including one nested past the kernel walk's 16 components — a depth the
  loader chooses. The walk now tells its two causes apart. Deeper than
  16 components is deeper than any module directory, whose modules sit
  a dozen down at most: it is killed, allowlisted loader or not. A failed
  kernel read leaves the origin unknown: an alert, raised from Medium to
  High. Lab, Ubuntu 24.04: the stock `dummy.ko.zst` copied 18
  directories deep and loaded with `insmod` drew R018 Critical,
  KillProcessTree (`…/d4/…/d18/dummy.ko.zst`); it drew a Medium alert
  before.
- **NN-AUD-042 (PROC-007), lab PR 86.** R009 killed every root exec from
  a home or a temporary directory, `sudo ~/deploy.sh` and RPM scriptlets
  included. It once killed `nn-admin`. An administrator's sudo/su
  session at a terminal, and a package manager's transaction, are now
  recorded instead — review 52's boundaries for the FIM rules. The
  audit's proposed carve-out, any "auth-mediated" process, was not
  taken. That covers every descendant of sshd (NN-AUD-043), so it would
  have spared the escalation R009 exists for: an exploit run from an ssh
  session. Lab, Ubuntu 24.04: a root script in `/home/nn` run with `sudo`
  at a terminal drew R009 at Log and completed; the same script run with
  `sudo` without a terminal was killed. A script that exits within a few
  milliseconds can still draw the kill: its lineage is read once it has
  gone, and the kill then finds nothing to stop.
- **NN-AUD-041 (PROC-005), left open here as a design question; decided
  in lab PR 109 (its entry below).** Only root can load a module, and root
  can put one under /lib/modules, so R018's path test cannot be the
  discriminant. The audit's fix (a baseline of module inodes) would kill
  every DKMS build after a kernel update. The candidates were the kernel's
  own module-signature verdict, and a trusted-installer window for module
  loads as for kexec (review 82).
- **NN-AUD-024 and NN-AUD-025 (FIMR-002, FIMR-003).** Fixed after the
  audit's commit by review 85 (PR #246, lab PR 75): NN-L-FIM-011..019
  fire for every process, and `OwnClient` drops the verdict only for a
  client told by what the kernel executed. The `(name)` form systemd
  gives a unit's pre-exec child now only shapes the reasoning.
- **NN-AUD-037 (NETR-003).** Fixed with NN-AUD-006 (NET-010, PR #249,
  lab PR 78): every network rule, listeners included, judges its
  allowlist on exec identity (`CommAllowlist::judge`).
- **NN-AUD-055 (LLMR-012), lab PR 87.** NN-L-BPF-001/002 and
  NN-L-IOU-001/002 skipped any process whose `comm` was on the rule's
  known list or in the process allowlist.
  - The known lists became program names (`KNOWN_BPF_PROGRAMS`,
    `KNOWN_IOURING_PROGRAMS`), matched on the executable alone
    (`ExecIdentity::is_known_binary`: `node` is known whatever script it
    runs). The operator allowlist is matched as the network allowlist
    is (`is_client`: the executable, or the script an interpreter
    runs). Both must lie in a root-owned system tree.
  - The process allowlist is now built with the lineage tracker
    (`with_identity`). R011–R017 judge it on the exec event's own
    identity (`judge_spawn` → `CommAllowlist::judge_exec`), with no
    lookup.
  - A 15-character entry, the kernel's cut of a longer name, matches
    the longer program (`names` in `posture/lineage.rs`), so the shipped
    allowlists keep working: `unattended-upgr`, `systemd-network`,
    `systemd-resolve`, `northnarrow-wat`, `qemu-system-x86`.
  - Not changed: R018's module-loader allowlist (`systemd-udevd`,
    `systemd-modules`, `kmod`) still reads `comm`. It only spares the
    alerts for loads from the module directories, and loading a module
    needs CAP_SYS_MODULE, so it gives an unprivileged process nothing.
    On exec identity it would over-match: `modprobe` and `insmod` are
    links to `kmod`. It belongs with NN-AUD-041, how R018 tells a
    legitimate load (lab PR 109 kept it: a system loader's unowned module
    is an alert, not a kill).
  - Lab, Ubuntu 24.04. Before: the io_uring probe built as `nginx` in a
    home directory read `/etc/hostname` and connected to port 22 through
    one ring, and python renamed `systemd` loaded a socket filter, both
    with no verdict. After: the probe drew NN-L-IOU-001 and
    NN-L-IOU-002, and the renamed python NN-L-BPF-001, each noting
    `[named 'nginx' (or 'systemd'), an allowlisted program, but the
    kernel ran something else]`. Restarting `systemd-timesyncd` (PID 1
    attaching the unit's device policy) drew no BPF verdict.
- **NN-AUD-022, NN-AUD-067, NN-AUD-076 (EVD-021, WDG-001, TST-003), lab
  PR 88.** The watchdog stood down for any marker with a 64-hex
  `entry_hash` and a future deadline; the unit test proved a hand-made
  marker was accepted, and no test covered the watchdog's half.
  - The fix the audit sketched — signing the marker with the agent's key
    — would not hold: root reads `agent.sig.key`. The marker
    (`common::shutdown_marker`, v2) carries the quorum-signed payload's
    canonical CBOR, the signatures and the agent's pid. `verify` checks,
    as the agent did, against `admin.pub` (private keys off the host):
    2 distinct keys, one with `shutdown`; `agent_id`; signed no later
    than 60 s ahead and acted on within 60 s + grace (capped at 300 s);
    not before the dying agent started (`/proc/<pid>/stat`); the pid the
    watchdog saw exit; the nonce never honoured before
    (`/run/northnarrow/watchdog.honoured`).
  - `admin.pub` parsing and the quorum rule moved from the agent to
    `common::admin_quorum`, so the agent and the watchdog run the same
    code; the Kani proof moved with the rule.
  - Every failure — unreadable keys or install id included — is a
    refusal: respawn, an ERROR (`watchdog.tamper`), the marker removed,
    a record at `/run/northnarrow/agent.shutdown_rejected`. The agent's
    self-integrity check turns it into a signed `integrity_drift` entry
    (`shutdown_marker_rejected`).
  - The agent's temporary marker file is removed and created with
    `O_EXCL | O_NOFOLLOW`; the terminator write is no longer ignored.
  - Tests: `common` (forgery, edited payload, quorum and role, replay,
    wrong pid, before the agent started, expired, future, other install,
    not a shutdown); the agent's dispatcher test runs the watchdog's
    verification on the marker it wrote; the watchdog's unit test now
    refuses the old shape; two privileged watchdog e2e tests (forged →
    respawn and recorded; quorum-signed → stand-down, exit 0, recorded).
  - Lab, Ubuntu 24.04. Before: a hand-written old-shape marker and
    `systemctl stop northnarrow-agent` left agent and watchdog inactive
    ("admin-authorised shutdown marker present + deadline valid —
    watchdog standing down"). After: the watchdog logged `shutdown
    marker REFUSED … not a v2 marker`, restarted the agent through
    systemd within a second, and both were active; 15 s after its start
    the agent appended a signed `integrity_drift` entry (`the watchdog
    refused a shutdown marker … (agent pid …)`). The quorum-signed path
    is covered by the privileged e2e tests on the same guest.
- **NN-AUD-008, NN-AUD-012, NN-AUD-068, NN-AUD-069 (MAIN-001, ATP-002,
  WDG-002, WDG-003), lab PR 89.** Who the anti-tamper trusts is now told
  by the executable a process runs, never by a pidfile alone or by
  `comm`.
  - Agent: the boot no longer co-registers whatever pid
    `watchdog.pid` names. Stale entries of the pinned map are kept only
    while they run the agent's or the watchdog's executable
    (`ExeIdentity`, device and inode; was `comm`), so the watchdog's own
    entry survives an agent restart and a decoy's does not. The agent
    registers itself before that scan: the previous agent's pinned
    `ptrace_access_check` hook lets only a protected caller read a
    protected process's `exe` (found in the lab — unregistered, the scan
    read EPERM and would have evicted the live watchdog). The refresh
    task (first round right after boot, then every 30 s) registers a
    watchdog it has verified by `/proc/<pid>/exe`; the previous pid
    leaves PROTECTED_PIDS once it no longer runs the watchdog binary — a
    deleted or rewritten pidfile alone does not unprotect the running
    watchdog.
  - Watchdog: `open_verified_agent` opens the pidfd, checks
    `/proc/<pid>/exe` against `--agent-bin` (default
    `/usr/local/bin/northnarrow-agent`) by device and inode, then checks
    the process alive through the pidfd, so the pid cannot be reused in
    between. Used at boot, after a respawn and to end a hold; stuck
    recovery verifies the same way and signals with
    `pidfd_send_signal`. A pidfile naming another process is an ERROR on
    `watchdog.tamper`, waited out like a missing one. A process that has
    already exited (a respawned agent killed at once leaves a zombie with
    no `exe`) is not verified, protected or signalled: its pidfd only
    reports its death, so the next respawn follows. The agent is not
    dumpable, so the check needs CAP_SYS_PTRACE: added to the unit's
    bounding set (a unit test pins it), and the watchdog registers
    itself in PROTECTED_PIDS before it reads the agent's `exe`.
  - WDG-002: the stuck channel carries the pid it was raised against;
    the ping task restarts its count when the watched agent changes (a
    `watch` channel); the main loop drops a signal for another pid and
    drains the channel after every respawn or hold.
  - Not covered: a root process running the genuine agent or watchdog
    binary under `LD_PRELOAD` is that binary by executable — the class of
    NN-AUD-015 (EBPF-002), closed in lab PR 95 (below). A pidfile overwritten at the
    moment the watchdog starts leaves the agent unsupervised until it is
    fixed (refused, never trusted); systemd's `MainPID` is a possible
    second source.
  - Lab, Ubuntu 24.04. Before: a root `sleep` copied as
    `/root/northnarrow-watchdog` and written into `watchdog.pid` was
    co-registered at the agent's restart, and `kill -9` from root got
    EPERM; the same decoy's pid in `agent.pid` was taken by a restarted
    watchdog as the agent ("boot sequence complete … agent_pid=<decoy>").
    After: the decoy in `watchdog.pid` was not protected (`kill -9` from
    root succeeded) while the real watchdog stayed protected across the
    agent's restart (`kill -CONT` from root: EPERM); a restarted
    watchdog refused the decoy in `agent.pid` (ERROR on
    `watchdog.tamper`, start refused) and came up on its own once the
    pidfile named the agent again.
- **NN-AUD-021, NN-AUD-057, NN-AUD-066 (EVD-005, NET-003, DEC-006), lab
  PR 90.** The append-only chain logs outside `RotatingChainLog` were
  read strictly at open: one unreadable line made the open fail, and the
  callers turned that into a subsystem switched off (the agent refusing
  to start, the network drain not spawned, deception disabled).
  - `chainlog::repair_torn_tail`: only the final fragment after the last
    newline — the signature of a write cut short — is repaired: given its
    newline back when it parses as a whole line, otherwise cut off. A
    file with no complete line is refused and left untouched, so a
    repair never empties a chain (the audit's warning about
    `recover_tail` truncating to GENESIS). Complete lines before the end
    are never touched.
  - `audit.log`: repaired at `AuditLog::open` and attested in the chain
    itself (`chain_tail_repaired`: file, dropped length, dropped bytes'
    SHA-256). A bad complete line before the end still refuses the log
    and stays fatal in enforce mode, as the audit recommends: the
    evidence is left for the operator.
  - `netflow_listeners.jsonl`: repaired at open and attested by `main`.
    The drain now takes the listener log as optional: if it cannot be
    opened, flows and listener events still reach the rules. Not
    changed: the file still has no rotation (`RotatingChainLog`
    migration noted for later).
  - Canary registry and access log: repaired at open; an unreadable line
    elsewhere is skipped and counted, `main` records it as a signed
    `integrity_drift` (`chain_lines_unreadable`), and the readable
    canaries stay deployed and watched. Appends resume after the last
    readable line, so an off-host verifier sees the gap the attestation
    explains.
  - Lab, Ubuntu 22.04. With agent and watchdog stopped, root cannot
    modify these files (the pinned hooks keep protecting them), so the
    power-loss state was reproduced by unmounting bpffs first. Before (the
    build in place): a torn fragment at the end of `audit.log` kept the
    agent from starting at every attempt ("Refusing to run unaudited");
    with `audit.log` restored, the torn listener log left "net: drain
    loop not spawned" and a garbage line in `canaries.jsonl` "canary
    registry open failed — rule engine sees no CanaryTripped events".
    After, on the same corrupted files: the agent started; the signed
    chain holds `chain_tail_repaired` for `audit.log` (38 bytes cut,
    447,661 bytes of complete lines kept) and for the listener log (50
    bytes cut), and `integrity_drift`/`chain_lines_unreadable` for
    `canaries.jsonl` (1 line skipped); the journal shows "canary indexes
    rebuilt from registry canaries=2" and "net: drain loop spawned".
- **NN-AUD-010, NN-AUD-023, NN-AUD-029 (MAIN-003, FIMR-001, FIMP-001), lab
  PR 91.** FIM could be switched off, or blinded, by one line.
  - MAIN-003: the boot no longer nests the FIM sensors, the file-open
    sensor, `populate_watched_paths`, the drain and the admin state under
    a successful `BaselineDb::open`. Without the database only the
    recompute task (a new baseline) is missing: `fim baseline` requests
    are dropped with a WARN, and the boot writes a signed
    `integrity_drift`/`subsystem_degraded` entry. `BaselineDb::open`
    itself now repairs a torn last write and skips malformed rows (the
    chain resumes after the last readable one), attested like the other
    chain logs.
  - FIMP-001: `BaselineCache::load_verified` replaces the unchecked
    loader at boot. Rows are checked one by one (`verify_entry`: recomputed
    `entry_hash`, `agent_sig` under the agent's key) and for their link to
    the row before; a failure makes every row up to it untrusted, and only
    the suffix after the last break feeds the cache. A path without a
    cache entry reports every change, so a break costs suppression, never
    detection; a signed `fim baseline` appends a fresh verified suffix and
    restores it durably. Breaks are an ERROR and a signed
    `subsystem_degraded` entry. `verify_chain`'s doc no longer claims a
    boot caller it never had. Residual, as the audit notes: root can read
    `agent.sig.key` (NN-AUD-020) and sign a row.
  - FIMR-001: `parse_default_list` and the boot reading of a `.local`
    overlay skip and report a bad line instead of failing the list;
    content submitted for signing (`config overlay set`) is still checked
    strictly. An empty effective FIM list is an ERROR and a signed entry.
    `fim-paths.v1` joins `ETC_WRITE_DENY_FILES`.
  - Lab, Ubuntu 24.04; each file edited through the maintenance path
    (trusted-installer window, units stopped, pins dropped), then the
    agent started. A relative line appended to `fim-paths.v1`: before,
    "no defaults this boot", `effective=0`; after, the line skipped with
    an ERROR, `effective=125`. The `/etc/hosts.allow` baseline row
    rewritten with the hash of the content the file was then changed to:
    before, the cache loaded it (`entries=80`) and the change drew no
    event; after, `entries=70 rows=80 untrusted=10`, an ERROR, a signed
    `subsystem_degraded` entry, and `FIM DRIFT path=/etc/hosts.allow
    op=Modified`. `fim_baseline.jsonl` replaced by a lone fragment:
    before, "fim baseline DB open failed" and no FIM drain; after, the
    same failure, "FIM still detects", and "fim: drain loop spawned".
- **NN-AUD-011 and NN-AUD-074 (ATP-001, DEP-003), lab PR 92.** The
  COMBAT rulesets and carve-out were outside the protected set, unsigned,
  and re-read at every engage: what COMBAT did was up to whoever could
  write `/etc/northnarrow`.
  - The two audit fixes differed (signed overlays; a hash in the install
    manifest). The overlay one is used: it lets an operator change the
    carve-out during an incident with an off-host key, and works without
    an install manifest (source-tree installs). `OverlayKind` gains
    `CombatRulesV4`, `CombatRulesV6`, `CombatAllow` (wire bytes 8-10,
    append-only), with their own file names.
  - `overlay_auth::shipped_default`: the content the agent was built with
    (`include_str!` of `configs/`) needs no signature — an unmodified
    install changes nothing. `NetworkIsolator::trusted_source`, at every
    engage: the file when shipped or signed (the gate logs and records a
    refusal), the built-in content otherwise or when the file is missing —
    a deleted ruleset no longer makes engage fail, and a missing v6 ruleset
    no longer leaves IPv6 open.
  - `validate_content`: a ruleset submitted for signing must keep the
    filter table, the COMBAT chain and its catch-all DROP, the INPUT and
    OUTPUT jumps and COMMIT (`network_isolate::validate_ruleset`); a
    carve-out must parse with no rejected line.
  - The six files (three, and their `.sig`) join `ETC_PROTECTED_FILES`
    (MUTATE only — an operator's signed change goes through the agent).
    `install.sh --upgrade` maps the new kinds to their files when it adopts
    unsigned overlays; `nn-admin config overlay status` reports "shipped
    default"; `COMBAT_RECOVERY.md` describes the signed carve-out.
  - The self-integrity check (every ~30 s) now also reports a COMBAT file
    that differs from the shipped content and carries no valid signature
    (`config_overlay` finding, signed `integrity_drift`), so a tampered
    ruleset is visible at once, not only when COMBAT engages.
  - Lab, Ubuntu 22.04. Before: with the agent installed, root appended a
    second filter section to `combat-rules.v4` that inserts an ACCEPT at
    the top of the COMBAT chain (the in-place write MUTATE does not deny);
    the file was applied as such at every engage, and `config overlay
    status` did not know the COMBAT files. After, with the same tampered
    file: `combat-rules-v4 NOT LOADED … no signature file — COMBAT applies
    the built-in content`, v6 and the carve-out "shipped default"; a signed
    `integrity_drift` for `/etc/northnarrow/combat-rules.v4 (1840 bytes)`
    15 s after the boot; `rm combat-rules.v6` denied. COMBAT itself was not
    engaged in the lab (the empty carve-out would cut the lab's SSH); the
    rulesets it builds are covered by the unit tests.
- **NN-AUD-013 (ATP-004), lab PR 93.** The bootstrap gate (BUG-013)
  relaxes the first `rotate-keys add` on a one-key install to one
  signature when a sentinel equals SHA-256(install nonce ‖ `admin.pub`)
  and `admin.pub` holds one key. Root could meet that again after the
  bootstrap: the nonce is readable, the sentinel can be created, and
  `admin.pub` was read anew at each request. The gate now takes the
  `admin.pub` bytes the agent's keys were loaded from
  (`AdminAuth::loaded_admin_pub`), so a file shown later — rewritten or
  bind-mounted — does not count, and it is closed once used: at boot,
  when the signed chain holds a successful `rotate_keys_add`
  (`AuditLog::second_key_added`; the log is never rotated), and right
  after the add. `ANTITAMPER_TRUST_MODEL.md` now says what the code does.
  Residuals: before the bootstrap is used, the gate still opens on the
  sentinel and nonce files, which root can write; the one signature it
  then needs, from a key with `rotate-keys`, is what guards the first
  add. A rewrite before the agent starts is outside its view, and the
  chain still closes the gate then.
  - Lab, lab keys K1 (with `rotate-keys`), K2, K3; files laid through
    the maintenance path. Before (Ubuntu 22.04, main): `admin.pub` with
    K1 and K2 written at install; a one-key copy bind-mounted over it,
    with a sentinel recomputed from the nonce — "bootstrap gate ARMED",
    and an add of K3 signed by K1 alone passed the quorum (it failed
    only at the rename onto the mount point, EBUSY). After the legitimate
    bootstrap (K2 added with K1's signature), `admin.pub` laid back to K1
    with a recomputed sentinel and the agent restarted: K3 was added with
    K1's signature alone. After (Ubuntu 24.04), the same two attempts:
    "leftover sentinel scrubbed (admin.pub already has ≥2 keys)" and
    "bootstrap already used (signed audit chain) — sentinel ignored",
    each refused with "quorum not met (1/2)". The legitimate bootstrap
    works on both.
- **NN-AUD-073 (DEP-002), lab PR 93.** `install.sh` writes
  `northnarrow-agent.service.d/10-debian-perf-paranoid.conf` on
  Debian-family hosts. It was not in the protected binary/unit set, and
  `unit_dropins()` skipped it by path, so a rewrite (`ExecStart=`,
  `ConditionPathExists=`, `Environment=`) was neither denied nor
  reported. The directory and the file now join `BINARY_AND_UNIT_PATHS`
  (MUTATE and WRITE): writes to the file, and unlink or rename in the
  directory, are denied while the agent runs (a new `.conf` beside it is
  not — there is no create hook — and is reported like any unknown
  drop-in); `install.sh` writes the file only with the units stopped and
  the pins removed. Its content moved from a heredoc to
  `deploy/systemd/10-debian-perf-paranoid.conf`, which `install.sh`
  installs and the agent embeds: `KNOWN_DROPINS` pairs the path with
  that content, and anything else at the path is a `unit_dropin`
  finding. Lab (Ubuntu 24.04), the shipped drop-in laid down through the
  maintenance path. Before: root's `printf … >>` to it succeeded and no
  integrity finding followed. After: the append fails with EPERM; the
  drop-in rewritten through the maintenance path is reported at the next
  boot — an ERROR `INTEGRITY DRIFT … kind="unit_dropin"` and a signed
  `integrity_drift` entry (`at_boot: true`).
- **NN-AUD-014 (EBPF-001), lab PR 94.** BUG-010's `KILL_OVERRIDE` let PID 1
  send any signal to any protected pid for the agent's whole life, so root
  only had to ask systemd. `KILL_GRANT` replaces it: one pinned slot
  (`{nonce, sig_mask, expires_ns}`) the agent writes when a signed
  trusted-installer window opens — SIGTERM, SIGCONT, SIGKILL until the
  window ends — and withdraws when it closes; zeroed at every boot. The
  other way through is the final stage of a shutdown: PID 1's comm is
  `systemd-shutdown` and its executable is the one recorded in
  `SHUTDOWN_EXE` (refreshed every minute, so a systemd upgrade is
  followed; the executable check defeats a comm set by `ptrace` of PID 1).
  - systemd treats the EPERM as "ignoring": a refused `systemctl stop`
    reported both units dead while they ran. The units now refuse a manual
    stop (`RefuseManualStop=yes`), and `SendSIGKILL=no` makes systemd
    refuse to start a second instance next to a running one (verified:
    "Unit process … remains running after unit stopped"). `install.sh`,
    `uninstall.sh` and the lab stop the units with `systemctl kill -s
    SIGTERM` inside the window; `respawn-check`, `btrfs-check` and the
    anti-tamper suite open the window before they restart or kill the
    agent.
  - Posture: the first lab run of the fix isolated the guest. The refused
    `systemctl kill` became a Decisive `AntiTamperDenial` with init as the
    offender; NEUTRALIZE spares init, so the ladder isolated the host. A
    denial from PID 1 now raises `RelayedTamperAttempt` (ENGAGED, Kernel
    class, not Decisive), init is never a COMBAT offender, and the
    NN-L-AT-001 detection names the `systemctl` request. While systemd
    reports the host as `stopping` (`SystemState` over its private socket,
    read in-process — a child `systemctl` sits in the agent's cgroup and was
    killed by the very request it judged — and only from a server whose
    `SO_PEERCRED` is PID 1), the refusal is not reported, the ladder stands
    down and the posture stops escalating; a 2-s watch catches the
    shutdown before the agent's own stop job.
  - Found on the way: the agent and the watchdog aborted (SIGABRT) as soon
    as `systemd-journald@northnarrow` stopped — tracing-subscriber reports a
    failed write with `eprintln!`, which panics on the same broken pipe, and
    the release profile aborts on panic. Every reboot ended the agent that
    way ("previous run ended abruptly"); root could repeat it until the
    watchdog's ceiling. `log_internal_errors(false)` in both. And the
    mass-write counter counted device nodes (`/dev/console` at shutdown,
    `> /dev/null` loops): regular files only now, `/dev/shm` still counted.
  - Lab. Before (Ubuntu 22.04, main): `systemctl kill -s SIGKILL
    northnarrow-agent` killed the agent (respawned); `systemctl stop` of
    both units: exit 0 in 0.58 s, both inactive, no respawn. A reboot ended
    the agent with SIGABRT. After (Ubuntu 22.04, 5.15): `systemctl kill` →
    "Access denied", same pid, signed NN-L-AT-001, posture ENGAGED
    (`RelayedTamperAttempt`), no COMBAT; `systemctl stop` → refused at once
    (exit 4), both units still active; the window, then `systemctl kill -s
    SIGTERM` → `agent_stop` "sigterm" and the watchdog's respawn; reboot in
    19 s (26 s before), the agent's stop job timed out after 5 s, the
    process ended at the final stage with `agent_stop` "system_shutdown",
    the next boot read `previous_run: clean`, and no detection or COMBAT
    stage was recorded during the shutdown. The anti-tamper suite passes
    whole (C01–C33, with the new C31 `systemctl kill -s SIGKILL`, C32
    `systemctl kill -s SIGSTOP` of the watchdog, C33 `systemctl stop`), and
    `respawn-check` takes the window path.
- **NN-AUD-015 (EBPF-002), lab PR 95.** The BPF self-defence exempted any
  process whose executable was one of the agent's binaries (agent, watchdog,
  `nn-admin`, by inode) from both halves: write handles on the agent's maps
  and handles to its links. The executable is not the code that runs: root
  could start `nn-admin`, or a second agent or watchdog, with `LD_PRELOAD`
  (or `ptrace` it before it registered) and take `PROTECTED_PIDS`,
  `KILL_GRANT` or the mode map, or detach every LSM hook.
  - What the exemption was for stays: the successor of an agent or a
    watchdog that exited must open the pinned maps before it is a protected
    pid (the dead agent's guard is still attached through its pinned link).
    `OWN_EXE_INODES` now carries a role (1 watchdog, 2 agent; `nn-admin` is
    gone — it talks to the agent over its socket). `ROLE_TGIDS` (pinned)
    holds the live watchdog's and agent's tgid; each claims its slot once it
    is a protected pid (the agent also records the watchdog it verifies),
    and `role_exit`, a raw tracepoint on `sched_process_exit` with a pinned
    link (`link_role_exit`), empties the slot when that process's main
    thread exits. A process running one of the two binaries takes write
    handles only while its role is vacant, from its main thread (a thread's
    `start_time` is its own: a process could keep the window open by
    spawning threads), in its first minute. No binary is exempt from the
    link deny, and `ptrace_access_check` refuses a process running either
    binary before it registers, so a fresh successor cannot be injected
    into.
  - The audit's diff (a 10-s window for the watchdog binary, at any time)
    would have let a preloaded watchdog started beside the live one take
    the maps in its first 10 s; the vacancy check closes that.
  - One watchdog at a time: while the registered watchdog still runs the
    watchdog binary, the agent does not protect another pid the pidfile
    names (a rewritten pidfile would have handed a preloaded watchdog the
    agent's maps through `PROTECTED_PIDS`).
  - Found in the lab: with the liveness watch on a transient link, a clean
    agent exit released the link before the process ended, the slot stayed
    taken, and the respawned agent was refused its own pinned maps (aya
    then failed with EEXIST pinning a fresh copy): the agent did not come
    back. The link is pinned since. A failure to record the agent's role is
    logged and leaves the window bounded by age only; it no longer aborts
    the registration of the agent's objects (that left the guard in observe
    mode).
  - Residual: while a role is vacant — at boot, between the agent's start
    and the watchdog's registration, and in the respawn gap after a crash —
    a root process already running could start a preloaded binary of that
    role. Trust model, "EBPF-002".
  - Lab procedure: a trusted-installer window suspends the filesystem deny
    hooks by design, and one left open by an earlier watchdog-only restart
    made the anti-tamper suite's C04–C07 pass (C04 corrupted `admin.pub`,
    which then disabled the admin socket — correctly — and C07 purged the
    pins). The suite now waits for an open window to close before it starts,
    and its own watchdog restart (C38) takes a 20-s window. C30 (bpftool
    count of PROTECTED_INODES) is skipped in enforce mode, where bpftool
    cannot open the map and the count read 0 → 0.
  - Lab. Before (Ubuntu 22.04, the #265 build, guard in enforce):
    `nn-admin`, `northnarrow-agent` and `northnarrow-watchdog` started with a
    preloaded library each got a write handle on `PROTECTED_PIDS` and a
    handle on `link_task_kill`. After, on 22.04 (5.15) and 24.04 (6.8): all
    six refused (`ANTI-TAMPER DENIAL op=bpf_map` / `op=bpf_link`,
    NN-L-AT-001); the agent restarted in a window came back and registered
    (22.04: 2350 → 2745; 24.04: 6324 → 6738), so did the watchdog (2269 →
    2935; 6255 → 6924), and the role slots followed both; a cold boot
    attached the watch and filled both slots (`previous_run: clean`, the
    stop recorded as `system_shutdown`). Anti-tamper suite C01–C38 OK with
    the guard in enforce (22.04), with the new C34 (ptrace of a fresh agent
    binary), C35–C37 (`nn-admin` / a second agent / a second watchdog,
    preloaded) and C38 (a watchdog restarted in a window registers itself);
    `respawn-check` OK; privileged gate (`test-ignored`, 24.04): 27 suites,
    63 passed, 0 failed.
- **NN-AUD-072 (DEP-001), lab PR 96.** `install.sh` wrote the private half
  of the bootstrap admin key to `/etc/northnarrow/admin.key` with every role
  the product has (`unlock,audit-read,trusted-installer,config-manage`),
  only a banner asked the operator to move it, nothing checked that it had
  gone — and the package hooks fell back to it on their own, so every
  `apt upgrade` / `dpkg -i` / `rpm -U` opened the trusted-installer window
  (the anti-tamper suspended, the pin root removable) with whatever key
  root could read. Root on the host read one file and held the whole
  control plane.
  - The fallback is gone: the package hooks take the key from
    `NN_GRANT_KEY` only, or find a window the operator opened first.
  - A fresh install writes the private key outside the product's trees:
    `/root/northnarrow-admin.key` by default, `--admin-key-out PATH`
    otherwise; a path under `/etc/northnarrow` or `/var/lib/northnarrow` is
    refused (those trees are backed up, kept in etckeeper, and read by
    tooling that would pick a key up from there). An existing file at that
    path is never overwritten. `uninstall.sh --purge` removes it, as it
    removed the key inside `/etc/northnarrow` before.
  - Reported while it stays: `nn-admin host-check` has a new `admin_key`
    check (WARN with the path, both locations), and the agent's integrity
    check records `admin_key_on_host` at boot and whenever a key appears
    there (ERROR + signed `integrity_drift`), seen through PID 1's mount
    namespace.
  - The audit's third point (cut the bootstrap key's roles to
    `unlock,audit-read`) is rejected, as the audit itself concluded: it
    would break the documented `install.sh --upgrade --grant-key` /
    `uninstall.sh --grant-key` path (registry entry 19,
    `install-key-roles-doc-1`).
  - Lab scripts find the lab key at either path (new installs:
    `/root/northnarrow-admin.key`; guests installed before:
    `/etc/northnarrow/admin.key`). `pkg-check` passes `NN_GRANT_KEY` and
    first checks that a package operation over a running install WITHOUT it
    is refused; `uninstall-check` checks that the purge removed the key and
    that the reinstall wrote a new one outside `/etc/northnarrow`.
    `upgrade-check` and `uninstall-check` now run `install.sh` /
    `uninstall.sh` at a pty (`script`): R009 (PROC-007) sanctions a root
    exec from a home directory only in an administrator's sudo session at a
    terminal, and killed both scripts run over a non-interactive ssh.
    `pkg-check` waits for the dpkg lock (unattended-upgrades took it once).
  - Lab, Ubuntu 22.04. Before: `pkg-check` (2026-10-11) installed, upgraded
    and removed the package over a running install without being given a
    key — the hooks took `/etc/northnarrow/admin.key` on their own. After:
    on a guest installed before the fix, `nn-admin host-check` reports
    `WARN admin_key /etc/northnarrow/admin.key` and the agent records
    `integrity_drift` / `admin_key_on_host` at boot (signed); a fresh
    install writes `/root/northnarrow-admin.key` (0600) and nothing in
    `/etc/northnarrow`, reported the same way; `upgrade-check` opens the
    window with it; `uninstall-check` (purge) removes it and the reinstall
    writes a new one; `pkg-check` PASS (28/28) with the new step 0 —
    `dpkg -i` over a running install without `NN_GRANT_KEY` is refused and
    the units are untouched; the anti-tamper suite's window cases (C23,
    C24, C38) pass with the key at the new path.
- **NN-AUD-028 (FIMR-006) and NN-AUD-036 (NETR-002), lab PR 98.** Two
  rules killed processes on shapes legitimate software produces every day.
  - NN-L-FIM-002 ("new SUID-root binary") killed the process tree, Critical
    — and so moved the host to COMBAT — for ANY file created in a watched
    directory under `/home`, `/tmp`, `/var/tmp` or `/dev/shm`: the kernel
    hook carries no mode bits, so it never checked a SUID bit, and the
    shipped `fim-paths.v1` tells operators to watch `/home/<user>/…`
    profile paths (a browser's temporary file, a GnuPG lock). Now a
    `Created` there is recorded (Log, Medium); a `Linked` — reported only
    when the link's SOURCE inode is watched, i.e. a watched binary given a
    name in a user-writable directory, the §13 Q2 evasion — keeps Critical
    and the kill. This is what the drift classifier already did (Critical
    only for `Linked`). A SUID bit set afterwards is a `chmod`, judged by
    the rules on Modified and on capabilities.
  - NN-L-NET-004 killed the sender of any DNS name over 60 characters or
    whose first label had 20+ characters of the base64 alphabet — which
    every LDH label of that length has: S3 buckets, storage accounts, CDN
    and load-balancer names, Kubernetes FQDNs, ACME challenges (its own
    tests killed `curl` and `getent`; review 43 had shortened the
    telemetry probe's nonce to get under it). The base64 branch is gone —
    an encoded payload in a label is NN-L-NET-014's, by Shannon entropy
    over a ≥ 25-character label — and a long name is recorded (Log,
    Medium), still attributed to the originating process (FP-3).
  - NN-L-NET-014 killed on a single query too: a first label of ≥ 25
    characters at ≥ 3.8 bits/char — which a 30-character name of English
    words reaches (`my-company-prod-backups-archive`: 4.0), as do hex and
    UUID labels. In the lab (Debian 12) `python3` was killed for an S3
    bucket, a hashed ELB name and a Kubernetes FQDN — by NET-004 and
    NET-014 both. A tunnel carries a new encoded label per query under the
    attacker's domain, so the kill now takes 8 distinct high-entropy
    labels under one parent domain from one process within 60 s
    (`DnsTunnelCorroboration`, bounded at 4096 pairs); a single one is
    recorded (Log, Medium), against the originator.
  - `dns-sensor-check` proved the DNS sensor by NET-004's kill of the
    sender; it now proves it by NET-004's record of the sender (names over
    60 characters), the sender left running.
  - Lab, Debian 12 (6.1). Before (the build installed on the guest): a
    `python3` that resolved `my-company-prod-backups-archive.s3.amazonaws.com`,
    `internal-payments-api-1234567890.eu-west-1.elb.amazonaws.com` or
    `payments-api-7d4f8b9c6-x2kq9.payments-namespace.svc.cluster.local` was
    killed (exit 137; NN-L-NET-004 and NN-L-NET-014 KillProcess), and one that
    wrote a file in a `/home/nn/.nnx-profile` watched through a signed
    `fim-paths` overlay was killed (NN-L-FIM-002 KillProcessTree,
    Critical). After: all four ran to the end (exit 0), recorded (Log,
    Medium); a process resolving 20 random base32 labels under one domain
    (a tunnel's shape) was killed at the 8th distinct label (NN-L-NET-014
    KillProcess). `dns-sensor-check` OK (every send shape recorded,
    senders untouched).
- **NN-AUD-019 (EBPF-010), lab PR 97.** The deny on link handles taken
  through a pin compared the caller's path string: read twice from user
  memory, not compared at all past the 255-byte buffer, and blind to a
  symlink with another name. The lab confirmed the bypass (a 294-byte path
  to `link_task_kill`, and a symlink, took a handle in enforce mode) and
  measured what the handle can do: on 5.15 and 6.8 `BPF_LINK_DETACH` gets
  EOPNOTSUPP and `BPF_LINK_UPDATE` EINVAL — even with the link's own
  program — on every link type the agent uses (tracing/LSM, raw
  tracepoint, perf: no `.detach`, no `.update_prog`). So the audit's "the
  whole kernel half detached" does not hold on the supported kernels; the
  fix makes the guarantee the agent's instead of the kernel's.
  - The `bpf` hook denies `BPF_LINK_DETACH` and `BPF_LINK_UPDATE` on one of
    the agent's links to a foreign process, by the link the fd names
    (`task->files->fdt->fd[fd]->private_data`, `bpf_link.id` in
    `OWN_BPF_IDS`): whatever gave the handle — a symlink, a rewritten
    buffer, an fd passed over a socket. Six new optional BTF offsets
    (`task_struct.files`, `files_struct.fdt`, `fdtable.max_fds/fd`,
    `file.private_data`, `bpf_link.id`); a kernel without one of them runs
    without this deny (the kernel's own refusal stays).
  - A path that does not fit the buffer and starts with the pin root
    (`/sys/fs/bpf/northnarrow/`) is treated as ours: denied in enforce.
  - Pin names are matched by a one-pass FNV-1a hash of the final component
    (`common::wire::pin_name_hash`, `OWN_PIN_NAMES` keyed by `u64`) instead
    of a 32-byte key copied byte by byte, and the name check and the fd
    lookup are global BPF functions verified on their own. Found in the
    lab: with the deny inlined, `bpf_syscall_observe` hit the verifier's
    million-instruction limit ("BPF program is too large") and the agent
    ran without its `bpf()` observer — reported only as an observe-hook
    shortfall; the copy loop alone explored every length and `/` position.
  - Found in the lab, fixed here: the link self-check of an agent stopped
    in a trusted-installer window reported a link the stop had just
    released (44 ms after `agent_stop`) — a signed `bpf_link_missing` for
    an authorised restart. The check stops once the event loop ends
    (`mark_stopping`).
  - Not done: the link self-check still reports a missing link (ERROR,
    signed) instead of re-attaching it; with detach denied the only way a
    link goes is a pin removed inside a trusted-installer window.
- **NN-AUD-064 (DEC-004) and NN-AUD-065 (DEC-005), lab PR 99.** A canary
  trip killed the accessor's process tree (Critical) on every access, and
  whoever the accessor was.
  - DEC-004: the detector computed the single-trip flag (design §7.5, §12
    Q2) but used it only for the chain row; the trip event did not carry
    it, so a backup's every scheduled run, an indexer's every pass, each
    read killed again. `Event::CanaryTripped` now carries `first_trip`
    (serde default `true` for records written before); the K5 rules
    respond to the first access and record the later ones (Log, Low). Every
    access is still a row of the signed `canary_access.jsonl` chain.
  - DEC-005: "no workflow reads a canary" holds for Process and Network
    canaries, not for File and Credential canaries placed in homes and
    application trees. A read of one by a program that reads whole trees
    by design — told by what the kernel executed, the exe or the script an
    interpreter runs, in a root-owned system tree
    (`ExecIdentity::is_client`), never by `comm` — is recorded (Log,
    High), not killed. Built-in readers: dedicated backup, anti-malware,
    indexing and sync programs (`canary::readers::CANARY_READERS`). Generic
    tools (`tar`, `rsync`, `cp`, `cat`, `rclone`) are not built in — an
    intruder collects and stages with them — and go in the new signed
    overlay `canary-readers.local` (`OverlayKind::CanaryReaders`, protected
    like the other overlays) when an operator's backup runs them.
  - The trip event and the chain row now carry the accessor's executable
    (`/proc/<pid>/exe`; it was always `None`).
- **NN-AUD-046 (CMB-001), lab PR 100.** The quarantine resolved
  `/proc/<pid>/exe` once, then checked the denylist, read the file and
  unlinked it BY NAME (and NEUTRALIZE resolved the name before the kill
  and quarantined after it). A user who owns a directory of their own
  binary's path could swap it for a symlink in between and have the agent —
  root, `CAP_DAC_OVERRIDE` — vault and delete any file; the lexical
  denylist (registry entry 3) was judged on the string from before the
  swap.
  - The binary is now held open (`ExeHandle`): opened through
    `/proc/<pid>/exe`, the kernel's link to the inode (NEUTRALIZE opens it
    before the kill, which also keeps the inode alive). Size and content
    come from that descriptor; the denylist is judged on the inode's own
    current path (`/proc/self/fd/N`).
  - The removal is verified (`remove_verified`): the parent directory is
    opened once (host view), the name opened under it with `O_NOFOLLOW` and
    compared by `(dev, ino)` with the descriptor, then `unlinkat` under that
    same directory; a mismatch is `PathSwapped` — the content stays vaulted,
    nothing is removed, the outcome is a refusal naming the swap. The
    fallback for an unlink that fails (EBUSY) is `fchmod 000` on the
    verified descriptor, not a `chmod` by name.
  - The audit's `openat2(RESOLVE_NO_SYMLINKS)` on the parent path was not
    used: it refuses every host where a legitimate component is a symlink
    (`/usr/local`, `/home` → elsewhere); the `(dev, ino)` comparison is the
    protection.
  - A binary replaced under its name after it was opened (a rename over
    it) is `Gone`: its inode is no longer on disk, the new file is left
    alone.
  - The removal is tried up to 8 times (`remove_held`), each try from the
    inode's current name re-read from the descriptor and judged by the
    denylist again: a swap racing one try fails that try's comparison,
    not the quarantine. Unit test with a real flipper thread
    (`a_directory_flipped_in_a_loop_never_redirects_the_removal`, 20
    rounds): the victim survives every round. Measured once over 200
    rounds: with one try the binary was left in place in 156
    (`PathSwapped`), with eight it was removed in all 200.
  - Found in the lab: on a fresh install no quarantine had ever completed.
    The vault directory was created on first use inside
    `/var/lib/northnarrow`, which is `chattr +i` (EPERM). The agent now
    creates `quarantine/vault` (0700) at start, lifting `+i` for that step
    only when it is missing (`ensure_quarantine_dirs`).
  - Lab, Debian 12 (6.1), before: an unprivileged offender (a 40-file mass
    write and 21 connects to one address: COMBAT, NEUTRALIZE) whose
    directory `~/nnx-q/own` a loop of the same user kept exchanging
    (`renameat2(RENAME_EXCHANGE)`) with a relative symlink to a root-owned
    `/opt/nnx-victim` holding a file of the binary's name. At the 4th
    attempt the vault held the offender's binary (16 380 bytes: 16 352
    and the GCM nonce and tag) and the unlink followed the swapped name:
    the root-owned `/opt/nnx-victim/mw` was deleted, the offender's binary
    stayed in place. An absolute symlink was stopped only by the unit's
    read-only view of `/opt` (EROFS); a relative one resolves inside
    `/proc/1/root`, the host view the quarantine works through.
  - Lab, Ubuntu 22.04 (5.15), after, the same probe: with one removal try,
    8 attempts, the victim intact in all 8, the binary removed in 6 and
    left in place, reported, in 2; with the retry, 8 attempts, the victim
    intact and the binary vaulted and removed in all 8.
- **NN-AUD-043 (POS-002) and NN-AUD-044 (POS-003), lab PR 101.** The
  posture's auth-lineage exemption covered whole sessions and could be
  borrowed.
  - POS-002: `AUTH_BINARY_EXES` lists the login daemons (sshd, login,
    cron, gdm, logind, polkitd) next to sudo and su, and the walk climbs
    to PID 1: every process of an SSH, desktop or cron session was
    auth-mediated, so both mass-write arms ignored it whatever it wrote
    (silently: the WARN came after the exemption) and so did the
    credential-read arm.
  - POS-003: the walk read the spawn cache first and took whatever exe it
    held for a pid. A parent that forks its payload and then executes
    `sudo` (anyone may; the exec event comes before any password) made
    the payload sudo's — deterministically, no race — and a pid an exited
    parent left could be taken by a later process.
  - The audit's fix for POS-002 (drop the session from the mass-write
    arms) was not taken as written: a session's own new files cross the
    threshold of 20 write-opens a minute all day — a browser's cache, a
    build, a clone, an archive extracted — and a false COMBAT reaches
    NEUTRALIZE (kill and quarantine) 30 s later. The kernel tells what
    ransomware does to existing files from what those do: the open sensor
    counts, per process, the write-opens of files that existed before the
    open (no `FMODE_CREATED`) apart from all write-opens, and reports each
    threshold once per window (`open_reason::MASS_OVERWRITE`,
    `Event::MassWrite::overwrites`). An auth-mediated process's new files
    do not count (recorded at INFO, no longer silent); its rewrites of
    existing files raise ConfirmedIntrusion like anyone's. Package
    managers and npm stay exempt. Tracepoint mode, which sees flags but
    not the file, counts a session's opens without `O_CREAT`.
  - The credential-read exemption (`sensitive_file_access`) is now the
    PAM stack's: the authentication binary itself or its direct child
    (`is_credential_reader`), not every process below it. `chage` and
    `expiry` (setgid `shadow`, a user's own `chage -l`) are listed.
  - POS-003: the audit's fix (compare a cached start with
    `/proc/<pid>/stat`) does not stop the exec after the fork, which
    keeps the pid and the start. Exec events now carry the process's own
    start (`task->start_time`, its fork; `ProcessSpawnRaw::start_ns`), and
    the walk (`lineage_match`) is ordered: an ancestor's match counts only
    if it ran the binary before the process below it was forked; a child
    never seen executing runs the image it was forked with, so it counts
    only with the same exe; a process seen only in `/proc` counts if it
    started before the agent or was forked, without executing, from a
    parent that validly runs the same exe (sudo's monitor, a cron worker,
    an sshd session process). A parent starts before its child: a hop
    that started later is a later process given an exited parent's pid,
    and the walk ends there. `parent_start_ns` was not used for this: it
    is the start of the thread that forked, not of its process. The
    agent's tracker (`for_host`) also checks a cached exec against the
    start `/proc` shows for its pid (boot clock, ahead by the time
    suspended), so a fork that took an exited sudo's pid is read from
    `/proc`, not from sudo's entry. Same walk for the package-manager
    exemption and for review 52's interactive-admin test.
  - Accepted: a session copying over an existing tree (`cp -r` onto it,
    `unzip -o`) rewrites existing files and raises ConfirmedIntrusion —
    an alert (ENGAGED); COMBAT needs a second kind of evidence. GNU tar
    extracting over a tree removes and recreates, and counts as new files.
  - Not covered: ransomware that writes encrypted copies as new files and
    deletes the originals, run from a session, is not counted by the
    mass-write arm (no unlink count yet); File canaries in the session's
    trees, the exec, persistence and network arms still apply.
  - Lab, Ubuntu 22.04 (5.15), before: in an SSH session a program created
    40 test files and then rewrote 40 existing ones in place — no trigger,
    no log line. A transient service's child, forked before its parent
    executed `sudo -n sleep 6`, created 40 files — no trigger, while the
    same writes from a service without the sudo exec raised
    ConfirmedIntrusion.
  - Lab, after (22.04 / 5.15, Debian 12 / 6.1, Ubuntu 24.04 / 6.8): the
    session's 40 new files recorded at INFO, not counted; its 40 rewrites
    raised ConfirmedIntrusion (`overwrites=true`, ENGAGED); the laundered
    child raised it (`overwrites=false`); a service's new files and its
    rewrites carry `overwrites=false` and `true` on every kernel
    (`FMODE_CREATED` at bit 20). In the session, `tar` extractions (over
    an existing tree too) and `cp -r` into a new directory, 6 315 files,
    were recorded at INFO only; `cp -r` over the existing tree raised it.
- **NN-AUD-026 (FIMR-004), NN-AUD-027 (FIMR-005), NN-AUD-031 (FIMP-003),
  NN-AUD-032 (FIMP-004), lab PR 102.** File integrity: a replacement no
  rule judged, a classification blind to the path, a drain one large file
  could stall, a re-baseline that watched nothing new.
  - FIMR-004: a file renamed over a watched one — how installers and
    rootkits alike swap a binary, a PAM module, a unit — reached the drain
    as `Renamed`, which only the rename rules (ransomware extension, shell
    history, baits) read; every rule guarding a path's content watches
    modifications. The kernel now flags the replaced inode
    (`FimDriftRaw::op_flags`, `FIM_RENAME_REPLACED`, set only on the
    `new_dentry` arm — the audit's userland inference would also have
    matched a rename out of a watched directory). Once the rename lands
    (the hook fires before it; FIMP-005's settle and retry) the file now
    at the path is checked as a modification, against the baseline,
    attributed to the renamer. A package transaction's renames keep
    NN-L-FIM-001's package carve-out (Log); `authorized_keys` rewritten
    through a rename (`sed -i`, some editors) now draws the same kill as
    an in-place edit.
  - FIMR-005: the main vector — 60 throwaway drifts spending the host-wide
    buckets so the next real one skipped the rules — was closed by review
    76 (lab PR 64), the same day as the audit's commit: only a package
    transaction's drift is paced. What remained: the classifier went by
    the op alone, so a modification of `/usr/sbin/sshd` was "Medium".
    A path a Critical rule guards (system binaries, kernel and PAM
    modules, `ld.so.preload`, the baits: `is_critical_rule_path`, built
    from the rules' own constants) is now Critical whatever the op, and
    never throttled.
  - FIMP-003: the drain — the only reader of the kernel's FIM ring —
    hashed each event's file (up to 512 MiB since FIMP-002) on a runtime
    worker, holding the drift log's lock. Found in the lab: during 3 000
    one-byte appends to a watched 256 MiB file the drain wrote 106 rows in
    a minute, the admin socket stopped answering the watchdog's STATUS
    ping, and the watchdog's stuck recovery killed (SIGKILL) and restarted
    the agent; a change to another watched file a second into the burst
    was never recorded. Now an event that happened before a hash of its
    path began (by more than 50 ms: the hooks fire before the change) is
    answered by that hash — each event still checked and attributed on
    its own; the synchronous work runs in `block_in_place`; the drift log
    is locked for its append only (`DriftSink`). The ring is 1 MiB
    (was 256 KiB), the drain writing a signed row per event.
  - FIMP-004: the recompute task (`nn-admin fim baseline`, a path added
    to the signed `fim-paths` overlay) wrote the baseline chain and never
    touched the inode map or the kernel's `WATCHED_PATHS`: a path added at
    runtime was not watched until a restart, and a replaced file kept its
    old inode's entry. Each re-baselined path is now watched by the inode
    it holds (`reenroll_path`), the inodes it held before forgotten in the
    map and in `WATCHED_PATHS`.
  - Lab, Ubuntu 22.04 (5.15), before: a copy of `/usr/bin/wget` one byte
    longer renamed over it gave `FIM DRIFT op=Renamed` and nothing else; a
    file added through the overlay and `fim baseline` drew no drift when
    changed; the burst above. After: the same rename gave `Renamed`, then
    `Modified` by `mv` and NN-L-FIM-001 (Critical, KillProcessTree of
    `mv`); renaming the original back matched the baseline and was
    dropped as a no-op; the runtime-added file's change was recorded; the
    burst wrote all 3 000 rows in 8.4 s with no ring drop, no watchdog
    recovery, the other file's change recorded in order (with the 256 KiB
    ring: 862 rows in 3 s, 4 275 events dropped and audited, no restart).
  - Not done: a reader task that drains the ring into a queue coalescing
    one writer's repeated closes of a file, which would keep a single
    process from filling any ring size.
- **NN-AUD-050 (CMB-006), lab PR 103.** A second host-wide isolation sat
  beside the COMBAT ladder's. `ResponseAction::FullNetworkIsolation`,
  which an ADE `Isolate` verdict maps to (in production nothing else
  emits it: the demo rule is behind `demo-tappa5`), installed two nftables
  chains with policy drop in the agent's table: no management carve-out,
  no established-traffic rule on output (an operator's open SSH session
  died too), no release verb, no status line, and a flag file nothing
  re-read. A model's verdict — fed by strings an attacker writes — could
  cut the host off for good.
  - The executor refuses the action, enforcing or not (`Refused`, "host-
    wide isolation is the COMBAT ladder's"): isolation is engaged only from
    locked COMBAT (POS-001), through `combat-allow.cidrs`, released with
    the signed unlock, reported by `nn-admin status`.
  - An ADE `Isolate` verdict contains the process tree it names
    (`KillProcessTree`), the most a model's verdict may do on its own.
    The audit's fix (route the verdict to the ladder's isolator) was not
    taken: it would hand the model, and whoever steers it, the host's
    network.
  - The nftables blackout is gone (`network_isolation.rs` keeps only its
    cleanup, and `c2_endpoints` its placeholder). At start the agent
    removes the two chains an older agent may have left — the per-process
    blocks share the table and stay — and the flag file, at WARN, with a
    `legacy_isolation_removed` entry in the signed audit log.
    COMBAT_RECOVERY §4 gives the console commands.
  - Lab, Ubuntu 22.04 (5.15): the two chains planted in `inet northnarrow`
    (policy accept here, to keep the session) next to the per-process
    `output_blocked` and a test chain. Before, an agent restart left them;
    after, the agent's start removed the two and kept the others (WARN,
    `legacy_isolation_removed` in the audit log), again after a second
    planting. Debian 12's image ships without `nft`: the old blackout
    could only fail there. The state directory's `+i` refused the old
    flag file, so the old engage applied the drop policy and then
    reported a failure; the cleanup treats an unremovable flag as inert.
- **NN-AUD-017 (EBPF-006) and NN-AUD-058 (NET-004), lab PR 104.** DNS.
  - EBPF-006: the kprobe at `udp_sendmsg` entry read the query's name from
    the sender's memory, which another thread can rewrite before the
    kernel copies it — the name recorded and the one sent could differ.
    Tappa 10.9 step 3 (lab PR 57, merged the day of the audit's commit,
    after it) made the default sensor read the kernel's copy, on
    `udp_send_skb` / `udp_v6_send_skb` (`dns_flags::SKB`); the `udp_sendmsg`
    program remains only where those cannot attach (or with
    `--dns-sensor sendmsg`). That degraded mode is now attested in the
    signed audit log at start (MAIN-003's `subsystem_degraded`), not only
    in a WARN line.
  - NET-004: the cache of recent queries capped the pids (4096) and the
    queries per pid (1024), not the total: over a gigabyte at worst. The
    kernel's DNS budgets (review 78, after the audit's commit: 1 024
    queries a second per user) cut what one user can record to ~300 000
    queries in the 300 s window — still ~90 MB with long names, and more
    users add up.
    The audit's fix (32 per pid) would drop the attribution of a chatty
    process's long-lived flows (NET-005 looks up the query before the
    connect when the flow closes). A global cap instead, 65 536 queries
    (~20 MiB at worst), kept by the only three places that change the
    per-pid queues (`push`, `retain_pids`, `remove_pid`); past it the
    oldest query of the pid holding the most goes — the flooder's, not a
    quiet process's one lookup.
  - Lab, Ubuntu 22.04 (5.15): one user sending ~1 000 DNS queries a second
    (a child every 100 ms, 100 distinct ~200-byte names each, to
    127.0.0.2:53) for 180 s. Before, the agent's RSS grew linearly, 38 MB
    → 77 MB, and would have kept growing to the 300 s window. After, it
    grew to 63 MB by 120 s and stayed there (64.8 MB at the end).
- **NN-AUD-053 (LLMR-004), lab PR 105.** The ADE loaded whatever GGUF and
  `tokenizer.json` sat at the configured path — no owner, mode or link
  check — and the default path was `/home/forty/models/…`, a user's home:
  the user, or anyone who can write a directory on the path, chose the
  root agent's model (verdicts tailored to `Allow`, or output that keeps
  the escalation busy) and fed candle's GGUF parser a file of their
  making.
  - The default is under the state directory,
    `/var/lib/northnarrow/models/`.
  - `model_trust::open_trusted`, sshd's StrictModes for model artefacts:
    the path resolved; every directory on it owned by root (or the
    agent's own user) and not writable by group or others, a sticky
    directory excepted; the file opened without following a link, a
    regular file, same owner, no group or other write bit. The GGUF is
    parsed from that descriptor and the tokenizer read from its own
    (`Tokenizer::from_bytes`), so what was checked is what is loaded. A
    refusal (`AdeError::ModelUntrusted`) leaves the ADE off and the agent
    on its rules, with the reason in the journal — not on the mock
    backend the other load failures fall back to (LLMR-005).
  - Found in the lab: the ADE could not load on an installed host even
    with a model. Its system prompt — the model's instructions — defaulted
    to `dataset/system_prompt_v1.md`, a path relative to the working
    directory that nothing installs, and a service runs from `/`. The v1
    prompt is now built into the agent (`include_str!`) and used for the
    default; a prompt given with `--ade-prompt` goes through the same
    `open_trusted` as the model.
  - LLMR-005 (Wave 2), taken here because the built-in prompt made it
    reachable on installed hosts: any other load failure (a corrupt or
    unsupported GGUF, a missing tokenizer, OOM) fell back to the mock
    backend, a substring match on comm and the exec path — `Allow` at 0.97
    for a process named `cargo` or `git`, a tree kill for a name holding
    `miner`. A failed load now leaves the ADE off; the mock answers only
    with `NN_ADE_ALLOW_MOCK=1` (demos, benchmarks).
  - Lab, Debian 12 (6.1), with stand-in files (a few bytes, no model) at
    the default location. Before: a GGUF and tokenizer owned by the
    unprivileged user in `/home/forty/models/` reached candle's parser
    (`reading GGUF metadata: unknown magic`), then the mock backend. After:
    that file is no longer looked at; a GGUF owned by uid 1000 in
    `/var/lib/northnarrow/models/` was refused (`ModelUntrusted … owned by
    uid 1000`, ADE off, rules only); root's files passed the check and the
    stand-in failed to parse — which, with `NN_ADE_ALLOW_MOCK` unset,
    leaves the ADE off too.
  - Not done: a pinned digest of the model. Root can replace a root-owned
    model, and root is the anti-tamper layer's adversary, not this
    check's.
- **NN-AUD-075 (SUP-003), lab PR 106.** The release workflow built and
  signed in one job: `contents: write`, `id-token: write` and
  `attestations: write`, a checkout that left the job's token in
  `.git/config` (`persist-credentials` defaults to true), and the build of
  the whole dependency tree — every build script and proc-macro of ~370
  crates running unconfined. One hostile build script anywhere in the tree
  got the repository write token and the OIDC token that signs the
  provenance attestations.
  - `package` now holds `contents: read` only, checks out without
    persisting the token, builds, smoke-tests and uploads the artefacts;
    its last step fails the job if a token sits in the git config or the
    job could request an OIDC token.
  - `sign` (after `package`, not on pull requests) checks nothing out and
    compiles nothing: it downloads the artefacts, verifies `SHA256SUMS`,
    attests them and, on a tag, publishes them (`GH_REPO`, no checkout).
  - Checked on GitHub: a `workflow_dispatch` run of the branch — `package`
    built, smoke-tested and passed its no-credential step with
    `contents: read`; `sign` downloaded the artefacts, matched
    `SHA256SUMS` and attested them (nothing published off a tag).
- **NN-AUD-020 (EVD-001), lab PR 107.** The private key that signs every
  evidence chain was readable by root: the `file_open` deny refused only
  write opens, so root could copy the key and rebuild any chain offline
  with valid signatures (a reopening of at-authz-2).
  - `FS_PROTECT_READ` (bit2) on `agent.sig.key`: any open by a process
    outside the agent's family, read included, is refused (`FS_OP_READ`),
    the trusted-installer window excepted. A read-only open is matched on
    the inode number against a 4-slot pinned array (`READ_PROTECTED_INOS`)
    before any map lookup, so the host's read path stays cheap.
  - A refused read is recorded (NN-L-AT-001, the signed chains) and raises
    `SensitiveFileAccess` (ALERTED), not the decisive `AntiTamperDenial`:
    a backup of `/etc` meets it too.
  - The agent publishes the public half at `agent.sig.pub` (0444,
    write-denied); `nn-admin audit verify` reads it and no longer goes
    through `load_or_bootstrap` — a verifier minted a key on a host
    without one. The lab's upgrade check fingerprints the public half.
  - Lab, Ubuntu 22.04 (5.15). Before: `sudo cat agent.sig.key` printed the
    key (65 bytes); there was no public half. After: `Operation not
    permitted`; `agent.sig.pub` published (0444); the anti-tamper suite,
    with two new cases, OK — C41 (read the key: denied, `op=read`,
    NN-L-AT-001) and C42 (`nn-admin audit verify` from the public half:
    OK).
  - Not closed: root able to bypass the LSM (a kernel module, the disk
    from another OS). A TPM- or keyring-held key and off-host chain
    anchors remain the follow-up.
- **NN-AUD-204 (SUP-006), lab PR 110.** The RustSEC gate read only the
  root `Cargo.lock`: the fuzz harness and the eBPF crate have lockfiles of
  their own, never audited. It now audits all three. It also runs
  `cargo-audit` itself (pinned, `--locked`) instead of
  `rustsec/audit-check`, which reported through the checks API and from
  2026-10-13 failed PR runs that had found nothing ("Not Found" updating
  its own check run); the job's exit status is the gate, and its token is
  read-only (no `checks: write`, no `issues: write`).
- **Already fixed (Wave 2).** NN-AUD-131 (PROC-006): the io_uring and BPF
  rules judge exec identity, not `comm` (NN-AUD-055). NN-AUD-140 (CMB-008):
  NEUTRALIZE opens the offender's binary before the kill and quarantines
  the held inode (review 87, NN-AUD-046). NN-AUD-141 (CMB-009): the whole
  `northnarrow` table is no longer deleted; only the legacy isolation
  chains are retired (NN-AUD-050). NN-AUD-157 (LLMR-005): no silent
  fallback to the mock backend (NN-AUD-053). NN-AUD-171 (DEC-009): the
  canary file is opened `O_NONBLOCK` and checked to be a regular file
  (NN-AUD-062). NN-AUD-192 (WDG-006): the watchdog registers itself before
  it waits for the agent (NN-AUD-069).
- **NN-AUD-045 (POS-004), lab PR 108.** In tracepoint mode (no LSM
  `file_open`, or `--file-open-sensor tracepoint`) an open's `filename` is
  the string the caller passed, read from its memory at `sys_enter_openat`
  — before any permission check and unresolved. The posture judged it like
  the LSM sensor's canonical path: a refused `open("/etc/cron.d/x",
  O_WRONLY)` raised PersistenceMechanism (and a critical path
  CriticalFileModification) with no privilege and nothing written; and
  `/proc/self/cwd/…` or `/proc/../home/…` dodged the mass-write count
  through its `/proc/` carve-out. Known internally as `posture-path-string-1`
  (fixed in LSM mode, open on the fallback).
  - `Event::FileOpen::path_from_user` marks the tracepoint's events.
  - Their persistence and critical-file hits raise SensitiveFileAccess
    (ALERTED): no COMBAT-tier file signal, no corroboration, from a string.
  - The mass-write carve-out judges such a path after folding its `.` and
    `..` segments, and never carves out one through a process's `cwd`,
    `root` or `fd` link under `/proc`.
  - Lab, Debian 12 (6.1), agent in tracepoint mode, an unprivileged
    service. Before: `open("/etc/cron.d/nnx-tp", "w")` and
    `open("/etc/ssh/sshd_config", "a")`, both refused (EACCES), took the
    posture to ENGAGED on PersistenceMechanism; 25 files written through
    `/proc/self/cwd/` raised nothing. After: the refused opens took it to
    ALERTED (SensitiveFileAccess); the 25 writes raised ConfirmedIntrusion
    (ENGAGED).
- **NN-AUD-041 (PROC-005), lab PR 109.** R018's only autonomous kill was
  "a module loaded from outside /lib/modules", and the path was the only
  discriminator: whoever loads a module holds `CAP_SYS_MODULE` and can copy
  the image under /lib/modules first, which turned the kill into a Medium
  alert. Two path-reconstruction holes made it easier still.
  - Decided (the design question this entry was left with): the path
    stays the first discriminator, provenance is the second. A module file
    under a module directory that no package lists (dpkg's `.list` files,
    read once and again when `/var/lib/dpkg/status` changes; `rpm -qf` on
    the RPM family) and DKMS did not build (a registered module in
    `updates/dkms` or `extra`) was put there by hand: from an unexpected
    loader it is the non-standard case — Critical, KillProcessTree; from a
    system loader (`systemd-udevd`, `systemd-modules-load`: a locally built
    module at boot, or a comm only claiming to be one) High, alert only. A
    host with neither database is judged as before. `/usr` is dropped from
    both sides (a merged-`/usr` host reports `/usr/lib/modules`, packages
    list `/lib/modules`). `module_provenance::ModuleOwners`.
  - The kernel's walk stopped at the root of the `.ko`'s filesystem, so a
    file on a mount whose own tree reads `lib/modules/…` was "standard".
    The hook now records that root's inode key (`ModuleLoadRaw::root_dev`,
    `root_ino`) and the module-load pump puts the path on its mount point
    (the file-open sensor's `MountTable`); a filesystem no mount shows is
    `/(unplaced filesystem dev:ino)/…`, a non-standard path.
  - A component that is not UTF-8 was dropped, and `<bytes>/lib/modules/…`
    collapsed into a standard path; it is now kept (lossily).
  - Lab, Debian 12 (6.1), the in-tree `dummy` module loaded with
    `finit_module(2)` by a small loader of its own (an `insmod` exec draws
    R011's kill first). Before: a copy under
    `/usr/lib/modules/<ver>/kernel/drivers/net/nnx-rk.ko` — R018 Log,
    Medium; a copy on a tmpfs mounted at `/mnt/nnx` (its tree
    `lib/modules/<ver>/`) — reported as `/lib/modules/<ver>/dummy.ko`, Log,
    Medium. After: the copy — Critical, KillProcessTree (no package
    installed it); the tmpfs one — `/mnt/nnx/lib/modules/…`, Critical, the
    loader killed before it printed; the packaged `dummy.ko` (dpkg lists
    `/lib/modules/…`, the kernel reports `/usr/lib/modules/…`) — Log,
    Medium, as before.
  - The package database and the DKMS registry are root's to rewrite:
    copying the image is no longer enough, but a root that also adds its
    path to a dpkg list passes. What root cannot forge is the kernel's own
    judgement, which needs the distribution's key — after a load,
    `/sys/module/<name>/taint` shows an unsigned (`E`) or out-of-tree (`O`)
    module. That check, and denying the load at the hook (BUG-037), are not
    done here.
- **NN-AUD-226 (TST-004), NN-AUD-116 (FIMR-007), NN-AUD-117 (FIMR-008),
  NN-AUD-118 (FIMR-009), NN-AUD-123 (FIMP-011), lab PR 111.** Blind spots
  of the FIM.
  - TST-004's test accepted an `Opened` row for a `Modified` one; behind it
    was a real gap: the drain dropped any `Modified` event whose content
    hash matched the baseline, and the kernel reports a `chmod`/`chown` as
    `Modified`. A set-uid bit on a watched binary, `chmod o+r
    /etc/shadow`, a new owner: no trace. The baseline records mode, owner
    and group; a difference there is now drift of its own,
    `FimOp::AttrChanged` (wire byte 8, built in userland), with the values
    before and after on the event and on the signed row (`attrs`, absent
    on every other row, so older lines verify as they did).
    NN-L-FIM-001 kills on a system binary given power it did not have — a
    set-id bit, write for group/others, a new owner — and records one that
    only loses it (`chmod u-s` is a hardening step); NN-L-FIM-003 fires on
    a sensitive config made readable or writable by more users or given a
    new owner; NN-L-FIM-004 on a key file given to another owner;
    NN-L-FIM-024 on any change of a bait. The e2e asserts the `Modified`
    row on the watched path and adds `fim_chmod_setuid_records_attribute_drift`.
  - FIMR-007: NN-L-FIM-004 matched only `.ssh/authorized_keys`; sshd's
    built-in `AuthorizedKeysFile` also reads `.ssh/authorized_keys2`, and
    the shipped watch list covers `/etc/ssh/authorized_keys`. It now
    matches both, the `/etc/ssh/authorized_keys/<user>` form, and a key
    file created in a watched directory.
  - FIMR-008: the boot sweep re-creates missing baits after the watch set
    is built, and nothing enrolled them: after every reboot the tmpfs pair
    under `/run/northnarrow` was unwatched until the agent restarted.
    Re-created baits are watched at once. The kernel's boot id, recorded
    in the state directory, tells the expected case (the `/run` pair after
    a reboot: INFO) from a bait removed within a boot or a persistent one
    (WARN and a signed `bait_missing_at_boot` record).
  - FIMR-009: the sweep judged a bait by following links and restored it
    with `fs::write`. It now looks at the entry itself: a link or another
    type is replaced (the link removed, never its target), a bait is
    created exclusively with `O_NOFOLLOW`, mode 0644; only a missing
    directory is created (0700).
  - FIMP-011: a FIM that attached no observer (no `bpf` in `lsm=`, no
    BTF), or watches none of a non-empty list, said so in an INFO line.
    It is now an ERROR and a signed `subsystem_degraded` record; a partial
    attach names the shortfall.
  - Lab, Ubuntu 24.04 (6.8). Before: `chmod u+s /usr/sbin/sshd` (a copy of
    `chmod`) — nothing; a key appended to `/root/.ssh/authorized_keys2`
    (created before the agent started) — a drift row only; after a
    reboot, a WARN "Medium" at every boot, and `rm
    /run/northnarrow/pause.flag` as root — nothing. After: an
    `AttrChanged` row (`0o755` → `0o4755`, same hash) and NN-L-FIM-001
    Critical; restoring the mode — nothing (back to the baseline);
    NN-L-FIM-004 on the key; after a reboot an INFO "the runtime pair
    re-created after a reboot", and NN-L-FIM-024 Critical on the `rm`; the
    same bait removed and the agent restarted within one boot — a WARN and
    a signed `bait_missing_at_boot` record (`rebooted: false`). FIMP-011
    is unit-tested (it needs a kernel without `bpf` in `lsm=`).
  - Found on the way: the state directory is `chattr +i`, so the boot id
    is written through the same protection the log rotation uses, and
    registered as a protected inode.
  - Found on the way: the lab gate (`nn-lab.sh test-ignored`) runs the
    `#[ignore]`d tests, and the FIM e2e suite and six admin e2e tests
    (force-combat/unlock, a wrong key, status, the signed shutdown, key
    rotation, audit verify) are gated by the feature alone: they never
    ran in the gate. They now do, on their own pass. One of them,
    `audit_verify_e2e`, had gone stale: it counted the audit entries, and
    the agent now attests what it finds on the host (external audit
    MAIN-003 — on a lab guest, the installed agent's FIM baseline signed
    by another key); it checks the admin operations in order instead.
  - Privileged gate: Ubuntu 24.04 (6.8) 29 suites, 74 passed; Ubuntu
    22.04 (5.15) 73 passed, the one failure `audit_verify_e2e` before
    that fix.
- **NN-AUD-100 (ATP-013), NN-AUD-097 (ATP-009), NN-AUD-101 (EBPF-004), lab
  PR 112.** The BPF guard's own-object set.
  - ATP-013, worse than reported: `register_own_objects` listed the maps
    still in the eBPF object, and `take_map` removes one. The twelve ring
    buffers and `RING_DROPS` were taken by the sensors before it ran, so
    none was in `OWN_BPF_IDS`, and the guard handed a foreign root process
    a writable handle on each, every boot — enough to move a ring's
    consumer position and silence that sensor (`FS_PROTECT_EVENTS` carries
    the anti-tamper denials), or to zero the drop counters. A map or
    program whose id could not be read was skipped in silence. Now the
    ids of every map are recorded right after the load, before any
    `take_map`; an unreadable id is a registration failure (a missing
    deny hook), not a skip; every map an own program uses must be in the
    set, checked at each boot; the programs and links attached after the
    anti-tamper step (the FIM observers, the file-open sensor) are added
    in a second pass.
  - ATP-009: a guard that only observes was reported as an attached deny
    hook. In a production build the observe switch is now a missing deny
    hook (the agent then starts only with the degraded-mode override); a
    debug-trigger build observes by design, and the signed `agent_boot`
    entry records the build's test features and the guard's mode.
  - EBPF-004: `BTF_OFFSETS` stayed writable after it was armed. It is
    frozen right after (`BPF_MAP_FREEZE`): no process can rewrite the
    kernel offsets the hooks read; the programs still read them.
  - Lab, Debian 12 (6.1), guard in enforce mode. Before: a root process
    (a library preloaded into `/bin/true`) took a read-write handle by id
    on all thirteen — `RING_DROPS`, `FS_PROTECT_EVENTS`, `EVENTS`,
    `FILE_OPEN_EVENTS`, `EXEC_CHECK_EVENTS`, `TCP_CONNECT_EVENTS`,
    `DNS_QUERY_EVENTS`, `MODULE_LOAD_EVENTS`, `IOURING_EVENTS`,
    `BPF_SYSCALL_EVENTS` and the three `NET_*` rings — while a handle on
    `PROTECTED_PIDS` was refused; 54 maps registered. After: the thirteen
    refused (tamper-check C43), 68 maps registered, all deny hooks
    attached; `BTF_OFFSETS` shown `frozen` and an update refused even with
    the guard observing; `agent_boot` records `build_features`
    (`debug-trigger`, `test-privileged`) and `bpf_guard: enforce`.
- **NN-AUD-102 (EBPF-008), NN-AUD-096 (ATP-008), lab PR 113.** Two ways
  around the filesystem deny.
  - EBPF-008, worse than reported: the `file_ioctl` deny filtered only
    `FS_IOC_SETFLAGS` and its 32-bit twin; the fsxattr interface
    (`FS_IOC_FSSETXATTR`, `xfs_io -c 'chattr -i'`) changes the same inode
    flags and was let through — and the constant the program held for it
    (`0x40285821`) is no ioctl number at all, so the audit's "constant
    already defined" fix would have matched nothing. Root cleared `+i` on
    the state directory (the only thing keeping new entries out of it) or
    made `audit.log` append-only to the agent. The three numbers now come
    from `common`, built as `<asm-generic/ioctl.h>` builds them
    (`_IOW('X', 32, struct fsxattr)` = `0x401c5820`) and pinned to the
    uapi by a test, and the deny filters all three.
  - ATP-008: the shipped `.v1` lists (`netflow-blocklist`,
    `netflow-ja3-blocklist`, `process-comm-allowlist`,
    `netflow-comm-allowlist`) were mutation-denied only: an in-place append
    went through, and the next boot read it — a blocklist blinded, a comm
    allowlisted. Like `fim-paths.v1` (FIMR-001) they are now write-denied;
    install.sh writes them with the pins dropped, operators tune the
    signed `.local` overlays. Recording each list's hash on the signed
    boot entry (the detection half) is left for later.
  - Lab. Before, Debian 12 (6.1), the build of main: through the fsxattr
    interface root cleared `+i` on `/var/lib/northnarrow` and set `+a` on
    `audit.log` (the probe put each flag back), and an append to
    `netflow-blocklist.v1` went through. After, Ubuntu 22.04 (5.15): all
    three refused and recorded (NN-L-AT-001; `op=ioctl` twice, `op=write`),
    in three new tamper-check cases — C44 and C45 with
    `deploy/lab/adversarial/fsxattr-probe.c`, C46 the append — and the
    anti-tamper suite OK.
- **NN-AUD-094 (ATP-003), NN-AUD-099 (ATP-012), lab PR 114.** The
  trusted-installer window's kernel half had no deadline. The hooks read
  `FS_PROTECT_OVERRIDE`, which held the session nonce alone; only the
  agent's sweep on the event path zeroed it, so a host whose events had
  stopped (a saturated ring, a dead pump, the telemetry probe off, an
  agent that died in the window) kept every protected file — and, since
  review 82, the kexec refusal and the pin root's protection — open past
  the deadline. And a close whose zeroing failed was recorded as "closed".
  - `FsGrant { nonce, expires_ns }` in a new pinned map `FS_GRANT` (a new
    name: aya reuses a by-name pin at load, and an older agent's 4-byte
    `FS_PROTECT_OVERRIDE` pin would fail the hooks' verification). The
    hooks test the session and the deadline themselves
    (`FsGrant::active`, `bpf_ktime_get_ns`), as for `KILL_GRANT`; the
    window's one deadline is written into both grants.
  - A one-second ticker closes the window — and records it — at the
    deadline, not at the next event, and retries a failed zeroing.
  - ATP-012: a close is read back; a zeroing that failed, or that the map
    does not show, is an ERROR and a signed `close_failed` entry (the
    kernel's deadline still ends the window).
  - Lab, Debian 12 (6.1): a 20-s window, then a process started inside it
    opens `agent_id` for writing at t=25 s, executing nothing in between.
    Before: allowed — the window was still open in the kernel 5 s past
    its deadline, closed only when an event reached the agent. After: the
    ticker closed it at t≈20.8 s with a signed `closed: ttl_expired`, and
    the open was refused. With the agent's cgroup frozen for the whole
    window (no ticker, no event path): allowed at t=10 s, refused at
    t=25 s — the kernel's deadline alone.
- **NN-AUD-086 (AUT-003), NN-AUD-087 (AUT-004), NN-AUD-090 (MAIN-005),
  NN-AUD-085 (AUT-002), lab PR 115.** The admin key files.
  - AUT-003, worse than reported: the agent rewrote `admin.pub`
    (rotate-keys) and the signed overlays (`config overlay set`) through a
    temporary file at a fixed name, opened with `create(true)
    .truncate(true)` — no `O_NOFOLLOW`, no `create_new`, no directory
    fsync. Root may create entries in `/etc/northnarrow` while the agent
    runs (there is no `inode_create` hook; the directory is
    MUTATE-protected only), and the agent is the one process its own hooks
    let write there: a link planted at the temporary name
    (`.admin.pub.tmp -> audit.log`) made the next legitimate rotation
    truncate the audit chain — written through by the one process allowed
    to — and rename the link over `admin.pub`. `atomic_file::replace`
    removes whatever sits at the temporary name (`unlink` never follows a
    link), creates it exclusively with `O_NOFOLLOW`, sets the mode on the
    descriptor, writes, syncs, renames and syncs the directory; `admin.pub`
    and the overlays go through it.
  - AUT-004: one malformed line in `admin.pub` made the agent refuse the
    whole file and run without its admin socket — no unlock, no way out of
    COMBAT — and the watchdog, as strict, without a key to verify a
    shutdown marker with. `admin.pub` is now read key by key
    (`parse_admin_pub_lenient`, shared by the agent, the watchdog and
    `verify-keys`, so both judge with the same keys): a bad line costs its
    own key, and is an ERROR and a signed record naming the line. Skipping
    a line never adds authority. A file with no valid key still disables
    the socket, now with an ERROR and a signed record instead of a WARN.
  - MAIN-005: `nn-admin verify-keys` required every line to be exactly 64
    characters, so it rejected every `admin.pub` install.sh writes (a key
    and its roles). It parses as the agent does, prints each key's roles
    and the skipped lines, and exits non-zero when a line was skipped (it
    is a checker).
  - AUT-002, narrowed: the CLI read the admin private key whatever its
    mode or owner. A key group- or other-accessible, or owned by another
    user, is now refused (OpenSSH's rule for identity files;
    `NN_ADMIN_ALLOW_LOOSE_KEY=1` accepts one — a key on a vfat stick shows
    0644, and COMBAT recovery must not stop at a mode bit); the key's text
    and bytes are wiped after use; `init --force` resets the mode to 0600
    and never writes through a link. The audit's third point was wrong:
    `SigningKey` was already wiped on drop (ed25519-dalek's `zeroize`,
    enabled through `std`); it is now asked for explicitly.
  - Lab, Debian 12 (6.1), before and after on the same guest. Before: a
    `config overlay set` with links planted at the temporary names wrote
    the overlay into the probe's sentinel file and left
    `mass-write-carveout.local` and its `.sig` as links to it;
    `verify-keys` refused the installed `admin.pub` (`pub key must be 64
    hex chars (got 128)`, exit 1); a 0644 copy of the admin key opened a
    trusted-installer window. After: the sentinel untouched, both files
    regular (0644), the links at the old names left as they were;
    `verify-keys` lists the key with its five roles (exit 0); the 0644
    copy refused (`chmod 600` it), the same copy at 0600 accepted; a
    malformed line appended to `admin.pub` (inside a window) and the agent
    restarted: an ERROR and a signed `subsystem_degraded` record naming
    line 4, the admin socket still answering (status, a new window), and
    `verify-keys` naming the line with exit 1; the line removed: exit 0.
    The anti-tamper suite: OK.
  - Found on the way: `ade::tests::a_model_that_fails_to_load_leaves_the_ade_off`
    relied on the umask for its files' mode — under umask 0002 (a login
    shell on Ubuntu) the trust check refused them before the GGUF parser
    ran. The test sets the mode.
- **NN-AUD-160 (LLMR-013), NN-AUD-162 (LLMR-016), lab PR 116.** The overlay
  gate applies what it verified.
  - LLMR-013, worse than reported: `OverlayGate::check` read and verified
    an overlay's bytes, `effective` returned its path, and every loader —
    the netflow and JA3 blocklists, the comm allowlists, the FIM paths (at
    boot and at a signed `fim baseline`), the canary readers, the
    mass-write carve-out (read twice), the escalation allowlist — read the
    path again. The same shape, in reverse, sat in the Wave 1 COMBAT fix
    (ATP-001/DEP-003): `trusted_source` read the ruleset, let the gate
    verify a second read, and applied the first, at every engage. A root
    process able to pause the agent's `open()` (fanotify permission
    events) could serve the gate the signed bytes and the loader others.
    `OverlayGate::verified` reads an overlay once — not through a link,
    without waiting on a FIFO planted at its name, at most 4 MiB — decides
    on those bytes and hands over their text (`Verified`); the loaders take
    that instead of a path, so a second read cannot come back. `effective`
    and its `/dev/null` stand-in are gone, the journal names the SHA-256
    applied, and the two unused convenience loaders that read the comm
    allowlists' default paths themselves, past the gate, are removed.
  - LLMR-016: a `.v1` default list that could not be read gave an empty
    list and a WARN — FIM then watched only the overlay's additions, the
    blocklists blocked nothing. The shipped lists are built into the agent
    (`include_str!`, pinned to `configs/` by tests); an unreadable `.v1`
    gives way to that copy, with an ERROR and a signed `integrity_drift`
    (`default_list_unavailable`).
  - Found on the way: the gate read with a blocking `open()`, so a FIFO
    planted by root at an overlay's name stopped the agent's boot there;
    it is refused now ("not a regular file").
  - Found in the lab: the integrity check (`self_integrity::config_overlays`)
    and its known-drop-in comparison read with a blocking `open()` too, so
    the same FIFO stopped that check for good; they read as the gate does
    now, and an overlay that cannot be read so is a finding ("not read").
  - Lab, Debian 12 (6.1) and Ubuntu 24.04 (6.8), the build of main before.
    A FIFO planted by root at `mass-write-carveout.local`: before, the
    agent's boot stopped in `open()` — systemd showed it `activating`, no
    admin socket — until a writer opened the FIFO (the probe's release
    found the agent waiting), and the agent had registered the FIFO as a
    protected inode; after, the agent boots at once (UNAUTHORIZED OVERLAY,
    the socket listening within a second), the integrity check reports
    `config_overlay … (not read: not a regular file)`, and the release
    finds nobody waiting. `fim-paths.v1` moved aside: before (24.04),
    `defaults=0 … effective=0` and "no path to watch — FIM and the
    anti-tamper baits see nothing", nothing signed; after (Debian), the
    ERROR "the copy built into the agent is in force", the same 125
    defaults watched, and a signed `default_list_unavailable` record. A
    signed `fim-paths.local`: the SHA-256 the journal names as applied is
    the file's and the one its signature covers (`9eed6038…848e`). The
    anti-tamper suite: OK.
- **NN-AUD-161 (LLMR-014), lab PR 117.** The rollback floor of the signed
  overlays comes from the verified audit chain.
  - `recorded_signatures` read `audit.log` line by line as plain JSON — no
    hash link or signature checked — and a missing or unreadable log gave
    an empty map: no floor, no log line, and a retired signature (an
    exemption signed for a maintenance, then superseded) loaded again.
    `RollbackFloor::scan` (`config/overlay_floor.rs`) reads the chain
    before the boot bootstraps the key and the log (a log found missing
    must not look like a fresh install) and verifies every entry after the
    last anchor: its link, its own hash, the agent's signature (with the
    public half of the private key, or `agent.sig.pub` when a restart
    under the previous instance's hooks closes the key). The tail's
    signature alone would not do: the agent appends to a history it does
    not verify, so a genuine entry on top of a rehashed history vouches
    for nothing.
  - An anchor (`overlay_floor_anchor`, signed by the agent) carries the
    floor a boot verified and the hash of the entry it verified up to. A
    boot whose scan verified 256 entries past the last anchor writes one,
    so the next boot verifies only what came after (on several threads
    from 1 024 entries): the log is never rotated.
  - A log missing or empty while the key exists, a chain that does not
    verify, a key that cannot be read: the floor is reset to the time of
    that boot (never below the newest signature the chain still shows, so
    a clock set back does not reopen it), an ERROR, and a signed
    `integrity_drift` (`overlay_rollback_floor_unavailable`, with
    `not_before`) written as soon as the log opens, before `agent_boot`: a
    log cut back to any entry of that boot still carries it. A break with
    a reset after it is known at the next boots; one without is found
    again. A signature made after the reset loads: the recovery is
    `nn-admin config overlay set` (or `sign`) and a restart.
  - `nn-admin config overlay status` computes the same floor
    (`--agent-sig-key`) and shows a reset to come (`rollback-floor`).
  - Residual, as triaged: a log cut back offline to an older prefix that
    verifies, the key, its public half and the log all removed (what a
    fresh install looks like), or a chain forged with the key itself — an
    offline reader of an unencrypted disk has it — cannot be told apart on
    the host; that takes an anchor off it (Tappa 13).
  - Lab, Debian 12 (6.1), the build of main before (`floor-probe.sh`). A
    `process-comm-allowlist` overlay signed and stored, a copy of it and
    its signature kept, a newer one stored and loaded; then, with agent and
    watchdog stopped and no pinned hooks (offline), the retired copy put
    back. With the log as it was: refused before and after (older than the
    signature accepted). With `audit.log` moved aside: before, the retired
    exemption loaded (`effective=14`, its SHA-256 `df043379…`) and the new
    chain began with `agent_boot` and `config_overlay_accepted`, no trace;
    after, `OVERLAY ROLLBACK FLOOR RESET`, the overlay refused ("signed at
    1791959516 — before 1791959573, when the rollback floor was reset"),
    and the new chain begins with the signed
    `overlay_rollback_floor_unavailable` and its anchor. With the records
    of the newer signature removed from the log: before, loaded again;
    after, "entry 1450 does not chain from the one before it", reset,
    refused. The first boot of the new build verified the lab's 1 444-entry
    chain in 17 ms and anchored it; the restarts after it verified 9 to 13
    entries (1 ms), the warm ones with `agent.sig.pub`. The anti-tamper
    suite: OK.
- **NN-AUD-093 (MAIN-008), NN-AUD-089 (MAIN-004), NN-AUD-092 (MAIN-007),
  lab PR 118.** The variables that weaken the agent.
  - MAIN-008, worse than reported: detect-only is `--detect-only` or
    `NN_DETECT_ONLY` / `NORTHNARROW_DRY_RUN` set to `1`, `true` or `yes`,
    but `WEAKENING_ENV` matched `1` only, so `NN_DETECT_ONLY=yes` switched
    the response off with no `weakening_env` finding — the audit's
    verification note took the finding for granted. And
    `audit_failure_is_fatal(detect_only, …)` let a detect-only agent run
    without a writable audit chain, so the one variable also lifted the
    fail-closed gate (the refusal even suggested `--detect-only`). The
    gate now needs `NN_AUDIT_ALLOW_UNWRITABLE=1` whatever the mode; each
    `WEAKENING_ENV` entry carries the test its consumer applies
    (`response::config::is_truthy` for the detect-only pair); `agent_boot`
    records `detect_only_source` (`--detect-only` or `NAME=value`).
  - MAIN-004: `NN_FIM_DRIFT_CAP_BYTES`, `NN_DETECTIONS_CAP_BYTES` and
    `NN_STATUS_EVENTS_CAP_BYTES` took any `u64` (1 rotated the signed
    evidence after every row), and only the first one logged.
    `chainlog::cap_from_env` raises a value below 1 MiB to 1 MiB, keeps the
    default for a value that does not parse, and logs every override; the
    three names are in `WEAKENING_ENV` (any value), so an override is a
    signed `integrity_drift`.
  - MAIN-007, narrowed: per-event errors never ended either drain loop
    (FIM logs "event dropped, drain continues", netflow keeps the event),
    and the ladder tick and posture decay have no exit (a panic aborts the
    process, so the watchdog respawns it and the chain records
    `previous_run: Abrupt`). What is left — a tokio I/O failure (an
    `AsyncFd` that cannot be set up or polled) ending a drain — is now an
    ERROR and a signed `subsystem_degraded` record (`at_boot: false`)
    naming the stream, instead of a WARN.
  - Found on the way: `NN_TELEMETRY_PROBE_SECS` was reported only for the
    exact text `0`, while the probe is off for any spelling of 0 (`00`,
    ` 0`) and an interval of hours thins it out to nothing; a value of 0
    or above the 60 s default is reported now. `NN_ADE_ALLOW_MOCK=1` (the
    mock backend answers for a model that failed to load) was not in the
    list.
  - Lab: Lab, Ubuntu 24.04 (6.8), the build of main before, the
    guests under QEMU for Windows + WHPX (KVM is unavailable in WSL since
    KB5127648, microsoft/WSL#41918). A drop-in
    `Environment=NN_DETECT_ONLY=yes NN_DETECTIONS_CAP_BYTES=16384
    NN_TELEMETRY_PROBE_SECS=00`, laid down offline (`envweak-probe.sh`):
    before, detect-only on, `agent_boot` with `detect_only: true` and no
    `weakening_env` record — the 16 KiB cap and the probe switched off taken
    silently; after, three signed `weakening_env` records (the three
    variables), "rotation cap override below the floor — raised to the
    floor" (1 048 576), and `detect_only_source: "NN_DETECT_ONLY=yes"`. The
    same drop-in with `audit.log` replaced by a directory: before, the agent
    started, detect-only and unaudited, its admin socket up; after, it
    refuses ("Refusing to run unaudited; set NN_AUDIT_ALLOW_UNWRITABLE=1 to
    start anyway"). Recovering from that refusal takes the documented path
    (no admin socket for a window, the pins still protect `/etc/northnarrow`:
    units disabled, guest restarted, files fixed). A drain that ends needs a
    tokio I/O failure and was not provoked in the lab. The anti-tamper
    suite: OK. Privileged gate: Ubuntu 24.04 (6.8) and Debian 12 (6.1), 29
    suites, 74 passed, 0 failed each.
