# Triage of the external research of 11 October 2026

> Wave 4 (lab PR 214, 20 October 2026): the on-host LLM advisor (ADE) was
> removed. The lines below about the LLM and the ADE (a verdict that cannot
> be lowered, a separate ADE process, a prompt injection benchmark, the
> dependencies under Candle) are historical.

Source: `northnarrow_repo_audit_frontier_and_defence.md` (founder, 11 October
2026) — Part A (gaps against the state of the art), Part B (check of the
repository at commit `86ee590`), Part 4 (military and government standards).
Each item was compared with the code of `main` after PRs #197 and #198;
where the research says "not verified", the check was done in the lab
(ubuntu 24.04 / 6.8) and the result is given.

Legend: **done** = already in the code; **applied** = done in PR #200 of the
adversarial test (Tappa 10.8, merged); **roadmap** = added to the Tappa given in
this PR, without changing the order of the Tappe; **to place** = a proposal
for the founder; **no** = do not apply, with the reason.

## 1. Already done (the research was behind the code)

| Research item | State | Where |
|---|---|---|
| io_uring sensor | done | `agent-ebpf/src/io_uring.rs`, rules IOU-001/002 |
| `bpf()` observer and `bpf_map` guard | done | PR #194 |
| Protection of BPF links, detach and pins | done | PR #197 (finding 39) |
| Telemetry probe ("hooks that fail silently", Datadog 2026) | done | PR #198 |
| `/proc/<pid>/mem` of the protected pids | done | denied by the `ptrace_access_check` hook (`mm_access` goes through it); checked in the lab |
| The LLM cannot lower a deterministic verdict | done by construction | the ADE runs only if no rule produced a verdict (`main.rs`, "no rule matched, escalating to ADE") |
| JA4 | half done | computed in `net/tls_parser.rs`, no rule uses it → roadmap 10.9 |
| exec from memfd, PAM, `ld.so.preload` | done | R004, FIM-021, FIM-022 |
| Hash of the binaries and of the eBPF object at start, SLSA at install | done | PR #187 |

## 2. Applied (PR #200, Tappa 10.8, adversarial test of the anti-tamper)

The `nn-lab.sh tamper-check` check (20 cases, outcome + evidence in the signed
chain logs) confirmed the research's SQ4 points in the lab and found others.

| Item | What changes |
|---|---|
| SQ4.5 / BPF self-defence | **bug** in PR #197: `OWN_BPF_IDS` was keyed by id only, so maps, programs and links with the same number overwrote each other (66 registrations, 48 entries) → key `(type, id)` |
| kill/ptrace denied without a trace | `FS_OP_SIGNAL` / `FS_OP_PTRACE` on the anti-tamper ring (ptrace only in ATTACH mode, dedup per caller and a global cap in the kernel); rule NN-L-AT-001: every denial becomes a signed detection |
| SQ4.2 `systemctl set-property`, drop-ins, mask/override | integrity check every 30 s ±20 %: unexpected drop-ins of the two units (also `system.control` and `service.d`), cgroup limits (`memory.max`, `pids.max`, `cpu.max`), `integrity_drift` audit |
| Part B 1.4.6 `OOMScoreAdjust` | `-500` agent, `-900` watchdog; `oom_score_adj` raised by root → `integrity_drift` (only root can change the value, so it is proven, not prevented) |
| SQ4 bind mount, second bpffs (Not done yet) | a mount over `/etc/northnarrow`, state, pins, binaries and units, a bpffs outside `/sys/fs/bpf` → `integrity_drift` (the host's view, `/proc/1/mountinfo`) |
| cgroup freezer | a frozen agent cannot notice it while frozen: the stall is recorded on wake-up (`agent_stalled`) |
| SQ4.4 saturation / loss of visibility | every ring that loses events → a `ringbuf_drop` audit entry (one per ring every 10 min) |
| M4.3 Unpredictability (NIST 800-160v2) | ±20 % jitter on the telemetry probe, the link self-check and the integrity check |
| (new, from the check) `.local` overlay | a `process-comm-allowlist.local` in `/etc/northnarrow` exempts a comm at the next restart without authentication: it is now reported with a hash; the signed version goes to the roadmap |
| environment variables that weaken | `NN_ANTI_TAMPER_ALLOW_DEGRADED`, `NN_BPF_DEFENSE_OBSERVE`, `NN_TELEMETRY_PROBE_SECS=0`, … → `integrity_drift` at boot |
| (new, from the check) signed logs that could be redirected | a bind mount over `/etc/northnarrow` made the agent write the audit into the attacker's file, including the entry that reported the mount: every log now writes through a directory fd taken at open (finding 44) |
| (new, from the `ringbuf_drop` audit) | on 5.15 a `daemon-reload` makes the `file_open` ring lose events (finding 45, open): this confirms the priority of moving the sensor to LSM in 10.9 |

## 3. Added to the roadmap (this PR)

**Tappa 10.7** — Elastic's PANIX (persistence) and FENIX (fileless) as a
regression suite next to Atomic Red Team.

**Tappa 10.8**
- Kani after fuzzing: harnesses on the `unsafe` blocks, on the binary parsers
  and on the verification of signatures and quorum (HACMS / s2n-quic).
- `.local` overlay only through a signed `nn-admin`.
- These stay in the adversarial test: `cgroup.kill`, kexec/unsigned module with
  `lockdown` active, adversarial saturation of the ring (the soak proves
  capacity, not resistance).

**Tappa 10.9**
- **Sensor attach point** (Phantom TOCTOU, Guo/Zeng; io_uring,
  ARMO 2025): `sys_enter_openat` → LSM `file_open`; DNS QNAME read after the
  copy into the kernel, not from the user iov at the entry of `udp_sendmsg`;
  `sys_enter_execve` → LSM `bprm_check_security` with an optional deny. The
  toolchain limit written in `exec_check.rs` no longer holds: the agent
  already attaches more than twenty LSM programs with the same toolchain.
- Exec by inode property (tmpfs, memfd, `O_TMPFILE`, `nlink == 0`,
  `execveat(AT_EMPTY_PATH)`, dynamic loader as argv[0]) and identity by
  a hash computed in the kernel (`bpf_ima_file_hash`, where IMA is active).
- BPF ecosystem, second phase: `bpf_prog` hook, rare helpers at load
  (`bpf_probe_write_user`, `bpf_override_return`, `bpf_send_signal`; Datadog
  2026, LinkPro, VoidLink), XDP/TC attach.
- Kernel integrity: `init_module` from a buffer, distinct from
  `finit_module`; syscall table / ftrace / hidden modules; credentials
  changed without a legitimate setuid (a shadow copy, as LKRG does); cross
  views for hidden processes and sockets.
- JA4 in the blocklist next to JA3.
- Inline enforcement (LSM `-EPERM`) for a deterministic subset:
  exec from tmpfs/memfd, reading credentials from binaries outside the
  allowlist, connect to the blocklist. The LLM and the posture ladder stay
  in userland.

**Tappa (ex 10) Scout** — a baseline of the ANSSI-BP-028 v2.0 controls (SCAP /
ComplianceAsCode, Licence Ouverte 2.0) with the level reached; an optional
"appliance" profile with IPE + dm-verity (6.12+).

## 4. To place (founder's decision)

| Proposal | Why it matters | Note |
|---|---|---|
| Process separation (network/DNS/TLS parsers and ADE separate from decision and keys) + Landlock (ABI 6, signal scope) + seccomp | a compromised parser today has all the agent's capabilities | HACMS "seismic retrofit"; a large piece of work, it touches the architecture |
| `mseal` on admin keys and policy tables | in-memory integrity | 6.10+, useful only after the separation |
| Crypto-agility: an algorithm field in admin keys, audit chain, manifest; LMS or ML-DSA-87 for releases and manifests; SHA-384 | NIAP PP-EDR asks for RSA/ECDSA FIPS 186-4; CNSA 2.0 from 2027 for US systems | ML-DSA signatures ~4.6 KB: one signature per batch in the chain log |
| MITRE D3FEND IDs on rules and actions, coverage analysis | audit, procurement, XAI vocabulary | Restore is not covered today |
| Automatic restore of protected files from the signed baseline | Restore / Non-persistence (NIST 800-160v2) | |
| A signed local verdict of the host's health (sensors, drops, hashes, hardening) | a bridge to Zero Trust and to the fleet console | |
| A provenance graph to bound the incident, taint in xattrs | explanation and a targeted kill-tree | not as an inline GNN detector (immature, by its own authors' account) |
| A prompt injection benchmark on the ADE with the real model (fragmented payloads) + CyberSOCEval | log fields are written by the attacker | 2026 preprint, not peer-reviewed |
| Certification path: EUCC, and for Italy ACN / Perimetro / CVCN; a Security Target modelled on the NIAP PP-EDR; SWID tags | public administration market and EU regulated infrastructure | the research flags Italy as a gap: a dedicated research is needed |
| Inventory of `unsafe` and C dependencies (under Candle) | required by the 2025 NSA/CISA guidance | small, useful for the Security Target |
| MITRE Engage: a narrative for the lures, an observation phase before neutralising, signed rules of engagement | deception as a process | it plugs into INVESTIGATE → NEUTRALIZE |
| CRS AIxCC (for example Buttercup) in a weekly CI | automatic bug finding | evaluated on C/Java, not on Rust/eBPF |

## 5. Do not apply, or apply with care

- **Inline SIGKILL with `bpf_send_signal` / `bpf_override_return`**: the
  right primitive to block is the LSM returning `-EPERM`, already in use;
  `bpf_override_return` needs `CONFIG_BPF_KPROBE_OVERRIDE` and functions in
  the error-injection allowlist, and a kill in the kernel on a false positive
  cannot be undone.
- **Denying io_uring to processes outside the allowlist**: io_uring is used
  by modern runtimes (databases, proxies); at most optional, and off by
  default.
- **Hornet / upstream signing of BPF programs**: a scheme disputed between
  the LSM and BPF maintainers; to reconsider when it reaches mainline.
- **Inline provenance GNN detector**: the authors themselves (USENIX 2025)
  warn that real time does not scale.
