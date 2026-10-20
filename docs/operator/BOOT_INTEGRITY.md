# Boot integrity: phases, self-test, degradations, trust level

Lab PR 218 (external review G-09, G-11, G-12, AR-09, P0 C-13, P0 C-14;
capability program C01 and C23). What the agent checks before it touches
the kernel, how it proves that its deny hooks run, how it records what it
runs without, and how it says, signed, how far its protection is measured.
Code: `agent/src/boot/` (`mod.rs`, `lsm.rs`, `deny_selftest.rs`,
`degradation.rs`, `trust.rs`, `manifest.rs`).

## 1. The start in phases

The order of the start is enforced by the code (`BootSequence`), not by
comments in `main()`. Each step is recorded in its phase; a step recorded in
another phase, a phase skipped, or a phase left with a required step
missing stops the start. The sensor and anti-tamper attach take an
`AttachPermit`, and only the move from preflight to attach hands one out:
an attach placed before a preflight check does not compile, a check moved
after the attach fails every start (and the test
`boot::tests::main_runs_the_phases_in_order`).

| Phase | What runs | Required before the next phase |
|---|---|---|
| 1. preflight | the embedded eBPF object; the state directory; the BTF offsets; the chains against their heads; the identity; the capabilities (`caps::boot_gate`); the install manifest; the audit log's writability; the host hardening table; the BPF LSM gate (section 2) | eBPF object, BTF offsets, capabilities, install manifest, audit log, BPF LSM |
| 2. attach | the eBPF object loads; the sensors; the deny hooks (`anti_tamper::attach`) | sensors, deny hooks |
| 3. self-test | one deny hook exercised against the agent (section 3) | self-test |
| 4. attest | the signed audit log opens (`agent_boot`); every degradation found so far is signed (section 4) | `agent_boot`, boot degradations |
| 5. subsystems | the blocklists, the rule engine, the response executor, the posture, the FIM observers and the file-open sensor, the drains, the admin socket | — |
| 6. run | the capability manifest and the trust level are signed (sections 5 and 6); `READY=1`; the event loop | capability manifest |

A refusal in the preflight leaves the host as it was: nothing is loaded
into the kernel. The capability, install-manifest and audit checks used to
run after the eBPF programs were loaded, attached and pinned.

The audit log's preflight opens it for append without writing (or, when
the file does not exist yet, checks that its directory can take it): a
read-only mount, an immutable file or a missing `ReadWritePaths` refuse the
start before anything attaches, unless `NN_AUDIT_ALLOW_UNWRITABLE=1`. The
signed `agent_boot` row after the attach still proves it with a write. A
permission error while the previous agent's pinned hooks may close the
file to a process not yet registered (its early registration failed) is
left to that row.

Follow-up: `main()` keeps one body; splitting it into one function per
phase, each taking the previous phase's output, is the next step of this
refactor.

## 2. The BPF LSM gate

The deny hooks are BPF LSM programs. A kernel built with
`CONFIG_BPF_LSM=y` but without `bpf` in its active LSM list
(`/sys/kernel/security/lsm`; the default on Ubuntu) lets every one of them
attach and never runs them. The agent used to start there with one WARN,
its health line saying "all LSM hooks attached", and no self-defence.

**Decision.** Such a start is refused before anything attaches (exit 78,
`EX_CONFIG`), unless the degraded-mode opt-in the deny-hook shortfall
already uses is set: `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`. Either way the
signed chain gets a `subsystem_degraded` (`source: bpf_lsm`) with the list
the kernel runs; a refusal adds an `agent_boot` row with `result: refused`
and `refused_by: bpf_lsm`. The opt-in starts the agent at trust level L0,
and the self-integrity check reports the variable as a `weakening_env`.
Detect-only does not change the decision: it turns the response off, not
the self-defence the agent promises.

A list that cannot be read (securityfs not mounted) is not a refusal: the
self-test decides, and the gap is signed.

Alternatives not taken: keep starting with a WARN (the silent absence this
fixes); a new variable for this case alone (one more weakening switch, when
the existing one already means "start below the expected protection" and is
already watched); refuse an unreadable list too (the self-test measures the
same thing directly).

Enable `bpf` as `KERNEL_COMPATIBILITY.md` ("Enabling the bpf LSM")
describes: add it to the list the kernel runs, never write a fixed list.

## 3. The deny self-test

Right after the deny hooks attach, the agent runs a child of its own binary
(`northnarrow-agent --deny-self-test`, hidden flag). The child is not in
`PROTECTED_PIDS`; it sends `SIGURG` to its parent, the agent. `task_kill`
refuses every signal but 0 to a protected process from an unprotected one,
so the child must get `EPERM` — a root caller signalling a root process
gets no `EPERM` from the permission checks, only from an LSM, and the child
runs in the agent's own SELinux domain or AppArmor profile, which may signal
itself. `SIGURG` is ignored by default and the
agent installs no handler: when the hook does not run, the signal it lets
through changes nothing.

| Outcome | Meaning | The start |
|---|---|---|
| `denied` | the signal was refused: the deny hooks run | goes on |
| `not_denied` | the signal was delivered: the hooks are attached and not run ("attached but not executed", seen on Ubuntu) | refused, exit 78 (`refused_by: deny_self_test`, signed), unless `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`: then L0, signed |
| `inconclusive` | no child, no exit within 5 s, another errno | goes on, signed, L1 |

The refusal leaves a denial on the evidence ring like any attempt on the
agent. The agent takes that one record — the child's pid, `SIGURG`, the
agent's pid as the target, a kernel timestamp between the spawn and the
reap, once — before the posture and the rules see it: the self-test never
raises COMBAT nor writes an NN-L-AT-001 detection. Any other denial goes on
as before. The journal says `deny self-test: its refused signal reached the
evidence ring` when it arrives: the refusal came from the agent's own hook,
which writes that record.

What the self-test proves: the kernel runs the agent's BPF LSM programs and
one deny hook (`task_kill`) refuses. It does not exercise each of the 16
mandatory deny hooks one by one; the attach counts them (the health line),
and a per-hook self-test is a follow-up.

## 4. Degradations

A sensor on its fallback attach point, a hook that did not attach, a stream
that is not persisted: each one used to be a WARN, some of them a signed
record, none of them visible in `nn-admin status`. Every one now:

- is signed in the audit chain as a `subsystem_degraded`
  (`op: integrity_drift`, `extra.kind: subsystem_degraded`, `extra.source`
  naming the part): at once when the code that finds it holds the audit
  log, at the log's open (phase 4) for what came before it, otherwise by a
  flush every 15 s — within 60 s of the report in every case once the log
  is open (the audit log now opens before the subsystems load);
- is listed by `nn-admin status --key` (`degradations`), and counted
  against the trust level.

The sources added by this PR: `bpf_lsm`, `deny_self_test`, `exec_sensor`
(the exec sensor on `sys_enter_execve`: the path read from the caller's
memory), `file_open_sensor` (the file-open sensor on `sys_enter_openat`,
each of its four fallbacks and the tracepoint mode), `dns_sensor`
(`udp_v6_send_skb` not attached: queries to IPv6 resolvers not observed;
the `udp_sendmsg` fallback, signed since EBPF-006), `io_uring_sensor` (no
tracepoint, or no submit tracepoint), `net_sensor` (`udpv6_sendmsg` not
attached), `net_drain` (the netflow or listener log cannot be opened). The
earlier boot records (tracepoint offsets, hook arguments, capabilities,
anti-tamper observe hooks and degraded starts, JA3 without producer, no
`nft`, FIM coverage, the admin socket…) go through the same
registry and keep their shape.

An operator's choice of a weaker sensor (`--exec-sensor tracepoint`,
`--file-open-sensor tracepoint`, `--dns-sensor sendmsg`) is recorded too:
the trust level says what runs, not why.

**The network drain without its log (P0 C-14).** When the netflow log
cannot be opened, the drain used to stay off for the whole boot: TCP, UDP
and listener events reached no rule. It now runs without the log — every
flow and listener still reaches the rules, nothing is written — and the
degradation is signed (`source: net_drain`), as the listener log's already
was evaluated-not-persisted.

## 5. Trust levels

How far this run's protection is measured, from the boot's own checks:

| Level | Meaning | When |
|---|---|---|
| **L3** | enforcing and verified | `bpf` in the active LSMs, every mandatory deny hook attached and armed, the deny self-test refused its signal, the response enforcing, nothing degraded |
| **L2** | enforcing and verified, degraded | as L3, with at least one degradation recorded (section 4) or detect-only |
| **L1** | enforcement partial or not verified | a mandatory deny hook missing (a start under `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`), or the self-test inconclusive |
| **L0** | no enforcement | `bpf` not in the active LSMs, the self-test's signal delivered, or no deny hook attached |

The mandatory deny hooks are the 16 of `DENY_HOOKS` plus the optional ones
the running kernel has (`OPTIONAL_DENY_HOOKS`), as the health line counts
them. The host's own hardening (lockdown, Secure Boot, IMA, module
signatures, kexec — `nn-admin host-check`) is not part of the level: it is
listed next to it in the manifest. `nn-admin status --key` shows the level
recomputed with the degradations recorded since the boot (a sensor that
degrades later lowers it); the manifest keeps the boot's.

## 6. The capability manifest

At every boot, before `READY=1`, the agent signs what it runs with: one
`capability_manifest` row of the audit chain (the agent's key,
hash-chained: `nn-admin audit verify` checks it), whose `extra` is:

| Field | Content |
|---|---|
| `manifest_version` | 1 |
| `agent_version`, `kernel` | the agent's version, `/proc/sys/kernel/osrelease` |
| `btf`, `btf_offsets_resolved`, `btf_offsets_drifted`, `btf_offsets_absent` | `/sys/kernel/btf/vmlinux` present; the offsets resolved from it |
| `active_lsms`, `bpf_lsm` | the active LSM list; `active`, `absent` or `unknown` |
| `deny_hooks` | `expected`, `attached`, `missing` (each hook or failed step with why), `observe_missing` |
| `deny_self_test` | `denied`, `not_denied` or `inconclusive: <why>` |
| `bpf_guard` | `enforce`, or `observe` (a debug build) |
| `sensors` | each sensor and its attach point (`exec`: `lsm:bprm_check_security` or `tracepoint:syscalls/sys_enter_execve (user memory)`; `file_open`, `dns`, `process_spawn`, `tcp_connect`, `net_flows`, `io_uring`, `fim_observers`) |
| `host_hardening` | each check of `nn-admin host-check`: id, `ok`/`warn`/`unknown`, value |
| `detect_only` | the response mode |
| `degradations` | section 4, as of the boot |
| `trust_level`, `trust_reasons` | section 5, and why it is below L3 |

Read it from the running agent with `nn-admin capabilities --key <key>`
(`--json` prints `{"entry_hash": …, "manifest": {…}}`, the row's hash and
the manifest as signed). The key needs `audit-read` or `telemetry-read`:
the manifest, the trust level and the degradations are telemetry, served
by the signed status verb only (external audit ASK-009). `nn-admin status
--key` prints the trust level, its reasons and the degradations; without a
key they are withheld like the other telemetry. The status reply appends
`trust_level`, `trust_reasons`, `degradations` and `capability_manifest`
after the fields of lab PR 207 (postcard: an older `nn-admin` reads a newer
agent's reply; upgrade the agent first).

## 7. Journal lines

- `boot phase done phase=… next=… steps=…` at each phase change.
- `BPF LSM active — the deny hooks will run`, or the gate's ERROR.
- `deny self-test: a signal from an unprotected child was refused — the
  deny hooks run`, or the ERROR / WARN of the other outcomes.
- `capability manifest of this boot trust_level=… entry_hash=…`, and
  `trust level below L3` with the reasons when it is.
