# Triage della ricerca esterna dell'11 ottobre 2026

Fonte: `northnarrow_repo_audit_frontier_and_defence.md` (founder, 11 ottobre
2026) — Parte A (gap rispetto allo stato dell'arte), Parte B (verifica del
repository al commit `86ee590`), Parte 4 (standard militari e governativi).
Ogni voce è stata confrontata con il codice di `main` dopo le PR #197 e #198;
dove la ricerca dice «non verificato» la verifica è stata fatta in lab
(ubuntu 24.04 / 6.8) e il risultato è riportato.

Legenda: **fatto** = già nel codice; **applicato** = fatto nella PR del test
avversariale (Tappa 10.8); **roadmap** = aggiunto alla Tappa indicata in
questa PR, senza cambiare l'ordine delle Tappe; **da collocare** = proposta
per il founder; **no** = non applicare, con il motivo.

## 1. Già fatto (la ricerca era indietro rispetto al codice)

| Voce della ricerca | Stato | Dove |
|---|---|---|
| Sensore io_uring | fatto | `agent-ebpf/src/io_uring.rs`, regole IOU-001/002 |
| Osservatore `bpf()` e guardia `bpf_map` | fatto | PR #194 |
| Protezione di link, detach e pin BPF | fatto | PR #197 (rilievo 39) |
| Sonda di telemetria («hook che falliscono in silenzio», Datadog 2026) | fatto | PR #198 |
| `/proc/<pid>/mem` dei pid protetti | fatto | negato dall'hook `ptrace_access_check` (`mm_access` passa da lì); verificato in lab |
| L'LLM non può abbassare un verdetto deterministico | fatto per costruzione | l'ADE gira solo se nessuna regola ha prodotto un verdetto (`main.rs`, «no rule matched, escalating to ADE») |
| JA4 | fatto a metà | calcolato in `net/tls_parser.rs`, nessuna regola lo usa → roadmap 10.9 |
| exec da memfd, PAM, `ld.so.preload` | fatto | R004, FIM-021, FIM-022 |
| Hash di binari e oggetto eBPF all'avvio, SLSA all'install | fatto | PR #187 |

## 2. Applicato ora (Tappa 10.8, test avversariale dell'anti-tamper)

Il check `nn-lab.sh tamper-check` (20 casi, esito + evidenza nei chain log
firmati) ha confermato in lab i punti SQ4 della ricerca e ne ha trovati altri.

| Voce | Cosa cambia |
|---|---|
| SQ4.5 / autodifesa BPF | **bug** della PR #197: `OWN_BPF_IDS` indicizzata solo per id, mappe, programmi e link con lo stesso numero si sovrascrivevano (66 registrazioni, 48 voci) → chiave `(tipo, id)` |
| kill/ptrace negati senza traccia | `FS_OP_SIGNAL` / `FS_OP_PTRACE` sul ring anti-tamper (ptrace solo in modalità ATTACH, dedup per chiamante e tetto globale nel kernel); regola NN-L-AT-001: ogni denial diventa una detection firmata |
| SQ4.2 `systemctl set-property`, drop-in, mask/override | controllo di integrità ogni 30 s ±20 %: drop-in inattesi delle due unit (anche `system.control` e `service.d`), limiti della cgroup (`memory.max`, `pids.max`, `cpu.max`), audit `integrity_drift` |
| Parte B 1.4.6 `OOMScoreAdjust` | `-500` agent, `-900` watchdog; `oom_score_adj` alzato da root → `integrity_drift` (il valore lo può cambiare solo root, quindi si prova, non si impedisce) |
| SQ4 bind mount, secondo bpffs (Non ancora fatto) | mount sopra `/etc/northnarrow`, stato, pin, binari e unit, bpffs fuori da `/sys/fs/bpf` → `integrity_drift` (vista dell'host, `/proc/1/mountinfo`) |
| cgroup freezer | l'agent congelato non può accorgersene mentre lo è: lo stallo viene registrato al risveglio (`agent_stalled`) |
| SQ4.4 saturazione / perdita di visibilità | ogni ring che perde eventi → voce di audit `ringbuf_drop` (una per ring ogni 10 min) |
| M4.3 Unpredictability (NIST 800-160v2) | jitter ±20 % su sonda di telemetria, self-check dei link e controllo di integrità |
| (nuovo, dal check) overlay `.local` | un `process-comm-allowlist.local` in `/etc/northnarrow` esenta un comm al riavvio successivo senza autenticazione: ora è riportato con hash; la versione firmata va in roadmap |
| variabili d'ambiente che indeboliscono | `NN_ANTI_TAMPER_ALLOW_DEGRADED`, `NN_BPF_DEFENSE_OBSERVE`, `NN_TELEMETRY_PROBE_SECS=0`, … → `integrity_drift` al boot |

## 3. Aggiunto alla roadmap (questa PR)

**Tappa 10.7** — PANIX (persistenza) e FENIX (fileless) di Elastic come suite
di regressione accanto ad Atomic Red Team.

**Tappa 10.8**
- Kani dopo il fuzzing: harness sui blocchi `unsafe`, sui parser binari e
  sulla verifica di firme e quorum (HACMS / s2n-quic).
- Overlay `.local` solo via `nn-admin` firmato.
- Restano nel test avversariale: `cgroup.kill`, kexec/modulo non firmato con
  `lockdown` attivo, saturazione avversa del ring (il soak prova la
  capacità, non la resistenza).

**Tappa 10.9**
- **Punto di aggancio dei sensori** (Phantom TOCTOU, Guo/Zeng; io_uring,
  ARMO 2025): `sys_enter_openat` → LSM `file_open`; QNAME DNS letto dopo la
  copia nel kernel, non dall'iov utente all'ingresso di `udp_sendmsg`;
  `sys_enter_execve` → LSM `bprm_check_security` con deny opzionale. Il
  limite di toolchain scritto in `exec_check.rs` non vale più: l'agent
  attacca già più di venti programmi LSM con la stessa toolchain.
- Exec per proprietà dell'inode (tmpfs, memfd, `O_TMPFILE`, `nlink == 0`,
  `execveat(AT_EMPTY_PATH)`, loader dinamico come argv[0]) e identità per
  hash calcolato nel kernel (`bpf_ima_file_hash`, dove IMA è attivo).
- Ecosistema BPF, seconda fase: hook `bpf_prog`, helper rari al caricamento
  (`bpf_probe_write_user`, `bpf_override_return`, `bpf_send_signal`; Datadog
  2026, LinkPro, VoidLink), attach XDP/TC.
- Integrità del kernel: `init_module` da buffer distinto da
  `finit_module`, syscall table / ftrace / moduli nascosti, credenziali
  cambiate senza setuid legittimo (copia ombra alla LKRG), viste incrociate
  per processi e socket nascosti.
- JA4 nella blocklist accanto a JA3.
- Enforcement inline (LSM `-EPERM`) per un sottoinsieme deterministico:
  exec da tmpfs/memfd, lettura di credenziali da binari fuori allowlist,
  connect verso blocklist. L'LLM e la scala di posture restano in userland.

**Tappa (ex 10) Scout** — base dei controlli ANSSI-BP-028 v2.0 (SCAP /
ComplianceAsCode, Licence Ouverte 2.0) con il livello raggiunto; profilo
«appliance» opzionale con IPE + dm-verity (6.12+).

## 4. Da collocare (decisione del founder)

| Proposta | Perché conta | Nota |
|---|---|---|
| Separazione dei processi (parser di rete/DNS/TLS e ADE separati da decisione e chiavi) + Landlock (ABI 6, scope sui segnali) + seccomp | un parser compromesso oggi ha tutte le capability dell'agent | «seismic retrofit» HACMS; lavoro grande, tocca l'architettura |
| `mseal` su chiavi admin e tabelle di policy | integrità in memoria | 6.10+, utile solo dopo la separazione |
| Crypto-agility: campo algoritmo in chiavi admin, audit chain, manifest; LMS o ML-DSA-87 per release e manifest; SHA-384 | NIAP PP-EDR chiede RSA/ECDSA FIPS 186-4; CNSA 2.0 dal 2027 per i sistemi USA | firme ML-DSA ~4,6 KB: firma per lotto nel chain log |
| ID MITRE D3FEND su regole e azioni, analisi di copertura | audit, procurement, vocabolario XAI | Restore oggi scoperto |
| Ripristino automatico dei file protetti dalla baseline firmata | Restore / Non-persistence (NIST 800-160v2) | |
| Verdetto locale firmato di salute dell'host (sensori, drop, hash, hardening) | ponte verso Zero Trust e console di flotta | |
| Grafo di provenienza per delimitare l'incidente, taint in xattr | spiegazione e kill-tree mirato | non come detector GNN in linea (immaturo per gli stessi autori) |
| Benchmark di prompt injection sull'ADE con il modello reale (payload frammentati) + CyberSOCEval | i campi di log sono scritti dall'attaccante | preprint 2026, non peer-reviewed |
| Percorso di certificazione: EUCC, e per l'Italia ACN / Perimetro / CVCN; Security Target modellata sul NIAP PP-EDR; tag SWID | mercato PA e infrastrutture regolate UE | la ricerca segnala l'Italia come lacuna: serve una ricerca dedicata |
| Inventario di `unsafe` e dipendenze C (sotto Candle) | richiesto dalla guida NSA/CISA 2025 | piccolo, utile per la Security Target |
| MITRE Engage: narrativa delle esche, fase di osservazione prima di neutralizzare, regole di ingaggio firmate | inganno come processo | si innesta su INVESTIGATE → NEUTRALIZE |
| CRS AIxCC (es. Buttercup) in CI settimanale | ricerca automatica di bug | valutati su C/Java, non su Rust/eBPF |

## 5. Non applicare, o con cautela

- **SIGKILL inline con `bpf_send_signal` / `bpf_override_return`**: il
  primitivo giusto per bloccare è l'LSM che restituisce `-EPERM`, già in uso;
  `bpf_override_return` richiede `CONFIG_BPF_KPROBE_OVERRIDE` e funzioni in
  allowlist di error injection, e un kill nel kernel su un falso positivo è
  irreversibile.
- **Deny di io_uring per i processi fuori allowlist**: io_uring è usato da
  runtime moderni (database, proxy); al massimo opzionale e spento di default.
- **Hornet / firma dei programmi BPF upstream**: schema conteso tra i
  maintainer LSM e BPF; da riconsiderare quando arriva mainline.
- **Detector GNN di provenienza in linea**: gli stessi autori (USENIX 2025)
  avvertono che il tempo reale non scala.
