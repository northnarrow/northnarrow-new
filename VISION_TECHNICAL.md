# NorthNarrow — Visione tecnica di lungo termine

> Questo documento NON è una roadmap eseguibile. È la stella polare.
> Descrive il prodotto finale completamente maturo: la fortezza assoluta.
> Le feature qui dentro vengono integrate nella ROADMAP.md tappa per
> tappa, quando le condizioni tecniche e di risorse lo permettono.

Le 7 milestone della v3 architetturale, conservate come riferimento
e ambizione.

---

## Milestone 1: La Fortezza (Ring -1, Hardware Isolation, Telemetria)

- Rust Micro-Hypervisor (Ring -1): hypervisor Type-1.5 in Rust puro.
  Bypass EDR e rootkit avanzati anche con privilegi SYSTEM/root via EPT.
- Windows Kernel Driver + BYOVD Annihilation: blocklist driver
  vulnerabili, integrazione ELAM.
- Linux Kernel Sensor + Anti-DMA: IOMMU enforcement contro PCILeech,
  Thunderbolt attacks.
- Network Interception WFP/XDP + eBPF Uprobes: lettura traffico
  cifrato pre-encryption (libssl, bcrypt).
- Crittografia Post-Quantistica: Kyber/Dilithium contro
  "Harvest Now, Decrypt Later".

## Milestone 2: Sistema Nervoso + Hardware CFI

- Tokio + crossbeam lock-free.
- Hardware-Assisted Control Flow Integrity: Intel CET, ARM BTI,
  Shadow Stacks. Blocca ROP/JOP zero-day a livello CPU.
- Aho-Corasick O(1) anti-worm matching.
- JA4 fingerprinting: identifica client malevoli dall'handshake TLS.

## Milestone 3: Corteccia Cerebrale + Anti-Steganografia

- Candle nativo Rust per inferenza LLM.
- LLM quantizzato anti-distillation.
- Prompting contestuale anti-PromptFlux.
- Rilevamento steganografia/covert channels: ICMP tunneling,
  DNS TXT exfiltration, LSB image steganography.

## Milestone 4: Carnefice + Micro-Segmentazione

- Kill chain Ring -1/Ring 0.
- Micro-segmentazione dinamica: isolamento process-to-process via
  WFP/eBPF, anche su localhost/IPC.
- Quarantena AES-256-GCM.

## Milestone 5: Sigillo Crittografico + UEFI Integrity

- Ed25519 challenge-response.
- TPM PCR measurements + UEFI bootkit detection (es. BlackLotus).
- Initramfs hardened per isolamento at-boot.

## Milestone 6: Scout Proattivo + Deception

- Edge monitoring continuo.
- Patching virtuale anti-supply-chain: regole eBPF/WFP iniettate
  al volo per CVE non patchate.
- Honeypot locali: finte credenziali LSASS, finte chiavi registro.
  Lateral movement detection invisibile.

## Milestone 7: Centro di Comando

- Iced/Slint/Yew UI nativa Rust.
- mTLS post-quantistico (rustls + Kyber).
- Console centrale Axum + flotta + Key Vault.

---

## Regole architetturali assolute

1. No C/C++ in produzione. Ogni dipendenza con backend C va
   sostituita con alternativa Rust pura quando possibile.
2. Isolamento unsafe. Blocchi unsafe minimali, documentati,
   incapsulati in API safe.
3. Zero allocazioni dinamiche nei kernel hot paths.
4. Verifica formale dei moduli Ring 0 (long-term goal).
5. Paranoia di grado militare: assumi root/SYSTEM compromesso.
   La difesa si basa su isolamento Kernel/Hypervisor + firme
   crittografiche, non su permessi OS.

---

## Quando integrare queste feature?

Le feature di questo documento entrano nella ROADMAP.md quando:

- La tecnologia di base è production-ready (es. windows-drivers-rs
  esce da preview)
- Il founder ha le risorse (tempo, eventualmente team) per affrontarle
- Il threat landscape lo richiede commercialmente
- Beta tester chiedono la feature specifica

Mai vengono promesse a clienti finché non sono in roadmap eseguibile.
Mai vengono iniziate prima delle tappe di ROADMAP.md che le precedono.
