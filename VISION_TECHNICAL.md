# NorthNarrow — Long-term technical vision

> This document is NOT a roadmap to execute. It is the north star.
> It describes the final, fully mature product: the absolute fortress.
> Its features are brought into ROADMAP.md one Tappa (stage) at a time,
> when the technical conditions and the resources allow it.

The 7 milestones of the architectural v3, kept as a reference and an
ambition.

---

## Milestone 1: The Fortress (Ring -1, Hardware Isolation, Telemetry)

- Rust Micro-Hypervisor (Ring -1): a Type-1.5 hypervisor in pure Rust.
  Against EDR bypasses and advanced rootkits, even with SYSTEM/root
  privileges, through EPT.
- Windows Kernel Driver + BYOVD Annihilation: a blocklist of vulnerable
  drivers, ELAM integration.
- Linux Kernel Sensor + Anti-DMA: IOMMU enforcement against PCILeech and
  Thunderbolt attacks.
- Network Interception WFP/XDP + eBPF Uprobes: reading encrypted traffic
  before encryption (libssl, bcrypt).
- Post-Quantum Cryptography: Kyber/Dilithium against
  "Harvest Now, Decrypt Later".

## Milestone 2: Nervous System + Hardware CFI

- Tokio + lock-free crossbeam.
- Hardware-Assisted Control Flow Integrity: Intel CET, ARM BTI,
  Shadow Stacks. Blocks zero-day ROP/JOP at the CPU level.
- Aho-Corasick O(1) anti-worm matching.
- JA4 fingerprinting: identifies malicious clients from the TLS handshake.

## Milestone 3: Cerebral Cortex + Anti-Steganography

> Historical: the on-host LLM advisor was removed in Wave 4, lab PR 214
> (the three LLM items below; the detection of steganography and covert
> channels remains).

- Native Rust Candle for LLM inference.
- Quantised anti-distillation LLM.
- Contextual anti-PromptFlux prompting.
- Detection of steganography/covert channels: ICMP tunneling,
  DNS TXT exfiltration, LSB image steganography.

## Milestone 4: Executioner + Micro-Segmentation

- Ring -1/Ring 0 kill chain.
- Dynamic micro-segmentation: process-to-process isolation through
  WFP/eBPF, also on localhost/IPC.
- AES-256-GCM quarantine.

## Milestone 5: Cryptographic Seal + UEFI Integrity

- Ed25519 challenge-response.
- TPM PCR measurements + UEFI bootkit detection (for example BlackLotus).
- Hardened initramfs for isolation at boot.

## Milestone 6: Proactive Scout + Deception

- Continuous edge monitoring.
- Anti-supply-chain virtual patching: eBPF/WFP rules injected on the fly
  for unpatched CVEs.
- Local honeypots: fake LSASS credentials, fake registry keys.
  Invisible lateral movement detection.

## Milestone 7: Command Centre

- Iced/Slint/Yew native Rust UI.
- Post-quantum mTLS (rustls + Kyber).
- Axum central console + fleet + Key Vault.

---

## Absolute architectural rules

1. No C/C++ in production. Every dependency with a C backend is replaced
   with a pure Rust alternative when possible.
2. `unsafe` isolation. Minimal `unsafe` blocks, documented, wrapped in a
   safe API.
3. Zero dynamic allocations in kernel hot paths.
4. Formal verification of the Ring 0 modules (long-term goal).
5. Military-grade paranoia: assume root/SYSTEM is compromised.
   The defence relies on Kernel/Hypervisor isolation + cryptographic
   signatures, not on OS permissions.

---

## When to bring these features in?

The features in this document enter ROADMAP.md when:

- The base technology is production-ready (for example, windows-drivers-rs
  leaves preview)
- The founder has the resources (time, maybe a team) to take them on
- The threat landscape requires it commercially
- Beta testers ask for the specific feature

They are never promised to customers until they are in the roadmap to
execute.
They are never started before the ROADMAP.md Tappe that come before them.
