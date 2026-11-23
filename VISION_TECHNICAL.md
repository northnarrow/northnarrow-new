# NorthNarrow — Long-term technical vision

> This document describes where NorthNarrow is going. For what it does
> today, see [README.md](README.md) and
> [docs/operator/KNOWN_LIMITATIONS.md](docs/operator/KNOWN_LIMITATIONS.md).

This is not a roadmap to execute. It is the north star: the mature product
we are aiming for, kept as a reference and an ambition. Nothing on this
page is a claim about the current release. A few items have a first form in
the Linux agent today (the Ed25519-signed release of COMBAT, for one), and
[CAPABILITY_PROGRAM.md](docs/roadmap/CAPABILITY_PROGRAM.md) tracks what is
real. Features move into ROADMAP.md one Tappa (stage) at a time, when the
technology and the resources allow it. The agent runs on Linux today; the
Windows items below are later goals, like macOS.

The 7 milestones of architecture v3:

---

## Milestone 1: The fortress (Ring -1, hardware isolation, telemetry)

- A Rust micro-hypervisor (Ring -1): a Type-1.5 hypervisor in pure Rust
  that uses EPT to keep the defence standing against EDR bypasses and
  advanced rootkits, even with SYSTEM/root privileges.
- A Windows kernel driver: a blocklist of vulnerable drivers (BYOVD) and
  ELAM integration.
- A Linux kernel sensor with anti-DMA: IOMMU enforcement against DMA
  attacks (PCILeech, Thunderbolt).
- Network interception (WFP/XDP and eBPF uprobes): seeing TLS traffic
  before it is encrypted (libssl, bcrypt).
- Post-quantum cryptography (Kyber/Dilithium) against "harvest now,
  decrypt later".

## Milestone 2: Nervous system and hardware CFI

- Tokio and lock-free crossbeam.
- Hardware-assisted control-flow integrity (Intel CET, ARM BTI, shadow
  stacks), to stop ROP/JOP at the CPU level.
- Aho-Corasick multi-pattern matching against worms.
- JA4 fingerprinting, to recognise malicious clients from the TLS
  handshake.

## Milestone 3: Covert channels

Since October 2026 there is no AI on the host, so the on-host LLM items
once planned here (Candle inference, a quantised model, prompt hardening)
are dropped; an assistant, if there is one, stays outside enforcement.
What remains:

- Detection of steganography and covert channels: ICMP tunnelling, DNS TXT
  exfiltration, LSB image steganography.

## Milestone 4: Response and micro-segmentation

- A response chain anchored in Ring 0 and Ring -1.
- Dynamic micro-segmentation: process-to-process isolation through
  WFP/eBPF, localhost and IPC included.
- AES-256-GCM quarantine.

## Milestone 5: Cryptographic seal and UEFI integrity

- Ed25519 challenge-response.
- TPM PCR measurements and UEFI bootkit detection (BlackLotus, for
  example).
- A hardened initramfs, for isolation from boot.

## Milestone 6: Proactive scout and deception

- Continuous edge monitoring.
- Virtual patching against supply-chain risk: eBPF/WFP rules added on the
  fly for unpatched CVEs.
- Local honeypots (decoy LSASS credentials, decoy registry keys) that
  reveal lateral movement.

## Milestone 7: Command centre

- A native Rust UI (Iced, Slint or Yew).
- Post-quantum mTLS (rustls and Kyber).
- An Axum central console, fleet management and the key vault.

---

## Architectural rules

These are the principles the code is held to, now and as it grows.

1. No C/C++ in production. A dependency with a C backend is replaced with
   a pure Rust alternative when one exists.
2. `unsafe` stays isolated: minimal blocks, documented, wrapped in a safe
   API.
3. No dynamic allocation in kernel hot paths.
4. Formal verification of the kernel-side modules (a long-term goal).
5. Assume root/SYSTEM is compromised. The defence rests on kernel
   enforcement and cryptographic signatures, and later on hypervisor
   isolation, not on OS permissions.

---

## When do these features come in?

The features in this document enter ROADMAP.md when:

- the base technology is production-ready (for example, windows-drivers-rs
  leaves preview);
- the founder has the resources (time, maybe a team) to take them on;
- the threat landscape calls for it commercially;
- beta testers ask for the specific feature.

They are never promised to customers until they are in the roadmap to
execute, and never started before the ROADMAP.md Tappe that come before
them.
