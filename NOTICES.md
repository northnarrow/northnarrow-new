# NOTICES

NorthNarrow is licensed under the Apache License, Version 2.0 (`LICENSE`).
It contains, or is built from, the third-party material below, each under
its own terms; the verbatim licence texts are in `LICENSES/`, and the
vendored crate's in its own directory. This file, `LICENSE` and `LICENSES/`
ship with every release: at the root of the tarball's tree, and in
`/usr/share/doc/northnarrow/` from a package.

## Which files are under which terms

| Material | Where it is | Terms |
|---|---|---|
| NorthNarrow's own code, configuration and documentation | everything not named below | Apache-2.0 — `LICENSE` |
| MITRE ATT&CK® content | the RAG knowledge base `cargo xtask rag-kb` builds from the pin below; the ATT&CK technique descriptions among the notes built into the agent (`agent/src/rag/kb_seed.rs`) | MITRE ATT&CK Terms of Use — `LICENSES/MITRE_ATTACK_ToU.md` |
| SigmaHQ detection rules, distilled | the RAG knowledge base `cargo xtask rag-kb` builds from the pin below | Detection Rule License 1.1 — `LICENSES/SIGMA_DRL-1.1.md` |
| candle-core 0.10.2, modified | `vendor/candle-core/`, compiled into the agent | MIT OR Apache-2.0, used under Apache-2.0 — `vendor/candle-core/LICENSE` |
| Rust crates from crates.io | compiled into `northnarrow-agent`, `northnarrow-watchdog` and `nn-admin` | each crate's own licence (below) |
| The ADE model and its tokenizer | not distributed: the operator installs them | see "Model (not distributed)" |

The knowledge base's dumps are not in the repository or in the release
artefacts: `cargo xtask rag-kb` builds them on the build or install host
from the pinned inputs below, and the agent opens only dumps whose digests
match `docs/kb-sources/kb_index.json`, which is built into it.

LOLBAS is deliberately excluded: its GPL-3.0 terms would extend to the
knowledge base distilled from it, which NorthNarrow distributes under
Apache-2.0 (plan §4.2.3). The pipeline does not fetch it, and no file of
the LOLBAS project is in the tree; the five `lolbas_*` notes of
`agent/src/rag/kb_seed.rs` are short descriptions, written for the
agent's retrieval context, of Windows binaries the LOLBAS project lists.

<!-- BEGIN rag-kb: written by `cargo xtask rag-kb` (xtask/src/rag_kb.rs); edit it there -->

## MITRE ATT&CK® (Enterprise)

- Source: https://github.com/mitre-attack/attack-stix-data
- Pin: v18.1 (commit 7ad8a86f41edc91dd37de0487b0c2f44ae3a3af7)
- License: MITRE ATT&CK Terms of Use — `LICENSES/MITRE_ATTACK_ToU.md`
- Designation (verbatim, as the Terms of Use require in every copy): "© 2025 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

## SigmaHQ detection rules (Linux subset, distilled)

- Source: https://github.com/SigmaHQ/sigma
- Pin: commit df5c6a6ecc149e05cb4dea306012668fb2ae5a12
- License: Detection Rule License (DRL) 1.1 — `LICENSES/SIGMA_DRL-1.1.md`
- Rules are distilled (modified form); per-rule `author` attribution is preserved in the canonical dump's `author` field.
- Aggregate rule authors (DRL-1.1 attribution):

  - @Joseliyo_Jstnk
  - @d4ns4n_
  - @d4ns4n_ (Wuerth-Phoenix)
  - @kostastsale
  - @signalblur
  - Aayush Gupta
  - Alejandro Ortuno
  - Andreas Braathen (mnemonic.io)
  - Andreas Hunkeler (@Karneades)
  - Andy Parkidomo
  - Arnim Rupp
  - Beyu Denis
  - Bhabesh Raj
  - Blake Hartstein (Bloomberg L.P.)
  - Cedric MAURUGEON (Update)
  - Cedric Maurugeon
  - CheraaghiMilad
  - CheraghiMilad
  - Christian Burkard (Nextron Systems)
  - Christopher Peacock @SecurePeacock
  - Daniil Yugoslavskiy
  - David Burkett
  - David Burkett (@signalblur)
  - E.M. Anhaus (originally from Atomic Blue Detections
  - Elastic (idea)
  - Florian Roth
  - Florian Roth (Nextron Systems)
  - Georg Lauenstein (sure[secure])
  - Hugh Ryan (HueCodes)
  - IAI
  - Igor Fits
  - Ilyas Ochkov
  - Jakob Weinzettl
  - Joseliyo Sanchez
  - Joseph Kamau
  - Josh Nickels
  - Li Ling
  - Luc Génaux
  - MSTIC
  - Marie Euler
  - Max Altgelt (Nextron Systems)
  - Mikhail Larin
  - Milad Cheraghi
  - Mohamed LAKRI
  - Muhammad Faisal
  - Nasreddine Bencherchali
  - Nasreddine Bencherchali (Nextron Systems)
  - Nextron Systems
  - OTR (Open Threat Research)
  - Patrick Bareiss
  - Pawel Mazur
  - Peter Matkovski
  - Qi Nan
  - Rafal Piasecki
  - Red Canary (idea)
  - Robert Rakowski
  - Roberto Rodriguez (Cyb3rWard0g)
  - SCYTHE @scythe_io
  - Seth Hanford
  - Sittikorn S
  - Sreeman
  - Swachchhanda Shrawan Poudel (Nextron Systems)
  - Swachchhanda Shrawn Poudel (Nextron Systems)
  - Teoderick Contreras
  - Thomas Patzke
  - Timur Zinniatullin
  - Tony Lambert)
  - Tuan Le (NCSGroup)
  - TuanLe (GTSC)
  - frack113
  - hasselj
  - oscd.community
  - pH-T (Nextron Systems)
  - Ömer Günal
  - Ömer Günal and remotephone

<!-- END rag-kb -->

## candle-core (vendored, modified)

- Source: https://github.com/huggingface/candle — the crates.io package
  `candle-core` 0.10.2, in `vendor/candle-core/`.
- License: MIT OR Apache-2.0 (its `Cargo.toml`). NorthNarrow uses it under
  Apache-2.0, whose text is `vendor/candle-core/LICENSE` (the same text as
  `LICENSE`).
- Modified: the lines marked `NorthNarrow` in `vendor/candle-core/Cargo.toml`,
  `src/npy.rs` and `src/pickle.rs` (`tokenizers` on `fancy-regex` instead of
  Oniguruma, `zip` 9.0.4, the deprecation warnings of its unchanged code
  allowed); the reasons are next to `[patch.crates-io]` in the workspace
  `Cargo.toml`.

## Rust crates (crates.io)

The three binaries statically link the crates `Cargo.lock` pins, each under
its own licence. The per-crate list (name, version, licence) is in the
release's CycloneDX SBOMs (`*.sbom.cdx.json`); on a checkout,
`cargo tree -e normal -p northnarrow-agent --format "{p} {l}"` (and
`-p northnarrow-watchdog`) prints it. On 2026-10-20 the licence
expressions of the crates the binaries link used only MIT, Apache-2.0
(with or without the LLVM exception), BSD-2-Clause, BSD-3-Clause, Zlib,
Unicode-3.0, Unlicense and BSL-1.0.

## Licence declarations

- `Cargo.toml` (the workspace `license`, which every member inherits),
  `agent-ebpf/Cargo.toml` and the `.rpm` (`License:`) say `Apache-2.0`, the
  licence of `LICENSE`. The expression covers NorthNarrow's own code; the
  third-party material above keeps the terms this file gives for it.
- The eBPF object declares `Dual MIT/GPL` in its `license` section
  (`agent-ebpf/src/main.rs`): the kernel loads LSM programs only when that
  section names a GPL-compatible licence, so it cannot say `Apache-2.0`.
  That declaration and the `Apache-2.0` of `agent-ebpf/Cargo.toml` do not
  say the same thing. Whether the eBPF programs are also offered under MIT
  or GPL-2.0 is a decision for the maintainer, still open.

## Model (not distributed)

The ADE's model and its tokenizer are not in this repository or in any
release artefact. The operator installs them (`docs/ADE_BACKEND_NOTES.md`,
"Model files"); without them the agent runs on its rules alone.

- Model: Foundation-Sec-8B-Reasoning, Q4_K_M GGUF
  (`foundation-sec-8b-reasoning-q4_k_m.gguf`), from
  https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF.
  Tokenizer: the `tokenizer.json` (Llama 3.1 BPE) of
  https://huggingface.co/fdtn-ai/Foundation-Sec-8B-Reasoning.
- Pin: none — the agent does not check the model's digest. Revisions read
  on 2026-10-20: `4a04f7b19513ff9f672169b8fe4288000ab87b07` (the GGUF
  repository), `63c930c82d7646226d33502bec5870019738400e` (the model's,
  with its `NOTICE.md`).
- Lineage: a fine-tune of fdtn-ai/Foundation-Sec-8B (`apache-2.0` in its
  metadata), which is built on meta-llama/Llama-3.1-8B.
- Licence, as determined on 2026-10-20 from those repositories (a record,
  not a legal opinion): both declare `license: other`. The model's
  `NOTICE.md` reads "Llama 3.1 is licensed under the Llama 3.1 Community
  License, Copyright © Meta Platforms, Inc. All Rights Reserved." and
  "Cisco changes to the Llama-3.1-FoundationAI-SecurityLLM-base-8B is
  licensed under the Apache 2.0 License, Copyright Cisco Systems, Inc." The
  Llama 3.1 part is under the Llama 3.1 Community License and its
  Acceptable Use Policy, Cisco's changes under Apache-2.0.
- What the operator takes on: whoever downloads and runs the model accepts
  those terms, the Acceptable Use Policy included. Whoever passes the model
  on (in a host image, on a mirror) also takes on the redistribution terms
  of the Llama 3.1 Community License: a copy of the agreement with it, the
  Llama notice line above in a "Notice" text file, "Built with Llama"
  displayed. The NorthNarrow release does not pass the model on.
