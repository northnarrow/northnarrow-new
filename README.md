# NorthNarrow

XDR ipercompetitivo Linux-first, 100% Rust nativo, superiore a CrowdStrike.

- Visione: [VISION.md](VISION.md)
- Roadmap eseguibile: [ROADMAP.md](ROADMAP.md)
- Stella polare tecnica: [VISION_TECHNICAL.md](VISION_TECHNICAL.md)
- Come contribuire: [CONTRIBUTING.md](CONTRIBUTING.md)

## Status

**Tappa 0 — Fondamenta del repo.** Workspace Rust pronto, niente sensori
ancora. La Tappa 1 (sensore eBPF Rust via Aya) è la prossima.

## Building

Linux x86_64, Rust stable (rust-toolchain.toml lo pinna in automatico).

```sh
cargo build --release
cargo test --workspace
```

Binari prodotti:

- `target/release/northnarrow-agent` — daemon (skeleton).
- `target/release/northnarrow` — CLI di controllo (subcommand stub).

## Workspace

- `agent/` — daemon: sensori, decision engine, response executor.
- `common/` — tipi condivisi (Event, Verdict, ResponseAction, ...).
- `cli/` — CLI di controllo locale.

## Operator documentation

- [Anti-tamper honeypots (NN-L-FIM-024)](docs/operator/anti-tamper-honeypots.md)
  — inert bait files that mimic agent control points; tampering triggers
  Critical + COMBAT. **Read before touching `/etc/northnarrow/`,
  `/var/lib/northnarrow/`, or `/run/northnarrow/`.**
- [FIM trust model](docs/operator/TAPPA9_FIM_TRUST_MODEL.md)

## Licenza

Apache-2.0. Vedi [LICENSE](LICENSE).
