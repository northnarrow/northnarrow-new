# Contribuire a NorthNarrow

## Regola d'oro

Prima di qualunque cosa, leggi:

1. [VISION.md](VISION.md) — il contratto. Definisce cos'è NorthNarrow,
   cos'è la sua autonomia di difesa, e cos'è la riattivazione
   supervisionata. Non si negozia.
2. [ROADMAP.md](ROADMAP.md) — la marcia operativa. Tappe in ordine
   fisso, una alla volta. Non si salta. Non si torna indietro. Mai.
3. [VISION_TECHNICAL.md](VISION_TECHNICAL.md) — la stella polare
   tecnica di lungo termine. Le feature qui dentro entrano in roadmap
   solo quando le condizioni lo permettono.

## Una tappa alla volta

Ogni PR appartiene alla tappa corrente di ROADMAP.md. PR che provano a
correre avanti (es. iniziare Tappa 4 mentre la 3 non è chiusa) vengono
rifiutate. Eccezioni richiedono una modifica esplicita di ROADMAP.md
firmata dal founder.

Se uno strumento (Claude, Copilot, qualsiasi tool) suggerisce di
saltare una tappa o di ridimensionare la visione, ha torto lo
strumento.

## Quality gates locali

Prima di aprire una PR, sul tuo branch:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo build --workspace
cargo test --workspace
```

La CI esegue gli stessi controlli su Linux x86_64. Una PR rossa non si
fonde.

## Stile

- 100% Rust. No C/C++ in produzione (vedi VISION_TECHNICAL.md, regola 1).
- `unsafe` solo dove indispensabile, isolato dietro API safe, motivato
  con un commento.
- Niente dipendenze gratuite. Ogni nuova crate va giustificata.

## Sicurezza

NorthNarrow è un prodotto di difesa. Le issue di sicurezza interne al
codice si segnalano in privato al founder, non in issue pubbliche.
