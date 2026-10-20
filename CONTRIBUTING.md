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
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
```

La CI esegue gli stessi controlli su Linux x86_64. Una PR rossa non si
fonde.

- `--locked` (audit esterno SUP-016): ogni build della CI e della release
  usa il `Cargo.lock` così com'è committato. Una PR che cambia un
  `Cargo.toml` committa anche il lockfile aggiornato — `Cargo.lock`,
  `fuzz/Cargo.lock` (il fuzz harness compila l'agente) e
  `agent-ebpf/Cargo.lock` se tocca quel crate — altrimenti la CI fallisce
  con "cannot update the lock file … because --locked was passed".
  `cargo xtask` si lancia come `cargo --locked xtask build --release
  --locked`: il secondo `--locked` arriva alle build annidate.
- Toolchain (SUP-015): `rust-toolchain.toml` fissa una release di Rust
  (rustup la installa al primo `cargo`); Dependabot propone la successiva
  in una PR a sé. `rust-version` in `Cargo.toml` è la MSRV reale (oggi
  1.89, imposta da `uuid`): il job `msrv` compila con quella versione e
  `xtask/tests/supply_chain.rs` fallisce se una dipendenza del lockfile ne
  chiede una più alta. Chi aggiorna una dipendenza così alza `rust-version`
  nella stessa PR.
- Advisory RustSEC (SUP-007): il job `audit` fallisce anche sugli advisory
  `unsound` e `unmaintained`, non solo sulle vulnerabilità;
  `cargo audit --file Cargo.lock` lanciato dalla radice del repository dà
  lo stesso esito (legge `.cargo/audit.toml`). Un advisory si corregge
  (bump del lockfile) oppure si registra come eccezione in
  `.cargo/audit.toml`, con il blocco di commento descritto in testa al
  file: motivo, responsabile, evento di riesame, data e scadenza (al
  massimo 184 giorni). Mai `--ignore` sulla riga di comando. Dal giorno
  dopo la scadenza il job è rosso finché l'eccezione non viene
  riesaminata e registrata di nuovo, o tolta. Il bump di una crate di
  sicurezza (elenco in `xtask/tests/supply_chain.rs`,
  `security_crates_are_locked_alike_for_the_fuzzer`) va applicato sia a
  `Cargo.lock` sia a `fuzz/Cargo.lock`, e il job fuzz deve compilare.

## Rilasci (audit esterno SUP-024)

- Un rilascio parte solo da un tag `v*` annotato e firmato con una chiave
  SSH elencata in `.github/allowed_signers` (formato "allowed signers" di
  `ssh-keygen`, `namespaces="git"`). Il job `verify-tag` di `release.yml`
  lo controlla prima di qualsiasi build
  (`.github/scripts/verify-release-tag.sh`): un tag leggero, non firmato,
  firmato con OpenPGP o con una chiave non elencata, rinominato o che non
  punta al commit compilato si ferma lì, e non viene compilato, firmato,
  attestato né pubblicato nulla. Finché il file non elenca nessuna chiave,
  ogni tag si ferma lì: aggiungere la propria chiave pubblica è il primo
  passo del maintainer.
- Firmare e controllare un tag prima del push (con `.pub` la chiave privata
  sta nell'ssh-agent; in alternativa il percorso della chiave privata):

  ```sh
  git -c gpg.format=ssh -c user.signingkey="$HOME/.ssh/<chiave>.pub" tag -s vX.Y.Z -m "vX.Y.Z"
  git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag vX.Y.Z
  .github/scripts/verify-release-tag.sh verify vX.Y.Z "$(git rev-parse 'vX.Y.Z^{commit}')"
  ```

- Aggiungere, ruotare o revocare una chiave è una PR su
  `.github/allowed_signers`; conta la lista committata nel commit taggato.
  Ruotando, la vecchia chiave resta con `valid-before="AAAAMMGG"`, così i
  tag precedenti si verificano ancora; una chiave compromessa si toglie.
  Le firme dei commit non sono richieste.
- La pubblicazione (job `publish`, l'unico con `contents: write`) non
  sostituisce mai un asset già pubblicato: se la release ha già degli
  asset il job fallisce. Per ripubblicare, il maintainer cancella prima la
  release (`gh release delete vX.Y.Z`, il tag resta) e rilancia il job.
- Revisione obbligatoria da una seconda persona (CODEOWNERS): rinviata
  finché c'è un solo maintainer, perché GitHub non permette di approvare
  le proprie PR e bloccherebbe ogni merge.

## Stile

- 100% Rust. No C/C++ in produzione (vedi VISION_TECHNICAL.md, regola 1).
  La CI fallisce se `onig_sys` o `zstd-sys` entrano nel grafo delle
  dipendenze dell'agente (vi entravano con tokenizers e tantivy, usciti con
  il consulente LLM on-host nella Wave 4, lab PR 214).
- Niente modelli generativi nell'agente: la detection on-host resta
  deterministica (regole, correlazione, posture, COMBAT).
- `unsafe` solo dove indispensabile, isolato dietro API safe, motivato
  con un commento.
- Niente dipendenze gratuite. Ogni nuova crate va giustificata.

## Sicurezza

NorthNarrow è un prodotto di difesa. Le issue di sicurezza interne al
codice si segnalano in privato al founder, non in issue pubbliche.
