# Fuzzing the agent's parsers

`cargo-fuzz` (libFuzzer) targets for every parser that consumes bytes an
attacker can shape: admin socket frames, TLS ClientHello and DNS payloads
from the kernel ring buffers, the BTF blob, tracefs `format` files, role
lists from `admin.pub` / the CLI, chain-log lines, the install manifest.
The property is always the same: **never panic** — reject or report.

```sh
cargo install cargo-fuzz --locked          # once
cargo +nightly-2025-12-01 fuzz list        # from the repository root
cargo +nightly-2025-12-01 fuzz build       # all targets, sanitizer on
# run a built binary directly (cargo fuzz run re-invokes cargo, and
# agent/build.rs re-runs whenever .git/refs changes — slow in a loop)
fuzz/target/x86_64-unknown-linux-gnu/release/tls_client_hello \
    -max_total_time=300 -max_len=8192 -artifact_prefix=fuzz/artifacts/tls_client_hello/ fuzz/corpus/tls_client_hello
```

`fuzz/corpus/<target>/` is the working corpus (not committed yet);

A crash lands in `fuzz/artifacts/<target>/`; reproduce it with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-…` and
turn the input into a regression test next to the parser. The `fuzz`
job in CI builds every target and runs each one for a short smoke
(no corpus persisted yet); longer campaigns run from a developer host.

## Formal verification (Kani)

Fuzzing samples the input space; the bounds-checking cores the two
attacker-facing parsers are built on are also *proved* with
[Kani](https://github.com/model-checking/kani) for every input of a
bounded size (`.github/workflows/kani.yml`, weekly + on demand):

| Proof | What it covers |
|---|---|
| `net::tls_parser::kani_proofs::cursor_operations_never_panic_and_keep_pos_in_bounds` | every `Cursor` read (`u8`, `u16`, `u24`, `bytes(n)` with any `n`) on any buffer ≤ 8 bytes from any position: no panic, the position never leaves the buffer — so any sequence of reads, i.e. the whole ClientHello parser, is in bounds |
| `model::kani_proofs::qname_label_walk_is_in_bounds_and_terminates` | the DNS name walk behind `decode_dns_qname` on any buffer ≤ 16 bytes: every label inside the buffer, at most `len` steps |

The first run found a real (if unreachable today) bug: the cursor's bound
check `pos + n > len` wraps for a huge `n` in a release build and passes;
it is now `n > len - pos` (saturating). Local run:

```sh
cargo install --locked kani-verifier --version 0.68.0 && cargo kani setup
cargo kani -p northnarrow-common --harness qname_label_walk_is_in_bounds_and_terminates
cargo kani -p northnarrow-agent --harness cursor_operations_never_panic_and_keep_pos_in_bounds \
    -Z unstable-options --ignore-global-asm
```

Functions that build `String`s byte by byte are out of reach for the model
checker (a 6-byte `decode_dns_qname` did not finish in 15 minutes): the
recipe is to separate the allocation-free index walk, prove that, and keep
the string building on top of it.
