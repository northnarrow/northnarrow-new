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
