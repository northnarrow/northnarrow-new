# Fuzzing the agent's parsers

`cargo-fuzz` (libFuzzer) targets for every parser that consumes bytes an
attacker can shape: admin socket frames, TLS ClientHello and DNS payloads
from the kernel ring buffers, the BTF blob, tracefs `format` files, role
lists from `admin.pub` / the CLI, chain-log lines, the install manifest,
the COMBAT management carve-out (`combat-allow.cidrs` spliced into
`combat-rules`), the operator canary templates and the watchdog's
shutdown marker. (The `ade_verdict` and `ade_preparse` targets, the LLM
advisor's output and its pre-parser, left with the advisor in Wave 4, lab
PR 214.) The base property is
always **never panic** — reject or report. Each target also asserts what
its parser promises, so a wrong answer fails as a crash does (external
audit WDG-R04 to WDG-R08, WDG-014):

| Target | Asserted beyond "no panic" |
|---|---|
| `admin_frame` | a decoded frame consumed exactly its length prefix and speaks a known version; the message re-encodes and decodes to itself (v1 envelope and v0 body) |
| `tls_client_hello` | on every accepted hello, JA3's input has five fields with one value per non-GREASE cipher and extension, JA3 is 32 hex digits, JA4 is a 10-character prefix and two 12-hex hashes; a record-wrapped hello parses as its handshake |
| `dns_records` | parsed answers fit in the packet; `decode_dns_qname` is printable ASCII, ends with `…` only at a compression pointer, and reads back as the wire labels byte for byte (distinct names never decode alike, NN-AUD-185); `qname_wire_end` ends just past a root label |
| `btf_parse` | an accepted blob carries the BTF magic and its whole header |
| `tracefs_format` | an offset comes from a `field:` line that names the field and writes it |
| `role_list` | a parsed list is non-empty, without duplicates, the roles of its keywords; a keyword is the one-role list of itself |
| `chainlog_line` | a terminator hash comes only from a JSON object carrying `rotate`, and is its `entry_hash` |
| `install_manifest` | against a fixed fixture directory every parsed manifest reaches the hash comparison; `Verified` exactly when every name is one of those install.sh records (`RECORDED_NAMES`) and its hash matches, an unknown name refused without being opened |
| `combat_allow` | every generated `iptables-restore` line is exactly `-A NORTHNARROW_COMBAT -s\|-d <validated address> -j ACCEPT`, two per entry of the block's family, none wider than /8 (IPv4) or /48 (IPv6), unspecified or multicast; the splice keeps every line of the operator's base ruleset |
| `canary_template` | a rendered canary keeps no `{{`, a JSON family's is JSON, the same body renders the same |
| `shutdown_marker` | a marker honoured against the fixture carries a shutdown the fixture keys signed (the fuzzer cannot sign: anything else is a forgery accepted), names the agent that exited, has at most the signature cap, two signers including the `shutdown` key, a capped grace, and is refused as a replay once honoured |

`install_manifest` and
`shutdown_marker` check against fixtures in `agent/src/fuzz_api.rs`
(three fixture binaries; three admin keys whose private halves are the
test seeds `[1; 32]`, `[2; 32]`, `[3; 32]`). `install_manifest` and
`canary_template` write only into one private directory per process
(`fuzz_targets/scratch.rs`: `tempfile`, files created exclusively, removed
at exit — WDG-R09).

## Committed inputs

- `fuzz/seeds/<target>/` — valid inputs, at least one per target, made to
  reach what the target asserts (a CIDR that validates, a template per
  family, a marker the fixture admins signed, a manifest that verifies).
- `fuzz/regressions/<target>/` — inputs of fixed bugs, each named by its
  finding; with the fix reverted, the target fails on it:
  `install_manifest` (WDG-R05: a relative alias of the agent, `/dev/zero`,
  which hung the check), `combat_allow` (NN-AUD-095: wide, unspecified,
  multicast entries), `canary_template` (DEC-017: an unclosed
  placeholder), `dns_records` (NN-AUD-185: a dot inside a label), `shutdown_marker`
  (AUT-005: nine signatures; AUT-011, declined on ciborium's recursion
  limit: a payload nested 10,000 deep).
- `fuzz/corpus/<target>/` — the working corpus, not committed: libFuzzer
  writes new inputs into the first directory it is given, so always put
  the corpus first and the seeds after it.

`cargo test -p northnarrow-agent --lib fuzz_api` checks that the seeds
reach the asserted paths and that the generated ones (admin frames,
install manifests, shutdown markers) are current; after a format change,
`NN_BLESS_FUZZ_SEEDS=1 cargo test -p northnarrow-agent --lib fuzz_api`
rewrites them. `xtask/tests/supply_chain.rs` checks that every target has
seeds and that CI replays them.

A crash lands in `fuzz/artifacts/<target>/`; reproduce it with
`cargo +nightly-2025-12-01 fuzz run <target> fuzz/artifacts/<target>/crash-…`,
fix it, add the input to `fuzz/regressions/<target>/` under the finding's
name and a deterministic unit test next to the parser.

```sh
cargo install cargo-fuzz --version 0.13.2 --locked   # once
cargo +nightly-2025-12-01 fuzz list                  # from the repository root
cargo +nightly-2025-12-01 fuzz build                 # all targets, sanitizer on
# run a built binary directly (cargo fuzz run re-invokes cargo, and
# agent/build.rs re-runs whenever .git/refs changes — slow in a loop)
b=fuzz/target/x86_64-unknown-linux-gnu/release
$b/install_manifest -runs=0 -timeout=25 fuzz/seeds/install_manifest fuzz/regressions/install_manifest
$b/tls_client_hello -max_total_time=300 -max_len=8192 -timeout=25 \
    -artifact_prefix=fuzz/artifacts/tls_client_hello/ \
    fuzz/corpus/tls_client_hello fuzz/seeds/tls_client_hello
```

The `fuzz` job in CI (every pull request) builds every target, replays
the seeds and the regressions of each with `-runs=0` (a failure or a hang
past 25 s fails the job), then runs each target for 20 s from the corpus
cached by the previous run and the seeds; longer campaigns run from a
developer host.

## Formal verification (Kani)

Fuzzing samples the input space; the bounds-checking cores the two
attacker-facing parsers are built on are also *proved* with
[Kani](https://github.com/model-checking/kani) for every input of a
bounded size (`.github/workflows/kani.yml`: weekly, on demand, and on every
pull request that touches a proved file — external audit SUP-023):

| Proof | What it covers |
|---|---|
| `net::tls_parser::kani_proofs::cursor_operations_never_panic_and_keep_pos_in_bounds` | every `Cursor` read (`u8`, `u16`, `u24`, `bytes(n)` with any `n`) on any buffer ≤ 8 bytes from any position: no panic, the position never leaves the buffer — so any sequence of reads, i.e. the whole ClientHello parser, is in bounds |
| `dns_qname::kani_proofs::qname_label_walk_is_in_bounds_and_terminates` | the DNS name walk behind `decode_dns_qname` on any buffer ≤ 16 bytes: every label inside the buffer, at most `len` steps |
| `dns_qname::kani_proofs::qname_wire_end_is_past_a_root_label` | the end of a name `qname_wire_end` reports, on any buffer ≤ 16 bytes: inside the buffer, just past a root label |
| `admin_quorum::kani_proofs::quorum_accepts_only_enough_distinct_keys_carrying_every_role` | the admin multi-signature rule behind `verify_quorum` and `verify_signed_payload_quorum`, with the signature checks abstracted (any key or none per signature, any role set per key; up to 4 signatures, 3 keys, 2 roles, any threshold): it accepts only when at least `max(threshold, 1)` **distinct** keys matched and every required role is carried by one of them, and each refusal reports the truth |

The pull-request filter names the files that hold proofs
(`agent/src/net/tls_parser.rs`, `common/src/dns_qname.rs`,
`common/src/admin_quorum.rs`) and the workflow;
`xtask/tests/supply_chain.rs` keeps it equal to the files with a
`#[kani::proof]` and checks that the workflow runs every harness. The DNS
walk moved out of the event model (`common/src/model.rs`), which changes
often, so that its edits do not start the proofs.

Separating the quorum rule from the cryptography also closed a release-build
gap: a threshold of 0 was rejected only by a `debug_assert`, so a caller
passing 0 would have minted a token with no signature; the rule now uses
`max(threshold, 1)`. No caller passes 0 today.

The first run found a real (if unreachable today) bug: the cursor's bound
check `pos + n > len` wraps for a huge `n` in a release build and passes;
it is now `n > len - pos` (saturating). Local run:

```sh
cargo install --locked kani-verifier --version 0.68.0 && cargo kani setup
cargo kani -p northnarrow-common --harness qname_label_walk_is_in_bounds_and_terminates
cargo kani -p northnarrow-common --harness qname_wire_end_is_past_a_root_label
cargo kani -p northnarrow-agent --harness cursor_operations_never_panic_and_keep_pos_in_bounds \
    -Z unstable-options --ignore-global-asm
```

Functions that build `String`s byte by byte are out of reach for the model
checker (a 6-byte `decode_dns_qname` did not finish in 15 minutes): the
recipe is to separate the allocation-free index walk, prove that, and keep
the string building on top of it — the fuzz target `dns_records` checks the
string building on top of the walk (it reads back as the labels).
