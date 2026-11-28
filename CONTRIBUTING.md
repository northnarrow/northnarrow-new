# Contributing to NorthNarrow

## Your first contribution (no Rust needed)

Welcome! If you arrived from [Up For Grabs](https://up-for-grabs.net) or the
[`good first issue`](https://github.com/northnarrow/northnarrow-new/labels/good%20first%20issue)
label, this section is for you. The rest of this file is about code changes. You can skip it for now.

**What you can do today, with no programming:**

- [#603](https://github.com/northnarrow/northnarrow-new/issues/603): follow the
  [alpha tester guide](docs/operator/ALPHA_TESTER_GUIDE.md) on a throwaway VM, and tell us
  where it was unclear (about 1–2 hours).
- [#604](https://github.com/northnarrow/northnarrow-new/issues/604): try the `.rpm` on Fedora,
  Rocky Linux or AlmaLinux 10, and tell us what happened (about 1 hour).
- Found a typo, a broken link or a confusing sentence in any document? A small pull request
  is welcome, and so is a comment.

**How it works:**

1. **Say you're on it.** A comment like "I'd like to try this" on the issue is enough. You
   don't need to wait for an assignment, and two people trying the same thing is fine.
2. **Use a throwaway VM.** NorthNarrow protects itself in the kernel. Don't try it on a
   machine you care about. Any hypervisor works: GNOME Boxes, virt-manager, VirtualBox,
   Multipass, or a cloud VM. The guide's §3 lists what the kernel needs.
3. **Partial results count.** "It wouldn't install on Fedora 43, here is the error" is a
   useful contribution. So is "step 4 confused me".
4. **Keep it private-safe.** No host names, IP addresses, user names, keys or files from
   `/etc/northnarrow`. The guide's
   [§8](docs/operator/ALPHA_TESTER_GUIDE.md#8-collect-diagnostics-without-personal-data)
   collects diagnostics without personal data.
5. **Ask anything.** Comment on the issue, or ask in
   [Discussions](https://github.com/northnarrow/northnarrow-new/discussions/645). English or
   Italian are both fine. You will usually get an answer within two days.

**What happens next.** Every report is read and answered. Wording fixes go in quickly. Bugs
become a tracked fix, and the contributor is credited in the release notes unless they ask
not to be.

**About AI.** NorthNarrow is built with AI assistance under the founder's direction (see the
README). Contributions written with or without AI are equally welcome. If a pull request is
mostly generated, please say so in its description: you stay responsible for what it changes.

**Be kind.** The [Code of Conduct](CODE_OF_CONDUCT.md) applies everywhere in the project.

A security weakness (a way to stop, blind or deceive the agent) is never a public issue: see
[SECURITY.md](SECURITY.md).

## Golden rule

Before anything else, read:

1. [VISION.md](VISION.md) — where NorthNarrow is going: its goals for
   defence autonomy and supervised reactivation. It guides the roadmap;
   what the agent does today is in README.md and
   docs/operator/KNOWN_LIMITATIONS.md.
2. [ROADMAP.md](ROADMAP.md) — the working plan. Tappe (stages) in a fixed
   order, one at a time. None is skipped. There is no going back. Ever.
3. [VISION_TECHNICAL.md](VISION_TECHNICAL.md) — the long-term technical
   north star. Its features enter the roadmap only when conditions allow
   it.

## One Tappa at a time

Every PR belongs to the current step: up to Tappa 10.9 a Tappa of
ROADMAP.md, and since Wave 4 (October 2026) the capability program's order
(`docs/roadmap/CAPABILITY_PROGRAM.md`, "Order"). PRs that try to run
ahead (for example, starting Tappa 4 while Tappa 3 is not closed) are
refused. An exception needs an explicit change to ROADMAP.md, signed off
by the founder.

If a tool (Claude, Copilot, any tool) suggests skipping a Tappa or scaling
down the vision, the tool is wrong.

## Local quality gates

Before you open a PR, on your branch:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
```

The CI runs the same checks on Linux x86_64. A red PR is not merged.

- `--locked` (external audit SUP-016): every CI and release build uses
  `Cargo.lock` as it is committed. A PR that changes a `Cargo.toml` also
  commits the updated lockfile — `Cargo.lock`, `fuzz/Cargo.lock` (the fuzz
  harness compiles the agent) and `agent-ebpf/Cargo.lock` if it touches
  that crate — otherwise the CI fails with "cannot update the lock file …
  because --locked was passed". `cargo xtask` is run as `cargo --locked
  xtask build --release --locked`: the second `--locked` reaches the
  nested builds.
- Toolchain (SUP-015): `rust-toolchain.toml` pins one Rust release (rustup
  installs it on the first `cargo`); Dependabot proposes the next one in a
  PR of its own. `rust-version` in `Cargo.toml` is the real MSRV (today
  1.98, set by `aya` and `aya-obj`): the `msrv` job compiles with that
  version, and `xtask/tests/supply_chain.rs` fails if a dependency in the
  lockfile asks for a higher one. Whoever updates such a dependency raises
  `rust-version` in the same PR. `common/` alone declares its own, the
  eBPF crate's nightly (1.93): that nightly builds it too, and refuses a
  crate whose `rust-version` is above it.
- RustSEC advisories (SUP-007): the `audit` job also fails on `unsound`
  and `unmaintained` advisories, not only on vulnerabilities;
  `cargo audit --file Cargo.lock`, run from the repository root, gives the
  same result (it reads `.cargo/audit.toml`). An advisory is fixed (a
  lockfile bump) or recorded as an exception in `.cargo/audit.toml`, with
  the comment block described at the top of that file: reason, owner,
  review event, date and expiry (at most 184 days). Never `--ignore` on
  the command line. From the day after the expiry, the job is red until
  the exception is reviewed and recorded again, or removed. The bump of a
  security crate (listed in `xtask/tests/supply_chain.rs`,
  `security_crates_are_locked_alike_for_the_fuzzer`) is applied to both
  `Cargo.lock` and `fuzz/Cargo.lock`, and the fuzz job must compile.

## Releases (external audit SUP-024)

- A release starts only from an annotated `v*` tag, signed with an SSH key
  listed in `.github/allowed_signers` (the `ssh-keygen` "allowed signers"
  format, `namespaces="git"`). The `verify-tag` job of `release.yml`
  checks it before any build (`.github/scripts/verify-release-tag.sh`): a
  tag that is lightweight, unsigned, signed with OpenPGP or with a key not
  in the list, renamed, or not pointing at the commit being built stops
  there, and nothing is built, signed, attested or published. While the
  file lists no key, every tag stops there: adding their own public key
  is the maintainer's first step.
- Signing and checking a tag before the push (with `.pub`, the private key
  is in the ssh-agent; otherwise, give the path of the private key):

  ```sh
  git -c gpg.format=ssh -c user.signingkey="$HOME/.ssh/<key>.pub" tag -s vX.Y.Z -m "vX.Y.Z"
  git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag vX.Y.Z
  .github/scripts/verify-release-tag.sh verify vX.Y.Z "$(git rev-parse 'vX.Y.Z^{commit}')"
  ```

- The version (lot 383): the tag is `v` plus the workspace version
  (`[workspace.package] version` in `Cargo.toml`: `v0.1.1-alpha` for
  `0.1.1-alpha`), and `CHANGELOG.md` opens with that version's section,
  dated. Until the tag, the section says `- unreleased`; in the last
  commit before the tag, the day of the tag (UTC) is written in its place:
  `## [0.1.1-alpha] - YYYY-MM-DD`. The `verify-tag` job checks it
  (`verify-release-tag.sh version`): a tag of another version, an
  `[Unreleased]` above the version, or a section with no date stops there.
  Before the push: `.github/scripts/verify-release-tag.sh version vX.Y.Z`.
  Between two tags the changes merged since the last one sit in
  `CHANGELOG.md`'s *Unreleased* block, a `###` heading above the tagged
  section (an `[Unreleased]` `##` heading would stop the check); the last
  commit before the tag makes it the new version's dated section, with the
  workspace version raised to match.
- The eBPF object (lot 1.2): `release.yml`'s `package` job rebuilds it and
  prints the sha256 of the object it embeds. Before a tag, compare the one
  a release dry run of the commit prints with
  `northnarrow-agent-ebpf.sha256` of `ci.yml`'s `ebpf-object` artefact for
  the same commit (`gh run download <run> -n ebpf-object`): a mismatch
  means the release does not embed the object CI tested. No job compares
  them yet.
- Adding, rotating or revoking a key is a PR on
  `.github/allowed_signers`; the list committed in the tagged commit is
  the one that counts. When rotating, the old key stays with
  `valid-before="YYYYMMDD"`, so earlier tags still verify; a compromised
  key is removed. Commit signatures are not required.
- Publishing (the `publish` job, the only one with `contents: write`)
  never replaces an asset that is already published: if the release
  already has assets, the job fails. To publish again, the maintainer
  first deletes the release (`gh release delete vX.Y.Z`; the tag stays)
  and runs the job again.
- Mandatory review by a second person (CODEOWNERS): postponed while there
  is only one maintainer, because GitHub does not allow approving your own
  PRs and it would block every merge.

## Style

- 100% Rust. No C/C++ in production (see VISION_TECHNICAL.md, rule 1).
  The CI fails if `onig_sys` or `zstd-sys` enter the agent's dependency
  graph (they came in with tokenizers and tantivy, and left with the
  on-host LLM advisor in Wave 4, lab PR 214).
- No generative models in the agent: on-host detection stays
  deterministic (rules, correlation, posture, COMBAT).
- `unsafe` only where it cannot be avoided, isolated behind a safe API,
  with a comment that says why.
- No needless dependencies. Every new crate must be justified.

## Security

NorthNarrow is a defence product. Security issues in the code are
reported privately, through GitHub's private vulnerability reporting as
[SECURITY.md](SECURITY.md) says, not in public issues.
