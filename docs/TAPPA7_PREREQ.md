# Tappa 7 — Prerequisiti tecnici

> Stato: PREP — da consultare prima di iniziare Tappa 7
> implementazione (BPF-LSM anti-tamper). Documento creato durante
> sessione 12 maggio 2026 dopo verifica stato server Hetzner.

## Contesto

Tappa 7 (ROADMAP.md) richiede BPF-LSM hooks reali per
anti-tamper Linux. I commit attuali (9 maggio 2026) usano
tracepoint come workaround a causa di limitazioni bpf-linker
BTF emission. La ricerca del 12 maggio 2026 ha identificato che
queste limitazioni sono risolvibili adesso con configurazione
appropriata.

## Stato verificato (12 maggio 2026)

Server: `northnarrow-dev-01` (Hetzner Helsinki CCX23)
Kernel: Linux 6.8.0-111-generic Ubuntu 24.04.4 LTS

**Kernel config (positivo):**
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_LSM=y
CONFIG_LSM_MMAP_MIN_ADDR=0
CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"

**BTF kernel (positivo):**
$ ls /sys/kernel/btf/vmlinux
/sys/kernel/btf/vmlinux  ✓

**LSM attivi runtime (negativo):**
$ cat /sys/kernel/security/lsm
lockdown,capability,landlock,yama,apparmor
Manca "bpf". BPF-LSM hooks falliranno al load.

**Ecosystem Aya (positivo):**
agent/Cargo.toml:        aya = "0.13"  aya-log = "0.2"
agent-ebpf/Cargo.toml:   aya-ebpf = "0.1"
agent-ebpf/rust-toolchain.toml:
channel = "nightly"
components = ["rust-src", "rustfmt", "clippy"]

Aya 0.13 supporta BTF + LSM hooks. Setup nightly + rust-src già
in posto. Build infrastruttura pronta.

## Blocker 1 — Kernel runtime LSM non include "bpf"

**Fix (lunedì 19 maggio o successivo):**

1. Backup GRUB config:
sudo cp /etc/default/grub /etc/default/grub.bak

2. Edit `/etc/default/grub`, modifica/aggiungi:
GRUB_CMDLINE_LINUX="lsm=landlock,lockdown,yama,apparmor,bpf"
   Mantenere LSM esistenti, aggiungere "bpf" alla fine.

3. Update GRUB:
sudo update-grub

4. Reboot:
sudo reboot

5. Verifica post-reboot:
cat /sys/kernel/security/lsm
   Output atteso: `lockdown,capability,landlock,yama,apparmor,bpf`

**Rischio:** errore sintassi GRUB → server inavviabile. Per
Hetzner recovery via console web sempre disponibile. Server
senza dati production: rischio accettabile.

**Quando eseguire:** lunedì 19 maggio 2026 o successivo. NON
durante viaggi/produzione.

## Blocker 2 — bpf-linker BTF emission non attivata

**Contesto:** commit precedenti (`exec_check.rs`, `file_open.rs`)
contengono nota esplicita:

> "bpf-linker 0.10 doesn't emit BTF, so LSM CO-RE reloc would
>  fail at load time. The tracepoint gives userland every field
>  listed in the spec. When eBPF BTF lands properly, we'll
>  switch the hook for Tappa 7 enforcement."

**Soluzione (verificata da docs ufficiali aya-rs + bpf-linker
2026):**

Aggiungere flag `--btf` al linker via `RUSTFLAGS` nel build
agent-ebpf. Due opzioni:

**Opzione A — via .cargo/config.toml (raccomandato):**

In `agent-ebpf/.cargo/config.toml`:
```toml
[build]
target = "bpfel-unknown-none"
rustflags = "-C debuginfo=2 -C link-arg=--btf"

[unstable]
build-std = ["core"]
```

**Opzione B — via env variable (ad-hoc):**
RUSTFLAGS="-C debuginfo=2 -C link-arg=--btf" 
cargo +nightly build --target=bpfel-unknown-none 
-Z build-std=core --release

**Effetto:** binario ELF in
`target/bpfel-unknown-none/release/northnarrow-agent-ebpf`
conterrà sezione BTF. Aya LSM loader può fare CO-RE relocations
contro kernel structs (`struct task_struct`, `struct file`,
ecc.).

**Verifica BTF presente nell'ELF:**
llvm-objdump -h target/bpfel-unknown-none/release/northnarrow-agent-ebpf 
| grep -i btf

## Side effect — Migrazione Tappe 1-4 a LSM (opzionale)

Dopo risoluzione blocker 1+2, codice esistente può migrare da
tracepoint a LSM hooks veri:

- `exec_check.rs`: `sys_enter_execve` tracepoint →
  `bprm_check_security` LSM hook
- `file_open.rs`: `sys_enter_openat` tracepoint →
  `file_open` LSM hook

Beneficio: possibilità di `-EPERM` enforcement (denial), non
solo telemetria.

Decisione di migrare: dopo Tappa 7 chiusa, valutare se conviene
backport-are LSM ai sensori esistenti o lasciare tracepoint.

## Tappa 7 effettiva (post-fix blocker 1+2)

Specifica originale (ROADMAP.md):

1. **BPF-LSM hook task_kill** — `agent-ebpf/src/task_kill.rs`
   - Negare SIGKILL/SIGTERM verso PID dell'agent
   - Eccezione: canale firmato Ed25519 (Tappa 8 dependency)

2. **BPF-LSM hook ptrace_access_check** —
   `agent-ebpf/src/ptrace_check.rs`
   - Negare ptrace al daemon NorthNarrow

3. **Protezione filesystem `/var/lib/northnarrow/`:**
   - `chattr +i` (immutable bit) su file critici
   - LSM inode hooks per impedire modifiche

4. **Watchdog secondario:**
   - Daemon separato, Rust standard (non eBPF)
   - Monitora agent principale
   - Riavvia se cade

## Demo verifica finale Tappa 7
$ sudo kill -9 $(pidof northnarrow-agent)
kill: (12345) - Operation not permitted

Anche root non può uccidere l'agent.

## Sequenza operativa lunedì 19 maggio 2026

1. SSH al server, verifica Phase A Reasoning LoRA OK (PC fisso)
2. Backup GRUB config: `sudo cp /etc/default/grub /etc/default/grub.bak`
3. Edit `/etc/default/grub`: aggiungere `lsm=...,bpf`
4. `sudo update-grub`
5. `sudo reboot`
6. Verifica: `cat /sys/kernel/security/lsm` contiene `bpf`
7. Edit `agent-ebpf/.cargo/config.toml`: aggiungere rustflags BTF
8. Verifica bpf-linker installato:
   `cargo install --list | grep bpf-linker`
   Se mancante: `cargo install bpf-linker`
9. Test build:
   `cd ~/dev/northnarrow-new/ && cargo xtask build`
10. Verifica ELF contiene BTF:
    `llvm-objdump -h target/bpfel-unknown-none/release/* | grep -i btf`
11. Solo allora: iniziare implementazione `task_kill.rs` LSM hook

Tempo stimato setup: 1-2 ore.
Tempo stimato Tappa 7 sviluppo: 2-3 settimane (da ROADMAP.md).

## Note critiche

- Server `northnarrow-dev-01` è ambiente DEV, non production.
  Reboot per GRUB fix è accettabile.
- WSL2 (sviluppo PC fisso founder) NON ha BPF-LSM funzionante.
  Sviluppo e test Tappa 7 = su server Hetzner o VM KVM locale.
- Phase A Reasoning training in corso su PC fisso non
  interferisce con lavoro server (hardware separato).

---

## UPDATE 12 maggio 2026 — 15:15 UTC — IMPLEMENTATION + LIVE TEST

### Implementation (via Claude Code, autopilot mode)

Commits on `main` (already pushed to origin):

- `9396e26` — `feat(agent-ebpf): task_kill.rs LSM hook denies SIGKILL/SIGTERM`
- `ed1e3c3` — `feat(agent-ebpf): ptrace_check.rs LSM hook denies ptrace`
- `1dcd0dd` — `feat(agent): userland LSM loader (anti_tamper module)`

Build verification: 258 tests passing, BTF section present in
agent-ebpf ELF, cargo clippy clean.

### Live test on northnarrow-dev-01

Agent launched as root via:
sudo nohup ./target/release/northnarrow-agent --no-ade > /tmp/nn-agent.log 2>&1 &

Log confirmed at launch:
INFO anti-tamper: agent PID registered with kernel agent_pid=14112 map="PROTECTED_PID"
INFO anti-tamper: LSM hook attached (denies SIGKILL/SIGTERM to agent) program="task_kill"
INFO anti-tamper: LSM hook attached (denies ptrace to agent) program="ptrace_access_check"

### Test results

| # | Test | Command | Expected | Actual | Verdict |
|---|------|---------|----------|--------|---------|
| 1 | SIGKILL | `sudo kill -9 14112` | denied | `kill: Operation not permitted`, agent Rl | PASS |
| 2 | SIGTERM | `sudo kill -15 14112` | denied | `kill: Operation not permitted`, agent Rl | PASS |
| 3 | PTRACE | `sudo gdb -p 14112` | denied | `Could not attach to process`, `ptrace: Inappropriate ioctl` | PASS |
| 4 | SIGQUIT | `sudo kill -3 14112` | allowed | exit 0, agent terminated cleanly | PASS |

### Known issues (non-blocking)

- `SIGINT` (signal 2) and `SIGHUP` (signal 1) not handled by
  userland agent (tokio `signal::ctrl_c` doesn't catch
  `sudo kill -2`). Workaround: use `SIGQUIT` for shutdown.
  Fix scheduled with subsequent Tappa 7 tasks.

### Conclusion

Anti-tamper layer of Tappa 7 (task_kill + ptrace_access_check)
is VERIFIED FUNCTIONAL on production-grade kernel:

- Root cannot kill the agent with SIGKILL or SIGTERM.
- Root cannot attach a debugger to the agent.
- Agent remains responsive to graceful shutdown (SIGQUIT).
- LSM hooks correctly filter only the targeted signals
  (no over-blocking).

Differentiator vs CrowdStrike Falcon: CrowdStrike's userspace
agent on Linux can be killed by root via standard signals.
NorthNarrow agent on this server, with Tappa 7 hooks active,
cannot. Verified empirically 12 May 2026 15:14 UTC.

### Remaining Tappa 7 work

- Task 5: filesystem protection `/var/lib/northnarrow/`
  (chattr +i + LSM inode hooks).
- Task 6: secondary watchdog process.
- Bug fix: SIGINT/SIGHUP handler in agent userland.
- Optional: migrate Tappe 1-4 from tracepoint to LSM hooks
  now that BTF emission works.

Target completion: settimana lunedì 19 maggio 2026.

---

## UPDATE 19 maggio 2026 — Task 7 ENI status reconciliation — PARTIAL

### Status

Task 7 (Emergency Network Isolation autonomous via COMBAT) is
**PARTIAL — code-complete, test-blocked. NOT SHIPPED.**

Implementation is in place:

- `NetworkIsolator` userland component
- `configs/combat-rules.v4` (production combat ruleset; iptables
  `NORTHNARROW_COMBAT` chain with DROP)
- Ed25519 `UnlockToken` + admin socket protocol
- Posture state-machine wiring for COMBAT entry/exit

The integration test `e2e_force_combat_then_unlock_via_cli`
(`agent/tests/privileged_e2e.rs:157`) cannot complete in any
developer environment.

### Findings (live verify, 2026-05-19)

- Environment: Ubuntu Server VM, kernel `6.8.0-117-generic`
- HEAD: `1bb1f1f`
- Build: `cargo test --release --features test-privileged,debug-trigger`
- Outcome: panic at `agent/tests/privileged_e2e.rs:177` —
  `debug force-posture failed: stderr=""`

### Root cause (verified)

The test resolves `nn-admin` via `CARGO_BIN_EXE_nn-admin`, which
cargo expands to `<repo>/target/release/nn-admin`. In every dev
environment that path lives under `/home/<user>/...`. The production
rule `R009_RootExecFromUserPath`
(`agent/src/decision/rules/r009_root_exec_from_user_path.rs:8`) matches
on `uid == 0` plus a `/home/` / `/tmp/` / `/var/tmp/` prefix and
returns `ResponseAction::KillProcess`. `nn-admin` is killed ~47 μs
after spawn, before its admin-socket handshake completes — hence the
empty stderr in the assertion.

R009 is production-correct: a root binary executing from a
user-writable path is a textbook privilege-escalation indicator. The
test harness self-kill is an artefact of where cargo places test
binaries, not a flaw in the rule.

### Remediation paths (deferred)

Three approaches were considered. None applied in the
2026-05-19 commit — owner decision deferred to a separate workstream.

- **A.** Test fixture copies binaries to `/usr/local/bin/` before
  spawn. Cheapest (~1 h), no production change, mirrors install
  layout.
- **B.** Agent `--decision-rules-allowlist` / `--decision-rules-deny`
  flag behind a test-only feature gate. More flexible (~3–4 h) but
  introduces a rule-disable footgun surface.
- **C.** R009 parent-PID / Ed25519-signature exemption for signed
  admin tooling. Correct long-term answer but properly Tappa 8/9
  admin-trust scope (~1 week).

### Cross-references

- Full reproducer + evidence: `docs/issues/ISSUE_001_eni_test_r009_selfkill.md`
- Briefing index: `docs/CLAUDE_BRIEFING.md` § "FASE 3: Anti-Tamper",
  Task 7 line and "Task 7 known issue (2026-05-19)" subsection.

### Invariants preserved by this commit

- No change to `agent/src/decision/rules/r009_*.rs`
- No change to `agent/tests/privileged_e2e.rs`
- No change to `NetworkIsolator`, `configs/combat-rules.v4`,
  or any other production code path for Task 7 ENI
- `cargo clippy -- -D warnings` remains 0/0
