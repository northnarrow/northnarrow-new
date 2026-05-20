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

## UPDATE 19 maggio 2026 — Task 7 ENI ✅ SHIPPED

### Status

Task 7 (Emergency Network Isolation autonomous via COMBAT) is
**SHIPPED**. Live-verify complete on
`northnarrowdev` (Ubuntu Server VM, kernel `6.8.0-117-generic`).

### Live-verify evidence

- **Host:** `northnarrowdev`
- **Kernel:** `6.8.0-117-generic`
- **LSM chain runtime:**
  `lockdown,capability,landlock,yama,apparmor,bpf` (bpf present)
- **Build:** `cargo test --release --features
  test-privileged,debug-trigger -p northnarrow-agent --test
  privileged_e2e --no-run`
- **Run dir:** `/tmp/eni_run/r009fix_1779177273/`
- **Target test (`e2e_force_combat_then_unlock_via_cli`):**
  exit code **0**, `test result: ok. 1 passed; 0 failed`,
  finished in **1.11 s**.
- **Full privileged_e2e suite:** exit code **0**, `3 passed;
  0 failed; 1 ignored` (the ignored one is the
  rate-limit-window timing test, still `#[ignore]` per existing
  doc note).
- **iptables side-effect:** pre-vs-post diff shows only
  packet/byte counter deltas; no chain added, no rule added,
  `NORTHNARROW_COMBAT` absent post-run — full engage→unlock
  cycle clean.
- **Agent log excerpts** (full log at
  `/tmp/eni_run/r009fix_1779177273/test.log`):
  ```
  decision engine ready rules=10 demo_tappa5=false
  admin socket listening (mode 0600) ...
  COMBAT: network isolated (loopback only) ...
  admin challenge issued (32-byte nonce)
  admin signature verified, unlock token minted
  COMBAT: network isolation released
  ```
- **Workspace clippy:** clean
  (`cargo clippy --workspace --all-targets -- -D warnings`).
- **Workspace default test suite:** `381 lib tests: 371 passed,
  0 failed, 10 ignored` + 50 integration tests, 0 failures.

### What shipped

Code-complete since the BPF pinning sprint
(`tappa-7-task6-bpf-pinning-WIP`); the live-verify was blocked
by `ISSUE_001` (test self-kill via R009 from `/home/*` paths)
and is now unblocked. No production code change shipped in this
verify step — only the test infrastructure under
`agent/tests/privileged_e2e.rs` was modified to sudo-install
both binaries into `/usr/local/bin/<name>-e2etest-<ts>-<pid>`
before each test (Option A from ISSUE_001 §4). RAII cleanup via
the existing `AgentGuard` removes both binaries on test exit;
verified no residue in `/usr/local/bin/` post-run.

The same Option-A pattern was independently re-applied across
the full agent priv-e2e suite in **Tappa 9 polish #1** (PR #46,
SHA `18baa66`, merged 2026-05-20) — the ENI fix was thereby
generalised to every test that spawns `nn-admin` against a
running agent.

### Invariants preserved

- ✅ No change to `agent/src/decision/rules/r009_*.rs`
- ✅ No change to `agent/src/anti_tamper/network_isolate.rs`
- ✅ No change to `configs/combat-rules.v4`
- ✅ No new agent CLI flags
- ✅ `cargo clippy -- -D warnings` 0/0
- ✅ All workspace tests pass

### Cross-references

- `docs/issues/ISSUE_001_eni_test_r009_selfkill.md` (root cause +
  remediation analysis + RESOLVED status with this same evidence).
- `docs/CLAUDE_BRIEFING.md` § "FASE 3: Anti-Tamper", Task 7 line.
- `agent/tests/privileged_e2e.rs` — fixture changes.
