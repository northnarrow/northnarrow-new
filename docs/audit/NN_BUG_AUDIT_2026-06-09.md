# NorthNarrow Bug-Hunt Audit — Defect Registry

- **Date:** 2026-06-09
- **Baseline:** branch `audit/nn-bug-hunt` @ `8fcd18b` — this is the **post-9.0.a.1-merge tree** (`8fcd18b`'s parent is `origin/main`'s tip `59f11d0`, so the feature-branch tip is bit-for-bit what `origin/main` becomes once 9.0.a.1 merges). The `exe: Option<String>` field and its `SCHEMA FREEZE` doc-comments are present and were excluded from false-flagging.
- **Mode:** READ-ONLY. No code/config/eBPF was modified. The only artifact produced is this markdown. Every one-line fix below is a registry entry, **not** an applied change.
- **Method:** 7 parallel finders (eBPF-LSM arity/`prev_retval`/`bpf_printk`, eBPF↔userland ABI encoding, posture escalation, COMBAT/availability, anti-tamper+privilege, detection-store/chainlog invariants, broad sweep) → one adversarial verifier per finding that re-read the code at `file:line`, ran `git blame`/`git log` to reject already-fixed items, and rewrote each VM-validation recipe to be runnable as-is. 29 raw findings → **19 confirmed**, **2 uncertain**, **8 dismissed** (one Medium was a duplicate framing, merged).

## How to read an entry

The **load-bearing column is "Validate on the 6.8 VM"** — trigger / observe-command / expected-vs-suspected. This codebase's real bugs pass the unit suite and only surface on the live Ubuntu 6.8.0-124 kernel, so a hypothesis without a concrete reproduction is noise. Entries marked **runtime-observable: NO** are reachable only by code-reading with no live signal — they are ranked lower regardless of mechanism severity. Each entry carries the verifier's confirmation (the mechanism was checked in the real code on `8fcd18b` and shown unfixed in git history).

## Severity legend

- **Beta-blocker** — silently breaks a core protection (LSM hook never attaches / a deny never fires), OR autonomously harms availability (isolates NIC / locks out SSH / SIGKILLs on benign activity), OR a silent security bypass.
- **High** — degraded protection or a real bug with a specific, non-exotic trigger.
- **Medium** — correctness bug with limited blast radius or a harder trigger.
- **Low** — minor / defensive-only / code-read-only with no runtime signal.

---

## Summary index

| # | ID | Sev | RT-obs | File:line | One-line |
|---|----|----|:--:|----------|----------|
| 1 | `abi-modpath-1` | **Beta** | yes | `agent-ebpf/src/module_load.rs:65` | Module paths >8 dentries lose `/usr/lib/modules` prefix → R018 autonomously SIGKILLs + COMBAT on ~20% of benign deep modules |
| 2 | `posture-1` | **Beta** | yes | `agent/src/posture/mod.rs:334` | Two COMBAT-tier triggers in **one** `observe()` collapse OBSERVING→COMBAT in a single hop (no ledger gate) |
| 3 | `posture-2` | **Beta** | yes | `agent/src/posture/mod.rs:489` | `CorroborationLedger` never cleared on admin release → one signal re-locks COMBAT within 15 min, defeating a signed unlock |
| 4 | `at-authz-1` | **Beta** | yes | `agent/src/anti_tamper/admin_auth.rs:258` | `admin.pub` is append-mutable despite PROTECTED_INODES → inject `Role::All` key → full auth-model defeat |
| 5 | `ebpf-lsm-1` | High | yes | `agent/src/anti_tamper/mod.rs:368` | Deny-hook attach failures are warn-and-continue → a verifier reject silently disables a protection while the agent reports healthy |
| 6 | `combat-avail-1` | High | yes | `watchdog/src/main.rs:104` | Watchdog respawn drops `--detect-only` (flag form) → detect-only host silently becomes full-enforcement after a crash |
| 7 | `at-authz-2` | High | yes | `agent/src/anti_tamper/filesystem.rs:119` | `agent.sig.key` is in-place-mutable despite PROTECTED_INODES → audit/detection/FIM chain forgery |
| 8 | `chain-audit-torn-1` | High | yes | `agent/src/audit.rs:459` | `audit.log` has no torn-tail recovery → one partial write = auditing silently OFF for the whole boot |
| 9 | `catchall-3` | High | yes | `agent/src/decision/rules/r004_exec_from_proc_self_fd.rs:69` | R004 systemd-executor exemption matches `argv[0].ends_with` + spoofable `parent_comm` → fileless-exec kill bypass |
| 10 | `abi-tcpconnect-srcport-1` | Medium | yes | `agent-ebpf/src/tcp_connect.rs:152` | TCP `src_addr`/`src_port` emitted as 0 → `flow_id` hashed over a zeroed source half; netflow rows carry `0.0.0.0:0` |
| 11 | `posture-3` | Medium | yes | `agent/src/posture/triggers.rs:686` | Mass-write arm has no `loginuid` carve-out → PAM user-session bursts escalate to ENGAGED |
| 12 | `combat-avail-2` | Medium | yes | `agent/src/response/kill.rs:126` | NEUTRALIZE kill-tree guards only attributed offenders, not `/proc` descendants → a guarded sshd/watchdog descendant is killed |
| 13 | `chain-protect-1` / `at-authz-3` | Medium | yes | `agent/src/anti_tamper/filesystem.rs:175` | **[KNOWN-b]** `detections.jsonl`+`status_events.jsonl` not in PROTECTED_INODES (subdir unreachable) → deletable/truncatable |
| 14 | `chain-persist-1` | Medium | yes | `agent/src/admin_socket.rs:3035` | **[KNOWN-a]** set-status persist failure is wire-indistinguishable from "detection not found" (both → exit 9) |
| 15 | `catchall-1` | Medium | yes | `agent/src/decision/rules/net.rs:170` | `DnsBurstWindow`/`BeaconWindow` outer HashMaps never evict idle keys → unbounded memory growth on a long-lived agent |
| 16 | `ebpf-lsm-4` | Low | NO | `agent-ebpf/src/inet_csk_listen.rs:6` | Stale 2-arg doc for `inet_csk_listen_start` (6.8 is 1-arg); kprobe so latent, not a verifier-reject |
| 17 | `abi-filename-trunc-1` | Low | yes | `agent-ebpf/src/main.rs:144` | Exec path ≥256 B truncated with no guaranteed NUL → forensic-only today (all filename rules are prefix-anchored) |
| 18 | `chain-genesis-residue-1` | Low | NO | `agent/src/chainlog.rs:1076` | Never-rotated (seq-0) detection chain can be wiped and a fresh genesis file still verifies — but `verify_log_set` has no prod caller |
| 19 | `catchall-4` | Low | NO | `agent/src/fim/drain.rs:307` | `DriftRateLimiter` doc claims `parking_lot::Mutex` but uses `std::sync::Mutex` + `.expect("poisoned")` — latent panic footgun |
| U1 | `abi-filefree-1` | **uncertain** | yes | `agent-ebpf/src/fim_watch.rs:689` | `file_free_security` close-emit hook may not fire with a readable `f_inode` on 6.8 → in-place/`O_APPEND` FIM blindness (fire-test) |
| U2 | `catchall-2` | **uncertain** | yes | `agent/src/sensors/multiplexer.rs:618` | Synchronous `/proc/<pid>/exe` readlink per DNS query on a tokio worker — real, but the telemetry-loss harm is unsubstantiated |

**Known-items (confirmed precisely, not re-discovered):** entry 14 = 9.0.c persist-failure→not-found fold; entry 13 = `detections/` subdir absent from `STATE_PROTECTED_FILES`. Both pinned to exact `file:line` below.

---

## Beta-blockers

### 1. `abi-modpath-1` — Deep module paths lose their prefix → R018 autonomously kills + COMBATs ~20% of benign module loads

- **Severity:** Beta-blocker · **Runtime-observable:** yes · **Sibling of:** T7 fixed-buffer / path-truncation
- **Primary:** `agent-ebpf/src/module_load.rs:65` (`MODULE_PATH_SLOTS = 8`); walk at `:152-188`; reconstruction at `common/src/model.rs:396`; rule at `agent/src/decision/rules/r018_kernel_module_load.rs:97`
- **Hypothesis:** `walk_components` captures only the leaf-most 8 dentries; modules nested deeper than 8 lose the `/usr/lib/modules` prefix, so R018 misclassifies the source path.

**Confirmed mechanism.** `walk_components` iterates `for i in 0..MODULE_PATH_SLOTS` (=8), writing the leaf-most 8 *named* dentries and breaking before root. `reconstruct_module_path` reverses+joins and, finding no leading `/`, prepends a single `/`. For a path with ≥10 named components (e.g. `/usr/lib/modules/<ver>/kernel/drivers/net/.../e1000e.ko.zst`) the `usr`,`lib`,`modules` components and root are all dropped, reconstructing to `/<ver>/kernel/.../e1000e.ko.zst` — which matches **neither** `/lib/modules/` nor `/usr/lib/modules/`. `is_standard_module_path()` then returns false → R018 **branch (2)** (`r018:97-112`) fires `Severity::Critical` + `ResponseAction::KillProcessTree` and drives posture→COMBAT. Branch (2) runs **before** the loader/parent allowlist (branch 3) and after only the kthread check, so a normal `udev`/`modprobe` load (parent `systemd-udevd`, non-kthread) is not exempt. On 6.8.0-124, ~1288/6474 modules (~20%, incl. `r8169`, `nouveau`, wifi drivers, Intel QAT) have ≥10 named components. The suite passes because every R018 test path is ≤8 dentries. `git blame`: lines 63-66 + 152-188 are original (`91efe14`, 2026-06-01), never modified.

**Validate on the 6.8 VM.**
- *Trigger:* force-load a deep but hardware-independent module so `finit_module(2)` hits the `kernel_read_file` LSM hook, via a non-kthread userspace loader. Confirm depth first: `find /usr/lib/modules/$(uname -r) -name 'mcp251xfd*' -o -name 'vcan*'`. Then `sudo modprobe mcp251xfd` (path = `.../kernel/drivers/net/can/spi/mcp251xfd/mcp251xfd.ko.zst` = 11 named comps). Control that must **not** trip: `sudo modprobe vcan` (9 named → reconstructs to `/lib/modules/...` → stays standard). Ensure the agent is **not** `--detect-only`.
- *Observe:*
  ```
  journalctl -u northnarrow-agent --since '2 min ago' | grep -iE 'ModuleLoad|R018|NON-standard path|KillProcessTree|COMBAT'
  nn-admin detections | grep -iE 'R018|mcp251xfd|NON-standard'
  nn-admin status | grep -iE 'posture|COMBAT'
  ```
- *Expected:* decoded path = `/usr/lib/modules/6.8.0-124-generic/kernel/drivers/net/can/spi/mcp251xfd/mcp251xfd.ko.zst`; `is_standard_module_path()=true`; R018 silent or at most a Medium/Log "standard path but non-allowlisted loader". No KillProcessTree, no COMBAT. `vcan` control behaves identically.
- *Suspected:* decoded path missing the prefix → `/6.8.0-124-generic/kernel/.../mcp251xfd.ko.zst`; `is_standard_module_path()=false` → R018 emits `Severity::Critical KillProcessTree` ("NON-standard path … near-certain rootkit … posture → COMBAT"), the `modprobe` tree is SIGKILLed, posture flips to COMBAT on a benign module. `vcan` stays standard — the ≥10-component depth is the discriminator.

---

### 2. `posture-1` — Two COMBAT-tier triggers in one `observe()` collapse OBSERVING→COMBAT in a single hop

- **Severity:** Beta-blocker · **Runtime-observable:** yes · **Sibling of:** T7.13
- **Primary:** `agent/src/posture/mod.rs:334`; triggers at `agent/src/posture/triggers.rs:711` (mass-write) + `:770` (persistence); carve-out list `triggers.rs:84`; transition `transitions.rs:73`
- **Hypothesis:** a single event raising two distinct `NeedsCorroboration` COMBAT-tier triggers in the same `detect()` auto-corroborates same-round, jumping straight to locked COMBAT + isolation with no 15-min ledger gate.

**Confirmed mechanism.** `observe()` builds `escalation_now` from this round's ≥Engaged hits; for each COMBAT-tier `NeedsCorroboration` trigger it sets the effective level to `Combat` if `escalation_now.iter().any(|o| *o != t)` (`mod.rs:334`) — i.e. one other escalating trigger this round is enough. A single `Event::FileOpen` can raise **both** `ConfirmedIntrusion` (mass-write arm counts non-carveout writes; `/etc/systemd/system/` and `/etc/cron.d/` are **not** in `MASS_WRITE_CARVEOUT_PREFIXES`) **and** `PersistenceMechanism` (same focal write is under `PERSISTENCE_PREFIXES`). Each then satisfies the predicate against the other, so both level to `Combat` and `apply_to_level(Observing, Combat)` returns `Combat{locked:true}` directly (`transitions.rs:73`) — the ledger is recorded *after* the decision (`mod.rs:363`), so it never gates this. The combat-entry hook engages the ladder at INVESTIGATE; at the 30 s deadline NEUTRALIZE SIGKILLs the attributed writer, escalating to ISOLATE (full iptables drop) if that pid is host-critical/gone. Lineage exemptions don't save a root process whose ancestry walks to systemd PID 1 (matches neither `is_auth_mediated` nor `is_system_daemon_mediated`). Both tests that reach COMBAT (`tests.rs:350`, `:851`) deliberately split the two signals across two `observe()` calls, hiding the single-call collapse. `git blame`: line 334 from `0e90816` (BUG-032, 2026-06-02), unamended.

**Validate on the 6.8 VM.**
- *Trigger:* as root (NOT via sudo, so lineage walks to PID 1), spawn directly under systemd so the 20th write is simultaneously a mass-write count-crossing and a persistence-prefix hit in one `detect()`:
  ```
  systemd-run --scope /bin/sh -c 'for i in $(seq 1 25); do : > /etc/systemd/system/nn-test-$i.service; done'
  ```
  Ensure the agent is in the enforcing (non-`--detect-only`) branch. Confirm baseline `nn-admin status | grep -i posture` = OBSERVING. Keep a second console — this session may be cut.
- *Observe:*
  ```
  journalctl -u northnarrow-agent --since '90 sec ago' -o cat | grep -iE 'POSTURE TRANSITION|ConfirmedIntrusion_MassWrite|combat.ladder|INVESTIGATE|NEUTRALIZE|ISOLATE|killed offending|full network isolation'
  nn-admin status | grep -i posture
  iptables -S | grep -iE 'DROP|northnarrow|combat'
  ss -tn state established | head
  ```
- *Expected:* posture rises **at most to ENGAGED** on this single round; no `POSTURE TRANSITION state=COMBAT`, no ladder engagement, no iptables DROP chain, the `sh` process survives, SSH stays up.
- *Suspected:* a single `POSTURE TRANSITION state=COMBAT` line appears for the OBSERVING→COMBAT hop; `nn-admin status`=COMBAT; `combat.ladder …→INVESTIGATE` immediately; ~30 s later `INVESTIGATE→NEUTRALIZE` SIGKILLs the benign writer; if unkillable/critical, `NEUTRALIZE→ISOLATE … full network isolation`, iptables shows the DROP chain, SSH drops — host self-isolates on a routine bulk unit install.

---

### 3. `posture-2` — `CorroborationLedger` never cleared on release → a single signal re-locks COMBAT within 15 min

- **Severity:** Beta-blocker · **Runtime-observable:** yes · **Sibling of:** T7.13
- **Primary:** `agent/src/posture/mod.rs:489` (`admin_release_combat_with_token`); ledger `agent/src/posture/corroboration.rs` (no `clear()`); release verb wired at `admin_socket.rs:1028`
- **Hypothesis:** after an operator releases COMBAT→Alerted, the stale escalation signals that drove the original COMBAT remain in the ledger for ≤15 min, so one new COMBAT-tier heuristic immediately corroborates against the stale entry and re-locks COMBAT, silently undoing the signed release.

**Confirmed mechanism.** The ledger is mutated **only** inside `observe()` (`mod.rs:309-310` prune, `:363-364` record). `admin_release_combat_with_token` (`:489`), `admin_release_combat` (`:427`), `admin_force_state_with_token` (`:559`) and `tick_decay` (`:399`) never touch it; `CorroborationLedger` has no `clear()` (only `new/prune/corroborated/record/len`). `prune()` drops entries solely by 15-min wall-`Instant`. So driving COMBAT via e.g. `ExfiltrationPattern`+`LateralMovement` records both; after release to Alerted the ledger still holds them, and one new **distinct** COMBAT-tier heuristic (e.g. a mass-write burst → `ConfirmedIntrusion`) hits `ledger.corroborated(t)=true` and re-levels to `Combat`. `apply_to_level(Alerted, Combat)` returns `Combat{locked:true}`; the `before≠Combat && after==Combat` edge re-fires `NetworkIsolator::engage`. (The new signal must be distinct from a stale entry — `SUSTAINED_SAME_TYPE_PROMOTES=false`.) `git blame`: release method from `1a63ddc1` (2026-05-13); `git log -Scorroboration` shows only BUG-032 (`0e90816`) — no ledger-clear ever landed. No test exercises a post-release re-collapse.

**Validate on the 6.8 VM.**
- *Trigger:* **Phase 1** — from one non-exempt pid, drive COMBAT with two distinct blunt signals within 15 min (e.g. 21 outbound connects to `1.1.1.1:443` for ExfiltrationPattern **plus** a fan-out to several internal `:22`/`:445` hosts for LateralMovement). **Phase 2** — `nn-admin unlock` (real signed Ed25519 release); confirm posture→ALERTED and isolation torn down. **Phase 3** — within 15 min, from a fresh non-exempt pid raise exactly one new distinct COMBAT-tier heuristic: `for i in $(seq 1 600); do : > /tmp/nn_probe_$i; done` (non-sudo, non-agent pid → `ConfirmedIntrusion`, distinct from the stale Exfil/Lateral entries).
- *Observe:*
  ```
  journalctl -u northnarrow-agent --since '20 min ago' -o cat | grep -iE 'POSTURE TRANSITION|admin token release|ConfirmedIntrusion|ExfiltrationPattern|LateralMovement|isolat'
  nn-admin status | grep -i posture
  sudo iptables -S | grep -iE 'northnarrow|DROP|REJECT'; ss -tan state established | wc -l
  ```
- *Expected:* after the signed unlock the host stays ALERTED; the single new `ConfirmedIntrusion` takes posture only to ENGAGED (`Alerted → Engaged`); no new iptables DROP/REJECT rules.
- *Suspected:* `POSTURE TRANSITION Alerted → Combat trigger=Some(ConfirmedIntrusion)` appears immediately after the just-logged `admin token release`; `nn-admin status` flips back to COMBAT; iptables isolation rules are re-inserted; established connections collapse — the cryptographically-signed operator unlock is autonomously undone within seconds by benign follow-on activity borrowing the stale pre-release ledger entries.

---

### 4. `at-authz-1` — `admin.pub` is append-mutable despite PROTECTED_INODES → inject a `Role::All` key, defeat the auth model

- **Severity:** Beta-blocker · **Runtime-observable:** yes · **Sibling of:** PROTECTED_INODES modification-only / anti-tamper trust gap
- **Primary:** `agent/src/anti_tamper/admin_auth.rs:258` (`load_with_agent_id`) + `:312` (`reload`); parse at `:1014`/`:1105`; `Role::All` super-role at `:170`; FS deny set `agent-ebpf/src/inode_protect.rs:293/331/358/408/437`; observe-only `file_open`/`file_permission` in `fim_watch.rs:642`
- **Hypothesis:** the trusted admin key allowlist `/etc/northnarrow/admin.pub` is protected only against unlink/rename/setattr/chattr, not write-open+append, so a root foothold can append its own pubkey line and gain full admin authority on the next reload/restart.

**Confirmed mechanism.** The FS anti-tamper deny set is exactly 5 LSM hooks (unlink/rmdir/rename/setattr/ioctl); there is **no** write-open/`file_permission` deny. The only `file_open`+`file_permission` hooks live in `fim_watch.rs` and are observe-only (`return 0` always); their own comment (`:639-641`) states an `O_APPEND`/same-size in-place rewrite never touches metadata so `inode_setattr` never fires (the BUG-023 root cause). `admin.pub` is in `ETC_PROTECTED_FILES` (`filesystem.rs:116`) → PROTECTED_INODES, which feeds only the 5 modification hooks — so `open(O_WRONLY|O_APPEND)`+write is neither denied nor (it's also absent from `WATCHED_PATHS`) observed. `load_with_agent_id`/`reload` `read_to_string` and trust every parsed line; `parse_admin_line` accepts `<hex64> all` → `Role::All`, which `authorizes()` treats as satisfying any required role; there's no signature/hash check over `admin.pub`. Quorum doesn't save it — the attacker appends N distinct all-keys. Takes effect on the next restart or the next `rotate-keys` (which calls `reload`). `git blame`: observe-only `file_permission` is `bf4dc59` (BUG-023, VM-pending); the 5-hook deny set has no write-deny added since; no pending `O_APPEND` deny work exists.

**Validate on the 6.8 VM.**
- *Trigger:* prove protection is live first — `sudo bpftool map dump pinned /sys/fs/bpf/PROTECTED_INODES | head` non-empty, and control `rm -f /etc/northnarrow/admin.pub` fails EPERM. Then attack:
  ```
  openssl genpkey -algorithm ed25519 -out /tmp/atk.pem
  PUB=$(openssl pkey -in /tmp/atk.pem -pubout -outform DER | tail -c 32 | xxd -p -c64)
  printf '%s all\n' "$PUB" >> /etc/northnarrow/admin.pub      # in-place append, NOT unlink/rename
  ```
  Force reload without restart via any benign `nn-admin rotate-keys add …` (calls `AdminAuth::reload`) or `systemctl restart northnarrow-agent`. Then sign an `unlock` `SignedPayload` with `/tmp/atk.pem` against the server challenge nonce + install `agent_id` and submit it.
- *Observe:*
  ```
  journalctl -u northnarrow-agent --since '2 min ago' | grep -iE 'FsProtectDenial|FS_PROTECT|EPERM|fim.*Modified|admin_auth.verify'
  ls -l /etc/northnarrow/admin.pub; tail -2 /etc/northnarrow/admin.pub
  nn-admin status | grep -iE 'combat|posture|locked'
  ```
- *Expected:* the `>>` append is **denied** (EPERM + an `FsProtectDenial` for `admin.pub`'s dev/ino, no attacker line in `tail`), exactly like the control `rm`; the unlock signed by the injected key fails (InvalidSignature/RoleDenied).
- *Suspected:* the append **succeeds silently** — no EPERM, no `FsProtectDenial`, no FIM `Modified` event (not in `WATCHED_PATHS`); `tail` shows the `<hex> all` line. After reload/restart the injected all-role key verifies (`admin_auth.verify_success` logs the attacker fingerprint) and `nn-admin status` shows COMBAT released — a full silent defeat of the auth model from a root foothold.

---

## High

### 5. `ebpf-lsm-1` — Deny-hook attach failures are warn-and-continue: a verifier reject silently disables protection

- **Severity:** High (amplifier) · **Runtime-observable:** yes · **Sibling of:** T7 inode_setattr arity / verifier-reject-silently
- **Primary:** `agent/src/anti_tamper/mod.rs:368` (task_kill) + `:377` (ptrace); FS deny loops `filesystem.rs:404-411` + `:417-424`; error origin `antitamper-bpf/src/lib.rs:267/307/447`; the only fail-closed gate `main.rs:488` covers offset drift only (`common/src/btf_offsets.rs`)
- **Hypothesis:** if any LSM deny hook fails `prog.load()`/`attach()` (e.g. a future `ctx.arg` arity mismatch like the `inode_setattr` `4a5492c` regression), the agent only logs a WARN and keeps running with that protection silently absent.

**Confirmed mechanism.** Every LSM deny/process hook attach is `if let Err(e) { warn!(...) }` and never propagates: `mod.rs:368/377`, the 5 inode hooks (`filesystem.rs:404-411`), the 2 module-load hooks (`:417-424`); `filesystem::attach` returns `Ok(())` and its caller (`mod.rs:391`) also warns. The error genuinely originates from a verifier reject — `attach_lsm`/`reattach_fresh` do `prog.load(...).with_context(|| "verifier rejected LSM program …")?`. The only fail-closed gate, `revalidate_offsets` (BUG-036), refuses to start **only** on struct-member offset drift — it never checks FUNC_PROTO `vlen`/arity, which is exactly what the verifier checks at load. There's **no aggregate "N of 9 attached" health line** on the deny path (unlike `fim/attach.rs:130-134`). Historical proof this is real, not theoretical: `4a5492c`'s own message records the wrong-arity `inode_setattr` "rejected the program at load … surfaced as 'anti-tamper FS: LSM hook attach FAILED … error=verifier rejected'" with the agent still running. Note: by itself, with correct arg-indexing, all hooks attach and this never fires — its severity is the multiplier it applies to every other T7 sibling (hence High, not Beta-blocker).

**Validate on the 6.8 VM.**
- *Trigger:* **(A)** healthy boot — start the agent with a working build, confirm all nine LSM programs attach. **(B)** force the failure mode without touching this code — rebuild the eBPF half with one deny hook deliberately mis-indexed (e.g. in `agent-ebpf` `inode_rmdir` read `ctx.arg(3)` for `prev_retval` as the 3-arg mainline layout instead of the 6.8 2-arg layout, mirroring `4a5492c`), reinstall (cycle without reboot per `northnarrow-vm-ops`; `nn-admin unlock` if COMBAT trips), restart.
- *Observe:*
  ```
  systemctl is-active northnarrow-agent
  journalctl -u northnarrow-agent -b --no-pager | grep -iE 'freshly attached \+ pinned|reused pinned LSM link|purged stale pin|LSM hook attach FAILED|module-load LSM hook attach FAILED|verifier rejected LSM program'
  ls -1 /sys/fs/bpf/northnarrow/ | grep -cE '^prog_'; ls -1 /sys/fs/bpf/northnarrow/ | grep -cE '^link_'
  bpftool prog show | grep -iE 'lsm|inode_|task_kill|ptrace|kernel_read_file|kernel_load_data'
  ```
- *Expected (A):* `active`; nine attach-disposition lines, zero FAILED/verifier-rejected; both pin counts = 9; bpftool lists all nine LSM progs.
- *Suspected (B):* one `attach FAILED … error=verifier rejected LSM program inode_rmdir`; `prog_inode_rmdir`/`link_inode_rmdir` pins **absent** (counts 8/8); bpftool omits that prog — **yet** `systemctl is-active`=`active`, no fatal exit, no aggregate shortfall line. A root `rmdir` of a PROTECTED_INODES dir would now succeed. The single easy-to-miss WARN is the only signal that a deny is silently absent.

---

### 6. `combat-avail-1` — Watchdog respawn drops `--detect-only` (flag form) → detect-only host silently becomes full-enforcement

- **Severity:** High (downgraded from finder's Beta — see caveat) · **Runtime-observable:** yes · **Sibling of:** T7.10/T7.13 watchdog cascade
- **Primary:** `watchdog/src/main.rs:104-111` (Some(`--agent-bin`) branch) + `:366-396` (`derive_agent_argv`); spawn `watchdog/src/lib.rs:598` (no `env_clear`); derivation `agent/src/main.rs:904-908`; actuator gate `main.rs:1225-1230`
- **Hypothesis:** on crash-respawn the watchdog reconstructs agent argv as `[bin, "--pid-file", pidfile]`, dropping every other flag — most critically `--detect-only` — so the respawned agent runs full-enforcement on a host the operator put in detect-only.

**Confirmed mechanism.** Both respawn branches hard-code `[bin, "--pid-file", agent_pidfile]` and drop all other flags; `spawn_agent` does not `env_clear`, so a `NN_DETECT_ONLY` **env var** survives but a **flag** `--detect-only` does not. `detect_only = ExecutorConfig::from_env() OR cli.detect_only`; a respawned agent with neither flag nor env → `detect_only=false` → `SystemActuator` built enforcing → real kill + real iptables isolation. `git log -S"--detect-only"` over the watchdog returns nothing — never handled. **Severity caveat (why High, not Beta):** the *default* prod unit uses neither flag nor env (already intentionally enforcing — respawn is no regression there), and the *officially-validated* detect-only mechanism is the `NN_DETECT_ONLY=1` systemd drop-in (`DETECT_ONLY_VALIDATION_2026-06-05.md`), which the watchdog **preserves**. The bug bites only an operator who chose the flag form — a real footgun worsened by `config.rs:46-47` labeling the flag "(canonical)", but not the default and not the validated path.

**Validate on the 6.8 VM.**
- *Trigger:* reproduce the flag-only path (the env drop-in is preserved and won't reproduce). First disable any drop-in: `rm -f /etc/systemd/system/northnarrow-agent.service.d/detect-only.conf` and confirm `systemctl show northnarrow-agent -p Environment` shows no `NN_DETECT_ONLY`. Launch the watchdog with `--agent-bin` (exercises the `:104` branch) and the first agent with `--detect-only` as a **flag**. Confirm first-boot detect-only via the **journal banner** (NOT `ps`/argv — the agent hides from `/proc` and `/proc/<pid>/environ` is anti-tamper-blocked). Then `kill -9 $(cat /run/northnarrow/agent.pid)` and wait ~5 s for backoff+respawn.
- *Observe:*
  ```
  journalctl --namespace=northnarrow -u northnarrow-watchdog --since '2 min ago' | grep -iE 'DETECT-ONLY mode active|detect_only=|response executor ready'
  ```
  Then drive the validated COMBAT pair (mass-write + persistence) and `iptables -S NORTHNARROW_COMBAT` (+ `ip6tables -S`).
- *Expected:* the respawned agent re-emits `DETECT-ONLY mode active` + `detect_only=true`; iptables shows "would execute"/"NOT applied", chain absent.
- *Suspected:* first boot shows `detect_only=true`; the respawned agent (later timestamp, new pid) shows **no** detect-only banner and `response executor ready … detect_only=false`; `NORTHNARROW_COMBAT` is populated and offender pids are SIGKILLed.

---

### 7. `at-authz-2` — `agent.sig.key` is in-place-mutable despite PROTECTED_INODES → chain forgery

- **Severity:** High · **Runtime-observable:** yes · **Sibling of:** PROTECTED_INODES modification-only
- **Primary:** `agent/src/anti_tamper/filesystem.rs:119` (key in `ETC_PROTECTED_FILES`); deny set `agent-ebpf/src/inode_protect.rs:293/331/358/408/437`; key load `agent/src/audit.rs:172`/`:208`, boot `main.rs:1198`; verify uses derived pubkey `chainlog.rs:1055/1269`
- **Hypothesis:** the chain-signing key is protected only against unlink/rename/setattr/chattr, not a non-truncating in-place `pwrite`, so a root attacker can substitute the key the agent loads at boot and forge tamper-evident chain entries.

**Confirmed mechanism.** Same 5-hook modification-only enforcement as `at-authz-1`: truncate routes through `inode_setattr` (denied) and `chattr` through `file_ioctl` (denied), but a non-truncating `open(O_WRONLY)`+`pwrite` over the 64-hex key body is denied by **no** hook (the `fim_watch.rs:639-641` comment confirms same-size in-place rewrite never hits `inode_setattr`). `AgentSigningKey::load_or_bootstrap` reads whatever 64-hex body is on disk at boot and `verify_log_set` verifies with the derived pubkey — so a substituted key makes the agent sign **and** verify forged audit/detection/FIM/netflow/canary rows. **Severity caveat (why High, not Beta):** the file is mode `0400` root-readable, so a root attacker already has an equivalent, strictly-undeniable offline forgery path (read the key, sign forged rows offline). The in-place-write is one of two equivalent root vectors against the same root-of-trust, not a unique bypass.

**Validate on the 6.8 VM.** *(Note: write a **valid 64-hex** key — random bytes are rejected by `parse_signing_key` at next boot, which would show a corrupt-key abort, not silent substitution.)*
- *Trigger:* as a root shell **not** in PROTECTED_PIDS, run three contrasting ops on `/etc/northnarrow/agent.sig.key`: (A) in-place valid-key overwrite `conv=notrunc`; (B) `truncate -s0`; (C) `chattr +i`:
  ```
  sudo bash -c 'ORIG=$(cat /etc/northnarrow/agent.sig.key); NEWKEY=$(head -c32 /dev/urandom | xxd -p -c64);
    printf "%s\n" "$NEWKEY" | dd of=/etc/northnarrow/agent.sig.key bs=65 count=1 conv=notrunc 2>/dev/null; echo "A_rc=$?";
    READBACK=$(cat /etc/northnarrow/agent.sig.key); [ "$READBACK" = "$NEWKEY" ] && echo A_substituted=YES || echo A_substituted=NO;
    truncate -s0 /etc/northnarrow/agent.sig.key 2>&1; echo "B_trunc_rc=$?";
    chattr +i /etc/northnarrow/agent.sig.key 2>&1; echo "C_chattr_rc=$?"'
  ```
- *Observe:*
  ```
  journalctl -u northnarrow-agent --since '30 sec ago' | grep -iE 'FsProtectDenial|FS_OP_|EPERM|denied'
  sudo systemctl restart northnarrow-agent; sleep 3
  journalctl -u northnarrow-agent --since '10 sec ago' | grep -iE 'reusing existing agent signing key|signing key.*corrupt|refuse to silently regenerate|pubkey_fp'
  ```
- *Expected:* Op A is **denied** — `A_rc != 0`, `A_substituted=NO`, an `FsProtectDenial`/`FS_OP_*` line appears for the in-place write, exactly as for B (truncate) and C (chattr).
- *Suspected:* Op A **succeeds silently** — `A_rc=0`, `A_substituted=YES`, no denial line (and no FIM event — not in the watch set), while B (setattr) and C (ioctl) **are** denied. After restart the agent logs `reusing existing agent signing key` with the attacker-chosen `pubkey_fp` — the chain root-of-trust silently replaced; every subsequent chain row verifies under the attacker-known key.

---

### 8. `chain-audit-torn-1` — `audit.log` has no torn-tail recovery → one partial write = auditing OFF for the whole boot

- **Severity:** High · **Runtime-observable:** yes
- **Primary:** `agent/src/audit.rs:459-460` (`from_str(&line)?` in `read_tail_hash`); non-fatal handling `main.rs:1200-1205`; emit short-circuit `admin_socket.rs:616-618`, `combat/evidence.rs:74/109`; the primitive that solves this `chainlog.rs:844` (`recover_tail`)
- **Hypothesis:** a torn final line in the non-rotating `audit.log` permanently disables the audit log for the boot (admin + COMBAT ops unrecorded) with no automatic repair.

**Confirmed mechanism.** `read_tail_hash` parses every line into a full `AuditEntry` and `?`-propagates on any unparseable line; `BufRead::lines()` yields a newline-less trailing fragment, so a torn final write produces an error that propagates up through `AuditLog::open`. `main.rs:1200-1205` treats that as **non-fatal**: sets `audit_log=None` and warns "COMBAT stage transitions + admin ops UNAUDITED this boot". Downstream `emit_audit_for` and `AuditEvidence::record_stage` short-circuit on `None`, so every admin op and every COMBAT stage transition that boot is unaudited (the deferred dispatch integration has since landed, so impact is current). The chainlog primitive `recover_tail` is O(tail) torn-fragment-robust with a `TornTailRepaired` attestation — `audit.rs` was never migrated. Repair is hard: `audit.log` is in `ETC_PROTECTED_FILES` → an `ftruncate` to fix the torn byte routes through `inode_setattr` (a live deny hook), so an operator can't trivially repair it while protection is pinned. `git blame`: `audit.rs:444-464` original (`143e88f`, 2026-05-19); no `recover_tail` ever added.

**Validate on the 6.8 VM.**
- *Trigger:* inject a torn final append (a raw `>>` is not blocked — `file_open` is observe-only — so this works on a live box):
  ```
  sudo wc -l /etc/northnarrow/audit.log    # pre-state
  printf '{"ts":"2026-06-09T00:00:00.000000Z","agent_id":"00000000000000000000000000000000","op":"unl' | sudo tee -a /etc/northnarrow/audit.log >/dev/null
  sudo systemctl restart northnarrow-agent
  ```
- *Observe:*
  ```
  sudo journalctl -u northnarrow-agent --since '-2min' | grep -E 'audit log open failed|UNAUDITED'
  sudo tail -n1 /etc/northnarrow/audit.log
  nn-admin force-posture observing       # an audited admin op (force-posture role)
  sudo tail -n1 /etc/northnarrow/audit.log; sudo wc -l /etc/northnarrow/audit.log
  ```
  Positive control: repeat the whole sequence on a clean (untorn) `audit.log` to confirm force-posture appends a row when `audit_log` is `Some`.
- *Expected:* with recover_tail-style repair, no `UNAUDITED` line; the fragment is discarded/repaired; after `force-posture` the tail is a new signed row, line count +≥1.
- *Suspected:* journal shows `audit log open failed — … UNAUDITED this boot`; `audit_log=None` for the session; after `force-posture` the tail is unchanged (still the truncated `…"op":"unl` fragment) and `wc -l` unchanged. The torn file can't be truncated to fix without clearing LSM protection. The clean-log control **does** append a row, isolating the failure to the torn-tail open path.

---

### 9. `catchall-3` — R004 systemd-executor exemption is `argv[0].ends_with` + spoofable `parent_comm` → fileless-exec kill bypass

- **Severity:** High (raised from finder's Medium) · **Runtime-observable:** yes · **Sibling of:** comm-trust silent bypass (contradicts the exe-over-comm discipline in `net.rs`/`combat`)
- **Primary:** `agent/src/decision/rules/r004_exec_from_proc_self_fd.rs:69-73` (`is_systemd_executor_path`) + `:83-88` (`is_systemd_executor_launch`); comm source `agent-ebpf/src/main.rs:200-208` + `common/src/model.rs:322`; contrast discipline `net.rs:449-454`
- **Hypothesis:** the exemption that suppresses R004 (Critical `KillProcessTree` on `/proc/self/fd` exec) accepts any `argv[0]` ending in `/systemd-executor` and accepts `parent_comm == "systemd"` (PR_SET_NAME-spoofable), so an attacker dodges the memfd-exec kill more easily than the docs claim.

**Confirmed mechanism.** `is_systemd_executor_path` returns true for the two canonical paths **or** any `argv0.ends_with("/systemd-executor")` (matches attacker-controlled `/tmp/x/systemd-executor`). `is_systemd_executor_launch` ANDs that with `ppid == 1 || parent_comm == "systemd"`. `parent_comm` is the kernel `comm` decoded straight from `real_parent->comm` — the `prctl(PR_SET_NAME)`-spoofable value the codebase **elsewhere explicitly refuses to trust** for kill-immunity (`net.rs:449-454`: "NEVER on `comm` … a comm check would hand a forged resolver KILL-IMMUNITY"). `argv` is read from the process's own `mm->arg_start`, so `argv[0]` is attacker-set at `fexecve`. The bypass needs **neither** a re-parent to PID 1 (the comm-OR arm suffices) **nor** the exact canonical path (the `ends_with` arm suffices) — strictly wider than the residual evasion the module docs acknowledge. The one green test (`:259-270`) only exercises `parent_comm="bash"`, never the `"systemd"` spoof. `git blame`: lines 69-89 from `f6053af` (the T10.6.5 fix that introduced the exemption); no remediation since. (Not full Beta: the attacker must already have local code-exec to memfd-exec.)

**Validate on the 6.8 VM.**
- *Trigger:* as a **non-root** user, a 2-process PoC. Parent P: `prctl(PR_SET_NAME,"systemd",0,0,0)` then `fork()`. Child C: `int fd=memfd_create("x",MFD_CLOEXEC)`; write a trivial `while(1) sleep(60)` ELF to `fd`; `char *argv[]={"/tmp/evil/systemd-executor",NULL}; fexecve(fd,argv,environ)`. (R004 checks the **parent's** comm, so `prctl` must run in P; the comm-OR arm alone satisfies `is_systemd_executor_launch` — no re-parent to PID 1 needed.) Control: identical loader but `argv[0]="/proc/self/fd/3"` and no `prctl`, to prove R004 is live.
- *Observe:*
  ```
  sudo journalctl -u northnarrow --since '2 min ago' -o cat | grep -E 'R004_ExecFromProcSelfFd|memfd-style exec detected|KillProcessTree'
  ps -o pid,ppid,comm,args -p <child_pid> 2>/dev/null || echo 'child gone (killed)'
  ```
- *Expected:* the control trips R004 (`KillProcessTree`, child killed); a correct rule would **also** trip on the spoofed child (a genuine non-systemd memfd exec is fileless execution regardless of forged `argv[0]`/`comm`).
- *Suspected:* the control trips R004 and kills its child (proving the rule + box work), but the **exploit** run emits **no** R004 verdict and the spoofed child keeps running — `parent_comm="systemd"` + `argv[0]` ending `/systemd-executor` suppressed the Critical `KillProcessTree`. The differential between the two runs is the bug signal.

---

## Medium

### 10. `abi-tcpconnect-srcport-1` — TCP `src_addr`/`src_port` emitted as 0 → `flow_id` hashed over a zeroed source half

- **Severity:** Medium (raised from finder's Low) · **Runtime-observable:** yes
- **Primary:** `agent-ebpf/src/tcp_connect.rs:152-180` (src never written); discard `agent/src/net/drain.rs:376-382` (`TcpCloseInfo` has no src fields) + `flow_tracker.rs:97-106`; flow_id over zeros `flow_tracker.rs:359-381`; persisted `drain.rs:193-194`; close-side **does** read real src `tcp_close.rs:111/152-156`
- **Hypothesis:** `flow_id` and persisted src fields use a zeroed source half, breaking the §4.1 reproducible-flow-id promise and cross-host correlation.

**Confirmed mechanism.** `try_tcp_connect_v4/v6` write only family/dst/sk_ptr; `src_addr`/`src_port` stay zero (correct — the local end is unbound at `tcp_v4_connect` entry). The bug is a **userland discard**, not a kernel limit: `tcp_close` *does* read `skc_rcv_saddr`/`skc_num`, and `NetFlowCloseRaw` carries both — but `drain.rs:376-382` builds `TcpCloseInfo` with only `end_ns/corr_id/bytes/close_reason`, so the real close-time source is thrown away; `on_tcp_close` then derives both the emitted `src_addr`/`src_port` **and** `canonical_flow_id` from the zeroed pending values, and `netflow.jsonl` rows get `0.0.0.0`/`0`. The UDP path (`drain.rs:398-400`) correctly uses the real source — only TCP drops it. The §4.1 doc-comment (`flow_tracker.rs:345-351`) promises a 5-tuple-reproducible, cross-host-correlatable `flow_id`, which is false for TCP. Tests pass because `connect_fixture` hand-feeds a non-zero src the real eBPF never produces. (Medium not Beta: no hook fails, internal connect↔close correlation still works via `corr_id`; but it's broad — every TCP row — and breaks the advertised forensic contract. Fix shape is already proven by the UDP path.)

**Validate on the 6.8 VM.**
- *Trigger:* one outbound TCP connection that opens and cleanly closes so a row is appended on close: `curl -s -o /dev/null https://1.1.1.1 ; sleep 1`.
- *Observe:*
  ```
  tail -1 /var/lib/northnarrow/netflow.jsonl | jq '{src_addr:.payload.src_addr, src_port:.payload.src_port, dst_addr:.payload.dst_addr, dst_port:.payload.dst_port, flow_id:.payload.flow_id, proto:.payload.proto}'
  ```
- *Expected:* a proto-6 row whose `src_addr` is the host's real outbound IP and `src_port` is curl's real ephemeral port; `flow_id` reproducible as `SHA-256(start_ns‖family‖src‖sport‖dst‖dport‖proto‖pid)[..16]` per §4.1.
- *Suspected:* proto-6 row with `src_addr=="0.0.0.0"`, `src_port==0` (dst correct: `1.1.1.1`/`443`), so the persisted `flow_id` is over a zeroed source and not reproducible. Cross-check: a UDP row (from a DNS lookup) in the same file **does** carry a real src, isolating the defect to the TCP close path's `TcpCloseInfo` discard.

---

### 11. `posture-3` — Mass-write arm has no `loginuid` carve-out → PAM user-session bursts escalate to ENGAGED

- **Severity:** Medium · **Runtime-observable:** yes · **Sibling of:** T7.13
- **Primary:** `agent/src/posture/triggers.rs:686-691` (gate); asymmetric counterpart `triggers.rs:560` (`sensitive_file_access` loginuid carve-out); `lineage.rs:480` (`has_valid_loginuid`, doc-bounded to sensitive-file only)
- **Hypothesis:** the `loginuid` signal that proves a benign PAM-mediated session is consulted only by `sensitive_file_access`, never by the mass-write arm, so a `systemd --user`/PAM-session helper that mass-writes (lineage walks to PID 1, never through an AUTH_BINARY) still escalates.

**Confirmed mechanism.** The mass-write arm gates only on `is_auth_mediated || is_system_daemon_mediated || is_npm_cli_writer` — none consults `loginuid` (a repo-wide `-S` search shows `has_valid_loginuid` in no other production arm; the BUG-018 commit itself says the carve-out applies only to `SensitiveFileAccess`). A `systemd-user@<uid>.service` helper's lineage walks to PID 1 without crossing `AUTH_BINARY_EXES`, so `is_auth_mediated=false`. `MASS_WRITE_CARVEOUT_PREFIXES` is only `/sys/`,`/proc/`,`/run/systemd/`,`/run/log/journal/` — `/run/user/<uid>/` is deliberately counted. `file_open.rs` reports all `openat` with no path filter, so a 25-write burst → 25 `FileOpen` events same focal pid > `MASS_WRITE_MIN=20` → `ConfirmedIntrusion_MassWrite`. Single-vector caps at ENGAGED (`mod.rs:331-338`); reaches COMBAT only via the `posture-1`/`posture-2` chaining — hence Medium. (A blanket `loginuid` fallback would re-open the compromised-user-session detection BUG-018 defends; the correct fix is narrower.)

**Validate on the 6.8 VM.**
- *Trigger:* log in interactively as uid 1000 so `pam_loginuid` sets a valid loginuid (`cat /proc/$$/loginuid` = 1000, not 4294967295). From a plain session shell (verify lineage walks to PID 1, not sudo/su), burst 25 write-opens to `/run/user/1000` from the same pid in <60 s: `for i in $(seq 1 25); do printf x > /run/user/1000/nn-burst-$i; done`. Control (must not fire): same burst to a carve-out prefix `for i in $(seq 1 25); do printf x > /run/systemd/nn-ctl-$i 2>/dev/null; done`.
- *Observe:*
  ```
  journalctl -u northnarrow-agent --since '2 min ago' --no-pager | grep -E 'ConfirmedIntrusion_MassWrite|POSTURE TRANSITION|trigger=ConfirmedIntrusion'
  nn-admin status 2>/dev/null | grep -iE 'posture|level|state'
  ```
- *Expected:* with a symmetric loginuid fallback the PAM-authenticated burst is exempt — no `ConfirmedIntrusion_MassWrite`, posture stays OBSERVING; the `/run/systemd` control also stays silent.
- *Suspected:* the `/run/user/1000` burst emits `trigger=ConfirmedIntrusion_MassWrite focal_comm=bash … count>=20 threshold=20` and a POSTURE TRANSITION to ENGAGED; the `/run/systemd` control stays silent — confirming the fire is the carve-out asymmetry, not noise.

---

### 12. `combat-avail-2` — NEUTRALIZE kill-tree guards only attributed offenders, not `/proc` descendants

- **Severity:** Medium · **Runtime-observable:** yes · **Sibling of:** `protected.rs` SSH/watchdog guard scope
- **Primary:** `agent/src/response/kill.rs:126` (per-descendant `kill_process(child, protected)` with the minimal set); caller `combat/actuator.rs:130`; guard applied only to offenders `combat/mod.rs:541/596`; minimal set `executor.rs:48-51`; the guard that knows sshd/watchdog `protected.rs:199-220` (not consulted by the kill path)
- **Hypothesis:** the ladder's host-critical guard (`split_protected` → `ProtectedProcs`) is applied only to the attributed offender set, but NEUTRALIZE issues `KillProcessTree` which walks `/proc` and SIGKILLs every descendant using only `{0,1,2,own_pid}` — which omits sshd and the watchdog — so a guarded descendant of an offender is killed unguarded.

**Confirmed mechanism.** `split_protected` runs over the attributed `offenders` only, then passes `actionable` to `neutralize`, which calls `kill_process_tree`; that snapshots `/proc` descendants and kills each via `kill_process(child, protected)` with `protected={0,1,2,own_pid}` — there is **no** `protected_reason` re-check inside the walk (it appears only at the ladder level). The `SystemProtectedProcs` guard that knows sshd/watchdog is a separate trait object never consulted by the kill path. `protected.rs:16-19` itself notes the executor set "does not carry the watchdog PID, so absent this guard the ladder could kill it" — yet the guard isn't applied to descendants. `kill_process` also bypasses `PID_PROTECTION_FLOOR` (that check is in `execute`, not `kill_process`). `git blame`: `kill.rs` untouched since Tappa 3 (`11df283`). **Why Medium:** for sshd/watchdog to be killed it must be a `/proc` **descendant** of an offender; in real systemd topology both are PID 1 children (ancestors of offenders), and re-parenting moves orphans toward init — so the trigger is narrow.

**Validate on the 6.8 VM.**
- *Trigger:* make a guarded process a `/proc` descendant of an attributed offender. E.g. parent P = `sh -c 'sleep 3; /usr/sbin/sshd -D -p 2222 & wait'` so child C (`exe=/usr/sbin/sshd`, a guarded `SshService`) is a direct child of P. Record with `ps -o pid,ppid,comm,exe -p <P>,<C>`. Force COMBAT attributing **P** as the offender (`sudo nn-admin force-combat`, or feed a `ProcessSpawn` for P); confirm ladder at INVESTIGATE with `offenders=[P]`. Let the 30 s INVESTIGATE window elapse so `tick()` drives NEUTRALIZE.
- *Observe:*
  ```
  journalctl --namespace=northnarrow -u northnarrow-agent --since '2 min ago' | grep -E 'NEUTRALIZE|killed offending process tree|refusing to kill host-critical|spared'
  ps -o pid,ppid,comm,exe -p <C> 2>/dev/null || echo 'C is DEAD (killed)'
  ```
- *Expected:* the guard is consulted for every PID actually SIGKILLed — C is **spared** (a "refusing to kill host-critical"/"spared" line for C, `ps` still lists C), and the episode escalates to ISOLATE because a guarded process couldn't be neutralized.
- *Suspected:* the single actuator line `NEUTRALIZE: killed offending process tree pid=P children=N` with **no** "spared" line for C, and `ps -p <C>` reports C dead — a guarded `SshService` SIGKILLed unguarded as a tree descendant.

---

### 13. `chain-protect-1` / `at-authz-3` — `detections.jsonl` + `status_events.jsonl` not in PROTECTED_INODES  **[KNOWN-b — CONFIRMED]**

- **Severity:** Medium · **Runtime-observable:** yes · **Sibling of:** Tappa 9 detection store / subdir gap
- **Primary:** `agent/src/anti_tamper/filesystem.rs:175` (`STATE_PROTECTED_FILES` — six bare basenames, no detections entries); join failure `:496-499` (`state_dir.join(name)` can't descend into the subdir); subdir path `detection_store.rs:68/78`; gap self-documented at `filesystem.rs:875-885`; eBPF exact-match `inode_protect.rs:175`
- **Known item (b), confirmed precisely.** `STATE_PROTECTED_FILES` holds six top-level basenames; `register_state_files` does `state_dir.join(name)` with `state_dir=/var/lib/northnarrow`, so it cannot reach `/var/lib/northnarrow/detections/`. Both chains live in that subdir; the subdir inode itself is never registered, and `chattr +i` is applied only to `STATE_DIR`, not the subdir. The deny hooks check the target (and parent-dir) inode by exact `(dev,ino)`; an inode absent from PROTECTED_INODES is never defended. So `rm`/`truncate` of either chain by root is **not** denied — no EPERM, no `ANTI-TAMPER DENIAL`. The chains remain Ed25519-signed (tampering is *detectable* post-hoc as a chain break), and the dir is `0700` — hence Medium, not Beta. **Two downstream consequences:** (i) erasure of audit-grade incident/triage history; (ii) removing `detections.jsonl` + its `.NNNNNN` archives sends `max_detection_id` (`detection_store.rs:1055` → `seed_last_id`) back to 0, so `dispatch_detection_set_status`'s `id > max_id` guard (`admin_socket.rs:3007`) then rejects every valid id as not-found. `git log`: only `dfeb29d` (9.0.c) touches these names; no fix.

**Validate on the 6.8 VM.** *(Non-destructive triad — a real deny on the control escalates to COMBAT, so don't truncate a registered control on a live box.)*
- *Trigger:* agent running with anti-tamper attached; ensure both chains are non-empty (fire ≥1 detection; run one `nn-admin detections set-status`). `fim_drift.jsonl` is the positive control (it **is** registered).
- *Observe:*
  ```
  # 1) which state files registered this boot (buggy state = detection files ABSENT):
  journalctl -u northnarrow-agent -b | grep -E 'register(ed)? in PROTECTED_INODES|FIM log registered|FIM-log registration complete'
  # 2) map keys — convert each file's stat dev to kernel MKDEV form before comparing (the map stores s_dev MKDEV, stat %d is stat-form):
  for f in /var/lib/northnarrow/fim_drift.jsonl /var/lib/northnarrow/detections/detections.jsonl /var/lib/northnarrow/detections/status_events.jsonl; do
    dev=$(stat -c '%d' "$f"); maj=$(((dev>>8)&0xfff)); min=$(((dev&0xff)|((dev>>12)&0xfff00))); kdev=$(((maj<<20)|min));
    printf '%s ino=%s kernel_dev=%s\n' "$f" "$(stat -c '%i' "$f")" "$kdev"; done
  bpftool map dump pinned /sys/fs/bpf/northnarrow/PROTECTED_INODES
  # 3) immutability:
  lsattr -d /var/lib/northnarrow /var/lib/northnarrow/detections; lsattr /var/lib/northnarrow/detections/*.jsonl
  ```
- *Expected:* both detection files appear in the registration lines and their `(kernel_dev,ino)` appear as map keys, like `fim_drift.jsonl`; the subdir shows the `i` attribute.
- *Suspected:* `registered=6 total=6`, registration lines only for the six top-level files; the detection files' `(kernel_dev,ino)` are **absent** from the map; `lsattr` shows the subdir/files have no `i` flag. Implication (do **not** run live): an in-place `truncate -s0` of either detection file routes through `inode_setattr` but finds no map entry and is **not** denied, whereas the same op on `fim_drift.jsonl` is denied with EPERM. *(Note: the journal token for a real deny is `ANTI-TAMPER DENIAL`, `main.rs:2398` — not the source enum name `FsProtectDenial`.)*

---

### 14. `chain-persist-1` — set-status persist failure is wire-indistinguishable from "detection not found"  **[KNOWN-a — CONFIRMED]**

- **Severity:** Medium · **Runtime-observable:** yes (agent journal only) · **Sibling of:** 9.0.c known item (a)
- **Primary:** `agent/src/admin_socket.rs:3035` (append-failure → `fail_set_status(UnknownOperation)`) vs `:3009` (id-range guard → same); CLI map `admin_cli.rs:2007` (`UnknownOperation → NotFound`); render `nn_admin.rs:2535` (exit 9); append fsync path `chainlog.rs:298/306/532`
- **Known item (a), confirmed precisely.** `dispatch_detection_set_status` maps two distinct outcomes to one wire result: the id-range guard (`extra.id==0 || extra.id>max_id`) **and** the `log.append(event)` error branch both return `AdminResult::UnknownOperation`. The CLI renders both as exit code 9 with the merged message "change not applied — no detection with that id, or the server could not persist it". The append failure is genuinely reachable — `append_and_fsync` re-opens + `sync_all`s on every append, so disk-full/EIO/EROFS/read-only-remount returns `Err`. So an operator script keying on exit code 9 cannot distinguish "id never existed" from "the change silently did not persist". **Why Medium (and the difference from the refuted `at-authz-4`):** the failure is fsync-backed and **propagating** (not silent success), and the human-readable stderr **does** name persistence as a cause + directs to the agent log — so this is a machine-distinguishability gap for automated triage, not silent data loss. *(Verifier note: the finder's suggested `AdminResult::Unavailable` variant does **not** exist today; a fix must add a variant, appended to preserve postcard discriminants, plus a CLI arm + exit code.)*

**Validate on the 6.8 VM.**
- *Trigger:* ensure ≥1 detection exists (`max_id>=1`). **Case A (bad id):** set-status against an id above max. **Case B (real persist failure, valid id):** make the chain append fail — cleanest is `sudo mount -o remount,ro /var/lib/northnarrow` (append re-opens under EROFS), or `fallocate -l $(df --output=avail -B1 /var/lib/northnarrow | tail -1) /var/lib/northnarrow/_fill` for ENOSPC — then set-status against valid id 1. Clean up (`remount,rw` / `rm _fill`).
- *Observe:*
  ```
  nn-admin detection-set-status 99999 resolved; echo "caseA_exit=$?"
  nn-admin detection-set-status 1 resolved; echo "caseB_exit=$?"
  journalctl -u northnarrow-agent --since '-2min' | grep -E 'detection-set-status: (id out of range \(not found\)|status-event append failed \(change not persisted\))'
  ```
- *Expected:* a persist failure (B) is distinguishable **by the caller** from an unknown id (A) — a different `AdminResult`/exit code, so a script can tell "lost write, retry" from "wrong id".
- *Suspected:* both A and B exit **9** with the identical stderr; only the **agent journal** differs (`id out of range (not found)` for A vs `status-event append failed (change not persisted)` for B). A caller with only stdout/stderr/exit-status cannot tell a lost triage write from a wrong id.

---

### 15. `catchall-1` — `DnsBurstWindow`/`BeaconWindow` outer HashMaps never evict idle keys → unbounded memory growth

- **Severity:** Medium (lowered from finder's High) · **Runtime-observable:** yes (slow ramp) · **Sibling of:** T7 unbounded-growth (note: not a true kernel/6.8 sibling — platform-independent)
- **Primary:** `agent/src/decision/rules/net.rs:170/180-189` (`DnsBurstWindow.per_pid`) + `:235-249` (`BeaconWindow.per_flow`); contrast `net.rs:626-627` (`DnsQnameDedupWindow` does `retain`-prune) + `flow_tracker.rs:154` (explicit eviction cap)
- **Hypothesis:** NN-L-NET-005 (per-PID TXT/NULL counter) and NN-L-NET-013 (per `(pid,dst)` beacon timer) only trim their inner `VecDeque`; the outer HashMap entry is never removed, so the maps grow as PIDs churn and destinations vary.

**Confirmed mechanism.** `DnsBurstWindow::observe` does `entry(pid).or_default()`, pops only deque-front entries >60 s old, and never removes a pid whose deque emptied. `BeaconWindow::observe` does `entry((pid,dst)).or_default()`, trims the inner deque, but never deletes the `(pid,dst)` key. Both are created once at boot and held for the agent's lifetime via `Arc<Mutex<_>>`; no external GC/`retain`/`clear` touches them. `observe()` is reached on every matching event. The contrast is load-bearing: `DnsQnameDedupWindow` `retain`-prunes its outer map every call and `FlowTracker` has an explicit eviction cap — proving the author knows the pattern; these two are the outliers, and the module-header "without unbounded growth" comment only covers the inner deque. **Why Medium not High:** `per_pid` is u32-PID-keyed and gated on rare TXT/NULL qtypes (barely a leak); `BeaconWindow.per_flow` is the genuinely unbounded one (per distinct dst IP per pid), but each entry is tiny (~key + a `VecDeque` of ≤8 `u64`), so millions of keys is tens-of-MB over long uptime. `git blame`: both original, never patched.

**Validate on the 6.8 VM.**
- *Trigger:* drive the `BeaconWindow` leak with a **non-allowlisted comm** and high destination cardinality (NN-L-NET-013 short-circuits via `allowlist.contains(&nf.comm)` **before** `observe()`, so do **not** use curl/wget/ssh — all in `NETFLOW_COMM_ALLOWLIST_DEFAULTS`; a bash `/dev/tcp` subshell has `comm=bash`). `observe()` is reached on the connect attempt regardless of an answer, so non-listening RFC1918 IPs are fine:
  ```
  for i in $(seq 1 50000); do o2=$((i/256)); o3=$((i%256)); timeout 1 bash -c "exec 3<>/dev/tcp/10.$o2.$o3.7/4444" 2>/dev/null; done
  ```
  Repeat the loop 3–4× over ~30–60 min so the cumulative key set far exceeds the live working set.
- *Observe:* sample agent RSS and diff start vs end (VmHWM is the robust monotonic signal):
  ```
  PID=$(pgrep -f northnarrow-agent); while :; do echo "$(date +%T) RSS=$(awk '/VmRSS/{print $2}' /proc/$PID/status) HWM=$(awk '/VmHWM/{print $2}' /proc/$PID/status)"; sleep 30; done | tee /tmp/nn_rss.log
  ```
- *Expected:* after the live working set is reached, VmRSS plateaus and VmHWM stops climbing across repeated churn passes — idle/aged keys are reclaimed; steady-state is bounded by the concurrent working set.
- *Suspected:* VmHWM climbs monotonically and never recedes even after the host idles — memory tracks the **cumulative** distinct `(pid,dst)` count since boot. A second 50k-loop with **new** IPs adds ~50k more permanent keys.

---

## Low

### 16. `ebpf-lsm-4` — Stale 2-arg doc for `inet_csk_listen_start` (kprobe, latent)

- **Severity:** Low · **Runtime-observable:** NO (static BTF/source diff only) · **Sibling of:** probe arity drift
- **Primary:** `agent-ebpf/src/inet_csk_listen.rs:3-6` (doc claims `(struct sock *sk, int backlog)`) + `:13-14` ("validated 6.8.0-117"); read site `:46-48` (only `ctx.arg(0)`); attach `multiplexer.rs:195` (`attach_kprobe`)
- **Confirmed (doc-only, no active bug).** The kernel removed `backlog` in 5.10, so on 6.8.0-124 the function is `inet_csk_listen_start(struct sock *sk)` (BTF `FUNC_PROTO vlen=1`); the doc is factually stale (and the validation note says -117, kernel is -124). `try_inet_csk_listen_start` reads only `ctx.arg(0)=sk`, so there's **no** active bug. **Crucially, do not bucket this with the `inode_setattr` arity class:** this is a `#[kprobe]`; aya's `ProbeContext::arg(n)` reads `pt_regs` CPU registers and never consults BTF `FUNC_PROTO`, so a wrong arity produces no verifier rejection / no silent non-attach — at worst a future `arg(1)` read would fetch a stale register (RSI) at runtime. Pure latent documentation footgun. Fix = one-line doc correction (drop `, int backlog`, bump note to -124).
- **Validate:** static only — `bpftool btf dump file /sys/kernel/btf/vmlinux format raw | grep -A2 "FUNC 'inet_csk_listen_start'"` shows `vlen=1` (single `sk` param), contradicting the doc; `grep -n 'ctx.arg' agent-ebpf/src/inet_csk_listen.rs` must show only `arg(0)`. There is **no runtime signal** — the agent behaves identically at any arity since it reads only `arg(0)`.

### 17. `abi-filename-trunc-1` — Exec path ≥256 B truncated with no guaranteed NUL (forensic-only today)

- **Severity:** Low · **Runtime-observable:** yes (only the stored string differs) · **Sibling of:** T7 fixed-buffer off-by-one
- **Primary:** `agent-ebpf/src/main.rs:144-169` (`f_len` clamp to `FILENAME_LEN=256`, `bpf_probe_read_kernel_buf`, NUL-fill only `[f_len..256]`); userland `common/src/wire/mod.rs:814-816` (`cstr_lossy` returns the 256-byte prefix); stored via `detection_store.rs:292-293` (`exe`)
- **Confirmed mechanism, impact corrected to forensic-only.** When the true path length-incl-NUL exceeds 256, `f_len==256`, the fill range is empty, and the buffer holds 256 non-NUL bytes with no terminator; `cstr_lossy` returns the full truncated prefix (no crash). **But the claimed security impact does not exist today:** every filename-based `ProcessSpawn` rule is **prefix-anchored** (R001 `/tmp/`, R002 `/dev/shm/`, R010 webroots, R017 shell prefixes, R008 `/home/`), and truncation drops the **end** — so a >256 B exec under `/tmp` still fires R001. R018's `.ko` match uses a separate wire struct. `exec_check.rs` uses the NUL-terminating `…_str_bytes` and feeds no rule. So no deny/match is defeated — only the recorded string is truncated. **Latent footgun:** a future suffix/basename rule on `ProcessSpawn.filename` would become a real >256 B bypass. Inconsistency worth noting: `main.rs` (kernel_buf, no NUL) vs `exec_check.rs` (str-read, terminates).
- **Validate:** build a binary at a `/tmp/<250 a's>/x` path (total ~257 B) so it fires R001 and a record is written; `nn-admin detections | tail -5` and inspect `exe`/`event_filename`. **Expected:** the complete 257-byte path ending `/x`. **Suspected:** exactly 256 bytes ending mid-path (last byte an `a`, `/x` chopped); `printf '%s' "$exe" | wc -c` = 256. The rule still fires (prefix intact) — proving forensic-only, not a detection bypass.

### 18. `chain-genesis-residue-1` — Never-rotated (seq-0) detection chain can be wiped and a fresh genesis file still verifies

- **Severity:** Low · **Runtime-observable:** NO (`verify_log_set` has no production caller) · **Sibling of:** BUG-026 genesis-root residue
- **Primary:** `agent/src/chainlog.rs:1076` (`expected_prev=GENESIS` when `earliest_retained_seq==0`) + `:1064`/`:1114`/`:1136-1140`; low rotation cap `detection_store.rs:81-94`; depends on entry 13
- **Confirmed mechanism, but runtime-unreachable.** For a never-rotated chain there are no `.NNNNNN` archives, so the meta-chain branch is skipped and `expected_prev` stays GENESIS; `verify_one_file` accepts an empty/forged-genesis active file as `Ok`. The detection chains have a low cap and may never rotate, so seq-0 is the normal state — and (entry 13) they're not inode-protected, so a root attacker can wipe `detections.jsonl` and a fresh genesis-rooted (forged-but-self-consistent) file still verifies. **However:** `verify_log_set` has **zero production callers** (every non-test reference is in `#[cfg(test)]`); `nn-admin audit verify` targets the **audit** log via `crate::audit::verify_chain` (a different single-file chain); and the production read path `read_last_n` does no verification. So there's no live-VM signal — demonstrable only via a bespoke compiled harness or the existing unit tests. Genuine BUG-026 sibling, but a hardening gap in an unused-at-runtime verifier.
- **Validate:** no shipped command exercises this — a one-off harness calling `chainlog::verify_log_set::<DetectionRecord>(…)` is required. Populate the chain, confirm no archives exist, stop the agent, `sudo truncate -s 0 /var/lib/northnarrow/detections/detections.jsonl`, re-run the harness. **Suspected:** returns `Ok(LogSetReport{ earliest_retained_seq:0, archives_verified:0, total_records:0 })` — identical to a fresh box — and a forged replacement likewise returns `Ok`. The wipe is silent on the live box (no prod path invokes this verify).

### 19. `catchall-4` — `DriftRateLimiter` uses `std::sync::Mutex` + `.expect("poisoned")` despite a doc claiming `parking_lot`

- **Severity:** Low · **Runtime-observable:** NO · **Sibling of:** —
- **Primary:** `agent/src/fim/drain.rs:72` (`use std::sync::Mutex`), `:257-261` (doc claims `parking_lot::Mutex` "no poisoning"), `:307` + `:350` (`state.lock().expect("DriftRateLimiter mutex poisoned")`)
- **Confirmed doc/impl divergence, no live failure.** The struct doc says `parking_lot::Mutex` chosen "for fairness + no poisoning (a panicked drain task shouldn't lock out a future restart)", but the field is `std::sync::Mutex` and both lock sites call `.expect` (the std Result API; parking_lot's `lock()` returns the guard directly and wouldn't type-check). So the implementation has the exact poison-panic semantics the comment says were avoided. **But it can never fire today:** both critical sections are panic-free (guarded `u32` decrements; `checked_sub().unwrap_or(0)`), and there's no `catch_unwind`. Pure documentation-accuracy / latent future footgun (would bite if a future change adds a panicking op inside the lock). Fix: switch the field to `parking_lot::Mutex` (match the doc) or correct the doc to `std::sync::Mutex` (lower-risk).
- **Validate:** source-only — `grep -n 'use std::sync::Mutex' agent/src/fim/drain.rs && grep -n 'state.lock().expect' agent/src/fim/drain.rs`. A FIM-drift burst exceeding the per-minute caps produces `rate_limit:tier_high`/`tier_medium` suppression but **never** a poison-panic line — expected and suspected are indistinguishable at runtime, which is why `runtime_observable=false`.

---

## Uncertain — require a VM fire-test to confirm or refute

### U1. `abi-filefree-1` — `file_free_security` close-emit hook may not fire with a readable `f_inode` on 6.8

- **Claimed Medium · Runtime-observable: yes · Verdict: UNCERTAIN**
- **Primary:** `agent-ebpf/src/fim_watch.rs:689` (`fim_close_emit_observe` on `file_free_security`); arity/read at `:695-697`/`:368`; comment flags this as VM-validation-pending `:684-688`; attach-failure WARN `agent/src/fim/attach.rs:120-127`
- **Why uncertain (the finder over-claimed; two sub-claims refuted, one open).** This hook is the **only** emitter of `FimOp::Modified` for an `O_APPEND`/same-size in-place rewrite (the BUG-023 class). (1) "Attach silently fails on the void hook" — **refuted**: `BUG_CATALOG_DESIGN.md:1174` says `bpf_lsm_file_free_security` is confirmed BPF-attachable on this kernel's BTF, and even an attach failure is **not** silent (`attach.rs:120-127` logs a WARN). (2) Code correctness is fine: arity matches (1-arg `file`, reads `arg(0)`), `f_inode` read via the same validated offset as the working `file_open` hook, gated on the `FIM_DIRTY_INODES` mark. (3) **The genuinely open question:** does `file_free_security` fire at last-`fput` with a still-readable `f_inode` under the BPF-LSM trampoline? The source comment + catalog flag exactly this as unproven (with `__fput`-fexit / `filp_close`-fexit named as a ~2-line fallback). On the kernel, `security_file_free(file)` runs from `__fput` while the struct is intact, which leans **toward** the hook being fine — but it's unproven, hence a fire-test, not a confirmed defect.

**Fire-test on the 6.8 VM.**
- *Trigger:* first decouple attach from fire — `journalctl -u northnarrow-agent -b | grep -iE 'fim_close_emit_observe|file_free_security'`. As a **non-family** root shell (not agent/watchdog), against a stable WATCHED_PATHS file (`/etc/sudoers`, `/root/.ssh/authorized_keys` are v1 defaults): (A) `printf 'x\n' >> /root/.ssh/authorized_keys` (`O_APPEND`); (B) `dd if=/dev/zero of=/etc/sudoers bs=1 count=1 seek=0 conv=notrunc 2>/dev/null` (same-size in-place, no metadata change); (C) control: rewrite identical bytes (must yield no drift). Do **not** chmod/chown/rename/resize between writes (would fire `inode_setattr` and mask the result).
- *Observe:*
  ```
  sudo bpftool prog show | grep -iE 'lsm.*fim_close_emit|fim_close_emit_observe'; sudo bpftool link show | grep -i file_free
  nn-admin detections | grep -E '/root/.ssh/authorized_keys|/etc/sudoers'
  journalctl -u northnarrow-agent --since '2 min ago' | grep -iE 'Fim|Modified|drift|FIM-003|FIM-004'
  sudo bpftool map dump name FIM_DIRTY_INODES | grep -c key   # >0 while fd open, 0 after close
  ```
- *Expected:* prog attached; for (A)+(B) exactly one `FimOp::Modified` per file **after** close, attributed to the writer; `FIM_DIRTY_INODES` holds the key while the fd is open and is empty after close; (C) no drift.
- *Suspected (the hypothesized bug):* prog attached, `FIM_DIRTY_INODES` **gains** the key during the open fd (write-intent fired) but the key is **still present** after close (never consumed) and **no** `Modified` drift appears for (A)/(B) → `file_free_security` didn't fire at last-fput (or with an unreadable `f_inode`) → silent FIM blindness for the entire `O_APPEND`/same-size-in-place class + a slow `FIM_DIRTY_INODES` leak. (The map before/after distinguishes this from a write-intent failure where the mark is never set.)

### U2. `catchall-2` — Synchronous `/proc/<pid>/exe` readlink per DNS query on a tokio worker

- **Claimed Medium · Runtime-observable: yes · Verdict: UNCERTAIN (fact real, harm unsubstantiated)**
- **Primary:** `agent/src/sensors/multiplexer.rs:618` (`*exe = resolve_pid_exe(*pid)` in `pump_dns_query`) + `:568-572` (`std::fs::read_link`); contrast `:538-542` (tcp/listen pumps set `exe=None`); same in-tree pattern `fim/drain.rs:881`
- **Why uncertain.** The **code fact is real and strace-observable**: `pump_dns_query` does a synchronous `read_link("/proc/<pid>/exe")` for every decoded DnsQuery, inside the `while inner.next()` drain loop, holding the `AsyncFd` guard, with no `spawn_blocking`; `git blame` = `95593ab` (FP-3, 2026-06-07), unfixed. **But the severity-bearing harm is not substantiated:** (1) a `readlinkat` is µs-scale even on ENOENT; (2) the real per-iteration await is `tx.send(event).await` into a 4096-deep mpsc, which cooperatively yields rather than thread-pinning; (3) this is the established in-tree pattern (`fim/drain.rs:881` identical); (4) two factual errors in the original recipe — the ringbuf is **256 KiB** (not 64 KiB), and kernel-side drops are silent (`reserve` failure just `return Ok(())`), while the finder's `dns_query.*rejected` grep matches the malformed-decode WARN, **not** back-pressure. So the readlink-per-query is confirmable; the telemetry-loss consequence likely does **not** reproduce at realistic DNS rates. Actionable as hygiene (move exe resolution off the drain loop via `spawn_blocking`/cache), not a beta-blocker.

**Fire-test on the 6.8 VM.**
- *Trigger:* sustained DNS load from short-lived processes (pid usually gone before the pump reads `/proc`): `for i in $(seq 1 50000); do getent hosts nx-$i.invalid >/dev/null 2>&1; done &` plus `while :; do dig +short @127.0.0.53 r$RANDOM.invalid >/dev/null 2>&1; done &`.
- *Observe — PART A (the real part):* `sudo strace -f -e trace=readlinkat -p $(pgrep -f northnarrow-agent) -qq 2>&1 | stdbuf -oL grep -c '/proc/[0-9]*/exe'` over a fixed 10 s window, correlated to offered DNS rate. **PART B (the claimed harm):** since there's no drop counter, compare offered vs delivered — count outbound `:53` (`tcpdump -ni any 'udp dst port 53' -c 100000 | wc -l`) against delivered `DnsQuery` events reaching the engine — over the same interval.
- *Expected (A):* readlink rate low/decoupled from DNS rate. *(B):* delivered tracks offered, no growing gap.
- *Suspected (A):* readlink rate ≈ DNS query rate, almost all ENOENT — confirms the per-query blocking readlink. *(B, likely does NOT reproduce):* the µs readlink is dwarfed by the awaited mpsc send, so no measurable loss — making this a code-smell, not a telemetry-blinding defect.

---

## Appendix — investigated and dismissed (7)

These were raised by finders and **refuted** by the adversarial verifier (mechanism didn't hold, or already addressed). Recorded so they aren't re-litigated.

| ID | Claimed | Why dismissed |
|----|---------|---------------|
| `ebpf-lsm-2` | Med | Not a T7 sibling: returning `i32` to the void `file_free_security` hook is benign; arg indexing is correct (`arg(0)` matches the 1-arg prototype), so no verifier reject / silent non-attach. (The *fire* question is captured separately as **U1**.) |
| `ebpf-lsm-3` | Med | Mechanism contradicted by code: `close_if_expired()` is called at the **top of `process_event`** (`main.rs:2261`), which handles a 7-pump mpsc (process_spawn fires on every system exec), **not** an FS-only path — so the trusted-installer FS-pin suspension does not persist on an FS-quiet host. |
| `posture-4` | Low | The `sort_by_key` is **stable** and `apply_to_level` returns the terminal Combat once reached, so the firing-trigger attribution is deterministic (detect() push order), not "unstable"/mislabeled. Real code path, but not a bug. |
| `combat-avail-3` | Med | Wiring is code-accurate (STATUS-ping stuck-recovery → SIGINT→SIGKILL; no CPUQuota) but the trigger requires *sustained* CPU saturation to miss two 30 s pings with a 2 s timeout — not a realistic benign-load self-DoS; healthy agents answer the ping cheaply. |
| `at-authz-4` | Med | **Duplicate of `chain-persist-1`, weaker framing — refuted.** The finder read only the agent side and assumed the CLI renders the append-failure as "detection not found"; it does **not** — `nn_admin.rs:2523-2535` explicitly names persistence failure as a cause and directs to the agent log. (The genuine machine-distinguishability gap is captured as entry 14.) |
| `at-authz-5` | Low | Exploit direction is backwards: `count_admin_pub_keys` counts *every* non-comment line (a malformed token **is** counted → count≥2 → gate **disarms**), the opposite of the claim; and the gate is independently locked by a whole-file sentinel hash. |
| `chain-overlay-rotation-1` | Low | No operator-observable channel exposes an in-memory-but-unflushed detection id: `read_last_n` reads disk only and never consults `SinkInner.queue`; the in-memory `last_id` is surfaced by no admin verb/metric, so the "under-reports max id after rotation" path is unreachable at runtime. |

---

*Generated by a 7-finder + per-finding adversarial-verifier workflow (36 agents). All entries verified against the real code on `audit/nn-bug-hunt` @ `8fcd18b` and checked against git history for already-fixed status. No code, config, or eBPF source was modified in producing this registry.*
