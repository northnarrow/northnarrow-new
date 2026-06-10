# at-authz-1 — admin.pub write-open deny (design, v3)

- Finding: at-authz-1 (docs/audit/NN_BUG_AUDIT_2026-06-09.md) — full auth-model defeat.
- Also closes: agent.sig.key in-place substitution (at-authz-2, write half).
- Branch: fix/at-authz-1. Kernel target: Ubuntu 6.8.0-124-generic (VM-validated).

## Problem
A root caller can open admin.pub (0644 root:root) O_WRONLY|O_APPEND and write; `tee -a admin.pub`
injects a Role::All break-glass key that loads at the next AdminAuth::load (restart or any
rotate-keys auth.reload), defeating the signed admin-key model. The 5 inode_protect deny hooks
cover unlink/rmdir/rename/setattr/file_ioctl; file_open/file_permission are observe-only
(fim_watch.rs). Fire-test on 6.8.0-124 (detect-only) confirmed: touch -> EPERM (op=setattr),
chattr +i -> EPERM (op=ioctl, file_ioctl dispatches for FILES), write-open -> NOT denied (the gap).

## Decision
Add `#[lsm(hook = "file_open")]` program `protected_open_deny` in inode_protect.rs: read
file->f_mode; if FMODE_WRITE is set, call deny_if_protected(FS_OP_WRITE, inode). Denial logs
as op=write. This blocks the write at the open chokepoint; because a MAP_SHARED|PROT_WRITE
mapping requires an FMODE_WRITE open (do_mmap -> -EACCES otherwise), it also forecloses the
mmap-write vector. Keyed on PROTECTED_INODES, it also closes the in-place overwrite of
agent.sig.key.

Subset scoping mechanism: the PROTECTED_INODES value (today an unused 1u8) becomes a flag-mask:
bit0 = MUTATE-deny (unlink/rmdir/rename/setattr/ioctl — ALL members, unchanged), bit1 =
WRITE-open-deny (secret/integrity subset only). Registration helpers set the bits per file
class. deny_if_protected becomes op-aware: FS_OP_WRITE denies only if value has bit1; the
mutation ops deny on presence (any value), as today. The exemption (FS_PROTECT_OVERRIDE +
PROTECTED_PIDS) stays shared inside deny_if_protected — NOT reimplemented in the hook body.

## Why file_open, not file_permission
security_file_permission(MAY_WRITE) is reached only from rw_verify_area() on the write(2)
family; a store through a shared-writable mmap is a page fault (do_shared_fault) and never
invokes it — so a file_permission deny is bypassable via open(O_RDWR)+mmap(PROT_WRITE,SHARED).
file_open(FMODE_WRITE) forecloses that (no writable fd -> no shared-writable mapping), is the
cooler hook (once per open vs every access), and FMODE_WRITE is a single unambiguous bit.
mmap_file deny is deliberately NOT added: redundant on 6.8 (open-deny already forecloses it),
its only marginal coverage is a boot-window stale fd (out of scope, already write(2)-exposed),
and a second deny program would only double the attach-failure surface.

## Rejected
- E3 (chattr +i): doesn't generalize to append-only chain logs (agent appends constantly) and
  breaks rename-based rotation (a +i target blocks rename; new inode loses the flag).
- file_permission(MAY_WRITE): mmap-bypassable (above), hotter. Fallback only.

## Not coupled to R004
deny_if_protected exemption is FS_PROTECT_OVERRIDE slot 0 + PROTECTED_PIDS.get(caller_tgid) —
tgid-keyed, no argv[0]/parent_comm. NOT R004's spoofable systemd-executor predicate. R004's
weakness is not inherited and remains a separate High.

## Scope
Principle: WRITE-deny (bit1) covers files written ONLY by the agent at runtime (a runtime
non-agent write is unambiguous tamper).
- bit1 (WRITE+MUTATE): admin.pub, agent_id, audit.log, agent.sig.key, the STATE_PROTECTED_FILES
  chain logs, agent/watchdog binaries + systemd units (legit upgrades stay exempt via
  FS_PROTECT_OVERRIDE — this is why verify-item 2 is load-bearing for the binary scope).
- bit0 only (MUTATE, unchanged posture): operator-tunable files — process/netflow
  comm-allowlists, net blocklists, fim-paths.{v1,local}, mass-write-carveout.local (if present),
  canary-templates. Reason: WRITE-denying these imports an enforce-mode COMBAT footgun (a routine
  live edit -> EPERM -> ANTI-TAMPER DENIAL -> NIC isolation). Their write-protection + a
  non-escalating denial classification is enforce-mode policy work, not this fix.
- NOTE: the detection chains (detections.jsonl, status_events.jsonl) are NOT in
  STATE_PROTECTED_FILES (tracked separately under chain-protect-1), so they are outside this fix.
  When chain-protect-1 registers them in PROTECTED_INODES with bit1, this hook covers them for free.

## Implementation verify-items
1. Re-register on rotation (CONFIRMED gap, mandatory). atomic_rewrite_admin_pub_add/_revoke do
   tmp-write + rename(2) + auth.reload(); register_inode runs only under attach() at boot, so
   after any rotate-keys op the new admin.pub inode is absent from PROTECTED_INODES and ALL deny
   hooks lapse until restart. Fix: in BOTH rotate dispatchers, after the rewrite, re-register the
   new inode (with its bit0|bit1 flags) and drop the stale old-inode key. Use the in-tree pattern
   the chain logs already use (register_active, chainlog.rs:620). Guard: post-rotation `tee -a` must
   still EPERM.
2. Dual exemption (satisfied by construction). Route through deny_if_protected; inherit
   FS_PROTECT_OVERRIDE + PROTECTED_PIDS. deny_if_protected only gains op-aware membership for the
   write op — do not re-implement the exemption.
3. Fire-test the deny on 6.8 + machine-detectable attach health. Validate empirically (T7 lesson).
   Per ebpf-lsm-1 the attach path stays warn-and-continue (refuse-to-start is rejected — a benign
   attach failure must not self-DoS), BUT expose a machine-detectable signal: a gauge
   `nn_anti_tamper_deny_hooks_attached` + its expected count, so monitoring can alert when
   attached < expected. Holistic fail-closed/enforce-gate = ebpf-lsm-1 (shelved).

Impl cost: file_open reads file->f_mode -> add FILE_F_MODE_OFFSET to the BUG-036 BTF revalidation
table (same pattern as FILE_F_INODE_OFFSET). New op code FS_OP_WRITE alongside setattr/ioctl/etc.

## Acceptance criteria (VM)
- root `tee -a admin.pub` (any O_WRONLY/O_APPEND/O_TRUNC write) -> EPERM + `ANTI-TAMPER DENIAL ... op=write`
- root open(O_RDWR)+mmap(PROT_WRITE,MAP_SHARED) on admin.pub -> fails at open (no writable fd)
- `cat admin.pub` (O_RDONLY) -> succeeds; agent's own chain-log appends -> succeed
- `nn-admin rotate-keys add` -> succeeds; re-run `tee -a` post-rotation -> still EPERM
- a tunable config (e.g. process-comm-allowlist.local) write -> NOT denied (bit0-only); rename still denied
- the five existing deny hooks still fire; zero posture/kill regression
- forced attach failure of the new hook -> the gauge reflects attached < expected

## Out of scope — follow-ups
Boot/stop window (bake SHA256(admin.pub) into the signed binary + verify at load; secure-boot);
agent.sig.key read->offline forge (at-authz-2 second half, HSM/TPM); tunable-config write-protection
+ non-escalating denial classification (enforce-mode); holistic deny-family fail-closed (ebpf-lsm-1).
