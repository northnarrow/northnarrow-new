# RANGE_SETUP.md — Adversarial Validation range (current state + runbook)

Operator runbook for the two-VM, fully isolated VirtualBox range that
validates the **69-rule** production engine against real attacker tooling.
Design of record: [`docs/design/TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md`](docs/design/TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md).

> This file reflects the range **as it actually is** (verified 2026-06-02),
> not greenfield. The VMs, the internal network, the static IPs, and the
> Kali toolchain already exist. It supersedes the
> [`docs/adversarial/`](docs/adversarial/) draft (placeholder
> 192.168.56.x IPs, `/opt` paths, the stale 61-rule pin).

---

## 1. State on the ground (already done — do NOT redo)

| Item | Reality |
|---|---|
| VMs | `northnarrowdev` (Ubuntu target) + `kalidev` (Kali attacker) both exist |
| Isolated network | `intnet-adversarial` — NIC 2 on both, cable connected (confirmed via `showvminfo`) |
| Target IP | `10.10.10.20` on `enp0s8`, **persistent** via netplan `99-intnet-adversarial.yaml` |
| Attacker IP | `10.10.10.10` on `eth1`, **persistent** via NetworkManager |
| Connectivity | ping verified both directions, sub-ms |
| Kali toolchain | Atomic Red Team, Sliver, Metasploit, LaZagne, Pupy, Caldera — installed in prior sessions |
| Provisioning scripts | `deploy/adversarial/provision-kali.sh` ships for reproducibility; **already run** |

## 2. Topology

```
  kalidev (attacker)              northnarrowdev (target, PROD mode)
  10.10.10.10  ──── intnet-adversarial (NIC2, no DHCP, no host route) ──── 10.10.10.20
      │                                                                          │
      │  eth1 (NM, static)                                  enp0s8 (netplan, static)
      │
      └─ DURING PROVISIONING ONLY: NAT (enp0s3-equiv) + Tailscale (tailscale0,
         100.108.16.10).  BOTH DETACHED before any attack run — see §5.

  Target NEVER carries a NAT adapter during a run. Its only reachable peer
  is kalidev on intnet-adversarial. That is the C2-containment invariant.
```

## 3. What's left (V1 remaining work)

V1 shrank: no VMs to create, no internal net to build, Kali already
provisioned. Remaining, in order:

1. **Bootstrap the target into production mode** — run, on `northnarrowdev` as root:
   ```bash
   sudo /home/forty/dev/northnarrow-new/deploy/adversarial/bootstrap-target-prod.sh
   ```
   This takes the box from its current dev/smoke state to a clean prod
   state: stops the dev agent, scrubs dev runtime telemetry (keeps `/etc`
   config + the single admin keypair — BUG-013), rebuilds the **shipped**
   binary (`cargo xtask build --release`, **no** `test-privileged`),
   installs via `deploy/install.sh` (which lands the **BUG-042** capability
   unit — `CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_LINUX_IMMUTABLE
   CAP_SYS_PTRACE CAP_DAC_OVERRIDE`, dropping near-root `CAP_SYS_ADMIN`),
   enables + starts the real units, re-seeds the FIM baseline, deploys
   canaries, then runs a **health check** (see §6).
2. **Remove the NOPASSWD sudoers entry** on the target (§4) — realistic privilege posture.
3. **Detach NAT + Tailscale**, verify isolation, snapshot (§5).
4. **Take the revert snapshots** — target `clean-prod`, attacker `armed` (§5).
5. **Set up the read-only shared folder** for evidence pull (§7).

## 4. Privilege posture — remove passwordless sudo before the sweep

The target currently has `/etc/sudoers.d/forty-claude-session`
(`forty ALL=(root) NOPASSWD: ALL`). A real target does not hand the
attacker passwordless root. **Before arming the range:**

```bash
sudo rm /etc/sudoers.d/forty-claude-session     # on northnarrowdev
```

- Do this **after** `bootstrap-target-prod.sh` (the bootstrap needs root)
  and **after** you no longer need unattended sudo for management.
- It is captured in the `clean-prod` snapshot, so every revert restores the
  realistic posture automatically.
- To do agent maintenance later, revert / re-add it, or use `su`.

## 5. Containment — the detach/reattach dance (C2 invariant)

Constraint: **no internet, everything on the Fisso.** During runs the
target must reach **only** kalidev on `intnet-adversarial`, nothing
outbound. Two external channels exist today and **must be detached for runs**:

- **NAT** adapter(s) on both VMs (the provisioning/management path).
- **Tailscale** on kalidev (`tailscale0`, `100.108.16.10`).

### Arming (before any attack run), on the VirtualBox host + guests
```bash
# 1. attacker: stop Tailscale (inside kalidev)
sudo tailscale down && sudo systemctl stop tailscaled

# 2. host: detach NAT from BOTH VMs (VMs can stay running; NIC1 = NAT slot)
VBoxManage controlvm kalidev        nic1 null
VBoxManage controlvm northnarrowdev nic1 null
#   (powered off instead? use:  VBoxManage modifyvm <vm> --nic1 none)

# 3. verify isolation from the target: intnet peer reachable, world is not
ping -c1 10.10.10.10        # MUST succeed  (kalidev on intnet)
ping -c1 1.1.1.1            # MUST fail     (no outbound)
```

### Target access with NAT detached
SSH-over-NAT is gone once armed. Choose one:

- **Host-only adapter for management (recommended):** give the target a
  third NIC on a `vboxnet` host-only network (e.g. `192.168.56.0/24`) used
  *only* for the operator's SSH. It is not the attack path and not
  internet — the C2 invariant still holds (target still can't reach the
  world; kalidev is not on the host-only net). Add it before snapshotting
  so it's part of `clean-prod`.
- **Console-only for pure-C2 runs:** for the strictest runs, use the
  VirtualBox console / serial console and attach **no** management NIC at
  all.

### Reattach (provisioning / maintenance only)
```bash
VBoxManage controlvm kalidev        nic1 nat   # re-enable NAT to download tools
# inside kalidev:  sudo systemctl start tailscaled  (only if needed)
# ...provision... then DETACH AGAIN before the next run + re-snapshot 'armed'.
```

### Snapshots (revert points)
```bash
# target — AFTER bootstrap health check passes, NOPASSWD removed, NAT detached:
VBoxManage snapshot northnarrowdev take clean-prod --description "69-rule prod, BUG-042 unit, isolated"
# attacker — AFTER toolchain verified, NAT + Tailscale detached:
VBoxManage snapshot kalidev take armed --description "toolchain ready, isolated"
```
Revert cadence (§6.1 / §13 Q10): target → `clean-prod` **per TTP family**;
**per-TTP** for state-mutating tests (PAM / `ld.so.preload` / log tamper /
persistence drops) so a prior write can't pre-satisfy a later rule.
Attacker → `armed` between runs for a clean toolchain.

## 6. Health check (what the bootstrap asserts)

`bootstrap-target-prod.sh` fails loud unless **all** of these hold (each
dry-run against the live agent on 2026-06-02):

| Probe | Pass condition |
|---|---|
| Units | `northnarrow-agent` **and** `northnarrow-watchdog` active |
| Rule count | `decision engine ready … rules=69` (engine's own load; not the stale 61/68) |
| LSM | `bpf` in `/sys/kernel/security/lsm` **and** NN BPF-LSM progs attached (`task_kill`, `inode_*`, `fim_*`, `ptrace_access_check`) |
| **Capabilities (master probe)** | running agent's `CapEff` decodes to the BUG-042 set **and does NOT include `cap_sys_admin`** |
| COMBAT at rest | `nn-admin status --json` → `network_isolation_engaged:false`; no `northnarrow` iptables chain |
| Anti-tamper | `+i` set on `/var/lib/northnarrow` |
| Admin surface | `/run/northnarrow/admin.sock` + `/run/northnarrow/agent.pid` present |

**Why the capability decode is the master probe (and there is no
"lineage log line" probe):** the `/proc/<pid>/exe` lineage path
(`posture/lineage.rs`) is **silent on success** — the only lineage-related
runtime log is a *failure* warning, and the one easy trigger (the
same-uid, dumpable watchdog) doesn't even require `CAP_SYS_PTRACE`, so it
can't discriminate. The cap is only needed for the real case: a
**cross-uid / non-dumpable** target (attacker lineage + quarantine).
Asserting `CAP_SYS_PTRACE` is present in `CapEff` is therefore the sound,
deterministic proof that lineage/quarantine exe-reads will work — and the
same decode simultaneously proves `+i` re-arm (`CAP_LINUX_IMMUTABLE`) and
the minimal BPF-attach path (`CAP_PERFMON`, not `CAP_SYS_ADMIN`).

> Note on the rule count: the *currently running* binary reports **68**,
> not 69 — it was built 2026-05-30, before BUG-034 added R018
> (2026-06-01). The bootstrap rebuilds from source, which loads **69**
> (`agent/src/decision/tests.rs` pins exactly this). The legacy docs say
> **61** (T10.5 era). All three numbers are reconciled in the design §4
> note; **69 is correct after bootstrap.**

## 7. Evidence pull — read-only shared folder

Pull logs/screencaps off the target **read-only** so a compromised target
can't tamper with evidence:
```bash
# host: share a host dir into the target, read-only, auto-mount
VBoxManage sharedfolder add northnarrowdev --name evidence \
    --hostpath /path/on/fisso/evidence --readonly --automount
```
Inside the target it mounts under `/media/sf_evidence` (read-only). Copy
the audit-chain + journald slice per run window; hash with `sha256sum` on
arrival; archive under `docs/validation/evidence/<run-id>/`. Selective
PCAP (NET + CHAIN families only) per §13 Q6.

## 8. End-to-end run order

```
# ── target (northnarrowdev), as root ──
sudo deploy/adversarial/bootstrap-target-prod.sh        # build+install prod, health check
sudo rm /etc/sudoers.d/forty-claude-session             # realistic privilege posture

# ── attacker (kalidev) ──   (toolchain already installed; only on rebuild:)
# deploy/adversarial/provision-kali.sh                   # NAT attached, then detach

# ── host: ARM ──
#   stop Tailscale on kalidev; detach NAT on both VMs (§5)
#   verify isolation (ping intnet OK, ping 1.1.1.1 FAIL)
VBoxManage snapshot northnarrowdev take clean-prod ...
VBoxManage snapshot kalidev        take armed ...
VBoxManage sharedfolder add northnarrowdev --name evidence ... --readonly

# ── run the sweep (V2–V4) ──   revert clean-prod per family; armed between runs
```

## 9. Superseded

The earlier draft under [`docs/adversarial/`](docs/adversarial/)
(`README.md`, `scripts/00–07`, the V2 sweep doc) predates the live range
and carries placeholder values. The canonical, range-accurate automation
is `deploy/adversarial/` + this file. See
[`docs/adversarial/SUPERSEDED.md`](docs/adversarial/SUPERSEDED.md).
