# Tappa 10.7 — Adversarial Validation Range (V1 setup)

Automation for the two-VM, fully isolated VirtualBox range that
validates the 61-rule production engine against real attacker tooling.
Design of record: `docs/design/TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md`
(RFC resolved 2026-05-21).

> **These scripts provision and orchestrate VMs. They are shipped as
> automation — V1 does not execute them.** Live execution (V2+) happens
> on the VirtualBox host the day the campaign runs.

## Topology (§2)

```
  kalidev (attacker)            northnarrowdev (target, PROD mode)
  192.168.56.10 ───── intnet-adversarial ───── 192.168.56.20
        │  (no DHCP, no host route, NO internet during runs)
        └─ NAT adapter attached ONLY during tool provisioning, then detached
```

- **Internal Network** `intnet-adversarial` is the hard C2-containment
  guarantee — no NAT engine, no host route. The target VM **never** has
  a NAT adapter; the attacker gets one **only** while installing tools,
  then it is detached before the `v1-baseline` snapshot.

## Where each script runs

| Script | Runs on | Purpose |
|---|---|---|
| `00_config.sh` | — (sourced) | shared config + idempotency helpers |
| `01_provision_kalidev.sh` | **host** | create the Kali VM, attach ISO |
| `02_configure_network.sh` | **host** | intnet wiring + NAT lifecycle |
| `03_provision_target_prod_mode.sh` | **target guest** (root) | build+install agent in production mode, verify |
| `04_install_attack_toolkit.sh` | **attacker guest** | Atomic / Sliver / Metasploit / LaZagne / Pupy |
| `05_verify_isolation.sh` | **host** (+ in-guest checks) | pre-attack containment gate |
| `06_baseline_snapshot.sh` | **host** | take `v1-baseline` snapshot |
| `07_teardown.sh` | **host** | destroy VMs + cleanup |

## Invocation order

```bash
# ── on the VirtualBox host ──
export KALI_ISO=/path/to/kali-linux-2025.x-installer-amd64.iso
./01_provision_kalidev.sh                 # create Kali VM + attach ISO
./02_configure_network.sh intnet          # both VMs onto intnet; target isolated
#   (create/clone the target VM 'northnarrowdev' separately, then:)
./02_configure_network.sh nat-on attacker # provisioning: give Kali temporary NAT
VBoxManage startvm kalidev                # install Kali interactively / preseed

# ── inside kalidev (attacker) ──
./04_install_attack_toolkit.sh            # clone/install the offensive toolkit

# ── inside northnarrowdev (target, as root) ──
./03_provision_target_prod_mode.sh        # production-mode agent + health check

# ── back on the host: ARM the range ──
./02_configure_network.sh nat-off attacker # DETACH NAT → fully isolated
./05_verify_isolation.sh                   # MUST pass before any attack
./06_baseline_snapshot.sh                  # snapshot 'v1-baseline' (revert point)

# ── teardown when done ──
./07_teardown.sh                           # (FORCE=1 to skip prompt)
```

## Configuration

All knobs live in `00_config.sh` and are env-overridable, e.g.:

```bash
KALI_ISO=/isos/kali.iso ATTACKER_RAM_MB=8192 ./01_provision_kalidev.sh
```

Key variables: `ATTACKER_VM`/`TARGET_VM`, `INTNET`, `ATTACKER_IP`/
`TARGET_IP`, `INTNET_NIC`/`NAT_NIC`, `KALI_ISO`, `BASELINE_SNAPSHOT`,
`NN_REPO_DIR`, `EXPECTED_RULE_COUNT`.

## Idempotency

Every script is safe to re-run: VM creation skips if the VM exists,
`modifyvm` is declarative, snapshots skip if `v1-baseline` already
exists, package/clone steps are existence-guarded, and teardown no-ops
on absent VMs. `bash -n` clean.

## Snapshot strategy (§13 Q10)

`v1-baseline` is the clean revert point. The test protocol reverts
**per-family** by default, and **per-TTP** for state-mutating tests
(PAM / `ld.so.preload` writes, log tamper, persistence drops) so a
prior write can't pre-satisfy or mask a later rule.

## Troubleshooting

- **`KALI_ISO is unset`** — export it before `01`.
- **`refusing: the target VM must NEVER have NAT`** — by design (§2.1);
  the target is isolated at all times. Provision its OS from an ISO the
  same way, but never give it a NAT adapter.
- **`05` reports ISOLATION BREACH** — a NAT adapter is still attached;
  run `./02_configure_network.sh nat-off attacker` and re-check. Do not
  start runs until `05` passes.
- **`03` health check fails / unit name differs** — confirm the systemd
  unit name emitted by `deploy/install.sh`; the script warns rather than
  hard-fails on a name mismatch so you can adjust.
- **Static IP not applied** — intnet has no DHCP; apply the netplan
  snippet `02` prints inside each guest, then `netplan apply`.
- **Sliver install needs network** — run it while NAT is attached
  (`nat-on attacker`), then detach before arming.
