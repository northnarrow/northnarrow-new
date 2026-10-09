# Install, upgrade, uninstall

NorthNarrow's anti-tamper layer makes the host actively resist changes to
the agent: the binaries, the units and `/etc/northnarrow` are in
`PROTECTED_INODES` (write/unlink/rename denied by LSM hooks), the agent
and watchdog pids are in `PROTECTED_PIDS` (every userspace signal
denied), and `/var/lib/northnarrow` carries `chattr +i`. That is the
point of the product — and it means the three lifecycle operations must
follow a precise order. The scripts below encode it; do not improvise
with `rm -f` or `kill -9`, they are denied by design.

| Operation | Command | Keeps keys / audit chain / state |
|---|---|---|
| Fresh install | `sudo ./deploy/install.sh` then `systemctl enable --now …` | n/a (bootstraps them) |
| Upgrade in place | `sudo ./deploy/install.sh --upgrade` | **yes** |
| Uninstall | `sudo ./deploy/uninstall.sh` | **yes** (`/etc/northnarrow`, `/var/lib/northnarrow`) |
| Retire the host | `sudo ./deploy/uninstall.sh --purge` | no — everything removed |

All three assume `cargo xtask build --release` (or the release tarball)
produced `target/release/{northnarrow-agent,northnarrow-watchdog,nn-admin}`.

## 1. Fresh install

`install.sh` copies binaries, units, the journald namespace config, the
rule and allowlist files, the canary templates and the ten inert
control-surface bait files; bootstraps an admin keypair if
`admin.pub` is absent (move `admin.key` off the host — see
`COMBAT_RECOVERY.md` §1); and does **not** start anything. Enable the
agent first, then the watchdog.

If the units are already active, `install.sh` refuses with
`Re-run with --upgrade`: with the hooks up every copy below would fail
with `Operation not permitted` halfway through.

## 2. Upgrade in place

```sh
sudo ./deploy/install.sh --upgrade
```

What it does, in order:

1. records which units are active and prints installed → new version;
2. stops the **watchdog first** (stopping the agent alone makes the
   watchdog respawn it), then the agent;
3. removes `/sys/fs/bpf/northnarrow`: the LSM programs survive agent
   restarts only through their pinned links, so dropping the pin root
   detaches them; waits until `bpftool prog show` reports 0 LSM programs
   (30 s budget, fails loudly otherwise);
4. runs the normal install (binaries, units, configs; `chattr +i` on the
   state dir is lifted and re-applied by the new agent at boot);
5. starts the agent, waits 3 s, starts the watchdog, prints their state.

Preserved across the upgrade: `admin.pub`, `agent.sig.key`, `agent_id`,
`audit.log` (the new agent appends a signed `agent_boot` entry — review
it with `nn-admin audit verify`), every chain log under
`/var/lib/northnarrow`, and every `*.local` overlay. The window with no
hooks attached is the few seconds between step 3 and the new agent's
boot; it is the same window a reboot has.

The lab verifies this path on every nightly (`nn-lab.sh upgrade-check`):
refusal without the flag, pid change, new audit entry, identity files
unchanged, ≥ 7 LSM programs and `PROTECTED_PIDS` re-pinned afterwards.

## 3. Uninstall

```sh
sudo ./deploy/uninstall.sh            # keep /etc/northnarrow + /var/lib/northnarrow
sudo ./deploy/uninstall.sh --purge    # remove them too (and the namespace journal)
```

Order: disable + stop watchdog then agent → drop the pin root and wait for
the LSM set to drain → `chattr -R -i` on state and config → remove
binaries, units, `journald@northnarrow.conf`, `/run/northnarrow` and the
ten bait files → `daemon-reload`. Without `--purge` the admin key, the
signed audit chain and the chain logs stay on disk: they are evidence and
identity, and a later reinstall picks them up (`install.sh` leaves an
existing `admin.pub` untouched). `--yes` skips the confirmation prompt.

If an unrelated NorthNarrow process (an e2e test, a manual
`northnarrow-agent` run) still holds the LSM programs, the script stops
and names the condition instead of leaving a half-removed host.

The lab verifies `uninstall.sh --purge --yes` leaves no binary, unit, pin,
LSM program, config, state or bait behind, then reinstalls
(`nn-lab.sh uninstall-check`).

## 4. What still needs a reboot

- Enabling the `bpf` LSM (`lsm=…,bpf` on the kernel command line) the
  first time — see `docs/TAPPA7_PREREQ.md`.
- A kernel upgrade: the agent revalidates BTF offsets at boot and refuses
  to start on a mismatch rather than run with wrong offsets; the
  supported-kernel matrix is the next item on the reliability list.
