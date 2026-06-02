# SUPERSEDED

The contents of `docs/adversarial/` (`README.md`, `scripts/00_config.sh`
… `scripts/07_teardown.sh`, `V2_ATOMIC_RED_TEAM_SWEEP.md`) were an **early
draft** written before the range existed. They carry placeholder values
that do **not** match the live range and will mislead if followed:

- IPs `192.168.56.10/.20` — the live range is `10.10.10.10/.20`.
- repo path `/opt/northnarrow-new` — actual: `/home/forty/dev/northnarrow-new`.
- unit name `northnarrow.service` — actual: `northnarrow-agent.service` (+ `northnarrow-watchdog.service`).
- `cargo build` for the agent — must be `cargo xtask build --release` (eBPF freshness gate).
- rule count `61` — current source loads **69** (61 was the T10.5-era pin).

## Use instead

- Automation: [`../../deploy/adversarial/`](../../deploy/adversarial/)
  (`00_config.sh`, `bootstrap-target-prod.sh`, `provision-kali.sh`).
- Runbook + host-side steps: [`../../RANGE_SETUP.md`](../../RANGE_SETUP.md).
- Validation workspace: [`../validation/`](../validation/).
- Design of record (unchanged): [`../design/TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md`](../design/TAPPA10_7_ADVERSARIAL_VALIDATION_DESIGN.md).

These files are kept for history only. Do not run the `scripts/` here.
