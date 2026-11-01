# The heartbeat and its external verifier

*R12c-2 (lab PR 270; report 06, INI-14 and R2-12). Code: the agent's
`agent/src/heartbeat.rs`, the beat and the verifier's checks in
`crates/nn-evidence/src/heartbeat.rs`, the commands in
`crates/nn-admin/src/heartbeat.rs`.*

Everything an agent signs on its host proves something only to a reader
who is not on that host: an attacker who owns the host owns its files, its
journal and the agent's key. What such an attacker cannot hide from a
reader elsewhere is the agent's *silence*, a chain that goes *back*, or a
beat that does not verify. The heartbeat gives that reader something to
watch, and `nn-admin heartbeat watch` is that reader: small, run on
another host, independent of any backend.

## What the agent writes

Every 30 s (`NN_HEARTBEAT_SECS`, 5 to 300; there is no off, and a period
longer than 30 s is reported as a weakening by the self-integrity check)
the agent appends a **beat** to its `heartbeat` chain,
`/var/lib/northnarrow/heartbeat.jsonl` (`--heartbeat-file`; rotating, 4 MiB
× 4 archives — days of beats). Each beat is a line signed with the agent's
key and chained to the line before by its hash, like every other chain
(`EVIDENCE_CHAINS.md`; `sudo nn-admin chain verify --log heartbeat`). It
carries:

| Field | What it says |
|---|---|
| `kind` | `start` (the run's first beat), `beat`, `stop` (a clean stop, with `stop_reason`) |
| `seq` | the beat's number, from 1, continuing across the agent's restarts |
| `ts`, `uptime_ms`, `interval_secs` | when, since when, how often (the verifier's freshness bound) |
| `agent_id`, `run`, `boot_id`, `version` | which agent, which run of it (the actions chain's `run`), which boot of the kernel |
| `posture`, `combat_stage`, `trust_level`, `degradations` | the agent's state and the degradations it signed this run |
| `decision_rounds`, `decision_since_last_ms` | the decision thread's progress: a count that stands still is a decision that does |
| `loss` | the events lost at each stage of their path since the run started — stages 1 to 7: the kernel's ring, the kernel's budget, the decoder, the bus's queues, the decision's delay, the response queue, the evidence writers ([the event bus, §5](https://github.com/northnarrow/northnarrow-new/blob/main/docs/architecture/EVENT_BUS.md)) |
| `actions` | the actions chain's intents and outcomes, rows it could not take, intents of an earlier run found interrupted, actions in flight (`EVIDENCE_CHAINS.md`, the actions chain) |
| `probe_gaps` | the telemetry probe's gaps since the run started (`null`: the probe is off) |
| `capabilities` | R13 (lab PR 271): the capability manifest's newest view — its capabilities `hash`, the last `revision` signed (0: the boot's), `settled` (the telemetry probe's first round has ended) and `contract` (the hash of the sensor contract's terms, the agent's version and the kernel's release); absent from an agent older than R13 (`SENSOR_CONTRACT.md` §4, §5) |
| `heads` | the audit chain's head (its row number and hash) and the actions chain's (its position — `file`, the number its active file will have as an archive, and `bytes`, its length — and hash, and `kept`: whether the chain still holds the head the agent's previous beat named, read back at each beat and at the start from the last run's last beat; with `actions.in_flight` and `actions.unwritten`): a chain rolled back on the host, or a tail cut from the actions chain (an intent removed) — even with rows appended past the cut — shows as a head that went back or is no longer kept |

Beside the beats, the agent signs a **`telemetry_loss`** row in the audit
log: the loss of every stage, its total since the run started and what it
lost since the last such row — at a change, at most once a minute; with no
change, once an hour (a zero signed too); and at the stop.

## What the verifier checks

`nn-admin heartbeat watch` fetches the newest lines of the chain, verifies
each one with the agent's public key and compares with what it verified
last (its state file). One line per check: `OK seq=… new=… age=…s`, or one
`ALERT <KIND> <detail>` per alert; R13: a `NOTICE <detail>` line, no alert
and no exit code, when the sensor contract's hash changed alone (an upgrade
of the agent, a new kernel). Run once (a timer), its exit code is the
most severe alert's:

| Exit | Alert | When | What to do |
|---|---|---|---|
| 13 | `TAMPERED` | a line does not verify (altered, or signed with another key) | treat the host as compromised: its chain was edited, or the key was replaced (after a planned key change, see below) |
| 12 | `REPLAY` | a beat older than one already seen, a fork of one, or a chain's head went back (the audit log's row, the actions chain's position: a tail cut, a rotation undone, a rewrite) or is gone from the beat (the chain did not open on the host), or the agent no longer finds in its actions chain the head its previous beat named (`kept: false`: cut or rewritten) | the chain was rolled back or an old export replayed: the host or the channel is lying |
| 11 | `BROKEN` | the chain does not link, or beats are missing | beats were removed — or the export was short of them: on the host, `sudo nn-admin heartbeat export --count 500` shows more (the forced command always exports the default 64) |
| 10 | `SILENT` | no new beat for two intervals plus 15 s (75 s by default; `--max-silence-secs`) on the **verifier's** clock — since it first saw the newest beat — or the source could not be read past that | the agent stopped, froze or was killed, the host is down, or the network is cut — go and look |
| 15 | `STOPPED` | the agent's signed `stop` beat (an admin shutdown, a host shutdown), and every check while it stays stopped | expected only during maintenance |
| 14 | `LOSS` | a stage's loss grew since the last beat seen | `nn-admin status --key` on the host: which stage, which queue |
| 16 | `DEGRADED` | the agent's clock gone back, or ahead of the verifier's past `--max-skew-secs`; a new run whose start beat follows no stop beat (the agent killed, crashed, or frozen and restarted by the watchdog — however soon it came back), a beat late after the one before it in one run (more than its interval + 15 s: the agent stood still — frozen, starved — for less than the silence bound), the decision thread stood still for two intervals, a telemetry gap, an action row not in its chain, an action interrupted between intent and outcome, a new degradation; R13: the capability manifest changed — a settled `capabilities.hash` other than the last one seen, within a run or across a restart (`bpf` gone from `lsm=`, a sensor partial or on a fallback, a probe's gap or its word stale) — or not settled 120 s after the start, or gone from the beats; an upgrade alone (`capabilities.contract`) is a `NOTICE`, not this | `nn-admin status --key`, `nn-admin capabilities --key` (what changed), the audit log's rows |

The host's clock decides nothing grave (review of #478): beats are
ordered by their numbers and links; a beat stamped before the one seen
(an RTC behind after a reboot) or ahead of the verifier's clock by more
than `--max-skew-secs` is `DEGRADED` ("the agent's clock went back",
"… is N s ahead"), never `REPLAY` or `TAMPERED`; freshness is the
verifier's own clock, and a late beat within a run is measured on the
agent's `uptime_ms`.

A state file that is there and cannot be read or decoded stops the
verifier (exit 3): it never re-anchors silently, which would take a
rolled-back chain for its first beat. `--reanchor` starts again from the
newest beat, on purpose.

The first check of a new state file **anchors**: it takes the newest beat
that verifies as the start (say `OK … (anchored: first beat seen)`) and
alerts on nothing the run counted before it. Compare that beat's
`agent_id` and `run` with the host's `nn-admin status` once, by hand. A
restart of the agent is a `start` beat of a new `run`: its counters start
again from zero, and it is not an alert (an action it found interrupted
is).

## Operating it

- **Planned maintenance** (an upgrade, a reboot): the agent's `stop` beat
  is `STOPPED` at every check while it is stopped — a page every 30 s
  with `OnFailure=`. Stop the verifier's timer for the window
  (`systemctl stop nn-heartbeat-web01.timer`) and start it after; the
  first check then sees the new run's `start` beat after the `stop`: no
  alert.
- **A key change** (the agent's signing key replaced): every check is
  `TAMPERED` until the verifier has the new public key, and the lines of
  the export signed before the change keep failing until they leave it
  (64 beats, about 32 minutes). In a maintenance window: install the new
  `agent.sig.pub`, and when the window ends run once with `--reanchor`.
- **A reinstall, or the chains removed**: the beats start again from 1 —
  `REPLAY` (and a head gone). Check the host, then `--reanchor`.

## Setting it up

The verifier pulls the beats over SSH, through a key that can run one
read-only command and nothing else.

On the **agent's host** (the account and the rule are an example; any
account works, it needs no shell):

```sh
sudo useradd --system --create-home --shell /bin/sh nn-heartbeat
# the one command the account may run as root (the chain is 0600 root)
echo 'nn-heartbeat ALL=(root) NOPASSWD: /usr/local/bin/nn-admin heartbeat export' \
  | sudo tee /etc/sudoers.d/nn-heartbeat && sudo chmod 0440 /etc/sudoers.d/nn-heartbeat
# the verifier's key, restricted to that command
sudo install -d -o nn-heartbeat -m 0700 ~nn-heartbeat/.ssh
echo 'restrict,command="sudo -n /usr/local/bin/nn-admin heartbeat export" ssh-ed25519 AAAA… verifier' \
  | sudo tee ~nn-heartbeat/.ssh/authorized_keys
# the agent's public key, to copy to the verifier (check its fingerprint
# against `sudo nn-admin status --key` out of band)
cat /etc/northnarrow/agent.sig.pub
```

On the **verifier's host** (any Linux host with `nn-admin`; it needs no
agent, no backend and no secret of the agent's — only its public key):

```ini
# /etc/systemd/system/nn-heartbeat-web01.service
[Unit]
Description=NorthNarrow heartbeat of web01
OnFailure=nn-heartbeat-alert@web01.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/nn-admin heartbeat watch \
  --agent-pubkey-file /etc/nn-heartbeat/web01.pub \
  --from-cmd 'ssh -i /etc/nn-heartbeat/id_ed25519 -o BatchMode=yes -o ConnectTimeout=10 nn-heartbeat@web01' \
  --state /var/lib/nn-heartbeat/web01.json

# /etc/systemd/system/nn-heartbeat-web01.timer
[Timer]
OnBootSec=1min
OnUnitActiveSec=30s
[Install]
WantedBy=timers.target
```

Any non-zero exit runs the `OnFailure=` unit (mail, a pager, a chat hook);
the `ALERT` lines are in that unit's journal. Or run it continuously
(`--every 15`) under a supervisor that forwards its output. An exported
copy of the chain read from shared storage works too (`--from-file`).

## Why this transport

- **No new listening service on the agent's host.** The beats leave the
  host only when the verifier asks, through `sshd`, which is already there
  and authenticates the verifier's key; the key runs one command that reads
  a file. Nothing in the agent listens, and the agent's host opens no
  connection of its own (no egress rule, no collector to reach).
- **The channel need not be trusted for integrity.** Each beat is signed by
  the agent's key end to end; a changed byte is `TAMPERED`, an old beat
  `REPLAY`, a removed one `BROKEN`, whatever carried them. SSH adds
  confidentiality (the counters are telemetry the agent withholds from
  unauthenticated local callers, external audit ASK-009) and keeps a
  stranger from asking.
- **The verifier holds nothing that matters.** The agent's public key and
  its own SSH key, limited to that one command; its state file says what it
  verified last.
- **Isolation stays visible.** During a COMBAT isolation the host answers
  only from the management networks (`combat-allow.cidrs`): a verifier
  there keeps reading the beats; one elsewhere sees the silence, which is
  what an isolated host is.

## What it does not prove

**Whoever holds the agent's key can forge everything** — every beat, its
`kept`, the chains' heads and the counters, from any host. The signature
proves the key, not the host's honesty; only an attestation the host
cannot forge (a TPM quote of the measured boot and the agent, the Keylime
model) closes that, and it is future work.

**`kept` protects the tail, not the middle**: a row between two heads the
beats named, rewritten with one of the same length, leaves the position and
the previous head intact — only `sudo nn-admin chain verify` on the host
sees it (its signature fails), until R15 exports the chains off the host.

The verifier runs `nn-admin heartbeat export` as root through `sudo` on
the agent's host; a chain readable by a dedicated group would remove that
(its file is 0600 root, under the agent's protection): open.

The signature proves which key wrote a beat, not that the host is honest:
an attacker who reads the agent's key (root that gets past the anti-tamper
hooks) can write beats that verify. What such an attacker cannot do is
make a frozen, killed or blinded agent *keep* beating without forging every
beat from then on, or roll a chain back without the verifier seeing the
head go back. The next step is an attestation the host cannot forge — a
TPM quote of the measured boot and the agent (the Keylime model; report
06, R2-12/R2-13) — and an anchor of the chains' heads off the host on every
beat (R15's export). The self-test that pushes a synthetic event through
the sensors, the bus, the rules and a dry response into a signed row is not
in the beat yet (the telemetry probe's gaps are); it is open.

**The capability manifest's hash is the agent's own word** (R13): it
changes when the agent sees a change — a hook not attached, a fallback, the
telemetry probe's event not arriving or its rounds stopping. The probe
finds a sensor blinded naively or by accident; a root on the host that
recognises the probe's child (the agent's own binary, `--telemetry-probe`)
and serves it, or that blinds a source the probe does not exercise while
leaving its attach in place, changes nothing the beats carry
(`SENSOR_CONTRACT.md` §5a, with the worst-case delays: about 82 s to the
signed row, about 2.4 minutes to `DEGRADED` for a probed source).
