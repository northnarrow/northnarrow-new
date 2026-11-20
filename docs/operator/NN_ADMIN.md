# `nn-admin`: the commands, the keys they need, the exit codes

`nn-admin` is the operator's client of the agent. It runs on the agent's
host (as root: the admin socket and the agent's files are root's; without
root a command that needs them exits 17 and says to use `sudo`), except
`heartbeat watch` and `export verify`, which run on another host. Every
command has its own help: `nn-admin <command> --help`. This page lists them
all, the options they share and every exit code an operator or a script
meets, `install.sh` and `uninstall.sh` included.

## 1. Keys and roles

A command that changes something, or reads more than the posture, is a
**signed request**: `--key` names an admin private key, and the agent
accepts it only if that key's line in `/etc/northnarrow/admin.pub` carries
the role the command needs. The key `install.sh` writes
(`/root/northnarrow-admin.key`) has `unlock`, `audit-read`,
`telemetry-read`, `trusted-installer` and `config-manage`, and nothing else:
the canary, FIM-baseline, response, force-posture, shutdown and key-rotation
commands answer "role denied" with it.
[`COMBAT_RECOVERY.md` §1.1](COMBAT_RECOVERY.md#11-what-the-install-key-can-do-roles)
explains the roles and how to add a key that holds others.

## 2. Options many commands share

| Option | What it is | Default |
|---|---|---|
| `--key PATH` | the admin private key that signs the request | none (required where the command is signed) |
| `--cosign-key PATH` | a second, distinct admin key, for the commands that need two (`shutdown`, `rotate-keys`) or accept one | none |
| `--socket PATH` | the agent's admin socket | `/run/northnarrow/admin.sock` |
| `--agent-id-file PATH` | this install's agent id: it binds a signed request to this agent, so a signature cannot be replayed on another host | `/etc/northnarrow/agent_id` |
| `--json` | JSON instead of text (one object per line where the command streams records) | text |

Colours: `nn-admin` colours a few verdict lines only on a terminal, and never
when `NO_COLOR` is set to a non-empty value. The colour only decorates: the
words carry the whole message. `install.sh` and `uninstall.sh` print no
colour.

## 3. The commands

### The agent's state

| Command | What it does | Key |
|---|---|---|
| `nn-admin status` | the posture, the network isolation, the last admin action, the COMBAT stage; with `--key` also the telemetry (lost events, the response mode: `OBSERVE-ONLY` under the `alpha` profile; the review of #565: the kernel-state round's findings past its quota, `kernel-state quota`, JSON `kernel_state_held_back`; lot 369: the container runtimes' sealed clones kept, compared, not compared and not read, `runtime clones`, JSON `runtime_clones`) | none, or `audit-read` / `telemetry-read` |
| `nn-admin capabilities` | this boot's signed capability manifest: kernel, BTF, deny hooks and their self-test, each sensor's attach point, the degradations, the trust level | `audit-read` or `telemetry-read` |
| `nn-admin host-check` | the host's hardening: lockdown, module signing, Secure Boot, unprivileged BPF, kexec, IMA, BPF LSM, a single bpffs (the agent's own pin lock, recognised as such, is not counted), the library preload list (`/etc/ld.so.preload`: a library every program would load fails the check, since the agent and the watchdog refuse to start with it), the install's verification level. Reads `/sys`, `/proc` and the preload list only | none |
| `nn-admin verify-keys` | parse `admin.pub`, print each key's fingerprint and roles | none |

### Detections

| Command | What it does | Key |
|---|---|---|
| `nn-admin detections` | the last N detections, newest first, as JSONL (filters: `--since`, `--until`, `--min-severity`, `--status`, `--sensor`, `--path`) | `telemetry-read` |
| `nn-admin detection-set-status` | change a detection's triage status (`--id`, `--status`, `--note`); the agent appends a signed status event, the detection itself is never rewritten | `triage` |

### Evidence

| Command | What it does | Key |
|---|---|---|
| `nn-admin audit read` | print the signed audit log (`--json`: the rows as on disk) | none (root reads the file) |
| `nn-admin audit verify` | verify a copy of the audit log, offline: every row's hash link and signature (`--from`, `--agent-pubkey` or `--agent-sig-key`, `--expect-head`) | none |
| `nn-admin chain verify` | verify every signed chain on the host in full, offline, and the files against their signed head anchor | none |
| `nn-admin heartbeat export` | print the newest lines of the heartbeat chain (for an SSH forced command) | none |
| `nn-admin heartbeat watch` | on another host: verify the heartbeat and alert on silence, a broken chain, a replay, a stop or degraded health ([`HEARTBEAT.md`](HEARTBEAT.md)) | none |
| `nn-admin export status` | the OCSF export's configuration, worker, sinks and cursors ([`EXPORT.md`](EXPORT.md)) | `--key` for the signed read |
| `nn-admin export verify` | where the records arrive: check each exported record against the agent's public key and each chain's continuity | none |

### File integrity, network, canaries

| Command | What it does | Key |
|---|---|---|
| `nn-admin fim baseline` | queue a re-compute of the watched files' baseline (done at the next agent start) | `fim-manage` |
| `nn-admin fim status` | the watched paths, the baseline's and the drift log's state | `fim-read` |
| `nn-admin fim report` | the signed drift log, newest first (`--since`) | `fim-read` |
| `nn-admin net status` | what the network observation covers now, and what it cannot see | `--key` for the signed read |
| `nn-admin net flows` | the signed netflow log, newest first | `net-read` |
| `nn-admin net listeners` | the listening sockets the agent observed, newest first (events, not a snapshot) | `net-read` |
| `nn-admin net resolve` | the hostname the agent attributed to a destination IP, from the newest flow to it | `net-read` |
| `nn-admin net fingerprint` | a flow's rows with their JA3 / JA4 / SNI (`--flow-id`) | `net-read` |
| `nn-admin canary deploy` | install a canary, one of four kinds below; prints its id | `canary-manage` |
| `nn-admin canary deploy file` | a decoy file the agent writes at `--path` | `canary-manage` |
| `nn-admin canary deploy credential` | a decoy credential file (`--cred-family`, e.g. `aws`) the agent writes at `--path` | `canary-manage` |
| `nn-admin canary deploy process` | a decoy executable: the agent registers `--path` and `--fake-arg0` and writes **no** file — place the decoy yourself (a copy of `/bin/true` is enough) | `canary-manage` |
| `nn-admin canary deploy network` | a decoy destination (`--bind-addr`, `--bind-port`): a local connect to it trips the canary; the agent opens no listener | `canary-manage` |
| `nn-admin canary list` | the canary registry, newest first | `canary-read` |
| `nn-admin canary refresh` | write a canary's decoy again (`--canary-id`) | `canary-manage` |
| `nn-admin canary burn` | retire a canary for good (`--canary-id`): the agent stops watching it; a decoy file stays on disk, remove it yourself | `canary-manage` |

### Responses, COMBAT and the posture

Under the `alpha` profile the agent takes no response against the users'
programs ([`ALPHA_PROFILE.md`](ALPHA_PROFILE.md)); these commands matter
under `enforcing`.

| Command | What it does | Key |
|---|---|---|
| `nn-admin unlock` | release COMBAT: the agent tears the network isolation down and reads the tables back clear | `unlock` |
| `nn-admin force-posture` | set the posture (leaving COMBAT this way also needs `unlock`; prefer `unlock`) | `force-posture` |
| `nn-admin response status` | the contained processes, the quarantined files, the COMBAT stage | `audit-read` |
| `nn-admin response release` | return a contained process to the cgroup it came from (`--pid`) | `response-manage` |
| `nn-admin response restore` | write a quarantined file back out of the vault, as a new file, mode 0600 (`--vault-id`, `--to`); it may be malware: inspect it, do not run it | `response-manage` |
| `nn-admin remediate ransomware` | restore the files a process tree rewrote, from the copies taken before each first write (`--pid`, `--since`, `--dry-run`) | `response-manage` |

### Configuration, keys and the agent's lifecycle

| Command | What it does | Key |
|---|---|---|
| `nn-admin config overlay set` | sign an operator overlay (`/etc/northnarrow/*.local`: allowlists, FIM paths, the profile, …) and store it through the agent; it applies at the next agent start | `config-manage` |
| `nn-admin config overlay sign` | the same offline, for a stopped agent: writes `<file>.sig` | `config-manage` |
| `nn-admin config overlay status` | which overlays are present and whether each would load | none |
| `nn-admin policy show` | the per-rule response policy in force and the held responses | none |
| `nn-admin policy set` | validate, sign and apply a new per-rule policy ([`RULE_POLICY.md`](RULE_POLICY.md)) | `config-manage` |
| `nn-admin policy test` | replay sample events under a candidate policy, offline; nothing is signed or applied | none |
| `nn-admin trusted-installer-grant` | open a trusted-installer window (at most 600 s, ended by an agent restart): what an upgrade, an uninstall or a restart needs ([`INSTALL_UPGRADE_UNINSTALL.md`](INSTALL_UPGRADE_UNINSTALL.md) §3.7) | `trusted-installer` |
| `nn-admin shutdown` | stop the agent with a request signed by two distinct keys; the watchdog stands down | `shutdown` on one of the two keys |
| `nn-admin init` | generate a new admin keypair and append its public half to `admin.pub` (from a root shell, before the agent protects the file) | none |
| `nn-admin rotate-keys add` | add an admin key, with the roles one of the two signers holds | two keys, one with `rotate-keys` |
| `nn-admin rotate-keys revoke` | remove an admin key by its fingerprint (never the last one) | two keys, one with `rotate-keys` |

## 4. Exit codes

### `nn-admin`

The numbers are stable: scripts may rely on them. A command's own help says
which of them it uses.

| Exit | Meaning |
|---|---|
| 0 | success |
| 1 | a failure before or around the request: a file that cannot be read, a key that does not load, no capability manifest signed yet (`capabilities`), an overlay or policy present that would not load (`config overlay status`, `policy show`) |
| 2 | a usage error (an unknown option, a missing value: the help is printed); `unlock` / `shutdown`: the agent rejected the signature; `host-check`: warnings found, no check failed |
| 3 | `unlock` / `shutdown`: the agent has no pending challenge for this request (retry); `host-check`: a check failed (`FAIL`, `fail` in `--json`): the agent cannot run on this host as it is |
| 4 | rate-limited by the agent (the wait is printed; retry after it) |
| 5 | the agent could not be reached or answered something else: no socket or nobody listening on it (the agent is not running), protocol, a skewed clock, another install's agent id, an operation this agent does not know (an `nn-admin` of another release) |
| 6 | `shutdown`, `rotate-keys`: the quorum was not met (two distinct valid keys are needed) |
| 7 | the key is valid but lacks the role the command needs |
| 8 | evidence missing or altered: `audit verify`, `chain verify` (a `BROKEN` chain), `audit read` (lines that are not rows were skipped) — [`EVIDENCE_CHAINS.md`](EVIDENCE_CHAINS.md#exit-codes-of-the-verifiers) |
| 9 | the agent verified the request and did nothing: no such canary (`canary burn` / `refresh`), nothing to release or restore (`response`), the isolation could not be released (`unlock`, `force-posture` out of COMBAT: the posture stays COMBAT) — the reason is printed |
| 10 | `detection-set-status`: the change was not recorded (the agent could not append its chain: disk full?) |
| 17 | the host refused this user the agent's admin socket, a key, the agent id or (`chain verify`) a chain (permission denied): run it with `sudo`. It says nothing about whether the agent runs, nor about the chains. 11 to 16 are left to the alerts of `heartbeat watch` and `export verify` |
| 141 | the output was closed before everything was written (`nn-admin status \| head -1`) |

`heartbeat watch` and `export verify` have their own codes, one per alert:
[`HEARTBEAT.md`](HEARTBEAT.md) ("What the verifier checks") and
[`EXPORT.md`](EXPORT.md).

### `install.sh`

| Exit | Meaning |
|---|---|
| 0 | installed (or upgraded), the health check passed |
| 1 | refused or failed, nothing changed: a release check (the attestation, the checksums, the manifest), a prerequisite, a preflight, the trusted-installer window |
| 2 | a usage error: an unknown or conflicting option, a profile switch asked of an installed agent |
| 3 | an upgrade failed and was rolled back: the previous version runs again |
| 4 | an upgrade failed and its rollback could not be completed: the message says how to finish it ([`INSTALL_UPGRADE_UNINSTALL.md`](INSTALL_UPGRADE_UNINSTALL.md) §2) |
| 5 | refused, nothing changed: `/etc/ld.so.preload` names a library every program would load (the files are named), or the list cannot be read as a regular file; the agent and the watchdog would refuse to start with it ([`INSTALL_UPGRADE_UNINSTALL.md`](INSTALL_UPGRADE_UNINSTALL.md) §1) |
| 129, 130, 143 | interrupted by a signal (HUP, INT, TERM) |

### `uninstall.sh`

| Exit | Meaning |
|---|---|
| 0 | removed |
| 1 | refused or failed: not root, no confirmation, no key or a unit that did not stop |
| 2 | an unknown argument |
| 3 | the agent was wedged: the removal finishes at the next boot — reboot |
| 4 | removed, but processes the agent had contained were found: they were thawed and are listed — look at each (kill it, or let it run) |

### The agent

| Exit | Meaning |
|---|---|
| 0 | stopped (a signal), or `--build-features` printed its list (`--btf-check` and `--own-dropins`: below) |
| 1 | an error without a status of its own |
| 2 | the command line was refused, or a lab-only option was asked of a release build |
| 75 | a stop cut at its deadline (`EX_TEMPFAIL`); inside a signed trusted-installer window it is the operator's stop (`stop_deadline`) |
| 78 | refused to start (`EX_CONFIG`): a verification failed — a binary that is not the one the installer verified, a kernel layout it cannot read safely, a deny hook that did not attach — or the start's own check found a loader variable in its environment or an executable mapping of a library the release does not link (`start_self_check`) |

A refused start leaves its unit `failed` (the watchdog's restart limit
bounds any respawn), the reason in its journal
(`journalctl --namespace=northnarrow -u northnarrow-agent`) and, when the
audit chain could be written, a signed `agent_boot` row.
[`INSTALL_UPGRADE_UNINSTALL.md`](INSTALL_UPGRADE_UNINSTALL.md) §5.1 says how to
recover.

Two modes have codes of their own: `--btf-check <file>` exits 0 when the
kernel is supported, 2 when the agent would refuse it, 3 when the file
cannot be read or parsed; `--own-dropins check` exits 0 when no drop-in of
its units would be set aside, 3 when one would, and `--own-dropins
quarantine` 0, or 1 when one could not be moved.

### The watchdog

Every status of the watchdog, and what each means, is in the table of
[`INSTALL_UPGRADE_UNINSTALL.md`](INSTALL_UPGRADE_UNINSTALL.md) §3.9: 0 for a
stop it was told to make, 16 when its start refused itself, one status per
failure otherwise.
