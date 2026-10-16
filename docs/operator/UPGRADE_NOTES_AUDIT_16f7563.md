# Upgrade notes: the remediation of external audit 16f7563

What changes for an operator who upgrades from `v0.0.1-tappa9.0`, or from
an earlier `main`, to a build that carries the fixes of the external audit
of commit `16f7563` (Waves 0, 1 and 2, and the Wave 3 lots as they land; tracker:
[`docs/audit/EXTERNAL_AUDIT_16f7563.md`](../audit/EXTERNAL_AUDIT_16f7563.md)).
Every item below is a change of behaviour or a regression that
[`CHANGELOG.md`](../../CHANGELOG.md) `[Unreleased]` declares, grouped by
what the operator touches. Each names the finding (`NN-AUD-xxx`, with the
audit's own reference) and the lab PR that fixed it; the CHANGELOG entry
and the tracker note have the details and the lab evidence.

## Before you upgrade

1. Upgrade the three binaries together (`install.sh --upgrade` and the
   packages do). An `nn-admin` older than the agent reports the agent's
   numbered chain rows as broken (§8).
2. Downgrading the agent is not supported once this build has run: an
   older agent misreads the numbered chains and the new canary rows (§8).
3. A build from source installs only with `--source-tree`; an extracted
   release without its tarball and `SHA256SUMS` needs `--tarball`/`--sums`
   or `--allow-manifest-only` (§1).
4. A model kept outside a root-owned directory is not loaded: move it to
   `/var/lib/northnarrow/models/` (§7).
5. The host needs `/usr/bin/mountpoint` (util-linux) to start the agent
   (§1), and `nft` for the COMBAT soft egress block (§6): `install.sh`
   refuses a host without it unless `--without-nftables` (§1).
6. Keep the trusted-installer key at hand: more operations on the agent's
   own directories need a window (§2).
7. A parser or SIEM rule that reads the agent's journal lines: they carry
   no colour codes any more, and a value with a separator is quoted
   (§11).
8. A `.v1` list edited by hand is no longer applied: move the change into
   the list's signed `.local` overlay (§1).
9. A reader of `/etc/northnarrow/audit.log` that does not run as root (a
   log shipper, a script without `sudo`) loses access: give it a group
   with `install.sh --audit-group` (§8).

## 1. Installation and upgrade

- **No silent downgrade of the release checks** (NN-AUD-198 DEP-007, lab
  PR 148). `install.sh` refuses a tree without `MANIFEST.sha256` unless
  `--source-tree` is given, and a tree vouched for only by its own
  `MANIFEST.sha256` (no tarball + `SHA256SUMS`, no attestation) unless
  `--allow-manifest-only`. The flag is recorded in `install-manifest.json`
  (`verify_override`) and `nn-admin host-check` warns about it.
  **Regression:** a scripted install from a source tree needs
  `--source-tree`; an extracted release without its tarball and
  `SHA256SUMS` needs `--tarball`/`--sums` or `--allow-manifest-only`.
  See [INSTALL_UPGRADE_UNINSTALL.md §5.1](INSTALL_UPGRADE_UNINSTALL.md#51-installsh-verifies-the-release-itself).
- **A host without `nft` is refused** (lab follow-up, lab PR 165).
  `install.sh`, an `--upgrade` included, refuses before changing anything
  when `nft` (nftables) is missing, and names the command;
  `--without-nftables` goes on and is recorded in `install-manifest.json`
  (`prerequisite_overrides`). The `.deb` pre-depends on and the `.rpm`
  requires `nftables`. **Regression:** a scripted install or upgrade on a
  host without `nft` needs `nftables` first (or the flag); a bare
  `dpkg -i` / `rpm -U` needs it installed first (`apt-get install ./…deb`
  and `dnf install ./…rpm` pull it in). See
  [INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md), Prerequisites.
- **A removed install manifest refuses the boot** (NN-AUD-200 DEP-009, lab
  PR 148). Once the signed audit chain holds a verified boot of this
  install, a missing manifest stops the agent (exit 78, `agent_boot`
  refused); `NN_ALLOW_UNVERIFIED_BINARY=1` is for development hosts.
  **Regression:** a host restored without its install manifest does not
  start until `install.sh` runs again (recovery: §5.1 of the install
  guide).
- **The upgrade and uninstall drain wait for the agent's own programs
  only** (NN-AUD-197 DEP-006, lab PR 148). The agent lists its BPF program
  ids in `/run/northnarrow/bpf-own-ids`; a second BPF-LSM product on the
  host no longer makes the scripts give up with the agent already
  stopped. Upgrading from an agent older than the list falls back to the
  old count and names what is left.
- **Attestations must come from a release tag** (NN-AUD-201 SUP-001, lab
  PR 150). `install.sh` (gh and cosign) and the documented commands accept
  only the release workflow at a `v*` tag
  (`--cert-identity-regex '…release\.yml@refs/tags/v'`,
  `--deny-self-hosted-runners`). **Regression:** the artefacts of a
  `workflow_dispatch` run on a branch no longer pass the attestation step
  (`--require-attestation` refuses them).
- **Packages: check the origin before the package command** (NN-AUD-199
  DEP-008, lab PR 150). The `.rpm` is signed on tag builds and checked with
  `rpm --import` + `rpm -K`, or dnf with `localpkg_gpgcheck=1`; the public
  key and its fingerprint are published with the first signed release.
  The `.deb` is checked with the tag-bound attestation before `dpkg -i`.
  `dpkg --verify` and `rpm -V` compare installed files with the package
  database and say nothing about the package's origin. See
  [§6.1](INSTALL_UPGRADE_UNINSTALL.md#61-verify-a-package-before-installing-it).
- **The bpffs pre-flight fails the unit instead of skipping it**
  (NN-AUD-196 DEP-004, lab PR 149). The agent unit runs
  `ExecStartPre=/usr/bin/mountpoint -q /sys/fs/bpf`: without bpffs the unit
  is `failed` and listed by `systemctl --failed`, where it used to read
  "inactive (dead)". Every watchdog hold is recorded at
  `/run/northnarrow/watchdog.hold` and signed by the agent at its next
  start (`integrity_drift`, `watchdog_hold`). **Regression:** a host
  without bpffs shows a failed agent unit; a host without
  `/usr/bin/mountpoint` cannot start the agent.
- **A removed admin socket comes back, and no longer hides a frozen
  agent** (Wave 3: NN-AUD-358 WDG-007, NN-AUD-364 WDG-015, NN-AUD-359
  WDG-008, NN-AUD-360 WDG-010, lab PR 170). The agent checks
  `/run/northnarrow/admin.sock` every 10 s and binds it again when it was
  removed or replaced, recording a signed `integrity_drift`
  (`admin_socket_removed`). The watchdog treats a socket gone after the
  agent answered as a stuck agent: a `watchdog.tamper` ERROR and a record
  the agent signs as `admin_socket_vanished` within about a minute, and
  the usual recovery (SIGINT, then SIGKILL, then a restart) within about
  90 s. A socket that
  never came up (no admin plane, a slow start) is still not a reason to
  restart. Pidfiles are written without following a link (temporaries
  `.agent.pid.tmp`, `.watchdog.pid.tmp`). Exec respawn backend only: the
  agent's argv is kept at `/run/northnarrow/agent.argv`, a fallback argv
  is signed as `respawn_argv_degraded`, and exited agents no longer stay
  zombies. **Regression:** an agent that cannot bind its socket again (a
  directory left at the path) is restarted once; an agent without admin
  plane next to a stale socket file is no longer restarted every minute.
- **The model moved** (NN-AUD-053 LLMR-004, lab PR 105). The model and its
  tokenizer are loaded only when root owns them and every directory above
  them, closed to others; the default location is
  `/var/lib/northnarrow/models/`. A model that fails to load leaves the ADE
  off; the mock backend is no longer a fallback (NN-AUD-157 LLMR-005) and
  comes back only with `NN_ADE_ALLOW_MOCK=1`, for demos. **Upgrade note:**
  move a model kept elsewhere (or pass `--ade-model` with a root-owned
  path), or the agent runs on its rules alone.
- **The bootstrap admin key leaves `/etc`** (NN-AUD-072 DEP-001, lab PR
  96). A fresh install writes it to `/root/northnarrow-admin.key`
  (`--admin-key-out`); the package hooks open the trusted-installer window
  only with the key in `NN_GRANT_KEY`, never with one they find on the
  host, so an unattended upgrade without the key fails cleanly and leaves
  the agent running. While a private admin key sits on the host,
  `nn-admin host-check` reports `WARN admin_key` and the agent records
  `admin_key_on_host` (`integrity_drift`).
- **The agent's signing key is not readable by root** (NN-AUD-020 EVD-001,
  lab PR 107). Its public half is `/etc/northnarrow/agent.sig.pub`, which
  `nn-admin audit verify` reads. **Note:** a backup of `/etc` gets `EPERM`
  on `agent.sig.key` (recorded, ALERTED); the key is not meant to leave
  the host.
- **Canary templates** (NN-AUD-169 DEC-007, NN-AUD-170 DEC-008, lab PR
  143). `install.sh` replaces an installed template that is byte-identical
  to one an earlier release shipped, keeps an edited one (with a WARNING
  if it still names the product) and installs them 0640 in a 0750
  directory. Decoys deployed before keep their content, which names the
  product, and are checked only for their presence (a WARN at boot):
  refresh them (`nn-admin canary refresh`, §3) or burn and deploy again.
- **Detect-only no longer waives the audit log** (NN-AUD-093 MAIN-008, lab
  PR 118). `NN_DETECT_ONLY=yes` or `true` is reported like `=1`, and an
  agent in detect-only mode no longer starts without a writable audit log
  unless `NN_AUDIT_ALLOW_UNWRITABLE=1` is set (its own override, reported).
- **The shipped `.v1` lists are the release's** (NN-AUD-327 LLMR-015,
  Wave 3, lab PR 168). `fim-paths`, `netflow-blocklist`,
  `netflow-ja3-blocklist`, `process-comm-allowlist` and
  `netflow-comm-allowlist` used to be applied as they stood in
  `/etc/northnarrow`, and `install.sh` never replaced one that existed,
  `--upgrade` and the packages included: an upgraded host kept the lists
  of its first install. One installed before lab PR 78 still killed
  processes talking to `100.64.0.0/10` (CGNAT, Tailscale, EKS) or
  `198.18.0.0/15` (VPN clients), NN-L-NET-001. Now `install.sh` installs
  the release's lists at every run; the agent applies the copy it was
  built with, and the file only when it is that copy. An earlier
  release's list is a WARN at boot; any other content is an ERROR and a
  signed `integrity_drift` (`default_list_modified`, both SHA-256) at
  every boot; a list that is a symbolic link or a FIFO is not read
  (`default_list_unavailable`). `NN_OVERLAY_ALLOW_UNSIGNED=1` applies an
  edited list anyway, still recorded. **Regression:** a `.v1` edited by
  hand — the old `install.sh` comments called the blocklists "operator
  copies" — is not applied by this agent. `install.sh --upgrade` keeps it
  as `<list>.v1.operator`, installs the shipped list and prints the
  difference (`+` your additions, `-` shipped entries you removed, the
  overlay's own syntax) with the command to carry it over: `nn-admin
  config overlay set <list> --file <overlay> --key <config-manage key>`
  (applies at the next start). See
  [INSTALL_UPGRADE_UNINSTALL.md §1](INSTALL_UPGRADE_UNINSTALL.md#1-fresh-install).
- **The telemetry probe's DNS datagram stays on the host** (NN-AUD-278
  EVD-015, lab PR 169). The probe's datagram to `127.0.0.1:53` was a
  recursive query whose name carried the agent's pid and the time, and a
  forwarding resolver on the host (dnsmasq, BIND in forward mode) passed
  it upstream every minute. The nonce is now random and the datagram is
  flagged as a DNS response (`QR` set, `RD` clear), which a resolver drops
  instead of answering or forwarding; the sensors read only the name, and
  the probe still reports `dns` as seen. A listener on `127.0.0.1:53`
  still receives one datagram per round (`<16 hex>.probe.northnarrow.invalid`,
  flags `0x8000`); `--sensor-feasibility` sends the same kind.
- **A sensor that stops stops the agent** (NN-AUD-184 SNS-001, lab PR
  128). A telemetry task that ends is recorded in the signed audit log and
  the agent exits non-zero (`sensor_pump_exited`); the watchdog restarts
  it. Expect a restart where the agent used to run blind on that sensor.

## 2. Anti-tamper: what now needs a trusted-installer window

The window is `nn-admin trusted-installer-grant --key <key with
trusted-installer> --window-secs N`; `install.sh`, `uninstall.sh` and the
packages open it themselves.

- **New entries in the agent's directories** (NN-AUD-107 EBPF-015, lab PR
  152). A new file, link, symlink, FIFO or directory in `/etc/northnarrow`,
  the state directory, the agent's drop-in directory and the pin root, and
  any extended attribute or (6.2+) ACL change on a protected file but
  `security.selinux`, are refused outside a window and recorded
  (`op=create`, `mkdir`, `mknod`, `symlink`, `link`, `xattr`; NN-L-AT-001).
  **Regression:** an overlay dropped into `/etc/northnarrow` by hand,
  `systemctl edit northnarrow-agent` on a Debian-family host,
  `nn-admin config overlay sign` writing its `.sig` there and `nn-admin
  init` creating a missing `admin.pub` need a window. Overlays go through
  `nn-admin config overlay set`, which the agent writes. See
  [§3.8](INSTALL_UPGRADE_UNINSTALL.md#38-no-new-entries-in-the-agents-directories-external-audit-ebpf-015).
- **The units refuse a manual stop** (NN-AUD-014 EBPF-001, lab PR 94).
  `RefuseManualStop=yes`, and systemd's signals to the agent and the
  watchdog pass only inside a window. To restart: the window, then
  `systemctl kill -s SIGTERM northnarrow-agent` (the watchdog starts it
  again); to stop for maintenance, the watchdog first. A refused attempt
  is a signed NN-L-AT-001 detection and raises the posture to ENGAGED. See
  [§3.7](INSTALL_UPGRADE_UNINSTALL.md#37-stopping-and-restarting-the-agent).
- **The Debian drop-in is protected and checked** (NN-AUD-073 DEP-002, lab
  PR 93). `10-debian-perf-paranoid.conf` passes the integrity check only
  while it matches `deploy/systemd/10-debian-perf-paranoid.conf` byte for
  byte; changing it needs a window.
- **The COMBAT rulesets and carve-out are signed** (NN-AUD-011 ATP-001,
  NN-AUD-074 DEP-003, lab PR 92). `combat-rules.v4`, `combat-rules.v6` and
  `combat-allow.cidrs` are applied as shipped or with a `config-manage`
  signature for their exact content; anything else makes COMBAT use the
  built-in content (ERROR, signed `integrity_drift`). Store a carve-out
  with `nn-admin config overlay set combat-allow --file <cidrs> --key
  <key>`; `install.sh --upgrade` adopts one edited by hand under an
  earlier release with the grant key.
- **Carve-out lines that are too wide are skipped** (NN-AUD-098 ATP-010,
  lab PR 136). A line wider than /8 (IPv4) or /48 (IPv6), or naming the
  unspecified or a multicast address, is skipped with a WARN and refused by
  `config overlay set|sign`. **Regression:** a signed carve-out with such
  a line loses that line at the next COMBAT engage; `nn-admin config
  overlay status` names it.
- **Flags and shipped lists** (NN-AUD-096 ATP-008, NN-AUD-102 EBPF-008,
  lab PR 113). Clearing the immutable flag through the fsxattr interface
  (`xfs_io -c 'chattr -i'`) is refused like `chattr`; the shipped `.v1`
  lists (netflow and JA3 blocklists, comm allowlists) can no longer be
  appended to — tune them through their signed `.local` overlays.
- **The overlays' rollback floor** (NN-AUD-161 LLMR-014, lab PR 117; lab
  PR 160). The floor comes from the verified audit chain; an audit log
  that is gone, does not verify or was cut resets it, recorded in the
  signed chain. After a reset no overlay signed before it is loaded until
  it is signed again.
- **Overlays and key files are not read or written through a link**
  (NN-AUD-160 LLMR-013, NN-AUD-162 LLMR-016, lab PR 116; NN-AUD-086
  AUT-003, NN-AUD-087 AUT-004, NN-AUD-090 MAIN-005, NN-AUD-085 AUT-002, lab
  PR 115). A malformed line in `admin.pub` costs only its own key
  (recorded); the CLI refuses an admin private key that others can read
  (`chmod 600` it).
- **The window ends at its deadline in the kernel** (NN-AUD-094 ATP-003,
  NN-AUD-099 ATP-012, lab PR 114), not when the next event reaches the
  agent: size `--window-secs` to the maintenance.
- **An observing BPF guard is a missing deny hook** (NN-AUD-097 ATP-009,
  NN-AUD-100 ATP-013, NN-AUD-101 EBPF-004, lab PR 112). On a production
  build, `NN_BPF_DEFENSE_OBSERVE=1` makes the agent refuse to start unless
  `NN_ANTI_TAMPER_ALLOW_DEGRADED=1` is also set; the agent's ring buffers
  and drop counters are guarded like its other maps.

## 3. `nn-admin`: new and changed verbs, roles

- **`nn-admin chain verify`** (NN-AUD-108 EVD-002, NN-AUD-109 EVD-003,
  NN-AUD-112 EVD-009, NN-AUD-174 DEC-018, lab PR 160): every chain in
  full, against the signed head anchor `/etc/northnarrow/chain_heads.json`;
  exit 8 on a broken chain. `nn-admin audit verify` gains `--expect-head`
  and `--min-seq`; `nn-admin detections` leaves out rows that do not
  verify. Runbook: [EVIDENCE_CHAINS.md](EVIDENCE_CHAINS.md).
- **`nn-admin net status`** (NN-AUD-168 NET-019, NN-AUD-166 NET-012,
  NN-AUD-165 NET-009, lab PR 142), no key: the netflow rows held back from
  the rules by the per-uid pacing, the pending connects evicted, the
  network rings' drops and the network rules that cannot fire in this
  build (NN-L-NET-003).
- **`nn-admin response status|release|restore`** (NN-AUD-148 CMB-016, with
  the Low CMB-026, lab PR 123). `status` needs `audit-read`; `release
  --pid` and `restore --vault-id [--to]` need the new `response-manage`
  role, which no default allowlist and no `install.sh` key holds: give it
  to a dedicated key. `nn-admin status` shows the COMBAT stage and whether
  COMBAT is locked. See [COMBAT_RECOVERY.md §6](COMBAT_RECOVERY.md#6-undoing-a-response).
- **Read verbs answer newest first** (NN-AUD-080 ASK-006, NN-AUD-081
  ASK-007, NN-AUD-082 ASK-008, lab PR 139). `fim report`, `canary list`,
  `net flows` and `net listeners` read the active file then the rotated
  archives, newest row first, within the same budget; `truncated` means
  older rows were left out. `fim report` and `net flows` read the files
  `--fim-drift-file` and `--netflow-file` name. `net listeners`, `net
  fingerprint` and `net resolve` now answer with data (`ja3`/`ja4`/`sni`
  null: no TLS capture yet). **Regression:** a script that read the first
  line as the oldest must read the last.
- **Roles and connections** (NN-AUD-077 ASK-002, NN-AUD-078 ASK-003,
  NN-AUD-079 ASK-004, NN-AUD-083 ASK-010, NN-AUD-084 ASK-011, lab PR 138).
  Leaving COMBAT with `force-posture` needs a signer that also holds
  `unlock`; `rotate-keys add` delegates — each role of the new key must be
  held by a signer, `all` only by a signer holding `all`, and an omitted
  list counts as `unlock,audit-read`. A signed request must arrive on the
  connection that fetched the challenge, within 10 s (every `nn-admin`
  verb does so); the third failed signature on a connection is answered
  `RateLimited` and closes it, other connections are not affected.
  **Regression:** a `force-posture`-only key can no longer leave COMBAT
  (use `nn-admin unlock`), and a key holding only `rotate-keys` can no
  longer add keys with roles it lacks. See
  [COMBAT_RECOVERY.md §1.1](COMBAT_RECOVERY.md#11-what-the-install-key-can-do-roles).
- **`nn-admin canary refresh`** (NN-AUD-172 DEC-010, NN-AUD-173 DEC-011,
  lab PR 143) writes a decoy again from a new random seed, in place, and
  records it. A trip is a signed `trip` row read back at boot.
  **Regression:** a tripped canary stays tripped (recorded, not responded
  to) across restarts until `canary refresh`. Reading a decoy trips it:
  `nn-admin canary list` is the inventory, and shows the boot-time
  `decoy_check` rows.
- **`nn-admin verify-keys`** (lab PR 115) accepts the `admin.pub` that
  `install.sh` writes and shows each key's roles.
- **`nn-admin host-check`** gains the release-verification line
  (`verify_override`, lab PR 148), `nft` (NN-AUD-146 CMB-014, lab PR 119)
  and `admin_key` (lab PR 96); **`nn-admin status`** shows `ringbuf
  rejected` for malformed open-sensor records (NN-AUD-190 SNS-008, lab PR
  128).

## 4. Detection records: the response as it happened

- **The outcome follows the action** (NN-AUD-234 TST-018, lab PR 155). The
  bare action name now means it was carried out; otherwise the outcome
  follows it: `KillProcess (already gone)`, `KillProcessTree (refused:
  <reason>)`, `KillProcess (permission denied)`, `Quarantine (failed:
  <error>)`, `KillProcessTree (partial: 1 not killed, 1 spared)`. The action
  stays the first word, so a reader that keys on it still finds it;
  `suppressed (detect-only)` and `none` are unchanged, and records already
  written keep their text. A report that counts kills should count the
  bare action only.
- **Model recommendations** (lab PR 134). A model verdict that names a
  response is a detection whose response reads `advisory: <action>
  recommended by the model, not executed` (§7).
- **A model that does not answer leaves a record** (NN-AUD-156 LLMR-003,
  lab PR 133): a timeout or a backend error is an ADE Escalate of kind
  `ade_unavailable`, with no response, instead of a journal line.
- **New fields and spellings.** Netflow rows held back by the per-uid
  pacing carry `"decision_engine_skipped": true` (lab PR 142); a connect's
  row carries the process start (`proc_start_ns`, NN-AUD-167 NET-016, lab
  PR 146); query names use RFC 4343 escapes (`\046`, `\092`, `\DDD` for
  unprintable bytes, which were all `?`; NN-AUD-185 SNS-002, lab PR 136);
  a path the agent cannot place reads `mnt[<dev>:<ino>]/…`, a component cut
  at 31 bytes ends in `…`, an unreadable one is `?` (NN-AUD-187 SNS-005,
  NN-AUD-188 SNS-006, NN-AUD-189 SNS-007, lab PR 137); a change undone
  before the FIM drain looked is a drift row flagged `content_restored`
  (NN-AUD-121 FIMP-009, lab PR 135).

## 5. Rules: recorded instead of killed, and the reverse

Rule ids and severities change for some of these cases; the engine now
holds 76 rule ids (R007 registered twice, by design).

Now **recorded, not killed**:

- R007 for a process whose name only contains a miner's (`xmrig-cleanup`);
  an exact miner name, in the process name or the executed file's, still
  kills the tree. R006 for the distribution's `socat`, unless it runs a
  shell. A root exec of a system-tree tool under a package manager or
  configuration management (DKMS running `modprobe` under apt): the
  shipped process allowlist now applies (NN-AUD-133 PROC-009, NN-AUD-134
  PROC-010, NN-AUD-132 PROC-008, NN-AUD-126 NETR-006, lab PR 140).
- NN-L-FIM-002: a file created in a watched directory under `/home`,
  `/tmp`, `/var/tmp` or `/dev/shm` (a watched binary hardlinked there is
  still killed; NN-AUD-028 FIMR-006, lab PR 98). NN-L-NET-004 and -014: a
  long DNS name or one high-entropy label; the kill is for a tunnel's
  shape, 8 distinct high-entropy labels under one parent domain from one
  process within a minute (NN-AUD-036 NETR-002, lab PR 98).
- R009: root scripts run from a home or `/tmp` in an administrator's sudo
  session at a terminal, and package scriptlets (NN-AUD-042 PROC-007, lab
  PR 86).
- R017 no longer fires for a shell in `/usr/local/bin`, `/usr/sbin`,
  `/sbin` or `/nix/store`, trees only root can write (a `bash` installed
  in `/usr/local/bin` was killed at every login or `#!/usr/bin/env bash`
  script; NN-AUD-299 PROC-011, lab PR 166).
- Canaries: every access after the first, and a File or Credential canary
  read by a backup, anti-malware, indexing or sync program (add a generic
  tool such as `tar` or `rsync` in the signed `canary-readers.local`;
  NN-AUD-064 DEC-004, NN-AUD-065 DEC-005, lab PR 99).
- A process named like an allowlisted program whose executable cannot be
  read (NN-AUD-055 LLMR-012, lab PR 87); a staged binary's process inside a
  package transaction (NN-AUD-125 NETR-005, lab PR 126); a forwarded DNS
  leg two processes could have asked for (logged as ambiguous; NN-AUD-167
  NET-016, NN-AUD-164 NET-006, lab PR 146).

Now **killed, or answered, where they were recorded or missed**:

- Every rule that kills is evaluated before the rules that record, and
  the specific tool rules before the staging ones: a shell in a hidden
  home directory is killed (R017) where R008 recorded it, and
  `/tmp/insmod` is R011 (High, T1547.006), not R001 (Medium). A canary
  accessed in a way its type does not expect (a File decoy's path
  executed) draws NN-L-CANARY-001 instead of no verdict (lab PR 140).
- The rules that kill an exec whose executable is the payload itself —
  R001..R003, R009, R010, R017, R006, and R011..R013 for a copy in
  `/tmp`, `/var/tmp` or `/dev/shm` — kill its process tree: a dropper's
  forked children die with it (lab follow-up, lab PR 166).
  **Regression:** more processes are killed, all of them descendants of
  the exec (what it forked, the children it had when it executed the
  payload in place); never its parent or siblings.
- NN-L-NET-008 fires: the image is named at connect time, so a dropper's
  forked child that never execs is killed when it calls out. NN-L-NET-007
  and -018 treat IPv6 unique-local and link-local peers as internal
  (NN-AUD-125 NETR-005, NN-AUD-127 NETR-007, NN-AUD-128 NETR-008, lab PR
  126).
- A module under `/lib/modules` that no package installed and DKMS did not
  build, loaded by an unexpected loader, is killed like one from `/tmp`
  (NN-AUD-041 PROC-005, lab PR 109); one from a directory nested deeper
  than 16 levels is killed (NN-AUD-039 PROC-003, lab PR 86).
- FIM: a change of a watched file's permissions, owner or group is drift
  of its own — a set-uid bit or write for others on a system binary is
  judged as a rewrite of it, `chmod o+r /etc/shadow` as a change of it;
  `.ssh/authorized_keys2` and `/etc/ssh/authorized_keys` are judged like
  `.ssh/authorized_keys` (NN-AUD-116 FIMR-007, NN-AUD-117 FIMR-008,
  NN-AUD-118 FIMR-009, lab PR 111). A watched file replaced by a rename is
  judged like a modification (NN-AUD-026 FIMR-004, lab PR 102).
- FIM (Wave 3, lab PR 173): a process under `mandb` is no longer treated
  as a package transaction, so a user's crontab installed through it is
  killed (NN-L-FIM-007); the package carve-out ends with the transaction
  (30 s after the package manager was last seen running, 60 s after its
  exec if never seen); a second cron drop-in by one process within 2 s
  draws its own verdict; NN-L-FIM-011..014 fire on a cloud credential file
  replaced by a rename, truncated, chmod'ed or chown'ed; NN-L-FIM-010
  matches `.LOCKED` like `.locked` (NN-AUD-284 FIMR-010, NN-AUD-285
  FIMR-011, NN-AUD-286 FIMR-012, NN-AUD-287 FIMR-013). `/etc/crontab.bak`
  no longer fires as `/etc/crontab` (NN-AUD-288 FIMR-014). **Regression:**
  a process a maintainer script left running that writes a watched path
  after the transaction is killed; an in-place edit of a watched cloud
  credential file by another program gives two High verdicts.
- Package transactions (lab PR 175, a follow-up found in the lab): a
  package transaction is a package manager the host's root executed,
  while it runs or for 30 s after it was last seen running (60 s after its
  exec if never seen) — for the FIM rules, NN-L-NET-008, the chains and
  R009 alike. A program from `/tmp` forked by a user's `mandb` or
  `dpkg --version` (run with `LD_PRELOAD`) that calls out is killed by
  NN-L-NET-008 (it was recorded) and judged by NN-L-CHAIN-002/005/007; a
  root exec from `/tmp` under a root `mandb` is killed by R009 (it was
  recorded, and R001 did not run). **Regression:** for these rules a
  package manager not executed by the host's root (rootless Podman,
  unprivileged LXC or LXD) is no transaction; a process a transaction left
  behind that calls out from a staging directory or executes from a user
  path as root after the window is killed.
- New rule NN-L-NET-021 names a process that floods `listen()` or
  `io_uring_setup()` (NN-AUD-103 EBPF-009, NN-AUD-105 EBPF-013, lab PR
  129).
- A network canary trips: a local process connecting to its
  `--bind-addr` and `--bind-port` (`0.0.0.0` / `::`: the port at any
  address of this host) is killed with its tree (NN-L-CANARY-003,
  Critical). No network canary tripped before. The agent opens no
  listener on the port, and a connection from another host is not seen.
  `nn-admin canary deploy network` is refused when the address is not an
  IP address or a listener on this host serves the port; a network canary
  deployed before with such an address trips nothing (burn it and deploy
  it again). Lab PR 163, a follow-up found in the lab.

## 6. Posture and COMBAT

- **Scopes** (NN-AUD-135 POS-005, NN-AUD-137 POS-015, NN-AUD-136 POS-009,
  lab PRs 141 and 161). A process without a login uid is scoped by the
  systemd unit or container its cgroup names, and a container (rootful or
  rootless, the units of a systemd inside it included) is an actor of its
  own whoever started it; a signal that cannot be placed corroborates
  nothing and locks nothing. One exec from `/tmp`,
  `/var/tmp` or `/dev/shm` raises `StagingExec` (ENGAGED, never
  corroboration). **Detection change:** a plain staged binary followed by
  another signal from the same session stays at ENGAGED (R001..R003 still
  kill the exec), and an attack split between a login session and a
  container it starts no longer corroborates across the two.
- **Corroboration and credential reads** (NN-AUD-305 POS-008, NN-AUD-303
  POS-006, NN-AUD-304 POS-007, lab PR 172). Each scope keeps its own
  corroboration signals (16 at most, the ledger 256), and a repeated signal
  refreshes its entry: a flood from one user or unit no longer evicts
  another actor's evidence, so that actor's next signal reaches the COMBAT
  it reached without the flood. A full ledger is logged once ("posture
  corroboration ledger full"). The triggers' correlation windows bound
  both sides of the focal event. A service uid (1..999) reading
  `/etc/shadow`, `/etc/gshadow` or `/etc/sudoers` with a shell, an
  interpreter (`php-fpm` included), a generic file tool or a binary
  outside a system tree raises `SensitiveFileAccess` (ALERTED); a daemon
  reading them with its own binary does not. **Detection change:** a
  service account in group `shadow` whose scripts read these files (a
  backup job, an application checking passwords itself) raises ALERTED.
- **Package transactions and `mandb`** (lab PR 175, a follow-up found in
  the lab). The persistence, staging-exec and mass-write arms exempt a
  package transaction only (a package manager the host's root executed,
  while its run covers the event), and the mass-write arm `mandb`'s own
  cache rebuild as root or a system account. What a user's `mandb` (or
  `dpkg --version`) run with `LD_PRELOAD` forks raises
  `PersistenceMechanism` for a crontab and `ConfirmedIntrusion` for a
  staged exec with a second factor or a mass rewrite. A package manager a
  user runs (a rootless `podman build`) is exempt for what it writes in
  that user's container storage: `~/.local/share/containers/`,
  `/run/user/<uid>/containers/`, `~/.local/share/lxc/`, a
  `/var/lib/lxc/<name>/` the user owns, or its own container's root
  overlay there. **Detection change:** its writes outside that storage
  (the user's home, a bind-mounted directory, the host's paths) count; a
  build whose storage is elsewhere (`storage.conf`), under
  `fuse-overlayfs`, or in an LXD pool can raise `ConfirmedIntrusion`; a
  user's own `mandb` that rewrites many files raises `ConfirmedIntrusion`.
- **Telemetry loss** (NN-AUD-184 SNS-001, NN-AUD-190 SNS-008, NN-AUD-191
  SNS-009, lab PR 128): a security ring losing more than 64 events in 10 s
  raises the posture to ALERTED (`TelemetryLoss`), never as corroboration
  for COMBAT, and not during a package transaction or a window.
- **The ladder** (NN-AUD-139 CMB-007, NN-AUD-143 CMB-011, NN-AUD-144
  CMB-012, NN-AUD-146 CMB-014, lab PR 119). Its side effects run in order
  on a worker thread; a stand-down waits for a step already under way. A
  soft egress block that did not take effect (no `nft`) is recorded and
  shortens INVESTIGATE to 10 s; a tree past 1,024 processes escalates.
- **Containment** (NN-AUD-142 CMB-010, NN-AUD-145 CMB-013, NN-AUD-147
  CMB-015, NN-AUD-149 CMB-017, lab PR 121; NN-AUD-138 CMB-004, NN-AUD-150
  CMB-019, lab PR 120). A released process goes back to its systemd unit,
  never to the root cgroup; kills go through a pidfd checked against the
  process the event named, and a tree that keeps forking is frozen in a
  cgroup of its own and killed as a whole.
- **Control-surface files** (lab PR 162, a follow-up found in the lab).
  A create, change, delete, rename, `chmod` or `chown` of one of the ten
  anti-tamper control-surface files (NN-L-FIM-024,
  [`anti-tamper-honeypots.md`](anti-tamper-honeypots.md)) now raises the
  posture to a locked COMBAT on its own (`ControlSurfaceTamper`), as a
  refused write to the agent's files does; the rule's kill was already
  there. Not raised for the agent's own writes, nor inside a
  trusted-installer window. **Detection change:** a host where a tool
  touches one of these files (a `sed -i` over `/etc/northnarrow/*.conf`)
  ends in a COMBAT that only a signed release ends.
- **Host isolation is the ladder's alone** (NN-AUD-050 CMB-006, lab PR
  103): an ADE `Isolate` verdict no longer adds an nftables blackout of
  its own; an older agent's leftover chains are removed at start.

## 7. The model (ADE) and RAG

- **The ADE is a consultant** (product decision, lab PR 134). A model
  verdict that names a response (Kill, KillTree, Quarantine, BlockNetwork,
  Isolate) is recorded as a recommendation and nothing runs; responses
  stay with the deterministic rules and the COMBAT ladder.
  `NN_ADE_ENFORCE=1` lets the verdicts act again; it is a weakening
  variable, recorded at every start in the signed audit log
  (`integrity_drift`, `weakening_env`).
- **What the model is shown** (NN-AUD-158 LLMR-008, NN-AUD-163 LLMR-017,
  NN-AUD-155 LLMP-013, lab PR 133; NN-AUD-177 XAI-004, NN-AUD-182 XAI-013,
  lab PR 144; NN-AUD-151 LLMP-003 and the rest of lab PR 132). The prompt
  fits a 3,328-token window by dropping the oldest correlated events, never
  the system prompt; an event whose prompt cannot fit is escalated without
  a model call. The system prompt is v1.1 (observed strings are evidence,
  never instructions; three behaviour-based examples instead of five).
  **Regression:** the model sees a different correlated context — at most
  20 events, those sharing the process, parent or file first. Its
  behaviour after these changes has not been re-measured on a model host
  (tracker, follow-ups).
- **One evaluation at a time** (NN-AUD-004 LLMR-002, lab PR 82). An exec
  that arrives while the model is busy is judged by the rules only and
  counted. Since lab PR 162 the model is shown an exec's `ProcessSpawn`
  (the child's name, arguments and file) and its `ExecCheck` only when no
  spawn follows within 2 s; before, the `ExecCheck` (the parent's name)
  took the slot and the spawn was dropped (found in lab PR 144).
- **Tokenizer** (NN-AUD-091 MAIN-006, lab PR 151): Rust `fancy-regex`
  instead of the C Oniguruma library; same pieces and ids on the golden
  corpus, a full prompt in about 7.5 ms instead of 6.
- **RAG** (NN-AUD-175 XAI-001, NN-AUD-179 XAI-009, NN-AUD-176 XAI-002,
  NN-AUD-180 XAI-010, NN-AUD-183 XAI-018, lab PR 145; off by default,
  `NN_ADE_RAG_ENABLED`). RAG starts only when the corpus directory holds
  exactly the dumps `docs/kb-sources/kb_index.json` pins, byte for byte;
  otherwise the agent runs without RAG, with a WARN and a signed
  `subsystem_degraded`. The index is built in memory at every start
  (about 0.4 s); `NN_ADE_RAG_INDEX_DIR` is ignored with a WARN.
  **Regression:** a knowledge-base update needs an agent release. The
  dumps are byte-identical to the previous ones, but `kb_index_hash`
  changed (`4d335aed…` → `b6cd7d32…`) when the Sigma pin became a commit
  (NN-AUD-194 WDG-011, lab PR 149).

## 8. Evidence chains

- **Numbered rows and anchored heads** (NN-AUD-108 EVD-002, NN-AUD-109
  EVD-003, NN-AUD-112 EVD-009, NN-AUD-174 DEC-018, lab PR 160). Rows of
  `audit.log` and the canary chains carry their position (`seq`) and a
  per-chain domain tag; the rotating logs checkpoint their active file; the
  heads of all chains are anchored in the signed
  `/etc/northnarrow/chain_heads.json` (at start, every 5 minutes, at
  stop). Every start compares the files with it and reports a cut,
  emptied, deleted or rewritten chain (ERROR, signed `integrity_drift`
  `chain_truncated`, …). Existing chains keep verifying and are numbered
  from their current length (`chain_numbering_started`). **Regression:**
  an `nn-admin` older than the agent reports numbered rows as broken;
  downgrading the agent is not supported. Runbook:
  [EVIDENCE_CHAINS.md](EVIDENCE_CHAINS.md).
- **Canary registry rows** (lab PR 143). An older agent skips the new
  `trip` and `decoy_check` rows as unreadable, re-arms tripped canaries and
  chains its next row to the last row it could read, which an off-host
  check then reports as broken: another reason not to downgrade.
- **Tails and rotation** (NN-AUD-110 EVD-004, NN-AUD-115 EVD-018, lab PR
  131). A forged or torn tail line of a signed log is cut and recorded in
  the signed manifest; a rotation never replaces an existing file, it moves
  to the next free name and records the foreign entry.
- **Netflow commits in batches** (NN-AUD-168 NET-019, lab PR 142): one
  fsync at most every 100 ms, so a crash of the host can lose the last
  100 ms or tear the last row, which the next open cuts and attests.
- **The evidence files are closed to other users** (NN-AUD-281 EVD-019,
  lab PR 169). `audit.log` and `chain_heads.json` in the world-readable
  `/etc/northnarrow` were `0644`: any local user read the key
  fingerprints, the callers' pid/uid/comm, the drift details and which
  sensor was in a `telemetry_gap`. They are created `0640` (root and the
  file's group), and `install.sh` (install, `--upgrade`, the packages'
  configure step) closes an existing copy. The chain logs under
  `/var/lib/northnarrow` (detections, status events, netflow and its
  listeners, FIM baseline and drift, the canary chains, their archives
  and manifests) are created `0600` and closed the same way; the
  directory's `0700` already kept other users out, a copy that keeps the
  mode did not. `--audit-group GROUP` (or `NN_AUDIT_GROUP`) gives the two
  `/etc` files an existing group for a log shipper; every later upgrade
  keeps the group, and the agent never changes the mode of a file it did
  not create. On a package install, `chgrp` the two files inside a
  trusted-installer window (§2) once. **Regression:** a non-root reader of `audit.log` or
  `chain_heads.json` gets `EACCES` until it has the group; `nn-admin` run
  as root, `sudo`, and the lab scripts (all run as root) are unaffected.
  Still readable by design: `admin.pub`, `agent_id`, `agent.sig.pub`,
  `install-manifest.json`, the shipped lists and the honeypot baits.
- **Findings that come back are reported again** (NN-AUD-114 EVD-013,
  NN-AUD-113 EVD-012, NN-AUD-111 EVD-006, lab PR 130): a finding that goes
  away is signed as `integrity_drift_cleared`; detections dropped from a
  full queue are counted in a signed `detections_dropped` entry per minute.

## 9. Release signing: actions for the maintainer

The rpm signing of lab PR 150 (NN-AUD-199 DEP-008) needs a key that does
not exist yet. Before the next `v*` tag:

1. Create the rpm signing key; commit its public half at
   `deploy/release/RPM-GPG-KEY-northnarrow.asc` and publish its
   fingerprint.
2. Store the private half as `RPM_SIGNING_KEY` (and
   `RPM_SIGNING_PASSPHRASE`, if any) in the `release-signing` environment,
   with deployments limited to `v*` tags.
3. Protect the creation of `v*` tags with a ruleset.

**Regression:** until then a tag release stops at the `rpm-sign` job and
nothing is attested or published. A signed apt repository for the `.deb`
is the other part of the same residual; until there is one, the `.deb` is
checked with its tag-bound attestation.

## 10. Lab, range and development hosts

- **Base images are verified** (NN-AUD-207 LAB-002, NN-AUD-213 LAB-008,
  NN-AUD-214 LAB-009, NN-AUD-220 LAB-015, lab PR 156). **Regression:** a new
  base image needs `gnupg` and `gpgv` on the host and, once, the vendor's
  key from the network; an image downloaded before is used with a warning
  until `nn-lab.sh verify-image` records it; a guest installed before the
  `trusted-installer` role must be recreated.
- **`tamper-check`** (NN-AUD-208 LAB-003, NN-AUD-209 LAB-004, NN-AUD-210
  LAB-005, NN-AUD-212 LAB-007, lab PR 154). **Regression:** the run deletes
  the agent journal namespace's archived files (case C57c).
- **Privileged fixtures** (NN-AUD-232 TST-011, NN-AUD-233 TST-012,
  NN-AUD-230 TST-009, lab PR 158). The honeypot e2e suite refuses to run
  without root, outside an nn-lab guest unless
  `NN_TEST_DISPOSABLE_HOST=1`, and while an agent or watchdog runs; the
  iptables self-tests run in their own binary, `fixture_selftest`.
  `docs/verify-2b.sh` is retired and the lab checks the guest's `bpftool`
  first (NN-AUD-206 LAB-001, NN-AUD-224 TST-001, lab PR 153).
- **One forced eBPF rebuild** (NN-AUD-106 EBPF-014, lab PR 147). A build
  stamp written before this change reads as absent and the agent build
  stops on "UNSTAMPED eBPF OBJECT" until `cargo xtask build-ebpf` (or
  `cargo xtask build --release`) runs once.
- **Default CPU target** (NN-AUD-205 SUP-017, lab PR 150).
  `.cargo/config.toml` defaults to `target-cpu=x86-64-v2`. **Regression:**
  dev, lab and range builds decode with candle at the x86-64-v2 ISA unless
  they opt into `native` ([`docs/PERFORMANCE.md`](../PERFORMANCE.md) §1).
- **`ade_attacks`** (NN-AUD-195 WDG-R01, lab PR 149) exits non-zero when it
  would score the mock backend, and names the backend next to the rate.
- **The range bootstrap** takes the rule count from the validation registry
  (76) instead of a fixed 69 (NN-AUD-217 LAB-012, lab PR 159).
- **The posture demo** (NN-AUD-430 POS-013, lab PR 172):
  `cargo run --example posture_demo` needs `--features posture-demo`, which
  compiles the test-only `admin_release_combat(bool)` it calls; no
  production build contains that call.

## 11. The journal: one event, one line (Wave 3)

- **No forged lines** (NN-AUD-413 LAB-023 and the Wave 3 cross-cutting
  finding, lab PR 167). A name another user chooses — a file in `/tmp`,
  a `comm`, a DNS name — could hold a newline, and the journal showed
  the rest as an entry of its own (a fake `ANTI-TAMPER DENIAL` or
  `VERDICT`). Every event of the agent and the watchdog is now one
  journal line. What the operator sees:
  - **no ANSI colour codes** in the journal (they stay on a terminal);
  - a value another user names is printed as it is when plain
    (`comm=bash`, `target_filename=/tmp/x`), and **quoted** when it holds
    a space, `"`, `=`, `\` or a control character, with those escaped:
    `target_filename="/tmp/x\nANTI-TAMPER DENIAL …"`. **Regression:**
    `reasoning` on `VERDICT (rule)` and `VERDICT (ADE)` lines is a
    sentence, so it is always quoted now (`reasoning="…"`);
  - a control character anywhere in a line (an error quoting a path)
    reads `\n`, `\r`, `\t` or `\xNN`, and a line over 16 KiB ends in
    `[cut: N more bytes]`.
  The signed chains are the evidence; the journal is a convenience.
- **NN-L-AT-001 records name the refused operation** in a new
  `"operation"` field (`signal`, `ptrace`, `write`, `unlink`, `bpf_map`,
  …), absent on every other record. **Regression:** an `nn-admin` older
  than the agent reports those records as broken: upgrade the three
  binaries together.
- **Lab:** `tamper-check` reads its evidence from the signed records: the
  column reads `deny=signal×1` (detections) where it read `op=signal×1`
  (journal), and its journal part only `errors=`.
