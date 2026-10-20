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
10. `iptables`, `ip6tables`, `nft` and `rpm` must be the distribution's,
    in `/usr/sbin`, `/usr/bin`, `/sbin` or `/bin`: a copy only under
    `/usr/local` is no longer run (§6).

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
- **Units and package hooks** (Wave 3: NN-AUD-386 DEP-014, NN-AUD-381
  DEP-005, NN-AUD-389 DEP-017, NN-AUD-382 DEP-010, lab PR 184). The
  watchdog's bounding set is `CAP_BPF CAP_SYS_PTRACE` (no
  `CAP_SYS_ADMIN`). On a host with no more memory than the agent's
  `MemoryMax=11G` the agent starts with `oom_score_adj` 0, not -500, with a
  WARN `memory cap at or above the host's memory`, and the integrity check
  expects 0 there; larger hosts keep -500. The agent's unit sets
  `LogRateLimitIntervalSec=30s` and `LogRateLimitBurst=50000` (journald's
  default is 10000). A `.deb` operation that fails after the units were
  stopped, and whose rollback leaves one of them down, now fails its
  rollback hook with the unit named on the terminal and at `auth.err`
  (tag `northnarrow-pkg`). **Regression:** such a failed rollback leaves
  the package half-installed (it used to read "installed" with no agent);
  on small hosts the agent is an ordinary OOM candidate (the watchdog
  brings it back); an agent burst can now take 50000 lines per 30 s of the
  namespace's 1 GiB; the watchdog's `exec` respawn backend inside its
  unit, already unsupported, now starts the agent without `CAP_SYS_ADMIN`
  too.
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
- **Install and uninstall scripts** (Wave 3: NN-AUD-388 DEP-016,
  NN-AUD-440 DEP-020, NN-AUD-384 DEP-012, lab PR 194). `install.sh` finds
  the tarball's line in `SHA256SUMS` by its exact name (it was a regular
  expression) and refuses a file that lists it with two different
  checksums. With both units stopped and the last agent's pin root still
  protected, `install.sh --grant-key` and `uninstall.sh --grant-key` start
  the installed agent for the trusted-installer window and stop it again
  (it is not restarted); without a key they name the two ways out
  (`--grant-key`, or disable the units and reboot). `uninstall.sh` stops
  the units before disabling them and, when a stop is refused (no
  window), ends there with nothing disabled or removed; its summary also
  names `/etc/northnarrow/admin.key`, the private key installs before lab
  PR 96 left. **Regression:** a `SHA256SUMS` with two different lines for
  the tarball no longer installs (it used the first); `uninstall.sh`
  without `--grant-key` on a running, protected host exits 1 at the stop
  (it used to disable the units first and exit 1 at the pin root), and
  scripts that read its output see `stopping <unit>` and `disabling
  <unit>` where it printed `stopping + disabling <unit>`.
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
- **Canary templates and decoy paths are checked at deploy** (NN-AUD-341
  DEC-016, NN-AUD-342 DEC-017, NN-AUD-340 DEC-015, Wave 3, lab PR 178).
  A template in `/etc/northnarrow/canary-templates/` is read only from a
  regular file of at most 64 KiB, never through a symbolic link or from a
  FIFO; any `{{` left after rendering, and an `azure`, `gcp` or `docker`
  template that does not render JSON, are errors. **Regression:** such a
  template now refuses `nn-admin canary deploy` and `canary refresh` for
  its family (the journal names the file); it used to deploy, or to block.
  A decoy path with a control character or of 4096 bytes or more is
  refused, and one written with `//` is deployed and recorded under its
  normal form. An unreadable line in `canaries.jsonl` or
  `canary_access.jsonl` (not UTF-8, or over 1 MiB) no longer switches
  deception off: it is skipped and recorded (`chain_lines_unreadable`).
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
- **The agent's directories are never followed through a link**
  (NN-AUD-260 ATP-007, lab PR 189). The agent refuses to start when
  `/var/lib/northnarrow` is a symbolic link, or holds one where it keeps its
  own entries (`quarantine`, `quarantine/vault`, `detections`, the chain
  logs); the error names the link and its target, and the target is not
  touched. It used to chmod the target 0700, chown it to root and — since
  lab PR 152 — refuse every new entry in it: a link to `/etc` would have
  made `/etc` refuse new files. `/etc/northnarrow`, the unit drop-in
  directory and the bpffs pin root as links are not registered (nor, for
  the pin root, chmodded or pinned into) and refuse the start the same way
  (`DENY HOOK SHORTFALL`, a failed step `linked agent directory` or `bpffs
  pin root`); a file of the agent's that is a link is registered as the
  link, not its target. **Regression:** an install that put the state
  directory elsewhere with a symbolic link does not start: move the
  directory back and bind-mount the other location instead
  (`mount --bind /data/nn-state /var/lib/northnarrow`, or a `.mount` unit
  ordered before `northnarrow-agent.service`). A pin-root link goes with a
  remount of `/sys/fs/bpf` (agent stopped).
- **The anti-tamper health line counts hooks** (NN-AUD-264 ATP-016, lab PR
  189). `deny_attached=N deny_expected=N` keep their names; a failed FS
  bootstrap now reads 3 of 16 (task_kill, ptrace, the BPF guard), not 15
  of 16, and the `DENY HOOK SHORTFALL` line carries `missing=[…]` (the
  deny hooks not attached and armed) and `infra_failed=[…]` (failed steps
  that are not hooks: the boot-zeroed ptrace override, the pin
  registration, a linked directory). Both refuse the start as before. A
  start under `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`, and missing observe hooks
  (module-load, the bpf() observer, the role watch), are now also in the
  signed chain: one `subsystem_degraded` for each of the two, with what is
  missing.
- **Foreign `link_*` entries in the pin root are reported, not adopted**
  (NN-AUD-265 ATP-017, lab PR 189). Only pins whose link runs one of the
  agent's programs are registered as its own; every other `link_*` entry
  (a stale pin of an earlier build, a planted one) is a WARN and one signed
  `integrity_drift` (`foreign_pin`) at boot, and is not removed. 64 or more
  of them no longer refuse the start. Remove them inside a window, or with
  a remount of `/sys/fs/bpf` with the agent stopped.
- **overlayfs, FUSE and NFS paths are attested** (NN-AUD-267 EBPF-016, lab
  PR 189). A boot that protects or watches a path on one of them logs a
  WARN and writes one signed `subsystem_degraded` (`reason:
  inode_identity_unverified`): there the agent cannot vouch that a deny or
  a FIM record follows. A host with an overlay root gets it at every boot.
  See
  [KERNEL_COMPATIBILITY.md](KERNEL_COMPATIBILITY.md#overlayfs-fuse-and-nfs-inode-identity-unverified-lab-pr-189).

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
- **Who may use the admin socket** (NN-AUD-238 ASK-012, lab PR 179). The
  agent checks each peer's `SO_PEERCRED`: uid 0 is served (the agent runs
  as root, so its own uid is the same), any other uid — and a peer whose
  credentials cannot be read — is closed without a reply, logged
  (`INTEGRITY DRIFT`, at most every 10 s) and recorded as a signed
  `integrity_drift` `admin_socket_foreign_peer` (one per 10 minutes, with
  the count of the others). The socket stays 0600 in a 0700 directory;
  the check holds when either was widened. **Regression:** a non-root
  process (a monitoring script, a dashboard user) can no longer reach the
  socket by widening its mode: run it as root or through `sudo nn-admin`.
  A descriptor a root process opens and hands on keeps root's credentials
  — the check is on the process that connected. The journal line names
  the refused uid, pid, `comm` and executable.
- **Signed requests: one shape, one key per fingerprint** (NN-AUD-244
  AUT-001, NN-AUD-245 AUT-005, NN-AUD-246 AUT-006, lab PR 192). A signed
  request carries at most 8 signatures, and its payload names the
  request's operation in both its tag and its fields; anything else is
  refused before a signature is checked (exit 2 and 5 respectively). The
  watchdog refuses a shutdown marker with more than 8 signatures (and
  respawns the agent). `rotate-keys add` of a key whose 8-hex fingerprint
  a different installed key already holds is refused as a collision, and
  `rotate-keys revoke` of a fingerprint shared by two different keys
  removes nothing (both lines went); both exit 2, and the agent's journal
  (`admin.rotate_keys`) says which refusal it was. **Regression:** only
  for such a colliding pair, which `nn-admin` never creates: remove the
  line you mean by hand. Every `nn-admin` verb, the wire format and every
  existing signature are unchanged.
- **`nn-admin` no longer creates `agent_id`** (NN-AUD-252 MAIN-010, lab
  PR 185). Every verb that signs for the agent's identity, and `config
  overlay status`, used to mint `/etc/northnarrow/agent_id` when it was
  missing — an identity the agent then adopted at its first start without
  a trace. They now stop with "agent_id not found at …: the agent creates
  it at its first start" (exit 5) and create nothing. **Regression:** run
  `nn-admin` after the agent's first start; to sign overlays before it,
  pre-seed `agent_id` yourself (32 hex characters and a newline, mode
  0644, not all zeros). `install.sh` already does nothing of the kind
  before the first start.
- **The verifiers on a damaged or large file** (NN-AUD-256 MAIN-014,
  NN-AUD-280 EVD-017, NN-AUD-283 EVD-022, lab PR 190). `nn-admin chain
  verify` reports an empty or cut sealed archive as that chain's `BROKEN`
  line and goes on (it aborted before printing any chain); `audit read`
  prints every row and names each line that is not a row on stderr;
  `audit verify` names the first such line and the rows verified before
  it; all of them read one line at a time (a line over 16 MiB is reported,
  not read), and archives past seq 999,999 are seen. **Regression:**
  `audit read` exits 8 (was 1) on a log with lines that are not rows, and
  `audit verify` exits 8 (was 1) on such a line. The exit codes:
  [EVIDENCE_CHAINS.md](EVIDENCE_CHAINS.md#exit-codes-of-the-verifiers).
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
- **`nn-admin status` says detect-only and what the audit log lacks**
  (NN-AUD-310 CMB-018, NN-AUD-318 CMB-027, lab PR 193). Two new lines:
  `response mode` — `enforcing`, or `DETECT-ONLY (NN_DETECT_ONLY=1)` /
  `(--detect-only)`: no response action and no COMBAT isolation touch the
  system — and `combat evidence` — `complete`, or the COMBAT stage
  transitions the signed audit log did not get when they happened (since
  boot), how many still wait to be written, how many were dropped (§6).
  `--json` gains `detect_only`, `detect_only_source`,
  `combat_evidence_unrecorded`, `combat_evidence_pending` and
  `combat_evidence_dropped`. **Regression:** an `nn-admin` newer than the
  agent cannot read the agent's `status` (a decode error, as for every
  field added to it since Tappa 10.8), nor can a watchdog newer than the
  agent (its ping decodes the same reply, and fails): upgrade the binaries
  together; an older `nn-admin` or watchdog reads a newer agent's reply
  without these fields.
- **A closed pipe** (lab PR 188, a follow-up found in the lab): `nn-admin
  status | head -1` and every other command whose stdout or stderr closes
  early end quietly with exit 141 (128 + SIGPIPE; it aborted with 134 and
  a panic message). Under `set -o pipefail` such a pipeline fails, as with
  any tool the signal ends.

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
- Process rules (Wave 3, lab PR 177): R015 (`base64`, `xxd`, `openssl`)
  and R016 (`gdb`, `strace`, `ltrace`) record an exec by `nobody` (65534)
  or by a `DynamicUser=yes` unit's account (61184..65519), as by a system
  account (1..999); root, users and their containers' sub-uids stay out
  (NN-AUD-300 PROC-012). R008 records an executable run from anywhere
  under `~/.cache/` or `~/.config/`, except the directories of named tools
  that run their own executables there: Go's build cache, Bazel and
  Bazelisk, Playwright, Puppeteer, Cypress, Selenium Manager, pre-commit,
  uv, Poetry's virtualenvs, yay, paru, Coursier's JDKs, JetBrains
  Gateway, and the extension storage of the VS Code-family editors (Code,
  Code - OSS, VSCodium, Cursor) and coc.nvim; `~/.config/systemd/` and
  `~/.config/autostart/` are never exempt (NN-AUD-301 PROC-013). These
  are Medium records: nothing more is killed. **Regression:** another
  tool's native executable under `~/.cache/` or `~/.config/` (Sublime
  Text's language servers, NixOS's `appimage-run`) draws an R008 record at
  each run, with no allowlist to exempt it; a `nobody` or `DynamicUser=`
  daemon running one of the six tools draws an R015 or R016 record —
  exempt the program in the signed `process-comm-allowlist.local`.
- Network rules (Wave 3, lab PR 186): a listener on 22, 53, 80, 443,
  8080 or 8443 is exempt from NN-L-NET-006 and -019 only when its program
  is installed in a root-owned tree (`/usr`, `/opt`, `/snap`, `/bin`,
  `/sbin`, `/lib`, `/lib64`, `/nix/store`) — the executable and, for an
  interpreter, the script it runs by an absolute path; nginx, sshd,
  systemd's socket units and systemd-resolved stay quiet. Any other
  listener there is judged as on any other port (NN-AUD-298 NETR-015).
  One DNS lookup of a long name with a high-entropy label gives one
  record, NN-L-NET-014's, where NN-L-NET-004 added a second (NN-AUD-428
  NETR-016). NN-L-NET-010 keeps its five C2 ports: 443 is not added.
  **Regression:** a developer server on 8080 or 8443 — `python3 -m
  http.server`, a script or binary in a home (node under `~/.nvm`), an
  inline program — draws a Medium record (NN-L-NET-019 on `0.0.0.0` or
  `::`, NN-L-NET-006 on another address) and the posture goes to ALERTED,
  as it already did on 8000 or 3000; so does a listener whose program
  exited before it was judged. The netflow comm allowlist cannot exempt
  such a program (its entries name programs in the system trees). The
  reasoning on a common port reads `on port 8080, a common service port,
  from a program not installed in a root-owned system tree …`. Nothing is
  killed.
- Cut command lines (Wave 3, lab PR 187): the exec record keeps 511 bytes
  of the command line and now says when it cut it. R006 records the
  distribution's `socat` with a longer command line, whose first 511
  bytes run no shell, at **Critical** (Log, not killed; High before):
  filler options can push the shell address past the cut. R006, R013,
  R015 and R017 end their reasoning on such an exec with `[argv truncated
  at 511 bytes: arguments past the cut were not seen]` (NN-AUD-272
  EBPF-021). An executable path whose component is 31 bytes long — the
  most the kernel's read keeps — reads with `…` after it (`/opt/x/<31
  bytes>…`), as the file-open sensor's paths do: **an allowlist entry or
  a process canary naming a file whose name is exactly 31 bytes no longer
  equals the kernel's path** (a canary still matches the path the caller
  passed).
- Credential stores in service accounts' homes (Wave 3, lab PR 196,
  NN-AUD-353 SNS-010): the file-open sensor's home trees — where a
  `Login Data`, `logins.json`, `key4.db`, `key3.db`, `signons.sqlite` or
  `*.kdbx` is reported by name — were `/root` and the accounts with uid
  1000 to 65533. They are now uid 0's declared home and **every
  account's home** (Jenkins `/var/lib/jenkins`, GitLab Runner,
  PostgreSQL `/var/lib/postgresql`, uids above 65534), except `nobody`
  and the overflow uids, and homes that are shared system directories
  (`/`, `/nonexistent`, `/var/lib`, `/var/mail`, `/usr/share`, `/tmp`, …,
  or anything under `/bin`, `/etc`, `/dev`, `/proc`, `/usr/lib`,
  `/var/empty`). **Regression:** NN-L-FIM-015/-016 can now report such a
  file read in a service account's home by a process that is not its own
  client (the reader's own browser or password manager stays exempt; a
  root reader is recorded, not killed, as before). The new homes are
  picked up at the next rule refresh (every minute).

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
- **An audit log that refuses a COMBAT transition does not hold the
  ladder** (NN-AUD-318 CMB-027, lab PR 193). The transition is logged
  whole at ERROR (`COMBAT stage transition NOT in the signed audit log —
  enforcement proceeds`; a WARN `failed to append COMBAT stage transition
  to audit log` before: **update journal searches**), the ladder goes on,
  and the transition is written late — in order, at the next transition
  or at the stand-down — as a `combat_stage` row with `deferred: true` and
  `occurred_at`; 64 wait at most, past that the oldest is dropped and the
  next row says `transitions_lost`. `nn-admin status` counts them (§3). A
  reader of `combat_stage` rows takes the time of a `deferred` one from
  `occurred_at`, not `ts`; an older `nn-admin` verifies these rows.
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
- **The binaries COMBAT runs** (NN-AUD-262 ATP-014, NN-AUD-259 ATP-006,
  lab PR 176). `iptables-restore`, `iptables`, their v6 pair, `nft` and
  `rpm` (R018's module provenance) are looked up in `/usr/sbin`,
  `/usr/bin`, `/sbin` and `/bin` only — no longer on `PATH`, whose
  systemd default put `/usr/local/sbin` first — and run only when the
  file they resolve to (through `/etc/alternatives`) is in one of those
  directories, root's, and writable by nobody else, as are its
  directories. The boot logs `COMBAT isolation binaries` with the files
  (`iptables-restore=/usr/sbin/xtables-nft-multi`, …) and the "network
  isolated" line names `restore_bin`. Both units now set
  `Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin`. **Regression:** a
  host whose iptables or nftables lives only under `/usr/local` (a build
  from source), or whose copy or directory is group- or world-writable or
  not root's, logs an ERROR at boot (`COMBAT isolation cannot run`, or the
  signed `block_outbound unavailable: nft missing (not trusted)`), and its
  STAGE 3 isolation or egress block fails; `nn-admin host-check` reports
  the `nft` as not installed or not trusted, and `install.sh` refuses the
  host without `--without-nftables`. Install the distribution's packages.
  `nn-admin status` now reports the isolation as engaged whenever the
  ruleset was applied, also when the jump dedup failed afterwards (it
  used to say `false` of an isolated host), and the release removes a
  duplicate jump that dedup left.
- **The isolation is read back** (lab PR 188, follow-ups of lab PR 176).
  An `iptables-restore` that exits 0 is no longer taken for an isolation:
  the agent lists the table (`iptables -S`) and wants the
  `NORTHNARROW_COMBAT` chain to reach its catch-all DROP (no
  unconditional ACCEPT or RETURN ahead of it) and INPUT, OUTPUT and the
  ruleset's FORWARD to jump into it. Otherwise: ERROR `COMBAT: isolation
  NOT in place` (with `restore_bin` and the gaps), "COMBAT isolate
  failed", `network_isolation_engaged: false`; for IPv6 a WARN, the v4
  isolation kept. `fim-paths.v1` adds `/usr/sbin/iptables-restore` and
  `/usr/sbin/ip6tables-restore`: re-pointing either link or its
  `/etc/alternatives` entry is NN-L-FIM-001 (Critical, KillProcessTree;
  Log Low inside a package transaction). **Action:** run `nn-admin fim
  baseline` after the upgrade so the two paths get a baseline row.
  **Detection change:** an administrator's `update-alternatives --set
  iptables …` outside a package transaction is NN-L-FIM-001 on the two
  links, as it already was on `/usr/sbin/iptables`. A stale COMBAT
  chain's `combat-audit.jsonl` line is now written, the file created when
  missing ([COMBAT_RECOVERY.md §4](COMBAT_RECOVERY.md#4-recovering-from-an-agent-crash-mid-combat)).
- **The COMBAT guard, the capability preflight, the quarantine's own
  files** (NN-AUD-313 CMB-022, NN-AUD-431 CMB-028, NN-AUD-315 CMB-024,
  NN-AUD-316 CMB-025, lab PR 181). Hosts whose drop-in removes a
  capability from the agent's `CapabilityBoundingSet=`:
  - in enforcement each missing capability other than `CAP_KILL` is now
    an ERROR at boot, `capability preflight: CAP_… missing from the
    effective capability set: … unavailable`, and a signed
    `subsystem_degraded` (a WARN `capability missing from effective set`
    before: **update journal searches**); in detect-only a WARN;
  - an agent in enforcement whose capability set can be read neither with
    `capget(2)` nor from `/proc/thread-self/status` (a seccomp filter
    denying `capget` on a hidden procfs) **no longer starts**, as without
    `CAP_KILL`; `--detect-only` starts;
  - without `CAP_SYS_PTRACE` the agent cannot read `/proc/<pid>/exe` of
    sshd, the watchdog or another user's process. COMBAT then spares a
    process whose executable it cannot read only as uid 0 in an SSH unit
    or in `northnarrow-watchdog.service` (or as the watchdog verified by
    the refresh task), with a WARN at most once a minute (`COMBAT guard:
    /proc/<pid>/exe unreadable`); every other process is acted on as
    before. The watchdog itself cannot be verified then (`watchdog exe
    verification failed`): no posture exemption, no kernel protection.
    Keep `CAP_SYS_PTRACE` in the set.
  - The quarantine also refuses the agent's own files where this host
    keeps them — the running binary and its `northnarrow-*` / `nn-admin*`
    siblings, `--watchdog-exe`, the master key, the vault, the containment
    record (listed at boot: `quarantine: the agent's own files are never
    quarantined`) — and `nn-admin response restore --to` refuses them as
    destinations. A binary that grows past `quarantine_max_bytes` while it
    is read is refused (EFBIG, nothing vaulted or removed); a vault
    entry's `size_bytes` is the bytes read.
- **Refused signals and ptrace attaches are counted when the kernel holds
  their records back** (NN-AUD-268 EBPF-017, lab PR 187). The kernel
  keeps at most 50 such records a second per CPU (one budget for the host
  before, updated from every CPU); the excess is counted in the new ring
  `task_denial_rate` of `nn-admin status`, with a journal WARN, a signed
  `ringbuf_drop` and, past 64 in 10 s, telemetry loss (ALERTED) — the
  first refused attempt has locked COMBAT already. The deny itself is
  unchanged.

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
- **Decode stop and threads** (NN-AUD-322 LLMP-010, NN-AUD-325 LLMR-009,
  lab PR 191). The decode stops at the close of the verdict object after a
  `<think>` block and after any prose before the object; a stray `}` or an
  odd quote there ran it to `max_output_tokens`, and braces in the
  reasoning stopped it before the verdict (a malformed-output Escalate).
  **Change:** on a model host such outputs now give the model's verdict,
  sooner (not measured on a model host). The journal line `ADE rayon
  worker count pinned via RAYON_NUM_THREADS` comes at the start of the
  boot (the variable is set before the runtime, when the ADE may load); an
  operator's `RAYON_NUM_THREADS` is said at INFO.
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
- **The caller's executable in the audit log** (NN-AUD-239 ASK-013, lab
  PR 179). `client_comm` is the name the connecting process gave itself
  (any process can call itself `nn-admin`); the operator's identity is
  the key fingerprint. Rows of admin operations now also carry
  `client_exe` (`/proc/<pid>/exe`, after `client_comm`), and triage status
  events `principal_exe`; a caller gone before it could be checked reads
  `<exited>`. Rows written before keep their bytes and verify.
  **Regression:** an `nn-admin` older than the agent reports the new rows
  as broken (`audit verify`, `chain verify`): upgrade the binaries
  together, as for the numbered rows above.
- **The agent's identity in the audit log** (NN-AUD-251 MAIN-009,
  NN-AUD-282 EVD-020, lab PR 185). The agent reads `agent_id` once per
  boot. Its first start signs `agent_id_minted`. A start whose id is not
  the one the chain's last row carries — the file removed and minted
  again, replaced, or restored from a backup while the agent was stopped
  — logs `AGENT IDENTITY CHANGED` (ERROR) and signs `integrity_drift`
  `agent_id_changed` with the old and the new id, once. A file the agent
  cannot use (corrupted, all zeros, unreadable) no longer means the
  all-zero id: the boot runs on a per-boot random id, logs `agent_id
  UNAVAILABLE` with it (`boot_agent_id`) and signs `subsystem_degraded`;
  signed admin requests and overlays made for the install's id are refused
  until the file is repaired. To repair it, sign for that boot: write its
  id (the `agent_id` of the boot's audit rows) and a newline to a file,
  `nn-admin trusted-installer-grant --agent-id-file <that file> …`, put the
  install's id back (or remove the file to mint a new one) and restart in
  the window. No field changes: existing rows verify, and an older
  `nn-admin` verifies the new rows. **Regression / note:** a deliberate
  re-mint or a restore of `agent_id` reports the change once (expected:
  record why); overlays and admin signatures made for the old id stop
  verifying, as they always did after a change.
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
- **Unit drop-ins and mounts the integrity check now sees, and the
  stale COMBAT chain's signed record** (Wave 3: NN-AUD-276 EVD-011,
  NN-AUD-277 EVD-014, NN-AUD-255 MAIN-013, NN-AUD-257 MAIN-015, lab PR
  180). Drop-ins for the agent's units are looked for in every directory
  of systemd's unit search path, `/etc/systemd/system.attached`,
  `/run/systemd/system.attached` and the generator directories included
  (`unit_dropin`). A mount laid after the agent started over a directory
  above its paths — a tmpfs over `/var/lib`, a bind over `/etc` or
  `/usr/local/bin`, a second bpffs on `/sys/fs/bpf` — is
  `mount_over_protected` ("… hides …"), and a mount they resolved through
  that is gone `protected_mount_gone`; when `/proc/1/mountinfo` cannot be
  read the agent checks its own namespace, and when neither can be read it
  records `mountinfo_unreadable` instead of checking nothing. A stale
  `NORTHNARROW_COMBAT` chain torn down at start is signed as
  `combat_reconcile` (`repaired`, or `failed`: the host may still be
  isolated, [COMBAT_RECOVERY.md §4](COMBAT_RECOVERY.md#4-recovering-from-an-agent-crash-mid-combat));
  `combat-audit.jsonl` stays, unsigned. **Regression / note:** a mount
  your own configuration lays over such a directory after the agent's
  start (a late remote `/var/lib`, an automount on `/usr/local`) is
  reported until the agent restarts with it in place (a trusted-installer
  window, §2); the mounts present when it starts are its baseline.
  Nothing changes on a stock Ubuntu 22.04/24.04 or Debian 12/13 host:
  those directories hold no drop-in for the agent's units, and the
  shipped Debian drop-in is still accepted only where `install.sh` puts
  it, with its content.
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
- **`corr_id` is now `corr_start_ns`** (NN-AUD-270 EBPF-019, lab PR 187)
  on the WARN `net drain: TCP close had a kernel flow id but no pending
  flow — row NOT recorded`: the kernel correlator's second half is the
  socket's kernel address, which the journal's readers (`adm`,
  `systemd-journal`) must not learn; the field is the connect's
  timestamp. Update a search on `corr_id=`.
- **Two WARN texts changed** (lab PR 196; the first words are the same):
  `ringbuf entries rejected — records of a size this pump does not
  decode, …` no longer names BUG-024 as a cause (every event ring is
  per boot; any count is a defect to report), and `BTF_OFFSETS map NOT
  armed — …` says why (no vmlinux BTF, or nothing resolved before the
  load) and that a start without BTF does not complete (NN-AUD-355).
- **File-open paths after a remount** (lab PR 196, NN-AUD-352 SNS-004): a
  path the sensor cannot place on a mount point it still sees reads
  `mnt[<major>:<minor>:<root inode>]/…`; for up to 2 s after a mount or
  an unmount this can be a path that used to read with the old mount
  point (which was wrong after a device reuse). Search on the path's
  tail, not only on its mount point.
- **Lab:** `tamper-check` reads its evidence from the signed records: the
  column reads `deny=signal×1` (detections) where it read `op=signal×1`
  (journal), and its journal part only `errors=`.
