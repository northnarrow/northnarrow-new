# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions
follow the ROADMAP "Tappe"; `0.0.1` covers everything up to Tappa 9.0.

## [Unreleased]

### Fixed
- An unprivileged UDP burst could erase every network flow record (review
  73, High). A connected UDP socket emitted one record per `send()` into the
  ring the TCP closes share. One process sending 146k datagrams/s lost 1.45
  million records in 10 s, TCP flows included. UDP sends are now aggregated
  in the kernel per destination: one record per second, or per MiB, carrying
  the bytes sent. UDP records also have their own ring.
- An unprivileged shell loop could blind the exec rules (review 72, High).
  For every event, the agent cloned its ring of up to 1,000 recent events to
  hand the posture triggers a slice. Under an exec burst (four `cat` loops,
  about 2,000 execs/s) that was a full CPU on Ubuntu 24.04. On Ubuntu 22.04
  and Debian 12 the exec rings overflowed, so the execs in the burst,
  including a hidden payload, reached no rule. The triggers now read the
  ring in place: the agent's CPU per exec drops from about 520 µs to 80 µs.
- A credential theft could be reported only as a `/tmp` C2 connection
  (review 70). CHAIN-007 (`/tmp` exec → credential read → egress) and
  CHAIN-001 checked their precursors only when the egress arrived. A
  credential read processed after the connect it preceded (it comes
  through another ring) left both silent: CHAIN-002 killed the tree but
  did not name the theft (lab, Ubuntu 22.04). A late read now completes
  the chain with the egress it preceded.
- The agent wrote every exec and every network flow to the journal at INFO
  (review 71). On a busy host journald then rate-limited the agent, which
  lost other lines too, and every command line on the host (with any
  secret in its arguments) was copied into the journal. Both lines are now
  DEBUG; the records stay in the detection store and the signed netflow
  log.
- An agent start could lose events in its first seconds (review 69). Until
  the LSM file-open sensor took over, the `sys_enter_openat` tracepoint sent
  every open of the host to the agent's event channel, which nothing reads
  before the boot sequence ends. The channel filled, every sensor waited
  behind it, and the file-open ring overflowed: up to 1,018 records lost on
  the lab. The tracepoint now stays inert in the default mode until it is
  needed (`--file-open-sensor tracepoint`, or as the fallback).
- UDP datagrams to IPv6 destinations left no flow row (review 68, High).
  The N2 UDP program was attached to `udp_sendmsg` only, so a QUIC-like
  beacon or raw-UDP exfiltration over IPv6 was invisible to the flow
  rules. It is now attached to `udpv6_sendmsg` too. An IPv4-mapped
  destination still gives one row, not two.
- DNS tunnelling could escape NET-004/-005/-014 (reviews 66, 67, High).
  The DNS sensor read the query name from user memory before the kernel
  copied it, and saw IPv4 only. On the lab, a tunnelling-shaped name ran
  untouched when it was sent in any of these ways:
  - to an IPv6 resolver (`[::1]:53`);
  - from a page the process had not touched yet (the name read as empty);
  - with a zero byte inside its first label (the name was cut there).
  The sensor now reads the kernel's copy, IPv4 and IPv6, and all three are
  killed. A query whose name does not end in the copy's linear data (sent
  in pieces, with UDP GSO or zero copy) is recorded by NET-004 (Log).
- The exec kill rules could be evaded with a relative path (review 61,
  High). They matched the string the caller passed to `execve`, so
  `cd /tmp && ./payload` ran with no detection while `/tmp/payload` was
  killed (lab, Debian 12). A symlink, `..` or `execveat` with a directory
  fd did the same, and a memfd behind a symlink escaped R004. R001, R002,
  R003, R008, R009, R010, R013's and R017's exemptions, CHAIN-002, the
  posture's `/tmp` arm, process canaries and the auth-lineage tracker now
  read the file the kernel executed, and R004 also fires on the kernel's
  memfd flag.
- Review 64's fix had no effect (review 65, High). `cargo xtask build`
  dropped every `CARGO_*` variable before building, including the release
  job's `x86-64-v2` override. A release built on a runner with AVX-512 still
  died with SIGILL on CPUs without it (seen on PR #223's tarball). xtask now
  passes per-target settings on to the nested build. The release job also
  starts the binaries on an emulated `x86-64-v2` CPU
  (`qemu-x86_64 -cpu Nehalem`).
- Release binaries could die with SIGILL at start (review 64, High). The
  workspace builds with `target-cpu=native`, and the release workflow did
  not override it, so a release built on a GitHub runner with AVX-512 used
  AVX-512 and did not run on CPUs without it (the lab's guests, many
  servers). Releases now target `x86-64-v2`.
- The agent stopped starting after about 41 restarts in one uptime
  (review 63, High). Every boot added the inodes it protects to the
  pinned `PROTECTED_INODES` map (23 per restart on the lab, mostly the
  re-created bpffs pins) and never removed the earlier boots' keys; at
  1024 entries an insert failed and the agent refused to start with a
  missing protection. The boot now removes every key it did not register
  itself, after registering its own, and `tamper-check` checks that one
  more restart does not grow the map.
- After an agent restart, kill -9 and ptrace attempts on the agent were
  still refused but left no evidence (review 62). The two hooks emit on the
  anti-tamper ring, yet reused the previous boot's pinned program, bound to
  a ring no one read any more. They are now reattached fresh every boot,
  like the file-protection hooks, and `tamper-check` repeats the kill and
  ptrace cases after its restarts.
- `nn-lab.sh tamper-check` left its overlays in `/etc/northnarrow`, and
  C24's was signed, so its `+backupd` exemption stayed in force on the
  lab guest. The e2e fixtures' agents then logged it as an unauthorised
  overlay, and `audit_verify_e2e` failed on its entry count (Ubuntu
  22.04). The check now purges the pins, removes the overlays and
  restarts the units.
- `nn-lab.sh sync` could leave the lab guest building stale code. rsync
  kept the host's file times, so sources synced from another checkout or
  worktree could be older than the guest's last build. cargo then kept
  the old crate: the build failed, or linked the previous code. Files are
  now compared by content, and a changed file takes the guest's clock.
- Every file operation on the host went through a global kernel lock
  (review 56). 45 `bpf_printk` diagnostic markers from a 2026-05
  investigation were still in the anti-tamper LSM programs: one per
  `file_open`, up to five per write-open, and more on every unlink,
  rename, setattr and ioctl. `bpf_trace_printk` serialises on one spinlock
  and writes the trace buffer, and its "trace_printk() … unsafe for
  production" banner appeared on every agent host. All are removed.
  Overhead benchmark on Ubuntu 24.04, 3 rounds: open throughput loss
  falls from 38.5 % to 31.9 %, write-open from 48.8 % to 25.6 %.
- FIM killed unrelated processes after a watched file was deleted
  (review 57). A file dropped in a watched directory is watched by its
  inode, and deleting the file left the inode number watched, even across
  agent restarts. ext4 hands that number to the next new file, so a
  compiler's temporary file in `/tmp` was killed as a "cron drop-in". A
  deleted file's inode is now forgotten, and stale keys are cleared at
  boot. The enrollment of dropped files itself often failed (review 58):
  it ran before the file existed at its final path. It is now retried
  for two seconds. `nn-lab.sh fim-reuse-check` covers both.
- On btrfs, FIM and the anti-tamper file protection saw nothing (review
  55). Userland keys watched and protected files by `(dev, ino)` from
  `stat()`, which on btrfs reports the subvolume's device. The eBPF hooks
  looked them up with the superblock's device, so no key ever matched.
  FIM missed every file on btrfs, the deny hooks protected none of them,
  the BPF guard's exemption for the agent's own executables never applied,
  and nothing warned. The eBPF side now reports the device as `stat()` does
  (`BTRFS_I(inode)->root->anon_dev` for btrfs inodes). The offsets come
  from the btrfs module's BTF, which the resolver now reads as split BTF
  on top of vmlinux. `nn-lab.sh btrfs-check` reads a watched credential
  file on the root filesystem and on a btrfs subvolume; NN-L-FIM-011 must
  fire both times. Before the fix it fired only for the root filesystem.
- Without the kernel BTF (`/sys/kernel/btf/vmlinux`) the anti-tamper
  attach only logged a WARN and skipped every LSM hook, outside the
  fail-closed check that refuses to start on a missing deny hook. Only the
  network sensor's own BTF load kept such an agent from running. The
  no-BTF case now takes the same fail-closed path
  (`NN_ANTI_TAMPER_ALLOW_DEGRADED=1` is the only way to start degraded),
  and a mount that hides `/sys/kernel/btf` while the agent runs is
  reported as `integrity_drift` (review 53).
- A copy of the agent's unit in an earlier directory of systemd's load
  path replaced the installed unit at the next `daemon-reload` without any
  evidence. The tmpfs `/run/systemd/transient` and `system.control`
  outrank even `/etc/systemd/system`, and both are outside the FIM watch.
  The integrity check now reports every second copy of the units as an
  `integrity_drift` entry of kind `unit_shadowed`, `systemctl mask`
  included.
- The FIM rules killed the package manager. dpkg was killed while it
  installed or removed any package that ships a systemd unit or timer, a
  cron drop-in, a PAM module or a setuid binary, which left packages
  half-installed (`apt-get install --reinstall rsync` failed). Writes made
  by dpkg, rpm, dnf/yum, microdnf or PackageKit, or by the maintainer
  scripts they run, are now recorded as Low log-only detections instead of
  killed. The package manager is recognised by the kernel-resolved
  executable of the writer's lineage, never by process name.
- NN-L-CHAIN-008 (sudo/su, then network) killed legitimate admin work: any
  network flow of a descendant of `sudo` or `su` within 5 minutes drew a
  Critical `KillProcessTree`, `sudo apt-get update` and loopback traffic
  included. The rule is now informational (Medium, log only), ignores
  loopback destinations and is evaluated after every other rule, so it
  never hides a blocking verdict on the same flow.
- NN-L-FIM-019 killed systemd's getty start-up child, which writes the
  login record under the name `(agetty)`: after a reboot both console
  gettys hit their start limit and the host had no console login. The
  login-record rules (FIM-018/019) now accept systemd's pre-exec name and
  the `systemd-update-utmp` and `sshd-session` writers.
- The mass-write posture trigger logged its WARN on every event while a
  steady writer kept the threshold crossed (one line per second for 24 h
  on the first soak); the line is now emitted once per pid per window.
  Detection and posture behaviour are unchanged.
- Memory leak in the DNS attribution cache: the per-pid map was never
  pruned of dead pids, so every short-lived process that resolved a name
  grew the agent by a few hundred bytes for the life of the process
  (~1 MB/h on the first 24 h soak). Stale pids are pruned by TTL and the
  map is capped at 4096 distinct pids.
- Lab soak sampler counts WARN/ERROR lines by text in the `northnarrow`
  journal namespace (tracing output has journald priority 6, so the
  priority filter counted nothing); `soak start` passes `SOAK_*_PER_S`
  rates through to the generator.
- RHEL 9 family (AlmaLinux 9 / 5.14 el9): the vendor tracepoint header
  shifts `sched_process_exec.filename` by 4 bytes; the exec sensor read an
  empty filename on every exec and R017 killed every shell. Tracepoint
  field offsets are now resolved from tracefs at boot (4 new `BTF_OFFSETS`
  slots), and the "non-standard path" rules (R017, R013) never fire on an
  empty filename.
- Short-lived TCP flows (connect and close within the pipeline latency:
  loopback probes, scanners, reverse-shell attempts) produced no netflow
  row and could silence CHAIN-007; the close now synthesises the row when
  it overtakes its connect.
- Debian-family hosts: the hardened agent unit could not attach its
  tracepoint/kprobe sensors (`perf_event_open` EACCES: Debian's
  `perf_event_paranoid=3` patch demands `CAP_SYS_ADMIN`); `install.sh`
  adds a drop-in with that capability on those hosts only, and the attach
  error explains the condition.
- Kernel 5.15 (Ubuntu 22.04): the eBPF object was rejected by the older
  verifier (`memset` subprogram call on ring-buffer entries; variable-length
  read into uninitialised stack; `Option` payload read before its
  discriminant in the FIM rename hook). Entries are zeroed inline, such
  reads land in the ring-buffer entry, the rename destination is a plain
  key; the agent now loads on 5.15 with every program and all 8 FIM hooks
  attached (DNS QNAME via `ITER_IOVEC` only — degraded, not refused).
- e2e fixtures (agent and watchdog): teardown signalled only the `sudo`
  pid and relied on the relay; sudo 1.9.9 does not relay from its own
  process group, so suites hung on 22.04. The whole subtree is now
  signalled, with a bounded wait. The map-pin test accepts the 15-byte
  kernel program name printed by older bpftool.

- FIM e2e suite: the credential-read test asserted a drift row that
  BUG-012 v2 deliberately never writes; it now asserts the
  `NN-L-FIM-011_AwsCredsRead` detection record and the empty drift log.
  The lab's `test-e2e` step runs the FIM suite (it ran nowhere before).

### Added
- DNS sensor on the socket buffer (Tappa 10.9 step 3). Kprobes on
  `udp_send_skb` and `udp_v6_send_skb` read the query from the buffer the
  kernel sends: the destination from the flow, and the name from the
  kernel's copy of the payload. Userland walks the labels, so a zero byte
  inside a label no longer cuts the name. `udp_sendmsg` is no longer
  attached for DNS; `--dns-sensor sendmsg` (or `NN_DNS_SENSOR`) keeps it
  for one soak cycle. `DnsQuery` gains `qname_partial`. Eight optional BTF
  slots (`sk_buff.{head,tail,transport_header,data_len}`,
  `flowi4.{daddr,uli}`, `flowi6.{daddr,uli}`). `nn-lab.sh
  dns-sensor-check` verifies it end to end.
- Exec sensor on LSM `bprm_check_security` (Tappa 10.9 step 2). For each
  binfmt pass (a `#!` script: the script, then its interpreter) it reads
  the file the kernel opened. It records `(dev, ino)`, whether the file is
  on a memory-backed filesystem, is a memfd or is unlinked, and its path
  rebuilt from the dentry up to the exec'ing task's root (containers and
  chroots keep their own view). The path walk is a global BPF function,
  verified on its own. The first pass's identity is handed to the
  post-exec `ProcessSpawn`, and `ExecCheck` now carries kernel data (and
  a real `ppid`). `sys_enter_execve` is no longer attached;
  `--exec-sensor tracepoint` (or `NN_EXEC_SENSOR`) keeps it for one soak
  cycle. The exec ring grows to 1 MiB for the larger records.
  `nn-lab.sh exec-sensor-check` verifies it end to end.
- File-open sensor on LSM `file_open` (Tappa 10.9 step 1). The FIM
  `file_open` observer now also classifies every open in the kernel, and
  only the opens a rule reads reach userland:
  - sensitive files, and writes to critical or persistence files and trees;
  - the telemetry probe directory;
  - credential stores found by name in every home (review 54);
  - one `Event::MassWrite` per process crossing 20 write-opens in 60 s,
    instead of every open.

  `sys_enter_openat` is detached once the sensor is armed, so the path is
  the one the kernel opened (no time-of-check gap) and opens through
  `io_uring` are seen. A relative path, a directory fd or a symlink no
  longer slips past the posture's file triggers (review 60, High). Directory classes are cached; a directory rename
  invalidates the cache and `rmdir` drops the removed directory's entry.
  Paths are rebuilt from the mount table.
  `--file-open-sensor tracepoint` (or `NN_FILE_OPEN_SENSOR`) keeps the old
  sensor for one soak cycle. Credential-store opens in homes outside the
  watch list are reported without killing the reader (design Q8).
  The posture's path lists are prefixes and the kernel classifies by
  directory, so `/etc/ssh/sshd_config.d/` is now listed: the
  `/etc/ssh/sshd_config` prefix used to cover sshd's drop-ins.
  Mass-write carve-outs are directory trees, with or without the final
  `/`. If the verifier refuses the sensor, FIM keeps its plain observer
  and the agent stays on `sys_enter_openat`.
  `nn-lab.sh open-sensor-check` verifies it end to end on Ubuntu 24.04
  (6.8), Ubuntu 22.04 (5.15) and Debian 12 (6.1). On the 6.8 lab guest
  the open benchmark loses 28.2 % instead of 31.9 %, and the agent's own
  CPU per open drops from 6.4 µs to almost nothing (design §10.6, Q7).
- `nn-lab.sh sensor-feasibility [BASE]`, step 0 of the Tappa 10.9 sensor
  attach points. A lab build of the agent (`--sensor-feasibility`, feature
  `test-privileged`) loads throw-away probes on the attach points the
  design proposes and exercises them from its own process. The probes are
  LSM `file_open` with the parent-directory, name and ancestor tables and
  the in-kernel write counter; LSM `bprm_check_security`; and the DNS
  payload read from the socket buffer by a `kretprobe` on
  `ip_make_skb`/`ip6_make_skb` and a `kprobe` on `udp_send_skb`. All 18
  properties hold on 6.8, 6.1 and 5.15. Among them: every record names the
  inode the open returned while another thread swaps the name, and an
  `execveat` of a memfd is seen. The run on btrfs found review 55. The
  probes ship in the shared eBPF object but the agent never loads them;
  their maps take about 70 KiB until step 1 replaces them. With
  `NN_FEASIBILITY_BENCH=<opens>` it also measures the cost per open. On
  6.8, an empty LSM program adds 147 ns, today's FIM observer 427 ns, and
  the full observer 1 587 ns (−34 %). The full checks cannot therefore run
  on every open: step 1 caches the classification per directory.
- Kani proof of the admin multi-signature rule. `verify_quorum` and
  `verify_signed_payload_quorum` now share `quorum_decision`, the tally of
  distinct keys, threshold and role check separated from the signature
  checks, and Kani proves it accepts only when enough distinct keys matched
  and every required role is carried by one of them (weekly job). A
  threshold of 0 was refused only by a `debug_assert`; the rule now uses
  `max(threshold, 1)` in every build.
- `nn-lab.sh release-check DIR`: the release tarball CI built and attested
  (`gh run download`), installed and verified on a guest. It checks
  SHA256SUMS, that the binaries run on the guest's glibc, `install.sh`'s
  tree and tarball verification (provenance `checksums`), the boot-time
  binary integrity check, every deny hook, the telemetry probe and one
  detection. It passes on Ubuntu 24.04, Ubuntu 22.04 and Debian 12.
- Fuzz targets `combat_allow` and `canary_template`: the COMBAT management
  carve-out (allow-file text, generated ACCEPT lines, splice into the
  operator ruleset) and the operator canary templates. Besides "never
  panics", `combat_allow` asserts that no allow-file content can inject an
  `iptables-restore` line other than an ACCEPT for one validated address.
- `tamper-check` with kernel lockdown: kexec (C17) is a required refusal
  when lockdown is active instead of a known gap, and C27 loads a module
  whose signature was stripped through a bare `finit_module`. Verified on
  Ubuntu 22.04 with `lockdown=integrity`: the agent runs unchanged, both
  are refused by the kernel, and R018 still records the module attempt.
  `nn-admin host-check` reports module signing as enforced when lockdown
  is in integrity or confidentiality mode, which refuses unsigned modules
  whatever `module.sig_enforce` says.
- Distribution packages: `northnarrow_<ver>-<rel>_amd64.deb` and
  `northnarrow-<ver>-<rel>.x86_64.rpm`, built by
  `deploy/release/mk-packages.sh` with dpkg-deb and rpmbuild only, and
  published, checksummed and attested with the tarball. Their scripts run
  `install.sh` / `uninstall.sh` in new package modes (`--package-stop`,
  `--package-configure`, `--package`). Installing over an `install.sh`
  install migrates it; upgrade and removal go through the
  trusted-installer window (`NN_GRANT_KEY`) and stop cleanly without it;
  the first install starts nothing. Lab: `nn-lab.sh pkg-check`.
- Package install layout: `install.sh` and `uninstall.sh` accept
  `BIN_DIR=/usr/bin UNIT_DIR=/usr/lib/systemd/system` and rewrite the units
  for `BIN_DIR`. The agent protects the binaries and units of both layouts
  and finds the watchdog next to its own executable, so `--watchdog-exe`
  is now optional. Prerequisite for `.deb`/`.rpm` packages (review 26).
- Overhead benchmark (`nn-lab.sh overhead [ROUNDS]`): the agent off and on,
  alternated, over four worst-case micro-workloads (open, open + write,
  exec, loopback connect); the report gives the median throughput lost and
  the agent's own CPU per workload. Runbook section "Overhead (agent off
  vs on)".
- Host hardening checks (`nn-admin host-check [--json]`, summary in
  `nn-admin status`, one WARN per gap at agent boot, table at the end of
  `install.sh`): BPF LSM, kernel lockdown, unprivileged BPF, module
  signature enforcement, Secure Boot, IMA, kexec, single bpffs mount —
  the host settings that keep root from rewriting the kernel at runtime,
  which is the only way around the anti-tamper.
- Kani model checking (`.github/workflows/kani.yml`, weekly): the TLS
  ClientHello `Cursor` and the DNS name walk (`QnameLabels`, split out of
  `decode_dns_qname` without behaviour change) are proved in bounds for
  every input of a bounded size. The first proof found the cursor's bound
  check `pos + n > len` wrapping for a huge `n` in release builds; it is
  now saturating.
- Signed operator overlays: the agent loads a `*.local` overlay
  (allowlists, blocklists, FIM paths, posture carve-outs) only if
  `<overlay>.sig` proves that a key with the new `config-manage` role signed
  its exact content, for this `agent_id`, and not earlier than the last
  accepted signature (rollback guard from the audit chain); otherwise it
  boots on the shipped defaults for that list and records an
  `unauthorized_overlay` integrity finding. `nn-admin config overlay
  set|sign|status`; `install.sh` bootstraps the key with `config-manage`
  and `--upgrade` adopts existing overlays with `--grant-key`; the posture
  overlays and the `.sig` files join the protected set; escape hatch
  `NN_OVERLAY_ALLOW_UNSIGNED=1` (reported). Closes the gap found by
  tamper-check C19.
- Adversarial anti-tamper check, second part: `cgroup.kill` on the agent's
  unit (C20), an exec flood hiding an exec from `/tmp` (C21) and an
  io_uring probe that opens, reads and connects through a ring with no
  openat/connect syscall (C22, `deploy/lab/adversarial/iouring-probe.c`, raw
  syscalls) — 23 cases, all with signed evidence on 6.8 and 5.15. Kills that
  nothing can refuse are now evidence: every run writes `agent_stop` with the
  reason it left its event loop, and every `agent_boot` says how the previous
  run ended (`previous_run`: none / clean / abrupt; review 46). The four
  remaining append-by-path logs (FIM baseline, canary registry and access
  log, listener log) also write through a directory fd (review 44).
- Adversarial anti-tamper check (`nn-lab.sh tamper-check`,
  `deploy/lab/adversarial/anti-tamper.sh`): 20 cases (signals, ptrace,
  protected files and pins, BPF maps/links/programs, unit drop-ins,
  `set-property`, bpffs and bind mounts, cgroup freeze, module load,
  `oom_score_adj`, config overlays), each with expected outcome and the
  evidence it must leave in the signed chain logs. Found and fixed:
  `OWN_BPF_IDS` collisions between map/program/link ids (review 40),
  silent signal/ptrace denials — now `op=signal`/`op=ptrace` records and
  detection NN-L-AT-001 for every anti-tamper denial (41), silent
  systemd/kernel tampering — now a self-integrity check every 30 s ±20 %
  with `integrity_drift` audit entries, `OOMScoreAdjust` in both units
  (42), the telemetry probe tripping NN-L-NET-004 (43), and the signed
  logs being divertible by a bind mount over their directory — every log now
  writes through a directory fd taken when it is opened (44). Ring-buffer
  losses are signed audit entries (`ringbuf_drop`); the telemetry probe
  and the link self-check run with ±20 % jitter.
- Telemetry probe: every 60 s the agent runs a child of its own binary
  (`--telemetry-probe <nonce>`, hidden) that produces one known event per
  probed sensor — exec, file open of `/run/northnarrow/probe/<nonce>`, DNS
  query for `<nonce>.probe.northnarrow.invalid` to 127.0.0.1:53 — and
  checks each reaches the pipeline within 5 s; a silent sensor is an
  `ERROR TELEMETRY GAP` and a signed audit entry (`telemetry_gap`, then
  `telemetry_restored`), coverage as a product function.
  `NN_TELEMETRY_PROBE_SECS=0` disables it.
- BPF self-defence, second half: the `bpf` LSM hook now DENIES (enforce
  mode) a handle to one of the agent's own links to a foreign process, by id
  (`LINK_GET_FD_BY_ID`) and through the pin (`OBJ_GET` whose final path
  component is one of our `link_*` pins) — the two routes to `bpftool link
  detach`; denial `operation=bpf_link` in the audit chain and the posture
  ladder. Own ids are kept with their kind (map / program / link live in
  separate kernel id spaces; before, a foreign map with the id of one of our
  programs would have been write-denied). Link self-check every 10 s: a
  registered link missing — checked through the agent's own fds and pins,
  no `CAP_SYS_ADMIN` — is an ERROR and a signed audit entry
  (`bpf_link_missing`), in every mode. Review entry 39 (High): the pin root
  `/sys/fs/bpf/northnarrow` and every pin are now in the protected-inode
  set, so `systemctl stop` + `rm -rf` of the pins no longer drops the
  hooks; the trusted-installer window is the authorised purge —
  `install.sh --upgrade --grant-key <key>` / `uninstall.sh --grant-key
  <key>` open it, the bootstrapped admin key carries the role
  (`unlock,audit-read,trusted-installer`), and the lab migrates guests
  installed with an older key once (units disabled across a VM restart).
- BPF self-defence, first half: LSM hook `bpf_map` denies any write handle
  on the agent's own maps (ids registered after load) to processes that
  are not the agent or the watchdog — `bpftool map update/delete` against
  `PROTECTED_PIDS` now fails with EPERM and lands in the audit chain as an
  anti-tamper denial (`bpf_map`); read-only handles stay allowed, but
  `bpftool` always asks for RDWR, so in enforce mode `map show/dump` on the
  agent's maps fail too (read the state with `nn-admin status`). LSM hook
  `bpf`
  observes program loads, attaches, link create/update/detach, BTF loads
  and handles-by-id on the agent's maps/links by foreign processes
  (`Event::BpfSyscall`, one record per pid per command per second); rules
  `NN-L-BPF-001_BpfProgramLoaded` (Medium, Log; known tooling exempt) and
  `NN-L-BPF-002_BpfForeignHandleOrDetach` (High, Log). Observe mode (no
  deny) in `debug-trigger` builds and with `NN_BPF_DEFENSE_OBSERVE=1`; the
  guard counts as a ninth deny hook in the fail-closed LSM health. Seven new
  BTF offset slots (`bpf_map`, `bpf_prog`, `bpf_prog_aux`, `mm_struct.exe_file`
  for the exe-inode exemption that lets a restarting watchdog register itself).
- io_uring sensor — the asynchronous I/O channel syscall-centric sensors
  miss: tracepoints `io_uring_create` and `io_uring_submit_{req,sqe}`
  (name resolved per kernel), submissions aggregated per pid in kernel by
  opcode class (file open, file read/write, network connect, network
  send/recv, filesystem mutation) and emitted on a new class or once per
  second; `Event::IoUring`; rules `NN-L-IOU-001_IoUringRingCreated` (Low,
  Log: baseline of ring creators outside the allowlist) and
  `NN-L-IOU-002_IoUringFileAndNetwork` (High, Log: file and network I/O
  through rings from the same unlisted process — the RingReaper shape).
  Known io_uring servers (qemu, nginx, postgres, mariadb, mysql, redis,
  node, fio, systemd-journal) and the process comm allowlist are exempt.
  Five new `BTF_OFFSETS` tracepoint slots; a kernel without
  `CONFIG_IO_URING` degrades with a WARN.
- Ring-buffer drop accounting: every eBPF producer bumps a per-ring
  counter (`RING_DROPS` per-CPU map, 11 rings) when its reservation
  fails; the agent samples it every 10 s, logs each increase at WARN with
  the ring's name, and `nn-admin status` shows the total and the per-ring
  breakdown (`ringbuf_drops_total`, `ringbuf_drops` in `--json`). Before,
  only the exec ring counted and nothing read it.
- Fuzzing (`fuzz/`, cargo-fuzz): eight libFuzzer targets over every
  parser that consumes attacker-shaped bytes — admin socket frames, TLS
  ClientHello and DNS payloads from the kernel rings, the BTF blob,
  tracefs `format` files, role lists, chain-log lines, the install
  manifest. The `fuzz` CI job builds every target and runs each for a
  short smoke on every PR; a crash artefact fails the job.
- Supply chain, install-time and runtime halves: `install.sh` verifies the
  extracted tree (`MANIFEST.sha256`, now shipped in the tarball), the
  tarball against `SHA256SUMS` and the SLSA provenance attestation (gh or
  cosign, bound to this repository's release workflow;
  `--require-attestation`, `--no-verify`), and records the level reached
  plus the hashes of every installed binary and of the eBPF object in
  `/etc/northnarrow/install-manifest.json`. The agent re-verifies those
  hashes at every boot and refuses to start on a mismatch
  (`NN_ALLOW_UNVERIFIED_BINARY=1` to override); the `agent_boot` audit
  entry carries `binary_integrity` and `install_provenance`.
- Lab: fourth guest AlmaLinux 9 (`NN_LAB_DISTRO=alma9`, kernel 5.14 el9,
  SELinux enforcing, port 2622) — verified end to end; the compatibility
  matrix records it.
- `BTF matrix` workflow + `deploy/btf-matrix/run.sh`: computed
  kernel-compatibility matrix over the BTFHub archive (newest non-cloud
  kernel per distro/version, `--btf-check` verdicts, BPF LSM floor),
  compared with a baseline (`expected.tsv`); on PRs touching the offset
  tables, weekly, and on demand. Verdicts recorded in
  `KERNEL_COMPATIBILITY.md`.
- `northnarrow-agent --btf-check <btf>`: offline compatibility verdict
  (SUPPORTED / SUPPORTED (degraded) / NOT SUPPORTED) for any kernel BTF;
  optional offsets (the `iov_iter` family behind DNS QNAME decoding)
  degrade the sensor instead of refusing the boot. Lab: third guest
  `ubuntu2204` (kernel 5.15), verified end to end.
- Multi-kernel, level 1: kernel struct offsets are resolved from the
  running kernel's BTF at boot and published to the eBPF programs through
  the `BTF_OFFSETS` map before any hook attaches (compiled-in values are
  only the fallback); `iov_iter` alternative paths (≤ 6.3) and the
  `ITER_UBUF` enumerator resolved by name. Debian 12 / kernel 6.1 now
  runs the full e2e suites (agent 6/6, watchdog 4/4); a field absent on
  the running kernel still refuses the boot (BUG-036, exit 78).
- Lab: second guest Debian 12 (`NN_LAB_DISTRO=debian12`, kernel 6.1) with
  its own disk, port and reports; `docs/operator/KERNEL_COMPATIBILITY.md`
  records the verified matrix. Finding: the agent refuses to start on 6.1
  (20 of 41 compiled-in BTF offsets differ — fail-closed as designed);
  runtime offsets tracked as review entry 27.
- Release workflow on tags `v*`: locked build, release tarball consumed by
  `install.sh` unchanged, CycloneDX SBOM, `SHA256SUMS`, SLSA build
  provenance attestation (`gh attestation verify`); dry run on packaging
  PRs. `deploy/release/mk-tarball.sh` builds the same tree locally.
- `install.sh --upgrade`: in-place upgrade of a running install (stops
  watchdog → agent, drains the LSM programs, replaces, restarts; keys,
  agent_id, audit chain and chain logs preserved). Without the flag the
  script now refuses when the units are active instead of failing halfway
  with `Operation not permitted`.
- `deploy/uninstall.sh` (`--purge`, `--yes`): ordered removal that the
  anti-tamper layer allows; keeps `/etc/northnarrow` and
  `/var/lib/northnarrow` unless purged.
- Lab: `nn-lab.sh upgrade-check` / `uninstall-check`, both in the nightly.
- `docs/operator/INSTALL_UPGRADE_UNINSTALL.md`.

### Fixed
- Lab/test only: `privileged_map_pin` and the watchdog 3-cycle respawn
  e2e evict the agent from PROTECTED_PIDS before signalling it (the
  `task_kill` deny-by-default policy refuses a bare SIGQUIT/SIGKILL);
  two illustrative doctests re-fenced as text.

## [0.0.1] - 2026-10-09

Tag `v0.0.1-tappa9.0`: everything up to Tappa 9.0 plus the 2026-10-08/09
hardening round (PR #145, #155–#170). All High/Medium findings of
`docs/audit/NN_BUG_AUDIT_2026-06-09.md` and
`docs/audit/NN_REVIEW_2026-10-08.md` closed and verified on the QEMU lab
guest (kernel 6.8, BPF-LSM).

### Security / safety
- RAG release gates (golden ≥ 90 %, latency, e2e format) fail fast when
  `target/kb` is missing instead of silently benchmarking the built-in
  seed; the lab ships the corpus and reports 28/30 = 93.3 % on the real
  ATT&CK + Sigma dumps (the earlier 36.7 % was the seed-only artefact).
- `nn-admin rotate-keys add --new-roles` accepts every role keyword the
  agent understands (`canary-manage`, `fim-manage`, `net-read`,
  `triage`, …), not only the legacy five: least-privilege keys for
  canary/FIM operators can now be granted from the CLI instead of
  hand-editing `admin.pub` or granting `all`. The install-bootstrapped
  key's roles (`unlock,audit-read` only) are documented in
  `docs/operator/COMBAT_RECOVERY.md` §1.1.
- An orphan TCP close (no pending flow) is logged at WARN with the
  5-tuple instead of silently dropped at debug.
- The outbound UDP sensor now observes unconnected `sendto()` traffic
  (destination read from `msghdr->msg_name`), rate-limited kernel-side
  to one netflow row per `(pid, destination)` per second. Before, only
  connected UDP sockets produced a row: QUIC-like beacons and raw-UDP
  exfil through an unconnected socket were invisible.
- Boot-time audit self-check: a signed `agent_boot` entry is appended at
  startup; an unwritable audit log is fatal in enforcement mode
  (`NN_AUDIT_ALLOW_UNWRITABLE=1` to override, detect-only warns).
- Posture corroboration ledger is scoped per login session (`loginuid`
  of the owning pid; host-level activity is its own scope): a weak
  ENGAGED-tier signal from one user/container no longer corroborates a
  blunt COMBAT-tier signal from an unrelated one into a host-wide COMBAT.
- Audit Medium round: TCP netflow rows and `flow_id` carry the real
  source address/port (close-time), not `0.0.0.0:0`; the COMBAT
  kill-tree spares host-critical descendants (sshd, watchdog) via the
  ladder guard; the `detections/` chain logs are in PROTECTED_INODES;
  mass-write ignores a session's own `/run/user/<uid>/` writes only;
  `nn-admin detection-set-status` reports a persistence failure (exit
  10) distinctly from "not found" (exit 9).
- `/etc/northnarrow` directory inode is now in PROTECTED_INODES
  (mutation-denied): the config tree can no longer be renamed or removed
  from under the agent by a root process outside PROTECTED_PIDS.
- Canary deploy enforces a path policy (no system trees, no `/run`, no
  NorthNarrow state/config, no `..`, no symlink escape, `O_NOFOLLOW`
  write): a leaked admin key can no longer write root-owned files at
  arbitrary paths through `nn-admin canary deploy`.
- Anti-tamper `task_kill` hook is deny-by-default: every userspace signal
  towards a protected pid is refused (previously only SIGKILL/SIGTERM, so
  `kill -INT/-HUP/-QUIT/-STOP` from root stopped or froze the agent).
  Allowed: signal 0, self-signals, signals between protected pids
  (watchdog ↔ agent) and PID 1 with the armed nonce. The watchdog now
  registers its own pid in PROTECTED_PIDS at boot (design §7.1; before,
  it was protected only if its pidfile pre-dated the agent's start).
- R004 (fileless exec) also matches `/dev/fd/N` (what glibc's `fexecve`
  really passes) and `/memfd:` pseudo-paths; previously a memfd exec on
  Ubuntu 24.04 was undetected.
- File canaries deployed at arbitrary paths trip again on READ: the FIM
  drain's BUG-012 v2 gate now forwards `Opened` events for canary inodes
  (published by the K3 index rebuild) to the rule engine.
- Watchdog respawn v2 (`docs/design/WATCHDOG_RESPAWN_V2_DESIGN.md`): a
  crashed agent is restarted with `systemctl start` under its own unit
  (full ExecStart argv, own cgroup/caps/ProtectHome) instead of as a
  fork-exec child of the watchdog's 64 MiB / 2-cap sandbox. `BindsTo=`
  removed from the watchdog unit; `StartLimitIntervalSec=0` on the agent
  unit. New flags `--respawn-backend {auto,systemd,exec}` and
  `--agent-unit`. Closes `watchdog-respawn-1` and `combat-avail-1`.
- Audit Beta-blockers closed: `abi-modpath-1` (module path sensor now
  keeps 16 components and flags truncation; R018 never auto-kills on an
  unverifiable prefix), `posture-1` (two blunt COMBAT-tier signals in one
  round cap at ENGAGED), `ebpf-lsm-1` (LSM deny-hook attach shortfall is
  fail-closed: the agent refuses to start unless
  `NN_ANTI_TAMPER_ALLOW_DEGRADED=1`). `at-authz-2` was already closed by #142.
  **Wire change:** `ModuleLoadRaw` grows from 312 to 568 bytes (eBPF and
  userland from the same `common` crate — rebuild both).
- `CAP_KILL` added to the agent's `CapabilityBoundingSet`; without it
  KillProcess could only signal root-owned targets. New boot preflight
  (`response/caps_preflight.rs`) refuses to start in enforcement mode when
  `CAP_KILL` is missing and logs any other missing capability.
- `kill_process_tree` refuses PID 0/1 as a root before walking `/proc`
  (PID 0's children are init + kthreadd, i.e. the whole host) and never
  yields PID 1/2 as descendants.
- Quarantine refuses to vault + unlink binaries under system prefixes
  (`/usr/bin`, `/usr/lib`, `/etc`, `/boot`, …) and NorthNarrow's own paths.
- Posture: the corroboration ledger is cleared on every COMBAT release
  path (audit `posture-2`).
- NN-L-NET-005 / NN-L-NET-013 stateful windows evict idle keys (audit
  `catchall-1`, unbounded memory growth on a long-lived agent).

### Fixed
- Agent unit: `/etc/northnarrow` added to `ReadWritePaths` — under
  `ProtectSystem=strict` the installed agent could not append its own
  signed audit log (EROFS) nor bootstrap `agent_id`/`agent.sig.key`.
- Agent unit: `RuntimeDirectoryPreserve=yes` — a respawn-v2 restart no
  longer wipes `/run/northnarrow` (watchdog pidfile, shutdown marker,
  honeypot baits).
- `install.sh` now ships `combat-rules.v4/.v6` from `configs/` (missing
  ruleset = no NetworkIsolator = admin socket silently absent = watchdog
  stuck-recovery restart loop) and lifts `chattr +i` on the state dir
  for upgrades. The agent logs an ERROR when the ruleset is missing.
- CI: `cargo fmt`, `cargo clippy -D warnings` and the `test` job are green
  again; `ade-build` no longer runs out of disk on the hosted runner;
  `ebpf-build` pins `bpf-linker 0.10.3` (0.11 needs a system LLVM 21+).
- Test flake `anti_tamper::network_isolate::release_is_idempotent`
  (ETXTBSY race on the mock `iptables-restore` script).
- Dependencies: `rustls` 0.23.45 (RUSTSEC-2026-0285), `crossbeam-epoch`
  0.9.21 (RUSTSEC-2026-0204).

### Added
- `deploy/lab/nn-lab.sh`: QEMU/KVM Ubuntu 24.04 lab guest (kernel 6.8,
  `lsm=…,bpf`) with sync/build/test-e2e/test-ignored/install/respawn-check
  sub-commands; runs from WSL2 with nested virtualization.
- `cargo audit` CI job, Dependabot (cargo + GitHub Actions), `SECURITY.md`.

## [0.0.1] — 2026-06-10

Tappe 0–9.0 as described in `ROADMAP.md`: eBPF sensors, rule engine,
response executors, local ADE (candle), posture machine, anti-tamper
(BPF-LSM + watchdog), signed admin channel, detection store.
