# External security audit of commit 16f7563 — remediation tracker

An external audit of commit `16f7563` (2026-10-12, the merge of #224)
reported 444 findings, each with a proposed fix and a regression test
(6 Critical, 70 High, 159 Medium, 188 Low, 21 Informational), and 234
hardening improvements. Its remediation plan groups them in waves:

- **Wave 0** (0–2 weeks): every Critical, and the High findings with a
  small fix.
- **Wave 1** (2–8 weeks): the remaining High findings.
- **Wave 2** (2–4 months): the Medium findings.
- **Wave 3** (continuous): Low and Informational.

The report itself lives with the repository owner. This file tracks what
was done about each finding, so that a reader of the repository can see
the status without it. Each finding is re-checked against the current
code before it is fixed: the audit predates PRs #225 onward, and some
code it cites has changed since. A fix follows the plan's rule: a failing
regression test first, then the fix, then the privileged suites on at
least two supported kernels (6.8 and 5.14/5.15).

Status: `open`, `fixed (lab PR N)`, `already fixed (PR)`, or
`declined (reason)`.

## Wave 0

| ID | Audit ref | Severity | Area | File | Status |
|---|---|---|---|---|---|
| NN-AUD-001 | PROC-001 | Critical | Process rules | `agent/src/decision/rules/r004_exec_from_proc_self_fd.rs` | fixed (lab PR 79) |
| NN-AUD-002 | POS-001 | Critical | Posture | `agent/src/posture/mod.rs` | fixed (lab PR 80) |
| NN-AUD-003 | LLMP-002 | Critical | LLM prompts | `agent/src/ade/structured_prompt.rs` | fixed (lab PR 81) |
| NN-AUD-004 | LLMR-002 | Critical | LLM runtime | `agent/src/ade/mod.rs` | fixed (lab PR 82) |
| NN-AUD-005 | NET-001 | Critical | Network | `agent/src/net/blocklist.rs` | fixed (lab PR 78) |
| NN-AUD-006 | NET-010 | Critical | Network | `configs/netflow-comm-allowlist.v1` | fixed (lab PR 78) |
| NN-AUD-016 | EBPF-003 | High | eBPF kernel | `agent-ebpf/src/ptrace_check.rs` | fixed (lab PR 85) |
| NN-AUD-018 | EBPF-007 | High | eBPF kernel | `agent-ebpf/src/udp_sendmsg_outbound.rs` | fixed (lab PR 78) |
| NN-AUD-030 | FIMP-002 | High | FIM pipeline | `agent/src/fim/baseline.rs` | fixed (lab PR 84) |
| NN-AUD-033 | FIMP-005 | High | FIM pipeline | `agent/src/fim/drain.rs` | fixed (lab PR 84) |
| NN-AUD-034 | FIMP-006 | High | FIM pipeline | `agent/src/fim/drain.rs` | fixed (lab PR 84) |
| NN-AUD-035 | NETR-001 | High | Net rules | `agent/src/decision/rules/chain.rs` | fixed (lab PR 84) |
| NN-AUD-047 | CMB-002 | High | Combat response | `agent/src/combat/actuator.rs` | fixed (lab PR 83) |
| NN-AUD-048 | CMB-003 | High | Combat response | `agent/src/combat/protected.rs` | fixed (lab PR 83; Wave 1, taken with NN-AUD-049) |
| NN-AUD-049 | CMB-005 | High | Combat response | `agent/src/response/executor.rs` | fixed (lab PR 83) |
| NN-AUD-051 | LLMP-001 | High | LLM prompts | `agent/src/ade/sanitize.rs` | fixed (lab PR 81) |
| NN-AUD-052 | LLMR-001 | High | LLM runtime | `agent/src/ade/escalate.rs` | fixed (lab PR 81) |
| NN-AUD-054 | LLMR-006 | High | LLM runtime | `agent/src/ade/dual_verify.rs` | fixed (lab PR 81) |
| NN-AUD-056 | NET-002 | High | Network | `agent/src/net/blocklist.rs` | fixed (lab PR 78) |
| NN-AUD-059 | NET-005 | High | Network | `agent/src/net/dns_cache.rs` | fixed (lab PR 78) |
| NN-AUD-060 | NET-011 | High | Network | `configs/netflow-blocklist.v1` | fixed (lab PR 78) |
| NN-AUD-061 | DEC-001 | High | Deception | `agent/src/admin_socket.rs` | fixed (lab PR 84; Wave 1, taken with NN-AUD-063) |
| NN-AUD-062 | DEC-002 | High | Deception | `agent/src/canary/path_policy.rs` | fixed (lab PR 84; Wave 1, taken with NN-AUD-063) |
| NN-AUD-063 | DEC-003 | High | Deception | `agent/src/canary/read_forward.rs` | fixed (lab PR 84) |
| NN-AUD-070 | WDG-004 | High | Watchdog tooling | `watchdog/src/main.rs` | fixed (lab PR 85) |

## Wave 1

| ID | Audit ref | Area | Effort | Status |
|---|---|---|---|---|
| NN-AUD-007 | ASK-001 | Admin socket | M | fixed (lab PR 84, with NN-AUD-062) |
| NN-AUD-008 | MAIN-001 | Agent main | M | open |
| NN-AUD-009 | MAIN-002 | Agent main | M | fixed (lab PR 82, as NN-AUD-004) |
| NN-AUD-010 | MAIN-003 | Agent main | M | open |
| NN-AUD-011 | ATP-001 | Anti-tamper | M | open |
| NN-AUD-012 | ATP-002 | Anti-tamper | M | open |
| NN-AUD-013 | ATP-004 | Anti-tamper | M | open |
| NN-AUD-014 | EBPF-001 | eBPF kernel | M | open |
| NN-AUD-015 | EBPF-002 | eBPF kernel | M | open |
| NN-AUD-017 | EBPF-006 | eBPF kernel | M | open |
| NN-AUD-019 | EBPF-010 | eBPF kernel | M | open |
| NN-AUD-020 | EVD-001 | Evidence logs | L | open |
| NN-AUD-021 | EVD-005 | Evidence logs | M | open |
| NN-AUD-022 | EVD-021 | Evidence logs | M | open |
| NN-AUD-023 | FIMR-001 | FIM rules | M | open |
| NN-AUD-024 | FIMR-002 | FIM rules | M | open |
| NN-AUD-025 | FIMR-003 | FIM rules | M | open |
| NN-AUD-026 | FIMR-004 | FIM rules | M | open |
| NN-AUD-027 | FIMR-005 | FIM rules | M | open |
| NN-AUD-028 | FIMR-006 | FIM rules | L | open |
| NN-AUD-029 | FIMP-001 | FIM pipeline | M | open |
| NN-AUD-031 | FIMP-003 | FIM pipeline | M | open |
| NN-AUD-032 | FIMP-004 | FIM pipeline | M | open |
| NN-AUD-036 | NETR-002 | Net rules | M | open |
| NN-AUD-037 | NETR-003 | Net rules | M | open |
| NN-AUD-038 | PROC-002 | Process rules | M | fixed (lab PR 86) |
| NN-AUD-039 | PROC-003 | Process rules | M | fixed (lab PR 86) |
| NN-AUD-040 | PROC-004 | Process rules | M | fixed (lab PR 86) |
| NN-AUD-041 | PROC-005 | Process rules | L | open |
| NN-AUD-042 | PROC-007 | Process rules | M | fixed (lab PR 86) |
| NN-AUD-043 | POS-002 | Posture | M | open |
| NN-AUD-044 | POS-003 | Posture | M | open |
| NN-AUD-045 | POS-004 | Posture | L | open |
| NN-AUD-046 | CMB-001 | Combat response | M | open |
| NN-AUD-048 | CMB-003 | Combat response | M | fixed (lab PR 83, with Wave 0) |
| NN-AUD-050 | CMB-006 | Combat response | M | open |
| NN-AUD-053 | LLMR-004 | LLM runtime | M | open |
| NN-AUD-055 | LLMR-012 | LLM runtime | M | open |
| NN-AUD-057 | NET-003 | Network | M | open |
| NN-AUD-058 | NET-004 | Network | M | open |
| NN-AUD-061 | DEC-001 | Deception | M | fixed (lab PR 84, with Wave 0) |
| NN-AUD-062 | DEC-002 | Deception | M | fixed (lab PR 84, with Wave 0) |
| NN-AUD-064 | DEC-004 | Deception | M | open |
| NN-AUD-065 | DEC-005 | Deception | M | open |
| NN-AUD-066 | DEC-006 | Deception | L | open |
| NN-AUD-067 | WDG-001 | Watchdog tooling | M | open |
| NN-AUD-068 | WDG-002 | Watchdog tooling | M | open |
| NN-AUD-069 | WDG-003 | Watchdog tooling | M | open |
| NN-AUD-071 | WDG-005 | Watchdog tooling | M | fixed (lab PR 85, with NN-AUD-070) |
| NN-AUD-072 | DEP-001 | Deploy | M | open |
| NN-AUD-073 | DEP-002 | Deploy | M | open |
| NN-AUD-074 | DEP-003 | Deploy | M | open |
| NN-AUD-075 | SUP-003 | Supply chain | M | open |
| NN-AUD-076 | TST-003 | Privileged tests | M | open |

## Notes on the fixes

- **NN-AUD-005 (NET-001), lab PR 78.** A dual-stack `AF_INET6` socket
  reaching an IPv4 peer reports it as `::ffff:a.b.c.d`. Every consumer
  compared that form with IPv4 entries and never matched. The address is
  now canonical where it is decoded (`common::netaddr`). That covers the
  netflow drain, the multiplexer, the posture's internal/loopback
  checks, the escalation allowlist and the log rendering. The blocklist
  also canonicalises both sides when it compares. Lab, Ubuntu 24.04 and
  22.04: a dual-stack connect to `::ffff:192.0.2.1` drew NN-L-NET-001
  (KillProcessTree); it drew nothing before.
- **NN-AUD-006 (NET-010), lab PR 78.** The network rules' allowlist is
  judged on exec identity (`CommAllowlist::judge`, the review-85
  mechanism), never on `comm`. When the identity cannot be read
  (the process exited before its exec event was), an allowlisted `comm`
  turns the verdict into a recorded Log rather than suppressing it or
  acting on it. NN-L-NET-009's UDP sum and NN-L-NET-013's beacon window
  judge only when they would fire. Lab: python renamed `curl` connecting
  to port 4444 drew NN-L-NET-010 (KillProcess) with
  `[named 'curl', an allowlisted program, but the kernel ran something else]`;
  it was suppressed before.
- **NN-AUD-018 (EBPF-007), lab PR 78.** Only a DNS server's answers to a
  local client stay out of the UDP sensor. Other sends from port 53 are
  flows, aggregated per client address when they go to a remote client.
  Lab: a socket bound to `<host>:53` sending to `192.0.0.9:4444` reached
  userland (NN-L-NET-010); the kernel dropped it before.
- **NN-AUD-056 (NET-002), lab PR 78.** At load, a malformed line in the
  IP or JA3 blocklists, or in their overlays, drops that line with a
  WARN, not the whole list. The validation of an overlay before signing
  stays strict.
- **NN-AUD-059 (NET-005), lab PR 78.** The DNS back-correlation returns
  the newest query at or before the connect. A later query by the same
  process no longer hides it.
- **NN-AUD-060 (NET-011), lab PR 78.** `100.64.0.0/10` (CGNAT: Tailscale,
  EKS, ISP space) and `198.18.0.0/15` (VPN and SD-WAN clients) are out of
  the shipped blocklist, which feeds a KillProcessTree rule.
- **NN-AUD-001 (PROC-001), lab PR 79.** R004's systemd-executor
  exemption trusted the parent's `comm` (`prctl`) and any `argv[0]`
  ending in `/systemd-executor` (the caller's choice).
  - **With the exec sensor's identity** (LSM mode, the default), R004
    has no exemption: what the kernel executed decides. Fileless code is
    a memfd, or an unlinked file (O_TMPFILE) reached through an fd. A
    real file reached through an fd is not fileless; the other rules
    judge it on its canonical path. One exception: systemd's own
    `systemd-executor` left unlinked by an upgrade, which PID 1 keeps
    launching units from.
  - **Tracepoint mode** keeps the path heuristic. Its exemption now
    needs `argv[0]` to be an install path exactly and a systemd parent:
    PID 1, or a `systemd --user` manager by exec identity, never by
    `comm`.
  - **A regression caught in the lab, before the PR.** A first version
    kept the exemption in LSM mode and required the executor's path to
    lack the `TASK_ROOT` flag. The exec sensor sets that flag for every
    process on the root filesystem. On Ubuntu 24.04 (systemd 255) R004
    then killed every unit start, the watchdog included — the regression
    the audit warned about.
  - **Lab.** Ubuntu 24.04 (systemd 255): units started with `systemd-run`
    drew no verdict; a memfd exec'd by a parent renamed `systemd`, with
    `argv[0]` set to the executor's path, drew R004 (KillProcessTree)
    and was killed. Ubuntu 22.04: the same forged exec was killed;
    before, it was exempt.
- **NN-AUD-003 (LLMP-002) and NN-AUD-051 (LLMP-001), lab PR 81.** The
  model read up to twenty correlated events, raw, inside the block the
  prompt calls trusted and immutable. Their names, paths and DNS queries
  are chosen by the processes observed. A LF, CR or TAB in a file name
  also passed the sanitizer, and a single LF could close the untrusted
  block and open a forged one.
  - The correlated events are sanitized like the focal one and printed
    in their own untrusted block, newest first, capped at 4 KiB. An
    event whose own score would have kept it from the model is left out
    and counted in the prompt.
  - Every untrusted string is printed as a JSON string literal, so no
    value can end its line. TAB, LF and CR count as non-printable. The
    prompt's section delimiter (`===`) inside an untrusted string is
    broken up and raises its own flag.
  - The sanity check weighs the correlated events' injection score with
    the focal event's.
- **NN-AUD-052 (LLMR-001), lab PR 81.** The raw model output kept in an
  escalation was cut at byte 4096 with a slice. A multi-byte character
  across the cut panicked, and with `panic = "abort"` that stopped the
  agent. The cut now falls on a character boundary.
- **NN-AUD-054 (LLMR-006), lab PR 81.** Below its confidence floor a
  `KillTree` came back `Inconclusive`, which the engine executed, while
  a `Kill` at the same confidence was refused. Below the floor every
  destructive action is now refused (KillTree 0.85, Kill and Quarantine
  0.70, BlockNetwork and Throttle 0.60), and an `Inconclusive` from any
  verifier is escalated, never executed.
- **Lab, for the LLM fixes (PR 81).** The lab guests carry no model (the
  8B GGUF does not fit the guests' memory and CPU budget), so ADE runs in
  rule-only mode there. The prompt builder, the sanitizer and the
  verifier are pure code; they are covered by unit tests and by
  end-to-end `evaluate` tests over scripted backends.
- **NN-AUD-002 (POS-001), lab PR 80.** Two heuristic signals of
  different trigger types corroborated each other into a locked COMBAT,
  and every heuristic is cheap for an unprivileged user. An update's
  twenty HTTPS connections followed by three internal SSH sessions
  reached COMBAT. Its ladder could then isolate the host, and only a
  signed release ended it.
  - **Corroboration needs two kinds of evidence**: network, execution,
    file system, kernel. The mass-write arm of ConfirmedIntrusion counts
    as file system, so snapd's state rewrite and its unit write (the
    2026-06-02 self-lock) are one kind.
  - **COMBAT on heuristics alone is unlocked.** The ladder contains at
    the process level, refuses ISOLATE (a signed audit entry says why)
    and the posture decays to ENGAGED after 30 minutes without a new
    escalation signal. The ladder stands down with it.
  - **COMBAT is locked** — isolation allowed, no decay, signed release —
    on a kernel-adjudicated denial, on root changing a system file
    outside an administrator's session, or when an administrator forces
    it. An isolation refused earlier in the episode runs as soon as
    COMBAT locks.
  - **Where this departs from the audit's fix.** It proposed that no two
    signals an unprivileged user can forge corroborate. The only signal
    such a user cannot forge (AntiTamperDenial) reaches COMBAT alone, so
    the corroboration path would have been dead. Here the kind of
    evidence gates COMBAT, and privilege gates isolation.
  - **Lab, Ubuntu 24.04 (6.8) and AlmaLinux 9 (5.14).** The exfiltration
    burst and the internal SSH fan-out each raised ENGAGED, in either
    order, and together stayed there. A binary run from /tmp, then an
    exfiltration burst through an `ssh -D` tunnel from the same session,
    reached COMBAT with `locked=false`. On 24.04 the offender was the
    session's sshd, which the ladder spares; it escalated to ISOLATE and
    refused it, and the host stayed reachable. Before the fix, that
    sequence isolated the host. On AlmaLinux (OpenSSH 9.9, sessions run
    `sshd-session`) the offender was killed and contained, with no
    isolation. On 24.04, thirty minutes after the last signal, the
    unlocked COMBAT decayed to ENGAGED and the ladder stood down. In a
    new episode, after the refused isolation, root's attempt to delete
    the agent binary was denied by the kernel; COMBAT locked, and the
    next ladder tick isolated the host. The signed audit log shows the
    refusal at 00:37:07 and the isolation at 00:37:24, "COMBAT since
    locked on non-heuristic evidence".
- **NN-AUD-004 (LLMR-002), lab PR 82.** The event loop awaited every ADE
  evaluation inline. An exec that no rule matched held every sensor's
  channel for up to the inference timeout (15 s), and the kernel ring
  buffers dropped what arrived meanwhile: any user could keep the agent
  blind by running unknown binaries in a loop. The timeout did not stop
  the generation either. Dropping the handle of a blocking task leaves
  it running, so it kept the model's weights up to the backend's own
  120 s budget, and the next evaluations queued behind it and timed out
  in turn.
  - The evaluation and the response to its verdict run on their own
    task (`AdeSlot`). One runs at a time; an exec that arrives while one
    runs is judged by the rules only, counted, and the count is logged
    once a minute. The event loop never waits on the model.
  - On timeout the engine stops the generation at its next token and
    reports the timeout once the backend is free. The backend's budget
    is the engine's timeout.
  - Tests: an evaluation that never ends refuses fifty more at once,
    without waiting, and frees the slot when it ends; an endless
    generation stops when the timeout fires, and the timeout is
    reported after it stopped.
  - Lab (Ubuntu 22.04): the agent run by hand with ADE on a placeholder
    model (candle refuses it; the mock backend answers). Forty unknown
    execs in a burst: the first was evaluated (VERDICT (ADE)), the others
    were counted as skipped ("ADE busy"), and an exec from /tmp right
    after still drew R001 at once. The privileged suite passed (55/55).
- **NN-AUD-047 (CMB-002), lab PR 83.** NEUTRALIZE judged a killed tree
  by its root alone. A descendant still running — not killed, spared by
  the host-critical guard, or beyond the 1000-descendant walk, which
  stopped silently — left the episode "verified contained". Every
  descendant now counts, the walk reports where it stopped
  (`TreeTruncated`), and the reason names the cause. An uncontained
  tree escalates like any uncontainable offender; isolation still needs
  a locked COMBAT (NN-AUD-002).
- **NN-AUD-049 (CMB-005) and NN-AUD-048 (CMB-003), lab PR 83.** The
  host-critical guard (the agent's stack, the SSH service) was consulted
  only by the kill-tree walk: a rule's KillProcess, or a Quarantine,
  BlockOutbound or Throttle verdict, could take down sshd or the
  watchdog. It now applies to every action on a process. That would
  have widened a hole: the guard spared *any* process running
  `/usr/sbin/sshd`, a binary any user can run, on a high port, to earn
  immunity. NN-AUD-048 is therefore taken with it, ahead of Wave 1:
  - sshd is spared only as root inside an SSH unit of systemd
    (`ssh.service`, `sshd.service`, socket-activated `ssh@`/`sshd@`);
  - with no systemd unit in the cgroup path, exe and uid 0 still decide;
  - a session's own processes run in the session's scope and are not
    spared — when one is the offender, killing it is the containment.
    OpenSSH 9.8 and later run sessions as `sshd-session` anyway; on
    Ubuntu 24.04 (OpenSSH 9.6) they ran `/usr/sbin/sshd` and were
    spared.
  - Lab, Ubuntu 24.04: a binary run from /tmp, then an exfiltration
    burst through an `ssh -D` tunnel. Before, the tunnel's sshd (uid
    1000, in the session's scope) was spared and the ladder escalated to
    ISOLATE (refused since NN-AUD-002). Now NEUTRALIZE killed it and the
    threat was contained without isolation. The SSH service kept
    accepting connections, and the quarantine refused `/usr/sbin/sshd`
    (a protected system prefix).
- **NN-AUD-030 (FIMP-002), lab PR 84.** The baseline hashed a watched
  symlink's target without checking its type. A link to a FIFO blocked
  the open for good, and with it the drain, which holds the drift
  database: FIM went blind, silently. A link to `/dev/zero` never reached
  EOF. A link to anything but a regular file now yields the link row
  only. The hash opens non-blocking and refuses a non-regular file, or
  one over 512 MiB.
- **NN-AUD-033 (FIMP-005), lab PR 84.** A watched file renamed away kept
  resolving to the watched path. `mv authorized_keys authorized_keys.bak`
  followed by an edit of the copy was reported as a change to
  `authorized_keys`, and its rule killed the editor. Once the rename
  lands, the moved inode is forgotten and whatever now lives at the path
  is watched — a file renamed over it included. The hook fires before
  the rename, so a drain that runs first retries for two seconds.
- **NN-AUD-034 (FIMP-006), lab PR 84.** A drift log that could not be
  written (disk full, a rotation or protection fault) made the drain
  return before the event reached the rules, silencing every FIM rule
  at once. The event now always goes out. Evidence that could not be
  recorded is reported at ERROR, once a minute with a count.
- **NN-AUD-035 (NETR-001), lab PR 84.** Review 54 decided that a
  wide-coverage credential open (any home's keyring, browser or
  password store) is reported, never acted on: the owner application
  opens it, and so does a backup. The chain rules ignored that and
  recorded it as the CredRead precursor, so the next flow of the same
  process drew KillProcessTree. They now skip wide-coverage opens; the
  FIM rules still log them.
- **NN-AUD-061 (DEC-001), NN-AUD-062 (DEC-002) and NN-AUD-063 (DEC-003),
  lab PR 84 — file canaries, end to end.** In the lab no file canary
  deployed at runtime ever tripped; three defects stacked up, and a
  fourth the audit did not list.
  - *The decoy was never watched* (DEC-001). Only the FIM path list
    filled the kernel's `WATCHED_PATHS`, so the kernel emitted nothing for
    a decoy outside it, and the drain would have dropped an event for an
    inode it could not name. The privileged e2e hid it by listing its
    decoys in `fim-paths.v1`. A deploy now watches the decoy's inode
    (`FimWatch`, the drain's own handles), a burn stops, and every boot
    watches the registry's decoys again — the FIM boot keeps only what it
    registers.
  - *The write could be redirected* (DEC-002). The path was checked, then
    re-resolved by `create_dir_all` and an open that refused a symlink
    only as the last component. A user owning a directory on the way
    could swap in a symlink in between. The decoy is now written by a
    walk from the root, `O_NOFOLLOW` on every component, with missing
    directories made by `mkdirat` inside the walk, and must be a regular
    file.
  - *The installed agent could not write a decoy at all.* The unit's
    `ProtectSystem=strict` and `ProtectHome=read-only` make every decoy
    location read-only in its namespace: each deploy failed with EROFS.
    The walk starts at the host's root as PID 1 sees it (`/proc/1/root`),
    as the quarantine and capability responses do (reviews 86 and 87).
  - *After a restart, reads were dropped* (DEC-003, below).
  - Lab, Ubuntu 22.04, installed agent: a deploy under `/home/nn` now
    succeeds; a `cat` of the decoy drew CANARY TRIPPED and NN-L-CANARY-001,
    and so did one after `systemctl restart northnarrow-agent` (the boot
    reported `read_forward=1`). Before: the deploy failed with EROFS, and
    a decoy in place never tripped.
- **Lab for NN-AUD-033 and NN-AUD-035 (Ubuntu 22.04).** `mv
  /etc/hosts.allow` away and an edit of the moved copy drew no event
  under `/etc/hosts.allow`; moved back, the file was watched again and
  its changed content reported (`FIM DRIFT … op=Created`). A process that
  read `~/.gnupg/private-keys-v1.d/…` and then opened a flow drew
  NN-L-FIM-017 at Log, and no CHAIN-001.
- **NN-AUD-063 (DEC-003), lab PR 84.** The boot rebuilt the canary
  indexes with no inode resolver. The read-forward set came out empty,
  and the FIM drain dropped every read of a file canary until an
  operator deployed, burned or refreshed one. Boot and admin now share
  one rebuild (`CanaryIndexes::rebuild_live`). The boot log reports the
  read-forward count, and warns when a file canary's decoy is missing.
- **NN-AUD-016 (EBPF-003), lab PR 85.** Of the three pinned override
  maps, `PTRACE_OVERRIDE` alone was neither tied to the session nonce nor
  zeroed at boot, and its hook accepted any non-zero value. One write to
  the pinned map lifted the ptrace protection of every later agent until
  a reboot: its memory became readable, a debugger attachable, and the
  hook returned before recording anything. It now opens only on this
  boot's session nonce, like `KILL_OVERRIDE` and `FS_PROTECT_OVERRIDE`,
  and the agent zeroes and pins it at boot, before the hooks attach. A
  failure there counts as a deny shortfall. Lab, Ubuntu 24.04: the hook
  loads with the compare, the pinned map reads 0 after boot, and root
  opening `/proc/<agent>/mem` gets EPERM, recorded as an `op=ptrace`
  denial.
- **NN-AUD-070 (WDG-004), lab PR 85.** Past the restart ceiling (five
  respawns in sixty seconds, "tamper suspected"), or when a respawn
  failed, the watchdog exited 0. Its unit's `Restart=on-failure`
  neither restarted it nor marked it failed: agent and watchdog were
  gone, with one journal line as the only trace. It now holds instead.
  It stays alive and protected, reports `DEGRADED` to systemd
  (`systemctl status` shows why), and respawns nothing. Once an operator
  starts the agent again, it supervises it with a fresh restart window.
  Lab, Ubuntu 24.04: the new privileged e2e killed every respawned agent
  until the ceiling tripped; the watchdog stayed alive and respawned
  nothing; an agent started by hand was supervised again (killed, it was
  respawned). The watchdog's privileged e2e had never run in the lab
  gate — they are gated by a feature, not `#[ignore]`, and `test-ignored`
  compiled them out — so `nn-lab.sh test-ignored` now runs them too (5/5).
- **NN-AUD-038 (PROC-002) and NN-AUD-039 (PROC-003), lab PR 86.** Since
  Tappa 10.9 the exec rules judge the path the kernel resolved from the
  executed file's dentry (canonical, symlinks resolved), which closes
  both findings where the LSM exec sensor runs — the default. Without it
  (tracepoint mode, or a file the sensor could not place) the rules fell
  back on the string passed to `execve`: a relative `./payload` run from
  /tmp matched no staging rule, and `/usr/bin/../../tmp/nsenter` passed
  R013/R017's standard-prefix exemption. That fallback is now the string
  resolved lexically (`.`, `..`, `//`) when it is absolute, and the
  running image's path when it is relative. The caller's string is kept
  as evidence.
- **NN-AUD-040 (PROC-004), lab PR 86.** R018's only autonomous response
  (Critical, KillProcessTree for a module loaded from outside
  /lib/modules) was turned into a Medium alert by any truncated path,
  including one nested past the kernel walk's 16 components — a depth the
  loader chooses. The walk now tells its two causes apart. Deeper than
  16 components is deeper than any module directory, whose modules sit
  a dozen down at most: it is killed, allowlisted loader or not. A failed
  kernel read leaves the origin unknown: an alert, raised from Medium to
  High. Lab, Ubuntu 24.04: the stock `dummy.ko.zst` copied 18
  directories deep and loaded with `insmod` drew R018 Critical,
  KillProcessTree (`…/d4/…/d18/dummy.ko.zst`); it drew a Medium alert
  before.
- **NN-AUD-042 (PROC-007), lab PR 86.** R009 killed every root exec from
  a home or a temporary directory, `sudo ~/deploy.sh` and RPM scriptlets
  included. It once killed `nn-admin`. An administrator's sudo/su
  session at a terminal, and a package manager's transaction, are now
  recorded instead — review 52's boundaries for the FIM rules. The
  audit's proposed carve-out, any "auth-mediated" process, was not
  taken. That covers every descendant of sshd (NN-AUD-043), so it would
  have spared the escalation R009 exists for: an exploit run from an ssh
  session. Lab, Ubuntu 24.04: a root script in `/home/nn` run with `sudo`
  at a terminal drew R009 at Log and completed; the same script run with
  `sudo` without a terminal was killed. A script that exits within a few
  milliseconds can still draw the kill: its lineage is read once it has
  gone, and the kill then finds nothing to stop.
- **NN-AUD-041 (PROC-005), open — a design question.** Only root can load
  a module, and root can put one under /lib/modules, so R018's path test
  cannot be the discriminant. The audit's fix (a baseline of module
  inodes) would kill every DKMS build after a kernel update. The
  candidates are the kernel's own module-signature verdict, and a
  trusted-installer window for module loads as for kexec (review 82).
  Both change what operators may do, and are left for a dedicated change.
