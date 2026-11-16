# Alpha tester guide

> Draft until rc-final: this guide is checked again before the v0.1.0-alpha tag.

NorthNarrow is an open-source endpoint detection and response (EDR) agent
for Linux. It watches what runs on a host, the files it touches and the
connections it makes, through small programs it loads into the kernel
(eBPF). It judges each event against its rules and writes every finding
as a signed record that you can check later. It sends nothing anywhere
unless you configure it to.

This guide takes you through one test of the alpha, start to finish, on a
throwaway virtual machine: install it, verify it, make it record a few
harmless things, read what it recorded, collect diagnostics, report what
you found and remove it. It needs about an hour and assumes no knowledge
of the project. You need to be at ease with a Linux shell and `sudo`.

What we already know does not work, or works only in part, is in
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md). Read it before you report:
it saves you time.

## 1. Who the alpha is for

The alpha is for people who want to try a Linux EDR on a test machine and
tell us what they see:

- system administrators and security engineers who run Linux servers;
- people who know another EDR and want to compare how this one records;
- anyone who finds a way to make it misbehave, and reports it.

It is **not** for protecting a real machine yet. Do not install it on a
host with real data, real users or real credentials, nor on a machine you
do not own or are not allowed to test. Nobody supports the alpha in
production, and a later release may change its formats without a
migration.

## 2. What "observe only" means

A fresh install runs the `alpha` profile
([ALPHA_PROFILE.md](ALPHA_PROFILE.md) §1). In that profile the agent
**records, and does not act**:

- It detects, judges and records exactly as it would in production. Every
  rule runs, the host's posture rises and falls with the evidence, and
  every record is signed in a hash chain.
- No response touches a program on the host. Kills, quarantines, network
  blocks, throttling and the network isolation of the highest posture
  (COMBAT) are not carried out. Each record says what would have been
  done: `"response": "would have: KillProcessTree"`, or `"none"`.
- The optional prevention features (exec policy, exec quarantine,
  copy-on-first-write restore) only observe.

A false positive is therefore a record, never a broken program.

**What the profile does not switch off: the agent protects itself**
([ALPHA_PROFILE.md](ALPHA_PROFILE.md) §1.1). Without that protection,
anyone with root could blind or stop the agent and its records would mean
nothing. Under every profile the kernel refuses, unless a signed
"trusted-installer window" is open:

- signals, debugging (ptrace) and memory access aimed at the agent, its
  watchdog and its helper processes, and changes to their priority or
  limits;
- writes, renames and deletes of the agent's files, units and state, and
  reads of its signing key;
- changes to the agent's own kernel programs, and foreign kernel tracing
  programs (bpftrace, BCC, `bpftool feature probe`) unless you allowed
  them at install;
- kernel modules the agent does not trust, kexec images, and changes to a
  few critical kernel settings.

So `sudo systemctl stop northnarrow-agent`, or a `kill` of the agent, is
refused and recorded. To stop, restart, upgrade or remove the agent you
open a window with your admin key
([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §3.7). The
uninstaller and `install.sh --upgrade` open it for you.

## 3. Before you start

**Use a throwaway VM, and take a snapshot** before you install. Reverting
the snapshot is the quickest way back.

**Pick a tested system**
([KERNEL_COMPATIBILITY.md](KERNEL_COMPATIBILITY.md), "Verified matrix"):

| Distribution | Kernel |
|---|---|
| Ubuntu 22.04 LTS | 5.15 (supported, degraded) |
| Debian 12 | 6.1 |
| Ubuntu 24.04 LTS | 6.8 |
| Debian 13 | 6.12 |
| Ubuntu 26.04 LTS | 7.0 |

The installer names any other distribution as untested and goes on. The
machine needs x86_64, systemd, kernel BTF, the `bpf` LSM in the kernel's
active list, bpffs at `/sys/fs/bpf`, and `nft`. Check the two that are
most often missing:

```sh
ls /sys/kernel/btf/vmlinux          # must exist
cat /sys/kernel/security/lsm        # must contain bpf
```

Ubuntu does not put `bpf` in the list by default. Add it to the running
list and reboot, as
[KERNEL_COMPATIBILITY.md](KERNEL_COMPATIBILITY.md#enabling-the-bpf-lsm-kernel-command-line)
shows. Never replace the list with a fixed one: that can switch AppArmor
or SELinux off.

**If you use bpftrace or BCC**, install them first and add
`--allow-bpf-tools` to the install command below
([ALPHA_PROFILE.md](ALPHA_PROFILE.md) §1.2). Otherwise the agent refuses
them.

## 4. Install and verify

([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §1 is the
full guide.) These commands work on Ubuntu 24.04 and Debian 12 as they
ship: git, gpg, gpgv and curl are there. Testing before the release is
tagged? Read "Before the release exists" at the end of this section
first.

Download the tarball, `SHA256SUMS` and its signature `SHA256SUMS.asc`
into one directory:

```sh
ver=<ver>                            # the release you test, e.g. 0.1.0-alpha
base=https://github.com/northnarrow/northnarrow-new/releases/download/v$ver
curl -fLO "$base/northnarrow-$ver-x86_64-linux.tar.gz"
curl -fLO "$base/SHA256SUMS"
curl -fLO "$base/SHA256SUMS.asc"
```

For the `.deb` instead of the tarball, download it the same way, by the
name the release page lists (`northnarrow_<ver>-<rel>_amd64.deb`), next
to `SHA256SUMS` and `SHA256SUMS.asc`.

Verify them with the release key committed at the release tag, never
with a copy from the release page
([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §5, "Without
`gh`"):

```sh
git clone https://github.com/northnarrow/northnarrow-new && cd northnarrow-new
git -c gpg.ssh.allowedSignersFile=.github/allowed_signers verify-tag "v$ver"   # Good "git" signature
git show "v$ver:deploy/release/RPM-GPG-KEY-northnarrow.asc" > ../nn-release-key.asc
cd .. && gpg --show-keys nn-release-key.asc     # BBBB EB6F 5566 A1CE 99AE  8379 C66A E018 C172 7C8D
gpg --dearmor < nn-release-key.asc > nn-release-key.gpg
gpgv --keyring ./nn-release-key.gpg SHA256SUMS.asc SHA256SUMS     # Good signature
sha256sum -c --ignore-missing SHA256SUMS                          # northnarrow-<ver>-…tar.gz: OK
```

Each line must print what its comment says. If one does not, stop: the
download is not the release. `sha256sum -c --ignore-missing` checks only
the files you downloaded and says nothing of the others: make sure the
line of each file you will install is there (with the `.deb`, also
`northnarrow_<ver>-<rel>_amd64.deb: OK`).

Then install. Leave the three downloaded files where they are, next to
the extracted tree: the installer checks the signature and the tarball
again itself before it changes anything.

```sh
tar xzf "northnarrow-$ver-x86_64-linux.tar.gz"
cd "northnarrow-$ver-x86_64-linux"
sudo ./deploy/install.sh            # alpha profile, started now and at every boot
```

**What `install.sh` needs to accept the release.** One of two proofs
([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §5.1):

- the build's provenance attestation, checked with `gh` 2.49 or newer
  (logged in, online), or with `cosign` and an attestation bundle
  downloaded beforehand (`--attestation <file>`);
- or, when neither tool is on the host, `SHA256SUMS.asc` next to
  `SHA256SUMS`, a good signature by the release key, checked with `gpgv`.
  This is the path on Ubuntu 24.04 and Debian 12 as they ship (no `gh`, or
  a `gh` older than 2.49).

With the second, it prints `tarball matches the signed SHA256SUMS`. A
`gh` 2.49 or newer that runs and fails (not logged in, no network) is a
refusal even with a good signature: fix what it says (`gh auth login`,
the network), or pass the offline bundle. If it refuses the host, the
message says why and what to do; nothing has been changed. Do not add
`--allow-unverified` to get past a refusal of a release download: that
flag means the files are not proven to be the release.

**Keep the extracted tree**: the uninstaller is in it.

From the `.deb` instead (Ubuntu 24.04, Debian 13; a package install
starts nothing by itself). dpkg and apt check no signature on a single
package file: the `northnarrow_<ver>-<rel>_amd64.deb: OK` line of the
verification above is its proof (or `gh attestation verify`, in
[INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §6.1). Then:

```sh
sudo apt-get install ./northnarrow_<ver>-<rel>_amd64.deb
sudo systemctl enable --now northnarrow-agent northnarrow-watchdog
```

The install writes an **admin key** to `/root/northnarrow-admin.key`.
On a throwaway VM, leave it there for the test; on any other machine,
move it off the host. Every command below uses it:

```sh
KEY=/root/northnarrow-admin.key
sudo nn-admin status --key "$KEY"
```

The first summary line must say `OBSERVE-ONLY — profile alpha`.

Run `nn-admin` with `sudo`: the agent's socket and the key are root's.
Without `sudo`, a command that talks to the agent fails with a permission
error; that does not mean the agent is stopped. If `sudo nn-admin status`
exits 5 with `connecting to /run/northnarrow/admin.sock`, the agent does
not run: see section 5.

### Before the release exists

Until the release is tagged, there is no release page, no tag, no
`SHA256SUMS.asc` and no attestation tied to a tag. A build you test
before then (a CI build the project gives you, or one you build from the
source) cannot be proven to be the release:

- **What you can check:** `sha256sum -c --ignore-missing SHA256SUMS`
  prints `OK` for each file you have. It proves the files are whole and
  the ones the build listed, not where they were built.
- **What you cannot check:** the tag, the release key's signature and the
  build's provenance. `install.sh` says so and refuses.
- **Install it only on a throwaway VM**, with the flag that records what
  it is:

  ```sh
  sudo ./deploy/install.sh --allow-unverified    # a CI build: recorded as 'checksums'
  sudo ./deploy/install.sh --source-tree         # a build from source: recorded as 'source-tree'
  ```

  For a CI build the installer prints `tarball matches SHA256SUMS` (not
  "signed"), and `nn-admin host-check` shows `release verified at
  install` as a WARN naming the flag. Both are expected for such a build.
  Its version can read `0.0.1`.
- A `.deb` of such a build has only its `SHA256SUMS` line: nothing
  checks more.

Or wait for the tag, and verify as above.

## 5. Read `nn-admin status`

Without a key (`sudo nn-admin status`), the agent shows its posture only:

```
── summary ──────────────────────────────────────────────
posture           : Observing
profile, sensors, records: withheld — `nn-admin status --key <key>` (a key with audit-read or telemetry-read) shows them
```

With the key (`sudo nn-admin status --key "$KEY"`) it starts with a
summary ([ALPHA_PROFILE.md](ALPHA_PROFILE.md) §3):

```
── summary ──────────────────────────────────────────────
posture           : Observing, OBSERVE-ONLY — profile alpha (install manifest): nothing is killed, blocked or quarantined; every verdict is recorded with what it would have done
sensors           : OK — no degradation, no event lost
records today     : 9 (2 High, 7 Low) — UTC day 2026-11-13, counted since 2026-11-13T09:30:00Z; `nn-admin detections` lists them
would have        : KillProcessTree x2
─────────────────────────────────────────────────────────
```

| Line | What it tells you | Worth a report when |
|---|---|---|
| `posture` | how alarmed the agent is (OBSERVING, ALERTED, ENGAGED, COMBAT) and the profile | the profile is not `alpha` on a fresh install |
| `sensors` | `OK`, or `DEGRADED` with the number of degradations and of events lost | a degradation you cannot explain from [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) |
| `records today` | the records of the current UTC day, by severity | — |
| `would have` | the responses the profile held back, by action | — |

Further down, among many lines:

- `trust level`: how much of the agent's protection is measured
  ([BOOT_INTEGRITY.md](BOOT_INTEGRITY.md) §5). Expect **L2** under
  `alpha` (for example `L2 (enforcing and verified, degraded)`); L3 needs
  responses that run. **L1** (a kernel deny hook missing, or the
  self-test inconclusive) or **L0** (no enforcement) is worth a report.
- `degradations`: each one of this run, one line each, also signed in the
  audit log ([BOOT_INTEGRITY.md](BOOT_INTEGRITY.md) §4).
- `deny fail-open`: should stay at 0. Another value names a kernel hook
  that let an operation through undecided: report it.
- `ringbuf drops`, `loss by stage`: events lost under load. A few under a
  burst are expected; losses on an idle host are worth a report. One
  line of `loss by stage` is not a loss: `decision delay` counts events
  judged later than their time budget, all of them judged. The agent's
  start, the scenarios and a slow VM add some; a count that keeps rising
  on an idle host is worth a report.
- `host hardening : <n> check(s), <m> warning(s)`, the last line: settings
  of the host that `nn-admin host-check` lists one per row, with how to
  fix each. They are the host's, not faults of the agent. On a throwaway
  cloud VM expect WARN rows for kernel lockdown, module signatures, Secure
  Boot, IMA, kexec and the cgroup v1 controllers, and for the admin key
  left on the host (section 4 tells you to leave it there); before the
  tag, `release verified at install` too. Worth a report: a WARN on the
  BPF LSM, `nft` or bpffs rows, or on `release verified at install` after
  you installed a tagged release as section 4 says.
- A warning from the system's C library when a command starts
  (`GLIBC_… not found`) is worth a report, with your distribution.

**Postures.** OBSERVING, then ALERTED, ENGAGED and COMBAT as evidence adds
up ([COMBAT_RECOVERY.md](COMBAT_RECOVERY.md)). Without new signals the
posture comes down by itself: ALERTED after an hour, ENGAGED after a day,
an unlocked COMBAT 30 minutes after its last signal. A COMBAT shown as
`locked` has no automatic exit; release it with
`sudo nn-admin unlock --key "$KEY"`
([COMBAT_RECOVERY.md](COMBAT_RECOVERY.md) §3). Under `alpha`, COMBAT is
entered and recorded but never isolates the host.

**If the agent does not run**, `sudo nn-admin status` exits 5. Look at:

```sh
systemctl status northnarrow-agent northnarrow-watchdog --no-pager
sudo journalctl --namespace=northnarrow -u northnarrow-agent -n 50 --no-pager
```

Every `nn-admin` command and its exit codes are in [NN_ADMIN.md](NN_ADMIN.md).

## 6. Harmless scenarios that draw a record

Each scenario makes the agent record something, with harmless commands
only: copies of `/bin/true` and `/bin/sleep`, files you create and remove,
the loopback interface and an address reserved for documentation. Nothing
is downloaded, nothing outside the VM answers, and each clean-up step
puts the machine back as it was.

How to run them:

- Run them as your normal user, in a normal shell (not a root shell),
  unless a command says `sudo`. Run as root, some of them are judged by
  another rule (`R009_RootExecFromUserPath`).
- Run one scenario at a time. Note the time just before it, wait about 5
  seconds after it, then list its records:

  ```sh
  since=$(date +%s)       # just before the scenario
  # ... run the scenario, wait 5 s ...
  sudo nn-admin detections --key "$KEY" --since "$since" \
    | jq -r '[.rule_id, .severity, .response] | @tsv'
  ```

  Without `jq`, drop the last line and read the JSON lines as they are.
- What each rule means, its known false positives and its own test are in
  the
  [rule catalogue](https://github.com/northnarrow/northnarrow-new/blob/main/docs/detection/RULE_CATALOGUE.md).
- The **record to expect** is the rule and severity listed. Other records
  can appear beside it (the posture's own, or a second rule on the same
  event): that is normal. A scenario whose expected record does not
  appear is worth a detection-gap report (section 8).
- A few scenarios in a row raise the posture, up to COMBAT (all eight in
  a row did, in our lab). Under `alpha` nothing follows from it but
  records, and it comes down by itself (section 5).

### 6.1 A program run from a temporary directory

```sh
cp /bin/true /tmp/nn-demo-tmp && /tmp/nn-demo-tmp
cp /bin/true /var/tmp/nn-demo-vartmp && /var/tmp/nn-demo-vartmp
```

Record to expect: `R001_ExecFromTmp` (High) and `R003_ExecFromVarTmp`
(High). Their `response` reads `none` on a calm host and `would have:
KillProcessTree` once the posture has risen: the rule's kill depends on
the posture. Malware often unpacks itself into a world-writable directory
and runs from there.

Clean up: `rm -f /tmp/nn-demo-tmp /var/tmp/nn-demo-vartmp`

### 6.2 A program in a hidden home directory

```sh
mkdir -p ~/.nn-demo && cp /bin/true ~/.nn-demo/x && ~/.nn-demo/x
```

Record to expect: `R008_HiddenHomeBinary` (Medium).

Clean up: `rm -rf ~/.nn-demo`

### 6.3 A program named like a crypto miner

`sleep` under another name, for 2 seconds. It mines nothing.

```sh
cp /bin/sleep ~/xmrig && ~/xmrig 2
```

Record to expect: `R007_CryptoMiner` (Critical), `would have:
KillProcessTree`. Under the `enforcing` profile it would be killed.

Clean up: `rm -f ~/xmrig`

### 6.4 A netcat port check

Needs netcat (`nc`), installed by default on Ubuntu. On Debian, install
it first: `sudo apt install netcat-openbsd`. Without it the command fails
with `nc: command not found` and nothing runs, so no record appears: that
is not a detection gap. It only asks whether the local SSH port answers.

```sh
nc -z -w 2 127.0.0.1 22
```

Record to expect: `R005_NetcatExec` (High). Nothing to clean up.

### 6.5 A connection to a blocked address

`203.0.113.5` is in a range reserved for documentation (RFC 5737): it is
never routed and nothing answers. `curl` gives up after 3 seconds. The
range is in the IP blocklist the agent ships, as a harmless example.

```sh
curl -s -m 3 -o /dev/null http://203.0.113.5/
```

Record to expect: `NN-L-NET-001_OutboundToBlockedIp` (Critical), `would
have: KillProcessTree`. `curl` itself exits 28 (its time-out): that is
expected. Nothing to clean up.

### 6.6 A new systemd unit file

An empty unit file, never loaded by systemd, written by a short-lived
service:

```sh
sudo systemd-run --quiet --wait cp /dev/null /etc/systemd/system/nn-demo.service
```

Record to expect: `NN-L-FIM-009_SystemdUnitDropped` (High). A new unit is
a common way to make malware start again at each boot.

Clean up: `sudo rm -f /etc/systemd/system/nn-demo.service`

### 6.7 Many files renamed to `.locked` by one process

Twenty files of zeros in a scratch directory, renamed by one Python
process: the shape of a ransomware rename burst, on files that hold
nothing.

```sh
sudo mkdir -p /srv/nn-demo-rename
for i in $(seq 1 20); do
  sudo dd if=/dev/zero of=/srv/nn-demo-rename/file$i.txt bs=4096 count=2 status=none
done
sudo python3 -c 'import glob, os; [os.rename(f, f + ".locked") for f in glob.glob("/srv/nn-demo-rename/*.txt")]'
```

Record to expect: `NN-L-IMP-002_RenameExtensionBurst` (High).

Clean up: `sudo rm -rf /srv/nn-demo-rename`

### 6.8 The agent refuses to be stopped

This shows that self-protection stays on under `alpha`:

```sh
sudo kill -TERM "$(sudo cat /run/northnarrow/agent.pid)"
systemctl is-active northnarrow-agent
```

The `kill` fails with `Operation not permitted`, and the agent stays
`active`. Record to expect: `NN-L-AT-001_AntiTamperDenial` (High) with
`"operation": "signal"` and the response `denied in kernel (anti-tamper
LSM hook)`: this refusal is not held back by the profile. Nothing to
clean up.

## 7. Read the records

```sh
sudo nn-admin detections --key "$KEY"                        # the last 50, newest first
sudo nn-admin detections --key "$KEY" --min-severity high --limit 20
sudo nn-admin detections --key "$KEY" --path /tmp/           # by executable, file or process name
```

The records come as JSON lines on standard output, a summary on standard
error. Other filters: `--since` and `--until` (UNIX seconds), `--sensor`
(`exec`, `file`, `module-load`, `network`, `anti-tamper`, `canary`). A
row whose signature does not verify is left out, and the agent logs an
error.

The fields to read first:

| Field | Meaning |
|---|---|
| `id`, `ts` | the record's number and its UTC time |
| `rule_id`, `rule_name` | the rule, as in the rule catalogue |
| `severity` | `Low`, `Medium`, `High` or `Critical` |
| `exe` | the executable, for exec records |
| `file` | the file, for file records |
| `operation` | what the kernel refused, for `NN-L-AT-001` records |
| `posture_at` | the posture when it was recorded |
| `response` | `would have: <action>` under `alpha`, or `none` |
| `matches` | every rule that matched, when more than one did |

On disk the records are in
`/var/lib/northnarrow/detections/detections.jsonl` and its rotated
archives. Each line is a link of a signed hash chain: read it through
`nn-admin`, never edit it. To check the chains and the signed audit log:

```sh
sudo nn-admin chain verify          # OK or BROKEN per chain; exit 8 on any problem
sudo nn-admin audit verify          # the signed audit log, /etc/northnarrow/audit.log
```

[EVIDENCE_CHAINS.md](EVIDENCE_CHAINS.md) says what a failed check means.

**On a quiet host** you will still see a few Low records: one
`NN-L-BPF-002` at each start of the agent or the watchdog, records at boot
for systemd's own kernel programs, logrotate's daily run, and on cloud
images cloud-init's netcat at each boot. Other known false positives are
in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md#false-positives-you-may-see).

## 8. Collect diagnostics without personal data

Status output, records and journal lines name your host, your user, your
paths, the command lines you ran and IP addresses. The commands below
gather what a report needs into one directory, then replace the host
name and its domain, your user name, the host's machine id and boot id,
and the IP and MAC addresses (loopback and the documentation addresses
of scenario 6.5 kept) with placeholders. Set `since` to a time before
the problem (UNIX seconds; one hour ago here):

```sh
KEY=/root/northnarrow-admin.key
since=$(( $(date +%s) - 3600 ))
d=$(mktemp -d /tmp/nn-diag.XXXXXX)
{ nn-admin --version; grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release; uname -r; } > "$d/system.txt" 2>&1
sudo nn-admin status --key "$KEY" > "$d/status.txt" 2>&1
nn-admin host-check > "$d/host-check.txt" 2>&1
sudo nn-admin chain verify > "$d/chain-verify.txt" 2>&1
sudo nn-admin detections --key "$KEY" --since "$since" --limit 200 > "$d/records.jsonl" 2> "$d/records-summary.txt"
sudo journalctl --namespace=northnarrow --since "@$since" --no-pager > "$d/agent-journal.txt" 2>&1
sudo journalctl -u northnarrow-agent -u northnarrow-watchdog --since "@$since" --no-pager > "$d/units-journal.txt" 2>&1
H=$(hostname) D=$(hostname -d 2>/dev/null) U=$(id -un) M=$(cat /etc/machine-id) \
B=$(cat /proc/sys/kernel/random/boot_id) perl -pi -e '
  BEGIN { ($b = $ENV{B}) =~ s/-//g }
  s/\Q$ENV{M}\E/machine-id/g if length $ENV{M};
  s/\Q$ENV{B}\E|\Q$b\E/boot-id/gi if length $b;
  s/\Q$ENV{H}\E/host1/g;
  s/(?<![\w-])\Q$ENV{D}\E(?![\w-])/domain1/g if length $ENV{D};
  s/(?<![\w-])\Q$ENV{U}\E(?![\w-])/user1/g;
  s/\b(?!127\.|203\.0\.113\.)(?:\d{1,3}\.){3}\d{1,3}\b/x.x.x.x/g;
  s/(?<![\w:])(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?::(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4})*)?(?![\w:])/x:x::x/gi;
  s/\b(?:[0-9a-f]{1,4}:){3,7}[0-9a-f]{1,4}\b/x:x::x/gi' "$d"/*
ls -l "$d"
```

Your user name is replaced where it stands as a word (a part of a path,
`user=`, a name in a list), never inside a longer word: with the user
`nn`, `nn-admin` stays `nn-admin`.

Then **read every file before you attach it**. The script cannot know
other names you consider private (a second user, a customer's host name, a
path with a person's name, a secret passed on a command line). Replace
them by hand, consistently (`user2`, `host2`), or delete the line. Never
attach the admin key, any file from `/etc/northnarrow`, or a real
credential. The journal can be long; `grep` helps:

```sh
grep -rlF -e "$(hostname)" -e "$(cat /etc/machine-id)" "$d"   # must print nothing
grep -rlP "(?<![\w-])\Q$(id -un)\E(?![\w-])" "$d"            # must print nothing
grep -nE ' (WARN|ERROR) ' "$d/agent-journal.txt"              # the lines to read first
```

Paste short files into the form's fields. Attach long ones, such as the
journal, as files: drag them into a text box of the form (GitHub takes
`.txt` files; rename `records.jsonl` to `records.txt`). When you are
done: `rm -rf "$d"`.

## 9. Report what you found

**A security vulnerability: report it privately.** Do not open a public
issue. Use GitHub's private vulnerability reporting: **Security → Report a
vulnerability** on https://github.com/northnarrow/northnarrow-new, or
directly https://github.com/northnarrow/northnarrow-new/security/advisories/new
(a GitHub account is needed). Include the component (agent, kernel
programs, watchdog, `nn-admin`), the kernel version, a minimal
reproduction and the impact you observed. You get an acknowledgement
within 5 working days. The full policy is the project's
[security policy](https://github.com/northnarrow/northnarrow-new/blob/main/SECURITY.md).
What counts, for example: a way to stop, blind or get around the agent's
self-protection without a record, a way to make it sign something false,
or a crash caused by an unprivileged user.

**Anything else: open an issue** on
https://github.com/northnarrow/northnarrow-new/issues/new/choose, after a
look at [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md). Pick the form that
fits; each asks for what the diagnostics of section 8 gather:

| Form | Use it for |
|---|---|
| **Bug report** | an install, upgrade or uninstall that failed; a crash; a command that misbehaves; a message you could not understand; a degradation or a lost event you cannot explain |
| **False positive** | a record about something harmless you did on purpose (name the rule, the command, and why it is harmless) |
| **Detection gap** | something the agent should have recorded and did not: a scenario of section 6 with no record, or a harmless reproduction of a known technique |

A detection gap is welcome as an issue only when the reproduction is
harmless (no real malware, nothing that leaves the VM). A way around the
self-protection goes through private reporting, above.

## 10. Uninstall

From the extracted release tree
([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §3):

```sh
sudo ./deploy/uninstall.sh --purge --grant-key /root/northnarrow-admin.key
```

It asks for confirmation (`--yes` skips it). It removes the agent's
binaries from `/usr/local/bin`, its systemd units and slice, its three
system accounts (`northnarrow-scan`, `northnarrow-worker`,
`northnarrow-export`), its kernel programs and their pins under
`/sys/fs/bpf`, its nftables table and `/run/northnarrow`. `--purge` also
removes the keys, the state and the records: `/etc/northnarrow`,
`/var/lib/northnarrow`, the admin key `/root/northnarrow-admin.key`, the
export directory under `/var/log/northnarrow` and the agent's own journal;
without it they stay for a later reinstall. The system journal keeps
systemd's lines about the units, as it does for any service. Exit codes:

- **0**: removed, clean;
- **3**: the agent did not answer, so the removal finishes at the next
  boot: `sudo systemctl reboot`;
- **4**: removed, but processes the agent had contained were found. They
  were thawed and listed by pid and command: look at each one, and keep or
  kill it. Under `alpha` this is rare.

For the `.deb`
([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §6):

```sh
sudo NN_GRANT_KEY=/root/northnarrow-admin.key dpkg -P northnarrow
```

Check that it is gone: `systemctl is-active northnarrow-agent` prints
`inactive` (or the unit is not found), `getent passwd northnarrow-scan`
prints nothing, `ls /sys/fs/bpf` lists no `northnarrow` entry, and after
`--purge` neither `/etc/northnarrow` nor `/var/lib/northnarrow` exists.
Two kernel modules the agent caused to load (`nf_tables`, and `unix_diag`
on Ubuntu 26.04) stay loaded until the next reboot; that is harmless. On
a throwaway VM, reverting to your snapshot is the simplest uninstall.

## 11. Where to read more

- [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md): what we know, with the
  evidence for each item.
- [ALPHA_PROFILE.md](ALPHA_PROFILE.md): the profile, what it holds back
  and what it keeps.
- [INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md): every
  install option, the upgrade, the windows.
- [NN_ADMIN.md](NN_ADMIN.md): every `nn-admin` command.
- [EXPORT.md](EXPORT.md): sending the signed records to your own SIEM
  (off by default).
