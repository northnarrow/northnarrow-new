# Testing the alpha

> Draft until rc-final: this guide is checked again before the v0.1.0-alpha tag.

This guide is for people who try the NorthNarrow alpha on a test machine:
what the alpha does, how to install it, a few harmless scenarios that
make it record something, how to read what it recorded, how to remove it
and how to report a problem. Read
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) first: it lists what we
already know about.

## 1. What the alpha does

**It records. It does not act.** A fresh install runs the `alpha`
profile, which is observe-only
([ALPHA_PROFILE.md](ALPHA_PROFILE.md) §1):

- The agent detects, judges and records exactly as it does in production.
  Every rule runs, the posture moves, and every record is signed in its
  chain.
- No response touches a user program. Kills, quarantines, the
  per-process network block, throttling and COMBAT's network isolation
  are not carried out. Each record says what would have been done
  (`"response": "would have: KillProcessTree"`), or `"none"`.
- The opt-in prevention features (exec policy, exec quarantine,
  copy-on-first-write restore) only observe.

**What `alpha` does not change: the agent still protects itself and the
host's integrity** ([ALPHA_PROFILE.md](ALPHA_PROFILE.md) §1.1). Without
that, anyone could blind or stop the agent, and its records would mean
nothing. Under every profile the kernel refuses, outside a signed
trusted-installer window:

- signals, ptrace and `/proc/<pid>/mem` access aimed at the agent, its
  watchdog or its workers, and priority or limit changes against them;
- writes, renames and deletes of its files, units, state and pins, and
  reads of its signing key;
- BPF operations on its own programs, maps and links, and foreign BPF
  tracing programs (bpftrace, BCC, `bpftool feature probe`) unless you
  allowed them at install;
- kernel modules the agent does not trust, kexec images, and changes to a
  few critical sysctls.

So, on a test machine: `sudo systemctl stop northnarrow-agent` or a
`kill` of the agent is refused and recorded. To stop, restart, upgrade or
remove the agent, open a window with your admin key
([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §3.7); the
uninstaller and `install.sh --upgrade` open it for you.

## 2. Before you start

**Use a throwaway VM.** Take a snapshot before you install. Do not use a
machine with real data, real credentials or other users, and test only
machines you own or are allowed to test.

**Pick a tested system**
([KERNEL_COMPATIBILITY.md](KERNEL_COMPATIBILITY.md), "Verified matrix"):

| Distribution | Kernel |
|---|---|
| Ubuntu 22.04 LTS | 5.15 (supported, degraded) |
| Debian 12 | 6.1 |
| Ubuntu 24.04 LTS | 6.8 |
| Debian 13 | 6.12 |
| Ubuntu 26.04 LTS | 7.0 |

Another distribution is named by the installer, not refused, but it is
untested. The machine needs x86_64, systemd, kernel BTF, the `bpf` LSM in
the kernel's active list, bpffs at `/sys/fs/bpf`, and `nft`. Check:

```sh
ls /sys/kernel/btf/vmlinux          # must exist
cat /sys/kernel/security/lsm        # must contain bpf
```

On Ubuntu, `bpf` is not in the list by default: add it to the running list
and reboot, as
[KERNEL_COMPATIBILITY.md](KERNEL_COMPATIBILITY.md#enabling-the-bpf-lsm-kernel-command-line)
shows. Never replace the list with a fixed one.

**If you use bpftrace or BCC**, install them before NorthNarrow and add
`--allow-bpf-tools` to the install command
([ALPHA_PROFILE.md](ALPHA_PROFILE.md) §1.2). Otherwise the agent refuses
them.

**Install** ([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md)
§1). These commands work on Ubuntu 24.04 as it ships (its gh 2.45 has no
`gh attestation`; git, gpg, gpgv and curl are there). Download the tarball,
`SHA256SUMS` and its signature `SHA256SUMS.asc` into one directory:

```sh
ver=<ver>                            # the release you test, e.g. 0.1.0-alpha
base=https://github.com/northnarrow/northnarrow-new/releases/download/v$ver
curl -fLO "$base/northnarrow-$ver-x86_64-linux.tar.gz"
curl -fLO "$base/SHA256SUMS"
curl -fLO "$base/SHA256SUMS.asc"
```

Verify them with the key committed at the release tag, never with a copy
from the release page
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

Then install. Leave the three files where they are, next to the extracted
tree: the installer checks the signature and the tarball again itself,
with `gpgv`, before it changes anything, and installs with no flag:

```sh
tar xzf "northnarrow-$ver-x86_64-linux.tar.gz"
cd "northnarrow-$ver-x86_64-linux"
sudo ./deploy/install.sh            # alpha profile, started now and at every boot
```

It prints `tarball matches the signed SHA256SUMS`, and records the
release as `signed-checksums` (`nn-admin host-check`: OK). With gh 2.49 or
newer on the machine, it also verifies the release's attestation and
records `attested`; when gh cannot (not logged in: `gh auth login`; no
network), that is a refusal. Do not add `--allow-unverified` to get past a
refusal: it says the download is not proven to be the release.

Keep the extracted tree: the uninstaller is in it. From the `.deb`
instead:

```sh
sudo apt-get install ./northnarrow_<ver>-<rel>_amd64.deb
sudo systemctl enable --now northnarrow-agent northnarrow-watchdog   # a package install starts nothing
```

The install writes an admin key to `/root/northnarrow-admin.key`. On a
throwaway VM you may leave it there for the test. On any other machine,
move it off the host. Every command below uses it:

```sh
KEY=/root/northnarrow-admin.key
sudo nn-admin status --key "$KEY"
```

The first summary line must say `OBSERVE-ONLY — profile alpha`.

## 3. Harmless scenarios that draw a record

Each scenario below makes the agent record something with harmless
commands only: copies of `/bin/true` and `/bin/sleep`, files you create
and remove, the loopback interface and a reserved documentation address.
Nothing is downloaded, nothing leaves the VM, and the clean-up step puts
the machine back as it was.

- Run them as your normal user, in a normal shell (not a root shell),
  unless the command says `sudo`. Run as root, the first scenarios are
  judged by another rule (`R009_RootExecFromUserPath`).
- Run one scenario at a time, wait about 5 seconds, then read its records:

  ```sh
  since=$(date +%s)       # just before the scenario
  # ... run the scenario, wait 5 s ...
  sudo nn-admin detections --key "$KEY" --since "$since" \
    | jq -r '[.ts, .rule_id, .severity, .response] | @tsv'
  ```

  Without `jq`, drop the last line and read the JSON lines as they are.
- What each rule means, its known false positives and its own test are in
  the
  [rule catalogue](https://github.com/northnarrow/northnarrow-new/blob/main/docs/detection/RULE_CATALOGUE.md).
  An expected severity below is the one the catalogue gives.
- A few scenarios in a row raise the posture (ALERTED, ENGAGED, even
  COMBAT). Under `alpha` nothing follows from it but records. It goes
  back down on its own (section 4). A COMBAT shown as `locked` is released
  with `sudo nn-admin unlock --key "$KEY"`.

### 3.1 A program run from a temporary directory

```sh
cp /bin/true /tmp/nn-demo-tmp && /tmp/nn-demo-tmp
cp /bin/true /var/tmp/nn-demo-vartmp && /var/tmp/nn-demo-vartmp
cp /bin/true /dev/shm/nn-demo-shm && /dev/shm/nn-demo-shm
```

Expected: `R001_ExecFromTmp` (High), `R003_ExecFromVarTmp` (High) and
`R002_ExecFromDevShm` (High). On a host that mounts `/dev/shm` with
`noexec`, the kernel refuses the last exec and there is no record.

Clean up: `rm -f /tmp/nn-demo-tmp /var/tmp/nn-demo-vartmp /dev/shm/nn-demo-shm`

### 3.2 A program in a hidden home directory

```sh
mkdir -p ~/.nn-demo && cp /bin/true ~/.nn-demo/x && ~/.nn-demo/x
```

Expected: `R008_HiddenHomeBinary` (Medium).

Clean up: `rm -rf ~/.nn-demo`

### 3.3 A program named like a crypto miner

`sleep` under another name. It mines nothing.

```sh
cp /bin/sleep ~/xmrig && ~/xmrig 5
cp /bin/sleep ~/xmrig-check && ~/xmrig-check 5
```

Expected: `R007_CryptoMiner` twice. The exact miner name is Critical, and
its record reads `would have: KillProcessTree` (under `enforcing` it would
be killed). A name that only contains a miner's name is High and recorded
only.

Clean up: `rm -f ~/xmrig ~/xmrig-check`

### 3.4 A netcat port check

Needs netcat (`nc`) installed. It only checks whether the local SSH port
answers.

```sh
nc -z -w 2 127.0.0.1 22
```

Expected: `R005_NetcatExec` (High). Nothing to clean up.

### 3.5 A listener on an uncommon port

Python's built-in web server, for 5 seconds, serving an empty directory:

```sh
mkdir -p /tmp/nn-demo-www
timeout 5 python3 -m http.server 18080 --bind 127.0.0.1 --directory /tmp/nn-demo-www
timeout 5 python3 -m http.server 18081 --directory /tmp/nn-demo-www
```

Expected: `NN-L-NET-006_UncommonListener` (Medium) for the first, which
listens on loopback only, and `NN-L-NET-019_WildcardListener` (Medium) for
the second, which listens on all addresses.

Clean up: `rmdir /tmp/nn-demo-www`

### 3.6 A connection to an address no DNS answer named

`203.0.113.5` is in a range reserved for documentation (RFC 5737): it is
never routed, nothing answers, and nothing is downloaded. `curl` gives up
after 3 seconds.

```sh
curl -s -m 3 -o /dev/null http://203.0.113.5/
```

Expected: `NN-L-NET-028_ConnectWithoutDns` (Medium). The same request to a
name (`curl -m 3 http://example.com/`) would not draw it, but it leaves
the VM, so it is not part of this list. Nothing to clean up.

### 3.7 A new systemd unit file

An empty unit file, never loaded by systemd, written by a short-lived
service:

```sh
sudo systemd-run --quiet --wait cp /dev/null /etc/systemd/system/nn-demo.service
```

Expected: `NN-L-FIM-009_SystemdUnitDropped` (High). By default its kill of
the writer is held back even under `enforcing`, because the file is
already there.

Clean up: `sudo rm -f /etc/systemd/system/nn-demo.service`

### 3.8 Many files renamed to `.locked` by one process

Twenty files of zeros in a scratch directory, renamed by one Python
process. This is the shape of a ransomware rename burst, on files that
hold nothing.

```sh
sudo mkdir -p /srv/nn-demo-rename
for i in $(seq 1 20); do
  sudo dd if=/dev/zero of=/srv/nn-demo-rename/file$i.txt bs=4096 count=2 status=none
done
sudo python3 -c 'import glob, os; [os.rename(f, f + ".locked") for f in glob.glob("/srv/nn-demo-rename/*.txt")]'
```

Expected: `NN-L-IMP-002_RenameExtensionBurst` (High). Run the rename as
written: other ways of renaming the same files may be judged by other
rules, or not at all
([KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md#detection-coverage)).

Clean up: `sudo rm -rf /srv/nn-demo-rename`

### 3.9 The agent refuses to be stopped

This shows that self-protection stays on under `alpha`:

```sh
sudo kill -TERM "$(sudo cat /run/northnarrow/agent.pid)"
systemctl is-active northnarrow-agent
```

Expected: the `kill` fails with `Operation not permitted`, the agent stays
`active` with the same pid, and the agent records
`NN-L-AT-001_AntiTamperDenial` (High) with `"operation": "signal"`. List it
with `--sensor anti-tamper` instead of the `jq` line if you prefer.
Nothing to clean up.

## 4. Reading `nn-admin status` and the records

### 4.1 `nn-admin status`

Without a key, the agent shows the posture only:

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

- **posture**: where the agent stands, and `OBSERVE-ONLY — profile alpha`.
- **sensors**: `OK`, or `DEGRADED` with the number of degradations and of
  lost events, for example
  `DEGRADED — 1 degradation(s), listed below, 3 event(s) lost since the start`.
  Each degradation is listed below the summary and signed in the audit
  log ([BOOT_INTEGRITY.md](BOOT_INTEGRITY.md) §4).
- **records today**: the records of the current UTC day, by severity.
- **would have**: the responses `alpha` held back, by action.

Further down, among other lines:

- **trust level**: how much of the agent's protection is measured
  ([BOOT_INTEGRITY.md](BOOT_INTEGRITY.md) §5). Under `alpha` expect **L2**
  (for example `L2 (enforcing and verified, degraded)`): L3 needs
  responses that run. **L1** (a deny hook missing, or the self-test
  inconclusive) or **L0** (no enforcement) is worth a report.
- **degradations**: each one of this run, for example
  `- bpf_lsm: anti-tamper: no enforcement`.
- **deny fail-open**: should stay at 0. Another value names a kernel hook
  that let an operation through undecided: report it.
- **ringbuf drops**, **loss by stage**: events lost under load.

If the agent does not run, `nn-admin status` exits 5 with
`status: connecting to /run/northnarrow/admin.sock: No such file or directory (os error 2)`.
Without sudo the same command exits 17 (`Permission denied`: run it with
`sudo`; the agent may be running). If it was run with sudo, look at `systemctl status northnarrow-agent northnarrow-watchdog`
and the agent's journal (below). The commands and their exit codes are in
[NN_ADMIN.md](NN_ADMIN.md).

**Postures.** OBSERVING, then ALERTED, ENGAGED and COMBAT as evidence
adds up ([COMBAT_RECOVERY.md](COMBAT_RECOVERY.md)). Without new signals
they go back down: ALERTED after an hour, ENGAGED after a day, an
unlocked COMBAT 30 minutes after its last signal. A **locked** COMBAT
(reached on kernel-proven evidence, for example) has no automatic exit:
`sudo nn-admin unlock --key "$KEY"` releases it
([COMBAT_RECOVERY.md](COMBAT_RECOVERY.md) §3). Under `alpha`, COMBAT is
entered and recorded but never isolates the host.

### 4.2 The records

```sh
sudo nn-admin detections --key "$KEY"                        # the last 50, newest first
sudo nn-admin detections --key "$KEY" --min-severity high --limit 20
sudo nn-admin detections --key "$KEY" --path /tmp/           # by executable, file or process name
```

The records come as JSON lines on stdout, a summary on stderr. Other
filters: `--since` and `--until` (UNIX seconds), `--sensor` (`exec`,
`file`, `module-load`, `network`, `anti-tamper`, `canary`). Rows whose
signature does not verify are left out, and the agent logs an ERROR.

The fields you need first:

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
| `matches` | every rule that matched, when there was more than one |

On disk the records are in
`/var/lib/northnarrow/detections/detections.jsonl` (and its rotated
archives). Each line is part of a signed hash chain: do not edit it, read
it through `nn-admin`. To check every chain:

```sh
sudo nn-admin chain verify          # OK or BROKEN per chain; exit 8 on any problem
sudo nn-admin audit verify          # the signed audit log, /etc/northnarrow/audit.log
sudo nn-admin audit read | grep integrity_drift
journalctl --namespace=northnarrow -u northnarrow-agent
```

[EVIDENCE_CHAINS.md](EVIDENCE_CHAINS.md) says what a failed check means.

**On a quiet host** you will still see a few Low records: one
`NN-L-BPF-002` at each start of the agent or the watchdog, the BPF
cross-view's records at boot for systemd's own programs, logrotate's
daily run, and on cloud images cloud-init's netcat at each boot. The
false positives we know of are in
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md#false-positives-you-may-see).

## 5. Uninstalling

From the extracted release tree
([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §3):

```sh
sudo ./deploy/uninstall.sh --purge --grant-key /root/northnarrow-admin.key
```

`--purge` removes the keys, the state and the records too; without it they
stay for a later reinstall. `--yes` skips the confirmation. Exit codes:

- **0**: removed, clean;
- **3**: the agent did not answer, the removal finishes at the next boot:
  `sudo systemctl reboot`;
- **4**: removed, but processes the agent had contained were found. They
  were thawed and listed by pid and command: look at each one, and keep or
  kill it. Under `alpha` this is rare.

For the `.deb`
([INSTALL_UPGRADE_UNINSTALL.md](INSTALL_UPGRADE_UNINSTALL.md) §6):

```sh
sudo NN_GRANT_KEY=/root/northnarrow-admin.key dpkg -P northnarrow
```

Until the next reboot, two kernel modules the agent caused to load stay
loaded (`nf_tables`, and `unix_diag` on Ubuntu 26.04). That is harmless.
On a throwaway VM, reverting to your snapshot is the simplest uninstall.

## 6. Reporting a problem

**A security vulnerability: report it privately.** Do not open a public
issue. Use GitHub's private vulnerability reporting: **Security → Report a
vulnerability** on https://github.com/northnarrow/northnarrow-new, or
directly https://github.com/northnarrow/northnarrow-new/security/advisories/new
(a GitHub account is needed). Include the component (agent, eBPF
programs, watchdog, `nn-admin`), the kernel version, a minimal
reproduction and the impact you observed. You get an acknowledgement
within 5 working days. The full policy, with the disclosure rules, is the
project's
[security policy](https://github.com/northnarrow/northnarrow-new/blob/main/SECURITY.md).
What counts: for example, a way to stop, blind or bypass the agent's self-protection
without a record, a way to make it sign something false, or a crash from
an unprivileged user's input.

**Anything else: open a GitHub issue** on
https://github.com/northnarrow/northnarrow-new/issues, after a look at
[KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md). A false positive, a rule
that did not fire in one of the scenarios above, an install or uninstall
that failed, a confusing message: all welcome. Attach:

- the release (`nn-admin --version`), and whether you installed from the
  tarball or the `.deb`;
- the distribution and kernel: `cat /etc/os-release` and `uname -r`;
- the output of `sudo nn-admin status --key "$KEY"`;
- the record lines (`nn-admin detections` with `--since` or `--path` to
  keep them few) and the journal lines around them;
- what you did, what you expected and what happened.

**Before you post, remove what you do not want public.** Status output,
records and journal lines contain host names, user names, paths, command
lines and IP addresses. Replace them consistently (`host1`, `user1`,
`10.0.0.x`). Never attach the admin key, any file from `/etc/northnarrow`,
or a real credential.
