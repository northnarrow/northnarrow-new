# The benign corpus (lot 283a)

Four reproducible benign workloads, run on a lab guest with the agent
installed in its default mode, to count what the agent kills, records and
escalates on hosts doing ordinary work: a developer's workstation, a CI
runner, a container host, a database server. The scripts are in
[`deploy/lab/corpus/`](../../deploy/lab/corpus/); they measure, they change
no rule and no policy.

## Running it

On the dev box, with a guest up, synced and installed (`nn-lab.sh sync`,
`nn-lab.sh install`, then `systemctl enable --now` of both units as an
operator does):

```sh
deploy/lab/nn-lab.sh corpus dev          # or ci, containers, db
NN_LAB_DISTRO=ubuntu2204 deploy/lab/nn-lab.sh corpus dev
```

On the guest itself, as the lab user (not root): `bash
deploy/lab/corpus/<script>.sh`. Each script refuses to run anywhere but on a
lab guest (cloud-init's `/var/lib/nn-lab-provisioned`) or on a host declared
disposable with `NN_TEST_DISPOSABLE_HOST=1`: it installs and purges
packages, services and containers.

| Corpus | Script | Context |
|---|---|---|
| `dev` | `dev-workstation.sh` | the lab user (uid 1000) in its ssh session — an authenticated session; sudo for packages only |
| `ci` | `ci-runner.sh` | transient systemd units, as the lab user and as root: no login session, no loginuid |
| `containers` | `container-host.sh` | rootless podman in the session; docker and k3s as root through sudo |
| `db` | `db-server.sh` | root through sudo, `postgres` for the database tools |

Options: `NN_CORPUS_SMALLFILE=0` runs the workstation without the small-file
probe; `NN_CORPUS_KEEP=<dir>` keeps the raw records (the chain slices, the
steps file, the probe's output) instead of removing them.

## What a run does

1. **Puts back what a run before it left** (a run killed half-way records
   the packages it installed in `/var/tmp/nn-corpus-<name>.installed`; the
   next run purges them first). A script can be run any number of times.
2. **Prepares, unmeasured**: the tools from the distribution's mirror, and
   the trees the steps work on (a crate in a local git repository, a Go
   module, an npm project with 300 small unformatted sources, two branches
   of a 3,000-file tree, a tree of 1,000 small files, an AppImage-style
   squashfs image).
3. **Settles the agent**: a restart inside a signed trusted-installer
   window, then 75 s — the posture starts from OBSERVING and nothing the
   preparation raised is counted.
4. **Runs the steps** in order, each timed, its rc and the posture after it
   recorded. One settle per corpus: the steps follow one another as on a
   real host, and what one step raises the next meets.
5. **Removes everything** it installed or wrote — as a measured step of its
   own (`cleanup`): packages it installed (purged with their automatic
   dependencies), images, k3s, the PostgreSQL clusters, the cron entries,
   `/srv/nn-corpus`. Every cache (cargo, Go, npm, pip) lives under
   `/srv/nn-corpus/<name>` for the run.
6. **Reports** ([`corpus-report.py`](../../deploy/lab/corpus/corpus-report.py)),
   from the signed chains written after the settle: every kill (the actions
   chain's intent and outcome, with the process and the posture of the
   verdict that asked for it), every verdict (rule, severity, response,
   `posture_at`, processes) and every COMBAT stage of the audit log, each
   attributed to the step it happened in. Lines starting with `TSV` carry
   the same facts for a table.

Network: the distribution's mirror, crates.io, the npm registry, PyPI,
Docker Hub, the Go toolchain's defaults (the module has no dependency), and
`get.k3s.io` for the container host. No secret is read or written.

## The steps

**dev** — `git clone` of the crate from its local repository, `cargo build`
and `cargo test` (three registry dependencies, pinned); `cargo fmt` over 120
small unformatted modules; `go test ./...`, `go run .` and `go build` (the
test binary and `go run`'s program run from `/tmp/go-build…`); `npm install`
(writes the lockfile), `npm ci`, `npm run build` (tsc), `prettier --write`
over the 300 sources; lot 346: the same project installed by `yarnpkg`
(the distribution's yarn 1), pnpm 9 and bun 1.1 (`npm i -g`, under
`/usr/local`; Node 18 or later), each once and once more with `--force`,
their caches at their default places in a home under the corpus' tree
(`$W/lab-home`), npm's cache at `$W/lab-home/.npm`; `python3 -m venv` and `pip install` of two packages;
`git checkout` between the two branches (2,400 of the 3,000 files differ)
and back; `rsync -a --inplace` of 1,000 changed small files onto their
copies; the AppImage: its squashfs image mounted by `squashfuse` on
`/tmp/.mount_nncorpus…` and `AppRun` run from the mount (what the AppImage
runtime does), then the image unpacked under `/tmp/appimage_extracted_…`
and run from there (`--appimage-extract-and-run`); the control (lot 283b):
one program copied to `/tmp` run for a few seconds by the lab user, then by
`www-data` — a person's exec is recorded, a system account's killed (rc
137). Versions pinned so the
same corpus runs on Node 12 and Go 1.18 (Ubuntu 22.04) and on 24.04.

**ci** — the same builds and tests (crate, Go, npm, pip) in session-less
units, then `docker build` of a small Dockerfile (alpine, `COPY`, `RUN`), a
`docker run` of the image and its removal, as root in units too.

**containers** — rootless podman pull, run and rmi of alpine; docker pull,
run and rmi; k3s from its vendor's install script as an operator runs it
(it writes and enables `k3s.service` and starts it), the node Ready, one pod
run to completion, `kubectl get pods -A`, the pod deleted,
`k3s-uninstall.sh`.

**db** — `apt-get install postgresql` (the package creates and starts its
cluster), `pg_createcluster` of a second cluster (initdb) on port 5444,
`createdb`, `pgbench -i -s 20` and a 60 s run with 4 clients, `pg_dump -Fc`,
`pg_restore` into a new database, `vacuumdb --analyze`; then the host's own
upkeep: `apt-get install --reinstall initramfs-tools` (a dpkg trigger's
`update-initramfs`, whose hooks run from forks of `mkinitramfs`),
`apt-get install --only-upgrade` of at most 15 upgradable packages
outside the kernel, boot, libc, systemd and ssh set (the guests are shared:
their kernel stays the one the lab measures; what was upgraded stays
upgraded), `unattended-upgrade --dry-run`, `systemctl start
logrotate.service`, and a cron job — a `crontab -u postgres` entry and an
`/etc/cron.d` drop-in written with `install -m 644` — seen running once.

## The small-file probe

The workstation corpus runs [`smallfile.bt`](../../deploy/lab/corpus/smallfile.bt)
(bpftrace, a kprobe on `security_file_open`, in its own unit) while its
steps run: every write-open of a regular file that existed before the open
(no `FMODE_CREATED`) and held under 4 KiB when opened — the files a rewrite
in place of small documents touches, the shape the agent's
`MASS_OVERWRITE_SMALL` counts. For each step the report gives the most
distinct such files one process opened in any 60 s (non-empty files; in
brackets, empty ones counted too), its top three processes, and marks a
step at or above the candidate threshold of 50. It is data for the
in-session small-file threshold (lot 282's backlog), not a verdict.
bpftrace is known BPF tooling to the agent (NN-L-BPF-001's exemption); its
kprobe adds the cost of one probe per open while it runs. Since lot 290 the
agent refuses bpftrace's `kprobe` and `perf_event` loads outside a
trusted-installer window in every mode: the probe is loaded inside a signed
window of its own (`smallfile_start`, 150 s) before the settle, whose
restart of the agent closes the window 75 s before the first step — no
window is open while the steps run, and neither the agent's code nor the
policy carries an exception for it. Its programs stay attached after the
window; the restarted agent's cross-view records them at its start
(`bpf_baseline`, before the corpus's mark: not counted).

## Reading a report

```
== report dev: 31 steps, … verdicts, … action intents, … COMBAT stages
  kills (actions chain: intent → outcome; the process and posture from its verdict):
    [dev go test ./...] R001_ExecFromTmp KillProcessTree pid … calc.test (/tmp/go-build…/calc.test) posture=Observing → Killed { pid: … }
  COMBAT stages (audit log):
  verdicts by step (rule, severity, response, posture at the verdict, count, processes):
  steps (rc, posture after):
  small-file probe: …
```

A record is attributed to the last step begun before it; one more than 10 s
after that step's end is marked `(after)`. A step killed by the agent shows
its rc (137 for SIGKILL) and the tail of its output.

## Measurements

**Lot 283a (2026-11-05), main fc438889**, default mode; ubuntu2404 (6.8) all
four corpora, ubuntu2204 (5.15) `dev` and `ci`. No COMBAT stage and no
NEUTRALIZE in any run; every kill was of a benign workload.

| Corpus | Kill intents | Rules | Outcome |
|---|---|---|---|
| dev 24.04 / 22.04 | 6 / 4 | R001 (go test binaries, `go run`, AppImage `AppRun` from `/tmp/.mount_*` and `/tmp/appimage_extracted_*`) | 24.04 AlreadyGone; 22.04 Killed (the AppImage steps exit 137) |
| ci 24.04 / 22.04 | 2 / 2 | R001 (go test, `go run`) | AlreadyGone / Killed |
| containers 24.04 | 650 | R013 ×645 (k3s's bundled `runc`), FIM-009 ×5 (the k3s installer's `touch`, `tee`, `chmod`) | runc Killed every time: no pod started; FIM-009 AlreadyGone |
| db 24.04 | 4 | FIM-007 ×3 (`crontab -u postgres`, `install` into `/etc/cron.d`, `crontab -r`), R011 ×1 (the initramfs-tools hook `kmod` in an apt upgrade) | AlreadyGone |

Small-file probe (dev, 24.04): `cargo fmt` over 120 modules (122),
`prettier --write` over 300 files (300) and `rsync --inplace` over 1,000
files (1,000) reach their tree's size in one process; every other step stays
at 5 or below.

**Lot 283b (2026-11-06)**, the lot's agent, ubuntu2404, `dev`,
`containers`, `db`: dev — one kill, the control's `www-data` run (rc 137);
go test, `go run`, both AppImage runs and the lab user's control are R001
High records. containers — 0 kills, k3s's pod runs to completion in 32 s.
db — 0 kills, the dpkg trigger's initramfs hook recorded twice. The
anti-tamper refusals, resolved: only the agent's own four drop-in
directories (`deb-systemd-helper`'s `rmdir` during a purge).

**Lot 283c (2026-11-06)**, the lot's agent, ubuntu2404 (6.8), the agent's
journal read for every `ConfirmedIntrusion_MassWrite` raised and every
crossing left out as the writer's own data. Round 1 (e24430a4): db — 21
raises from PostgreSQL's processes, 6 left out: their windows held their
dynamic shared memory (`/dev/shm/PostgreSQL.*`, opened to write by the
backends: a probe with bpftrace); containers — no crossing from containerd
or k3s (the pod ran in 11 s, no retries); a subset of `dev` and `ci` — `go
test` raised on `/tmp/go-build…/_pkg_.a` (go's work directory: the corpus
puts `GOCACHE` under `/srv`), `rsync --inplace` and `npm ci` raised as
before. Round 2 (67105468, a service's own `/dev/shm` segment its own
data): db — 23 crossings of the service's PostgreSQL left out, 2 raises,
both in the `pg_createcluster` step run from the SSH session (`initdb` and
a `postgres` process of that step); a probe of 25 files of 8 KiB rewritten
in place: `etcd.service` in `/var/lib/etcd` left out, another unit there
raised; `www-data` in its own directory under `/var/lib` from a service
left out, the same through `sudo` in the session raised; the lab user in
its `~/.cache` left out, root there raised. MS-23: 19 of 19 PASS.
