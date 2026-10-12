# Tappa 10.9 — Workload context (cgroup, namespaces, container, unit) Design

**Status:** Accepted on 2026-10-12. The owner delegated the decisions; they
are recorded in §8. Implementation follows §7, one PR per step.
**Author:** Claude Code (architecture), 2026-10-12.
**Scope:** the second item of Tappa 10.9 ("Contesto del carico di lavoro"):
the cgroup, namespaces and, where present, container, pod and systemd unit
of the process behind every event, and allowlists and rules keyed on that
identity as well as on path. Kubernetes workload identity (SPIFFE, service
account tokens) is a later 10.9 item and is out of scope, except where this
prepares it (§6).

---

## 1. Purpose

Every rule and allowlist keys on `comm` or on a path. Three costs follow.

1. **Exemptions are host-wide.** A container runtime needs `runc`, so an
   operator adds `+runc` to `process-comm-allowlist`. That disables R013
   (namespace-escape tooling) for every process named `runc` on the host,
   wherever it runs from. The shipped example says so
   (`configs/process-comm-allowlist.local.example`). The same holds for
   every `comm` exemption of R011–R017, the io_uring and BPF rules, and the
   eight `netflow-comm-allowlist` rules.
2. **A detection does not say where it happened.** The detection record's
   principal is pid, comm, uid and ppid. An analyst cannot tell whether
   R001 fired in a container, in a pod, in a systemd service or in an SSH
   session, nor which one.
3. **The 10.9 demo cannot be shown.** "The same attack from a container …
   produces the same detection chain" needs the chain to name the
   container. Today the agent does not know containers exist.

The proposal reads the process's cgroup in the kernel, one helper call per
record, and resolves the rest in userland once per cgroup.

## 2. Constraints that shape the design

- **Kernels:** 5.14 (RHEL 9), 5.15, 6.1, 6.8, with the 5.15 verifier rules
  (KERNEL_COMPATIBILITY) and no CO-RE: every struct read needs a
  `BTF_OFFSETS` slot.
- **cgroup v2.** Every lab distro mounts the unified hierarchy by default
  (Ubuntu 22.04 and 24.04, Debian 12, RHEL 9). A host still on cgroup v1 is
  a decision (Q4).
- **The event shape is a contract** (sensor RFC §2): new fields are
  appended with `#[serde(default)]`. The detection record and its principal
  are schema-frozen (`detection_store.rs`): a new field is an `Option` that
  is skipped when empty.
- **The response layer moves processes between cgroups.**
  `block_outbound` and `throttle` put a contained pid into
  `northnarrow.slice/{blocked,throttled}.scope`. From then on its cgroup is
  the agent's, not its workload's.
- **The agent has its own mount namespace** (`ProtectSystem=strict`). The
  host's namespaces are read from `/proc/1/ns/*`, not `/proc/self/ns/*`.
  `CAP_SYS_PTRACE`, which the unit already has, lets it read any
  `/proc/<pid>/ns/*` and `/proc/<pid>/cgroup`.
- **Cost.** Every record grows, and every event gets one more userland
  lookup, which must be a cached O(1).

## 3. What exists today (code survey, 2026-10-12)

- **Kernel side:** no program reads a cgroup or a namespace.
  `bpf_get_current_cgroup_id` is in the aya bindings and unused. The exec
  sensor reads `task->fs->root`, to cut paths at a chroot or container
  root (`TASK_ROOT`). The open sensor carves cgroupfs out of its write
  counting.
- **Userland:** the only cgroup read is the agent's own
  (`self_integrity.rs`, `/proc/self/cgroup`). No code parses
  `/proc/<pid>/cgroup` or `/proc/<pid>/ns`, extracts a container id, or
  talks to a container runtime.
- **Identity used today:** loginuid. The posture's corroboration ledger
  and the auth-lineage tracker scope by it (`lineage.rs`,
  `corroboration.rs`). That tracker is also the pattern for a bounded
  per-key cache with a `/proc` fallback.
- **Allowlists:** seven signed overlay kinds (`OverlayKind`). The comm
  lists are exact-match sets of `comm`; `escalation-allow` adds a CIDR and
  a port; the FIM and mass-write lists match paths. None keys on uid, exe,
  unit or cgroup.
- **Every event passes through `process_event`** (`main.rs`). Its first
  step resolves the exec identity (`exe_identity::resolve`, Tappa 10.9
  step 2): the place for a workload lookup.
- **Containers in tests:** none. No lab script or test runs docker,
  podman, `unshare` or `systemd-nspawn`; R013 is tested with synthetic
  events only.

## 4. Proposal

### 4.1 Kernel: the cgroup id in every record

`bpf_get_current_cgroup_id()` returns the id of the current task's cgroup
in the v2 hierarchy. On 64-bit kernels this is also the inode number of
that cgroup's directory under `/sys/fs/cgroup`. It is one helper call, needs no
offset, and is available to every program type the agent uses
(tracepoint, kprobe, fexit, LSM).

Each raw record gains `cgroup_id: u64`, appended:

- `ProcessSpawnRaw`, `ExecCheckRaw`;
- the open-sensor records;
- `DnsQueryRaw`, `TcpConnectRaw`, `NetFlowCloseRaw`, `NetListenRaw`;
- `ModuleLoadRaw`, `IoUringRaw`, `BpfSyscallRaw`;
- `FsProtectDenialRaw`, `FimDriftRaw`.

Events built in userland (FIM, canary, net flows) take the id of the
record they come from.

Namespaces are not read in the kernel in the first step (§4.2, Q3).

### 4.2 Userland: one workload cache, keyed by cgroup id

A `WorkloadCache` maps a cgroup id to a `WorkloadIdentity`:

- the cgroup path;
- a kind: host service, user session, container, pod, other;
- the systemd unit, if any;
- the container id and runtime, if any; the pod uid, if any;
- the pid, mount and network namespaces, and whether each is the host's.

**Resolution happens once per new id.** The cache reads
`/proc/<pid>/cgroup` of the event's process (`0::<path>`). It checks that
`stat("/sys/fs/cgroup<path>")` gives the same inode as the id, and walks
the hierarchy only if it does not (the process may have moved). It reads
the namespaces from `/proc/<pid>/ns/{pid,mnt,net}` and compares them with
`/proc/1/ns/*`. Then it parses the path:

| cgroup path | identity |
|---|---|
| `/system.slice/<name>.service` | host service, unit `<name>.service` |
| `/user.slice/user-<uid>.slice/session-<n>.scope` | user session |
| `…/docker-<id>.scope`, `/docker/<id>` | Docker container `<id>` |
| `…/cri-containerd-<id>.scope`, `…/crio-<id>.scope` | CRI container `<id>` |
| `…/kubepods…/pod<uid>/…` | pod `<uid>` |
| `…/libpod-<id>.scope` | Podman container `<id>` |
| `/northnarrow.slice/{blocked,throttled}.scope` | contained by the agent: keep the identity the pid had before |

The cache is a bounded LRU (4,096 cgroups). Per event it costs one hash
lookup. A short-lived process that exits before its first event is
resolved leaves its id with the path unknown, but the id is still recorded.

**Events and detections:**

- Each `Event` variant gains `cgroup_id` (serde default).
- The detection principal gains `workload: Option<…>`: kind, unit,
  container id, pod uid and cgroup path.
- The ADE prompt gains one line with the workload.

### 4.3 Identity in rules and allowlists

There is a new signed overlay kind, `identity-allowlist`. Its lines scope
an exemption to a rule (or a family) and a workload:

```
+R013 unit=containerd.service        # replaces "+runc" host-wide
+R013 unit=docker.service
+NN-L-IOU-001 cgroup=/system.slice/postgresql.service
+R017 uid=1001 exe=/opt/ci/bin/sh
```

Keys: `unit=`, `cgroup=` (a path prefix), `uid=`, `exe=` (the canonical
path from step 2 of the sensor RFC) and, with Q1, `image=`. The comm lists
stay for compatibility; an operator migrates entries one at a time.

Rules and posture use the identity in two places:

- R013 exempts `runc`, `nsenter` and `unshare` only inside the runtime's
  unit or cgroup.
- The posture's corroboration ledger scopes by workload as well as by
  loginuid: two weak signals from two containers of the same user no
  longer corroborate each other.

### 4.4 Container metadata (image, names)

The cgroup path gives the container id and the pod uid, not the image or
the names. Those need the runtime's API:

- containerd / CRI: `/run/containerd/containerd.sock`;
- Docker: `/var/run/docker.sock`;
- Podman: `/run/podman/podman.sock`.

It would be one read-only lookup per new container, cached. It is off by
default and is Q1: a root agent that talks to a root socket widens its own
surface.

## 5. Facts noted while writing this

- `+runc` in `process-comm-allowlist` disables R013 on the whole host
  (§1). The shipped example warns about it but offers no alternative.
- `NetFlow` and `NetListener` events never carry `exe`. `CanaryTripped`
  never does either.
- No lab test runs a container, so container behaviour is untested today,
  including the exec sensor's `TASK_ROOT` cut.

## 6. What this prepares

- Container-escape detections: a process in a container's cgroup with a
  host namespace, or reaching host paths through `/proc/1/root`.
- Per-workload baselines for ADE and the posture.
- Kubernetes workload identity (10.9, then Tappe 13–14): a pod uid is
  already the key.
- The 10.9 demo, with a container leg.

## 7. Plan and gates

**Step 0 — feasibility on the four lab kernels.** One throw-away probe
per program type, plus a runner. It must show that:

- the cgroup id is readable from tracepoint, kprobe, fexit and LSM
  programs;
- the id equals the cgroup directory's inode;
- `/proc/<pid>/cgroup` parses for a systemd service, an SSH session, a
  rootful and a rootless Podman container, and a Docker container where
  the distro ships one.

This needs Podman installed on the lab guests (Q6).

**Then one PR per step:**

1. the id in every record, the cache, the principal's `workload` and the
   ADE line (observe only);
2. `identity-allowlist`, R013's scoping and the posture's;
3. with Q1, the runtime metadata.

**Gates for every PR:** the usual ones (`tamper-check`, `pkgmgr-check`,
`pkg-check`, `release-check`, the e2e suites, the telemetry probe), plus:

| Gate | Target |
|---|---|
| `nn-lab.sh workload-check`: the R001, R004 and NET-004 cases of the sensor checks run in a Podman container | each detection names the container; the same cases on the host name their unit or session |
| `+R013 unit=…` | `runc` exempt only inside that unit |
| a process contained by `block_outbound` | its next detections keep the identity it had before |
| cost (`bpf_stats` and `nn-lab.sh overhead`) | one helper call per record; no measurable change in the workloads |

## 8. Decisions

Accepted on 2026-10-12, as proposed. The owner delegated the choice
("hai libertà di prendere decisioni"); the reasons are below each question.

- **Q1 — Container runtime APIs.** None (proposed: the id and the pod uid
  come from the cgroup path), or read-only lookups of image and names over
  the runtime sockets, off by default.
  **Decision: none for now.** The cgroup path gives the container id and the
  pod uid without the agent talking to a root socket. Image and names stay
  a later, opt-in step 3.
- **Q2 — Allowlist format.** A new `identity-allowlist` kind (proposed),
  or a scope suffix on the existing comm lists (`+runc @unit=…`).
  **Decision: the new kind.** It keeps the comm lists' meaning unchanged
  while operators migrate, and it is the place for `exe=` keys, which also
  replace the forgeable comm exemptions of NN-L-FIM-011..017.
- **Q3 — Namespaces.** Read in userland once per cgroup (proposed), or
  also in the kernel at exec, for processes that exit before their first
  event is resolved. The kernel option needs four new offsets: `nsproxy`
  and the inode of three namespaces.
  **Decision: userland, once per cgroup.** Revisit if step 1 shows many
  identities left unresolved by short-lived processes.
- **Q4 — cgroup v1 hosts.** Unsupported (proposed): the identity is
  "unknown" and rules fall back to comm and path. The alternative is
  parsing v1 controller paths.
  **Decision: unsupported.** Every supported distribution runs the unified
  hierarchy by default.
- **Q5 — Where the id lives in events.** On every variant (proposed), or
  on the process events only, with a lookup by pid for the others; that
  lookup races with process exit.
  **Decision: on every variant.** No race with process exit.
- **Q6 — Lab.** Install Podman on the four guests (proposed); Docker
  where the distro packages it.
  **Decision: Podman on the four guests**, Docker where packaged.
