# The event bus

*Wave 4 restructure, R12a (lab PR 267). Plan: `w4-restructure-plan` §3.4
and the R12 line. Code: `crates/nn-core/src/bus.rs` (the portable half:
classes, queues, take order) and `crates/nn-linux/src/sensors/bus.rs` (the
runtime: senders, waits, receiver, loss recorder).*

## 1. Why

Until R12a every source of events — a pump per eBPF ring, the FIM and
network drains, the file-open sensor, the exploit guard — sent into one
`tokio::mpsc` channel of 4,096 events, which the event loop read one event
at a time. A flood of one class held every other class back: while the
channel was full every pump waited on its send, its ring filled, and the
kernel dropped the next records of every ring. A flood of file opens made
the `fs_protect` denials late or lost (plan §1.5; the lab's EXP-13).

R12a gives each class of events a queue of its own. The event loop takes
from them by priority; a flood of opens fills the file queue, which drops
its new opens, and the tamper queue is taken first, its pump never waiting
behind the opens. The decision itself is unchanged: the one event loop
still judges every event through `process_event`; the decision thread
without `await` is R12b, the response dispatcher R12c (§7).

## 2. The classes

Every `Event` variant has its class, by an exhaustive match
(`nn_core::bus::class_of`: a new variant does not compile until it is
placed). Each class has its queue (`Priority::of`):

| Queue | Class | Events | Capacity | Full queue |
|---|---|---|---|---|
| P0 | tamper (and the sensors' health) | `FsProtectDenial`, `BpfSyscall`, `ModuleLoad`, `SensorFlood`, `DefenderSignal`, `ExploitPostcondition` | 1,024 | the sender waits for room 50 ms (the kernel ring absorbs), then the event is dropped, counted, signed |
| P1 | process | `ProcessSpawn`, `ExecCheck`, `IoUring` | 4,096 | waits 10 ms, then dropped and counted |
| P2 | file | `Fim`, `MassWrite`, `FileOpen`, `FileBurst` | 8,192 | a new `FileOpen` is dropped and counted; every other file event waits for room |
| P3 | network | `TcpConnect`, `DnsQuery`, `DnsFlood`, `NetFlow`, `NetListener` | 8,192 | the new event is dropped and counted |

The plan's table placed fifteen variants. The others: `DefenderSignal`
(lab PR 225, a stop signal to another security tool) and
`ExploitPostcondition` (lab PR 219, privilege gained with no mechanism for
it) are attempts on the host's defences, rare by nature and bounded in the
kernel — P0; `FileBurst` (lab PR 225, a rename or unlink burst) is a file
event — P2; `CanaryTripped` never travels the bus (the canary detector
makes it inside the event loop from the source event it replaces) and has
that event's class, by its `access_kind`. No event is of the health class
yet; its queue is P0's.

P2's exception keeps review 75: the FIM drain waited for room on the one
channel because a full channel had dropped its drift events — an
unprivileged loop of reads kept the FIM kill rules from seeing a
persistence write. On P2 the flood is `FileOpen`; a drift, a credential
read, a mass write or a rename burst waits for room, ahead of the opens
that come after it (the wait is fair: a semaphore per queue serves the
waiting sender first). The DNS pump's outbox (lab PR 229), which held its
events while the one channel was full, is gone: a network event never
waits.

## 3. The take order

Strict priority with aging: the next event is the head of the highest
queue that holds one, except that after 64 such takes in a row that passed
over a waiting lower queue the next is the head that was queued first
(`ClassQueues::take`; the higher queue on a tie). FIFO inside a queue. So a
lower class is never starved, and an event is never taken before an event
of a higher (or its own) class that reached the bus before it: only a
higher class overtakes — P0 the others, P1 the file and network events, P2
the network events.

**What the overtaking event is judged on.** The process lineage (the
posture's `AuthSessionTracker`) and the chains' ancestry tree learned an
exec only when the exec itself was judged. A tamper event that overtakes the
exec of its process — or of the process it signals — would be judged
without it. When the receiver takes a P0 event it hands over the
`ProcessSpawn`s still queued in P1 that reached the bus before it, each
once (`Received::overtaken`, `ClassQueues::hand_over_older`): the receiver
makes their paths absolute and the lineage ingests them, the event loop
teaches the engine's rules (`RuleEngine::observe_arrival`: CHAIN-002 records
the exec's edge), and the event is judged on the process tree of every exec
that arrived before it, as on a single queue. The execs are judged in their
own turn; a second ingest of an exec, or one older than the exec the cache
holds for the pid, changes nothing (`ingest_inner`; one ring delivers a
pid's execs in order).

## 4. Ordering safety: the property test

`agent/src/decision/golden.rs`,
`golden_verdicts_survive_every_per_class_fifo_interleaving`: every order of
a golden case's events (`agent/tests/golden/cases/`) that keeps each
class's own order gives the same verdicts as the stream's order. Checked:
every such order for the cases that have at most 2,000 of them (21 of the
24); for the others every class-major order (each class whole, the classes
in every order), the bus's own take order with the consumer 1 to all events
behind, and 256 random merges — 952 orders. The stream's order is the
arrival order: an event is judged on the lineage of every exec that arrived
before it, as the bus gives it (§3).

What is compared: for each rule and process the rule judged, the strongest
verdict it gave the process (action, severity, policy mode, held or exempt,
ATT&CK), and the responses run on each process (a tree kill includes the
process's). Not compared: which event's decision line carried a verdict
and what it was combined with (one line per event: a correlation completed
late is combined with the matches of the event that completed it), the
text and time of a line (a chain completed late says it was processed out
of order, by design: review 70, lab PRs 235 and 244), how often a rule
judged a process (in order a chain answers each flow; a precursor processed
late completes it once).

What it found, fixed in the stores (not by narrowing the test):

- the lineage and the ancestry tree learned execs only when judged (§3):
  NN-L-EVA-003 lost its target, NN-L-NET-026/027 the children's parent,
  NN-L-IMP-001 its actor — fixed by the hand-over;
- the chain store let the first two-step chain to answer a flow keep the
  other from a late completion, and CHAIN-007 took the egress from both: a
  flow whose staging exec came last lost the CHAIN-002 it has in order.
  Each chain now answers a noted egress once, in order or late, and none
  keeps another from it (`Answered`); a late exec's CHAIN-002 prefers the
  first egress whose kill is not held (port 53 of another server) over the
  earliest. The golden case `shadow-chain007-late-exec` gains CHAIN-002 on
  its late exec's line, as the flow has it in kernel order.

## 5. Losses

Per queue (`BusStats`): events queued, dropped, the depth and the most it
held, the longest wait, the sends that waited for room, the takes by aging,
the decisions timed and their latency from queue to decision (p50, p99,
max; a log-linear histogram, within 12.5 %).

A drop is never silent. The loss recorder (a telemetry task of the
multiplexer: if it ends the agent stops, as for a dead pump) samples every
10 s: a WARN for each queue that dropped; a signed `event_bus_drop` row —
P0 at the first sample after the drop (one row a sample at most), the other
queues at most once per 600 s — each row carrying every drop of its queue
since the previous row (`dropped_since_last_row`, `total`), the rows not yet
written signed at the stop; and, past the security rings' threshold (64 in
a sample), the posture's `TelemetryLoss` for P0, P1 and P2, with the same
exemptions (a trusted-installer window, a package transaction): those
queues carry what the exec, file-open, FIM and tamper rings carried, whose
kernel drops raised it before R12a. P3's network rings were never security
rings.

`nn-admin status --key` shows the queues and the loss counters of every
stage of an event's path (plan §3.4):

| Stage | Counted by | Since |
|---|---|---|
| 1 kernel ring | `RING_DROPS`, a ring or map full | Tappa 10.8 |
| 2 kernel budget | `RING_DROPS` `dns_rate`, `listen_rate`, `io_uring_rate`, `task_denial_rate` | reviews 78, EBPF-013/017 |
| 3 decode | `RejectThrottle` | SNS-008 |
| 4 bus queue | the bus, per queue | R12a |
| 5 decision delay | — | R12b |
| 6 response queue | — | R12c |
| 7 evidence writer queue | — | R12c |
| 8 export | — | R12c (signed `telemetry_loss` rows), R15 |

## 6. What it costs

Four queues of up to 21,504 events (the one channel held 4,096), whose
memory is given back when a queue above 1,024 runs empty; one lock per send
and per take; the hand-over scans P1 only when a P0 event is taken, each
queued event once. The lab's numbers (overhead, latency per class, the
soak) are in the lot's note of `docs/roadmap/CAPABILITY_PROGRAM.md`.

## 7. What is next

- **R12b** — the decision thread without `await`: `exe_identity::resolve`
  in the pumps (the bus's receiver does it for the execs it hands over),
  the systemd state as a snapshot, `close_if_expired` on a tick, the canary
  append through the writer's queue, a cache of `PackageOwnership` for
  module provenance; the decision delay per class (stage 5) against a
  budget; the envelope (`nn_core::bus::Envelope`: source, sequence, time,
  `ProcessKey`).
- **R12c** — the response dispatcher by severity, its queue (stage 6);
  no action without a signed record (intent, then outcome); the budget
  never limits an action's record; the evidence writer's queue (stage 7);
  signed `telemetry_loss` rows aggregating every stage, then the heartbeat
  (INI-14).
