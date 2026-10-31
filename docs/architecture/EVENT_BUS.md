# The event bus

*Wave 4 restructure, R12a (lab PR 267) and R12b (lab PR 269). Plan:
`w4-restructure-plan` §3.4 and the R12 line. Code: `crates/nn-core/src/bus.rs`
(the portable half: classes, queues, take order, the envelope, the
decision's budget, the per-uid cap) and `crates/nn-linux/src/sensors/bus.rs`
(the runtime: senders, batches, waits, receiver, loss recorder);
`crates/nn-linux/src/sensors/pump.rs` (the pumps' threads, R12b).*

## 1. Why

Until R12a every source of events — a pump per eBPF ring, the FIM and
network drains, the file-open sensor, the exploit guard — sent into one
`tokio::mpsc` channel of 4,096 events, which the event loop read one event
at a time. A flood of one class held every other class back: while the
channel was full every pump waited on its send, its ring filled, and the
kernel dropped the next records of every ring. A flood of file opens made
the `fs_protect` denials late or lost (plan §1.5; the lab's EXP-13).

R12b (lab PR 269) gives each ring's pump a thread of its own and makes it
send in batches (§2a): on R12a the pumps were tasks of the agent's async
runtime that sent one event at a time, and on a guest whose CPUs a flood
saturates a ring fell behind while no send had waited for room (EXP-13c,
EXP-13e).

R12a gives each class of events a queue of its own. The event loop takes
from them by priority; a flood of opens fills the file queue, which drops
its new opens, and the tamper queue is taken first, its pump never waiting
behind the opens. The decision itself is unchanged: the one event loop
still judges every event through `process_event`; the decision thread
without `await` is R12b's second part, the response dispatcher R12c (§7).

## 2. The classes

Every `Event` variant has its class, by an exhaustive match
(`nn_core::bus::class_of`: a new variant does not compile until it is
placed). Each class has its queue (`Priority::of`):

| Queue | Class | Events | Capacity | Full queue |
|---|---|---|---|---|
| P0 | tamper (and the sensors' health) | `FsProtectDenial`, `BpfSyscall`, `ModuleLoad`, `SensorFlood`, `DefenderSignal`, `ExploitPostcondition` | 1,024 | an `FsProtectDenial` repeated by its process on its inode within 1 s of the one queued is counted into it (signed `event_bus_coalesced`); a new one's sender waits for room 50 ms (the kernel ring absorbs), then the denial is dropped, counted, signed; every other tamper event waits for room; denials and `bpf()` calls take all but 64 slots, the rare tamper events' |
| P1 | process | `ProcessSpawn`, `ExecCheck`, `IoUring` | 4,096 | waits 10 ms, then dropped and counted |
| P2 | file | `Fim`, `MassWrite`, `FileOpen`, `FileBurst` | 8,192 | a new `FileOpen` is dropped and counted when the queue is full or holds 2,048 opens; a write-open of a CRITICAL or PERSIST file and every other file event wait for room |
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
waiting sender first). The opens fill at most a quarter of P2
(`FILE_OPEN_SHARE`, 2,048; review #471 B3; the opens counted, not the
queue — second review, R-E: 2,048 mass writes queued made the cap drop a
write-open of `/etc/cron.d/x`): a file event other than an open finds room
behind them at once, and waits behind at most 2,048 opens (≈ 0.6–1.2 s at
the shares a flood leaves P2), where the whole queue held it four times
longer. A write-open (`O_WRONLY`, `O_RDWR`) of a file the kernel classes
CRITICAL or PERSIST (`guarded_write_open`) is not one of those opens: only
who may write the file opens it so, and a flood of reads must not hide it —
it waits for room like the FIM records. The open-sensor pump checks the
cap before it decodes, resolves and allocates an open (an atomic hint,
`BusSender::open_room`; its drops are P2's), so a flood of opens the bus
drops costs the pump next to nothing. The DNS pump's outbox (lab PR 229), which held its
events while the one channel was full, is gone: a network event never
waits.

P0's exception (review #471 M1): root can fill P0 with refused operations
— the inode denials have no kernel budget — and while the event loop
stands still past 50 ms (a COMBAT response, a slow systemd answer) the
denials are dropped after their wait. A rare tamper event behind them (a
module load, a `bpf()` call, an exploit post-condition, a signal to a
security tool, a sensor flood) waits for room instead, as every source
waited before R12a, its own ring absorbing; it is judged late, never
dropped by the bus.

The tamper events a process can repeat at will (second review of #471,
R-A, R-D) — a refused operation (root; no kernel budget) and a `bpf()`
call (any user: on 6.x the LSM hook runs before the permission checks, one
record per new process and command a second) — are kept from filling P0
and from starving the rest:
- a denial repeated by its process on its inode within a second of the one
  queued is counted into it, not queued (`COALESCE_WINDOW_NS`; the window
  opens only once the denial is queued — third review, C1: one the bus
  dropped coalesces nothing, the process's next denial is queued and
  judged; the oldest of the 512 windows goes first, in O(1), C2); every
  repeat is in a signed `event_bus_coalesced` row (per key the repeats and
  their first and last time, the most repeated first) and in the status
  (`coalesced`). A loop of one `chmod` is one event a second; a loop of new
  processes is not coalesced (each is its own offender) and is bounded by
  the shares (§3);
- denials and `bpf()` calls (`floods_p0`) take all of P0 but
  `P0_RESERVE` (64) slots, the rare tamper events': a module load, an
  exploit post-condition, a signal to a security tool, a sensor flood —
  the last two carried by the open-sensor pump and by the network drain
  and the io_uring pump between their own events — find room at once and
  hold no pump back while a flood fills the rest. A denial holding a flood
  slot waits for the queue's slot within what is left of its 50 ms (third
  review, C6: the rare events past the reserve).

`DefenderSignal` shares the file-open sensor's ring and pump with the FIM
credential reads, mass writes and bursts (review #471 M2): the pump sends
a pass's signals first (R12b: a pass of up to 1,024 records, §2a), so one
read with a file event that waits for room is not held behind it (the test
`the_pump_queues_a_pass_s_signal_while_a_file_event_waits`). A signal read
in a later pass still waits while the pump waits — which, with the opens
capped, takes 6,144 file events other than opens queued in P2. A ring of
its own for the signals is an eBPF change, open (§7).

## 2a. The pumps (R12b)

Each ring's pump is an OS thread of its own (`nn-<ring>`, `sensors::pump`):
the process-spawn, file-open, exec-check, connect, DNS, `fs_protect`,
module-load, io_uring and `bpf()` rings, the exploit guard's and the LSM
file-open sensor's. It blocks in `poll(2)` on its ring's descriptor — the
kernel wakes it, no runtime in between — reads what the ring holds, at most
`PASS_MAX` (1,024) records a pass, and sends in batches
(`BusSender::send_batch_blocking`): the events that find room at once are
queued with one round of the queue's lock, the coalescer's and the cap's,
at most `BATCH_MAX` (256) a batch; a batch is sent as soon as it is full or
the ring is read empty — never held back to fill one. The rest of a batch,
from the first event that finds no slot, is sent as `send` sends one event
(each class's wait or drop); a wait runs on the runtime's timers while the
thread blocks. A batch queues exactly what the sends one by one would —
each class's FIFO, a repeat of a denial queued earlier in the same batch
counted into it, a full P2 or P3 dropping the new event (the test
`a_batch_queues_as_the_sends_one_by_one_would`).

The connect pump waits, per batch, for the DNS pump's pass over the
queries made before its connects (lab PR 229) and announces each connect
after its batch is on the bus (lab PR 246); the DNS pump answers the
lookups' requests for a pass as well as its ring, so its thread runs the
pump's own loop on the runtime's reactor (`Handle::block_on`). The FIM and
network drains stay tasks (their work is the drift log and the flows'
ledger). A pump never ends while the agent runs: one that ended — returned,
failed, panicked, or stopped by the lab's `debug-abort-pump` — is a blind
spot the event loop finds within 5 s (SNS-001) and the agent stops, as
before. Each pump and drain is a source of the bus with a sequence of its
own (§2b).

## 2b. The envelope (R12b)

The queues hold `nn_core::bus::Envelope`s: the event with its source (the
pump or drain that read it, `SourceId`, named by `BusSender::for_source`),
its place in the source's sends (`seq`), its class, the kernel's time of its
record (`record_time_ns`: the record's `CLOCK_MONOTONIC` timestamp; a TCP
flow's closed row its close, an open-phase row the time it was observed, a
UDP flow's row — a window of sends the drain closes — none) and the process
it is about (`ProcessKey`: the boot, its pid, its start when the record
names it). Inside a class the take order is each source's order (the debug
builds check it at every take); stage 5 times the decision from the
record's time (§5).

## 2c. The floods of P0, capped per uid (R12b, the third review of #471's C3)

Under the shares a flood that keeps P0 full takes two thirds of the
consumer (§3). The two tamper events a process can repeat at will —
`floods_p0`: a refused operation (root; no kernel budget) and a `bpf()`
call (any user on 6.x) — are queued at most `FLOOD_CAP_PER_UID` (256) a
second per uid and kind (`FloodCap`); the rest of that uid's second is
counted, not queued: in the status (`capped`) and in a signed
`event_bus_capped` row each sample (per uid and kind the count, its first
and last time, and what the flood is made of — the first process of each
distinct `comm` and action, at most 8: a fork loop of one program is one,
another program's attempt inside the flood is named apart), with a WARN.
A repeat of a queued denial is coalesced before the cap counts it; another
uid's events have their own allowance (a flood by one never caps another's);
the kinds are counted apart; a full table of uids (4,096) queues a new uid
uncapped. The capped denials are counted as NN-L-AT-001's held records (C5,
§5). What it costs: inside a flooding uid, another program's refused
operation in the same second is counted and named, not judged on its own —
the kernel refused it, and the uid's 256 a second keep the posture and the
ladder on the flood. A root fork loop's (EXP-13e) and any user's `bpf()`
loop's (EXP-13d) share of the consumer falls from two thirds to 256
decisions a second.

## 3. The take order

By weighted shares, 8 : 2 : 1 : 1 (`SHARE_WEIGHTS`, a smooth weighted
round robin over the queues that hold events: `ClassQueues::take`), FIFO
inside a queue. Work-conserving: a queue with nothing in it gives its
turns to the others and banks none for later. P0 is far ahead — a tamper
burst's first event is taken within a take or two, and the burst drains at
two thirds of the consumer or more — but never alone: the first version of
the review's fix took P0 strictly, and a flood that kept P0 full (a root
loop of new processes' refused `chmod`s, any user's `fork` + `bpf()` loop)
left exec, file and network events no take at all (second review, R-A).
With every queue flooded P1 keeps a sixth of the consumer and P2 and P3 a
twelfth each (~1,170 execs and ~580 file and network events a second at
EXP-13's ~7,000 decisions a second); against a tamper flood alone the
network keeps a ninth. Among P1–P3 the shares are 2 : 1 : 1: under a
flood of any one lower class the other two keep a quarter of the consumer
each (P1 half): at least 1,750 network events a second against a
file-open flood (3,500 with no exec load). The plan's aging — one take by age after 64 that passed over a
waiting lower queue — gave a lower class one take in 65 (~110 network
events a second), and P3 dropped past it (review #471 A2; the reviewer's
simulation is the test `a_flood_of_a_higher_class_leaves_the_network_its_share`;
the tamper flood's, `a_tamper_flood_leaves_the_other_classes_their_share`).
P1 has the larger share: an exec is the lineage every later event of its
process is judged on, and the exec quarantine holds a process until its
exec is judged.

**What the overtaking event is judged on.** The process lineage (the
posture's `AuthSessionTracker`) and the chains' ancestry tree learned an
exec only when the exec itself was judged. An event that overtakes the
exec of its process — or of the process it signals — would be judged
without it. When the receiver takes an event of any queue but P1 (P0
always overtakes, P2 and P3 by their share) it hands over the
`ProcessSpawn`s still queued in P1 that reached the bus before it, each
once (`Received::overtaken`, `ClassQueues::hand_over_older`): the receiver
makes their paths absolute and the lineage ingests them, the event loop
teaches the engine's rules (`RuleEngine::observe_arrival`: CHAIN-002 records
the exec's edge), and the event is judged on the process tree of every exec
that arrived before it, as on a single queue. The execs are judged in their
own turn; a second ingest of an exec, or one older than the exec the cache
holds for the pid, changes nothing (`ingest_inner`; one ring delivers a
pid's execs in order).

**And not on a later one** (review #471 A1). The other way round, an exec
of a pid can be judged — and learned — before an older event of the same
pid that waits in a lower queue. The lineage kept one exec per pid, so that
event was judged on the image of the later exec: a canary reader that then
execs `restic` was exempt as restic's, a `/tmp` program's credential read
and connect fell in the package carve-out once the process exec'd `dpkg`,
a listener was judged on the later `nginx`. The lineage keeps the last
three execs of a pid with their spawn times and answers as of a time:
`lineage::judged_at(ts, ..)` scopes every lookup of one event's judgement to
the event's own time (`event_time_ns`: its kernel timestamp, a flow's
connect), the `*_at(pid, ts)` lookups take it explicitly, and an exec later
than the time is "not known" — never the later image, never `/proc`; an
exec of the process a pid was reused from answers only for a time before
the current process started.
`in_package_transaction` walks the tree as of the event. The event loop and
the replay judge every event inside `judged_at`; the network drains' image
fallbacks ask as of the flow's start.

## 4. Ordering safety: the property test

`agent/src/decision/golden.rs`,
`golden_verdicts_survive_every_per_class_fifo_interleaving`: every order of
a golden case's events (`agent/tests/golden/cases/`) that keeps each
class's own order gives the same verdicts as the stream's order. Checked:
every such order for the cases that have at most 2,000 of them (25 of the
28); for the others every class-major order (each class whole, the classes
in every order), the bus's own take order with the consumer 1 to all events
behind, and 256 random merges — 973 orders. The stream's order is the
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
  its late exec's line, as the flow has it in kernel order. Outside the
  corpus this changes one behaviour: a late exec whose process had a
  port-53 flow to a server that is no resolver and then another flow now
  kills for the later flow, where the earliest (port 53, the kill held)
  answered it and the kill was held;
- (review #471 A1) the lineage answered with the latest exec of a pid (§3):
  the golden cases `a1-exec-after-egress-package`, `…-noread`,
  `a1-canary-reader-later-exec` and `a1-listener-later-exec` (the
  reviewer's demonstration and three of its kind) fail the property test
  without the time-scoped lineage and pass with it.

The test compares the strongest verdict per rule and process; the lines'
own order, how often a rule judged a process and which line carried a
verdict are not compared (by design, above) — review #471 B1, kept in §7.

## 5. Losses

Per queue (`BusStats`): events queued, dropped, the depth and the most it
held, the longest wait — since boot and in the last sample (review #471
B2: the boot's backlog is not the queue's state) —, the sends that waited
for room and the longest such wait, the takes by share ahead of a higher
queue that held events, the decisions timed and their latency from queue
to decision (p50, p99, max; a log-linear histogram, within 12.5 %).

A drop is never silent. The loss recorder (a telemetry task of the
multiplexer: if it ends the agent stops, as for a dead pump) samples every
10 s: a WARN for each queue that dropped; a signed `event_bus_drop` row —
P0 within a second of a drop (the drop wakes the recorder, one row a
second at most: an agent that crashes leaves at most a second of P0 drops
unsigned), the other queues at most once per 600 s — each row carrying
every drop of its queue since the previous row (`dropped_since_last_row`,
`total`); and the posture's `TelemetryLoss`, with the same exemptions (a
trusted-installer window, a package transaction): at any P0 drop, and for
the other queues past the security rings' threshold (64 in a sample) —
P3's too since review #471 A2 (NET-001's connects, the chains' egress, the
DNS rules).

At the stop (review #471 M3) the event loop closes the bus
(`SensorMultiplexer::stop_bus`): no event is taken, the pumps' sends are
refused, and what the queues still hold is counted in a signed
`event_bus_stop` row (`queued_at_stop` per queue) and WARNed — not judged,
never silent — with every drop not yet in a row signed whatever its
window.

Coalesced denials (§2) are not lost: each sample signs the repeats counted
since the last row (`event_bus_coalesced`: the key — pid, operation, inode
— the repeats, their first and last time; at most 32 keys named, the rest
and any evicted window's repeats summed), and so does the stop. R12b (the
third review's C5): each sample also counts them — and the capped denials
(§2c) — as NN-L-AT-001's records held back, per uid
(`detection_budget::count_coalesced_many`): the rule's next record of the
uid carries them in `suppressed_before` and its signed `detections_held`
rows count them, so a reader of the rule's records alone sees every
attempt (EXP-13: records + held = the 12,000 refused, as on R12a's `main`
before the coalescing).

**Stage 5, the decision's delay (R12b; review #471 B2).** Each decision is
timed from its record's kernel time (§2b) to the end of its judgement
(`BusReceiver::decided`), against its class's budget
(`DECISION_BUDGET_NS`): P0 tamper 100 ms, P1 process 250 ms (the exec
quarantine holds a process until its exec is judged), P2 file 1 s (the
opens' share leaves a file event at most 2,048 opens behind), P3 network
500 ms. A later decision is counted per queue (`over_budget`, stage 5's
total) and WARNed once a sample with its count and the longest delay; a
decision whose event has no record time is counted apart (`untimed`).
`nn-admin status --key` shows per queue the budget, the decisions timed and
untimed, p50/p99/max and those over budget, and P0's capped floods
(`StatusResponse::event_bus_decision`, appended after `event_bus`: an
R12a `nn-admin` reads the queues unchanged).

`nn-admin status --key` shows the queues and the loss counters of every
stage of an event's path (plan §3.4):

| Stage | Counted by | Since |
|---|---|---|
| 1 kernel ring | `RING_DROPS`, a ring or map full | Tappa 10.8 |
| 2 kernel budget | `RING_DROPS` `dns_rate`, `listen_rate`, `io_uring_rate`, `task_denial_rate` | reviews 78, EBPF-013/017 |
| 3 decode | `RejectThrottle` | SNS-008 |
| 4 bus queue | the bus, per queue | R12a |
| 5 decision delay | the decisions over their class's budget, from the record's kernel time | R12b |
| 6 response queue | — | R12c |
| 7 evidence writer queue | — | R12c |
| 8 export | — | R12c (signed `telemetry_loss` rows), R15 |

## 6. What it costs

Four queues of up to 21,504 events (the one channel held 4,096), whose
memory is given back when a queue above 1,024 runs empty; one lock per
batch of up to 256 events and per take (R12b); the hand-over scans P1 only
when an event of another queue is taken, each queued event once; the
lineage keeps three execs per pid (its cache's bound is unchanged). R12b:
eleven pump threads (blocked in `poll(2)` when their ring is empty), the
envelope's 40 bytes per queued event, the cap's table (at most 4,096 uids
and kinds). The lab's numbers (overhead, latency per class, the
soak) are in the lot's note of `docs/roadmap/CAPABILITY_PROGRAM.md`.

## 7. What is next

- **R12b, done in its first part (lab PR 269, R12b-1)**: the ring pumps on
  threads of their own with batched sends (§2a; EXP-13e ×3 per build: the
  lot's note in `docs/roadmap/CAPABILITY_PROGRAM.md`); the envelope (§2b);
  stage 5 against a budget per class (§5; review #471 B2); the per-uid cap
  of P0's floods (§2c; the third review's C3); the coalesced and capped
  denials in NN-L-AT-001's held records (§5; C5).
- **R12b, its second part (R12b-2)** — the decision thread without
  `await`: `exe_identity::resolve` in the pumps (the bus's receiver does it
  for the execs it hands over: review #471 B4), the systemd state as a
  snapshot, `close_if_expired` on a tick, the canary append through the
  writer's queue, a cache of `PackageOwnership` for module provenance, a
  guard against blocking I/O on the decision path; R-F (the judgement time
  as an explicit parameter, an `Absent` pid not known inside a judgement);
  R-B if it fits.
- **Open after review #471** — B1: the property test compares the
  strongest verdict per rule and process (§4); B5: "(agent predates the
  bus)" in `nn-admin status` is reachable only against an agent older than
  R12a (the matrix shows it through its mock); B7: the soak's thread count,
  measured again in the comparable pair (the lot's note: R12b adds eleven
  pump threads); M2: the signals to a security tool on a ring of their own
  (eBPF, not in R12b).
- **Open after the second review of #471** — R-B: the history is three
  execs deep — an event followed by four execs of its process before it is
  judged reads "not known" (an exemption then does not apply; a rule that
  wants a positive image, the transfer tools' staged ancestor or NET-008's
  fallback, does not fire), and a walk stops at a "not known" hop although
  its parent is known: a deeper history, the walk on from the parent,
  facts of a process kept past the cache's eviction. R-C (eBPF, wire): a
  FIM `Modified` carries its close's time, not its write's — a file kept
  open across an `exec dpkg` falls in the package carve-out (on `main`
  too). A kernel budget per uid for the `bpf` hook's records (stage 2): the
  userland cap (§2c) bounds the consumer's share, a kernel budget would
  bound the ring's.
- **Open after R12b-1** — the FIM and network drains stay tasks of the
  runtime that send one event at a time (they are no flood's source in the
  EXP-13 family); the DNS pump's thread runs its loop on the runtime's
  reactor (its pass answers the lookups' requests).
- **R12c** — the response dispatcher by severity, its queue (stage 6);
  no action without a signed record (intent, then outcome); the budget
  never limits an action's record; the evidence writer's queue (stage 7);
  signed `telemetry_loss` rows aggregating every stage, then the heartbeat
  (INI-14).
