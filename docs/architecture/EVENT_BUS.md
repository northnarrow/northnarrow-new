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
behind the opens. R12a left the decision unchanged — the one event loop
judged every event through `process_event`; R12b (§2d) puts it on a thread
of its own without `await`, the response dispatcher is R12c (§7).

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

A thread blocked in `poll(2)` must be scheduled when the kernel wakes it,
and on a saturated CPU that may take a scheduler slice (EEVDF's 3 ms with 4
CPUs on 6.8) — about the time one process's loop of refused operations
takes to fill the `fs_protect` ring the object declares (64 KiB, 1,024
denials). On R12a that pump was a task a runtime worker already running
polled; in the lab's EXP-13 (bursts of 1,500 under a flood of opens) the
threaded pump's ring lost more of them than R12a's. The loader sizes that ring
at 256 KiB (`FS_PROTECT_RING_BYTES`, 4,096 denials; the object unchanged):
four such waits of room.

The connect pump waits, per batch, for the DNS pump's pass over the
queries made before its connects (lab PR 229) and announces each connect
after its batch is on the bus (lab PR 246); the DNS pump answers the
lookups' requests for a pass as well as its ring, so its thread runs the
pump's own loop on the runtime's reactor (`Handle::block_on`). The FIM and
network drains (their loops are async: they await the bus, the DNS and
connect barriers, their periodic steps) run on threads of their own too
(`nn-fim_drain`, `nn-net_drain`; review of #474), each with a runtime of
its own — one thread, its own reactor and timers (`spawn_drain_thread`) —
so the kernel's wake-up for their rings reaches that thread instead of a
worker of the agent's runtime. A pump never ends while the agent runs: one that ended — returned,
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

## 2c. The floods of P0, capped per uid and target (R12b, the third review of #471's C3, the review of #474)

Under the shares a flood that keeps P0 full takes two thirds of the
consumer (§3). The two tamper events a process can repeat at will —
`floods_p0`: a refused operation (root; no kernel budget) and a `bpf()`
call (any user on 6.x) — are queued at most `FLOOD_CAP_PER_UID` (256) a
second per key (`FloodCap`, `CapKey`): the kind, the uid, and the target —
each refused operation on each target (operation, device, inode: a
signal's or a ptrace's target process), each `bpf()` command. One target's
or command's burst never holds back another's event: the review of #474
showed a program load, the 257th `bpf()` call of its uid in a second of
`BPF_MAP_CREATE`s, never queued and never judged by NN-L-BPF-001 when the
key was the uid alone. NN-L-BPF-001's commands — a program loaded,
attached, a link made (`NEVER_CAPPED_BPF`) — are never capped: each is
judged; a burst of them is bounded by P0's shares and its wait for room,
as on R12a. The records about the agent's own BPF objects (a handle to one
of its maps, programs or links taken by id, a write handle on one of its
maps: NN-L-BPF-002's tampering) are a kind of their own with four times the
allowance (`FLOOD_CAP_OWN_PER_UID`, 1,024: the lab's soak saw the sampler's
`bpftool map dump`s of the agent's maps make ~450 in a second as root,
which a cap of 256 kept from BPF-002).

The rest of a key's second is counted, not queued: in the status
(`capped`) and in signed `event_bus_capped` rows each sample — every key
that capped something, with its count, its first and last time and what
it is made of (the first process of each distinct `comm` and action, at
most 8 per key; the count covers them all), in rows of at most 256 keys,
each naming its part — with a WARN per uid and kind. A repeat of a queued
denial is coalesced before the cap counts it. The capped denials are
counted as NN-L-AT-001's held records, the capped records about the
agent's own objects as NN-L-BPF-002's (C5, §5). Root's floods capped raise
the posture's `TelemetryLoss` (ALERTED; not inside a trusted-installer
window or a package transaction): the cap is itself a signal.

A full table of keys (`FLOOD_CAP_KEYS`, 4,096 keys active in the same
second; those whose second ended and that hold nothing to sign go first)
queues a new key uncapped: it is judged like any P0 event, or — P0 itself
full — dropped by the bus with its own signed `event_bus_drop` row and
`TelemetryLoss`; never set aside uncounted and unjudged. Those events are
counted and signed in the next capped row
(`queued_uncapped_table_full`) and raise the posture's `TelemetryLoss`
whatever their uids (the re-review of #475: a full table is anomalous by
itself). Before it queues a new key uncapped, a full table releases the key
whose second ended longest ago, its count kept for the next row; past
4,096 released keys their counts are summed per kind and uid (a row's
`released_keys` target), past 4,096 sums per kind for the rest of the uids
(uid 4294967295) — the third review of #475: a row names a bounded number
of keys and keeps every count. Holding them back instead would let a burst over many targets hide
the rest of the second's events of every new key; queued, the flood falls
back to R12a's bounds (the shares, P0's reserve of 64 slots).

What it costs: inside a key's burst, another process's refused operation on
the same target, or its `bpf()` call of the same command, in the same
second is counted and named, not judged on its own — the kernel refused it,
and the key's 256 a second keep the posture and the ladder on the flood. A
root fork loop's (EXP-13e) and any user's `bpf()` loop's (EXP-13d) share of
the consumer falls from two thirds to 256 decisions a second per target or
command.

## 2d. The decision thread (R12b-2)

The decision runs on an OS thread of its own, `nn-decision`
(`agent/src/run_loop.rs`, `decision_loop`): it takes each event from the bus
(`BusReceiver::recv_blocking`, blocked on the bus's wait, at most 500 ms
before it looks at its stop and counts a round for the watchdog's progress
check), teaches the rules the execs it overtook, offers it to the telemetry
probe, judges it (`process_event`, a plain function: no `await`) and counts
its delay (stage 5). The event loop's task keeps the rest — the signals,
the admin shutdown, the telemetry tasks' liveness (SNS-001), the lab
triggers — and either end ends the other: a stop there stops the thread; a
closed bus, or the thread's end (a panic is rethrown at the join), stops
the loop. The thread is joined, and the canary trips' writer waited for,
before the bus is stopped and its stop row signed. `debug-stall-loop` (lab
PR 216, EXP-13b) stalls the decision thread.

What blocked the decision is off it:
- an exec's path is made absolute in its pump (`exe_identity::resolve`: the
  mount table, `/proc/<pid>/exe` for a relative path), right after the
  kernel recorded it — every exec, not only the handed-over ones (the
  receiver no longer reads `/proc`: review #471 B4);
- systemd's state is a snapshot (`SystemdSnapshot`) the systemd watch
  refreshes every 2 s: a signal PID 1 relayed (EBPF-001) is judged on an
  answer at most a second old; an older one hands the event to the watch,
  which asks systemd at once and hands it back answered — the decision
  thread judges it at its next turn (within its half-second wait), once
  (not through the bus: a denial sent again would be coalesced into the one
  already judged, or capped); without systemd's socket the answer is
  "none", as the question's was. R12a's event loop awaited systemd's answer
  up to a second;
- the trusted-installer window's expiry is its tick's (external audit
  ATP-003, every second), not swept at every event;
- a canary trip's access row and its registry mark are written by a thread
  of their own (`nn-canary-log`, `Detector::with_writer`), in the order
  DEC-011 and lab PR 260 fixed; the first trip is decided at once, a later
  access before the mark is not one; a full queue (1,024) holds a trip at
  most `CANARY_QUEUE_WAIT` (100 ms), then its rows are counted
  (`Detector::unwritten`, per canary, WARNed, and at the stop) while its
  event goes on to the rules (review of #475: a writer that stopped writing
  held the decision, and the stop);
- a kernel module's package ownership (R018) is asked by the module-load
  pump when it reads the load (`ModuleOwners::refresh`: dpkg's lists, or an
  `rpm -qf` process) and kept per file; R018 judges the load on that
  answer.

What the decision thread still does that is I/O, exactly (review of #475:
"no blocking I/O" was not exact):
- the responses a decision runs, in order, before the next event — the
  executor and what it calls: a kill's cgroup made, frozen, killed and
  removed, its verify retries (up to 50 ms), `/proc` reads, the
  quarantine's copy and its synced ledger, the containment ledger, the
  outbound block and the throttle's cgroup files (R12a's loop awaited them
  on the blocking pool); their dispatcher is R12c's;
- the ransomware tracker's sampler of a burst's files (their entropy, the
  copies) and its trust of the writer's executable (a digest, the package
  that owns it) — on a mass-write or rename burst only; R12c's dispatcher of
  slow work;
- the per-rule policy's exemption facts (a process's uid, cgroup and
  executable from `/proc`, a pidfile), read once per process and cached;
- a canary trip's reader, one readlink of `/proc/<pid>/exe`, on a trip
  only, and a trip's wait for room in the writer's full queue (≤ 100 ms);
- the security-tool detector's registration of a tool (its start and
  executable from `/proc`), at the tool's exec only;
- in a judgement, a process's start (`/proc/<pid>/stat`, POS-003's check of
  a reused pid, and a cached exec checked against the process its pid
  names now), and for a pid the lineage does not hold a fork's parent,
  start, executable and uid (`/proc/<pid>/stat`, `exe`, `status`) — the
  parent's cached image accepted only when `exe` is that file, never the
  image `/proc` shows instead (§3).

A guard keeps any more off the decision path
(`xtask/tests/decision_path_io.rs`, run by `cargo test`): the decision
thread's own code — `process_event.rs`, `decision_loop` — holds no
`await`, no file or `/proc` access, no process, no sleep, no
`block_in_place`; every other file of the code the decision calls into —
the rule engine, the posture and its lineage, the ladder, the canary
detector, the correlation buffer, the budget, the ransomware and
impairment trackers, the copy-on-write guard, the detection sink, the
telemetry probe, and (review of #475) the responses' code under
`crates/nn-linux/src/response` — is a ratchet: each file's I/O sites are
counted and listed with why; a new site, or a count above its pin, fails,
and a count below it fails until the pin is lowered. It is lexical: it
counts markers in the files of its list (the reviewer's mutation K9, a read
planted in `Executor::execute_for_started`, failed only once the responses'
code was on the list) — code the decision reaches outside the list is not
seen, and the list is kept by hand.

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
three execs of a pid with their spawn times and answers as of a time, an
exec later than the time "not known" — never the later image, never
`/proc`; an exec of the process a pid was reused from answers only for a
time before the current process started. R12b (R-F, the second review of
#471): the time is a parameter of every lookup, not a thread-local scope —
`lineage::AsOf`: `Judged(ts)` for the judgement of an event (each judge
takes it from the event itself, `AsOf::of_event`: its kernel timestamp, a
flow's connect), `Live(ts)` for a pump or drain reading a record right
after the fact (a connect's image, NETR-008; a flow's start), `Now` outside
any judgement (an admin verb, a response, a ladder step). A lookup cannot
be made "outside the scope" any more, so none can fall back to the latest
exec unseen (R12a caught that only by its pinned sources). In a judgement a
pid the spawn cache does not hold is not known — never read from `/proc`,
which shows the present image. The processes running when the agent starts
are in the cache: once the exec sensors are attached the start scans
`/proc` and enters each (`seed_from_proc`: the image it runs, at time 0 —
it has run it since before any exec could be seen —, its start, parent and
uid; a pid already held left alone, a deleted image not entered). The
boot's daemons and a session older than a restart of the agent are known
that way (without it, strict R-F left the COMBAT their descendants reach
unlocked after every restart: the posture golden case
`eva-installer-window`), and an exec such a process runs later is a later
entry, the scanned image its past. R12b-2's first version read `/proc`
instead for a process older than the agent, which could judge an event of
it on an image executed after the event (review of #475: a canary read,
then a backup tool's exec, the read judged as the tool's).

The re-review of #475 found strict R-F with a cache of 2,048 entries kept
first in, first out unsafe: 2,048 execs of other processes pushed out a
live daemon's entry — a `clamd` the scan entered became not known, its
read of a canary was no reader's and the daemon was killed; a fork that
never executes (a maintainer script's subshell, a cron worker, a prefork
backend) was not known at all. So:
- the cache is bounded by process lifetime: a thread of its own
  (`nn-lineage-sweep`, every 5 s) marks the cached processes that exited
  (or whose pid names another process now); past 2,048 entries only marked
  ones past a 30-s grace are dropped, a live process's never for newer
  ones; past 32,768 entries a gone process's go first, then the oldest of
  the uid holding the most among the processes executed since the start,
  whatever the uid's class (the start's scan's last), counted
  (`evicted_live`), WARNed and raising the posture's `TelemetryLoss` (the
  third review of #475 and its final check: an account's flood of live
  processes — a user's, or a webshell's as `www-data` — pushes out its own
  entries, not the boot's daemons nor a person's session);
- a fork runs its parent's image while `/proc` says so (`fork_entry`): for
  a pid the cache does not hold, its parent and start from
  `/proc/<pid>/stat` (no exec changes them), its parent's image as of that
  start (cached, or itself such a fork), accepted only when
  `/proc/<pid>/exe` is that very file — a fork that executed something
  else since stays not known; an event before the fork's start is not its;
  the sweep enters the running forks of cached processes, so a daemon's
  child outlives its parent's entry; the start is read again after the
  exe, so a reuse between the reads mixes no two processes.

The third review of #475 found two holes of the same family:
- a process that daemonizes after the agent's start (`Type=forking`,
  `daemon()`: the parent executes, forks and exits within milliseconds,
  the child reparented to pid 1) was compared with pid 1's image and never
  known. The sweep enters it as the orphan of a cached process it found
  gone (`orphan_entry`): reparented to pid 1 or to a subreaper among that
  process's ancestors, started no earlier than its exec, running that very
  file; every gone process of that image it could descend from must have
  run the same script. Its parent stays the one `/proc` shows. It runs
  that image from the sweep's instant only — the adoption is an inference
  about the present (the final check of #475: an attacker who ran a reader
  any user may run and let it exit, then executes it again with that exec
  still queued across a sweep, does not get the events before the exec
  judged as the reader's). Before that sweep (at most 5 s after its
  parent's exit) it is not known;
- a pid reused by a fork while the dead process's entry was cached
  answered with the dead process's image, and the walk stopped at it. A
  cached exec whose process is not the one the pid names now (another
  start in `/proc/<pid>/stat`), at a time that process may already have
  existed, answers as not held (`cached_live`): a fork of its parent in a
  judgement, `/proc` outside one; for a time before the reuse it is still
  what the pid ran. The sweep marks the pid and enters the fork.

A process the agent saw start whose exec it does not hold (dropped by P1,
or not yet read) and whose image is not its parent's, nor that of a gone
process it was orphaned from, is not known. What stays (§7): a fork that
executes another image and then executes its parent's again (RR3) is
judged as its parent's image for the events in between when neither exec
is held at the judgement (both still in the ring, or dropped and counted);
a fork the sweep entered whose later exec is lost is judged as its
parent's image (RR5, as any process whose later exec is lost).
`in_package_transaction` walks the tree as of the event; the replay judges
every event as the decision thread does.

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
window. A batch a pump had read and the closed bus refused is counted in
the same row (`refused_at_close`, review of #474): the stop asks the pump
threads to end and waits for them (at most two of their waits) before it
signs.

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
eleven pump threads (blocked in `poll(2)` when their ring is empty) and
the two drains' (each with a one-thread runtime of its own), the
`fs_protect` ring's 192 KiB more of kernel memory, the envelope's 40 bytes
per queued event, the cap's table (at most 4,096 uids
and kinds). The lab's numbers (overhead, latency per class, the
soak) are in the lot's note of `docs/roadmap/CAPABILITY_PROGRAM.md`.

## 7. What is next

- **R12b, done (lab PR 269)** — R12b-1: the ring pumps on threads of their
  own with batched sends (§2a; EXP-13e ×3 per build: the lot's note in
  `docs/roadmap/CAPABILITY_PROGRAM.md`), the envelope (§2b), stage 5 against
  a budget per class (§5; review #471 B2), the per-uid cap of P0's floods
  (§2c; the third review's C3), the coalesced and capped denials in
  NN-L-AT-001's held records (§5; C5). R12b-2: the decision thread without
  `await` and the blocking I/O taken off it, with its ratchet (§2d; review
  #471 B4); R-F (§3: the time a parameter, an `Absent` pid not known in a
  judgement; the running processes entered at the start; after the reviews
  of #475 the cache bounded by process lifetime, forks and a daemon's
  orphans running their parent's image, a pid reused by a fork not the dead
  process's).
- **Open after R12b** — the responses still run on the decision thread
  (R12c's dispatcher); the decision path's I/O the ratchet lists (§2d: the
  ransomware tracker's sampler and trust, the per-rule policy's exemption
  facts, a canary trip's reader, the security-tool detector's registration),
  and the guard's list kept by hand (lexical); R-B: the history is three execs deep — an event followed by four execs of
  its process before it is judged reads "not known", and a walk stops at a
  "not known" hop although its parent is known (a deeper history, the walk
  on from the parent, facts kept past the cache's eviction); the property
  test over the posture corpus (the posture's buffer and triggers see the
  loop's order; R12a's test covers verdicts only); the FIM and network
  drains send one event at a time (on threads of their own since the
  review of #474); the DNS pump's thread runs its loop on the runtime's
  reactor; the `fs_protect` ring is sized at load for a pump thread's
  wake-up on a saturated CPU (§2a), the other rings keep the object's
  sizes; a burst of NN-L-BPF-001's commands is uncapped (§2c). The
  lineage (§3, the third review of #475): RR3, a fork that executes Y and
  then its parent's image X again, is judged as X for Y's events when
  neither exec is held at the judgement (low: it needs code running in a
  fork of an exempt image, and both execs still in the ring or dropped,
  which is counted); RR5, a fork the sweep entered whose later exec is lost
  is judged as its parent's image; the structural fix for both and for a
  daemon's orphan before the sweep (≤ 5 s) is an exec identity the kernel
  keeps per task (task storage written at `bprm_committed`, copied at fork,
  read by pidfd). The start's scan can enter the image of an exec it reads
  before that exec's event arrives (milliseconds, at the start only). The
  session and workload attribution (`lookup_cache`: the login uid and the
  cgroup a walk reads) still takes a cached exec without checking it against
  the process its pid names now, so a pid reused by a fork can take the dead
  process's parent there (older than R12b).
- **Open after review #471** — B1: the property test compares the
  strongest verdict per rule and process (§4); B5: "(agent predates the
  bus)" in `nn-admin status` is reachable only against an agent older than
  R12a (the matrix shows it through its mock); M2: the signals to a
  security tool on a ring of their own (eBPF). R-C (eBPF, wire): a FIM
  `Modified` carries its close's time, not its write's. A kernel budget per
  uid for the `bpf` hook's records (stage 2): the userland cap (§2c) bounds
  the consumer's share, a kernel budget would bound the ring's.
- **R12c** — the response dispatcher by severity, its queue (stage 6);
  no action without a signed record (intent, then outcome); the budget
  never limits an action's record; the evidence writer's queue (stage 7);
  signed `telemetry_loss` rows aggregating every stage, then the heartbeat
  (INI-14).
