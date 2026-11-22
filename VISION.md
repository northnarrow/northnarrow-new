# NorthNarrow — Vision

> Note of 20 October 2026 (founder's decision, Wave 4, lab PR 214): the LLM
> no longer runs inside the agent. On-host detection is deterministic
> (rules, correlation, posture, COMBAT); an AI assistant, if there is one,
> will stay outside the enforcement path (for example on the backend, for
> the analyst). The paragraphs below about the built-in LLM describe the
> original vision.

NorthNarrow is a hyper-competitive XDR, superior to CrowdStrike, written in
native Rust. It is a fortress with an LLM inside that knows when a file is
a virus or legit. It has an attractive interface. It is prepared for ALL
attacks.

It is truly proactive, not as a marketing word: the moment it is
installed on a machine, it studies it, understands where its weak points
are, and finds ways to close the gaps before they are exploited.

The native LLM that runs inside it is self-aware: it knows its own weak
points as a defender, and it knows the weak points of the machine it
protects. It does not give blind verdicts. When it is not sure, it
escalates. When it sees a gap, it closes it. When it sees an attack, it
reacts and neutralises it.

## Defence autonomy

When it comes to defence, NorthNarrow does not depend on human will. When
it identifies a serious threat, it acts. It does everything it can to save
the machine, even at the cost of isolating it completely from the network
to stop the infection from spreading to other servers.

The human is told what NorthNarrow did. Permission is not asked before
acting when the danger is clear. Speed of response is part of the defence.

### Autonomy levels (default: level B)

- **Confirmed serious threats** (active ransomware, exfiltration in
  progress, kernel exploit, lateral movement): NorthNarrow acts on its own,
  at once. Kill, isolate, quarantine. Notify afterwards.

- **Ambiguous or low-level threats**: NorthNarrow raises an alert to the
  admin with a suggested action. It waits for human input.

- **Override set by the customer**: the organisation can choose a more
  aggressive or a more conservative level. Default = B.

## Supervised reactivation

When NorthNarrow isolates a machine from the network in response to a
serious threat, reactivation is **not automatic and not trivial**.

The network comes back online only when:

1. The admin is physically present, or in a supervised session, when the
   machine starts.
2. The admin enters a cryptographic key that only they hold.
3. Without that key, the machine stays offline, even after repeated
   reboots.

This model stops compromised admin credentials from reactivating a machine
that is still infected. The key has a company recovery system, managed by
a dedicated key vault (details in ROADMAP.md).

## Supreme defence

NorthNarrow is the supreme defence of everything that exists on Windows and
Linux.

NorthNarrow is the future. CrowdStrike is the past.

---

## Golden rule

This file is the contract. Every future work session (with any Claude or
any tool) starts by reading this file first. If a tool contradicts this
vision, the tool is wrong.

The vision is not scaled down. It is built in Tappe (stages), in a fixed
order (see ROADMAP.md). One Tappa at a time. None is skipped. There is no
going back. Ever.
