# NorthNarrow — Vision

> This document describes where NorthNarrow is going. For what it does
> today, see [README.md](README.md) and
> [docs/operator/KNOWN_LIMITATIONS.md](docs/operator/KNOWN_LIMITATIONS.md).

NorthNarrow is an endpoint defence written in Rust, built in the open. We
aim to match and then surpass the major commercial EDRs, with code anyone
can read and a lab anyone can rerun. It runs on Linux today; Windows and
macOS are later goals.

## Proactive

We want NorthNarrow to be truly proactive, not as a marketing word: once
installed, it studies the machine, finds where it is weak, and helps close
those gaps before anyone can use them.

Our goal is broad coverage of the attacks real machines face, stated
honestly: what we say it covers is backed by a test or a lab run, and what
it does not cover yet is listed as a limit, not hidden. It does not give
blind verdicts. When it is not sure, it escalates.

## Deterministic on the host

Since October 2026 there is no AI model on the host. Detection there is
deterministic: rules, correlation, posture and COMBAT, so every decision
can be read, tested and explained. An AI assistant, if there is one, stays
outside the enforcement path, for example on a backend that helps the
analyst.

## Defence autonomy

The alpha is observe-only. It detects, judges and records what it would
have done, and it does not touch a user's program
([ALPHA_PROFILE.md](docs/operator/ALPHA_PROFILE.md)); its protection of
itself stays on.

Autonomous response is the goal, behind a signed policy. The response
ladder exists in the code and is tested in our lab; the aim is that, on a
confirmed serious threat, NorthNarrow acts at once and tells the human
afterwards, because speed of response is part of the defence. At the far
end, that means isolating the machine from the network so an infection
does not spread to other servers.

The intended levels (default: level B):

- **Confirmed serious threats** (active ransomware, exfiltration in
  progress, a kernel exploit, lateral movement): act at once (kill,
  isolate, quarantine) and notify afterwards.
- **Ambiguous or low-level threats**: alert the administrator with a
  suggested action, and wait for a human.
- **The organisation's choice**: a more aggressive or a more conservative
  level, set in its signed policy.

## Supervised reactivation

When NorthNarrow isolates a machine, coming back online should be neither
automatic nor trivial, so that stolen administrator credentials cannot put
a machine that is still infected back on the network.

What exists today ([COMBAT_RECOVERY.md](docs/operator/COMBAT_RECOVERY.md)):
a confirmed (locked) COMBAT has no automatic exit while the agent runs. It
is released with `nn-admin unlock`, signed with an Ed25519 administrator
key that belongs off the host and is bound to that install, and the
release reports success only once the firewall reads back clear. A
management carve-out keeps the administrators' own network reachable, so
they are not locked out. In the alpha, isolation is recorded, not applied.

The goal goes further:

1. The administrator is present, or in a supervised session, when the
   machine starts.
2. The isolation holds across restarts and reboots until the
   administrator's key releases it.
3. The key can be recovered through a company key vault (ROADMAP.md).

## How we build it

This vision guides the roadmap. We do not scale it down to fit today;
we build it in stages, one at a time and in order
([ROADMAP.md](ROADMAP.md), and
[CAPABILITY_PROGRAM.md](docs/roadmap/CAPABILITY_PROGRAM.md) for the
current state), and a goal counts as reached only when a test or a lab run
shows it.

We are building the defence we would want on our own machines.
