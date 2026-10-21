# Security Policy

NorthNarrow is a security product. Reports about weaknesses in the agent,
the eBPF programs, the anti-tamper layer or the admin channel are welcome
and are handled as a priority.

## Supported versions

The project is pre-release (`0.0.x`). Security fixes land on the `main`
branch and ship in the next tag; there are no backports.

**Support period.** A `0.0.x` tag is supported until the next tag is
published: on that day its support period ends, and the fix for a
vulnerability found in it is the newer tag. The pre-release tags are not
meant for production. The support period of the first stable release
(`1.0.0`) is stated here, in years, before that release ships; where the
EU Cyber Resilience Act applies, it is at least five years unless the
product is expected to be in use for less (Article 13(8)).

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

- Use GitHub Security Advisories, the repository's private vulnerability
  reporting: **Security → Report a vulnerability** on
  https://github.com/northnarrow/northnarrow-new, or directly
  https://github.com/northnarrow/northnarrow-new/security/advisories/new.
- This is the only channel for now, and it needs a GitHub account. An
  encrypted e-mail channel will be listed here and in
  `.well-known/security.txt`, with its key fingerprint, when the maintainer
  publishes one.
- Include: affected component (agent / agent-ebpf / watchdog / nn-admin),
  kernel version, a minimal reproduction, and the impact you observed.
- You will get an acknowledgement within 5 working days and a status
  update at least every 14 days until the report is resolved.

`.well-known/security.txt` (RFC 9116) names the same channel and this
policy. Its `Expires` date is renewed before it passes: a repository test
fails once it has.

## Regulatory reporting (EU Cyber Resilience Act)

Article 14 of Regulation (EU) 2024/2847 (the Cyber Resilience Act, CRA)
applies from 11 September 2026 to the manufacturer of a product with
digital elements made available on the EU market. Whether and from when
it applies to NorthNarrow depends on when NorthNarrow is made available on
that market; this section is the procedure the maintainer follows once it
does, not a legal determination.

The maintainer, as the manufacturer, notifies the CSIRT designated as
coordinator of the Member State of the main establishment, and ENISA,
through ENISA's single reporting platform:

| What | Early warning | Notification | Final report |
|---|---|---|---|
| An actively exploited vulnerability in NorthNarrow | within 24 hours of becoming aware of it | within 72 hours | within 14 days after a corrective or mitigating measure is available |
| A severe incident having an impact on the security of NorthNarrow | within 24 hours of becoming aware of it | within 72 hours | within one month after the 72-hour notification |

- The clock starts when the maintainer becomes aware: the time is
  recorded in the advisory's draft on the day.
- A reporter whose report shows active exploitation is told that the
  report triggers these notifications. The notifications describe the
  vulnerability, not the reporter.
- The users of NorthNarrow are informed of the vulnerability or incident
  and of the mitigations through a GitHub Security Advisory (Article
  14(8)), without waiting for the final report.

## Scope notes

- Findings already tracked in `docs/audit/` are known — among them the
  external audit of commit `16f7563` and the follow-ups its remediation
  found in the lab (`docs/audit/EXTERNAL_AUDIT_16f7563.md`, which also
  gives the status of each finding); a report that adds a working
  reproduction or a different impact is still useful.
- The agent runs no language model: the on-host LLM advisor (ADE) was
  removed in Wave 4 (lab PR 214), and detection is deterministic. A report
  against the advisor of an earlier build is still welcome for that build;
  say which build it is.
- Testing must be done on hosts you own or are authorised to test.
  Do not test against third-party systems running NorthNarrow.

## Disclosure

We follow coordinated disclosure: a fix is published first, then the
advisory (GitHub Security Advisory + a note in the release). Credit is
given to the reporter unless they ask otherwise.

The embargo ends when the fix is released, and at the latest **90 days**
after the acknowledgement. It can be extended once, by agreement with the
reporter, for a fix that needs longer. After that the reporter may
publish. For an actively exploited vulnerability, the advisory with the
mitigations comes out as soon as there is one, before the fix if need be.
