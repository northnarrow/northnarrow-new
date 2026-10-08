# Security Policy

NorthNarrow is a security product. Reports about weaknesses in the agent,
the eBPF programs, the anti-tamper layer or the admin channel are welcome
and are handled as a priority.

## Supported versions

The project is pre-release (`0.0.x`). Only the `main` branch is supported;
there are no backports.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security problems.

- Use GitHub's private reporting: **Security → Report a vulnerability**
  on https://github.com/northnarrow/northnarrow-new.
- Include: affected component (agent / agent-ebpf / watchdog / nn-admin),
  kernel version, a minimal reproduction, and the impact you observed.
- You will get an acknowledgement within 5 working days and a status
  update at least every 14 days until the report is resolved.

## Scope notes

- Findings already tracked in `docs/audit/` are known; a report that adds
  a working reproduction or a different impact is still useful.
- Testing must be done on hosts you own or are authorised to test.
  Do not test against third-party systems running NorthNarrow.

## Disclosure

We follow coordinated disclosure: a fix is published first, then the
advisory (GitHub Security Advisory + a note in the release). Credit is
given to the reporter unless they ask otherwise.
