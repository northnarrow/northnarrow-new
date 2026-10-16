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

- Findings already tracked in `docs/audit/` are known — among them the
  external audit of commit `16f7563` and the follow-ups its remediation
  found in the lab (`docs/audit/EXTERNAL_AUDIT_16f7563.md`, which also
  gives the status of each finding); a report that adds a working
  reproduction or a different impact is still useful.
- The local model (ADE) is advisory: a verdict that names a response is
  recorded as a recommendation and not executed, unless the host runs with
  `NN_ADE_ENFORCE=1`, a weakening the agent records in its signed audit
  log. A prompt injection that changes a recommendation is in scope; say
  whether the host had that variable set.
- Testing must be done on hosts you own or are authorised to test.
  Do not test against third-party systems running NorthNarrow.

## Disclosure

We follow coordinated disclosure: a fix is published first, then the
advisory (GitHub Security Advisory + a note in the release). Credit is
given to the reporter unless they ask otherwise.
