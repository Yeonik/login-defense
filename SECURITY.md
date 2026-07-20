# Security Policy

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue.

Two ways, either is fine:

- **GitHub Security Advisories** — [open a private report](https://github.com/Yeonik/login-defense/security/advisories/new)
  (preferred: it keeps the discussion attached to the repository).
- **Email** — kirelitom@gmail.com

Helpful things to include: the affected version or commit, what an attacker
gains, and the smallest set of conditions needed to reach the behaviour. A short
description of the impact is more useful than a long one of the mechanism.

**Response time:** you can expect an initial reply within a few days. If a report
turns out to be valid, the fix and the disclosure timeline will be agreed with
you before anything is published. Credit is given unless you ask otherwise.

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅        |

## About this repository

`login-defense` is a **portfolio repository**. It is not deployed to production
anywhere, and it holds no user data, no credentials and no live infrastructure —
so there is no running system to attack.

Reports are still very welcome. The package is real, working code that others may
install, and a flaw in the escalation logic, the key strategy, or the captcha
verification would be a genuine bug worth fixing. Findings about the *design* —
a way the escalation ladder could be bypassed, a key-strategy tradeoff handled
wrongly — are as valuable here as an implementation bug.

Please keep reports free of working exploit code; a description of the conditions
and the impact is enough, and it matches how this repository treats the topic
everywhere else.
