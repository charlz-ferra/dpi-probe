# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting instead: the **Security** tab of
this repository → **Report a vulnerability** (or the "Report a vulnerability"
button under _Advisories_). It opens a private channel between you and the
maintainer — no email, no identity required on either side.

When you report, include:

- what the issue is and where (file / line / function),
- a minimal way to reproduce or trigger it,
- the impact you think it has.

You'll get an acknowledgement as soon as it's seen. Confirmed issues are fixed
on a priority branch and disclosed via a GitHub Security Advisory once a fix is
released; credit is offered unless you prefer to stay anonymous.

## Scope

This project is a defensive, read-only tool. The things most worth reporting:

- a check or probe that reports a **false `PASS`/clean** (a real risk hidden),
- any path where the tool **writes, mutates, or transmits** something it
  shouldn't (it is meant to only read and report),
- command/argument injection or unsafe handling of untrusted input.

## Out of scope

- Findings the tool produces about _your_ host — that's it doing its job.
- Issues in third-party dependencies; report those upstream.
