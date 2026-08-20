# Security Policy

pico-init is PID1 on any system that runs it: it is the parent of every
other process, it owns the cgroup hierarchy, and if it exits unexpectedly the
kernel panics. Security issues here have a larger blast radius than in most
software, and are treated accordingly.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for a suspected security
vulnerability. Instead, use
[GitHub's private vulnerability reporting](../../security/advisories/new)
for this repository, or email the maintainer directly (see the GitHub
profile at [github.com/koenkooi](https://github.com/koenkooi) for contact
details).

Include, where possible:

- What component is affected (PID1 core, `netd`, the journal reader, etc.)
- Reproduction steps or a minimal test case
- The potential impact (privilege escalation, denial of service, memory
  corruption, etc.)

## Supported versions

This project is pre-release. Until a first tagged version exists, only the
`main` branch is supported — there is no older version to backport a fix to.
This section will be updated once real releases exist.

## Response

This is presently a single-maintainer, part-time project. There is no SLA,
but security reports will be prioritized over ordinary feature work.
