# Security Policy

Pico-init is PID1 on any system that runs it: it is the parent of every
other process, it owns the cgroup hierarchy, and if it crashes the
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

- What component is affected (PID1 core, `netd`, `logd`, `devd`, the compatibility libraries, etc.)
- Reproduction steps or a minimal test case
- The potential impact (privilege escalation, denial of service, memory
  corruption, etc.)

## Supported versions

Only the `main` branch and the most recent tagged release are supported;
there are no older versions to backport a fix to.

## Response

This is presently a single-maintainer, part-time project. There is no SLA,
but security reports will be prioritized over ordinary feature work.
