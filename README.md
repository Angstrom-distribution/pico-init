# pico-init

A small, systemd-inspired PID1 for constrained embedded Linux targets —
starting with [Angstrom Linux](https://github.com/koenkooi)'s `angstrom-pico`
distro, aimed at ARMv5TE-class hardware with roughly 64MiB of RAM.

## What this is

systemd's actual design — cgroups-based process supervision, declarative
units, dependency-ordered startup — is the right architecture even on a
constrained device. Its footprint is not: a full systemd stack costs
somewhere around 15–20MiB of RAM on a device that only has 64MiB to begin
with. pico-init keeps the architecture and rebuilds the implementation at a
much smaller scale, in C, quarrying real systemd source where that's the
fastest path to something correct rather than reimplementing everything from
a man page.

**Status: pre-code.** This repository currently holds only a build-system
scaffold (meson, a placeholder binary, a placeholder test) so CI has
something real to exercise from the first commit. No PID1 logic exists yet.

## Scoping

The real design decisions — what gets quarried from systemd, cgroups v1 vs
v2, where the network stack comes from, how much of journald survives, the
DHCP-timezone story — were made against a 2011-era-systemd feasibility study
and a scoping dialog with the maintainer. A proper design doc belongs in
this repository once real implementation work starts; for now, the summary:

- **PID1 core**: quarried from systemd's ~2011-era unit parser, dependency
  engine, and service state machine — not a literal fork, not written from
  spec.
- **cgroups**: v2 (unified), matching every modern kernel default.
- **Networking**: a minimal from-scratch `netd` speaking `.network`-file
  syntax, built on lifted `sd-dhcp`/`sd-netlink` source rather than
  hand-rolled DHCP or the whole of modern `systemd-networkd`.
- **Logging**: journald's binary format plus a slim `journalctl`-equivalent
  reader; no rate-limiting, sealing, or remote forwarding.
- **Time**: an integrated minimal SNTP client with a DHCP option 100/101
  hook inside `netd`.
- **Build system**: meson.

## License

**GPL-2.0-or-later**, not required-by-preference but required-by-fact:
systemd was GPL-2.0-or-later until its 2012 relicensing to
LGPL-2.1-or-later, and the PID1 core here is planned to be quarried from
~2011-era systemd source — code that predates that relicensing. Quarrying
GPL-2.0-or-later source makes the resulting work GPL-2.0-or-later as a
whole (GPL terms propagate; there's no picking a more permissive license for
the combined work). `netd`'s planned `sd-dhcp`/`sd-netlink` lifts come from
*modern* systemd instead (post-relicense, LGPL-2.1-or-later) — those files
will carry their own `SPDX-License-Identifier: LGPL-2.1-or-later` tags per
the file-level exception pattern in [`REUSE.toml`](REUSE.toml)/[`LICENSES/`](LICENSES/),
same idea as systemd's own per-file licensing scheme, simplified. GPL-2.0-or-later
code linking against LGPL-2.1-or-later code is fine; the reverse wouldn't
be.

Every source file carries an
[SPDX license identifier](https://spdx.dev/learn/handling-license-info/);
full license text lives in [`LICENSES/`](LICENSES/).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). This repository is currently
private and pre-code; expect the process to firm up once real design work
starts.

## Security

See [`SECURITY.md`](SECURITY.md) for how to report a vulnerability. PID1 is
the process the kernel panics without — security issues here matter more
than in most software.
