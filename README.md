# pico-init

A small, systemd-inspired PID1 for constrained embedded Linux targets —
starting with [Angstrom Linux](https://github.com/koenkooi)'s `angstrom-pico`
distro, aimed at 200MHz-class hardware with roughly 64MiB of RAM.

## What this is

systemd's actual design — cgroups-based process supervision, declarative
units, dependency-ordered startup — is the right architecture even on a
constrained device. Its footprint is not: a full systemd stack costs
somewhere around 15–20MiB of RAM on a device that only has 64MiB to begin
with. pico-init keeps the architecture and rebuilds the implementation at a
much smaller scale, in C, quarrying real systemd source where that's the
fastest path to something correct rather than reimplementing everything from
a man page.

**Status: real, boots.** The PID1 core, `netd`, `devd`, and `logd` are
implemented, tested, and boot-validated — `console-pico-image` reaches a
login prompt with a working getty on every qemu test machine this project
targets. PID1's own main loop is a real `sd_event` consumer (the same
architecture modern systemd's own PID1 has always used), with a real
`sd_notify()` listener and a hardware-watchdog feeder built on top of it.
A `libsystemd-compat` shim (`src/compat/libsystemd/`) gives third-party
software written against real systemd's public API a genuine, mostly-real
implementation to link against under pico-init. Template/`%i` unit
instancing is partially built (unit-name parsing and fallback loading
land; generic-getty generation is still open). Resource-control/sandboxing
and a DRM-based boot splash are designed but not yet implemented.

## Scoping

The real design decisions — what gets quarried from systemd, cgroups v1 vs
v2, where the network stack comes from, how much of journald survives, the
DHCP-timezone story — were made against a 2011-era-systemd feasibility study
and a scoping dialog with the maintainer, then refined against real
implementation experience as each subsystem landed. Summary:

- **PID1 core**: quarried from systemd's ~2011-era unit parser, dependency
  engine, and service state machine — not a literal fork, not written from
  spec. The main loop itself is a real `sd_event` consumer, quarried from
  *current* systemd's `src/core/manager.c` for that specific shape.
- **cgroups**: v2 (unified), matching every modern kernel default.
- **Networking**: a minimal from-scratch `netd` speaking `.network`-file
  syntax, built on lifted `sd-dhcp`/`sd-netlink` source rather than
  hand-rolled DHCP or the whole of modern `systemd-networkd`.
- **Logging**: `logd`, a from-scratch syslog/journal-analogue daemon (not
  the real binary journal format) plus a slim `journalctl`-equivalent
  reader; no rate-limiting, sealing, or remote forwarding.
- **Time**: an integrated minimal SNTP client with a DHCP option 100/101
  hook inside `netd`. For boards whose RTC is dead or reset by a reboot,
  PID1 keeps the wall clock roughly right on its own: it restores
  `/etc/timestamp` (the OpenEmbedded file, `YYYYMMDDHHMMSS` UTC) before any
  service starts, saves it two minutes after boot, every ten minutes and
  at shutdown, and only ever moves the clock forward, to the largest of the
  saved time, the file's mtime and a build epoch. NTP corrects the rest.
- **systemd compatibility**: `libsystemd-compat`, a real/honest-failure/
  no-op shim over the public `sd-*` API surface (`sd-daemon`, `sd-event`,
  `sd-id128`, `sd-journal`, `sd-bus`/`sd-login`/`sd-hwdb`, `sd-device`/
  `sd-network`) — real wherever pico-init has a genuine equivalent
  mechanism, an honest error where it categorically doesn't, never a
  faked success.
- **Unit-file degradation is on the record**: a real systemd unit loads
  even when pico-init cannot honour every directive in it, and every drop
  is recorded on the unit — `picoctl show` reports it as
  `Degraded-Directives=`, PID 1 logs one warning per unit at load and one
  summary line once the boot has settled, and `pico-unit-lint DIR...` runs
  the same parser over an installed unit tree at build time so the gap is
  visible in a build log before anything boots.
- **Build system**: meson.

## License

**GPL-2.0-or-later**, not required-by-preference but required-by-fact:
systemd was GPL-2.0-or-later until its 2012 relicensing to
LGPL-2.1-or-later, and the PID1 core here is quarried from ~2011-era
systemd source — code that predates that relicensing. Quarrying
GPL-2.0-or-later source makes the resulting work GPL-2.0-or-later as a
whole (GPL terms propagate; there's no picking a more permissive license for
the combined work). Later-quarried subsystems (`netd`'s `sd-dhcp`/
`sd-netlink` lifts, the `libsystemd-compat` shim's public API contract)
read *current* systemd instead (post-relicense, LGPL-2.1-or-later) for
design shape and API contract only, never copied — those files carry
their own per-file LGPL-2.1-or-later license tag where source is genuinely
lifted, following the file-level exception pattern in
[`REUSE.toml`](REUSE.toml)/[`LICENSES/`](LICENSES/), same idea as systemd's
own per-file licensing scheme, simplified. GPL-2.0-or-later code linking
against LGPL-2.1-or-later code is fine; the reverse wouldn't be.

Every source file carries an
[SPDX license identifier](https://spdx.dev/learn/handling-license-info/);
full license text lives in [`LICENSES/`](LICENSES/).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). This repository is currently
private; no tagged release exists yet, so expect the process to keep
firming up as it does.

## Security

See [`SECURITY.md`](SECURITY.md) for how to report a vulnerability. PID1 is
the process the kernel panics without — security issues here matter more
than in most software.
