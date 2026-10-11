# Compatibility Libraries

Pico-init installs two shared libraries with the names, SONAMEs, header
layout, pkg-config files and symbol versions of the real ones:
`libsystemd.so.0` and `libudev.so.1`. A package built against systemd's
`libsystemd` or `libudev` links and loads against them unchanged. They are
not ports of systemd's code: each entry point is reimplemented over what
pico-init has (`logd`, `netd`, `devd`, cgroups, sysfs), and where nothing
backs an interface it returns the error real libsystemd returns on a system
without that component. This document lists which is which.

For the daemons the libraries talk to, see [LOGD.md](LOGD.md),
[NETD.md](NETD.md) and [DEVD.md](DEVD.md).

## What is installed

| File | Content |
|------|---------|
| `${libdir}/libsystemd.so.0.42.0` | SONAME `libsystemd.so.0` |
| `${libdir}/libudev.so.1.7.12` | SONAME `libudev.so.1`, links `libsystemd.so.0` |
| `${includedir}/systemd/sd-*.h` | `sd-daemon`, `sd-event`, `sd-id128`, `sd-journal`, `sd-bus`, `sd-bus-protocol`, `sd-bus-vtable`, `sd-login`, `sd-hwdb`, `sd-device`, `sd-network`, `_sd-common.h` |
| `${includedir}/libudev.h` | libudev API |
| `${libdir}/pkgconfig/libsystemd.pc` | `-lsystemd` |
| `${libdir}/pkgconfig/libudev.pc` | `-ludev` |
| `${libdir}/pkgconfig/systemd.pc` | directory and uid-range variables, no `Libs` |
| `${libdir}/pkgconfig/udev.pc` | `udevdir` |

The library file versions (`0.42.0`, `1.7.12`) are upstream's
`libsystemd_version` and `libudev_version` at the release the symbol files
were taken from. No static library is installed.

## Symbol versioning

The ABI contract is that a binary linked against real libsystemd runs
against this one. A versioned reference such as
`sd_bus_message_append@LIBSYSTEMD_209` or `udev_new@LIBUDEV_183` is only
answered by a library whose version script assigns the symbol to that exact
node, so the nodes are not designed here. `tools/gen-libsystemd-sym.py`
derives them:

- The input is upstream's version script for systemd v259, vendored as
  `src/compat/libsystemd/libsystemd-v259.sym` and
  `src/compat/libudev/libudev-v259.sym`.
- A symbol the compat archive defines, that a public header declares and
  that upstream lists, gets its upstream node, in upstream's order.
- A symbol the archive defines and a header declares, but upstream does not
  export from `libsystemd.so` (the `sd_network_*` family, which upstream
  keeps in an internal library), goes on one trailing node,
  `PICO_LIBSYSTEMD_0`, whose parent is `LIBSYSTEMD_259`. `libudev.so` has
  the equivalent `PICO_LIBUDEV_0`, omitted when empty.
- Everything else is `local`. Internal helpers are not exported.
- A public header that declares a function the archive does not define, or
  an archive that defines an `sd_*`/`udev_*` name no public header
  declares, is a generator error.

The result is committed as `libsystemd.sym` and `libudev.sym`. The `.pc`
version, which consumers compare with `systemd >= N`, is `259` for all four
files; it is the release the symbol files match.

Upstream names that are absent from `libsystemd.so.0`: the `sd_json_*` and
`sd_varlink_*` families (216 names) and `sd_path_lookup`,
`sd_path_lookup_strv` (218 in all). A program that references one fails to
load with an undefined-symbol error; there is no stub. `libudev.so.1` exports
all 92 names of the vendored upstream file.

Regenerate and check:

```
ninja -C build regen-libsystemd-sym
ninja -C build regen-libudev-sym
meson test -C build test-libsystemd-sym test-libudev-sym \
    test-libsystemd-so test-libudev-so
```

`test-libsystemd-so` and `test-libudev-so` run `src/compat/test-versioned-so.c`
against the built file: SONAME, the version definition table against the
script's nodes, `dlvsym()` of every listed symbol at its node, private
helpers hidden, and a `dlopen(RTLD_NOW)` that fails on any undefined
symbol.

## libsystemd

Status per interface. "Real" means it does what the API documents, backed by
pico-init. "Error" means it returns the stated error. "No-op" means a
success or empty answer that does nothing.

| Interface | Status |
|-----------|--------|
| `sd-daemon` | Real. `sd_notify*`, `sd_listen_fds*`, `sd_is_*`, `sd_booted`, `sd_watchdog_enabled`, `sd_pidfd_get_inode_id` (`-EOPNOTSUPP` without pidfs). `sd_pid_notify_with_fds()` and `sd_pid_notifyf_with_fds()` return `-EOPNOTSUPP` when passed fds: there is no fd store. |
| `sd-id128` | Real. Machine and boot ids are cached per thread. |
| `sd-event` | Real: epoll loop, all source types, accessors. Exceptions below. |
| `sd-journal` write side | Real, over `logd`. See below. |
| `sd-journal` read side | Real snapshot reader over `logd`'s ring. See below. |
| `sd-bus` | No bus. See [D-Bus-dependent programs](#d-bus-dependent-programs). |
| `sd-login` | Cgroup-derived calls are real; everything else reports no logind. See below. |
| `sd-hwdb` | Error. No `hwdb.bin` reader exists. |
| `sd-device` | Real over sysfs and netlink. Partial. See below. |
| `sd-network` | Partly real, mostly `-EOPNOTSUPP`. See below. |

### sd-event

All source constructors are implemented. Not implemented, each returning
`-EOPNOTSUPP`:

- `sd_event_add_memory_pressure()`.
- `sd_event_add_child()` with `WSTOPPED` or `WCONTINUED`; only exit is
  observed (pidfd based).
- Rate limiting: `sd_event_source_set_ratelimit()` and
  `sd_event_source_set_ratelimit_expire_callback()` fail,
  `sd_event_source_get_ratelimit()` returns `-ENOEXEC` and
  `sd_event_source_is_ratelimited()` returns 0.
- `sd_event_set_watchdog(e, 1)` when `WATCHDOG_USEC`/`WATCHDOG_PID` say the
  watchdog is enabled for this process: the loop does not ping, so the call
  fails. When the watchdog is not enabled for the process it succeeds and
  does nothing.

### sd-journal

Writing goes to `logd`'s `/dev/log` socket. `sd_journal_sendv()` is the one
function that talks to it; `sd_journal_print*()` and `sd_journal_send*()`
build on it. Only `MESSAGE`, `PRIORITY`, `SYSLOG_FACILITY` and
`SYSLOG_IDENTIFIER` are transported; other fields (`CODE_FILE`,
`MESSAGE_ID`, application fields) are dropped. As upstream, a missing
`/dev/log` (`ENOENT`) is reported as success.

`sd_journal_stream_fd()` connects to `/run/logd/stdout`. The priority
is range-checked but, like the identifier, not transported, and
`level_prefix` does not interpret `<N>` prefixes. The namespace variant
fails with `-EOPNOTSUPP` when given a namespace name.

Reading is a snapshot of the ring `logd` keeps under `/run/logd` (see
[LOGD.md](LOGD.md)), not the binary `.journal` format. Cursors are
pico-specific (`b=<bootid>;m=<monotonic>;r=<realtime>`), so a cursor from a
real journal fails `sd_journal_seek_cursor()` with `-EINVAL`. Errors:

| Call | Result |
|------|--------|
| `sd_journal_open_directory*`, `sd_journal_open_files*`, `sd_journal_open_container` | `-EOPNOTSUPP` |
| `sd_journal_open_namespace` with a namespace name | `-EOPNOTSUPP` |
| `sd_journal_add_disjunction`, `sd_journal_add_conjunction` | `-EOPNOTSUPP`; matches are a flat AND of ORs |
| `sd_journal_get_seqnum` | `-EOPNOTSUPP` |

### sd-login

Pico-init is not logind and registers no sessions, seats or users. The
errno contract is upstream's for a system where logind is absent.

- Real: `sd_pid_get_cgroup`, `sd_pid_get_unit`, `sd_pid_get_slice` and their
  `sd_pidfd_*` and `sd_peer_*` siblings. Services run in
  `system.slice/<unit>.service`, so `/proc/<pid>/cgroup` gives the answer.
- `sd_pid_get_session`, `sd_pid_get_owner_uid`, `sd_pid_get_user_unit`,
  `sd_pid_get_user_slice`, `sd_pid_get_machine_name` and the `pidfd`/`peer`
  forms: `-ENODATA` once the process resolves.
- `sd_session_*` and `sd_seat_*` on a named object: `-ENXIO`; on a NULL
  session or seat: `-ENODATA`.
- `sd_uid_get_state()` is `"offline"`; `sd_uid_get_sessions()`,
  `sd_uid_get_seats()`, `sd_get_seats()`, `sd_get_sessions()`,
  `sd_get_uids()` and `sd_get_machine_names()` succeed with an empty result;
  `sd_machine_get_class()` is `".host"`.
- `sd_login_monitor_new()` returns `-ENOENT`, the error upstream gives when
  `/run/systemd/<category>` is missing.

### sd-device

Backed by `/sys`, `/dev` and the uevent netlink socket, with `devd`'s
`/run/udev/data` entries overlaid (see [DEVD.md](DEVD.md)). Constructors,
parent walk, subsystem/driver/sysname, sysattr read and write,
`sd_device_trigger()`, `sd_device_open()`, the enumerator with its filters,
and the monitor with its userspace filters are real.

Limits: the udev database is written by `devd` for input devices only, so
other devices have no `ID_*` properties beyond the uevent; the tag set is
always empty; `sd_device_monitor_attach_event()` and
`sd_device_monitor_detach_event()` return `-EOPNOTSUPP`, and
`sd_device_monitor_get_event()` and `sd_device_monitor_get_event_source()`
return NULL. Poll `sd_device_monitor_get_fd()` instead.

### sd-network

The real library reads systemd-networkd's `/run/systemd/netif` files. These
read `netd`'s state under `/run/netd` instead (see [NETD.md](NETD.md)).

- Real: `sd_network_get_dns()`, `sd_network_get_search_domains()` and
  `sd_network_get_route_domains()`, from the `resolv.conf` `netd` writes;
  `sd_network_link_get_stat()`, a `stat()` of the link's lease file.
- `sd_network_monitor_new()`: an inotify watch on `/run/netd/leases`.
  Category `"leases"` works; `"links"` and NULL return `-EOPNOTSUPP`.
- Everything else, including all global and per-link state getters and
  `sd_network_get_ntp()`, returns `-EOPNOTSUPP`. It is not `-ENODATA`
  because callers such as `systemd-networkd-wait-online` treat `-ENODATA` as
  "not yet" and retry forever; `-EOPNOTSUPP` says this is not networkd.
  Per-link calls return `-EINVAL` first for `ifindex <= 0`.

The `sd_network_*` symbols are on the `PICO_LIBSYSTEMD_0` node.

## libudev

`libudev.so.1` is a thin wrapper over `sd_device_*`, as upstream's is, and
links `libsystemd.so.0`. `udev_device_*`, `udev_enumerate_*`,
`udev_list_entry_*` and `udev_monitor_*` are real, with libudev's calling
convention (NULL or 0 plus `errno`). `udev_monitor_new_from_netlink()`
accepts `"kernel"` and `"udev"` and wires both to the kernel uevent group,
since nothing rebroadcasts without `udevd`.
`udev_device_new_from_environment()` is supported.

| Interface | Status |
|-----------|--------|
| `udev_queue_*` | The state of a system with no `udevd`: `/run/udev/control` and `/run/udev/queue` do not exist. |
| `udev_hwdb_new()` | NULL with `errno = ENOENT`. |
| `udev_set_log_fn()` and the log priority calls | Accepted; the priority is stored, the function is never called. |

The properties a libudev consumer sees for an input device include
`ID_INPUT_TOUCHSCREEN` and the other classification `devd` writes, which is
why Xorg and libinput work without changes.

## pkg-config

`libsystemd.pc` and `libudev.pc` have the shape of the upstream files and
`Version: 259`. `systemd.pc` carries the same variables as upstream's, name
for name, so recipes that run

```
pkg-config --variable=systemdsystemunitdir systemd
```

get the directory pico-init reads units from. `udev.pc` carries `udevdir`
(`${prefix}/lib/udev`) for consumers such as alsa-utils. Two tests,
`test-libsystemd-pc` and `test-systemd-pc` (and the libudev equivalents),
run `tools/check-pc.py`, which fails if a variable is missing or reordered,
a value that upstream does not template differs, or a placeholder is left
unexpanded.

## Linking a program

Headers are under `systemd/`, except `libudev.h`:

```c
#include <systemd/sd-daemon.h>
#include <libudev.h>
```

```
cc -o app app.c $(pkg-config --cflags --libs libsystemd libudev)
```

Because the symbol versions match, a binary built elsewhere against real
libsystemd needs no rebuild, as long as it uses none of the missing families
listed above.

## D-Bus-dependent programs

There is no D-Bus implementation: no wire protocol, no bus connection, no
`dbus-daemon` client. The entry points exist so that programs compile,
link and take their no-bus path.

What works, because it involves no connection:

- `sd_bus_error_*`: the error struct, `sd_bus_error_set*()`, `_free()`,
  `_copy()`, `_has_name()`, `_get_errno()` and `sd_bus_error_add_map()`.
- Name validation: `sd_bus_interface_name_is_valid()`,
  `sd_bus_service_name_is_valid()`, `sd_bus_member_name_is_valid()`,
  `sd_bus_object_path_is_valid()`.
- Path encoding: `sd_bus_path_encode()`, `sd_bus_path_decode()` and the
  `_many` forms.
- The vtable macros in `sd-bus-vtable.h` (`SD_BUS_VTABLE_START`,
  `SD_BUS_METHOD`, `SD_BUS_SIGNAL`, `SD_BUS_PROPERTY`) and
  `sd_bus_object_vtable_format`, so existing vtable definitions compile.
- `sd_bus_ref()`, `sd_bus_unref()` and the other ref/unref calls return
  NULL; `sd_bus_close()` does nothing.

What fails, so that no sd_bus object can exist:

| Call | Result |
|------|--------|
| `sd_bus_open_system()`, `sd_bus_default_system()`, `sd_bus_open()` | `-ENOENT` |
| `sd_bus_open_user()`, `sd_bus_default_user()` | `-ENOENT` if `XDG_RUNTIME_DIR` is set, else `-ENOMEDIUM` |
| `sd_bus_open_system_remote()`, `_machine()` | `-EOPNOTSUPP` |
| `sd_bus_new()`, `sd_bus_creds_new_from_pid()` | `-EOPNOTSUPP` |
| every other call taking a bus, message, slot, track or creds | `-EINVAL`, no output parameter touched, no callback invoked |

`sd_bus_get_event()` returns NULL, `sd_bus_track_count()` returns 0 and
`sd_bus_track_contains()` returns NULL, since their return types cannot
carry an error.

In practice: a program that opens the system bus, checks the return value
and carries on without it (the pattern for optional logind, timedated or
hostnamed integration) behaves as on a system with no `dbus-daemon`. A
program whose purpose is a bus service or client, such as NetworkManager,
a polkit agent or `bluez`, cannot work against these libraries. An image
that ships a real `dbus-daemon` and needs `sd-bus` must use real
libsystemd instead.

## Tests

Each interface family has a `test-sd-*` or `test-libudev-*` target in
`meson.build`. `test-sd-bus-stubs` and `test-sd-bus-noop` call every
function in the stub files, so a wrong signature or return value fails the
test and does not only compile. Device and network tests run against a
fixture `/sys`, `/dev` or `/run/netd` through private hooks, so they link
the build-internal archives rather than the shared objects; the others link
the installed `.so`.

See also [DEBUGGING.md](DEBUGGING.md) and [../README.md](../README.md).
