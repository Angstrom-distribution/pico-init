# Hacking on pico-init

This document covers building pico-init, running its test suite, the checks
CI enforces (formatting and license headers), how to add a test, and where
things live in the source tree. For the overall design see
[ARCHITECTURE.md](ARCHITECTURE.md); for style rules beyond what
clang-format enforces see [CODING_STYLE.md](CODING_STYLE.md); for debugging a
running system see [DEBUGGING.md](DEBUGGING.md).

## Build

pico-init is a meson project written in C (`gnu17`). `warning_level=3` and
`werror=true` are the project defaults, so a new warning breaks the build.
The minimum meson version is 0.62.0. `meson.build` defines no project options
of its own; the usual built-in options (`--prefix`, `--libdir`, `--buildtype`
and so on) apply.

```
meson setup build
ninja -C build
```

For packaging in a distribution see [DISTRO_PORTING.md](DISTRO_PORTING.md).

The only non-libc build requirements are `git` (the version string is
produced by `git describe --always --dirty --tags` at build time and falls
back to `unknown` outside a git tree), `dl` (`dependency('dl')`, used by the
shared-object tests, and required at configure time), and optionally
`python3` and `nm`. Without both `python3` and `nm` the libsystemd and
libudev symbol-set tests and the `regen-*-sym` targets are not defined;
without `python3` the pkg-config template tests are not defined. The
`m0-link-and-symbols` smoke test (`src/test-m0.sh`) always runs and calls
`nm` itself, so it needs `nm` on `PATH`.

### What gets built

- `pico-init` (PID 1), `picoctl` (control client), `netd`, `devd` and
  `logd` install to `sbindir`.
- `pico-unit-lint` (runs the unit parser over an installed tree), `netctl`,
  `picolog` and `pico-tmpfiles` install to `bindir`.
- `libsystemd.so` and `libudev.so` install to `libdir`; see
  [COMPATIBILITY_LIBRARIES.md](COMPATIBILITY_LIBRARIES.md).
- Daemon details are in [NETD.md](NETD.md), [DEVD.md](DEVD.md) and
  [LOGD.md](LOGD.md).

The unit files for netd (`netd.service` and `network.target`), devd, logd
(`logd.service` and `logd.socket`) and pico-tmpfiles are installed under
`$prefix/lib/systemd/system` (never `lib64`), and the devd udev rule under
`$prefix/lib/udev/rules.d`. Public headers go to `includedir/systemd` and
`libudev.h` to `includedir`, with the `libsystemd`, `systemd`, `libudev` and
`udev` `.pc` files in `libdir/pkgconfig`.

## Running the tests

```
meson test -C build --print-errorlogs
```

Run one test, or list them:

```
meson test -C build test-unit-name --print-errorlogs
meson test -C build --list
```

Run the whole suite as root, as CI does:

```
sudo -E meson test -C build --print-errorlogs
```

Some tests need privileges. Without them they either skip (exit status 77,
which meson reports as SKIP) or, in a few cases, fail. CI runs the suite
under `sudo -E` and its comment states that "unprivileged they fail rather
than skip". What each group needs, as read from the tests:

- `test-cgroup-delegate` (last case), `test-boot` and `test-timer-cgroup`
  need a writable cgroup2 hierarchy under `/sys/fs/cgroup`, which means
  root. `test-boot` creates `pico-boot-test-<pid>` there. Without it they
  skip (77).
- `test-service` skips its cgroup membership and KillMode checks when it
  cannot use a cgroup. Its `User=`/`Group=` privilege-drop case needs root
  and runs the failed-drop path instead when `getuid() != 0`.
- `test-fstab-mount`, `test-machine-id-setup` and `test-root-check` run in a
  private user and mount namespace (`unshare(CLONE_NEWUSER|CLONE_NEWNS)`),
  which works unprivileged. They skip (77) if the host refuses user
  namespaces.
- `test-netd-rtnl`, `test-netd-dhcp` and `test-netd-lldp-link` use veth pairs
  in a network namespace made with `unshare(CLONE_NEWUSER|CLONE_NEWNET)`.
  They exit 1 if the namespace cannot be created; see below.
- `test-fsid-real` needs `blkid` and the relevant `mkfs` tools, and skips
  (77) per format.
- `test-picoctl` needs `systemctl` on `PATH` for its comparison cases, and
  exits 77 without it.
- `test-logd-write` needs `systemd-journal-remote` for the real-oracle round
  trip. Without it the local cases run, then it exits 77.
- `test-tmpfiles-create` skips its ownership assertions unless
  `geteuid() == 0`.

The netd namespace tests do not skip when the namespace cannot be created:
each prints that it cannot prove isolation and exits 1. The `test-netd-dhcp`
and `test-netd-rtnl` source headers explain that a bare
`unshare(CLONE_NEWNET)` fails with `EPERM` without `CAP_SYS_ADMIN`, while a
fresh user namespace that creates the network namespace in the same call owns
it and so holds `CAP_NET_ADMIN` inside it. The tests use that form. If the
host disables unprivileged user namespaces, run them as root. `test-netd-sntp`
runs a fake UDP/123 responder on loopback and needs no namespace.

Tests that skip print the reason on stderr. A skipped test is not a pass: read
the log before concluding that a run covered the code you changed.

### Test groups

- PID 1 core: `src/test-*.c`, for example `test-unit-parse`, `test-job`,
  `test-service`, `test-manager-ctrl`, `test-fstab` and `test-fsid-*`.
- Smoke: `src/test-m0.sh` checks that the binary links, runs and exits 0 when
  it is not PID 1, and that a fixed list of core symbols is present.
- Unit lint: `src/test-unit-lint.sh` runs `pico-unit-lint` against a fixture
  tree and asserts the output lines and exit statuses.
- netd: `src/netd/test-*.c`, for example `test-netd-codec`,
  `test-netd-lldp-frame` and `test-netctl-path`.
- devd: `src/devd/test-*.c`, for example `test-devd-rules` and
  `test-devd-uevent`.
- logd: `src/logd/test-*.c`, for example `test-logd-recv` and `test-picolog`.
- tmpfiles: `src/tmpfiles/test-*.c`, for example `test-tmpfiles-conf` and
  `test-tmpfiles-clean`.
- Compatibility libraries: `src/compat/` holds `test-sd-*` and
  `test-libudev-*` programs plus the symbol-set and pkg-config checks.

The compatibility library checks go beyond unit tests of the functions.
`test-libsystemd-sym` and `test-libudev-sym` compare the symbols exported
by the static archive and the public headers against the checked-in version
script and the upstream symbol file. The `-pc` tests diff the generated
`.pc` files against the upstream templates, and the `-so` tests load the
built shared object and check its version nodes. After changing the exported
set, regenerate the version scripts with:

```
ninja -C build regen-libsystemd-sym regen-libudev-sym
```

and commit the result. See
[COMPATIBILITY_LIBRARIES.md](COMPATIBILITY_LIBRARIES.md).

## Formatting

The style is defined by `.clang-format`, based on systemd's own file
(without its `ForEachMacros` and `IncludeCategories` lists): 8-column
indentation with no tabs, a 109-column limit, `AlwaysBreak` after open
brackets, one argument or parameter per line once a call is broken, and
pointer stars on the right. CI uses clang-format 18 and the version is
pinned, because a different major version can change the output without any
source change. Check:

```
find src -name '*.c' -o -name '*.h' | xargs -r clang-format-18 --dry-run --Werror
```

Reformat in place:

```
git ls-files 'src/*.[ch]' | xargs clang-format-18 -i -style=file
```

Format only the files you touched; do not mix a reformat of unrelated files
into a functional change.

## License headers

The project is REUSE compliant. Every source file carries SPDX headers on its
first lines:

```c
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */
```

Files that are not suited to inline headers are covered by annotations in
`REUSE.toml`. Verbatim third-party and upstream-derived files keep their own
identifiers (the DHCPv4 code under `src/netd/dhcp/` is
LGPL-2.1-or-later, `siphash24.c` is CC0-1.0), and the license texts live in
`LICENSES/`. Check locally with:

```
reuse lint
```

## Continuous integration

`.github/workflows/ci.yml` runs on pushes to `main` and on pull requests;
a newer run for the same ref cancels the older one. It has three
independent jobs, all on `ubuntu-latest`:

- `build` installs `meson` and `ninja-build`, then runs `meson setup build`,
  `ninja -C build` and `sudo -E meson test -C build --print-errorlogs`.
- `format` installs `clang-format-18` and runs the dry-run check above with
  `--Werror`.
- `reuse` runs `fsfe/reuse-action` for the license compliance check.

All three must pass before a change is merged (see `CONTRIBUTING.md`). To
reproduce the `build` job, run the commands from the Build and Running the
tests sections; to reproduce the other two, use the commands in the
Formatting and License headers sections.

## Source layout

Everything is under `src/`.

- `src/main.c`: PID 1 entry point and early boot sequence.
- `src/manager*.c`: manager core, event loop, startup, shutdown, state
  publisher, control socket, `sd_notify()` listener and hardware watchdog.
- `src/unit*.c`, `src/specifier.c`, `src/conf-scan.c`: unit objects, name
  parsing, file parser, dependencies, enablement and presets, reload.
- `src/service*.c`, `src/socket.c`, `src/timer.c`, `src/target.c`,
  `src/job.c`: unit types and the job queue. `src/timer.c` is an internal
  timerfd helper, not a unit type.
- `src/cgroups-v2.c`: cgroup v2 handling behind `Delegate=`.
- `src/mount-setup.c`, `src/fstab*.c`, `src/fsid*.c`, `src/gpt-scan.c`,
  `src/ext-super.c`, `src/root-check.c`, `src/ubi-attach.c`: API file systems,
  fstab, filesystem identity, partition scanning, root check.
- `src/hostname-setup.c`, `src/machine-id-setup.c`, `src/clock-persist.c`:
  early boot state.
- `src/status.c`, `src/os-release.c`, `src/pico-color.c`: boot console output.
- `src/signal.c`, `src/util.c`, `src/compat.c`: signalfd handling, shared
  helpers and logging, and the shims for quarried code.
- `src/picoctl.c`, `src/pico-unit-lint.c`: client tools.
- `src/netd/`: network daemon, `netctl`, `lldp/`, and `dhcp/` (code lifted
  from systemd).
- `src/devd/`: device daemon and its udev-rule engine.
- `src/logd/`: log daemon and `picolog`.
- `src/tmpfiles/`: `pico-tmpfiles`.
- `src/compat/libsystemd/`, `src/compat/libudev/`: compatibility libraries
  and their symbol files.
- `tools/`: `gen-libsystemd-sym.py` and `check-pc.py`.
- `src/test-*.c` and `src/*/test-*.c`: tests, next to the code they test.

`meson.build` builds the code of each program, except its `main()`, into a
static library (`pico-init-core`, `netd-core`, `devd-core`, `logd-core`,
`tmpfiles-core`). The tests link those libraries, so they exercise the real
code instead of copies. The executable links the library with `link_whole`
so no object is dropped. Only `src/main.c` is outside `pico-init-core`,
because a second `main()` would collide with every test's own.

`netd` is built with only `src/netd` on its include path because GCC
searches `-I` directories for angle-bracket includes too, and `src/signal.h`
would otherwise shadow the libc `<signal.h>`; shared code is reached there as
`"../util.h"`.

## Adding a test

1. Create `src/test-<name>.c` (or `src/<daemon>/test-<name>.c` for a daemon
   or library). Start with the two SPDX comment lines.
2. Include `test-util.h` and use its helpers: `ASSERT_TRUE`,
   `ASSERT_EQ_INT`, `ASSERT_STREQ` (each prints file, line and expression
   and exits 1), `test_tmpdir_new()` and `test_rm_rf()` for a scratch
   directory, `test_write_file()`, `test_mkdir()` and `test_symlink()` for
   fixtures, `test_enter_mount_namespace()` for tests that mount, and the
   fixture builders such as `test_block_device()` and `test_image_write()`.
3. Write a `main()` that calls each case and ends with a
   `printf("test-<name>: all checks passed\n"); return 0;`. Exit non-zero on
   failure and 77 to skip with the reason printed to stderr.
4. Register it in `meson.build`. For the PID 1 core, add the file stem to
   the `pico_tests` list; a test in that list is linked against
   `pico-init-core` together with `src/test-util.c`. The daemon sections have
   their own lists (`netd_tests`, `devd_tests`, `logd_tests`,
   `tmpfiles_tests`, `libsystemd_compat_device_tests`) with the right
   libraries and include directories. A test of a single file that should not
   link the rest, like `test-pico-color` or `test-netctl-path`, gets an
   explicit `executable()` and `test()` pair built from only the file under
   test.
5. Build against fixtures, not the host. Use a temporary tree and the
   `*_path` parameters the code under test already takes; a test that must
   touch the real system (cgroups, mounts, network) must skip when it cannot,
   and should say which privilege it needed.
6. Run `meson test -C build <name> --print-errorlogs` as a normal user and as
   root, then format with clang-format-18.

A test that needs a helper process built from another source file (the
`Type=notify` helper of `test-service`) declares it with `depends:` on the
test and builds it with the library it needs; see `test-notify-helper` in
`meson.build`. A test that reads files from the source tree (the devd tests
load `src/devd/60-pico-serial.rules`) gets `PICO_SOURCE_DIR` from `c_args`.

## Submitting changes

Open a pull request against `main`. Keep commits scoped to one logical
change and explain the reason in the message. Changes that alter scope,
meaning what is quarried from systemd and what is written fresh, or which
systemd behaviors are kept or dropped, should be raised in an issue first.
See `CONTRIBUTING.md`, and [RELEASE.md](RELEASE.md) for releases.
