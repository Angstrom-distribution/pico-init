# SPDX-FileCopyrightText: 2026 Koen Kooi
# SPDX-License-Identifier: GPL-2.0-or-later

project(
  'pico-init', 'c',
  version: '0.2.1',
  license: 'GPL-2.0-or-later',
  default_options: [
    'c_std=gnu17',
    'warning_level=3',
    'werror=true',
  ],
  meson_version: '>= 0.62.0',
)

# The version PID 1 announces on the console, in two halves mirroring systemd's
# PROJECT_VERSION/GIT_VERSION pair (see status.h). A -D because vcs_tag()
# substitutes only one placeholder.
add_project_arguments('-DPICO_INIT_VERSION="' + meson.project_version() + '"', language: 'c')

# vcs_tag() runs `git describe` at build time, so a rebuild after a commit
# reports the new hash without re-running meson. The fallback covers exported
# trees without a .git.
version_h = vcs_tag(
  command: ['git', 'describe', '--always', '--dirty', '--tags'],
  fallback: 'unknown',
  input: 'src/version.h.in',
  output: 'version.h',
)

# sd-event.c/sd-event-source.c in their own static library ahead of
# pico_init_core: PID 1's manager embeds an sd_event as its main loop and needs
# only these objects, and libsystemd-compat must not depend on pico-init-core.
# sd-daemon.c rides along because sd_event_set_watchdog() calls
# sd_watchdog_enabled(). libsystemd_compat link_wholes this library back in, so
# libsystemd.so still carries every symbol.
libsystemd_compat_includes = include_directories('src/compat/libsystemd')

sd_event_lib = static_library(
  'sd-event',
  files(
    'src/compat/libsystemd/sd-event.c',
    'src/compat/libsystemd/sd-event-source.c',
    'src/compat/libsystemd/sd-daemon.c',
  ),
  include_directories: libsystemd_compat_includes,
)

# sd-id128.c split out the same way: machine-id-setup.c (pico_init_core) needs
# sd_id128_randomize()/sd_id128_to_string() and id128_read_fd().
# sha256.c/hmac-sha256.c are sd_id128_get_app_specific()'s HMAC.
# -Wno-error=nonnull-compare: upstream's char s[_SD_ARRAY_STATIC N] signatures
# (_sd-common.h) make GCC treat s as nonnull and flag upstream's own
# `if (!s) return NULL;` guard.
sd_id128_lib = static_library(
  'sd-id128',
  files(
    'src/compat/libsystemd/sd-id128.c',
    'src/compat/libsystemd/sha256.c',
    'src/compat/libsystemd/hmac-sha256.c',
  ),
  include_directories: libsystemd_compat_includes,
  c_args: ['-Wno-error=nonnull-compare'],
)

# Everything except main() builds into a static library, so the test programs
# can link the real manager, unit and job code instead of re-declaring it.
# main.c stays out of it: a second main() would collide with every test's own.
pico_init_core_sources = files(
  'src/manager.c',
  'src/manager-loop.c',
  'src/manager-shutdown.c',
  'src/manager-startup.c',
  'src/mount-setup.c',
  'src/hostname-setup.c',
  # The wall clock across reboots on a board with a dead RTC: /etc/timestamp
  # restored first thing, saved periodically and at shutdown.
  'src/clock-persist.c',
  # First-boot detection and /etc/machine-id fill-in (main.c's early boot
  # sequence, and the signal manager-startup.c gates preset application on).
  'src/machine-id-setup.c',
  # The GPT reader and the Discoverable-Partitions swap activation on top of
  # it. The parser half is also used by devd.
  'src/gpt-scan.c',
  # The ext superblock reader. Here rather than under src/devd/ because both
  # devd (naming a removable partition) and PID 1's root check (gating a
  # filesystem checker) use it.
  'src/ext-super.c',
  # Filesystem identity (UUID/LABEL) the way blkid reports it, one narrow
  # reader per on-disk format, for resolving fstab's UUID=/LABEL= sources.
  'src/fsid.c',
  'src/fsid-swap.c',
  'src/fsid-vfat.c',
  'src/fsid-exfat.c',
  'src/fsid-xfs.c',
  'src/fsid-btrfs.c',
  'src/fsid-ntfs.c',
  # The root filesystem check and the remount that ends it; the two decision
  # tables inside it are what the tests link.
  'src/root-check.c',
  # /etc/fstab: the parser, option table and outcome record, kept apart from
  # the half that mounts so the decisions can be tested as values.
  'src/fstab.c',
  # The boot-time fstab pass main.c runs between the root check and swap
  # discovery, on the kernel's new mount API.
  'src/fstab-mount.c',
  # UUID=/LABEL=/PARTUUID=/PARTLABEL= resolution by walking sysfs, and the
  # bounded wait for a device that has not appeared yet.
  'src/fstab-resolve.c',
  # ubi.mtd= read from the kernel command line and carried out through
  # /dev/ubi_ctrl, for fstab's ubifs lines when UBI is a module.
  'src/ubi-attach.c',
  'src/unit.c',
  # Template/instance name parsing, split out of unit.c because it needs
  # nothing from Unit itself.
  'src/unit-name.c',
  # %x-specifier substitution engine; knows nothing about Unit.
  'src/specifier.c',
  'src/unit-load.c',
  'src/conf-scan.c',
  'src/unit-parse.c',
  # daemon-reload (SIGHUP or the picoctl ctrl verb): re-parse each loaded
  # fragment into a scratch unit, swap the directive values in only if it
  # parsed cleanly.
  'src/unit-reload.c',
  'src/unit-dependency.c',
  'src/unit-enable.c',
  'src/service.c',
  'src/service-exec.c',
  'src/target.c',
  # Socket units.
  'src/socket.c',
  'src/job.c',
  # PID 1's runtime state publisher, control socket, and sd_notify()
  # listener.
  'src/manager-state.c',
  'src/manager-ctrl.c',
  'src/manager-notify.c',
  # PID 1's hardware watchdog feeder; the per-service software watchdog
  # (WatchdogSec=) is not implemented, see manager-watchdog.h.
  'src/manager-watchdog.c',
  'src/cgroups-v2.c',
  'src/timer.c',
  'src/signal.c',
  'src/util.c',
  'src/compat.c',
  # The boot console channel and the os-release lookup behind its greeting.
  # Separate from util.c's logging; see status.h.
  'src/status.c',
  'src/os-release.c',
)

# version_h is listed as a source so ninja generates the header before
# anything that includes status.h is compiled, not because it is compiled.
pico_init_core = static_library(
  'pico-init-core',
  pico_init_core_sources,
  version_h,
  include_directories: libsystemd_compat_includes,
  link_with: [sd_event_lib, sd_id128_lib],
)

# link_whole, not link_with: a static library only contributes referenced
# objects, which would drop unreferenced translation units and make the
# symbol-presence test below pass by omission.
pico_init_exe = executable(
  'pico-init',
  'src/main.c',
  version_h,
  include_directories: libsystemd_compat_includes,
  link_whole: pico_init_core,
  install: true,
  install_dir: get_option('sbindir'),
)

# The binary links, runs, exits 0 when not PID 1, and every public symbol from
# src/*.h is present in it.
test(
  'm0-link-and-symbols',
  find_program('src/test-m0.sh'),
  args: [pico_init_exe],
)

# Shared test scaffolding: temp unit trees, fixture writing, assertions.
pico_test_sources = files('src/test-util.c')

# Each entry becomes a test program linked against the core library.
pico_tests = [
  'test-unit-dependency',
  'test-unit-name',
  'test-specifier',
  'test-unit-load',
  'test-job',
  'test-boot-root',
  # First-boot detection and the /etc/machine-id fallback (read-only /etc,
  # inside a private mount namespace).
  'test-machine-id-setup',
  # /etc/timestamp parsing, the forward-only decision and the atomic save.
  'test-clock-persist',
  # test-service is registered further down, after the shared libsystemd
  # its Type=notify helper links.
  'test-timer-cgroup',
  # Controller enabling, child-cgroup removal and stale-cgroup reset behind Delegate=.
  'test-cgroup-delegate',
  'test-boot',
  'test-socket',
  'test-manager-state',
  'test-picoctl',
  'test-manager-ctrl',
  # The sd_notify() listener: attribution, key handling, env injection/scrub,
  # teardown, and the not-fatal-to-boot policy.
  'test-manager-notify',
  # The five /dev symlinks, and the fixture-driven unit-file parser.
  'test-dev-setup',
  'test-unit-parse',
  # SIGHUP reload: new directive values land, a bad or vanished file and a
  # busy unit change nothing, and a running process is left alone.
  'test-unit-reload',
  # The boot console channel: the os-release parser behind the greeting, and
  # the byte-level shape of what lands on the console.
  'test-status',
  # The GPT reader, against partition tables built byte by byte in the test.
  'test-gpt-scan',
  # The ext superblock reader.
  'test-ext-super',
  # The shared half of the identity readers, and the dispatcher.
  'test-fsid',
  # One test per format reader, against images built byte by byte.
  'test-fsid-swap',
  'test-fsid-vfat',
  'test-fsid-exfat',
  'test-fsid-xfs',
  'test-fsid-btrfs',
  'test-fsid-ntfs',
  # The readers against real mkfs images, compared with blkid; SKIPs
  # without blkid, and skips each format whose mkfs is not installed.
  'test-fsid-real',
  # The root check's two decision tables. The I/O half remounts "/" and is
  # covered by booting instead.
  'test-root-check',
  # The fstab grammar, option routing, mount order and outcome record.
  'test-fstab',
  # The pass against real mounts, inside a private user + mount namespace.
  'test-fstab-mount',
  # Source resolution against a fixture sysfs tree and image files, and the
  # device wait driven through its poll hook.
  'test-fstab-resolve',
  # The ubi.mtd= grammar and the attach state machine, against a fixture
  # sysfs tree and a fake UBI_IOCATT.
  'test-ubi-attach',
  # Manager-level regression test for the SIGCHLD-before-cgroup-empty
  # dispatch-order property (manager.h's EVENT_PRIORITY_* table): drives
  # m->event directly, one dispatch at a time, since manager_loop() itself
  # only exposes the final state once a whole batch has drained.
  'test-loop-order',
  # The hardware watchdog feeder: graceful degrade with no device (the
  # container/qemu case), event-priority placement, and the cannot-be-
  # starved property. Real-device ioctl negotiation and reset-on-hang need
  # target hardware -- see manager-watchdog.h and this test's own header.
  'test-manager-watchdog',
  # Orderly shutdown: waiting on running stop jobs, cancelling queued start
  # jobs, the signal-to-objective mapping and the deadline.
  'test-manager-shutdown',
  # PID 1's argv and kernel command line.
  'test-init-opts',
]

# manager.h includes sd-event.h, so every test that reaches it (through
# manager.h/socket.h/cgroups-v2.h) needs libsystemd_compat_includes on its own
# compile line: include paths of pico_init_core do not propagate.
foreach t : pico_tests
  exe = executable(
    t,
    ['src/' + t + '.c'] + pico_test_sources + [version_h],
    include_directories: libsystemd_compat_includes,
    link_with: pico_init_core,
  )
  test(t, exe)
endforeach

# Built from only the file under test, like test-netctl-rtnl/-path below, so
# no other code can mask or cause a failure.
test_pico_color_exe = executable(
  'test-pico-color',
  ['src/test-pico-color.c', 'src/pico-color.c'] + pico_test_sources,
)
test('test-pico-color', test_pico_color_exe)

# pico-unit-lint -- PID 1's unit parser run over an installed unit tree at
# build time, printing the degradation record each unit would carry in
# `picoctl show`. It links pico-init-core so the verdict matches the boot-time
# one. bindir: it is a check, not an init tool.
pico_unit_lint_exe = executable(
  'pico-unit-lint',
  'src/pico-unit-lint.c',
  version_h,
  include_directories: libsystemd_compat_includes,
  link_with: pico_init_core,
  install: true,
  install_dir: get_option('bindir'),
)

test(
  'unit-lint',
  find_program('src/test-unit-lint.sh'),
  args: [pico_unit_lint_exe],
)

# ---------------------------------------------------------------------------
# netd -- the network daemon. Built like PID 1: one static library the tests
# link, one installed binary. It links timer.c, signal.c and util.c out of
# pico-init-core rather than reimplementing the event plumbing.
# ---------------------------------------------------------------------------

# 'src/netd' only, so the lifted files under src/netd/dhcp/ can say
# "netd-compat.h" without a relative path.
#
# 'src' must not be here: GCC searches -I directories for angle-bracket
# includes too, so netd's `#include <signal.h>` would resolve to src/signal.h,
# which never includes the libc header and so hides SIGTERM. netd reaches the
# shared code as "../util.h" etc. instead.
netd_includes = include_directories('src/netd')

# netd's own code: GPL-2.0-or-later, like the rest of the project.
netd_own_sources = files(
  'src/netd/netd-loop.c',
  'src/netd/netd-link.c',
  'src/netd/netd-network.c',
  'src/netd/netd-rtnl.c',
  # Low-level rtnetlink plumbing (request construction, send/recv,
  # NLMSG_ERROR decoding, generic attribute getters), split out of
  # netd-rtnl.c so netctl_exe below can share it without linking netd_core
  # or pico_init_core -- see netd-rtnl-core.h.
  'src/netd/netd-rtnl-core.c',
  'src/netd/netd-resolv.c',
  'src/netd/netd-sntp.c',
  'src/netd/netd-time.c',
  # LLDP (IEEE 802.1AB): the frame codec, the neighbour table and the receive
  # and transmit sides. Shaped after systemd's sd-lldp-rx/-tx and lldpd.
  'src/netd/lldp/lldp-frame.c',
  'src/netd/lldp/lldp-table.c',
  'src/netd/lldp/lldp-link.c',
)

# The DHCPv4 implementation lifted from systemd v261.2 (commit 4925d9f07f).
# Each file keeps its own LGPL-2.1-or-later identifier and its upstream-derived
# name, so the quarry provenance stays legible; the combined netd binary is
# GPL-2.0-or-later as a whole, the permitted linking direction.
#
netd_dhcp_sources = files(
  'src/netd/dhcp/dhcp-message.c',
  'src/netd/dhcp/dhcp-protocol.c',
  'src/netd/dhcp/dhcp-route.c',
  'src/netd/dhcp/dhcp-lease.c',
  'src/netd/dhcp/dhcp-client-id.c',
  'src/netd/dhcp/dhcp-client.c',
  'src/netd/dhcp/dhcp-client-send.c',
  'src/netd/dhcp/dhcp-server.c',
  'src/netd/dhcp/dhcp-server-request.c',
  'src/netd/dhcp/dhcp-server-send.c',
  'src/netd/dhcp/dhcp-server-lease.c',
  # struct sd_dhcp_message embeds a TLV by value, so dhcp-message.c cannot
  # compile without tlv-util.
  'src/netd/dhcp/tlv-util.c',
  # The flat-string DNS name subset, still needed by options 12 and 15. The
  # RFC 3397 compression decoder (option 119) is not carried.
  'src/netd/dhcp/dns-name.c',
  # Third-party support, carried near-verbatim with its own licence:
  # siphash24.{c,h} is CC0-1.0. sparse-endian.h (MIT, Josh Triplett) and
  # unaligned.h (LGPL-2.1-or-later) are headers and need no entry here.
  'src/netd/dhcp/siphash24.c',
)

netd_core = static_library(
  'netd-core',
  netd_own_sources + netd_dhcp_sources,
  include_directories: netd_includes,
)

# link_whole for netd's own objects, as for pico-init-core above; link_with
# for pico-init-core, which then contributes only the util/timer/signal objects
# netd references.
netd_exe = executable(
  'netd',
  'src/netd/netd.c',
  include_directories: netd_includes,
  link_whole: netd_core,
  link_with: pico_init_core,
  install: true,
  install_dir: get_option('sbindir'),
)

# netctl, the networkctl equivalent: a client for netd (see netctl.c). bindir,
# like picolog: reading network status is not privileged. It links neither
# netd_core nor pico_init_core; it uses sysfs, getifaddrs(3), its own rtnetlink
# client (netctl-rtnl.c over netd-rtnl-core.c) and ID_PATH walk (netctl-path.c),
# and signals netd's pid with SIGHUP.
netctl_exe = executable(
  'netctl',
  [
    'src/netd/netctl.c',
    'src/netd/netctl-rtnl.c',
    'src/netd/netctl-path.c',
    'src/netd/netctl-lldp.c',
    'src/netd/netd-rtnl-core.c',
    # Shared ANSI colour helper (pico-color.h): on/off rules and escape
    # sequences mirroring real networkctl's. Not part of pico-init-core, so
    # listed directly here like netctl's other own sources.
    'src/pico-color.c',
  ],
  include_directories: netd_includes,
  install: true,
  install_dir: get_option('bindir'),
)

# $prefix/lib/systemd/system, not lib64: systemd's convention for unit files
# even on a multilib install.
install_data(
  'src/netd/netd.service',
  'src/netd/network.target',
  install_dir: get_option('prefix') / 'lib' / 'systemd' / 'system',
)

# test-netd-codec checks the wire format against fixed golden bytes, so client
# and server cannot silently share a mirrored encoding bug; test-netd-dhcp
# drives the server end to end against a scripted client over a veth pair.
netd_tests = [
  'test-netd-network',
  'test-netd-rtnl',
  'test-netd-codec',
  'test-netd-dhcp',
  'test-netd-sntp',
  # Persistent-MAC generation for a random-hardware-address link
  # (netd_persistent_mac_derive() in netd-link.c): fixed siphash24 vectors
  # against the hash key from systemd's netif-util.c, plus the exemption cases
  # (loopback, already up, NET_ADDR_PERM/SET/STOLEN, all-zero machine id).
  'test-netd-mac',
  # LLDP frame parser and builder: real frames, rejection rules, mutation run.
  'test-netd-lldp-frame',
  'test-netd-lldp-table',
  # LLDP over a veth pair in a private network namespace.
  'test-netd-lldp-link',
  # --help, --version and refused arguments.
  'test-netd-opts',
]

foreach t : netd_tests
  exe = executable(
    t,
    ['src/netd/' + t + '.c'] + pico_test_sources,
    include_directories: netd_includes,
    link_with: [netd_core, pico_init_core],
  )
  test(t, exe)
endforeach

# netctl's own tests: each built from only the one netctl-*.c file it is
# actually testing (netd-rtnl-core.c for the rtnetlink decoder,
# netctl-path.c for the ID_PATH walk) -- no link to netd_core or
# pico_init_core either way, so a bug in netctl's own code can never be
# masked by (or blamed on) netd's own rtnl code.
test_netctl_rtnl_exe = executable(
  'test-netctl-rtnl',
  ['src/netd/test-netctl-rtnl.c', 'src/netd/netctl-rtnl.c', 'src/netd/netd-rtnl-core.c'] + pico_test_sources,
  include_directories: netd_includes,
)
test('test-netctl-rtnl', test_netctl_rtnl_exe)

test_netctl_path_exe = executable(
  'test-netctl-path',
  ['src/netd/test-netctl-path.c', 'src/netd/netctl-path.c'] + pico_test_sources,
  include_directories: netd_includes,
)
test('test-netctl-path', test_netctl_path_exe)

test_netctl_lldp_exe = executable(
  'test-netctl-lldp',
  ['src/netd/test-netctl-lldp.c', 'src/netd/netctl-lldp.c'] + pico_test_sources,
  include_directories: netd_includes,
)
test('test-netctl-lldp', test_netctl_lldp_exe)

# netctl's colour output: netctl.c's own colour helpers are file-local
# statics with no header, so this runs the real built `netctl` binary as a
# subprocess instead (test-picoctl.c's own pattern) -- no link to netctl.c,
# netctl-rtnl.c or netctl-path.c at all.
test_netctl_color_exe = executable(
  'test-netctl-color',
  ['src/netd/test-netctl-color.c'] + pico_test_sources,
)
test('test-netctl-color', test_netctl_color_exe)

# netctl's options, verbs and exit statuses; same subprocess approach.
test_netctl_opts_exe = executable(
  'test-netctl-opts',
  ['src/netd/test-netctl-opts.c'] + pico_test_sources,
)
test('test-netctl-opts', test_netctl_opts_exe)

# ---------------------------------------------------------------------------
# devd -- the device hotplug daemon. Built like netd, and a separate daemon
# rather than PID 1 code so that a crash costs a unit restart, not the machine.
#
# It links pico-init-core for the event plumbing (timer.c, signal.c, util.c)
# and for gpt-scan.c and ext-super.c, which it shares with PID 1: boot-time swap
# activation and removable-media policy read partition tables through one
# parser, and the root check and by-uuid/by-label naming read ext superblocks
# through one decoder.
#
# 'src/devd' only on the include path, never 'src'; see netd_includes above.
# ---------------------------------------------------------------------------
devd_includes = include_directories('src/devd')

devd_core_sources = files(
  'src/devd/devd-loop.c',
  'src/devd/devd-uevent.c',
  'src/devd/devd-block.c',
  'src/devd/devd-probe.c',
  'src/devd/devd-symlink.c',
  'src/devd/devd-media.c',
  # The rule engine: tokenizer, matcher (reads sysfs) and the RUN+= child
  # (fork/exec), each with its own test program.
  'src/devd/devd-rules.c',
  'src/devd/devd-match.c',
  'src/devd/devd-run.c',
  'src/devd/devd-modalias.c',
  # upstream's input_id builtin, and the /run/udev/data entry its answer is
  # published through for the compat libsystemd to overlay.
  'src/devd/devd-input-id.c',
  'src/devd/devd-udev-db.c',
)

devd_core = static_library(
  'devd-core',
  devd_core_sources,
  include_directories: devd_includes,
)

devd_exe = executable(
  'devd',
  'src/devd/devd.c',
  include_directories: devd_includes,
  link_whole: devd_core,
  link_with: pico_init_core,
  install: true,
  install_dir: get_option('sbindir'),
)

install_data(
  'src/devd/devd.service',
  install_dir: get_option('prefix') / 'lib' / 'systemd' / 'system',
)

# devd's own rules file, installed beside usb-modeswitch-data's rules in
# /usr/lib/udev/rules.d (usrmerge). Serial naming is a rules file rather than
# compiled in, so it goes through the same engine as the vendor file.
install_data(
  'src/devd/60-pico-serial.rules',
  install_dir: get_option('prefix') / 'lib' / 'udev' / 'rules.d',
)

# Covered: uevent parsing, the debounce state machine, GPT/ext4 field
# extraction, the symlink create/remove/reconcile lifecycle, the rules
# tokenizer (against excerpts of the real usb-modeswitch rules file), the
# matcher and substitutions (against a sysfs tree built in the test), and the
# async RUN+= path.
devd_tests = [
  'test-devd-uevent',
  'test-devd-block',
  'test-devd-probe',
  'test-devd-symlink',
  'test-devd-rules',
  'test-devd-match',
  'test-devd-run',
  'test-devd-media',
  'test-devd-input-id',
  'test-devd-udev-db',
  # The udevd-compatible command line and udev.* kernel parameters.
  'test-devd-opts',
]

# PICO_SOURCE_DIR lets test-devd-match.c parse the rules file that is
# installed above rather than a copy of it.
foreach t : devd_tests
  exe = executable(
    t,
    ['src/devd/' + t + '.c'] + pico_test_sources,
    include_directories: devd_includes,
    c_args: ['-DPICO_SOURCE_DIR="' + meson.current_source_dir() + '"'],
    link_with: [devd_core, pico_init_core],
  )
  test(t, exe)
endforeach

# ---------------------------------------------------------------------------
# pico-tmpfiles -- systemd-tmpfiles' --create, --clean and --remove over
# tmpfiles.d. A oneshot rather than a daemon; it makes the tmpfiles.d snippets
# that oe-core packages ship take effect. tmpfiles.h lists which line types are
# implemented and which are logged and skipped.
#
# It links pico-init-core for util.c's logging and os-release.c's reader
# (behind the %o/%w/%A specifiers) and nothing else of PID 1. bindir, like
# systemd-tmpfiles itself.
# ---------------------------------------------------------------------------
tmpfiles_includes = include_directories('src/tmpfiles')

tmpfiles_core = static_library(
  'tmpfiles-core',
  files(
    'src/tmpfiles/tmpfiles-conf.c',
    'src/tmpfiles/tmpfiles-create.c',
    'src/tmpfiles/tmpfiles-clean.c',
  ),
  include_directories: tmpfiles_includes,
)

pico_tmpfiles_exe = executable(
  'pico-tmpfiles',
  'src/tmpfiles/pico-tmpfiles.c',
  include_directories: tmpfiles_includes,
  link_whole: tmpfiles_core,
  link_with: pico_init_core,
  install: true,
  install_dir: get_option('bindir'),
)

install_data(
  'src/tmpfiles/pico-tmpfiles.service',
  install_dir: get_option('prefix') / 'lib' / 'systemd' / 'system',
)

# test-tmpfiles-conf covers the grammar and the file-precedence rule against
# fixture trees under a --root; test-tmpfiles-create applies real fixtures
# and reads the inodes back, then runs the installed binary end to end (found
# next to the test via /proc/self/exe, test-picoctl.c's idiom);
# test-tmpfiles-clean does the same for --clean/--remove over inodes whose
# ages it sets itself.
tmpfiles_tests = [
  'test-tmpfiles-conf',
  'test-tmpfiles-create',
  'test-tmpfiles-clean',
]

foreach t : tmpfiles_tests
  exe = executable(
    t,
    ['src/tmpfiles/' + t + '.c'] + pico_test_sources,
    include_directories: tmpfiles_includes,
    link_with: [tmpfiles_core, pico_init_core],
  )
  test(t, exe, depends: pico_tmpfiles_exe)
endforeach

test(
  'test-tmpfiles-cli',
  find_program('src/tmpfiles/test-tmpfiles-cli.sh'),
  args: [pico_tmpfiles_exe],
)

# picoctl is defined after logd below, because it links logd's ring reader.

# ---------------------------------------------------------------------------
# logd -- the log daemon, and picolog, its reader.
#
# Same shape as netd. logd stores journald's plain-text export format in a
# bounded /run ring; the binary journal format is not implemented. Full
# journalctl compatibility is reached off-device by feeding `picolog -o export`
# to upstream's systemd-journal-remote.
#
# Nothing here is lifted from upstream, so unlike src/netd/dhcp/ it is all
# GPL-2.0-or-later.
# ---------------------------------------------------------------------------
logd_includes = include_directories('src/logd')

# The ring reader (logd-read.c) is libc-only and its own static library: the
# sd-journal read side of libsystemd-compat is built on it and must not pull
# logd_core (whose writer/receiver need pico_init_core's util.c) into every
# libsystemd consumer. logd_core link_wholes it back in.
logd_read = static_library(
  'logd-read',
  files('src/logd/logd-read.c'),
  include_directories: logd_includes,
)

logd_core_sources = files(
  'src/logd/logd-write.c',
  'src/logd/logd-recv.c',
  'src/logd/logd-kmsg.c',
)

logd_core = static_library(
  'logd-core',
  logd_core_sources,
  include_directories: logd_includes,
  link_whole: logd_read,
)

logd_exe = executable(
  'logd',
  'src/logd/logd.c',
  include_directories: logd_includes,
  link_whole: logd_core,
  link_with: pico_init_core,
  install: true,
  install_dir: get_option('sbindir'),
)

# picolog goes to bindir, not sbindir: reading the log is not a privileged
# operation and an ordinary user on a booted board should be able to run it.
picolog_exe = executable(
  'picolog',
  [
    'src/logd/picolog.c',
    # Shared ANSI colour helper (pico-color.h), mirroring real journalctl's
    # on/off rules and escape sequences.
    'src/pico-color.c',
  ],
  include_directories: logd_includes,
  link_whole: logd_core,
  link_with: pico_init_core,
  install: true,
  install_dir: get_option('bindir'),
)

# logd.socket makes logd socket-activated.
install_data(
  'src/logd/logd.service',
  'src/logd/logd.socket',
  install_dir: get_option('prefix') / 'lib' / 'systemd' / 'system',
)

logd_tests = [
  'test-logd-write',
  'test-logd-recv',
  'test-logd-kmsg',
  'test-picolog',
  # logd's options and the refused log namespace argument.
  'test-logd-opts',
]

foreach t : logd_tests
  exe = executable(
    t,
    ['src/logd/' + t + '.c'] + pico_test_sources,
    include_directories: logd_includes,
    link_with: [logd_core, pico_init_core],
  )
  test(t, exe)
endforeach

# ---------------------------------------------------------------------------
# picoctl -- the on-device systemctl equivalent.
#
# It links pico-init-core so that the enable/disable/is-enabled/preset verbs
# share unit-enable.c with boot-time loading and cannot disagree about what
# "enabled" means. It links logd-core for `picoctl status`'s per-unit log tail,
# which calls logd_ring_read_filtered() directly. Defined after logd because
# logd_core must exist first. Installed to sbindir: it is the init's own tool.
# ---------------------------------------------------------------------------
picoctl_exe = executable(
  'picoctl',
  [
    'src/picoctl.c',
    # Shared ANSI colour helper (pico-color.h), mirroring real systemctl's
    # on/off rules and escape sequences.
    'src/pico-color.c',
  ],
  include_directories: [logd_includes, libsystemd_compat_includes],
  link_with: [pico_init_core, logd_core],
  install: true,
  install_dir: get_option('sbindir'),
)

# ---------------------------------------------------------------------------
# libsystemd-compat -- an ABI-compatible reimplementation of real systemd's
# public libsystemd surface, for recipes built assuming a real systemd. It is a
# library other packages link against, so it lives apart from PID 1's code; see
# sd-daemon.c for why it never calls into util.c.
#
# sd-event, sd-daemon and sd-id128 sources are in sd_event_lib and sd_id128_lib
# above and link_whole'd below. event-internal.h is the private struct layout
# shared by sd-event.c and sd-event-source.c, never installed.
#
# sd-journal is split by concern rather than into upstream's single file:
# -send/-sendv (write API funnelling into sd_journal_sendv() over logd's
# /dev/log socket), -stream (/run/logd/stdout), -open/-navigate/-data/-info
# (a snapshot reader over logd's ring, src/logd/logd-read.h, never the binary
# .journal format) and -util. sd-journal-internal.h is private.
# ---------------------------------------------------------------------------
libsystemd_compat_sources = files(
  'src/compat/libsystemd/sd-journal-util.c',
  'src/compat/libsystemd/sd-journal-send.c',
  'src/compat/libsystemd/sd-journal-sendv.c',
  'src/compat/libsystemd/sd-journal-stream.c',
  'src/compat/libsystemd/sd-journal-open.c',
  'src/compat/libsystemd/sd-journal-navigate.c',
  'src/compat/libsystemd/sd-journal-data.c',
  'src/compat/libsystemd/sd-journal-info.c',
  # sd-bus, sd-login and sd-hwdb are split by behaviour, not by upstream's
  # file layout. sd-bus-validate.c/-path.c/-error.c are the part of sd-bus
  # that works without a bus; -open.c is every way to obtain an sd_bus* (all
  # fail, since there is no wire protocol); -stubs.c/-noop.c are the ~270
  # remaining sd_bus_*() entry points, which need a live bus object that
  # cannot exist. sd-login-resolve.c is the pid/pidfd/peer-fd resolver shared
  # by sd-login-cgroup.c (real cgroup/unit/slice getters) and sd-login.c
  # (getters that report failure).
  'src/compat/libsystemd/sd-bus-validate.c',
  'src/compat/libsystemd/sd-bus-path.c',
  'src/compat/libsystemd/sd-bus-error.c',
  'src/compat/libsystemd/sd-bus-open.c',
  'src/compat/libsystemd/sd-bus-stubs.c',
  'src/compat/libsystemd/sd-bus-noop.c',
  'src/compat/libsystemd/sd-login-resolve.c',
  'src/compat/libsystemd/sd-login-cgroup.c',
  'src/compat/libsystemd/sd-login.c',
  'src/compat/libsystemd/sd-hwdb.c',
  # sd-json: constructors, parsers and the builder fail, NULL-variant answers
  # are in -noop, the dispatcher in -dispatch. sd-path: lookups fail.
  'src/compat/libsystemd/sd-json-stubs.c',
  'src/compat/libsystemd/sd-json-noop.c',
  'src/compat/libsystemd/sd-json-dispatch.c',
  'src/compat/libsystemd/sd-path-stubs.c',
  # sd-device/sd-network: device-new.c (refcounting, the
  # sd_device_new_from_*() constructors, the parent walk), device-attr.c
  # (subsystem, driver, sysname), device-uevent.c (the property table),
  # device-db.c (the /run/udev/data overlay devd writes for input devices),
  # device-property.c (iteration plus the always-empty tag family),
  # device-devlink.c/-sysattr.c/-child.c/-trigger.c, device-enumerator.c and
  # device-monitor.c. device-internal.h is the shared private struct layout.
  # network-resolv.c/-state.c/-monitor.c are the sd-network equivalents;
  # network-internal.h holds its test-root-prefix hook.
  'src/compat/libsystemd/device-new.c',
  'src/compat/libsystemd/device-attr.c',
  'src/compat/libsystemd/device-uevent.c',
  'src/compat/libsystemd/device-db.c',
  'src/compat/libsystemd/device-property.c',
  'src/compat/libsystemd/device-devlink.c',
  'src/compat/libsystemd/device-sysattr.c',
  'src/compat/libsystemd/device-child.c',
  'src/compat/libsystemd/device-trigger.c',
  'src/compat/libsystemd/device-enumerator.c',
  'src/compat/libsystemd/device-monitor.c',
  'src/compat/libsystemd/network-resolv.c',
  'src/compat/libsystemd/network-state.c',
  'src/compat/libsystemd/network-monitor.c',
)

# The archive is the build-internal form, never installed: the tests that
# reach private hooks (device_set_sys_root_for_tests() and friends, hidden
# behind the version script's `local: *`) link it, and
# gen-libsystemd-sym.py reads its full symbol table through nm. Real
# systemd ships no static libsystemd either; a consumer lands on the .so.
libsystemd_compat = static_library(
  'systemd-compat',
  libsystemd_compat_sources,
  include_directories: libsystemd_compat_includes,
  link_whole: [sd_event_lib, sd_id128_lib, logd_read],
)

# The installed library, ${libdir}/libsystemd.so.0.<minor>.<micro> with SONAME
# libsystemd.so.0: the name, path and SONAME of real systemd's libsystemd, so
# consumers' -lsystemd resolves to it. Two version numbers go with the vendored
# libsystemd-v262.sym and change together on a systemd bump: upstream's
# libsystemd_version at that tag, and the systemd release number the .pc files
# report, since consumers gate on `systemd >= N`. meson's default b_lundef makes
# an undefined symbol a link error here rather than a load failure on the
# target.
libsystemd_version = '0.45.0'
libsystemd_compat_systemd_version = '262'
libsystemd_sym = files('src/compat/libsystemd/libsystemd.sym')
libsystemd = shared_library(
  'systemd',
  version: libsystemd_version,
  link_whole: libsystemd_compat,
  link_args: ['-Wl,--version-script=' + meson.current_source_dir() / 'src/compat/libsystemd/libsystemd.sym'],
  link_depends: libsystemd_sym,
  install: true,
)

# Not a test: the Type=notify service that test-service.c execs (found next to
# the test binary via /proc/self/exe). Links the shared library so its READY=1
# goes through the installed ABI, which is why test-service is registered here
# rather than in pico_tests.
test_notify_helper_exe = executable(
  'test-notify-helper',
  'src/test-notify-helper.c',
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test_service_exe = executable(
  'test-service',
  ['src/test-service.c'] + pico_test_sources + [version_h],
  include_directories: libsystemd_compat_includes,
  link_with: pico_init_core,
)
test('test-service', test_service_exe, depends: test_notify_helper_exe)

# libsystemd.pc for the -lsystemd consumers and systemd.pc for the larger
# population that never links anything and only asks pkg-config where
# units go (systemdsystemunitdir and its siblings). Both templates mirror
# the vendored upstream ones name for name; test-systemd-pc fails on any
# drift. Path values follow upstream's own derivation (an absolute
# libdir/sysconfdir passes through the join unchanged); the uid-range
# values are upstream's option defaults.
pc_prefix = get_option('prefix')
pc_conf = configuration_data({
  'PREFIX': pc_prefix,
  'PREFIX_NOSLASH': '/' + pc_prefix.strip('/'),
  'LIBDIR': pc_prefix / get_option('libdir'),
  'INCLUDE_DIR': pc_prefix / get_option('includedir'),
  'SYSCONF_DIR': pc_prefix / get_option('sysconfdir'),
  'PROJECT_URL': 'https://github.com/Angstrom-distribution/pico-init',
  'PROJECT_VERSION': libsystemd_compat_systemd_version,
  'SYSTEM_ALLOC_UID_MIN': 1,
  'SYSTEM_UID_MAX': 999,
  'SYSTEM_ALLOC_GID_MIN': 1,
  'SYSTEM_GID_MAX': 999,
  'GREETER_UID_MIN': 60578,
  'GREETER_UID_MAX': 60705,
  'DYNAMIC_UID_MIN': 61184,
  'DYNAMIC_UID_MAX': 65519,
  'CONTAINER_UID_BASE_MIN': 524288,
  'CONTAINER_UID_BASE_MAX': 1878982656,
  'FOREIGN_UID_BASE': 2147352576,
})
pkgconfig_dir = get_option('libdir') / 'pkgconfig'
libsystemd_pc = configure_file(
  input: 'src/compat/libsystemd/libsystemd.pc.in',
  output: 'libsystemd.pc',
  configuration: pc_conf,
  install: true,
  install_dir: pkgconfig_dir,
)
systemd_pc = configure_file(
  input: 'src/compat/libsystemd/systemd.pc.in',
  output: 'systemd.pc',
  configuration: pc_conf,
  install: true,
  install_dir: pkgconfig_dir,
)

# Consumers expect "systemd/sd-daemon.h" etc., the layout of a real
# systemd-devel package. _sd-common.h is installed too, as upstream does: it is
# a quoted include and resolves against the installed header's own directory.
libsystemd_public_headers = files(
  'src/compat/libsystemd/sd-daemon.h',
  'src/compat/libsystemd/sd-event.h',
  'src/compat/libsystemd/sd-id128.h',
  'src/compat/libsystemd/sd-journal.h',
  'src/compat/libsystemd/_sd-common.h',
  'src/compat/libsystemd/sd-bus.h',
  'src/compat/libsystemd/sd-bus-protocol.h',
  'src/compat/libsystemd/sd-bus-vtable.h',
  'src/compat/libsystemd/sd-login.h',
  'src/compat/libsystemd/sd-hwdb.h',
  'src/compat/libsystemd/sd-device.h',
  'src/compat/libsystemd/sd-network.h',
  'src/compat/libsystemd/sd-json.h',
  'src/compat/libsystemd/sd-path.h',
)
install_headers(libsystemd_public_headers, subdir: 'systemd')

# Symbol versions are real systemd's, so a binary linked against real
# libsystemd (sd_bus_message_append@LIBSYSTEMD_209) resolves against this
# library too. libsystemd.sym is generated: the upstream libsystemd-v262.sym
# (verbatim from systemd's v262 tag) intersected with what the archive
# defines, each symbol on its upstream node, except the sd_network_* family
# (not exported by upstream's libsystemd) on a trailing PICO_LIBSYSTEMD_0. A
# systemd version bump is: replace the upstream file,
# `ninja regen-libsystemd-sym`, review the diff. test-libsystemd-sym fails
# on a stale committed file, on a public header declaring an undefined
# function, and on an sd_*-named internal helper leaking out of the archive.
libsystemd_sym_gen = files('tools/gen-libsystemd-sym.py')
libsystemd_sym_upstream = files('src/compat/libsystemd/libsystemd-v262.sym')
python3 = find_program('python3', required: false)
nm = find_program('nm', required: false)
if python3.found() and nm.found()
  libsystemd_sym_args = [libsystemd_sym_gen, '--upstream', libsystemd_sym_upstream, '--nm', nm.full_path(), '--archive', libsystemd_compat]
  foreach h : libsystemd_public_headers
    libsystemd_sym_args += ['--header', h]
  endforeach
  test('test-libsystemd-sym', python3, args: libsystemd_sym_args + ['--check', libsystemd_sym])
  run_target(
    'regen-libsystemd-sym',
    command: [python3] + libsystemd_sym_args + ['--summary', '-o', meson.current_source_dir() / 'src/compat/libsystemd/libsystemd.sym'],
  )
endif

if python3.found()
  check_pc = files('tools/check-pc.py')
  test('test-libsystemd-pc', python3, args: [check_pc, '--upstream', files('src/compat/libsystemd/libsystemd-v262.pc.in'), '--generated', libsystemd_pc])
  test('test-systemd-pc', python3, args: [check_pc, '--upstream', files('src/compat/libsystemd/systemd-v262.pc.in'), '--generated', systemd_pc])
endif

# A built .so checked as the file a consumer gets: SONAME, the
# version-definition table against its version script's nodes, every
# listed symbol resolving at its node through dlvsym(), private helpers
# (one named per link_whole'd or internal family) hidden, and an RTLD_NOW
# load that fails on any undefined symbol. Shared with libudev.so below.
test_versioned_so_exe = executable(
  'test-versioned-so',
  ['src/compat/test-versioned-so.c'] + pico_test_sources,
  dependencies: dependency('dl'),
)
test(
  'test-libsystemd-so',
  test_versioned_so_exe,
  args: [libsystemd, libsystemd_sym, 'libsystemd.so.0',
         'logd_ring_read', 'hmac_sha256', 'event_source_new', 'device_new_bare', 'journal_current_entry'],
)

# Tests that only use the installed headers link the shared library, so
# the versioned export list is what they exercise; the ones below that
# reach private test hooks (*-internal.h) link the archive instead.
test_sd_daemon_exe = executable(
  'test-sd-daemon',
  ['src/compat/libsystemd/test-sd-daemon.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-daemon', test_sd_daemon_exe)

test_sd_event_exe = executable(
  'test-sd-event',
  ['src/compat/libsystemd/test-sd-event.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-event', test_sd_event_exe)

test_sd_id128_exe = executable(
  'test-sd-id128',
  ['src/compat/libsystemd/test-sd-id128.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd_compat,
)
test('test-sd-id128', test_sd_id128_exe)

# sd-journal's read side resolves its logd_ring_*() calls from logd_read,
# link_whole'd into libsystemd_compat above, so this links exactly what an
# external consumer would: the compat library alone. The fixture writes
# logd's export format itself rather than through logd-write.h, whose
# writer needs pico_init_core.
test_sd_journal_read_exe = executable(
  'test-sd-journal-read',
  ['src/compat/libsystemd/test-sd-journal-read.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-journal-read', test_sd_journal_read_exe)

test_sd_journal_send_exe = executable(
  'test-sd-journal-send',
  ['src/compat/libsystemd/test-sd-journal-send.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-journal-send', test_sd_journal_send_exe)


# sd-bus/sd-login/sd-hwdb tests. test-sd-bus-stubs/-noop call every function
# in sd-bus-stubs.c/sd-bus-noop.c, so a wrong signature or return value fails
# the test rather than only compiling.
test_sd_bus_validate_exe = executable(
  'test-sd-bus-validate',
  ['src/compat/libsystemd/test-sd-bus-validate.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-bus-validate', test_sd_bus_validate_exe)

test_sd_bus_path_exe = executable(
  'test-sd-bus-path',
  ['src/compat/libsystemd/test-sd-bus-path.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-bus-path', test_sd_bus_path_exe)

test_sd_bus_error_exe = executable(
  'test-sd-bus-error',
  ['src/compat/libsystemd/test-sd-bus-error.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-bus-error', test_sd_bus_error_exe)

test_sd_bus_open_exe = executable(
  'test-sd-bus-open',
  ['src/compat/libsystemd/test-sd-bus-open.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-bus-open', test_sd_bus_open_exe)

test_sd_bus_stubs_exe = executable(
  'test-sd-bus-stubs',
  ['src/compat/libsystemd/test-sd-bus-stubs.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-bus-stubs', test_sd_bus_stubs_exe)

test_sd_bus_noop_exe = executable(
  'test-sd-bus-noop',
  ['src/compat/libsystemd/test-sd-bus-noop.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-bus-noop', test_sd_bus_noop_exe)

test_sd_json_exe = executable(
  'test-sd-json',
  ['src/compat/libsystemd/test-sd-json.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-json', test_sd_json_exe)

test_sd_path_exe = executable(
  'test-sd-path',
  ['src/compat/libsystemd/test-sd-path.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-path', test_sd_path_exe)

# Creates and removes real /sys/fs/cgroup/system.slice/*.service directories
# and moves a forked child into them, so needs root.
test_sd_login_cgroup_exe = executable(
  'test-sd-login-cgroup',
  ['src/compat/libsystemd/test-sd-login-cgroup.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-login-cgroup', test_sd_login_cgroup_exe)

test_sd_login_exe = executable(
  'test-sd-login',
  ['src/compat/libsystemd/test-sd-login.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-login', test_sd_login_exe)

test_sd_hwdb_exe = executable(
  'test-sd-hwdb',
  ['src/compat/libsystemd/test-sd-hwdb.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd,
)
test('test-sd-hwdb', test_sd_hwdb_exe)

# sd-device.c/sd-network.c getters against a real /sys or /dev fixture
# (device-internal.h's device_set_sys_root_for_tests()/
# device_set_dev_root_for_tests(), network-internal.h's
# network_set_root_for_tests()), plus a handful of assertions against the
# real host's own /sys, /dev/null and loopback interface where a fixture
# would prove nothing (test-sd-device-new.c, test-sd-device-monitor.c).
libsystemd_compat_device_tests = [
  'test-sd-device-new',
  'test-sd-device-uevent',
  'test-sd-device-db',
  'test-sd-device-sysattr',
  'test-sd-device-devlink',
  'test-sd-device-enumerator',
  'test-sd-device-monitor',
  'test-sd-network',
  'test-sd-network-monitor',
]

foreach t : libsystemd_compat_device_tests
  exe = executable(
    t,
    ['src/compat/libsystemd/' + t + '.c'] + pico_test_sources,
    include_directories: libsystemd_compat_includes,
    link_with: libsystemd_compat,
  )
  test(t, exe)
endforeach

# ---------------------------------------------------------------------------
# libudev shim -- ${libdir}/libudev.so.1 with real libudev's SONAME, symbol
# versions (libudev-v262.sym, all 92 exports on their upstream nodes) and
# libudev.pc, for consumers that want the library rather than the daemon. As
# upstream does, every udev_* entry point is a thin wrapper over sd_device_*,
# so the shared object links libsystemd.so.0 and carries no device code.
#
# udev_device_*, udev_enumerate_*, udev_list_entry_* and udev_monitor_* are
# real; udev_queue_*/udev_hwdb_* report the true no-udevd/no-hwdb state.
# ---------------------------------------------------------------------------
libudev_includes = include_directories('src/compat/libudev')
libudev_sources = files(
  'src/compat/libudev/libudev.c',
  'src/compat/libudev/libudev-list.c',
  'src/compat/libudev/libudev-device.c',
  'src/compat/libudev/libudev-enumerate.c',
  'src/compat/libudev/libudev-monitor.c',
  'src/compat/libudev/libudev-queue.c',
  'src/compat/libudev/libudev-hwdb.c',
  'src/compat/libudev/libudev-util.c',
)

# Build-internal archive, never installed: the fixture-driven tests link
# it together with libsystemd_compat to reach the /sys test hooks, and the
# sym generator reads its symbol table through nm.
libudev_compat = static_library(
  'udev-compat',
  libudev_sources,
  include_directories: libsystemd_compat_includes,
)

# Upstream's libudev_version at v262; bump with the vendored files.
libudev_version = '1.7.15'
libudev_sym = files('src/compat/libudev/libudev.sym')
libudev = shared_library(
  'udev',
  version: libudev_version,
  link_whole: libudev_compat,
  link_with: libsystemd,
  link_args: ['-Wl,--version-script=' + meson.current_source_dir() / 'src/compat/libudev/libudev.sym'],
  link_depends: libudev_sym,
  install: true,
)

install_headers('src/compat/libudev/libudev.h')

libudev_pc = configure_file(
  input: 'src/compat/libudev/libudev.pc.in',
  output: 'libudev.pc',
  configuration: pc_conf,
  install: true,
  install_dir: pkgconfig_dir,
)

# udev.pc is a separate package from libudev.pc: consumers run
# `pkg-config --variable=udevdir udev` (e.g. alsa-utils), and only "udev"
# carries udevdir. Without it they fall back to a hardcoded /lib/udev/rules.d.
# The path matches devd's rules install location.
udev_pc = configure_file(
  input: 'src/compat/libudev/udev.pc.in',
  output: 'udev.pc',
  configuration: pc_conf,
  install: true,
  install_dir: pkgconfig_dir,
)

if python3.found()
  test('test-udev-pc', python3, args: [check_pc, '--upstream', files('src/compat/libudev/udev-v262.pc.in'), '--generated', udev_pc])
endif

if python3.found() and nm.found()
  libudev_sym_args = [
    libsystemd_sym_gen,
    '--upstream', files('src/compat/libudev/libudev-v262.sym'),
    '--nm', nm.full_path(),
    '--archive', libudev_compat,
    '--header', files('src/compat/libudev/libudev.h'),
    '--prefix', 'udev_',
    '--pico-node', 'PICO_LIBUDEV_0',
    '--regen-target', 'regen-libudev-sym',
  ]
  test('test-libudev-sym', python3, args: libudev_sym_args + ['--check', libudev_sym])
  run_target(
    'regen-libudev-sym',
    command: [python3] + libudev_sym_args + ['--summary', '-o', meson.current_source_dir() / 'src/compat/libudev/libudev.sym'],
  )
endif

if python3.found()
  test('test-libudev-pc', python3, args: [check_pc, '--upstream', files('src/compat/libudev/libudev-v262.pc.in'), '--generated', libudev_pc])
endif

test(
  'test-libudev-so',
  test_versioned_so_exe,
  args: [libudev, libudev_sym, 'libudev.so.1', 'libudev_list_new', 'libudev_device_new'],
)

# test-libudev-device/-enumerate drive the wrappers against a fixture /sys
# through the compat archives; test-libudev-monitor links the installed .so.
foreach t : ['test-libudev-device', 'test-libudev-enumerate']
  exe = executable(
    t,
    ['src/compat/libudev/' + t + '.c'] + pico_test_sources,
    include_directories: [libudev_includes, libsystemd_compat_includes],
    link_with: [libudev_compat, libsystemd_compat],
  )
  test(t, exe)
endforeach

test_libudev_monitor_exe = executable(
  'test-libudev-monitor',
  ['src/compat/libudev/test-libudev-monitor.c'] + pico_test_sources,
  include_directories: libudev_includes,
  link_with: libudev,
)
test('test-libudev-monitor', test_libudev_monitor_exe)
