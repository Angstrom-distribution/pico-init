# SPDX-FileCopyrightText: 2026 Koen Kooi
# SPDX-License-Identifier: GPL-2.0-or-later

project(
  'pico-init', 'c',
  version: '0.1.0',
  license: 'GPL-2.0-or-later',
  default_options: [
    'c_std=gnu17',
    'warning_level=3',
    'werror=true',
  ],
  meson_version: '>= 0.62.0',
)

# The version PID 1 announces on the console. Two halves, mirroring systemd's
# own PROJECT_VERSION/GIT_VERSION pair -- see status.h for what each is for.
#
# A -D rather than a second generated header: vcs_tag() substitutes exactly one
# placeholder, so carrying the project version through it too would mean
# chaining a configure_file() into it for what one compiler flag does.
add_project_arguments('-DPICO_INIT_VERSION="' + meson.project_version() + '"', language: 'c')

# vcs_tag() runs `git describe` at BUILD time rather than configure time, so a
# rebuild after a commit reports the new hash without anyone re-running meson.
#
# The fallback is not decoration: an OE build compiles whatever the fetcher
# unpacked, which may be an exported tree with no .git in it at all, and a
# board that says "unknown" is telling the truth about what it was built from.
version_h = vcs_tag(
  command: ['git', 'describe', '--always', '--dirty', '--tags'],
  fallback: 'unknown',
  input: 'src/version.h.in',
  output: 'version.h',
)

# sd-event.c/sd-event-source.c, hoisted into their own tiny static library
# ahead of pico_init_core: PID 1's own manager (manager.c/manager-loop.c)
# embeds an sd_event as its main loop and needs just these objects, not the
# rest of libsystemd-compat (sd-bus, sd-device, ...), and vice versa
# libsystemd-compat must not depend on pico-init-core. sd-daemon.c rides
# along too, purely as a link dependency: sd_event_set_watchdog() calls its
# real sd_watchdog_enabled() env parser, and pulling in the .o that defines
# it means every consumer of this small library must resolve that symbol
# too, whether or not it ever calls the watchdog path. The full
# libsystemd_compat static library below link_wholes this back in rather
# than listing these three files directly among its own sources, so the
# libsystemd.so built from it still carries every symbol it always did.
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

# sd-id128.c hoisted the same way, for the same reason: machine-id-setup.c
# (pico_init_core) needs sd_id128_randomize()/sd_id128_to_string() and
# id128_read_fd(), not the rest of libsystemd-compat (sd-bus, sd-journal,
# ...), and vice versa libsystemd_compat must not depend on pico-init-core.
# sha256.c/hmac-sha256.c ride along because they are sd-id128.c's own
# -- sd_id128_get_app_specific()'s HMAC -- not a separate public API.
# -Wno-error=nonnull-compare: sd-id128.c's char s[_SD_ARRAY_STATIC N]
# parameters are real systemd's own upstream signature (_sd-common.h), and
# the defensive `if (!s) return NULL;` alongside them is real systemd's own
# style too -- GCC's nonnull-compare treats the [static N] bound as an
# implicit nonnull contract and flags the very check that guards against a
# caller violating it. Real behavior, not a bug; scoped to this one warning.
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
  # it (plans/31, Slice A). In the core library rather than beside main.c
  # because the parser half is meant to have a second consumer later.
  'src/gpt-scan.c',
  # The ext superblock reader (plan §10). Here rather than under src/devd/
  # because it has two consumers that are two different binaries: devd names a
  # removable partition from it, and PID 1's root check gates a filesystem
  # checker on it.
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
  # The root filesystem check and the remount that ends it (plan §10, R1).
  # Beside gpt-scan.c for the same reason: it is boot-path code main.c calls
  # once, and the two decision tables inside it are what the tests link.
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
  # Template/instance name parsing (G2), split out of unit.c because it
  # needs nothing from Unit itself -- unit.c calls into it, not vice versa.
  'src/unit-name.c',
  # %x-specifier substitution engine (G2): knows nothing about Unit, so it
  # is its own file rather than folded into unit.c, mirroring v30's split.
  'src/specifier.c',
  'src/unit-load.c',
  'src/conf-scan.c',
  'src/unit-parse.c',
  # daemon-reload (SIGHUP or the picoctl ctrl verb): re-parse each loaded fragment into a scratch
  # unit, swap the directive values in only if it parsed cleanly.
  'src/unit-reload.c',
  'src/unit-dependency.c',
  'src/unit-enable.c',
  'src/service.c',
  'src/service-exec.c',
  'src/target.c',
  # Socket units (plan §1.6): a third unit type extending this same core,
  # not a separate daemon.
  'src/socket.c',
  'src/job.c',
  # PID 1's own runtime state publisher, control socket, and sd_notify()
  # listener (plan §1.7). All three are wired into unit.c/job.c/
  # manager-loop.c/service-exec.c already; see their headers for why the
  # hooks live at those choke points.
  'src/manager-state.c',
  'src/manager-ctrl.c',
  'src/manager-notify.c',
  # PID 1's hardware watchdog feeder. The per-service software watchdog
  # (WatchdogSec=/Type=notify) is separate, deferred scope -- see
  # manager-watchdog.h.
  'src/manager-watchdog.c',
  'src/cgroups-v2.c',
  'src/timer.c',
  'src/signal.c',
  'src/util.c',
  'src/compat.c',
  # The boot console channel and the os-release lookup behind its greeting
  # (plan §1.8). Separate from util.c's logging on purpose; status.h says why.
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

# link_whole, not link_with: a static library only contributes the object
# files something references, which would silently drop any translation unit
# PID 1 has not wired up yet (service-exec.c, compat.c) and make the M0
# symbol-presence test below pass by omission. The binary should contain the
# init it claims to be.
pico_init_exe = executable(
  'pico-init',
  'src/main.c',
  version_h,
  include_directories: libsystemd_compat_includes,
  link_whole: pico_init_core,
  install: true,
  install_dir: get_option('sbindir'),
)

# M0 acceptance: the binary links, runs, exits 0 when not PID 1, and every
# public symbol from src/*.h is present in the linked binary.
test(
  'm0-link-and-symbols',
  find_program('src/test-m0.sh'),
  args: [pico_init_exe],
)

# Shared test scaffolding: temp unit trees, fixture writing, assertions.
pico_test_sources = files('src/test-util.c')

# Each entry becomes a test program linked against the core library. Every
# milestone's test is registered here up front, placeholder or not, so that
# adding one never means editing this file while another milestone is also
# editing it.
pico_tests = [
  'test-unit-dependency',
  'test-unit-name',
  'test-specifier',
  'test-unit-load',
  'test-job',
  'test-boot-root',
  # First-boot detection and the /etc/machine-id fallback (read-only /etc,
  # inside a private mount namespace), beside the manager-startup.c tests
  # whose first-boot gating this feeds.
  'test-machine-id-setup',
  # /etc/timestamp parsing, the forward-only decision and the atomic save.
  'test-clock-persist',
  # test-service is registered further down, after the shared libsystemd
  # its Type=notify helper links.
  'test-timer-cgroup',
  'test-boot',
  # Socket activation (plan §1.6) and picoctl (plan §1.7), registered up
  # front and placeholder-bodied for exactly the reason above.
  'test-socket',
  'test-manager-state',
  'test-picoctl',
  'test-manager-ctrl',
  # The sd_notify() listener (plan §1.7 follow-on): attribution, key
  # handling, env injection/scrub, teardown, and the not-fatal-to-boot policy.
  'test-manager-notify',
  # D0's five /dev symlinks (plan §1.8), and the fixture-driven unit-file
  # parser test the §7 unit-test item asks for.
  'test-dev-setup',
  'test-unit-parse',
  # SIGHUP reload: new directive values land, a bad or vanished file and a
  # busy unit change nothing, and a running process is left alone.
  'test-unit-reload',
  # The boot console channel: the os-release parser behind the greeting, and
  # the byte-level shape of what lands on the console.
  'test-status',
  # The GPT reader (plans/31, Slice A), against real partition tables built
  # byte by byte in the test itself.
  'test-gpt-scan',
  # The ext superblock reader, moved here with the code it covers when that
  # code left src/devd/ to gain its second consumer (plan §10).
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
  # The root check's two decision tables (plan §10, R1). The I/O half of it
  # remounts "/" and is proven by a boot instead.
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
]

# manager.h now pulls in sd-event.h, so every test that reaches it
# (transitively, through manager.h/socket.h/cgroups-v2.h) needs
# libsystemd_compat_includes on its own compile line too -- a quoted
# #include inside manager.h resolves against manager.h's own directory
# first, then the including translation unit's search path, never
# pico_init_core's.
foreach t : pico_tests
  exe = executable(
    t,
    ['src/' + t + '.c'] + pico_test_sources + [version_h],
    include_directories: libsystemd_compat_includes,
    link_with: pico_init_core,
  )
  test(t, exe)
endforeach

# pico-color's own test: like test-netctl-rtnl/test-netctl-path below, built
# from only the one file it tests -- no link to pico_init_core, so a bug
# there can never be masked by (or blamed on) the rest of PID 1.
test_pico_color_exe = executable(
  'test-pico-color',
  ['src/test-pico-color.c', 'src/pico-color.c'] + pico_test_sources,
)
test('test-pico-color', test_pico_color_exe)

# pico-unit-lint -- PID 1's own unit parser run over an installed unit tree
# at build time, printing the degradation record each unit would carry in
# `picoctl show`. It links pico-init-core so the verdict cannot drift from
# the boot-time one. bindir, not sbindir: it is a check, not an init tool.
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
# netd -- the network daemon (plan §2). A second executable in the same tree,
# built exactly like PID 1: one static library the tests link, one installed
# binary. It lives here rather than in its own repo because the recipe already
# fetches this one, and because one build means one test harness and one REUSE
# tree.
#
# netd does not reimplement PID 1's event plumbing: it links timer.c, signal.c
# and util.c out of pico-init-core, so the loop in src/netd/netd-loop.c is a
# thin epoll wrapper over already-tested code rather than a second
# implementation of the same thing.
# ---------------------------------------------------------------------------

# 'src/netd' only, so the lifted files under src/netd/dhcp/ can say
# "netd-compat.h" without a relative path.
#
# 'src' is deliberately NOT here, and that is not a style preference. GCC
# searches -I directories for angle-bracket includes too, so putting src/ on
# the include path makes netd's own `#include <signal.h>` resolve to this
# project's src/signal.h -- which documents that it never includes the libc
# header, and so hides SIGTERM from every netd translation unit. netd reaches
# the shared code as "../util.h" / "../timer.h" / "../signal.h" instead, which
# is explicit about crossing out of netd into the PID 1 core and cannot shadow
# a system header.
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
)

# The DHCPv4 implementation lifted from systemd v261.2 (commit 4925d9f07f).
# Each file keeps its own LGPL-2.1-or-later identifier and its upstream-derived
# name, so the quarry provenance stays legible; the combined netd binary is
# GPL-2.0-or-later as a whole, the permitted linking direction.
#
# Placeholders at N0, and registered now on purpose: it means N2 and N3 add
# code to files that already exist and are already built, instead of editing
# this file while another milestone is also editing it.
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
  # tlv-util is not optional: struct sd_dhcp_message embeds a TLV by value, so
  # dhcp-message.c cannot compile without it. Missing from the plan's quarry
  # table; found by the quarry-history review.
  'src/netd/dhcp/tlv-util.c',
  # The flat-string DNS name subset. Options 12 and 15 still route through it
  # even with 81/162/119 dropped, so dns-domain.c does not disappear entirely
  # the way the plan assumed -- only its RFC 3397 compression decoder does.
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

# link_whole for netd's own objects, for the reason spelled out above
# pico-init-core; link_with for pico-init-core itself, which then contributes
# only the shared util/timer/signal objects netd actually references and none
# of PID 1.
netd_exe = executable(
  'netd',
  'src/netd/netd.c',
  include_directories: netd_includes,
  link_whole: netd_core,
  link_with: pico_init_core,
  install: true,
  install_dir: get_option('sbindir'),
)

# networkctl -- a client for netd, not a second copy of it (see netctl.c's own
# header). bindir, not sbindir: reading network status is not a privileged
# operation, matching picolog's own reasoning; aliased as "networkctl" by the
# recipe's ALTERNATIVE, same mechanism as picoctl -> systemctl. No link to
# netd_core or pico_init_core at all -- it talks to the kernel directly
# (sysfs + getifaddrs(3) + its own netctl-rtnl.c rtnetlink client, built from
# netd-rtnl-core.c only, and its own netctl-path.c ID_PATH walk) and to netd's
# pid only via SIGHUP, not through any of netd's own internals.
netctl_exe = executable(
  'netctl',
  [
    'src/netd/netctl.c',
    'src/netd/netctl-rtnl.c',
    'src/netd/netctl-path.c',
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

# netd's own units (plan §2.7): $prefix/lib/systemd/system, not
# $prefix/lib64 -- systemd's own convention for unit files even on a
# multilib install, and the path meta-angstrom's recipe's FILES:netd already
# expects (${nonarch_libdir}/systemd/system).
install_data(
  'src/netd/netd.service',
  'src/netd/network.target',
  install_dir: get_option('prefix') / 'lib' / 'systemd' / 'system',
)

# All of netd's tests, registered up front and placeholder-bodied, for exactly
# the reason the PID 1 list above gives: N1 through N4 are independent of each
# other, and none of them should have to touch this file.
#
# test-netd-codec is a fifth program where the plan (section 2.8) named four,
# and the split is deliberate. That section asks for golden-byte codec tests
# "so client and server can't silently share a mirrored wire-format bug", and
# folding them into test-netd-dhcp would put the codec, the client and the
# server in one file owned by three different implementers working in
# parallel -- the precise file-collision shape the previous milestone's
# retrospective asked to design out. test-netd-codec covers the wire format
# against fixed bytes; test-netd-dhcp stays the end-to-end client-vs-server
# pairing over a veth pair.
netd_tests = [
  'test-netd-network',
  'test-netd-rtnl',
  'test-netd-codec',
  'test-netd-dhcp',
  'test-netd-sntp',
  # Persistent-MAC generation for a random-hardware-address link
  # (netd-link.c's link_apply_persistent_mac()) -- fixed siphash24 vectors
  # against the documented upstream key, plus the exemption cases
  # (loopback, already up, NET_ADDR_PERM/SET/STOLEN, all-zero machine id).
  'test-netd-mac',
  # LLDP frame parser and builder: real frames, rejection rules, mutation run.
  'test-netd-lldp-frame',
  'test-netd-lldp-table',
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

# netctl's colour output: netctl.c's own colour helpers are file-local
# statics with no header, so this runs the real built `netctl` binary as a
# subprocess instead (test-picoctl.c's own pattern) -- no link to netctl.c,
# netctl-rtnl.c or netctl-path.c at all.
test_netctl_color_exe = executable(
  'test-netctl-color',
  ['src/netd/test-netctl-color.c'] + pico_test_sources,
)
test('test-netctl-color', test_netctl_color_exe)

# ---------------------------------------------------------------------------
# devd -- the device hotplug daemon (plans/31, Part 2, milestone H1). A third
# executable in the same tree, built exactly like netd, and a separate daemon
# rather than PID 1 code by owner decision: its crash costs a unit restart
# rather than the machine.
#
# It links pico-init-core for two different reasons at once. The event plumbing
# (timer.c, signal.c, util.c) is the same share netd takes. gpt-scan.c and
# ext-super.c are the other, and are the whole point of those files' two-consumer
# split: PID 1's boot-time swap activation and devd's removable-media policy read
# the same partition table through the same parser, and PID 1's root check and
# devd's by-uuid/by-label naming read the same ext superblock through the same
# decoder.
#
# 'src/devd' only on the include path, never 'src' -- see netd_includes above
# for what putting src/ there does to a daemon's own <signal.h>.
# ---------------------------------------------------------------------------
devd_includes = include_directories('src/devd')

devd_core_sources = files(
  'src/devd/devd-loop.c',
  'src/devd/devd-uevent.c',
  'src/devd/devd-block.c',
  'src/devd/devd-probe.c',
  'src/devd/devd-symlink.c',
  'src/devd/devd-media.c',
  # H2, the rule engine: the parser, what a rule means, and the RUN+= child.
  # Three files rather than one because they are three different kinds of
  # code -- a tokenizer, a matcher that reads sysfs, and a fork/exec -- and
  # each has its own test program.
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

# devd's own rules file (H2), into the same directory usb-modeswitch-data's
# already installs into -- /usr/lib/udev/rules.d under this distro's mandatory
# usrmerge. Shipping a rules file rather than compiling the serial naming in is
# the point: it is the same engine reading the same syntax as the vendor file
# beside it.
install_data(
  'src/devd/60-pico-serial.rules',
  install_dir: get_option('prefix') / 'lib' / 'udev' / 'rules.d',
)

# The four acceptance areas H1 is measured against: uevent parsing, the
# debounce state machine, the GPT/ext4 field extraction, and the symlink
# create/remove/reconcile lifecycle. H2 adds three: the rules tokenizer against
# verbatim excerpts of the real shipped usb-modeswitch file, the matcher and
# substitutions against a sysfs tree built in the test, and the async RUN+=
# path end to end. Registered up front, same as netd's and PID 1's lists and
# for the same reason.
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
]

# PICO_SOURCE_DIR lets test-devd-match.c parse the very file meson installs
# above, rather than a copy of its one rule pasted into the test. A rules file
# that ships is only correct if the engine that ships with it reads it, and a
# retyped copy could not catch an edit to one and not the other.
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
# tmpfiles.d (plans/38 §9.4). A fifth binary out of the same tree, a oneshot
# rather than a daemon, and the thing that makes the tmpfiles.d snippets
# oe-core packages already ship do something under pico-init. tmpfiles.h
# lists exactly which line types are real and which are an explicit, logged
# skip.
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

# picoctl is defined after logd below, because it links logd's ring reader.

# ---------------------------------------------------------------------------
# logd -- the log daemon, and picolog, its reader (plan §3).
#
# Same shape as netd: one static library the tests link, installed binaries
# alongside. logd stores journald's documented plain-text EXPORT format in a
# bounded /run ring; the binary on-disk journal format is deliberately NOT
# built (plan §3.1), and full journalctl compatibility is reached off-device by
# feeding `picolog -o export` to upstream's own systemd-journal-remote.
#
# No file here is lifted from upstream, so unlike src/netd/dhcp/ there is no
# LGPL island: all of logd and picolog is GPL-2.0-or-later, this project's own
# copyright, with upstream cited as a reference only.
# ---------------------------------------------------------------------------
logd_includes = include_directories('src/logd')

# The ring reader (logd-read.c) is its own tiny static library, same shape
# as sd_event_lib above: libsystemd-compat's sd-journal read side is built
# on it and must not drag logd_core (whose writer/receiver need
# pico_init_core's util.c) into every libsystemd consumer -- logd-read.c is
# libc-only for exactly this reason. logd_core link_wholes it back in, so
# picolog, picoctl and the logd tests keep seeing one archive with every
# symbol it always had.
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

# logd's own units (plan §3.6). logd.socket is this distro's first real
# .socket unit -- the concrete consumer socket activation exists for.
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
# picoctl -- the on-device systemctl equivalent (plan §1.7).
#
# It links pico-init-core rather than duplicating anything: the symlink verbs
# (enable/disable/is-enabled/preset) operate on the very same .wants/ and
# preset layouts unit-enable.c already reads at boot, so sharing that code is
# what keeps the two halves from drifting apart and disagreeing about what
# "enabled" means.
#
# It links logd-core too, for `picoctl status`'s per-unit log tail: that calls
# logd_ring_read_filtered() directly rather than shelling out to picolog, which
# is the whole reason the ring reader lives in its own translation unit instead
# of inside picolog.c's main(). Defined here rather than next to the other
# PID 1 targets because logd_core has to exist first.
#
# Installed to sbindir as part of the MAIN pico-init package, not a subpackage:
# it is the init's own tool, not an optional daemon the way netd and logd are.
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
# libsystemd-compat -- a from-scratch, ABI-compatible reimplementation of
# real systemd's public libsystemd surface, for OE recipes that were built
# assuming a real systemd is present. Lives under its own directory rather
# than beside PID 1's own code because it is a library other packages link
# against, not PID 1 code itself -- see sd-daemon.c's own header for why it
# never calls into util.c/log.
#
# sd-daemon.h, sd-event.h, sd-id128.h and sd-journal.h are wired in so far;
# other real headers this eventual shim will need to cover (sd-bus.h, ...)
# get their own sources added to libsystemd_compat_sources as each one's
# own family lands.
#
# sd-event.c/sd-event-source.c split the sd_event_*() family in two: the
# event object and its epoll-backed loop mechanics versus every
# sd_event_source_*() property accessor. event-internal.h is the private
# struct layout and helper set the two share; never installed, since a real
# consumer only ever sees opaque sd_event/sd_event_source pointers. Both live
# in sd_event_lib (above, defined ahead of pico_init_core) and are pulled
# back into this library via link_whole below, not listed as sources here.
#
# sd-journal's own sources are split by concern rather than upstream's
# single sd-journal.c: -send/-sendv (printf-shaped write API funnelling
# into one real sd_journal_sendv() choke point over logd's /dev/log
# socket), -stream (the separate /run/logd/stdout mechanism), -open/
# -navigate/-data/-info (the read side, a snapshot reader over logd's own
# ring -- src/logd/logd-read.h -- never the binary .journal format), and
# -util (helpers shared across the read side). sd-journal-internal.h is
# their private struct sd_journal layout, never installed.
#
# sd-id128.c/sha256.c/hmac-sha256.c live in sd_id128_lib (above, defined
# ahead of pico_init_core for the same reason sd_event_lib is) and are
# pulled back into this library via link_whole below, not listed as
# sources here.
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
  # src/logd/logd-read.h's LogdEntry/LogdReadField views and its ring
  # reader (logd_ring_read() et al) are what sd-journal-open.c/-navigate.c/
  # -data.c build the whole read side on; logd_read is link_whole'd below.
  #
  # sd-bus.h/sd-login.h/sd-hwdb.h family: split by behavioral bucket, not
  # upstream's file layout. sd-bus-validate.c/-path.c/-error.c are the
  # corner of sd-bus with a real, bus-free answer; -open.c is every way to
  # obtain an sd_bus* (all fail, since no wire protocol exists); -stubs.c/
  # -noop.c are the ~270 remaining sd_bus_*() entry points that need a
  # live bus/message/slot/track/creds object that can never exist.
  # sd-login-resolve.c is the shared pid/pidfd/peer-fd resolver both
  # sd-login-cgroup.c's real cgroup/unit/slice getters and sd-login.c's
  # honest_failure getters build on.
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
  # sd-device/sd-network: device-new.c (refcounting, every
  # sd_device_new_from_*() constructor, the parent walk), device-attr.c
  # (readlink-/grammar-based identity: subsystem, driver, sysname),
  # device-uevent.c (the property table and its uevent-derived getters),
  # device-db.c (the /run/udev/data overlay devd writes for input devices),
  # device-property.c (iteration plus the always-empty tag family),
  # device-devlink.c/-sysattr.c/-child.c/-trigger.c (one real mechanism
  # each), device-enumerator.c and device-monitor.c (the two subsystems
  # big enough for their own file). device-internal.h is their shared
  # private struct layout, never installed. network-resolv.c/-state.c/
  # -monitor.c mirror the same split for sd-network; network-internal.h
  # is its equivalent private (test-root-prefix) header.
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

# The installed artifact: ${libdir}/libsystemd.so.0.<minor>.<micro> with
# DT_SONAME libsystemd.so.0 -- the name, path and SONAME real systemd's
# libsystemd occupies, so package.bbclass's shlib pass and every
# consumer's -lsystemd resolve to it with nothing downstream needing to
# know. Two version numbers travel with the vendored libsystemd-v259.sym
# and change together on a systemd bump: the library version is
# upstream's own libsystemd_version at that tag, and the systemd release
# number is what the .pc files report, since consumers gate on
# `systemd >= N`. meson's default b_lundef makes an undefined symbol a
# link error here rather than a load failure on the target.
libsystemd_version = '0.42.0'
libsystemd_compat_systemd_version = '259'
libsystemd_sym = files('src/compat/libsystemd/libsystemd.sym')
libsystemd = shared_library(
  'systemd',
  version: libsystemd_version,
  link_whole: libsystemd_compat,
  link_args: ['-Wl,--version-script=' + meson.current_source_dir() / 'src/compat/libsystemd/libsystemd.sym'],
  link_depends: libsystemd_sym,
  install: true,
)

# Not a test: the Type=notify service test-service.c execs (found next to
# the test binary via /proc/self/exe, test-picoctl.c's own idiom). Links the
# shared library above so its READY=1 goes through the installed ABI, which
# is why test-service itself is registered here rather than in pico_tests.
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
  'PROJECT_URL': 'https://github.com/koenkooi/pico-init',
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

# Real consumers expect "systemd/sd-daemon.h" (etc.) on their include path,
# the same layout a real systemd-devel package ships. _sd-common.h rides
# along unconditionally, same as real systemd's own src/systemd/meson.build
# does (install_headers(systemd_headers, '_sd-common.h', subdir: 'systemd'))
# -- any public sd-*.h that #includes "_sd-common.h" needs it installed
# beside itself, since that's a quoted include and resolves against the
# installed file's own directory, not the source tree's.
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
)
install_headers(libsystemd_public_headers, subdir: 'systemd')

# Symbol versions are real systemd's own, so a binary linked against real
# libsystemd (sd_bus_message_append@LIBSYSTEMD_209) resolves against this
# library too. libsystemd.sym is generated, not maintained: the pinned
# upstream libsystemd.sym (libsystemd-v259.sym, verbatim from systemd's
# v259 tag) intersected with what the archive defines, every symbol on its
# upstream node, the sd_network_* family (never exported by upstream's
# libsystemd, it lives in libsystemd-shared) on a trailing
# PICO_LIBSYSTEMD_0. A systemd version bump is: replace the upstream file,
# `ninja regen-libsystemd-sym`, review the diff. test-libsystemd-sym fails
# on a stale committed file, on a public header declaring an undefined
# function, and on an sd_*-named internal helper leaking out of the archive.
libsystemd_sym_gen = files('tools/gen-libsystemd-sym.py')
libsystemd_sym_upstream = files('src/compat/libsystemd/libsystemd-v259.sym')
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
  test('test-libsystemd-pc', python3, args: [check_pc, '--upstream', files('src/compat/libsystemd/libsystemd-v259.pc.in'), '--generated', libsystemd_pc])
  test('test-systemd-pc', python3, args: [check_pc, '--upstream', files('src/compat/libsystemd/systemd-v259.pc.in'), '--generated', systemd_pc])
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


# sd-bus.h/sd-login.h/sd-hwdb.h family tests. test-sd-bus-stubs/-noop
# exhaustively call every function in their respective mechanical bucket
# (see sd-bus-stubs.c/sd-bus-noop.c's own headers) -- generated the same
# way the stub bodies were, so a slipped signature or return value in
# either shows up as a real test failure, not just a build success.
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

# Real cgroups: creates/removes real /sys/fs/cgroup/system.slice/*.service
# directories and moves a real forked child into them, so needs CAP_SYS_ADMIN
# (root, same as every other privileged pico-init test already assumes).
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
# versions (libudev-v259.sym, all 92 exports on their upstream nodes) and
# libudev.pc, for the DEPENDS = "udev" population that wants the library
# rather than the daemon. Built the way upstream builds its own: every
# udev_* entry point is a thin wrapper over sd_device_*, so the shared
# object links libsystemd.so.0 and carries no device code of its own.
#
# Scope is the read-only half: udev_device_*/udev_enumerate_*/
# udev_list_entry_* are real. udev_monitor_* is the silent-but-successful
# interim of libudev-monitor.c, kept until live uevent subscription lands;
# udev_queue_*/udev_hwdb_* report the true no-udevd/no-hwdb state.
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

# Upstream's own libudev_version at v259, bumped together with the
# vendored files on a systemd bump.
libudev_version = '1.7.12'
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

# udev.pc, a SEPARATE package name from libudev.pc: real consumers doing
# `pkg-config --variable=udevdir udev` (alsa-utils' PACKAGECONFIG[udev] is
# the real one that surfaced this, 2026-09-13 -- no udev.pc meant no
# udevdir, so its configure script fell back to a hardcoded non-usrmerge
# /lib/udev/rules.d) look up the package literally named "udev", which
# carries udevdir; "libudev" is the library and carries no such variable
# upstream either. Real path matches devd's own rules install location.
udev_pc = configure_file(
  input: 'src/compat/libudev/udev.pc.in',
  output: 'udev.pc',
  configuration: pc_conf,
  install: true,
  install_dir: pkgconfig_dir,
)

if python3.found()
  test('test-udev-pc', python3, args: [check_pc, '--upstream', files('src/compat/libudev/udev-v259.pc.in'), '--generated', udev_pc])
endif

if python3.found() and nm.found()
  libudev_sym_args = [
    libsystemd_sym_gen,
    '--upstream', files('src/compat/libudev/libudev-v259.sym'),
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
  test('test-libudev-pc', python3, args: [check_pc, '--upstream', files('src/compat/libudev/libudev-v259.pc.in'), '--generated', libudev_pc])
endif

test(
  'test-libudev-so',
  test_versioned_so_exe,
  args: [libudev, libudev_sym, 'libudev.so.1', 'libudev_list_new', 'libudev_device_new'],
)

# test-libudev-device/-enumerate drive the wrappers against a fixture /sys
# through the compat archives; test-libudev-monitor links the installed
# shape (the .so) and pins the never-delivers monitor contract that
# libusb_init() depends on.
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
