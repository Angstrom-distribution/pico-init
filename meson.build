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

# Everything except main() builds into a static library, so the test programs
# can link the real manager, unit and job code instead of re-declaring it.
# main.c stays out of it: a second main() would collide with every test's own.
pico_init_core_sources = files(
  'src/manager.c',
  'src/manager-loop.c',
  'src/manager-shutdown.c',
  'src/manager-startup.c',
  'src/mount-setup.c',
  # The GPT reader and the Discoverable-Partitions swap activation on top of
  # it (plans/31, Slice A). In the core library rather than beside main.c
  # because the parser half is meant to have a second consumer later.
  'src/gpt-scan.c',
  # The ext superblock reader (plan §10). Here rather than under src/devd/
  # because it has two consumers that are two different binaries: devd names a
  # removable partition from it, and PID 1's root check gates a filesystem
  # checker on it.
  'src/ext-super.c',
  # The root filesystem check and the remount that ends it (plan §10, R1).
  # Beside gpt-scan.c for the same reason: it is boot-path code main.c calls
  # once, and the two decision tables inside it are what the tests link.
  'src/root-check.c',
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
  'src/unit-dependency.c',
  'src/unit-enable.c',
  'src/service.c',
  'src/service-exec.c',
  'src/target.c',
  # Socket units (plan §1.6): a third unit type extending this same core,
  # not a separate daemon.
  'src/socket.c',
  'src/job.c',
  # PID 1's own runtime state publisher and control socket (plan §1.7).
  # Both are wired into unit.c/job.c/manager-loop.c already; see their
  # headers for why the hooks live at those choke points.
  'src/manager-state.c',
  'src/manager-ctrl.c',
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
  'test-service',
  'test-timer-cgroup',
  'test-boot',
  # Socket activation (plan §1.6) and picoctl (plan §1.7), registered up
  # front and placeholder-bodied for exactly the reason above.
  'test-socket',
  'test-manager-state',
  'test-picoctl',
  'test-manager-ctrl',
  # D0's five /dev symlinks (plan §1.8), and the fixture-driven unit-file
  # parser test the §7 unit-test item asks for.
  'test-dev-setup',
  'test-unit-parse',
  # The boot console channel: the os-release parser behind the greeting, and
  # the byte-level shape of what lands on the console.
  'test-status',
  # The GPT reader (plans/31, Slice A), against real partition tables built
  # byte by byte in the test itself.
  'test-gpt-scan',
  # The ext superblock reader, moved here with the code it covers when that
  # code left src/devd/ to gain its second consumer (plan §10).
  'test-ext-super',
  # The root check's two decision tables (plan §10, R1). The I/O half of it
  # remounts "/" and is proven by a boot instead.
  'test-root-check',
]

foreach t : pico_tests
  exe = executable(
    t,
    ['src/' + t + '.c'] + pico_test_sources + [version_h],
    link_with: pico_init_core,
  )
  test(t, exe)
endforeach

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
  'src/netd/netd-resolv.c',
  'src/netd/netd-sntp.c',
  'src/netd/netd-time.c',
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

logd_core_sources = files(
  'src/logd/logd-write.c',
  'src/logd/logd-recv.c',
  'src/logd/logd-kmsg.c',
  # The ring reader lives in the library, not inside picolog.c, because
  # picoctl's per-unit log tail (plan §1.7, C1) reuses exactly this reader.
  'src/logd/logd-read.c',
)

logd_core = static_library(
  'logd-core',
  logd_core_sources,
  include_directories: logd_includes,
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
  'src/logd/picolog.c',
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
  'src/picoctl.c',
  include_directories: logd_includes,
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
# Only the sd-daemon.h family is wired in here; other real headers this
# eventual shim will need to cover (sd-id128.h, sd-bus.h, ...) get their own
# sources added to libsystemd_compat_sources as each one's own family lands.
# ---------------------------------------------------------------------------
libsystemd_compat_includes = include_directories('src/compat/libsystemd')

libsystemd_compat_sources = files(
  'src/compat/libsystemd/sd-daemon.c',
)

libsystemd_compat = static_library(
  'systemd-compat',
  libsystemd_compat_sources,
  include_directories: libsystemd_compat_includes,
  install: true,
)

# Real consumers expect "systemd/sd-daemon.h" on their include path, the
# same layout a real systemd-devel package ships.
install_headers(
  'src/compat/libsystemd/sd-daemon.h',
  subdir: 'systemd',
)

test_sd_daemon_exe = executable(
  'test-sd-daemon',
  ['src/compat/libsystemd/test-sd-daemon.c'] + pico_test_sources,
  include_directories: libsystemd_compat_includes,
  link_with: libsystemd_compat,
)
test('test-sd-daemon', test_sd_daemon_exe)
