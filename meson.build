# SPDX-FileCopyrightText: 2026 Koen Kooi
# SPDX-License-Identifier: GPL-2.0-or-later

project(
  'pico-init', 'c',
  version: '0.0.0',
  license: 'GPL-2.0-or-later',
  default_options: [
    'c_std=gnu17',
    'warning_level=3',
    'werror=true',
  ],
  meson_version: '>= 0.62.0',
)

# Everything except main() builds into a static library, so the test programs
# can link the real manager, unit and job code instead of re-declaring it.
# main.c stays out of it: a second main() would collide with every test's own.
pico_init_core_sources = files(
  'src/manager.c',
  'src/manager-loop.c',
  'src/manager-shutdown.c',
  'src/manager-startup.c',
  'src/unit.c',
  'src/unit-load.c',
  'src/unit-parse.c',
  'src/unit-dependency.c',
  'src/unit-enable.c',
  'src/service.c',
  'src/service-exec.c',
  'src/target.c',
  'src/job.c',
  'src/cgroups-v2.c',
  'src/timer.c',
  'src/signal.c',
  'src/util.c',
  'src/compat.c',
)

pico_init_core = static_library(
  'pico-init-core',
  pico_init_core_sources,
)

# link_whole, not link_with: a static library only contributes the object
# files something references, which would silently drop any translation unit
# PID 1 has not wired up yet (service-exec.c, compat.c) and make the M0
# symbol-presence test below pass by omission. The binary should contain the
# init it claims to be.
pico_init_exe = executable(
  'pico-init',
  'src/main.c',
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
  'test-job',
  'test-boot-root',
  'test-service',
  'test-timer-cgroup',
]

foreach t : pico_tests
  exe = executable(
    t,
    ['src/' + t + '.c'] + pico_test_sources,
    link_with: pico_init_core,
  )
  test(t, exe)
endforeach
