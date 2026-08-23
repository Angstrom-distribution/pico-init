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

# M0 source layout (plan section 1.4): every file below exists with stub
# bodies returning -ENOSYS; real logic lands per-milestone (M1 unit parser,
# M2 jobs, M3 services, M4 cgroups/timer/signal).
pico_init_sources = files(
  'src/main.c',
  'src/manager.c',
  'src/manager-loop.c',
  'src/manager-shutdown.c',
  'src/unit.c',
  'src/unit-load.c',
  'src/unit-parse.c',
  'src/unit-dependency.c',
  'src/service.c',
  'src/service-exec.c',
  'src/job.c',
  'src/cgroups-v2.c',
  'src/timer.c',
  'src/signal.c',
  'src/util.c',
  'src/compat.c',
)

pico_init_exe = executable(
  'pico-init',
  pico_init_sources,
  install: true,
  install_dir: get_option('sbindir'),
)

# M0 acceptance: the binary links, runs, exits 0 when not PID1, and every
# public symbol from src/*.h is present in the linked binary.
test(
  'm0-link-and-symbols',
  find_program('src/test-m0.sh'),
  args: [pico_init_exe],
)
