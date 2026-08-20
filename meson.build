# SPDX-FileCopyrightText: 2026 Koen Kooi
# SPDX-License-Identifier: LGPL-2.1-or-later

project(
  'pico-init', 'c',
  version: '0.0.0',
  license: 'LGPL-2.1-or-later',
  default_options: [
    'c_std=gnu17',
    'warning_level=3',
    'werror=true',
  ],
  meson_version: '>= 0.62.0',
)

# Scaffold only -- no real PID1 logic yet. See README.md for the scoping
# decisions (quarry systemd's unit parser/dependency engine/service state
# machine, cgroups v2, a from-scratch netd built on sd-dhcp/sd-netlink,
# journald's format + a slim reader, meson as the build system). This
# target exists so CI has something real to build and test from the very
# first commit.
pico_init_exe = executable(
  'pico-init',
  'src/main.c',
  install: false,
)

test(
  'placeholder',
  find_program('src/test-placeholder.sh'),
  args: [pico_init_exe],
)
