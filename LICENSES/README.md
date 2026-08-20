# pico-init Project Licensing

pico-init follows the same SPDX/REUSE-style scheme as its main source of
quarried code, [systemd](https://github.com/systemd/systemd/blob/main/LICENSES/README.md),
simplified: one default license, growing the exception list only when a
specific file actually needs one.

## Main License

Unless a source file's own header says otherwise, pico-init sources are
licensed under **LGPL-2.1-or-later** (GNU Lesser General Public License v2.1
or later). Every source file carries a single-line SPDX identifier at the
top, e.g.:

```c
/* SPDX-License-Identifier: LGPL-2.1-or-later */
```

This is not just a style choice: pico-init's own PID1 core is planned to be
quarried directly from systemd's LGPL-2.1-or-later-licensed source (unit
parser, dependency engine, service state machine — see this project's
angstrom-pico TODO for the scoping decisions), and DHCP/netlink handling is
planned to lift from systemd's `sd-dhcp`/`sd-netlink`, also
LGPL-2.1-or-later. Matching the upstream license for those files is required,
not optional — a derivative of LGPL-2.1-or-later code cannot be relicensed
away from it.

## Other Licenses

None yet. When a file is copied or adapted from a source under a different
license (as systemd itself does for individual files under MIT, CC0-1.0,
BSD-3-Clause, etc. — see systemd's own `LICENSES/README.md` for their much
longer list), add its license text to `LICENSES/` here and note the
exception in this file, scoped to the specific file(s) it applies to. Do not
add a license to this directory speculatively before a file actually needs
it.

## `LICENSES/` Directory

Contains the full text of every license actually in use. Currently:

- `LGPL-2.1-or-later.txt` — the default, and (as of this writing) the only
  license in use.
