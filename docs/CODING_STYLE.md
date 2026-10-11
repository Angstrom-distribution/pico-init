# Coding Style

pico-init is C (`gnu17`), formatted by `clang-format` with a configuration
derived from systemd's own, and written to systemd's conventions where the
two projects overlap. A large part of the source is lifted or quarried from
systemd, so staying close to its style keeps diffs against upstream small.
This document records what the tree and `.clang-format` actually do. See
[HACKING.md](HACKING.md) for the build and test workflow.

## Formatting

Formatting is not a matter of taste: CI runs `clang-format-18 --dry-run
--Werror` over every `*.c` and `*.h` under `src/`. The version is pinned
because an unpinned one changes the rules when the runner image
changes. To format in place:

```sh
git ls-files 'src/*.[ch]' | xargs clang-format -i -style=file
```

The rules that matter when writing code by hand:

| Rule                | Value                                              |
|---------------------|----------------------------------------------------|
| Indent              | 8 columns, spaces only, never tabs                 |
| Continuation indent | 16 columns                                         |
| Column limit        | 109                                                |
| Pointer `*`         | binds to the name: `char *p`                       |
| Cast                | space after: `(long long) x`                       |
| Control statements  | space before the paren: `if (x)`, `for (;;)`       |
| Function braces     | opening brace on the signature line                |
| Short functions     | never collapsed onto one line                      |
| Call arguments      | one per line once they do not fit; no bin-packing |
| Ternary             | operators stay at the end of the line, not the next |
| Preprocessor        | directives indented after the `#`                  |
| Blank lines         | at most two in a row                               |
| Line endings        | LF                                                 |

Preprocessor nesting is shown by indenting after the hash:

```c
#ifdef SYSTEMD_QUARRY_COMPAT
#        define log_error(...) pico_log(PICO_LOG_ERR, __VA_ARGS__)
#endif
```

Single-statement `if`, `for` and `while` bodies take no braces and sit on
the next line, indented one level:

```c
if (!ret)
        return -EINVAL;
```

Headers use `#pragma once`, not include guards. The baseline is
`warning_level=3` with `werror=true` in `meson.build`, so a new warning
fails the build.

### Includes

A `.c` file includes, in this order, separated by blank lines:

1. `_GNU_SOURCE` if it needs a glibc extension, defined before any include
   (a comment naming the extension helps). `-std=gnu17` does not imply it.
2. Its own header (when it has one).
3. System headers in alphabetical order.
4. Project headers in quotes, in alphabetical order.

`src/main.c` and `src/mount-setup.c` are representative.

## Naming

- Types are `CamelCase` typedefs of `struct` or `enum`: `Manager`, `Job`,
  `JobState`, `FstabEntry`, `PicoSignal`. Enum values are upper-case with
  the type's prefix, followed by `_<TYPE>_MAX` and `_<TYPE>_INVALID`
  sentinels where the enum is iterated or has a "no value yet" state
  (`JOB_START`, `_JOB_TYPE_MAX`, `_JOB_RESULT_INVALID`).
- Functions and variables are `snake_case`. A function is prefixed with the
  name of the module or type it belongs to: `job_new()`, `manager_reload()`,
  `dhcp_client_new()`, `netd_*`, `devd_*`, `logd_*`.
- Helpers shared by several programs are prefixed `pico_` (`pico_log()`,
  `pico_strv_free()`, `pico_extract_first_word()` in `src/util.h`;
  `pico_signal_new()`, `pico_timer_new()`).
- Constructors are `<type>_new()`, destructors `<type>_free()`; reference
  counted objects use `_ref()` and `_unref()`. Cleanup helpers for
  `_cleanup_()` end in `p` (`dhcp_message_unrefp`).
- Macros and constants are upper-case with a module prefix
  (`PICO_LOG_ERR`, `CGROUP_PRUNE_MAX_DEPTH`, `PICO_CTRL_MAX_CONNS`).
- Test programs are named `test-<module>.c` next to the module and are
  registered in `meson.build`.
- Functions that only matter inside one file are `static` and carry a short
  file-local prefix when the name would otherwise be generic (`cs_strip()` in
  `conf-scan.c`).

The `sd_*` and `udev_*` names exported by the compatibility libraries are
dictated by the upstream ABI and are the exception; see
[COMPATIBILITY_LIBRARIES.md](COMPATIBILITY_LIBRARIES.md).

## Error handling

Functions that can fail return an `int`: zero (or a positive value with a
documented meaning) on success, a negative errno value on failure. Results
come back through an out-parameter, named `ret` when it is the primary
result:

```c
int job_new(Manager *m, JobType type, Unit *u, Job **ret);
```

- Capture `errno` into a local `r` immediately, as `r = -errno;`, before
  any call that can overwrite it (`free()`, `close()`, `pico_log()`).
- Do not return `-1` or a bare `errno`. Return `-EINVAL` for a NULL or
  malformed argument, `-ENOMEM` for an allocation failure.
- Header comments state the return contract in one line: "0 or -errno",
  "1 with `*ret` set, 0 at end of string, -EINVAL on ...". Keep that line
  accurate when behavior changes.
- Log an error where it is handled, not where it is first detected, and
  include the unit or object name and `strerror(-r)`:

  ```c
  pico_log(PICO_LOG_ERR, "%s: failed to spawn ExecStart=: %s", UNIT(s)->id, strerror(-r));
  ```

- Cleanup on failure uses `goto` to a single label in functions that hold
  several resources, or unwinds inline in short ones (`signal.c`). Both
  forms exist in the tree.
- A result that is ignored on purpose is cast to `void`:
  `(void) close(fd);`.
- Best-effort steps are marked as such in a comment, and a failure there
  must not abort the caller.

Malformed input from a unit file, a client, a packet or a device is an
error return that costs that one token or message, never an `assert()` or
`abort()`. Where a lifted function contained an `assert()` reachable from
input, the lifted copy replaces it with a checked early return and says so
in the file header (`unit-name.h`, `specifier.h`). Core, daemon and library
code does not call `assert()` either, except in the lifted netd files, where
`netd-compat.h` maps `assert()` to its own check; tests use
`ASSERT_TRUE`, `ASSERT_EQ_INT` and `ASSERT_STREQ` from `src/test-util.h`,
which print file, line and expression and exit non-zero. For data supplied
by a network peer, `netd_validate()` in `src/netd/netd-compat.h` returns an
errno value (`-EBADMSG` for a malformed packet) where upstream would assert.

## Memory ownership

Every pointer in a struct or function contract is either owned or
borrowed, and the header or field comment says which:

```c
Unit *unit; /* borrowed; unit->job points back while installed */
```

- An out-parameter named `ret` hands the caller an owned object on success
  (`manager_new()`, `job_new()`).
- A function documented as taking ownership ("ownership transfers to the
  manager") means the caller must not free the object afterwards.
- Allocation failure is always checked. Allocation uses `malloc`,
  `calloc`, `realloc` and `pico_strdup()` directly; there is no wrapper
  that aborts.
- `free(p)` followed by a reset is written `p = pico_mfree(p);`. String
  vectors are freed with `pico_strv_free()`, which returns `NULL`.
- Intrusive lists are used for state PID 1 walks on every event, so lookup
  does not allocate (the job run queue, control connections).
- `netd` and the code lifted into it use `_cleanup_free_`,
  `_cleanup_close_`, `_cleanup_fclose_` and `_cleanup_strv_free_` from
  `netd-compat.h`. Elsewhere the tree frees explicitly.

## Code that runs as PID 1

If PID 1 exits or crashes the kernel panics. `main.c` therefore ends in
`freeze()`, which logs and sleeps in `pause()` forever instead of
returning. The same posture applies everywhere PID 1 code runs:

- **Never block.** Sockets are `SOCK_NONBLOCK`, writes use `MSG_DONTWAIT`,
  files that might be FIFOs or devices are opened with `O_NONBLOCK`, and
  work is driven from the `sd_event` loop. A client that does not read its
  reply gets no reply; it does not stall the loop (`manager-ctrl.c`).
- **Bound everything a peer can grow.** Accepted control connections are
  capped (`PICO_CTRL_MAX_CONNS`), deadlines saturate rather than wrap
  (`usec_add()`), and directory walks carry an explicit depth limit
  (`CGROUP_PRUNE_MAX_DEPTH`).
- **No unbounded recursion.** Dependency propagation uses a worklist rather
  than recursing per requirer (`job.c`), and job completion takes an
  explicit `recursive` flag so a completion inside a transaction does not
  re-enter it. A recursive walk needs a depth cap.
- **No `assert()`, no `abort()`, no `exit()` on input-reachable paths.** See
  [Error handling](#error-handling).
- **No `malloc` after `fork()`.** The region between `fork()` and
  `execve()` in `service-exec.c` is kept as close to async-signal-safe as
  the project gets: no `malloc`, no NSS, no `dlopen`, no `pico_log()` (it
  formats with `vsnprintf()`). Everything the child needs is built in the
  parent first: the environment vector, resolved uid and gid lists, the fd
  table. The one value that cannot exist before the fork, `LISTEN_PID`, is written
  with `snprintf()` into a slot reserved in the parent. If you need a sort
  there, hand-roll it; glibc's `qsort` can allocate.
- **Signals are read, not handled.** They are blocked and consumed from a
  `signalfd` (`signal.c`) on the event loop.
- **Failure to set up is not fatal unless nothing works.** Mount setup
  marks each mount as required or best-effort; a missing `/dev/shm` must
  not stop a board from reaching a console.

## Comments

Comments explain why, not what. The tree uses a small number of shapes:

- A file header block directly after the SPDX lines, saying what the file
  is for, which upstream file it comes from (if any), and where it
  departs from upstream.
- A block above a non-obvious function or constant in the multi-line form:

  ```c
  /*
   * Saturating a + b, for computing a deadline from "now + timeout". ...
   */
  ```

- A trailing `/* ... */` on a struct field or enum value for its meaning,
  ownership or invariants.
- `/* ... */` only. `//` comments are not used.

Comments name the failure they prevent. If a line looks removable and is
not, say what breaks when it is removed (as `unaligned.h` does for the
ARMv5TE misaligned load). Do not restate the code, narrate history, or
leave `TODO`/`FIXME` markers.

Upstream behavior that was adopted or rejected is cited by short commit
hash and subject so a reader can check it, as in the header of
`conf-scan.c`.

## Lifted systemd code and licensing

Three tiers exist, and the tier decides how the file is written.

- Fresh: most of `src/`, written in pico-init style.
- Quarried: `conf-scan.c`, `job.c`, `service.c`, `service-exec.c`,
  `socket.c`, `specifier.c`, `unit-load.c`, `unit-name.c`, `unit-parse.c`
  and `util.c`, plus functions inside other files that say so in a comment
  (`unit.c`). Rewritten to pico-init style, keeping the behavior and fixes of
  the early systemd source.
- Lifted: `src/netd/dhcp/`, `netd-sntp.c` and `netd-time.c`. Near-verbatim
  from current systemd; the style stays upstream's.

**Quarried** files come from early systemd source (the 2011-era tree).
Their headers say which upstream file they derive from, list the upstream
fixes that were backported by commit, and list where behavior intentionally
differs. They are GPL-2.0-or-later. `src/compat.h` holds shims for systemd's
`log_*()` macros, the D-Bus change signals and the cgroup v1 entry points,
guarded by `SYSTEMD_QUARRY_COMPAT`, which no file in the tree defines at
present. Fresh code must not use anything from that header.

**Lifted** files come from current systemd (`src/libsystemd-network/` and
`src/timesync/`, ported into `netd`). They are LGPL-2.1-or-later and are
changed as little as possible, so that a later upstream change applies.
Anything a lifted file needs that the tree does not provide is added to
`src/netd/netd-compat.h`, never edited into the lifted file. That shim
replaces GNU statement expressions with standard C because `-Wpedantic` is
on for every build, and it is GPL-2.0-or-later: a GPL header included by
LGPL files is the permitted direction, and the linked `netd` binary is
GPL-2.0-or-later as a whole. Read the per-macro evaluation-count notes in
the shim before using a macro on an expression with side effects.

**Reimplemented** libraries (`libsystemd.so.0`, `libudev.so.1`) follow
upstream's API contract and error semantics, but no code is copied. Their
headers cite the upstream files and commit used as the reference. As
libraries that other packages link, they do not call pico-init's `util.c`
or logging.

The header of a lifted or quarried file states its origin (upstream path
and version), what was changed, and which upstream commits were rejected
and why. Do not "simplify" lifted code to local taste; if something must
change, document it in that header.

## SPDX and copyright

Every file carries SPDX tags on its first lines, and `reuse lint` in CI
fails on a missing one. In C sources:

```c
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */
```

In Meson, shell and other `#` comment files, the same two lines with `#`.

- Original files are `GPL-2.0-or-later`.
- Files with substantial upstream code keep the upstream copyright line
  above the project's, and use the upstream license:
  `/* SPDX-FileCopyrightText: 2010 Lennart Poettering */` for quarried
  code; `The systemd project` or the original author line (for example
  `2013 Intel Corporation`) for lifted code, with
  `LGPL-2.1-or-later`.
- Small third-party files keep their own license: `siphash24.[ch]` and
  `sparse-endian.h` under `src/netd/dhcp/` carry their upstream identifiers
  (`CC0-1.0`, `MIT`), and the license texts are in `LICENSES/`.
- Files that cannot carry a header (verbatim `.sym` and `.pc.in` copies from
  systemd, documentation, `LICENSE`) are covered by `REUSE.toml`
  annotations instead. Add an annotation there rather than modifying a
  verbatim file.
- Do not remove or rewrite an existing copyright or license line when
  editing a file.
- A new license needs its text in `LICENSES/` before it is used.

## Checklist

Before sending a change:

- `clang-format --dry-run --Werror` is clean on the files you touched.
- The build is warning-free under `werror=true`.
- `reuse lint` passes.
- New fallible functions return `-errno`, with the contract in a comment.
- Nothing PID 1 runs blocks, recurses without a bound, or allocates between
  `fork()` and `execve()`.
- A lifted file's header still describes how it differs from upstream.
