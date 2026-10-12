# Presets

A preset file is a list of `enable` and `disable` rules that say which
installed units should be turned on by default. On a stock systemd system
`systemctl preset-all` reads them once, at install or first-boot
provisioning time, and writes `.wants/` symlinks. A rootfs without systemd's
`systemctl` has nothing to run that command, so pico-init does it itself:
PID 1 reads the preset files on the first boot of a machine and persists the
result as the same symlinks `picoctl enable` creates. After that, only the
symlinks matter.

## Where preset files are read

Two directories are searched, in this order:

1. `/etc/systemd/system-preset`
2. `/usr/lib/systemd/system-preset`

Only files whose name ends in `.preset` are read. A file in the first
directory shadows a file of the same name in the second. The files from both
directories are then merged and sorted by file name, so rules in
`10-foo.preset` are consulted before rules in `90-default.preset`
regardless of which directory holds them. `/run/systemd/system-preset` is
not searched.

A missing directory is not an error. An image with no preset files at all is
supported; see [Units without a matching rule](#units-without-a-matching-rule)
for what that means.

## Syntax

One rule per line:

```
enable  sshd.socket
enable  dropbear@*.socket
disable wpa_supplicant*.service
disable *
```

| Line | Meaning |
| --- | --- |
| `enable GLOB` | Units whose name matches GLOB are enabled. |
| `disable GLOB` | Units whose name matches GLOB are not enabled. |
| `ignore GLOB` | Units whose name matches GLOB are left as they are: not enabled, and no later rule applies. |
| empty, or starting with `#` or `;` | Ignored. |
| anything else | Ignored. |

Leading and trailing blanks are stripped. The keyword must be followed by a
space or tab, and a rule with no glob is skipped. GLOB is matched against
the complete unit name with `fnmatch(3)` and `FNM_NOESCAPE`, so `*`, `?` and
`[...]` work and a backslash is literal. There are no `disable-all`-style
directives and no instance lists.

The first matching line wins, in file order and then line order within the
file. A rule for a unit type pico-init does not implement, such as
`.timer`, parses without complaint and never matches a loaded unit.

## When presets are applied

Presets are applied by PID 1 during startup, once the unit files have been
loaded and the `.wants/` and `.requires/` directories have been scanned, and
only if this is a first boot. PID 1 treats a boot as the first boot when
`/etc/machine-id` is missing, empty, all zero, unparseable, or contains
`uninitialized`.
The check runs after the root filesystem has been checked and remounted and
`/etc/fstab` has been processed, and PID 1 writes a fresh machine ID
in the same step. See [BOOT.md](BOOT.md) for the sequence around it.

On every later boot PID 1 does not read preset files. A unit is enabled if
and only if a symlink says so. This is what keeps `picoctl disable` in
effect: a unit that a preset enables stays disabled after its symlink is
removed.

Presets are never re-applied by `picoctl daemon-reload` or `SIGHUP`. A unit
file added later is known and loadable after a reload, but it stays
undecided until `picoctl enable` or `picoctl preset` decides it.

If `/etc/machine-id` cannot be written because the root filesystem is
read-only, PID 1 writes a transient ID to `/run/machine-id` and bind-mounts it
over `/etc/machine-id`, which therefore has to exist as a file in the image.
The file underneath stays uninitialized. Every boot of such a system is then a
first boot, and presets are evaluated in memory each time. Persisting the
symlinks fails on a read-only `/etc` and is logged as a warning; the
in-memory decision for that boot is unaffected.

### Rules of the first-boot pass

For every loaded unit, in order:

1. A unit that an existing `.wants/` or `.requires/` symlink already enabled
   is skipped. A symlink is an explicit decision; a preset is only a
   default.
2. A unit with no `WantedBy=` and no `RequiredBy=` in `[Install]` is
   skipped. There is nothing for a preset to act on.
3. The unit name is looked up in the merged rule set. If a matching rule says
   `enable`, or no rule matches, the unit is enabled: the target named by
   each `WantedBy=` gets a `Wants=` edge to it, and each `RequiredBy=` target
   gets a `Requires=` edge.
4. A matching `disable` rule leaves the unit without an edge and without a
   symlink.

Each unit enabled this way gets a real symlink, created under
`/etc/systemd/system`:

```
/etc/systemd/system/multi-user.target.wants/foo.service
    -> /usr/lib/systemd/system/foo.service
```

for every `WantedBy=` target, and the same under `<target>.requires/` for
every `RequiredBy=` target. The result on disk is the same as `picoctl
enable`. If creating one symlink fails, a warning is logged and the
remaining units are still processed.

### Units without a matching rule

A unit that no rule mentions is enabled, as with `systemctl preset`. An
image that wants the opposite ships a catch-all `disable *` as the last rule,
conventionally in a high-numbered file such as `99-default.preset`.

## picoctl verbs

All verbs below work on files and do not talk to PID 1. They operate on
`/etc/systemd/system`, prefixed with `--root DIR` if given, and use the
same unit parser and preset reader as PID 1.

| Verb | Behaviour |
| --- | --- |
| `enable UNIT...` | Creates one symlink per `WantedBy=` under `<target>.wants/` and per `RequiredBy=` under `<target>.requires/`, pointing at the unit file's absolute path with `--root` stripped. Prints `Created symlink '...' → '...'.` for each one created. An existing correct symlink is left alone. Presets are not consulted. |
| `disable UNIT...` | Removes the `.wants/` and `.requires/` symlinks that `enable` would create, printing `Removed '...'.` for each. Missing symlinks are not an error. |
| `reenable UNIT...` | `disable` followed by `enable`. |
| `preset UNIT...` | Runs the same rule lookup as the first-boot pass. On `enable`, or no matching rule, it does what `enable` does; on `disable` it does what `disable` does. Unlike the first-boot pass, it also removes symlinks. |
| `mask UNIT...` | Creates `/etc/systemd/system/UNIT` as a symlink to `/dev/null`. Idempotent. Rejects invalid unit names. A unit does not need to exist to be masked. |
| `unmask UNIT...` | Removes `/etc/systemd/system/UNIT` only if it is a symlink to `/dev/null`. Anything else, including a real unit file, is left alone. |
| `is-enabled UNIT...` | Prints `masked`, `static`, `enabled`, `disabled` or `not-found` per unit, read fresh from the filesystem. Exit status 0 if any unit is `enabled` or `static`, 4 if none was found, 1 otherwise. |
| `list-unit-files` | Lists units in both unit directories with their state and a `PRESET` column. |

`enable`, `disable`, `reenable` and `preset` on a unit without `WantedBy=`
or `RequiredBy=` create and remove nothing, print a notice that the unit is
not meant to be enabled with `picoctl`, and exit 0. A unit that cannot be
found or does not parse makes them fail with `unit UNIT does not exist` and
exit 1. `[Install]` `Alias=`, `Also=` and `DefaultInstance=` are not
implemented, so `enable` does not create alias or companion symlinks.

None of these verbs starts or stops anything. `picoctl enable` does not
imply `--now`; use `picoctl start` for that.

### list-unit-files

`STATE` is `masked` for a `/dev/null` symlink in `/etc/systemd/system`,
`static` for a unit without `WantedBy=`/`RequiredBy=`, `enabled` if one of
its symlinks exists, `disabled` otherwise, and `bad` for a unit file that
failed to load. `PRESET` is only filled in for `disabled` units, and shows
what a preset query would decide (`enabled` when the answer is enable or no
rule matched); every other row shows `-`.

### Masking

A mask is a symlink in `/etc/systemd/system` pointing at a character or
block device such as `/dev/null`, or an empty regular file. The unit loader
refuses to load a unit whose first match in the search path is such a file,
without falling through to a lower-priority real unit file. A masked unit
can therefore never be started, and it is not touched by presets. Mask a
unit in `/etc` to override a unit shipped under `/usr/lib`.

## Shipping a preset from a package

Install the file into the packaged preset directory, with a numeric prefix
that sorts it where you want it relative to other packages:

```
/usr/lib/systemd/system-preset/50-foo.preset
```

```
enable foo.service
enable foo.socket
```

The unit files must carry the `[Install]` section that a preset acts on:

```
[Install]
WantedBy=multi-user.target
```

An administrator or image recipe overrides a packaged file by installing one
with the same name into `/etc/systemd/system-preset`, or adds rules that sort
earlier in the name order. To deny everything not listed, the image ships a
catch-all at the end of the order:

```
# /usr/lib/systemd/system-preset/99-default.preset
disable *
```

Because presets are read from the image on first boot, a package needs no
post-install step and no call to `picoctl preset`. A unit that is enabled by
an existing symlink, for example one created at image build time by `picoctl
--root /path/to/rootfs enable foo.service`, is never overridden by a preset.

To check what the first boot will do from a build host, query the rules and
list the result against the rootfs:

```
picoctl --root /path/to/rootfs list-unit-files
picoctl --root /path/to/rootfs preset foo.service
```

The second command writes symlinks into the rootfs; it applies the decision
and does not just report it.
