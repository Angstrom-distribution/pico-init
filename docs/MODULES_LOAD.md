# Loading modules at boot

`pico-modules-load` loads the kernel modules that `modules-load.d` and the kernel command line name, the job of `systemd-modules-load.service`. It is a separate program, installed as `/usr/sbin/pico-modules-load` and started by `systemd-modules-load.service`. [devd](DEVD.md) loads the modules that devices ask for by `MODALIAS`; this covers the modules no device asks for, such as virtual devices, file systems, and crypto and netfilter modules.

## Where the names come from

- `modules_load=a,b` and `rd.modules_load=a,b` on the kernel command line. The spellings with `-` are read too. These are loaded first. `rd.modules_load=` is read on the real root as well as in an initrd; systemd ignores it outside the initrd.
- The `*.conf` files of `/etc/modules-load.d`, `/run/modules-load.d`, `/usr/local/lib/modules-load.d`, `/usr/lib/modules-load.d` and `/lib/modules-load.d`; systemd's program does not read the last one itself.

A file with the same name in an earlier directory hides the one in a later directory, whatever it holds, so an empty file or a link to `/dev/null` in `/etc/modules-load.d` switches a packaged file off. Files are read in order of file name, not of directory. Hidden files, names that do not end in `.conf`, and entries that are not regular files (a link to `/dev/null` counts as empty) are not read; a read error is logged and the file is skipped.

In a file, a line is one module name. Leading and trailing white space is removed, and empty lines and lines that start with `#` or `;` are ignored. A line of 4096 bytes or more is skipped with a warning. `-` and `_` in a module name are the same module, so `snd-dummy` and `snd_dummy` are loaded once.

## What it does

Each distinct name is passed to `/sbin/modprobe -b -- <name>` once, one run after another. A name that modprobe refuses is logged as `modules-load: failed to load '<name>': ...` and the next name is still tried. When any name failed, the program exits with status 1 after the last one, so the unit shows as failed; nothing waits on that. `-b` makes a blacklist entry stop the module, as in systemd; `modprobe` has to accept it; busybox applies the blacklist only when built with `FEATURE_MODPROBE_BLACKLIST`. A module the kernel does not have also fails the unit, because modprobe's exit status does not tell that from other failures; systemd only warns about it.

When no directory has a `*.conf` file and the command line has no `modules_load=`, the program exits with status 0 without starting modprobe. The unit has no `Condition*=` lines for this, because pico-init has no `ConditionDirectoryNotEmpty=` or `ConditionKernelCommandLine=`.

## The unit

```ini
[Unit]
Description=Load Kernel Modules
DefaultDependencies=no
Conflicts=shutdown.target
Before=sysinit.target shutdown.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/pico-modules-load
TimeoutSec=90

[Install]
WantedBy=sysinit.target
```

The unit has systemd's name, so `After=systemd-modules-load.service` in other units keeps working. `modprobe` has to be installed; see [DISTRO_PORTING](DISTRO_PORTING.md). The unit is enabled by the preset file like any other, for example `enable systemd-modules-load.service`. Unlike systemd's, it has an `[Install]` section and is not linked into `sysinit.target.wants/` statically, so a distro whose presets do not enable it never loads `modules-load.d`.

## Testing

`test-modules-load` runs fixture directories and command lines through a stand-in for modprobe that records the names it is given. See [HACKING](HACKING.md).
