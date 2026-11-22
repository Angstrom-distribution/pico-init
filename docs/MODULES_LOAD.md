# Loading modules at boot

`pico-modules-load` loads the kernel modules that `modules-load.d` and the kernel command line name, the job of `systemd-modules-load.service`. It is a separate program, installed as `/usr/sbin/pico-modules-load` and started by `systemd-modules-load.service`. [devd](DEVD.md) loads the modules that devices ask for by `MODALIAS`; this covers the modules no device asks for, such as virtual devices, file systems, and crypto and netfilter modules.

## Where the names come from

- `modules_load=a,b` and `rd.modules_load=a,b` on the kernel command line. The spellings with `-` are read too. These are loaded first. `rd.modules_load=` is read on the real root as well as in an initrd; systemd ignores it outside the initrd.
- The `*.conf` files of `/etc/modules-load.d`, `/run/modules-load.d`, `/usr/local/lib/modules-load.d`, `/usr/lib/modules-load.d` and `/lib/modules-load.d`; systemd's program does not read the last one itself.

A file with the same name in an earlier directory hides the one in a later directory, whatever it holds, so an empty file or a link to `/dev/null` in `/etc/modules-load.d` switches a packaged file off. Files are read in order of file name, not of directory. Hidden files, names that do not end in `.conf`, and entries that are not regular files (a link to `/dev/null` counts as empty) are not read; a read error is logged and the file is skipped.

In a file, a line is one module name. Leading and trailing white space is removed, and empty lines and lines that start with `#` or `;` are ignored. A line of 4096 bytes or more is skipped with a warning. `-` and `_` in a module name are the same module, so `snd-dummy` and `snd_dummy` are loaded once.

## What it does

Each distinct name is passed to `/sbin/modprobe -b -- <name>` once, one run after another. A name that modprobe refuses is logged as `modules-load: failed to load '<name>': ...` and the next name is still tried. When any name failed, the program exits with status 1 after the last one, so the unit shows as failed; nothing waits on that. A module the kernel does not have also fails the unit, because modprobe's exit status does not tell that from other failures; systemd only warns about it.

## Blacklists

systemd-modules-load asks libkmod to apply the blacklist to every module it loads (`KMOD_PROBE_APPLY_BLACKLIST`), including a module named directly, which plain `modprobe` does not do. `-b` is the modprobe option with that effect, and pico-modules-load always passes it. The modprobe flavours differ in what they do with it:

- kmod's `modprobe` always skips a blacklisted alias; `-b` adds a module named directly. A skipped module is not an error, modprobe exits 0 and loads nothing.
- busybox accepts `-b` in every build, including `modprobe-small`. A build with `FEATURE_MODPROBE_BLACKLIST` applies `blacklist` lines to directly named modules only with `-b`; a build without it ignores the option and loads the module.
- toybox accepts `-b` as well, with the same meaning.

Since every flavour accepts the option, there is no probe of which modprobe is installed. A modprobe that rejects `-b` would fail every module, and the unit with it.

The kernel has its own list, `module_blacklist=` on the command line. The kernel refuses such a module and modprobe reports a plain failure. systemd recognises that case by the errno; modprobe's exit status does not carry it, so pico-modules-load checks the list after a failure and treats a listed name (with `-` and `_` alike) as deny-listed, logged at info level and not counted as failed. Only the name as written in the configuration is compared, not the module an alias resolves to.

When no directory has a `*.conf` file and the command line has no `modules_load=`, the program exits with status 0 without starting modprobe. The unit's `Condition*=` lines keep it from starting in that case, and the program's own exit covers a directory that holds only other files.

## The unit

```ini
[Unit]
Description=Load Kernel Modules
DefaultDependencies=no
Conflicts=shutdown.target
Before=sysinit.target shutdown.target
ConditionDirectoryNotEmpty=|/lib/modules-load.d
ConditionDirectoryNotEmpty=|/usr/lib/modules-load.d
ConditionDirectoryNotEmpty=|/usr/local/lib/modules-load.d
ConditionDirectoryNotEmpty=|/etc/modules-load.d
ConditionDirectoryNotEmpty=|/run/modules-load.d
ConditionKernelCommandLine=|modules-load
ConditionKernelCommandLine=|modules_load
ConditionKernelCommandLine=|rd.modules-load
ConditionKernelCommandLine=|rd.modules_load

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/pico-modules-load
TimeoutSec=90

[Install]
WantedBy=sysinit.target
```

The unit starts when one of the five directories has an entry that is not hidden or a backup file, or the kernel command line has one of the four spellings of `modules_load` or `rd.modules_load`, as systemd's does. It has no `ConditionCapability=CAP_SYS_MODULE`, which pico-init does not implement. See [Conditions](INCOMPATIBILITIES.md#conditions). The unit has systemd's name, so `After=systemd-modules-load.service` in other units keeps working. `modprobe` has to be installed; see [DISTRO_PORTING](DISTRO_PORTING.md). The unit is enabled by the preset file like any other, for example `enable systemd-modules-load.service`. Unlike systemd's, it has an `[Install]` section and is not linked into `sysinit.target.wants/` statically, so a distro whose presets do not enable it never loads `modules-load.d`.

## Testing

`test-modules-load` runs fixture directories and command lines through a stand-in for modprobe that records the names it is given, with stand-ins that behave like kmod and like busybox for `-b`, and, when kmod's `modprobe`, `depmod` and a C compiler are installed, through the real `modprobe --dry-run` against a fixture module tree with a `blacklist` line. See [HACKING](HACKING.md).
