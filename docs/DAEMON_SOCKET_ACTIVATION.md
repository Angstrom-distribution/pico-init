# Socket Activation of Daemons

pico-init implements the `sd_listen_fds()` flavour of socket activation: PID 1
binds the listening sockets of a `.socket` unit, and hands them to the paired
`.service` as file descriptors starting at 3, announced through `LISTEN_PID`
and `LISTEN_FDS`. A socket unit has four states, no `Exec*=` lines, and no
D-Bus. This document lists what is honoured, how the descriptors reach the
daemon, how `Accept=yes` instances behave, and where this differs from
systemd. Unit file syntax is that of systemd; the sources are `src/socket.c`,
`src/service-exec.c`, `src/unit-parse.c` and
`src/compat/libsystemd/sd-daemon.c`.

## Supported directives

All in the `[Socket]` section.

| Directive          | Behaviour                                                   |
|--------------------|-------------------------------------------------------------|
| `ListenStream=`    | Absolute path (AF_UNIX stream) or a bare port number.       |
| `ListenDatagram=`  | Same, datagram.                                             |
| `Service=`         | Name of the paired service. Not allowed with `Accept=yes`.  |
| `Accept=`          | Boolean, default no. See below.                             |
| `SocketMode=`      | Octal, default `0666`. AF_UNIX paths only.                  |
| `Backlog=`         | Positive integer, default `INT_MAX`.                        |
| `MaxConnections=`  | Positive integer, default 64. Only used with `Accept=yes`.  |

A bare port must be 1 to 65535. `ListenStream=addr:port`, `ListenFIFO=`,
`ListenSequentialPacket=`, `ListenSpecial=`, `ListenMessageQueue=`,
`ListenNetlink=` and every other directive are not implemented. They are
logged at debug level, ignored, and recorded as degraded directives of the
unit; `PassCredentials=` is one of them, see
[Datagram sockets](#datagram-sockets). A malformed value of a supported
directive is logged as a warning and ignored, leaving the default. A path
that does not fit `sun_path` is dropped with a warning.

A socket unit with no valid `Listen*=` line refuses to load. Under
`Accept=yes`, a `Service=` line or any `ListenDatagram=` line also makes it
refuse to load.

## Binding

Sockets are bound when the `.socket` unit starts, not lazily. Every socket is
created `SOCK_NONBLOCK|SOCK_CLOEXEC`.

- AF_UNIX: missing parent directories are created with mode 0755. If `bind()`
  fails with `EADDRINUSE` and the existing path is a socket, it is unlinked
  and `bind()` is retried. Anything else at the path is never removed.
  `SocketMode=` is applied through the umask around `bind()` and is exact,
  independent of the process umask.
- Bare port: the wildcard address. If `/proc/net/if_inet6` exists the socket is
  AF_INET6 (`in6addr_any`), otherwise AF_INET. The choice is made at bind time.
  `IPV6_V6ONLY` is not set, so dual-stack behaviour follows the sysctl.
- `SO_REUSEADDR` is set on every socket.
- Stream sockets `listen()` with `Backlog=`; the kernel clamps it to
  `net.core.somaxconn`.

If any port fails to bind, the ports already opened are closed again and the
unit goes to `failed`.

On an orderly stop the sockets are closed, and an AF_UNIX path is unlinked only
if it still refers to the inode this unit bound. Failure and teardown paths do
not unlink.

## Socket unit states

| State       | Meaning                                                          |
|-------------|------------------------------------------------------------------|
| `dead`      | Not started, or stopped.                                         |
| `listening` | Descriptors open and watched by PID 1.                           |
| `running`   | Descriptors open but not watched: they belong to the service.    |
| `failed`    | Bind failed, trigger rate limit hit, or paired service gone.     |

`listening` and `running` are both reported as active.

## Pairing and ordering

Without `Accept=yes`, the paired service is `Service=` if given, otherwise the
unit name with `.socket` replaced by `.service`. It is loaded when the socket
unit is loaded, and a socket whose service cannot be resolved refuses to load.
The socket gets an implicit `Before=` on its service, and every loaded
service gets `After=sockets.target` unless the unit file orders itself
explicitly against that target.

Enable a socket the usual way, with `WantedBy=sockets.target` in `[Install]`
(see [PRESET.md](PRESET.md)). `src/logd/logd.socket` is an example.

## What triggers the service

PID 1 watches the listening descriptors for readability while the socket is
`listening`.

Without `Accept=yes`, PID 1 never calls `accept()`. On the first wakeup it
queues a start job for the paired service and moves to `running`, which stops
watching the descriptors. If the service is already active, activating, or has
a job pending, no new job is queued. The connection or datagram stays in the
kernel queue for the daemon to pick up.

When a service is started for any other reason (for example `WantedBy=` at
boot) it receives the descriptors in the same way, and the socket moves from
`listening` to `running` just before the fork.

When the paired service reaches a terminal state, the socket moves back to
`listening` and its descriptors are watched again, so the next connection
starts the service again and queued data is not lost. The exception is a
service that failed because it exceeded its own start limit: the socket then
goes to `failed` rather than re-triggering the same crash loop.

Triggers are rate limited at 20 per 2 seconds (200 per 2 seconds with
`Accept=yes`). The values are fixed; `TriggerLimitIntervalSec=` and
`TriggerLimitBurst=` are not parsed. Exceeding the limit puts the socket in
`failed` and closes its descriptors.

While a stop or restart job is queued for the socket, readable data is
discarded in place (an `accept()` and `close()` per stream connection, a
`recv()` per datagram) so that it does not keep waking PID 1.

## Passing the descriptors: LISTEN_FDS

The service's main command (`ExecStart=`) gets the descriptors. `ExecStartPre=`
and the other control commands do not.

In the child, after the fork and before `execve()`:

- All other descriptors are closed, except those below.
- The socket descriptors are renumbered to a contiguous run starting at 3
  (`SD_LISTEN_FDS_START`), in declared `Listen*=` order.
- `O_NONBLOCK` and `FD_CLOEXEC` are cleared on them, so a daemon sees blocking
  descriptors unless it changes that.
- `LISTEN_PID` is set to the child's own PID.
- `LISTEN_FDS` is set to the number of descriptors.

If renumbering fails the start fails; the daemon is not started with a partial
set. At most `PICO_MAX_SOCKET_FDS` (16) descriptors can be passed to one
service; with more, none are passed and a warning is logged.

If several socket units are paired with the same service, the descriptors are
concatenated in the order of the manager's unit table.

Any `LISTEN_*` and `NOTIFY_SOCKET` variables inherited by PID 1 are discarded
first. A `LISTEN_PID=` from `Environment=` or `EnvironmentFile=` is dropped
whenever descriptors are passed, so a unit cannot set it.

### LISTEN_FDNAMES

`LISTEN_FDNAMES` is not set, and `FileDescriptorName=` is not parsed.
`sd_listen_fds_with_names()` therefore returns the name `unknown` for every
descriptor. A daemon that needs to tell its descriptors apart relies on the
declared order or on `sd_is_socket_unix()` and friends.

### LISTEN_PIDFDID

Not set.

## Consuming the descriptors

pico-init ships a `libsystemd` compatibility library whose `sd-daemon` is
symbol-compatible with systemd (see
[COMPATIBILITY_LIBRARIES.md](COMPATIBILITY_LIBRARIES.md)). A daemon written
for systemd needs no change:

```c
int n = sd_listen_fds(1);        /* 1: unset LISTEN_* afterwards */
if (n < 0)
        return n;
if (n == 0)
        /* not socket activated: bind our own socket */;
for (int fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++)
        if (sd_is_socket_unix(fd, SOCK_STREAM, 1, "/run/foo.sock", 0) > 0)
                /* use fd */;
```

`sd_listen_fds()` checks that `LISTEN_PID` equals `getpid()`, parses
`LISTEN_FDS` strictly (a non-positive or overflowing value is `-EINVAL`),
sets `FD_CLOEXEC` again on each descriptor, and optionally unsets the
variables. `sd_listen_fds_with_names()`, `sd_is_socket()`,
`sd_is_socket_inet()`, `sd_is_socket_unix()`, `sd_is_fifo()`,
`sd_is_special()` and `sd_is_mq()` are exported too.

A daemon that does not link `libsystemd` can do the same by hand: compare
`LISTEN_PID` with its PID, read `LISTEN_FDS`, and use descriptors 3 to
`3 + LISTEN_FDS - 1`. `src/logd/logd.c` does this.

Daemon guidelines that follow from the implementation:

- Do not call `bind()` on a descriptor you were given. PID 1 already did.
- Without `Accept=yes`, `accept()` on the descriptor yourself. PID 1 never
  does.
- Exiting does not close the socket: PID 1 keeps its own copy, so queued
  connections survive a service restart.

## Accept=yes

With `Accept=yes`, PID 1 calls `accept4()` itself, once per wakeup, and starts
a separate service instance for each connection. Only stream ports are
allowed. A `ListenDatagram=` line, including an AF_UNIX path, and `Service=`
make the unit fail to load.

The socket stays in `listening` throughout; it never moves to `running`.

### Instance names

The instance unit is `<prefix>@<instance>.service`, where `<prefix>` is the
socket unit's name without its suffix and the unit file is the template
`<prefix>@.service` (so `%i` expands to the instance). The instance string is

| Listener   | Instance                                  |
|------------|-------------------------------------------|
| IPv4       | `<nr>-<local-ip>:<port>-<remote-ip>:<port>` |
| IPv6       | `<nr>-<local-ip>:<port>-<remote-ip>:<port>` |
| AF_UNIX    | `<nr>-<peer-pid>-<peer-uid>`               |

`<nr>` is a counter per socket unit, starting at 0 and increased for every
accepted connection, so each name is unique even for repeated connections from
the same peer. On a dual-stack socket, IPv4 peers are written as dotted
quads rather than `::ffff:` addresses.

Example: `dropbear.socket` with `ListenStream=22` yields instances such as
`dropbear@0-192.0.2.1:22-192.0.2.77:50412.service`.

If the template is missing or fails to load, the connection is closed and the
socket keeps listening. So is the case where the name is already taken.

### Descriptor and lifetime

The instance gets exactly one descriptor, the accepted connection, as
`LISTEN_FDS=1` descriptor 3, or on fd 0 to 2 with `StandardInput=socket`.
PID 1 keeps its own copy of the connection descriptor for as long as the
instance exists.

When an instance is inactive or failed and has no job left, PID 1 closes its
copy of the connection and removes the instance from the unit table. This runs
deferred, after the event that ended the instance has been handled. An
instance that is still running, restarting, or has a job stays.
`MaxConnections=` limits the number of instances alive at the same time per
socket unit. A connection that arrives beyond the limit is accepted and closed
immediately, with a warning. The default is 64.

An instance is an ordinary service: `ExecStart=`, `User=`, `KillMode=`,
`Delegate=` and the rest of the `[Service]` section apply. With
`KillMode=process` an instance's children outlive it, which is how a login
shell started by a socket-activated `dropbear@` survives the instance exiting.

## StandardInput=socket

`StandardInput=socket` in a `[Service]` section selects inetd-style handling:
the connection is duplicated onto file descriptors 0, 1 and 2 of the main
command, and `LISTEN_PID` is not set, so `sd_listen_fds()` returns 0 in the
child. The original descriptor is closed afterwards. A daemon that serves
one connection on stdin and stdout, such as `dropbear -i`, can run unmodified.

Rules as implemented:

- It applies when exactly one descriptor was collected for the service, which
  is the `Accept=yes` case. It is meant for `Accept=yes` instances; with a
  plain socket holding a single listening descriptor the same code path would
  put the listening descriptor on fd 0, which is not useful.
- stdout and stderr cannot be set independently: all three go to the
  connection. `StandardOutput=` and `StandardError=` do not override it.
- `LISTEN_FDS=1` is still exported without `LISTEN_PID`, which
  `sd_listen_fds()` treats as "not for me".

`StandardInput=tty`, `tty-force` and `tty-fail` are also supported. An
`Accept=yes` instance with one of those receives its connection via
`LISTEN_FDS`. Any other `StandardInput=` value (`null`, `file:`, `data` and so
on) is recorded as a degraded directive, and an `Accept=yes` instance
requesting it is refused: the connection is closed and the instance is not
started, rather than running with the console on stdin.

## Datagram sockets

On an AF_UNIX `ListenDatagram=` port, `SO_PASSCRED` is set before `bind()`.
The kernel decides at queue time whether to attach credentials, so setting it
only in the daemon is too late for datagrams that were queued while the
daemon was not running. `PassCredentials=` is therefore not needed; it is not
parsed and is recorded as a degraded directive. Other socket options
(`ReceiveBuffer=`, `Broadcast=` and so on) are not implemented.

## Differences from systemd

- `FileDescriptorName=` and `LISTEN_FDNAMES` are absent.
- Only the seven directives listed above are parsed. In particular there are
  no `Exec*=` lines in `[Socket]`, and no `TriggerLimit*=`, `FlushPending=`,
  `RemoveOnStop=`, `Symlinks=`, `DirectoryMode=`, `SocketUser=`,
  `SocketGroup=`, `Transparent=`, `FreeBind=`, `ReusePort=`, `KeepAlive=` or
  `PollLimit*=`.
- Unlinking the AF_UNIX path on stop is always on, guarded by an inode
  comparison.
- The paired service may be named only with `Service=`; `Sockets=` in
  `[Service]` is not parsed, so a service cannot claim a socket that is not
  paired with it by name.
- Listening sockets are never passed to `ExecStartPre=` commands.
- `Accept=yes` instance names carry a counter prefix.
- `Accept=yes` is limited to stream ports.
- `StandardInput=socket` forces stdout and stderr onto the connection.
- `LISTEN_PIDFDID` is not produced; `sd_listen_fds()` honours it if some other
  supervisor sets it.
- Every loaded service is ordered `After=sockets.target`, so boot-time
  services do not race the binding of their own socket.

See [INCOMPATIBILITIES.md](INCOMPATIBILITIES.md) for the general list and
[ARCHITECTURE.md](ARCHITECTURE.md) for how units are loaded and jobs are
queued.
