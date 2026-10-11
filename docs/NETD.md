# netd and netctl

netd is pico-init's network daemon. It reads `systemd.network(5)` files from
the directories `systemd-networkd` uses, configures static IPv4 addresses and
a default route, runs a DHCPv4 client and server, writes `/etc/resolv.conf`,
sets the clock over SNTP, applies the time zone a DHCP server hands out, and
speaks LLDP. It is an ordinary service supervised by pico-init, not part of
PID 1. netctl is its `networkctl`-style client. This document is the
reference for both: which `.network` keys are implemented, which are not, what
netd writes to `/run/netd`, and what the netctl verbs print. For how the
daemons fit together see [ARCHITECTURE.md](ARCHITECTURE.md).

## Service

netd ships `netd.service` (`Restart=on-failure`, `RestartSec=2`,
`Before=network.target`, `WantedBy=default.target`) and a
passive `network.target`. There is no `After=` on a device manager: netd
subscribes to rtnetlink link events before it enumerates existing links, so an
interface that appears at any time is configured when it appears. The
shipped unit is enabled or not by the distribution's preset file (see
[PRESET.md](PRESET.md)). `network-online.target` is not provided.

Startup order:

1. Write `net.core.default_qdisc` (the first of `fq_codel`, `fq`, `cake` the
   kernel accepts) and `net.ipv4.tcp_congestion_control` (`bbr`). A kernel
   without them is not an error.
2. Move `CLOCK_REALTIME` forward if it is earlier than the clock floor (see
   [Clock floor](#clock-floor)).
3. Load every `.network` file.
4. Open the rtnetlink socket and subscribe to link events.
5. Bring `lo` up. It does not go through `.network` matching.
6. Enumerate existing links and configure them.
7. Start SNTP if `[Network] NTP=` named any server.

A link that matches a `.network` file is brought up before anything else is
applied. If its hardware address is random (`addr_assign_type` 1), the link
is down, it is Ethernet, and `/etc/machine-id` holds a real ID, netd first
sets a stable address derived from the machine ID and the interface name, the
way `systemd-networkd` does for `MACAddressPolicy=persistent`.

| Signal | Effect |
| --- | --- |
| `SIGHUP` | Re-read all `.network` files, re-match and reconfigure every link. |
| `SIGTERM`, `SIGINT` | Leave the event loop and exit 0. |

A reload replaces the running configuration only after the new set has been
built. A file that fails to parse is skipped with a warning; the other files
still load. A link whose match and configuration did not change is not
touched, so a reload does not drop a working lease.

## .network files

### Locations

Searched in this order, highest priority first:

| Directory | Purpose |
| --- | --- |
| `/etc/systemd/network` | Administrator configuration. |
| `/run/systemd/network` | Runtime configuration. |
| `/usr/lib/systemd/network` | Packaged defaults. |

Only files whose name ends in `.network` are read. A file name found in a
higher-priority directory shadows the same name in a lower one; the shadowed
file is never opened. The surviving files are sorted lexicographically by
file name, and the first file whose `[Match]` matches an interface is the one
used for it. Hence the usual `10-`, `15-` numeric prefixes keep their meaning.
Drop-in directories (`foo.network.d/`) are not read.

### Syntax

Section headers, `#` and `;` comments, backslash continuation and a leading
UTF-8 BOM are handled by the same scanner pico-init uses for unit files. A
malformed line skips that line, not the file. A key in a known section that
netd does not implement, and any unknown section, is accepted and dropped with
a debug-level log message; the file still loads. An assignment before the
first section header is dropped with a warning. A value that is invalid for an
implemented key is dropped with a warning and the key keeps its default.

Booleans accept `1`, `yes`, `y`, `true`, `t`, `on` and `0`, `no`, `n`,
`false`, `f`, `off`, case-insensitively.

### [Match]

| Key | Meaning |
| --- | --- |
| `Name=` | Space-separated list of `fnmatch(3)` globs matched against the interface name. |

`Name=` is the only match key. A file without `Name=` matches nothing; there
is no unconditional catch-all. Other `[Match]` keys (`MACAddress=`, `Driver=`,
`Type=`, `Host=` and so on) are not implemented, and a file using them
matches on `Name=` alone, or not at all if it has none.

### [Network]

| Key | Values | Behaviour |
| --- | --- | --- |
| `DHCP=` | `no`, `ipv4`, `ipv6`, `yes` (also `true`/`1`/`on`, `false`/`0`/`off`) | `yes` and `ipv4` start the DHCPv4 client. `ipv6` parses and does nothing. `yes` is IPv4 only in practice. Default `no`. |
| `Address=` | `a.b.c.d/nn` | Static IPv4 address. Only the first valid line is applied; later ones are parsed and ignored. A value without a prefix length is rejected. |
| `Gateway=` | IPv4 address | Static default route. |
| `DNS=` | IPv4 address literals, space-separated | Written to `/etc/resolv.conf`. A host name is rejected: netd has no resolver. |
| `NTP=` | IPv4 address literals, space-separated | SNTP servers. A host name is rejected. |
| `DHCPServer=` | boolean | Run a DHCPv4 server on the link. Default no. |
| `LLDP=` | boolean, `routers-only` | Receive LLDP neighbour announcements. Default no. |
| `EmitLLDP=` | boolean, `nearest-bridge`, `non-tpmr-bridge`, `customer-bridge` | Transmit LLDP to the given group address. `yes` means `nearest-bridge`. Default no. |

For `DNS=` and `NTP=` an invalid token is dropped and the remaining tokens
on the line are kept, and values accumulate across lines.

Each link has one default route, whether from `Gateway=` or from a lease. It
is installed with a metric of 100 plus the interface index, so two managed
uplinks keep separate, individually removable routes and the kernel prefers
the lower metric.

### [DHCPv4]

| Key | Default | Behaviour |
| --- | --- | --- |
| `UseDNS=` | yes | Use option 6 for `/etc/resolv.conf`. |
| `UseNTP=` | yes | Use option 42 as SNTP servers. |
| `UseTimezone=` | yes | Apply option 101 as the system time zone. |

`UseTimezone=` defaults to yes, where `systemd-networkd` defaults to no. An
explicit `UseTimezone=no` is honoured. See
[INCOMPATIBILITIES.md](INCOMPATIBILITIES.md) for the other differences.

### Example

```ini
# /etc/systemd/network/10-eth0.network
[Match]
Name=eth0

[Network]
DHCP=ipv4
LLDP=yes
EmitLLDP=nearest-bridge

# /etc/systemd/network/15-usb0.network
[Match]
Name=usb0

[Network]
Address=192.168.7.2/24
DHCPServer=yes
```

### Not implemented

Everything not listed above. Notably:

- IPv6: `DHCP=ipv6`, router advertisements, DHCPv6, `Address=` with an IPv6
  literal. The `[IPv6AcceptRA]` section and similar are dropped.
- `[Match]` keys other than `Name=`; `.link` and `.netdev` files; virtual
  devices (bridges, VLANs, bonds).
- `[Route]`, `[Address]` and `[DHCPServer]` sections and their keys, so the
  DHCP server's pool, lease times and options cannot be configured, and
  `Domains=`, `Hostname=`, `MTUBytes=`, `Bridge=` and `RequiredForOnline=`
  have no effect.
- DHCPv4 client keys such as `UseRoutes=`, `UseHostname=`, `ClientIdentifier=`
  and `RouteMetric=`.
- DHCP server static leases, lease persistence across a netd restart, relay
  and DHCPINFORM.
- Link-local addressing, `ConfigureWithoutCarrier=`, `ActivationPolicy=`.
- Host names in `DNS=` and `NTP=`.

Of what a DHCP lease carries, netd applies the address, the first router
(option 3) as the default route, DNS, the domain name as a `search` line, NTP
servers and the time zone. The host name, static and classless routes and the
MTU are not applied.

## DHCPv4 client

The client requests options 1 (subnet mask), 3 (router), 6 (DNS), 12 (host
name), 15 (domain name), 42 (NTP) and 101 (time zone). Option 100 (POSIX
time zone) is not used. A lease is applied by a direct function call, in this
order:

- Address, with the lease time as the kernel address lifetime. A renewal of
  the same address refreshes the lifetime in place. A changed address in the
  same subnet is replaced delete-first; a changed subnet is replaced
  add-first.
- A default route through the first router.
- `/run/netd/leases/<ifindex>`.
- `/etc/resolv.conf`, when `UseDNS=` allows.
- SNTP servers from option 42, when `UseNTP=` allows.
- The time zone from option 101, when `UseTimezone=` allows.

When a lease expires, is NAKed or is declined, netd removes the address and
route it added, and the client starts a new DISCOVER cycle by itself. When
netd starts and finds `/run/netd/leases/<ifindex>`, the client first asks for
that address by name (INIT-REBOOT).

The client identifier uses an IAID hashed from the MAC address. A board moved
from `systemd-networkd` therefore presents a different client identifier on
the same interface, and a DHCP server keyed on it may hand out a different
address.

## DHCPv4 server

`DHCPServer=yes` starts a server on the link. It needs an `Address=`; the
first one is the server address and the advertised router, and the pool is the
rest of that subnet, excluding the network and broadcast addresses and the
server address. The default lease time is one hour and the maximum is twelve
hours. `DNS=` and `NTP=` of the same file are offered to clients as options 6
and 42.

Leases live in memory and are forgotten when netd restarts; a client
asks again. A request with a non-zero `giaddr` is rejected. Offering the same
address to a client that DISCOVERs twice is done by hashing the client
identifier into the pool, without remembering anything.

If `DHCPServer=yes` is set without an `Address=`, the link goes to `failed`.

## DNS: /etc/resolv.conf

netd writes `/etc/resolv.conf` directly, replacing it atomically with
a temporary file and `rename(2)`. The file is rebuilt from scratch whenever
any link's DNS state changes:

- Per link, in link order: the static `DNS=` addresses, then the lease's
  option 6 addresses unless `UseDNS=no`.
- Duplicates are removed and the list is capped at three `nameserver` lines.
- The first lease's domain name (option 15) becomes one `search` line.
- When there is no nameserver and no search domain, the existing file is
  left alone. netd never replaces a working file with an empty one.

The first line is `# generated by netd -- do not edit`.

## Time

### SNTP

netd has one SNTP client. Its servers are the union of `[Network] NTP=` over
all loaded files (at startup and on reload) or, when a DHCP lease supplies
option 42 and `UseNTP=` allows, the servers from that lease; each source
replaces the list, so stale entries do not accumulate. At most eight servers
are kept. The client asks one server at a time, round-robin.

| Parameter | Value |
| --- | --- |
| Resync interval | 2048 s, fixed |
| Retry while unanswered | 10 s |
| Maximum root distance | 5 s |

A reply is discarded when any of these hold: shorter than the NTP header; no
request outstanding; not from the server asked; origin timestamp not equal to
the transmitted nonce; zero transmit timestamp; receive or transmit time
before 2026-01-01T00:00:00Z; leap indicator 3; stratum 0 or 16 and above;
version other than 3 or 4; mode other than server; root distance above the
maximum.

An accepted reply gives an offset by RFC 5905. An offset of 0.4 s or more
steps the clock with `clock_adjtime(ADJ_SETOFFSET)`; a smaller one is slewed.
netd does not write the RTC itself; with `STA_UNSYNC` clear, the kernel's
periodic RTC update does it. There is no poll-interval backoff, no
statistical filtering and no D-Bus interface.

### Clock floor

netd keeps `/var/lib/netd/clock`, an empty file whose modification time is
the time of the last accepted sync. At startup, if `CLOCK_REALTIME` is earlier
than the later of that time and 2026-01-01T00:00:00Z, netd sets it to that
time plus one second, so a board without a working RTC does not start in 1970.

### Time zone from DHCP

Option 101 is validated as a TZDB name (no leading `/`, no `..`) that exists
under `/usr/share/zoneinfo`, then installed by atomically replacing the
`/etc/localtime` symlink. An empty value or `UTC` removes the symlink. netd
then calls `tzset()` and passes the offset to the kernel with
`settimeofday()`; a failure of the kernel call is logged and ignored.
Processes that are already running pick the change up the next time glibc
re-stats `/etc/localtime`.

## LLDP

`LLDP=` receives and `EmitLLDP=` transmits, on one `AF_PACKET` socket per
link that is open only while at least one is enabled.

Receive follows a strict parser: ethertype 0x88cc, one of the three reserved
group addresses, a unicast non-zero source, and Chassis ID, Port ID and TTL as
the first three TLVs. A frame is accepted or rejected whole. `routers-only`
keeps neighbours with at least one enabled repeater, bridge, WLAN access
point, router, DOCSIS, C-VLAN, S-VLAN or TPMR capability, and neighbours that
send no capabilities TLV. At most 8 neighbours are held per link. When
the table is full, frames from unknown neighbours are dropped and the existing
ones stay until they expire. At most 16 frames are read per wakeup. Carrier
loss forgets all neighbours.

Transmit sends a frame every 30 s with a TTL of 120 s, and four frames one
second apart after carrier comes up or a new neighbour appears. Nothing is
sent while there is no carrier. A TTL 0 frame is sent when LLDP is turned off
on a link, when the link is deconfigured, and when netd stops. Frames carry:

- Chassis ID: a 32-character hash of the machine ID as a local identifier, or
  the MAC address when there is no machine ID.
- Port ID: the interface name.
- System name: the host name, when one is set.
- System description: the OS pretty name.
- Capabilities: station and router; router is marked enabled when IPv4
  forwarding is on.
- Management address: the link's configured IPv4 address, when it has one.

## Files netd writes

The files under `/run/netd`, `/etc/resolv.conf` and `/etc/localtime` are
replaced atomically (temporary file or symlink and `rename(2)`). `/run/netd`
is tmpfs.

| Path | Content |
| --- | --- |
| `/run/netd/links/<ifindex>` | Link state, one `KEY=VALUE` per line. Written for every link. |
| `/run/netd/leases/<ifindex>` | The applied DHCP lease. Present while a lease is held. |
| `/run/netd/lldp/<ifindex>` | LLDP neighbours. Removed when the table is empty. |
| `/etc/resolv.conf` | See [DNS](#dns-etcresolvconf). |
| `/etc/localtime` | Symlink to the DHCP-supplied zone. |
| `/var/lib/netd/clock` | Mtime marks the last accepted SNTP sync. |

The formats are netd's own and stable; they are not `systemd-networkd`'s
state files.

### links/&lt;ifindex&gt;

```
IFNAME=usb0
STATE=configured
NETWORK=/etc/systemd/network/15-usb0.network
```

`STATE` is one of the following. `NETWORK` is omitted when no file matched.

| STATE | Meaning |
| --- | --- |
| `pending` | Seen on netlink, not yet matched. |
| `unmanaged` | No `.network` matched; netd leaves the link alone. |
| `configuring` | Matched; the link is up and static configuration applied, DHCP has no lease yet. |
| `configured` | Everything the file asked for is in the kernel. |
| `failed` | A step failed. Retried on `SIGHUP` or the next link event. |

### leases/&lt;ifindex&gt;

```
ADDRESS=192.168.1.23
PREFIXLEN=24
ROUTER=192.168.1.1
DNS=192.168.1.1 9.9.9.9
NTP=192.168.1.1
TIMEZONE=Europe/Amsterdam
LIFETIME=86400
T1=43200
T2=75600
```

An option the lease did not carry is an absent line, never an empty value.
`LIFETIME`, `T1` and `T2` are in seconds. `DNS` and `NTP` are space-separated.

### lldp/&lt;ifindex&gt;

The first line is `IFNAME=<name>`. Each following line is one neighbour,
`N` followed by space-separated `key=value` fields:

```
N expires=123456 src=00:11:22:33:44:55 scope=nearest-bridge chassis=4:00:11:22:33:44:55 port=5:ge-0/0/1 name=sw1 caps=0014 enabled=0004 mgmt=192.168.1.2
```

| Field | Content |
| --- | --- |
| `expires` | Expiry in seconds on the monotonic clock. |
| `src`, `scope` | Source MAC and the group address the frame arrived on. |
| `chassis`, `port` | `<subtype>:<id>`. |
| `descr`, `name`, `sysdescr` | Port description, system name, system description; present when set. |
| `caps`, `enabled` | Capability bit masks in hex, present when the frame has them. |
| `mgmt` | Management IPv4 address. |
| `vlan` | Port VLAN ID. |
| `mud` | MUD URL. |

Any byte outside printable ASCII, and `%` and `=`, is written as `%XX`.

## netctl

netctl reads kernel state (sysfs, `getifaddrs(3)`, `/proc/net/route`, an
rtnetlink query, `/etc/resolv.conf`) and the files above. It does not talk to
netd, so `list`, `status` and `lldp` work when netd is not running; `reload`
is the only verb that needs it. It is installed in `bindir`. Colours follow
`networkctl`'s rules: on for a terminal, off for `NO_COLOR` or `TERM=dumb`,
and forced by `SYSTEMD_COLORS`. Without a
verb, `list` runs.

| Verb | Description |
| --- | --- |
| `list` | One line per interface. |
| `status [LINK]` | System status, or detail for one interface. |
| `lldp [LINK...]` | Neighbours heard, optionally filtered by interface name. |
| `reload` | Send `SIGHUP` to netd. |

An unknown verb prints `networkctl: unknown command '<verb>'` and exits 2.
Error messages are prefixed `networkctl:`.

### list

```
IDX LINK     TYPE     OPERATIONAL SETUP
  2 eth0     ether    routable    configured
  3 usb0     ether    no-carrier  configuring

2 links listed.
```

`TYPE` is `bridge`, `loopback`, `ether` or `other`. `OPERATIONAL` comes from
`/sys/class/net/<if>/operstate`: `up` is shown as `routable` when the link has
an IPv4 or IPv6 address that is not loopback or link-local, and as `carrier`
otherwise; `down` is shown as `no-carrier`; other kernel states are shown as
they are. `SETUP` is `STATE` from `links/<ifindex>`, or `unmanaged` when that
file does not exist. The trailer is always `N links listed.`, including
for N = 1.

### status

Without an argument, the system view: the interface indices, the aggregate
`State` (`routable`, `carrier` or `no-carrier`), `Online state` (always
`unknown`), then `Address` (as `<addr> on <iface>`), `Gateway` (default routes
from `/proc/net/route`), `DNS` and `Search Domains` from `/etc/resolv.conf`,
and `NTP` collected from the `NTP=` lines of all lease files.

With an interface name, the detail view. Rows are omitted when netd or the
kernel has no value for them:

| Row | Source |
| --- | --- |
| `Network File` | `NETWORK` from `links/<ifindex>`. |
| `State` | Operational state and, in parentheses, the setup state. |
| `Online state` | Always `unknown`. |
| `Type` | `bridge` (sysfs), otherwise from the ARPHRD value. |
| `Path` | A `ID_PATH`-style identifier derived from sysfs. |
| `Driver` | Basename of `device/driver`. |
| `Vendor`, `Model` | USB `manufacturer` and `product` descriptors. |
| `Alternative Names` | rtnetlink. |
| `Hardware Address` | sysfs. |
| `MTU` | rtnetlink, with `min` and `max` when reported. |
| `QDisc` | rtnetlink. |
| `IPv6 Address Generation Mode` | rtnetlink. |
| `Number of Queues (Tx/Rx)` | rtnetlink. |
| `Address` | `getifaddrs(3)`, without prefix length. |
| `Gateway` | Default routes on that interface. |

An unknown interface name prints `networkctl: unknown interface '<name>'` to
standard error; the exit status is 0.

Not shown, because netd computes none of it: `.link` and `.netdev` files,
activation policy, required-for-online, route domains and offered DHCP
leases.

### lldp

The columns are `LINK`, `CHASSIS-ID`, `SYSTEM-NAME`, `CAPS`, `PORT-ID` and
`PORT-DESCRIPTION`. When there are neighbours, a capability legend follows.
The last line is `N neighbors listed.` (`neighbor` for N = 1), also for 0.
`CAPS` has eleven positions, one letter per capability or `.` when absent:
`o` other, `p` repeater, `b` bridge, `w` WLAN access point, `r` router,
`t` telephone, `d` DOCSIS, `a` station, `c` customer VLAN, `s` service VLAN,
`m` TPMR. Rows are sorted by link, then chassis ID. At most 256 neighbours
are listed. Entries whose expiry has passed, such as those left by a netd
that is no longer running, are skipped. Every string comes from the network
and is reduced to printable ASCII before it is shown.

### reload

Finds netd by scanning `/proc/<pid>/comm` for `netd` (there is no pid file)
and sends `SIGHUP`. It exits 1 with `networkctl: netd is not running` when no
such process exists, and 0 once the signal is sent. It does not wait for the
reload to finish. Copying a file into `/etc/systemd/network` and running
`netctl reload` is the whole reconfiguration interface; netd has no D-Bus or
Varlink API.
