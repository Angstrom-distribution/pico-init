/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * networkctl -- a client for netd, not netd itself.
 *
 * Unlike picoctl (which genuinely talks to PID 1's own control surface),
 * netd has no IPC of its own to query: LinkState's comment in netd-link.h
 * says so explicitly -- "netd has no status CLI for anyone to read a finer
 * distinction from". So this does not invent one. `status` reads kernel
 * ground truth (sysfs + getifaddrs(3) + /proc/net/route + /etc/resolv.conf)
 * plus the two small documented text files netd itself publishes for this
 * purpose -- /run/netd/links/<ifindex> (setup state, matched .network) and
 * /run/netd/leases/<ifindex> (DNS/NTP/router, when DHCP actually leased
 * them) -- without a round trip through netd at all; it works even if netd
 * is not running. `reload` is the one verb that genuinely needs netd: it
 * SIGHUPs the live process, which netd-loop.c's signal handler already
 * turns into a config reload.
 *
 * Exists because bt-pan-client.sh (meta-handhelds) hard-requires a
 * `networkctl` binary on $PATH and calls `reload` and `status <iface>`.
 * Output is modelled on real systemd's own `networkctl`/`networkctl
 * status`/`networkctl status IFACE`, close enough to be useful to someone
 * who already knows that tool, but it does not claim fields netd has no way
 * to back honestly. Driver, Vendor and Model are sysfs reads with no
 * rtnetlink equivalent (real networkctl's own ID_NET_DRIVER/vendor/model
 * resolve through udev/hwdb this tree does not have); `status <iface>`'s
 * kernel-sourced rows (Type, Alternative Names, MTU min/max, QDisc, IPv6
 * Address Generation Mode, Number of Queues) come from one
 * netctl_rtnl_get_link() round trip (netctl-rtnl.c) -- this file's own tiny
 * rtnetlink client, built from netd-rtnl-core.c only, with no link to
 * netd_core or pico_init_core: `networkctl` stays a standalone binary that
 * works whether or not netd is running, it just now also talks to the
 * kernel directly for the handful of fields sysfs cannot answer. Path is a
 * third source again (netctl-path.c, a scope-limited udev builtin_path_id()
 * port over plain sysfs directory walking -- no netlink involved). Still
 * missing, because nothing in this tree computes them: NetDev/Link File (no
 * udev .link matching), Activation Policy and Required For Online (.network
 * directives netd-network.c does not implement), and Route Domains
 * (networkd's per-link Domains=~ routing-only domains) -- netd tracks none
 * of them. Offered DHCP leases is omitted too: it is a DHCP-server-only row,
 * and DhcpServerLease state is kept in memory only
 * (dhcp-server-lease-internal.h), with nothing published for this file to
 * read even when a link is running one.
 */

#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "netctl-path.h"
#include "netctl-rtnl.h"

#define NETD_LINKS_DIR "/run/netd/links"
#define NETD_LEASES_DIR "/run/netd/leases"

/* --- reload: SIGHUP the running netd ---------------------------------- */

/*
 * Finds netd's pid by scanning /proc for a /proc/<pid>/comm equal to "netd".
 * No pidfile exists to read instead -- netd is supervised by pico-init, which
 * tracks its MainPid internally, but exposing that would mean adding IPC to
 * PID 1 just for this, where /proc already has the answer for free.
 */
static pid_t find_netd_pid(void) {
        DIR *d;
        struct dirent *e;
        pid_t found = -1;

        d = opendir("/proc");
        if (!d)
                return -1;

        while ((e = readdir(d))) {
                char path[64], comm[32];
                FILE *f;
                pid_t pid;
                char *end;

                pid = (pid_t) strtol(e->d_name, &end, 10);
                if (*end != '\0' || pid <= 0)
                        continue; /* not a /proc/<pid> entry */

                snprintf(path, sizeof path, "/proc/%d/comm", (int) pid);
                f = fopen(path, "re");
                if (!f)
                        continue;
                if (!fgets(comm, sizeof comm, f)) {
                        fclose(f);
                        continue;
                }
                fclose(f);

                comm[strcspn(comm, "\n")] = '\0';
                if (strcmp(comm, "netd") == 0) {
                        found = pid;
                        break;
                }
        }

        closedir(d);
        return found;
}

static int cmd_reload(void) {
        pid_t pid = find_netd_pid();

        if (pid < 0) {
                fprintf(stderr, "networkctl: netd is not running\n");
                return 1;
        }

        if (kill(pid, SIGHUP) < 0) {
                fprintf(stderr, "networkctl: kill(%d, SIGHUP): %s\n", (int) pid, strerror(errno));
                return 1;
        }

        return 0;
}

/* --- small KEY=VALUE readers for netd's own published files ------------ */

/* Read one `key`'s value out of a netd KEY=VALUE text file into `out`
 * (bufsize-bounded, NUL-terminated). Returns true if found. */
static bool read_keyvalue(const char *path, const char *key, char *out, size_t bufsize) {
        FILE *f;
        char line[512];
        size_t keylen = strlen(key);
        bool found = false;

        f = fopen(path, "re");
        if (!f)
                return false;

        while (fgets(line, sizeof line, f)) {
                line[strcspn(line, "\n")] = '\0';
                if (strncmp(line, key, keylen) == 0 && line[keylen] == '=') {
                        snprintf(out, bufsize, "%s", line + keylen + 1);
                        found = true;
                        break;
                }
        }

        fclose(f);
        return found;
}

static void netd_link_file_path(unsigned ifindex, char *out, size_t bufsize) {
        snprintf(out, bufsize, "%s/%u", NETD_LINKS_DIR, ifindex);
}

/* NETD_LEASES_DIR's own per-ifindex path is still built directly, inline,
 * by status_all()'s NTP aggregation loop (the only remaining reader of a
 * lease file's path by ifindex) -- the Gateway row no longer reads one, see
 * collect_default_gateways(). */

/* "configured", "configuring", "unmanaged", "pending", "failed", or
 * "unmanaged" as the honest default when netd has never seen this link
 * (not running, or the link predates it). */
static void iface_setup_state(const char *ifname, char *out, size_t bufsize) {
        char path[128];
        unsigned idx = if_nametoindex(ifname);

        snprintf(out, bufsize, "unmanaged");
        if (idx == 0)
                return;

        netd_link_file_path(idx, path, sizeof path);
        (void) read_keyvalue(path, "STATE", out, bufsize);
}

static bool iface_network_file(const char *ifname, char *out, size_t bufsize) {
        char path[128];
        unsigned idx = if_nametoindex(ifname);

        if (idx == 0)
                return false;

        netd_link_file_path(idx, path, sizeof path);
        return read_keyvalue(path, "NETWORK", out, bufsize);
}

/* --- link classification: TYPE, OPERATIONAL --------------------------- */

static const char *iface_type(const char *ifname) {
        char path[128];
        FILE *f;
        long type = -1;

        snprintf(path, sizeof path, "/sys/class/net/%s/bridge", ifname);
        if (access(path, F_OK) == 0)
                return "bridge";

        snprintf(path, sizeof path, "/sys/class/net/%s/type", ifname);
        f = fopen(path, "re");
        if (f) {
                if (fscanf(f, "%ld", &type) != 1)
                        type = -1;
                fclose(f);
        }

        switch (type) {
        case ARPHRD_LOOPBACK:
                return "loopback";
        case ARPHRD_ETHER:
                return "ether";
        default:
                return "other";
        }
}

/* Any real (non-link-local, non-loopback) address currently on the link --
 * networkd's own bar for calling an "up" link "routable" rather than just
 * "carrier". */
static bool iface_has_routable_address(const char *ifname) {
        struct ifaddrs *all, *a;
        bool routable = false;

        if (getifaddrs(&all) < 0)
                return false;

        for (a = all; a; a = a->ifa_next) {
                if (!a->ifa_addr || strcmp(a->ifa_name, ifname) != 0)
                        continue;
                if (a->ifa_addr->sa_family == AF_INET) {
                        struct in_addr ip = ((struct sockaddr_in *) a->ifa_addr)->sin_addr;
                        uint32_t h = ntohl(ip.s_addr);

                        if ((h & 0xFF000000u) == 0x7F000000u) /* 127.0.0.0/8 */
                                continue;
                        if ((h & 0xFFFF0000u) == 0xA9FE0000u) /* 169.254.0.0/16 */
                                continue;
                        routable = true;
                        break;
                } else if (a->ifa_addr->sa_family == AF_INET6) {
                        struct in6_addr ip6 = ((struct sockaddr_in6 *) a->ifa_addr)->sin6_addr;

                        if (IN6_IS_ADDR_LOOPBACK(&ip6) || IN6_IS_ADDR_LINKLOCAL(&ip6))
                                continue;
                        routable = true;
                        break;
                }
        }

        freeifaddrs(all);
        return routable;
}

/* The kernel's own /sys/class/net/<if>/operstate, mapped onto networkd's
 * richer display vocabulary where the mapping is honest: "up" splits into
 * "routable" (has a real address) or "carrier" (does not) the same way
 * networkd's own operational-state derivation does; everything else is the
 * kernel's own word, which is already one of networkd's own states
 * (no-carrier, dormant, off) or close enough (unknown). */
static void iface_operational(const char *ifname, char *out, size_t bufsize) {
        char path[128], kstate[32] = "unknown";
        FILE *f;

        snprintf(path, sizeof path, "/sys/class/net/%s/operstate", ifname);
        f = fopen(path, "re");
        if (f) {
                if (fgets(kstate, sizeof kstate, f))
                        kstate[strcspn(kstate, "\n")] = '\0';
                fclose(f);
        }

        if (strcmp(kstate, "up") == 0)
                snprintf(out, bufsize, "%s", iface_has_routable_address(ifname) ? "routable" : "carrier");
        else if (strcmp(kstate, "down") == 0)
                snprintf(out, bufsize, "no-carrier");
        else
                snprintf(out, bufsize, "%s", kstate);
}

/* --- link classification: Driver, Vendor, Model ------------------------ */

/* Truncating copy that gcc can see is bounded: snprintf("%s") from a
 * PATH_MAX buffer trips -Wformat-truncation at -Os with -Werror. */
static void copy_clamped(char *dst, size_t dstsize, const char *src) {
        size_t n = strlen(src);

        if (n >= dstsize)
                n = dstsize - 1;
        memcpy(dst, src, n);
        dst[n] = '\0';
}

/* /sys/class/net/<if>/device/driver is a symlink to the bound driver's own
 * sysfs entry; its basename is the driver name. A link with no backing
 * device (a virtual link) has no "device" symlink at all, so this returns
 * false rather than guessing. */
static bool iface_driver(const char *ifname, char *out, size_t bufsize) {
        char path[128], target[PATH_MAX];
        ssize_t len;
        const char *base;

        snprintf(path, sizeof path, "/sys/class/net/%s/device/driver", ifname);
        len = readlink(path, target, sizeof target - 1);
        if (len < 0)
                return false;
        target[len] = '\0';

        base = strrchr(target, '/');
        copy_clamped(out, bufsize, base ? base + 1 : target);
        return true;
}

/* Walks up from /sys/class/net/<if>/device looking for the usb_device node
 * sysfs itself marks with an "idVendor" file -- net's own "device" symlink
 * points at the usb_interface node, one or two directories below it,
 * nesting differently for a USB gadget function than for a discrete
 * adapter. Bounded to a few levels: a PCI or platform device never has an
 * idVendor file anywhere above it, and stops there rather than walking to
 * "/". */
static bool usb_device_dir(const char *ifname, char *out, size_t bufsize) {
        char path[128], real[PATH_MAX], probe[PATH_MAX + sizeof "/idVendor"];

        snprintf(path, sizeof path, "/sys/class/net/%s/device", ifname);
        if (!realpath(path, real))
                return false;

        for (int i = 0; i < 4; i++) {
                char *slash;

                snprintf(probe, sizeof probe, "%s/idVendor", real);
                if (access(probe, F_OK) == 0) {
                        snprintf(out, bufsize, "%s", real);
                        return true;
                }

                slash = strrchr(real, '/');
                if (!slash || slash == real)
                        break;
                *slash = '\0';
        }
        return false;
}

/* manufacturer/product are the USB device's own string descriptors (e.g.
 * the gadget framework's "Linux Foundation" / "Multifunction Composite
 * Gadget" defaults) -- real descriptor text read straight from sysfs, not
 * a hwdb lookup netd has no database for. A device that never set one is
 * valid USB, not an error: the caller just omits that row. */
static bool usb_string_attr(const char *ifname, const char *attr, char *out, size_t bufsize) {
        char dir[PATH_MAX], path[PATH_MAX + 32];
        FILE *f;

        if (!usb_device_dir(ifname, dir, sizeof dir))
                return false;

        snprintf(path, sizeof path, "%s/%s", dir, attr);
        f = fopen(path, "re");
        if (!f)
                return false;
        if (!fgets(out, bufsize, f)) {
                fclose(f);
                return false;
        }
        fclose(f);
        out[strcspn(out, "\n")] = '\0';
        return out[0] != '\0';
}

/* IPv6 Address Generation Mode, QDisc, MTU min/max, Alternative Names and
 * Number of Queues used to each be their own sysfs/procfs read here. All
 * five now come from one netctl_rtnl_get_link() round trip (netctl-rtnl.c)
 * instead -- see this file's own header comment -- so there is nothing
 * left to define in this section; status_one() calls netctl_rtnl_get_link()
 * directly. */

/* --- status: kernel ground truth + netd's published files -------------- */

/*
 * A labeled field whose value may be more than one line -- real networkctl's
 * own table renders every multi-value field (Address, Gateway, DNS, NTP...)
 * with the first value on the label's own line and the rest right-aligned
 * under it (networkctl-dump-util.c's dump_list(), via format-table.c's own
 * vertical-table layout). LABEL_WIDTH is a fixed stand-in for that table's
 * real dynamic column sizing, chosen to match the label width real
 * networkctl's own output actually uses for these fields.
 */
#define LABEL_WIDTH 28
#define FIELD_MAX 16
#define FIELD_VAL_LEN 160

typedef struct {
        char v[FIELD_MAX][FIELD_VAL_LEN];
        int n;
} FieldList;

static void field_add(FieldList *fl, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void field_add(FieldList *fl, const char *fmt, ...) {
        va_list ap;

        if (fl->n >= FIELD_MAX)
                return;

        va_start(ap, fmt);
        vsnprintf(fl->v[fl->n], FIELD_VAL_LEN, fmt, ap);
        va_end(ap);
        fl->n++;
}

static void field_print(const char *label, const FieldList *fl) {
        if (fl->n == 0)
                return;

        printf("%*s: %s\n", LABEL_WIDTH, label, fl->v[0]);
        for (int i = 1; i < fl->n; i++)
                printf("%*s  %s\n", LABEL_WIDTH, "", fl->v[i]);
}

/* real dump_addresses() never appends a /prefix -- just the address, plus
 * " on " and the interface name for system-wide status
 * (networkctl-dump-util.c). FORMAT_IFNAME_FULL()'s "%<ifindex>" form is only
 * its fallback when the name cannot be resolved. */
static void collect_addr_on_iface(FieldList *fl, const char *ifname, const char *addr) {
        field_add(fl, "%s on %s", addr, ifname);
}

/* inet_ntop(), not getnameinfo(): getnameinfo() appends "%<ifname>" to a
 * link-local IPv6 address, while real networkctl prints the bare address
 * (IN_ADDR_TO_STRING()). */
static bool ifaddr_to_string(const struct sockaddr *sa, char *buf, size_t len) {
        if (sa->sa_family == AF_INET)
                return inet_ntop(AF_INET, &((const struct sockaddr_in *) sa)->sin_addr, buf, len) != NULL;

        return inet_ntop(AF_INET6, &((const struct sockaddr_in6 *) sa)->sin6_addr, buf, len) != NULL;
}

/*
 * Default routes from the kernel's own plain-text table -- far simpler and
 * just as authoritative as a raw rtnetlink dump for one field (real
 * networkctl's own dump_gateways() queries the same kernel route table via
 * RTM_GETROUTE instead, but needs no privileged socket either way).
 * `only_ifname` NULL collects every default route system-wide
 * (status_all()); non-NULL filters to that one interface (status_one()) --
 * replacing a read of netd's own lease file there, which goes stale the
 * moment the kernel's default route changes by any other means (manual
 * `ip route`, a different lease, route removal) without netd rewriting it.
 * Destination 00000000 (hex, little-endian) is the default route; Gateway
 * is the same encoding.
 */
static void collect_default_gateways(const char *only_ifname, FieldList *fl) {
        FILE *f = fopen("/proc/net/route", "re");
        char line[256];
        bool header = true;

        if (!f)
                return;

        while (fgets(line, sizeof line, f)) {
                char iface[IFNAMSIZ];
                unsigned long dest, gw;
                unsigned flags;
                struct in_addr a;

                if (header) {
                        header = false;
                        continue;
                }

                if (sscanf(line, "%15s %lx %lx %x", iface, &dest, &gw, &flags) != 4)
                        continue;
                if (dest != 0 || gw == 0)
                        continue;
                if (only_ifname && strcmp(iface, only_ifname) != 0)
                        continue;

                a.s_addr = gw;
                if (only_ifname)
                        field_add(fl, "%s", inet_ntoa(a));
                else
                        field_add(fl, "%s on %s", inet_ntoa(a), iface);
        }
        fclose(f);
}

/*
 * MTU, with networkctl-status-link.c's own min/max formatting
 * (format_bytes_full()'s "(min: X, max: Y)" suffix, only the parts the
 * kernel actually reported):
 *   neither known: "%u"
 *   max only:      "%u (max: %u)"
 *   min only:      "%u (min: %u)"
 *   both known:    "%u (min: %u, max: %u)"
 */
static void format_mtu(const NetctlLinkInfo *info, char *out, size_t bufsize) {
        if (info->has_min_mtu && info->has_max_mtu)
                snprintf(out, bufsize, "%u (min: %u, max: %u)", info->mtu, info->min_mtu, info->max_mtu);
        else if (info->has_min_mtu)
                snprintf(out, bufsize, "%u (min: %u)", info->mtu, info->min_mtu);
        else if (info->has_max_mtu)
                snprintf(out, bufsize, "%u (max: %u)", info->mtu, info->max_mtu);
        else
                snprintf(out, bufsize, "%u", info->mtu);
}

static void status_one(const char *ifname) {
        unsigned idx = if_nametoindex(ifname);
        char buf[128];
        FieldList addrs = { .n = 0 };
        struct ifaddrs *all, *a;
        NetctlLinkInfo info;

        if (idx == 0) {
                fprintf(stderr, "networkctl: unknown interface '%s'\n", ifname);
                return;
        }

        /*
         * One rtnetlink round trip for everything below that rtnetlink can
         * answer (Type's ARPHRD, Alternative Names, MTU min/max, QDisc,
         * IPv6 Address Generation Mode, Number of Queues). A failure here
         * (r < 0) just means those rows are omitted below --
         * netctl_rtnl_get_link() zeroes `info` even on failure, so every
         * has_* / non-NULL check that follows is honest either way; not
         * logged, to keep this file free of any dependency on netd's own
         * logging (pico_log() lives in pico_init_core, which this binary
         * deliberately does not link -- see this file's own header).
         */
        (void) netctl_rtnl_get_link(ifname, &info);

        printf("\xe2\x97\x8f %u: %s\n", idx, ifname); /* U+25CF BLACK CIRCLE */

        if (iface_network_file(ifname, buf, sizeof buf))
                printf("%*s: %s\n", LABEL_WIDTH, "Network File", buf);

        {
                char op[32], setup[32];

                iface_operational(ifname, op, sizeof op);
                iface_setup_state(ifname, setup, sizeof setup);
                printf("%*s: %s (%s)\n", LABEL_WIDTH, "State", op, setup);
                /* real per-link status always has an Online state row right
                 * after State (networkctl-status-link.c); netd has no separate
                 * online-state concept, so this is honestly always "unknown",
                 * matching real's own fallback for the same unknown case. */
                printf("%*s: %s\n", LABEL_WIDTH, "Online state", "unknown");
        }

        {
                /* Bridge detection has no rtnetlink equivalent (kept as the
                 * existing sysfs check); the ARPHRD classification below it
                 * now comes from the same RTM_GETLINK reply as every other
                 * new row, rather than a second, separate sysfs /type
                 * read. */
                char bridge_path[128];
                const char *type;

                snprintf(bridge_path, sizeof bridge_path, "/sys/class/net/%s/bridge", ifname);
                if (access(bridge_path, F_OK) == 0)
                        type = "bridge";
                else if (info.arp_type == ARPHRD_LOOPBACK)
                        type = "loopback";
                else if (info.arp_type == ARPHRD_ETHER)
                        type = "ether";
                else
                        type = "other";

                printf("%*s: %s\n", LABEL_WIDTH, "Type", type);
        }

        {
                char pathid[256];

                if (iface_path_id(ifname, pathid, sizeof pathid))
                        printf("%*s: %s\n", LABEL_WIDTH, "Path", pathid);
        }

        {
                char drv[64];

                if (iface_driver(ifname, drv, sizeof drv))
                        printf("%*s: %s\n", LABEL_WIDTH, "Driver", drv);
        }

        {
                char vendor[128];

                if (usb_string_attr(ifname, "manufacturer", vendor, sizeof vendor))
                        printf("%*s: %s\n", LABEL_WIDTH, "Vendor", vendor);
        }

        {
                char model[128];

                if (usb_string_attr(ifname, "product", model, sizeof model))
                        printf("%*s: %s\n", LABEL_WIDTH, "Model", model);
        }

        {
                FieldList alts = { .n = 0 };

                if (info.alt_names)
                        for (size_t i = 0; info.alt_names[i]; i++)
                                field_add(&alts, "%s", info.alt_names[i]);
                field_print("Alternative Names", &alts);
        }

        {
                char path[128], mac[64] = "";
                FILE *f;

                snprintf(path, sizeof path, "/sys/class/net/%s/address", ifname);
                f = fopen(path, "re");
                if (f) {
                        if (fgets(mac, sizeof mac, f))
                                mac[strcspn(mac, "\n")] = '\0';
                        fclose(f);
                }
                if (mac[0] != '\0')
                        printf("%*s: %s\n", LABEL_WIDTH, "Hardware Address", mac);
        }

        if (info.has_mtu) {
                char mtubuf[64];

                format_mtu(&info, mtubuf, sizeof mtubuf);
                printf("%*s: %s\n", LABEL_WIDTH, "MTU", mtubuf);
        }

        if (info.qdisc)
                printf("%*s: %s\n", LABEL_WIDTH, "QDisc", info.qdisc);

        if (info.has_addr_gen_mode) {
                static const char * const names[] = {
                        [0] = "eui64",
                        [1] = "none",
                        [2] = "stable-privacy",
                        [3] = "random",
                };

                /* Same numeric values real networkctl's own
                 * ipv6_addr_gen_mode_to_string() maps
                 * (Documentation/networking/ip-sysctl.rst); an out-of-range
                 * value is omitted rather than guessed. */
                if (info.addr_gen_mode < sizeof names / sizeof names[0])
                        printf("%*s: %s\n",
                               LABEL_WIDTH,
                               "IPv6 Address Generation Mode",
                               names[info.addr_gen_mode]);
        }

        if (info.has_queues)
                printf("%*s: %u/%u\n", LABEL_WIDTH, "Number of Queues (Tx/Rx)", info.tx_queues, info.rx_queues);

        if (getifaddrs(&all) == 0) {
                for (a = all; a; a = a->ifa_next) {
                        char host[NI_MAXHOST];

                        if (!a->ifa_addr || strcmp(a->ifa_name, ifname) != 0)
                                continue;
                        if (a->ifa_addr->sa_family != AF_INET && a->ifa_addr->sa_family != AF_INET6)
                                continue;
                        if (!ifaddr_to_string(a->ifa_addr, host, sizeof host))
                                continue;

                        /* real dump_addresses() never appends a /prefix, per-link
                         * or system-wide (networkctl-dump-util.c). */
                        field_add(&addrs, "%s", host);
                }
                freeifaddrs(all);
        }
        field_print("Address", &addrs);

        {
                FieldList gw = { .n = 0 };

                collect_default_gateways(ifname, &gw);
                field_print("Gateway", &gw);
        }

        netctl_link_info_free(&info);
}

static void status_all(void) {
        struct if_nameindex *list, *i;
        bool any_routable = false, any_carrier = false, first = true;
        FieldList addrs = { .n = 0 }, gateways = { .n = 0 }, dns = { .n = 0 }, ntp = { .n = 0 };

        list = if_nameindex();
        if (!list) {
                fprintf(stderr, "networkctl: if_nameindex: %s\n", strerror(errno));
                return;
        }

        printf("\xe2\x97\x8f Interfaces: ");
        for (i = list; i->if_name; i++) {
                printf("%s%u", first ? "" : ", ", i->if_index);
                first = false;
        }
        printf("\n");

        for (i = list; i->if_name; i++) {
                char op[32];

                iface_operational(i->if_name, op, sizeof op);
                if (strcmp(op, "routable") == 0)
                        any_routable = true;
                else if (strcmp(op, "carrier") == 0)
                        any_carrier = true;
        }
        if_freenameindex(list);

        printf("%*s: %s\n",
               LABEL_WIDTH,
               "State",
               any_routable                ? "routable" :
                               any_carrier ? "carrier" :
                                             "no-carrier");
        /* real system_status() always adds Online state right after State
         * (networkctl-status-system.c); netd has no separate online-state
         * concept, so this is honestly always "unknown". */
        printf("%*s: %s\n", LABEL_WIDTH, "Online state", "unknown");

        {
                struct ifaddrs *all, *a;

                if (getifaddrs(&all) == 0) {
                        for (a = all; a; a = a->ifa_next) {
                                char host[NI_MAXHOST];

                                if (!a->ifa_addr)
                                        continue;
                                if (a->ifa_addr->sa_family != AF_INET && a->ifa_addr->sa_family != AF_INET6)
                                        continue;
                                if (!ifaddr_to_string(a->ifa_addr, host, sizeof host))
                                        continue;

                                collect_addr_on_iface(&addrs, a->ifa_name, host);
                        }
                        freeifaddrs(all);
                }
        }
        field_print("Address", &addrs);

        /* Every default route system-wide -- see collect_default_gateways()
         * for why /proc/net/route is an acceptable, no-extra-socket kernel
         * source for this field, far simpler and just as authoritative as a
         * raw rtnetlink dump for one field. */
        collect_default_gateways(NULL, &gateways);
        field_print("Gateway", &gateways);

        {
                FILE *f = fopen("/etc/resolv.conf", "re");
                char line[256];

                if (f) {
                        while (fgets(line, sizeof line, f)) {
                                char ns[128];

                                if (sscanf(line, "nameserver %127s", ns) == 1)
                                        field_add(&dns, "%s", ns);
                        }
                        fclose(f);
                }
        }
        field_print("DNS", &dns);

        /* real system_status() also dumps Search Domains and Route Domains
         * (networkctl-status-system.c). Search Domains maps cleanly onto
         * resolv.conf's own "search" directive; Route Domains (per-link
         * routing-only domains, networkd's Domains=~ syntax) has no netd
         * equivalent to back honestly, so it stays unclaimed like the other
         * fields this file's header comment already lists. */
        {
                FILE *f = fopen("/etc/resolv.conf", "re");
                char line[256];
                FieldList search = { .n = 0 };

                if (f) {
                        while (fgets(line, sizeof line, f)) {
                                char tok[256], *save, *w;

                                if (strncmp(line, "search", 6) != 0 || !isspace((unsigned char) line[6]))
                                        continue;
                                snprintf(tok, sizeof tok, "%s", line + 6);
                                for (w = strtok_r(tok, " \t\n", &save); w; w = strtok_r(NULL, " \t\n", &save))
                                        field_add(&search, "%s", w);
                        }
                        fclose(f);
                }
                field_print("Search Domains", &search);
        }

        /* NTP: aggregated from every interface's own lease file -- netd has
         * no single system-wide NTP list of its own, each link's DHCP lease
         * carries its own option 42 servers. */
        {
                DIR *d = opendir(NETD_LEASES_DIR);
                struct dirent *e;

                if (d) {
                        while ((e = readdir(d))) {
                                char path[PATH_MAX], line[256];

                                if (e->d_name[0] == '.')
                                        continue;

                                snprintf(path, sizeof path, "%s/%s", NETD_LEASES_DIR, e->d_name);
                                if (read_keyvalue(path, "NTP", line, sizeof line))
                                        field_add(&ntp, "%s", line);
                        }
                        closedir(d);
                }
        }
        field_print("NTP", &ntp);
}

static int cmd_status(int argc, char *argv[]) {
        if (argc >= 3) {
                status_one(argv[2]);
                return 0;
        }
        status_all();
        return 0;
}

static int cmd_list(void) {
        struct if_nameindex *list, *i;
        unsigned n = 0;

        list = if_nameindex();
        if (!list) {
                fprintf(stderr, "networkctl: if_nameindex: %s\n", strerror(errno));
                return 1;
        }

        printf("IDX LINK     TYPE     OPERATIONAL SETUP\n");
        for (i = list; i->if_name; i++) {
                char op[32], setup[32];

                iface_operational(i->if_name, op, sizeof op);
                iface_setup_state(i->if_name, setup, sizeof setup);
                printf("%3u %-8s %-8s %-11s %s\n", i->if_index, i->if_name, iface_type(i->if_name), op, setup);
                n++;
        }

        if_freenameindex(list);
        /* No pluralization -- matches real networkctl's own
         * printf("\n%i links listed.\n", c) exactly, singular included. */
        printf("\n%u links listed.\n", n);
        return 0;
}

int main(int argc, char *argv[]) {
        if (argc < 2)
                return cmd_list();

        if (strcmp(argv[1], "reload") == 0)
                return cmd_reload();
        if (strcmp(argv[1], "status") == 0)
                return cmd_status(argc, argv);
        if (strcmp(argv[1], "list") == 0)
                return cmd_list();

        fprintf(stderr, "networkctl: unknown command '%s'\n", argv[1]);
        return 2;
}
