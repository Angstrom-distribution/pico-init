/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * networkctl -- a client for netd, not netd itself.
 *
 * netd has no IPC of its own to query, so `status` reads kernel ground truth
 * (sysfs, getifaddrs(3), /proc/net/route, /etc/resolv.conf) plus the two small
 * text files netd publishes -- /run/netd/links/<ifindex> (setup state,
 * matched .network) and /run/netd/leases/<ifindex> (DNS/NTP/router) -- and
 * works even if netd is not running. `reload` is the one verb that needs
 * netd: it SIGHUPs the live process, which netd-loop.c turns into a config
 * reload.
 *
 * Output is modelled on systemd's `networkctl` and `networkctl status IFACE`
 * but does not claim fields netd cannot back. Driver, Vendor and Model are
 * sysfs reads (real networkctl resolves them through udev/hwdb); the
 * kernel-sourced rows of `status <iface>` (Type, Alternative Names, MTU
 * min/max, QDisc, IPv6 Address Generation Mode, Number of Queues) come from
 * one netctl_rtnl_get_link() round trip (netctl-rtnl.c), a small rtnetlink
 * client built from netd-rtnl-core.c only, so networkctl stays standalone.
 * Path comes from netctl-path.c, a scope-limited port of udev's
 * builtin_path_id() over sysfs.
 *
 * Not shown, because netd computes none of it: NetDev/Link File (no udev
 * .link matching), Activation Policy and Required For Online (.network
 * directives netd-network.c does not implement), Route Domains, and Offered
 * DHCP leases (DhcpServerLease state is in memory only, see
 * dhcp-server-lease-internal.h).
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
#include <time.h>
#include <unistd.h>

#include "../pico-color.h"
#include "netctl-lldp.h"
#include "netctl-path.h"
#include "netctl-rtnl.h"

#define NETD_LINKS_DIR "/run/netd/links"
#define NETD_LEASES_DIR "/run/netd/leases"
#define NETD_LLDP_DIR "/run/netd/lldp"

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

/*
 * --- colour: mirrors real networkctl's rules ----------------------------
 *
 * operational_state_to_color()/setup_state_to_color()/online_state_to_color()
 * (src/network/networkctl-util.c, systemd main as of commit
 * 4c63532c28094aeba6dccc5afb9690e02fd98d66, 2026-10-04) -- same checks,
 * reproduced byte-for-byte; pico-color.h's accessors carry the upstream
 * ANSI_* literals and the colours_enabled() decision, so these only pick
 * which accessor applies.
 */

static void operational_color(const char *ifname, const char *state, const char **on, const char **off) {
        if (strcmp(state, "routable") == 0 || strcmp(state, "enslaved") == 0 ||
            (ifname && strcmp(ifname, "lo") == 0 && strcmp(state, "carrier") == 0)) {
                *on = pico_ansi_highlight_green();
                *off = pico_ansi_normal();
        } else if (strcmp(state, "degraded") == 0) {
                *on = pico_ansi_highlight_yellow();
                *off = pico_ansi_normal();
        } else {
                *on = "";
                *off = "";
        }
}

static void setup_color(const char *state, const char **on, const char **off) {
        if (strcmp(state, "configured") == 0) {
                *on = pico_ansi_highlight_green();
                *off = pico_ansi_normal();
        } else if (strcmp(state, "configuring") == 0) {
                *on = pico_ansi_highlight_yellow();
                *off = pico_ansi_normal();
        } else if (strcmp(state, "failed") == 0 || strcmp(state, "linger") == 0) {
                *on = pico_ansi_highlight_red();
                *off = pico_ansi_normal();
        } else {
                *on = "";
                *off = "";
        }
}

static void online_color(const char *state, const char **on, const char **off) {
        if (strcmp(state, "online") == 0) {
                *on = pico_ansi_highlight_green();
                *off = pico_ansi_normal();
        } else if (strcmp(state, "partial") == 0) {
                *on = pico_ansi_highlight_yellow();
                *off = pico_ansi_normal();
        } else {
                *on = "";
                *off = "";
        }
}

/*
 * ANSI_BRIGHT_BLUE ("\x1B[0;94m") -- real networkctl's per-link/system
 * status table colours every field label this way by default
 * (src/shared/format-table.c's table_data_color(): any TABLE_FIELD cell
 * with no colour of its own gets ansi_bright_blue(); networkctl-status-
 * link.c/-status-system.c never override it for any field they add). Not
 * one of pico-color.h's own accessors -- that set was built from the
 * explicit ansi_*() call sites in networkctl-util.c/-status-{link,system}.c,
 * and this is format-table.c's own implicit default, never an explicit
 * call in either of those -- so it is reproduced locally here rather than
 * adding an accessor there.
 */
static const char *field_label_color(void) {
        return pico_colors_enabled() ? "\x1B[0;94m" : "";
}

/* "%*s: %s\n" with the label (and its trailing colon) coloured the way
 * every field label in real networkctl's vertical status table is --
 * pico_ansi_normal()/field_label_color() both collapse to "" when colours
 * are off, giving plain output. */
static void print_field_plain(const char *label, const char *value) {
        printf("%s%*s:%s %s\n", field_label_color(), LABEL_WIDTH, label, pico_ansi_normal(), value);
}

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

        print_field_plain(label, fl->v[0]);
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
 * (status_all()); non-NULL filters to that one interface (status_one()). The
 * lease file is not used because it goes stale when the default route changes
 * by other means.
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
         * netctl_rtnl_get_link() zeroes `info` even on failure. Not logged:
         * pico_log() lives in pico_init_core, which this binary does not
         * link.
         */
        (void) netctl_rtnl_get_link(ifname, &info);

        {
                /* Real networkctl's bullet (the very first line) is coloured
                 * the same as the State row's operational half
                 * (operational_state_to_color()) further down, so both are
                 * computed once here and reused for the State row. */
                char op[32], setup[32];
                const char *on_op, *off_op, *on_setup, *off_setup, *on_online, *off_online;

                iface_operational(ifname, op, sizeof op);
                iface_setup_state(ifname, setup, sizeof setup);
                operational_color(ifname, op, &on_op, &off_op);
                setup_color(setup, &on_setup, &off_setup);

                printf("%s\xe2\x97\x8f%s %u: %s\n", on_op, off_op, idx, ifname); /* U+25CF BLACK CIRCLE */

                if (iface_network_file(ifname, buf, sizeof buf))
                        print_field_plain("Network File", buf);

                printf("%s%*s:%s %s%s%s (%s%s%s)\n",
                       field_label_color(),
                       LABEL_WIDTH,
                       "State",
                       pico_ansi_normal(),
                       on_op,
                       op,
                       off_op,
                       on_setup,
                       setup,
                       off_setup);
                /* real per-link status always has an Online state row right
                 * after State (networkctl-status-link.c); netd has no separate
                 * online-state concept, so this is honestly always "unknown",
                 * matching real's own fallback for the same unknown case --
                 * online_state_to_color() leaves an "unknown" value plain,
                 * same as here. */
                online_color("unknown", &on_online, &off_online);
                printf("%s%*s:%s %s%s%s\n",
                       field_label_color(),
                       LABEL_WIDTH,
                       "Online state",
                       pico_ansi_normal(),
                       on_online,
                       "unknown",
                       off_online);
        }

        {
                /* Bridge detection has no rtnetlink equivalent, so it uses
                 * sysfs; the ARPHRD classification below comes from the
                 * RTM_GETLINK reply. */
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

                print_field_plain("Type", type);
        }

        {
                char pathid[256];

                if (iface_path_id(ifname, pathid, sizeof pathid))
                        print_field_plain("Path", pathid);
        }

        {
                char drv[64];

                if (iface_driver(ifname, drv, sizeof drv))
                        print_field_plain("Driver", drv);
        }

        {
                char vendor[128];

                if (usb_string_attr(ifname, "manufacturer", vendor, sizeof vendor))
                        print_field_plain("Vendor", vendor);
        }

        {
                char model[128];

                if (usb_string_attr(ifname, "product", model, sizeof model))
                        print_field_plain("Model", model);
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
                        print_field_plain("Hardware Address", mac);
        }

        if (info.has_mtu) {
                char mtubuf[64];

                format_mtu(&info, mtubuf, sizeof mtubuf);
                print_field_plain("MTU", mtubuf);
        }

        if (info.qdisc)
                print_field_plain("QDisc", info.qdisc);

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
                        print_field_plain("IPv6 Address Generation Mode", names[info.addr_gen_mode]);
        }

        if (info.has_queues)
                printf("%s%*s:%s %u/%u\n",
                       field_label_color(),
                       LABEL_WIDTH,
                       "Number of Queues (Tx/Rx)",
                       pico_ansi_normal(),
                       info.tx_queues,
                       info.rx_queues);

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

        /*
         * The aggregate state has to be known before the bullet is printed
         * (real system_status() colours its own bullet the same as the
         * State row, operational_state_to_color() with no particular
         * ifname -- networkctl-status-system.c), so this loop runs
         * ahead of the interface-list printing loop below it.
         */
        for (i = list; i->if_name; i++) {
                char op[32];

                iface_operational(i->if_name, op, sizeof op);
                if (strcmp(op, "routable") == 0)
                        any_routable = true;
                else if (strcmp(op, "carrier") == 0)
                        any_carrier = true;
        }

        {
                const char *state_word;
                const char *on_op, *off_op, *on_online, *off_online;

                if (any_routable)
                        state_word = "routable";
                else if (any_carrier)
                        state_word = "carrier";
                else
                        state_word = "no-carrier";

                operational_color(NULL, state_word, &on_op, &off_op);

                printf("%s\xe2\x97\x8f%s Interfaces: ", on_op, off_op);
                for (i = list; i->if_name; i++) {
                        printf("%s%u", first ? "" : ", ", i->if_index);
                        first = false;
                }
                printf("\n");
                if_freenameindex(list);

                printf("%s%*s:%s %s%s%s\n",
                       field_label_color(),
                       LABEL_WIDTH,
                       "State",
                       pico_ansi_normal(),
                       on_op,
                       state_word,
                       off_op);
                /* real system_status() always adds Online state right after
                 * State (networkctl-status-system.c); netd has no separate
                 * online-state concept, so this is honestly always
                 * "unknown" -- online_state_to_color() leaves that plain,
                 * same as here. */
                online_color("unknown", &on_online, &off_online);
                printf("%s%*s:%s %s%s%s\n",
                       field_label_color(),
                       LABEL_WIDTH,
                       "Online state",
                       pico_ansi_normal(),
                       on_online,
                       "unknown",
                       off_online);
        }

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

        /* Column headers are never coloured -- real networkctl's own table
         * header row has no TABLE_FIELD/colour of its own either. */
        printf("IDX LINK     TYPE     OPERATIONAL SETUP\n");
        for (i = list; i->if_name; i++) {
                char op[32], setup[32];
                const char *on_op, *off_op, *on_setup, *off_setup;

                iface_operational(i->if_name, op, sizeof op);
                iface_setup_state(i->if_name, setup, sizeof setup);
                operational_color(i->if_name, op, &on_op, &off_op);
                setup_color(setup, &on_setup, &off_setup);
                /* %-11s applies to `op` itself -- the colour escapes around
                 * it add no visible width, so the column stays aligned
                 * exactly like the uncoloured case. */
                printf("%3u %-8s %-8s %s%-11s%s %s%s%s\n",
                       i->if_index,
                       i->if_name,
                       iface_type(i->if_name),
                       on_op,
                       op,
                       off_op,
                       on_setup,
                       setup,
                       off_setup);
                n++;
        }

        if_freenameindex(list);
        /* No pluralization -- matches real networkctl's own
         * printf("\n%i links listed.\n", c) exactly, singular included. */
        printf("\n%u links listed.\n", n);
        return 0;
}

#define LLDP_ROWS_MAX 256

static int lldp_row_compare(const void *a, const void *b) {
        const NetctlLldpRow *x = a, *y = b;
        int c = strcmp(x->link, y->link);

        return c ? c : strcmp(x->chassis, y->chassis);
}

static bool lldp_wanted(int argc, char *argv[], const char *ifname) {
        int i;

        if (argc < 3)
                return true;
        for (i = 2; i < argc; i++)
                if (strcmp(argv[i], ifname) == 0)
                        return true;
        return false;
}

/* networkctl lldp [LINK...]: the neighbours netd heard, from the files it publishes. */
static int cmd_lldp(int argc, char *argv[]) {
        static NetctlLldpRow rows[LLDP_ROWS_MAX];
        size_t n = 0, i, w_link = 4, w_chassis = 10, w_name = 11, w_port = 7;
        struct timespec now;
        DIR *d = opendir(NETD_LLDP_DIR);
        struct dirent *e;

        clock_gettime(CLOCK_MONOTONIC, &now);

        while (d && (e = readdir(d)) != NULL && n < LLDP_ROWS_MAX) {
                char path[PATH_MAX], ifname[IFNAMSIZ], line[2048];
                FILE *f;

                if (e->d_name[0] == '.' || strstr(e->d_name, ".netd-tmp"))
                        continue;
                snprintf(path, sizeof path, "%s/%s", NETD_LLDP_DIR, e->d_name);
                if (!read_keyvalue(path, "IFNAME", ifname, sizeof ifname) || !lldp_wanted(argc, argv, ifname))
                        continue;

                f = fopen(path, "re");
                if (!f)
                        continue;
                while (n < LLDP_ROWS_MAX && fgets(line, sizeof line, f)) {
                        line[strcspn(line, "\n")] = '\0';
                        if (!netctl_lldp_parse_row(line, ifname, &rows[n]))
                                continue;
                        /* A file left behind by a netd that is no longer running. */
                        if (rows[n].expires != 0 && rows[n].expires <= (uint64_t) now.tv_sec)
                                continue;
                        n++;
                }
                fclose(f);
        }
        if (d)
                closedir(d);

        qsort(rows, n, sizeof rows[0], lldp_row_compare);
        for (i = 0; i < n; i++) {
                if (strlen(rows[i].link) > w_link)
                        w_link = strlen(rows[i].link);
                if (strlen(rows[i].chassis) > w_chassis)
                        w_chassis = strlen(rows[i].chassis);
                if (strlen(rows[i].name) > w_name)
                        w_name = strlen(rows[i].name);
                if (strlen(rows[i].port) > w_port)
                        w_port = strlen(rows[i].port);
        }

        printf("%-*s %-*s %-*s %-11s %-*s %s\n",
               (int) w_link,
               "LINK",
               (int) w_chassis,
               "CHASSIS-ID",
               (int) w_name,
               "SYSTEM-NAME",
               "CAPS",
               (int) w_port,
               "PORT-ID",
               "PORT-DESCRIPTION");
        for (i = 0; i < n; i++)
                printf("%-*s %-*s %-*s %-11s %-*s %s\n",
                       (int) w_link,
                       rows[i].link,
                       (int) w_chassis,
                       rows[i].chassis,
                       (int) w_name,
                       rows[i].name,
                       rows[i].caps,
                       (int) w_port,
                       rows[i].port,
                       rows[i].descr);

        if (n)
                printf("\nCapability Flags:\no - Other; p - Repeater; b - Bridge; w - WLAN Access Point; r - Router;\n"
                       "t - Telephone; d - DOCSIS cable device; a - Station; c - Customer VLAN;\n"
                       "s - Service VLAN, m - Two-port MAC Relay (TPMR)\n");
        printf("\n%zu neighbor%s listed.\n", n, n == 1 ? "" : "s");
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
        if (strcmp(argv[1], "lldp") == 0)
                return cmd_lldp(argc, argv);

        fprintf(stderr, "networkctl: unknown command '%s'\n", argv[1]);
        return 2;
}
