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
 * reload (`reconfigure` is the same signal, since a reload re-applies every
 * link).
 *
 * Options and verbs follow networkctl v262. What netd cannot back is either a
 * silent no-op where nothing could have been expected to happen (--no-pager,
 * --full, --lines, persistent-storage) or a loud failure where a script would
 * otherwise believe an action took place (renew, forcerenew, dhcp-lease, edit,
 * --no-reconfigure).
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
#include <fcntl.h>
#include <fnmatch.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <limits.h>
#include <linux/if_addrlabel.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
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
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
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

/* --- options ------------------------------------------------------------ */

enum { JSON_OFF, JSON_PRETTY, JSON_SHORT };

static bool arg_legend = true;
static bool arg_all, arg_stats, arg_no_reload, arg_no_reconfigure, arg_runtime;
static int arg_json = JSON_OFF;

/* --- JSON output, shaped like sd-json's pretty/short dump ---------------- */

#define JSON_DEPTH_MAX 8

static struct {
        int depth;
        bool after_key;
        bool comma[JSON_DEPTH_MAX];
} jw;

static void json_nl(void) {
        if (arg_json != JSON_PRETTY)
                return;
        putchar('\n');
        for (int i = 0; i < jw.depth * 2; i++)
                putchar(' ');
}

/* Comma and indentation before the next value, unless a key just wrote them. */
static void json_item(void) {
        if (jw.after_key) {
                jw.after_key = false;
                return;
        }
        if (jw.depth == 0)
                return; /* a top-level value starts its own line */
        if (jw.comma[jw.depth])
                putchar(',');
        jw.comma[jw.depth] = true;
        json_nl();
}

static void json_open(char c) {
        json_item();
        putchar(c);
        if (jw.depth + 1 < JSON_DEPTH_MAX)
                jw.depth++;
        jw.comma[jw.depth] = false;
}

static void json_close(char c) {
        bool had = jw.comma[jw.depth];

        if (jw.depth > 0)
                jw.depth--;
        if (had)
                json_nl();
        putchar(c);
}

static void json_string_raw(const char *s) {
        putchar('"');
        for (; *s; s++) {
                unsigned char c = (unsigned char) *s;

                if (c == '"' || c == '\\')
                        printf("\\%c", c);
                else if (c == '\n')
                        fputs("\\n", stdout);
                else if (c == '\t')
                        fputs("\\t", stdout);
                else if (c < 0x20 || c == 0x7f)
                        printf("\\u%04x", c);
                else
                        putchar(c);
        }
        putchar('"');
}

static void json_key(const char *k) {
        json_item();
        json_string_raw(k);
        fputs(arg_json == JSON_PRETTY ? " : " : ":", stdout);
        jw.after_key = true;
}

static void json_str(const char *k, const char *v) {
        json_key(k);
        jw.after_key = false;
        json_string_raw(v);
}

static void json_uint(const char *k, unsigned long long v) {
        json_key(k);
        jw.after_key = false;
        printf("%llu", v);
}

static void json_int_item(unsigned v) {
        json_item();
        printf("%u", v);
}

static void json_finish(void) {
        putchar('\n');
        memset(&jw, 0, sizeof jw);
}

/* --- patterns: PATTERN... on list, status and lldp ---------------------- */

typedef struct {
        unsigned idx;
        char name[IFNAMSIZ];
} LinkRef;

static bool is_glob(const char *s) {
        return strpbrk(s, "*?[") != NULL;
}

static int pattern_pos(char **patterns, int npat, const char *s) {
        for (int i = 0; i < npat; i++)
                if (fnmatch(patterns[i], s, 0) == 0)
                        return i;
        return -1;
}

/* Position of the first pattern matching the link by index, name or an
 * alternative name; -1 for none. */
static int link_match_pos(const char *ifname, unsigned idx, char **patterns, int npat) {
        char str[16];
        int pos;
        NetctlLinkInfo info;

        snprintf(str, sizeof str, "%u", idx);
        pos = pattern_pos(patterns, npat, str);
        if (pos < 0)
                pos = pattern_pos(patterns, npat, ifname);
        if (pos >= 0)
                return pos;

        if (netctl_rtnl_get_link(ifname, &info) == 0 && info.alt_names)
                for (size_t i = 0; info.alt_names[i] && pos < 0; i++)
                        pos = pattern_pos(patterns, npat, info.alt_names[i]);
        netctl_link_info_free(&info);
        return pos;
}

/* Every link when there are no patterns. A pattern that is not a glob and
 * matches nothing is an error, as in networkctl; a glob may match nothing. */
static int select_links(char **patterns, int npat, LinkRef **ret, size_t *n_ret) {
        struct if_nameindex *list, *i;
        bool *matched = NULL;
        LinkRef *links;
        size_t n = 0, total = 0;

        list = if_nameindex();
        if (!list) {
                fprintf(stderr, "networkctl: Failed to enumerate links: %s\n", strerror(errno));
                return -1;
        }
        for (i = list; i->if_name; i++)
                total++;

        links = calloc(total + 1, sizeof *links);
        if (npat > 0)
                matched = calloc((size_t) npat, sizeof *matched);
        if (!links || (npat > 0 && !matched)) {
                free(links);
                free(matched);
                if_freenameindex(list);
                fprintf(stderr, "networkctl: Out of memory\n");
                return -1;
        }

        for (i = list; i->if_name; i++) {
                if (npat > 0) {
                        int pos = link_match_pos(i->if_name, i->if_index, patterns, npat);

                        if (pos < 0)
                                continue;
                        matched[pos] = true;
                }
                links[n].idx = i->if_index;
                snprintf(links[n].name, sizeof links[n].name, "%s", i->if_name);
                n++;
        }
        if_freenameindex(list);

        for (int p = 0; p < npat; p++)
                if (!matched[p] && !is_glob(patterns[p])) {
                        fprintf(stderr, "networkctl: Interface \"%s\" not found.\n", patterns[p]);
                        free(links);
                        free(matched);
                        return -1;
                }
        free(matched);

        if (npat > 0 && n == 0)
                fprintf(stderr, "networkctl: No interfaces matched.\n");

        *ret = links;
        *n_ret = n;
        return 0;
}

/* An interface given as a name or an index number, as up/down/delete/... take. */
static unsigned resolve_interface(const char *s) {
        unsigned idx = 0;
        char *end, name[IFNAMSIZ];

        if (*s >= '0' && *s <= '9') {
                unsigned long v = strtoul(s, &end, 10);

                if (*end == '\0' && v > 0 && v < UINT_MAX && if_indextoname((unsigned) v, name))
                        idx = (unsigned) v;
        }
        if (idx == 0)
                idx = if_nametoindex(s);
        if (idx == 0)
                fprintf(stderr, "networkctl: Failed to resolve interface \"%s\": No such device\n", s);
        return idx;
}

/* One rtnetlink request; `cb` sees every message of the reply. Returns 0 or
 * -errno. A dump runs until NLMSG_DONE, anything else until the ACK. */
static int
                nl_request(uint16_t type,
                           uint16_t flags,
                           const void *body,
                           size_t bodylen,
                           int (*cb)(const struct nlmsghdr *, void *),
                           void *arg) {
        static char buf[16384];
        struct {
                struct nlmsghdr h;
                char body[64];
        } req;
        int fd, r = 0;
        bool dump = flags & NLM_F_DUMP;

        if (bodylen > sizeof req.body)
                return -EINVAL;
        memset(&req, 0, sizeof req);
        req.h.nlmsg_len = (uint32_t) NLMSG_LENGTH(bodylen);
        req.h.nlmsg_type = type;
        req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
        req.h.nlmsg_seq = 1;
        memcpy(req.body, body, bodylen);

        fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0)
                return -errno;
        if (send(fd, &req, req.h.nlmsg_len, 0) < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        for (bool done = false; !done;) {
                ssize_t len = recv(fd, buf, sizeof buf, 0);
                struct nlmsghdr *h = (struct nlmsghdr *) buf;

                if (len < 0) {
                        r = -errno;
                        break;
                }
                for (; NLMSG_OK(h, (size_t) len); h = NLMSG_NEXT(h, len)) {
                        if (h->nlmsg_type == NLMSG_DONE) {
                                done = true;
                                break;
                        }
                        if (h->nlmsg_type == NLMSG_ERROR) {
                                const struct nlmsgerr *e = NLMSG_DATA(h);

                                r = e->error;
                                if (!dump || r < 0)
                                        done = true;
                                if (r == 0)
                                        continue;
                                break;
                        }
                        if (cb && cb(h, arg) < 0) {
                                done = true;
                                break;
                        }
                }
        }
        close(fd);
        return r;
}

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

static int reload_netd(void) {
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

/* networkctl's --no-reconfigure reloads the files without touching the links;
 * netd's reload always re-applies every link, so refuse instead of doing more
 * than was asked. */
static int cmd_reload(int argc, char *argv[]) {
        (void) argc;
        (void) argv;

        if (arg_no_reconfigure) {
                fprintf(stderr, "networkctl: netd does not support --no-reconfigure.\n");
                return 1;
        }
        return reload_netd();
}

/* netd has no per-link reconfigure: a reload re-applies every link, which
 * includes the requested ones. */
static int cmd_reconfigure(int argc, char *argv[]) {
        for (int i = 1; i < argc; i++)
                if (resolve_interface(argv[i]) == 0)
                        return 1;
        return reload_netd();
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
 * "unmanaged" as the default when netd has never seen this link
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
 * richer display vocabulary where the mapping is exact: "up" splits into
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

/* --stats: the counters networkctl lists last. sysfs has the same 64-bit
 * values as IFLA_STATS64. */
static void status_statistics(const char *ifname) {
        static const char * const rows[][2] = {
                {        "Rx Packets", "rx_packets" },
                {        "Tx Packets", "tx_packets" },
                {          "Rx Bytes",   "rx_bytes" },
                {          "Tx Bytes",   "tx_bytes" },
                {         "Rx Errors",  "rx_errors" },
                {         "Tx Errors",  "tx_errors" },
                {        "Rx Dropped", "rx_dropped" },
                {        "Tx Dropped", "tx_dropped" },
                { "Multicast Packets",  "multicast" },
                {        "Collisions", "collisions" },
        };

        for (size_t i = 0; i < sizeof rows / sizeof rows[0]; i++) {
                char path[160], val[32];
                FILE *f;

                snprintf(path, sizeof path, "/sys/class/net/%s/statistics/%s", ifname, rows[i][1]);
                f = fopen(path, "re");
                if (!f)
                        return;
                if (fgets(val, sizeof val, f)) {
                        val[strcspn(val, "\n")] = '\0';
                        print_field_plain(rows[i][0], val);
                }
                fclose(f);
        }
}

static void status_one(const char *ifname) {
        unsigned idx = if_nametoindex(ifname);
        char buf[128];
        FieldList addrs = { .n = 0 };
        struct ifaddrs *all, *a;
        NetctlLinkInfo info;

        if (idx == 0)
                return;

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
                 * online-state concept, so this is always "unknown",
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

        if (arg_stats)
                status_statistics(ifname);

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
                 * online-state concept, so this is always
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
         * equivalent to back it, so it stays unclaimed like the other
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

/*
 * One link as networkd's Describe reports it, limited to the members netd can
 * back: no addresses, DNS, DHCP or netdev detail, which networkd adds from
 * its own state.
 */
static void json_link(const LinkRef *l) {
        static const char * const kstates[] = {
                "unknown", "notpresent", "down", "lowerlayerdown", "testing", "dormant", "up",
        };
        char path[128], buf[128], op[32], setup[32];
        NetctlLinkInfo info;
        FILE *f;

        (void) netctl_rtnl_get_link(l->name, &info);

        json_open('{');
        json_uint("Index", l->idx);
        json_str("Name", l->name);
        if (info.alt_names && info.alt_names[0]) {
                json_key("AlternativeNames");
                json_open('[');
                for (size_t i = 0; info.alt_names[i]; i++) {
                        json_item();
                        json_string_raw(info.alt_names[i]);
                }
                json_close(']');
        }
        json_str("Type", iface_type(l->name));
        if (iface_driver(l->name, buf, sizeof buf))
                json_str("Driver", buf);
        json_uint("Flags", info.flags);

        snprintf(path, sizeof path, "/sys/class/net/%s/operstate", l->name);
        snprintf(buf, sizeof buf, "unknown");
        f = fopen(path, "re");
        if (f) {
                if (fgets(buf, sizeof buf, f))
                        buf[strcspn(buf, "\n")] = '\0';
                fclose(f);
        }
        {
                unsigned k = 0;

                for (unsigned i = 0; i < sizeof kstates / sizeof kstates[0]; i++)
                        if (strcmp(buf, kstates[i]) == 0)
                                k = i;
                json_uint("KernelOperationalState", k);
                json_str("KernelOperationalStateString", kstates[k]);
        }

        if (info.has_mtu)
                json_uint("MTU", info.mtu);
        if (info.has_min_mtu)
                json_uint("MinimumMTU", info.min_mtu);
        if (info.has_max_mtu)
                json_uint("MaximumMTU", info.max_mtu);

        snprintf(path, sizeof path, "/sys/class/net/%s/address", l->name);
        f = fopen(path, "re");
        if (f) {
                unsigned b[32];
                size_t n = 0;
                bool any = false;

                if (fgets(buf, sizeof buf, f)) {
                        for (char *p = buf; *p && n < 32;) {
                                char *end;
                                unsigned long v = strtoul(p, &end, 16);

                                if (end == p || v > 255)
                                        break;
                                b[n++] = (unsigned) v;
                                any |= v != 0;
                                p = *end == ':' ? end + 1 : end;
                        }
                        if (any) {
                                json_key("HardwareAddress");
                                json_open('[');
                                for (size_t i = 0; i < n; i++)
                                        json_int_item(b[i]);
                                json_close(']');
                        }
                }
                fclose(f);
        }

        iface_setup_state(l->name, setup, sizeof setup);
        iface_operational(l->name, op, sizeof op);
        json_str("AdministrativeState", setup);
        json_str("OperationalState", op);
        if (iface_network_file(l->name, buf, sizeof buf))
                json_str("NetworkFile", buf);
        json_close('}');

        netctl_link_info_free(&info);
}

/* --json for list and status: every link in networkd's {"Interfaces": [...]}
 * wrapper, or, when links were named, one bare object per link. */
static int json_links(const LinkRef *links, size_t n, bool named) {
        if (named) {
                for (size_t i = 0; i < n; i++) {
                        json_link(&links[i]);
                        json_finish();
                }
                return 0;
        }

        json_open('{');
        json_key("Interfaces");
        json_open('[');
        for (size_t i = 0; i < n; i++)
                json_link(&links[i]);
        json_close(']');
        json_close('}');
        json_finish();
        return 0;
}

static int cmd_status(int argc, char *argv[]) {
        LinkRef *links;
        size_t n;
        int r = 0;

        if (argc < 2 && !arg_all && arg_json == JSON_OFF) {
                status_all();
                return 0;
        }

        if (select_links(arg_all ? NULL : argv + 1, arg_all ? 0 : argc - 1, &links, &n) < 0)
                return 1;

        if (arg_json != JSON_OFF)
                r = json_links(links, n, argc > 1 && !arg_all);
        else
                for (size_t i = 0; i < n; i++) {
                        if (i > 0)
                                putchar('\n');
                        status_one(links[i].name);
                }

        free(links);
        return r;
}

typedef struct {
        unsigned idx;
        char name[IFNAMSIZ];
        const char *type;
        char op[32], setup[32];
} ListRow;

static int cmd_list(int argc, char *argv[]) {
        LinkRef *links;
        ListRow *rows;
        size_t n, w_link = 4, w_type = 4, w_op = 11;
        unsigned w_idx = 3;
        /* --all only widens the JSON dump to the whole manager. */
        bool named = argc > 1 && !(arg_all && arg_json != JSON_OFF);

        if (select_links(named ? argv + 1 : NULL, named ? argc - 1 : 0, &links, &n) < 0)
                return 1;

        if (arg_json != JSON_OFF) {
                int r = json_links(links, n, named);

                free(links);
                return r;
        }

        rows = calloc(n + 1, sizeof *rows);
        if (!rows) {
                free(links);
                fprintf(stderr, "networkctl: Out of memory\n");
                return 1;
        }

        for (size_t i = 0; i < n; i++) {
                char digits[16];

                rows[i].idx = links[i].idx;
                snprintf(rows[i].name, sizeof rows[i].name, "%s", links[i].name);
                rows[i].type = iface_type(links[i].name);
                iface_operational(links[i].name, rows[i].op, sizeof rows[i].op);
                iface_setup_state(links[i].name, rows[i].setup, sizeof rows[i].setup);

                if (strlen(rows[i].name) > w_link)
                        w_link = strlen(rows[i].name);
                if (strlen(rows[i].type) > w_type)
                        w_type = strlen(rows[i].type);
                if (strlen(rows[i].op) > w_op)
                        w_op = strlen(rows[i].op);
                snprintf(digits, sizeof digits, "%u", rows[i].idx);
                if (strlen(digits) > w_idx)
                        w_idx = (unsigned) strlen(digits);
        }

        /* Column headers are never coloured -- real networkctl's own table
         * header row has no TABLE_FIELD/colour of its own either. */
        if (arg_legend)
                printf("%*s %-*s %-*s %-*s %s\n",
                       (int) w_idx,
                       "IDX",
                       (int) w_link,
                       "LINK",
                       (int) w_type,
                       "TYPE",
                       (int) w_op,
                       "OPERATIONAL",
                       "SETUP");
        for (size_t i = 0; i < n; i++) {
                const char *on_op, *off_op, *on_setup, *off_setup;

                operational_color(rows[i].name, rows[i].op, &on_op, &off_op);
                setup_color(rows[i].setup, &on_setup, &off_setup);
                /* The width applies to the text itself -- the colour escapes
                 * around it add no visible width, so the column stays aligned
                 * exactly like the uncoloured case. */
                printf("%*u %-*s %-*s %s%-*s%s %s%s%s\n",
                       (int) w_idx,
                       rows[i].idx,
                       (int) w_link,
                       rows[i].name,
                       (int) w_type,
                       rows[i].type,
                       on_op,
                       (int) w_op,
                       rows[i].op,
                       off_op,
                       on_setup,
                       rows[i].setup,
                       off_setup);
        }

        /* No pluralization -- matches real networkctl's own
         * printf("\n%i links listed.\n", c) exactly, singular included. */
        if (arg_legend)
                printf("\n%zu links listed.\n", n);
        free(rows);
        free(links);
        return 0;
}

#define LLDP_ROWS_MAX 256
#define LLDP_SYSDESCR_MAX 128

typedef struct {
        NetctlLldpRow row;
        unsigned idx;
        unsigned vlan;
        uint16_t caps;
        char sysdescr[LLDP_SYSDESCR_MAX];
} LldpEntry;

static int lldp_entry_compare(const void *a, const void *b) {
        const LldpEntry *x = a, *y = b;
        int c;

        if (x->idx != y->idx)
                return x->idx < y->idx ? -1 : 1;
        c = strcmp(x->row.name, y->row.name);
        return c ? c : strcmp(x->row.chassis, y->row.chassis);
}

/* The value of "key=" in a space separated state line. netctl-lldp.c has the
 * same helper but keeps it file-local. */
static bool line_token(const char *line, const char *key, const char **value, size_t *len) {
        size_t klen = strlen(key);

        while (*line) {
                const char *end = strchr(line, ' ');
                size_t tlen = end ? (size_t) (end - line) : strlen(line);

                if (tlen > klen && strncmp(line, key, klen) == 0 && line[klen] == '=') {
                        *value = line + klen + 1;
                        *len = tlen - klen - 1;
                        return true;
                }
                if (!end)
                        break;
                line = end + 1;
        }
        return false;
}

/* What NetctlLldpRow does not carry: the system description, the VLAN, and
 * the capability bits behind the CAPS string. Same ASCII-only rule as the row. */
static void lldp_extras(const char *line, LldpEntry *e) {
        const char *v;
        size_t len;
        uint8_t raw[300];

        for (unsigned i = 0; i < 11; i++)
                if (e->row.caps[i] != '.')
                        e->caps |= (uint16_t) (1u << i);

        if (strncmp(line, "N ", 2) != 0)
                return;
        line += 2;

        if (line_token(line, "sysdescr", &v, &len)) {
                size_t d = netctl_lldp_unescape(raw, sizeof raw, v, len);

                if (d != (size_t) -1) {
                        if (d > sizeof e->sysdescr - 1)
                                d = sizeof e->sysdescr - 1;
                        for (size_t i = 0; i < d; i++)
                                e->sysdescr[i] = raw[i] >= 0x20 && raw[i] < 0x7f ? (char) raw[i] : '?';
                        e->sysdescr[d] = '\0';
                }
        }
        if (line_token(line, "vlan", &v, &len))
                e->vlan = (unsigned) strtoul(v, NULL, 10);
}

static unsigned columns(void) {
        const char *c = getenv("COLUMNS");
        struct winsize ws;

        if (c && atoi(c) > 0)
                return (unsigned) atoi(c);
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) >= 0 && ws.ws_col > 0)
                return ws.ws_col;
        return 80;
}

/* Only the capabilities some neighbour has, or all of them with --all. */
static void lldp_capabilities_legend(uint16_t seen) {
        static const char * const table[] = {
                "o - Other",
                "p - Repeater",
                "b - Bridge",
                "w - WLAN Access Point",
                "r - Router",
                "t - Telephone",
                "d - DOCSIS cable device",
                "a - Station",
                "c - Customer VLAN",
                "s - Service VLAN",
                "m - Two-port MAC Relay (TPMR)",
        };
        unsigned cols = columns();

        if (seen == 0)
                return;

        printf("\nCapability Flags:\n");
        for (unsigned w = 0, i = 0; i < sizeof table / sizeof table[0]; i++)
                if ((seen & (1u << i)) || arg_all) {
                        bool newline = w + strlen(table[i]) + (w == 0 ? 0 : 2) > cols;

                        if (newline)
                                w = 0;
                        w += (unsigned) printf("%s%s%s", newline ? "\n" : "", w == 0 ? "" : "; ", table[i]);
                }
        puts("");
}

static const char *dash(const char *s) {
        return s[0] ? s : "-";
}

static void lldp_json(const LldpEntry *e, size_t n) {
        json_open('{');
        json_key("Neighbors");
        json_open('[');
        for (size_t i = 0; i < n;) {
                size_t j = i;

                json_open('{');
                json_uint("InterfaceIndex", e[i].idx);
                json_str("InterfaceName", e[i].row.link);
                json_key("Neighbors");
                json_open('[');
                for (; j < n && e[j].idx == e[i].idx; j++) {
                        json_open('{');
                        json_str("ChassisID", e[j].row.chassis);
                        json_str("PortID", e[j].row.port);
                        if (e[j].row.descr[0])
                                json_str("PortDescription", e[j].row.descr);
                        if (e[j].row.name[0])
                                json_str("SystemName", e[j].row.name);
                        if (e[j].sysdescr[0])
                                json_str("SystemDescription", e[j].sysdescr);
                        if (e[j].caps)
                                json_uint("EnabledCapabilities", e[j].caps);
                        if (e[j].vlan)
                                json_uint("VlanID", e[j].vlan);
                        json_close('}');
                }
                json_close(']');
                json_close('}');
                i = j;
        }
        json_close(']');
        json_close('}');
        json_finish();
}

/* networkctl lldp [PATTERN...]: the neighbours netd heard, from the files it publishes. */
static int cmd_lldp(int argc, char *argv[]) {
        static LldpEntry rows[LLDP_ROWS_MAX];
        size_t n = 0, i, w_link = 4, w_name = 11, w_desc = 18, w_chassis = 10, w_port = 7, w_pdesc = 16;
        uint16_t seen = 0;
        struct timespec now;
        DIR *d = opendir(NETD_LLDP_DIR);
        struct dirent *e;

        clock_gettime(CLOCK_MONOTONIC, &now);

        while (d && (e = readdir(d)) != NULL && n < LLDP_ROWS_MAX) {
                char path[PATH_MAX], ifname[IFNAMSIZ], line[2048];
                unsigned idx;
                FILE *f;

                if (e->d_name[0] == '.' || strstr(e->d_name, ".netd-tmp"))
                        continue;
                snprintf(path, sizeof path, "%s/%s", NETD_LLDP_DIR, e->d_name);
                if (!read_keyvalue(path, "IFNAME", ifname, sizeof ifname))
                        continue;
                idx = if_nametoindex(ifname);
                if (argc > 1 && link_match_pos(ifname, idx, argv + 1, argc - 1) < 0)
                        continue;

                f = fopen(path, "re");
                if (!f)
                        continue;
                while (n < LLDP_ROWS_MAX && fgets(line, sizeof line, f)) {
                        line[strcspn(line, "\n")] = '\0';
                        memset(&rows[n], 0, sizeof rows[n]);
                        if (!netctl_lldp_parse_row(line, ifname, &rows[n].row))
                                continue;
                        /* A file left behind by a netd that is no longer running. */
                        if (rows[n].row.expires != 0 && rows[n].row.expires <= (uint64_t) now.tv_sec)
                                continue;
                        rows[n].idx = idx;
                        lldp_extras(line, &rows[n]);
                        n++;
                }
                fclose(f);
        }
        if (d)
                closedir(d);

        qsort(rows, n, sizeof rows[0], lldp_entry_compare);

        if (arg_json != JSON_OFF) {
                lldp_json(rows, n);
                return 0;
        }

        for (i = 0; i < n; i++) {
                if (strlen(rows[i].row.link) > w_link)
                        w_link = strlen(rows[i].row.link);
                if (strlen(rows[i].row.name) > w_name)
                        w_name = strlen(rows[i].row.name);
                if (strlen(rows[i].sysdescr) > w_desc)
                        w_desc = strlen(rows[i].sysdescr);
                if (strlen(rows[i].row.chassis) > w_chassis)
                        w_chassis = strlen(rows[i].row.chassis);
                if (strlen(rows[i].row.port) > w_port)
                        w_port = strlen(rows[i].row.port);
                if (strlen(rows[i].row.descr) > w_pdesc)
                        w_pdesc = strlen(rows[i].row.descr);
                seen |= rows[i].caps;
        }

        if (arg_legend)
                printf("%-*s %-*s %-*s %-*s %-*s %-*s %s\n",
                       (int) w_link,
                       "LINK",
                       (int) w_name,
                       "SYSTEM-NAME",
                       (int) w_desc,
                       "SYSTEM-DESCRIPTION",
                       (int) w_chassis,
                       "CHASSIS-ID",
                       (int) w_port,
                       "PORT-ID",
                       (int) w_pdesc,
                       "PORT-DESCRIPTION",
                       "CAPS");
        for (i = 0; i < n; i++)
                printf("%-*s %-*s %-*s %-*s %-*s %-*s %s\n",
                       (int) w_link,
                       rows[i].row.link,
                       (int) w_name,
                       dash(rows[i].row.name),
                       (int) w_desc,
                       dash(rows[i].sysdescr),
                       (int) w_chassis,
                       rows[i].row.chassis,
                       (int) w_port,
                       rows[i].row.port,
                       (int) w_pdesc,
                       dash(rows[i].row.descr),
                       rows[i].row.caps);

        if (arg_legend) {
                lldp_capabilities_legend(seen);
                printf("\n%zu neighbor(s) listed.\n", n);
        }
        return 0;
}

/* --- label: the kernel's IPv6 address label table ------------------------ */

#define LABELS_MAX 64

typedef struct {
        uint32_t label;
        char prefix[INET6_ADDRSTRLEN + 8];
} Label;

typedef struct {
        Label v[LABELS_MAX];
        size_t n;
} LabelSet;

static int label_collect(const struct nlmsghdr *h, void *arg) {
        LabelSet *s = arg;
        const struct ifaddrlblmsg *m = NLMSG_DATA(h);
        const struct rtattr *a = (const struct rtattr *) ((const char *) m + NLMSG_ALIGN(sizeof *m));
        size_t left;
        struct in6_addr addr;
        uint32_t label = 0;
        bool have_addr = false;
        char ip[INET6_ADDRSTRLEN];

        if (h->nlmsg_type != RTM_NEWADDRLABEL || h->nlmsg_len < NLMSG_LENGTH(sizeof *m) || s->n >= LABELS_MAX)
                return 0;

        left = h->nlmsg_len - NLMSG_LENGTH(sizeof *m);
        for (; RTA_OK(a, left); a = RTA_NEXT(a, left)) {
                if (a->rta_type == IFAL_ADDRESS && RTA_PAYLOAD(a) == sizeof addr) {
                        memcpy(&addr, RTA_DATA(a), sizeof addr);
                        have_addr = true;
                } else if (a->rta_type == IFAL_LABEL && RTA_PAYLOAD(a) == sizeof label)
                        memcpy(&label, RTA_DATA(a), sizeof label);
        }
        if (!have_addr || !inet_ntop(AF_INET6, &addr, ip, sizeof ip))
                return 0;

        s->v[s->n].label = label;
        snprintf(s->v[s->n].prefix, sizeof s->v[s->n].prefix, "%s/%u", ip, (unsigned) m->ifal_prefixlen);
        s->n++;
        return 0;
}

static int label_compare(const void *a, const void *b) {
        const Label *x = a, *y = b;

        return x->label < y->label ? -1 : x->label > y->label;
}

static int cmd_label(int argc, char *argv[]) {
        static LabelSet set;
        struct ifaddrlblmsg req = { .ifal_family = AF_INET6 };
        size_t w_label = 5, w_prefix = 16;
        int r;

        (void) argc;
        (void) argv;

        r = nl_request(RTM_GETADDRLABEL, NLM_F_DUMP, &req, sizeof req, label_collect, &set);
        if (r < 0) {
                fprintf(stderr, "networkctl: Failed to get address labels: %s\n", strerror(-r));
                return 1;
        }

        qsort(set.v, set.n, sizeof set.v[0], label_compare);
        for (size_t i = 0; i < set.n; i++) {
                char digits[16];

                snprintf(digits, sizeof digits, "%u", (unsigned) set.v[i].label);
                if (strlen(digits) > w_label)
                        w_label = strlen(digits);
                if (strlen(set.v[i].prefix) > w_prefix)
                        w_prefix = strlen(set.v[i].prefix);
        }

        if (arg_legend)
                printf("%*s %*s\n", (int) w_label, "LABEL", (int) w_prefix, "PREFIX/PREFIXLEN");
        for (size_t i = 0; i < set.n; i++)
                printf("%*u %*s\n", (int) w_label, (unsigned) set.v[i].label, (int) w_prefix, set.v[i].prefix);
        return 0;
}

/* --- delete, up, down ----------------------------------------------------- */

static int cmd_delete(int argc, char *argv[]) {
        unsigned idx[argc];
        int ret = 0;

        for (int i = 1; i < argc; i++) {
                idx[i] = resolve_interface(argv[i]);
                if (idx[i] == 0)
                        return 1;
        }

        for (int i = 1; i < argc; i++) {
                struct ifinfomsg ifi = { .ifi_family = AF_UNSPEC, .ifi_index = (int) idx[i] };
                int r = nl_request(RTM_DELLINK, 0, &ifi, sizeof ifi, NULL, NULL);

                if (r < 0) {
                        fprintf(stderr,
                                "networkctl: Failed to delete interface %s: %s\n",
                                argv[i],
                                strerror(-r));
                        ret = 1;
                }
        }
        return ret;
}

static int set_admin_state(int argc, char *argv[], bool up) {
        unsigned idx[argc];
        int fd, ret = 0;

        for (int i = 1; i < argc; i++) {
                idx[i] = resolve_interface(argv[i]);
                if (idx[i] == 0)
                        return 1;
        }

        fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
                fprintf(stderr, "networkctl: socket: %s\n", strerror(errno));
                return 1;
        }

        for (int i = 1; i < argc; i++) {
                struct ifreq ifr;

                memset(&ifr, 0, sizeof ifr);
                if (!if_indextoname(idx[i], ifr.ifr_name) || ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
                        fprintf(stderr, "networkctl: %s: %s\n", argv[i], strerror(errno));
                        ret = 1;
                        continue;
                }
                if (up)
                        ifr.ifr_flags = (short) (ifr.ifr_flags | IFF_UP);
                else
                        ifr.ifr_flags = (short) (ifr.ifr_flags & ~IFF_UP);
                if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
                        fprintf(stderr,
                                "networkctl: Failed to bring %s %s: %s\n",
                                up ? "up" : "down",
                                argv[i],
                                strerror(errno));
                        ret = 1;
                }
        }
        close(fd);
        return ret;
}

static int cmd_up(int argc, char *argv[]) {
        return set_admin_state(argc, argv, true);
}

static int cmd_down(int argc, char *argv[]) {
        return set_admin_state(argc, argv, false);
}

/* --- cat, mask, unmask: the .network files netd reads -------------------- */

/* netd's search order; networkctl's /usr/local/lib and /lib entries are not read by netd. */
static const char * const config_dirs[] = {
        "/etc/systemd/network",
        "/run/systemd/network",
        "/usr/lib/systemd/network",
};

static bool filename_valid(const char *s) {
        return s[0] && strlen(s) <= NAME_MAX && !strchr(s, '/') && strcmp(s, ".") != 0 && strcmp(s, "..") != 0;
}

static bool has_suffix(const char *s, const char *suffix) {
        size_t a = strlen(s), b = strlen(suffix);

        return a > b && strcmp(s + a - b, suffix) == 0;
}

/* /dev/null, or an empty file: how a config file is masked. */
static bool path_masked(const char *path) {
        struct stat st;

        if (stat(path, &st) < 0)
                return false;
        return (S_ISCHR(st.st_mode) && st.st_rdev == makedev(1, 3)) ||
                        (S_ISREG(st.st_mode) && st.st_size == 0);
}

/* First hit in netd's search order. -ENOENT for none, -ERFKILL for a masked
 * hit unless `allow_masked`. */
static int find_config(const char *name, bool allow_masked, char *path, size_t size) {
        for (size_t i = 0; i < sizeof config_dirs / sizeof config_dirs[0]; i++) {
                snprintf(path, size, "%s/%s", config_dirs[i], name);
                if (access(path, F_OK) < 0)
                        continue;
                return !allow_masked && path_masked(path) ? -ERFKILL : 0;
        }
        return -ENOENT;
}

static int cat_one(const char *path, bool *first) {
        FILE *f = fopen(path, "re");
        char buf[1024];
        size_t n;
        char last = '\n';

        if (!f) {
                fprintf(stderr, "networkctl: Failed to open %s: %s\n", path, strerror(errno));
                return 1;
        }
        if (!*first)
                putchar('\n');
        *first = false;
        printf("# %s\n", path);
        while ((n = fread(buf, 1, sizeof buf, f)) > 0) {
                fwrite(buf, 1, n, stdout);
                last = buf[n - 1];
        }
        if (last != '\n')
                putchar('\n');
        fclose(f);
        return 0;
}

/* @IFNAME[:network]: the .network file netd matched to the link. */
static int cat_link(const char *spec, bool *first) {
        char ifname[IFNAMSIZ + 16], path[PATH_MAX];
        char *colon;
        bool explicit_type = false;
        unsigned idx;

        snprintf(ifname, sizeof ifname, "%s", spec);
        colon = strchr(ifname, ':');
        if (colon) {
                *colon++ = '\0';
                if (strcmp(colon, "network") != 0) {
                        fprintf(stderr,
                                "networkctl: Invalid config type '%s': netd reads only .network files.\n",
                                colon);
                        return 1;
                }
                explicit_type = true;
        }

        idx = resolve_interface(ifname);
        if (idx == 0)
                return 1;

        if (!iface_network_file(ifname, path, sizeof path)) {
                if (!explicit_type)
                        return 0;
                fprintf(stderr, "networkctl: Interface \"%s\" has no .network file.\n", ifname);
                return 1;
        }
        return cat_one(path, first);
}

static int cmd_cat(int argc, char *argv[]) {
        bool first = true;
        int ret = 0;

        /* networkctl shows networkd.conf here; netd has no main configuration file. */
        if (argc < 2) {
                fprintf(stderr,
                        "networkctl: netd has no main configuration file; name .network files or @DEVICE.\n");
                return 1;
        }

        for (int i = 1; i < argc; i++) {
                char path[PATH_MAX];
                int r;

                if (argv[i][0] == '@') {
                        if (cat_link(argv[i] + 1, &first) != 0)
                                return 1;
                        continue;
                }

                if (!filename_valid(argv[i]) || !has_suffix(argv[i], ".network")) {
                        fprintf(stderr, "networkctl: Invalid network config name: %s\n", argv[i]);
                        return 1;
                }
                r = find_config(argv[i], false, path, sizeof path);
                if (r == -ENOENT) {
                        fprintf(stderr, "networkctl: Cannot find network config file '%s'.\n", argv[i]);
                        ret = 1;
                        continue;
                }
                if (r == -ERFKILL)
                        continue; /* masked */
                if (cat_one(path, &first) != 0)
                        ret = 1;
        }
        return ret;
}

static int mkdir_p(const char *dir) {
        char tmp[PATH_MAX];

        snprintf(tmp, sizeof tmp, "%s", dir);
        for (char *p = tmp + 1; *p; p++) {
                if (*p != '/')
                        continue;
                *p = '\0';
                if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
                        return -errno;
                *p = '/';
        }
        if (mkdir(tmp, 0755) < 0 && errno != EEXIST)
                return -errno;
        return 0;
}

/* Which kind of file `name` is: 1 for one netd reads, 0 for .link (udev's), -1 for anything else. */
static int config_kind(const char *name) {
        if (!filename_valid(name)) {
                fprintf(stderr, "networkctl: Invalid config filename: %s\n", name);
                return -1;
        }
        if (has_suffix(name, ".network") || has_suffix(name, ".netdev"))
                return 1;
        if (has_suffix(name, ".link"))
                return 0;
        fprintf(stderr, "networkctl: Network config of unknown type: %s\n", name);
        return -1;
}

static int reload_after_edit(bool changed) {
        if (!changed || arg_no_reload || find_netd_pid() < 0)
                return 0;
        return reload_netd();
}

static int cmd_mask(int argc, char *argv[]) {
        bool changed = false;

        for (int i = 1; i < argc; i++) {
                char existing[PATH_MAX], link[PATH_MAX];
                const char *dir = config_dirs[arg_runtime ? 1 : 0];
                int kind = config_kind(argv[i]), r;

                if (kind < 0)
                        return 1;

                r = find_config(argv[i], true, existing, sizeof existing);
                if (r == -ENOENT)
                        fprintf(stderr,
                                "networkctl: No existing network config '%s' found, proceeding anyway.\n",
                                argv[i]);
                else if (strncmp(existing, "/usr/", 5) != 0) {
                        if (path_masked(existing))
                                continue;
                        /* A real file under /etc or /run cannot be masked from the other directory, nor over itself. */
                        if (arg_runtime || strncmp(existing, "/etc/", 5) == 0) {
                                fprintf(stderr,
                                        "networkctl: Cannot mask network config %s: %s exists\n",
                                        argv[i],
                                        existing);
                                return 1;
                        }
                }

                snprintf(link, sizeof link, "%s/%s", dir, argv[i]);
                (void) mkdir_p(dir);
                if (symlink("/dev/null", link) < 0) {
                        fprintf(stderr,
                                "networkctl: Failed to create symlink '%s' to /dev/null: %s\n",
                                link,
                                strerror(errno));
                        return 1;
                }
                changed |= kind == 1;
                fprintf(stderr, "Successfully created symlink '%s' to /dev/null.\n", link);
        }
        return reload_after_edit(changed);
}

static int cmd_unmask(int argc, char *argv[]) {
        bool changed = false;

        for (int i = 1; i < argc; i++) {
                char path[PATH_MAX];
                int kind = config_kind(argv[i]);

                if (kind < 0)
                        return 1;
                if (find_config(argv[i], true, path, sizeof path) < 0 || !path_masked(path))
                        continue;
                if (strncmp(path, "/usr/", 5) == 0) {
                        fprintf(stderr, "networkctl: Cannot unmask network config under /usr/: %s\n", path);
                        return 1;
                }
                if (unlink(path) < 0) {
                        if (errno == ENOENT)
                                continue;
                        fprintf(stderr, "networkctl: Failed to remove '%s': %s\n", path, strerror(errno));
                        return 1;
                }
                changed |= kind == 1;
                fprintf(stderr, "Successfully removed masked network config '%s'.\n", path);
        }
        return reload_after_edit(changed);
}

/* --- verbs netd cannot back --------------------------------------------- */

/* Refused rather than accepted: the caller expects a lease renewed or a file
 * edited, and a success status would claim it happened. */
static int cmd_unsupported(int argc, char *argv[]) {
        const char *why;

        (void) argc;
        if (strcmp(argv[0], "dhcp-lease") == 0)
                why = "netd does not keep the DHCP message of a lease";
        else if (strcmp(argv[0], "edit") == 0)
                why = "edit the .network file and run 'reload'";
        else
                why = "netd cannot renew a lease on demand";
        fprintf(stderr, "networkctl: '%s' is not supported: %s.\n", argv[0], why);
        return 1;
}

/* There is nothing persistent for netd to be told about. */
static int cmd_persistent_storage(int argc, char *argv[]) {
        static const char * const yes[] = { "1", "yes", "y", "true", "t", "on" };
        static const char * const no[] = { "0", "no", "n", "false", "f", "off" };

        (void) argc;
        for (size_t i = 0; i < sizeof yes / sizeof yes[0]; i++)
                if (strcasecmp(argv[1], yes[i]) == 0 || strcasecmp(argv[1], no[i]) == 0)
                        return 0;
        fprintf(stderr, "networkctl: Failed to parse argument: %s\n", argv[1]);
        return 1;
}

/* --- command line ------------------------------------------------------- */

static void usage(void) {
        printf("Usage: networkctl [OPTIONS...] COMMAND [ARGS...]\n"
               "\n"
               "Query and control the networking subsystem.\n"
               "\n"
               "Commands:\n"
               "  list [PATTERN...]        List links\n"
               "  status [PATTERN...]      Show link status\n"
               "  lldp [PATTERN...]        Show LLDP neighbors\n"
               "  label                    Show current address label entries in the kernel\n"
               "  delete DEVICES...        Delete virtual netdevs\n"
               "  up DEVICES...            Bring devices up\n"
               "  down DEVICES...          Bring devices down\n"
               "  reconfigure DEVICES...   Reload the configuration (every link is re-applied)\n"
               "  reload                   Reload .network files\n"
               "  cat FILES|@DEVICE...     Show network configuration files\n"
               "  mask FILES...            Mask network configuration files\n"
               "  unmask FILES...          Unmask network configuration files\n"
               "  persistent-storage BOOL  Accepted; netd keeps no persistent state\n"
               "\n"
               "Not supported by netd, they fail: dhcp-lease, renew, forcerenew, edit\n"
               "\n"
               "Options:\n"
               "  -h --help                Show this help\n"
               "     --version             Show package version\n"
               "     --no-pager            Accepted; there is no pager\n"
               "     --no-legend           Do not show headers and footers\n"
               "     --no-ask-password     Accepted; there is no authentication\n"
               "  -a --all                 Show status for all links\n"
               "  -s --stats               Show detailed link statistics\n"
               "  -l --full                Accepted; output is never ellipsized\n"
               "  -n --lines=INTEGER       Accepted; there is no journal\n"
               "     --json=FORMAT         Generate JSON output (pretty, short, or off)\n"
               "     --no-reload           Do not reload netd after mask or unmask\n"
               "     --no-reconfigure      Refused by reload; netd always re-applies every link\n"
               "     --drop-in=NAME        Accepted; only edit uses it\n"
               "     --runtime             Mask or unmask in /run/systemd/network\n"
               "     --stdin               Accepted; only edit uses it\n");
}

typedef struct {
        const char *name;
        int (*fn)(int argc, char *argv[]);
        int min, max; /* argument counts including the verb itself; -1 for no upper bound */
} Verb;

static const Verb verbs[] = {
        {               "list",               cmd_list, 1, -1 },
        {             "status",             cmd_status, 1, -1 },
        {         "dhcp-lease",        cmd_unsupported, 2, -1 },
        {               "lldp",               cmd_lldp, 1, -1 },
        {              "label",              cmd_label, 1,  1 },
        {             "delete",             cmd_delete, 2, -1 },
        {                 "up",                 cmd_up, 2, -1 },
        {               "down",               cmd_down, 2, -1 },
        {              "renew",        cmd_unsupported, 2, -1 },
        {         "forcerenew",        cmd_unsupported, 2, -1 },
        {        "reconfigure",        cmd_reconfigure, 2, -1 },
        {             "reload",             cmd_reload, 1,  1 },
        {               "edit",        cmd_unsupported, 2, -1 },
        {                "cat",                cmd_cat, 1, -1 },
        {               "mask",               cmd_mask, 2, -1 },
        {             "unmask",             cmd_unmask, 2, -1 },
        { "persistent-storage", cmd_persistent_storage, 2,  2 },
};

enum {
        ARG_VERSION = 0x100,
        ARG_NO_PAGER,
        ARG_NO_LEGEND,
        ARG_NO_ASK_PASSWORD,
        ARG_JSON,
        ARG_NO_RELOAD,
        ARG_NO_RECONFIGURE,
        ARG_DROP_IN,
        ARG_RUNTIME,
        ARG_STDIN,
};

/* Returns <0 to continue with the verb, otherwise the exit status. */
static int parse_argv(int argc, char *argv[]) {
        static const struct option options[] = {
                {            "help",       no_argument, NULL,                 'h' },
                {         "version",       no_argument, NULL,         ARG_VERSION },
                {        "no-pager",       no_argument, NULL,        ARG_NO_PAGER },
                {       "no-legend",       no_argument, NULL,       ARG_NO_LEGEND },
                { "no-ask-password",       no_argument, NULL, ARG_NO_ASK_PASSWORD },
                {             "all",       no_argument, NULL,                 'a' },
                {           "stats",       no_argument, NULL,                 's' },
                {            "full",       no_argument, NULL,                 'l' },
                {           "lines", required_argument, NULL,                 'n' },
                {            "json", required_argument, NULL,            ARG_JSON },
                {       "no-reload",       no_argument, NULL,       ARG_NO_RELOAD },
                {  "no-reconfigure",       no_argument, NULL,  ARG_NO_RECONFIGURE },
                {         "drop-in", required_argument, NULL,         ARG_DROP_IN },
                {         "runtime",       no_argument, NULL,         ARG_RUNTIME },
                {           "stdin",       no_argument, NULL,           ARG_STDIN },
                {              NULL,                 0, NULL,                   0 },
        };
        int c;

        while ((c = getopt_long(argc, argv, "hasln:", options, NULL)) >= 0)
                switch (c) {
                case 'h':
                        usage();
                        return 0;

                case ARG_VERSION:
                        printf("networkctl " PICO_INIT_VERSION " (pico-init netctl)\n");
                        return 0;

                case ARG_NO_PAGER:        /* no pager exists */
                case ARG_NO_ASK_PASSWORD: /* nothing asks for one */
                case 'l':                 /* nothing is ellipsized */
                case ARG_STDIN:           /* only edit reads it */
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case 'a':
                        arg_all = true;
                        break;

                case 's':
                        arg_stats = true;
                        break;

                case 'n': { /* validated, then unused: there is no journal to tail */
                        char *end;

                        errno = 0;
                        (void) strtoul(optarg, &end, 10);
                        if (errno || end == optarg || *end != '\0') {
                                fprintf(stderr, "networkctl: Failed to parse --lines value '%s'\n", optarg);
                                return 1;
                        }
                        break;
                }

                case ARG_JSON:
                        if (strcmp(optarg, "help") == 0) {
                                printf("pretty\nshort\noff\n");
                                return 0;
                        }
                        if (strcmp(optarg, "pretty") == 0)
                                arg_json = JSON_PRETTY;
                        else if (strcmp(optarg, "short") == 0)
                                arg_json = JSON_SHORT;
                        else if (strcmp(optarg, "off") == 0)
                                arg_json = JSON_OFF;
                        else {
                                fprintf(stderr, "networkctl: Unknown argument to --json=: %s\n", optarg);
                                return 1;
                        }
                        break;

                case ARG_NO_RELOAD:
                        arg_no_reload = true;
                        break;

                case ARG_NO_RECONFIGURE:
                        arg_no_reconfigure = true;
                        break;

                case ARG_DROP_IN:
                        if (optarg[0] == '\0') {
                                fprintf(stderr, "networkctl: Empty drop-in file name.\n");
                                return 1;
                        }
                        break;

                case ARG_RUNTIME:
                        arg_runtime = true;
                        break;

                default: /* getopt_long() said why */
                        return 1;
                }

        return -1;
}

int main(int argc, char *argv[]) {
        char *default_args[] = { "list", NULL };
        char **args;
        int r, nargs;

        r = parse_argv(argc, argv);
        if (r >= 0)
                return r;

        args = argv + optind;
        nargs = argc - optind;
        if (nargs <= 0) {
                args = default_args;
                nargs = 1;
        }

        for (size_t i = 0; i < sizeof verbs / sizeof verbs[0]; i++) {
                if (strcmp(args[0], verbs[i].name) != 0)
                        continue;
                if (nargs < verbs[i].min) {
                        fprintf(stderr, "networkctl: Too few arguments.\n");
                        return 1;
                }
                if (verbs[i].max >= 0 && nargs > verbs[i].max) {
                        fprintf(stderr, "networkctl: Too many arguments.\n");
                        return 1;
                }
                return verbs[i].fn(nargs, args);
        }

        fprintf(stderr, "networkctl: Unknown command verb '%s'.\n", args[0]);
        return 1;
}
