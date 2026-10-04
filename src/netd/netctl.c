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
 * to back honestly: no NetDev/Link File, Driver, QDisc, bridge internals,
 * Activation Policy, Required For Online or Route Domains (networkd's
 * per-link Domains=~ routing-only domains) -- netd tracks none of them.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

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

static void netd_lease_file_path(unsigned ifindex, char *out, size_t bufsize) {
        snprintf(out, bufsize, "%s/%u", NETD_LEASES_DIR, ifindex);
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
 * " on " FORMAT_IFNAME_FULL() (ifname%ifindex) for system-wide status
 * (networkctl-dump-util.c). */
static void collect_addr_on_iface(FieldList *fl, const char *ifname, unsigned ifindex, const char *addr) {
        field_add(fl, "%s on %s%%%u", addr, ifname, ifindex);
}

static void status_one(const char *ifname) {
        unsigned idx = if_nametoindex(ifname);
        char buf[128];
        const char *type;
        FieldList addrs = { .n = 0 };
        struct ifaddrs *all, *a;

        if (idx == 0) {
                fprintf(stderr, "networkctl: unknown interface '%s'\n", ifname);
                return;
        }

        type = iface_type(ifname);

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

        printf("%*s: %s\n", LABEL_WIDTH, "Type", type);

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

        {
                char path[128];
                long mtu = -1;
                FILE *f;

                snprintf(path, sizeof path, "/sys/class/net/%s/mtu", ifname);
                f = fopen(path, "re");
                if (f) {
                        if (fscanf(f, "%ld", &mtu) != 1)
                                mtu = -1;
                        fclose(f);
                }
                if (mtu >= 0)
                        printf("%*s: %ld\n", LABEL_WIDTH, "MTU", mtu);
        }

        if (getifaddrs(&all) == 0) {
                for (a = all; a; a = a->ifa_next) {
                        char host[NI_MAXHOST];

                        if (!a->ifa_addr || strcmp(a->ifa_name, ifname) != 0)
                                continue;
                        if (a->ifa_addr->sa_family != AF_INET && a->ifa_addr->sa_family != AF_INET6)
                                continue;
                        if (getnameinfo(a->ifa_addr,
                                        a->ifa_addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) :
                                                                            sizeof(struct sockaddr_in6),
                                        host,
                                        sizeof host,
                                        NULL,
                                        0,
                                        NI_NUMERICHOST) != 0)
                                continue;

                        /* real dump_addresses() never appends a /prefix, per-link
                         * or system-wide (networkctl-dump-util.c). */
                        field_add(&addrs, "%s", host);
                }
                freeifaddrs(all);
        }
        field_print("Address", &addrs);

        {
                char path[128], router[64];

                netd_lease_file_path(idx, path, sizeof path);
                if (read_keyvalue(path, "ROUTER", router, sizeof router))
                        printf("%*s: %s\n", LABEL_WIDTH, "Gateway", router);
        }
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
                                if (getnameinfo(a->ifa_addr,
                                                a->ifa_addr->sa_family == AF_INET ?
                                                                sizeof(struct sockaddr_in) :
                                                                sizeof(struct sockaddr_in6),
                                                host,
                                                sizeof host,
                                                NULL,
                                                0,
                                                NI_NUMERICHOST) != 0)
                                        continue;

                                collect_addr_on_iface(&addrs, a->ifa_name, if_nametoindex(a->ifa_name), host);
                        }
                        freeifaddrs(all);
                }
        }
        field_print("Address", &addrs);

        /* Default routes, from the kernel's own plain-text table -- far
         * simpler and just as authoritative as a raw rtnetlink dump for one
         * field, and needs no privileged socket. Destination 00000000 (hex,
         * little-endian) is the default route; Gateway is the same encoding. */
        {
                FILE *f = fopen("/proc/net/route", "re");
                char line[256];
                bool header = true;

                if (f) {
                        while (fgets(line, sizeof line, f)) {
                                char iface[IFNAMSIZ];
                                unsigned long dest, gw;
                                unsigned flags;

                                if (header) {
                                        header = false;
                                        continue;
                                }

                                if (sscanf(line, "%15s %lx %lx %x", iface, &dest, &gw, &flags) != 4)
                                        continue;
                                if (dest != 0 || gw == 0)
                                        continue;

                                struct in_addr a = { .s_addr = gw };
                                field_add(&gateways, "%s on %s", inet_ntoa(a), iface);
                        }
                        fclose(f);
                }
        }
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
