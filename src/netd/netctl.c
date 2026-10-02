/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * networkctl -- a client for netd, not netd itself.
 *
 * Unlike picoctl (which genuinely talks to PID 1's own control surface),
 * netd has no IPC of its own to query: LinkState's comment in netd-link.h
 * says so explicitly -- "netd has no status CLI for anyone to read a finer
 * distinction from". So this does not invent one. `status` reads kernel
 * ground truth directly (sysfs operstate + getifaddrs(3)), the same
 * information `ip addr`/`networkctl status` ultimately both show, without a
 * round trip through netd at all -- it works even if netd is not running.
 * `reload` is the one verb that genuinely needs netd: it signals the live
 * process with SIGHUP, which netd-loop.c's signal handler already turns into
 * a config reload (the same mechanism a real `systemctl reload` would drive
 * through D-Bus upstream).
 *
 * Exists because bt-pan-client.sh (meta-handhelds) hard-requires a
 * `networkctl` binary on $PATH and calls exactly these two things: `reload`
 * after handing a fresh bnepN interface a .network file, and `status
 * <iface>` as a diagnostic hint when a DHCP lease never arrives.
 */

#include <dirent.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

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

/* --- status: kernel ground truth, no netd involved --------------------- */

static void print_operstate(const char *ifname) {
        char path[64], state[32] = "unknown";
        FILE *f;

        snprintf(path, sizeof path, "/sys/class/net/%s/operstate", ifname);
        f = fopen(path, "re");
        if (f) {
                if (fgets(state, sizeof state, f))
                        state[strcspn(state, "\n")] = '\0';
                fclose(f);
        }

        printf("           State: %s\n", state);
}

/* Prefix length from a netmask sockaddr, IPv4 or IPv6. NULL (no netmask --
 * getifaddrs leaves it unset for some link types) prints nothing rather than
 * guessing. */
static int mask_prefixlen(const struct sockaddr *mask) {
        int bits = 0;

        if (!mask)
                return -1;

        if (mask->sa_family == AF_INET) {
                uint32_t m = ((const struct sockaddr_in *) mask)->sin_addr.s_addr;
                while (m) {
                        bits += m & 1;
                        m >>= 1;
                }
        } else if (mask->sa_family == AF_INET6) {
                const struct sockaddr_in6 *m6 = (const struct sockaddr_in6 *) mask;
                for (size_t i = 0; i < sizeof m6->sin6_addr.s6_addr; i++) {
                        unsigned char byte = m6->sin6_addr.s6_addr[i];
                        while (byte) {
                                bits += byte & 1;
                                byte >>= 1;
                        }
                }
        } else
                return -1;

        return bits;
}

static void print_addresses(const char *ifname) {
        struct ifaddrs *all, *a;

        if (getifaddrs(&all) < 0) {
                fprintf(stderr, "networkctl: getifaddrs: %s\n", strerror(errno));
                return;
        }

        for (a = all; a; a = a->ifa_next) {
                char host[NI_MAXHOST];
                int prefix;

                if (strcmp(a->ifa_name, ifname) != 0 || !a->ifa_addr)
                        continue;
                if (a->ifa_addr->sa_family != AF_INET && a->ifa_addr->sa_family != AF_INET6)
                        continue;

                if (getnameinfo(a->ifa_addr,
                                 a->ifa_addr->sa_family == AF_INET ? sizeof(struct sockaddr_in)
                                                                    : sizeof(struct sockaddr_in6),
                                 host, sizeof host, NULL, 0, NI_NUMERICHOST) != 0)
                        continue;

                prefix = mask_prefixlen(a->ifa_netmask);
                if (prefix >= 0)
                        printf("       Address: %s/%d\n", host, prefix);
                else
                        printf("       Address: %s\n", host);
        }

        freeifaddrs(all);
}

static int status_one(const char *ifname) {
        unsigned int idx = if_nametoindex(ifname);

        if (idx == 0) {
                fprintf(stderr, "networkctl: unknown interface '%s'\n", ifname);
                return 1;
        }

        printf("%s (%u):\n", ifname, idx);
        print_operstate(ifname);
        print_addresses(ifname);
        return 0;
}

static int status_all(void) {
        struct if_nameindex *list, *i;

        list = if_nameindex();
        if (!list) {
                fprintf(stderr, "networkctl: if_nameindex: %s\n", strerror(errno));
                return 1;
        }

        printf("IDX LINK\n");
        for (i = list; i->if_name; i++)
                printf("%3u %s\n", i->if_index, i->if_name);

        if_freenameindex(list);
        return 0;
}

static int cmd_status(int argc, char *argv[]) {
        if (argc >= 3)
                return status_one(argv[2]);
        return status_all();
}

int main(int argc, char *argv[]) {
        if (argc < 2) {
                fprintf(stderr, "Usage: %s reload | status [INTERFACE]\n", argv[0]);
                return 2;
        }

        if (strcmp(argv[1], "reload") == 0)
                return cmd_reload();
        if (strcmp(argv[1], "status") == 0)
                return cmd_status(argc, argv);

        fprintf(stderr, "networkctl: unknown command '%s'\n", argv[1]);
        return 2;
}
