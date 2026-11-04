/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * /etc/resolv.conf. See netd-resolv.h for the rules.
 *
 * A full rebuild from every link's static DNS= plus, where UseDNS=
 * allows it, the link's lease's option 6 and its routers' RDNSS -- and the
 * lease's domainname (option 15) and, where [IPv6AcceptRA] UseDomains=
 * allows it, the routers' DNSSL as the `search` line. There is no static
 * equivalent of the domain (netd-network.h's Network has no Domain= field).
 */

#include "netd-resolv.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "../util.h"
#include "dhcp/dhcp-lease-internal.h"
#include "ndisc/ndisc-link.h"
#include "netd-addr.h"
#include "netd-link.h"
#include "netd-network.h"
#include "netd.h"

/* One nameserver line: a link-local IPv6 server needs its interface. */
typedef struct ResolvServer {
        uint8_t family;
        NetdInAddr address;
        const char *ifname; /* borrowed from the Link, for a link-local server */
} ResolvServer;

/* Add a server unless it is already listed or the list is full. Silently
 * drops anything past NETD_RESOLV_MAX_NAMESERVERS -- glibc itself reads no
 * more than that, so a fourth entry would be misleading, not generous. */
static void add_nameserver(ResolvServer *servers, size_t *n, int family, const NetdInAddr *a, const char *ifname) {
        bool ll = family == AF_INET6 && netd_addr_is_link_local(AF_INET6, a);

        if (*n >= NETD_RESOLV_MAX_NAMESERVERS)
                return;

        for (size_t i = 0; i < *n; i++)
                if (servers[i].family == family && netd_addr_eq(family, &servers[i].address, a) &&
                    (!ll || strcmp(servers[i].ifname, ifname) == 0))
                        return;

        servers[*n].family = (uint8_t) family;
        servers[*n].address = *a;
        servers[*n].ifname = ifname;
        (*n)++;
}

/* A search domain, unless already listed (case does not matter in DNS) or
 * the list is full. */
static void add_domain(const char **domains, size_t *n, const char *d) {
        if (*n >= NETD_RESOLV_MAX_DOMAINS)
                return;

        for (size_t i = 0; i < *n; i++)
                if (strcasecmp(domains[i], d) == 0)
                        return;

        domains[(*n)++] = d;
}

/* Atomic tmp+rename over a fixed suffix -- netd is single-threaded and this
 * runs to completion within one epoll iteration, so there is no concurrent
 * writer to race (same reasoning as netd-time.c's atomic_symlink()). */
static int write_atomic(const char *path, const char *content, size_t len) {
        char tmp[PATH_MAX];
        int fd, len_snp, r;
        ssize_t written;

        len_snp = snprintf(tmp, sizeof(tmp), "%s.netd-tmp", path);
        if (len_snp < 0 || (size_t) len_snp >= sizeof(tmp))
                return -ENAMETOOLONG;

        fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd < 0)
                return -errno;

        written = write(fd, content, len);
        if (written < 0 || (size_t) written != len) {
                r = written < 0 ? -errno : -EIO;
                (void) close(fd);
                (void) unlink(tmp);
                return r;
        }

        if (close(fd) < 0) {
                r = -errno;
                (void) unlink(tmp);
                return r;
        }

        if (rename(tmp, path) < 0) {
                r = -errno;
                (void) unlink(tmp);
                return r;
        }

        return 0;
}

int netd_resolv_write(Netd *n) {
        ResolvServer servers[NETD_RESOLV_MAX_NAMESERVERS];
        const char *domains[NETD_RESOLV_MAX_DOMAINS];
        size_t n_servers = 0, n_domains = 0;
        const char *domain = NULL;
        char buf[4096];
        size_t off = 0;
        int written;

        if (!n || !n->resolv_conf)
                return -EINVAL;

        for (size_t i = 0; i < n->n_links; i++) {
                Link *l = n->links[i];
                Network *nw = l->network;

                if (!nw)
                        continue;

                for (size_t j = 0; j < nw->n_dns; j++)
                        add_nameserver(servers, &n_servers, nw->dns[j].family, &nw->dns[j].address, l->ifname);

                if (nw->dhcp_use_dns && l->lease) {
                        const struct in_addr *dns;
                        int r = dhcp_lease_get_dns(l->lease, &dns);

                        for (int k = 0; k < r; k++) {
                                NetdInAddr a = { .in = dns[k] };

                                add_nameserver(servers, &n_servers, AF_INET, &a, l->ifname);
                        }
                }

                if (!domain && l->lease) {
                        const char *d;

                        if (dhcp_lease_get_domainname(l->lease, &d) >= 0)
                                domain = d;
                }

                if (nw->ra_use_dns && l->ndisc)
                        for (size_t k = 0; k < l->ndisc->n_rdnss; k++) {
                                NetdInAddr a = { .in6 = l->ndisc->rdnss[k].addr };

                                add_nameserver(servers, &n_servers, AF_INET6, &a, l->ifname);
                        }
        }

        /* The lease's domain first, then the routers' search lists, in link
         * order. */
        if (domain)
                add_domain(domains, &n_domains, domain);
        for (size_t i = 0; i < n->n_links; i++) {
                Link *l = n->links[i];

                if (!l->network || !l->network->ra_use_domains || !l->ndisc)
                        continue;
                for (size_t k = 0; k < l->ndisc->n_dnssl; k++)
                        add_domain(domains, &n_domains, l->ndisc->dnssl[k].name);
        }

        if (n_servers == 0 && n_domains == 0) {
                /* Nothing to write: never blank out a working file just
                 * because the last link lost its lease (netd-resolv.h). */
                return 1;
        }

        written = snprintf(buf + off, sizeof(buf) - off, "# generated by netd -- do not edit\n");
        if (written > 0 && (size_t) written < sizeof(buf) - off)
                off += (size_t) written;

        for (size_t i = 0; i < n_servers; i++) {
                const ResolvServer *s = &servers[i];
                char ip[INET6_ADDRSTRLEN];
                bool ll = s->family == AF_INET6 && netd_addr_is_link_local(AF_INET6, &s->address);

                written = snprintf(
                                buf + off,
                                sizeof(buf) - off,
                                "nameserver %s%s%s\n",
                                netd_addr_to_string(s->family, &s->address, ip),
                                ll ? "%" : "",
                                ll ? s->ifname : "");
                if (written < 0 || (size_t) written >= sizeof(buf) - off)
                        break;
                off += (size_t) written;
        }

        if (n_domains > 0) {
                written = snprintf(buf + off, sizeof(buf) - off, "search");
                if (written > 0 && (size_t) written < sizeof(buf) - off)
                        off += (size_t) written;
                for (size_t i = 0; i < n_domains; i++) {
                        written = snprintf(buf + off, sizeof(buf) - off, " %s", domains[i]);
                        if (written > 0 && (size_t) written < sizeof(buf) - off)
                                off += (size_t) written;
                }
                written = snprintf(buf + off, sizeof(buf) - off, "\n");
                if (written > 0 && (size_t) written < sizeof(buf) - off)
                        off += (size_t) written;
        }

        return write_atomic(n->resolv_conf, buf, off);
}
