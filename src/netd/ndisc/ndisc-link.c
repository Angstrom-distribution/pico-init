/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* See ndisc-link.h. */

/* struct in6_pktinfo (RFC 3542) is behind __USE_GNU in glibc's <netinet/in.h>. */
#define _GNU_SOURCE

#include "ndisc-link.h"

#include <errno.h>
#include <netinet/icmp6.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include "netd.h"

/* An Ethernet-sized datagram. A router advertisement does not fragment
 * (RFC 4861 6.1.2 asks for hop limit 255 on one link), so anything longer is
 * dropped whole. */
#define NDISC_RX_BUFFER 1500

static void ndisc_debug(const NdiscLink *l, const char *what) {
        pico_log(PICO_LOG_DEBUG, "netd: %s: router advertisement: %s", l->ifname, what);
}

static bool in6_eq(const struct in6_addr *a, const struct in6_addr *b) {
        return memcmp(a, b, sizeof(*a)) == 0;
}

static usec_t usec_min_set(usec_t a, usec_t b) {
        if (a == 0 || a == USEC_INFINITY)
                return b;
        if (b == 0 || b == USEC_INFINITY)
                return a;
        return a < b ? a : b;
}

/* --- the tables --- */

static void routers_remove(NdiscLink *l, size_t i) {
        memmove(&l->routers[i], &l->routers[i + 1], (l->n_routers - i - 1) * sizeof(l->routers[0]));
        l->n_routers--;
        l->warned_full_routers = false;
}

static void prefixes_remove(NdiscLink *l, size_t i) {
        memmove(&l->prefixes[i], &l->prefixes[i + 1], (l->n_prefixes - i - 1) * sizeof(l->prefixes[0]));
        l->n_prefixes--;
        l->warned_full_prefixes = false;
}

static void rdnss_remove(NdiscLink *l, size_t i) {
        memmove(&l->rdnss[i], &l->rdnss[i + 1], (l->n_rdnss - i - 1) * sizeof(l->rdnss[0]));
        l->n_rdnss--;
        l->warned_full_rdnss = false;
}

static void dnssl_remove(NdiscLink *l, size_t i) {
        memmove(&l->dnssl[i], &l->dnssl[i + 1], (l->n_dnssl - i - 1) * sizeof(l->dnssl[0]));
        l->n_dnssl--;
        l->warned_full_dnssl = false;
}

static void tables_clear(NdiscLink *l) {
        l->n_routers = l->n_prefixes = l->n_rdnss = l->n_dnssl = 0;
        l->mtu = 0;
        l->warned_full_routers = l->warned_full_prefixes = false;
        l->warned_full_rdnss = l->warned_full_dnssl = false;
}

static bool tables_empty(const NdiscLink *l) {
        return l->n_routers == 0 && l->n_prefixes == 0 && l->n_rdnss == 0 && l->n_dnssl == 0 && l->mtu == 0;
}

static void warn_full(NdiscLink *l, bool *warned, const char *what, unsigned max) {
        if (*warned)
                return;

        pico_log(PICO_LOG_WARNING,
                 "netd: %s: more than %u %s advertised, ignoring the rest until one expires",
                 l->ifname,
                 max,
                 what);
        *warned = true;
}

static void router_update(NdiscLink *l, const struct in6_addr *src, const NdiscRaHeader *h, usec_t now) {
        for (size_t i = 0; i < l->n_routers; i++) {
                if (!in6_eq(&l->routers[i].addr, src))
                        continue;

                if (h->router_lifetime == 0)
                        routers_remove(l, i);
                else {
                        l->routers[i].pref = h->pref;
                        l->routers[i].until = ndisc_lifetime_deadline(now, h->router_lifetime);
                }
                return;
        }

        if (h->router_lifetime == 0)
                return;

        if (l->n_routers >= NDISC_ROUTERS_MAX) {
                warn_full(l, &l->warned_full_routers, "routers", NDISC_ROUTERS_MAX);
                return;
        }

        l->routers[l->n_routers++] = (NdiscRouter){
                .addr = *src,
                .pref = h->pref,
                .until = ndisc_lifetime_deadline(now, h->router_lifetime),
        };
}

static void prefix_update(NdiscLink *l, const NdiscPrefixInfo *pi, NdiscPref pref, usec_t now) {
        NdiscPrefix *p = NULL;
        bool slaac = pi->autonomous && pi->preferred_sec <= pi->valid_sec;

        /* RFC 4861 4.6.2: a link-local prefix is ignored; so is multicast. */
        if ((pi->prefix.s6_addr[0] == 0xfe && (pi->prefix.s6_addr[1] & 0xc0) == 0x80) ||
            pi->prefix.s6_addr[0] == 0xff)
                return;

        for (size_t i = 0; i < l->n_prefixes; i++)
                if (l->prefixes[i].prefixlen == pi->prefixlen && in6_eq(&l->prefixes[i].prefix, &pi->prefix)) {
                        p = &l->prefixes[i];
                        break;
                }

        if (!p) {
                if (pi->valid_sec == 0 || (!pi->onlink && !slaac))
                        return;

                if (l->n_prefixes >= NDISC_PREFIXES_MAX) {
                        warn_full(l, &l->warned_full_prefixes, "prefixes", NDISC_PREFIXES_MAX);
                        return;
                }

                p = &l->prefixes[l->n_prefixes++];
                memset(p, 0, sizeof(*p));
                p->prefix = pi->prefix;
                p->prefixlen = pi->prefixlen;
        }

        if (pi->onlink) {
                p->onlink_until = pi->valid_sec == 0 ? 0 : ndisc_lifetime_deadline(now, pi->valid_sec);
                p->pref = pref;
        }

        if (slaac && (p->valid_until != 0 || pi->valid_sec != 0)) {
                p->valid_until = ndisc_slaac_valid_until(now, pi->valid_sec, p->valid_until);
                p->preferred_until = ndisc_lifetime_deadline(now, pi->preferred_sec);
                if (p->preferred_until > p->valid_until)
                        p->preferred_until = p->valid_until;
                if (p->valid_until <= now)
                        p->valid_until = p->preferred_until = 0;
        }

        if (p->onlink_until == 0 && p->valid_until == 0)
                prefixes_remove(l, (size_t) (p - l->prefixes));
}

static void rdnss_update(NdiscLink *l, const struct in6_addr *a, uint32_t lifetime, usec_t now) {
        for (size_t i = 0; i < l->n_rdnss; i++) {
                if (!in6_eq(&l->rdnss[i].addr, a))
                        continue;

                if (lifetime == 0)
                        rdnss_remove(l, i);
                else
                        l->rdnss[i].until = ndisc_lifetime_deadline(now, lifetime);
                return;
        }

        if (lifetime == 0)
                return;

        if (l->n_rdnss >= NDISC_RDNSS_MAX) {
                warn_full(l, &l->warned_full_rdnss, "DNS servers", NDISC_RDNSS_MAX);
                return;
        }

        l->rdnss[l->n_rdnss++] = (NdiscRdnss){ .addr = *a, .until = ndisc_lifetime_deadline(now, lifetime) };
}

static void dnssl_update(NdiscLink *l, const char *name, uint32_t lifetime, usec_t now) {
        for (size_t i = 0; i < l->n_dnssl; i++) {
                if (strcasecmp(l->dnssl[i].name, name) != 0)
                        continue;

                if (lifetime == 0)
                        dnssl_remove(l, i);
                else
                        l->dnssl[i].until = ndisc_lifetime_deadline(now, lifetime);
                return;
        }

        if (lifetime == 0)
                return;

        if (l->n_dnssl >= NDISC_DNSSL_MAX) {
                warn_full(l, &l->warned_full_dnssl, "search domains", NDISC_DNSSL_MAX);
                return;
        }

        snprintf(l->dnssl[l->n_dnssl].name, sizeof(l->dnssl[0].name), "%s", name);
        l->dnssl[l->n_dnssl].until = ndisc_lifetime_deadline(now, lifetime);
        l->n_dnssl++;
}

/* One option of an advertisement, in the pass for its lifetime: options with
 * a zero lifetime go first, so an advertisement that withdraws one entry and
 * announces another never finds the table full of the withdrawn one. */
static void option_apply(NdiscLink *l, const NdiscOpt *opt, const NdiscRaHeader *h, bool zero_pass, usec_t now) {
        NdiscPrefixInfo pi;
        uint32_t lifetime;
        size_t n, pos = 0;
        char name[NDISC_DNSSL_NAME_MAX];

        switch (opt->type) {
        case NDISC_OPT_PREFIX:
                if (ndisc_opt_prefix(opt, &pi) < 0) {
                        ndisc_debug(l, "malformed prefix option skipped");
                        return;
                }
                if ((pi.valid_sec == 0) == zero_pass)
                        prefix_update(l, &pi, h->pref, now);
                return;

        case NDISC_OPT_RDNSS:
                if (ndisc_opt_rdnss(opt, &lifetime, &n) < 0) {
                        ndisc_debug(l, "malformed RDNSS option skipped");
                        return;
                }
                if ((lifetime == 0) != zero_pass)
                        return;
                for (size_t i = 0; i < n; i++) {
                        struct in6_addr a;

                        ndisc_opt_rdnss_addr(opt, i, &a);
                        rdnss_update(l, &a, lifetime, now);
                }
                return;

        case NDISC_OPT_DNSSL:
                if (ndisc_opt_dnssl(opt, &lifetime) < 0) {
                        ndisc_debug(l, "malformed DNSSL option skipped");
                        return;
                }
                if ((lifetime == 0) != zero_pass)
                        return;
                while (ndisc_opt_dnssl_next(opt, &pos, name) > 0)
                        dnssl_update(l, name, lifetime, now);
                return;

        case NDISC_OPT_ROUTE:
                if (!zero_pass && !l->logged_route_info) {
                        ndisc_debug(l, "route information options are not used");
                        l->logged_route_info = true;
                }
                return;

        default:
                return;
        }
}

/* --- expiry --- */

static void expire_cb(void *userdata, usec_t now);

static usec_t next_deadline(const NdiscLink *l) {
        usec_t next = 0;

        for (size_t i = 0; i < l->n_routers; i++)
                next = usec_min_set(next, l->routers[i].until);
        for (size_t i = 0; i < l->n_prefixes; i++) {
                next = usec_min_set(next, l->prefixes[i].onlink_until);
                next = usec_min_set(next, l->prefixes[i].valid_until);
        }
        for (size_t i = 0; i < l->n_rdnss; i++)
                next = usec_min_set(next, l->rdnss[i].until);
        for (size_t i = 0; i < l->n_dnssl; i++)
                next = usec_min_set(next, l->dnssl[i].until);

        return next == USEC_INFINITY ? 0 : next;
}

static void expire_rearm(NdiscLink *l) {
        usec_t next = next_deadline(l);

        if (next == l->expire_deadline && (l->expire_timer || next == 0))
                return;

        if (l->expire_timer)
                (void) pico_timer_cancel(l->netd->timer, l->expire_timer);
        l->expire_deadline = next;
        if (next != 0 && pico_timer_add(l->netd->timer, next, expire_cb, l, &l->expire_timer) < 0)
                l->expire_deadline = 0;
}

static bool expired(usec_t until, usec_t now) {
        return until != 0 && until != USEC_INFINITY && until <= now;
}

/* Drops what has run out; true when anything did. */
static bool tables_expire(NdiscLink *l, usec_t now) {
        bool changed = false;

        for (size_t i = l->n_routers; i > 0; i--)
                if (expired(l->routers[i - 1].until, now)) {
                        routers_remove(l, i - 1);
                        changed = true;
                }

        for (size_t i = l->n_prefixes; i > 0; i--) {
                NdiscPrefix *p = &l->prefixes[i - 1];

                if (expired(p->onlink_until, now)) {
                        p->onlink_until = 0;
                        changed = true;
                }
                if (expired(p->valid_until, now)) {
                        p->valid_until = p->preferred_until = 0;
                        changed = true;
                }
                if (p->onlink_until == 0 && p->valid_until == 0)
                        prefixes_remove(l, i - 1);
        }

        for (size_t i = l->n_rdnss; i > 0; i--)
                if (expired(l->rdnss[i - 1].until, now)) {
                        rdnss_remove(l, i - 1);
                        changed = true;
                }

        for (size_t i = l->n_dnssl; i > 0; i--)
                if (expired(l->dnssl[i - 1].until, now)) {
                        dnssl_remove(l, i - 1);
                        changed = true;
                }

        return changed;
}

static void expire_cb(void *userdata, usec_t now) {
        NdiscLink *l = userdata;

        l->expire_deadline = 0;
        if (tables_expire(l, now) && l->notify)
                l->notify(l->userdata);
        expire_rearm(l);
}

/* --- solicitations --- */

static void rs_cb(void *userdata, usec_t now);

static void rs_cancel(NdiscLink *l) {
        if (l->rs_timer)
                (void) pico_timer_cancel(l->netd->timer, l->rs_timer);
        l->rs_timer = NULL;
        l->soliciting = false;
}

static int rs_send(NdiscLink *l) {
        static const struct sockaddr_in6 all_routers = {
                .sin6_family = AF_INET6,
                .sin6_addr = { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 } } },
        };
        uint8_t buf[NDISC_RS_HEADER_LEN + 8];
        size_t len = ndisc_rs_build(buf, l->hw, l->hw_len);
        struct sockaddr_in6 dst = all_routers;

        dst.sin6_scope_id = (uint32_t) l->ifindex;
        if (sendto(l->fd, buf, len, MSG_DONTWAIT, (const struct sockaddr *) &dst, sizeof(dst)) < 0)
                return -errno;

        return 0;
}

/* `interval` give or take 10%. */
static usec_t jittered(usec_t interval) {
        uint32_t r = 0;

        if (getrandom(&r, sizeof(r), GRND_NONBLOCK) != (ssize_t) sizeof(r))
                return interval;

        return interval - interval / 10 + (usec_t) (r % 1000) * (interval / 5) / 1000;
}

static void rs_cb(void *userdata, usec_t now) {
        NdiscLink *l = userdata;
        int r;

        if (!l->soliciting || l->fd < 0)
                return;

        r = rs_send(l);
        if (r < 0)
                pico_log(PICO_LOG_DEBUG, "netd: %s: router solicitation: %s", l->ifname, strerror(-r));

        if (pico_timer_add(l->netd->timer, usec_add(now, jittered(l->rs_interval)), rs_cb, l, &l->rs_timer) < 0)
                l->soliciting = false;

        l->rs_interval *= 2;
        if (l->rs_interval > NDISC_RS_INTERVAL_MAX_USEC)
                l->rs_interval = NDISC_RS_INTERVAL_MAX_USEC;
}

/* RFC 4861 6.3.7: the first solicitation waits up to a second at random, so
 * boards powered up together do not all solicit at once. */
static usec_t rs_first_delay(void) {
        uint32_t r = 0;

        if (getrandom(&r, sizeof(r), GRND_NONBLOCK) != (ssize_t) sizeof(r))
                return NDISC_RS_DELAY_MAX_USEC / 2;

        return (usec_t) r % NDISC_RS_DELAY_MAX_USEC;
}

static void rs_start(NdiscLink *l) {
        rs_cancel(l);
        l->soliciting = true;
        l->rs_interval = NDISC_RS_INTERVAL_USEC;
        if (pico_timer_add(l->netd->timer, usec_add(now_monotonic(), rs_first_delay()), rs_cb, l, &l->rs_timer) <
            0)
                l->soliciting = false;
}

/* --- receive --- */

void ndisc_link_receive(
                NdiscLink *l,
                const uint8_t *buf,
                size_t len,
                const struct in6_addr *src,
                int hop_limit,
                int ifindex,
                usec_t now) {
        NdiscRaHeader h;
        NdiscOptIter it;
        NdiscOpt opt;
        uint32_t mtu = 0;

        if (hop_limit != 255 || ifindex != l->ifindex) {
                ndisc_debug(l, "dropped: not from this link (hop limit or interface)");
                return;
        }
        if (src->s6_addr[0] != 0xfe || (src->s6_addr[1] & 0xc0) != 0x80) {
                ndisc_debug(l, "dropped: source is not link-local");
                return;
        }
        if (ndisc_ra_parse_header(buf, len, &h) < 0) {
                ndisc_debug(l, "dropped: not a router advertisement");
                return;
        }
        if (ndisc_ra_check_options(buf, len) < 0) {
                ndisc_debug(l, "dropped: malformed options");
                return;
        }

        if ((h.managed || h.other) && !l->logged_dhcpv6) {
                ndisc_debug(l, "the router asks for DHCPv6, which is not implemented");
                l->logged_dhcpv6 = true;
        }

        router_update(l, src, &h, now);
        if (h.router_lifetime > 0 && l->soliciting)
                rs_cancel(l);

        for (int pass = 0; pass < 2; pass++) {
                ndisc_opt_iter_init(&it, buf, len);
                while (ndisc_opt_iter_next(&it, &opt) > 0)
                        option_apply(l, &opt, &h, pass == 0, now);
        }

        ndisc_opt_iter_init(&it, buf, len);
        while (ndisc_opt_iter_next(&it, &opt) > 0)
                if (opt.type == NDISC_OPT_MTU && ndisc_opt_mtu(&opt, &mtu) == 0)
                        l->mtu = mtu;

        if (l->notify)
                l->notify(l->userdata);
        expire_rearm(l);
}

static int io_cb(Netd *n, struct netd_epoll_tag *tag, uint32_t revents) {
        NdiscLink *l = tag->userdata;

        (void) n;
        (void) revents;

        for (unsigned i = 0; i < NDISC_RX_BATCH && l->fd >= 0; i++) {
                uint8_t buf[NDISC_RX_BUFFER];
                union {
                        struct cmsghdr align;
                        uint8_t buf[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct in6_pktinfo))];
                } control;
                struct sockaddr_in6 from;
                struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
                struct msghdr msg = {
                        .msg_name = &from,
                        .msg_namelen = sizeof(from),
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                        .msg_control = &control,
                        .msg_controllen = sizeof(control),
                };
                int hop_limit = -1, ifindex = 0;
                ssize_t len;

                len = recvmsg(l->fd, &msg, MSG_DONTWAIT | MSG_TRUNC);
                if (len < 0) {
                        if (errno == EINTR)
                                continue;
                        if (errno != EAGAIN)
                                pico_log(PICO_LOG_DEBUG,
                                         "netd: %s: router advertisement receive: %s",
                                         l->ifname,
                                         strerror(errno));
                        break;
                }

                if ((size_t) len > sizeof(buf) || (msg.msg_flags & MSG_TRUNC)) {
                        pico_log(PICO_LOG_DEBUG,
                                 "netd: %s: router advertisement: dropped: longer than %d bytes",
                                 l->ifname,
                                 NDISC_RX_BUFFER);
                        continue;
                }
                if ((msg.msg_flags & MSG_CTRUNC) || msg.msg_namelen < sizeof(from) ||
                    from.sin6_family != AF_INET6)
                        continue;

                for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
                        if (c->cmsg_level != IPPROTO_IPV6)
                                continue;

                        if (c->cmsg_type == IPV6_HOPLIMIT && c->cmsg_len == CMSG_LEN(sizeof(int)))
                                memcpy(&hop_limit, CMSG_DATA(c), sizeof(int));
                        else if (c->cmsg_type == IPV6_PKTINFO &&
                                 c->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
                                struct in6_pktinfo pi;

                                memcpy(&pi, CMSG_DATA(c), sizeof(pi));
                                ifindex = (int) pi.ipi6_ifindex;
                        }
                }

                ndisc_link_receive(l, buf, (size_t) len, &from.sin6_addr, hop_limit, ifindex, now_monotonic());
        }

        return 0;
}

/* --- socket and lifecycle --- */

static int open_socket(NdiscLink *l) {
        static const struct ipv6_mreq all_nodes_template = {
                .ipv6mr_multiaddr = { { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 } } },
        };
        struct ipv6_mreq all_nodes = all_nodes_template;
        struct icmp6_filter filter;
        int fd, one = 1, zero = 0, hops = 255, ifindex = l->ifindex, r;

        fd = socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_ICMPV6);
        if (fd < 0)
                return -errno;

        ICMP6_FILTER_SETBLOCKALL(&filter);
        ICMP6_FILTER_SETPASS(ND_ROUTER_ADVERT, &filter);
        all_nodes.ipv6mr_interface = (unsigned) l->ifindex;

        if (setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter, sizeof(filter)) < 0 ||
            setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &one, sizeof(one)) < 0 ||
            setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one)) < 0 ||
            setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &ifindex, sizeof(ifindex)) < 0 ||
            setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) < 0 ||
            setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)) < 0 ||
            setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &zero, sizeof(zero)) < 0 ||
            setsockopt(fd, IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP, &all_nodes, sizeof(all_nodes)) < 0)
                goto fail;

        /* SO_BINDTOIFINDEX needs Linux 5.0; the name works on older kernels. */
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTOIFINDEX, &ifindex, sizeof(ifindex)) < 0 &&
            setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, l->ifname, (socklen_t) strlen(l->ifname)) < 0)
                goto fail;

        return fd;

fail:
        r = -errno;
        (void) close(fd);
        return r;
}

int ndisc_link_new(
                Netd *n,
                int ifindex,
                const char *ifname,
                ndisc_link_notify_t notify,
                void *userdata,
                NdiscLink **ret) {
        NdiscLink *l;

        if (!n || !ifname || !ret || ifindex <= 0)
                return -EINVAL;

        l = calloc(1, sizeof(*l));
        if (!l)
                return -ENOMEM;

        l->netd = n;
        l->ifindex = ifindex;
        l->fd = -1;
        l->notify = notify;
        l->userdata = userdata;
        snprintf(l->ifname, sizeof(l->ifname), "%s", ifname);
        *ret = l;
        return 0;
}

bool ndisc_link_is_running(const NdiscLink *l) {
        return l && l->fd >= 0;
}

int ndisc_link_start(NdiscLink *l, const uint8_t *hw, size_t hw_len) {
        int fd, r;

        if (!l)
                return -EINVAL;

        l->hw_len = hw && hw_len == sizeof(l->hw) ? hw_len : 0;
        if (l->hw_len)
                memcpy(l->hw, hw, sizeof(l->hw));

        if (l->fd >= 0)
                return 0;

        fd = open_socket(l);
        if (fd < 0)
                return fd;

        r = netd_loop_add_io(l->netd, &l->io_tag, fd, EPOLLIN, NETD_EPOLL_NDISC, io_cb, l);
        if (r < 0) {
                (void) close(fd);
                return r;
        }

        l->fd = fd;
        l->carrier = l->ll_ready = false;
        pico_log(PICO_LOG_INFO, "netd: %s: accepting IPv6 router advertisements", l->ifname);
        return 0;
}

void ndisc_link_stop(NdiscLink *l) {
        if (!l)
                return;

        rs_cancel(l);
        if (l->expire_timer)
                (void) pico_timer_cancel(l->netd->timer, l->expire_timer);
        l->expire_timer = NULL;
        l->expire_deadline = 0;

        (void) netd_loop_remove_io(l->netd, &l->io_tag);
        if (l->fd >= 0)
                (void) close(l->fd);
        l->fd = -1;
        l->carrier = l->ll_ready = false;
        tables_clear(l);
}

void ndisc_link_set_state(NdiscLink *l, bool carrier, bool ll_ready) {
        bool was_ready, ready;

        if (!l || l->fd < 0 || (l->carrier == carrier && l->ll_ready == ll_ready))
                return;

        was_ready = l->carrier && l->ll_ready;
        ready = carrier && ll_ready;

        if (l->carrier && !carrier) {
                rs_cancel(l);
                if (!tables_empty(l)) {
                        tables_clear(l);
                        if (l->notify)
                                l->notify(l->userdata);
                        expire_rearm(l);
                }
        }

        l->carrier = carrier;
        l->ll_ready = ll_ready;

        if (ready && !was_ready)
                rs_start(l);
}

void ndisc_link_free(NdiscLink *l) {
        if (!l)
                return;

        ndisc_link_stop(l);
        free(l);
}

void ndisc_link_free_void(void *l) {
        ndisc_link_free(l);
}
