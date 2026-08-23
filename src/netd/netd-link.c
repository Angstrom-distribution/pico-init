/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The interface table and the per-link state machine. See netd-link.h.
 *
 * N1: table operations, .network matching, the per-link state machine, and
 * static Address=/Gateway= application are real. Arming a DHCPv4
 * client/server is logged and deferred -- src/netd/dhcp/'s client and server
 * objects are still quarry placeholders (N2/N3), so there is nothing yet to
 * call. link_apply_lease()/link_write_lease_file() are implemented against
 * the real DhcpLease accessor API (already landed) so N2's client has
 * somewhere real to hand a lease the moment it exists.
 */

#include "netd-link.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../util.h"
#include "dhcp/dhcp-lease-internal.h"
#include "netd-network.h"
#include "netd-resolv.h"
#include "netd-sntp.h"
#include "netd-time.h"
#include "netd.h"

/*
 * Shared by static Gateway= and by a lease's default route: a link has one
 * "the route netd put in" slot (Link.gateway/gateway_configured), so
 * whichever source configured it, removing it later needs the same metric to
 * find the same kernel route again. RTA_PRIORITY lets a second interface's
 * default route coexist rather than collide (netd-rtnl.h) -- one fixed
 * metric is enough for netd's own routes to stay out of each other's way; a
 * link with more than one default route source at once is not a shape any
 * real .network file here produces.
 */
#define NETD_LINK_ROUTE_METRIC 100

/* --- idempotent rtnl wrappers ---
 *
 * -EEXIST from an add that is already exactly as requested, and -ENOENT/
 * -ESRCH/-EADDRNOTAVAIL from a delete of something already gone, are both
 * translated to success here, not in netd-rtnl.c (netd-rtnl.h's own
 * contract): this layer is what knows a repeated add or a redundant delete
 * during idempotent reconvergence is not a failure.
 */

static int address_add_idempotent(
                NetdRtnl *rtnl, int ifindex, const struct in_addr *addr, unsigned char prefixlen, uint32_t life) {
        int r = netd_rtnl_address_add(rtnl, ifindex, addr, prefixlen, NULL, life);
        return r == -EEXIST ? 0 : r;
}

static int address_del_idempotent(
                NetdRtnl *rtnl, int ifindex, const struct in_addr *addr, unsigned char prefixlen) {
        int r = netd_rtnl_address_del(rtnl, ifindex, addr, prefixlen);
        return (r == -EADDRNOTAVAIL || r == -ENOENT) ? 0 : r;
}

static int route_add_default_idempotent(NetdRtnl *rtnl, int ifindex, const struct in_addr *gw, uint32_t metric) {
        int r = netd_rtnl_route_add_default(rtnl, ifindex, gw, metric);
        return r == -EEXIST ? 0 : r;
}

static int route_del_default_idempotent(NetdRtnl *rtnl, int ifindex, const struct in_addr *gw, uint32_t metric) {
        int r = netd_rtnl_route_del(rtnl, ifindex, NULL, 0, gw, metric);
        return (r == -ESRCH || r == -ENOENT) ? 0 : r;
}

/* --- table operations --- */

int link_new(Netd *n, const NetdRtnlLink *rl, Link **ret) {
        Link **grown;
        Link *l;

        if (!n || !rl)
                return -EINVAL;

        l = calloc(1, sizeof(*l));
        if (!l)
                return -ENOMEM;

        l->netd = n;
        l->ifindex = rl->ifindex;
        l->flags = rl->flags;
        l->arp_type = rl->arp_type;
        l->hw_addr_len = rl->hw_addr_len;
        memcpy(l->hw_addr, rl->hw_addr, sizeof(l->hw_addr));

        /* rl->ifname is NUL-terminated by the decoder; copy defensively
         * anyway, since it comes off the wire. */
        memcpy(l->ifname, rl->ifname, sizeof(l->ifname) - 1);
        l->ifname[sizeof(l->ifname) - 1] = '\0';

        l->state = LINK_PENDING;

        grown = realloc(n->links, (n->n_links + 1) * sizeof(Link *));
        if (!grown) {
                free(l);
                return -ENOMEM;
        }

        n->links = grown;
        n->links[n->n_links++] = l;

        if (ret)
                *ret = l;

        return 0;
}

Link *link_free(Link *l) {
        Netd *n;

        if (!l)
                return NULL;

        n = l->netd;

        /*
         * link_deconfigure() itself refuses (logged -EBUSY) if
         * l->applying_lease is somehow set, but that can only happen if a
         * REMOVED rtnl event for this exact ifindex were processed from
         * inside link_apply_lease()'s own call graph -- and it never is:
         * link_apply_lease() only performs synchronous rtnl writes, never
         * netd_rtnl_process(), so no live event can be dispatched while it is
         * on the stack. The (void) here is the same best-effort discipline
         * every other caller of link_free() already uses.
         */
        (void) link_deconfigure(l);

        if (l->lease)
                l->lease = dhcp_lease_unref(l->lease);

        if (n) {
                for (size_t i = 0; i < n->n_links; i++)
                        if (n->links[i] == l) {
                                memmove(&n->links[i], &n->links[i + 1], (n->n_links - i - 1) * sizeof(Link *));
                                n->n_links--;
                                break;
                        }
        }

        free(l);
        return NULL;
}

Link *netd_find_link(Netd *n, int ifindex) {
        if (!n)
                return NULL;

        for (size_t i = 0; i < n->n_links; i++)
                if (n->links[i]->ifindex == ifindex)
                        return n->links[i];

        return NULL;
}

Link *netd_find_link_by_name(Netd *n, const char *ifname) {
        if (!n || !ifname)
                return NULL;

        for (size_t i = 0; i < n->n_links; i++)
                if (strcmp(n->links[i]->ifname, ifname) == 0)
                        return n->links[i];

        return NULL;
}

static void link_update_snapshot(Link *l, const NetdRtnlLink *rl) {
        l->flags = rl->flags;
        l->arp_type = rl->arp_type;
        l->hw_addr_len = rl->hw_addr_len;
        memcpy(l->hw_addr, rl->hw_addr, sizeof(l->hw_addr));
        memcpy(l->ifname, rl->ifname, sizeof(l->ifname) - 1);
        l->ifname[sizeof(l->ifname) - 1] = '\0';
}

int netd_link_rtnl_handler(void *userdata, NetdRtnlLinkEvent event, const NetdRtnlLink *rl) {
        Netd *n = userdata;
        Link *l;
        int r;

        if (!n || !rl)
                return -EINVAL;

        switch (event) {

        case NETD_RTNL_LINK_REMOVED:
                /* Never seen from inside a dump (netd-rtnl.h: a dump only
                 * ever reports ADDED), so no rtnl_dump_in_progress check is
                 * needed here -- link_free()/link_deconfigure()'s rtnl
                 * writes cannot land mid-dump through this path. */
                l = netd_find_link(n, rl->ifindex);
                if (l)
                        (void) link_free(l);
                return 0;

        case NETD_RTNL_LINK_ADDED:
                /*
                 * A re-enumeration dump reports every link ADDED regardless
                 * of history (netd-rtnl.h's own contract), so an already-known
                 * ifindex arriving here is netd's ENOBUFS-recovery path, not
                 * a bug -- update in place rather than creating a duplicate.
                 */
                l = netd_find_link(n, rl->ifindex);
                if (l)
                        link_update_snapshot(l, rl);
                else {
                        r = link_new(n, rl, &l);
                        if (r < 0)
                                return r;
                }

                /*
                 * See Netd.rtnl_dump_in_progress: every ADDED reaching this
                 * function during netd_rtnl_enumerate_links() must only
                 * update the table, never write to the kernel -- the caller
                 * (netd-loop.c) configures every discovered link itself once
                 * the dump has fully drained.
                 */
                if (n->rtnl_dump_in_progress)
                        return 0;

                return link_configure(l);

        case NETD_RTNL_LINK_CHANGED:
                /* A live event only (netd-rtnl.h: a dump never reports
                 * CHANGED), so the socket is always idle here -- no deferral
                 * needed. */
                l = netd_find_link(n, rl->ifindex);
                if (!l) {
                        /* Defensive: a CHANGED for an ifindex netd never saw
                         * ADDED for should not happen, but treating it as a
                         * fresh sighting is safer than dropping it. */
                        r = link_new(n, rl, &l);
                        if (r < 0)
                                return r;
                } else
                        link_update_snapshot(l, rl);

                return link_configure(l);

        default:
                return -EINVAL;
        }
}

/* --- static Address=/Gateway= convergence --- */

static int apply_static_address(Link *l, const Network *nw) {
        Netd *n = l->netd;
        const NetworkAddress *want;
        int r;

        if (nw->n_addresses == 0) {
                if (!l->address_configured)
                        return 0;

                r = address_del_idempotent(n->rtnl, l->ifindex, &l->address, l->prefixlen);
                if (r < 0)
                        return r;

                l->address_configured = false;
                return 0;
        }

        if (nw->n_addresses > 1)
                pico_log(PICO_LOG_DEBUG,
                         "netd: %s: %s lists %zu Address= entries, only the first is applied",
                         l->ifname,
                         nw->basename,
                         nw->n_addresses);

        want = &nw->addresses[0];

        /* Already exactly right: leave it strictly alone. Reloading must not
         * bounce a working interface (netd-link.h on link_reconfigure()). */
        if (l->address_configured && l->address.s_addr == want->address.s_addr &&
            l->prefixlen == want->prefixlen)
                return 0;

        /*
         * Old address first, then the new one. The "already exactly right"
         * check above is what makes an unchanged address never reach here at
         * all, which is the case that actually needs a no-window guarantee
         * (a lease renewal, or a reload that changed nothing) -- REPLACE
         * refreshes it in place with no delete involved. A *genuine* change
         * of address must not add-then-delete: reproduced directly against
         * this kernel, adding a second address in the same subnet the
         * current one already covers makes it "secondary", and deleting the
         * primary cascades into deleting every secondary in that subnet too
         * (net.ipv4.conf.*.promote_secondaries defaults to 0) -- so
         * add-before-remove would silently delete BOTH addresses instead of
         * leaving a brief gap, and the very next gateway route add then
         * fails as "Nexthop has invalid gateway" because the interface has
         * no covering route left at all.
         */
        if (l->address_configured) {
                r = address_del_idempotent(n->rtnl, l->ifindex, &l->address, l->prefixlen);
                if (r < 0)
                        return r;
                l->address_configured = false;
        }

        r = address_add_idempotent(n->rtnl, l->ifindex, &want->address, want->prefixlen, UINT32_MAX);
        if (r < 0)
                return r;

        l->address = want->address;
        l->prefixlen = want->prefixlen;
        l->address_configured = true;
        return 0;
}

static int apply_static_gateway(Link *l, const Network *nw) {
        Netd *n = l->netd;
        int r;

        if (!nw->gateway_set) {
                if (!l->gateway_configured)
                        return 0;

                r = route_del_default_idempotent(n->rtnl, l->ifindex, &l->gateway, NETD_LINK_ROUTE_METRIC);
                if (r < 0)
                        return r;

                l->gateway_configured = false;
                return 0;
        }

        if (l->gateway_configured && l->gateway.s_addr == nw->gateway.s_addr)
                return 0;

        r = route_add_default_idempotent(n->rtnl, l->ifindex, &nw->gateway, NETD_LINK_ROUTE_METRIC);
        if (r < 0)
                return r;

        if (l->gateway_configured)
                (void) route_del_default_idempotent(n->rtnl, l->ifindex, &l->gateway, NETD_LINK_ROUTE_METRIC);

        l->gateway = nw->gateway;
        l->gateway_configured = true;
        return 0;
}

/* --- the state machine --- */

int link_configure(Link *l) {
        Netd *n;
        Network *nw;
        bool converged = true;
        int r;

        if (!l)
                return -EINVAL;

        n = l->netd;

        /* See netd-link.h's comment on Link.applying_lease: refuse to
         * reconfigure while a lease application for this same link is on the
         * call stack, rather than mutate state it may still depend on. */
        if (l->applying_lease) {
                pico_log(PICO_LOG_WARNING,
                         "netd: %s: refusing to (re)configure while a lease is being applied",
                         l->ifname);
                return -EBUSY;
        }

        /*
         * Always re-match from scratch, never trust a previous l->network:
         * this is what makes link_configure() safe to call from a live event,
         * from re-enumeration, and (via link_reconfigure()) from SIGHUP,
         * where the old Network the pointer named has already been freed by
         * network_load_all().
         */
        nw = network_find(n, l->ifname);
        l->network = nw;

        if (!nw) {
                if (l->state == LINK_CONFIGURING || l->state == LINK_CONFIGURED || l->state == LINK_FAILED) {
                        r = link_deconfigure(l);
                        if (r < 0)
                                pico_log(PICO_LOG_WARNING,
                                         "netd: %s: teardown on losing its match failed: %s",
                                         l->ifname,
                                         strerror(-r));
                }
                l->state = LINK_UNMANAGED;
                return 0;
        }

        l->state = LINK_CONFIGURING;

        r = netd_rtnl_link_up(n->rtnl, l->ifindex);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "netd: %s: failed to bring link up: %s", l->ifname, strerror(-r));
                l->state = LINK_FAILED;
                return r;
        }

        r = apply_static_address(l, nw);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "netd: %s: failed to apply Address=: %s", l->ifname, strerror(-r));
                l->state = LINK_FAILED;
                return r;
        }

        r = apply_static_gateway(l, nw);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "netd: %s: failed to apply Gateway=: %s", l->ifname, strerror(-r));
                l->state = LINK_FAILED;
                return r;
        }

        /*
         * DHCP client/server: src/netd/dhcp/'s client and server objects are
         * still N2/N3 quarry placeholders with no constructor to call, so
         * there is nothing to arm yet. Logged, not failed -- a link that
         * asks for DHCP is not misconfigured, N2/N3 simply have not landed.
         * A link in this state stays LINK_CONFIGURING rather than
         * LINK_CONFIGURED: not everything the .network asked for is in the
         * kernel yet.
         */
        if (network_dhcp4_enabled(nw) && !l->dhcp_client) {
                pico_log(PICO_LOG_DEBUG,
                         "netd: %s: DHCP= requested; client not implemented yet (N2)",
                         l->ifname);
                converged = false;
        }

        if (nw->dhcp_server && !l->dhcp_server) {
                pico_log(PICO_LOG_DEBUG,
                         "netd: %s: DHCPServer=yes requested; server not implemented yet (N3)",
                         l->ifname);
                converged = false;
        }

        l->state = converged ? LINK_CONFIGURED : LINK_CONFIGURING;

        /* Static DNS= may have just changed; not incremental, see
         * netd-resolv.h. */
        r = netd_resolv_write(n);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "netd: resolv.conf: %s", strerror(-r));

        return 0;
}

int link_reconfigure(Link *l) {
        if (!l)
                return -EINVAL;

        /*
         * The SIGHUP path for one link (netd-link.h). link_configure()
         * already re-matches from scratch and converges idempotently against
         * whatever it finds -- a link whose match and configuration are
         * unchanged takes the "already exactly right" branch in
         * apply_static_address()/apply_static_gateway() and is left alone,
         * which is what makes this safe to call unconditionally for every
         * link on every reload rather than only for ones that look dirty.
         */
        return link_configure(l);
}

int link_deconfigure(Link *l) {
        Netd *n;
        int r, ret = 0;

        if (!l)
                return -EINVAL;

        n = l->netd;

        if (l->applying_lease) {
                pico_log(PICO_LOG_WARNING,
                         "netd: %s: refusing to deconfigure while a lease is being applied",
                         l->ifname);
                return -EBUSY;
        }

        /* N2/N3: stop l->dhcp_client / l->dhcp_server here once those objects
         * exist. Neither is ever non-NULL yet (see link_configure()). */

        if (l->gateway_configured) {
                r = route_del_default_idempotent(n->rtnl, l->ifindex, &l->gateway, NETD_LINK_ROUTE_METRIC);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: failed to remove route: %s",
                                 l->ifname,
                                 strerror(-r));
                        if (ret == 0)
                                ret = r;
                } else
                        l->gateway_configured = false;
        }

        if (l->address_configured) {
                r = address_del_idempotent(n->rtnl, l->ifindex, &l->address, l->prefixlen);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: failed to remove address: %s",
                                 l->ifname,
                                 strerror(-r));
                        if (ret == 0)
                                ret = r;
                } else
                        l->address_configured = false;
        }

        if (l->lease) {
                (void) link_remove_lease_file(l);
                l->lease = dhcp_lease_unref(l->lease);
        }

        return ret;
}

/* --- lease application --- */

int link_apply_lease(Link *l, DhcpLease *lease) {
        Netd *n;
        Network *nw;
        struct in_addr addr;
        unsigned char prefixlen;
        usec_t lifetime;
        uint32_t lifetime_sec = UINT32_MAX;
        DhcpLease *old;
        int r;

        if (!l || !lease)
                return -EINVAL;

        n = l->netd;
        nw = l->network;

        /* See netd-link.h: a nested lease application for the same link
         * should never happen, but refuse rather than corrupt state if it
         * ever does. */
        if (l->applying_lease) {
                dhcp_lease_unref(lease);
                return -EBUSY;
        }

        l->applying_lease = true;

        r = dhcp_lease_get_address(lease, &addr);
        if (r < 0)
                goto fail;

        r = dhcp_lease_get_prefix(lease, NULL, &prefixlen);
        if (r < 0) {
                /* No subnet mask option in the lease: fall back to the
                 * classful default the way a bare BOOTP reply would need to. */
                r = in4_addr_default_prefixlen(&addr, &prefixlen);
                if (r < 0)
                        goto fail;
        }

        if (dhcp_lease_get_lifetime(lease, &lifetime) >= 0 && lifetime != USEC_INFINITY)
                lifetime_sec = (uint32_t) (lifetime / USEC_PER_SEC);

        /*
         * A renewal to the *same* address (the common case: T1/T2 firing
         * with nothing else changed) is a single NLM_F_REPLACE that only
         * refreshes the kernel lifetime -- no delete, so no window with no
         * address at all, exactly netd-link.h's contract. A renewal to a
         * genuinely different address deletes the old one first: adding the
         * new one first would make it "secondary" whenever both addresses
         * share a subnet, and deleting the old (primary) one then cascades
         * into deleting the new (secondary) one too
         * (net.ipv4.conf.*.promote_secondaries defaults to 0) -- reproduced
         * directly against this kernel while building N1's own test, see
         * apply_static_address()'s comment for the repro. Losing both
         * addresses at once for one lease-cycle tick is a worse outage than
         * the brief gap this ordering accepts.
         */
        if (l->address_configured && (l->address.s_addr != addr.s_addr || l->prefixlen != prefixlen)) {
                r = address_del_idempotent(n->rtnl, l->ifindex, &l->address, l->prefixlen);
                if (r < 0)
                        goto fail;
                l->address_configured = false;
        }

        r = address_add_idempotent(n->rtnl, l->ifindex, &addr, prefixlen, lifetime_sec);
        if (r < 0)
                goto fail;

        l->address = addr;
        l->prefixlen = prefixlen;
        l->address_configured = true;

        {
                const struct in_addr *routers;
                int nrouters = dhcp_lease_get_router(lease, &routers);

                if (nrouters > 0 && routers[0].s_addr != 0 &&
                    (!l->gateway_configured || l->gateway.s_addr != routers[0].s_addr)) {
                        int rr = route_add_default_idempotent(
                                        n->rtnl, l->ifindex, &routers[0], NETD_LINK_ROUTE_METRIC);

                        if (rr == 0) {
                                if (l->gateway_configured)
                                        (void) route_del_default_idempotent(
                                                        n->rtnl, l->ifindex, &l->gateway, NETD_LINK_ROUTE_METRIC);
                                l->gateway = routers[0];
                                l->gateway_configured = true;
                        } else
                                pico_log(PICO_LOG_WARNING,
                                         "netd: %s: failed to apply lease default route: %s",
                                         l->ifname,
                                         strerror(-rr));
                }
        }

        old = l->lease;
        l->lease = lease; /* takes ownership, per netd-link.h */
        if (old)
                dhcp_lease_unref(old);

        r = link_write_lease_file(l);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "netd: %s: failed to write lease file: %s", l->ifname, strerror(-r));

        if (!nw || nw->dhcp_use_dns) {
                r = netd_resolv_write(n);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING, "netd: resolv.conf: %s", strerror(-r));
        }

        if (!nw || nw->dhcp_use_ntp) {
                const struct in_addr *ntp;
                int nntp = dhcp_lease_get_ntp(l->lease, &ntp);

                if (nntp > 0) {
                        if (!n->sntp) {
                                int rr = netd_sntp_new(n, &n->sntp);

                                if (rr < 0)
                                        pico_log(PICO_LOG_WARNING,
                                                 "netd: sntp: failed to start: %s",
                                                 strerror(-rr));
                        }
                        if (n->sntp) {
                                (void) netd_sntp_set_servers(n->sntp, ntp, (size_t) nntp);
                                (void) netd_sntp_start(n->sntp);
                        }
                }
        }

        if (!nw || nw->dhcp_use_timezone) {
                const char *tz;

                if (dhcp_lease_get_timezone(l->lease, &tz) >= 0) {
                        r = netd_time_set_timezone(n, tz);
                        if (r < 0 && r != -EINVAL)
                                pico_log(PICO_LOG_WARNING,
                                         "netd: %s: failed to apply DHCP timezone: %s",
                                         l->ifname,
                                         strerror(-r));
                }
        }

        l->state = LINK_CONFIGURED;
        l->applying_lease = false;
        return 0;

fail:
        l->applying_lease = false;
        dhcp_lease_unref(lease);
        return r;
}

int link_lose_lease(Link *l) {
        int r;

        if (!l)
                return -EINVAL;

        if (l->applying_lease)
                return -EBUSY;

        r = link_deconfigure(l);

        /* N2: restart l->dhcp_client here once it exists -- see the report
         * on this milestone for why that call cannot be wired yet. */

        l->state = LINK_CONFIGURING;
        return r;
}

/* --- lease state files --- */

int link_write_lease_file(Link *l) {
        Netd *n;
        char *path = NULL;
        char name[32];
        char tmp[PATH_MAX];
        char ip[INET_ADDRSTRLEN];
        FILE *f;
        int len, r;

        if (!l)
                return -EINVAL;

        if (!l->lease)
                return -ENODATA;

        n = l->netd;

        len = snprintf(name, sizeof(name), "%d", l->ifindex);
        if (len < 0 || (size_t) len >= sizeof(name))
                return -ENAMETOOLONG;

        r = netd_runtime_path(n, "leases", name, true, &path);
        if (r < 0)
                return r;

        len = snprintf(tmp, sizeof(tmp), "%s.netd-tmp", path);
        if (len < 0 || (size_t) len >= sizeof(tmp)) {
                free(path);
                return -ENAMETOOLONG;
        }

        f = fopen(tmp, "we");
        if (!f) {
                r = -errno;
                free(path);
                return r;
        }

        if (!inet_ntop(AF_INET, &l->address, ip, sizeof(ip))) {
                r = -errno;
                goto fail;
        }

        fprintf(f, "ADDRESS=%s\n", ip);
        fprintf(f, "PREFIXLEN=%u\n", (unsigned) l->prefixlen);

        if (l->gateway_configured && inet_ntop(AF_INET, &l->gateway, ip, sizeof(ip)))
                fprintf(f, "ROUTER=%s\n", ip);

        {
                const struct in_addr *dns;
                int n_dns = dhcp_lease_get_dns(l->lease, &dns);

                if (n_dns > 0) {
                        fprintf(f, "DNS=");
                        for (int i = 0; i < n_dns; i++)
                                if (inet_ntop(AF_INET, &dns[i], ip, sizeof(ip)))
                                        fprintf(f, "%s%s", i > 0 ? " " : "", ip);
                        fprintf(f, "\n");
                }
        }

        {
                const struct in_addr *ntp;
                int n_ntp = dhcp_lease_get_ntp(l->lease, &ntp);

                if (n_ntp > 0) {
                        fprintf(f, "NTP=");
                        for (int i = 0; i < n_ntp; i++)
                                if (inet_ntop(AF_INET, &ntp[i], ip, sizeof(ip)))
                                        fprintf(f, "%s%s", i > 0 ? " " : "", ip);
                        fprintf(f, "\n");
                }
        }

        {
                const char *tz;

                if (dhcp_lease_get_timezone(l->lease, &tz) >= 0)
                        fprintf(f, "TIMEZONE=%s\n", tz);
        }

        {
                usec_t v;

                if (dhcp_lease_get_lifetime(l->lease, &v) >= 0)
                        fprintf(f, "LIFETIME=%llu\n", (unsigned long long) (v / USEC_PER_SEC));
                if (dhcp_lease_get_t1(l->lease, &v) >= 0)
                        fprintf(f, "T1=%llu\n", (unsigned long long) (v / USEC_PER_SEC));
                if (dhcp_lease_get_t2(l->lease, &v) >= 0)
                        fprintf(f, "T2=%llu\n", (unsigned long long) (v / USEC_PER_SEC));
        }

        if (fflush(f) != 0 || ferror(f)) {
                r = -EIO;
                goto fail;
        }

        if (fclose(f) != 0) {
                r = -errno;
                f = NULL;
                goto fail_unlink;
        }

        if (rename(tmp, path) < 0) {
                r = -errno;
                goto fail_unlink;
        }

        free(path);
        return 0;

fail:
        if (f)
                (void) fclose(f);
fail_unlink:
        (void) unlink(tmp);
        free(path);
        return r;
}

int link_remove_lease_file(Link *l) {
        Netd *n;
        char *path = NULL;
        char name[32];
        int len, r;

        if (!l)
                return -EINVAL;

        n = l->netd;

        len = snprintf(name, sizeof(name), "%d", l->ifindex);
        if (len < 0 || (size_t) len >= sizeof(name))
                return -ENAMETOOLONG;

        r = netd_runtime_path(n, "leases", name, false, &path);
        if (r < 0)
                return r;

        if (unlink(path) < 0 && errno != ENOENT) {
                r = -errno;
                free(path);
                return r;
        }

        free(path);
        return 0;
}

static const char * const link_state_table[_LINK_STATE_MAX] = {
        [LINK_PENDING] = "pending",       [LINK_UNMANAGED] = "unmanaged", [LINK_CONFIGURING] = "configuring",
        [LINK_CONFIGURED] = "configured", [LINK_FAILED] = "failed",
};

const char *link_state_to_string(LinkState s) {
        if (s < 0 || s >= _LINK_STATE_MAX)
                return "invalid";

        return link_state_table[s];
}
