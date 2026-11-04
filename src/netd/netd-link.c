/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The interface table and the per-link state machine. See netd-link.h.
 */

#include "netd-link.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <linux/if_addr.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../util.h"
#include "dhcp/dhcp-client-internal.h"
#include "dhcp/dhcp-lease-internal.h"
#include "dhcp/dhcp-server-internal.h"
#include "dhcp/siphash24.h"
#include "lldp/lldp-link.h"
#include "netd-network.h"
#include "netd-resolv.h"
#include "netd-sntp.h"
#include "netd-time.h"
#include "netd.h"

/*
 * Route metrics follow systemd-networkd. A lease's default route, its host
 * route to an off-subnet router and the prefix route of the leased address
 * use [DHCPv4] RouteMetric=, default 1024 (networkd's DHCP_ROUTE_METRIC). A
 * Gateway= route has no metric of its own, so it gets the kernel's 0, as does
 * the prefix route of an Address= without RouteMetric=.
 *
 * Links sharing a metric do not collide: routes are added with
 * NLM_F_CREATE|NLM_F_APPEND and deleted by oif, gateway and priority (see
 * netd-rtnl.h), so each link's route stays its own.
 */
#define NETD_DHCP_ROUTE_METRIC 1024

static uint32_t link_lease_route_metric(const Link *l) {
        if (l->network && l->network->dhcp_route_metric_set)
                return l->network->dhcp_route_metric;

        return NETD_DHCP_ROUTE_METRIC;
}

static uint32_t link_route_metric(const Link *l, bool from_lease) {
        return from_lease ? link_lease_route_metric(l) : 0;
}

/* --- idempotent rtnl wrappers ---
 *
 * -EEXIST from an add that is already exactly as requested, and -ENOENT/
 * -ESRCH/-EADDRNOTAVAIL from a delete of something already gone, are both
 * translated to success here, not in netd-rtnl.c (netd-rtnl.h's own
 * contract): this layer is what knows a repeated add or a redundant delete
 * during idempotent reconvergence is not a failure.
 */

/* An IPv4 address with no peer, label, flags or scope, as a lease's is sent. */
static void address_v4(NetdRtnlAddress *a, int ifindex, const struct in_addr *addr, unsigned char prefixlen) {
        memset(a, 0, sizeof(*a));
        a->ifindex = ifindex;
        a->family = AF_INET;
        a->prefixlen = prefixlen;
        a->address.in = *addr;
}

static int address_add_idempotent(
                NetdRtnl *rtnl,
                int ifindex,
                const struct in_addr *addr,
                unsigned char prefixlen,
                uint32_t life,
                uint32_t metric) {
        NetdRtnlAddress a;
        int r;

        address_v4(&a, ifindex, addr, prefixlen);
        a.valid_sec = life;
        a.preferred_sec = life;
        a.route_metric = metric;

        r = netd_rtnl_address_add(rtnl, &a);
        return r == -EEXIST ? 0 : r;
}

static int address_del_idempotent(
                NetdRtnl *rtnl, int ifindex, const struct in_addr *addr, unsigned char prefixlen) {
        NetdRtnlAddress a;
        int r;

        address_v4(&a, ifindex, addr, prefixlen);

        r = netd_rtnl_address_del(rtnl, &a);
        return (r == -EADDRNOTAVAIL || r == -ENOENT) ? 0 : r;
}

static int route_add_idempotent(NetdRtnl *rtnl, const NetdRtnlRoute *rt) {
        int r = netd_rtnl_route_add(rtnl, rt);
        return r == -EEXIST ? 0 : r;
}

static int route_del_idempotent(NetdRtnl *rtnl, const NetdRtnlRoute *rt) {
        int r = netd_rtnl_route_del(rtnl, rt);
        return (r == -ESRCH || r == -ENOENT) ? 0 : r;
}

/* True when `a`/`a_pfx` and `b`/`b_pfx` name the same connected-route
 * prefix -- the condition that makes the kernel's secondary-address
 * cascade-delete reachable (see converge_address() below). Passed by value:
 * in4_addr_mask() masks its argument in place. */
static bool same_subnet(struct in_addr a, unsigned char a_pfx, struct in_addr b, unsigned char b_pfx) {
        if (a_pfx != b_pfx)
                return false;

        (void) in4_addr_mask(&a, a_pfx);
        (void) in4_addr_mask(&b, b_pfx);

        return a.s_addr == b.s_addr;
}

static int link_gateway_remove(Link *l);
static uint32_t lease_remaining_sec(DhcpLease *lease);

/* --- the static route table --- */

static bool link_route_same(const LinkRoute *a, const LinkRoute *b) {
        return a->family == b->family && a->dst_len == b->dst_len && a->scope == b->scope &&
                        a->has_gw == b->has_gw && a->has_prefsrc == b->has_prefsrc && a->flags == b->flags &&
                        a->metric == b->metric &&
                        memcmp(a->dst.bytes, b->dst.bytes, sizeof(a->dst.bytes)) == 0 &&
                        memcmp(a->gw.bytes, b->gw.bytes, sizeof(a->gw.bytes)) == 0 &&
                        memcmp(a->prefsrc.bytes, b->prefsrc.bytes, sizeof(a->prefsrc.bytes)) == 0;
}

static void link_route_to_rtnl(const Link *l, const LinkRoute *r, NetdRtnlRoute *out) {
        memset(out, 0, sizeof(*out));
        out->ifindex = l->ifindex;
        out->family = r->family;
        out->dst_len = r->dst_len;
        out->scope = r->scope;
        out->dst = r->dst;
        out->gw = r->gw;
        out->has_gw = r->has_gw;
        out->prefsrc = r->prefsrc;
        out->has_prefsrc = r->has_prefsrc;
        out->flags = r->flags;
        out->metric = r->metric;
}

static LinkRoute *link_route_find(Link *l, const LinkRoute *like) {
        for (size_t i = 0; i < l->n_routes; i++)
                if (link_route_same(&l->routes[i], like))
                        return &l->routes[i];

        return NULL;
}

/* Forgets the record at `r`, which points into l->routes. */
static void link_route_forget(Link *l, LinkRoute *r) {
        size_t i = (size_t) (r - l->routes);

        memmove(&l->routes[i], &l->routes[i + 1], (l->n_routes - i - 1) * sizeof(*r));
        l->n_routes--;
}

/* Records `r`, or updates the record of the same route. */
static int link_route_record(Link *l, const LinkRoute *r) {
        LinkRoute *have = link_route_find(l, r), *grown;

        if (have) {
                *have = *r;
                return 0;
        }

        if (l->n_routes >= LINK_ROUTES_MAX)
                return -ENOSPC;

        grown = realloc(l->routes, (l->n_routes + 1) * sizeof(*grown));
        if (!grown)
                return -ENOMEM;

        l->routes = grown;
        l->routes[l->n_routes++] = *r;
        return 0;
}

static int link_route_send(Link *l, const LinkRoute *r) {
        NetdRtnlRoute rt;

        link_route_to_rtnl(l, r, &rt);
        return route_add_idempotent(l->netd->rtnl, &rt);
}

/* A link that is gone has no routes left to delete. */
static int link_route_unsend(Link *l, const LinkRoute *r) {
        NetdRtnlRoute rt;
        int rc;

        link_route_to_rtnl(l, r, &rt);
        rc = route_del_idempotent(l->netd->rtnl, &rt);
        return rc == -ENODEV ? 0 : rc;
}

/* True when a [Route] entry that is not going away names this route: its
 * kernel object then has two owners and is removed only when the last one
 * lets go. */
static bool link_static_route_owns(const Link *l, const LinkRoute *r) {
        for (size_t i = 0; i < l->n_routes; i++)
                if (!l->routes[i].doomed && link_route_same(&l->routes[i], r))
                        return true;

        return false;
}

/* The default route through `gw`, or the host route to it, as the single
 * gateway slot sends them. */
static void link_route_v4(LinkRoute *out, const struct in_addr *gw, bool host, uint32_t metric) {
        memset(out, 0, sizeof(*out));
        out->family = AF_INET;
        out->metric = metric;

        if (host) {
                out->dst.in = *gw;
                out->dst_len = 32;
                out->scope = RT_SCOPE_LINK;
        } else {
                out->gw.in = *gw;
                out->has_gw = true;
        }
}

static bool link_gateway_owns(const Link *l, const LinkRoute *r) {
        LinkRoute own;

        if (!l->gateway_configured)
                return false;

        link_route_v4(&own, &l->gateway, false, l->gateway_metric);
        if (link_route_same(&own, r))
                return true;

        link_route_v4(&own, &l->gateway, true, l->gateway_metric);
        return l->gateway_host_route && link_route_same(&own, r);
}

static int link_gateway_route_add(Link *l, const struct in_addr *gw, bool host, uint32_t metric) {
        LinkRoute id;

        link_route_v4(&id, gw, host, metric);
        return link_route_send(l, &id);
}

/* Deletes one of the gateway slot's routes unless a [Route] entry is the same
 * route. */
static int link_gateway_route_del(Link *l, const struct in_addr *gw, bool host, uint32_t metric) {
        LinkRoute id;

        link_route_v4(&id, gw, host, metric);
        if (link_static_route_owns(l, &id))
                return 0;

        return link_route_unsend(l, &id);
}

/* --- the static address table --- */

/* One address is one kernel object: an IPv4 address by (address, prefix
 * length), an IPv6 address by its address alone. */
static bool link_address_same(const LinkAddress *a, const LinkAddress *b) {
        return a->family == b->family && netd_addr_eq(a->family, &a->address, &b->address) &&
                        (a->family == AF_INET6 || a->prefixlen == b->prefixlen);
}

static bool link_address_equal(const LinkAddress *a, const LinkAddress *b) {
        return link_address_same(a, b) && a->prefixlen == b->prefixlen && a->scope == b->scope &&
                        a->flags == b->flags && a->has_peer == b->has_peer &&
                        (!a->has_peer || netd_addr_eq(a->family, &a->peer, &b->peer)) &&
                        a->route_metric == b->route_metric && a->preferred_sec == b->preferred_sec &&
                        strcmp(a->label, b->label) == 0;
}

/*
 * What an NLM_F_REPLACE changes in place. IPv4 takes only the lifetimes and
 * the prefix route metric; IPv6 also takes the peer and the flags. Anything
 * else needs the address deleted and added again.
 */
static bool link_address_updatable(const LinkAddress *have, const LinkAddress *want) {
        if (have->prefixlen != want->prefixlen || have->scope != want->scope ||
            strcmp(have->label, want->label) != 0)
                return false;

        if (have->family == AF_INET6)
                return true;

        return have->flags == want->flags && have->has_peer == want->has_peer &&
                        (!have->has_peer || netd_addr_eq(AF_INET, &have->peer, &want->peer));
}

static void link_address_to_rtnl(const Link *l, const LinkAddress *a, NetdRtnlAddress *out) {
        memset(out, 0, sizeof(*out));
        out->ifindex = l->ifindex;
        out->family = a->family;
        out->prefixlen = a->prefixlen;
        out->scope = a->scope;
        out->address = a->address;
        out->peer = a->peer;
        out->has_peer = a->has_peer;
        out->flags = a->flags;
        out->valid_sec = UINT32_MAX;
        out->preferred_sec = a->preferred_sec;
        out->route_metric = a->route_metric;
        out->label = a->label[0] ? a->label : NULL;
}

static LinkAddress *link_address_find(Link *l, const LinkAddress *like) {
        for (size_t i = 0; i < l->n_addrs; i++)
                if (link_address_same(&l->addrs[i], like))
                        return &l->addrs[i];

        return NULL;
}

static int link_address_send(Link *l, const LinkAddress *a) {
        NetdRtnlAddress ra;
        int r;

        link_address_to_rtnl(l, a, &ra);
        r = netd_rtnl_address_add(l->netd->rtnl, &ra);
        return r == -EEXIST ? 0 : r;
}

static int link_address_unsend(Link *l, const LinkAddress *a) {
        NetdRtnlAddress ra;
        int r;

        link_address_to_rtnl(l, a, &ra);
        r = netd_rtnl_address_del(l->netd->rtnl, &ra);
        return (r == -EADDRNOTAVAIL || r == -ENOENT || r == -ENODEV) ? 0 : r;
}

/* Forgets the record at `a`, which points into l->addrs. */
static void link_address_forget(Link *l, LinkAddress *a) {
        size_t i = (size_t) (a - l->addrs);

        memmove(&l->addrs[i], &l->addrs[i + 1], (l->n_addrs - i - 1) * sizeof(*a));
        l->n_addrs--;
}

/* Records `a`, or updates the record of the same address. */
static int link_address_record(Link *l, const LinkAddress *a) {
        LinkAddress *have = link_address_find(l, a), *grown;

        if (have) {
                *have = *a;
                return 0;
        }

        if (l->n_addrs >= LINK_ADDRS_MAX)
                return -ENOSPC;

        grown = realloc(l->addrs, (l->n_addrs + 1) * sizeof(*grown));
        if (!grown)
                return -ENOMEM;

        l->addrs = grown;
        l->addrs[l->n_addrs++] = *a;
        return 0;
}

/* True when a static entry also names this IPv4 address: its kernel object
 * then has two owners and is removed only when the last one lets go. */
static bool link_static_owns_v4(const Link *l, struct in_addr addr, unsigned char prefixlen) {
        for (size_t i = 0; i < l->n_addrs; i++) {
                const LinkAddress *a = &l->addrs[i];

                if (a->family == AF_INET && !a->doomed && a->prefixlen == prefixlen &&
                    a->address.in.s_addr == addr.s_addr)
                        return true;
        }

        return false;
}

static bool link_lease_owns_v4(const Link *l, struct in_addr addr, unsigned char prefixlen) {
        return l->address_configured && l->prefixlen == prefixlen && l->address.s_addr == addr.s_addr;
}

/*
 * Deleting the primary IPv4 address of a subnet also deletes every secondary
 * one (net.ipv4.conf.*.promote_secondaries defaults to 0) and the routes that
 * went through it. After any IPv4 delete, send the other addresses of that
 * subnet, the [Route] routes and the default route again; what is still there
 * answers EEXIST. A route that cannot come back is forgotten, so the next
 * converge sees it missing instead of trusting the record.
 */
static void link_v4_address_deleted(Link *l, struct in_addr addr, unsigned char prefixlen) {
        Netd *n = l->netd;
        int r;

        for (size_t i = 0; i < l->n_addrs; i++) {
                const LinkAddress *a = &l->addrs[i];

                if (a->family != AF_INET || a->doomed ||
                    !same_subnet(a->address.in, a->prefixlen, addr, prefixlen))
                        continue;

                r = link_address_send(l, a);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: failed to restore an address after a delete: %s",
                                 l->ifname,
                                 strerror(-r));
        }

        if (l->address_configured && same_subnet(l->address, l->prefixlen, addr, prefixlen) &&
            !(l->address.s_addr == addr.s_addr && l->prefixlen == prefixlen) &&
            !link_static_owns_v4(l, l->address, l->prefixlen)) {
                uint32_t life = l->lease ? lease_remaining_sec(l->lease) : UINT32_MAX;

                r = address_add_idempotent(
                                n->rtnl, l->ifindex, &l->address, l->prefixlen, life, l->address_metric);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: failed to restore the lease address after a delete: %s",
                                 l->ifname,
                                 strerror(-r));
        }

        /* What netd recorded as installed, doomed ones included: a later delete
         * at metric 0 matches any metric, so it must find the route it means. */
        for (size_t i = 0; i < l->n_routes; i++) {
                LinkRoute *rt = &l->routes[i];

                if (rt->family != AF_INET || !rt->installed)
                        continue;

                r = link_route_send(l, rt);
                if (r < 0) {
                        pico_log(PICO_LOG_DEBUG,
                                 "netd: %s: a route did not survive an address delete: %s",
                                 l->ifname,
                                 strerror(-r));
                        rt->installed = false;
                }
        }

        if (!l->gateway_configured)
                return;

        r = 0;
        if (l->gateway_host_route)
                r = link_gateway_route_add(l, &l->gateway, true, l->gateway_metric);
        if (r == 0)
                r = link_gateway_route_add(l, &l->gateway, false, l->gateway_metric);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING,
                         "netd: %s: default route did not survive an address delete: %s",
                         l->ifname,
                         strerror(-r));
                l->gateway_configured = false;
                l->gateway_host_route = false;
                l->gateway_from_lease = false;
        }
}

/*
 * The kernel flushes a link's routes with its last IPv4 address, so the
 * default route goes first and the caller adds it back; left in place, the
 * slot would claim a route the kernel no longer has. A lease address that a
 * static entry also names stays in the kernel.
 */
static int link_address_del(Link *l) {
        struct in_addr addr = l->address;
        unsigned char prefixlen = l->prefixlen;
        bool shared = link_static_owns_v4(l, addr, prefixlen);
        int r;

        if (l->gateway_configured) {
                r = link_gateway_remove(l);
                if (r < 0)
                        return r;
        }

        if (!shared) {
                r = address_del_idempotent(l->netd->rtnl, l->ifindex, &addr, prefixlen);
                if (r < 0)
                        return r;
        }

        l->address_configured = false;
        if (!shared)
                link_v4_address_deleted(l, addr, prefixlen);
        return 0;
}

/*
 * Converge Link's configured address to (want, want_pfx), choosing add/
 * delete ordering by the three cases the kernel's secondary-address
 * behaviour forces on us (netd-link.h, on link_apply_lease()):
 *
 *   1. unchanged -- a single NLM_F_REPLACE refresh (e.g. a DHCP renewal to
 *      the same address, or a reload that changed nothing). No delete at
 *      all, so no window without an address.
 *   2. a genuine change WITHIN the same subnet (e.g. a DHCP rebind handing
 *      out a different host address in the same /24) -- delete first. Adding
 *      the new address first would make it "secondary" to the old one
 *      (net.ipv4.conf.*.promote_secondaries defaults to 0), and the
 *      following delete of the old (primary) address would then cascade
 *      into deleting the new (secondary) one too. The default route goes
 *      with the old address (link_address_del()).
 *   3. a genuine change to a DIFFERENT subnet -- add first, safely, for the
 *      shortest possible address-less window; the two addresses never share
 *      a connected route, so there is no secondary/cascade risk.
 *
 * `lifetime_sec` is the lease time and `metric` the prefix route's. Used for
 * the lease only; static entries have their own table.
 */
static int converge_address(
                Link *l,
                const struct in_addr *want,
                unsigned char want_pfx,
                uint32_t lifetime_sec,
                uint32_t metric) {
        Netd *n = l->netd;
        bool shared = link_static_owns_v4(l, *want, want_pfx);
        int r;

        /* An address a static entry also names keeps the static entry's
         * lifetime and metric: the lease only records that it is there. */
        if (l->address_configured && l->address.s_addr == want->s_addr && l->prefixlen == want_pfx) {
                r = shared ? 0 :
                             address_add_idempotent(n->rtnl, l->ifindex, want, want_pfx, lifetime_sec, metric);
                if (r < 0)
                        return r;
        } else if (l->address_configured && same_subnet(l->address, l->prefixlen, *want, want_pfx)) {
                r = link_address_del(l);
                if (r < 0)
                        return r;

                r = shared ? 0 :
                             address_add_idempotent(n->rtnl, l->ifindex, want, want_pfx, lifetime_sec, metric);
                if (r < 0)
                        return r;
        } else {
                r = shared ? 0 :
                             address_add_idempotent(n->rtnl, l->ifindex, want, want_pfx, lifetime_sec, metric);
                if (r < 0)
                        return r;

                if (l->address_configured && !link_static_owns_v4(l, l->address, l->prefixlen)) {
                        struct in_addr old = l->address;
                        unsigned char old_pfx = l->prefixlen;

                        (void) address_del_idempotent(n->rtnl, l->ifindex, &old, old_pfx);
                        l->address_configured = false;
                        link_v4_address_deleted(l, old, old_pfx);
                }
        }

        l->address = *want;
        l->prefixlen = want_pfx;
        l->address_configured = true;
        l->address_metric = metric;
        return 0;
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

        (void) link_write_state_file(l);

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
         * link_deconfigure() refuses (logged -EBUSY) if l->applying_lease is
         * set, which would need a REMOVED event for this ifindex processed
         * from inside link_apply_lease(); that only performs synchronous rtnl
         * writes, never netd_rtnl_process(), so it cannot happen. Best-effort.
         */
        (void) link_deconfigure(l);

        if (l->lease)
                l->lease = dhcp_lease_unref(l->lease);

        (void) link_remove_state_file(l);
        free(l->addrs);
        free(l->routes);

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

static void link_address_from_network(const NetworkAddress *na, LinkAddress *out) {
        memset(out, 0, sizeof(*out));
        out->family = na->family;
        out->prefixlen = na->prefixlen;
        out->scope = na->scope;
        out->address = na->address;
        out->peer = na->peer;
        out->has_peer = na->peer_set;
        out->route_metric = na->route_metric;
        out->preferred_sec = na->deprecated ? 0 : UINT32_MAX;
        memcpy(out->label, na->label, sizeof(out->label));

        if (na->family == AF_INET6 && !na->dad)
                out->flags |= IFA_F_NODAD;
        if (na->no_prefix_route)
                out->flags |= IFA_F_NOPREFIXROUTE;
}

static void link_warn_address(const Link *l, const char *what, const LinkAddress *a, int r) {
        char buf[INET6_ADDRSTRLEN];

        pico_log(PICO_LOG_WARNING,
                 "netd: %s: failed to %s address %s/%u: %s",
                 l->ifname,
                 what,
                 netd_addr_to_string(a->family, &a->address, buf),
                 (unsigned) a->prefixlen,
                 strerror(-r));
}

/* Deletes the kernel address of `a` (a record in l->addrs) and forgets it. */
static int link_static_address_remove(Link *l, LinkAddress *a, bool cascade) {
        LinkAddress gone = *a;
        int r;

        /* A lease address that is also this one stays in the kernel. */
        if (!(gone.family == AF_INET && link_lease_owns_v4(l, gone.address.in, gone.prefixlen))) {
                r = link_address_unsend(l, &gone);
                if (r < 0) {
                        link_warn_address(l, "remove", &gone, r);
                        return r;
                }
        }

        link_address_forget(l, a);
        if (cascade && gone.family == AF_INET)
                link_v4_address_deleted(l, gone.address.in, gone.prefixlen);
        return 0;
}

/*
 * Brings the kernel's static addresses in line with the file: what is
 * recorded and still wanted is left alone (an unchanged reload makes no
 * netlink write), what is new is added, what differs is replaced in place when
 * the kernel takes that, and what is no longer wanted is deleted. Only
 * addresses netd recorded are ever deleted.
 *
 * Order, for the kernel's secondary-address rule (see converge_address()):
 * an address that is going away and shares an IPv4 subnet with a new one is
 * deleted first; everything else is added first and deleted last, so the
 * link is never without an address it keeps. Every IPv4 delete re-sends what
 * the kernel may have taken with it.
 */
static int apply_static_addresses(Link *l, const Network *nw) {
        LinkAddress want[NETWORK_ADDRESS_MAX];
        size_t n_want = 0;
        int first_error = 0, r;

        for (size_t i = 0; i < nw->n_addresses && n_want < NETWORK_ADDRESS_MAX; i++) {
                const NetworkAddress *na = &nw->addresses[i];

                if (na->family == AF_INET6 && !netd_ipv6_supported()) {
                        if (!l->warned_no_ipv6)
                                pico_log(PICO_LOG_WARNING,
                                         "netd: %s: %s configures IPv6 addresses but the kernel has no IPv6, skipping them",
                                         l->ifname,
                                         nw->basename);
                        l->warned_no_ipv6 = true;
                        continue;
                }

                link_address_from_network(na, &want[n_want++]);
        }

        for (size_t i = 0; i < l->n_addrs; i++) {
                bool wanted = false;

                for (size_t k = 0; k < n_want; k++)
                        if (link_address_same(&l->addrs[i], &want[k])) {
                                wanted = true;
                                break;
                        }

                l->addrs[i].doomed = !wanted;
        }

        /* Phase A: a doomed IPv4 address in the subnet of one about to be
         * added goes first, so the new one is not made its secondary. */
        for (size_t i = 0; i < l->n_addrs;) {
                LinkAddress *have = &l->addrs[i];
                bool clash = false;

                for (size_t k = 0; have->doomed && have->family == AF_INET && k < n_want; k++)
                        if (want[k].family == AF_INET && !link_address_find(l, &want[k]) &&
                            same_subnet(have->address.in, have->prefixlen, want[k].address.in, want[k].prefixlen))
                                clash = true;

                if (!clash) {
                        i++;
                        continue;
                }

                r = link_static_address_remove(l, have, true);
                if (r < 0) {
                        if (!first_error)
                                first_error = r;
                        i++;
                }
        }

        /* Phase B */
        for (size_t k = 0; k < n_want; k++) {
                LinkAddress *have = link_address_find(l, &want[k]);

                if (have && have->installed && link_address_equal(have, &want[k]))
                        continue;

                if (have && (!have->installed || !link_address_updatable(have, &want[k]))) {
                        if (have->installed) {
                                r = link_static_address_remove(l, have, true);
                                if (r < 0) {
                                        if (!first_error)
                                                first_error = r;
                                        continue;
                                }
                        } else
                                link_address_forget(l, have);
                        have = NULL;
                }

                r = link_address_send(l, &want[k]);
                if (r < 0 && want[k].family == AF_INET6 && (r == -EACCES || r == -EPERM)) {
                        /* IPv6 is disabled on this link (disable_ipv6); not a failed link.
                         * Every link event retries, so say it once. */
                        if (!l->warned_ipv6_disabled)
                                link_warn_address(l, "add", &want[k], r);
                        l->warned_ipv6_disabled = true;
                        continue;
                }
                if (r < 0) {
                        link_warn_address(l, "add", &want[k], r);
                        if (!first_error)
                                first_error = r;
                        continue;
                }

                if (want[k].family == AF_INET6)
                        l->warned_ipv6_disabled = false;

                want[k].installed = true;
                r = link_address_record(l, &want[k]);
                if (r < 0 && !first_error)
                        first_error = r;
        }

        /* Phase C */
        for (size_t i = 0; i < l->n_addrs;) {
                if (!l->addrs[i].doomed) {
                        i++;
                        continue;
                }

                r = link_static_address_remove(l, &l->addrs[i], true);
                if (r < 0) {
                        if (!first_error)
                                first_error = r;
                        i++;
                }
        }

        return first_error;
}

static void link_route_from_network(const NetworkRoute *nr, LinkRoute *out) {
        memset(out, 0, sizeof(*out));
        out->family = nr->family;
        out->dst_len = nr->dst_len;
        out->scope = nr->scope;
        out->dst = nr->dst;
        out->gw = nr->gw;
        out->has_gw = nr->gw_family != 0;
        out->prefsrc = nr->prefsrc;
        out->has_prefsrc = nr->prefsrc_family != 0;
        out->flags = nr->onlink ? RTNH_F_ONLINK : 0;
        out->metric = nr->metric;
}

static void link_warn_route(const Link *l, const char *what, const LinkRoute *r, int rc) {
        char dst[INET6_ADDRSTRLEN], gw[INET6_ADDRSTRLEN];

        pico_log(PICO_LOG_WARNING,
                 "netd: %s: failed to %s route %s/%u%s%s: %s",
                 l->ifname,
                 what,
                 netd_addr_to_string(r->family, &r->dst, dst),
                 (unsigned) r->dst_len,
                 r->has_gw ? " via " : "",
                 r->has_gw ? netd_addr_to_string(r->family, &r->gw, gw) : "",
                 strerror(-rc));
}

/* What the kernel says of a gateway no address of the link reaches yet. */
static bool route_unreachable(int rc) {
        return rc == -ENETUNREACH || rc == -ENETDOWN || rc == -EHOSTUNREACH;
}

/* Deletes the kernel route of `r` (a record in l->routes) and forgets it. A
 * route that is not installed is only forgotten: a delete of it could hit
 * another route at the same gateway, and one the gateway slot also names stays
 * in the kernel. */
static int link_static_route_remove(Link *l, LinkRoute *r) {
        LinkRoute gone = *r;
        int rc;

        if (gone.installed && !link_gateway_owns(l, &gone)) {
                rc = link_route_unsend(l, &gone);
                if (rc < 0) {
                        link_warn_route(l, "remove", &gone, rc);
                        return rc;
                }
        }

        link_route_forget(l, r);
        return 0;
}

/* True when a wanted route that is not in the table yet takes the place of
 * `have`: the same destination and gateway at another metric. */
static bool link_route_replaced(Link *l, const LinkRoute *have, const LinkRoute *want, size_t n_want) {
        for (size_t k = 0; k < n_want; k++)
                if (!link_route_find(l, &want[k]) && want[k].family == have->family &&
                    want[k].dst_len == have->dst_len && want[k].has_gw == have->has_gw &&
                    memcmp(want[k].dst.bytes, have->dst.bytes, sizeof(have->dst.bytes)) == 0 &&
                    memcmp(want[k].gw.bytes, have->gw.bytes, sizeof(have->gw.bytes)) == 0)
                        return true;

        return false;
}

/*
 * Brings the kernel's [Route] routes in line with the file, as
 * apply_static_addresses() does for addresses: what is recorded and installed
 * is left alone, what is new is added and what is no longer wanted is deleted,
 * after the adds so that a changed metric never leaves the destination
 * without a route. The exception is an IPv4 route at metric 0 that a new one
 * replaces at the same destination and gateway: a delete at 0 matches any
 * metric, so it goes first. Only routes netd recorded are ever deleted.
 *
 * A gateway that no address reaches yet (ENETUNREACH and its kin) stays
 * recorded and not installed, with one warning, and is tried again by every
 * later call: after an address or a lease changes, the next converge finds
 * it reachable. The error is still returned, for a link that has nothing
 * else that could bring the address.
 */
static int apply_static_routes(Link *l, const Network *nw) {
        LinkRoute want[NETWORK_ROUTE_MAX];
        size_t n_want = 0;
        int first_error = 0, rc;

        for (size_t i = 0; i < nw->n_routes && n_want < NETWORK_ROUTE_MAX; i++) {
                const NetworkRoute *nr = &nw->routes[i];

                if (nr->family == AF_INET6 && !netd_ipv6_supported()) {
                        if (!l->warned_no_ipv6_routes)
                                pico_log(PICO_LOG_WARNING,
                                         "netd: %s: %s configures IPv6 routes but the kernel has no IPv6, skipping them",
                                         l->ifname,
                                         nw->basename);
                        l->warned_no_ipv6_routes = true;
                        continue;
                }

                link_route_from_network(nr, &want[n_want++]);
        }

        for (size_t i = 0; i < l->n_routes; i++) {
                bool wanted = false;

                for (size_t k = 0; k < n_want; k++)
                        if (link_route_same(&l->routes[i], &want[k])) {
                                wanted = true;
                                break;
                        }

                l->routes[i].doomed = !wanted;
        }

        for (size_t i = 0; i < l->n_routes;) {
                LinkRoute *have = &l->routes[i];
                bool clash = have->doomed && have->installed && have->family == AF_INET &&
                                have->metric == 0 && link_route_replaced(l, have, want, n_want);

                if (!clash) {
                        i++;
                        continue;
                }

                rc = link_static_route_remove(l, have);
                if (rc < 0) {
                        if (!first_error)
                                first_error = rc;
                        i++;
                }
        }

        for (size_t k = 0; k < n_want; k++) {
                LinkRoute *have = link_route_find(l, &want[k]);

                if (have && have->installed)
                        continue;

                want[k].warned = have && have->warned;
                rc = link_route_send(l, &want[k]);
                if (rc == 0) {
                        want[k].installed = true;
                        want[k].warned = false;
                } else if (route_unreachable(rc)) {
                        if (!want[k].warned)
                                pico_log(PICO_LOG_WARNING,
                                         "netd: %s: a route is not reachable yet, trying again when an address or lease changes: %s",
                                         l->ifname,
                                         strerror(-rc));
                        want[k].warned = true;
                        if (!first_error)
                                first_error = rc;
                } else {
                        link_warn_route(l, "add", &want[k], rc);
                        if (!first_error)
                                first_error = rc;
                        continue;
                }

                rc = link_route_record(l, &want[k]);
                if (rc < 0 && !first_error)
                        first_error = rc;
        }

        for (size_t i = 0; i < l->n_routes;) {
                if (!l->routes[i].doomed) {
                        i++;
                        continue;
                }

                rc = link_static_route_remove(l, &l->routes[i]);
                if (rc < 0) {
                        if (!first_error)
                                first_error = rc;
                        i++;
                }
        }

        return first_error;
}

/*
 * With DHCP= off the lease's address no longer has an owner: delete it before
 * the static addresses are settled, so one in its subnet is not made its
 * secondary. An address a static entry also names is only released, and that
 * entry's add refreshes it to the static lifetime.
 */
static int link_drop_lease_address(Link *l, const Network *nw) {
        if (!l->address_configured || network_dhcp4_enabled(nw))
                return 0;

        for (size_t i = 0; i < nw->n_addresses; i++) {
                const NetworkAddress *na = &nw->addresses[i];

                if (na->family == AF_INET && na->prefixlen == l->prefixlen &&
                    na->address.in.s_addr == l->address.s_addr) {
                        l->address_configured = false;
                        return 0;
                }
        }

        return link_address_del(l);
}

/* Removes the default route and, if there is one, its host route. */
static int link_gateway_remove(Link *l) {
        int r;

        r = link_gateway_route_del(l, &l->gateway, false, l->gateway_metric);
        if (r < 0)
                return r;

        if (l->gateway_host_route) {
                r = link_gateway_route_del(l, &l->gateway, true, l->gateway_metric);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: failed to remove gateway host route: %s",
                                 l->ifname,
                                 strerror(-r));
        }

        l->gateway_configured = false;
        l->gateway_host_route = false;
        l->gateway_from_lease = false;
        return 0;
}

/*
 * Installs `gw` as the default route and drops the previous one. A router
 * outside the interface's subnet needs a link-scope host route first, or the
 * kernel refuses the default route with ENETUNREACH (systemd c9ee0d2eeb,
 * 863293dbd3: the netmask may mask out the gateway).
 *
 * Adding first keeps a default route in place throughout; APPEND never
 * collides with the old route, which is then deleted at the metric it was
 * added with. A delete at metric 0 matches any metric at that router, so an
 * old route at 0 to the same router goes first instead.
 */
static int link_gateway_replace(Link *l, const struct in_addr *gw, bool host_route, bool from_lease) {
        uint32_t new_metric = link_route_metric(l, from_lease), old_metric = l->gateway_metric;
        struct in_addr old_gw = l->gateway;
        bool had_gateway = l->gateway_configured, had_host_route = l->gateway_host_route;
        int r;

        if (had_gateway && old_metric == 0 && new_metric != 0 && old_gw.s_addr == gw->s_addr) {
                r = link_gateway_remove(l);
                if (r < 0)
                        return r;
                had_gateway = had_host_route = false;
        }

        if (host_route) {
                r = link_gateway_route_add(l, gw, true, new_metric);
                if (r < 0)
                        return r;
        }

        r = link_gateway_route_add(l, gw, false, new_metric);
        if (r < 0) {
                if (host_route)
                        (void) link_gateway_route_del(l, gw, true, new_metric);
                return r;
        }

        if (had_gateway) {
                bool same = old_gw.s_addr == gw->s_addr && old_metric == new_metric;

                if (!same)
                        (void) link_gateway_route_del(l, &old_gw, false, old_metric);
                if (had_host_route && (!same || !host_route))
                        (void) link_gateway_route_del(l, &old_gw, true, old_metric);
        }

        l->gateway = *gw;
        l->gateway_configured = true;
        l->gateway_host_route = host_route;
        l->gateway_from_lease = from_lease;
        l->gateway_metric = new_metric;
        return 0;
}

static int link_converge_static_gateway(Link *l, const Network *nw) {
        if (!nw->gateway_set)
                return l->gateway_configured ? link_gateway_remove(l) : 0;

        /* A lease's route at this address becomes Gateway='s, as at startup. */
        if (l->gateway_configured && l->gateway.s_addr == nw->gateway.s_addr && !l->gateway_from_lease &&
            l->gateway_metric == link_route_metric(l, false))
                return 0;

        return link_gateway_replace(l, &nw->gateway, false, false);
}

static int apply_static_gateway(Link *l, const Network *nw) {
        /* With a lease held, its router decides, Gateway= being the fallback:
         * link_reapply_lease_routes() settles the route. */
        if (l->lease && network_dhcp4_enabled(nw))
                return 0;

        return link_converge_static_gateway(l, nw);
}

static int lease_get_address_prefix(DhcpLease *lease, struct in_addr *addr, unsigned char *prefixlen) {
        int r;

        r = dhcp_lease_get_address(lease, addr);
        if (r < 0)
                return r;

        r = dhcp_lease_get_prefix(lease, NULL, prefixlen);
        if (r < 0)
                /* No subnet mask option in the lease: fall back to the
                 * classful default the way a bare BOOTP reply would need to. */
                return in4_addr_default_prefixlen(addr, prefixlen);

        return 0;
}

/*
 * A router that is also Gateway= stays static at metric 0, as it is at
 * startup, so a lease without a router never removes it. Such a lease removes
 * a lease's route and puts Gateway= back. Failures are only warnings.
 */
static void link_apply_lease_router(Link *l, DhcpLease *lease, struct in_addr addr, unsigned char prefixlen) {
        const Network *nw = l->network;
        const struct in_addr *routers, *router = NULL;
        int nrouters = dhcp_lease_get_router(lease, &routers);
        int r = 0;

        for (int i = 0; i < nrouters; i++)
                if (routers[i].s_addr != 0) {
                        router = &routers[i];
                        break;
                }

        if (router) {
                bool host_route = !same_subnet(addr, prefixlen, *router, prefixlen);
                bool from_lease = !(nw && nw->gateway_set && nw->gateway.s_addr == router->s_addr);

                if (l->gateway_configured && l->gateway.s_addr == router->s_addr &&
                    l->gateway_host_route == host_route && l->gateway_from_lease == from_lease &&
                    l->gateway_metric == link_route_metric(l, from_lease))
                        return;

                r = link_gateway_replace(l, router, host_route, from_lease);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: failed to apply lease default route: %s",
                                 l->ifname,
                                 strerror(-r));
                return;
        }

        if (nw)
                r = link_converge_static_gateway(l, nw);
        else if (l->gateway_configured)
                r = link_gateway_remove(l);
        if (r < 0)
                pico_log(PICO_LOG_WARNING,
                         "netd: %s: failed to remove lease default route: %s",
                         l->ifname,
                         strerror(-r));
}

/* What is left of the lease, so re-sending its address does not extend it.
 * 0 once it has run out. */
static uint32_t lease_remaining_sec(DhcpLease *lease) {
        usec_t lifetime, deadline, now;

        if (dhcp_lease_get_lifetime(lease, &lifetime) < 0 || lifetime == USEC_INFINITY)
                return UINT32_MAX;

        now = now_monotonic();
        if (dhcp_lease_get_lifetime_timestamp(lease, &deadline) >= 0 && now != USEC_INFINITY)
                lifetime = deadline > now ? deadline - now : 0;

        return (uint32_t) (lifetime / USEC_PER_SEC);
}

/*
 * A reload re-derives the held lease's routes at once, as a lease event would:
 * a changed RouteMetric= moves them, the prefix route included (bt-pan-
 * client.sh rewrites its file and runs `networkctl reload` for exactly that),
 * a changed Gateway= is weighed against the lease's router, and an unchanged
 * file changes nothing.
 */
static void link_reapply_lease_routes(Link *l, const Network *nw) {
        struct in_addr addr;
        unsigned char prefixlen;
        uint32_t metric, life;
        int r;

        if (!l->lease || !network_dhcp4_enabled(nw))
                return;

        if (lease_get_address_prefix(l->lease, &addr, &prefixlen) < 0)
                return;

        metric = link_lease_route_metric(l);
        life = lease_remaining_sec(l->lease);
        if (l->address_configured && l->address.s_addr == addr.s_addr && l->prefixlen == prefixlen &&
            l->address_metric != metric && life > 0 && !link_static_owns_v4(l, addr, prefixlen)) {
                r = address_add_idempotent(l->netd->rtnl, l->ifindex, &addr, prefixlen, life, metric);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: failed to move the prefix route: %s",
                                 l->ifname,
                                 strerror(-r));
                else
                        l->address_metric = metric;
        }

        link_apply_lease_router(l, l->lease, addr, prefixlen);
}

/* Defined near link_deconfigure() below. */
static void link_stop_dhcp_client(Link *l);
static void link_stop_dhcp_server(Link *l);
static void link_sync_lldp(Link *l, const Network *nw);

/* --- DHCPv4 client --- */

/*
 * Read ADDRESS= back out of this link's own lease file (netd-link.h's
 * KEY=VALUE format), for dhcp_client_set_request_address() below --
 * RFC 2131 4.4.2's INIT-REBOOT: a restarted netd reconfirms the lease it
 * already had instead of renumbering the interface. 0 with *ret filled, or -errno (ENOENT on a
 * first boot, or after a clean teardown already removed the file).
 */
static int link_read_lease_address(Link *l, struct in_addr *ret) {
        Netd *n = l->netd;
        _cleanup_free_ char *path = NULL;
        char name[32];
        char line[256];
        FILE *f;
        int len, r;

        len = snprintf(name, sizeof(name), "%d", l->ifindex);
        if (len < 0 || (size_t) len >= sizeof(name))
                return -ENAMETOOLONG;

        r = netd_runtime_path(n, "leases", name, false, &path);
        if (r < 0)
                return r;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        r = -ENODATA;
        while (fgets(line, sizeof(line), f)) {
                char *nl = strchr(line, '\n');
                const char *value;

                if (nl)
                        *nl = '\0';

                value = startswith(line, "ADDRESS=");
                if (!value)
                        continue;

                r = inet_pton(AF_INET, value, ret) == 1 ? 0 : -ENODATA;
                break;
        }

        (void) fclose(f);
        return r;
}

/*
 * The DHCPv4 client's event callback (dhcp-client-internal.h): `event` is a
 * DhcpClientEvent, or a negative errno on a hard client failure. Only
 * SELECTING's return value is looked at (dhcp-client-internal.h) -- netd has
 * no OFFER policy, so it always accepts.
 *
 * IP_ACQUIRE/IP_CHANGE/RENEW hand the lease to link_apply_lease() by direct
 * call. EXPIRED (NAK, expiry, or after a DECLINE) hands off to
 * link_lose_lease(), which does *not* touch the client -- see
 * that function's doc for why it restarts itself.
 */
static int dhcp_client_event_callback(DhcpClient *client, int event, void *userdata) {
        Link *l = userdata;
        int r;

        switch (event) {

        case DHCP_CLIENT_EVENT_IP_ACQUIRE:
        case DHCP_CLIENT_EVENT_IP_CHANGE:
        case DHCP_CLIENT_EVENT_RENEW: {
                DhcpLease *lease = NULL;

                r = dhcp_client_get_lease(client, &lease);
                if (r < 0 || !lease) {
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: DHCP event %d but no lease is available",
                                 l->ifname,
                                 event);
                        return 0;
                }

                /* dhcp_client_get_lease() hands back the client's own
                 * borrowed reference (dhcp-client-internal.h); link_apply_
                 * lease() takes ownership of the ref it is given, so this
                 * needs its own. */
                lease = dhcp_lease_ref(lease);

                r = link_apply_lease(l, lease);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: failed to apply DHCP lease: %s",
                                 l->ifname,
                                 strerror(-r));
                return 0;
        }

        case DHCP_CLIENT_EVENT_EXPIRED:
                pico_log(PICO_LOG_INFO, "netd: %s: DHCP lease lost (expired, NAKed, or declined)", l->ifname);
                r = link_lose_lease(l);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: failed to tear down an expired lease: %s",
                                 l->ifname,
                                 strerror(-r));
                return 0;

        case DHCP_CLIENT_EVENT_SELECTING:
                /* Accept every OFFER: netd has no policy for preferring one
                 * server's offer over another's. */
                return 0;

        case DHCP_CLIENT_EVENT_TRANSIENT_FAILURE:
                pico_log(PICO_LOG_WARNING, "netd: %s: no DHCP server answering", l->ifname);
                return 0;

        case DHCP_CLIENT_EVENT_STOP:
                return 0;

        default:
                /* A negative event is a hard client failure carrying -errno. */
                if (event < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: DHCP client failed: %s",
                                 l->ifname,
                                 strerror(-event));
                return 0;
        }
}

/*
 * Create, configure and start a DHCPv4 client for `l`. Always builds a fresh
 * client; link_configure() does not call this when l->dhcp_client is set.
 * 0 or -errno.
 */
static int link_start_dhcp_client(Link *l) {
        Netd *n = l->netd;
        DhcpClient *client = NULL;
        struct in_addr last_addr;
        int r;

        r = dhcp_client_new(n, l->ifindex, l->ifname, &client);
        if (r < 0)
                return r;

        r = dhcp_client_set_mac(client, l->hw_addr, NULL, l->hw_addr_len, l->arp_type);
        if (r < 0)
                goto fail;

        r = dhcp_client_set_callback(client, dhcp_client_event_callback, l);
        if (r < 0)
                goto fail;

        /* Best-effort: nothing to request on a first boot, or once a clean
         * teardown has already removed the lease file. */
        if (link_read_lease_address(l, &last_addr) == 0)
                (void) dhcp_client_set_request_address(client, &last_addr);

        r = dhcp_client_start(client);
        if (r < 0)
                goto fail;

        l->dhcp_client = client;
        return 0;

fail:
        dhcp_client_unref(client);
        return r;
}

/* --- DHCPv4 server --- */

/*
 * Create, configure and start a DHCPv4 server for `l`, pool derived from the
 * .network's own Address= (a usb0 gadget's static address doubles as the
 * server's address and default router). 0 or -errno.
 */
static int link_start_dhcp_server(Link *l, const Network *nw) {
        Netd *n = l->netd;
        DhcpServer *server = NULL;
        const NetworkAddress *served = network_first_address_v4(nw);
        struct in_addr address;
        unsigned char prefixlen;
        int r;

        if (!served) {
                pico_log(PICO_LOG_WARNING,
                         "netd: %s: DHCPServer=yes but no IPv4 Address= to derive the pool from",
                         l->ifname);
                return -EINVAL;
        }

        address = served->address.in;
        prefixlen = served->prefixlen;

        r = dhcp_server_new(n, l->ifindex, l->ifname, &server);
        if (r < 0)
                return r;

        /*
         * offset 0 / size 0 both mean "default" to dhcp_server_configure_
         * pool() (dhcp-server.c): skip the subnet address, fill the rest of
         * the subnet up to (not including) the broadcast address. The
         * server's own address is excluded automatically.
         */
        r = dhcp_server_configure_pool(server, &address, prefixlen, 0, 0);
        if (r < 0)
                goto fail;

        r = dhcp_server_set_router(server, &address);
        if (r < 0)
                goto fail;

        if (nw->n_dns > 0) {
                r = dhcp_server_set_dns(server, nw->dns, nw->n_dns);
                if (r < 0)
                        goto fail;
        }

        if (nw->n_ntp > 0) {
                r = dhcp_server_set_ntp(server, nw->ntp, nw->n_ntp);
                if (r < 0)
                        goto fail;
        }

        r = dhcp_server_start(server);
        if (r < 0)
                goto fail;

        l->dhcp_server = server;
        return 0;

fail:
        dhcp_server_unref(server);
        return r;
}

/* --- persistent MAC for a random-hardware-address link --- */

/*
 * include/linux/netdevice.h's enum netdev_addr_type, read back out of
 * /sys/class/net/<if>/addr_assign_type as a plain integer -- not a UAPI
 * header, so these four values are transcribed rather than #include'd.
 * Stable since the sysfs attribute was added; see
 * Documentation/ABI/testing/sysfs-class-net.
 */
#define NETD_NET_ADDR_PERM 0
#define NETD_NET_ADDR_RANDOM 1
#define NETD_NET_ADDR_STOLEN 2
#define NETD_NET_ADDR_SET 3

/* *out is one of the NETD_NET_ADDR_* values above. false when the
 * attribute is missing or unreadable (a kernel too old to have it, or a
 * link type that never gets one) -- the caller treats that the same as any
 * other "nothing to go on", never guessing. */
static bool link_read_addr_assign_type(const char *ifname, unsigned *out) {
        char path[128];
        FILE *f;
        int v;

        snprintf(path, sizeof path, "/sys/class/net/%s/addr_assign_type", ifname);
        f = fopen(path, "re");
        if (!f)
                return false;

        if (fscanf(f, "%d", &v) != 1) {
                fclose(f);
                return false;
        }
        fclose(f);

        *out = (unsigned) v;
        return true;
}

/*
 * Upstream's HASH_KEY for net_get_unique_predictable_data_from_name()
 * (systemd netif-util.c). Not dhcp-client-id.c's HASH_KEY, which is a
 * different constant for the DHCP client id.
 */
static const uint8_t PERSISTENT_MAC_HASH_KEY[16] = {
        0xd3, 0x1e, 0x48, 0xfa, 0x90, 0xfe, 0x4b, 0x4c, 0x9d, 0xaf, 0xd5, 0xd7, 0xa1, 0xb1, 0x2e, 0x8a,
};

/* True when every byte of a 16-byte id is 0 -- an uninitialized placeholder
 * /etc/machine-id, not a real identity yet. netd_machine_id() (netd-compat.h)
 * only rejects a short/malformed file, so link_apply_persistent_mac() checks
 * this itself. */
static bool id128_is_null(const NetdId128 *id) {
        for (size_t i = 0; i < sizeof(id->bytes); i++)
                if (id->bytes[i] != 0)
                        return false;

        return true;
}

void netd_persistent_mac_derive(
                const uint8_t machine_id[16], const char *ifname, uint8_t mac_out[NETD_HW_ADDR_MAX]) {
        uint8_t v[16 + IFNAMSIZ];
        size_t namelen = strlen(ifname);
        uint64_t result;

        memcpy(v, machine_id, 16);
        memcpy(v + 16, ifname, namelen);

        result = htole64(siphash24(v, 16 + namelen, PERSISTENT_MAC_HASH_KEY));
        memcpy(mac_out, &result, NETD_HW_ADDR_MAX);

        mac_out[0] &= 0xfe; /* clear multicast */
        mac_out[0] |= 0x02; /* set local-admin */
}

/*
 * Derive and apply a stable hardware address for `l`, the same algorithm
 * real systemd-networkd uses for MACAddressPolicy=persistent
 * (link-config.c's link_generate_new_hw_addr() plus
 * net_get_unique_predictable_data()/net_get_unique_predictable_data_from_name(),
 * netif-util.c), applied only to a link without a real burned-in address:
 *
 *   mac = low 6 bytes of htole64(siphash24(machine_id || ifname,
 *                                          PERSISTENT_MAC_HASH_KEY))
 *   mac[0] &= ~0x01 (clear multicast); mac[0] |= 0x02 (set local-admin)
 *
 * -- both unconditional for a generated address (net_verify_hardware_
 * address(), netif-util.c). Called on every link_configure_impl()
 * invocation, right before netd_rtnl_link_up(), so the exemptions below are
 * re-checked each time:
 *
 *   - already up: the kernel refuses an address change on most drivers once
 *     a link is administratively up, and real policy never touches an
 *     already-up link's address either.
 *   - loopback: never gets a generated address (link-config.c's own
 *     loopback short-circuit).
 *   - non-Ethernet: upstream also covers ARPHRD_INFINIBAND, which netd does
 *     not; NETD_HW_ADDR_MAX (netd-rtnl.h) is 6 bytes, too short for it.
 *   - addr_assign_type PERM/SET/STOLEN, or unreadable/unrecognized: a real
 *     burned-in address, one something else already set deliberately, or
 *     nothing to go on -- never overwritten, never guessed.
 *   - machine id missing or all-zero (id128_is_null()): logged once, no
 *     address derived from a placeholder identity a later real write would
 *     invalidate.
 *
 * Non-fatal: a MAC that could not be derived or applied is cosmetic, as in
 * upstream's link_apply_rtnl_settings() (link-config.c); l->state is never
 * affected.
 */
static void link_apply_persistent_mac(Link *l) {
        Netd *n = l->netd;
        unsigned addr_assign_type;
        NetdId128 mid;
        uint8_t mac[NETD_HW_ADDR_MAX];
        int r;

        if (l->flags & IFF_UP)
                return;

        if (l->flags & IFF_LOOPBACK)
                return;

        if (l->arp_type != ARPHRD_ETHER)
                return;

        if (!link_read_addr_assign_type(l->ifname, &addr_assign_type))
                return;

        if (addr_assign_type != NETD_NET_ADDR_RANDOM)
                return; /* PERM/SET/STOLEN, or a value this function does not recognize */

        r = netd_machine_id(&mid);
        if (r < 0 || id128_is_null(&mid)) {
                pico_log(PICO_LOG_INFO,
                         "netd: %s: machine-id not yet available, skipping persistent MAC",
                         l->ifname);
                return;
        }

        netd_persistent_mac_derive(mid.bytes, l->ifname, mac);

        r = netd_rtnl_link_set_hwaddr(n->rtnl, l->ifindex, mac, NETD_HW_ADDR_MAX);
        if (r < 0)
                pico_log(PICO_LOG_WARNING,
                         "netd: %s: failed to set persistent hardware address: %s",
                         l->ifname,
                         strerror(-r));
}

/* --- the state machine --- */

static int link_configure_impl(Link *l) {
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
         * after SIGHUP the old Network has already been freed by
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

        /*
         * A down link has lost its IPv6 addresses (keep_addr_on_down is off
         * by default) and every route through it, so those are sent again
         * below. IPv4 addresses stay.
         */
        if (!(l->flags & IFF_UP)) {
                for (size_t i = 0; i < l->n_addrs; i++)
                        if (l->addrs[i].family == AF_INET6)
                                l->addrs[i].installed = false;
                for (size_t i = 0; i < l->n_routes; i++)
                        l->routes[i].installed = false;
        }

        /*
         * Before bringing the link up: a MAC change needs the link down.
         * Self-gating, see link_apply_persistent_mac().
         */
        link_apply_persistent_mac(l);

        r = netd_rtnl_link_up(n->rtnl, l->ifindex);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "netd: %s: failed to bring link up: %s", l->ifname, strerror(-r));
                l->state = LINK_FAILED;
                return r;
        }

        r = link_drop_lease_address(l, nw);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING,
                         "netd: %s: failed to remove the lease address: %s",
                         l->ifname,
                         strerror(-r));
                l->state = LINK_FAILED;
                return r;
        }

        r = apply_static_addresses(l, nw);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "netd: %s: failed to apply Address=: %s", l->ifname, strerror(-r));
                l->state = LINK_FAILED;
                return r;
        }

        /* Likewise a [Route] whose gateway no address reaches yet; each
         * failure was already reported once. */
        r = apply_static_routes(l, nw);
        if (r < 0 && !network_dhcp4_enabled(nw)) {
                pico_log(PICO_LOG_WARNING, "netd: %s: failed to apply [Route]: %s", l->ifname, strerror(-r));
                l->state = LINK_FAILED;
                return r;
        }

        /* With DHCP on, a Gateway= not reachable yet (no Address= in its
         * subnet) must not stop the client: the next lease retries it. */
        r = apply_static_gateway(l, nw);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "netd: %s: failed to apply Gateway=: %s", l->ifname, strerror(-r));
                if (!network_dhcp4_enabled(nw)) {
                        l->state = LINK_FAILED;
                        return r;
                }
        }

        link_reapply_lease_routes(l, nw);

        /*
         * DHCPv4 client. Starting it is not itself convergence: nothing is
         * in the kernel until a lease lands, which link_apply_lease() applies
         * and only then marks CONFIGURED. An already-running client is left
         * alone, so a reload never throws away a working lease.
         */
        if (network_dhcp4_enabled(nw)) {
                if (!l->dhcp_client) {
                        r = link_start_dhcp_client(l);
                        if (r < 0) {
                                pico_log(PICO_LOG_WARNING,
                                         "netd: %s: failed to start DHCP client: %s",
                                         l->ifname,
                                         strerror(-r));
                                l->state = LINK_FAILED;
                                return r;
                        }
                }
                if (!l->lease)
                        converged = false;
        } else {
                /* DHCP= was removed by a reload: stop asking, and forget the
                 * lease so turning DHCP= back on does not route through it. */
                link_stop_dhcp_client(l);
                if (l->lease) {
                        (void) link_remove_lease_file(l);
                        l->lease = dhcp_lease_unref(l->lease);
                }
        }

        /*
         * DHCPv4 server. Unlike the client, starting it *is* full convergence
         * for this directive.
         */
        if (nw->dhcp_server) {
                if (!l->dhcp_server) {
                        r = link_start_dhcp_server(l, nw);
                        if (r < 0) {
                                pico_log(PICO_LOG_WARNING,
                                         "netd: %s: failed to start DHCP server: %s",
                                         l->ifname,
                                         strerror(-r));
                                l->state = LINK_FAILED;
                                return r;
                        }
                }
        } else if (l->dhcp_server)
                /* DHCPServer= was removed by a reload: stop serving. */
                link_stop_dhcp_server(l);

        link_sync_lldp(l, nw);

        l->state = converged ? LINK_CONFIGURED : LINK_CONFIGURING;

        /* Static DNS= may have just changed; not incremental, see
         * netd-resolv.h. */
        r = netd_resolv_write(n);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "netd: resolv.conf: %s", strerror(-r));

        return 0;
}

/*
 * Public entry point: run link_configure_impl(), then publish whatever state
 * it settled on in one place rather than at each of its returns. A failed
 * state file write never turns a configure success into a failure.
 */
int link_configure(Link *l) {
        int r = link_configure_impl(l);

        if (l) {
                int wr = link_write_state_file(l);

                if (wr < 0)
                        pico_log(PICO_LOG_WARNING, "netd: %s: state file: %s", l->ifname, strerror(-wr));
        }

        return r;
}

int link_reconfigure(Link *l) {
        if (!l)
                return -EINVAL;

        /*
         * link_configure() re-matches from scratch and converges
         * idempotently: an unchanged link takes the "already exactly right"
         * branch in apply_static_address()/apply_static_gateway() and is left
         * alone, so this is safe to call for every link on every reload.
         */
        return link_configure(l);
}

/* Deletes every recorded static address. A kernel that already dropped one
 * (link gone, IPv6 flushed on link down) is not an error. */
static int link_teardown_static_addresses(Link *l) {
        int ret = 0;

        for (size_t i = 0; i < l->n_addrs;) {
                int r = link_static_address_remove(l, &l->addrs[i], false);

                if (r < 0) {
                        if (ret == 0)
                                ret = r;
                        i++;
                }
        }

        return ret;
}

/* Deletes every recorded [Route] route. One the gateway slot also names stays
 * until the slot lets go. */
static int link_teardown_static_routes(Link *l) {
        int ret = 0;

        for (size_t i = 0; i < l->n_routes;) {
                int r = link_static_route_remove(l, &l->routes[i]);

                if (r < 0) {
                        if (ret == 0)
                                ret = r;
                        i++;
                }
        }

        return ret;
}

/* What a lease put in the kernel: the default route, the address and the
 * lease file. Static addresses and routes stay. */
static int link_teardown_lease_state(Link *l) {
        int r, ret = 0;

        if (l->gateway_configured) {
                r = link_gateway_remove(l);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: failed to remove route: %s",
                                 l->ifname,
                                 strerror(-r));
                        ret = r;
                }
        }

        if (l->address_configured) {
                r = link_address_del(l);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: failed to remove address: %s",
                                 l->ifname,
                                 strerror(-r));
                        if (ret == 0)
                                ret = r;
                }
        }

        if (l->lease) {
                (void) link_remove_lease_file(l);
                l->lease = dhcp_lease_unref(l->lease);
        }

        return ret;
}

/*
 * The kernel/lease-file half of teardown, shared by link_deconfigure() (which
 * also stops DHCP outright) and link_lose_lease() (which uses only the lease
 * half -- see that function's doc in netd-link.h for why the DHCP client is
 * not touched here). Never touches l->dhcp_client/l->dhcp_server.
 */
static int link_teardown_kernel_state(Link *l) {
        int r, ret = link_teardown_static_routes(l);

        r = link_teardown_static_addresses(l);
        if (!ret)
                ret = r;

        r = link_teardown_lease_state(l);
        return ret ? ret : r;
}

static void dhcp_client_unref_void(void *p) {
        (void) dhcp_client_unref(p);
}

static void dhcp_server_unref_void(void *p) {
        (void) dhcp_server_unref(p);
}

/*
 * Drop this link's reference to an already-stopped DHCP object -- through the
 * loop's post-batch queue, never inline. Both stop functions below can run
 * from inside an epoll callback (link_configure() off an RTM_NEWLINK,
 * link_free() off an RTM_DELLINK), and the object carries the netd_epoll_tag
 * that epoll_wait() may already have reported for a later event in the same
 * batch; freeing it here is exactly what netd_loop_defer_free() exists to
 * stop (see its comment in netd-loop.h).
 *
 * On -ENOMEM the reference is dropped on the floor: the object is stopped,
 * so it holds no fd, timer or epoll registration, and leaking that inert
 * memory beats handing the rest of the batch a freed tag.
 */
static void link_release_dhcp_object(Link *l, void *object, netd_free_func_t free_func, const char *what) {
        int r = netd_loop_defer_free(l->netd, object, free_func);

        if (r < 0)
                pico_log(PICO_LOG_WARNING,
                         "netd: %s: cannot queue the %s for release, leaking it: %s",
                         l->ifname,
                         what,
                         strerror(-r));
}

/* dhcp_client_stop() before the reference is dropped: the client's own doc
 * asks for that order (a running client refuses a second start otherwise, and
 * a stopped-but-still-refcounted client would leak its socket/timers if this
 * were the only reference). Safe to call from inside that same client's own
 * callback -- upstream's DHCP_CLIENT_DONT_DESTROY (carried, dhcp-client-
 * internal.h) keeps the object alive through the notify call that got us
 * here, and the client re-checks its own state afterwards. Idempotent: a
 * NULL l->dhcp_client is a no-op. */
static void link_stop_dhcp_client(Link *l) {
        DhcpClient *client = l->dhcp_client;

        if (!client)
                return;

        (void) dhcp_client_stop(client);

        /* stop() notifies, and a notify callback is allowed to re-enter here;
         * if one did, this link's reference is already queued. */
        if (l->dhcp_client != client)
                return;

        l->dhcp_client = NULL;
        link_release_dhcp_object(l, client, dhcp_client_unref_void, "DHCP client");
}

/* Same shape for the server side; see DHCP_SERVER_DONT_DESTROY in
 * dhcp-server-internal.h. */
static void link_stop_dhcp_server(Link *l) {
        DhcpServer *server = l->dhcp_server;

        if (!server)
                return;

        (void) dhcp_server_stop(server);

        if (l->dhcp_server != server)
                return;

        l->dhcp_server = NULL;
        link_release_dhcp_object(l, server, dhcp_server_unref_void, "DHCP server");
}

/* Sends the shutdown frame, then queues the object for release (see link_release_dhcp_object()). */
static void link_stop_lldp(Link *l) {
        LldpLink *lldp = l->lldp;

        if (!lldp)
                return;

        lldp_link_stop(lldp);
        l->lldp = NULL;
        link_release_dhcp_object(l, lldp, lldp_link_free_void, "LLDP state");
}

/* The management address is the lease's, else the first static IPv4 one. */
static void link_lldp_update_address(Link *l) {
        struct in_addr none = { 0 };

        if (!l->lldp)
                return;

        if (l->address_configured) {
                lldp_link_set_address(l->lldp, true, l->address);
                return;
        }

        for (size_t i = 0; i < l->n_addrs; i++)
                if (l->addrs[i].family == AF_INET && l->addrs[i].installed) {
                        lldp_link_set_address(l->lldp, true, l->addrs[i].address.in);
                        return;
                }

        lldp_link_set_address(l->lldp, false, none);
}

/*
 * Brings LLDP in line with LLDP=/EmitLLDP=. Only Ethernet-type links with a
 * 6 byte address can carry it. Failure is logged and leaves LLDP off on this
 * link; it never fails the link, which has nothing to do with its neighbours.
 */
static void link_sync_lldp(Link *l, const Network *nw) {
        LldpLinkConfig cfg = {
                .rx = nw->lldp != NETWORK_LLDP_NO,
                .routers_only = nw->lldp == NETWORK_LLDP_ROUTERS_ONLY,
                .tx = nw->emit_lldp != NETWORK_EMIT_LLDP_NO,
                .tx_scope = nw->emit_lldp == NETWORK_EMIT_LLDP_NO ? LLDP_SCOPE_NEAREST_BRIDGE :
                                                                    (LldpScope) (nw->emit_lldp - 1),
        };
        NetdId128 mid;
        bool have_mid;
        int r;

        if ((!cfg.rx && !cfg.tx) || (l->flags & IFF_LOOPBACK) || l->arp_type != ARPHRD_ETHER ||
            l->hw_addr_len != 6) {
                link_stop_lldp(l);
                return;
        }

        if (!l->lldp) {
                r = lldp_link_new(l->netd, l->ifindex, l->ifname, &l->lldp);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING, "netd: %s: LLDP: %s", l->ifname, strerror(-r));
                        return;
                }
        }

        have_mid = netd_machine_id(&mid) >= 0 && !id128_is_null(&mid);
        r = lldp_link_configure(l->lldp, &cfg, l->hw_addr, have_mid ? mid.bytes : NULL);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "netd: %s: LLDP: cannot start: %s", l->ifname, strerror(-r));
                link_stop_lldp(l);
                return;
        }

        link_lldp_update_address(l);
        lldp_link_set_carrier(l->lldp, (l->flags & (IFF_UP | IFF_RUNNING)) == (IFF_UP | IFF_RUNNING));
}

int link_deconfigure(Link *l) {
        if (!l)
                return -EINVAL;

        if (l->applying_lease) {
                pico_log(PICO_LOG_WARNING,
                         "netd: %s: refusing to deconfigure while a lease is being applied",
                         l->ifname);
                return -EBUSY;
        }

        link_stop_dhcp_client(l);
        link_stop_dhcp_server(l);
        link_stop_lldp(l);

        return link_teardown_kernel_state(l);
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

        r = lease_get_address_prefix(lease, &addr, &prefixlen);
        if (r < 0)
                goto fail;

        if (dhcp_lease_get_lifetime(lease, &lifetime) >= 0 && lifetime != USEC_INFINITY)
                lifetime_sec = (uint32_t) (lifetime / USEC_PER_SEC);

        /*
         * The three cases converge_address() distinguishes map directly onto
         * client_enter_bound()'s event choice (dhcp-client.c): RENEW is
         * case 1 (same address/mask), IP_CHANGE is case 2 or 3 depending on
         * whether the new address shares a subnet with the old one.
         * converge_address() decides from the addresses themselves, so the
         * event is not needed here.
         */
        r = converge_address(l, &addr, prefixlen, lifetime_sec, link_lease_route_metric(l));
        if (r < 0)
                goto fail;

        link_apply_lease_router(l, lease, addr, prefixlen);

        /* The lease's address may put a [Route] gateway in reach. */
        if (nw)
                (void) apply_static_routes(l, nw);

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
        link_lldp_update_address(l);
        (void) link_write_state_file(l);
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

        /* Reached from the DHCP client's own EXPIRED notification (see
         * dhcp_client_event_callback()); guarded exactly like
         * link_apply_lease() against being reached reentrantly for the same
         * link. link_teardown_kernel_state() below does not touch
         * l->dhcp_client -- see this function's doc in netd-link.h. */
        if (l->applying_lease)
                return -EBUSY;

        l->applying_lease = true;
        r = link_teardown_lease_state(l);

        /* The static addresses stayed; this settles any the lease's delete
         * cost, and puts Gateway= back. */
        if (l->network) {
                int rr = apply_static_addresses(l, l->network);

                if (rr < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: failed to apply Address=: %s",
                                 l->ifname,
                                 strerror(-rr));
                (void) apply_static_routes(l, l->network);
                rr = apply_static_gateway(l, l->network);
                if (rr < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "netd: %s: failed to apply Gateway=: %s",
                                 l->ifname,
                                 strerror(-rr));
        }

        l->state = LINK_CONFIGURING;
        l->applying_lease = false;
        link_lldp_update_address(l);
        (void) link_write_state_file(l);

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

/* --- link state files --- */

int link_write_state_file(Link *l) {
        Netd *n;
        char *path = NULL;
        char name[32];
        char tmp[PATH_MAX];
        FILE *f;
        int len, r;

        if (!l)
                return -EINVAL;

        n = l->netd;

        len = snprintf(name, sizeof(name), "%d", l->ifindex);
        if (len < 0 || (size_t) len >= sizeof(name))
                return -ENAMETOOLONG;

        r = netd_runtime_path(n, "links", name, true, &path);
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

        fprintf(f, "IFNAME=%s\n", l->ifname);
        fprintf(f, "STATE=%s\n", link_state_to_string(l->state));
        if (l->network && l->network->filename)
                fprintf(f, "NETWORK=%s\n", l->network->filename);

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

int link_remove_state_file(Link *l) {
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

        r = netd_runtime_path(n, "links", name, false, &path);
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
