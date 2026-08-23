/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The interface table and the per-link state machine. See netd-link.h.
 *
 * N1+N2+N3: table operations, .network matching, the per-link state
 * machine, static Address=/Gateway= application, and now the real DHCPv4
 * client and server (dhcp-client-internal.h / dhcp-server-internal.h, both
 * landed) are wired in. link_apply_lease()/link_write_lease_file() were
 * already implemented against the real DhcpLease accessor API at N1, so N2's
 * client had somewhere real to hand a lease the moment it existed.
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
#include "dhcp/dhcp-client-internal.h"
#include "dhcp/dhcp-lease-internal.h"
#include "dhcp/dhcp-server-internal.h"
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
 *      into deleting the new (secondary) one too -- reproduced directly
 *      against this kernel while building N1's own end-to-end test.
 *   3. a genuine change to a DIFFERENT subnet -- add first, safely, for the
 *      shortest possible address-less window; the two addresses never share
 *      a connected route, so there is no secondary/cascade risk.
 *
 * `lifetime_sec` is UINT32_MAX for a static Address=, the lease time for a
 * DHCP one. Used by both apply_static_address() and link_apply_lease() so
 * the same kernel hazard is fixed in exactly one place.
 */
static int converge_address(Link *l, const struct in_addr *want, unsigned char want_pfx, uint32_t lifetime_sec) {
        Netd *n = l->netd;
        int r;

        if (l->address_configured && l->address.s_addr == want->s_addr && l->prefixlen == want_pfx) {
                r = address_add_idempotent(n->rtnl, l->ifindex, want, want_pfx, lifetime_sec);
                if (r < 0)
                        return r;
        } else if (l->address_configured && same_subnet(l->address, l->prefixlen, *want, want_pfx)) {
                r = address_del_idempotent(n->rtnl, l->ifindex, &l->address, l->prefixlen);
                if (r < 0)
                        return r;
                l->address_configured = false;

                r = address_add_idempotent(n->rtnl, l->ifindex, want, want_pfx, lifetime_sec);
                if (r < 0)
                        return r;
        } else {
                r = address_add_idempotent(n->rtnl, l->ifindex, want, want_pfx, lifetime_sec);
                if (r < 0)
                        return r;

                if (l->address_configured)
                        (void) address_del_idempotent(n->rtnl, l->ifindex, &l->address, l->prefixlen);
        }

        l->address = *want;
        l->prefixlen = want_pfx;
        l->address_configured = true;
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

        return converge_address(l, &want->address, want->prefixlen, UINT32_MAX);
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

/* Defined near link_deconfigure() below; forward-declared here so
 * link_configure() can call them without reordering the file around the
 * teardown helpers they share with link_deconfigure() itself. */
static void link_stop_dhcp_client(Link *l);
static void link_stop_dhcp_server(Link *l);

/* --- DHCPv4 client --- */

/*
 * Read ADDRESS= back out of this link's own lease file (netd-link.h's
 * KEY=VALUE format), for dhcp_client_set_request_address() below --
 * RFC 2131 4.4.2's INIT-REBOOT, and the whole reason a netd crash is cheap
 * (plan §2.7): a restarted netd reconfirms the lease it already had instead
 * of renumbering the interface. 0 with *ret filled, or -errno (ENOENT on a
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
 * call, exactly the design the plan (§2.6) and this milestone's own header
 * comments describe. EXPIRED (NAK, expiry, or after a DECLINE) hands off to
 * link_lose_lease(), which deliberately does *not* touch the client -- see
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
 * Create, configure and start a DHCPv4 client for `l`. Idempotent by
 * construction from the caller's side only (link_configure() never calls
 * this when l->dhcp_client is already set); this function itself always
 * builds a fresh client. 0 or -errno.
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
 * .network's own Address= (plan §2.7's usb0-gadget scenario: the host's own
 * static address on usb0 doubles as the server's address and default
 * router). 0 or -errno.
 */
static int link_start_dhcp_server(Link *l, const Network *nw) {
        Netd *n = l->netd;
        DhcpServer *server = NULL;
        struct in_addr address;
        unsigned char prefixlen;
        int r;

        if (nw->n_addresses == 0) {
                pico_log(PICO_LOG_WARNING,
                         "netd: %s: DHCPServer=yes but no Address= to derive the pool from",
                         l->ifname);
                return -EINVAL;
        }

        address = nw->addresses[0].address;
        prefixlen = nw->addresses[0].prefixlen;

        r = dhcp_server_new(n, l->ifindex, l->ifname, &server);
        if (r < 0)
                return r;

        /*
         * offset 0 / size 0 both mean "default" to dhcp_server_configure_
         * pool() (dhcp-server.c): skip the subnet address, fill the rest of
         * the subnet up to (not including) the broadcast address. The
         * server's own address is excluded automatically wherever it falls
         * in that range (dhcp_server_address_available()/_is_in_pool()), so
         * no separate carve-out is needed here.
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
         * DHCPv4 client. Starting it is not itself convergence: nothing the
         * .network asked for is in the kernel until a lease actually lands,
         * which link_apply_lease() applies and only then marks CONFIGURED.
         * Idempotent by construction -- an already-running client (the
         * common SIGHUP case: DHCP= was already armed and has a lease) is
         * left alone rather than restarted, so a reload never throws away a
         * working lease to ask for a fresh DISCOVER.
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
        } else if (l->dhcp_client)
                /* DHCP= was removed by a reload: stop asking. */
                link_stop_dhcp_client(l);

        /*
         * DHCPv4 server. Unlike the client, starting it successfully *is*
         * full convergence for this directive -- there is no lease to wait
         * for on the server's own side of the link.
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

/*
 * The kernel/lease-file half of teardown, shared by link_deconfigure() (which
 * also stops DHCP outright) and link_lose_lease() (which does not -- see
 * that function's doc in netd-link.h for why the DHCP client is not touched
 * here). Never touches l->dhcp_client/l->dhcp_server.
 */
static int link_teardown_kernel_state(Link *l) {
        Netd *n = l->netd;
        int r, ret = 0;

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

/* dhcp_client_stop() before dhcp_client_unref(): the client's own doc asks
 * for that order (a running client refuses a second start otherwise, and a
 * stopped-but-still-refcounted client would leak its socket/timers if this
 * were the only reference). Safe to call from inside that same client's own
 * callback -- upstream's DHCP_CLIENT_DONT_DESTROY (carried, dhcp-client-
 * internal.h) keeps the object alive through the notify call that got us
 * here, and the client re-checks its own state afterwards. Idempotent: a
 * NULL l->dhcp_client is a no-op. */
static void link_stop_dhcp_client(Link *l) {
        if (!l->dhcp_client)
                return;

        (void) dhcp_client_stop(l->dhcp_client);
        l->dhcp_client = dhcp_client_unref(l->dhcp_client);
}

/* Same shape for the server side; DHCP_SERVER_DONT_DESTROY (dhcp-server-
 * internal.h) is this milestone's own addition to a defect upstream never
 * fixed -- see that header's comment. */
static void link_stop_dhcp_server(Link *l) {
        if (!l->dhcp_server)
                return;

        (void) dhcp_server_stop(l->dhcp_server);
        l->dhcp_server = dhcp_server_unref(l->dhcp_server);
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
         * The three cases converge_address() distinguishes map directly onto
         * client_enter_bound()'s own event choice (dhcp-client.c): RENEW is
         * exactly case 1 (same address/mask -- a REPLACE-only refresh),
         * IP_CHANGE is case 2 or 3 depending on whether the new address
         * shares a subnet with the one being replaced. converge_address()
         * decides from the addresses themselves rather than the event
         * netd-link.c is not even passed here, which gives the same answer
         * for both a live client event and a static reload.
         */
        r = converge_address(l, &addr, prefixlen, lifetime_sec);
        if (r < 0)
                goto fail;

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

        /* Reached from the DHCP client's own EXPIRED notification (see
         * dhcp_client_event_callback()); guarded exactly like
         * link_apply_lease() against being reached reentrantly for the same
         * link. link_teardown_kernel_state() below deliberately does not
         * touch l->dhcp_client -- see this function's doc in netd-link.h. */
        if (l->applying_lease)
                return -EBUSY;

        l->applying_lease = true;
        r = link_teardown_kernel_state(l);
        l->state = LINK_CONFIGURING;
        l->applying_lease = false;

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
