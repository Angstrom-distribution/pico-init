/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The interface table and the per-link state machine.
 *
 * A Link is created when rtnetlink first reports an ifindex and destroyed
 * when it reports it gone -- never from configuration, and never in response
 * to an ordering dependency. That is the whole reason netd's unit has no
 * After=eudev.service: an interface appearing at any time (a usb gadget
 * binding, a module loading) is just another RTM_NEWLINK, and it gets matched
 * and configured whenever it shows up. It is also why a netd crash is cheap:
 * Restart=on-failure respawns it, it re-enumerates, re-reads
 * /run/netd/leases, and re-converges.
 *
 * This file also owns lease application, which is the point where the DHCP
 * implementation under src/netd/dhcp/ meets the rest of the daemon: address,
 * default route, /etc/resolv.conf, the lease state file, and the direct
 * function call into netd-sntp.c/netd-time.c that replaces upstream's entire
 * networkd -> state file -> inotify -> timesyncd -> D-Bus -> timedated relay.
 */

#pragma once

#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "netd-rtnl.h"

typedef struct Netd Netd;
typedef struct Link Link;
typedef struct Network Network;

/* full definitions under src/netd/dhcp/ */
typedef struct DhcpClient DhcpClient;
typedef struct DhcpServer DhcpServer;
typedef struct DhcpLease DhcpLease;
typedef struct LldpLink LldpLink;

/*
 * Per-link states. Coarser than networkd's two-axis
 * operational/administrative pair: netd has no status CLI for anyone to read
 * a finer distinction from, so the states that exist are the ones that change
 * behaviour.
 */
typedef enum LinkState {
        LINK_PENDING,     /* seen by netlink; not yet matched against .network files */
        LINK_UNMANAGED,   /* no .network matched, or [Match] excluded it: netd leaves it alone */
        LINK_CONFIGURING, /* matched; link set up, static config applied and/or DHCP running */
        LINK_CONFIGURED,  /* everything the .network asked for is in the kernel */
        LINK_FAILED,      /* a configuration step failed; retried on SIGHUP or a link event */
        _LINK_STATE_MAX,
} LinkState;

/*
 * One static address netd put into the kernel, with the fields it sent, so a
 * reload can tell "already correct" from "needs replacing" without reading
 * the kernel back. Leases do not use this table: the lease has its own slot
 * in Link.
 */
typedef struct LinkAddress {
        uint8_t family;
        uint8_t prefixlen;
        uint8_t scope;
        bool has_peer;
        bool installed;  /* false once the kernel is known to have dropped it (link down) */
        bool doomed;     /* during a converge pass: recorded but no longer wanted */
        bool dad_warned; /* the kernel's duplicate address detection failure was reported */
        uint32_t flags;  /* IFA_F_* */
        NetdInAddr address;
        NetdInAddr peer;
        uint32_t route_metric;
        uint32_t valid_sec;     /* UINT32_MAX forever; SLAAC: what was last sent */
        uint32_t preferred_sec; /* UINT32_MAX forever, 0 deprecated */
        uint64_t sent_at;       /* SLAAC: CLOCK_MONOTONIC usec of the last send */
        char label[IFNAMSIZ];
} LinkAddress;

/* More than a file can ask for, so a delete that keeps failing cannot let the
 * table grow without bound. */
#define LINK_ADDRS_MAX (2 * 16)

/*
 * One static route netd put into the kernel, or wants there: what a reload
 * compares and what a delete sends. Every field is part of the route's
 * identity. A route the kernel refused as unreachable stays in the table with
 * `installed` false, and is tried again whenever an address or a lease
 * changes.
 */
typedef struct LinkRoute {
        uint8_t family;
        uint8_t dst_len;
        uint8_t scope;
        bool has_gw;
        bool has_prefsrc;
        bool installed;   /* false while the kernel has not taken it, or has dropped it (link down) */
        bool warned;      /* the failed add was already reported */
        bool doomed;      /* during a converge pass: recorded but no longer wanted */
        uint8_t protocol; /* RTPROT_*; 0 is RTPROT_STATIC */
        uint8_t pref;     /* router advertisement routes: ICMPV6_ROUTER_PREF_* */
        /* RTPROT_* of the kernel route when the other table, [Route] or
         * router advertisements, put it in first; 0 when this entry did. */
        uint8_t kernel_protocol;
        uint32_t flags; /* RTNH_F_* */
        uint32_t metric;
        uint32_t expires_sec; /* router advertisement routes: what was last sent, UINT32_MAX none */
        uint64_t sent_at;     /* CLOCK_MONOTONIC usec of that send */
        NetdInAddr dst;
        NetdInAddr gw;
        NetdInAddr prefsrc;
} LinkRoute;

/* More than a file can ask for, as for LINK_ADDRS_MAX. */
#define LINK_ROUTES_MAX (2 * 16)

/* What router advertisements can put on a link: an address per prefix, a
 * default route per router and an on-link route per prefix (ndisc-link.h). */
#define LINK_RA_ADDRS_MAX 8
#define LINK_RA_ROUTES_MAX 12

typedef struct NdiscLink NdiscLink;

struct Link {
        Netd *netd; /* borrowed */

        /* --- identity, from rtnetlink --- */
        int ifindex;
        char ifname[IFNAMSIZ];
        unsigned int flags;
        uint16_t arp_type;
        uint32_t mtu;
        uint8_t hw_addr[NETD_HW_ADDR_MAX];
        size_t hw_addr_len;
        uint32_t num_tx_queues;

        /*
         * The root qdisc netd put on this link, empty when it did not: its kind
         * and the handle the kernel gave it. Only a root with this handle (or
         * the kernel's own default, handle 0) is replaced or removed by a
         * reload; any other one was set by something else and stays.
         * qdisc_implicit says it came from the multi-queue rule, not a section.
         */
        char qdisc[IFNAMSIZ];
        uint32_t qdisc_handle;
        bool qdisc_implicit;
        char qdisc_failed[IFNAMSIZ]; /* the kind whose last attempt failed, reported once until a reload */

        LinkState state;

        /*
         * The .network that matched, borrowed from netd->networks and
         * therefore invalidated by a reload. Every reload re-matches every
         * link before anything reads this again -- see the deferred-reload
         * note on Netd.reload_requested.
         */
        Network *network;

        /* --- DHCPv4, owned; NULL unless the .network asked for it --- */
        DhcpClient *dhcp_client;
        DhcpServer *dhcp_server;

        /*
         * The lease currently applied, owned. Distinct from whatever the
         * client is presently negotiating: on renewal the client acquires a
         * new lease and only replaces this one once it has been applied, so a
         * failed renewal never leaves the link with no lease at all.
         */
        DhcpLease *lease;

        /* LLDP receive/transmit, owned; NULL unless the .network asked for either. */
        LldpLink *lldp;

        /*
         * What netd actually put into the kernel, so teardown removes exactly
         * what it added and a reconfigure can tell "already correct" from
         * "needs replacing". Not re-read from the kernel: another process
         * adding an address is not netd's to remove.
         *
         * `addrs` is every static address, IPv4 and IPv6. The fields below
         * are the lease's address only, which lives beside them.
         */
        LinkAddress *addrs;
        size_t n_addrs;
        bool warned_no_ipv6;       /* IPv6 entries skipped on a kernel without IPv6, said once */
        bool warned_ipv6_disabled; /* IPv6 refusal said once, until an address is accepted */

        /*
         * Every route from a [Route] section, IPv4 and IPv6. The default
         * route below is separate and stays the one slot it was: a [Route]
         * with a gateway and no destination is an ordinary entry here, kept
         * beside a lease's default route and never replaced by it.
         */
        LinkRoute *routes;
        size_t n_routes;
        bool warned_no_ipv6_routes;

        /* The kernel's IPv6 link-local address once duplicate address
         * detection has passed on it, followed through address events. */
        NetdInAddr ipv6ll;
        bool ipv6ll_ready;

        /*
         * IPv6 router advertisements, owned; NULL unless IPv6AcceptRA= is in
         * effect. What they put in the kernel is recorded beside the static
         * tables, with the same rule: only what is recorded is deleted.
         */
        NdiscLink *ndisc;
        LinkAddress *ra_addrs;
        size_t n_ra_addrs;
        LinkRoute *ra_routes;
        size_t n_ra_routes;
        uint64_t ra_dns_sig; /* of the servers and domains last written to resolv.conf */
        uint32_t ra_mtu;     /* the MTU last written for IPv6 */
        int ra_secret_state; /* 0 not read yet, 1 ra_secret holds the RFC 7217 secret, -1 none */
        uint8_t ra_secret[16];
        bool ra_accept_ra_done; /* accept_ra=0 written, or the failure reported */
        bool ra_warned_token;   /* a token that cannot be made on this link was reported */

        struct in_addr address;
        unsigned char prefixlen;
        bool address_configured;
        /* The prefix route's metric (IFA_RT_PRIORITY): the lease's RouteMetric=.
         * A reload compares it to move the prefix route. */
        uint32_t address_metric;

        struct in_addr gateway;
        bool gateway_configured;
        /* A /32 link-scope route to `gateway` was added because it lies
         * outside the leased subnet; removed together with the default
         * route. */
        bool gateway_host_route;
        /* The default route came from a lease, so a lease without a router
         * takes it away again; a static Gateway= is never removed that way. */
        bool gateway_from_lease;
        /* The metric both routes were added at. Stored, not recomputed: a
         * delete must use the add's metric, and after a reload the Network
         * that chose it is gone and RouteMetric= may have changed. */
        uint32_t gateway_metric;

        /*
         * Reentrancy guard. Set for the duration of link_apply_lease(), which
         * upstream's own history warns is reachable from inside a DHCP
         * client/server callback still on the call stack (sd-dhcp-server.c
         * has no DONT_DESTROY guard around its callbacks the way
         * sd-dhcp-client.c does). link_apply_lease() never itself calls
         * link_configure()/link_reconfigure()/link_deconfigure(), so the
         * current call graph cannot re-enter through this flag. It turns a
         * future mistake into a logged -EBUSY instead of a use-after-free:
         * link_configure() and link_deconfigure() both refuse to run while it
         * is set, rather than mutate or free state a still-running callback
         * may depend on.
         */
        bool applying_lease;
};

/* --- netd-link.c --- */

/* Create a Link from an rtnetlink snapshot and append it to n->links
 * (ownership transfers to the Netd). 0 or -errno. */
int link_new(Netd *n, const NetdRtnlLink *rl, Link **ret);

/* Remove every configured address/route, stop DHCP, drop the lease file,
 * detach from n->links, free. Returns NULL. */
Link *link_free(Link *l);

Link *netd_find_link(Netd *n, int ifindex);
Link *netd_find_link_by_name(Netd *n, const char *ifname);

/*
 * The netd_rtnl_link_handler_t installed by netd_startup(). ADDED creates and
 * configures, CHANGED updates the cached flags and re-evaluates, REMOVED
 * frees. Registered as a handler rather than called directly so the
 * enumeration dump and the live event stream go down exactly the same path --
 * a link that existed at startup and one that appeared a second later must
 * not be able to behave differently.
 */
int netd_link_rtnl_handler(void *userdata, NetdRtnlLinkEvent event, const NetdRtnlLink *rl);

/*
 * The netd_rtnl_addr_handler_t installed by netd_startup(): follows the
 * link-local address of each link and reports a static IPv6 address whose
 * duplicate address detection failed. Writes nothing to the kernel while a
 * dump is in progress.
 */
int netd_link_rtnl_addr_handler(void *userdata, bool removed, const NetdRtnlAddr *a);

/*
 * Match `l` against the current .network set and apply it: bring the link up,
 * add the static addresses and any Gateway=, arm the DHCPv4 client when DHCP= says so,
 * start the DHCPv4 server when DHCPServer=yes.
 *
 * Idempotent: it is called on the
 * initial event, on every subsequent link change, and once per link on
 * SIGHUP, and each of those may find the link already exactly right.
 *
 * 0 or -errno; on failure the link goes to LINK_FAILED and the daemon keeps
 * running.
 */
int link_configure(Link *l);

/*
 * The SIGHUP path for one link: drop what netd configured, re-match against
 * the reloaded .network set, and configure again. A link whose match did not
 * change and whose configuration is unchanged is left strictly alone --
 * reloading must not bounce a working interface.
 *
 * 0 or -errno.
 */
int link_reconfigure(Link *l);

/*
 * Remove everything netd put in the kernel for this link (address, route,
 * lease file), and stop and drop l->dhcp_client/l->dhcp_server if either is
 * running -- unlike link_lose_lease() below, which tears down only the
 * kernel state a lease put there and leaves the client running (it restarts
 * its own DISCOVER cycle internally; see that function's doc). This is the
 * "DHCP is no longer wanted on this link at all" path: the link losing its
 * .network match, the link disappearing, or a reload dropping DHCP=/
 * DHCPServer=. Without freeing the Link. 0 or -errno.
 */
int link_deconfigure(Link *l);

/*
 * The root qdisc kind a link matching `nw` should have, or NULL for leaving
 * what the kernel gave it. An explicit [FairQueueingControlledDelay],
 * [FairQueueing] or [CAKE] section with Parent=root decides, on any link.
 * Without one, `default_qdisc` (what netd wrote to net.core.default_qdisc;
 * empty or NULL for none) is chosen only for a link with more than one tx
 * queue whose root is the kernel's mq (`root_kind` "mq", `root_handle` 0): mq
 * applies the default to its per-queue children only. A device flagged
 * IFF_NO_QUEUE (veth, bonds, mac80211 Wi-Fi) has noqueue as its root whatever
 * its queue count and keeps it, as does a link with a single tx queue or an
 * unknown count (0) or a root that something else installed.
 */
const char *link_qdisc_choose(
                const Network *nw,
                uint32_t num_tx_queues,
                const char *root_kind,
                uint32_t root_handle,
                const char *default_qdisc);

/* --- lease application --- */

/*
 * Take ownership of `lease` and put it into effect: address (with the lease
 * time as the kernel address lifetime), default route from option 3,
 * /etc/resolv.conf from option 6 when UseDNS=, the lease state file, and --
 * when UseNTP=/UseTimezone= allow it -- option 42's NTP servers and option
 * 101's timezone handed to netd-sntp.c and netd-time.c by direct call.
 *
 * The lease's address is added beside the static ones, as networkd does;
 * one that a static entry also names is left as the static entry set it. Its
 * default route is added beside any [Route] default route, and a [Route]
 * whose gateway the new address puts in reach is installed then.
 *
 * Address application is three cases, not one, chosen from the addresses
 * themselves (netd-link.c's converge_address()) rather than from the
 * DhcpClientEvent -- the two give the same answer, and the addresses are the
 * ground truth the kernel actually cares about:
 *
 *   1. RENEW, i.e. the *same* address/prefix as already configured (the
 *      common case: T1/T2 firing with nothing else changed) -- a single
 *      in-place NLM_F_REPLACE (lifetime refresh only), never a delete, so
 *      never a window with no address on the interface.
 *   2. IP_CHANGE within the *same* subnet (a rebind handing out a different
 *      host address in the same /24, say) -- delete the old address before
 *      adding the new one. Adding first would make the new address
 *      "secondary" to the old one (both cover the same connected route), and
 *      the kernel cascades a primary-address delete into deleting every
 *      secondary in that subnet too (net.ipv4.conf.*.promote_secondaries
 *      defaults to 0). Add-then-remove would lose both addresses at once
 *      instead of leaving a brief gap.
 *   3. IP_CHANGE to a *different* subnet -- add the new address before
 *      removing the old one, safely: the two addresses never share a
 *      connected route, so there is no secondary/cascade risk.
 *
 * 0 or -errno.
 */
int link_apply_lease(Link *l, DhcpLease *lease);

/*
 * Lease expired, was NAKed, or was DECLINEd: remove what it configured
 * (address, route, lease file), put back a static Gateway=, settle the
 * [Route] routes the address had made reachable, and go
 * back to LINK_CONFIGURING -- but leave
 * l->dhcp_client running. The client is not netd-link.c's to restart: it
 * already returns itself to INIT and restarts its own DISCOVER cycle
 * internally after notifying this event (dhcp-client.c's
 * client_restart_full()/client_timeout_expire()), so the client needs
 * nothing from here. Unrelated to
 * link_deconfigure(), which is the "stop DHCP outright" path. 0 or -errno.
 */
int link_lose_lease(Link *l);

/* --- lease state files --- */

/*
 * /run/netd/leases/<ifindex>, netd's own trivial documented text format --
 * not networkd's, which upstream marks "do not parse".
 *
 * Written atomically (tmp + rename), one KEY=VALUE per line, keys stable:
 * ADDRESS, PREFIXLEN, ROUTER, DNS, NTP, TIMEZONE, LIFETIME, T1, T2. Absent
 * options are absent lines, never empty values -- a consumer testing for a
 * key must not have to also test for emptiness.
 */
int link_write_lease_file(Link *l);
int link_remove_lease_file(Link *l);

/* --- link state files --- */

/*
 * /run/netd/links/<ifindex>, same trivial documented text format and the
 * same write-atomically discipline as the lease files above, but written
 * for every link regardless of whether it ever gets a lease: a LINK_PENDING
 * or LINK_UNMANAGED link never has one. Keys: IFNAME, STATE (one of
 * link_state_to_string()'s own strings), and NETWORK (the matched .network
 * file's path, omitted when l->network is NULL).
 *
 * Lets networkctl (netctl.c) report setup state and the matched config file
 * without any IPC to netd.
 */
int link_write_state_file(Link *l);
int link_remove_state_file(Link *l);

const char *link_state_to_string(LinkState s);

/* --- persistent MAC derivation ---
 *
 * The pure half of link_apply_persistent_mac() (netd-link.c): no I/O, no
 * gating, just real systemd-networkd's MACAddressPolicy=persistent algorithm
 * (netif-util.c's net_get_unique_predictable_data_from_name() plus
 * link-config.c's own bit fixup) for `machine_id`/`ifname`. `machine_id` is
 * the raw 16 bytes (NetdId128.bytes, netd-compat.h) -- taken as a plain
 * array rather than that type so this header does not pull netd-compat.h's
 * assert()/log_*() redefinitions into every translation unit that includes
 * it. Exposed only so test-netd-mac.c can check it against fixed vectors;
 * real callers reach it through link_configure_impl(). Writes exactly
 * NETD_HW_ADDR_MAX bytes to `mac_out`.
 */
void netd_persistent_mac_derive(
                const uint8_t machine_id[16], const char *ifname, uint8_t mac_out[NETD_HW_ADDR_MAX]);
