/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The interface table and the per-link state machine (plan §2.4, §2.5).
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
 * networkd -> state file -> inotify -> timesyncd -> D-Bus -> timedated relay
 * (§2.6).
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

/*
 * Per-link states. Deliberately coarser than networkd's two-axis
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

struct Link {
        Netd *netd; /* borrowed */

        /* --- identity, from rtnetlink --- */
        int ifindex;
        char ifname[IFNAMSIZ];
        unsigned int flags;
        uint16_t arp_type;
        uint8_t hw_addr[NETD_HW_ADDR_MAX];
        size_t hw_addr_len;

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

        /*
         * What netd actually put into the kernel, so teardown removes exactly
         * what it added and a reconfigure can tell "already correct" from
         * "needs replacing". Not re-read from the kernel: another process
         * adding an address is not netd's to remove.
         */
        struct in_addr address;
        unsigned char prefixlen;
        bool address_configured;

        struct in_addr gateway;
        bool gateway_configured;

        /*
         * Reentrancy guard. Set for the duration of link_apply_lease(), which
         * upstream's own history warns is reachable from inside a DHCP
         * client/server callback still on the call stack (sd-dhcp-server.c
         * has no DONT_DESTROY guard around its callbacks the way
         * sd-dhcp-client.c does -- plan §2.2's history-review finding).
         * link_apply_lease() never itself calls link_configure()/
         * link_reconfigure()/link_deconfigure() -- only address/route/
         * resolv.conf/lease-file/time state -- so today's call graph cannot
         * actually re-enter through this flag. It exists so a future mistake
         * (a DHCP callback calling into the reconfigure path directly, or
         * link_apply_lease growing such a call) becomes a logged -EBUSY
         * instead of a use-after-free: link_configure() and
         * link_deconfigure() both refuse to run while this is set, rather
         * than mutate or free kernel/lease state a still-running callback may
         * depend on. See the report on this milestone for the full reasoning.
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
 * Match `l` against the current .network set and apply it: bring the link up,
 * add any static Address=/Gateway=, arm the DHCPv4 client when DHCP= says so,
 * start the DHCPv4 server when DHCPServer=yes.
 *
 * Idempotent, and that is load-bearing rather than tidy: it is called on the
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
 * reloading must not bounce a working interface, which is the failure mode
 * `networkctl reconfigure` is famous for.
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

/* --- lease application --- */

/*
 * Take ownership of `lease` and put it into effect: address (with the lease
 * time as the kernel address lifetime), default route from option 3,
 * /etc/resolv.conf from option 6 when UseDNS=, the lease state file, and --
 * when UseNTP=/UseTimezone= allow it -- option 42's NTP servers and option
 * 101's timezone handed to netd-sntp.c and netd-time.c by direct call.
 *
 * Address application is three cases, not one, chosen from the addresses
 * themselves (netd-link.c's converge_address(), shared with static Address=
 * reconfiguration) rather than from the DhcpClientEvent -- the two give the
 * same answer, and the addresses are the ground truth the kernel actually
 * cares about:
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
 *      defaults to 0) -- reproduced directly while building N1's own
 *      end-to-end test. Add-then-remove here would silently lose both
 *      addresses at once instead of leaving a brief gap.
 *   3. IP_CHANGE to a *different* subnet -- add the new address before
 *      removing the old one, safely: the two addresses never share a
 *      connected route, so there is no secondary/cascade risk, and this is
 *      the case an "atomic renewal" description was actually written for.
 *
 * 0 or -errno.
 */
int link_apply_lease(Link *l, DhcpLease *lease);

/*
 * Lease expired, was NAKed, or was DECLINEd: remove what it configured
 * (address, route, lease file) and go back to LINK_CONFIGURING -- but leave
 * l->dhcp_client running. The client is not netd-link.c's to restart: it
 * already returns itself to INIT and restarts its own DISCOVER cycle
 * internally after notifying this event (dhcp-client.c's
 * client_restart_full()/client_timeout_expire()), so there is nothing here
 * to do beyond clearing the state this lease put in the kernel. Unrelated to
 * link_deconfigure(), which is the "stop DHCP outright" path. 0 or -errno.
 */
int link_lose_lease(Link *l);

/* --- lease state files --- */

/*
 * /run/netd/leases/<ifindex>, netd's own trivial documented text format --
 * not networkd's, which upstream marks "do not parse" and which
 * usb-multi-gadget-dhcp-fallback.sh currently probes anyway (§2.5, §2.7).
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
 * Exists for networkctl (netctl.c, netd's own client) to report real setup
 * state and the matched config file without any IPC to netd -- see that
 * file's own header for why it reads kernel/netd state directly rather than
 * inventing an IPC protocol.
 */
int link_write_state_file(Link *l);
int link_remove_state_file(Link *l);

const char *link_state_to_string(LinkState s);
