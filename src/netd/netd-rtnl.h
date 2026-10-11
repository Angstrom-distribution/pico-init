/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The hand-rolled rtnetlink layer.
 *
 * sd-netlink is not lifted: a minimal rtnl-only
 * subset is ~6,500 LOC whose src/basic dependency closure adds ~22,000 more,
 * of which netd would exercise ~20 of 145 public functions -- and two
 * structural facts make trimming it impractical anyway. Its attribute type
 * system is unavoidable (every append/read goes through a policy table;
 * there is no raw-TLV mode), and there is no public sd_netlink_get_fd(), so
 * driving it from netd's own epoll loop already means forking private
 * internals. This file is new code, using kernel UAPI structs and macros
 * directly, with netlink-message-rtnl.c read only as a design reference for
 * its worked-out NLM_F flag choices -- no code copied, hence GPL-2.0-or-later
 * like the rest of netd's own source.
 *
 * The whole operation set is below and it is short by design: enumerate and
 * match links, subscribe to RTM_NEWLINK/RTM_DELLINK, bring a link up, add an
 * address, add a route including the default route. Nothing else. Everything
 * networkd's netlink surface additionally covers -- tunnels, bonding, bridge
 * and VLAN attributes, MACsec, WireGuard, tc, policy routing -- is out of
 * scope, and it was most of that type table.
 *
 * TWO SOCKETS. `event_fd` is subscribed to RTNLGRP_LINK and is
 * the only one epoll ever sees; the request socket is private and every
 * operation on it is a synchronous request -> ACK exchange. One socket would
 * work too, but then every synchronous request would have to buffer the
 * unsolicited multicast messages that arrive while it waits for its own ACK,
 * and get that right under every interleaving. Two sockets makes each half
 * trivially correct, at the cost of one extra fd.
 *
 * Both sockets set NETLINK_EXT_ACK, so a rejected request comes back with the
 * kernel's own explanation: rtnetlink's bare -EINVAL is otherwise
 * indistinguishable between a dozen different malformed-attribute mistakes.
 *
 * The low-level socket/message plumbing (request construction, send/recv,
 * NLMSG_ERROR decoding, generic attribute getters) lives in
 * netd-rtnl-core.c/.h, shared with netctl-rtnl.c -- this header and
 * netd-rtnl.c keep only netd's own policy: the link table, event dispatch,
 * and the idempotent writers below.
 */

#pragma once

#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct NetdRtnl NetdRtnl;

/* The maximum hardware address netd stores. 6 covers ether and the CDC-Subset
 * gadget; InfiniBand's 20 is not supported. */
#define NETD_HW_ADDR_MAX 6

/*
 * One interface, as rtnetlink describes it. This is a snapshot decoded out of
 * an RTM_NEWLINK message, not a live view: Link (netd-link.h) keeps the
 * authoritative copy and updates it from each event.
 */
typedef struct NetdRtnlLink {
        int ifindex;
        char ifname[IFNAMSIZ];

        unsigned int flags; /* IFF_UP, IFF_RUNNING, IFF_LOOPBACK, ... */
        uint16_t arp_type;  /* ARPHRD_ETHER, ARPHRD_LOOPBACK, ... */
        uint32_t mtu;

        uint8_t hw_addr[NETD_HW_ADDR_MAX];
        size_t hw_addr_len; /* 0 when the link has no hardware address */
} NetdRtnlLink;

typedef enum NetdRtnlLinkEvent {
        NETD_RTNL_LINK_ADDED,   /* RTM_NEWLINK for an ifindex not seen before */
        NETD_RTNL_LINK_CHANGED, /* RTM_NEWLINK for one already known */
        NETD_RTNL_LINK_REMOVED, /* RTM_DELLINK */
        _NETD_RTNL_LINK_EVENT_MAX,
} NetdRtnlLinkEvent;

/*
 * Delivered for every link event and for every entry of an enumeration dump
 * (as ADDED). Returning negative logs; it does not abort the dump, because
 * one interface netd cannot configure must not prevent it from seeing the
 * rest.
 *
 * ADDED vs CHANGED is decided by this layer against the set of ifindexes it
 * has already reported, not by the caller: the kernel says RTM_NEWLINK for
 * both, and every caller would otherwise reimplement the same bookkeeping.
 */
typedef int (*netd_rtnl_link_handler_t)(void *userdata, NetdRtnlLinkEvent event, const NetdRtnlLink *link);

/* --- lifecycle --- */

/*
 * Open both sockets, set NETLINK_EXT_ACK and a receive buffer large enough
 * for a link dump, bind the event socket to RTNLGRP_LINK. 0 or -errno.
 *
 * Note what this does *not* do: it does not enumerate. Subscription happens
 * here and enumeration is a separate call, so netd_startup() can order them
 * correctly -- subscribe first, then dump. The other order loses any
 * interface that appears in between, and on a usb gadget that window is
 * exactly when the interface appears.
 */
int netd_rtnl_new(NetdRtnl **ret);

NetdRtnl *netd_rtnl_free(NetdRtnl *rtnl); /* returns NULL */

/* The subscribed socket, for registration in netd's epoll. The request socket
 * is not exposed: nothing should poll it. */
int netd_rtnl_event_fd(NetdRtnl *rtnl);

/* Install the link event/enumeration handler. */
void netd_rtnl_set_link_handler(NetdRtnl *rtnl, netd_rtnl_link_handler_t handler, void *userdata);

/* --- reading --- */

/*
 * RTM_GETLINK with NLM_F_REQUEST|NLM_F_DUMP, reading the multi-part reply to
 * completion (every NLM_F_MULTI part until NLMSG_DONE) and delivering each
 * link through the handler as ADDED. Returns the number of links seen, or
 * -errno.
 *
 * Synchronous, on the request socket. A dump of a busy machine can exceed the
 * socket buffer and come back with ENOBUFS/NLM_F_DUMP_INTR -- and a single
 * dump entry that exceeds nl_recv()'s fixed receive buffer surfaces the same
 * way -- either is retried rather than reported, because a partially-observed
 * link table is worse than a slow one.
 */
int netd_rtnl_enumerate_links(NetdRtnl *rtnl);

/*
 * Call on event_fd epoll readiness: drain everything pending and dispatch
 * each RTM_NEWLINK/RTM_DELLINK through the handler. Returns the number
 * dispatched, or -errno.
 *
 * A multicast socket that overruns returns ENOBUFS and the kernel has thrown
 * messages away -- as does a single event datagram bigger than nl_recv()'s
 * fixed receive buffer, already discarded by the time that's detected. Either
 * is unrecoverable by reading harder, so this reports it to the caller, which
 * re-enumerates -- the only way to get back to a correct link table.
 */
int netd_rtnl_process(NetdRtnl *rtnl);

/* --- writing --- */
/*
 * Each of these is a synchronous request -> ACK on the private socket:
 * returns 0 once the kernel has acknowledged, or -errno decoded from the
 * NLMSG_ERROR reply (with any NLMSGERR_ATTR_MSG extended-ACK string logged).
 * -EEXIST from an address or route that is already exactly as requested is
 * translated to success by the callers in netd-link.c, not here -- this layer
 * reports what the kernel said.
 */

/* RTM_SETLINK with IFF_UP in ifi_flags/ifi_change. Idempotent. */
int netd_rtnl_link_up(NetdRtnl *rtnl, int ifindex);
int netd_rtnl_link_down(NetdRtnl *rtnl, int ifindex);

/*
 * RTM_SETLINK carrying only IFLA_ADDRESS -- ifi_flags/ifi_change are left at
 * 0, so this never brings a link up or down, only changes its hardware
 * address. `addr`/`len` are copied into IFLA_ADDRESS as given; the caller
 * (netd-link.c's link_apply_persistent_mac()) is responsible for the link
 * being administratively down first, which the kernel otherwise refuses a
 * MAC change against. 0 or -errno.
 */
int netd_rtnl_link_set_hwaddr(NetdRtnl *rtnl, int ifindex, const uint8_t *addr, size_t len);

/*
 * RTM_NEWADDR, NLM_F_REQUEST|NLM_F_CREATE|NLM_F_REPLACE|NLM_F_ACK.
 *
 * IFA_LOCAL and IFA_ADDRESS are both set to `address` (they differ only for
 * point-to-point links, which no pico target has), and IFA_BROADCAST is
 * derived from the prefix unless `broadcast` is non-NULL. Omitting the
 * broadcast address is a real bug on the DHCP path: the client's own
 * broadcast socket then never sees the server's renewal replies.
 *
 * `lifetime_sec` is the DHCP lease time, passed through as IFA_CACHEINFO so
 * the kernel expires the address if netd dies before the lease does;
 * UINT32_MAX means forever, which is what a static Address= gets.
 */
int netd_rtnl_address_add(
                NetdRtnl *rtnl,
                int ifindex,
                const struct in_addr *address,
                unsigned char prefixlen,
                const struct in_addr *broadcast,
                uint32_t lifetime_sec);

int netd_rtnl_address_del(NetdRtnl *rtnl, int ifindex, const struct in_addr *address, unsigned char prefixlen);

/*
 * RTM_NEWROUTE, RTN_UNICAST / RT_TABLE_MAIN / RT_SCOPE_UNIVERSE (or LINK when
 * there is no gateway), NLM_F_REQUEST|NLM_F_CREATE|NLM_F_REPLACE|NLM_F_ACK.
 *
 * `destination` NULL with prefixlen 0 is the default route, which is the case
 * that actually matters and which netd_rtnl_route_add_default() exists to
 * make unmistakable at the call site. `gateway` NULL means an on-link route.
 * `metric` goes into RTA_PRIORITY, which is part of what the kernel matches a
 * route by (table+prefix+priority) -- and NLM_F_REPLACE means two default
 * routes offered at the same metric are one route that the second add
 * overwrites, not two. So coexistence is the caller's to arrange, not
 * something this call provides: a distinct metric per interface makes two
 * default routes genuinely distinct routes, individually replaceable and
 * individually deletable, with the kernel preferring the lowest metric. That
 * is exactly what netd-link.c's link_route_metric() derives from the ifindex;
 * a caller reusing one metric across interfaces gets silent replacement.
 */
int netd_rtnl_route_add(
                NetdRtnl *rtnl,
                int ifindex,
                const struct in_addr *destination,
                unsigned char prefixlen,
                const struct in_addr *gateway,
                uint32_t metric);

int netd_rtnl_route_add_default(NetdRtnl *rtnl, int ifindex, const struct in_addr *gateway, uint32_t metric);

int netd_rtnl_route_del(
                NetdRtnl *rtnl,
                int ifindex,
                const struct in_addr *destination,
                unsigned char prefixlen,
                const struct in_addr *gateway,
                uint32_t metric);

const char *netd_rtnl_link_event_to_string(NetdRtnlLinkEvent e);
