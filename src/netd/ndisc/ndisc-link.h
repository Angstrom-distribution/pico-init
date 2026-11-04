/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Router advertisements on one link: the solicitations netd sends, the
 * advertisements it receives, and what they announce, kept until their
 * lifetimes run out.
 *
 * One raw ICMPv6 socket per link, bound to the interface and filtered to
 * router advertisements, is open while IPv6AcceptRA= is in effect. An
 * advertisement is used only when its hop limit is 255, it arrived on this
 * interface and its source is link-local (RFC 4861 6.1.2). At most
 * NDISC_RX_BATCH datagrams are read per wakeup and every table below has a
 * fixed size, so a hostile link costs a bounded amount of CPU and memory and
 * no allocation per advertisement.
 *
 * Solicitations start once the link has carrier and a link-local address
 * past duplicate address detection: one after a random delay of up to 1 s
 * (RFC 4861 6.3.7), then after 4 s, doubling up to an hour with 10% jitter
 * (RFC 7559), until an advertisement from a default router arrives. Carrier
 * loss forgets everything learnt, as systemd-networkd does.
 *
 * This file keeps what the network announced and nothing else. Which of it
 * becomes an address, a route or a resolv.conf line, and with which metric,
 * is netd-link.c's decision, made each time the notify callback runs.
 */

#pragma once

#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../timer.h"
#include "ndisc-msg.h"
#include "netd-loop.h"

typedef struct Netd Netd;
typedef struct NdiscLink NdiscLink;

/* Real networks have one or two routers and a few prefixes. These bound what
 * a hostile one can make netd keep to about 2 KiB per link; networkd's limits
 * (64 routers, 64 addresses, 64 servers) are sized for servers. */
#define NDISC_ROUTERS_MAX 4
#define NDISC_PREFIXES_MAX 8
#define NDISC_RDNSS_MAX 4
#define NDISC_DNSSL_MAX 4

#define NDISC_RX_BATCH 16
#define NDISC_RS_DELAY_MAX_USEC (1 * USEC_PER_SEC)
#define NDISC_RS_INTERVAL_USEC (4 * USEC_PER_SEC)
#define NDISC_RS_INTERVAL_MAX_USEC (3600 * USEC_PER_SEC)

typedef struct NdiscRouter {
        struct in6_addr addr;
        NdiscPref pref;
        usec_t until;
} NdiscRouter;

/*
 * One prefix, from any router. `onlink_until` is the deadline of its on-link
 * route and `valid_until`/`preferred_until` those of its SLAAC address; 0 is
 * "none" for each, and the entry goes when both are 0. `dad_counter` and
 * `dad_given_up` belong to netd-link.c, which regenerates the address after a
 * duplicate address detection failure; a new entry starts them at zero.
 */
typedef struct NdiscPrefix {
        struct in6_addr prefix;
        uint8_t prefixlen;
        NdiscPref pref; /* of the router that last advertised it */
        usec_t onlink_until;
        usec_t valid_until;
        usec_t preferred_until;
        uint8_t dad_counter;
        bool dad_given_up;
} NdiscPrefix;

typedef struct NdiscRdnss {
        struct in6_addr addr;
        usec_t until;
} NdiscRdnss;

typedef struct NdiscDnssl {
        char name[NDISC_DNSSL_NAME_MAX];
        usec_t until;
} NdiscDnssl;

/* Called after every accepted advertisement and every expiry, so the owner
 * can bring the kernel in line. Must not free the NdiscLink. */
typedef void (*ndisc_link_notify_t)(void *userdata);

struct NdiscLink {
        Netd *netd;
        int ifindex;
        char ifname[IFNAMSIZ];
        ndisc_link_notify_t notify;
        void *userdata;

        int fd; /* -1 while stopped */
        struct netd_epoll_tag io_tag;
        PicoTimerEvent *rs_timer;
        PicoTimerEvent *expire_timer;
        usec_t expire_deadline;

        uint8_t hw[6];
        size_t hw_len;
        bool carrier;
        bool ll_ready;
        bool soliciting;
        usec_t rs_interval;

        bool logged_dhcpv6;
        bool logged_route_info;
        bool warned_full_routers;
        bool warned_full_prefixes;
        bool warned_full_rdnss;
        bool warned_full_dnssl;

        NdiscRouter routers[NDISC_ROUTERS_MAX];
        size_t n_routers;
        NdiscPrefix prefixes[NDISC_PREFIXES_MAX];
        size_t n_prefixes;
        NdiscRdnss rdnss[NDISC_RDNSS_MAX];
        size_t n_rdnss;
        NdiscDnssl dnssl[NDISC_DNSSL_MAX];
        size_t n_dnssl;
        uint32_t mtu; /* from the last advertisement that carried one; 0 none */
};

int ndisc_link_new(
                Netd *n,
                int ifindex,
                const char *ifname,
                ndisc_link_notify_t notify,
                void *userdata,
                NdiscLink **ret);

/* Opens the socket and registers it, unless it is open already; `hw` is the
 * source link-layer address of the solicitations. 0 or -errno, with the
 * engine stopped on error. */
int ndisc_link_start(NdiscLink *l, const uint8_t *hw, size_t hw_len);

/* Closes the socket, cancels the timers and forgets everything learnt,
 * without calling notify. The object stays usable. */
void ndisc_link_stop(NdiscLink *l);

bool ndisc_link_is_running(const NdiscLink *l);

/*
 * The link's carrier and whether its link-local address is usable.
 * Edge-triggered: the same values again change nothing. Both becoming true
 * starts the solicitations; carrier loss stops them and forgets what was
 * learnt, calling notify when there was anything.
 */
void ndisc_link_set_state(NdiscLink *l, bool carrier, bool ll_ready);

/*
 * One received datagram, as the socket callback hands it over: the ICMPv6
 * message, its IPv6 source, hop limit and arrival interface. Exposed for
 * tests; anything that fails the checks of RFC 4861 6.1.2 is dropped.
 */
void ndisc_link_receive(
                NdiscLink *l,
                const uint8_t *buf,
                size_t len,
                const struct in6_addr *src,
                int hop_limit,
                int ifindex,
                usec_t now);

/* Frees the object; free through netd_loop_defer_free() with ndisc_link_free_void(). */
void ndisc_link_free(NdiscLink *l);
void ndisc_link_free_void(void *l);
