/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * LLDP on one link: receive (LLDP=) and transmit (EmitLLDP=).
 *
 * One AF_PACKET socket per link serves both directions. It is opened only
 * while LLDP is enabled on the link, joined to the three LLDP group addresses
 * only when receiving, and given a drop-everything filter when it only
 * transmits, so a transmit-only link buffers nothing. The kernel receive
 * buffer is capped, at most LLDP_RX_BATCH frames are read per wakeup, and the
 * neighbour table (lldp-table.h) bounds what is kept, so a flood on the wire
 * costs a bounded amount of CPU and memory and cannot starve the rest of netd.
 *
 * Transmit follows IEEE 802.1AB: a frame every 30 s (TTL 120, a little
 * jitter), four at one second spacing after the link comes up or a new
 * neighbour appears, and a TTL 0 frame when LLDP is turned off or the daemon
 * stops, so neighbours forget this host at once. Carrier loss forgets every
 * neighbour: they cannot be reached any more.
 *
 * Neighbours are published for netctl in /run/netd/lldp/<ifindex>, rewritten
 * only when the set or the content of a neighbour changes.
 */

#pragma once

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#include "lldp-frame.h"

typedef struct Netd Netd;
typedef struct LldpLink LldpLink;

typedef struct LldpLinkConfig {
        bool rx;
        bool routers_only; /* keep only neighbours that advertise infrastructure capabilities */
        bool tx;
        LldpScope tx_scope;
} LldpLinkConfig;

#define LLDP_TX_INTERVAL_SEC 30
#define LLDP_TX_HOLD 4 /* TTL = interval * hold */
#define LLDP_TX_FAST_COUNT 4
#define LLDP_RX_BATCH 16

/* Capabilities that count as "routers" for routers-only: everything but other, telephone and station. */
#define LLDP_CAPS_ALL_ROUTERS                                                                   \
        ((uint16_t) (LLDP_CAP_REPEATER | LLDP_CAP_BRIDGE | LLDP_CAP_WLAN_AP | LLDP_CAP_ROUTER | \
                     LLDP_CAP_DOCSIS | LLDP_CAP_CVLAN | LLDP_CAP_SVLAN | LLDP_CAP_TPMR))

int lldp_link_new(Netd *n, int ifindex, const char *ifname, LldpLink **ret);

/*
 * Applies `cfg`: opens or closes the socket, joins or leaves the groups, and
 * starts or stops the timers. `hw` is the 6 byte hardware address used as the
 * source address, `machine_id` (16 bytes, or NULL) seeds the chassis ID.
 * Calling it again with the same configuration changes nothing. 0 or -errno;
 * on error the link is left with LLDP off.
 */
int lldp_link_configure(LldpLink *l, const LldpLinkConfig *cfg, const uint8_t hw[6], const uint8_t *machine_id);

/* The IPv4 address advertised as the management address, if any. */
void lldp_link_set_address(LldpLink *l, bool have, struct in_addr address);

/* Carrier up starts the fast transmit burst; carrier down forgets the neighbours. */
void lldp_link_set_carrier(LldpLink *l, bool up);

/* Sends the shutdown frame if transmitting, then closes everything. The object stays usable. */
void lldp_link_stop(LldpLink *l);

/* Frees the object. Call lldp_link_stop() first; free through netd_loop_defer_free() with lldp_link_free_void(). */
void lldp_link_free(LldpLink *l);
void lldp_link_free_void(void *l);

bool lldp_link_is_active(const LldpLink *l);
bool lldp_link_config_equal(const LldpLink *l, const LldpLinkConfig *cfg);
