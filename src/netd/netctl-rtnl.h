/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * netctl's own tiny RTM_GETLINK client -- the kernel-sourced rows `networkctl
 * status` prints that netd-rtnl.c's own NetdRtnlLink never needed to carry
 * (QDisc, MTU min/max, Alternative Names, queue counts, IPv6 Address
 * Generation Mode): netd configures links, it never displays them, so those
 * attributes have no reason to exist in netd's own snapshot type.
 *
 * Built only from netd-rtnl-core.c -- no link to netd_core or
 * pico_init_core, same hard constraint netctl.c's own header states for the
 * whole binary. See that file for why.
 */

#pragma once

#include <linux/netlink.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct NetctlLinkInfo {
        char *qdisc; /* strdup'd; NULL if the kernel sent none */

        uint32_t mtu;
        bool has_mtu;
        uint32_t min_mtu;
        bool has_min_mtu;
        uint32_t max_mtu;
        bool has_max_mtu;

        /* NULL-terminated; NULL itself when the link has none. Netctl's own
         * tiny strv, not systemd's strv.h -- see this file's own header. */
        char **alt_names;

        uint32_t tx_queues;
        uint32_t rx_queues;
        bool has_queues; /* false when the kernel reported 0 of both */

        /* Free from the same reply as the rows above -- not why this call
         * exists, but no reason to make a second one either. */
        uint16_t arp_type;  /* ifi_type: ARPHRD_ETHER, ARPHRD_LOOPBACK, ... */
        unsigned int flags; /* ifi_flags: IFF_UP, ... */

        /* 0=eui64, 1=none, 2=stable-privacy, 3=random -- same numbering as
         * /proc/sys/net/ipv6/conf/<if>/addr_gen_mode, which this replaces. */
        uint8_t addr_gen_mode;
        bool has_addr_gen_mode; /* mode 0 is a valid value, not "absent" */
} NetctlLinkInfo;

/*
 * One RTM_GETLINK round trip for `ifname` (by ifindex, not a dump -- the
 * kernel answers a single-ifindex GETLINK with one reply, no NLM_F_DUMP
 * needed). Fills `out` (zeroed first) and takes ownership of any heap memory
 * it allocates into it -- release with netctl_link_info_free().
 *
 * 0 on success, -ENODEV if `ifname` does not exist, or another -errno from
 * the socket/kernel.
 */
int netctl_rtnl_get_link(const char *ifname, NetctlLinkInfo *out);

/* Frees qdisc/alt_names and zeroes `*info`. Safe to call on an info that
 * netctl_rtnl_get_link() never filled (all-zero already) or on NULL. */
void netctl_link_info_free(NetctlLinkInfo *info);

/*
 * The attribute-decode half of netctl_rtnl_get_link(), split out and
 * exposed (non-static) so test-netctl-rtnl.c can feed it hand-built
 * RTM_NEWLINK byte buffers directly -- the same golden-byte approach
 * test-netd-codec.c uses for the DHCP wire format -- without a real
 * netlink socket. `nlh` must be a complete RTM_NEWLINK/RTM_GETLINK reply
 * (an ifinfomsg header plus however many rtattrs); `out` is zeroed first.
 * 0 or -EBADMSG (a message too short to hold even the ifinfomsg header) or
 * -ENOMEM.
 */
int netctl_rtnl_decode_link(const struct nlmsghdr *nlh, NetctlLinkInfo *out);
