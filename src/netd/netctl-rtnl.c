/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * netctl's own tiny RTM_GETLINK client. See netctl-rtnl.h for what it
 * fetches and why it is a separate client.
 *
 * One socket, one request, one reply -- no event subscription, no dump, no
 * persistent state: `networkctl status <iface>` is a one-shot CLI, so
 * there is nothing here to keep open between invocations.
 */

#include "netctl-rtnl.h"

#include <errno.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

#include "netd-rtnl-core.h"

/* Not every kernel header in the wild carries these yet -- same fallback
 * discipline netd-rtnl-core.c uses for NLM_F_CAPPED. Values are the kernel
 * UAPI's own, stable since they were added (if_link.h). */
#ifndef IFLA_MIN_MTU
#        define IFLA_MIN_MTU 50
#endif
#ifndef IFLA_MAX_MTU
#        define IFLA_MAX_MTU 51
#endif
#ifndef IFLA_PROP_LIST
#        define IFLA_PROP_LIST 52
#endif
#ifndef IFLA_ALT_IFNAME
#        define IFLA_ALT_IFNAME 53
#endif
#ifndef IFLA_INET6_ADDR_GEN_MODE
#        define IFLA_INET6_ADDR_GEN_MODE 8
#endif

/* --- netctl's own tiny NULL-terminated string vector ---
 *
 * Not systemd's strv.h: this is the one place that needs a growable list,
 * and it is a few lines of realloc doubling.
 */
static int strv_push(char ***arr, size_t *n, size_t *cap, char *s) {
        if (*n + 1 >= *cap) {
                size_t new_cap = *cap == 0 ? 4 : *cap * 2;
                char **grown = realloc(*arr, new_cap * sizeof(*grown));

                if (!grown) {
                        free(s);
                        return -ENOMEM;
                }
                *arr = grown;
                *cap = new_cap;
        }

        (*arr)[(*n)++] = s;
        (*arr)[*n] = NULL;
        return 0;
}

static void strv_free(char **arr) {
        if (!arr)
                return;

        for (size_t i = 0; arr[i]; i++)
                free(arr[i]);
        free(arr);
}

/* --- attribute decoding --- */

/*
 * IFLA_PROP_LIST is a container of repeated IFLA_ALT_IFNAME string
 * attributes (one per alternative name the kernel knows for this link) --
 * unlike IFLA_AF_SPEC below, there is exactly one level of nesting and
 * every child is the same type, so this is a plain RTA_OK/RTA_NEXT walk
 * collecting each match, not a second rtattr_enter().
 */
static int decode_alt_names(const struct rtattr *first, int rem, char ***out) {
        const struct rtattr *rta;
        char **names = NULL;
        size_t n = 0, cap = 0;
        int r;

        for (rta = first; RTA_OK(rta, rem); rta = RTA_NEXT(rta, rem)) {
                char buf[IFNAMSIZ];
                char *dup;
                size_t len;

                if (rta->rta_type != IFLA_ALT_IFNAME)
                        continue;

                len = RTA_PAYLOAD(rta);
                if (len >= sizeof(buf))
                        len = sizeof(buf) - 1;
                memcpy(buf, RTA_DATA(rta), len);
                buf[len] = '\0';

                dup = strdup(buf);
                if (!dup) {
                        strv_free(names);
                        return -ENOMEM;
                }

                r = strv_push(&names, &n, &cap, dup);
                if (r < 0) {
                        strv_free(names);
                        return r;
                }
        }

        *out = names;
        return 0;
}

/*
 * IFLA_AF_SPEC is a container keyed by address family (AF_INET6 among
 * others); within the AF_INET6 child, IFLA_INET6_ADDR_GEN_MODE is itself a
 * further-nested attribute -- two rtattr_enter() calls, not one, which is
 * exactly what that helper is for.
 */
static bool decode_addr_gen_mode(const struct rtattr *first, int rem, uint8_t *out) {
        const struct rtattr *af_inet6;
        int af_inet6_rem;

        if (!rtattr_enter(first, rem, IFLA_AF_SPEC, &af_inet6, &af_inet6_rem))
                return false;

        if (!rtattr_enter(af_inet6, af_inet6_rem, AF_INET6, &af_inet6, &af_inet6_rem))
                return false;

        return rtattr_get_u8(af_inet6, af_inet6_rem, IFLA_INET6_ADDR_GEN_MODE, out);
}

int netctl_rtnl_decode_link(const struct nlmsghdr *nlh, NetctlLinkInfo *out) {
        const struct ifinfomsg *ifi;
        const struct rtattr *rta;
        int rem;
        char qdisc[64];
        const struct rtattr *prop_list;
        int prop_list_rem;

        if (!nlh || !out)
                return -EINVAL;

        memset(out, 0, sizeof(*out));

        if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*ifi)))
                return -EBADMSG;

        ifi = (const struct ifinfomsg *) NLMSG_DATA(nlh);
        out->arp_type = (uint16_t) ifi->ifi_type;
        out->flags = ifi->ifi_flags;

        rem = (int) (nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi)));
        rta = (const struct rtattr *) ((const uint8_t *) ifi + NLMSG_ALIGN(sizeof(*ifi)));

        if (rtattr_get_string(rta, rem, IFLA_QDISC, qdisc, sizeof qdisc)) {
                out->qdisc = strdup(qdisc);
                if (!out->qdisc)
                        return -ENOMEM;
        }

        out->has_mtu = rtattr_get_u32(rta, rem, IFLA_MTU, &out->mtu);
        out->has_min_mtu = rtattr_get_u32(rta, rem, IFLA_MIN_MTU, &out->min_mtu);
        out->has_max_mtu = rtattr_get_u32(rta, rem, IFLA_MAX_MTU, &out->max_mtu);

        {
                bool got_tx = rtattr_get_u32(rta, rem, IFLA_NUM_TX_QUEUES, &out->tx_queues);
                bool got_rx = rtattr_get_u32(rta, rem, IFLA_NUM_RX_QUEUES, &out->rx_queues);

                /* Upstream's own ">0" guard (networkctl-link-info.c): a link
                 * reporting neither attribute, or 0 of both, has no
                 * row to print. */
                out->has_queues = (got_tx && out->tx_queues > 0) || (got_rx && out->rx_queues > 0);
        }

        if (rtattr_enter(rta, rem, IFLA_PROP_LIST, &prop_list, &prop_list_rem)) {
                int r = decode_alt_names(prop_list, prop_list_rem, &out->alt_names);

                if (r < 0)
                        return r;
        }

        out->has_addr_gen_mode = decode_addr_gen_mode(rta, rem, &out->addr_gen_mode);

        return 0;
}

int netctl_rtnl_get_link(const char *ifname, NetctlLinkInfo *out) {
        NlSock sock = { .fd = -1 };
        struct nl_request req;
        struct nlmsghdr *nlh;
        struct ifinfomsg *ifi;
        unsigned idx;
        uint32_t seq;
        int r;

        if (!ifname || !out)
                return -EINVAL;

        memset(out, 0, sizeof(*out));

        idx = if_nametoindex(ifname);
        if (idx == 0)
                return -ENODEV;

        r = nl_sock_open(&sock, false);
        if (r < 0)
                return r;

        /* A single-ifindex GETLINK (no NLM_F_DUMP) is answered with exactly
         * one RTM_NEWLINK reply, the same way `ip link show <iface>` works --
         * there is no dump to drain and no NLMSG_DONE to wait for. */
        nlh = nl_req_init(&req, RTM_GETLINK, NLM_F_REQUEST);
        if (!nlh) {
                r = -ENOBUFS;
                goto out_close;
        }

        ifi = nl_reserve(&req, sizeof(*ifi));
        if (!ifi) {
                r = -ENOBUFS;
                goto out_close;
        }
        ifi->ifi_family = AF_UNSPEC;
        ifi->ifi_index = (int) idx;

        r = nl_finish_and_send(&sock, &req, &seq);
        if (r < 0)
                goto out_close;

        for (;;) {
                union nl_recv_buf rb;
                ssize_t len;
                struct nlmsghdr *m;
                int rem;

                len = nl_recv(sock.fd, false, &rb);
                if (len < 0) {
                        r = (int) len;
                        goto out_close;
                }
                if (len == 0) {
                        r = -EIO;
                        goto out_close;
                }

                m = (struct nlmsghdr *) rb.buf;
                rem = (int) len;

                for (; NLMSG_OK(m, rem); m = NLMSG_NEXT(m, rem)) {
                        if (m->nlmsg_seq != seq)
                                continue;

                        if (m->nlmsg_type == NLMSG_ERROR) {
                                r = nl_parse_error(m, NULL, 0);
                                /* A plain ACK (r == 0) should never answer a
                                 * GETLINK -- treat it the same as any other
                                 * reply that is not the RTM_NEWLINK this
                                 * call is waiting for. */
                                if (r == 0)
                                        r = -EIO;
                                goto out_close;
                        }

                        if (m->nlmsg_type == RTM_NEWLINK) {
                                r = netctl_rtnl_decode_link(m, out);
                                goto out_close;
                        }
                }
        }

out_close:
        nl_sock_close(&sock);
        if (r < 0)
                netctl_link_info_free(out);
        return r;
}

void netctl_link_info_free(NetctlLinkInfo *info) {
        if (!info)
                return;

        free(info->qdisc);
        strv_free(info->alt_names);
        memset(info, 0, sizeof(*info));
}
