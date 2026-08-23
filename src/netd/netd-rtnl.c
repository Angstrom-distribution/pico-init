/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The hand-rolled rtnetlink layer. New code -- sd-netlink is read as a design
 * reference and nothing is copied from it, which is why this file is
 * GPL-2.0-or-later like the rest of netd's own source. See netd-rtnl.h for
 * why it is hand-rolled and why there are two sockets.
 *
 * N0 scaffold: everything below is -ENOSYS until N1.
 */

#include "netd-rtnl.h"

#include <errno.h>
#include <stddef.h>

#include "../util.h"

int netd_rtnl_new(NetdRtnl **ret) {
        if (!ret)
                return -EINVAL;

        return -ENOSYS;
}

NetdRtnl *netd_rtnl_free(NetdRtnl *rtnl) {
        (void) rtnl;

        return NULL;
}

int netd_rtnl_event_fd(NetdRtnl *rtnl) {
        (void) rtnl;

        return -ENOSYS;
}

void netd_rtnl_set_link_handler(NetdRtnl *rtnl, netd_rtnl_link_handler_t handler, void *userdata) {
        (void) rtnl;
        (void) handler;
        (void) userdata;
}

int netd_rtnl_enumerate_links(NetdRtnl *rtnl) {
        (void) rtnl;

        return -ENOSYS;
}

int netd_rtnl_process(NetdRtnl *rtnl) {
        (void) rtnl;

        return -ENOSYS;
}

int netd_rtnl_link_up(NetdRtnl *rtnl, int ifindex) {
        (void) rtnl;
        (void) ifindex;

        return -ENOSYS;
}

int netd_rtnl_link_down(NetdRtnl *rtnl, int ifindex) {
        (void) rtnl;
        (void) ifindex;

        return -ENOSYS;
}

int netd_rtnl_address_add(
                NetdRtnl *rtnl,
                int ifindex,
                const struct in_addr *address,
                unsigned char prefixlen,
                const struct in_addr *broadcast,
                uint32_t lifetime_sec) {

        (void) rtnl;
        (void) ifindex;
        (void) address;
        (void) prefixlen;
        (void) broadcast;
        (void) lifetime_sec;

        return -ENOSYS;
}

int netd_rtnl_address_del(NetdRtnl *rtnl, int ifindex, const struct in_addr *address, unsigned char prefixlen) {
        (void) rtnl;
        (void) ifindex;
        (void) address;
        (void) prefixlen;

        return -ENOSYS;
}

int netd_rtnl_route_add(
                NetdRtnl *rtnl,
                int ifindex,
                const struct in_addr *destination,
                unsigned char prefixlen,
                const struct in_addr *gateway,
                uint32_t metric) {

        (void) rtnl;
        (void) ifindex;
        (void) destination;
        (void) prefixlen;
        (void) gateway;
        (void) metric;

        return -ENOSYS;
}

int netd_rtnl_route_add_default(NetdRtnl *rtnl, int ifindex, const struct in_addr *gateway, uint32_t metric) {
        return netd_rtnl_route_add(rtnl, ifindex, NULL, 0, gateway, metric);
}

int netd_rtnl_route_del(
                NetdRtnl *rtnl,
                int ifindex,
                const struct in_addr *destination,
                unsigned char prefixlen,
                const struct in_addr *gateway,
                uint32_t metric) {

        (void) rtnl;
        (void) ifindex;
        (void) destination;
        (void) prefixlen;
        (void) gateway;
        (void) metric;

        return -ENOSYS;
}

static const char * const netd_rtnl_link_event_table[_NETD_RTNL_LINK_EVENT_MAX] = {
        [NETD_RTNL_LINK_ADDED] = "added",
        [NETD_RTNL_LINK_CHANGED] = "changed",
        [NETD_RTNL_LINK_REMOVED] = "removed",
};

const char *netd_rtnl_link_event_to_string(NetdRtnlLinkEvent e) {
        if (e < 0 || e >= _NETD_RTNL_LINK_EVENT_MAX)
                return "invalid";

        return netd_rtnl_link_event_table[e];
}
