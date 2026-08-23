/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * N1's acceptance test: the hand-rolled rtnetlink layer.
 *
 * Registered up front, placeholder body. What lands here with N1 (plan §2.8):
 * the test unshare(CLONE_NEWNET)s into its own network namespace -- the
 * container runs as root, so this is real kernel networking with zero effect
 * on the host -- creates dummy interfaces and veth pairs, and exercises lo
 * up, address add, route add including the default route, the NLM_F_DUMP
 * enumeration, and RTM_NEWLINK event delivery for an interface created after
 * the subscription.
 *
 * The event-after-subscription case is the one worth writing first. It is the
 * whole reason netd's unit has no After=eudev.service, and it is exactly what
 * a dump-then-subscribe implementation would pass every other test while
 * silently getting wrong.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test-util.h"
#include "netd-rtnl.h"

/* Every event kind has a name; nothing falls through to "invalid". A missing
 * table entry is a NULL deref in a log call on a board, which is a miserable
 * way to find out. */
static void test_event_names(void) {
        ASSERT_STREQ(netd_rtnl_link_event_to_string(NETD_RTNL_LINK_ADDED), "added");
        ASSERT_STREQ(netd_rtnl_link_event_to_string(NETD_RTNL_LINK_CHANGED), "changed");
        ASSERT_STREQ(netd_rtnl_link_event_to_string(NETD_RTNL_LINK_REMOVED), "removed");
        ASSERT_STREQ(netd_rtnl_link_event_to_string(_NETD_RTNL_LINK_EVENT_MAX), "invalid");
        ASSERT_STREQ(netd_rtnl_link_event_to_string((NetdRtnlLinkEvent) -1), "invalid");
}

/* NetdRtnlLink is filled in from bytes off a netlink socket, so its name
 * field has to be able to hold what the kernel can send. */
static void test_link_snapshot_shape(void) {
        NetdRtnlLink l;

        memset(&l, 0, sizeof(l));

        ASSERT_TRUE(sizeof(l.ifname) >= IFNAMSIZ);
        ASSERT_TRUE(sizeof(l.hw_addr) >= NETD_HW_ADDR_MAX);
        ASSERT_EQ_INT(l.hw_addr_len, 0);
}

int main(void) {
        test_event_names();
        test_link_snapshot_shape();

        printf("test-netd-rtnl: ok\n");
        return EXIT_SUCCESS;
}
