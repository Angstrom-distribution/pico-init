/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The interface table and the per-link state machine. See netd-link.h.
 *
 * N0 scaffold: the table operations are real (they are the same code either
 * way, and netd_free() needs them to tear down cleanly); matching,
 * configuration and lease application are -ENOSYS until N1/N2.
 */

#include "netd-link.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "../util.h"
#include "netd-network.h"
#include "netd.h"

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

        /* N1/N2: link_deconfigure() here, once there is anything to undo. */

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

int netd_link_rtnl_handler(void *userdata, NetdRtnlLinkEvent event, const NetdRtnlLink *rl) {
        (void) userdata;
        (void) event;
        (void) rl;

        return -ENOSYS;
}

int link_configure(Link *l) {
        if (!l)
                return -EINVAL;

        return -ENOSYS;
}

int link_reconfigure(Link *l) {
        if (!l)
                return -EINVAL;

        return -ENOSYS;
}

int link_deconfigure(Link *l) {
        if (!l)
                return -EINVAL;

        return -ENOSYS;
}

int link_apply_lease(Link *l, DhcpLease *lease) {
        (void) lease;

        if (!l)
                return -EINVAL;

        return -ENOSYS;
}

int link_lose_lease(Link *l) {
        if (!l)
                return -EINVAL;

        return -ENOSYS;
}

int link_write_lease_file(Link *l) {
        if (!l)
                return -EINVAL;

        return -ENOSYS;
}

int link_remove_lease_file(Link *l) {
        if (!l)
                return -EINVAL;

        return -ENOSYS;
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
