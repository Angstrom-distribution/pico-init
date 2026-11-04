/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The hand-rolled rtnetlink layer. New code -- sd-netlink is read as a design
 * reference and nothing is copied from it, which is why this file is
 * GPL-2.0-or-later like the rest of netd's own source. See netd-rtnl.h for
 * why it is hand-rolled and why there are two sockets.
 *
 * Link enumerate/match, RTM_NEWLINK/DELLINK subscription, IPv6 address
 * events and enumeration, link up/down,
 * RTM_NEWADDR/DELADDR, RTM_NEWROUTE/DELROUTE including a default route, and
 * netd_rtnl_link_set_hwaddr() for persistent-MAC generation.
 *
 * The low-level socket/message plumbing (request construction, send/recv,
 * NLMSG_ERROR decoding, the generic rtattr_get_* and rtattr_enter() getters)
 * lives in netd-rtnl-core.c, shared with netctl-rtnl.c. This file keeps
 * netd's own policy: the NetdRtnl struct,
 * event-fd subscription, ADDED/CHANGED/REMOVED bookkeeping, nl_parse_link(),
 * every netd_rtnl_* writer, and every pico_log() call -- the core layer
 * decodes a kernel error into a string, this file is what logs it.
 *
 * ALIGNMENT. Every multi-byte field this file reads off a socket is reached
 * through NLMSG_DATA()/RTA_DATA() on a message walked with NLMSG_OK()/
 * NLMSG_NEXT() and RTA_OK()/RTA_NEXT() -- never by hand-adding offsets -- so
 * every pointer this file dereferences is 4-byte aligned by construction of
 * the netlink framing itself (NLMSG_ALIGN/RTA_ALIGN round every message and
 * every attribute up to a 4-byte boundary, and the receive buffer is a
 * `union nl_recv_buf`, the same nlmsghdr-typed-member trick struct
 * nl_request uses, so its stack storage is never less aligned than that
 * floor requires -- a bare uint8_t[] on the stack would not be). Fixed-offset
 * struct field access (struct ifinfomsg, struct nlmsgerr) is therefore safe
 * without a copy. Attribute *payloads* of unpredictable length (an interface
 * name, a hardware address) are still copied byte-wise with memcpy() rather
 * than cast-and-dereferenced, because their length is kernel-supplied and
 * reading past what RTA_PAYLOAD() actually reports would be the real bug,
 * alignment aside. On ARMv5TE a stray unaligned word load does not fault, it
 * rotates -- so a mistake here would not crash, it would silently hand netd
 * the wrong ifindex or address. Every message loop below is bounds-checked
 * with NLMSG_OK/RTA_OK, and no attribute array is ever indexed by a
 * kernel-supplied rta_type -- dispatch is a switch, not a table.
 */

#include "netd-rtnl.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../util.h"
#include "netd-rtnl-core.h"

/* A dump interrupted mid-flight (ENOBUFS, or NLM_F_DUMP_INTR on the closing
 * NLMSG_DONE) is retried from scratch rather than reported: a partially
 * observed link table is worse than a slow one. Bounded so a pathologically
 * busy machine fails loudly instead of looping forever. */
#define NETD_RTNL_DUMP_MAX_RETRIES 5

struct NetdRtnl {
        NlSock req;   /* private: synchronous request -> ACK only */
        int event_fd; /* subscribed to RTNLGRP_LINK and RTNLGRP_IPV6_IFADDR; the only fd netd polls */

        netd_rtnl_link_handler_t link_handler;
        void *link_userdata;

        netd_rtnl_addr_handler_t addr_handler;
        void *addr_userdata;

        /* ifindexes already reported through the handler, so a live
         * RTM_NEWLINK can be told apart from a first sighting (ADDED) versus
         * an update to something already known (CHANGED) -- see
         * netd-rtnl.h's comment on netd_rtnl_link_handler_t. */
        int *known;
        size_t n_known;
        size_t known_cap;
};

/* --- thin wrappers that add netd's own logging over the silent core --- */

static ssize_t rtnl_recv(int fd, bool nonblock, union nl_recv_buf *rb) {
        ssize_t len = nl_recv(fd, nonblock, rb);

        if (len == -ENOBUFS)
                pico_log(PICO_LOG_WARNING,
                         "netd: rtnl: receive-queue overrun or oversized datagram on fd %d -- "
                         "resyncing",
                         fd);

        return len;
}

static int rtnl_execute(NetdRtnl *rtnl, struct nl_request *req) {
        char errbuf[256] = "";
        int r = nl_execute(&rtnl->req, req, errbuf, sizeof errbuf);

        if (r != 0 && errbuf[0] != '\0')
                pico_log(PICO_LOG_WARNING, "netd: rtnl: kernel: %s (%s)", errbuf, strerror(-r));

        return r;
}

/* --- RTM_(NEW|DEL)LINK parsing --- */

/*
 * Decode one RTM_NEWLINK/RTM_DELLINK into a snapshot. `nlh` must already have
 * passed NLMSG_OK against the caller's remaining buffer length, so
 * nlh->nlmsg_len is trustworthy as the real extent of this message.
 */
static int nl_parse_link(const struct nlmsghdr *nlh, NetdRtnlLink *out) {
        const struct ifinfomsg *ifi;
        const struct rtattr *rta, *addr_rta;
        int rem;

        if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*ifi)))
                return -EBADMSG;

        ifi = (const struct ifinfomsg *) NLMSG_DATA(nlh);

        memset(out, 0, sizeof(*out));
        out->ifindex = ifi->ifi_index;
        out->flags = ifi->ifi_flags;
        out->arp_type = (uint16_t) ifi->ifi_type;

        if (out->ifindex <= 0)
                return -EBADMSG;

        rem = (int) (nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi)));
        rta = (const struct rtattr *) ((const uint8_t *) ifi + NLMSG_ALIGN(sizeof(*ifi)));

        (void) rtattr_get_string(rta, rem, IFLA_IFNAME, out->ifname, sizeof(out->ifname));
        (void) rtattr_get_u32(rta, rem, IFLA_MTU, &out->mtu);

        addr_rta = rtattr_find(rta, rem, IFLA_ADDRESS);
        if (addr_rta) {
                size_t n = RTA_PAYLOAD(addr_rta);

                if (n > NETD_HW_ADDR_MAX)
                        n = NETD_HW_ADDR_MAX;
                memcpy(out->hw_addr, RTA_DATA(addr_rta), n);
                out->hw_addr_len = n;
        }

        return 0;
}

/* --- RTM_(NEW|DEL)ADDR parsing --- */

/* As nl_parse_link(): `nlh` has passed NLMSG_OK. -EAFNOSUPPORT for an
 * address that is not IPv6, which is not an error, just not delivered. */
static int nl_parse_addr(const struct nlmsghdr *nlh, NetdRtnlAddr *out) {
        const struct ifaddrmsg *ifa;
        const struct rtattr *rta, *a;
        int rem;

        if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*ifa)))
                return -EBADMSG;

        ifa = (const struct ifaddrmsg *) NLMSG_DATA(nlh);
        if (ifa->ifa_family != AF_INET6)
                return -EAFNOSUPPORT;

        memset(out, 0, sizeof(*out));
        out->ifindex = (int) ifa->ifa_index;
        out->family = AF_INET6;
        out->prefixlen = ifa->ifa_prefixlen;
        out->scope = ifa->ifa_scope;
        out->flags = ifa->ifa_flags;

        if (out->ifindex <= 0 || out->prefixlen > 128)
                return -EBADMSG;

        rem = (int) (nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));
        rta = (const struct rtattr *) ((const uint8_t *) ifa + NLMSG_ALIGN(sizeof(*ifa)));

        (void) rtattr_get_u32(rta, rem, IFA_FLAGS, &out->flags);

        a = rtattr_find(rta, rem, IFA_LOCAL);
        if (!a)
                a = rtattr_find(rta, rem, IFA_ADDRESS);
        if (!a || RTA_PAYLOAD(a) != sizeof(struct in6_addr))
                return -EBADMSG;

        memcpy(out->address.bytes, RTA_DATA(a), sizeof(struct in6_addr));
        return 0;
}

static void dispatch_addr(NetdRtnl *rtnl, const struct nlmsghdr *m) {
        NetdRtnlAddr addr;
        int r;

        r = nl_parse_addr(m, &addr);
        if (r == -EAFNOSUPPORT)
                return;
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "netd: rtnl: dropping malformed address message: %s", strerror(-r));
                return;
        }

        if (!rtnl->addr_handler)
                return;

        r = rtnl->addr_handler(rtnl->addr_userdata, m->nlmsg_type == RTM_DELADDR, &addr);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "netd: rtnl: address handler failed: %s", strerror(-r));
}

/* --- ADDED/CHANGED/REMOVED bookkeeping --- */

static bool known_contains(const NetdRtnl *rtnl, int ifindex) {
        for (size_t i = 0; i < rtnl->n_known; i++)
                if (rtnl->known[i] == ifindex)
                        return true;

        return false;
}

static int known_add(NetdRtnl *rtnl, int ifindex) {
        if (known_contains(rtnl, ifindex))
                return 0;

        if (rtnl->n_known == rtnl->known_cap) {
                size_t new_cap = rtnl->known_cap == 0 ? 8 : rtnl->known_cap * 2;
                int *grown = realloc(rtnl->known, new_cap * sizeof(*grown));

                if (!grown)
                        return -ENOMEM;

                rtnl->known = grown;
                rtnl->known_cap = new_cap;
        }

        rtnl->known[rtnl->n_known++] = ifindex;
        return 0;
}

static void known_remove(NetdRtnl *rtnl, int ifindex) {
        for (size_t i = 0; i < rtnl->n_known; i++) {
                if (rtnl->known[i] == ifindex) {
                        rtnl->known[i] = rtnl->known[rtnl->n_known - 1];
                        rtnl->n_known--;
                        return;
                }
        }
}

/*
 * Parse and deliver one link message. `from_dump` is true only for
 * netd_rtnl_enumerate_links(), where every entry is reported ADDED per
 * netd-rtnl.h's contract; a live RTM_NEWLINK instead consults the known set
 * to tell a first sighting from an update. A handler failure is logged, not
 * propagated -- one interface netd cannot make sense of must not stop the
 * rest from being seen (dump) or processed (live events).
 */
static void dispatch_link(NetdRtnl *rtnl, const struct nlmsghdr *m, bool from_dump) {
        NetdRtnlLink link;
        NetdRtnlLinkEvent event;
        int r;

        r = nl_parse_link(m, &link);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING,
                         "netd: rtnl: dropping malformed %s message: %s",
                         m->nlmsg_type == RTM_DELLINK ? "RTM_DELLINK" : "RTM_NEWLINK",
                         strerror(-r));
                return;
        }

        if (m->nlmsg_type == RTM_DELLINK) {
                known_remove(rtnl, link.ifindex);
                event = NETD_RTNL_LINK_REMOVED;
        } else if (from_dump) {
                (void) known_add(rtnl, link.ifindex);
                event = NETD_RTNL_LINK_ADDED;
        } else {
                bool was_known = known_contains(rtnl, link.ifindex);

                (void) known_add(rtnl, link.ifindex);
                event = was_known ? NETD_RTNL_LINK_CHANGED : NETD_RTNL_LINK_ADDED;
        }

        if (!rtnl->link_handler)
                return;

        r = rtnl->link_handler(rtnl->link_userdata, event, &link);
        if (r < 0)
                pico_log(PICO_LOG_WARNING,
                         "netd: rtnl: link handler failed for %s (%s): %s",
                         link.ifname,
                         netd_rtnl_link_event_to_string(event),
                         strerror(-r));
}

/* --- lifecycle --- */

int netd_rtnl_new(NetdRtnl **ret) {
        NetdRtnl *rtnl;
        NlSock event_sock;
        int r;

        if (!ret)
                return -EINVAL;

        rtnl = calloc(1, sizeof(*rtnl));
        if (!rtnl)
                return -ENOMEM;

        rtnl->req.fd = -1;
        rtnl->event_fd = -1;

        r = nl_sock_open(&rtnl->req, false);
        if (r < 0)
                goto fail;

        r = nl_sock_open(&event_sock, true);
        if (r < 0)
                goto fail;
        rtnl->event_fd = event_sock.fd;

        /* Best effort: without the group, solicitations wait for a link-local
         * address the startup dump saw and lost detection goes unnoticed, but
         * IPv4 and received advertisements still work. */
        if (netd_ipv6_supported()) {
                r = nl_sock_join_group(&event_sock, RTNLGRP_IPV6_IFADDR);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "netd: rtnl: cannot follow IPv6 address events, continuing without them: %s",
                                 strerror(-r));
        }

        *ret = rtnl;
        return 0;

fail:
        netd_rtnl_free(rtnl);
        return r;
}

NetdRtnl *netd_rtnl_free(NetdRtnl *rtnl) {
        if (!rtnl)
                return NULL;

        nl_sock_close(&rtnl->req);
        if (rtnl->event_fd >= 0)
                (void) close(rtnl->event_fd);

        free(rtnl->known);
        free(rtnl);
        return NULL;
}

int netd_rtnl_event_fd(NetdRtnl *rtnl) {
        if (!rtnl)
                return -EINVAL;

        return rtnl->event_fd;
}

void netd_rtnl_set_link_handler(NetdRtnl *rtnl, netd_rtnl_link_handler_t handler, void *userdata) {
        if (!rtnl)
                return;

        rtnl->link_handler = handler;
        rtnl->link_userdata = userdata;
}

void netd_rtnl_set_addr_handler(NetdRtnl *rtnl, netd_rtnl_addr_handler_t handler, void *userdata) {
        if (!rtnl)
                return;

        rtnl->addr_handler = handler;
        rtnl->addr_userdata = userdata;
}

/* --- reading --- */

/* A dump of links (RTM_GETLINK) or IPv6 addresses (RTM_GETADDR), each entry
 * delivered as a new one. */
static int rtnl_dump(NetdRtnl *rtnl, uint16_t type) {
        int attempt;

        for (attempt = 0; attempt < NETD_RTNL_DUMP_MAX_RETRIES; attempt++) {
                struct nl_request req;
                struct nlmsghdr *nlh;
                uint32_t seq;
                int count = 0;
                bool retry = false;
                bool done = false;
                int r;

                nlh = nl_req_init(&req, type, NLM_F_REQUEST | NLM_F_DUMP);
                if (!nlh)
                        return -ENOBUFS;

                if (type == RTM_GETLINK) {
                        struct ifinfomsg *ifi = nl_reserve(&req, sizeof(*ifi));

                        if (!ifi)
                                return -ENOBUFS;
                        ifi->ifi_family = AF_UNSPEC;
                } else {
                        struct ifaddrmsg *ifa = nl_reserve(&req, sizeof(*ifa));

                        if (!ifa)
                                return -ENOBUFS;
                        ifa->ifa_family = AF_INET6;
                }

                r = nl_finish_and_send(&rtnl->req, &req, &seq);
                if (r < 0)
                        return r;

                while (!done) {
                        union nl_recv_buf rb;
                        ssize_t len;
                        struct nlmsghdr *m;
                        int rem;

                        len = rtnl_recv(rtnl->req.fd, false, &rb);
                        if (len == -ENOBUFS) {
                                retry = true;
                                break;
                        }
                        if (len < 0)
                                return (int) len;
                        if (len == 0)
                                return -EIO;

                        m = (struct nlmsghdr *) rb.buf;
                        rem = (int) len;

                        /* rem is an int because NLMSG_OK() compares it
                         * against signed values. */
                        for (; NLMSG_OK(m, rem); m = NLMSG_NEXT(m, rem)) {
                                if (m->nlmsg_seq != seq)
                                        continue;

                                if (m->nlmsg_type == NLMSG_ERROR) {
                                        char errbuf[256] = "";

                                        r = nl_parse_error(m, errbuf, sizeof errbuf);
                                        if (r != 0 && errbuf[0] != '\0')
                                                pico_log(PICO_LOG_WARNING,
                                                         "netd: rtnl: kernel: %s (%s)",
                                                         errbuf,
                                                         strerror(-r));
                                        return r;
                                }

                                if (m->nlmsg_type == NLMSG_DONE) {
                                        if (m->nlmsg_flags & NLM_F_DUMP_INTR)
                                                retry = true;
                                        done = true;
                                        break;
                                }

                                if (m->nlmsg_type == RTM_NEWLINK && type == RTM_GETLINK) {
                                        dispatch_link(rtnl, m, true);
                                        count++;
                                } else if (m->nlmsg_type == RTM_NEWADDR && type == RTM_GETADDR) {
                                        dispatch_addr(rtnl, m);
                                        count++;
                                }
                        }
                }

                if (retry)
                        continue;

                return count;
        }

        return -ENOBUFS;
}

int netd_rtnl_enumerate_links(NetdRtnl *rtnl) {
        if (!rtnl)
                return -EINVAL;

        return rtnl_dump(rtnl, RTM_GETLINK);
}

int netd_rtnl_enumerate_addresses(NetdRtnl *rtnl) {
        if (!rtnl)
                return -EINVAL;

        if (!netd_ipv6_supported())
                return 0;

        return rtnl_dump(rtnl, RTM_GETADDR);
}

int netd_rtnl_process(NetdRtnl *rtnl) {
        int dispatched = 0;

        if (!rtnl)
                return -EINVAL;

        for (;;) {
                union nl_recv_buf rb;
                ssize_t len;
                struct nlmsghdr *m;
                int rem;

                len = rtnl_recv(rtnl->event_fd, true, &rb);
                if (len == -EAGAIN)
                        break;
                if (len < 0)
                        return (int) len; /* ENOBUFS included -- see netd-rtnl.h's contract */
                if (len == 0)
                        break;

                m = (struct nlmsghdr *) rb.buf;
                rem = (int) len;

                for (; NLMSG_OK(m, rem); m = NLMSG_NEXT(m, rem)) {
                        switch (m->nlmsg_type) {

                        case RTM_NEWLINK:
                        case RTM_DELLINK:
                                dispatch_link(rtnl, m, false);
                                dispatched++;
                                break;

                        case RTM_NEWADDR:
                        case RTM_DELADDR:
                                dispatch_addr(rtnl, m);
                                dispatched++;
                                break;

                        case NLMSG_ERROR: {
                                char errbuf[256] = "";
                                int err = nl_parse_error(m, errbuf, sizeof errbuf);

                                pico_log(PICO_LOG_WARNING,
                                         "netd: rtnl: unexpected error message on event socket: %s%s%s",
                                         strerror(-err),
                                         errbuf[0] ? " -- " : "",
                                         errbuf);
                                break;
                        }

                        default:
                                break;
                        }
                }
        }

        return dispatched;
}

/* --- writing --- */

static int set_link_flags(NetdRtnl *rtnl, int ifindex, unsigned int flags, unsigned int change) {
        struct nl_request req;
        struct nlmsghdr *nlh;
        struct ifinfomsg *ifi;

        if (!rtnl || ifindex <= 0)
                return -EINVAL;

        nlh = nl_req_init(&req, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK);
        if (!nlh)
                return -ENOBUFS;

        ifi = nl_reserve(&req, sizeof(*ifi));
        if (!ifi)
                return -ENOBUFS;

        ifi->ifi_family = AF_UNSPEC;
        ifi->ifi_index = ifindex;
        ifi->ifi_flags = flags;
        ifi->ifi_change = change;

        return rtnl_execute(rtnl, &req);
}

int netd_rtnl_link_up(NetdRtnl *rtnl, int ifindex) {
        return set_link_flags(rtnl, ifindex, IFF_UP, IFF_UP);
}

int netd_rtnl_link_down(NetdRtnl *rtnl, int ifindex) {
        return set_link_flags(rtnl, ifindex, 0, IFF_UP);
}

/*
 * RTM_SETLINK carrying only IFLA_ADDRESS, ifi_flags/ifi_change left at 0 so
 * this never touches admin state -- link_apply_persistent_mac() (netd-link.c)
 * is the one caller, and it decides up/down separately. Mirrors
 * set_link_flags()'s own shape; see that function and netd-rtnl.h's writer
 * contract (0/-errno, -EEXIST-style translation is the *caller's* job, not
 * this layer's -- though a MAC change has no natural "already exists" case
 * the way an address add does).
 */
int netd_rtnl_link_set_hwaddr(NetdRtnl *rtnl, int ifindex, const uint8_t *addr, size_t len) {
        struct nl_request req;
        struct nlmsghdr *nlh;
        struct ifinfomsg *ifi;
        int r;

        if (!rtnl || ifindex <= 0 || !addr || len == 0)
                return -EINVAL;

        nlh = nl_req_init(&req, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK);
        if (!nlh)
                return -ENOBUFS;

        ifi = nl_reserve(&req, sizeof(*ifi));
        if (!ifi)
                return -ENOBUFS;

        ifi->ifi_family = AF_UNSPEC;
        ifi->ifi_index = ifindex;

        r = nl_add_attr(&req, IFLA_ADDRESS, addr, len);
        if (r < 0)
                return r;

        return rtnl_execute(rtnl, &req);
}

/* address | ~mask, entirely in network byte order: OR and NOT are
 * bit-position operations, so they need no host-order conversion, only the
 * mask's construction does (the shift amount is a numeric quantity). */
static void derive_broadcast(const struct in_addr *address, unsigned char prefixlen, struct in_addr *ret) {
        uint32_t mask_be;

        if (prefixlen == 0)
                mask_be = 0;
        else if (prefixlen >= 32)
                mask_be = 0xffffffffu;
        else
                mask_be = htonl(0xffffffffu << (32 - prefixlen));

        ret->s_addr = address->s_addr | ~mask_be;
}

int netd_rtnl_address_add(NetdRtnl *rtnl, const NetdRtnlAddress *a) {
        struct nl_request req;
        struct nlmsghdr *nlh;
        struct ifaddrmsg *ifa;
        struct ifa_cacheinfo ci;
        size_t size;
        int r;

        if (!rtnl || !a || a->ifindex <= 0 || (a->family != AF_INET && a->family != AF_INET6) ||
            a->prefixlen > (a->family == AF_INET ? 32 : 128))
                return -EINVAL;

        size = a->family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);

        nlh = nl_req_init(&req, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK);
        if (!nlh)
                return -ENOBUFS;

        ifa = nl_reserve(&req, sizeof(*ifa));
        if (!ifa)
                return -ENOBUFS;

        ifa->ifa_family = a->family;
        ifa->ifa_prefixlen = a->prefixlen;
        ifa->ifa_flags = (uint8_t) (a->flags & 0xff);
        ifa->ifa_scope = a->scope;
        ifa->ifa_index = (unsigned) a->ifindex;

        r = nl_add_attr(&req, IFA_LOCAL, a->address.bytes, size);
        if (r < 0)
                return r;

        r = nl_add_attr(&req, IFA_ADDRESS, a->has_peer ? a->peer.bytes : a->address.bytes, size);
        if (r < 0)
                return r;

        if (a->family == AF_INET && !a->has_peer) {
                struct in_addr bcast;

                derive_broadcast(&a->address.in, a->prefixlen, &bcast);
                r = nl_add_attr(&req, IFA_BROADCAST, &bcast, sizeof(bcast));
                if (r < 0)
                        return r;
        }

        if (a->family == AF_INET && a->label && a->label[0] != '\0') {
                r = nl_add_attr(&req, IFA_LABEL, a->label, strlen(a->label) + 1);
                if (r < 0)
                        return r;
        }

        memset(&ci, 0, sizeof(ci));
        ci.ifa_prefered = a->preferred_sec;
        ci.ifa_valid = a->valid_sec;

        r = nl_add_attr(&req, IFA_CACHEINFO, &ci, sizeof(ci));
        if (r < 0)
                return r;

        r = nl_add_attr(&req, IFA_RT_PRIORITY, &a->route_metric, sizeof(a->route_metric));
        if (r < 0)
                return r;

        if (a->flags != 0) {
                r = nl_add_attr(&req, IFA_FLAGS, &a->flags, sizeof(a->flags));
                if (r < 0)
                        return r;
        }

        return rtnl_execute(rtnl, &req);
}

int netd_rtnl_address_del(NetdRtnl *rtnl, const NetdRtnlAddress *a) {
        struct nl_request req;
        struct nlmsghdr *nlh;
        struct ifaddrmsg *ifa;
        size_t size;
        int r;

        if (!rtnl || !a || a->ifindex <= 0 || (a->family != AF_INET && a->family != AF_INET6) ||
            a->prefixlen > (a->family == AF_INET ? 32 : 128))
                return -EINVAL;

        size = a->family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);

        nlh = nl_req_init(&req, RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK);
        if (!nlh)
                return -ENOBUFS;

        ifa = nl_reserve(&req, sizeof(*ifa));
        if (!ifa)
                return -ENOBUFS;

        ifa->ifa_family = a->family;
        ifa->ifa_prefixlen = a->prefixlen;
        ifa->ifa_index = (unsigned) a->ifindex;

        r = nl_add_attr(&req, IFA_LOCAL, a->address.bytes, size);
        if (r < 0)
                return r;

        r = nl_add_attr(&req, IFA_ADDRESS, a->has_peer ? a->peer.bytes : a->address.bytes, size);
        if (r < 0)
                return r;

        return rtnl_execute(rtnl, &req);
}

static int build_route(struct nl_request *req, uint16_t type, uint16_t flags, const NetdRtnlRoute *rt) {
        size_t size = rt->family == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr);
        struct nlmsghdr *nlh;
        struct rtmsg *rtm;
        int r;

        if (rt->ifindex <= 0 || (rt->family != AF_INET && rt->family != AF_INET6) ||
            rt->dst_len > (rt->family == AF_INET ? 32 : 128))
                return -EINVAL;

        nlh = nl_req_init(req, type, flags);
        if (!nlh)
                return -ENOBUFS;

        rtm = nl_reserve(req, sizeof(*rtm));
        if (!rtm)
                return -ENOBUFS;

        rtm->rtm_family = rt->family;
        rtm->rtm_dst_len = rt->dst_len;
        rtm->rtm_src_len = 0;
        rtm->rtm_tos = 0;
        rtm->rtm_table = RT_TABLE_MAIN;
        rtm->rtm_protocol = rt->protocol ? rt->protocol : RTPROT_STATIC;
        rtm->rtm_scope = rt->family == AF_INET ? rt->scope : RT_SCOPE_UNIVERSE;
        rtm->rtm_type = RTN_UNICAST;
        rtm->rtm_flags = rt->flags;

        /* dst_len 0 is the default route: no RTA_DST at all, the kernel's own
         * convention. */
        if (rt->dst_len > 0) {
                r = nl_add_attr(req, RTA_DST, rt->dst.bytes, size);
                if (r < 0)
                        return r;
        }

        if (rt->has_gw) {
                r = nl_add_attr(req, RTA_GATEWAY, rt->gw.bytes, size);
                if (r < 0)
                        return r;
        }

        r = nl_add_attr(req, RTA_OIF, &rt->ifindex, sizeof(rt->ifindex));
        if (r < 0)
                return r;

        r = nl_add_attr(req, RTA_PRIORITY, &rt->metric, sizeof(rt->metric));
        if (r < 0)
                return r;

        if (rt->has_prefsrc)
                return nl_add_attr(req, RTA_PREFSRC, rt->prefsrc.bytes, size);

        return 0;
}

int netd_rtnl_route_add(NetdRtnl *rtnl, const NetdRtnlRoute *route) {
        struct nl_request req;
        int r;

        if (!rtnl || !route)
                return -EINVAL;

        r = build_route(&req, RTM_NEWROUTE, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_APPEND | NLM_F_ACK, route);
        if (r < 0)
                return r;

        return rtnl_execute(rtnl, &req);
}

int netd_rtnl_route_del(NetdRtnl *rtnl, const NetdRtnlRoute *route) {
        struct nl_request req;
        int r;

        if (!rtnl || !route)
                return -EINVAL;

        r = build_route(&req, RTM_DELROUTE, NLM_F_REQUEST | NLM_F_ACK, route);
        if (r < 0)
                return r;

        return rtnl_execute(rtnl, &req);
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
