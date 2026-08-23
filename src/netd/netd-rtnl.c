/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The hand-rolled rtnetlink layer. New code -- sd-netlink is read as a design
 * reference and nothing is copied from it, which is why this file is
 * GPL-2.0-or-later like the rest of netd's own source. See netd-rtnl.h for
 * why it is hand-rolled and why there are two sockets.
 *
 * N1: link enumerate/match, RTM_NEWLINK/DELLINK subscription, link up/down,
 * RTM_NEWADDR/DELADDR, RTM_NEWROUTE/DELROUTE including a default route.
 *
 * ALIGNMENT. Every multi-byte field this file reads off a socket is reached
 * through NLMSG_DATA()/RTA_DATA() on a message walked with NLMSG_OK()/
 * NLMSG_NEXT() and RTA_OK()/RTA_NEXT() -- never by hand-adding offsets -- so
 * every pointer this file dereferences is 4-byte aligned by construction of
 * the netlink framing itself (NLMSG_ALIGN/RTA_ALIGN round every message and
 * every attribute up to a 4-byte boundary, and the receive buffer is
 * malloc()'d, which is more aligned than that floor requires). Fixed-offset
 * struct field access (struct ifinfomsg, struct nlmsgerr) is therefore safe
 * without a copy. Attribute *payloads* of unpredictable length (an
 * interface name, a hardware address) are still copied byte-wise with
 * memcpy() rather than cast-and-dereferenced, because their length is
 * kernel-supplied and reading past what RTA_PAYLOAD() actually reports would
 * be the real bug, alignment aside. On ARMv5TE a stray unaligned word load
 * does not fault, it rotates -- so a mistake here would not crash, it would
 * silently hand netd the wrong ifindex or address. Every message loop below
 * is bounds-checked with NLMSG_OK/RTA_OK, and no attribute array is ever
 * indexed by a kernel-supplied rta_type -- dispatch is a switch, not a table.
 */

#include "netd-rtnl.h"

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
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

/* Not every kernel header in the wild carries these (added for
 * NETLINK_EXT_ACK, Linux 4.12) -- cheap insurance rather than a hard
 * dependency on a specific header vintage. */
#ifndef NLM_F_CAPPED
#        define NLM_F_CAPPED 0x100
#endif
#ifndef NLM_F_ACK_TLVS
#        define NLM_F_ACK_TLVS 0x200
#endif
#ifndef NLMSGERR_ATTR_MSG
#        define NLMSGERR_ATTR_MSG 1
#endif

/* Every request this file builds is small and fixed-shape (an ifinfomsg or
 * ifaddrmsg or rtmsg plus a handful of address-sized attributes); 512 bytes
 * is generous headroom over the largest of them, not a tight fit. */
#define NL_REQUEST_BUFSZ 512

/* Best-effort SO_RCVBUF on the request socket, so a link dump on a busy
 * machine is less likely to overrun. Not load-bearing: the receive path
 * below sizes its buffer per-datagram via MSG_PEEK|MSG_TRUNC, so it never
 * loses data to a buffer that guessed too small -- this only reduces how
 * often ENOBUFS forces a whole dump to be retried. */
#define NETD_RTNL_RCVBUF (1 << 20)

/* A dump interrupted mid-flight (ENOBUFS, or NLM_F_DUMP_INTR on the closing
 * NLMSG_DONE) is retried from scratch rather than reported: a partially
 * observed link table is worse than a slow one. Bounded so a pathologically
 * busy machine fails loudly instead of looping forever. */
#define NETD_RTNL_DUMP_MAX_RETRIES 5

struct NetdRtnl {
        int req_fd;   /* private: synchronous request -> ACK only */
        int event_fd; /* subscribed to RTNLGRP_LINK; the only fd netd polls */

        uint32_t req_pid;
        uint32_t req_seq;

        netd_rtnl_link_handler_t link_handler;
        void *link_userdata;

        /* ifindexes already reported through the handler, so a live
         * RTM_NEWLINK can be told apart from a first sighting (ADDED) versus
         * an update to something already known (CHANGED) -- see
         * netd-rtnl.h's comment on netd_rtnl_link_handler_t. */
        int *known;
        size_t n_known;
        size_t known_cap;
};

/* --- request message construction --- */

/*
 * A netlink request under construction. The union guarantees `hdr` and `buf`
 * start at the same, correctly-aligned address without relying on `len`'s
 * incidental alignment to do it -- see the file banner.
 */
struct nl_request {
        union {
                struct nlmsghdr hdr;
                uint8_t buf[NL_REQUEST_BUFSZ];
        };
        size_t len;
};

/* Reserve `len` bytes at the end of the message, NLMSG_ALIGNed and
 * zero-filled (so any padding bytes the kernel sees are well-defined rather
 * than stack garbage). NULL on overflow. */
static void *nl_reserve(struct nl_request *req, size_t len) {
        size_t aligned = NLMSG_ALIGN(len);
        void *ptr;

        if (aligned > sizeof(req->buf) - req->len)
                return NULL;

        ptr = req->buf + req->len;
        memset(ptr, 0, aligned);
        req->len += aligned;
        return ptr;
}

static struct nlmsghdr *nl_req_init(struct nl_request *req, uint16_t type, uint16_t flags) {
        struct nlmsghdr *nlh;

        req->len = 0;
        nlh = nl_reserve(req, sizeof(struct nlmsghdr));
        if (!nlh)
                return NULL;

        nlh->nlmsg_type = type;
        nlh->nlmsg_flags = flags;
        /* nlmsg_len/seq/pid are filled in by nl_finish_and_send(), once the
         * caller is done appending the payload and attributes. */
        return nlh;
}

/* Append one rtattr, RTA_ALIGNed and zero-padded. -ENOBUFS on overflow. */
static int nl_add_attr(struct nl_request *req, unsigned short type, const void *data, size_t datalen) {
        struct rtattr *rta;
        size_t rtalen = RTA_LENGTH(datalen);
        size_t total = RTA_ALIGN(rtalen);
        size_t pad;

        if (total > sizeof(req->buf) - req->len)
                return -ENOBUFS;

        rta = (struct rtattr *) (req->buf + req->len);
        rta->rta_type = type;
        rta->rta_len = (unsigned short) rtalen;

        if (datalen)
                memcpy(RTA_DATA(rta), data, datalen);

        pad = total - rtalen;
        if (pad)
                memset(req->buf + req->len + rtalen, 0, pad);

        req->len += total;
        return 0;
}

/* --- socket-level send/receive --- */

static int nl_send(int fd, const void *buf, size_t len) {
        struct sockaddr_nl kernel;
        ssize_t n;

        memset(&kernel, 0, sizeof(kernel));
        kernel.nl_family = AF_NETLINK;

        do {
                n = sendto(fd, buf, len, 0, (struct sockaddr *) &kernel, sizeof(kernel));
        } while (n < 0 && errno == EINTR);

        return n < 0 ? -errno : 0;
}

/*
 * Allocate exactly as much as the next pending datagram needs (via
 * MSG_PEEK|MSG_TRUNC) and read it in whole, so a message is never silently
 * truncated by a fixed-size guess. *ret_buf is malloc()'d and owned by the
 * caller on a non-negative return; left untouched otherwise.
 *
 * Returns the message length (>= 0), or -errno -- including -EAGAIN when
 * `nonblock` and nothing is pending, and -ENOBUFS when the kernel reports the
 * socket's receive queue overran (from either the peek or the real read).
 */
static ssize_t nl_recv_alloc(int fd, bool nonblock, uint8_t **ret_buf) {
        int peek_flags = MSG_PEEK | MSG_TRUNC | (nonblock ? MSG_DONTWAIT : 0);
        int flags = nonblock ? MSG_DONTWAIT : 0;
        ssize_t len;
        uint8_t *buf;

        for (;;) {
                len = recv(fd, NULL, 0, peek_flags);
                if (len < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                break;
        }

        if (len == 0) {
                *ret_buf = NULL;
                return 0;
        }

        if (len > INT_MAX)
                return -EMSGSIZE;

        buf = malloc((size_t) len);
        if (!buf)
                return -ENOMEM;

        for (;;) {
                ssize_t n = recv(fd, buf, (size_t) len, flags);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        free(buf);
                        return -errno;
                }

                len = n;
                break;
        }

        *ret_buf = buf;
        return len;
}

static int nl_finish_and_send(NetdRtnl *rtnl, struct nl_request *req, uint32_t *ret_seq) {
        req->hdr.nlmsg_len = (uint32_t) req->len;
        req->hdr.nlmsg_pid = rtnl->req_pid;
        req->hdr.nlmsg_seq = ++rtnl->req_seq;

        *ret_seq = req->hdr.nlmsg_seq;

        return nl_send(rtnl->req_fd, req->buf, req->len);
}

/* --- NLMSG_ERROR / extended-ACK decoding --- */

/*
 * The TLV attributes after a struct nlmsgerr are preceded by an echo of the
 * failing request -- just its header if NLM_F_CAPPED, header-plus-payload
 * otherwise -- so the TLVs start at a variable offset that has to be computed
 * from what the kernel actually says it echoed, not assumed. `total` is the
 * bounds of the whole NLMSG_ERROR message (already validated by the caller's
 * NLMSG_OK); `off` is checked against it before anything is read from there.
 */
static int nl_parse_ext_ack(
                const struct nlmsghdr *nlh, const struct nlmsgerr *err, char *msgbuf, size_t msgbuf_len) {
        size_t total = nlh->nlmsg_len;
        size_t off = NLMSG_LENGTH(sizeof(*err));
        const struct rtattr *rta;
        int rem;

        if (!(nlh->nlmsg_flags & NLM_F_CAPPED) && err->msg.nlmsg_len >= sizeof(struct nlmsghdr))
                off += NLMSG_ALIGN(err->msg.nlmsg_len) - sizeof(struct nlmsghdr);

        if (off > total)
                return -EBADMSG;

        rta = (const struct rtattr *) ((const uint8_t *) nlh + off);
        rem = (int) (total - off);

        for (; RTA_OK(rta, rem); rta = RTA_NEXT(rta, rem)) {
                if (rta->rta_type == NLMSGERR_ATTR_MSG) {
                        size_t n = RTA_PAYLOAD(rta);

                        if (n >= msgbuf_len)
                                n = msgbuf_len - 1;
                        memcpy(msgbuf, RTA_DATA(rta), n);
                        msgbuf[n] = '\0';
                        return 0;
                }
        }

        return -ENOENT;
}

/* Decode one NLMSG_ERROR message. Returns the kernel's own -errno (0 for a
 * plain ACK), logging the extended-ACK string when the kernel provided one --
 * this is the whole reason a bare -EINVAL becomes a real diagnostic. */
static int nl_parse_error(const struct nlmsghdr *nlh) {
        const struct nlmsgerr *err;
        int error;

        if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
                return -EBADMSG;

        err = (const struct nlmsgerr *) NLMSG_DATA(nlh);
        error = err->error;

        if (error != 0 && (nlh->nlmsg_flags & NLM_F_ACK_TLVS)) {
                char msg[256];

                if (nl_parse_ext_ack(nlh, err, msg, sizeof(msg)) == 0)
                        pico_log(PICO_LOG_WARNING, "netd: rtnl: kernel: %s (%s)", msg, strerror(-error));
        }

        return error;
}

static int nl_execute(NetdRtnl *rtnl, struct nl_request *req) {
        uint32_t seq;
        int r;

        r = nl_finish_and_send(rtnl, req, &seq);
        if (r < 0)
                return r;

        for (;;) {
                uint8_t *buf = NULL;
                ssize_t len;
                struct nlmsghdr *m;
                int rem;

                len = nl_recv_alloc(rtnl->req_fd, false, &buf);
                if (len < 0)
                        return (int) len;
                if (len == 0)
                        return -EIO;

                m = (struct nlmsghdr *) buf;
                rem = (int) len;

                /*
                 * rem stays int -- NLMSG_NEXT subtracts from it, and the
                 * kernel's own iteration idiom needs that to go negative on a
                 * truncated tail. clang's sign-compare inside NLMSG_OK is a
                 * false positive: the macro's first clause has already
                 * established rem >= sizeof(struct nlmsghdr) before the
                 * unsigned comparison, so the promotion is value-preserving.
                 * gcc suppresses it as system-header-originated; clang blames
                 * the expansion site. Same at the loops in
                 * netd_rtnl_enumerate_links() and netd_rtnl_process().
                 */
                for (; NLMSG_OK(m, rem); m = NLMSG_NEXT(m, rem)) {
                        int result;

                        if (m->nlmsg_seq != seq)
                                continue;

                        if (m->nlmsg_type != NLMSG_ERROR) {
                                pico_log(PICO_LOG_DEBUG,
                                         "netd: rtnl: unexpected reply type %u to seq %u",
                                         m->nlmsg_type,
                                         seq);
                                continue;
                        }

                        result = nl_parse_error(m);
                        free(buf);
                        return result;
                }

                free(buf);
        }
}

/* --- RTM_(NEW|DEL)LINK parsing --- */

/*
 * Decode one RTM_NEWLINK/RTM_DELLINK into a snapshot. `nlh` must already have
 * passed NLMSG_OK against the caller's remaining buffer length, so
 * nlh->nlmsg_len is trustworthy as the real extent of this message.
 */
static int nl_parse_link(const struct nlmsghdr *nlh, NetdRtnlLink *out) {
        const struct ifinfomsg *ifi;
        const struct rtattr *rta;
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

        for (; RTA_OK(rta, rem); rta = RTA_NEXT(rta, rem)) {
                size_t n;

                switch (rta->rta_type) {

                case IFLA_IFNAME:
                        n = RTA_PAYLOAD(rta);
                        if (n == 0)
                                break;
                        if (n >= sizeof(out->ifname))
                                n = sizeof(out->ifname) - 1;
                        memcpy(out->ifname, RTA_DATA(rta), n);
                        out->ifname[n] = '\0';
                        break;

                case IFLA_ADDRESS:
                        n = RTA_PAYLOAD(rta);
                        if (n > NETD_HW_ADDR_MAX)
                                n = NETD_HW_ADDR_MAX;
                        memcpy(out->hw_addr, RTA_DATA(rta), n);
                        out->hw_addr_len = n;
                        break;

                case IFLA_MTU:
                        if (RTA_PAYLOAD(rta) >= sizeof(uint32_t))
                                memcpy(&out->mtu, RTA_DATA(rta), sizeof(out->mtu));
                        break;

                default:
                        break;
                }
        }

        return 0;
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

static int nl_socket_open(bool subscribe_link_group) {
        int fd, one = 1, rcvbuf = NETD_RTNL_RCVBUF, e;
        struct sockaddr_nl addr;

        fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0)
                return -errno;

        if (setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one)) < 0) {
                e = errno;
                goto fail;
        }

        /* Best-effort: see NETD_RTNL_RCVBUF's comment. */
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

        memset(&addr, 0, sizeof(addr));
        addr.nl_family = AF_NETLINK;

        if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
                e = errno;
                goto fail;
        }

        if (subscribe_link_group) {
                int group = RTNLGRP_LINK;

                if (setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
                        e = errno;
                        goto fail;
                }
        }

        return fd;

fail:
        (void) close(fd);
        return -e;
}

int netd_rtnl_new(NetdRtnl **ret) {
        NetdRtnl *rtnl;
        struct sockaddr_nl local;
        socklen_t local_len = sizeof(local);
        int r;

        if (!ret)
                return -EINVAL;

        rtnl = calloc(1, sizeof(*rtnl));
        if (!rtnl)
                return -ENOMEM;

        rtnl->req_fd = -1;
        rtnl->event_fd = -1;

        r = nl_socket_open(false);
        if (r < 0)
                goto fail;
        rtnl->req_fd = r;

        /* Best-effort: an unset req_pid (0) still works, the kernel does not
         * require the requester's own port id back in nlmsg_pid to route an
         * ACK on a connected/bound socket -- this just matches convention. */
        if (getsockname(rtnl->req_fd, (struct sockaddr *) &local, &local_len) == 0)
                rtnl->req_pid = local.nl_pid;

        r = nl_socket_open(true);
        if (r < 0)
                goto fail;
        rtnl->event_fd = r;

        *ret = rtnl;
        return 0;

fail:
        netd_rtnl_free(rtnl);
        return r;
}

NetdRtnl *netd_rtnl_free(NetdRtnl *rtnl) {
        if (!rtnl)
                return NULL;

        if (rtnl->req_fd >= 0)
                (void) close(rtnl->req_fd);
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

/* --- reading --- */

int netd_rtnl_enumerate_links(NetdRtnl *rtnl) {
        int attempt;

        if (!rtnl)
                return -EINVAL;

        for (attempt = 0; attempt < NETD_RTNL_DUMP_MAX_RETRIES; attempt++) {
                struct nl_request req;
                struct nlmsghdr *nlh;
                struct ifinfomsg *ifi;
                uint32_t seq;
                int count = 0;
                bool retry = false;
                bool done = false;
                int r;

                nlh = nl_req_init(&req, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP);
                if (!nlh)
                        return -ENOBUFS;

                ifi = nl_reserve(&req, sizeof(*ifi));
                if (!ifi)
                        return -ENOBUFS;
                ifi->ifi_family = AF_UNSPEC;

                r = nl_finish_and_send(rtnl, &req, &seq);
                if (r < 0)
                        return r;

                while (!done) {
                        uint8_t *buf = NULL;
                        ssize_t len;
                        struct nlmsghdr *m;
                        int rem;

                        len = nl_recv_alloc(rtnl->req_fd, false, &buf);
                        if (len == -ENOBUFS) {
                                retry = true;
                                break;
                        }
                        if (len < 0)
                                return (int) len;
                        if (len == 0)
                                return -EIO;

                        m = (struct nlmsghdr *) buf;
                        rem = (int) len;

                        /* int rem, NLMSG_OK sign-compare: see nl_execute(). */
                        for (; NLMSG_OK(m, rem); m = NLMSG_NEXT(m, rem)) {
                                if (m->nlmsg_seq != seq)
                                        continue;

                                if (m->nlmsg_type == NLMSG_ERROR) {
                                        r = nl_parse_error(m);
                                        free(buf);
                                        return r;
                                }

                                if (m->nlmsg_type == NLMSG_DONE) {
                                        if (m->nlmsg_flags & NLM_F_DUMP_INTR)
                                                retry = true;
                                        done = true;
                                        break;
                                }

                                if (m->nlmsg_type == RTM_NEWLINK) {
                                        dispatch_link(rtnl, m, true);
                                        count++;
                                }
                        }

                        free(buf);
                }

                if (retry)
                        continue;

                return count;
        }

        return -ENOBUFS;
}

int netd_rtnl_process(NetdRtnl *rtnl) {
        int dispatched = 0;

        if (!rtnl)
                return -EINVAL;

        for (;;) {
                uint8_t *buf = NULL;
                ssize_t len;
                struct nlmsghdr *m;
                int rem;

                len = nl_recv_alloc(rtnl->event_fd, true, &buf);
                if (len == -EAGAIN)
                        break;
                if (len < 0)
                        return (int) len; /* ENOBUFS included -- see netd-rtnl.h's contract */
                if (len == 0)
                        break;

                m = (struct nlmsghdr *) buf;
                rem = (int) len;

                /* int rem, NLMSG_OK sign-compare: see nl_execute(). */
                for (; NLMSG_OK(m, rem); m = NLMSG_NEXT(m, rem)) {
                        switch (m->nlmsg_type) {

                        case RTM_NEWLINK:
                        case RTM_DELLINK:
                                dispatch_link(rtnl, m, false);
                                dispatched++;
                                break;

                        case NLMSG_ERROR: {
                                int err = nl_parse_error(m);

                                pico_log(PICO_LOG_WARNING,
                                         "netd: rtnl: unexpected error message on event socket: %s",
                                         strerror(-err));
                                break;
                        }

                        default:
                                break;
                        }
                }

                free(buf);
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

        return nl_execute(rtnl, &req);
}

int netd_rtnl_link_up(NetdRtnl *rtnl, int ifindex) {
        return set_link_flags(rtnl, ifindex, IFF_UP, IFF_UP);
}

int netd_rtnl_link_down(NetdRtnl *rtnl, int ifindex) {
        return set_link_flags(rtnl, ifindex, 0, IFF_UP);
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

int netd_rtnl_address_add(
                NetdRtnl *rtnl,
                int ifindex,
                const struct in_addr *address,
                unsigned char prefixlen,
                const struct in_addr *broadcast,
                uint32_t lifetime_sec) {

        struct nl_request req;
        struct nlmsghdr *nlh;
        struct ifaddrmsg *ifa;
        struct in_addr bcast;
        struct ifa_cacheinfo ci;
        int r;

        if (!rtnl || ifindex <= 0 || !address || prefixlen > 32)
                return -EINVAL;

        nlh = nl_req_init(&req, RTM_NEWADDR, NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK);
        if (!nlh)
                return -ENOBUFS;

        ifa = nl_reserve(&req, sizeof(*ifa));
        if (!ifa)
                return -ENOBUFS;

        ifa->ifa_family = AF_INET;
        ifa->ifa_prefixlen = prefixlen;
        ifa->ifa_flags = 0;
        ifa->ifa_scope = 0;
        ifa->ifa_index = (unsigned) ifindex;

        r = nl_add_attr(&req, IFA_LOCAL, address, sizeof(*address));
        if (r < 0)
                return r;

        r = nl_add_attr(&req, IFA_ADDRESS, address, sizeof(*address));
        if (r < 0)
                return r;

        if (broadcast)
                bcast = *broadcast;
        else
                derive_broadcast(address, prefixlen, &bcast);

        r = nl_add_attr(&req, IFA_BROADCAST, &bcast, sizeof(bcast));
        if (r < 0)
                return r;

        /* UINT32_MAX passed straight through as ifa_valid/ifa_prefered is
         * already the kernel's own "forever" sentinel -- no special-casing
         * needed, per netd-rtnl.h. */
        memset(&ci, 0, sizeof(ci));
        ci.ifa_prefered = lifetime_sec;
        ci.ifa_valid = lifetime_sec;

        r = nl_add_attr(&req, IFA_CACHEINFO, &ci, sizeof(ci));
        if (r < 0)
                return r;

        return nl_execute(rtnl, &req);
}

int netd_rtnl_address_del(NetdRtnl *rtnl, int ifindex, const struct in_addr *address, unsigned char prefixlen) {
        struct nl_request req;
        struct nlmsghdr *nlh;
        struct ifaddrmsg *ifa;
        int r;

        if (!rtnl || ifindex <= 0 || !address || prefixlen > 32)
                return -EINVAL;

        nlh = nl_req_init(&req, RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK);
        if (!nlh)
                return -ENOBUFS;

        ifa = nl_reserve(&req, sizeof(*ifa));
        if (!ifa)
                return -ENOBUFS;

        ifa->ifa_family = AF_INET;
        ifa->ifa_prefixlen = prefixlen;
        ifa->ifa_index = (unsigned) ifindex;

        r = nl_add_attr(&req, IFA_LOCAL, address, sizeof(*address));
        if (r < 0)
                return r;

        r = nl_add_attr(&req, IFA_ADDRESS, address, sizeof(*address));
        if (r < 0)
                return r;

        return nl_execute(rtnl, &req);
}

static int
                build_route(struct nl_request *req,
                            uint16_t type,
                            uint16_t flags,
                            int ifindex,
                            const struct in_addr *destination,
                            unsigned char prefixlen,
                            const struct in_addr *gateway,
                            uint32_t metric) {

        struct nlmsghdr *nlh;
        struct rtmsg *rtm;
        int r;

        nlh = nl_req_init(req, type, flags);
        if (!nlh)
                return -ENOBUFS;

        rtm = nl_reserve(req, sizeof(*rtm));
        if (!rtm)
                return -ENOBUFS;

        rtm->rtm_family = AF_INET;
        rtm->rtm_dst_len = prefixlen;
        rtm->rtm_src_len = 0;
        rtm->rtm_tos = 0;
        rtm->rtm_table = RT_TABLE_MAIN;
        rtm->rtm_protocol = RTPROT_STATIC;
        rtm->rtm_scope = gateway ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
        rtm->rtm_type = RTN_UNICAST;
        rtm->rtm_flags = 0;

        /* prefixlen 0 is the default route: no RTA_DST at all, matching the
         * kernel's own convention (see netd_rtnl_route_add_default()). */
        if (prefixlen > 0) {
                r = nl_add_attr(req, RTA_DST, destination, sizeof(*destination));
                if (r < 0)
                        return r;
        }

        if (gateway) {
                r = nl_add_attr(req, RTA_GATEWAY, gateway, sizeof(*gateway));
                if (r < 0)
                        return r;
        }

        r = nl_add_attr(req, RTA_OIF, &ifindex, sizeof(ifindex));
        if (r < 0)
                return r;

        return nl_add_attr(req, RTA_PRIORITY, &metric, sizeof(metric));
}

int netd_rtnl_route_add(
                NetdRtnl *rtnl,
                int ifindex,
                const struct in_addr *destination,
                unsigned char prefixlen,
                const struct in_addr *gateway,
                uint32_t metric) {

        struct nl_request req;
        int r;

        if (!rtnl || ifindex <= 0 || prefixlen > 32 || (!destination && prefixlen != 0))
                return -EINVAL;

        r = build_route(&req,
                        RTM_NEWROUTE,
                        NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE | NLM_F_ACK,
                        ifindex,
                        destination,
                        prefixlen,
                        gateway,
                        metric);
        if (r < 0)
                return r;

        return nl_execute(rtnl, &req);
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

        struct nl_request req;
        int r;

        if (!rtnl || ifindex <= 0 || prefixlen > 32 || (!destination && prefixlen != 0))
                return -EINVAL;

        r = build_route(&req,
                        RTM_DELROUTE,
                        NLM_F_REQUEST | NLM_F_ACK,
                        ifindex,
                        destination,
                        prefixlen,
                        gateway,
                        metric);
        if (r < 0)
                return r;

        return nl_execute(rtnl, &req);
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
