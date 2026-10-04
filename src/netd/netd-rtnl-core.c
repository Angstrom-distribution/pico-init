/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The low-level rtnetlink plumbing shared by netd-rtnl.c and netctl-rtnl.c.
 * See netd-rtnl-core.h for why this is a separate file and what it
 * deliberately does not do (log, or depend on anything outside kernel UAPI
 * headers and libc).
 *
 * Moved near-verbatim out of netd-rtnl.c; see that file's own banner for the
 * ALIGNMENT and nl_recv() oversized-datagram reasoning, unchanged by the
 * move.
 */

#include "netd-rtnl-core.h"

#include <errno.h>
#include <linux/if_link.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Not every kernel header in the wild carries these (added for
 * NETLINK_EXT_ACK, Linux 4.12) -- cheap insurance, same as netd-rtnl.c. */
#ifndef NLM_F_CAPPED
#        define NLM_F_CAPPED 0x100
#endif
#ifndef NLM_F_ACK_TLVS
#        define NLM_F_ACK_TLVS 0x200
#endif
#ifndef NLMSGERR_ATTR_MSG
#        define NLMSGERR_ATTR_MSG 1
#endif

/* Best-effort SO_RCVBUF on the request socket -- see netd-rtnl.c's
 * NETD_RTNL_RCVBUF comment; not load-bearing, only reduces retries. */
#define NL_SOCK_RCVBUF (1 << 20)

/* --- request construction --- */

void *nl_reserve(struct nl_request *req, size_t len) {
        size_t aligned = NLMSG_ALIGN(len);
        void *ptr;

        if (aligned > sizeof(req->buf) - req->len)
                return NULL;

        ptr = req->buf + req->len;
        memset(ptr, 0, aligned);
        req->len += aligned;
        return ptr;
}

struct nlmsghdr *nl_req_init(struct nl_request *req, uint16_t type, uint16_t flags) {
        struct nlmsghdr *nlh;

        req->len = 0;
        nlh = nl_reserve(req, sizeof(struct nlmsghdr));
        if (!nlh)
                return NULL;

        nlh->nlmsg_type = type;
        nlh->nlmsg_flags = flags;
        /* nlmsg_len/seq/pid are filled in by nl_finish_and_send(). */
        return nlh;
}

int nl_add_attr(struct nl_request *req, unsigned short type, const void *data, size_t datalen) {
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

/* --- socket lifecycle --- */

int nl_sock_open(NlSock *sock, bool subscribe_link_group) {
        int fd, one = 1, rcvbuf = NL_SOCK_RCVBUF, e;
        struct sockaddr_nl addr;
        struct sockaddr_nl local;
        socklen_t local_len = sizeof(local);

        if (!sock)
                return -EINVAL;

        memset(sock, 0, sizeof(*sock));
        sock->fd = -1;

        fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0)
                return -errno;

        if (setsockopt(fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one)) < 0) {
                e = errno;
                goto fail;
        }

        /* Best-effort: see NL_SOCK_RCVBUF's comment. */
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

        /* Best-effort: an unset pid (0) still works, see netd-rtnl.c's
         * netd_rtnl_new() comment on the same getsockname() call. */
        if (getsockname(fd, (struct sockaddr *) &local, &local_len) == 0)
                sock->pid = local.nl_pid;

        sock->fd = fd;
        return 0;

fail:
        (void) close(fd);
        return -e;
}

void nl_sock_close(NlSock *sock) {
        if (!sock || sock->fd < 0)
                return;

        (void) close(sock->fd);
        sock->fd = -1;
}

/* --- socket-level send/receive --- */

ssize_t nl_recv(int fd, bool nonblock, union nl_recv_buf *rb) {
        int flags = MSG_TRUNC | (nonblock ? MSG_DONTWAIT : 0);
        ssize_t len;

        for (;;) {
                len = recv(fd, rb->buf, NL_RECV_BUFSZ, flags);
                if (len < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                break;
        }

        /* See netd-rtnl.c's nl_recv() doc: an oversized datagram has already
         * been dequeued (and truncated) by the kernel by the time MSG_TRUNC
         * reveals it -- reported as -ENOBUFS, the same code a genuine
         * receive-queue overrun uses, so callers retry/resync identically.
         * This layer does not log it; netd-rtnl.c's own wrapper does. */
        if (len > NL_RECV_BUFSZ)
                return -ENOBUFS;

        return len;
}

int nl_finish_and_send(NlSock *sock, struct nl_request *req, uint32_t *ret_seq) {
        struct sockaddr_nl kernel;
        ssize_t n;

        req->hdr.nlmsg_len = (uint32_t) req->len;
        req->hdr.nlmsg_pid = sock->pid;
        req->hdr.nlmsg_seq = ++sock->seq;

        *ret_seq = req->hdr.nlmsg_seq;

        memset(&kernel, 0, sizeof(kernel));
        kernel.nl_family = AF_NETLINK;

        do {
                n = sendto(sock->fd, req->buf, req->len, 0, (struct sockaddr *) &kernel, sizeof(kernel));
        } while (n < 0 && errno == EINTR);

        return n < 0 ? -errno : 0;
}

/* --- NLMSG_ERROR / extended-ACK decoding --- */

int nl_parse_ext_ack(const struct nlmsghdr *nlh, const struct nlmsgerr *err, char *msgbuf, size_t msgbuf_len) {
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

int nl_parse_error(const struct nlmsghdr *nlh, char *errbuf, size_t errbuf_len) {
        const struct nlmsgerr *err;
        int error;

        if (errbuf && errbuf_len)
                errbuf[0] = '\0';

        if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(*err)))
                return -EBADMSG;

        err = (const struct nlmsgerr *) NLMSG_DATA(nlh);
        error = err->error;

        if (error != 0 && errbuf && errbuf_len && (nlh->nlmsg_flags & NLM_F_ACK_TLVS))
                (void) nl_parse_ext_ack(nlh, err, errbuf, errbuf_len);

        return error;
}

int nl_execute(NlSock *sock, struct nl_request *req, char *errbuf, size_t errbuf_len) {
        uint32_t seq;
        int r;

        r = nl_finish_and_send(sock, req, &seq);
        if (r < 0)
                return r;

        for (;;) {
                union nl_recv_buf rb;
                ssize_t len;
                struct nlmsghdr *m;
                int rem;

                len = nl_recv(sock->fd, false, &rb);
                if (len < 0)
                        return (int) len;
                if (len == 0)
                        return -EIO;

                m = (struct nlmsghdr *) rb.buf;
                rem = (int) len;

                /* int rem, NLMSG_OK sign-compare: see netd-rtnl.c's
                 * nl_execute() comment -- unchanged by the move. */
                for (; NLMSG_OK(m, rem); m = NLMSG_NEXT(m, rem)) {
                        if (m->nlmsg_seq != seq)
                                continue;

                        if (m->nlmsg_type != NLMSG_ERROR)
                                continue;

                        return nl_parse_error(m, errbuf, errbuf_len);
                }
        }
}

/* --- attribute reading --- */

const struct rtattr *rtattr_find(const struct rtattr *first, int rem, uint16_t type) {
        const struct rtattr *rta = first;

        for (; RTA_OK(rta, rem); rta = RTA_NEXT(rta, rem))
                if (rta->rta_type == type)
                        return rta;

        return NULL;
}

bool rtattr_get_u8(const struct rtattr *first, int rem, uint16_t type, uint8_t *out) {
        const struct rtattr *rta = rtattr_find(first, rem, type);

        if (!rta || RTA_PAYLOAD(rta) < sizeof(uint8_t))
                return false;

        memcpy(out, RTA_DATA(rta), sizeof(*out));
        return true;
}

bool rtattr_get_u16(const struct rtattr *first, int rem, uint16_t type, uint16_t *out) {
        const struct rtattr *rta = rtattr_find(first, rem, type);

        if (!rta || RTA_PAYLOAD(rta) < sizeof(uint16_t))
                return false;

        memcpy(out, RTA_DATA(rta), sizeof(*out));
        return true;
}

bool rtattr_get_u32(const struct rtattr *first, int rem, uint16_t type, uint32_t *out) {
        const struct rtattr *rta = rtattr_find(first, rem, type);

        if (!rta || RTA_PAYLOAD(rta) < sizeof(uint32_t))
                return false;

        memcpy(out, RTA_DATA(rta), sizeof(*out));
        return true;
}

bool rtattr_get_string(const struct rtattr *first, int rem, uint16_t type, char *out, size_t bufsize) {
        const struct rtattr *rta = rtattr_find(first, rem, type);
        size_t n;

        if (!rta || bufsize == 0)
                return false;

        n = RTA_PAYLOAD(rta);
        if (n >= bufsize)
                n = bufsize - 1;

        memcpy(out, RTA_DATA(rta), n);
        out[n] = '\0';
        return true;
}

bool rtattr_enter(const struct rtattr *first, int rem, uint16_t type, const struct rtattr **nested, int *nested_rem) {
        const struct rtattr *rta = rtattr_find(first, rem, type);

        if (!rta)
                return false;

        *nested = (const struct rtattr *) RTA_DATA(rta);
        *nested_rem = (int) RTA_PAYLOAD(rta);
        return true;
}
