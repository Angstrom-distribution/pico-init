/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The low-level rtnetlink plumbing shared by netd-rtnl.c (netd's own policy
 * layer: link table, event dispatch, idempotent writers) and netctl-rtnl.c
 * (netctl's one-shot RTM_GETLINK client). Extracted so netctl can speak
 * rtnetlink for itself without linking netd_core/pico_init_core -- see
 * netctl.c's own header for why that link must not exist.
 *
 * Deliberately not logging anything: netd-rtnl.c logs through pico_log(),
 * which pulls in "../util.h" and, transitively, PID 1's own shared code --
 * exactly what netctl's build must not depend on. Every function here
 * reports failure as -errno (and, for the one path that decodes a kernel
 * explanation, an optional caller-supplied buffer) and leaves logging to
 * whichever caller can afford it.
 *
 * ALIGNMENT and error-decoding reasoning: see netd-rtnl.c's file banner,
 * unchanged by this split -- every rule there (NLMSG_OK/RTA_OK bounds
 * checking, no kernel-controlled dispatch table, MSG_TRUNC's one-syscall
 * sizing) still applies to the code that moved here.
 */

#pragma once

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* See netd-rtnl.c's file banner: every request this layer builds is small
 * and fixed-shape; 512 bytes is generous headroom, not a tight fit. */
#define NL_REQUEST_BUFSZ 512

/* Real rtnetlink traffic -- one event, one dump entry, or an ACK -- fits a
 * single page; see netd-rtnl.c's NL_RECV_BUFSZ comment for the full
 * reasoning (also governs nl_recv()'s oversized-datagram -ENOBUFS case). */
#define NL_RECV_BUFSZ 8192

/*
 * A netlink request under construction. The union guarantees `hdr` and `buf`
 * start at the same, correctly-aligned address -- see netd-rtnl.c's file
 * banner.
 */
struct nl_request {
        union {
                struct nlmsghdr hdr;
                uint8_t buf[NL_REQUEST_BUFSZ];
        };
        size_t len;
};

/* Storage for nl_recv(): see netd-rtnl.c's file banner for why this is a
 * union rather than a bare uint8_t[]. */
union nl_recv_buf {
        struct nlmsghdr hdr;
        uint8_t buf[NL_RECV_BUFSZ];
};

/* One request/ACK socket: req_fd plus the sequence/port-id bookkeeping
 * nl_finish_and_send() needs. netd-rtnl.c's NetdRtnl embeds one of these for
 * its own request socket; netctl-rtnl.c opens one per invocation. */
typedef struct NlSock {
        int fd;
        uint32_t pid;
        uint32_t seq;
} NlSock;

/* --- request construction --- */

/* Reserve `len` bytes at the end of the message, NLMSG_ALIGNed and
 * zero-filled. NULL on overflow. */
void *nl_reserve(struct nl_request *req, size_t len);

struct nlmsghdr *nl_req_init(struct nl_request *req, uint16_t type, uint16_t flags);

/* Append one rtattr, RTA_ALIGNed and zero-padded. -ENOBUFS on overflow. */
int nl_add_attr(struct nl_request *req, unsigned short type, const void *data, size_t datalen);

/* --- socket lifecycle --- */

/*
 * AF_NETLINK/NETLINK_ROUTE, NETLINK_EXT_ACK set, bound; joins RTNLGRP_LINK
 * when `subscribe_link_group`. 0 or -errno; *sock is zeroed first so a
 * failed open leaves it in a known (fd == -1) state.
 */
int nl_sock_open(NlSock *sock, bool subscribe_link_group);

/* Closes sock->fd if open; idempotent, leaves sock->fd == -1. */
void nl_sock_close(NlSock *sock);

/* --- socket-level send/receive --- */

/*
 * Read the next pending datagram into `rb->buf`. See netd-rtnl.c's nl_recv()
 * doc for the full MSG_TRUNC/one-syscall reasoning and why an oversized
 * datagram is reported as -ENOBUFS rather than retried bigger. Returns the
 * message length (>= 0), or -errno (including -EAGAIN when `nonblock`).
 */
ssize_t nl_recv(int fd, bool nonblock, union nl_recv_buf *rb);

/* Fills in nlmsg_len/pid/seq from `sock` and sends. *ret_seq gets the
 * sequence number used, for matching the reply. 0 or -errno. */
int nl_finish_and_send(NlSock *sock, struct nl_request *req, uint32_t *ret_seq);

/* --- NLMSG_ERROR / extended-ACK decoding --- */

/*
 * Decode the kernel's own explanation out of a NLMSGERR_ATTR_MSG TLV, if the
 * reply carried one. 0 with `msgbuf` filled, or -ENOENT/-EBADMSG. See
 * netd-rtnl.c's file banner for why the TLV offset has to be computed rather
 * than assumed.
 */
int nl_parse_ext_ack(const struct nlmsghdr *nlh, const struct nlmsgerr *err, char *msgbuf, size_t msgbuf_len);

/*
 * Decode one NLMSG_ERROR message: the kernel's own -errno (0 for a plain
 * ACK). When non-NULL and the kernel provided an extended-ACK string,
 * `errbuf` is filled with it (empty string otherwise) -- logging it, if at
 * all, is the caller's job, not this layer's.
 */
int nl_parse_error(const struct nlmsghdr *nlh, char *errbuf, size_t errbuf_len);

/*
 * Send `req` on `sock` and wait for its ACK/NLMSG_ERROR. 0 once the kernel
 * has acknowledged, or -errno decoded from the reply. `errbuf`/`errbuf_len`
 * as in nl_parse_error(); pass NULL/0 when the caller does not want the
 * string.
 */
int nl_execute(NlSock *sock, struct nl_request *req, char *errbuf, size_t errbuf_len);

/* --- attribute reading ---
 *
 * Generic typed getters over an already-bounds-checked attribute list
 * [first, rem) (the same RTA_OK/RTA_NEXT walk every caller already has to do
 * to get there). Each returns true and fills `out` on the first matching
 * attribute, false if none is present or the payload is too short to hold
 * the requested type -- never partially filling `out`.
 */

const struct rtattr *rtattr_find(const struct rtattr *first, int rem, uint16_t type);

bool rtattr_get_u8(const struct rtattr *first, int rem, uint16_t type, uint8_t *out);
bool rtattr_get_u16(const struct rtattr *first, int rem, uint16_t type, uint16_t *out);
bool rtattr_get_u32(const struct rtattr *first, int rem, uint16_t type, uint32_t *out);

/* NUL-terminates into `out` (bufsize-bounded), even when the kernel's own
 * attribute payload omits the trailing NUL (IFLA_IFNAME-style attributes do
 * not guarantee one). */
bool rtattr_get_string(const struct rtattr *first, int rem, uint16_t type, char *out, size_t bufsize);

/*
 * Finds a container attribute (IFLA_AF_SPEC, IFLA_PROP_LIST, ...) and points
 * `*nested`/`*nested_rem` at its payload, walkable with the kernel's own
 * RTA_OK()/RTA_NEXT() exactly like the top-level list. False if the
 * container attribute is absent.
 */
bool rtattr_enter(const struct rtattr *first, int rem, uint16_t type, const struct rtattr **nested, int *nested_rem);
