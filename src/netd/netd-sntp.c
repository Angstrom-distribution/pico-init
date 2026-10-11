/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * The SNTP client. See netd-sntp.h for the validation set that is kept and
 * the statistics machinery that is not.
 *
 * Derived from systemd v261.2 (commit 4925d9f07f), src/timesync/timesyncd-
 * manager.c's manager_send_request()/manager_receive_response()/
 * manager_adjust_clock() (packet build, the validation chain, the offset/
 * delay arithmetic of RFC 5905 §8) and timesyncd-ntp-message.h (the
 * TIME_EPOCH/OFFSET_1900_1970 epoch-floor constants). Neither carries a
 * per-file copyright line upstream, so this file follows the project-default
 * attribution.
 *
 * Upstream commits after that point that touch src/timesync do not apply:
 *
 *  - 98e7cc36f0 "timesyncd: resolve NTP hostnames through resolved's
 *    varlink interface": netd has no resolver; servers arrive as addresses.
 *  - 8027ff6ecd "timesyncd: don't ask for AAAA when IPv6 is disabled":
 *    follow-up to the above, same DNS path.
 *
 * Beyond the basic validation set, the short-packet reject and the epoch
 * floor are carried (manager_receive_response() in timesyncd-manager.c); see
 * NETD_SNTP_REJECT_MALFORMED and NETD_SNTP_REJECT_EPOCH in netd-sntp.h.
 *
 * Adapted rather than ported near-verbatim: no sd-event, no Manager object,
 * one server queried at a time, and no eight-sample spike/jitter detector or
 * adaptive poll-interval doubling (manager_adjust_poll()). The validation
 * chain follows the fixed order NetdSntpReject declares in netd-sntp.h
 * (pending-request correlation before the source-address compare, where
 * upstream checks source first); every check upstream performs is still here.
 */

#include "netd-sntp.h"

#include <endian.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../util.h"
#include "netd-time.h"
#include "netd.h"

/* --- wire-format helpers --- */

/* A 16.16 fixed-point NTP short timestamp (root delay / root dispersion),
 * RFC 5905 §7.3 -- half the width of NetdNtpTs, same shape otherwise. */
static usec_t ntp_ts_short_to_usec(const NetdNtpTsShort *ts) {
        uint32_t sec, frac;

        sec = be16toh(ts->sec);
        frac = be16toh(ts->frac);

        return (usec_t) sec * USEC_PER_SEC + (((usec_t) frac * USEC_PER_SEC) >> 16);
}

/* --- validation (pure) --- */

NetdSntpReject netd_sntp_validate(
                const void *packet, size_t size, const struct in_addr *source, const NetdSntpRequest *request) {
        const NetdNtpMsg *m;
        uint8_t leap, version, mode, stratum;
        uint64_t floor, recv_sec, trans_sec;
        usec_t root_distance;

        if (!packet || !source || !request)
                return NETD_SNTP_REJECT_MALFORMED;

        if (size < sizeof(NetdNtpMsg))
                return NETD_SNTP_REJECT_MALFORMED;

        if (!request->pending)
                return NETD_SNTP_REJECT_UNSOLICITED;

        if (source->s_addr != request->server.s_addr)
                return NETD_SNTP_REJECT_SOURCE;

        m = (const NetdNtpMsg *) packet;

        /* Anti-off-path-spoofing: the origin timestamp in the reply must be
         * the exact random nonce we sent, byte for byte -- it is never
         * interpreted as a time, so no byte-swap here on either side. */
        if (m->origin_time.sec != request->nonce.sec || m->origin_time.frac != request->nonce.frac)
                return NETD_SNTP_REJECT_NONCE;

        if (m->trans_time.sec == 0 && m->trans_time.frac == 0)
                return NETD_SNTP_REJECT_ZERO_TIMESTAMP;

        floor = (uint64_t) NETD_TIME_EPOCH_SEC + NETD_NTP_OFFSET_1900_1970;
        recv_sec = be32toh(m->recv_time.sec);
        trans_sec = be32toh(m->trans_time.sec);
        if (recv_sec < floor || trans_sec < floor)
                return NETD_SNTP_REJECT_EPOCH;

        leap = NETD_NTP_FIELD_LEAP(m->field);
        version = NETD_NTP_FIELD_VERSION(m->field);
        mode = NETD_NTP_FIELD_MODE(m->field);
        stratum = m->stratum;

        if (leap == NETD_NTP_LEAP_NOTINSYNC)
                return NETD_SNTP_REJECT_LEAP;

        if (stratum == 0 || stratum >= 16)
                return NETD_SNTP_REJECT_STRATUM;

        if (version != 3 && version != 4)
                return NETD_SNTP_REJECT_VERSION;

        if (mode != NETD_NTP_MODE_SERVER)
                return NETD_SNTP_REJECT_MODE;

        root_distance = ntp_ts_short_to_usec(&m->root_delay) / 2 + ntp_ts_short_to_usec(&m->root_dispersion);
        if (root_distance > NETD_SNTP_MAX_ROOT_DISTANCE_USEC)
                return NETD_SNTP_REJECT_ROOT_DISTANCE;

        return NETD_SNTP_ACCEPTED;
}

int netd_sntp_compute(
                const NetdNtpMsg *m,
                usec_t origin,
                usec_t dest,
                int64_t *ret_offset_usec,
                int64_t *ret_delay_usec) {
        int64_t t1, t2, t3, t4;

        if (!m || !ret_offset_usec || !ret_delay_usec)
                return -EINVAL;

        /*
         * RFC 5905 §8:
         *   t1 = origin (our send time, T1)   t2 = recv_time (T2)
         *   t3 = trans_time (T3)               t4 = dest (our receive time, T4)
         *   offset = ((T2 - T1) + (T3 - T4)) / 2
         *   delay  =  (T4 - T1) - (T3 - T2)
         */
        t1 = (int64_t) origin;
        t2 = (int64_t) netd_ntp_ts_to_usec(&m->recv_time);
        t3 = (int64_t) netd_ntp_ts_to_usec(&m->trans_time);
        t4 = (int64_t) dest;

        *ret_offset_usec = ((t2 - t1) + (t3 - t4)) / 2;
        *ret_delay_usec = (t4 - t1) - (t3 - t2);

        return 0;
}

usec_t netd_ntp_ts_to_usec(const NetdNtpTs *ts) {
        uint64_t sec, frac;

        if (!ts)
                return 0;

        sec = be32toh(ts->sec);
        frac = be32toh(ts->frac);

        if (sec < NETD_NTP_OFFSET_1900_1970)
                return 0;

        /* The fraction is 2^-32 seconds; scale to usec without losing the low
         * bits to an early divide. */
        return (usec_t) ((sec - NETD_NTP_OFFSET_1900_1970) * USEC_PER_SEC + (frac * USEC_PER_SEC >> 32));
}

void netd_ntp_ts_from_usec(NetdNtpTs *ts, usec_t usec) {
        uint64_t sec, frac;

        if (!ts)
                return;

        sec = usec / USEC_PER_SEC + NETD_NTP_OFFSET_1900_1970;
        frac = ((usec % USEC_PER_SEC) << 32) / USEC_PER_SEC;

        ts->sec = htobe32((uint32_t) sec);
        ts->frac = htobe32((uint32_t) frac);
}

static const char * const netd_sntp_reject_table[_NETD_SNTP_REJECT_MAX] = {
        [NETD_SNTP_ACCEPTED] = "accepted",
        [NETD_SNTP_REJECT_MALFORMED] = "malformed",
        [NETD_SNTP_REJECT_UNSOLICITED] = "unsolicited",
        [NETD_SNTP_REJECT_SOURCE] = "source address mismatch",
        [NETD_SNTP_REJECT_NONCE] = "origin timestamp mismatch",
        [NETD_SNTP_REJECT_ZERO_TIMESTAMP] = "zero transmit timestamp",
        [NETD_SNTP_REJECT_EPOCH] = "reply predates build epoch",
        [NETD_SNTP_REJECT_LEAP] = "server not synchronised",
        [NETD_SNTP_REJECT_STRATUM] = "bad stratum",
        [NETD_SNTP_REJECT_VERSION] = "unsupported version",
        [NETD_SNTP_REJECT_MODE] = "not a server reply",
        [NETD_SNTP_REJECT_ROOT_DISTANCE] = "root distance too large",
};

const char *netd_sntp_reject_to_string(NetdSntpReject r) {
        if (r < 0 || r >= _NETD_SNTP_REJECT_MAX)
                return "invalid";

        return netd_sntp_reject_table[r];
}

/* --- the client itself --- */

/* Forward declarations: sntp_send_request() arms the timer that fires
 * netd_sntp_timer_fired(), which sends the next request -- a three-way cycle
 * that needs a break somewhere in C's single-pass declaration order. */
static int sntp_send_request(NetdSntp *s);
static int sntp_arm_timer(NetdSntp *s, usec_t interval);
static void netd_sntp_timer_fired(void *userdata, usec_t t);

static int netd_sntp_io_callback(Netd *n, struct netd_epoll_tag *tag, uint32_t revents) {
        NetdSntp *s = tag->userdata;

        (void) n;
        (void) revents;

        return netd_sntp_process(s);
}

/* Fill `ts` with 8 random bytes, used as-is: the nonce is never a time, so it
 * has no byte-order and needs no conversion on either side. */
static int sntp_random_nonce(NetdNtpTs *ts) {
        ssize_t n;

        n = getrandom(ts, sizeof(*ts), 0);
        if (n < 0)
                return -errno;
        if ((size_t) n != sizeof(*ts))
                return -EIO;

        return 0;
}

/* Cancel any outstanding timer_event and queue a new one -- never call
 * pico_timer_add() on a handle that might already hold an event (timer.h):
 * the old event would stay queued with its owner_ref pointed at the same
 * slot, and firing it later would clobber the new event's handle. */
static int sntp_arm_timer(NetdSntp *s, usec_t interval) {
        if (s->timer_event)
                (void) pico_timer_cancel(s->netd->timer, s->timer_event);

        return pico_timer_add(
                        s->netd->timer,
                        usec_add(now_monotonic(), interval),
                        netd_sntp_timer_fired,
                        s,
                        &s->timer_event);
}

/* Build and send one client-mode request to the current round-robin server,
 * record the pending request, and arm the retry timer -- the same operation
 * whether this is the very first query, a scheduled resync, or a retry after
 * no reply arrived in time. */
static int sntp_send_request(NetdSntp *s) {
        NetdNtpMsg msg = { 0 };
        struct sockaddr_in dest = { 0 };
        struct timespec ts;
        ssize_t len;
        int r;

        if (s->n_servers == 0)
                return 0;

        msg.field = NETD_NTP_FIELD(0, 4, NETD_NTP_MODE_CLIENT);

        r = sntp_random_nonce(&msg.trans_time);
        if (r < 0)
                return r;

        s->request.pending = true;
        s->request.server = s->servers[s->next_server];
        s->request.nonce = msg.trans_time;

        if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
                return -errno;
        s->request.origin = (usec_t) ts.tv_sec * USEC_PER_SEC + (usec_t) ts.tv_nsec / 1000;
        s->request.sent_at = now_monotonic();

        dest.sin_family = AF_INET;
        dest.sin_port = htons(NETD_NTP_PORT);
        dest.sin_addr = s->request.server;

        len = sendto(s->fd, &msg, sizeof(msg), 0, (const struct sockaddr *) &dest, sizeof(dest));
        if (len < 0)
                r = -errno;
        else if ((size_t) len != sizeof(msg))
                r = -EIO;
        else
                r = 0;

        s->next_server = (s->next_server + 1) % s->n_servers;

        /* Arm the retry regardless of the send outcome: a transient sendto()
         * failure should not stop the client forever, and there is nothing
         * more useful to do with the error than return it. */
        (void) sntp_arm_timer(s, NETD_SNTP_RETRY_USEC);

        return r;
}

static void netd_sntp_timer_fired(void *userdata, usec_t t) {
        NetdSntp *s = userdata;

        (void) t;

        /* timer.h: the handle is already cleared by the queue before this
         * runs, so sntp_arm_timer()'s "cancel if non-NULL" check is correct
         * on the very next call from here without an explicit clear. */
        (void) sntp_send_request(s);
}

int netd_sntp_new(Netd *n, NetdSntp **ret) {
        NetdSntp *s;
        int fd, one = 1, r;
        struct sockaddr_in any = { 0 };

        if (!n || !ret)
                return -EINVAL;

        s = calloc(1, sizeof(*s));
        if (!s)
                return -ENOMEM;

        s->netd = n;
        s->fd = -1;
        /* calloc() leaves tag.fd at 0, a valid descriptor number; -1 means
         * "none yet". */
        s->tag.fd = -1;

        fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) {
                r = -errno;
                goto fail;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPNS, &one, sizeof(one)) < 0) {
                r = -errno;
                close(fd);
                goto fail;
        }

        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(fd, (const struct sockaddr *) &any, sizeof(any)) < 0) {
                r = -errno;
                close(fd);
                goto fail;
        }

        s->fd = fd;

        r = netd_loop_add_io(n, &s->tag, fd, EPOLLIN, NETD_EPOLL_SNTP, netd_sntp_io_callback, s);
        if (r < 0) {
                close(fd);
                goto fail;
        }

        *ret = s;
        return 0;

fail:
        free(s);
        return r;
}

NetdSntp *netd_sntp_free(NetdSntp *s) {
        if (!s)
                return NULL;

        if (s->timer_event)
                (void) pico_timer_cancel(s->netd->timer, s->timer_event);

        /* Deregister before closing (netd-loop.h): a still-armed epoll entry
         * must never outlive the fd number it names. */
        (void) netd_loop_remove_io(s->netd, &s->tag);

        if (s->fd >= 0)
                (void) close(s->fd);

        free(s);
        return NULL;
}

int netd_sntp_set_servers(NetdSntp *s, const struct in_addr *servers, size_t n) {
        if (!s)
                return -EINVAL;
        if (n > 0 && !servers)
                return -EINVAL;
        if (n > NETD_SNTP_MAX_SERVERS)
                return -E2BIG;

        for (size_t i = 0; i < n; i++)
                s->servers[i] = servers[i];

        s->n_servers = n;
        s->next_server = 0;

        if (n == 0)
                return netd_sntp_stop(s);

        return 0;
}

int netd_sntp_start(NetdSntp *s) {
        if (!s)
                return -EINVAL;

        if (s->n_servers == 0)
                return 0;

        return sntp_send_request(s);
}

int netd_sntp_stop(NetdSntp *s) {
        if (!s)
                return -EINVAL;

        if (s->timer_event)
                (void) pico_timer_cancel(s->netd->timer, s->timer_event);

        s->request.pending = false;

        return 0;
}

int netd_sntp_process(NetdSntp *s) {
        uint8_t buf[512];
        struct sockaddr_in src = { 0 };
        /* Union, not a plain char array: msg_control must be suitably
         * aligned for struct cmsghdr, which a bare char buffer is not
         * guaranteed to be. Zero-initialized -- see glibc bug #20741,
         * cited in timesyncd-manager.c's own CMSG_BUFFER_TYPE use, which
         * this mirrors. */
        union {
                struct cmsghdr align_hdr;
                uint8_t buf[CMSG_SPACE(sizeof(struct timespec))];
        } control = { 0 };
        struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
        struct msghdr msg = {
                .msg_name = &src,
                .msg_namelen = sizeof(src),
                .msg_iov = &iov,
                .msg_iovlen = 1,
                .msg_control = control.buf,
                .msg_controllen = sizeof(control.buf),
        };
        struct cmsghdr *cmsg;
        struct timespec *recv_ts = NULL;
        ssize_t len;
        usec_t dest;
        NetdSntpReject rej;
        int64_t offset, delay;
        int r;

        if (!s)
                return -EINVAL;

        len = recvmsg(s->fd, &msg, MSG_DONTWAIT);
        if (len < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                        return 0;
                return -errno;
        }

        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPNS) {
                        recv_ts = (struct timespec *) (void *) CMSG_DATA(cmsg);
                        break;
                }

        if (recv_ts)
                dest = (usec_t) recv_ts->tv_sec * USEC_PER_SEC + (usec_t) recv_ts->tv_nsec / 1000;
        else {
                /* SO_TIMESTAMPNS is set at socket creation, so a missing
                 * timestamp means something has gone wrong with the kernel's
                 * cmsg delivery, not a hostile packet. Fall back to reading
                 * the clock directly rather than dropping an otherwise-valid
                 * reply outright. */
                struct timespec now_ts;

                if (clock_gettime(CLOCK_REALTIME, &now_ts) < 0)
                        return -errno;
                dest = (usec_t) now_ts.tv_sec * USEC_PER_SEC + (usec_t) now_ts.tv_nsec / 1000;
        }

        rej = netd_sntp_validate(buf, (size_t) len, &src.sin_addr, &s->request);
        if (rej != NETD_SNTP_ACCEPTED) {
                pico_log(PICO_LOG_DEBUG, "netd: sntp: rejected reply: %s", netd_sntp_reject_to_string(rej));
                return 0;
        }

        r = netd_sntp_compute(
                        (const NetdNtpMsg *) (const void *) buf, s->request.origin, dest, &offset, &delay);
        if (r < 0)
                return r;

        s->request.pending = false;
        s->synchronised = true;

        r = netd_time_adjust_clock(s->netd, offset);
        if (r < 0)
                pico_log(PICO_LOG_ERR, "netd: sntp: clock_adjtime failed: %s", strerror(-r));

        (void) netd_time_clock_floor_touch(s->netd);

        /* Successful sync: cancel the short retry and go to the fixed resync
         * interval instead. */
        (void) sntp_arm_timer(s, NETD_SNTP_POLL_INTERVAL_USEC);

        return 0;
}
