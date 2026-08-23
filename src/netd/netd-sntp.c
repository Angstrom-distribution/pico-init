/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The SNTP client. See netd-sntp.h for the validation set that is kept and
 * the statistics machinery that is not.
 *
 * N0 scaffold: the timestamp conversions and the rejection-reason table are
 * real (pure arithmetic and a lookup, no easier stubbed); validation,
 * computation and the socket path land with N4.
 */

#include "netd-sntp.h"

#include <endian.h>
#include <errno.h>
#include <stddef.h>

#include "../util.h"
#include "netd.h"

int netd_sntp_new(Netd *n, NetdSntp **ret) {
        if (!n || !ret)
                return -EINVAL;

        return -ENOSYS;
}

NetdSntp *netd_sntp_free(NetdSntp *s) {
        (void) s;

        return NULL;
}

int netd_sntp_set_servers(NetdSntp *s, const struct in_addr *servers, size_t n) {
        (void) servers;
        (void) n;

        if (!s)
                return -EINVAL;

        return -ENOSYS;
}

int netd_sntp_start(NetdSntp *s) {
        if (!s)
                return -EINVAL;

        return -ENOSYS;
}

int netd_sntp_stop(NetdSntp *s) {
        if (!s)
                return -EINVAL;

        return -ENOSYS;
}

int netd_sntp_process(NetdSntp *s) {
        if (!s)
                return -EINVAL;

        return -ENOSYS;
}

NetdSntpReject netd_sntp_validate(
                const void *packet, size_t size, const struct in_addr *source, const NetdSntpRequest *request) {

        (void) packet;
        (void) size;
        (void) source;
        (void) request;

        return NETD_SNTP_REJECT_MALFORMED;
}

int netd_sntp_compute(
                const NetdNtpMsg *m,
                usec_t origin,
                usec_t dest,
                int64_t *ret_offset_usec,
                int64_t *ret_delay_usec) {

        (void) m;
        (void) origin;
        (void) dest;
        (void) ret_offset_usec;
        (void) ret_delay_usec;

        return -ENOSYS;
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
        [NETD_SNTP_REJECT_LEAP] = "server not synchronised",
        [NETD_SNTP_REJECT_STRATUM] = "bad stratum",
        [NETD_SNTP_REJECT_VERSION] = "unsupported version",
        [NETD_SNTP_REJECT_MODE] = "not a server reply",
        [NETD_SNTP_REJECT_ROOT_DISTANCE] = "root distance too large",
        [NETD_SNTP_REJECT_ZERO_TIMESTAMP] = "zero transmit timestamp",
};

const char *netd_sntp_reject_to_string(NetdSntpReject r) {
        if (r < 0 || r >= _NETD_SNTP_REJECT_MAX)
                return "invalid";

        return netd_sntp_reject_table[r];
}
