/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The SNTP client.
 *
 * This replaces systemd-timesyncd by keeping only the part that decides
 * whether a reply may be believed and dropping everything that decides how
 * hard to ask. Kept, because each rejects a class of wrong answer:
 * source-address match, the origin-timestamp nonce echo (the
 * anti-off-path-spoofing check), pending-request correlation, leap != 3,
 * stratum not 0 and not >= 16, version 3 or 4 only, mode == server, and the
 * root-distance bound. Dropped: adaptive poll-interval doubling, the
 * eight-sample jitter/spike statistics, and server-list/DNS iteration --
 * servers arrive as addresses, from [Network] NTP= or from DHCP option 42.
 *
 * Two further checks are carried: a short-packet reject
 * (NETD_SNTP_REJECT_MALFORMED on a datagram smaller than the header), and an
 * epoch floor (NETD_SNTP_REJECT_EPOCH) that rejects recv_time/trans_time
 * claiming a time before this build's compiled-in epoch (netd-time.h's
 * NETD_TIME_EPOCH_SEC) -- the only thing stopping a hostile or broken server
 * from walking an RTC-less board's clock back past the day it was built.
 *
 * The packet layout below is netd's own, written from RFC 5905 §7.3 rather
 * than lifted, which is why this file is GPL-2.0-or-later with no systemd
 * attribution: an on-the-wire header has exactly one legal shape.
 *
 * The validation and offset-computation entry points are pure functions over
 * a buffer -- no socket, no clock, no side effects -- so test-netd-sntp can
 * exercise every rejection path and the step/slew decision without calling
 * clock_adjtime(), which is process-global even inside a network namespace.
 */

#pragma once

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../timer.h"
#include "../util.h"
#include "netd-loop.h"

typedef struct Netd Netd;
typedef struct NetdSntp NetdSntp;

#define NETD_NTP_PORT 123

#define NETD_NTP_LEAP_NOTINSYNC 3
#define NETD_NTP_MODE_CLIENT 3
#define NETD_NTP_MODE_SERVER 4

#define NETD_NTP_FIELD_LEAP(f) (((f) >> 6) & 3)
#define NETD_NTP_FIELD_VERSION(f) (((f) >> 3) & 7)
#define NETD_NTP_FIELD_MODE(f) ((f) & 7)
#define NETD_NTP_FIELD(l, v, m) (((l) << 6) | ((v) << 3) | (m))

/* NTP timestamps count seconds from 1900-01-01, POSIX time from 1970. */
#define NETD_NTP_OFFSET_1900_1970 UINT64_C(2208988800)

/* Fixed resync interval: no adaptive backoff. 2048s is upstream's own
 * maximum poll, and on a board that gets its time from DHCP anyway there is
 * nothing to gain from asking more often. */
#define NETD_SNTP_POLL_INTERVAL_USEC ((usec_t) (2048ULL * USEC_PER_SEC))

/* Retry interval while no server has answered yet. */
#define NETD_SNTP_RETRY_USEC ((usec_t) (10ULL * USEC_PER_SEC))

/* A reply whose root delay/2 + root dispersion exceeds this is discarded: the
 * server may be correct and still be too far from a real clock to be worth
 * stepping to. */
#define NETD_SNTP_MAX_ROOT_DISTANCE_USEC ((usec_t) (5ULL * USEC_PER_SEC))

#define NETD_SNTP_MAX_SERVERS 8

/* A 32.32 fixed-point NTP timestamp, in network byte order as it sits on the
 * wire. Kept as raw uint32_t rather than a bitwise-tagged typedef: netd has
 * no sparse annotations, and an explicit be32toh() at each use is clearer
 * than a type that only a checker enforces. */
typedef struct NetdNtpTs {
        uint32_t sec;
        uint32_t frac;
} __attribute__((__packed__)) NetdNtpTs;

typedef struct NetdNtpTsShort {
        uint16_t sec;
        uint16_t frac;
} __attribute__((__packed__)) NetdNtpTsShort;

typedef struct NetdNtpMsg {
        uint8_t field; /* leap (2) | version (3) | mode (3) */
        uint8_t stratum;
        int8_t poll;
        int8_t precision;
        NetdNtpTsShort root_delay;
        NetdNtpTsShort root_dispersion;
        char refid[4];
        NetdNtpTs reference_time;
        NetdNtpTs origin_time;
        NetdNtpTs recv_time;
        NetdNtpTs trans_time;
} __attribute__((__packed__)) NetdNtpMsg;

/* The outstanding query. One at a time: netd asks its servers in turn rather
 * than in parallel, so correlation is a single comparison and there is no
 * per-server state to age out. */
typedef struct NetdSntpRequest {
        bool pending;
        struct in_addr server;
        NetdNtpTs nonce; /* the random transmit timestamp that was sent */
        usec_t origin;   /* CLOCK_REALTIME at send, for the offset arithmetic */
        usec_t sent_at;  /* CLOCK_MONOTONIC at send, for the timeout */
} NetdSntpRequest;

/*
 * Every reason a reply can be thrown away. An enum rather than a bool because
 * test-netd-sntp asserts each one individually, and because "the NTP reply
 * was rejected" is close to useless in a log on a board with no journal yet.
 */
typedef enum NetdSntpReject {
        NETD_SNTP_ACCEPTED,
        NETD_SNTP_REJECT_MALFORMED,      /* short packet */
        NETD_SNTP_REJECT_UNSOLICITED,    /* no request outstanding */
        NETD_SNTP_REJECT_SOURCE,         /* not from the server we asked */
        NETD_SNTP_REJECT_NONCE,          /* origin timestamp != our transmit nonce */
        NETD_SNTP_REJECT_ZERO_TIMESTAMP, /* transmit timestamp 0: nothing to compute from */
        /*
         * recv_time or trans_time claims a time before this build's epoch
         * floor: the reason a broken or hostile server cannot walk an
         * RTC-less board's clock backwards past the build date. Checked after
         * ZERO_TIMESTAMP so an all-zero reply (trivially before any epoch)
         * gets the more specific reason.
         */
        NETD_SNTP_REJECT_EPOCH,
        NETD_SNTP_REJECT_LEAP,          /* leap indicator 3: server not synchronised */
        NETD_SNTP_REJECT_STRATUM,       /* 0 (kiss-o'-death) or >= 16 (unsynchronised) */
        NETD_SNTP_REJECT_VERSION,       /* neither 3 nor 4 */
        NETD_SNTP_REJECT_MODE,          /* not mode 4 */
        NETD_SNTP_REJECT_ROOT_DISTANCE, /* too far from a real clock to trust */
        _NETD_SNTP_REJECT_MAX,
} NetdSntpReject;

struct NetdSntp {
        Netd *netd; /* borrowed */

        int fd; /* UDP, SO_TIMESTAMPNS for the receive timestamp */
        struct netd_epoll_tag tag;

        struct in_addr servers[NETD_SNTP_MAX_SERVERS];
        size_t n_servers;
        size_t next_server; /* round-robin cursor */

        NetdSntpRequest request;
        PicoTimerEvent *timer_event; /* retry or next poll; see timer.h on handle lifetime */

        bool synchronised; /* a reply has been accepted at least once this boot */
};

/* --- netd-sntp.c --- */

/* Allocate and open the socket. 0 or -errno. */
int netd_sntp_new(Netd *n, NetdSntp **ret);

NetdSntp *netd_sntp_free(NetdSntp *s); /* returns NULL */

/*
 * Replace the server list. Called from netd_startup() with [Network] NTP=
 * and from link_apply_lease() with DHCP option 42, so the two sources cannot
 * accumulate stale entries across a lease change. An empty list stops the
 * client. 0 or -errno.
 */
int netd_sntp_set_servers(NetdSntp *s, const struct in_addr *servers, size_t n);

/* Send the first query and arm the retry timer. 0 or -errno; a no-op when the
 * server list is empty. */
int netd_sntp_start(NetdSntp *s);

/* Cancel the timer and stop querying, without dropping the server list. */
int netd_sntp_stop(NetdSntp *s);

/* Socket-readiness callback: receive, validate, compute, and (on acceptance)
 * hand the offset to netd_time_adjust_clock(). 0 or -errno. */
int netd_sntp_process(NetdSntp *s);

/* --- pure helpers, exercised directly by test-netd-sntp --- */

/*
 * Every check from the list at the top of this file, in the order a cheap
 * check should precede an expensive one. `source` is the datagram's real
 * source address, not anything read out of the packet. Returns
 * NETD_SNTP_ACCEPTED or the first reason it failed.
 */
NetdSntpReject netd_sntp_validate(
                const void *packet, size_t size, const struct in_addr *source, const NetdSntpRequest *request);

/*
 * The SNTP offset/delay arithmetic of RFC 5905 §8:
 *   offset = ((T2 - T1) + (T3 - T4)) / 2
 *   delay  =  (T4 - T1) - (T3 - T2)
 * with T1 = `origin` (our send time), T2/T3 from the packet, and T4 = `dest`
 * (the SO_TIMESTAMPNS receive time). Both results in usec, signed, because
 * the whole point is that the local clock may be ahead. 0 or -errno.
 */
int netd_sntp_compute(
                const NetdNtpMsg *m,
                usec_t origin,
                usec_t dest,
                int64_t *ret_offset_usec,
                int64_t *ret_delay_usec);

/* NTP 32.32 <-> usec since the epoch, both directions, for the packet builder
 * and for the tests' fixtures. */
usec_t netd_ntp_ts_to_usec(const NetdNtpTs *ts);
void netd_ntp_ts_from_usec(NetdNtpTs *ts, usec_t usec);

const char *netd_sntp_reject_to_string(NetdSntpReject r);
