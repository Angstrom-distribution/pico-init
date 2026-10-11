/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The SNTP client and the clock/timezone applier.
 *
 * test_sntp_process_over_real_socket() below is a fake UDP/123 responder, and
 * it only ever exercises a REJECT: an accepted reply would make
 * netd_sntp_process() call netd_time_adjust_clock() -> clock_adjtime() for
 * real, which is process-global even inside a network namespace (see
 * netd-sntp.h). Every individual validation check, including the nonce
 * mismatch that is the anti-off-path-spoofing test, is exercised directly
 * against netd_sntp_validate(), a pure function over a buffer, a source
 * address and a request.
 *
 * settimeofday() and clock_settime() need CAP_SYS_TIME, which test containers
 * may deny even to root. netd_time_build_tz() and
 * netd_time_clock_floor_decide() (netd-time.h) exist so this file can test the
 * kernel-timezone-push computation and the TIME_EPOCH-vs-clock-file-mtime
 * floor decision without calling the syscalls that would apply them.
 */

#include <endian.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timex.h>
#include <time.h>
#include <unistd.h>

#include "../test-util.h"
#include "netd-sntp.h"
#include "netd-time.h"
#include "netd.h"

/* An NTP header is 48 bytes on the wire, and no compiler is allowed to pad
 * it. Getting this wrong produces a client that talks to nothing. */
static void test_packet_layout(void) {
        ASSERT_EQ_INT(sizeof(NetdNtpTs), 8);
        ASSERT_EQ_INT(sizeof(NetdNtpTsShort), 4);
        ASSERT_EQ_INT(sizeof(NetdNtpMsg), 48);
        ASSERT_EQ_INT(offsetof(NetdNtpMsg, origin_time), 24);
        ASSERT_EQ_INT(offsetof(NetdNtpMsg, trans_time), 40);
}

/* leap/version/mode share one byte; the accessors have to agree with the
 * constructor. */
static void test_field_packing(void) {
        uint8_t f = NETD_NTP_FIELD(0, 4, NETD_NTP_MODE_CLIENT);

        ASSERT_EQ_INT(NETD_NTP_FIELD_LEAP(f), 0);
        ASSERT_EQ_INT(NETD_NTP_FIELD_VERSION(f), 4);
        ASSERT_EQ_INT(NETD_NTP_FIELD_MODE(f), NETD_NTP_MODE_CLIENT);

        f = NETD_NTP_FIELD(NETD_NTP_LEAP_NOTINSYNC, 3, NETD_NTP_MODE_SERVER);
        ASSERT_EQ_INT(NETD_NTP_FIELD_LEAP(f), NETD_NTP_LEAP_NOTINSYNC);
        ASSERT_EQ_INT(NETD_NTP_FIELD_VERSION(f), 3);
        ASSERT_EQ_INT(NETD_NTP_FIELD_MODE(f), NETD_NTP_MODE_SERVER);
}

/*
 * usec <-> NTP 32.32, round trip. The transmit timestamp doubles as the
 * anti-spoofing nonce that has to come back byte-identical in the reply's
 * origin field, so a lossy conversion here makes the client reject every
 * valid reply.
 */
static void test_timestamp_roundtrip(void) {
        static const usec_t samples[] = {
                0, 1, USEC_PER_SEC, 1234567890ULL * USEC_PER_SEC, 1780000000ULL * USEC_PER_SEC + 999999,
        };

        for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
                NetdNtpTs ts;
                usec_t back;

                netd_ntp_ts_from_usec(&ts, samples[i]);
                back = netd_ntp_ts_to_usec(&ts);

                /* One usec of slack: 2^-32 s does not divide a microsecond. */
                ASSERT_TRUE(back <= samples[i] ? samples[i] - back <= 1 : back - samples[i] <= 1);
        }
}

/* Every rejection reason is loggable. */
static void test_reject_names(void) {
        for (NetdSntpReject r = 0; r < _NETD_SNTP_REJECT_MAX; r++)
                ASSERT_TRUE(netd_sntp_reject_to_string(r) != NULL);

        ASSERT_STREQ(netd_sntp_reject_to_string(NETD_SNTP_ACCEPTED), "accepted");
        ASSERT_STREQ(netd_sntp_reject_to_string(_NETD_SNTP_REJECT_MAX), "invalid");

        ASSERT_STREQ(netd_clock_adjust_to_string(NETD_CLOCK_STEP), "step");
        ASSERT_STREQ(netd_clock_adjust_to_string(NETD_CLOCK_SLEW), "slew");
}

/* --- netd_sntp_validate(): one case per NetdSntpReject value --- */

/* A fully NETD_SNTP_ACCEPTED-worthy request/reply/source triple. Every
 * validate() test below starts here and mutates exactly one thing, so a
 * failing test names precisely which check caught it. */
static void baseline(NetdNtpMsg *m, NetdSntpRequest *req, struct in_addr *source) {
        memset(m, 0, sizeof(*m));
        memset(req, 0, sizeof(*req));

        req->pending = true;
        req->server.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
        req->nonce.sec = htobe32(0x11223344);
        req->nonce.frac = htobe32(0x55667788);

        *source = req->server;

        m->field = NETD_NTP_FIELD(0, 4, NETD_NTP_MODE_SERVER);
        m->stratum = 2;
        m->origin_time = req->nonce; /* echo, byte for byte, not reinterpreted */
        netd_ntp_ts_from_usec(&m->recv_time, 1780000000ULL * USEC_PER_SEC);
        netd_ntp_ts_from_usec(&m->trans_time, 1780000000ULL * USEC_PER_SEC + 1000);
}

static void test_validate_accepted(void) {
        NetdNtpMsg m;
        NetdSntpRequest req;
        struct in_addr source;

        baseline(&m, &req, &source);
        ASSERT_EQ_INT(netd_sntp_validate(&m, sizeof(m), &source, &req), NETD_SNTP_ACCEPTED);
}

static void test_validate_malformed(void) {
        NetdNtpMsg m;
        NetdSntpRequest req;
        struct in_addr source;

        baseline(&m, &req, &source);
        ASSERT_EQ_INT(netd_sntp_validate(&m, sizeof(m) - 1, &source, &req), NETD_SNTP_REJECT_MALFORMED);
}

static void test_validate_unsolicited(void) {
        NetdNtpMsg m;
        NetdSntpRequest req;
        struct in_addr source;

        baseline(&m, &req, &source);
        req.pending = false;
        ASSERT_EQ_INT(netd_sntp_validate(&m, sizeof(m), &source, &req), NETD_SNTP_REJECT_UNSOLICITED);
}

static void test_validate_source(void) {
        NetdNtpMsg m;
        NetdSntpRequest req;
        struct in_addr source;

        baseline(&m, &req, &source);
        source.s_addr = htonl(0x7f000002); /* not the server we asked */
        ASSERT_EQ_INT(netd_sntp_validate(&m, sizeof(m), &source, &req), NETD_SNTP_REJECT_SOURCE);
}

/* The anti-off-path-spoofing check: an attacker on a different path can spoof
 * the source address but cannot guess the 64-bit random nonce. */
static void test_validate_nonce(void) {
        NetdNtpMsg m;
        NetdSntpRequest req;
        struct in_addr source;

        baseline(&m, &req, &source);
        m.origin_time.frac = htobe32(0xdeadbeef);
        ASSERT_EQ_INT(netd_sntp_validate(&m, sizeof(m), &source, &req), NETD_SNTP_REJECT_NONCE);
}

static void test_validate_zero_timestamp(void) {
        NetdNtpMsg m;
        NetdSntpRequest req;
        struct in_addr source;

        baseline(&m, &req, &source);
        m.trans_time.sec = 0;
        m.trans_time.frac = 0;
        ASSERT_EQ_INT(netd_sntp_validate(&m, sizeof(m), &source, &req), NETD_SNTP_REJECT_ZERO_TIMESTAMP);
}

/*
 * A reply claiming a
 * time before this build's epoch is rejected, not stepped to -- the whole
 * point being that a broken or hostile server cannot walk an RTC-less
 * board's clock backwards past the day it was built.
 */
static void test_validate_epoch(void) {
        NetdNtpMsg m;
        NetdSntpRequest req;
        struct in_addr source;

        baseline(&m, &req, &source);
        /* 2020-09-13, comfortably before NETD_TIME_EPOCH_SEC (2026-01-01). */
        netd_ntp_ts_from_usec(&m.recv_time, 1600000000ULL * USEC_PER_SEC);
        netd_ntp_ts_from_usec(&m.trans_time, 1600000000ULL * USEC_PER_SEC);
        ASSERT_EQ_INT(netd_sntp_validate(&m, sizeof(m), &source, &req), NETD_SNTP_REJECT_EPOCH);
}

static void test_validate_leap(void) {
        NetdNtpMsg m;
        NetdSntpRequest req;
        struct in_addr source;

        baseline(&m, &req, &source);
        m.field = NETD_NTP_FIELD(NETD_NTP_LEAP_NOTINSYNC, 4, NETD_NTP_MODE_SERVER);
        ASSERT_EQ_INT(netd_sntp_validate(&m, sizeof(m), &source, &req), NETD_SNTP_REJECT_LEAP);
}

static void test_validate_stratum(void) {
        NetdNtpMsg m;
        NetdSntpRequest req;
        struct in_addr source;

        baseline(&m, &req, &source);
        m.stratum = 0; /* kiss-o'-death */
        ASSERT_EQ_INT(netd_sntp_validate(&m, sizeof(m), &source, &req), NETD_SNTP_REJECT_STRATUM);

        baseline(&m, &req, &source);
        m.stratum = 16; /* unsynchronised */
        ASSERT_EQ_INT(netd_sntp_validate(&m, sizeof(m), &source, &req), NETD_SNTP_REJECT_STRATUM);
}

static void test_validate_version(void) {
        NetdNtpMsg m;
        NetdSntpRequest req;
        struct in_addr source;

        baseline(&m, &req, &source);
        m.field = NETD_NTP_FIELD(0, 2, NETD_NTP_MODE_SERVER);
        ASSERT_EQ_INT(netd_sntp_validate(&m, sizeof(m), &source, &req), NETD_SNTP_REJECT_VERSION);
}

static void test_validate_mode(void) {
        NetdNtpMsg m;
        NetdSntpRequest req;
        struct in_addr source;

        baseline(&m, &req, &source);
        m.field = NETD_NTP_FIELD(0, 4, NETD_NTP_MODE_CLIENT);
        ASSERT_EQ_INT(netd_sntp_validate(&m, sizeof(m), &source, &req), NETD_SNTP_REJECT_MODE);
}

static void test_validate_root_distance(void) {
        NetdNtpMsg m;
        NetdSntpRequest req;
        struct in_addr source;

        baseline(&m, &req, &source);
        m.root_dispersion.sec = htobe16(10); /* 10s >> NETD_SNTP_MAX_ROOT_DISTANCE_USEC (5s) */
        m.root_dispersion.frac = 0;
        ASSERT_EQ_INT(netd_sntp_validate(&m, sizeof(m), &source, &req), NETD_SNTP_REJECT_ROOT_DISTANCE);
}

/* --- netd_sntp_compute(): RFC 5905 §8 offset/delay arithmetic --- */

static void test_compute(void) {
        NetdNtpMsg m;
        usec_t base = 1780000000ULL * USEC_PER_SEC;
        int64_t offset, delay;
        int r;

        memset(&m, 0, sizeof(m));
        /* T1 = base, T2 = base+500ms, T3 = base+600ms, T4 = base+1000ms. */
        netd_ntp_ts_from_usec(&m.recv_time, base + 500000);
        netd_ntp_ts_from_usec(&m.trans_time, base + 600000);

        r = netd_sntp_compute(&m, base, base + 1000000, &offset, &delay);
        ASSERT_EQ_INT(r, 0);

        /* offset = ((T2-T1)+(T3-T4))/2 = (500000 + (600000-1000000)) / 2 = 50000
         * delay  =  (T4-T1)-(T3-T2)    =  1000000 - 100000            = 900000
         * A couple of microseconds of slack: both recv_time and trans_time
         * round-trip through the lossy 32.32 <-> usec conversion. */
        ASSERT_TRUE(offset >= 50000 - 2 && offset <= 50000 + 2);
        ASSERT_TRUE(delay >= 900000 - 2 && delay <= 900000 + 2);

        r = netd_sntp_compute(NULL, 0, 0, &offset, &delay);
        ASSERT_TRUE(r < 0);
}

/* --- netd_time_build_timex(): the step/slew decision --- */

static void test_build_timex_slew(void) {
        struct timex tmx;
        NetdClockAdjust mode;
        int r;

        r = netd_time_build_timex(100000, &tmx, &mode); /* 100ms: well under 400ms */
        ASSERT_EQ_INT(r, 0);
        ASSERT_EQ_INT(mode, NETD_CLOCK_SLEW);
        ASSERT_TRUE((tmx.modes & ADJ_OFFSET) != 0);
        ASSERT_TRUE((tmx.status & STA_PLL) != 0);
        ASSERT_EQ_INT(tmx.offset, 100000L * 1000L); /* ADJ_NANO: nanoseconds */
}

static void test_build_timex_step(void) {
        struct timex tmx;
        NetdClockAdjust mode;
        int r;

        r = netd_time_build_timex(1500000, &tmx, &mode); /* +1.5s */
        ASSERT_EQ_INT(r, 0);
        ASSERT_EQ_INT(mode, NETD_CLOCK_STEP);
        ASSERT_TRUE((tmx.modes & ADJ_SETOFFSET) != 0);
        ASSERT_EQ_INT(tmx.time.tv_sec, 1);
        ASSERT_EQ_INT(tmx.time.tv_usec, 500000000L);

        r = netd_time_build_timex(-1500000, &tmx, &mode); /* -1.5s: kernel wants {-2, 500000000} */
        ASSERT_EQ_INT(r, 0);
        ASSERT_EQ_INT(mode, NETD_CLOCK_STEP);
        ASSERT_EQ_INT(tmx.time.tv_sec, -2);
        ASSERT_EQ_INT(tmx.time.tv_usec, 500000000L);
}

static void test_build_timex_boundary(void) {
        struct timex tmx;
        NetdClockAdjust mode;
        int r;

        /* "below it, slew; at or above it, step" (netd-time.h). */
        r = netd_time_build_timex(400000, &tmx, &mode);
        ASSERT_EQ_INT(r, 0);
        ASSERT_EQ_INT(mode, NETD_CLOCK_STEP);

        r = netd_time_build_timex(399999, &tmx, &mode);
        ASSERT_EQ_INT(r, 0);
        ASSERT_EQ_INT(mode, NETD_CLOCK_SLEW);

        r = netd_time_build_timex(0, NULL, &mode);
        ASSERT_TRUE(r < 0);
}

/* --- netd_time_clock_floor_decide(): both TIME_EPOCH halves --- */

static void test_clock_floor_decide(void) {
        usec_t target;
        usec_t epoch_usec = (usec_t) NETD_TIME_EPOCH_SEC * USEC_PER_SEC;

        /* First boot, no clock file (mtime 0 stands in for "does not exist"):
         * TIME_EPOCH is the only floor there is, and "now" clears it. */
        ASSERT_TRUE(!netd_time_clock_floor_decide(0, epoch_usec + 3600ULL * USEC_PER_SEC, &target));

        /* First boot, clock stuck at/near 1970 (dead RTC): must step, to the
         * epoch floor plus one second. */
        ASSERT_TRUE(netd_time_clock_floor_decide(0, USEC_PER_SEC, &target));
        ASSERT_EQ_INT(target, epoch_usec + USEC_PER_SEC);

        /* A clock-file mtime NEWER than the epoch must win the max(): "now"
         * sits between the two, so a step is still needed, to mtime+1s. */
        {
                usec_t mtime = epoch_usec + 10ULL * USEC_PER_SEC;
                usec_t now = epoch_usec + 5ULL * USEC_PER_SEC;

                ASSERT_TRUE(netd_time_clock_floor_decide(mtime, now, &target));
                ASSERT_EQ_INT(target, mtime + USEC_PER_SEC);
        }

        /* A clock-file mtime OLDER than the epoch must not win: the epoch
         * alone remains the floor, and "now" already clears it. */
        {
                usec_t mtime = epoch_usec - 3600ULL * USEC_PER_SEC;
                usec_t now = epoch_usec + 3600ULL * USEC_PER_SEC;

                ASSERT_TRUE(!netd_time_clock_floor_decide(mtime, now, &target));
        }
}

/*
 * netd_time_clock_floor_apply()/_touch() themselves, against a test-root
 * state_dir. The apply() case only exercises the "no step needed" path --
 * the container's real clock is already years past NETD_TIME_EPOCH_SEC, so
 * this never reaches clock_settime(), which needs CAP_SYS_TIME this
 * container does not have; the decision logic itself is what
 * test_clock_floor_decide() above already covers purely.
 */
static void test_clock_floor_apply_and_touch(void) {
        Netd n;
        char *tmp;
        char clock_path[PATH_MAX];
        struct stat st1, st2;
        int r;

        /* A bare Netd rather than netd_new()/netd_free():
         * n.state_dir is the only field netd_time_clock_floor_apply()/_touch()
         * read, and neither frees or reassigns it, so pointing it at
         * caller-owned storage is safe without a strdup. */
        memset(&n, 0, sizeof(n));
        tmp = test_tmpdir_new();
        ASSERT_TRUE(tmp != NULL);
        n.state_dir = tmp;

        r = netd_time_clock_floor_apply(&n);
        ASSERT_EQ_INT(r, 0);

        r = netd_time_clock_floor_touch(&n);
        ASSERT_EQ_INT(r, 0);

        snprintf(clock_path, sizeof(clock_path), "%s/clock", tmp);
        ASSERT_EQ_INT(stat(clock_path, &st1), 0);

        r = netd_time_clock_floor_touch(&n);
        ASSERT_EQ_INT(r, 0);
        ASSERT_EQ_INT(stat(clock_path, &st2), 0);

        /* Every touch must move the mtime forward, never backward -- that
         * monotonicity is the entire state the clock floor keeps. */
        ASSERT_TRUE(st2.st_mtime >= st1.st_mtime);

        test_rm_rf(tmp);
        free(tmp);
}

/* --- timezone: validation, the symlink swap, and the tzset() ordering --- */

/* Real /usr/share/zoneinfo (Netd's default), read-only: both UTC and
 * Etc/GMT-9 are present in the verify image, so there is no need for a
 * hand-rolled TZif fixture just to exercise is_valid(). */
static void test_timezone_validity(void) {
        Netd n;

        memset(&n, 0, sizeof(n));
        n.zoneinfo_dir = NETD_ZONEINFO_DIR;

        ASSERT_TRUE(netd_time_timezone_is_valid(&n, "UTC"));
        ASSERT_TRUE(netd_time_timezone_is_valid(&n, "Etc/GMT-9"));

        ASSERT_TRUE(!netd_time_timezone_is_valid(&n, NULL));
        ASSERT_TRUE(!netd_time_timezone_is_valid(&n, ""));
        ASSERT_TRUE(!netd_time_timezone_is_valid(&n, "/etc/passwd"));                /* absolute path */
        ASSERT_TRUE(!netd_time_timezone_is_valid(&n, "../../etc/passwd"));           /* traversal */
        ASSERT_TRUE(!netd_time_timezone_is_valid(&n, "Europe/../../../etc/passwd")); /* mid-path traversal */
        ASSERT_TRUE(!netd_time_timezone_is_valid(&n, "."));
        ASSERT_TRUE(!netd_time_timezone_is_valid(&n, ".."));
        ASSERT_TRUE(!netd_time_timezone_is_valid(&n, "Nonexistent/Zone"));
}

/*
 * The atomic symlink swap, the empty/UTC unlink, and idempotency -- against
 * a test-root localtime_path, never the container's real /etc/localtime.
 * zoneinfo_dir is left at its real default (read-only access to a real
 * TZif file, safe) so the symlink target actually resolves to something.
 */
static void test_timezone_symlink_swap(void) {
        Netd n;
        char *tmp;
        char localtime_path[PATH_MAX], linktarget[PATH_MAX];
        /* Wider than localtime_path's own bound: appending ".netd-tmp" to a
         * worst-case-length localtime_path must not make gcc's own
         * -Wformat-truncation worry it might not fit. */
        char tmp_link[PATH_MAX + 16];
        char *cur;
        ssize_t len;
        struct stat st;
        int r;

        memset(&n, 0, sizeof(n));
        n.zoneinfo_dir = NETD_ZONEINFO_DIR; /* real default: read-only access to a real TZif file */

        tmp = test_tmpdir_new();
        ASSERT_TRUE(tmp != NULL);

        snprintf(localtime_path, sizeof(localtime_path), "%s/localtime", tmp);
        n.localtime_path = localtime_path;

        /* Nothing installed yet: an empty-or-UTC request is a no-op. */
        ASSERT_TRUE(netd_time_get_timezone(&n) == NULL);
        ASSERT_EQ_INT(netd_time_set_timezone(&n, "UTC"), 1);
        ASSERT_EQ_INT(netd_time_set_timezone(&n, ""), 1);

        r = netd_time_set_timezone(&n, "Etc/GMT-9");
        ASSERT_EQ_INT(r, 0);

        len = readlink(localtime_path, linktarget, sizeof(linktarget) - 1);
        ASSERT_TRUE(len > 0);
        linktarget[len] = '\0';
        ASSERT_STREQ(linktarget, "/usr/share/zoneinfo/Etc/GMT-9");

        cur = netd_time_get_timezone(&n);
        ASSERT_TRUE(cur != NULL);
        ASSERT_STREQ(cur, "Etc/GMT-9");
        free(cur);

        /* Same zone again: idempotent, "nothing was written" per the header
         * contract, signalled by returning 1. */
        ASSERT_EQ_INT(netd_time_set_timezone(&n, "Etc/GMT-9"), 1);

        /* No leftover ".netd-tmp" from the rename -- the swap is really
         * atomic, not append-then-someone-cleans-up. */
        snprintf(tmp_link, sizeof(tmp_link), "%s.netd-tmp", localtime_path);
        ASSERT_TRUE(lstat(tmp_link, &st) < 0);

        /* Empty/UTC unlinks a real symlink rather than leaving it stale --
         * the case a DHCP server that stops sending option 101 depends on. */
        ASSERT_EQ_INT(netd_time_set_timezone(&n, "UTC"), 0);
        ASSERT_TRUE(netd_time_get_timezone(&n) == NULL);

        /* Traversal is rejected before anything is written -- the symlink
         * from the last successful call above must survive untouched, i.e.
         * still be absent (the UTC unlink above removed it). */
        r = netd_time_set_timezone(&n, "../../etc/passwd");
        ASSERT_EQ_INT(r, -EINVAL);
        ASSERT_TRUE(netd_time_get_timezone(&n) == NULL);

        test_rm_rf(tmp);
        free(tmp);
}

/*
 * The tzset()-before-kernel-push ordering that netd_time_set_timezone()'s
 * header comment says must hold. settimeofday() itself needs
 * CAP_SYS_TIME (denied here, verified directly), so the symlink-swap test
 * above cannot observe the kernel-push side of an inversion -- only that the
 * symlink lands correctly. This drives netd_time_build_tz(), the pure half
 * split out of netd_time_set_timezone() for exactly this reason, directly
 * against a controlled TZ environment: no socket, symlink, or privilege
 * needed at all.
 */
static void test_tz_build_ordering(void) {
        struct timezone before, after;
        int r;

        /* A known "stale" zone: UTC0, offset 0 -- exactly what a caller that
         * forgot to call tzset() after installing a new zone would still
         * read. */
        ASSERT_EQ_INT(setenv("TZ", "UTC0", 1), 0);
        tzset();

        r = netd_time_build_tz(&before);
        ASSERT_EQ_INT(r, 0);
        ASSERT_EQ_INT(before.tz_minuteswest, 0);

        /* glibc's ":<path>" TZ form reaches the same tzfile a symlink swap
         * against Netd.zoneinfo_dir would install. Etc/GMT-9 is UTC+9 under
         * POSIX's own inverted TZ sign convention, and has no DST to make
         * the expected offset date-dependent. tzset() *before* reading is
         * the correct order. */
        ASSERT_EQ_INT(setenv("TZ", ":/usr/share/zoneinfo/Etc/GMT-9", 1), 0);
        tzset();

        r = netd_time_build_tz(&after);
        ASSERT_EQ_INT(r, 0);

        /* struct timezone's own sign convention: west of UTC is positive, so
         * UTC+9 is tz_minuteswest == -540. An implementation that read this
         * BEFORE the tzset() above would still see 0, exactly `before`'s
         * value -- precisely the inversion netd_time_set_timezone()'s header
         * comment warns against. */
        ASSERT_EQ_INT(after.tz_minuteswest, -540);
        ASSERT_TRUE(after.tz_minuteswest != before.tz_minuteswest);

        unsetenv("TZ");
        tzset();
}

/*
 * Fake UDP/123 responder. Rejects-only (see the file header): a real NTP server on loopback, replying with a
 * packet too short to be a valid header, driven through netd_sntp_process()'s real recvmsg()/SO_TIMESTAMPNS
 * path rather than a synthetic buffer -- proof the socket plumbing and netd_sntp_validate() agree outside a
 * unit test's own hand-built bytes. No network namespace: two loopback UDP sockets have no effect to isolate
 * from the host in the first place, unlike the interfaces and routes the rtnl/DHCP tests touch.
 */
static void test_sntp_process_over_real_socket(void) {
        Netd n;
        NetdSntp *s = NULL;
        int server_fd;
        struct sockaddr_in server_addr = { 0 };
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        struct in_addr servers[1];
        uint8_t reqbuf[128];
        uint8_t garbage[4] = { 1, 2, 3, 4 };
        ssize_t rlen, slen;
        struct pollfd pfd;
        int pr;

        /* netd_sntp_new()/_start()/_free() only ever touch n.epoll_fd (via
         * netd_loop_add_io()/_remove_io()) and n.timer (via the retry/resync
         * timer) -- not netd_loop_setup()'s signalfd/timerfd registration, so
         * building exactly those two fields directly is enough. See the
         * comment on test_clock_floor_apply_and_touch() for why this does
         * not go through netd_new(). */
        memset(&n, 0, sizeof(n));

        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(NETD_NTP_PORT);
        server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        server_fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (server_fd < 0) {
                fprintf(stderr, "test-netd-sntp: socket() failed: %s\n", strerror(errno));
                exit(1);
        }

        /* A hang here must fail the test loudly rather than stall the whole
         * suite: bound to a few seconds, not left blocking forever. */
        {
                struct timeval tv = { .tv_sec = 5, .tv_usec = 0 };

                if (setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
                        fprintf(stderr,
                                "test-netd-sntp: setsockopt(SO_RCVTIMEO) failed: %s\n",
                                strerror(errno));
                        exit(1);
                }
        }

        if (bind(server_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
                fprintf(stderr,
                        "test-netd-sntp: bind(:%d) failed: %s -- the verify container must run this as root\n",
                        NETD_NTP_PORT,
                        strerror(errno));
                exit(1);
        }

        n.epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (n.epoll_fd < 0) {
                fprintf(stderr, "test-netd-sntp: epoll_create1() failed: %s\n", strerror(errno));
                exit(1);
        }
        if (pico_timer_new(&n.timer) < 0) {
                fprintf(stderr, "test-netd-sntp: pico_timer_new() failed\n");
                exit(1);
        }

        ASSERT_EQ_INT(netd_sntp_new(&n, &s), 0);

        servers[0].s_addr = htonl(INADDR_LOOPBACK);
        ASSERT_EQ_INT(netd_sntp_set_servers(s, servers, 1), 0);
        ASSERT_EQ_INT(netd_sntp_start(s), 0);

        rlen = recvfrom(server_fd, reqbuf, sizeof(reqbuf), 0, (struct sockaddr *) &client_addr, &client_len);
        if (rlen != (ssize_t) sizeof(NetdNtpMsg)) {
                fprintf(stderr,
                        "test-netd-sntp: fake server got %zd bytes, expected %zu\n",
                        rlen,
                        sizeof(NetdNtpMsg));
                exit(1);
        }

        slen = sendto(server_fd, garbage, sizeof(garbage), 0, (struct sockaddr *) &client_addr, client_len);
        if (slen != (ssize_t) sizeof(garbage)) {
                fprintf(stderr, "test-netd-sntp: fake server sendto() failed: %s\n", strerror(errno));
                exit(1);
        }

        pfd.fd = s->fd;
        pfd.events = POLLIN;
        pr = poll(&pfd, 1, 2000);
        if (pr != 1) {
                fprintf(stderr, "test-netd-sntp: client socket never became readable\n");
                exit(1);
        }

        ASSERT_EQ_INT(netd_sntp_process(s), 0);
        ASSERT_TRUE(!s->synchronised);
        ASSERT_TRUE(s->request.pending); /* a rejected reply leaves the request outstanding */

        netd_sntp_free(s);
        (void) pico_timer_free(n.timer);
        (void) close(n.epoll_fd);
        (void) close(server_fd);
}

int main(void) {
        test_packet_layout();
        test_field_packing();
        test_timestamp_roundtrip();
        test_reject_names();

        test_validate_accepted();
        test_validate_malformed();
        test_validate_unsolicited();
        test_validate_source();
        test_validate_nonce();
        test_validate_zero_timestamp();
        test_validate_epoch();
        test_validate_leap();
        test_validate_stratum();
        test_validate_version();
        test_validate_mode();
        test_validate_root_distance();

        test_compute();

        test_build_timex_slew();
        test_build_timex_step();
        test_build_timex_boundary();

        test_clock_floor_decide();
        test_clock_floor_apply_and_touch();

        test_timezone_validity();
        test_timezone_symlink_swap();
        test_tz_build_ordering();

        test_sntp_process_over_real_socket();

        printf("test-netd-sntp: ok\n");
        return EXIT_SUCCESS;
}
