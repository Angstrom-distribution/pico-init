/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * N4's acceptance test: the SNTP client and the clock/timezone applier.
 *
 * Registered up front, placeholder body. What lands here (plan §2.8): a
 * ~50-line fake UDP/123 responder, one case per NetdSntpReject value -- every
 * validation check exercised individually, including the nonce mismatch that
 * is the anti-off-path-spoofing test -- plus assertions on the computed
 * step-versus-slew decision.
 *
 * Computed, never applied. clock_adjtime() is process-global and stays global
 * inside a network namespace, so the netns trick that makes the rtnl and DHCP
 * tests safe does nothing here; a test that actually stepped the clock would
 * be a test that broke the machine running it. That constraint is why
 * netd_sntp_validate() and netd_time_build_timex() are pure functions in the
 * first place.
 *
 * What it can already assert: the wire-format arithmetic and the shape of the
 * packet header, both of which are fixed by RFC 5905 and neither of which
 * needs a socket.
 */

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test-util.h"
#include "netd-sntp.h"
#include "netd-time.h"

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
 * origin field, so a lossy conversion here is a client that rejects every
 * honest answer it gets.
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

int main(void) {
        test_packet_layout();
        test_field_packing();
        test_timestamp_roundtrip();
        test_reject_names();

        printf("test-netd-sntp: ok\n");
        return EXIT_SUCCESS;
}
