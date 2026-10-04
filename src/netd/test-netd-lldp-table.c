/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The LLDP neighbour table: add, refresh, update, shutdown, expiry, the size
 * cap and the capability filter, all against a clock the test moves by hand.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test-util.h"
#include "lldp/lldp-table.h"

#define SEC 1000000ull

/* Neighbour number `id` on a made-up port, with the given TTL and name. */
static size_t make_frame(uint8_t *buf, unsigned id, unsigned ttl, const char *name, bool caps, uint16_t enabled) {
        uint8_t chassis[2] = { (uint8_t) (id >> 8), (uint8_t) id };
        LldpBuild b = {
                .src = { 0x02, 0, 0, 0, 0, (uint8_t) id },
                .scope = LLDP_SCOPE_NEAREST_BRIDGE,
                .chassis_subtype = LLDP_CHASSIS_SUBTYPE_LOCAL,
                .chassis = chassis,
                .chassis_len = 2,
                .port_subtype = LLDP_PORT_SUBTYPE_LOCAL,
                .port = (const uint8_t *) "p1",
                .port_len = 2,
                .ttl = (uint16_t) ttl,
                .system_name = name,
                .has_capabilities = caps,
                .capabilities = enabled,
                .enabled_capabilities = enabled,
        };
        size_t len = 0;

        ASSERT_EQ_INT(lldp_frame_build(buf, LLDP_FRAME_MAX, &b, &len), 0);
        return len;
}

static LldpEvent offer(LldpTable *t, unsigned id, unsigned ttl, const char *name, uint64_t now, uint16_t mask) {
        uint8_t buf[LLDP_FRAME_MAX];
        LldpFrame f;
        size_t len = make_frame(buf, id, ttl, name, true, LLDP_CAP_STATION);

        ASSERT_EQ_INT(lldp_frame_parse(buf, len, &f, NULL), 0);
        return lldp_table_offer(t, buf, len, &f, mask, now);
}

static void test_add_refresh_update_shutdown(void) {
        LldpTable t = { 0 };

        ASSERT_EQ_INT(offer(&t, 1, 120, "alpha", 10 * SEC, UINT16_MAX), LLDP_EVENT_ADDED);
        ASSERT_EQ_INT(t.n, 1);
        ASSERT_TRUE(lldp_table_next_expiry(&t) == 130 * SEC);

        /* The same frame again, and the same with another TTL: content unchanged, only the expiry moves. */
        ASSERT_EQ_INT(offer(&t, 1, 120, "alpha", 40 * SEC, UINT16_MAX), LLDP_EVENT_REFRESHED);
        ASSERT_TRUE(lldp_table_next_expiry(&t) == 160 * SEC);
        ASSERT_EQ_INT(offer(&t, 1, 60, "alpha", 50 * SEC, UINT16_MAX), LLDP_EVENT_REFRESHED);
        ASSERT_TRUE(lldp_table_next_expiry(&t) == 110 * SEC);
        ASSERT_EQ_INT(t.entries[0]->f.ttl, 60);

        /* Same length, different content; then a different length. */
        ASSERT_EQ_INT(offer(&t, 1, 120, "alpHa", 60 * SEC, UINT16_MAX), LLDP_EVENT_UPDATED);
        ASSERT_EQ_INT(offer(&t, 1, 120, "a-much-longer-name", 61 * SEC, UINT16_MAX), LLDP_EVENT_UPDATED);
        ASSERT_EQ_INT(t.n, 1);
        ASSERT_EQ_INT(t.entries[0]->f.system_name.len, strlen("a-much-longer-name"));
        ASSERT_TRUE(memcmp(t.entries[0]->frame + t.entries[0]->f.system_name.off, "a-much-longer-name", 18) ==
                    0);

        /* A second neighbour, then a shutdown for the first: only the first goes. */
        ASSERT_EQ_INT(offer(&t, 2, 120, "beta", 62 * SEC, UINT16_MAX), LLDP_EVENT_ADDED);
        ASSERT_EQ_INT(offer(&t, 1, 0, "a-much-longer-name", 63 * SEC, UINT16_MAX), LLDP_EVENT_REMOVED);
        ASSERT_EQ_INT(t.n, 1);
        ASSERT_EQ_INT(t.entries[0]->f.chassis.len, 2);
        ASSERT_EQ_INT(offer(&t, 1, 0, "x", 64 * SEC, UINT16_MAX), LLDP_EVENT_IGNORED); /* unknown */

        lldp_table_clear(&t);
        ASSERT_EQ_INT(t.n, 0);
        ASSERT_TRUE(lldp_table_next_expiry(&t) == 0);
}

static void test_expiry(void) {
        LldpTable t = { 0 };

        ASSERT_EQ_INT(offer(&t, 1, 30, "a", 0, UINT16_MAX), LLDP_EVENT_ADDED);
        ASSERT_EQ_INT(offer(&t, 2, 60, "b", 0, UINT16_MAX), LLDP_EVENT_ADDED);
        ASSERT_EQ_INT(offer(&t, 3, 90, "c", 0, UINT16_MAX), LLDP_EVENT_ADDED);
        ASSERT_TRUE(lldp_table_next_expiry(&t) == 30 * SEC);

        ASSERT_EQ_INT(lldp_table_expire(&t, 29 * SEC), 0);
        ASSERT_EQ_INT(lldp_table_expire(&t, 30 * SEC), 1); /* at the deadline is expired */
        ASSERT_EQ_INT(t.n, 2);
        ASSERT_TRUE(lldp_table_next_expiry(&t) == 60 * SEC);
        ASSERT_EQ_INT(lldp_table_expire(&t, 1000 * SEC), 2);
        ASSERT_EQ_INT(t.n, 0);

        /* A frame for a neighbour that has silently expired is a new one, not a refresh. */
        ASSERT_EQ_INT(offer(&t, 1, 30, "a", 0, UINT16_MAX), LLDP_EVENT_ADDED);
        ASSERT_EQ_INT(offer(&t, 1, 30, "a", 100 * SEC, UINT16_MAX), LLDP_EVENT_ADDED);
        lldp_table_clear(&t);
}

static void test_full_table(void) {
        LldpTable t = { 0 };
        unsigned i;

        for (i = 1; i <= LLDP_TABLE_MAX; i++)
                ASSERT_EQ_INT(offer(&t, i, 100, "n", 0, UINT16_MAX), LLDP_EVENT_ADDED);
        ASSERT_EQ_INT(t.n, LLDP_TABLE_MAX);

        /* Further neighbours are dropped, however many, and the table does not grow or evict. */
        for (i = 100; i < 400; i++)
                ASSERT_EQ_INT(offer(&t, i, 100, "n", 1 * SEC, UINT16_MAX), LLDP_EVENT_FULL);
        ASSERT_EQ_INT(t.n, LLDP_TABLE_MAX);

        /* A known neighbour still refreshes, updates and can shut down while the table is full. */
        ASSERT_EQ_INT(offer(&t, 3, 100, "n", 2 * SEC, UINT16_MAX), LLDP_EVENT_REFRESHED);
        ASSERT_EQ_INT(offer(&t, 3, 100, "changed", 3 * SEC, UINT16_MAX), LLDP_EVENT_UPDATED);
        ASSERT_EQ_INT(offer(&t, 4, 0, "n", 4 * SEC, UINT16_MAX), LLDP_EVENT_REMOVED);

        /* ...which makes room for exactly one newcomer. */
        ASSERT_EQ_INT(offer(&t, 200, 100, "n", 5 * SEC, UINT16_MAX), LLDP_EVENT_ADDED);
        ASSERT_EQ_INT(offer(&t, 201, 100, "n", 5 * SEC, UINT16_MAX), LLDP_EVENT_FULL);

        /* Once the old ones have expired a newcomer fits again. */
        ASSERT_EQ_INT(offer(&t, 201, 100, "n", 1000 * SEC, UINT16_MAX), LLDP_EVENT_ADDED);
        ASSERT_EQ_INT(t.n, 1);
        lldp_table_clear(&t);
}

static void test_capability_filter(void) {
        LldpTable t = { 0 };
        uint8_t buf[LLDP_FRAME_MAX];
        LldpFrame f;
        size_t len;

        /* A station is not a router: filtered. */
        ASSERT_EQ_INT(offer(&t, 1, 120, "host", 0, LLDP_CAP_ROUTER | LLDP_CAP_BRIDGE), LLDP_EVENT_IGNORED);
        ASSERT_EQ_INT(t.n, 0);

        /* A bridge passes; when it later stops being one it is dropped again. */
        len = make_frame(buf, 2, 120, "sw", true, LLDP_CAP_BRIDGE);
        ASSERT_EQ_INT(lldp_frame_parse(buf, len, &f, NULL), 0);
        ASSERT_EQ_INT(lldp_table_offer(&t, buf, len, &f, LLDP_CAP_ROUTER | LLDP_CAP_BRIDGE, 0),
                      LLDP_EVENT_ADDED);
        len = make_frame(buf, 2, 120, "sw", true, LLDP_CAP_STATION);
        ASSERT_EQ_INT(lldp_frame_parse(buf, len, &f, NULL), 0);
        ASSERT_EQ_INT(lldp_table_offer(&t, buf, len, &f, LLDP_CAP_ROUTER | LLDP_CAP_BRIDGE, 1),
                      LLDP_EVENT_REMOVED);

        /* No capabilities TLV at all is accepted, as in systemd. */
        len = make_frame(buf, 3, 120, "plain", false, 0);
        ASSERT_EQ_INT(lldp_frame_parse(buf, len, &f, NULL), 0);
        ASSERT_EQ_INT(lldp_table_offer(&t, buf, len, &f, LLDP_CAP_ROUTER, 2), LLDP_EVENT_ADDED);
        lldp_table_clear(&t);
}

int main(void) {
        test_add_refresh_update_shutdown();
        test_expiry();
        test_full_table();
        test_capability_filter();
        printf("test-netd-lldp-table: ok\n");
        return EXIT_SUCCESS;
}
