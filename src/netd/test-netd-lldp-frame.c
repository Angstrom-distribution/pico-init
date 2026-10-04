/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * LLDP frame parser and builder: real frames (from systemd's fuzz corpus and
 * hand-built ones), golden bytes for the builder, every rejection rule, and a
 * seeded mutation run that checks the parser never reports a slice outside the
 * frame, whatever bytes it is fed.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test-util.h"
#include "lldp/lldp-frame.h"

/* test/fuzz/fuzz-lldp-rx/basic in systemd (source MAC's group bit cleared, which the parser rejects):
 * chassis MAC, port "1/3", TTL 120, a port description, name and description. */
static const uint8_t frame_basic[] = {
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x03, 0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x88,
        0xcc, 0x02, 0x07, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x04, 0x04, 0x05,
        0x31, 0x2f, 0x33, 0x06, 0x02, 0x00, 0x78, 0x08, 0x04, 0x50, 0x6f, 0x72, 0x74,
        0x0a, 0x03, 0x53, 0x59, 0x53, 0x0c, 0x04, 0x66, 0x6f, 0x6f, 0x00, 0x00, 0x00,
};

/* .../incomplete: ends before the TTL TLV. */
static const uint8_t frame_incomplete[] = {
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x03, 0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x88, 0xcc, 0x02, 0x07,
        0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x04, 0x04, 0x05, 0x31, 0x2f, 0x33, 0x00, 0x00,
};

/* .../oui: 802.1 organizationally specific TLVs, the first of which is the port VLAN ID 0x1234. */
static const uint8_t frame_oui[] = {
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x03, 0x02, 0x02, 0x03, 0x04, 0x05, 0x06, 0x88, 0xcc, 0x02,
        0x07, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x04, 0x04, 0x05, 0x31, 0x2f, 0x33, 0x06,
        0x02, 0x00, 0x78, 0xfe, 0x06, 0x00, 0x80, 0xc2, 0x01, 0x12, 0x34, 0xfe, 0x07, 0x00, 0x80,
        0xc2, 0x02, 0x01, 0x77, 0x88, 0xfe, 0x0d, 0x00, 0x80, 0xc2, 0x03, 0x12, 0x34, 0x06, 0x56,
        0x6c, 0x61, 0x6e, 0x35, 0x31, 0xfe, 0x06, 0x00, 0x80, 0xc2, 0x06, 0x01, 0x02, 0xfe, 0x09,
        0x00, 0x80, 0xc2, 0x07, 0x01, 0x00, 0x14, 0x00, 0x12, 0x00, 0x00,
};

static bool in_frame(const LldpSlice s, size_t len) {
        return (size_t) s.off + s.len <= len;
}

static void expect_str(const uint8_t *frame, LldpSlice s, const char *want) {
        ASSERT_EQ_INT(s.len, strlen(want));
        ASSERT_TRUE(memcmp(lldp_slice_data(frame, s), want, s.len) == 0);
}

static void test_real_frames(void) {
        LldpFrame f;
        const char *why = NULL;

        ASSERT_EQ_INT(lldp_frame_parse(frame_basic, sizeof(frame_basic), &f, &why), 0);
        ASSERT_EQ_INT(f.scope, LLDP_SCOPE_NON_TPMR_BRIDGE);
        ASSERT_EQ_INT(f.chassis_subtype, LLDP_CHASSIS_SUBTYPE_MAC);
        ASSERT_EQ_INT(f.chassis.len, 6);
        ASSERT_EQ_INT(f.port_subtype, LLDP_PORT_SUBTYPE_INTERFACE_NAME);
        expect_str(frame_basic, f.port, "1/3");
        ASSERT_EQ_INT(f.ttl, 120);
        expect_str(frame_basic, f.port_description, "Port");
        expect_str(frame_basic, f.system_name, "SYS");
        ASSERT_EQ_INT(f.system_description.len, 4); /* "foo" and its terminating NUL, kept as sent */
        ASSERT_TRUE(!f.has_capabilities);
        ASSERT_TRUE(memcmp(f.src, "\x02\x02\x03\x04\x05\x06", 6) == 0);

        /* The TTL TLV never arrives: rejected, with a reason. */
        ASSERT_EQ_INT(lldp_frame_parse(frame_incomplete, sizeof(frame_incomplete), &f, &why), -EBADMSG);
        ASSERT_TRUE(why != NULL);

        ASSERT_EQ_INT(lldp_frame_parse(frame_oui, sizeof(frame_oui), &f, &why), 0);
        ASSERT_TRUE(f.has_port_vlan_id);
        ASSERT_EQ_INT(f.port_vlan_id, 0x1234);
}

static LldpBuild sample_build(void) {
        static const uint8_t chassis[] = "0123456789abcdef0123456789abcdef";
        static const uint8_t port[] = "usb0";

        return (LldpBuild){
                .src = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 },
                .scope = LLDP_SCOPE_NEAREST_BRIDGE,
                .chassis_subtype = LLDP_CHASSIS_SUBTYPE_LOCAL,
                .chassis = chassis,
                .chassis_len = sizeof(chassis) - 1,
                .port_subtype = LLDP_PORT_SUBTYPE_INTERFACE_NAME,
                .port = port,
                .port_len = sizeof(port) - 1,
                .ttl = 120,
                .system_name = "h2200",
                .system_description = "Angstrom-pico v2026.06",
                .has_capabilities = true,
                .capabilities = LLDP_CAP_STATION | LLDP_CAP_ROUTER,
                .enabled_capabilities = LLDP_CAP_STATION,
                .has_management_ipv4 = true,
                .management_ipv4 = { 192, 168, 7, 2 },
                .management_ifindex = 2,
        };
}

static void test_build_golden(void) {
        uint8_t buf[LLDP_FRAME_MAX];
        size_t len = 0;
        LldpBuild b = {
                .src = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 },
                .scope = LLDP_SCOPE_NEAREST_BRIDGE,
                .chassis_subtype = LLDP_CHASSIS_SUBTYPE_MAC,
                .chassis = (const uint8_t *) "\x02\x11\x22\x33\x44\x55",
                .chassis_len = 6,
                .port_subtype = LLDP_PORT_SUBTYPE_INTERFACE_NAME,
                .port = (const uint8_t *) "usb0",
                .port_len = 4,
                .ttl = 120,
        };
        static const uint8_t want[] = {
                0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e, /* destination: nearest bridge */
                0x02, 0x11, 0x22, 0x33, 0x44, 0x55, /* source */
                0x88, 0xcc, 0x02, 0x07, 0x04, 0x02, 0x11,
                0x22, 0x33, 0x44, 0x55,                  /* chassis ID: MAC address */
                0x04, 0x05, 0x05, 'u',  's',  'b',  '0', /* port ID: interface name */
                0x06, 0x02, 0x00, 0x78,                  /* TTL 120 */
                0x00, 0x00,                              /* End */
        };

        ASSERT_EQ_INT(lldp_frame_build(buf, sizeof(buf), &b, &len), 0);
        ASSERT_EQ_INT(len, LLDP_ETH_MIN_FRAME); /* padded to the Ethernet minimum */
        ASSERT_TRUE(memcmp(buf, want, sizeof(want)) == 0);
        {
                size_t i;

                for (i = sizeof(want); i < len; i++)
                        ASSERT_EQ_INT(buf[i], 0);
        }
}

static void test_build_parse_roundtrip(void) {
        uint8_t buf[LLDP_FRAME_MAX];
        LldpBuild b = sample_build();
        LldpFrame f;
        size_t len = 0;

        ASSERT_EQ_INT(lldp_frame_build(buf, sizeof(buf), &b, &len), 0);
        ASSERT_TRUE(len > LLDP_ETH_MIN_FRAME);
        ASSERT_EQ_INT(lldp_frame_parse(buf, len, &f, NULL), 0);
        ASSERT_EQ_INT(f.scope, LLDP_SCOPE_NEAREST_BRIDGE);
        ASSERT_EQ_INT(f.chassis_subtype, LLDP_CHASSIS_SUBTYPE_LOCAL);
        ASSERT_EQ_INT(f.chassis.len, 32);
        expect_str(buf, f.port, "usb0");
        ASSERT_EQ_INT(f.ttl, 120);
        expect_str(buf, f.system_name, "h2200");
        expect_str(buf, f.system_description, "Angstrom-pico v2026.06");
        ASSERT_TRUE(f.has_capabilities);
        ASSERT_EQ_INT(f.capabilities, LLDP_CAP_STATION | LLDP_CAP_ROUTER);
        ASSERT_EQ_INT(f.enabled_capabilities, LLDP_CAP_STATION);
        ASSERT_TRUE(f.has_management_ipv4);
        ASSERT_TRUE(memcmp(f.management_ipv4, "\xc0\xa8\x07\x02", 4) == 0);
        ASSERT_TRUE(lldp_frame_same_msap(buf, &f, buf, &f));

        /* Control bytes in a string are sent as spaces, and a string longer than 255 bytes is cut. */
        {
                char long_name[400];

                memset(long_name, 'x', sizeof(long_name) - 1);
                long_name[sizeof(long_name) - 1] = '\0';
                long_name[3] = '\n';
                b.system_name = long_name;
                ASSERT_EQ_INT(lldp_frame_build(buf, sizeof(buf), &b, &len), 0);
                ASSERT_EQ_INT(lldp_frame_parse(buf, len, &f, NULL), 0);
                ASSERT_EQ_INT(f.system_name.len, 255);
                ASSERT_EQ_INT(buf[f.system_name.off + 3], ' ');
        }
}

static void test_build_rejects_bad_input(void) {
        uint8_t buf[LLDP_FRAME_MAX], small[40];
        size_t len = 0;
        LldpBuild b = sample_build();

        ASSERT_EQ_INT(lldp_frame_build(small, sizeof(small), &b, &len), -ENOBUFS);
        ASSERT_EQ_INT(lldp_frame_build(buf, 80, &b, &len), -ENOBUFS); /* too small for the optional TLVs */

        b.chassis_len = 0;
        ASSERT_EQ_INT(lldp_frame_build(buf, sizeof(buf), &b, &len), -EINVAL);
        b = sample_build();
        b.port_subtype = 8;
        ASSERT_EQ_INT(lldp_frame_build(buf, sizeof(buf), &b, &len), -EINVAL);
        b = sample_build();
        b.scope = _LLDP_SCOPE_MAX;
        ASSERT_EQ_INT(lldp_frame_build(buf, sizeof(buf), &b, &len), -EINVAL);
}

/* A valid frame, patched, and what the parser says about it. */
static void expect_reject(const uint8_t *frame, size_t len, const char *what) {
        LldpFrame f;
        const char *why = NULL;
        int r = lldp_frame_parse(frame, len, &f, &why);

        if (r != -EBADMSG && r != -EMSGSIZE) {
                fprintf(stderr, "test-netd-lldp-frame: %s was accepted (%d)\n", what, r);
                exit(1);
        }
        ASSERT_TRUE(why != NULL && why[0] != '\0');
}

static void test_rejections(void) {
        uint8_t base[LLDP_FRAME_MAX], f[LLDP_FRAME_MAX];
        LldpBuild b = sample_build();
        size_t len = 0, i;
        LldpFrame parsed;

        ASSERT_EQ_INT(lldp_frame_build(base, sizeof(base), &b, &len), 0);

        /* The header. */
        memcpy(f, base, len);
        f[13] = 0xcd;
        expect_reject(f, len, "wrong ethertype");
        memcpy(f, base, len);
        f[5] = 0x01; /* not a reserved address */
        expect_reject(f, len, "wrong destination");
        memcpy(f, base, len);
        f[0] = 0xff;
        f[1] = f[2] = f[3] = f[4] = f[5] = 0xff;
        expect_reject(f, len, "broadcast destination");
        memcpy(f, base, len);
        f[6] = 0x03; /* group bit set in the source */
        expect_reject(f, len, "group source");
        memcpy(f, base, len);
        memset(f + 6, 0, 6);
        expect_reject(f, len, "all zero source");

        /* Too short for a header and the three TLVs, at every length. */
        for (i = 0; i < LLDP_ETH_HEADER + 6; i++)
                expect_reject(base, i, "short frame");
        expect_reject(base, LLDP_FRAME_MAX + 1, "frame over the limit");

        /* Cut anywhere inside the mandatory TLVs or in the middle of any TLV: never accepted past the point it breaks. */
        for (i = LLDP_ETH_HEADER; i < len; i++) {
                int r = lldp_frame_parse(base, i, &parsed, NULL);

                if (r == 0) {
                        /* Accepted only if it ends on a TLV boundary after the mandatory three. */
                        ASSERT_TRUE(in_frame(parsed.chassis, i) && in_frame(parsed.port, i));
                }
        }

        /* Mandatory TLVs: out of order, repeated, missing. */
        memcpy(f, base, len);
        f[LLDP_ETH_HEADER] = LLDP_TLV_PORT_ID << 1; /* the first TLV claims to be a port ID */
        expect_reject(f, len, "port ID first");

        {
                /* chassis, port, then a second TTL TLV after the first */
                uint8_t dup[64];
                size_t n = LLDP_ETH_HEADER;
                const uint8_t tlvs[] = { 0x02, 0x03, 0x07, 'a',  'b',  0x04, 0x03, 0x05, 'c',  'd',
                                         0x06, 0x02, 0x00, 0x78, 0x06, 0x02, 0x00, 0x05, 0x00, 0x00 };

                memcpy(dup, base, LLDP_ETH_HEADER);
                memcpy(dup + n, tlvs, sizeof(tlvs));
                expect_reject(dup, n + sizeof(tlvs), "second TTL TLV");

                /* the same frame without the repeated TTL is fine */
                memcpy(dup + n, tlvs, 14);
                dup[n + 14] = 0;
                dup[n + 15] = 0;
                ASSERT_EQ_INT(lldp_frame_parse(dup, n + 16, &parsed, NULL), 0);
                ASSERT_EQ_INT(parsed.chassis_subtype, 7);
        }

        /* ID TLVs: subtype 0 and 8 are not defined, an ID with no value is not an ID, size 257 is too long. */
        memcpy(f, base, len);
        f[LLDP_ETH_HEADER + 2] = 0;
        expect_reject(f, len, "chassis subtype 0");
        memcpy(f, base, len);
        f[LLDP_ETH_HEADER + 2] = 8;
        expect_reject(f, len, "chassis subtype 8");
        {
                uint8_t big[LLDP_FRAME_MAX];
                size_t n = LLDP_ETH_HEADER;

                memcpy(big, base, LLDP_ETH_HEADER);
                big[n++] = (LLDP_TLV_CHASSIS_ID << 1) | 1; /* length 257 */
                big[n++] = 1;
                big[n++] = 7;
                memset(big + n, 'a', 256);
                n += 256;
                big[n++] = LLDP_TLV_PORT_ID << 1;
                big[n++] = 2;
                big[n++] = 5;
                big[n++] = 'p';
                big[n++] = LLDP_TLV_TTL << 1;
                big[n++] = 2;
                big[n++] = 0;
                big[n++] = 1;
                big[n++] = 0;
                big[n++] = 0;
                expect_reject(big, n, "chassis ID of 257 bytes");

                big[LLDP_ETH_HEADER] = LLDP_TLV_CHASSIS_ID << 1; /* 256 bytes, the most the standard allows */
                big[LLDP_ETH_HEADER + 1] = 0;
                expect_reject(big, n, "chassis ID of length 0 with trailing garbage");
        }

        /* A TTL of the wrong size, a TLV that runs past the end, an End TLV with a value. */
        memcpy(f, base, len);
        f[LLDP_ETH_HEADER + 35 + 7 + 1] =
                        3; /* TTL TLV length 3: after the 35 byte chassis and 7 byte port TLVs */
        expect_reject(f, len, "TTL of three bytes");
        memcpy(f, base, len);
        f[LLDP_ETH_HEADER + 1] = 200; /* chassis TLV claims 200 bytes */
        expect_reject(f, len, "TLV overruns the frame");
        {
                uint8_t e[64];
                size_t n = LLDP_ETH_HEADER;
                const uint8_t tlvs[] = { 0x02, 0x03, 0x07, 'a',  'b',  0x04, 0x03, 0x05, 'c',
                                         'd',  0x06, 0x02, 0x00, 0x78, 0x00, 0x01, 0xaa };

                memcpy(e, base, LLDP_ETH_HEADER);
                memcpy(e + n, tlvs, sizeof(tlvs));
                expect_reject(e, n + sizeof(tlvs), "End TLV with a value");
        }

        /* A lone trailing byte after the last TLV is not a TLV header. */
        {
                uint8_t t[64];
                size_t n = LLDP_ETH_HEADER;
                const uint8_t tlvs[] = { 0x02, 0x03, 0x07, 'a',  'b',  0x04, 0x03, 0x05,
                                         'c',  'd',  0x06, 0x02, 0x00, 0x78, 0x0a };

                memcpy(t, base, LLDP_ETH_HEADER);
                memcpy(t + n, tlvs, sizeof(tlvs));
                expect_reject(t, n + sizeof(tlvs), "one trailing byte");

                /* Without an End TLV but ending exactly on a TLV boundary is accepted. */
                ASSERT_EQ_INT(lldp_frame_parse(t, n + sizeof(tlvs) - 1, &parsed, NULL), 0);
        }
}

static void test_optional_tlvs(void) {
        uint8_t buf[256];
        LldpFrame f;
        size_t n = LLDP_ETH_HEADER;
        /* chassis, port, TTL, then: port description twice (the first one wins), a capabilities TLV of the wrong
         * size (skipped), an unknown type 9 (skipped), a short organizationally specific TLV (skipped), End. */
        const uint8_t tlvs[] = {
                0x02, 0x03, 0x07, 'a',  'b',  0x04, 0x03, 0x05, 'c',  'd',  0x06, 0x02, 0x00,
                0x78, 0x08, 0x03, 'o',  'n',  'e',  0x08, 0x03, 't',  'w',  'o',  0x0e, 0x02,
                0x00, 0x14, 0x12, 0x01, 0xff, 0xfe, 0x02, 0x00, 0x80, 0x00, 0x00,
        };

        memcpy(buf, frame_basic, LLDP_ETH_HEADER);
        memcpy(buf + n, tlvs, sizeof(tlvs));
        ASSERT_EQ_INT(lldp_frame_parse(buf, n + sizeof(tlvs), &f, NULL), 0);
        expect_str(buf, f.port_description, "one");
        ASSERT_TRUE(!f.has_capabilities);
        ASSERT_EQ_INT(f.system_name.len, 0);

        /* An 802.1 VLAN TLV of the wrong length is skipped, not trusted. */
        n = LLDP_ETH_HEADER;
        {
                const uint8_t v[] = {
                        0x02, 0x03, 0x07, 'a',  'b',  0x04, 0x03, 0x05, 'c',  'd',  0x06, 0x02,
                        0x00, 0x78, 0xfe, 0x05, 0x00, 0x80, 0xc2, 0x01, 0x12, 0x00, 0x00,
                };

                memcpy(buf + n, v, sizeof(v));
                ASSERT_EQ_INT(lldp_frame_parse(buf, n + sizeof(v), &f, NULL), 0);
                ASSERT_TRUE(!f.has_port_vlan_id);
        }
}

/* xorshift64: deterministic, so a failure reproduces. */
static uint64_t rng_state = 0x9e3779b97f4a7c15ull;

static uint64_t rng(void) {
        rng_state ^= rng_state << 13;
        rng_state ^= rng_state >> 7;
        rng_state ^= rng_state << 17;
        return rng_state;
}

static void check_invariants(const uint8_t *frame, size_t len, const LldpFrame *f) {
        ASSERT_TRUE(f->scope < _LLDP_SCOPE_MAX);
        ASSERT_TRUE(f->chassis.len >= 1 && in_frame(f->chassis, len));
        ASSERT_TRUE(f->port.len >= 1 && in_frame(f->port, len));
        ASSERT_TRUE(f->chassis_subtype >= 1 && f->chassis_subtype <= 7);
        ASSERT_TRUE(f->port_subtype >= 1 && f->port_subtype <= 7);
        ASSERT_TRUE(in_frame(f->port_description, len));
        ASSERT_TRUE(in_frame(f->system_name, len));
        ASSERT_TRUE(in_frame(f->system_description, len));
        ASSERT_TRUE(in_frame(f->mud_url, len));
        ASSERT_TRUE(f->port_description.len <= 255 && f->system_name.len <= 255 &&
                    f->system_description.len <= 255 && f->mud_url.len <= 255);
        ASSERT_TRUE(!(f->src[0] & 1));
        (void) frame;
}

/* Mutate valid frames in every way that is cheap to think of and require that nothing reaches outside the frame. */
static void test_mutation(void) {
        const uint8_t *seeds[3] = { frame_basic, frame_oui, NULL };
        size_t seed_len[3] = { sizeof(frame_basic), sizeof(frame_oui), 0 };
        uint8_t built[LLDP_FRAME_MAX];
        LldpBuild b = sample_build();
        unsigned iter;
        size_t blen = 0;

        ASSERT_EQ_INT(lldp_frame_build(built, sizeof(built), &b, &blen), 0);
        seeds[2] = built;
        seed_len[2] = blen;

        for (iter = 0; iter < 300000; iter++) {
                uint8_t f[LLDP_FRAME_MAX + 8];
                unsigned s = (unsigned) (rng() % 3), flips, k;
                size_t len = seed_len[s];
                LldpFrame parsed;
                int r;

                memcpy(f, seeds[s], len);
                flips = (unsigned) (rng() % 6);
                for (k = 0; k < flips; k++)
                        f[rng() % len] = (uint8_t) rng();

                switch (rng() % 4) {
                case 0:
                        len = rng() % (len + 1); /* truncate */
                        break;
                case 1: {
                        size_t add = rng() % 64; /* extend with garbage */

                        while (add-- && len < LLDP_FRAME_MAX)
                                f[len++] = (uint8_t) rng();
                        break;
                }
                default:
                        break;
                }

                r = lldp_frame_parse(f, len, &parsed, NULL);
                if (r == 0)
                        check_invariants(f, len, &parsed);
        }
}

int main(void) {
        test_real_frames();
        test_build_golden();
        test_build_parse_roundtrip();
        test_build_rejects_bad_input();
        test_rejections();
        test_optional_tlvs();
        test_mutation();
        printf("test-netd-lldp-frame: ok\n");
        return EXIT_SUCCESS;
}
