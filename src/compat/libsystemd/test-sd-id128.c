/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * memfd_create() needs _GNU_SOURCE on glibc.
 */
#define _GNU_SOURCE

#include "hmac-sha256.h"
#include "id128-internal.h"
#include "sd-id128.h"
#include "sha256.h"

#include "../../test-util.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* --- small test-only helpers (not part of the shim under test) --- */

static void hex_decode(const char *hex, uint8_t *out, size_t n) {
        for (size_t i = 0; i < n; i++) {
                unsigned v = 0;

                sscanf(hex + i * 2, "%2x", &v);
                out[i] = (uint8_t) v;
        }
}

/* A memfd pre-loaded with `content`, rewound to offset 0, ready for
 * id128_read_fd(). -1 on any setup failure (a test bug, not a shim bug). */
static int memfd_with(const char *content, size_t len) {
        int fd;

        fd = memfd_create("id128-test", 0);
        if (fd < 0)
                return -1;

        if (len > 0) {
                ssize_t n = write(fd, content, len);

                if (n < 0 || (size_t) n != len) {
                        close(fd);
                        return -1;
                }
        }

        if (lseek(fd, 0, SEEK_SET) < 0) {
                close(fd);
                return -1;
        }

        return fd;
}

/* Reads a whole real file into buf (NUL-terminated), for cross-checking a
 * getter against the actual backing file it just read. */
static int slurp(const char *path, char *buf, size_t bufsize) {
        FILE *f;
        size_t n;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        n = fread(buf, 1, bufsize - 1, f);
        fclose(f);
        buf[n] = '\0';

        return 0;
}

#define ID_EXPECT SD_ID128_MAKE(01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f, 10)
#define ID_EXPECT_PLAIN_STR "0102030405060708090a0b0c0d0e0f10"
#define ID_EXPECT_UUID_STR "01020304-0506-0708-090a-0b0c0d0e0f10"

/* --- string conversion --- */

static void test_to_string(void) {
        sd_id128_t id = ID_EXPECT;
        char buf[SD_ID128_STRING_MAX];
        char ubuf[SD_ID128_UUID_STRING_MAX];
        char * volatile null_buf = NULL; /* volatile: the armv5te cross-compiler's
                                          * constant propagation proves a plain local is NULL
                                          * at -Os and raises -Wnonnull; this exercises the
                                          * runtime NULL check. */

        ASSERT_TRUE(sd_id128_to_string(id, buf) == buf);
        ASSERT_STREQ(buf, ID_EXPECT_PLAIN_STR);

        ASSERT_TRUE(sd_id128_to_uuid_string(id, ubuf) == ubuf);
        ASSERT_STREQ(ubuf, ID_EXPECT_UUID_STR);

        ASSERT_TRUE(sd_id128_to_string(id, null_buf) == NULL);
        ASSERT_TRUE(sd_id128_to_uuid_string(id, null_buf) == NULL);

        ASSERT_STREQ(SD_ID128_TO_STRING(id), ID_EXPECT_PLAIN_STR);
        ASSERT_STREQ(SD_ID128_TO_UUID_STRING(id), ID_EXPECT_UUID_STR);
        ASSERT_STREQ(SD_ID128_CONST_STR(id), ID_EXPECT_PLAIN_STR);
}

static void test_make_str_macros(void) {
        ASSERT_STREQ(SD_ID128_MAKE_STR(01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f, 10),
                     ID_EXPECT_PLAIN_STR);
        ASSERT_STREQ(SD_ID128_MAKE_UUID_STR(01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c, 0d, 0e, 0f, 10),
                     ID_EXPECT_UUID_STR);
}

static void test_format_macros(void) {
        sd_id128_t id = ID_EXPECT;
        char buf[SD_ID128_STRING_MAX];
        char ubuf[SD_ID128_UUID_STRING_MAX];

        snprintf(buf, sizeof(buf), SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(id));
        ASSERT_STREQ(buf, ID_EXPECT_PLAIN_STR);

        snprintf(ubuf, sizeof(ubuf), SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(id));
        ASSERT_STREQ(ubuf, ID_EXPECT_UUID_STR);
}

static void test_from_string(void) {
        sd_id128_t id;
        int r;

        r = sd_id128_from_string(ID_EXPECT_PLAIN_STR, &id);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(id, ID_EXPECT));

        r = sd_id128_from_string("0102030405060708090A0B0C0D0E0F10", &id);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(id, ID_EXPECT));

        r = sd_id128_from_string(ID_EXPECT_UUID_STR, &id);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(id, ID_EXPECT));

        r = sd_id128_from_string("urn:uuid:" ID_EXPECT_UUID_STR, &id);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(id, ID_EXPECT));

        r = sd_id128_from_string("URN:UUID:" ID_EXPECT_UUID_STR, &id);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(id, ID_EXPECT));

        /* the urn:uuid: prefix requires the dashed remainder -- a plain body after it is rejected */
        r = sd_id128_from_string("urn:uuid:" ID_EXPECT_PLAIN_STR, &id);
        ASSERT_EQ_INT(r, -EINVAL);

        r = sd_id128_from_string(NULL, &id);
        ASSERT_EQ_INT(r, -EINVAL);

        r = sd_id128_from_string("", &id);
        ASSERT_EQ_INT(r, -EINVAL);

        /* one hex digit short */
        r = sd_id128_from_string("0102030405060708090a0b0c0d0e0f1", &id);
        ASSERT_EQ_INT(r, -EINVAL);

        /* one byte too many trailing an otherwise-valid plain id */
        r = sd_id128_from_string(ID_EXPECT_PLAIN_STR "00", &id);
        ASSERT_EQ_INT(r, -EINVAL);

        /* non-hex character */
        r = sd_id128_from_string("01020304g5060708090a0b0c0d0e0f10", &id);
        ASSERT_EQ_INT(r, -EINVAL);

        /* dash at a position that is never valid (not 8, not 13/18/23) */
        r = sd_id128_from_string("0102-304-506-0708090a0b0c0d0e0f10", &id);
        ASSERT_EQ_INT(r, -EINVAL);

        /* a dash at 13 with no dash at 8 first: not GUID mode yet, so it's just "a wrong position" */
        r = sd_id128_from_string("010203040506-708-090a0b0c0d0e0f10a", &id);
        ASSERT_EQ_INT(r, -EINVAL);

        /* dashed, but the interior dashes land on the wrong offsets */
        r = sd_id128_from_string("01020304-05060-708-090a0b0c0d0e0f10", &id);
        ASSERT_EQ_INT(r, -EINVAL);

        /* NULL ret is a valid validation-only probe */
        r = sd_id128_from_string(ID_EXPECT_PLAIN_STR, NULL);
        ASSERT_EQ_INT(r, 0);
}

static void test_string_equal(void) {
        ASSERT_EQ_INT(sd_id128_string_equal(NULL, ID_EXPECT), 0);
        ASSERT_EQ_INT(sd_id128_string_equal(ID_EXPECT_PLAIN_STR, ID_EXPECT), 1);
        ASSERT_EQ_INT(sd_id128_string_equal(ID_EXPECT_UUID_STR, ID_EXPECT), 1);
        ASSERT_EQ_INT(sd_id128_string_equal("00000000000000000000000000000000", ID_EXPECT), 0);
        /* from_string's error propagates verbatim */
        ASSERT_EQ_INT(sd_id128_string_equal("not-an-id", ID_EXPECT), -EINVAL);
}

/* --- equal / is_null / is_allf / in_set --- */

static void test_null_allf_equal(void) {
        sd_id128_t a = SD_ID128_MAKE(aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa);
        sd_id128_t a2 = SD_ID128_MAKE(aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa);
        sd_id128_t b = SD_ID128_MAKE(bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb);

        ASSERT_TRUE(sd_id128_is_null(SD_ID128_NULL));
        ASSERT_TRUE(!sd_id128_is_null(SD_ID128_ALLF));
        ASSERT_TRUE(sd_id128_is_allf(SD_ID128_ALLF));
        ASSERT_TRUE(!sd_id128_is_allf(SD_ID128_NULL));

        ASSERT_TRUE(sd_id128_equal(a, a2));
        ASSERT_TRUE(!sd_id128_equal(a, b));
}

static void test_in_set(void) {
        sd_id128_t a = SD_ID128_MAKE(aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa, aa);
        sd_id128_t b = SD_ID128_MAKE(bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb);
        sd_id128_t c = SD_ID128_MAKE(cc, cc, cc, cc, cc, cc, cc, cc, cc, cc, cc, cc, cc, cc, cc, cc);

        ASSERT_TRUE(sd_id128_in_set(a, b, a, c));
        ASSERT_TRUE(!sd_id128_in_set(a, b, c));
        ASSERT_TRUE(!sd_id128_in_set(a));
}

/* --- randomize --- */

static void test_randomize(void) {
        sd_id128_t a, b;
        int r;

        r = sd_id128_randomize(NULL);
        ASSERT_EQ_INT(r, -EINVAL);

        r = sd_id128_randomize(&a);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(!sd_id128_is_null(a));

        /* RFC 4122 v4: version nibble 4, variant bits 10xxxxxx */
        ASSERT_EQ_INT(a.bytes[6] >> 4, 4);
        ASSERT_EQ_INT(a.bytes[8] >> 6, 2);

        r = sd_id128_randomize(&b);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(!sd_id128_equal(a, b));
}

/* --- id128_read_fd: every branch, driven through a memfd (id128-internal.h) --- */

static void test_read_fd_machine_format(void) {
        int fd;
        sd_id128_t id;
        int r;

        fd = memfd_with(ID_EXPECT_PLAIN_STR, strlen(ID_EXPECT_PLAIN_STR));
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, false, &id);
        close(fd);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(id, ID_EXPECT));

        fd = memfd_with(ID_EXPECT_PLAIN_STR "\n", strlen(ID_EXPECT_PLAIN_STR) + 1);
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, false, &id);
        close(fd);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(id, ID_EXPECT));

        fd = memfd_with("0102030405060708090A0B0C0D0E0F10", 32);
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, false, &id);
        close(fd);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(id, ID_EXPECT));

        fd = memfd_with("", 0);
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, false, &id);
        close(fd);
        ASSERT_EQ_INT(r, -ENOMEDIUM);

        fd = memfd_with("uninitialized", strlen("uninitialized"));
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, false, &id);
        close(fd);
        ASSERT_EQ_INT(r, -ENOPKG);

        fd = memfd_with("uninitialized\n", strlen("uninitialized\n"));
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, false, &id);
        close(fd);
        ASSERT_EQ_INT(r, -ENOPKG);

        /* wrong length */
        fd = memfd_with(ID_EXPECT_PLAIN_STR "ff", strlen(ID_EXPECT_PLAIN_STR) + 2);
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, false, &id);
        close(fd);
        ASSERT_EQ_INT(r, -EUCLEAN);

        /* dashed content is not the plain format machine-id wants */
        fd = memfd_with(ID_EXPECT_UUID_STR, strlen(ID_EXPECT_UUID_STR));
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, false, &id);
        close(fd);
        ASSERT_EQ_INT(r, -EUCLEAN);

        /* right length, unparseable content */
        {
                char garbage[64];

                strcpy(garbage, ID_EXPECT_PLAIN_STR);
                garbage[18] = 'z';
                garbage[19] = 'z';

                fd = memfd_with(garbage, strlen(ID_EXPECT_PLAIN_STR));
                ASSERT_TRUE(fd >= 0);
                r = id128_read_fd(fd, false, &id);
                close(fd);
                ASSERT_EQ_INT(r, -EUCLEAN);
        }

        /* well-formed but all-zero: refused same as a missing id */
        fd = memfd_with("00000000000000000000000000000000", 32);
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, false, &id);
        close(fd);
        ASSERT_EQ_INT(r, -ENOMEDIUM);
}

static void test_read_fd_boot_format(void) {
        int fd;
        sd_id128_t id;
        int r;

        fd = memfd_with(ID_EXPECT_UUID_STR, strlen(ID_EXPECT_UUID_STR));
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, true, &id);
        close(fd);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(id, ID_EXPECT));

        fd = memfd_with(ID_EXPECT_UUID_STR "\n", strlen(ID_EXPECT_UUID_STR) + 1);
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, true, &id);
        close(fd);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(id, ID_EXPECT));

        /* plain content is not the dashed form boot_id wants */
        fd = memfd_with(ID_EXPECT_PLAIN_STR, strlen(ID_EXPECT_PLAIN_STR));
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, true, &id);
        close(fd);
        ASSERT_EQ_INT(r, -EUCLEAN);

        fd = memfd_with("00000000-0000-0000-0000-000000000000", 36);
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, true, &id);
        close(fd);
        ASSERT_EQ_INT(r, -ENOMEDIUM);

        fd = memfd_with("", 0);
        ASSERT_TRUE(fd >= 0);
        r = id128_read_fd(fd, true, &id);
        close(fd);
        ASSERT_EQ_INT(r, -ENOMEDIUM);
}

/* --- sd_id128_get_machine() / sd_id128_get_boot(): real files, cross-checked --- */

static void test_get_machine_real(void) {
        char raw[64];
        sd_id128_t id, id_again;
        char formatted[SD_ID128_STRING_MAX];
        int r;

        r = slurp("/etc/machine-id", raw, sizeof(raw));
        if (r < 0 || raw[0] == '\0') {
                /* No usable machine-id on this host: the file is missing
                 * (r < 0) or empty (slurp() returns 0 on any successful open, so
                 * emptiness is detected from the buffer), as in a fresh container
                 * image. The getter returns -ENOENT for a missing file and
                 * -ENOMEDIUM for an empty one. */
                r = sd_id128_get_machine(&id);
                ASSERT_TRUE(r == -ENOENT || r == -ENOMEDIUM);
                return;
        }

        r = sd_id128_get_machine(&id);
        ASSERT_EQ_INT(r, 0);

        sd_id128_to_string(id, formatted);

        /* Cross-check against the file this process just read directly -- proof the
         * real getter parsed the real file, not a fixture. */
        ASSERT_TRUE(strncmp(raw, formatted, SD_ID128_STRING_MAX - 1) == 0);

        /* Cached: a second call returns the identical id without re-reading. */
        r = sd_id128_get_machine(&id_again);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(id, id_again));
}

static void test_get_boot_real(void) {
        char raw[64];
        sd_id128_t id, id_again;
        char formatted[SD_ID128_UUID_STRING_MAX];
        int r;

        r = slurp("/proc/sys/kernel/random/boot_id", raw, sizeof(raw));
        ASSERT_EQ_INT(r, 0); /* every real Linux kernel this project targets has this */

        r = sd_id128_get_boot(&id);
        ASSERT_EQ_INT(r, 0);

        sd_id128_to_uuid_string(id, formatted);

        ASSERT_TRUE(strncmp(raw, formatted, SD_ID128_UUID_STRING_MAX - 1) == 0);

        r = sd_id128_get_boot(&id_again);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(id, id_again));
}

/* --- sd_id128_get_invocation(): the environment-variable path only --- */

static void test_get_invocation(void) {
        sd_id128_t id;
        int r;

        unsetenv("INVOCATION_ID");
        r = sd_id128_get_invocation(&id);
        ASSERT_EQ_INT(r, -ENXIO);

        /* A successful call fills the per-process cache, which cannot be
         * cleared (as in libsystemd), so this is the only successful call here. */
        setenv("INVOCATION_ID", ID_EXPECT_PLAIN_STR, 1);
        r = sd_id128_get_invocation(&id);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(id, ID_EXPECT));
}

/* --- app-specific derivation --- */

static void test_app_specific_errors(void) {
        sd_id128_t base = ID_EXPECT;
        sd_id128_t app = SD_ID128_MAKE(bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb, bb);
        sd_id128_t out;
        int r;

        r = sd_id128_get_app_specific(base, app, NULL);
        ASSERT_EQ_INT(r, -EINVAL);

        r = sd_id128_get_app_specific(base, SD_ID128_NULL, &out);
        ASSERT_EQ_INT(r, -ENXIO);

        ASSERT_EQ_INT(sd_id128_get_machine_app_specific(app, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_id128_get_boot_app_specific(app, NULL), -EINVAL);
        ASSERT_EQ_INT(sd_id128_get_invocation_app_specific(app, NULL), -EINVAL);
}

/*
 * Bit-identical cross-check against real systemd (Ubuntu 24.04 arm64,
 * systemd 255.4-1ubuntu8.17):
 *
 *   # cat /etc/machine-id
 *   96460b7e615a40aaabc72b9c7be70b6e
 *   # systemd-id128 --app-specific=489b4c98cd9046f680d5f4b302cbcfe4 machine-id
 *   c32adb0230da41a9978346b9359f4acf
 *
 * Also reproduced with Python's hmac/hashlib, so this checks the HMAC
 * key/message order against an external implementation.
 */
static void test_app_specific_real_cross_check(void) {
        sd_id128_t base = SD_ID128_MAKE(96, 46, 0b, 7e, 61, 5a, 40, aa, ab, c7, 2b, 9c, 7b, e7, 0b, 6e);
        sd_id128_t app = SD_ID128_MAKE(48, 9b, 4c, 98, cd, 90, 46, f6, 80, d5, f4, b3, 02, cb, cf, e4);
        sd_id128_t expect = SD_ID128_MAKE(c3, 2a, db, 02, 30, da, 41, a9, 97, 83, 46, b9, 35, 9f, 4a, cf);
        sd_id128_t got;
        int r;

        r = sd_id128_get_app_specific(base, app, &got);
        ASSERT_EQ_INT(r, 0);
        ASSERT_TRUE(sd_id128_equal(got, expect));
}

static void test_app_specific_compositions(void) {
        sd_id128_t app = SD_ID128_MAKE(11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11);
        sd_id128_t machine, boot, invocation;
        sd_id128_t direct, composed;
        int r;

        /* sd_id128_get_invocation()'s cache was already warmed by test_get_invocation(). */

        r = sd_id128_get_machine(&machine);
        if (r == 0) {
                ASSERT_EQ_INT(sd_id128_get_app_specific(machine, app, &direct), 0);
                ASSERT_EQ_INT(sd_id128_get_machine_app_specific(app, &composed), 0);
                ASSERT_TRUE(sd_id128_equal(direct, composed));
        }

        r = sd_id128_get_boot(&boot);
        if (r == 0) {
                ASSERT_EQ_INT(sd_id128_get_app_specific(boot, app, &direct), 0);
                ASSERT_EQ_INT(sd_id128_get_boot_app_specific(app, &composed), 0);
                ASSERT_TRUE(sd_id128_equal(direct, composed));
        }

        r = sd_id128_get_invocation(&invocation);
        if (r == 0) {
                ASSERT_EQ_INT(sd_id128_get_app_specific(invocation, app, &direct), 0);
                ASSERT_EQ_INT(sd_id128_get_invocation_app_specific(app, &composed), 0);
                ASSERT_TRUE(sd_id128_equal(direct, composed));
        }
}

/* --- sha256.c / hmac-sha256.c: the primitives sd_id128_get_app_specific() is built on --- */

static void test_sha256_vectors(void) {
        struct sha256_ctx ctx;
        uint8_t digest[SHA256_DIGEST_SIZE];
        uint8_t expect[SHA256_DIGEST_SIZE];

        /* FIPS 180-4 empty-message and one-block ("abc") test vectors. */
        sha256_init(&ctx);
        sha256_final(&ctx, digest);
        hex_decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", expect, 32);
        ASSERT_TRUE(memcmp(digest, expect, SHA256_DIGEST_SIZE) == 0);

        sha256_init(&ctx);
        sha256_update(&ctx, "abc", 3);
        sha256_final(&ctx, digest);
        hex_decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", expect, 32);
        ASSERT_TRUE(memcmp(digest, expect, SHA256_DIGEST_SIZE) == 0);

        /* FIPS 180-4's 56-byte two-block message vector: exercises sha256_final()'s
         * "no room for the length in the current block" padding branch. */
        {
                static const char msg[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

                sha256_init(&ctx);
                sha256_update(&ctx, msg, strlen(msg));
                sha256_final(&ctx, digest);
                hex_decode("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", expect, 32);
                ASSERT_TRUE(memcmp(digest, expect, SHA256_DIGEST_SIZE) == 0);
        }
}

static void test_hmac_sha256_rfc4231(void) {
        uint8_t mac[SHA256_DIGEST_SIZE];
        uint8_t expect[SHA256_DIGEST_SIZE];

        /* RFC 4231 test case 1 */
        {
                uint8_t key[20];

                memset(key, 0x0b, sizeof(key));
                hmac_sha256(key, sizeof(key), "Hi There", 8, mac);
                hex_decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", expect, 32);
                ASSERT_TRUE(memcmp(mac, expect, SHA256_DIGEST_SIZE) == 0);
        }

        /* RFC 4231 test case 2: a key shorter than one block */
        {
                static const char data[] = "what do ya want for nothing?";

                hmac_sha256("Jefe", 4, data, strlen(data), mac);
                hex_decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", expect, 32);
                ASSERT_TRUE(memcmp(mac, expect, SHA256_DIGEST_SIZE) == 0);
        }

        /* RFC 4231 test case 3 */
        {
                uint8_t key[20], data[50];

                memset(key, 0xaa, sizeof(key));
                memset(data, 0xdd, sizeof(data));
                hmac_sha256(key, sizeof(key), data, sizeof(data), mac);
                hex_decode("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", expect, 32);
                ASSERT_TRUE(memcmp(mac, expect, SHA256_DIGEST_SIZE) == 0);
        }

        /* RFC 4231 test case 6: a key longer than one block, exercising hmac_sha256()'s
         * own "hash the key down first" branch. */
        {
                uint8_t key[131];
                static const char data[] = "Test Using Larger Than Block-Size Key - Hash Key First";

                memset(key, 0xaa, sizeof(key));
                hmac_sha256(key, sizeof(key), data, strlen(data), mac);
                hex_decode("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", expect, 32);
                ASSERT_TRUE(memcmp(mac, expect, SHA256_DIGEST_SIZE) == 0);
        }
}

int main(void) {
        test_to_string();
        test_make_str_macros();
        test_format_macros();
        test_from_string();
        test_string_equal();
        test_null_allf_equal();
        test_in_set();
        test_randomize();
        test_read_fd_machine_format();
        test_read_fd_boot_format();
        test_get_machine_real();
        test_get_boot_real();
        test_get_invocation();
        test_app_specific_errors();
        test_app_specific_real_cross_check();
        test_app_specific_compositions();
        test_sha256_vectors();
        test_hmac_sha256_rfc4231();

        printf("test-sd-id128: all checks passed\n");
        return 0;
}
