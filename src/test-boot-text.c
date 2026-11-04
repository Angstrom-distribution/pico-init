/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The architecture name and the timespan in the early boot lines, checked
 * against the spellings systemd prints.
 */

#include <stdio.h>
#include <string.h>

#include "boot-text.h"
#include "test-util.h"

static void test_architecture_name(void) {
        ASSERT_STREQ(pico_architecture_name("armv4l"), "arm");
        ASSERT_STREQ(pico_architecture_name("armv5tel"), "arm");
        ASSERT_STREQ(pico_architecture_name("armv5tejl"), "arm");
        ASSERT_STREQ(pico_architecture_name("armv7l"), "arm");
        ASSERT_STREQ(pico_architecture_name("armv7ml"), "arm");
        ASSERT_STREQ(pico_architecture_name("armv8l"), "arm");
        ASSERT_STREQ(pico_architecture_name("armv5teb"), "arm-be");
        ASSERT_STREQ(pico_architecture_name("armv7b"), "arm-be");
        ASSERT_STREQ(pico_architecture_name("aarch64"), "arm64");
        ASSERT_STREQ(pico_architecture_name("aarch64_be"), "arm64-be");
        ASSERT_STREQ(pico_architecture_name("x86_64"), "x86-64");
        ASSERT_STREQ(pico_architecture_name("i386"), "x86");
        ASSERT_STREQ(pico_architecture_name("i686"), "x86");
        ASSERT_STREQ(pico_architecture_name("riscv64"), "riscv64");
        ASSERT_STREQ(pico_architecture_name("riscv32"), "riscv32");
        ASSERT_STREQ(pico_architecture_name("riscv"), sizeof(void *) == 8 ? "riscv64" : "riscv32");
        ASSERT_STREQ(pico_architecture_name("ppc64le"), "ppc64-le");
        ASSERT_STREQ(pico_architecture_name("ppc64"), "ppc64");
        ASSERT_STREQ(pico_architecture_name("s390x"), "s390x");
        ASSERT_STREQ(pico_architecture_name("mips"), "mips");
        ASSERT_STREQ(pico_architecture_name("mips64"), "mips64");
        ASSERT_STREQ(pico_architecture_name("arceb"), "arc-be");
        ASSERT_STREQ(pico_architecture_name("crisv32"), "cris");
        ASSERT_STREQ(pico_architecture_name("loongarch64"), "loongarch64");

        /* Unknown machines come back as given; "arm" alone is not an ARM version. */
        ASSERT_STREQ(pico_architecture_name("xtensa"), "xtensa");
        ASSERT_STREQ(pico_architecture_name("arm"), "arm");
        ASSERT_STREQ(pico_architecture_name(""), "");
        ASSERT_STREQ(pico_architecture_name(NULL), "unknown");
}

static void check_timespan(usec_t t, const char *expect) {
        char buf[64];

        ASSERT_STREQ(pico_format_timespan(buf, sizeof buf, t), expect);
}

static void test_format_timespan(void) {
        char small[6];

        check_timespan(0, "0");
        check_timespan(500000, "0");
        check_timespan(1 * USEC_PER_SEC, "1s");
        check_timespan(30 * USEC_PER_SEC, "30s");
        check_timespan(60 * USEC_PER_SEC, "1min");
        check_timespan(930 * USEC_PER_SEC, "15min 30s");
        check_timespan(3600 * USEC_PER_SEC, "1h");
        check_timespan(3661 * USEC_PER_SEC, "1h 1min 1s");
        check_timespan(86400 * USEC_PER_SEC, "1d");
        check_timespan(604800 * USEC_PER_SEC, "1w");
        check_timespan(USEC_INFINITY, "infinity");

        /* Cut off, still terminated, when the buffer is short. */
        pico_format_timespan(small, sizeof small, 930 * USEC_PER_SEC);
        ASSERT_STREQ(small, "15min");
        pico_format_timespan(small, 1, 30 * USEC_PER_SEC);
        ASSERT_STREQ(small, "");
}

int main(void) {
        test_architecture_name();
        test_format_timespan();

        printf("test-boot-text: all checks passed\n");
        return 0;
}
