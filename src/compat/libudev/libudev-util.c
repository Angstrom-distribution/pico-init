/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * udev_util_encode_string(): the documented device-node-name escape.
 * Bytes that are ASCII alphanumerics or one of "#+-.:=@_" pass through,
 * a well-formed multi-byte UTF-8 sequence passes through whole, and every
 * other byte becomes "\xHH". Written from the documented contract, not
 * from upstream's encode_devnode_name().
 */

#include "libudev.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int utf8_sequence_length(const unsigned char *s, size_t avail) {
        unsigned char c = s[0];
        int len, i;
        unsigned int cp;

        if ((c & 0xE0) == 0xC0) {
                len = 2;
                cp = c & 0x1F;
        } else if ((c & 0xF0) == 0xE0) {
                len = 3;
                cp = c & 0x0F;
        } else if ((c & 0xF8) == 0xF0) {
                len = 4;
                cp = c & 0x07;
        } else
                return 0;

        if ((size_t) len > avail)
                return 0;
        for (i = 1; i < len; i++) {
                if ((s[i] & 0xC0) != 0x80)
                        return 0;
                cp = (cp << 6) | (s[i] & 0x3F);
        }

        /* Overlong forms, surrogates and out-of-range code points are not
         * valid UTF-8 and get escaped byte by byte instead. */
        if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000))
                return 0;
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF))
                return 0;
        return len;
}

static int is_plain(unsigned char c) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
                return 1;
        return strchr("#+-.:=@_", (int) c) != NULL && c != '\0';
}

int udev_util_encode_string(const char *str, char *str_enc, size_t len) {
        const unsigned char *s = (const unsigned char *) str;
        size_t in = 0, out = 0, n;

        if (!str || !str_enc || len == 0)
                return -EINVAL;

        n = strlen(str);
        while (in < n) {
                int seq = utf8_sequence_length(s + in, n - in);

                if (seq > 0) {
                        if (out + (size_t) seq >= len)
                                return -EINVAL;
                        memcpy(str_enc + out, s + in, (size_t) seq);
                        out += (size_t) seq;
                        in += (size_t) seq;
                } else if (is_plain(s[in])) {
                        if (out + 1 >= len)
                                return -EINVAL;
                        str_enc[out++] = (char) s[in++];
                } else {
                        if (out + 4 >= len)
                                return -EINVAL;
                        (void) snprintf(str_enc + out, 5, "\\x%02x", s[in++]);
                        out += 4;
                }
        }

        str_enc[out] = '\0';
        return 0;
}
