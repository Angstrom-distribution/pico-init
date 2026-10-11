/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Unaligned integer access, carried near-verbatim from systemd v261.2:
 * src/basic/unaligned.h plus the
 * src/fundamental/unaligned.h it includes, merged into one file because the
 * two-file split exists only to serve systemd's EFI build.
 *
 * This is not a convenience. On ARMv5TE -- the whole point of angstrom-pico --
 * a misaligned 32-bit load does not fault, it silently *rotates* the loaded
 * word, so reading a DHCP option value straight through a uint32_t* returns
 * plausible garbage rather than crashing. The packed __may_alias__ struct
 * below is what makes the compiler emit byte loads instead. Do not
 * "simplify" any of it.
 *
 * Changed from upstream: the "basic-forward.h" include becomes <stdint.h> and
 * <endian.h>, since netd has no forward-declaration header.
 */

#pragma once

#include <endian.h>
#include <stdint.h>

/* NE -- from src/fundamental/unaligned.h */

static inline uint16_t unaligned_read_ne16(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) {
                uint16_t x;
        } *u = _u;

        return u->x;
}

static inline uint32_t unaligned_read_ne32(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) {
                uint32_t x;
        } *u = _u;

        return u->x;
}

static inline uint64_t unaligned_read_ne64(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) {
                uint64_t x;
        } *u = _u;

        return u->x;
}

static inline void unaligned_write_ne16(void *_u, uint16_t a) {
        struct __attribute__((__packed__, __may_alias__)) {
                uint16_t x;
        } *u = _u;

        u->x = a;
}

static inline void unaligned_write_ne32(void *_u, uint32_t a) {
        struct __attribute__((__packed__, __may_alias__)) {
                uint32_t x;
        } *u = _u;

        u->x = a;
}

static inline void unaligned_write_ne64(void *_u, uint64_t a) {
        struct __attribute__((__packed__, __may_alias__)) {
                uint64_t x;
        } *u = _u;

        u->x = a;
}

/* BE */

static inline uint16_t unaligned_read_be16(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) {
                uint16_t x;
        } *u = _u;

        return be16toh(u->x);
}

static inline uint32_t unaligned_read_be32(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) {
                uint32_t x;
        } *u = _u;

        return be32toh(u->x);
}

static inline uint64_t unaligned_read_be64(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) {
                uint64_t x;
        } *u = _u;

        return be64toh(u->x);
}

static inline void unaligned_write_be16(void *_u, uint16_t a) {
        struct __attribute__((__packed__, __may_alias__)) {
                uint16_t x;
        } *u = _u;

        u->x = be16toh(a);
}

static inline void unaligned_write_be32(void *_u, uint32_t a) {
        struct __attribute__((__packed__, __may_alias__)) {
                uint32_t x;
        } *u = _u;

        u->x = be32toh(a);
}

static inline void unaligned_write_be64(void *_u, uint64_t a) {
        struct __attribute__((__packed__, __may_alias__)) {
                uint64_t x;
        } *u = _u;

        u->x = be64toh(a);
}

/* LE */

static inline uint16_t unaligned_read_le16(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) {
                uint16_t x;
        } *u = _u;

        return le16toh(u->x);
}

static inline uint32_t unaligned_read_le32(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) {
                uint32_t x;
        } *u = _u;

        return le32toh(u->x);
}

static inline uint64_t unaligned_read_le64(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) {
                uint64_t x;
        } *u = _u;

        return le64toh(u->x);
}

static inline void unaligned_write_le16(void *_u, uint16_t a) {
        struct __attribute__((__packed__, __may_alias__)) {
                uint16_t x;
        } *u = _u;

        u->x = le16toh(a);
}

static inline void unaligned_write_le32(void *_u, uint32_t a) {
        struct __attribute__((__packed__, __may_alias__)) {
                uint32_t x;
        } *u = _u;

        u->x = le32toh(a);
}

static inline void unaligned_write_le64(void *_u, uint64_t a) {
        struct __attribute__((__packed__, __may_alias__)) {
                uint64_t x;
        } *u = _u;

        u->x = le64toh(a);
}
