/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Implementation behind sd-id128.h -- see that header for the compatibility
 * contract and provenance note. Written from scratch against real, current
 * sd-id128.c/id128-util.c (systemd.git, HEAD ded83144, 2026-08-23) for
 * behaviour and error semantics only.
 *
 * sd_id128_get_machine()/get_boot()/get_invocation() each cache their
 * result in a per-thread static, exactly like real libsystemd: once a
 * process has a valid machine/boot/invocation id, that id cannot change out
 * from under it for the rest of the process's life, so re-reading the
 * backing file or environment on every call would only add I/O for no
 * behavioural benefit.
 */

#include "sd-id128.h"

#include "id128-internal.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/random.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "hmac-sha256.h"

static char hex_digit(unsigned nibble) {
        return (char) (nibble < 10 ? '0' + nibble : 'a' + nibble - 10);
}

char *sd_id128_to_string(sd_id128_t id, char s[_SD_ARRAY_STATIC SD_ID128_STRING_MAX]) {
        size_t k = 0;

        if (!s)
                return NULL;

        for (size_t i = 0; i < sizeof(id.bytes); i++) {
                s[k++] = hex_digit((unsigned) (id.bytes[i] >> 4));
                s[k++] = hex_digit((unsigned) (id.bytes[i] & 0x0f));
        }

        s[k] = '\0';
        return s;
}

/*
 * Always big-endian byte order, even for an id whose own variant bits claim
 * otherwise -- matching every other Linux userspace UUID renderer rather
 * than reinterpreting the bytes per RFC 4122's (rarely honoured) variant
 * field. Real upstream's own comment calls this out explicitly; carried
 * here as behaviour, not as text.
 */
char *sd_id128_to_uuid_string(sd_id128_t id, char s[_SD_ARRAY_STATIC SD_ID128_UUID_STRING_MAX]) {
        size_t k = 0;

        if (!s)
                return NULL;

        for (size_t i = 0; i < sizeof(id.bytes); i++) {
                if (i == 4 || i == 6 || i == 8 || i == 10)
                        s[k++] = '-';

                s[k++] = hex_digit((unsigned) (id.bytes[i] >> 4));
                s[k++] = hex_digit((unsigned) (id.bytes[i] & 0x0f));
        }

        s[k] = '\0';
        return s;
}

static int unhex_nibble(char c) {
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}

#define URN_UUID_PREFIX "urn:uuid:"

static bool has_urn_uuid_prefix(const char *s) {
        for (size_t i = 0; URN_UUID_PREFIX[i] != '\0'; i++) {
                char c = s[i];

                if (c >= 'A' && c <= 'Z')
                        c = (char) (c - 'A' + 'a');
                if (c != URN_UUID_PREFIX[i])
                        return false;
        }
        return true;
}

/*
 * Accepts exactly: 32 hex digits, or a 36-char dashed UUID (dashes at
 * positions 8/13/18/23), either optionally preceded by a case-insensitive
 * "urn:uuid:" -- which then requires the dashed form, matching real
 * upstream's own is_guid latch (the prefix sets is_guid before the loop
 * even sees a dash, so a plain 32-char body after the prefix comes up
 * short against the UUID length check below and is rejected).
 */
int sd_id128_from_string(const char *s, sd_id128_t *ret) {
        sd_id128_t parsed;
        bool is_guid = false;
        size_t si = 0, bi = 0;

        if (!s)
                return -EINVAL;

        if (has_urn_uuid_prefix(s)) {
                s += strlen(URN_UUID_PREFIX);
                is_guid = true;
        }

        while (bi < sizeof(parsed.bytes)) {
                int hi, lo;

                if (s[si] == '-') {
                        if (si == 8)
                                is_guid = true;
                        else if (si == 13 || si == 18 || si == 23) {
                                if (!is_guid)
                                        return -EINVAL;
                        } else
                                return -EINVAL;

                        si++;
                        continue;
                }

                hi = unhex_nibble(s[si]);
                if (hi < 0)
                        return -EINVAL;
                si++;

                lo = unhex_nibble(s[si]);
                if (lo < 0)
                        return -EINVAL;
                si++;

                parsed.bytes[bi++] = (uint8_t) ((hi << 4) | lo);
        }

        if (si != (is_guid ? SD_ID128_UUID_STRING_MAX : SD_ID128_STRING_MAX) - 1)
                return -EINVAL;
        if (s[si] != '\0')
                return -EINVAL;

        if (ret)
                *ret = parsed;
        return 0;
}

int sd_id128_string_equal(const char *s, sd_id128_t id) {
        sd_id128_t parsed;
        int r;

        if (!s)
                return 0;

        r = sd_id128_from_string(s, &parsed);
        if (r < 0)
                return r;

        return sd_id128_equal(parsed, id);
}

/* Shared by sd_id128_randomize() and every get_*_app_specific(): forces the
 * version nibble to 4 and the variant bits to DCE, "to be nice" per real
 * upstream's own comment -- not a promise about entropy quality. */
sd_id128_t id128_make_v4_uuid(sd_id128_t id) {
        id.bytes[6] = (uint8_t) ((id.bytes[6] & 0x0f) | 0x40);
        id.bytes[8] = (uint8_t) ((id.bytes[8] & 0x3f) | 0x80);
        return id;
}

int sd_id128_randomize(sd_id128_t *ret) {
        sd_id128_t id;
        size_t got = 0;

        if (!ret)
                return -EINVAL;

        while (got < sizeof(id.bytes)) {
                ssize_t n = getrandom(id.bytes + got, sizeof(id.bytes) - got, 0);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }

                got += (size_t) n;
        }

        *ret = id128_make_v4_uuid(id);
        return 0;
}

#define UNINITIALIZED_STR "uninitialized"

/* See id128-internal.h for the exact contract this implements. */
int id128_read_fd(int fd, bool uuid_format, sd_id128_t *ret) {
        char buf[SD_ID128_UUID_STRING_MAX + 1]; /* +1 for a trailing newline */
        size_t total = 0;
        size_t body_len;
        sd_id128_t id;
        int r;

        for (;;) {
                ssize_t n;

                if (total >= sizeof(buf))
                        break;

                n = read(fd, buf + total, sizeof(buf) - total);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                if (n == 0)
                        break;

                total += (size_t) n;
        }

        if (total == 0)
                return -ENOMEDIUM;

        if ((total == strlen(UNINITIALIZED_STR) || total == strlen(UNINITIALIZED_STR) + 1) &&
            memcmp(buf, UNINITIALIZED_STR, strlen(UNINITIALIZED_STR)) == 0 &&
            (total == strlen(UNINITIALIZED_STR) || buf[strlen(UNINITIALIZED_STR)] == '\n'))
                return -ENOPKG;

        body_len = uuid_format ? SD_ID128_UUID_STRING_MAX - 1 : SD_ID128_STRING_MAX - 1;

        if (total == body_len + 1) {
                if (buf[body_len] != '\n')
                        return -EUCLEAN;
        } else if (total != body_len)
                return -EUCLEAN;

        buf[body_len] = '\0';

        r = sd_id128_from_string(buf, &id);
        if (r == -EINVAL)
                return -EUCLEAN;
        if (r < 0)
                return r;

        if (sd_id128_is_null(id))
                return -ENOMEDIUM;

        if (ret)
                *ret = id;
        return 0;
}

static _Thread_local sd_id128_t cached_machine_id;

int sd_id128_get_machine(sd_id128_t *ret) {
        if (sd_id128_is_null(cached_machine_id)) {
                int fd, r;

                fd = open("/etc/machine-id", O_RDONLY | O_CLOEXEC | O_NOCTTY);
                if (fd < 0)
                        return -errno;

                r = id128_read_fd(fd, false, &cached_machine_id);
                close(fd);
                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = cached_machine_id;
        return 0;
}

static bool proc_is_mounted(void) {
        struct statfs sfs;

        if (statfs("/proc", &sfs) < 0)
                return false;

        return sfs.f_type == PROC_SUPER_MAGIC;
}

static _Thread_local sd_id128_t cached_boot_id;

int sd_id128_get_boot(sd_id128_t *ret) {
        if (sd_id128_is_null(cached_boot_id)) {
                int fd, r;

                fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC | O_NOCTTY);
                if (fd < 0) {
                        /* Real upstream's own proc_mounted() check: ENOENT on this exact path can
                         * mean either "old kernel, no boot_id" or "/proc isn't mounted at all" --
                         * the latter gets its own distinct -ENOSYS rather than a misleading -ENOENT. */
                        if (errno == ENOENT && !proc_is_mounted())
                                return -ENOSYS;
                        return -errno;
                }

                r = id128_read_fd(fd, true, &cached_boot_id);
                close(fd);
                if (r < 0)
                        return r;
        }

        if (ret)
                *ret = cached_boot_id;
        return 0;
}

/*
 * glibc/musl's secure_getenv() reimplemented by hand rather than called:
 * both gate it behind their own feature-test-macro conventions, and there
 * is no portable, reliable compile-time test for "is this libc one of the
 * two" -- doing the actual safety check ourselves (kernel AT_SECURE flag,
 * then the classic real-vs-effective id mismatch) is fewer moving parts
 * than branching on __GLIBC__ and hoping every other libc's secure_getenv()
 * needs no _GNU_SOURCE-equivalent toggle. Same documented behaviour either
 * way: the environment is trusted only when this process crossed no
 * privilege boundary to get here.
 */
static const char *pico_secure_getenv(const char *name) {
#ifdef AT_SECURE
        if (getauxval(AT_SECURE))
                return NULL;
#endif
        if (geteuid() != getuid() || getegid() != getgid())
                return NULL;

        return getenv(name);
}

static _Thread_local sd_id128_t cached_invocation_id;

/*
 * Real upstream also falls back to a kernel user-keyring "invocation_id"
 * key when the environment variable is unset, for system services that
 * don't get it as an environment variable. Deliberately not carried here:
 * pico-init's service-exec never stores an invocation id in the keyring,
 * and upstream's own behaviour when that key is genuinely absent is the
 * same -ENXIO this returns for "unset" -- so the omission is observably
 * identical on a pico system, not a shortcut. If service-exec ever starts
 * exporting INVOCATION_ID (see sd-id128.h), this starts working unchanged.
 */
int sd_id128_get_invocation(sd_id128_t *ret) {
        if (sd_id128_is_null(cached_invocation_id)) {
                const char *e;
                sd_id128_t id;
                int r;

                e = pico_secure_getenv("INVOCATION_ID");
                if (!e)
                        return -ENXIO;

                r = sd_id128_from_string(e, &id);
                if (r == -EINVAL)
                        return -EUCLEAN;
                if (r < 0)
                        return r;

                if (sd_id128_is_null(id))
                        return -ENOMEDIUM;

                cached_invocation_id = id;
        }

        if (ret)
                *ret = cached_invocation_id;
        return 0;
}

_Static_assert(SHA256_DIGEST_SIZE >= sizeof(((sd_id128_t *) 0)->bytes), "digest too small to truncate");

/*
 * Bit-identical to real libsystemd for the same inputs: HMAC-SHA256 is a
 * standardized construction (FIPS 198 / RFC 2104, over FIPS 180-4), and the
 * key/message order below -- key material is `base`, the HMAC'd message is
 * `app_id` -- is the one compat-critical detail this shim has to get right;
 * everything else follows from the standard.
 */
int sd_id128_get_app_specific(sd_id128_t base, sd_id128_t app_id, sd_id128_t *ret) {
        uint8_t digest[SHA256_DIGEST_SIZE];
        sd_id128_t result;

        if (!ret)
                return -EINVAL;
        if (sd_id128_is_null(app_id))
                return -ENXIO;

        hmac_sha256(&base, sizeof(base), &app_id, sizeof(app_id), digest);

        memcpy(result.bytes, digest, sizeof(result.bytes));
        *ret = id128_make_v4_uuid(result);
        return 0;
}

int sd_id128_get_machine_app_specific(sd_id128_t app_id, sd_id128_t *ret) {
        sd_id128_t id;
        int r;

        if (!ret)
                return -EINVAL;

        r = sd_id128_get_machine(&id);
        if (r < 0)
                return r;

        return sd_id128_get_app_specific(id, app_id, ret);
}

int sd_id128_get_boot_app_specific(sd_id128_t app_id, sd_id128_t *ret) {
        sd_id128_t id;
        int r;

        if (!ret)
                return -EINVAL;

        r = sd_id128_get_boot(&id);
        if (r < 0)
                return r;

        return sd_id128_get_app_specific(id, app_id, ret);
}

int sd_id128_get_invocation_app_specific(sd_id128_t app_id, sd_id128_t *ret) {
        sd_id128_t id;
        int r;

        if (!ret)
                return -EINVAL;

        r = sd_id128_get_invocation(&id);
        if (r < 0)
                return r;

        return sd_id128_get_app_specific(id, app_id, ret);
}
