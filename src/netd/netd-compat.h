/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The shim layer that lets the lifted LGPL-2.1-or-later files under
 * src/netd/dhcp/ compile nearly verbatim (plan §2.2, "Support" row).
 *
 * Everything here exists because a real v261.2 file under
 * src/libsystemd-network/ reaches for it. The set was not guessed: it is the
 * measured macro/helper census over the eleven files in the lift set
 * (dhcp-message.c, sd-dhcp-client.c, dhcp-client-send.c, sd-dhcp-lease.c,
 * sd-dhcp-client-id.c, dhcp-protocol.c, dhcp-route.c, sd-dhcp-server.c,
 * dhcp-server-request.c, dhcp-server-send.c, sd-dhcp-server-lease.c) -- so
 * nothing is defined "just in case", and anything a lift turns out to still
 * need gets added here rather than edited into the lifted file.
 *
 * Header-only on purpose. The test programs link netd-core, not netd.c, so a
 * shim implemented in a .c file would either have to live in netd-core (where
 * it does not belong) or be missing from every test binary. `static inline`
 * costs nothing and keeps the shim one file, as plan §2.4 lists it.
 *
 * DELIBERATELY NOT statement expressions. Upstream implements TAKE_PTR,
 * ASSERT_PTR, IN_SET and friends with GNU `({ ... })`, which -Wpedantic (on
 * for every build here, see the verify harness) rejects outright. Each one
 * below is re-expressed in standard C, at the cost of the evaluation-count
 * caveats called out per macro. Read those before using one on an expression
 * with side effects.
 *
 * Licensing note: this header is GPL-2.0-or-later like the rest of netd's own
 * code, and is included by LGPL-2.1-or-later files. That is the permitted
 * direction (plan §2.3/§2.11) -- each lifted file keeps its own LGPL
 * identifier, and the combined netd binary is GPL-2.0-or-later as a whole.
 */

#pragma once

#include <arpa/inet.h>
#include <assert.h> /* IWYU pragma: export -- lifted files call assert() directly */
#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../util.h"

/* --- attributes --- */

#define _packed_ __attribute__((__packed__))
#define _unused_ __attribute__((__unused__))
#define _pure_ __attribute__((__pure__))
#define _const_ __attribute__((__const__))
#define _printf_(a, b) __attribute__((__format__(printf, a, b)))
#define _fallthrough_ __attribute__((__fallthrough__))

#define assert_cc(expr) _Static_assert(expr, #expr)

#define ELEMENTSOF(x) (sizeof(x) / sizeof((x)[0]))

/* --- assertions --- */

/*
 * ASSERTION POLICY. Read this before writing or lifting anything that touches
 * a received packet -- it is the highest-severity thing in this header.
 *
 * The lift set contains 199 assert() calls, 93 of them in dhcp-message.c
 * alone, and a large share of those assert facts about *parsed packet input*
 * rather than about netd's own internal state. Upstream compiles assert() to
 * `if (!(expr)) __builtin_unreachable();` under NDEBUG, which turns every one
 * of those into a licence for the optimizer to do anything at all with
 * attacker-supplied bytes. A pico build adding -DNDEBUG for size is an
 * entirely natural thing to do on a 64MiB ARMv5TE target, so this is not a
 * hypothetical.
 *
 * netd's rule, and it applies to every lifted file:
 *
 *   - An assertion about an INTERNAL INVARIANT -- a non-NULL parameter from
 *     netd's own caller, a state enum that can only hold known values, an
 *     array index the loop just bounded -- may stay an assert. It documents a
 *     programming error, and firing it is correct behaviour.
 *
 *   - An assertion about EXTERNALLY-SUPPLIED DATA -- an option length, a
 *     message type, an address family, a count read off the wire -- is not an
 *     assertion at all and must be rewritten as a real check returning
 *     -EBADMSG. netd_validate() below exists to make that one line. A remote
 *     DHCP server must never be able to reach an assert.
 *
 * And regardless of which: netd's assert() never compiles to
 * __builtin_unreachable() and never compiles away. It is redefined here,
 * unconditionally, over whatever <assert.h> provided, so NDEBUG cannot
 * silently change the meaning of a lifted file. The cost is a few kilobytes
 * of message strings; the alternative is undefined behaviour on network
 * input.
 *
 * One ordering rule follows: <assert.h> has no include guard around its macro,
 * so including it *after* this header puts libc's assert() back. Lifted files
 * must not include <assert.h> directly -- this header already does, and then
 * replaces it.
 */

__attribute__((__noreturn__)) static inline void
                netd_assert_failed(const char *expr, const char *file, int line, const char *func) {
        fprintf(stderr, "netd: assertion failed: %s at %s:%d in %s()\n", expr, file, line, func);
        abort();
}

#define netd_assert(expr) \
        ((void) ((expr) ? (void) 0 : netd_assert_failed(#expr, __FILE__, __LINE__, __func__)))

#undef assert
#define assert(expr) netd_assert(expr)

/* Upstream's "evaluated even under NDEBUG" variant. Same thing here, since
 * the above is already unconditional; kept so lifted call sites compile. */
#define assert_se(expr) netd_assert(expr)

/*
 * The externally-supplied-data counterpart. Use this, not assert(), for
 * anything a peer on the network controls. -EBADMSG is the house answer for
 * a malformed packet.
 */
#define netd_validate(expr, err)      \
        do {                          \
                if (!(expr))          \
                        return (err); \
        } while (0)

/*
 * Upstream's assert_return() logs and returns; here it just returns, since a
 * bad argument from netd's own code is a bug to fix, not a runtime condition
 * to report. Note that `r` is returned as-is: callers pass -EINVAL, not EINVAL.
 */
#define assert_return(expr, r)      \
        do {                        \
                if (!(expr))        \
                        return (r); \
        } while (0)

/* Evaluates `p` twice. Every upstream use site passes a plain variable or
 * parameter, which is why this is safe -- keep it that way. */
#define ASSERT_PTR(p) (assert(p), (p))

/* --- logging --- */

/*
 * systemd's log macros collapsed onto pico_log(). The object argument
 * (client/server) is accepted and discarded: it exists upstream only to
 * prefix the message with an interface name, which netd's link layer logs
 * itself. Keeping the argument means the lifted call sites are untouched.
 */
#define log_error(...) pico_log(PICO_LOG_ERR, __VA_ARGS__)
#define log_warning(...) pico_log(PICO_LOG_WARNING, __VA_ARGS__)
#define log_info(...) pico_log(PICO_LOG_INFO, __VA_ARGS__)
#define log_debug(...) pico_log(PICO_LOG_DEBUG, __VA_ARGS__)

/*
 * The errno-carrying variants are expressions, not statements: upstream
 * writes `return log_dhcp_client_errno(client, r, "...")`. Reproducing that
 * without a statement expression takes two steps sequenced by the comma
 * operator, with the value carried between them in a file-static.
 *
 * That static is safe here and nowhere near as fragile as it looks: netd is
 * single-threaded by construction (one process, one epoll loop, §2.3), and
 * the two halves are separated only by the pico_log() call in the same
 * expression -- nothing can run in between. The point of the dance is that
 * `error` is evaluated exactly once, which the obvious three-way comma
 * version would not manage.
 */
static int netd_log_errno_value = 0;

/* Normalize to negative and publish it as errno, so a "%m" in the format
 * string expands to the right message. */
static inline void netd_log_errno_set(int error) {
        netd_log_errno_value = error < 0 ? error : -error;
        errno = -netd_log_errno_value;
}

static inline int netd_log_errno_get(void) {
        return netd_log_errno_value;
}

#define netd_log_errno(level, error, ...) \
        (netd_log_errno_set(error), pico_log((level), __VA_ARGS__), netd_log_errno_get())

#define log_error_errno(error, ...) netd_log_errno(PICO_LOG_ERR, (error), __VA_ARGS__)
#define log_warning_errno(error, ...) netd_log_errno(PICO_LOG_WARNING, (error), __VA_ARGS__)
#define log_debug_errno(error, ...) netd_log_errno(PICO_LOG_DEBUG, (error), __VA_ARGS__)

#define log_dhcp_client(client, ...)                   \
        do {                                           \
                (void) (client);                       \
                pico_log(PICO_LOG_DEBUG, __VA_ARGS__); \
        } while (0)

#define log_dhcp_server(server, ...)                   \
        do {                                           \
                (void) (server);                       \
                pico_log(PICO_LOG_DEBUG, __VA_ARGS__); \
        } while (0)

#define log_dhcp_client_errno(client, error, ...) \
        ((void) (client), netd_log_errno(PICO_LOG_ERR, (error), __VA_ARGS__))

#define log_dhcp_server_errno(server, error, ...) \
        ((void) (server), netd_log_errno(PICO_LOG_ERR, (error), __VA_ARGS__))

/* --- errno classification --- */

/* The negative-argument forms are the ones the lift set uses. */
static inline bool ERRNO_IS_NEG_TRANSIENT(int r) {
        return r == -EAGAIN || r == -EINTR || r == -EWOULDBLOCK;
}

static inline bool ERRNO_IS_NEG_DISCONNECT(int r) {
        return r == -ECONNRESET || r == -ECONNABORTED || r == -EPIPE || r == -ENETDOWN ||
                        r == -ENETUNREACH || r == -ENETRESET || r == -EHOSTDOWN || r == -EHOSTUNREACH ||
                        r == -ENOTCONN || r == -ESHUTDOWN;
}

static inline bool ERRNO_IS_NEG_RESOURCE(int r) {
        return r == -EMFILE || r == -ENFILE || r == -ENOMEM;
}

/*
 * Fold `err` into `ret` if `ret` is not already carrying a failure, and hand
 * back the result. Upstream keeps the first error, not the last.
 */
static inline int ret_gather_internal(int *ret, int err) {
        assert(ret);

        if (err < 0 && *ret >= 0)
                *ret = err;

        return *ret;
}

#define RET_GATHER(ret, err) ret_gather_internal(&(ret), (err))

/* --- allocation --- */

static inline void *netd_malloc_multiply(size_t size, size_t need) {
        if (need != 0 && size > SIZE_MAX / need)
                return NULL;

        return malloc(size * need);
}

static inline void *netd_calloc_multiply(size_t size, size_t need) {
        return calloc(need != 0 ? need : 1, size);
}

static inline void *netd_memdup(const void *p, size_t n) {
        void *q;

        if (!p)
                return NULL;

        q = malloc(n != 0 ? n : 1);
        if (!q)
                return NULL;

        return memcpy(q, p, n);
}

/* new() is uninitialized, new0() is zeroed -- same split as upstream. */
#define new(t, n) ((t *) netd_malloc_multiply(sizeof(t), (n)))
#define new0(t, n) ((t *) netd_calloc_multiply(sizeof(t), (n)))
#define newdup(t, p, n) ((t *) netd_memdup((p), sizeof(t) * (n)))
#define malloc0(n) calloc(1, (n))
#define memdup(p, n) netd_memdup((p), (n))
#define mfree(p) pico_mfree(p)

/*
 * Grow *p so it holds at least `need` elements of `size` bytes, doubling
 * rather than growing by one. Returns the (possibly moved) array, or NULL on
 * OOM with the old array left intact -- so a failed GREEDY_REALLOC never
 * leaks the buffer it was given.
 */
static inline void *netd_greedy_realloc(void **p, size_t need, size_t size, size_t *allocated) {
        size_t new_allocated;
        void *q;

        assert(p);
        assert(allocated);

        if (need <= *allocated)
                return *p;

        new_allocated = *allocated == 0 ? 8 : *allocated * 2;
        if (new_allocated < need)
                new_allocated = need;

        if (size != 0 && new_allocated > SIZE_MAX / size)
                return NULL;

        q = realloc(*p, new_allocated * size);
        if (!q)
                return NULL;

        *p = q;
        *allocated = new_allocated;
        return q;
}

/*
 * Upstream's GREEDY_REALLOC hides the allocation count in a `_allocated_`
 * variable the caller is expected to have declared next to the array. netd
 * keeps that convention rather than inventing a different one, so a lifted
 * call site keeps working: declare `size_t x_allocated = 0;` beside `x`.
 */
#define GREEDY_REALLOC(array, need) \
        netd_greedy_realloc((void **) &(array), (need), sizeof((array)[0]), &(array##_allocated))

/* --- ownership transfer --- */

/*
 * The strict-aliasing cast through void** is the standard idiom for this and
 * is what upstream's non-statement-expression fallbacks do too; every use is
 * on an ordinary object pointer, never a function pointer.
 */
static inline void *netd_take_ptr(void **pp) {
        void *p;

        assert(pp);

        p = *pp;
        *pp = NULL;
        return p;
}

#define TAKE_PTR(p) netd_take_ptr((void **) &(p))

static inline int netd_take_fd(int *pfd) {
        int fd;

        assert(pfd);

        fd = *pfd;
        *pfd = -1;
        return fd;
}

#define TAKE_FD(fd) netd_take_fd(&(fd))

/* --- cleanup attributes --- */

#define _cleanup_(f) __attribute__((__cleanup__(f)))

static inline void netd_freep(void *p) {
        *(void **) p = pico_mfree(*(void **) p);
}

static inline void netd_closep(int *fd) {
        if (*fd >= 0)
                (void) close(*fd);
}

static inline void netd_fclosep(FILE **f) {
        if (*f)
                (void) fclose(*f);
}

static inline void netd_strv_freep(char ***p) {
        *p = pico_strv_free(*p);
}

#define _cleanup_free_ _cleanup_(netd_freep)
#define _cleanup_close_ _cleanup_(netd_closep)
#define _cleanup_fclose_ _cleanup_(netd_fclosep)
#define _cleanup_strv_free_ _cleanup_(netd_strv_freep)

#define DEFINE_TRIVIAL_CLEANUP_FUNC(type, func) \
        static inline void func##p(type *p) {   \
                if (*p)                         \
                        *p = func(*p);          \
        }                                       \
        struct netd_swallow_semicolon_##func

/*
 * Reference counting. The lift set's objects (sd_dhcp_message, sd_dhcp_lease,
 * ...) are refcounted upstream, and the codec files hand them around by ref,
 * so the counting is kept rather than flattened -- flattening it would mean
 * editing exactly the near-verbatim files this shim exists to leave alone.
 */
#define DEFINE_TRIVIAL_REF_UNREF_FUNC(type, name, free_func) \
        type *name##_ref(type *p) {                          \
                if (!p)                                      \
                        return NULL;                         \
                assert(p->n_ref > 0);                        \
                p->n_ref++;                                  \
                return p;                                    \
        }                                                    \
        type *name##_unref(type *p) {                        \
                if (!p)                                      \
                        return NULL;                         \
                assert(p->n_ref > 0);                        \
                if (--p->n_ref > 0)                          \
                        return NULL;                         \
                return free_func(p);                         \
        }                                                    \
        struct netd_swallow_semicolon_##name

/* --- iteration --- */

/*
 * Both loop variables must have the same declared type for the for-init to be
 * legal C, hence the derived end pointer rather than upstream's shape.
 */
#define FOREACH_ARRAY(i, array, num) \
        for (typeof(&(array)[0]) i = (array), i##_end_ = (array) + (num); i < i##_end_; i++)

#define FOREACH_ELEMENT(i, array) FOREACH_ARRAY(i, array, ELEMENTSOF(array))

/*
 * Integer/enum membership only -- everything the lift set uses it for is a
 * message type, option code or state constant. `x` is evaluated once; the
 * list is expanded twice, so keep it to constants.
 */
static inline bool netd_in_set(long long x, size_t n, const long long *set) {
        for (size_t i = 0; i < n; i++)
                if (set[i] == x)
                        return true;

        return false;
}

#define IN_SET(x, ...)                                                              \
        netd_in_set((long long) (x),                                                \
                    sizeof((const long long[]){ __VA_ARGS__ }) / sizeof(long long), \
                    (const long long[]){ __VA_ARGS__ })

/* --- the option-code set --- */

/*
 * dhcp-message.c and sd-dhcp-client.c both build the DHCP parameter request
 * list with set_ensure_put() over UINT8_TO_PTR() keys -- so hashmap.h reaches
 * into what §2.1 called the "pure codec", not just into the server's lease
 * table where it was expected.
 *
 * It does not follow that netd needs a hashmap. The key is a uint8_t: the
 * entire key space is 256 values, so the set is a 32-byte bitmap with no
 * allocation, no hash function, no ordering question and nothing to free.
 * That is smaller than the Set shim would have been and strictly faster, and
 * it removes the last reason to think about lifting hashmap.c.
 *
 * The one behavioural difference to know: iteration is in ascending option
 * order rather than upstream's hash order. That is an improvement -- it makes
 * the emitted parameter request list deterministic, which the golden-byte
 * codec tests of §2.8 depend on.
 */
typedef struct NetdU8Set {
        uint8_t bits[32];
} NetdU8Set;

static inline void netd_u8set_clear(NetdU8Set *s) {
        assert(s);

        memset(s->bits, 0, sizeof(s->bits));
}

static inline bool netd_u8set_contains(const NetdU8Set *s, uint8_t v) {
        assert(s);

        return (s->bits[v / 8] & (uint8_t) (1U << (v % 8))) != 0;
}

/* 1 when newly added, 0 when it was already there -- the same answer
 * set_ensure_put() gives. */
static inline int netd_u8set_put(NetdU8Set *s, uint8_t v) {
        assert(s);

        if (netd_u8set_contains(s, v))
                return 0;

        s->bits[v / 8] |= (uint8_t) (1U << (v % 8));
        return 1;
}

static inline int netd_u8set_remove(NetdU8Set *s, uint8_t v) {
        assert(s);

        if (!netd_u8set_contains(s, v))
                return 0;

        s->bits[v / 8] &= (uint8_t) ~(1U << (v % 8));
        return 1;
}

static inline size_t netd_u8set_size(const NetdU8Set *s) {
        size_t n = 0;

        assert(s);

        for (size_t i = 0; i < 256; i++)
                if (netd_u8set_contains(s, (uint8_t) i))
                        n++;

        return n;
}

/* Ascending iteration: `v` is the current member each time round. */
#define FOREACH_U8SET(v, s)                                      \
        for (unsigned v##_i_ = 0; v##_i_ < 256; v##_i_++)        \
                if (!netd_u8set_contains((s), (uint8_t) v##_i_)) \
                        continue;                                \
                else                                             \
                        for (uint8_t v = (uint8_t) v##_i_, v##_once_ = 1; v##_once_; v##_once_ = 0)

/* --- strings --- */

static inline bool streq(const char *a, const char *b) {
        return strcmp(a, b) == 0;
}

static inline bool streq_ptr(const char *a, const char *b) {
        if (!a || !b)
                return a == b;

        return streq(a, b);
}

static inline bool isempty(const char *s) {
        return !s || s[0] == '\0';
}

static inline const char *strempty(const char *s) {
        return s ? s : "";
}

static inline const char *startswith(const char *s, const char *prefix) {
        size_t n;

        if (!s || !prefix)
                return NULL;

        n = strlen(prefix);
        return strncmp(s, prefix, n) == 0 ? s + n : NULL;
}

static inline size_t strlen_ptr(const char *s) {
        return s ? strlen(s) : 0;
}

/* --- time --- */

/*
 * util.h supplies usec_t, USEC_PER_SEC and usec_add(); these are the pieces
 * the lift set additionally reaches for. now_monotonic() covers
 * CLOCK_MONOTONIC, so netd_now() exists for the CLOCK_BOOTTIME and
 * CLOCK_REALTIME call sites.
 */
#define NSEC_PER_USEC ((uint64_t) 1000ULL)
#define USEC_PER_MINUTE ((usec_t) (60ULL * USEC_PER_SEC))
#define USEC_PER_HOUR ((usec_t) (3600ULL * USEC_PER_SEC))

static inline usec_t netd_now(clockid_t clock) {
        struct timespec ts;

        if (clock_gettime(clock, &ts) < 0)
                return USEC_INFINITY;

        return (usec_t) ts.tv_sec * USEC_PER_SEC + (usec_t) ts.tv_nsec / NSEC_PER_USEC;
}

#define now(clock) netd_now(clock)

/* Saturating at zero -- "how long ago", never a wrapped huge number. */
static inline usec_t usec_sub_unsigned(usec_t a, usec_t b) {
        if (a == USEC_INFINITY)
                return USEC_INFINITY;
        if (a < b)
                return 0;

        return a - b;
}

static inline usec_t usec_sub_signed(usec_t a, int64_t b) {
        if (b < 0)
                return usec_add(a, (usec_t) (-(b + 1)) + 1);

        return usec_sub_unsigned(a, (usec_t) b);
}

/* --- IPv4 address helpers (the "mini in-addr" set of plan §2.2) --- */

static inline bool in4_addr_is_null(const struct in_addr *a) {
        assert(a);

        return a->s_addr == 0;
}

static inline bool in4_addr_is_set(const struct in_addr *a) {
        return !in4_addr_is_null(a);
}

static inline bool in4_addr_is_localhost(const struct in_addr *a) {
        assert(a);

        /* 127.0.0.0/8 */
        return (be32toh(a->s_addr) >> 24) == 127;
}

static inline bool in4_addr_is_multicast(const struct in_addr *a) {
        assert(a);

        /* 224.0.0.0/4 */
        return (be32toh(a->s_addr) & 0xf0000000U) == 0xe0000000U;
}

static inline bool in4_addr_is_broadcast(const struct in_addr *a) {
        assert(a);

        return a->s_addr == 0xffffffffU;
}

static inline uint32_t netd_prefixlen_to_netmask_h(unsigned char prefixlen) {
        if (prefixlen == 0)
                return 0;
        if (prefixlen >= 32)
                return 0xffffffffU;

        return 0xffffffffU << (32 - prefixlen);
}

static inline int in4_addr_prefixlen_to_netmask(struct in_addr *ret, unsigned char prefixlen) {
        assert(ret);

        if (prefixlen > 32)
                return -ERANGE;

        ret->s_addr = htobe32(netd_prefixlen_to_netmask_h(prefixlen));
        return 0;
}

/* -EINVAL when the mask is not contiguous, which is the check that matters:
 * a DHCP server may hand out anything, and a non-CIDR mask has no prefixlen. */
static inline int in4_addr_netmask_to_prefixlen(const struct in_addr *mask, unsigned char *ret) {
        uint32_t m;
        unsigned char n = 0;

        assert(mask);
        assert(ret);

        m = be32toh(mask->s_addr);
        while (n < 32 && (m & 0x80000000U)) {
                m <<= 1;
                n++;
        }

        if (m != 0)
                return -EINVAL;

        *ret = n;
        return 0;
}

static inline int in4_addr_mask(struct in_addr *addr, unsigned char prefixlen) {
        assert(addr);

        if (prefixlen > 32)
                return -ERANGE;

        addr->s_addr &= htobe32(netd_prefixlen_to_netmask_h(prefixlen));
        return 0;
}

/* Classful default, still what DHCP falls back to when option 1 is absent. */
static inline int in4_addr_default_prefixlen(const struct in_addr *addr, unsigned char *ret) {
        uint8_t msb;

        assert(addr);
        assert(ret);

        msb = (uint8_t) (be32toh(addr->s_addr) >> 24);

        if (msb < 128)
                *ret = 8;
        else if (msb < 192)
                *ret = 16;
        else if (msb < 224)
                *ret = 24;
        else
                return -ERANGE;

        return 0;
}

/*
 * The buffer is a compound literal in the caller's block, so the result is
 * valid until the end of the enclosing statement's block -- long enough for a
 * log call, which is all upstream uses it for. Never store the pointer.
 */
static inline const char *netd_in4_addr_to_string(const struct in_addr *a, char *buf, size_t len) {
        if (!a || !inet_ntop(AF_INET, a, buf, (socklen_t) len))
                return "n/a";

        return buf;
}

#define IN4_ADDR_TO_STRING(a) netd_in4_addr_to_string((a), (char[INET_ADDRSTRLEN]){ 0 }, INET_ADDRSTRLEN)

/* --- machine id --- */

/*
 * sd_id128_get_machine() replacement (plan §2.2, "Client identity" row). The
 * DHCP client derives its default DUID from the machine ID, so this needs to
 * be stable across boots and identical in shape to upstream's: 16 bytes read
 * from /etc/machine-id's 32 lowercase hex characters.
 */
typedef struct NetdId128 {
        uint8_t bytes[16];
} NetdId128;

#define NETD_MACHINE_ID_PATH "/etc/machine-id"

/* 0, or -errno. -ENOMEDIUM when the file exists but is empty or malformed --
 * the same distinction upstream draws, and the one the caller needs to decide
 * between "no identity yet" and "broken system". */
static inline int netd_machine_id(NetdId128 *ret) {
        char buf[33];
        FILE *f;
        size_t n;

        assert(ret);

        f = fopen(NETD_MACHINE_ID_PATH, "re");
        if (!f)
                return -errno;

        n = fread(buf, 1, 32, f);
        (void) fclose(f);

        if (n != 32)
                return -ENOMEDIUM;

        buf[32] = '\0';

        for (size_t i = 0; i < 16; i++) {
                unsigned v;

                if (sscanf(buf + i * 2, "%2x", &v) != 1)
                        return -ENOMEDIUM;

                ret->bytes[i] = (uint8_t) v;
        }

        return 0;
}
