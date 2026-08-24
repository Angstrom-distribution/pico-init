/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Small shared helpers: time type, logging, string/strv basics.
 * Deliberately minimal -- grown only when another file actually needs it.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

typedef uint64_t usec_t;

#define USEC_INFINITY ((usec_t) UINT64_MAX)
#define USEC_PER_SEC ((usec_t) 1000000ULL)
#define USEC_PER_MSEC ((usec_t) 1000ULL)

/* CLOCK_MONOTONIC in usec; USEC_INFINITY on failure */
usec_t now_monotonic(void);

/*
 * Saturating a + b, for computing a deadline from "now + timeout". Every
 * caller that does that arithmetic must use this rather than a bare '+': a
 * timeout of USEC_INFINITY ("never") added to a real timestamp would wrap
 * uint64_t and produce a deadline in the past, firing immediately instead of
 * never (see B1 in service.c). Callers with a USEC_INFINITY timeout should
 * skip arming a timer at all rather than relying on this to no-op, per
 * timer.h's own rule -- this exists for the few places that still need a
 * concrete (possibly-saturated) deadline value.
 */
static inline usec_t usec_add(usec_t a, usec_t b) {
        usec_t c = a + b;
        return c < a ? USEC_INFINITY : c;
}

/*
 * What kind of thing an epoll registration's data.ptr tag refers to. Every
 * struct registered in the manager's epoll set embeds a struct
 * pico_epoll_tag as its first member (or is one), and dispatch always reads
 * events[i].data.ptr -- never events[i].data.fd -- so which union member a
 * given registration used is never ambiguous at dispatch time. Mixing
 * data.fd and data.ptr registrations in one epoll set is a real bug class:
 * epoll_wait() returns whichever member was written at epoll_ctl() time,
 * and a dispatcher that always reads data.fd silently reinterprets a
 * pointer's low bits as a file descriptor for any event actually
 * registered via data.ptr.
 */
typedef enum PicoEpollSource {
        PICO_EPOLL_SIGNAL,
        PICO_EPOLL_TIMER,
        PICO_EPOLL_CGROUP,
        /* A .socket unit's listening fd (socket.c). EPOLLIN in LISTENING
         * triggers the paired service; under Accept=no PID 1 never accept()s. */
        PICO_EPOLL_SOCKET,
        /* The picoctl control socket and its accepted connections
         * (manager-ctrl.c). Root-only, one bounded request per connection. */
        PICO_EPOLL_CONTROL,
} PicoEpollSource;

struct pico_epoll_tag {
        PicoEpollSource source;
        int fd; /* for logging only; dispatch reaches the real owner via a cast back to the containing struct */
};

typedef enum PicoLogLevel {
        PICO_LOG_ERR,
        PICO_LOG_WARNING,
        PICO_LOG_INFO,
        PICO_LOG_DEBUG,
} PicoLogLevel;

void pico_log_internal(PicoLogLevel level, const char *format, ...) __attribute__((format(printf, 2, 3)));

/*
 * Redirect pico_log() to /dev/kmsg, with a real syslog priority prefix so the
 * kernel ring carries the level rather than flattening it.
 *
 * Opt-in at runtime, and deliberately not unconditional: pico_log() is shared
 * by the daemons AND by the interactive tools (picolog, picoctl), and an
 * interactive tool's diagnostics belong on the caller's own terminal, never in
 * the kernel ring. A settable sink also leaves pico_log()'s signature alone,
 * so no existing call site changes.
 *
 * Best-effort: if /dev/kmsg cannot be opened the sink stays stderr, which is
 * the pre-existing behaviour and always safe.
 */
void pico_log_to_kmsg(void);

#define pico_log(level, ...) pico_log_internal((level), __VA_ARGS__)

/* strdup returning NULL on OOM (plain strdup, named to avoid confusion later) */
char *pico_strdup(const char *s);

/* free(p) and return NULL, for `x = pico_mfree(x)` */
void *pico_mfree(void *p);

/* NULL-terminated string vectors (argv-style) */
int pico_strv_extend(char ***strv, const char *value); /* 0 or -ENOMEM */
char **pico_strv_free(char **strv);                    /* frees elements + vector, returns NULL */
size_t pico_strv_length(char * const *strv);
