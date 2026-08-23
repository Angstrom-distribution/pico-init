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

#define pico_log(level, ...) pico_log_internal((level), __VA_ARGS__)

/* strdup returning NULL on OOM (plain strdup, named to avoid confusion later) */
char *pico_strdup(const char *s);

/* free(p) and return NULL, for `x = pico_mfree(x)` */
void *pico_mfree(void *p);

/* NULL-terminated string vectors (argv-style) */
int pico_strv_extend(char ***strv, const char *value); /* 0 or -ENOMEM */
char **pico_strv_free(char **strv);                    /* frees elements + vector, returns NULL */
size_t pico_strv_length(char * const *strv);
