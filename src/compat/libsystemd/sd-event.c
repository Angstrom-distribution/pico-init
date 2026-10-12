/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The event object itself: construction/refcounting, the epoll-backed
 * prepare/wait/dispatch loop, every sd_event_add_*() constructor, and the
 * handful of sd_event_get_/set_*() accessors. Per-source property accessors
 * live in sd-event-source.c; both files share event-internal.h.
 *
 * -std=gnu17 alone does not reliably expose gettid()/pidfd_*()/timerfd_*()
 * across glibc versions, so _GNU_SOURCE is defined explicitly, first.
 */
#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <malloc.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/inotify.h>
#include <sys/signalfd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

#include "event-internal.h"
#include "sd-daemon.h" /* sd_watchdog_enabled() -- sd_event_set_watchdog() below reuses its real env parsing */

#ifndef P_PIDFD
#        define P_PIDFD 3 /* kernel-stable idtype value; not yet in every libc's <sys/wait.h> */
#endif

/* One epoll_wait() batch; anything beyond it is picked up by the next call. */
#define EVENT_MAX_EVENTS 32

/* This thread's sd_event_default() loop. Weak: sd_event_unref() clears it
 * itself when the event it points at reaches zero refs, so it is never a
 * counted reference and never dangles. */
static __thread sd_event *default_event;

/* ---- time helpers -------------------------------------------------- */

uint64_t event_timespec_to_usec(const struct timespec *ts) {
        return (uint64_t) ts->tv_sec * EVENT_USEC_PER_SEC + (uint64_t) ts->tv_nsec / 1000ULL;
}

void event_usec_to_timespec(uint64_t usec, struct timespec *ts) {
        ts->tv_sec = (time_t) (usec / EVENT_USEC_PER_SEC);
        ts->tv_nsec = (long) ((usec % EVENT_USEC_PER_SEC) * 1000ULL);
}

static bool clock_supported(clockid_t clock) {
        return clock == CLOCK_REALTIME || clock == CLOCK_MONOTONIC || clock == CLOCK_BOOTTIME ||
                        clock == CLOCK_REALTIME_ALARM || clock == CLOCK_BOOTTIME_ALARM;
}

/* ---- pidfd wrappers -------------------------------------------------
 *
 * Called through syscall() rather than glibc's own pidfd_open()/
 * pidfd_send_signal() wrappers: those only exist from glibc 2.36, and going
 * straight to the syscall number means one code path instead of an
 * ifdef-per-glibc-version maze. The #ifdef SYS_* guards are for building
 * against kernel headers old enough to lack the syscall numbers at all. */

int event_pidfd_open(pid_t pid, unsigned int flags) {
#ifdef SYS_pidfd_open
        return (int) syscall(SYS_pidfd_open, pid, flags);
#else
        errno = ENOSYS;
        return -1;
#endif
}

int event_pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags) {
#ifdef SYS_pidfd_send_signal
        return (int) syscall(SYS_pidfd_send_signal, pidfd, sig, info, flags);
#else
        errno = ENOSYS;
        return -1;
#endif
}

/* Best-effort pidfd -> pid via /proc/self/fdinfo. Only add_child_pidfd()
 * needs this (add_child() already knows the pid it was given); documented
 * as best-effort in sd-event.h's own get_child_pid() note. */
int event_pidfd_get_pid(int pidfd, pid_t *ret) {
        char path[64];
        char line[256];
        FILE *f;

        snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", pidfd);
        f = fopen(path, "r");
        if (!f)
                return -errno;

        while (fgets(line, sizeof(line), f)) {
                long v;
                if (sscanf(line, "Pid: %ld", &v) == 1) {
                        *ret = (pid_t) v;
                        fclose(f);
                        return 0;
                }
        }
        fclose(f);
        return -ENODATA;
}

/* ---- source lifecycle (shared with sd-event-source.c) --------------- */

sd_event *event_resolve(sd_event *e) {
        return e == SD_EVENT_DEFAULT ? default_event : e;
}

sd_event_source *event_source_new(sd_event *e, bool floating, EventSourceType type) {
        sd_event_source *s;

        s = calloc(1, sizeof(*s));
        if (!s)
                return NULL;

        s->n_ref = 1;
        s->event = e;
        s->floating = floating;
        s->type = type;
        s->enabled = SD_EVENT_OFF;
        s->fd = -1;
        s->priority = SD_EVENT_PRIORITY_NORMAL;

        /* Non-floating: the source holds the event alive, not the reverse
         * (sd_event_source_set_floating(3)'s documented contract). */
        if (!floating)
                sd_event_ref(e);

        s->sources_next = e->sources;
        e->sources = s;
        e->n_sources++;

        return s;
}

void event_source_unlink(sd_event_source *s) {
        sd_event_source **cur;

        for (cur = &s->event->sources; *cur; cur = &(*cur)->sources_next)
                if (*cur == s) {
                        *cur = s->sources_next;
                        s->sources_next = NULL;
                        s->event->n_sources--;
                        return;
                }
}

/* Tear down everything the source itself owns: kill+reap an owned child
 * before its pidfd is closed, unregister and close the backing fd per its
 * ownership flag, run the destroy callback last. Does not touch the
 * event's source list or refcount -- event_source_destroy() does that, and
 * sd_event_unref()'s teardown sweep calls this directly instead, on
 * sources it is discarding outright. */
void event_source_free(sd_event_source *s) {
        if (s->type == SOURCE_CHILD && s->child.process_own && s->fd >= 0) {
                siginfo_t si = { 0 };
                event_pidfd_send_signal(s->fd, SIGKILL, NULL, 0);
                waitid(P_PIDFD, s->fd, &si, WEXITED);
        }

        if (s->fd >= 0) {
                if (s->event)
                        epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, s->fd, NULL);

                bool own = true;
                if (s->type == SOURCE_IO)
                        own = s->io.fd_own;
                else if (s->type == SOURCE_CHILD)
                        own = s->child.pidfd_own;
                /* timerfd/signalfd/inotify fds are always ours */

                if (own)
                        close(s->fd);
        }

        if (s->type == SOURCE_INOTIFY)
                free(s->inotify.path);

        if (s->destroy_callback)
                s->destroy_callback(s->userdata);

        free(s->description);
        free(s);
}

/* The ordinary destruction path: unlink, free, and drop the reference the
 * source held on the event (skipped for a floating source, which never
 * held one -- see event_source_new()). Used both when construction fails
 * partway through an add_*() and when sd_event_source_unref() reaches
 * zero. */
void event_source_destroy(sd_event_source *s) {
        bool floating = s->floating;
        sd_event *e = s->event;

        event_source_unlink(s);
        event_source_free(s);

        if (!floating)
                sd_event_unref(e);
}

int event_epoll_add(sd_event *e, sd_event_source *s, uint32_t events) {
        struct epoll_event ev = { .events = events, .data.ptr = s };

        if (epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, s->fd, &ev) < 0)
                return -errno;
        return 0;
}

int event_source_apply_enabled(sd_event_source *s, int enabled) {
        int old = s->enabled;

        if (old == enabled)
                return 0;

        if (s->fd >= 0) {
                if (enabled == SD_EVENT_OFF)
                        epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, s->fd, NULL);
                else if (old == SD_EVENT_OFF) {
                        struct epoll_event ev = { .data.ptr = s };
                        ev.events = s->type == SOURCE_IO ? s->io.events : EPOLLIN;
                        if (epoll_ctl(s->event->epoll_fd, EPOLL_CTL_ADD, s->fd, &ev) < 0)
                                return -errno;
                }
        }

        s->enabled = enabled;

        /* A disabled source must never be found pending: sd_event_dispatch()'s
         * best-pending scan does not itself check `enabled`, so a source
         * disabled after its event was already collected in the current
         * batch would otherwise still fire once more before going quiet. */
        if (enabled == SD_EVENT_OFF)
                s->pending = false;

        return 0;
}

/* A dispatch or prepare callback returned r < 0: exit the whole loop with
 * that code if the source asked for that, otherwise just stop calling it
 * again. Shared by sd_event_prepare() and sd_event_dispatch(). */
void event_source_apply_failure(sd_event_source *s, int r) {
        if (s->exit_on_failure)
                sd_event_exit(s->event, r);
        else
                event_source_apply_enabled(s, SD_EVENT_OFF);
}

/* ---- construction/refcounting ---------------------------------------- */

int sd_event_new(sd_event **ret) {
        sd_event *e;
        int fd;

        if (!ret)
                return -EINVAL;

        fd = epoll_create1(EPOLL_CLOEXEC);
        if (fd < 0)
                return -errno;

        e = calloc(1, sizeof(*e));
        if (!e) {
                close(fd);
                return -ENOMEM;
        }

        e->n_ref = 1;
        e->epoll_fd = fd;
        e->state = SD_EVENT_INITIAL;
        e->original_pid = getpid();
        /* Upstream records the tid only in sd_event_default(); recording it
         * here too is harmless. */
        e->tid = gettid();

        *ret = e;
        return 0;
}

int sd_event_default(sd_event **ret) {
        sd_event *e;
        int r;

        /* A query, not always "0": upstream returns whether a default
         * already exists when ret is NULL, it does not create one. */
        if (!ret)
                return !!default_event;

        if (default_event) {
                sd_event_ref(default_event);
                *ret = default_event;
                return 0;
        }

        r = sd_event_new(&e);
        if (r < 0)
                return r;

        default_event = e; /* weak stash -- see the file-scope comment above */
        *ret = e;
        return 1;
}

sd_event *sd_event_ref(sd_event *e) {
        if (!e)
                return NULL;
        e->n_ref++;
        return e;
}

sd_event *sd_event_unref(sd_event *e) {
        sd_event_source *s;

        if (!e)
                return NULL;
        if (--e->n_ref > 0)
                return NULL;

        /* By the refcounting invariant, only floating sources can still be
         * here (a non-floating one holds a ref on the event, which would
         * have kept n_ref above zero). Freed unconditionally rather than
         * asserted: aborting the whole process over a caller's leaked
         * reference is worse than a graceful teardown for a small
         * userspace helper library, and it costs nothing to be defensive
         * about a "can't happen". */
        while ((s = e->sources)) {
                e->sources = s->sources_next;
                event_source_free(s);
        }

        if (e->epoll_fd >= 0)
                close(e->epoll_fd);

        if (default_event == e)
                default_event = NULL;

        free(e);
        return NULL;
}

/* ---- generic "NULL callback fires the loop's exit" fallbacks -------- */

static int io_exit_cb(sd_event_source *s, int fd, uint32_t revents, void *userdata) {
        (void) fd;
        (void) revents;
        return sd_event_exit(s->event, (int) (intptr_t) userdata);
}
static int time_exit_cb(sd_event_source *s, uint64_t usec, void *userdata) {
        (void) usec;
        return sd_event_exit(s->event, (int) (intptr_t) userdata);
}
static int signal_exit_cb(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        (void) si;
        return sd_event_exit(s->event, (int) (intptr_t) userdata);
}
static int child_exit_cb(sd_event_source *s, const siginfo_t *si, void *userdata) {
        (void) si;
        return sd_event_exit(s->event, (int) (intptr_t) userdata);
}
static int generic_exit_cb(sd_event_source *s, void *userdata) {
        return sd_event_exit(s->event, (int) (intptr_t) userdata);
}
static int inotify_exit_cb(sd_event_source *s, const struct inotify_event *ev, void *userdata) {
        (void) ev;
        return sd_event_exit(s->event, (int) (intptr_t) userdata);
}

/* ---- constructors ----------------------------------------------------
 *
 * Every one of these follows the same shape: resolve/validate e, apply the
 * NULL-callback fallback, allocate via event_source_new() (floating iff
 * ret == NULL -- sd_event_add_io(3)'s documented contract for every add_*
 * call), do the type-specific setup, and unwind through
 * event_source_destroy() on any failure after allocation. */

int sd_event_add_io(
                sd_event *e,
                sd_event_source **ret,
                int fd,
                uint32_t events,
                sd_event_io_handler_t callback,
                void *userdata) {
        sd_event_source *s;
        int r;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (fd < 0)
                return -EINVAL;
        if (events & ~(uint32_t) (EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLPRI | EPOLLET))
                return -EINVAL;
        if (e->state == SD_EVENT_FINISHED)
                return -ESTALE;
        if (getpid() != e->original_pid)
                return -ECHILD;

        if (!callback)
                callback = io_exit_cb;

        s = event_source_new(e, ret == NULL, SOURCE_IO);
        if (!s)
                return -ENOMEM;

        s->fd = fd;
        s->enabled = SD_EVENT_ON;
        s->io.callback = callback;
        s->io.events = events;
        s->userdata = userdata;

        r = event_epoll_add(e, s, events);
        if (r < 0) {
                event_source_destroy(s);
                return r;
        }

        if (ret)
                *ret = s;
        return 0;
}

int sd_event_add_time(
                sd_event *e,
                sd_event_source **ret,
                clockid_t clock,
                uint64_t usec,
                uint64_t accuracy,
                sd_event_time_handler_t callback,
                void *userdata) {
        sd_event_source *s;
        int fd, r;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (!clock_supported(clock))
                return -EOPNOTSUPP;
        if (e->state == SD_EVENT_FINISHED)
                return -ESTALE;
        if (getpid() != e->original_pid)
                return -ECHILD;

        if (!callback)
                callback = time_exit_cb;

        /* CLOCK_*_ALARM without CAP_WAKE_ALARM fails right here
         * as -errno from the kernel -- not silently downgraded to a
         * non-alarm clock. */
        fd = timerfd_create(clock, TFD_CLOEXEC | TFD_NONBLOCK);
        if (fd < 0)
                return -errno;

        s = event_source_new(e, ret == NULL, SOURCE_TIME);
        if (!s) {
                close(fd);
                return -ENOMEM;
        }

        s->fd = fd;
        s->enabled = SD_EVENT_ON;
        s->time.callback = callback;
        s->time.clock = clock;
        s->time.accuracy = accuracy == 0 ? 250 * EVENT_USEC_PER_MSEC : accuracy;
        s->time.next = usec;
        s->userdata = userdata;

        r = event_epoll_add(e, s, EPOLLIN);
        if (r < 0) {
                event_source_destroy(s);
                return r;
        }

        if (usec != UINT64_MAX) {
                struct itimerspec its = { 0 };
                event_usec_to_timespec(usec, &its.it_value);
                if (timerfd_settime(fd, TFD_TIMER_ABSTIME, &its, NULL) < 0) {
                        r = -errno;
                        event_source_destroy(s);
                        return r;
                }
        }
        /* usec == UINT64_MAX: leave disarmed -- timerfd_create() starts
         * with an all-zero itimerspec already. */

        if (ret)
                *ret = s;
        return 0;
}

int sd_event_add_time_relative(
                sd_event *e,
                sd_event_source **ret,
                clockid_t clock,
                uint64_t usec,
                uint64_t accuracy,
                sd_event_time_handler_t callback,
                void *userdata) {
        uint64_t now_usec;
        int r;

        r = sd_event_now(e, clock, &now_usec);
        if (r < 0)
                return r;

        if (usec == UINT64_MAX)
                return sd_event_add_time(e, ret, clock, UINT64_MAX, accuracy, callback, userdata);
        if (usec > UINT64_MAX - now_usec)
                return -EOVERFLOW;

        return sd_event_add_time(e, ret, clock, now_usec + usec, accuracy, callback, userdata);
}

int sd_event_add_signal(
                sd_event *e, sd_event_source **ret, int sig, sd_event_signal_handler_t callback, void *userdata) {
        sd_event_source *s, *cur;
        sigset_t mask, old;
        bool procmask;
        int fd, r;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;

        procmask = (sig & SD_EVENT_SIGNAL_PROCMASK) != 0;
        sig &= ~SD_EVENT_SIGNAL_PROCMASK;

        if (sig <= 0 || sig >= _NSIG || sig == SIGKILL || sig == SIGSTOP)
                return -EINVAL;
        if (e->state == SD_EVENT_FINISHED)
                return -ESTALE;
        if (getpid() != e->original_pid)
                return -ECHILD;

        for (cur = e->sources; cur; cur = cur->sources_next)
                if (cur->type == SOURCE_SIGNAL && cur->signal.sig == sig)
                        return -EBUSY;

        sigemptyset(&mask);
        sigaddset(&mask, sig);

        if (procmask) {
                /* Single-threaded helper scope: sigprocmask() only ever
                 * touches the calling thread's mask. A caller that spawns
                 * threads must block the signal before doing so, in every
                 * thread that should not handle it via its own disposition. */
                if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
                        return -errno;
        } else {
                if (sigprocmask(SIG_SETMASK, NULL, &old) < 0)
                        return -errno;
                if (!sigismember(&old, sig))
                        return -EBUSY;
        }

        if (!callback)
                callback = signal_exit_cb;

        fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
        if (fd < 0)
                return -errno;

        s = event_source_new(e, ret == NULL, SOURCE_SIGNAL);
        if (!s) {
                close(fd);
                return -ENOMEM;
        }

        s->fd = fd;
        s->enabled = SD_EVENT_ON;
        s->signal.callback = callback;
        s->signal.sig = sig;
        s->userdata = userdata;

        r = event_epoll_add(e, s, EPOLLIN);
        if (r < 0) {
                event_source_destroy(s);
                return r;
        }

        if (ret)
                *ret = s;
        return 0;
}

static int child_options_valid(int options) {
        if (options == 0 || (options & ~(WEXITED | WSTOPPED | WCONTINUED | WNOWAIT)))
                return -EINVAL;
        /* pidfd polling only signals exit; stop/continue transitions cannot
         * be observed. */
        if (options & (WSTOPPED | WCONTINUED))
                return -EOPNOTSUPP;
        if (!(options & WEXITED))
                return -EINVAL;
        return 0;
}

int sd_event_add_child(
                sd_event *e,
                sd_event_source **ret,
                pid_t pid,
                int options,
                sd_event_child_handler_t callback,
                void *userdata) {
        sd_event_source *s, *cur;
        int fd, r;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (pid <= 1)
                return -EINVAL;

        r = child_options_valid(options);
        if (r < 0)
                return r;

        if (e->state == SD_EVENT_FINISHED)
                return -ESTALE;
        if (getpid() != e->original_pid)
                return -ECHILD;

        for (cur = e->sources; cur; cur = cur->sources_next)
                if (cur->type == SOURCE_CHILD && cur->child.pid == pid)
                        return -EBUSY;

        if (!callback)
                callback = child_exit_cb;

        fd = event_pidfd_open(pid, 0);
        if (fd < 0)
                return -errno;

        s = event_source_new(e, ret == NULL, SOURCE_CHILD);
        if (!s) {
                close(fd);
                return -ENOMEM;
        }

        s->fd = fd;
        s->enabled = SD_EVENT_ON;
        s->child.callback = callback;
        s->child.pid = pid;
        s->child.options = options;
        s->child.pidfd_own = true;
        s->userdata = userdata;

        r = event_epoll_add(e, s, EPOLLIN);
        if (r < 0) {
                event_source_destroy(s);
                return r;
        }

        if (ret)
                *ret = s;
        return 0;
}

int sd_event_add_child_pidfd(
                sd_event *e,
                sd_event_source **ret,
                int pidfd,
                int options,
                sd_event_child_handler_t callback,
                void *userdata) {
        sd_event_source *s, *cur;
        pid_t pid = 0;
        int r;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (pidfd < 0)
                return -EINVAL;

        r = child_options_valid(options);
        if (r < 0)
                return r;

        if (e->state == SD_EVENT_FINISHED)
                return -ESTALE;
        if (getpid() != e->original_pid)
                return -ECHILD;

        /* Best effort: duplicate detection only covers add_child()-created
         * sources, since resolving this pidfd back to a pid is itself
         * best-effort (see event_pidfd_get_pid()). A failed resolution
         * just means no duplicate check runs, not that add fails. */
        event_pidfd_get_pid(pidfd, &pid);
        if (pid > 0)
                for (cur = e->sources; cur; cur = cur->sources_next)
                        if (cur->type == SOURCE_CHILD && cur->child.pid == pid)
                                return -EBUSY;

        if (!callback)
                callback = child_exit_cb;

        s = event_source_new(e, ret == NULL, SOURCE_CHILD);
        if (!s)
                return -ENOMEM;

        s->fd = pidfd;
        s->enabled = SD_EVENT_ON;
        s->child.callback = callback;
        s->child.pid = pid;
        s->child.options = options;
        s->child.pidfd_own = false;
        s->userdata = userdata;

        r = event_epoll_add(e, s, EPOLLIN);
        if (r < 0) {
                event_source_destroy(s);
                return r;
        }

        if (ret)
                *ret = s;
        return 0;
}

int sd_event_add_inotify(
                sd_event *e,
                sd_event_source **ret,
                const char *path,
                uint32_t mask,
                sd_event_inotify_handler_t callback,
                void *userdata) {
        sd_event_source *s;
        int fd, wd, r;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (!path)
                return -EINVAL;
        if (e->state == SD_EVENT_FINISHED)
                return -ESTALE;
        if (getpid() != e->original_pid)
                return -ECHILD;

        if (!callback)
                callback = inotify_exit_cb;

        /* One inotify instance per source -- no systemd-style per-inode
         * watch sharing. Contract-legal (the caller only ever sees its own
         * mask/path back), and helper tools do not run enough overlapping
         * watches for the sharing to matter. */
        fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (fd < 0)
                return -errno;

        wd = inotify_add_watch(fd, path, mask);
        if (wd < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        s = event_source_new(e, ret == NULL, SOURCE_INOTIFY);
        if (!s) {
                close(fd);
                return -ENOMEM;
        }

        s->fd = fd;
        s->enabled = SD_EVENT_ON;
        s->inotify.callback = callback;
        s->inotify.mask = mask;
        s->inotify.path = strdup(
                        path); /* best-effort; NULL just means get_inotify_path() later returns -ENODATA */
        s->userdata = userdata;

        r = event_epoll_add(e, s, EPOLLIN);
        if (r < 0) {
                event_source_destroy(s);
                return r;
        }

        if (ret)
                *ret = s;
        return 0;
}

int sd_event_add_inotify_fd(
                sd_event *e,
                sd_event_source **ret,
                int fd,
                uint32_t mask,
                sd_event_inotify_handler_t callback,
                void *userdata) {
        sd_event_source *s;
        char procpath[32];
        char linkbuf[4096];
        char *path = NULL;
        ssize_t n;
        int ifd, wd, r;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (fd < 0)
                return -EINVAL;
        if (e->state == SD_EVENT_FINISHED)
                return -ESTALE;
        if (getpid() != e->original_pid)
                return -ECHILD;

        if (!callback)
                callback = inotify_exit_cb;

        snprintf(procpath, sizeof(procpath), "/proc/self/fd/%d", fd);

        ifd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
        if (ifd < 0)
                return -errno;

        /* The kernel resolves the symlink to the real inode at watch-add
         * time; fd itself is never stored or owned by the source. */
        wd = inotify_add_watch(ifd, procpath, mask);
        if (wd < 0) {
                r = -errno;
                close(ifd);
                return r;
        }

        n = readlink(procpath, linkbuf, sizeof(linkbuf) - 1);
        if (n > 0) {
                linkbuf[n] = 0;
                path = strdup(linkbuf); /* best-effort snapshot; failure just leaves path NULL */
        }

        s = event_source_new(e, ret == NULL, SOURCE_INOTIFY);
        if (!s) {
                close(ifd);
                free(path);
                return -ENOMEM;
        }

        s->fd = ifd;
        s->enabled = SD_EVENT_ON;
        s->inotify.callback = callback;
        s->inotify.mask = mask;
        s->inotify.path = path;
        s->userdata = userdata;

        r = event_epoll_add(e, s, EPOLLIN);
        if (r < 0) {
                event_source_destroy(s);
                return r;
        }

        if (ret)
                *ret = s;
        return 0;
}

int sd_event_add_defer(sd_event *e, sd_event_source **ret, sd_event_handler_t callback, void *userdata) {
        sd_event_source *s;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (e->state == SD_EVENT_FINISHED)
                return -ESTALE;
        if (getpid() != e->original_pid)
                return -ECHILD;

        if (!callback)
                callback = generic_exit_cb;

        s = event_source_new(e, ret == NULL, SOURCE_DEFER);
        if (!s)
                return -ENOMEM;

        /* An enabled DEFER source is marked pending on every prepare(),
         * which is what makes the loop non-blocking while one is ON --
         * callers throttle via ONESHOT or set_enabled(), not via this
         * constructor. */
        s->enabled = SD_EVENT_ON;
        s->generic.callback = callback;
        s->userdata = userdata;

        if (ret)
                *ret = s;
        return 0;
}

int sd_event_add_post(sd_event *e, sd_event_source **ret, sd_event_handler_t callback, void *userdata) {
        sd_event_source *s;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (e->state == SD_EVENT_FINISHED)
                return -ESTALE;
        if (getpid() != e->original_pid)
                return -ECHILD;

        if (!callback)
                callback = generic_exit_cb;

        s = event_source_new(e, ret == NULL, SOURCE_POST);
        if (!s)
                return -ENOMEM;

        s->enabled = SD_EVENT_ON;
        s->generic.callback = callback;
        s->userdata = userdata;

        if (ret)
                *ret = s;
        return 0;
}

int sd_event_add_exit(sd_event *e, sd_event_source **ret, sd_event_handler_t callback, void *userdata) {
        sd_event_source *s;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (!callback) /* the one add_*() that requires a real callback -- no useful default exists */
                return -EINVAL;
        if (e->state == SD_EVENT_FINISHED)
                return -ESTALE;
        if (getpid() != e->original_pid)
                return -ECHILD;

        s = event_source_new(e, ret == NULL, SOURCE_EXIT);
        if (!s)
                return -ENOMEM;

        s->enabled = SD_EVENT_ONESHOT;
        s->generic.callback = callback;
        s->userdata = userdata;

        if (ret)
                *ret = s;
        return 0;
}

/* The PSI pressure source needs the $MEMORY_PRESSURE_WATCH/cgroup PSI
 * protocol. Upstream returns -EOPNOTSUPP when PSI is unavailable, so
 * portable callers already handle it; a fake success would promise wakeups
 * that never come. */
int sd_event_add_memory_pressure(sd_event *e, sd_event_source **ret, sd_event_handler_t callback, void *userdata) {
        (void) e;
        (void) ret;
        (void) callback;
        (void) userdata;
        return -EOPNOTSUPP;
}

int sd_event_add_cpu_pressure(sd_event *e, sd_event_source **ret, sd_event_handler_t callback, void *userdata) {
        (void) e;
        (void) ret;
        (void) callback;
        (void) userdata;
        return -EOPNOTSUPP;
}

int sd_event_add_io_pressure(sd_event *e, sd_event_source **ret, sd_event_handler_t callback, void *userdata) {
        (void) e;
        (void) ret;
        (void) callback;
        (void) userdata;
        return -EOPNOTSUPP;
}

/* ---- the loop itself -------------------------------------------------- */

static bool event_is_idle(sd_event *e) {
        sd_event_source *s;

        for (s = e->sources; s; s = s->sources_next) {
                if (s->type == SOURCE_EXIT)
                        continue;
                if (s->type == SOURCE_POST && !s->pending)
                        continue;
                if (s->enabled != SD_EVENT_OFF)
                        return false;
        }
        return true;
}

static bool event_has_pending(sd_event *e) {
        sd_event_source *s;

        for (s = e->sources; s; s = s->sources_next)
                if (s->pending)
                        return true;
        return false;
}

static int priority_cmp(const void *a, const void *b) {
        const sd_event_source *sa = *(const sd_event_source * const *) a;
        const sd_event_source *sb = *(const sd_event_source * const *) b;

        return sa->priority < sb->priority ? -1 : sa->priority > sb->priority ? 1 : 0;
}

/* Every enabled source's prepare() callback, lowest priority first. Sorted
 * into a scratch array so priority order does not depend on list-insertion
 * order; on OOM (only realistic on a rather large source count) it falls
 * back to list order rather than failing prepare() outright -- every
 * enabled callback still runs, just not guaranteed lowest-priority-first
 * relative to each other.
 *
 * Every entry is ref'd before the loop and unref'd after, the same idiom
 * sd_event_dispatch() already uses around its own single callback: without
 * it, one source's prepare callback destroying a DIFFERENT still-unvisited
 * entry would leave arr[] holding a freed pointer for the rest of this
 * scan. Holding a ref merely defers the actual free (event_source_destroy())
 * until this function's own unref drops it back to whatever the callback
 * left it at -- it does not change what the callback observed. */
static void run_prepare_callbacks(sd_event *e) {
        sd_event_source **arr, *s;
        size_t n = 0, i;
        int r;

        arr = e->n_sources ? calloc(e->n_sources, sizeof(*arr)) : NULL;
        if (!arr) {
                for (s = e->sources; s; s = s->sources_next)
                        if (s->enabled != SD_EVENT_OFF && s->prepare) {
                                r = s->prepare(s, s->userdata);
                                if (r < 0)
                                        event_source_apply_failure(s, r);
                        }
                return;
        }

        for (s = e->sources; s; s = s->sources_next)
                arr[n++] = sd_event_source_ref(s);

        qsort(arr, n, sizeof(*arr), priority_cmp);

        for (i = 0; i < n; i++) {
                s = arr[i];
                if (s->enabled != SD_EVENT_OFF && s->prepare) {
                        r = s->prepare(s, s->userdata);
                        if (r < 0)
                                event_source_apply_failure(s, r);
                }
        }

        for (i = 0; i < n; i++)
                sd_event_source_unref(arr[i]);

        free(arr);
}

int sd_event_prepare(sd_event *e) {
        sd_event_source *s;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (getpid() != e->original_pid)
                return -ECHILD;
        if (e->state == SD_EVENT_FINISHED)
                return -ESTALE;
        if (e->state != SD_EVENT_INITIAL)
                return -EBUSY;

        if (e->exit_on_idle && !e->exit_requested && event_is_idle(e))
                sd_event_exit(e, 0);

        if (e->exit_requested) {
                e->state = SD_EVENT_ARMED;
                return sd_event_wait(e, 0);
        }

        e->iteration++;
        e->state = SD_EVENT_PREPARING;
        run_prepare_callbacks(e);
        e->state = SD_EVENT_INITIAL;

        for (s = e->sources; s; s = s->sources_next)
                if (s->type == SOURCE_DEFER && s->enabled != SD_EVENT_OFF)
                        s->pending = true;

        if (event_has_pending(e)) {
                e->state = SD_EVENT_ARMED;
                return sd_event_wait(e, 0);
        }

        e->state = SD_EVENT_ARMED;
        return 0;
}

static int usec_to_epoll_timeout(uint64_t usec) {
        uint64_t ms;

        if (usec == UINT64_MAX)
                return -1;

        ms = (usec + 999) / 1000;
        return ms > (uint64_t) INT_MAX ? INT_MAX : (int) ms;
}

static void event_cache_timestamps(sd_event *e) {
        struct timespec ts;

        clock_gettime(CLOCK_REALTIME, &ts);
        e->ts_realtime = event_timespec_to_usec(&ts);
        clock_gettime(CLOCK_MONOTONIC, &ts);
        e->ts_monotonic = event_timespec_to_usec(&ts);
        clock_gettime(CLOCK_BOOTTIME, &ts);
        e->ts_boottime = event_timespec_to_usec(&ts);

        e->timestamp_valid = true;
}

int sd_event_wait(sd_event *e, uint64_t timeout) {
        struct epoll_event events[EVENT_MAX_EVENTS];
        int n, i;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (e->state != SD_EVENT_ARMED)
                return -EBUSY;

        if (e->exit_requested) {
                e->state = SD_EVENT_PENDING;
                return 1;
        }

        n = epoll_wait(e->epoll_fd, events, EVENT_MAX_EVENTS, usec_to_epoll_timeout(timeout));
        if (n < 0) {
                if (errno == EINTR)
                        n = 0;
                else {
                        e->state = SD_EVENT_INITIAL;
                        return -errno;
                }
        }

        event_cache_timestamps(e);

        for (i = 0; i < n; i++) {
                sd_event_source *s = events[i].data.ptr;
                s->pending = true;
                if (s->type == SOURCE_IO)
                        s->io.revents = events[i].events;
        }

        if (n > 0 || event_has_pending(e)) {
                e->state = SD_EVENT_PENDING;
                return 1;
        }

        e->state = SD_EVENT_INITIAL;
        return 0;
}

static int dispatch_source_callback(sd_event_source *s) {
        switch (s->type) {
        case SOURCE_IO:
                return s->io.callback(s, s->fd, s->io.revents, s->userdata);

        case SOURCE_TIME: {
                uint64_t expirations, now_usec;
                struct timespec ts;
                ssize_t n;

                /* Best-effort drain; the callback runs below with a fresh
                 * timestamp regardless of whether this returned anything. */
                n = read(s->fd, &expirations, sizeof(expirations));
                (void) n;

                clock_gettime(s->time.clock, &ts);
                now_usec = event_timespec_to_usec(&ts);
                return s->time.callback(s, now_usec, s->userdata);
        }

        case SOURCE_SIGNAL: {
                struct signalfd_siginfo si;
                if (read(s->fd, &si, sizeof(si)) != (ssize_t) sizeof(si))
                        return 0; /* spurious wakeup; nothing meaningful to hand the callback */
                return s->signal.callback(s, &si, s->userdata);
        }

        case SOURCE_CHILD: {
                siginfo_t si = { 0 };
                int wopts = WEXITED | WNOHANG | (s->child.options & WNOWAIT);
                int r;

                if (waitid(P_PIDFD, s->fd, &si, wopts) < 0)
                        return -errno;

                r = s->child.callback(s, &si, s->userdata);

                /* A reaped zombie can never signal again, regardless of
                 * whether the source was ON or ONESHOT to begin with. */
                if (!(s->child.options & WNOWAIT))
                        event_source_apply_enabled(s, SD_EVENT_OFF);

                return r;
        }

        case SOURCE_DEFER:
        case SOURCE_POST:
                return s->generic.callback(s, s->userdata);

        case SOURCE_INOTIFY: {
                char buf[4096] __attribute__((aligned(__alignof__(struct inotify_event))));
                ssize_t n;
                char *p;
                int r = 0;

                n = read(s->fd, buf, sizeof(buf));
                if (n <= 0)
                        return 0;

                for (p = buf; p < buf + n;) {
                        struct inotify_event *ev = (struct inotify_event *) p;

                        r = s->inotify.callback(s, ev, s->userdata);
                        if (r < 0 || s->enabled == SD_EVENT_OFF)
                                break; /* callback disabled (or is tearing down) this source */

                        p += sizeof(struct inotify_event) + ev->len;
                }
                return r;
        }

        case SOURCE_EXIT:
        default:
                return 0; /* SOURCE_EXIT is dispatched from sd_event_dispatch()'s exit_requested branch, not here */
        }
}

int sd_event_dispatch(sd_event *e) {
        sd_event_source *s, *best;
        int r;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (e->state != SD_EVENT_PENDING)
                return -EBUSY;

        if (e->exit_requested) {
                best = NULL;
                for (s = e->sources; s; s = s->sources_next) {
                        if (s->type != SOURCE_EXIT || s->enabled == SD_EVENT_OFF || s->ran)
                                continue;
                        if (!best || s->priority < best->priority)
                                best = s;
                }

                if (!best) {
                        e->state = SD_EVENT_FINISHED;
                        return 0;
                }

                best->ran = true;
                e->state = SD_EVENT_EXITING;
                sd_event_source_ref(best);
                r = best->generic.callback(best, best->userdata);
                if (r < 0)
                        event_source_apply_failure(best, r);
                sd_event_source_unref(best);

                e->state = SD_EVENT_INITIAL;
                return 1;
        }

        best = NULL;
        for (s = e->sources; s; s = s->sources_next) {
                if (!s->pending)
                        continue;
                if (!best || s->priority < best->priority)
                        best = s;
        }

        if (!best) {
                /* Nothing pending despite state==PENDING: defensive, should
                 * not happen given sd_event_wait()'s own contract. */
                e->state = SD_EVENT_INITIAL;
                return 0;
        }

        best->pending = false;
        if (best->enabled == SD_EVENT_ONESHOT)
                event_source_apply_enabled(best, SD_EVENT_OFF);

        e->state = SD_EVENT_RUNNING;
        sd_event_source_ref(best);

        r = dispatch_source_callback(best);
        if (r < 0)
                event_source_apply_failure(best, r);

        if (best->type != SOURCE_POST)
                for (s = e->sources; s; s = s->sources_next)
                        if (s->type == SOURCE_POST && s->enabled != SD_EVENT_OFF)
                                s->pending = true;

        sd_event_source_unref(best);
        e->state = SD_EVENT_INITIAL;
        return 1;
}

int sd_event_run(sd_event *e, uint64_t timeout) {
        int r;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (e->state == SD_EVENT_FINISHED)
                return -ESTALE;
        if (e->state != SD_EVENT_INITIAL)
                return -EBUSY;

        r = sd_event_prepare(e);
        if (r == 0)
                r = sd_event_wait(e, timeout);
        if (r > 0) {
                r = sd_event_dispatch(e);
                return r < 0 ? r : 1;
        }
        return r;
}

int sd_event_loop(sd_event *e) {
        int r;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (e->state != SD_EVENT_INITIAL)
                return -EBUSY;

        sd_event_ref(e);
        while (e->state != SD_EVENT_FINISHED) {
                r = sd_event_run(e, UINT64_MAX);
                if (r < 0) {
                        sd_event_unref(e);
                        return r;
                }
        }

        r = e->exit_code;
        sd_event_unref(e);
        return r;
}

int sd_event_exit(sd_event *e, int code) {
        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (e->state == SD_EVENT_FINISHED)
                return -ESTALE;

        e->exit_requested = true;
        e->exit_code = code;
        return 0;
}

int sd_event_now(sd_event *e, clockid_t clock, uint64_t *ret) {
        struct timespec ts;

        if (!e || !ret)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (!clock_supported(clock))
                return -EOPNOTSUPP;

        if (e->timestamp_valid) {
                switch (clock) {
                case CLOCK_MONOTONIC:
                        *ret = e->ts_monotonic;
                        break;
                case CLOCK_BOOTTIME:
                case CLOCK_BOOTTIME_ALARM:
                        *ret = e->ts_boottime;
                        break;
                default: /* CLOCK_REALTIME, CLOCK_REALTIME_ALARM */
                        *ret = e->ts_realtime;
                        break;
                }
                return 0;
        }

        /* Before the first completed wait(): a fresh read, and a positive
         * return says so (sd_event_now(3)'s documented "not from the loop
         * cache" signal). */
        clock_gettime(clock, &ts);
        *ret = event_timespec_to_usec(&ts);
        return 1;
}

/* ---- misc accessors ---------------------------------------------------- */

/* What makes the shim loop embeddable in a foreign epoll loop, per
 * sd_event_get_fd(3). PID 1 itself never needs this: the manager's loop IS
 * an sd_event (src/manager.h), not a foreign loop grafted onto one. */
int sd_event_get_fd(sd_event *e) {
        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        return e->epoll_fd;
}

int sd_event_get_state(sd_event *e) {
        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        return e->state;
}

int sd_event_get_tid(sd_event *e, pid_t *ret) {
        if (!e || !ret)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        *ret = e->tid;
        return 0;
}

int sd_event_get_exit_code(sd_event *e, int *ret) {
        if (!e || !ret)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        if (!e->exit_requested)
                return -ENODATA;
        *ret = e->exit_code;
        return 0;
}

int sd_event_set_watchdog(sd_event *e, int b) {
        uint64_t usec;
        int r;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;

        if (!b) {
                e->watchdog = false;
                return 0;
        }

        /*
         * Uses sd_watchdog_enabled() so both agree on what "enabled, for us"
         * means. unset_environment=0: this is a query and must not clear
         * the variables for other consumers.
         *
         * r <= 0 (env absent, malformed, or naming a different pid) all
         * mean "not enabled".
         */
        r = sd_watchdog_enabled(0, &usec);
        if (r <= 0) {
                e->watchdog = false;
                return 0;
        }

        /* Enabled and for us, but pinging is not implemented (it would need a
         * CLOCK_MONOTONIC timer at usec/2 calling sd_notify("WATCHDOG=1")).
         * Failing visibly beats silently never pinging and being killed by
         * the supervisor. */
        return -EOPNOTSUPP;
}

int sd_event_get_watchdog(sd_event *e) {
        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        return e->watchdog;
}

int sd_event_get_iteration(sd_event *e, uint64_t *ret) {
        if (!e || !ret)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        *ret = e->iteration;
        return 0;
}

int sd_event_set_signal_exit(sd_event *e, int b) {
        sigset_t mask;

        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;

        if (!!b == e->signal_exit_set)
                return 0;

        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGINT);

        if (b) {
                sd_event_source *term = NULL, *sig_int = NULL;
                int r;

                if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
                        return -errno;

                /* Already blocked above, so add_signal()'s own "must
                 * already be blocked" check passes without SD_EVENT_SIGNAL_PROCMASK. */
                r = sd_event_add_signal(e, &term, SIGTERM, NULL, (void *) (intptr_t) SIGTERM);
                if (r >= 0)
                        r = sd_event_add_signal(e, &sig_int, SIGINT, NULL, (void *) (intptr_t) SIGINT);
                if (r < 0) {
                        if (term)
                                sd_event_source_unref(term);
                        sigprocmask(SIG_UNBLOCK, &mask, NULL);
                        return r;
                }

                sd_event_source_set_floating(term, true);
                sd_event_source_unref(term);
                sd_event_source_set_floating(sig_int, true);
                sd_event_source_unref(sig_int);

                e->signal_exit_term = term;
                e->signal_exit_int = sig_int;
        } else {
                if (e->signal_exit_term)
                        sd_event_source_unref(e->signal_exit_term);
                if (e->signal_exit_int)
                        sd_event_source_unref(e->signal_exit_int);
                e->signal_exit_term = NULL;
                e->signal_exit_int = NULL;

                sigprocmask(SIG_UNBLOCK, &mask, NULL);
        }

        e->signal_exit_set = !!b;
        return 1;
}

int sd_event_set_exit_on_idle(sd_event *e, int b) {
        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        e->exit_on_idle = !!b;
        return 0;
}

int sd_event_get_exit_on_idle(sd_event *e) {
        if (!e)
                return -EINVAL;
        e = event_resolve(e);
        if (!e)
                return -ENOPKG;
        return e->exit_on_idle;
}

int sd_event_trim_memory(void) {
#if defined(__GLIBC__)
        malloc_trim(0);
        return 0;
#else
        return -EOPNOTSUPP;
#endif
}
