/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * See manager-watchdog.h for the contract. This is the real body: open,
 * negotiate, feed. ioctl numbers/flags come straight from the real uapi
 * <linux/watchdog.h>, never redefined here.
 *
 * STARVATION ARGUMENT (the property EVENT_PRIORITY_WATCHDOG exists to
 * guarantee):
 * sd-event.c's time sources become pending only via epoll, and
 * sd_event_dispatch() re-polls with a ZERO timeout between single-source
 * dispatches while anything stays pending -- so a due watchdog timerfd is
 * picked up on the very next re-poll even mid-batch, and at -20 it beats
 * every other source in the program (dispatch is strictly lowest-priority-
 * first). Worst-case feed latency under any event storm is therefore one
 * callback's own runtime, not a queue depth. This is exactly why it must
 * NOT sit at SD_EVENT_PRIORITY_IDLE: an idle source stays pending-but-
 * never-dispatched for as long as anything higher keeps re-arming, and a
 * watchdog a busy loop can silently starve fires a reset on a HEALTHY
 * machine -- worse than no watchdog at all. In the other direction, this
 * source cannot starve anything else: it is pending at most once per
 * interval (re-arm targets strictly-future usec), and its callback is one
 * ioctl plus one timerfd_settime -- no allocation, no I/O beyond the ioctl.
 */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/watchdog.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "manager-watchdog.h"
#include "manager.h"
#include "sd-event.h"
#include "util.h"

/*
 * Requested timeout: long enough that no legitimate single PID1 operation
 * (a unit-dir scan on slow media, a sync()) plausibly exceeds three feed
 * intervals, short enough that an unattended embedded device recovers from
 * a wedge in under a minute. Upstream defaults to off
 * (RuntimeWatchdogSec=0).
 */
#define PICO_WATCHDOG_TIMEOUT_SEC 30

struct pico_manager_watchdog {
        sd_event_source *source;
        int fd; /* -1 in manager_watchdog_debug_arm() mode: feeds count only */
        usec_t interval;
        bool magic_close;
        bool ping_failed_logged;
        size_t n_pings;
};

/* open() + O_CLOEXEC (mandatory: PID 1 forks every service, a leaked fd
 * would let any child write the device) + S_ISCHR guard, so a misconfigured
 * path pointing at a regular file cannot "succeed" while every later ioctl
 * fails and feeding is fiction. */
static int watchdog_try_open(const char *path, int *fd_out) {
        struct stat st;
        int fd, r;

        fd = open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (fstat(fd, &st) < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        if (!S_ISCHR(st.st_mode)) {
                close(fd);
                return -ENODEV;
        }

        *fd_out = fd;
        return 0;
}

/* m->watchdog_device (test override) if set, else /dev/watchdog0 then
 * /dev/watchdog, new-style node first -- same order and reason as upstream
 * watchdog_open(). *path_out is set even on failure, to whichever path was
 * last tried, so the caller can name it in a WARNING. */
static int watchdog_open_device(Manager *m, int *fd_out, const char **path_out) {
        static const char * const candidates[] = { "/dev/watchdog0", "/dev/watchdog" };
        int r;
        size_t i;

        if (m->watchdog_device) {
                *path_out = m->watchdog_device;
                return watchdog_try_open(m->watchdog_device, fd_out);
        }

        r = -ENOENT;
        for (i = 0; i < 2; i++) {
                *path_out = candidates[i];
                r = watchdog_try_open(candidates[i], fd_out);
                if (r == 0)
                        return 0;
                if (r != -ENOENT)
                        pico_log(PICO_LOG_DEBUG, "%s: %s", candidates[i], strerror(-r));
        }

        return r;
}

/*
 * SETTIMEOUT(request) -> GETTIMEOUT(read back) -> fallback. The read-back
 * value, not the request, is the real timeout: a driver may clamp 30 to its
 * own min/max. Neither ioctl failing is fatal -- assume the request stood,
 * same fallback upstream watchdog_update_timeout() takes.
 */
static usec_t watchdog_negotiate_timeout(int fd) {
        int sec = PICO_WATCHDOG_TIMEOUT_SEC;

        if (ioctl(fd, WDIOC_SETTIMEOUT, &sec) < 0)
                pico_log(PICO_LOG_DEBUG, "WDIOC_SETTIMEOUT: %s", strerror(errno));

        sec = PICO_WATCHDOG_TIMEOUT_SEC;
        if (ioctl(fd, WDIOC_GETTIMEOUT, &sec) < 0) {
                pico_log(PICO_LOG_WARNING,
                         "WDIOC_GETTIMEOUT failed (%s), assuming the requested %ds timeout stood",
                         strerror(errno),
                         PICO_WATCHDOG_TIMEOUT_SEC);
                sec = PICO_WATCHDOG_TIMEOUT_SEC;
        } else if (sec <= 0) {
                pico_log(PICO_LOG_WARNING,
                         "driver reported a non-positive timeout (%d), assuming %ds",
                         sec,
                         PICO_WATCHDOG_TIMEOUT_SEC);
                sec = PICO_WATCHDOG_TIMEOUT_SEC;
        }

        return (usec_t) sec * USEC_PER_SEC;
}

usec_t manager_watchdog_interval_from_timeout(usec_t timeout_usec) {
        return timeout_usec / 4;
}

/*
 * The feed timer's own callback (EVENT_PRIORITY_WATCHDOG). CALLBACK
 * CONTRACT (manager-loop.c's header): returns 0 on every path, including a
 * failed ping or a failed re-arm -- a transient ioctl failure must never
 * permanently disable the feeder, and a failed re-arm is logged loudly
 * instead, since the timer genuinely cannot fire again.
 */
static int watchdog_feed_cb(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = userdata;
        struct pico_manager_watchdog *wd = m->watchdog;
        int r;

        if (!wd)
                return 0;

        if (wd->fd >= 0) {
                if (ioctl(wd->fd, WDIOC_KEEPALIVE, 0) < 0) {
                        if (!wd->ping_failed_logged) {
                                pico_log(PICO_LOG_ERR, "watchdog keepalive failed: %s", strerror(errno));
                                wd->ping_failed_logged = true;
                        }
                } else if (wd->ping_failed_logged) {
                        pico_log(PICO_LOG_INFO, "watchdog keepalive recovered");
                        wd->ping_failed_logged = false;
                }
        }
        wd->n_pings++;

        r = sd_event_source_set_time(s, usec_add(usec, wd->interval));
        if (r < 0)
                pico_log(PICO_LOG_ERR,
                         "failed to re-arm the watchdog feed timer: %s -- the hardware watchdog will now fire",
                         strerror(-r));

        return 0;
}

static int watchdog_arm_timer(Manager *m, struct pico_manager_watchdog *wd) {
        int r;

        r = sd_event_add_time(
                        m->event,
                        &wd->source,
                        CLOCK_MONOTONIC,
                        usec_add(now_monotonic(), wd->interval),
                        0,
                        watchdog_feed_cb,
                        m);
        if (r < 0)
                return r;

        sd_event_source_set_priority(wd->source, EVENT_PRIORITY_WATCHDOG);
        return 0;
}

int manager_watchdog_setup(Manager *m) {
        struct pico_manager_watchdog *wd;
        struct watchdog_info info;
        const char *path = NULL;
        int fd, opt, r;

        if (!m || !m->event)
                return -EINVAL;

        r = watchdog_open_device(m, &fd, &path);
        if (r < 0) {
                if (r != -ENOENT)
                        pico_log(PICO_LOG_WARNING, "%s: %s", path ? path : "(watchdog device)", strerror(-r));
                return r;
        }

        wd = calloc(1, sizeof(*wd));
        if (!wd) {
                close(fd);
                return -ENOMEM;
        }
        wd->fd = fd;

        if (ioctl(fd, WDIOC_GETSUPPORT, &info) < 0)
                pico_log(PICO_LOG_DEBUG, "%s: WDIOC_GETSUPPORT: %s", path, strerror(errno));
        else {
                char ident[sizeof(info.identity) + 1];

                memcpy(ident, info.identity, sizeof(info.identity));
                ident[sizeof(info.identity)] = '\0';
                wd->magic_close = (info.options & WDIOF_MAGICCLOSE) != 0;
                pico_log(PICO_LOG_INFO,
                         "%s: %s (firmware 0x%" PRIx32 "), magic-close %s",
                         path,
                         ident,
                         info.firmware_version,
                         wd->magic_close ? "supported" : "not supported");
        }

        wd->interval = manager_watchdog_interval_from_timeout(watchdog_negotiate_timeout(fd));

        opt = WDIOS_ENABLECARD;
        if (ioctl(fd, WDIOC_SETOPTIONS, &opt) < 0 && errno != ENOTTY)
                pico_log(PICO_LOG_WARNING, "%s: WDIOC_SETOPTIONS(ENABLECARD): %s", path, strerror(errno));

        if (ioctl(fd, WDIOC_KEEPALIVE, 0) < 0)
                pico_log(PICO_LOG_WARNING, "%s: initial keepalive: %s", path, strerror(errno));

        r = watchdog_arm_timer(m, wd);
        if (r < 0) {
                close(fd);
                free(wd);
                return r;
        }

        m->watchdog = wd;
        pico_log(PICO_LOG_INFO,
                 "watchdog armed: %s, timeout %" PRIu64 "s, feeding every %" PRIu64 "ms",
                 path,
                 (wd->interval * 4) / USEC_PER_SEC,
                 wd->interval / USEC_PER_MSEC);

        return 0;
}

void manager_watchdog_done(Manager *m) {
        struct pico_manager_watchdog *wd;

        if (!m || !m->watchdog)
                return;

        wd = m->watchdog;
        wd->source = sd_event_source_disable_unref(wd->source);

        if (wd->fd >= 0) {
                /*
                 * PID 1 itself (m->is_system) never disarms -- see this
                 * file's header block / manager-watchdog.h's SHUTDOWN note:
                 * main.c frees the manager before sync()+reboot(), so
                 * staying armed protects exactly the tail of shutdown a
                 * software deadline cannot. A non-system manager (tests)
                 * gets a real disarm, so a privileged test run on real
                 * hardware never leaves a ticking watchdog behind -- though
                 * a nowayout driver can still ignore both writes below;
                 * nothing userspace does can override that kernel policy.
                 */
                if (!m->is_system) {
                        int disopt = WDIOS_DISABLECARD;

                        if (ioctl(wd->fd, WDIOC_SETOPTIONS, &disopt) < 0)
                                pico_log(PICO_LOG_WARNING, "watchdog disarm (SETOPTIONS): %s", strerror(errno));

                        for (;;) {
                                ssize_t n = write(wd->fd, "V", 1);

                                if (n == 1)
                                        break;
                                if (n < 0 && errno == EINTR)
                                        continue;
                                pico_log(PICO_LOG_WARNING,
                                         "watchdog magic-close write: %s",
                                         n < 0 ? strerror(errno) : "short write");
                                break;
                        }
                }

                close(wd->fd);
        }

        free(wd);
        m->watchdog = NULL;
}

bool manager_watchdog_armed(Manager *m) {
        return m && m->watchdog && m->watchdog->source;
}

usec_t manager_watchdog_ping_interval(Manager *m) {
        if (!m || !m->watchdog)
                return 0;

        return m->watchdog->interval;
}

sd_event_source *manager_watchdog_debug_source(Manager *m) {
        if (!m || !m->watchdog)
                return NULL;

        return m->watchdog->source;
}

int manager_watchdog_debug_arm(Manager *m, usec_t interval) {
        struct pico_manager_watchdog *wd;
        int r;

        if (!m || !m->event || interval == 0 || interval == USEC_INFINITY)
                return -EINVAL;

        if (m->watchdog)
                manager_watchdog_done(m);

        wd = calloc(1, sizeof(*wd));
        if (!wd)
                return -ENOMEM;

        wd->fd = -1;
        wd->interval = interval;

        r = watchdog_arm_timer(m, wd);
        if (r < 0) {
                free(wd);
                return r;
        }

        m->watchdog = wd;
        return 0;
}

size_t manager_watchdog_debug_n_pings(Manager *m) {
        if (!m || !m->watchdog)
                return 0;

        return m->watchdog->n_pings;
}
