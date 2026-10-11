/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * devd's event loop: one epoll fd multiplexing the shared signalfd, the shared
 * timerfd (which is what closes a settle window) and the group-1 uevent socket.
 *
 * The registration pattern is the same as netd-loop.c's. Registrations carry
 * their own callback in the tag, dispatch reads data.ptr back, and
 * `registered` -- never `fd >= 0` -- says a tag is live: every tag lives inside
 * a calloc()'d owner, so fd == 0 is a valid descriptor and only the bool is
 * reliably zero.
 *
 * The callback is kept although the sources are fixed, so the RUN+= child
 * reaping source can be added without editing a dispatch switch.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct Devd Devd;

typedef enum DevdEpollSource {
        DEVD_EPOLL_SIGNAL,
        DEVD_EPOLL_TIMER,
        DEVD_EPOLL_UEVENT,
        _DEVD_EPOLL_SOURCE_MAX,
} DevdEpollSource;

struct devd_epoll_tag;

typedef int (*devd_io_callback_t)(Devd *d, struct devd_epoll_tag *tag, uint32_t revents);

struct devd_epoll_tag {
        DevdEpollSource source;
        int fd;          /* -1 when not registered; see `registered` */
        bool registered; /* authoritative; false is calloc()'s own default */
        devd_io_callback_t callback;
        void *userdata;
};

/* epoll_create1(), then register the signalfd and the timerfd. 0 or -errno. */
int devd_loop_setup(Devd *d);

/* Register `fd`, filling in `tag` (caller-owned, must outlive the
 * registration). -EBUSY on a tag that is already registered. */
int devd_loop_add_io(
                Devd *d,
                struct devd_epoll_tag *tag,
                int fd,
                uint32_t events,
                DevdEpollSource source,
                devd_io_callback_t callback,
                void *userdata);

/* Deregister. Safe on a never-registered tag. Does NOT close the fd -- the
 * owner does, and only after this, or a still-armed epoll entry can outlive
 * the descriptor number and fire for whatever reuses it. */
int devd_loop_remove_io(Devd *d, struct devd_epoll_tag *tag);

/* The loop. Blocks until objective != DEVD_RUNNING. 0 or -errno. */
int devd_loop_run(Devd *d);

/* SIGTERM/SIGINT -> DEVD_EXIT; anything else logged and ignored. There is no
 * SIGHUP verb: devd has no configuration to reload, and the resync a reload
 * would mean is what the coldplug walk already is. 0 or -errno. */
int devd_loop_dispatch_signal(Devd *d, int signo);

const char *devd_epoll_source_to_string(DevdEpollSource s);
