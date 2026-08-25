/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * devd's event loop: one epoll fd multiplexing the shared signalfd, the shared
 * timerfd (which is what closes a settle window) and the group-1 uevent socket.
 *
 * This is netd-loop.c's registration pattern copied deliberately rather than
 * reinvented, and the copy is the point: the daemon decision in plans/31 (Part
 * 2, "What is already decided") makes devd a second instance of a shape this
 * project has already proven, not a first instance of a new one. Registrations
 * carry their own callback in the tag, dispatch always reads data.ptr back, and
 * `registered` -- never `fd >= 0` -- is what says a tag is live, for the reason
 * netd-loop.h spells out at length: every tag lives inside a calloc()'d owner,
 * so fd == 0 is a perfectly valid descriptor and only the bool is reliably
 * zero.
 *
 * devd has three fixed sources where netd has dynamic ones, so a switch would
 * have done. The callback stays anyway: H2's rule engine adds an async RUN+=
 * child-reaping source to this loop, and it should be able to do that without
 * editing a dispatch switch in this file.
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
