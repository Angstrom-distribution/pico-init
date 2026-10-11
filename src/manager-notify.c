/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * See manager-notify.h for the contract. This is the real body: bind, one
 * datagram per dispatch (recvmsg() re-polls at zero timeout while more are
 * queued -- manager-loop.c's own re-poll rule), attribute via SO_PASSCRED +
 * manager_get_unit_by_pid(), apply recognized keys.
 *
 * Not adopted from real systemd's manager_setup_notify(), each with a reason:
 * fd_increase_rxbuf(fd, 8*U64_MB), because SO_RCVBUF does not change the queue
 * depth of an AF_UNIX SOCK_DGRAM socket (net.unix.max_dgram_qlen does);
 * SO_PASSPIDFD, because upstream marks it a TODO pending a kernel baseline,
 * and pico attributes by plain pid_t everywhere (SIGCHLD,
 * manager_get_unit_by_pid()), so half-adopting pidfds would be false hardening.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "manager-notify.h"
#include "manager-state.h"
#include "manager.h"
#include "sd-event.h"
#include "service.h"
#include "unit.h"
#include "util.h"

/* Upstream NOTIFY_BUFFER_MAX == PIPE_BUF; matched here for the same reason
 * upstream picked it (the guaranteed atomic pipe-write size, a natural cap
 * on one legitimate sd_notify() payload). */
#define PICO_NOTIFY_BUFFER_MAX 4096

/* SCM_RIGHTS fds this listener will ever collect from one datagram --
 * generous for BARRIER=1's single pipe-write end; anything beyond this is
 * still received (the kernel does not truncate SCM_RIGHTS short of its own
 * control-buffer size) but not tracked past PICO_NOTIFY_FD_MAX. */
#define PICO_NOTIFY_FD_MAX 8

/* Upstream caps STATUS_TEXT_MAX the same way: bounded, not because a longer
 * status is meaningful, but because this is attacker-influenced data from a
 * world-writable socket. */
#define PICO_NOTIFY_STATUS_MAX 128

struct pico_manager_notify {
        sd_event_source *source;
        char *socket_path; /* owned, unlinked at teardown */
        size_t n_unattributed;
};

/*
 * Apply every recognized KEY=VALUE line in `buf` (mutated in place by
 * strtok_r(), already NUL-terminated by the caller) to `u`, a unit whose
 * ucred-attributed sender is `ucred`. Republishes u's state file iff
 * anything actually changed. `m` is currently unused inside the loop
 * itself but kept in the signature: a future push/broadcast hook attaches
 * right here, after a validated event has already been applied to state,
 * and will need it to reach the Manager's subscriber list.
 *
 * Every key not handled below (WATCHDOG*, STOPPING=1, RELOADING=1 excepted,
 * which are diagnosable-but-inert) is silently skipped -- see
 * manager-notify.h's list of what is not implemented; an unknown or
 * unimplemented key must never be an error, matching real systemd's own forward-compatible parser.
 */
static void notify_apply(Manager *m, Unit *u, const struct ucred *ucred, char *buf, size_t len) {
        Service *s;
        bool changed = false;
        bool from_main;
        char *line, *save = NULL;

        (void) m;
        (void) len; /* buf is already NUL-terminated; kept for a future broadcast hook */

        if (u->type != UNIT_SERVICE)
                return;
        s = SERVICE(u);

        /* Decided once, before any MAINPID= in this same datagram can move
         * the goalposts -- upstream gates access on the sender the same
         * way, up front. NotifyAccess= is not built; this is its =main
         * default, upstream's own for Type=notify. */
        from_main = s->main_pid > 0 && ucred->pid == s->main_pid;

        for (line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
                if (strcmp(line, "READY=1") == 0) {
                        s->notify_ready = true;
                        changed = true;
                        /* The one key that drives the state machine: a
                         * Type=notify start completes here, nowhere else.
                         * A no-op for other types and states (service.c). */
                        if (from_main)
                                service_notify_ready(s);
                } else if (strncmp(line, "STATUS=", 7) == 0) {
                        const char *val = line + 7;
                        size_t vlen = strlen(val);
                        bool bad = false;
                        char *dup;
                        size_t i;

                        /* A raw control character (esp. '\n', already split
                         * out here, but '\r' and friends are not) would
                         * inject a fake Property=value line into the
                         * published state file -- this matters, not
                         * cosmetic. */
                        for (i = 0; i < vlen; i++)
                                if ((unsigned char) val[i] < 0x20 || val[i] == 0x7f) {
                                        bad = true;
                                        break;
                                }

                        if (bad) {
                                pico_log(PICO_LOG_DEBUG, "%s: STATUS= has a control character, dropping", u->id);
                                continue;
                        }

                        if (vlen > PICO_NOTIFY_STATUS_MAX)
                                vlen = PICO_NOTIFY_STATUS_MAX;

                        dup = malloc(vlen + 1);
                        if (!dup) {
                                pico_log(PICO_LOG_WARNING, "%s: STATUS=: out of memory", u->id);
                                continue;
                        }
                        memcpy(dup, val, vlen);
                        dup[vlen] = '\0';

                        s->status_text = pico_mfree(s->status_text);
                        s->status_text = dup;
                        changed = true;
                } else if (strncmp(line, "ERRNO=", 6) == 0) {
                        char *end;
                        long v = strtol(line + 6, &end, 10);

                        if (end != line + 6 && *end == '\0' && v > 0 && v <= INT_MAX) {
                                s->status_errno = (int) v;
                                changed = true;
                        }
                } else if (strncmp(line, "MAINPID=", 8) == 0) {
                        /*
                         * Gated on ucred->uid == 0 rather than upstream's
                         * cgroup-membership check (service_is_suitable_
                         * main_pid(), src/core/service.c): every pico
                         * service runs as root, so this check is only correct
                         * while there are no user services.
                         */
                        if (ucred->uid == 0) {
                                char *end;
                                long v = strtol(line + 8, &end, 10);

                                if (end != line + 8 && *end == '\0' && v > 0) {
                                        s->main_pid = (pid_t) v;
                                        changed = true;
                                }
                        }
                } else if (strcmp(line, "BARRIER=1") == 0) {
                        /* No state to apply -- the ack is the caller's
                         * unconditional close() of the fd this arrived
                         * with (sd_notify_barrier() blocks on its POLLHUP). */
                } else if (strcmp(line, "STOPPING=1") == 0) {
                        pico_log(PICO_LOG_INFO, "%s: STOPPING=1 (no stop-by-notify path yet)", u->id);
                } else if (strcmp(line, "RELOADING=1") == 0) {
                        pico_log(PICO_LOG_INFO, "%s: RELOADING=1 (no reload machinery yet)", u->id);
                } else if (strncmp(line, "WATCHDOG", 8) == 0) {
                        /* Covers WATCHDOG=1/WATCHDOG=trigger and
                         * WATCHDOG_USEC= alike: no watchdog machinery
                         * exists to act on any of them yet. */
                        pico_log(PICO_LOG_DEBUG, "%s: %s (no watchdog machinery yet)", u->id, line);
                }
                /* every other key: silently skipped, see this function's header */
        }

        if (changed)
                manager_state_notify_unit(u);
}

/*
 * The listener's io callback (EVENT_PRIORITY_NOTIFY). CALLBACK CONTRACT
 * (manager-loop.c's header): every path returns 0 except a hard recvmsg()
 * errno, where the source is disabled and the error logged, never a
 * silent < 0 propagation.
 */
static int notify_io_cb(sd_event_source *es, int fd, uint32_t revents, void *userdata) {
        Manager *m = userdata;
        char buf[PICO_NOTIFY_BUFFER_MAX + 1];
        union {
                char buf[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(sizeof(int) * PICO_NOTIFY_FD_MAX)];
                struct cmsghdr align;
        } control;
        struct iovec iov;
        struct msghdr msghdr;
        struct cmsghdr *cmsg;
        struct ucred ucred;
        bool have_ucred = false;
        int recv_fds[PICO_NOTIFY_FD_MAX];
        unsigned n_recv_fds = 0, i;
        ssize_t n;
        Unit *u;

        (void) revents;

        iov.iov_base = buf;
        iov.iov_len = PICO_NOTIFY_BUFFER_MAX;

        memset(&msghdr, 0, sizeof(msghdr));
        msghdr.msg_iov = &iov;
        msghdr.msg_iovlen = 1;
        msghdr.msg_control = control.buf;
        msghdr.msg_controllen = sizeof(control.buf);

        n = recvmsg(fd, &msghdr, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
        if (n < 0) {
                if (errno == EAGAIN || errno == EINTR)
                        return 0;

                /* Disable explicitly: "this source must
                 * never fire again" beats propagating < 0 and having the
                 * shim disable it silently (manager-loop.c's own contract). */
                pico_log(PICO_LOG_ERR, "notify socket recvmsg: %s, disabling the listener", strerror(errno));
                sd_event_source_set_enabled(es, SD_EVENT_OFF);
                return 0;
        }

        /* Collect every SCM_RIGHTS fd and the one SCM_CREDENTIALS block
         * before deciding anything -- a malformed cmsg_len is treated as
         * absent credentials, not trusted. */
        for (cmsg = CMSG_FIRSTHDR(&msghdr); cmsg; cmsg = CMSG_NXTHDR(&msghdr, cmsg)) {
                if (cmsg->cmsg_level != SOL_SOCKET)
                        continue;

                if (cmsg->cmsg_type == SCM_RIGHTS) {
                        unsigned n_fds = (unsigned) ((cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int));
                        const int *fds = (const int *) CMSG_DATA(cmsg);

                        for (i = 0; i < n_fds && n_recv_fds < PICO_NOTIFY_FD_MAX; i++)
                                recv_fds[n_recv_fds++] = fds[i];
                } else if (cmsg->cmsg_type == SCM_CREDENTIALS &&
                           cmsg->cmsg_len == CMSG_LEN(sizeof(struct ucred))) {
                        memcpy(&ucred, CMSG_DATA(cmsg), sizeof(ucred));
                        have_ucred = true;
                }
        }

        /* Every fd that arrived is closed unconditionally, whichever way
         * this datagram ends up handled: pico has no fd store, and this
         * close IS the BARRIER=1 ack (sd_notify_barrier() blocks on its
         * own pipe's POLLHUP). */
        for (i = 0; i < n_recv_fds; i++)
                close(recv_fds[i]);

        if (msghdr.msg_flags & MSG_TRUNC) {
                pico_log(PICO_LOG_WARNING, "notify: oversized datagram, dropping");
                return 0;
        }
        if (msghdr.msg_flags & MSG_CTRUNC) {
                pico_log(PICO_LOG_WARNING, "notify: truncated control data, dropping");
                return 0;
        }

        if (!have_ucred || ucred.pid <= 0) {
                pico_log(PICO_LOG_DEBUG, "notify: datagram lacking valid credentials, dropping");
                return 0;
        }

        if (n == 0) {
                pico_log(PICO_LOG_DEBUG, "notify: empty datagram from pid %d, dropping", (int) ucred.pid);
                return 0;
        }

        if (memchr(buf, '\0', (size_t) n)) {
                pico_log(PICO_LOG_DEBUG,
                         "notify: embedded NUL in datagram from pid %d, dropping",
                         (int) ucred.pid);
                return 0;
        }

        buf[n] = '\0';

        u = manager_get_unit_by_pid(m, ucred.pid);
        if (!u) {
                /* As PID 1 we inherit every orphan on the system, so a
                 * stray sender (or one mid-shutdown) is the common case,
                 * not an error -- debug, not warning. */
                m->notify->n_unattributed++;
                pico_log(PICO_LOG_DEBUG, "notify: no unit owns pid %d, ignoring", (int) ucred.pid);
                return 0;
        }

        notify_apply(m, u, &ucred, buf, (size_t) n);
        return 0;
}

int manager_notify_setup(Manager *m) {
        struct pico_manager_notify *nt;
        struct sockaddr_un addr;
        char path[PATH_MAX];
        struct stat st;
        mode_t old_mask;
        int fd, n, r, passcred;

        if (!m || !m->runtime_dir)
                return -EINVAL;

        if (mkdir(m->runtime_dir, 0755) < 0 && errno != EEXIST)
                return -errno;

        n = snprintf(path, sizeof(path), "%s/notify", m->runtime_dir);
        if (n < 0 || (size_t) n >= sizeof(path))
                return -ENAMETOOLONG;

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        if (strlen(path) >= sizeof(addr.sun_path))
                return -ENAMETOOLONG;
        memcpy(addr.sun_path, path, strlen(path) + 1);

        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
        if (fd < 0)
                return -errno;

        /* Stale-socket hygiene, matching manager-ctrl.c's own bind-time
         * unlink: the only legitimate occupant is a previous PID 1 that
         * exited without cleanup. */
        if (stat(path, &st) == 0 && S_ISSOCK(st.st_mode))
                unlink(path);

        /* Umask sandwich, not a chmod() after -- manager-ctrl.c's own
         * reasoning: a chmod leaves a window where the socket is live under
         * the ambient umask. 0666 here (0111 mask), unlike
         * control's 0600: every service must be able to sendto(); the
         * kernel-filled SO_PASSCRED below is what stops a sender claiming a
         * foreign pid, not this socket's permissions. */
        old_mask = umask(0111);
        r = bind(fd, (struct sockaddr *) &addr, sizeof(addr));
        umask(old_mask);
        if (r < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        /* Mandatory, not best-effort: attribution is the whole point of
         * this listener, and one that cannot attribute is worse than none. */
        passcred = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &passcred, sizeof(passcred)) < 0) {
                r = -errno;
                close(fd);
                unlink(path);
                return r;
        }

        nt = calloc(1, sizeof(*nt));
        if (!nt) {
                close(fd);
                unlink(path);
                return -ENOMEM;
        }

        nt->socket_path = pico_strdup(path);
        if (!nt->socket_path) {
                free(nt);
                close(fd);
                unlink(path);
                return -ENOMEM;
        }

        r = sd_event_add_io(m->event, &nt->source, fd, EPOLLIN, notify_io_cb, m);
        if (r < 0) {
                pico_mfree(nt->socket_path);
                free(nt);
                close(fd);
                unlink(path);
                return r;
        }
        sd_event_source_set_priority(nt->source, EVENT_PRIORITY_NOTIFY);
        sd_event_source_set_io_fd_own(nt->source, 1); /* DEL+close ride this source's teardown */

        m->notify = nt;
        return 0;
}

void manager_notify_done(Manager *m) {
        struct pico_manager_notify *nt;

        if (!m || !m->notify)
                return;

        nt = m->notify;

        nt->source = sd_event_source_disable_unref(nt->source);

        if (nt->socket_path)
                unlink(nt->socket_path);

        pico_mfree(nt->socket_path);
        free(nt);
        m->notify = NULL;
}

const char *manager_notify_socket_path(Manager *m) {
        if (!m || !m->notify)
                return NULL;

        return m->notify->socket_path;
}

size_t manager_notify_debug_n_unattributed(Manager *m) {
        if (!m || !m->notify)
                return 0;

        return m->notify->n_unattributed;
}
