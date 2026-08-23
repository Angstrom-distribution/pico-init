/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * cgroups v2 supervision. Written fresh rather than quarried: the ~2011
 * systemd this project quarries elsewhere is cgroup-v1 only, and v1's
 * release-agent notification is unreliable enough that a whole PID-set
 * tracker exists upstream to work around it. v2's cgroup.events makes all of
 * that unnecessary, so the v1 code was studied and then not used.
 *
 * Three things here are load-bearing and easy to get wrong:
 *  - cgroup.kill takes "1", not "all". "all" is rejected with EIO.
 *  - cgroup.kill only exists on Linux >= 5.14, so its absence must be
 *    survivable rather than fatal.
 *  - "empty" is the `populated` field of cgroup.events, which is recursive;
 *    reading cgroup.procs is not, and reports empty for a cgroup whose
 *    children still hold processes.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cgroups-v2.h"
#include "util.h"

/*
 * How many read-and-SIGKILL passes the fallback makes before giving up. A
 * process forking as it is killed can be missed on one pass, which is why
 * this loops at all; the bound is what stops a pathological forker from
 * hanging the manager forever.
 */
#define CGROUP_KILL_FALLBACK_PASSES 16

/*
 * How many already-signalled pids the fallback remembers, so it can tell a
 * zombie it has killed from a process that appeared since. A fixed array
 * rather than a growing one on purpose: this runs on a stop path that may
 * already be failing, and an allocation there is exactly what should not be
 * needed. Overflowing it merely costs a redundant SIGKILL to a dead pid.
 */
#define CGROUP_KILL_MAX_TRACKED 256

static int write_all(int fd, const char *s) {
        size_t len = strlen(s);
        size_t off = 0;

        if (fd < 0)
                return -EBADF;

        while (off < len) {
                ssize_t n = write(fd, s + off, len - off);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                off += (size_t) n;
        }

        return 0;
}

static int open_ctrl_file(const char *dir, const char *name, int flags) {
        char path[PATH_MAX];
        int fd;
        int n;

        n = snprintf(path, sizeof(path), "%s/%s", dir, name);
        if (n < 0 || (size_t) n >= sizeof(path))
                return -ENAMETOOLONG;

        fd = open(path, flags | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return fd;
}

int cgroup_v2_new(const char *path, struct pico_cgroup **ret) {
        struct pico_cgroup *cg;
        int r;

        if (!path || !ret)
                return -EINVAL;

        /* No real cgroupfs (test/CI): mkdir fails ENOENT/EACCES/EROFS, propagate cleanly. */
        if (mkdir(path, 0755) < 0 && errno != EEXIST)
                return -errno;

        cg = calloc(1, sizeof(*cg));
        if (!cg)
                return -ENOMEM;

        /* calloc() zero-inits epoll_tag.source to PICO_EPOLL_SIGNAL (enum
         * value 0) -- set it explicitly so an un-monitored cgroup can never
         * be mistaken for one if its pointer ever ends up read as a tag. */
        cg->epoll_tag.source = PICO_EPOLL_CGROUP;
        cg->epoll_tag.fd = -1;
        cg->procs_fd = cg->events_fd = cg->kill_fd = cg->events_efd = -1;

        cg->path = pico_strdup(path);
        if (!cg->path) {
                free(cg);
                return -ENOMEM;
        }

        /* O_RDWR: the fallback kill path has to read cgroup.procs, and
         * reopening it mid-kill would be one more failure mode. */
        cg->procs_fd = open_ctrl_file(path, "cgroup.procs", O_RDWR);
        if (cg->procs_fd < 0) {
                r = cg->procs_fd;
                goto fail;
        }

        cg->events_fd = open_ctrl_file(path, "cgroup.events", O_RDONLY);
        if (cg->events_fd < 0) {
                r = cg->events_fd;
                goto fail;
        }

        /*
         * Deliberately NOT fatal. cgroup.kill arrived in Linux 5.14, and the
         * kernels least likely to have it are exactly the old ARM vendor
         * kernels this project targets. Failing cgroup creation here would
         * mean every service fails to start on precisely those boards --
         * while the SIGKILL fallback below exists specifically to serve them.
         */
        cg->kill_fd = open_ctrl_file(path, "cgroup.kill", O_WRONLY);
        if (cg->kill_fd < 0) {
                pico_log(PICO_LOG_DEBUG,
                         "%s: no cgroup.kill (%s), using the SIGKILL fallback",
                         path,
                         strerror(-cg->kill_fd));
                cg->kill_fd = -1;
        }

        *ret = cg;
        return 0;

fail:
        cgroup_v2_free(cg);
        return r;
}

int cgroup_v2_add_process(struct pico_cgroup *cg, pid_t pid) {
        char buf[32];

        if (!cg)
                return -EINVAL;

        snprintf(buf, sizeof(buf), "%lld", (long long) pid);

        return write_all(cg->procs_fd, buf);
}

int cgroup_v2_monitor(struct pico_cgroup *cg, int epoll_fd) {
        struct epoll_event ev = { 0 };

        if (!cg)
                return -EINVAL;

        cg->epoll_tag.fd = cg->events_fd;

        /* EPOLLPRI, not EPOLLIN: cgroup.events signals a change through the
         * exceptional-condition path, the same way sysfs attributes do. */
        ev.events = EPOLLPRI;
        ev.data.ptr = &cg->epoll_tag; /* first member of *cg, so dispatch casts it straight back */

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, cg->events_fd, &ev) < 0)
                return -errno;

        cg->events_efd = cg->events_fd;

        /*
         * Arm, then poll once. EPOLLPRI fires on a *transition*, so a cgroup
         * that went empty in the window between opening cgroup.events and the
         * epoll_ctl() above produces no wakeup -- ever. Reading emptiness once
         * here, unconditionally, is the only thing that catches it; without
         * this the supervisor waits forever for an edge that already happened.
         * (systemd rediscovered this same bug three separate times:
         * 3a11183858, a5a8776ae5, 869f52f218.)
         */
        return cgroup_v2_is_empty(cg);
}

bool cgroup_v2_kill_is_atomic(struct pico_cgroup *cg) {
        return cg && cg->kill_fd >= 0;
}

/* Has this pid already been signalled in an earlier pass? */
static bool pid_seen(const pid_t *seen, size_t n_seen, pid_t pid) {
        size_t i;

        for (i = 0; i < n_seen; i++)
                if (seen[i] == pid)
                        return true;

        return false;
}

/*
 * Read every pid out of cgroup.procs and SIGKILL any not signalled before.
 * Returns the number of *newly* signalled pids, or -errno.
 *
 * Counting only new pids is what lets the caller terminate. A SIGKILLed
 * process remains a member of the cgroup as a zombie until its parent reaps
 * it, so cgroup.procs keeps listing it and "loop until empty" would never
 * finish -- the reap happens in the manager's SIGCHLD handler, which cannot
 * run while this loop is spinning. Once a pass finds nothing new, every member
 * has been signalled and there is nothing further this function can do.
 */
static int cgroup_v2_kill_one_pass(struct pico_cgroup *cg, pid_t *seen, size_t *n_seen, size_t max_seen) {
        char buf[4096];
        ssize_t n;
        int killed = 0;
        off_t off = 0;

        for (;;) {
                char *line;
                char *saveptr = NULL;
                char *nl;

                n = pread(cg->procs_fd, buf, sizeof(buf) - 1, off);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        /* the cgroup went away underneath us: nothing left to kill */
                        if (errno == ENOENT || errno == ENODEV)
                                return killed;
                        return -errno;
                }
                if (n == 0)
                        return killed;

                buf[n] = '\0';

                /*
                 * Only consume up to the last complete line, and resume the
                 * next pread from there -- a pid split across two reads would
                 * otherwise be parsed as two wrong pids, and killing a wrong
                 * pid from PID 1 is not a recoverable mistake.
                 */
                nl = strrchr(buf, '\n');
                if (!nl)
                        return killed; /* partial line with no newline: give up this pass */

                nl[1] = '\0';
                off += (off_t) (nl - buf) + 1;

                for (line = strtok_r(buf, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
                        long long pid;
                        char *end;

                        errno = 0;
                        pid = strtoll(line, &end, 10);
                        if (errno != 0 || end == line || *end != '\0')
                                continue;

                        /* never signal ourselves, init, or the whole process group */
                        if (pid <= 1 || (pid_t) pid == getpid())
                                continue;

                        /* already signalled on an earlier pass; it is a zombie
                         * awaiting reaping, not something still to kill */
                        if (pid_seen(seen, *n_seen, (pid_t) pid))
                                continue;

                        if (*n_seen < max_seen)
                                seen[(*n_seen)++] = (pid_t) pid;

                        if (kill((pid_t) pid, SIGKILL) == 0)
                                killed++;
                        else if (errno != ESRCH)
                                pico_log(PICO_LOG_WARNING, "%s: kill(%lld): %s", cg->path, pid, strerror(errno));
                }
        }
}

int cgroup_v2_kill(struct pico_cgroup *cg) {
        pid_t seen[CGROUP_KILL_MAX_TRACKED];
        size_t n_seen = 0;
        int pass;

        if (!cg)
                return -EINVAL;

        /*
         * Fast path. The value is "1" -- cgroup.kill takes a boolean, and
         * "all" is rejected with EIO. (An earlier draft of this project's own
         * design document said "all"; it was wrong, and writing it fails
         * against a real kernel every time.)
         */
        if (cg->kill_fd >= 0)
                return write_all(cg->kill_fd, "1");

        /*
         * Fallback for kernels older than 5.14. This is what cgroup-v1
         * supervisors always did, and it is not atomic: a process forking as
         * it is killed can appear only after the pass that would have caught
         * it, hence the repeat.
         *
         * The loop ends when a pass finds no pid it has not already signalled
         * -- NOT when the cgroup reads empty. Waiting for empty would never
         * terminate: a SIGKILLed process stays a cgroup member as a zombie
         * until reaped, and the reap happens in the manager's SIGCHLD handler,
         * which cannot run while this loop is spinning. The contract matches
         * the atomic path above, which also only delivers the kill rather than
         * waiting for the members to be gone.
         */
        for (pass = 0; pass < CGROUP_KILL_FALLBACK_PASSES; pass++) {
                int r;

                r = cgroup_v2_kill_one_pass(cg, seen, &n_seen, CGROUP_KILL_MAX_TRACKED);
                if (r < 0)
                        return r;

                if (r == 0)
                        return 0; /* nothing new to signal: everything has been killed */
        }

        pico_log(PICO_LOG_WARNING,
                 "%s: new processes still appearing after %d SIGKILL passes, giving up",
                 cg->path,
                 CGROUP_KILL_FALLBACK_PASSES);

        return -EBUSY;
}

int cgroup_v2_is_empty(struct pico_cgroup *cg) {
        char buf[128];
        ssize_t n;

        if (!cg)
                return -EINVAL;

        if (cg->events_fd < 0)
                return 1; /* nothing to be populated */

        for (;;) {
                n = pread(cg->events_fd, buf, sizeof(buf) - 1, 0);
                if (n >= 0)
                        break;
                if (errno == EINTR)
                        continue;

                /*
                 * ENOENT means the cgroup directory is gone, which means it is
                 * empty -- not an error. This is reached routinely: the normal
                 * sequence after a stop timeout is kill, cgroup removed, then
                 * a late emptiness check.
                 */
                if (errno == ENOENT || errno == ENODEV)
                        return 1;

                return -errno;
        }

        buf[n] = '\0';

        /*
         * The `populated` field, not cgroup.procs: populated is recursive and
         * accounts for descendant cgroups, while reading cgroup.procs reports
         * empty for a cgroup whose children still hold processes.
         */
        if (strstr(buf, "populated 0"))
                return 1;
        if (strstr(buf, "populated 1"))
                return 0;

        return -EINVAL;
}

struct pico_cgroup *cgroup_v2_free(struct pico_cgroup *cg) {
        if (!cg)
                return NULL;

        if (cg->procs_fd >= 0)
                close(cg->procs_fd);
        if (cg->events_fd >= 0)
                close(cg->events_fd);
        if (cg->kill_fd >= 0)
                close(cg->kill_fd);

        if (cg->path) {
                /*
                 * Best-effort. A still-populated cgroup fails EBUSY, and the
                 * directory is then orphaned -- which is why the caller should
                 * only free once the empty event has arrived. Logged rather
                 * than silently swallowed so a leaked cgroup is findable.
                 */
                if (rmdir(cg->path) < 0 && errno != ENOENT)
                        pico_log(PICO_LOG_DEBUG, "%s: rmdir: %s", cg->path, strerror(errno));

                free(cg->path);
        }

        free(cg);
        return NULL;
}
