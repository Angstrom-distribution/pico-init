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

#include <dirent.h>
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
#include "sd-event.h"
#include "util.h"

/*
 * Mirrors manager.h's EVENT_PRIORITY_CGROUP_EVENTS. Not pulled in from
 * manager.h itself: that header pulls in unit.h via job.h, and this layer
 * must stay unaware of Unit/Manager (struct pico_cgroup's own comment says
 * why). A stale mismatch between the two would only ever change relative
 * dispatch order within one epoll batch, never correctness on its own.
 */
#define CGROUP_EVENTS_PRIORITY (-10)

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

/* Contents of <dir>/<name> into buf, NUL-terminated. Length, or -errno. */
static int read_ctrl_file(const char *dir, const char *name, char *buf, size_t size) {
        ssize_t n;
        int fd;

        fd = open_ctrl_file(dir, name, O_RDONLY);
        if (fd < 0)
                return fd;

        n = read(fd, buf, size - 1);
        close(fd);
        if (n < 0)
                return -errno;

        buf[n] = '\0';
        return (int) n;
}

/* One write(2) of `text` to <dir>/<name>, no truncate and no append: the way cgroup files are written. */
static int write_ctrl_file(const char *dir, const char *name, const char *text) {
        size_t len = strlen(text);
        ssize_t n;
        int fd, r = 0;

        fd = open_ctrl_file(dir, name, O_WRONLY);
        if (fd < 0)
                return fd;

        n = write(fd, text, len);
        if (n < 0)
                r = -errno;
        else if ((size_t) n != len)
                r = -EIO;

        close(fd);
        return r;
}

/* True when `word` is one of the space or newline separated words of `list`. */
static bool list_has_word(const char *list, const char *word) {
        size_t len = strlen(word);
        const char *p = list;

        while (*p) {
                size_t n = strcspn(p, " \t\n");

                if (n == len && strncmp(p, word, len) == 0)
                        return true;
                p += n;
                p += strspn(p, " \t\n");
        }
        return false;
}

int cgroup_v2_enable_controllers(const char *dir, const char *wanted, int *ret_errno) {
        char offered[256], enabled[256];
        const char *p;
        int done = 0, first_errno = 0, r;

        if (ret_errno)
                *ret_errno = 0;
        if (!dir || !wanted)
                return -EINVAL;

        r = read_ctrl_file(dir, "cgroup.controllers", offered, sizeof(offered));
        if (r < 0)
                return r;
        r = read_ctrl_file(dir, "cgroup.subtree_control", enabled, sizeof(enabled));
        if (r < 0)
                return r;

        for (p = wanted; *p;) {
                char word[32], cmd[sizeof(word) + 1];
                size_t n;

                p += strspn(p, " ");
                n = strcspn(p, " ");
                if (n == 0)
                        break;
                if (n >= sizeof(word)) {
                        p += n;
                        continue;
                }
                memcpy(word, p, n);
                word[n] = '\0';
                p += n;

                if (!list_has_word(offered, word) || list_has_word(enabled, word))
                        continue;

                snprintf(cmd, sizeof(cmd), "+%s", word);
                r = write_ctrl_file(dir, "cgroup.subtree_control", cmd);
                if (r < 0) {
                        pico_log(PICO_LOG_DEBUG, "%s: enabling %s: %s", dir, word, strerror(-r));
                        if (first_errno == 0)
                                first_errno = -r;
                        continue;
                }
                done++;
        }

        if (ret_errno)
                *ret_errno = first_errno;
        return done;
}

int cgroup_v2_disable_controllers(const char *dir, int *ret_errno) {
        char enabled[256];
        const char *p;
        int done = 0, first_errno = 0, r;

        if (ret_errno)
                *ret_errno = 0;
        if (!dir)
                return -EINVAL;

        r = read_ctrl_file(dir, "cgroup.subtree_control", enabled, sizeof(enabled));
        if (r < 0)
                return r;

        for (p = enabled; *p;) {
                char word[32], cmd[sizeof(word) + 1];
                size_t n;

                p += strspn(p, " \t\n");
                n = strcspn(p, " \t\n");
                if (n == 0)
                        break;
                if (n >= sizeof(word)) {
                        p += n;
                        continue;
                }
                memcpy(word, p, n);
                word[n] = '\0';
                p += n;

                snprintf(cmd, sizeof(cmd), "-%s", word);
                r = write_ctrl_file(dir, "cgroup.subtree_control", cmd);
                if (r < 0) {
                        pico_log(PICO_LOG_DEBUG, "%s: disabling %s: %s", dir, word, strerror(-r));
                        if (first_errno == 0)
                                first_errno = -r;
                        continue;
                }
                done++;
        }

        if (ret_errno)
                *ret_errno = first_errno;
        return done;
}

int cgroup_v2_prepare_root(const char *root) {
        char slice[PATH_MAX];
        int n, enabled, err = 0;

        if (!root)
                return -EINVAL;

        n = snprintf(slice, sizeof(slice), "%s/system.slice", root);
        if (n < 0 || (size_t) n >= sizeof(slice))
                return -ENAMETOOLONG;
        if (mkdir(slice, 0755) < 0 && errno != EEXIST)
                return -errno;

        enabled = cgroup_v2_enable_controllers(root, "cpu memory", &err);
        if (enabled > 0)
                pico_log(PICO_LOG_INFO, "cgroup: enabled %d controller(s) for %s", enabled, root);
        if (err)
                pico_log(PICO_LOG_WARNING,
                         "cgroup: cannot enable all controllers in %s: %s",
                         root,
                         strerror(err));

        /* Only useful if the root passed them down: a slice below a root that
         * enables nothing offers nothing, and the call then just returns 0. */
        err = 0;
        enabled = cgroup_v2_enable_controllers(slice, "cpu memory", &err);
        if (enabled > 0)
                pico_log(PICO_LOG_INFO, "cgroup: enabled %d controller(s) for %s", enabled, slice);
        if (err)
                pico_log(PICO_LOG_WARNING,
                         "cgroup: cannot enable all controllers in %s: %s",
                         slice,
                         strerror(err));

        return 0;
}

/* Deepest nesting walked below a cgroup; the kernel's default is unlimited, a real tree is a handful. */
#define CGROUP_PRUNE_MAX_DEPTH 32

static int cgroup_remove_below(const char *path, unsigned depth, bool remove_self) {
        char **names = NULL;
        size_t n_names = 0, i;
        struct dirent *e;
        DIR *d;
        int r = 0;

        if (depth > CGROUP_PRUNE_MAX_DEPTH)
                return -ELOOP;

        d = opendir(path);
        if (!d)
                return errno == ENOENT ? 0 : -errno;

        /* Names first, removal second: unlinking while readdir() runs may skip entries. */
        while ((e = readdir(d)) != NULL) {
                struct stat st;
                char **grown;

                if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                        continue;
                if (fstatat(dirfd(d), e->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0 || !S_ISDIR(st.st_mode))
                        continue;

                grown = realloc(names, (n_names + 1) * sizeof(*names));
                if (!grown) {
                        r = -ENOMEM;
                        break;
                }
                names = grown;
                names[n_names] = pico_strdup(e->d_name);
                if (!names[n_names]) {
                        r = -ENOMEM;
                        break;
                }
                n_names++;
        }
        closedir(d);

        for (i = 0; i < n_names; i++) {
                char child[PATH_MAX];
                int k, n;

                n = snprintf(child, sizeof(child), "%s/%s", path, names[i]);
                if (n < 0 || (size_t) n >= sizeof(child))
                        k = -ENAMETOOLONG;
                else
                        k = cgroup_remove_below(child, depth + 1, true);
                if (k < 0 && r == 0)
                        r = k;
                free(names[i]);
        }
        free(names);

        if (remove_self && rmdir(path) < 0 && errno != ENOENT && r == 0)
                r = -errno;

        return r;
}

int cgroup_v2_prune_children(const char *path) {
        if (!path)
                return -EINVAL;
        return cgroup_remove_below(path, 0, false);
}

int cgroup_v2_remove_tree(const char *path) {
        if (!path)
                return -EINVAL;
        return cgroup_remove_below(path, 0, true);
}

/*
 * A unit cgroup left over from an earlier run: empty, but possibly with child
 * cgroups and controllers enabled for them. Writing a new main pid into it
 * would fail with EBUSY (a cgroup that enables controllers for its children
 * cannot hold processes), so the children go and the controllers are switched
 * off. A cgroup that still has members is not touched.
 */
static void cgroup_reset_stale(const char *path) {
        char events[128];
        int r;

        if (read_ctrl_file(path, "cgroup.events", events, sizeof(events)) < 0 ||
            !strstr(events, "populated 0"))
                return;

        r = cgroup_v2_prune_children(path);
        if (r < 0)
                pico_log(PICO_LOG_DEBUG, "%s: pruning stale children: %s", path, strerror(-r));
        (void) cgroup_v2_disable_controllers(path, NULL);
}

bool cgroup_v2_subgroup_name_valid(const char *name) {
        if (!name || name[0] == '\0' || strlen(name) > 64)
                return false;
        if (name[0] == '.' || name[0] == '_' || strncmp(name, "cgroup.", 7) == 0)
                return false;
        return strchr(name, '/') == NULL;
}

int cgroup_v2_make_subgroup(const char *parent, const char *name, char *buf, size_t size) {
        int n;

        if (!parent || !name || !buf)
                return -EINVAL;

        n = snprintf(buf, size, "%s/%s", parent, name);
        if (n < 0 || (size_t) n >= size)
                return -ENAMETOOLONG;

        if (mkdir(buf, 0755) < 0 && errno != EEXIST)
                return -errno;

        return 0;
}

int cgroup_v2_delegate_to(const char *path, uid_t uid, gid_t gid) {
        static const char * const files[] = { "cgroup.procs", "cgroup.subtree_control", "cgroup.threads" };
        size_t i;

        if (!path)
                return -EINVAL;

        if (chown(path, uid, gid) < 0)
                return -errno;

        for (i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
                char file[PATH_MAX];
                int n = snprintf(file, sizeof(file), "%s/%s", path, files[i]);

                if (n < 0 || (size_t) n >= sizeof(file))
                        return -ENAMETOOLONG;
                if (chown(file, uid, gid) < 0 && errno != ENOENT)
                        return -errno;
        }
        return 0;
}

int cgroup_v2_new(const char *path, struct pico_cgroup **ret) {
        struct pico_cgroup *cg;
        int r;

        if (!path || !ret)
                return -EINVAL;

        /* No real cgroupfs (test/CI): mkdir fails ENOENT/EACCES/EROFS, propagate cleanly. */
        if (mkdir(path, 0755) < 0) {
                if (errno != EEXIST)
                        return -errno;
                cgroup_reset_stale(path);
        }

        cg = calloc(1, sizeof(*cg));
        if (!cg)
                return -ENOMEM;

        cg->procs_fd = cg->events_fd = cg->kill_fd = -1;

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

int cgroup_v2_monitor(struct pico_cgroup *cg, sd_event *e) {
        int r;

        if (!cg || !e)
                return -EINVAL;

        /* EPOLLPRI, not EPOLLIN: cgroup.events signals a change through the
         * exceptional-condition path, the same way sysfs attributes do. */
        r = sd_event_add_io(e, &cg->events_source, cg->events_fd, EPOLLPRI, manager_dispatch_cgroup_events, cg);
        if (r < 0)
                return r;

        sd_event_source_set_priority(cg->events_source, CGROUP_EVENTS_PRIORITY);

        /*
         * Arm, then poll once. EPOLLPRI fires on a *transition*, so a cgroup
         * that went empty in the window between opening cgroup.events and the
         * source registration above produces no wakeup -- ever. Reading
         * emptiness once here, unconditionally, is the only thing that
         * catches it; without this the supervisor waits forever for an edge
         * that already happened. (systemd rediscovered this same bug three
         * separate times: 3a11183858, a5a8776ae5, 869f52f218.)
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
 * Walk cgroup.procs, calling cb for every pid in it. The callback's return
 * value is accumulated (a negative one stops the walk and is returned as
 * is). Returns the sum, or -errno from the read itself.
 *
 * A cgroup that went away underneath us reads as empty, not as an error:
 * every caller here is asking "who is left", and the answer is nobody.
 */
static int cgroup_v2_foreach_pid(struct pico_cgroup *cg, int (*cb)(pid_t pid, void *userdata), void *userdata) {
        char buf[4096];
        ssize_t n;
        int total = 0;
        off_t off = 0;

        if (cg->procs_fd < 0)
                return 0;

        for (;;) {
                char *line;
                char *saveptr = NULL;
                char *nl;

                n = pread(cg->procs_fd, buf, sizeof(buf) - 1, off);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        if (errno == ENOENT || errno == ENODEV)
                                return total;
                        return -errno;
                }
                if (n == 0)
                        return total;

                buf[n] = '\0';

                /*
                 * Only consume up to the last complete line, and resume the
                 * next pread from there -- a pid split across two reads would
                 * otherwise be parsed as two wrong pids, and killing a wrong
                 * pid from PID 1 is not a recoverable mistake.
                 */
                nl = strrchr(buf, '\n');
                if (!nl)
                        return total; /* partial line with no newline: give up this pass */

                nl[1] = '\0';
                off += (off_t) (nl - buf) + 1;

                for (line = strtok_r(buf, "\n", &saveptr); line; line = strtok_r(NULL, "\n", &saveptr)) {
                        long long pid;
                        char *end;
                        int r;

                        errno = 0;
                        pid = strtoll(line, &end, 10);
                        if (errno != 0 || end == line || *end != '\0')
                                continue;

                        /* never report ourselves, init, or the whole process group */
                        if (pid <= 1 || (pid_t) pid == getpid())
                                continue;

                        r = cb((pid_t) pid, userdata);
                        if (r < 0)
                                return r;
                        total += r;
                }
        }
}

struct kill_pass_ctx {
        pid_t *seen;
        size_t *n_seen;
        size_t max_seen;
        const char *path;
};

static int cgroup_v2_kill_pass_cb(pid_t pid, void *userdata) {
        struct kill_pass_ctx *c = userdata;

        /* already signalled on an earlier pass; it is a zombie awaiting
         * reaping, not something still to kill */
        if (pid_seen(c->seen, *c->n_seen, pid))
                return 0;

        if (*c->n_seen < c->max_seen)
                c->seen[(*c->n_seen)++] = pid;

        if (kill(pid, SIGKILL) == 0)
                return 1;
        if (errno != ESRCH)
                pico_log(PICO_LOG_WARNING, "%s: kill(%d): %s", c->path, (int) pid, strerror(errno));
        return 0;
}

/*
 * SIGKILL every pid in cgroup.procs not signalled before. Returns the number
 * of *newly* signalled pids, or -errno.
 *
 * Counting only new pids is what lets the caller terminate. A SIGKILLed
 * process remains a member of the cgroup as a zombie until its parent reaps
 * it, so cgroup.procs keeps listing it and "loop until empty" would never
 * finish -- the reap happens in the manager's SIGCHLD handler, which cannot
 * run while this loop is spinning. Once a pass finds nothing new, every member
 * has been signalled and there is nothing further this function can do.
 */
static int cgroup_v2_kill_one_pass(struct pico_cgroup *cg, pid_t *seen, size_t *n_seen, size_t max_seen) {
        struct kill_pass_ctx c = { .seen = seen, .n_seen = n_seen, .max_seen = max_seen, .path = cg->path };

        return cgroup_v2_foreach_pid(cg, cgroup_v2_kill_pass_cb, &c);
}

struct get_pids_ctx {
        pid_t *pids;
        size_t max;
        size_t n;
};

static int cgroup_v2_get_pids_cb(pid_t pid, void *userdata) {
        struct get_pids_ctx *c = userdata;

        if (c->n < c->max)
                c->pids[c->n] = pid;
        c->n++;
        return 0;
}

int cgroup_v2_get_pids(struct pico_cgroup *cg, pid_t *pids, size_t max, size_t *ret_n) {
        struct get_pids_ctx c = { .pids = pids, .max = max, .n = 0 };
        int r;

        if (!cg || !ret_n || (max > 0 && !pids))
                return -EINVAL;

        r = cgroup_v2_foreach_pid(cg, cgroup_v2_get_pids_cb, &c);
        if (r < 0)
                return r;

        *ret_n = c.n;
        return 0;
}

int cgroup_v2_get_pids_in(const char *dir, pid_t *pids, size_t max, size_t *ret_n) {
        struct pico_cgroup cg = { .procs_fd = -1, .events_fd = -1, .kill_fd = -1 };
        int r;

        if (!dir)
                return -EINVAL;

        cg.procs_fd = open_ctrl_file(dir, "cgroup.procs", O_RDONLY);
        if (cg.procs_fd < 0)
                return cg.procs_fd;

        r = cgroup_v2_get_pids(&cg, pids, max, ret_n);
        close(cg.procs_fd);
        return r;
}

struct signal_ctx {
        int sig;
        const char *path;
};

static int cgroup_v2_signal_cb(pid_t pid, void *userdata) {
        struct signal_ctx *c = userdata;

        if (kill(pid, c->sig) == 0)
                return 1;
        if (errno != ESRCH)
                pico_log(PICO_LOG_WARNING, "%s: kill(%d, %d): %s", c->path, (int) pid, c->sig, strerror(errno));
        return 0;
}

int cgroup_v2_signal(struct pico_cgroup *cg, int sig) {
        struct signal_ctx c = { .sig = sig, .path = cg ? cg->path : NULL };

        if (!cg)
                return -EINVAL;

        return cgroup_v2_foreach_pid(cg, cgroup_v2_signal_cb, &c);
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
        int r;

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
                 * Best-effort. Empty child cgroups a delegated service made
                 * go first (rmdir of a cgroup with children fails EBUSY). A
                 * still-populated cgroup fails EBUSY too, and the directory
                 * is then orphaned -- which is why the caller should only
                 * free once the empty event has arrived. Logged rather than
                 * silently swallowed so a leaked cgroup is findable.
                 */
                r = cgroup_v2_remove_tree(cg->path);
                if (r < 0)
                        pico_log(PICO_LOG_DEBUG, "%s: rmdir: %s", cg->path, strerror(-r));

                free(cg->path);
        }

        free(cg);
        return NULL;
}
