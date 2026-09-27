/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The --clean and --remove halves: deleting what parsed lines say may go.
 *
 * One walker does both, as upstream's dir_cleanup() does: --clean passes
 * the line's age as a cutoff, --remove passes "everything is old enough".
 * Either way the walk honours the same exceptions, and they are the part
 * that keeps a running system intact rather than a detail: an entry that
 * has a line of its own or matches any glob line (x/X among them) is left
 * alone, as are sticky files, device nodes, AF_UNIX sockets something is
 * still listening on, and anything another process holds a BSD lock on.
 * The walk never crosses into another filesystem, is bounded in depth, and
 * puts a directory's own atime/mtime back after deleting from it, so a
 * cleanup never makes a directory look freshly used.
 */

/* O_NOATIME and GLOB_BRACE are glibc extensions (tmpfiles-create.c's note). */
#define _GNU_SOURCE

#include "tmpfiles.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <glob.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../util.h"

#define NSEC_INFINITY UINT64_MAX
#define MAX_DEPTH 256

typedef struct Cleanup {
        PicoTmpfiles *t;
        unsigned operations;

        /* /proc/net/unix, loaded on first need */
        char **unix_sockets;
        bool unix_sockets_loaded;
        bool unix_sockets_failed;
} Cleanup;

static uint64_t timespec_nsec(const struct timespec *ts) {
        return (uint64_t) ts->tv_sec * 1000000000ULL + (uint64_t) ts->tv_nsec;
}

static uint64_t now_realtime_usec(void) {
        struct timespec ts;

        if (clock_gettime(CLOCK_REALTIME, &ts) < 0)
                return 0;
        return (uint64_t) ts.tv_sec * 1000000ULL + (uint64_t) ts.tv_nsec / 1000ULL;
}

/* needs_cleanup(): old enough by every timestamp age-by names. */
static bool needs_cleanup(const struct stat *st, uint64_t cutoff_nsec, const char *path, unsigned age_by) {
        const char *what = S_ISDIR(st->st_mode) ? "directory" : "file";

        if ((age_by & PICO_TMPFILES_AGE_BY_MTIME) && timespec_nsec(&st->st_mtim) >= cutoff_nsec) {
                pico_log(PICO_LOG_DEBUG, "%s \"%s\": modify time is too new", what, path);
                return false;
        }
        if ((age_by & PICO_TMPFILES_AGE_BY_ATIME) && timespec_nsec(&st->st_atim) >= cutoff_nsec) {
                pico_log(PICO_LOG_DEBUG, "%s \"%s\": access time is too new", what, path);
                return false;
        }
        if ((age_by & PICO_TMPFILES_AGE_BY_CTIME) && timespec_nsec(&st->st_ctim) >= cutoff_nsec) {
                pico_log(PICO_LOG_DEBUG, "%s \"%s\": change time is too new", what, path);
                return false;
        }
        /* no birth time from fstatat(): 'b' is upstream's "unknown", never too new */

        return true;
}

/* xopendirat_nomod(): reading a directory to clean it must not refresh its atime. */
static DIR *opendir_nomod(int dfd, const char *name) {
        DIR *d;
        int fd;

        fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NOATIME);
        if (fd < 0 && errno == EPERM)
                fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
                return NULL;

        d = fdopendir(fd);
        if (!d) {
                int e = errno;

                close(fd);
                errno = e;
        }
        return d;
}

static void unix_sockets_load(Cleanup *c) {
        FILE *f;
        char *line = NULL;
        size_t cap = 0;
        bool header = true;

        c->unix_sockets_loaded = true;

        f = fopen("/proc/net/unix", "re");
        if (!f) {
                pico_log(errno == ENOENT ? PICO_LOG_DEBUG : PICO_LOG_WARNING,
                         "failed to open /proc/net/unix, ignoring: %s",
                         strerror(errno));
                c->unix_sockets_failed = true;
                return;
        }

        while (getline(&line, &cap, f) >= 0) {
                char *p;
                size_t n;

                if (header) {
                        header = false;
                        continue;
                }

                /* the path is the eighth column, and the only one starting with '/' */
                p = strchr(line, '/');
                if (!p)
                        continue;
                n = strcspn(p, "\n");
                p[n] = '\0';

                if (pico_strv_extend(&c->unix_sockets, p) < 0) {
                        c->unix_sockets_failed = true;
                        break;
                }
        }

        free(line);
        fclose(f);
}

static bool unix_socket_alive(Cleanup *c, const char *path) {
        char **s;

        if (!c->unix_sockets_loaded)
                unix_sockets_load(c);
        if (c->unix_sockets_failed)
                return true; /* don't know, so assume it is */

        for (s = c->unix_sockets; s && *s; s++)
                if (strcmp(*s, path) == 0)
                        return true;
        return false;
}

/* find_glob(): any glob line's pattern matching the path, x/X included. */
static bool matches_glob_line(const PicoTmpfiles *t, const char *path) {
        size_t k, j;

        for (k = 0; k < t->n_globs; k++)
                for (j = 0; j < t->globs[k]->n_items; j++)
                        if (fnmatch(t->globs[k]->items[j].path, path, FNM_PATHNAME | FNM_PERIOD) == 0)
                                return true;
        return false;
}

static bool has_line_of_its_own(Cleanup *c, const char *path) {
        if (pico_tmpfiles_find(c->t, path)) {
                pico_log(PICO_LOG_DEBUG, "ignoring \"%s\": a separate entry exists", path);
                return true;
        }
        if (matches_glob_line(c->t, path)) {
                pico_log(PICO_LOG_DEBUG, "ignoring \"%s\": a separate glob exists", path);
                return true;
        }
        return false;
}

static bool is_mountpoint_fd(int fd, const struct stat *st) {
        struct stat parent;

        if (fstatat(fd, "..", &parent, 0) < 0)
                return false;
        return parent.st_dev != st->st_dev || parent.st_ino == st->st_ino;
}

/*
 * dir_cleanup(): delete what is old enough below `p`, whose open handle is
 * `d`. The self_* times are `p`'s own from before the walk, restored after
 * it when anything was deleted; NSEC_INFINITY skips that.
 */
static int
                dir_cleanup(Cleanup *c,
                            const char *p,
                            DIR *d,
                            uint64_t self_atime_nsec,
                            uint64_t self_mtime_nsec,
                            uint64_t cutoff_nsec,
                            dev_t rootdev,
                            bool mountpoint,
                            int maxdepth,
                            bool keep_this_level,
                            unsigned age_by_file,
                            unsigned age_by_dir) {
        struct dirent *de;
        bool deleted = false;
        int r = 0;

        while ((de = readdir(d))) {
                char sub_path[PATH_MAX];
                struct stat st;
                int n;

                if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                        continue;

                if (fstatat(dirfd(d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
                        if (errno != ENOENT)
                                pico_log(errno == EACCES ? PICO_LOG_DEBUG : PICO_LOG_ERR,
                                         "stat(%s/%s) failed: %s",
                                         p,
                                         de->d_name,
                                         strerror(errno));
                        continue;
                }

                if (st.st_dev != rootdev) {
                        pico_log(PICO_LOG_DEBUG, "ignoring \"%s/%s\": different mount points", p, de->d_name);
                        continue;
                }

                n = snprintf(sub_path, sizeof(sub_path), "%s/%s", p, de->d_name);
                if (n < 0 || (size_t) n >= sizeof(sub_path)) {
                        pico_log(PICO_LOG_WARNING, "path \"%s/%s\" too long, skipping", p, de->d_name);
                        continue;
                }

                if (has_line_of_its_own(c, sub_path))
                        continue;

                if (S_ISDIR(st.st_mode)) {
                        if (mountpoint && strcmp(de->d_name, "lost+found") == 0 && st.st_uid == 0) {
                                pico_log(PICO_LOG_DEBUG, "ignoring directory \"%s\"", sub_path);
                                continue;
                        }

                        if (maxdepth <= 0)
                                pico_log(PICO_LOG_WARNING, "reached max depth on \"%s\"", sub_path);
                        else {
                                DIR *sub = opendir_nomod(dirfd(d), de->d_name);
                                int q;

                                if (!sub) {
                                        if (errno != ENOENT) {
                                                r = -errno;
                                                pico_log(PICO_LOG_WARNING,
                                                         "opening directory \"%s\" failed, ignoring: %s",
                                                         sub_path,
                                                         strerror(-r));
                                        }
                                        continue;
                                }

                                if (flock(dirfd(sub), LOCK_EX | LOCK_NB) < 0) {
                                        pico_log(PICO_LOG_DEBUG,
                                                 "couldn't acquire exclusive BSD lock on directory \"%s\", skipping",
                                                 sub_path);
                                        closedir(sub);
                                        continue;
                                }

                                q = dir_cleanup(c,
                                                sub_path,
                                                sub,
                                                timespec_nsec(&st.st_atim),
                                                timespec_nsec(&st.st_mtim),
                                                cutoff_nsec,
                                                rootdev,
                                                false,
                                                maxdepth - 1,
                                                false,
                                                age_by_file,
                                                age_by_dir);
                                closedir(sub);
                                if (q < 0)
                                        r = q;
                        }

                        if (keep_this_level) {
                                pico_log(PICO_LOG_DEBUG, "keeping directory \"%s\"", sub_path);
                                continue;
                        }

                        /* the times from before the walk: deleting children changed mtime */
                        if (!needs_cleanup(&st, cutoff_nsec, sub_path, age_by_dir))
                                continue;

                        pico_log(PICO_LOG_DEBUG, "removing directory \"%s\"", sub_path);
                        if (unlinkat(dirfd(d), de->d_name, AT_REMOVEDIR) < 0) {
                                if (errno == ENOTEMPTY)
                                        continue;
                                if (errno != ENOENT) {
                                        r = -errno;
                                        pico_log(PICO_LOG_WARNING,
                                                 "failed to remove directory \"%s\", ignoring: %s",
                                                 sub_path,
                                                 strerror(-r));
                                }
                        }
                        deleted = true;

                } else {
                        int fd;

                        /* upstream's own convention (the XDG_RUNTIME_DIR spec) */
                        if (st.st_mode & S_ISVTX) {
                                pico_log(PICO_LOG_DEBUG, "skipping \"%s\": sticky bit set", sub_path);
                                continue;
                        }

                        if (mountpoint && S_ISREG(st.st_mode) && st.st_uid == 0 &&
                            (strcmp(de->d_name, ".journal") == 0 || strcmp(de->d_name, "aquota.user") == 0 ||
                             strcmp(de->d_name, "aquota.group") == 0)) {
                                pico_log(PICO_LOG_DEBUG, "skipping \"%s\"", sub_path);
                                continue;
                        }

                        if (S_ISSOCK(st.st_mode) && unix_socket_alive(c, sub_path)) {
                                pico_log(PICO_LOG_DEBUG, "skipping \"%s\": live socket", sub_path);
                                continue;
                        }

                        if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode)) {
                                pico_log(PICO_LOG_DEBUG, "skipping \"%s\": a device", sub_path);
                                continue;
                        }

                        if (keep_this_level) {
                                pico_log(PICO_LOG_DEBUG, "keeping \"%s\"", sub_path);
                                continue;
                        }

                        if (!needs_cleanup(&st, cutoff_nsec, sub_path, age_by_file))
                                continue;

                        /* held until after the unlink, so the lock covers it */
                        fd = openat(dirfd(d),
                                    de->d_name,
                                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOATIME | O_NONBLOCK | O_NOCTTY);
                        if (fd < 0 && errno == EPERM)
                                fd = openat(dirfd(d),
                                            de->d_name,
                                            O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY);
                        if (fd < 0 && errno != ENOENT && errno != ELOOP && errno != ENXIO)
                                pico_log(PICO_LOG_WARNING,
                                         "opening file \"%s\" failed, proceeding without lock: %s",
                                         sub_path,
                                         strerror(errno));
                        if (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) < 0 && errno == EWOULDBLOCK) {
                                pico_log(PICO_LOG_DEBUG,
                                         "couldn't acquire exclusive BSD lock on file \"%s\", skipping",
                                         sub_path);
                                close(fd);
                                continue;
                        }

                        pico_log(PICO_LOG_DEBUG, "removing \"%s\"", sub_path);
                        if (unlinkat(dirfd(d), de->d_name, 0) < 0 && errno != ENOENT) {
                                r = -errno;
                                pico_log(PICO_LOG_WARNING,
                                         "failed to remove \"%s\", ignoring: %s",
                                         sub_path,
                                         strerror(-r));
                        }
                        if (fd >= 0)
                                close(fd);
                        deleted = true;
                }
        }

        if (deleted && (self_atime_nsec != NSEC_INFINITY || self_mtime_nsec != NSEC_INFINITY)) {
                struct timespec ts[2] = {
                        { .tv_nsec = UTIME_OMIT },
                        { .tv_nsec = UTIME_OMIT },
                };

                if (self_atime_nsec != NSEC_INFINITY) {
                        ts[0].tv_sec = (time_t) (self_atime_nsec / 1000000000ULL);
                        ts[0].tv_nsec = (long) (self_atime_nsec % 1000000000ULL);
                }
                if (self_mtime_nsec != NSEC_INFINITY) {
                        ts[1].tv_sec = (time_t) (self_mtime_nsec / 1000000000ULL);
                        ts[1].tv_nsec = (long) (self_mtime_nsec % 1000000000ULL);
                }
                if (futimens(dirfd(d), ts) < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "failed to revert timestamps of '%s', ignoring: %s",
                                 p,
                                 strerror(errno));
        }

        return r;
}

/* opendir_and_stat(): 1 with *ret open, 0 when missing or not a directory. */
static int opendir_and_stat(const char *path, DIR **ret, struct stat *st, bool *mountpoint) {
        DIR *d;
        int r;

        d = opendir_nomod(AT_FDCWD, path);
        if (!d) {
                if (errno == ENOENT || errno == ENOTDIR || errno == ELOOP) {
                        pico_log(PICO_LOG_DEBUG, "failed to open directory %s: %s", path, strerror(errno));
                        return 0;
                }
                r = -errno;
                pico_log(PICO_LOG_ERR, "failed to open directory %s: %s", path, strerror(-r));
                return r;
        }

        if (fstat(dirfd(d), st) < 0) {
                r = -errno;
                pico_log(PICO_LOG_ERR, "stat(%s) failed: %s", path, strerror(-r));
                closedir(d);
                return r;
        }

        *mountpoint = is_mountpoint_fd(dirfd(d), st);
        *ret = d;
        return 1;
}

/* --- --remove ------------------------------------------------------------ */

static int remove_recursive(Cleanup *c, const char *instance, bool remove_instance) {
        DIR *d = NULL;
        struct stat st;
        bool mountpoint;
        int r;

        r = opendir_and_stat(instance, &d, &st, &mountpoint);
        if (r < 0)
                return r;
        if (r == 0) {
                if (remove_instance) {
                        pico_log(PICO_LOG_DEBUG, "removing file \"%s\"", instance);
                        if (remove(instance) < 0 && errno != ENOENT) {
                                r = -errno;
                                pico_log(PICO_LOG_ERR, "rm %s: %s", instance, strerror(-r));
                                return r;
                        }
                }
                return 0;
        }

        r = dir_cleanup(c,
                        instance,
                        d,
                        NSEC_INFINITY,
                        NSEC_INFINITY,
                        NSEC_INFINITY,
                        st.st_dev,
                        mountpoint,
                        MAX_DEPTH,
                        false,
                        0,
                        0);
        closedir(d);
        if (r < 0)
                return r;

        if (remove_instance) {
                pico_log(PICO_LOG_DEBUG, "removing directory \"%s\"", instance);
                if (rmdir(instance) < 0 && errno != ENOENT && errno != ENOTEMPTY) {
                        r = -errno;
                        pico_log(PICO_LOG_ERR, "failed to remove %s: %s", instance, strerror(-r));
                        return r;
                }
        }
        return 0;
}

static int remove_item_instance(Cleanup *c, const PicoTmpfilesItem *i, const char *instance) {
        int r;

        if (i->type == 'R')
                return remove_recursive(c, instance, true);

        /* 'r': a file, or an empty directory, never anything below it */
        pico_log(PICO_LOG_DEBUG, "removing \"%s\"", instance);
        if (remove(instance) < 0 && errno != ENOENT) {
                r = -errno;
                pico_log(PICO_LOG_ERR, "rm %s: %s", instance, strerror(-r));
                return r;
        }
        return 0;
}

/* --- --clean ------------------------------------------------------------- */

static int
                clean_dir(Cleanup *c,
                          const PicoTmpfilesItem *i,
                          const char *instance,
                          DIR *d,
                          const struct stat *st,
                          bool mountpoint) {
        uint64_t n, cutoff;

        if (!i->age_set)
                return 0;

        n = now_realtime_usec();
        if (n < i->age_usec)
                return 0;
        cutoff = n - i->age_usec;

        pico_log(PICO_LOG_DEBUG,
                 "cleanup threshold for %s \"%s\" is %llu",
                 mountpoint ? "mount point" : "directory",
                 instance,
                 (unsigned long long) cutoff);

        return dir_cleanup(
                        c,
                        instance,
                        d,
                        timespec_nsec(&st->st_atim),
                        timespec_nsec(&st->st_mtim),
                        cutoff * 1000ULL,
                        st->st_dev,
                        mountpoint,
                        MAX_DEPTH,
                        i->keep_first_level,
                        i->age_by_file,
                        i->age_by_dir);
}

static int clean_item_instance(Cleanup *c, const PicoTmpfilesItem *i, const char *instance) {
        DIR *d = NULL;
        struct stat st;
        bool mountpoint;
        int r;

        if (!i->age_set)
                return 0;

        r = opendir_and_stat(instance, &d, &st, &mountpoint);
        if (r <= 0)
                return r;

        r = clean_dir(c, i, instance, d, &st, mountpoint);
        closedir(d);
        return r;
}

/* item_instance_needs_cleanup(): the instance itself, for r/R lines with an age. */
static bool instance_needs_cleanup(const PicoTmpfilesItem *i, const char *instance, const struct stat *st) {
        uint64_t n;

        if (!i->age_set)
                return false;

        n = now_realtime_usec();
        if (n < i->age_usec)
                return false;

        return needs_cleanup(
                        st,
                        (n - i->age_usec) * 1000ULL,
                        instance,
                        S_ISDIR(st->st_mode) ? i->age_by_dir : i->age_by_file);
}

/* clean_remove_item_instance_at(): an old file goes, an old directory only when empty. */
static int clean_remove_instance(const PicoTmpfilesItem *i, const char *instance, const struct stat *st) {
        int fd, r;

        if (!instance_needs_cleanup(i, instance, st))
                return 0;

        if (S_ISDIR(st->st_mode)) {
                pico_log(PICO_LOG_DEBUG, "removing directory \"%s\"", instance);
                if (rmdir(instance) < 0 && errno != ENOENT && errno != ENOTEMPTY && errno != EBUSY) {
                        r = -errno;
                        pico_log(PICO_LOG_ERR, "failed to remove %s: %s", instance, strerror(-r));
                        return r;
                }
                return 0;
        }

        fd = open(instance, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NOATIME | O_NONBLOCK | O_NOCTTY);
        if (fd < 0 && errno == EPERM)
                fd = open(instance, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY);
        if (fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) < 0 && errno == EWOULDBLOCK) {
                pico_log(PICO_LOG_DEBUG,
                         "couldn't acquire exclusive BSD lock on file \"%s\", skipping",
                         instance);
                close(fd);
                return 0;
        }

        pico_log(PICO_LOG_DEBUG, "removing \"%s\"", instance);
        if (unlink(instance) < 0 && errno != ENOENT)
                pico_log(PICO_LOG_WARNING, "failed to remove \"%s\", ignoring: %s", instance, strerror(errno));
        if (fd >= 0)
                close(fd);
        return 0;
}

static int clean_remove_item_instance(Cleanup *c, const PicoTmpfilesItem *i, const char *instance) {
        struct stat st;
        DIR *d;
        bool old;
        int r;

        if (!i->age_set)
                return 0;

        if (lstat(instance, &st) < 0) {
                if (errno == ENOENT || errno == ENOTDIR)
                        return 0;
                r = -errno;
                pico_log(PICO_LOG_ERR, "failed to stat \"%s\": %s", instance, strerror(-r));
                return r;
        }

        if (i->type == 'r' || !S_ISDIR(st.st_mode))
                return clean_remove_instance(i, instance, &st);

        /* 'R' on a directory: age out its contents, then the directory itself if emptied */
        d = opendir_nomod(AT_FDCWD, instance);
        if (!d) {
                if (errno == ENOENT || errno == ENOTDIR || errno == ELOOP)
                        return 0;
                r = -errno;
                pico_log(PICO_LOG_ERR, "failed to open directory \"%s\": %s", instance, strerror(-r));
                return r;
        }
        if (flock(dirfd(d), LOCK_EX | LOCK_NB) < 0) {
                pico_log(PICO_LOG_DEBUG,
                         "couldn't acquire exclusive BSD lock on directory \"%s\", skipping",
                         instance);
                closedir(d);
                return 0;
        }

        old = instance_needs_cleanup(i, instance, &st);

        r = clean_dir(c, i, instance, d, &st, is_mountpoint_fd(dirfd(d), &st));
        closedir(d);
        if (r < 0)
                return r;

        if (i->keep_first_level || !old)
                return 0;

        pico_log(PICO_LOG_DEBUG, "removing directory \"%s\"", instance);
        if (rmdir(instance) < 0 && errno != ENOENT && errno != ENOTEMPTY && errno != EBUSY) {
                r = -errno;
                pico_log(PICO_LOG_ERR, "failed to remove %s: %s", instance, strerror(-r));
                return r;
        }
        return 0;
}

/* --- dispatch ------------------------------------------------------------ */

typedef int (*InstanceAction)(Cleanup *c, const PicoTmpfilesItem *i, const char *instance);

static int glob_each(Cleanup *c, const PicoTmpfilesItem *i, InstanceAction action) {
        glob_t g = { 0 };
        size_t k;
        int r = 0, q;

        q = glob(i->path, GLOB_NOSORT | GLOB_BRACE, NULL, &g);
        if (q == GLOB_NOMATCH)
                return 0;
        if (q != 0) {
                pico_log(PICO_LOG_ERR, "failed to glob '%s'", i->path);
                globfree(&g);
                return q == GLOB_NOSPACE ? -ENOMEM : -EIO;
        }

        for (k = 0; k < g.gl_pathc; k++) {
                q = action(c, i, g.gl_pathv[k]);
                if (r >= 0)
                        r = q;
        }

        globfree(&g);
        return r;
}

static int remove_item(Cleanup *c, const PicoTmpfilesItem *i) {
        pico_log(PICO_LOG_DEBUG, "running remove action for entry %c %s", i->type, i->path);

        switch (i->type) {
        case 'D':
                return remove_recursive(c, i->path, false);
        case 'r':
        case 'R':
                return glob_each(c, i, remove_item_instance);
        default:
                return 0;
        }
}

static int clean_item(Cleanup *c, const PicoTmpfilesItem *i) {
        pico_log(PICO_LOG_DEBUG, "running clean action for entry %c %s", i->type, i->path);

        switch (i->type) {
        case 'd':
        case 'D':
        case 'v':
        case 'q':
        case 'Q':
        case 'C':
                return clean_item_instance(c, i, i->path);
        case 'e':
        case 'x':
        case 'X':
                return glob_each(c, i, clean_item_instance);
        case 'r':
        case 'R':
                return glob_each(c, i, clean_remove_item_instance);
        default:
                return 0;
        }
}

static int process_item(Cleanup *c, PicoTmpfilesItem *i) {
        int r = 0, q;

        if (i->cleanup_done)
                return 0;
        i->cleanup_done = true;

        /* unlike --create, a '-' line's failure here still counts, as upstream */
        if (c->operations & PICO_TMPFILES_REMOVE)
                r = remove_item(c, i);
        if (c->operations & PICO_TMPFILES_CLEAN) {
                q = clean_item(c, i);
                if (r >= 0)
                        r = q;
        }
        return r;
}

static int process_array(Cleanup *c, PicoTmpfilesArray *a);

/* the arrays whose closest configured ancestor is `a`, before `a` itself */
static int process_children(Cleanup *c, PicoTmpfilesArray *a, PicoTmpfilesArray **set, size_t n) {
        size_t k;
        int r = 0;

        for (k = 0; k < n; k++)
                if (set[k]->parent == a) {
                        int q = process_array(c, set[k]);

                        if (r >= 0 && q < 0)
                                r = q;
                }

        return r;
}

static int process_array(Cleanup *c, PicoTmpfilesArray *a) {
        size_t k;
        int r, q;

        r = process_children(c, a, c->t->items, c->t->n_items);
        q = process_children(c, a, c->t->globs, c->t->n_globs);
        if (r >= 0)
                r = q;

        for (k = 0; k < a->n_items; k++) {
                q = process_item(c, &a->items[k]);
                if (r >= 0 && q < 0)
                        r = q;
        }

        return r;
}

/*
 * The d-type line an X line takes its age from, by upstream's rule: the
 * exact path, else the first ancestor line, narrowed to a line below that
 * one which the X pattern itself matches.
 */
static PicoTmpfilesItem *x_age_source(PicoTmpfiles *t, const PicoTmpfilesItem *x) {
        PicoTmpfilesItem *candidate = NULL;
        size_t a, b;

        for (a = 0; a < t->n_items; a++)
                for (b = 0; b < t->items[a]->n_items; b++) {
                        PicoTmpfilesItem *d = &t->items[a]->items[b];

                        if (!strchr("dDvqQ", d->type))
                                continue;

                        if (strcmp(d->path, x->path) == 0)
                                return d;

                        if (!candidate) {
                                if (pico_tmpfiles_path_startswith(x->path, d->path))
                                        candidate = d;
                        } else if (pico_tmpfiles_path_startswith(d->path, candidate->path) &&
                                   fnmatch(x->path, d->path, FNM_PATHNAME | FNM_PERIOD) == 0)
                                candidate = d;
                }

        return candidate;
}

/*
 * read_config_file()'s X pass: an X line takes the age of the d-type line
 * it lives under, so the directory it protects is still aged out inside.
 */
static void inherit_x_ages(PicoTmpfiles *t) {
        size_t k, j;

        for (k = 0; k < t->n_globs; k++)
                for (j = 0; j < t->globs[k]->n_items; j++) {
                        PicoTmpfilesItem *x = &t->globs[k]->items[j], *src;

                        if (x->type != 'X')
                                continue;

                        src = x_age_source(t, x);
                        if (src && src->age_set) {
                                x->age_usec = src->age_usec;
                                x->age_set = true;
                                x->age_by_file = src->age_by_file;
                                x->age_by_dir = src->age_by_dir;
                        }
                }
}

int pico_tmpfiles_remove_and_clean(PicoTmpfiles *t, unsigned operations) {
        Cleanup c = { .t = t, .operations = operations };
        size_t k;
        int r = 0;

        if (!t)
                return -EINVAL;
        if ((operations & (PICO_TMPFILES_REMOVE | PICO_TMPFILES_CLEAN)) == 0)
                return 0;

        pico_tmpfiles_link_parents(t);
        inherit_x_ages(t);

        for (k = 0; k < t->n_items; k++) {
                int q = process_array(&c, t->items[k]);

                if (r >= 0 && q < 0)
                        r = q;
        }
        for (k = 0; k < t->n_globs; k++) {
                int q = process_array(&c, t->globs[k]);

                if (r >= 0 && q < 0)
                        r = q;
        }

        pico_strv_free(c.unix_sockets);
        return r;
}
