/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The --create half: turning parsed lines into inodes.
 *
 * Each action mirrors the same-named function in systemd's tmpfiles.c --
 * create_directory(), create_file(), truncate_file(), create_symlink(),
 * copy_files(), fd_set_perms() -- including the details that only show up
 * on a second boot: an existing directory keeps its mode under a ':' prefix,
 * a symlink is chown()ed but never chmod()ed, an `L` that finds a foreign
 * file in the way leaves it alone unless it is `L+`, and a mode change on a
 * node that also changes owner is narrowed to the common bits first so the
 * old owner never briefly holds the new, wider mode.
 *
 * Parents are created 0755 root, as upstream does, whatever the line's own
 * mode says; a line that wants a different parent mode adds a `d` line for
 * the parent, and the parent-before-child ordering guarantees it applies
 * first.
 */

/* O_PATH, AT_EMPTY_PATH and GLOB_BRACE are glibc extensions; gnu17 alone
 * does not expose them (picoctl.c's own note). */
#define _GNU_SOURCE

#include "tmpfiles.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "../util.h"

typedef enum Creation {
        CREATION_NORMAL,
        CREATION_EXISTING,
        CREATION_FORCE,
        /* copy_files(): unknown, so both only-create prefixes are ignored */
        CREATION_UNKNOWN,
} Creation;

/* --- fd helpers --------------------------------------------------------- */

static int proc_fd_path(int fd, char *buf, size_t size) {
        int n = snprintf(buf, size, "/proc/self/fd/%d", fd);

        if (n < 0 || (size_t) n >= size)
                return -ENAMETOOLONG;
        return 0;
}

/* chmod through an O_PATH fd: fchmod() refuses those, the /proc alias does not. */
static int fd_chmod(int fd, mode_t mode) {
        char p[64];
        int r;

        if (fchmod(fd, mode) == 0)
                return 0;
        if (errno != EBADF)
                return -errno;

        r = proc_fd_path(fd, p, sizeof(p));
        if (r < 0)
                return r;
        if (chmod(p, mode) < 0)
                return -errno;
        return 0;
}

static int fd_chown(int fd, uid_t uid, gid_t gid) {
        if (fchownat(fd, "", uid, gid, AT_EMPTY_PATH) < 0)
                return -errno;
        return 0;
}

static bool hardlinks_protected(void) {
        char buf[8];
        int fd;
        ssize_t n;

        fd = open("/proc/sys/fs/protected_hardlinks", O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return false;
        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n <= 0)
                return false;
        buf[n] = '\0';
        return buf[0] == '1';
}

static bool hardlink_vulnerable(const struct stat *st) {
        return !S_ISDIR(st->st_mode) && st->st_nlink > 1 && !hardlinks_protected();
}

static int split_parent(const char *path, char **ret_dir, const char **ret_bn) {
        const char *slash;
        char *dir;

        slash = strrchr(path, '/');
        if (!slash || slash[1] == '\0')
                return -EINVAL;

        if (slash == path)
                dir = strdup("/");
        else
                dir = strndup(path, (size_t) (slash - path));
        if (!dir)
                return -ENOMEM;

        *ret_dir = dir;
        *ret_bn = slash + 1;
        return 0;
}

static int open_parent(const char *path, bool allow_failure, const char **ret_bn) {
        char *dir = NULL;
        int r, fd;

        r = split_parent(path, &dir, ret_bn);
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "cannot determine parent directory of \"%s\"", path);
                return r;
        }

        fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY);
        if (fd < 0) {
                r = -errno;
                pico_log(allow_failure ? PICO_LOG_INFO : PICO_LOG_ERR,
                         "failed to open parent directory of \"%s\"%s: %s",
                         path,
                         allow_failure ? ", ignoring" : "",
                         strerror(-r));
                free(dir);
                return r;
        }

        free(dir);
        return fd;
}

/* mkdir_parents_label(): every missing component, 0755, errors ignored. */
static void mkdir_parents(const char *path) {
        char buf[PATH_MAX];
        size_t len = strlen(path), k;

        if (len >= sizeof(buf))
                return;
        memcpy(buf, path, len + 1);

        for (k = 1; k < len; k++) {
                if (buf[k] != '/')
                        continue;
                buf[k] = '\0';
                (void) mkdir(buf, 0755);
                buf[k] = '/';
        }
}

/* --- fd_set_perms() ----------------------------------------------------- */

static mode_t process_mask_perms(mode_t mode, mode_t current) {
        if ((current & 0111) == 0)
                mode &= ~(mode_t) 0111;
        if ((current & 0222) == 0)
                mode &= ~(mode_t) 0222;
        if ((current & 0444) == 0)
                mode &= ~(mode_t) 0444;
        if (!S_ISDIR(current))
                mode &= ~(mode_t) 07000; /* remove sticky/sgid/suid bit, unless directory */

        return mode;
}

static int set_perms(const PicoTmpfilesItem *i, int fd, const char *path, const struct stat *st, Creation creation) {
        struct stat stbuf;
        mode_t new_mode;
        uid_t new_uid;
        gid_t new_gid;
        bool do_chown, do_chmod;
        int r;

        if (!i->mode_set && !i->uid_set && !i->gid_set)
                return 0;

        if (!st) {
                if (fstat(fd, &stbuf) < 0) {
                        r = -errno;
                        pico_log(PICO_LOG_ERR, "fstat(%s) failed: %s", path, strerror(-r));
                        return r;
                }
                st = &stbuf;
        }

        if (hardlink_vulnerable(st)) {
                pico_log(PICO_LOG_ERR,
                         "refusing to set permissions on hardlinked file %s while fs.protected_hardlinks is off",
                         path);
                return -EPERM;
        }

        new_uid = i->uid_set && (creation != CREATION_EXISTING || !i->uid_only_create) ? i->uid : st->st_uid;
        new_gid = i->gid_set && (creation != CREATION_EXISTING || !i->gid_only_create) ? i->gid : st->st_gid;
        do_chown = new_uid != st->st_uid || new_gid != st->st_gid;

        new_mode = i->mode_set && (creation != CREATION_EXISTING || !i->mode_only_create) ?
                        (i->mask_perms ? process_mask_perms(i->mode, st->st_mode) : i->mode) :
                        (st->st_mode & 07777);
        do_chmod = ((new_mode ^ st->st_mode) & 07777) != 0;

        if (do_chmod && do_chown && !S_ISLNK(st->st_mode)) {
                mode_t m = new_mode & st->st_mode;

                if (((m ^ st->st_mode) & 07777) != 0) {
                        r = fd_chmod(fd, m);
                        if (r < 0) {
                                pico_log(PICO_LOG_ERR, "fchmod() of %s failed: %s", path, strerror(-r));
                                return r;
                        }
                }
        }

        if (do_chown) {
                r = fd_chown(fd,
                             new_uid != st->st_uid ? new_uid : (uid_t) -1,
                             new_gid != st->st_gid ? new_gid : (gid_t) -1);
                if (r < 0) {
                        pico_log(PICO_LOG_ERR, "fchownat() of %s failed: %s", path, strerror(-r));
                        return r;
                }
        }

        /* after a chown too: it may have stripped suid/sgid bits */
        if ((do_chmod || do_chown) && !S_ISLNK(st->st_mode)) {
                r = fd_chmod(fd, new_mode);
                if (r < 0) {
                        pico_log(PICO_LOG_ERR, "fchmod() of %s failed: %s", path, strerror(-r));
                        return r;
                }
        }

        return 0;
}

/* path_set_perms(): the O_PATH|O_NOFOLLOW open; a missing path is not an error. */
static int path_set_perms(const PicoTmpfilesItem *i, const char *path, Creation creation) {
        int fd, r;

        fd = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
                if (errno == ENOENT)
                        return 0;
                r = -errno;
                pico_log(PICO_LOG_ERR, "failed to open path %s: %s", path, strerror(-r));
                return r;
        }

        r = set_perms(i, fd, path, NULL, creation);
        close(fd);
        return r;
}

/* item_do(): the action on fd, then on everything below it, never following symlinks. */
static int set_perms_recursively(const PicoTmpfilesItem *i, int fd, const char *path) {
        struct stat st;
        int r, q;

        if (fstat(fd, &st) < 0) {
                r = -errno;
                pico_log(PICO_LOG_ERR, "fstat() on %s failed: %s", path, strerror(-r));
                close(fd);
                return r;
        }

        r = set_perms(i, fd, path, &st, CREATION_EXISTING);

        if (S_ISDIR(st.st_mode)) {
                char p[64];
                DIR *d = NULL;
                struct dirent *de;

                if (proc_fd_path(fd, p, sizeof(p)) == 0)
                        d = opendir(p);
                if (!d) {
                        q = -errno;
                        pico_log(PICO_LOG_ERR, "failed to opendir() %s: %s", path, strerror(-q));
                        close(fd);
                        return r < 0 ? r : q;
                }

                while ((de = readdir(d))) {
                        char child[PATH_MAX];
                        int cfd, n;

                        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                                continue;

                        cfd = openat(fd, de->d_name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
                        if (cfd < 0) {
                                if (errno != ENOENT) {
                                        q = -errno;
                                        pico_log(PICO_LOG_ERR,
                                                 "failed to open %s/%s: %s",
                                                 path,
                                                 de->d_name,
                                                 strerror(-q));
                                        if (r >= 0)
                                                r = q;
                                }
                                continue;
                        }

                        n = snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
                        if (n < 0 || (size_t) n >= sizeof(child)) {
                                close(cfd);
                                if (r >= 0)
                                        r = -ENAMETOOLONG;
                                continue;
                        }

                        q = set_perms_recursively(i, cfd, child); /* closes cfd */
                        if (r >= 0)
                                r = q;
                }

                closedir(d);
        }

        close(fd);
        return r;
}

static int path_set_perms_recursively(const PicoTmpfilesItem *i, const char *path) {
        int fd, r;

        fd = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
                if (errno == ENOENT)
                        return 0;
                r = -errno;
                pico_log(PICO_LOG_ERR, "failed to open path %s: %s", path, strerror(-r));
                return r;
        }

        return set_perms_recursively(i, fd, path);
}

/* glob_item(): every match, or nothing at all when there is none. */
static int glob_item(const PicoTmpfilesItem *i, bool recursive) {
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
                q = recursive ? path_set_perms_recursively(i, g.gl_pathv[k]) :
                                path_set_perms(i, g.gl_pathv[k], CREATION_EXISTING);
                if (r >= 0)
                        r = q;
        }

        globfree(&g);
        return r;
}

/* --- d D v q Q ----------------------------------------------------------- */

static int create_directory(const PicoTmpfilesItem *i) {
        const char *bn;
        struct stat st;
        Creation creation;
        int pfd, fd, r, q;

        pfd = open_parent(i->path, i->allow_failure, &bn);
        if (pfd < 0)
                return pfd;

        r = mkdirat(pfd, bn, i->mode) < 0 ? -errno : 0;
        creation = r >= 0 ? CREATION_NORMAL : CREATION_EXISTING;

        fd = openat(pfd, bn, O_NOFOLLOW | O_CLOEXEC | O_DIRECTORY | O_PATH);
        q = -errno;
        close(pfd);
        if (fd < 0) {
                if (q == -ENOTDIR) {
                        pico_log(PICO_LOG_ERR, "\"%s\" already exists and is not a directory", i->path);
                        return -EEXIST;
                }
                if (r < 0) {
                        pico_log(i->allow_failure ? PICO_LOG_INFO : PICO_LOG_ERR,
                                 "failed to create directory \"%s\"%s: %s",
                                 i->path,
                                 i->allow_failure ? ", ignoring" : "",
                                 strerror(-r));
                        return r;
                }
                pico_log(PICO_LOG_ERR,
                         "failed to open directory we just created \"%s\": %s",
                         i->path,
                         strerror(-q));
                return q;
        }

        if (fstat(fd, &st) < 0) {
                r = -errno;
                pico_log(PICO_LOG_ERR, "failed to fstat(%s): %s", i->path, strerror(-r));
                close(fd);
                return r;
        }

        pico_log(PICO_LOG_DEBUG,
                 "%s directory \"%s\"",
                 creation == CREATION_NORMAL ? "created" : "found existing",
                 i->path);

        r = set_perms(i, fd, i->path, &st, creation);
        close(fd);
        return r;
}

/* --- f f+ F ------------------------------------------------------------- */

static int write_argument(const PicoTmpfilesItem *i, int fd) {
        const char *p = i->argument;
        size_t left;

        if (!p)
                return 0;

        left = strlen(p);
        while (left > 0) {
                ssize_t n = write(fd, p, left);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        return -errno;
                }
                p += n;
                left -= (size_t) n;
        }

        return 0;
}

/* 'f' operates on regular files exclusively; an existing one is left as is. */
static int create_file(const PicoTmpfilesItem *i) {
        const char *bn;
        struct stat stbuf, *st = NULL;
        Creation creation;
        int pfd, fd, r;

        pfd = open_parent(i->path, i->allow_failure, &bn);
        if (pfd < 0)
                return pfd;

        fd = openat(pfd,
                    bn,
                    O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | O_WRONLY | O_NOCTTY,
                    i->mode);
        if (fd < 0) {
                r = -errno;
                if (r != -EEXIST) {
                        pico_log(PICO_LOG_ERR, "failed to create file %s: %s", i->path, strerror(-r));
                        close(pfd);
                        return r;
                }

                fd = openat(pfd, bn, O_NOFOLLOW | O_CLOEXEC | O_PATH);
                if (fd < 0) {
                        r = -errno;
                        pico_log(PICO_LOG_ERR, "failed to reopen file %s: %s", i->path, strerror(-r));
                        close(pfd);
                        return r;
                }
                close(pfd);

                if (fstat(fd, &stbuf) < 0) {
                        r = -errno;
                        pico_log(PICO_LOG_ERR, "stat(%s) failed: %s", i->path, strerror(-r));
                        close(fd);
                        return r;
                }
                if (!S_ISREG(stbuf.st_mode)) {
                        pico_log(PICO_LOG_ERR, "%s exists and is not a regular file", i->path);
                        close(fd);
                        return -EEXIST;
                }
                st = &stbuf;
                creation = CREATION_EXISTING;
        } else {
                close(pfd);
                r = write_argument(i, fd);
                if (r < 0) {
                        pico_log(PICO_LOG_ERR, "failed to write file \"%s\": %s", i->path, strerror(-r));
                        close(fd);
                        return r;
                }
                creation = CREATION_NORMAL;
        }

        r = set_perms(i, fd, i->path, st, creation);
        close(fd);
        return r;
}

/* 'F' and 'f+': create or truncate, then write; still regular files only. */
static int truncate_file(const PicoTmpfilesItem *i) {
        const char *bn;
        struct stat stbuf, *st = NULL;
        Creation creation = CREATION_EXISTING;
        bool erofs = false;
        int pfd, fd, r;

        pfd = open_parent(i->path, i->allow_failure, &bn);
        if (pfd < 0)
                return pfd;

        fd = openat(pfd, bn, O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | O_WRONLY | O_NOCTTY);
        if (fd < 0 && errno == ENOENT) {
                creation = CREATION_NORMAL;
                fd = openat(pfd,
                            bn,
                            O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC | O_WRONLY | O_NOCTTY,
                            i->mode);
        }

        if (fd < 0) {
                r = -errno;
                if (r != -EROFS) {
                        pico_log(PICO_LOG_ERR, "failed to open/create file %s: %s", i->path, strerror(-r));
                        close(pfd);
                        return r;
                }

                /* read-only: fine as long as it is already empty with the right perms */
                fd = openat(pfd, bn, O_NOFOLLOW | O_CLOEXEC | O_PATH);
                if (fd < 0) {
                        r = -errno;
                        pico_log(PICO_LOG_ERR,
                                 r == -ENOENT ? "cannot create file %s on a read-only file system" :
                                                "failed to reopen file %s: %s",
                                 i->path,
                                 strerror(-r));
                        close(pfd);
                        return r == -ENOENT ? -EROFS : r;
                }
                erofs = true;
                creation = CREATION_EXISTING;
        }
        close(pfd);

        if (fstat(fd, &stbuf) < 0) {
                r = -errno;
                pico_log(PICO_LOG_ERR, "stat(%s) failed: %s", i->path, strerror(-r));
                close(fd);
                return r;
        }
        if (!S_ISREG(stbuf.st_mode)) {
                pico_log(PICO_LOG_ERR, "%s exists and is not a regular file", i->path);
                close(fd);
                return -EEXIST;
        }

        if (stbuf.st_size > 0) {
                if (erofs) {
                        pico_log(PICO_LOG_ERR, "cannot truncate %s on a read-only file system", i->path);
                        close(fd);
                        return -EROFS;
                }
                if (ftruncate(fd, 0) < 0) {
                        r = -errno;
                        pico_log(PICO_LOG_ERR, "failed to truncate file %s: %s", i->path, strerror(-r));
                        close(fd);
                        return r;
                }
        } else
                st = &stbuf;

        if (!erofs) {
                r = write_argument(i, fd);
                if (r < 0) {
                        pico_log(PICO_LOG_ERR, "failed to write file \"%s\": %s", i->path, strerror(-r));
                        close(fd);
                        return r;
                }
        }

        r = set_perms(i, fd, i->path, st, creation);
        close(fd);
        return r;
}

/* --- L L+ L? ------------------------------------------------------------- */

static int rm_rf_at(int dfd, const char *name);

static int rm_rf_dir_contents(int fd) {
        char p[64];
        DIR *d = NULL;
        struct dirent *de;
        int r = 0;

        if (proc_fd_path(fd, p, sizeof(p)) == 0)
                d = opendir(p);
        if (!d)
                return -errno;

        while ((de = readdir(d))) {
                int q;

                if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                        continue;
                q = rm_rf_at(dirfd(d), de->d_name);
                if (r >= 0 && q < 0)
                        r = q;
        }

        closedir(d);
        return r;
}

static int rm_rf_at(int dfd, const char *name) {
        struct stat st;
        int r;

        if (fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                return errno == ENOENT ? 0 : -errno;

        if (S_ISDIR(st.st_mode)) {
                int fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

                if (fd < 0)
                        return -errno;
                r = rm_rf_dir_contents(fd);
                close(fd);
                if (r < 0)
                        return r;
                if (unlinkat(dfd, name, AT_REMOVEDIR) < 0)
                        return -errno;
                return 0;
        }

        if (unlinkat(dfd, name, 0) < 0)
                return -errno;
        return 0;
}

/*
 * Where an `L?` target lives: an absolute target under --root, a relative
 * one beside the link itself, which is what the kernel will do with it.
 */
static int symlink_target_path(const PicoTmpfiles *t, const PicoTmpfilesItem *i, char *buf, size_t size) {
        int n;

        if (i->argument[0] == '/')
                n = snprintf(buf, size, "%s%s", t->root ? t->root : "", i->argument);
        else {
                const char *slash = strrchr(i->path, '/');
                int dl = slash ? (int) (slash - i->path) : 0;

                n = snprintf(buf, size, "%.*s/%s", dl, i->path, i->argument);
        }

        if (n < 0 || (size_t) n >= size)
                return -ENAMETOOLONG;
        return 0;
}

static int create_symlink(const PicoTmpfiles *t, const PicoTmpfilesItem *i) {
        const char *bn;
        struct stat st;
        Creation creation;
        bool good = false;
        int pfd, fd, r;

        if (i->ignore_if_target_missing) {
                char target[PATH_MAX];

                r = symlink_target_path(t, i, target, sizeof(target));
                if (r < 0)
                        return r;
                if (fstatat(AT_FDCWD, target, &st, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT) {
                        pico_log(PICO_LOG_INFO,
                                 "symlink source path '%s' does not exist, skipping line",
                                 i->argument);
                        return 0;
                }
        }

        pfd = open_parent(i->path, i->allow_failure, &bn);
        if (pfd < 0)
                return pfd;

        r = symlinkat(i->argument, pfd, bn) < 0 ? -errno : 0;
        creation = r >= 0 ? CREATION_NORMAL : CREATION_EXISTING;

        fd = openat(pfd, bn, O_NOFOLLOW | O_CLOEXEC | O_PATH);
        if (fd < 0) {
                int q = -errno;

                close(pfd);
                if (r < 0) {
                        pico_log(PICO_LOG_ERR, "failed to create symlink '%s': %s", i->path, strerror(-r));
                        return r;
                }
                pico_log(PICO_LOG_ERR, "failed to open symlink we just created '%s': %s", i->path, strerror(-q));
                return q;
        }

        if (fstat(fd, &st) < 0) {
                r = -errno;
                pico_log(PICO_LOG_ERR, "failed to fstat(%s): %s", i->path, strerror(-r));
                close(fd);
                close(pfd);
                return r;
        }

        if (S_ISLNK(st.st_mode)) {
                char x[PATH_MAX];
                ssize_t n;

                n = readlinkat(pfd, bn, x, sizeof(x) - 1);
                if (n < 0) {
                        r = -errno;
                        pico_log(PICO_LOG_ERR, "readlinkat(%s) failed: %s", i->path, strerror(-r));
                        close(fd);
                        close(pfd);
                        return r;
                }
                x[n] = '\0';
                good = strcmp(x, i->argument) == 0;
        }

        if (!good) {
                if (!i->append_or_force) {
                        pico_log(PICO_LOG_DEBUG,
                                 "\"%s\" is not a symlink or does not point to the correct path",
                                 i->path);
                        close(fd);
                        close(pfd);
                        return 0;
                }

                close(fd);

                r = rm_rf_at(pfd, bn);
                if (r < 0) {
                        pico_log(PICO_LOG_ERR, "rm -rf %s failed: %s", i->path, strerror(-r));
                        close(pfd);
                        return r;
                }
                if (symlinkat(i->argument, pfd, bn) < 0) {
                        r = -errno;
                        pico_log(PICO_LOG_ERR, "symlink(%s, %s) failed: %s", i->argument, i->path, strerror(-r));
                        close(pfd);
                        return r;
                }

                fd = openat(pfd, bn, O_NOFOLLOW | O_CLOEXEC | O_PATH);
                if (fd < 0) {
                        r = -errno;
                        pico_log(PICO_LOG_ERR,
                                 "failed to open symlink we just created '%s': %s",
                                 i->path,
                                 strerror(-r));
                        close(pfd);
                        return r;
                }
                if (fstat(fd, &st) < 0 || !S_ISLNK(st.st_mode)) {
                        pico_log(PICO_LOG_ERR, "symlink we just created is not a symlink, refusing");
                        close(fd);
                        close(pfd);
                        return -EBADF;
                }
                creation = CREATION_FORCE;
        }

        close(pfd);
        pico_log(PICO_LOG_DEBUG,
                 "%s symlink \"%s\"",
                 creation == CREATION_NORMAL                ? "created" :
                                 creation == CREATION_FORCE ? "replaced" :
                                                              "found existing",
                 i->path);

        r = set_perms(i, fd, i->path, &st, creation);
        close(fd);
        return r;
}

/* --- C C+ ---------------------------------------------------------------- */

#define COPY_MERGE 1       /* merge into a populated directory, skip existing files */
#define COPY_MERGE_EMPTY 2 /* merge only into an empty directory */

static int copy_times(int fd, const struct stat *st) {
        struct timespec ts[2] = { st->st_atim, st->st_mtim };

        return futimens(fd, ts) < 0 ? -errno : 0;
}

static int copy_owner_mode(int fd, const struct stat *st, uid_t uid, gid_t gid, bool is_link) {
        int r;

        r = fd_chown(fd, uid != (uid_t) -1 ? uid : st->st_uid, gid != (gid_t) -1 ? gid : st->st_gid);
        if (r < 0)
                return r;
        if (is_link)
                return 0;
        return fd_chmod(fd, st->st_mode & 07777);
}

static int copy_tree_at(
                int sfd, const char *from, int dfd, const char *to, uid_t uid, gid_t gid, unsigned flags, int depth);

static int copy_regular(
                int sfd, const char *from, const struct stat *st, int dfd, const char *to, uid_t uid, gid_t gid) {
        int in, out, r = 0;
        char buf[65536];

        in = openat(sfd, from, O_RDONLY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
        if (in < 0)
                return -errno;

        out = openat(dfd,
                     to,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW,
                     st->st_mode & 07777);
        if (out < 0) {
                r = -errno;
                close(in);
                return r;
        }

        for (;;) {
                ssize_t n = read(in, buf, sizeof(buf));
                const char *p = buf;

                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        r = -errno;
                        break;
                }
                if (n == 0)
                        break;

                while (n > 0) {
                        ssize_t w = write(out, p, (size_t) n);

                        if (w < 0) {
                                if (errno == EINTR)
                                        continue;
                                r = -errno;
                                break;
                        }
                        p += w;
                        n -= w;
                }
                if (r < 0)
                        break;
        }

        if (r >= 0)
                r = copy_owner_mode(out, st, uid, gid, false);
        if (r >= 0)
                r = copy_times(out, st);

        close(in);
        close(out);
        return r;
}

static int copy_symlink(
                int sfd, const char *from, const struct stat *st, int dfd, const char *to, uid_t uid, gid_t gid) {
        char target[PATH_MAX];
        ssize_t n;
        int fd, r;

        n = readlinkat(sfd, from, target, sizeof(target) - 1);
        if (n < 0)
                return -errno;
        target[n] = '\0';

        if (symlinkat(target, dfd, to) < 0)
                return -errno;

        fd = openat(dfd, to, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
                return -errno;
        r = copy_owner_mode(fd, st, uid, gid, true);
        close(fd);
        return r;
}

static int copy_node(
                int sfd, const char *from, const struct stat *st, int dfd, const char *to, uid_t uid, gid_t gid) {
        int fd, r;

        (void) sfd;
        (void) from;

        if (mknodat(dfd, to, st->st_mode, st->st_rdev) < 0)
                return -errno;

        fd = openat(dfd, to, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
                return -errno;
        r = copy_owner_mode(fd, st, uid, gid, false);
        close(fd);
        return r;
}

static int dir_is_empty_at(int dfd, const char *name) {
        int fd;
        DIR *d;
        struct dirent *de;
        bool empty = true;

        fd = openat(dfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
                return -errno;
        d = fdopendir(fd);
        if (!d) {
                close(fd);
                return -errno;
        }
        while ((de = readdir(d)))
                if (strcmp(de->d_name, ".") != 0 && strcmp(de->d_name, "..") != 0) {
                        empty = false;
                        break;
                }
        closedir(d);
        return empty;
}

static int
                copy_directory(int sfd,
                               const char *from,
                               const struct stat *st,
                               int dfd,
                               const char *to,
                               uid_t uid,
                               gid_t gid,
                               unsigned flags,
                               int depth) {
        int fdf, fdt, r, ret = 0;
        DIR *d;
        struct dirent *de;
        bool exists;

        if (depth == 0)
                return -ENAMETOOLONG;

        fdf = openat(sfd, from, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
        if (fdf < 0)
                return -errno;
        d = fdopendir(fdf);
        if (!d) {
                r = -errno;
                close(fdf);
                return r;
        }

        r = dir_is_empty_at(dfd, to);
        if (r < 0 && r != -ENOENT) {
                closedir(d);
                return r;
        }
        if ((r > 0 && !(flags & (COPY_MERGE | COPY_MERGE_EMPTY))) || (r == 0 && !(flags & COPY_MERGE))) {
                closedir(d);
                return -EEXIST;
        }
        exists = r >= 0;

        if (!exists && mkdirat(dfd, to, st->st_mode & 07777) < 0) {
                r = -errno;
                closedir(d);
                return r;
        }

        fdt = openat(dfd, to, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOCTTY | O_NOFOLLOW);
        if (fdt < 0) {
                r = -errno;
                closedir(d);
                return r;
        }

        while ((de = readdir(d))) {
                if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                        continue;

                r = copy_tree_at(dirfd(d), de->d_name, fdt, de->d_name, uid, gid, flags, depth - 1);
                if (r == -ENOSPC || r == -EINTR) {
                        closedir(d);
                        close(fdt);
                        return r;
                }
                if (r == -EEXIST && (flags & COPY_MERGE))
                        r = 0;
                if (ret >= 0 && r < 0)
                        ret = r;
        }

        if (!exists) {
                r = copy_owner_mode(fdt, st, uid, gid, false);
                if (r >= 0)
                        r = copy_times(fdt, st);
                if (ret >= 0 && r < 0)
                        ret = r;
        }

        closedir(d);
        close(fdt);
        return ret;
}

static int copy_tree_at(
                int sfd, const char *from, int dfd, const char *to, uid_t uid, gid_t gid, unsigned flags, int depth) {
        struct stat st;

        if (fstatat(sfd, from, &st, AT_SYMLINK_NOFOLLOW) < 0)
                return -errno;

        if (S_ISREG(st.st_mode))
                return copy_regular(sfd, from, &st, dfd, to, uid, gid);
        if (S_ISDIR(st.st_mode))
                return copy_directory(sfd, from, &st, dfd, to, uid, gid, flags, depth);
        if (S_ISLNK(st.st_mode))
                return copy_symlink(sfd, from, &st, dfd, to, uid, gid);
        if (S_ISFIFO(st.st_mode) || S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
                return copy_node(sfd, from, &st, dfd, to, uid, gid);

        return -EOPNOTSUPP;
}

static int copy_files(const PicoTmpfilesItem *i) {
        const char *bn;
        struct stat st, a;
        int pfd, fd, r;

        pfd = open_parent(i->path, i->allow_failure, &bn);
        if (pfd < 0)
                return pfd;

        r = copy_tree_at(
                        AT_FDCWD,
                        i->argument,
                        pfd,
                        bn,
                        i->uid_set ? i->uid : (uid_t) -1,
                        i->gid_set ? i->gid : (gid_t) -1,
                        i->append_or_force ? COPY_MERGE : COPY_MERGE_EMPTY,
                        256);

        fd = openat(pfd, bn, O_NOFOLLOW | O_CLOEXEC | O_PATH);
        close(pfd);
        if (fd < 0) {
                int q = -errno;

                if (r < 0) {
                        pico_log(PICO_LOG_ERR, "failed to copy files to %s: %s", i->path, strerror(-r));
                        return r;
                }
                pico_log(PICO_LOG_ERR, "failed to openat(%s): %s", i->path, strerror(-q));
                return q;
        }

        if (fstat(fd, &st) < 0) {
                r = -errno;
                pico_log(PICO_LOG_ERR, "failed to fstat(%s): %s", i->path, strerror(-r));
                close(fd);
                return r;
        }
        if (stat(i->argument, &a) < 0) {
                r = -errno;
                pico_log(PICO_LOG_ERR, "failed to stat(%s): %s", i->argument, strerror(-r));
                close(fd);
                return r;
        }

        if (((st.st_mode ^ a.st_mode) & S_IFMT) != 0) {
                pico_log(PICO_LOG_DEBUG,
                         "can't copy to %s, file exists already and is of different type",
                         i->path);
                close(fd);
                return 0;
        }

        r = set_perms(i, fd, i->path, &st, CREATION_UNKNOWN);
        close(fd);
        return r;
}

/* --- dispatch ----------------------------------------------------------- */

static int create_item(const PicoTmpfiles *t, PicoTmpfilesItem *i) {
        pico_log(PICO_LOG_DEBUG, "running create action for entry %c %s", i->type, i->path);

        switch (i->type) {
        case 'x':
        case 'X':
        case 'r':
        case 'R':
                return 0;

        case 'f':
        case 'F':
                mkdir_parents(i->path);
                if (i->type == 'F' || i->append_or_force)
                        return truncate_file(i);
                return create_file(i);

        case 'C':
                mkdir_parents(i->path);
                return copy_files(i);

        case 'd':
        case 'D':
        case 'v':
        case 'q':
        case 'Q':
                mkdir_parents(i->path);
                return create_directory(i);

        case 'L':
                mkdir_parents(i->path);
                return create_symlink(t, i);

        case 'z':
                return glob_item(i, false);
        case 'Z':
                return glob_item(i, true);

        default:
                /* the parser only lets the letters above through */
                return -EINVAL;
        }
}

static int process_item(const PicoTmpfiles *t, PicoTmpfilesItem *i) {
        int r;

        if (i->done)
                return 0;
        i->done = true;

        r = create_item(t, i);
        if (i->allow_failure)
                r = 0;
        return r;
}

static int process_array(const PicoTmpfiles *t, PicoTmpfilesArray *a) {
        size_t k;
        int r = 0;

        if (a->parent)
                r = process_array(t, a->parent);

        for (k = 0; k < a->n_items; k++) {
                int q = process_item(t, &a->items[k]);

                if (r >= 0 && q < 0)
                        r = q;
        }

        return r;
}

/* link_parent(): the closest ancestor path that has lines of its own. */
static void link_parent(PicoTmpfiles *t, PicoTmpfilesArray *a) {
        char prefix[PATH_MAX];
        size_t len;

        a->parent = NULL;
        if (a->n_items == 0)
                return;

        len = strlen(a->path);
        if (len >= sizeof(prefix))
                return;
        memcpy(prefix, a->path, len + 1);

        for (;;) {
                char *slash = strrchr(prefix, '/');
                PicoTmpfilesArray *j;

                if (!slash || slash == prefix)
                        return;
                *slash = '\0';

                j = pico_tmpfiles_find(t, prefix);
                if (j && j != a) {
                        a->parent = j;
                        return;
                }
        }
}

int pico_tmpfiles_create(PicoTmpfiles *t) {
        mode_t saved;
        size_t k;
        int r = 0;

        if (!t)
                return -EINVAL;

        for (k = 0; k < t->n_items; k++)
                link_parent(t, t->items[k]);
        for (k = 0; k < t->n_globs; k++)
                link_parent(t, t->globs[k]);

        saved = umask(0);

        /* the non-globbing lines create things, so they go first */
        for (k = 0; k < t->n_items; k++) {
                int q = process_array(t, t->items[k]);

                if (r >= 0 && q < 0)
                        r = q;
        }
        for (k = 0; k < t->n_globs; k++) {
                int q = process_array(t, t->globs[k]);

                if (r >= 0 && q < 0)
                        r = q;
        }

        umask(saved);
        return r;
}
