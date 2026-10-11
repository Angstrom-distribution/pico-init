/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * pico-init's own implementation of the sd-daemon.h ABI. The control flow
 * follows systemd v30 (commit 501c92c, 2010, Lennart Poettering) for the
 * functions that existed then; the API contract and the later functions
 * (sd_pid_notify*, sd_notify_barrier*, sd_pidfd_get_inode_id,
 * sd_watchdog_enabled, sd_is_socket_sockaddr, sd_listen_fds_with_names) come
 * from current systemd main. Nothing is copied; the commit hashes cited
 * below are upstream fixes reimplemented here.
 *
 * The socket-activation producer is src/service-exec.c: build_exec_envp()
 * exports LISTEN_FDS=<n> and scrubs any inherited LISTEN_*, child_exec()
 * fills LISTEN_PID with its own pid after fork, and shift_fds()/flags_fds()
 * renumber the fds into [3, n+2] with FD_CLOEXEC cleared. sd_listen_fds()
 * re-arms FD_CLOEXEC, as the sd-daemon.h contract requires.
 *
 * This is a library other packages link against, so it calls nothing from
 * pico-init's util.c or logging. Allocation failure is a plain -ENOMEM.
 */

/* vasprintf(), pipe2(), ppoll() are GNU/glibc extensions; -std=gnu17 alone
 * does not imply _GNU_SOURCE, so it must be defined first. */
#define _GNU_SOURCE

#include "sd-daemon.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mqueue.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/vfs.h>
#include <unistd.h>

/* struct statx and STATX_INO come from <sys/stat.h> on glibc >= 2.28 and
 * musl >= 1.1.20; the <linux/stat.h> fallback is for older toolchains. */
#ifndef STATX_INO
#        include <linux/stat.h>
#endif

/* PID_FS_MAGIC ("PIDF") from uapi/linux/magic.h, which older kernel headers
 * lack. */
#ifndef PID_FS_MAGIC
#        define PID_FS_MAGIC 0x50494446
#endif

/* ---------------------------------------------------------------------
 * Strict decimal parsing shared by every LISTEN_ and WATCHDOG_ variable.
 * strtoul()/strtoull()'s own contract skips leading whitespace and accepts
 * a leading '+' -- PID 1 never writes either into a child's environment, so
 * seeing one here means the value came from somewhere else and should be
 * rejected, not silently accepted (backport f3910003bc's actual point: an
 * empty string is exactly what a blank/absent value looks like, and v30
 * accepted it as 0).
 * --------------------------------------------------------------------- */

static int parse_strict_u64(const char *s, uint64_t *ret) {
        char *end;
        unsigned long long v;

        if (!s || !isdigit((unsigned char) s[0]))
                return -EINVAL;

        errno = 0;
        v = strtoull(s, &end, 10);
        if (errno == ERANGE)
                return -ERANGE;
        if (*end != '\0')
                return -EINVAL;

        *ret = (uint64_t) v;
        return 0;
}

static int parse_strict_int(const char *s, int *ret) {
        char *end;
        long v;

        if (!s || s[0] == '\0')
                return -EINVAL;
        if (!isdigit((unsigned char) s[0]) && !(s[0] == '-' && isdigit((unsigned char) s[1])))
                return -EINVAL;

        errno = 0;
        v = strtol(s, &end, 10);
        if (errno == ERANGE)
                return -ERANGE;
        if (*end != '\0')
                return -EINVAL;
        if (v < INT_MIN || v > INT_MAX)
                return -ERANGE;

        *ret = (int) v;
        return 0;
}

static int parse_strict_pid(const char *s, pid_t *ret) {
        uint64_t v;
        int r;

        r = parse_strict_u64(s, &v);
        if (r < 0)
                return r;
        if (v == 0 || v > (uint64_t) INT_MAX)
                return -ERANGE;

        *ret = (pid_t) v;
        return 0;
}

/* ---------------------------------------------------------------------
 * sd_pidfd_get_inode_id() and the own-pidfd cache sd_listen_fds() reuses
 * for its LISTEN_PIDFDID check.
 * --------------------------------------------------------------------- */

/* Raw syscall: glibc only has pidfd_open() from 2.36. SYS_pidfd_open is the
 * compile-time check; the runtime check is probe_pidfs(). */
static int raw_pidfd_open(pid_t pid, unsigned int flags) {
#ifdef SYS_pidfd_open
        return (int) syscall(SYS_pidfd_open, pid, flags);
#else
        errno = ENOSYS;
        return -1;
#endif
}

/* Cached for the process's lifetime, since probing opens a throwaway pidfd.
 * -1 = not yet probed, 0 = no pidfs (old kernel), 1 = pidfs present. */
static int probe_pidfs(void) {
        static int have = -1;
        int fd, ok;
        struct statfs sfs;

        if (have >= 0)
                return have;

        fd = raw_pidfd_open(getpid(), 0);
        if (fd < 0)
                return (have = 0);

        ok = fstatfs(fd, &sfs) == 0 && (long) sfs.f_type == (long) PID_FS_MAGIC;
        close(fd);
        return (have = ok ? 1 : 0);
}

int sd_pidfd_get_inode_id(int pidfd, uint64_t *ret) {
        struct statfs sfs;
        struct statx stx;

        if (pidfd < 0)
                return -EBADF;
        if (!ret)
                return -EINVAL;

        if (!probe_pidfs())
                return -EOPNOTSUPP;

        if (fstatfs(pidfd, &sfs) < 0)
                return -errno;
        if ((long) sfs.f_type != (long) PID_FS_MAGIC)
                /* pidfs definitely exists (probe_pidfs() said so); this fd
                 * is just the wrong kind. */
                return -EBADF;

        if (statx(pidfd, "", AT_EMPTY_PATH, STATX_INO, &stx) < 0)
                return -errno;

        *ret = stx.stx_ino;
        return 0;
}

/* Cached like probe_pidfs(). r < 0 means "couldn't get one" (old kernel,
 * most likely); sd_listen_fds() then ignores LISTEN_PIDFDID. */
static int own_pidfd_inode_id(uint64_t *ret) {
        static uint64_t cached_id;
        static int cached_r = 1; /* 1 = not yet computed (never a real errno) */
        int fd;

        if (cached_r <= 0) {
                if (cached_r == 0)
                        *ret = cached_id;
                return cached_r;
        }

        fd = raw_pidfd_open(getpid(), 0);
        if (fd < 0)
                return (cached_r = -errno);

        cached_r = sd_pidfd_get_inode_id(fd, &cached_id);
        close(fd);
        if (cached_r == 0)
                *ret = cached_id;
        return cached_r;
}

/* ---------------------------------------------------------------------
 * sd_listen_fds() / sd_listen_fds_with_names()
 * --------------------------------------------------------------------- */

static void unsetenv_listen(bool unset_environment) {
        if (!unset_environment)
                return;

        unsetenv("LISTEN_PID");
        unsetenv("LISTEN_PIDFDID");
        unsetenv("LISTEN_FDS");
        unsetenv("LISTEN_FDNAMES");
}

int sd_listen_fds(int unset_environment) {
        const char *e;
        pid_t pid;
        int fd, n, r;

        e = getenv("LISTEN_PID");
        if (!e) {
                r = 0;
                goto finish;
        }

        r = parse_strict_pid(e, &pid);
        if (r < 0)
                goto finish;

        if (getpid() != pid) {
                r = 0;
                goto finish;
        }

        /* pico-init's producer never sets LISTEN_PIDFDID; this guards against
         * a foreign init reusing a pid. */
        e = getenv("LISTEN_PIDFDID");
        if (e) {
                uint64_t want, have = 0;

                r = parse_strict_u64(e, &want);
                if (r < 0)
                        goto finish;

                if (own_pidfd_inode_id(&have) >= 0 && have != want) {
                        r = 0;
                        goto finish;
                }
        }

        e = getenv("LISTEN_FDS");
        if (!e) {
                r = 0;
                goto finish;
        }

        r = parse_strict_int(e, &n);
        if (r < 0)
                goto finish;

        /* backport 046c93f8db: v30 cast this straight to (int) with no
         * overflow check at all. */
        if (n <= 0 || n > INT_MAX - SD_LISTEN_FDS_START) {
                r = -EINVAL;
                goto finish;
        }

        /* service-exec.c clears FD_CLOEXEC before execve() so the fds survive
         * it; the sd-daemon.h contract says to re-arm it here. */
        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
                int flags = fcntl(fd, F_GETFD);

                if (flags < 0) {
                        r = -errno;
                        goto finish;
                }
                if (!(flags & FD_CLOEXEC) && fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0) {
                        r = -errno;
                        goto finish;
                }
        }

        r = n;

finish:
        unsetenv_listen(unset_environment);
        return r;
}

/* Splits on ':' without coalescing adjacent separators, so "a::b" is three
 * fields ("a", "", "b") and "" itself is one field (""). Mirrors real
 * systemd's strv_split_full(..., EXTRACT_DONT_COALESCE_SEPARATORS) contract
 * without linking anything of its own -- this shim owns no strv library. */
static int split_colon_keep_empty(const char *s, char ***ret, int *ret_n) {
        char **v = NULL;
        int n = 0;
        const char *start = s;

        for (;;) {
                const char *p = strchr(start, ':');
                size_t len = p ? (size_t) (p - start) : strlen(start);
                char **nv;
                char *field;

                field = malloc(len + 1);
                if (!field)
                        goto oom;
                memcpy(field, start, len);
                field[len] = '\0';

                nv = realloc(v, (size_t) (n + 2) * sizeof(char *));
                if (!nv) {
                        free(field);
                        goto oom;
                }
                v = nv;
                v[n++] = field;
                v[n] = NULL;

                if (!p)
                        break;
                start = p + 1;
        }

        *ret = v;
        *ret_n = n;
        return 0;

oom:
        for (int i = 0; i < n; i++)
                free(v[i]);
        free(v);
        return -ENOMEM;
}

int sd_listen_fds_with_names(int unset_environment, char ***ret_names) {
        const char *e;
        char *raw = NULL;
        char **names = NULL;
        int n_fds, n_names = 0, r;

        if (!ret_names)
                return sd_listen_fds(unset_environment);

        /* Copy LISTEN_FDNAMES before sd_listen_fds() runs, as it may unset it
         * and the getenv() pointer would not survive that. */
        e = getenv("LISTEN_FDNAMES");
        if (e) {
                raw = strdup(e);
                if (!raw) {
                        /* Still unset the environment before reporting OOM. */
                        (void) sd_listen_fds(unset_environment);
                        return -ENOMEM;
                }
        }

        n_fds = sd_listen_fds(unset_environment);
        if (n_fds <= 0) {
                free(raw);
                return n_fds;
        }

        /*
         * pico-init's build_exec_envp() (service-exec.c) scrubs LISTEN_FDNAMES
         * and never re-exports it, so `raw == NULL` is the normal case here;
         * the split path serves other producers.
         */
        if (raw) {
                r = split_colon_keep_empty(raw, &names, &n_names);
                free(raw);
                if (r < 0)
                        return r;

                if (n_names != n_fds) {
                        for (int i = 0; i < n_names; i++)
                                free(names[i]);
                        free(names);
                        return -EINVAL;
                }
        } else {
                names = calloc((size_t) n_fds + 1, sizeof(char *));
                if (!names)
                        return -ENOMEM;
                for (int i = 0; i < n_fds; i++) {
                        names[i] = strdup("unknown");
                        if (!names[i]) {
                                for (int j = 0; j < i; j++)
                                        free(names[j]);
                                free(names);
                                return -ENOMEM;
                        }
                }
        }

        *ret_names = names;
        return n_fds;
}

/* ---------------------------------------------------------------------
 * sd_is_fifo() / sd_is_special() / sd_is_socket*() / sd_is_mq()
 *
 * Pure kernel introspection -- none of these care whether pico-init or any
 * other init started the process. Quarry shape: v30 src/sd-daemon.c, same
 * logic in current systemd.
 * --------------------------------------------------------------------- */

int sd_is_fifo(int fd, const char *path) {
        struct stat st_fd;

        if (fd < 0)
                return -EBADF;

        if (fstat(fd, &st_fd) < 0)
                return -errno;
        if (!S_ISFIFO(st_fd.st_mode))
                return 0;

        if (path) {
                struct stat st_path;

                if (stat(path, &st_path) < 0)
                        return (errno == ENOENT || errno == ENOTDIR) ? 0 : -errno;

                return st_path.st_dev == st_fd.st_dev && st_path.st_ino == st_fd.st_ino;
        }

        return 1;
}

int sd_is_special(int fd, const char *path) {
        struct stat st_fd;

        if (fd < 0)
                return -EBADF;

        if (fstat(fd, &st_fd) < 0)
                return -errno;
        if (!S_ISREG(st_fd.st_mode) && !S_ISCHR(st_fd.st_mode))
                return 0;

        if (path) {
                struct stat st_path;

                if (stat(path, &st_path) < 0)
                        return (errno == ENOENT || errno == ENOTDIR) ? 0 : -errno;

                if (S_ISREG(st_fd.st_mode) && S_ISREG(st_path.st_mode))
                        return st_path.st_dev == st_fd.st_dev && st_path.st_ino == st_fd.st_ino;
                if (S_ISCHR(st_fd.st_mode) && S_ISCHR(st_path.st_mode))
                        return st_path.st_rdev == st_fd.st_rdev;

                return 0;
        }

        return 1;
}

static int is_socket_internal(int fd, int type, int listening) {
        struct stat st;
        socklen_t l;

        if (fd < 0)
                return -EBADF;
        if (type < 0)
                return -EINVAL;

        if (fstat(fd, &st) < 0)
                return -errno;
        if (!S_ISSOCK(st.st_mode))
                return 0;

        if (type != 0) {
                int other_type = 0;

                l = sizeof(other_type);
                if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &other_type, &l) < 0)
                        return -errno;
                if (l != sizeof(other_type))
                        return -EINVAL;
                if (other_type != type)
                        return 0;
        }

        if (listening >= 0) {
                int accepting = 0;

                l = sizeof(accepting);
                if (getsockopt(fd, SOL_SOCKET, SO_ACCEPTCONN, &accepting, &l) < 0)
                        return -errno;
                if (l != sizeof(accepting))
                        return -EINVAL;
                if (!accepting != !listening)
                        return 0;
        }

        return 1;
}

int sd_is_socket(int fd, int family, int type, int listening) {
        struct sockaddr_storage sa;
        socklen_t l;
        int r;

        if (family < 0)
                return -EINVAL;

        r = is_socket_internal(fd, type, listening);
        if (r <= 0)
                return r;

        if (family > 0) {
                l = sizeof(sa);
                if (getsockname(fd, (struct sockaddr *) &sa, &l) < 0)
                        return -errno;
                if (l < sizeof(sa_family_t))
                        return -EINVAL;

                return sa.ss_family == family;
        }

        return 1;
}

int sd_is_socket_inet(int fd, int family, int type, int listening, uint16_t port) {
        struct sockaddr_storage sa;
        socklen_t l;
        int r;

        if (family != 0 && family != AF_INET && family != AF_INET6)
                return -EINVAL;

        r = is_socket_internal(fd, type, listening);
        if (r <= 0)
                return r;

        l = sizeof(sa);
        if (getsockname(fd, (struct sockaddr *) &sa, &l) < 0)
                return -errno;
        if (l < sizeof(sa_family_t))
                return -EINVAL;
        if (sa.ss_family != AF_INET && sa.ss_family != AF_INET6)
                return 0;
        if (family > 0 && sa.ss_family != (sa_family_t) family)
                return 0;

        if (port > 0) {
                if (sa.ss_family == AF_INET) {
                        const struct sockaddr_in *in = (const struct sockaddr_in *) &sa;

                        if (l < sizeof(struct sockaddr_in))
                                return -EINVAL;
                        return ntohs(in->sin_port) == port;
                } else {
                        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *) &sa;

                        if (l < sizeof(struct sockaddr_in6))
                                return -EINVAL;
                        return ntohs(in6->sin6_port) == port;
                }
        }

        return 1;
}

/* Added upstream by f6f372d2f4 ("Add sd_is_socket_sockaddr (#4885)"); no
 * v30 shape to quarry, reimplemented straight from the current header's
 * documented semantics. */
int sd_is_socket_sockaddr(int fd, int type, const struct sockaddr *addr, unsigned addr_len, int listening) {
        struct sockaddr_storage sa;
        socklen_t l;
        int r;

        if (fd < 0)
                return -EBADF;
        if (!addr)
                return -EINVAL;
        if (addr_len < sizeof(sa_family_t))
                return -ENOBUFS;
        if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
                return -EPFNOSUPPORT;

        r = is_socket_internal(fd, type, listening);
        if (r <= 0)
                return r;

        l = sizeof(sa);
        if (getsockname(fd, (struct sockaddr *) &sa, &l) < 0)
                return -errno;
        if (l < sizeof(sa_family_t))
                return -EINVAL;
        if (sa.ss_family != addr->sa_family)
                return 0;

        if (sa.ss_family == AF_INET) {
                const struct sockaddr_in *want = (const struct sockaddr_in *) addr;
                const struct sockaddr_in *have = (const struct sockaddr_in *) &sa;

                if (l < sizeof(struct sockaddr_in) || addr_len < sizeof(struct sockaddr_in))
                        return -EINVAL;
                if (want->sin_port != 0 && have->sin_port != want->sin_port)
                        return 0;

                return have->sin_addr.s_addr == want->sin_addr.s_addr;
        } else {
                const struct sockaddr_in6 *want = (const struct sockaddr_in6 *) addr;
                const struct sockaddr_in6 *have = (const struct sockaddr_in6 *) &sa;

                if (l < sizeof(struct sockaddr_in6) || addr_len < sizeof(struct sockaddr_in6))
                        return -EINVAL;
                if (want->sin6_port != 0 && have->sin6_port != want->sin6_port)
                        return 0;
                if (want->sin6_flowinfo != 0 && have->sin6_flowinfo != want->sin6_flowinfo)
                        return 0;
                if (want->sin6_scope_id != 0 && have->sin6_scope_id != want->sin6_scope_id)
                        return 0;

                return memcmp(have->sin6_addr.s6_addr,
                              want->sin6_addr.s6_addr,
                              sizeof(want->sin6_addr.s6_addr)) == 0;
        }
}

int sd_is_socket_unix(int fd, int type, int listening, const char *path, size_t length) {
        struct sockaddr_un sun;
        socklen_t l;
        int r;

        r = is_socket_internal(fd, type, listening);
        if (r <= 0)
                return r;

        l = sizeof(sun);
        if (getsockname(fd, (struct sockaddr *) &sun, &l) < 0)
                return -errno;
        if (l < sizeof(sa_family_t))
                return -EINVAL;
        if (sun.sun_family != AF_UNIX)
                return 0;

        if (path) {
                if (length == 0)
                        length = strlen(path);
                if (length == 0) /* unnamed socket */
                        return l == offsetof(struct sockaddr_un, sun_path);

                if (path[0] != '\0') /* pathname socket -- pico's socket units bind these */
                        return (l >= offsetof(struct sockaddr_un, sun_path) + length + 1) &&
                                        memcmp(path, sun.sun_path, length + 1) == 0;

                /* abstract namespace: caller's path[0] is the leading NUL,
                 * length counts it */
                return (l == offsetof(struct sockaddr_un, sun_path) + length) &&
                                memcmp(path, sun.sun_path, length) == 0;
        }

        return 1;
}

int sd_is_mq(int fd, const char *path) {
        struct mq_attr attr;

        if (fcntl(fd, F_GETFD) < 0)
                return -EBADF;

        if (mq_getattr(fd, &attr) < 0)
                /* A valid fd (checked above) that just isn't an mq. */
                return (errno == EBADF) ? 0 : -errno;

        if (path) {
                struct stat a, b;
                char fpath[PATH_MAX];
                int n;

                if (path[0] != '/')
                        return -EINVAL;

                if (fstat(fd, &a) < 0)
                        return -errno;

                /* mq names always start with '/' already, so a plain
                 * concat is the real path under the mqueue pseudo-fs. */
                n = snprintf(fpath, sizeof(fpath), "/dev/mqueue%s", path);
                if (n < 0 || (size_t) n >= sizeof(fpath))
                        return -ENAMETOOLONG;

                if (stat(fpath, &b) < 0)
                        return -errno;

                if (a.st_dev != b.st_dev || a.st_ino != b.st_ino)
                        return 0;
        }

        return 1;
}

/* ---------------------------------------------------------------------
 * sd_notify() family.
 *
 * Narrower than current systemd, which also handles AF_VSOCK and
 * SOCK_STREAM/SOCK_SEQPACKET NOTIFY_SOCKET values: pico's listener
 * (manager-notify.c) is AF_UNIX SOCK_DGRAM only, so any other address is
 * -EINVAL.
 * --------------------------------------------------------------------- */

static void unsetenv_notify(bool unset_environment) {
        if (unset_environment)
                unsetenv("NOTIFY_SOCKET");
}

/*
 * Shared sender for every sd_*notify*() entry point. fds/n_fds is not the
 * FDSTORE=1 mechanism -- the only internal callers ever pass n_fds <= 1 (the
 * barrier's own synchronization pipe); sd_pid_notify_with_fds() and
 * sd_pid_notifyf_with_fds() gate n_fds > 0 to -EOPNOTSUPP themselves,
 * *before* ever calling this, so a real fd-store request never reaches this
 * function at all.
 */
static int notify_internal(pid_t pid, const char *state, const int *fds, unsigned n_fds) {
        const char *e;
        size_t e_len, state_len;
        struct sockaddr_un sun;
        struct iovec iovec;
        struct msghdr msghdr;
        bool send_ucred;
        union {
                char buf[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct ucred))];
                struct cmsghdr align;
        } control;
        int fd, saved_errno;
        ssize_t n;

        if (!state)
                return -EINVAL;

        e = getenv("NOTIFY_SOCKET");
        if (!e || e[0] == '\0')
                return 0;

        /* AF_UNIX only -- must be an absolute path or an abstract-namespace
         * '@' address. */
        if ((e[0] != '/' && e[0] != '@') || e[1] == '\0')
                return -EINVAL;

        e_len = strlen(e);
        /* backport 638b56cd3c: fail instead of silently truncating onto the
         * wrong socket. */
        if (e_len > sizeof(sun.sun_path))
                return -EINVAL;

        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        memset(&sun, 0, sizeof(sun));
        sun.sun_family = AF_UNIX;
        memcpy(sun.sun_path, e, e_len);
        if (sun.sun_path[0] == '@')
                sun.sun_path[0] = '\0';

        state_len = strlen(state);
        iovec.iov_base = (void *) state;
        iovec.iov_len = state_len;

        memset(&msghdr, 0, sizeof(msghdr));
        msghdr.msg_name = &sun;
        msghdr.msg_namelen = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + e_len);
        msghdr.msg_iov = &iovec;
        msghdr.msg_iovlen = 1;

        /* manager-notify.c attributes senders via SCM_CREDENTIALS; the kernel
         * enforces who may claim which pid. */
        send_ucred = pid != 0 && pid != getpid();

        if (n_fds > 0 || send_ucred) {
                struct cmsghdr *cmsg;
                socklen_t controllen = 0;

                if (n_fds > 0)
                        controllen += CMSG_SPACE(sizeof(int) * n_fds);
                if (send_ucred)
                        controllen += CMSG_SPACE(sizeof(struct ucred));

                memset(&control, 0, sizeof(control));
                msghdr.msg_control = control.buf;
                msghdr.msg_controllen = controllen;

                cmsg = CMSG_FIRSTHDR(&msghdr);
                if (n_fds > 0) {
                        cmsg->cmsg_level = SOL_SOCKET;
                        cmsg->cmsg_type = SCM_RIGHTS;
                        cmsg->cmsg_len = CMSG_LEN(sizeof(int) * n_fds);
                        memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * n_fds);
                        if (send_ucred)
                                cmsg = CMSG_NXTHDR(&msghdr, cmsg);
                }
                if (send_ucred && cmsg) {
                        struct ucred cred;

                        cred.pid = pid;
                        cred.uid = getuid();
                        cred.gid = getgid();

                        cmsg->cmsg_level = SOL_SOCKET;
                        cmsg->cmsg_type = SCM_CREDENTIALS;
                        cmsg->cmsg_len = CMSG_LEN(sizeof(cred));
                        memcpy(CMSG_DATA(cmsg), &cred, sizeof(cred));
                }
        } else {
                msghdr.msg_control = NULL;
                msghdr.msg_controllen = 0;
        }

        n = sendmsg(fd, &msghdr, MSG_NOSIGNAL);
        if (n < 0 && send_ucred) {
                /* Claiming a foreign pid's SCM_CREDENTIALS is subject to
                 * kernel ownership rules and can fail on permissions alone
                 * -- retry once attributing as ourselves, dropping only the
                 * trailing ucred cmsg and keeping any fd cmsg (the
                 * barrier's token) intact. */
                msghdr.msg_controllen -= CMSG_SPACE(sizeof(struct ucred));
                if (msghdr.msg_controllen == 0)
                        msghdr.msg_control = NULL;
                n = sendmsg(fd, &msghdr, MSG_NOSIGNAL);
        }

        if (n < 0) {
                saved_errno = errno;
                close(fd);
                return -saved_errno;
        }

        close(fd);

        if ((size_t) n < state_len)
                return -EIO;

        return 1;
}

int sd_notify(int unset_environment, const char *state) {
        int r = notify_internal(0, state, NULL, 0);

        unsetenv_notify(unset_environment);
        return r;
}

int sd_notifyf(int unset_environment, const char *format, ...) {
        char *p = NULL;
        int r;

        if (format) {
                va_list ap;

                va_start(ap, format);
                r = vasprintf(&p, format, ap);
                va_end(ap);

                if (r < 0) {
                        /* vasprintf() leaves *strp undefined on failure --
                         * do not touch p, and still perform the unsetenv
                         * step (backport 362dcfc5db's second half: an
                         * early return here must never skip it). */
                        unsetenv_notify(unset_environment);
                        return -ENOMEM;
                }
        }

        r = notify_internal(0, p, NULL, 0);
        free(p);

        unsetenv_notify(unset_environment);
        return r;
}

int sd_pid_notify(pid_t pid, int unset_environment, const char *state) {
        int r = notify_internal(pid, state, NULL, 0);

        unsetenv_notify(unset_environment);
        return r;
}

int sd_pid_notifyf(pid_t pid, int unset_environment, const char *format, ...) {
        char *p = NULL;
        int r;

        if (format) {
                va_list ap;

                va_start(ap, format);
                r = vasprintf(&p, format, ap);
                va_end(ap);

                if (r < 0) {
                        unsetenv_notify(unset_environment);
                        return -ENOMEM;
                }
        }

        r = notify_internal(pid, p, NULL, 0);
        free(p);

        unsetenv_notify(unset_environment);
        return r;
}

/*
 * fds/n_fds exist only for FDSTORE=1, and pico-init has no fd store
 * (manager-notify.c closes any fd it receives). Returning 1 would make the
 * caller close its copies expecting them back after a restart, so this is
 * -EOPNOTSUPP and the daemon can keep them itself.
 */
int sd_pid_notify_with_fds(pid_t pid, int unset_environment, const char *state, const int *fds, unsigned n_fds) {
        int r;

        if (n_fds > 0)
                r = fds ? -EOPNOTSUPP : -EINVAL;
        else
                r = notify_internal(pid, state, NULL, 0);

        unsetenv_notify(unset_environment);
        return r;
}

/* Same split as sd_pid_notify_with_fds() above, plus vasprintf handling.
 * The argument order (fds before format) and n_fds's width (size_t here,
 * unsigned above) match the upstream header. */
int sd_pid_notifyf_with_fds(
                pid_t pid, int unset_environment, const int *fds, size_t n_fds, const char *format, ...) {
        char *p = NULL;
        int r;

        if (format) {
                va_list ap;

                va_start(ap, format);
                r = vasprintf(&p, format, ap);
                va_end(ap);

                if (r < 0) {
                        unsetenv_notify(unset_environment);
                        return -ENOMEM;
                }
        }

        if (n_fds > 0)
                r = fds ? -EOPNOTSUPP : -EINVAL;
        else
                r = notify_internal(pid, p, NULL, 0);

        free(p);
        unsetenv_notify(unset_environment);
        return r;
}

/*
 * The fd is a synchronization token consumed at delivery, not FDSTORE=1.
 * AF_UNIX SOCK_DGRAM delivers in order, and a receiver whose recvmsg() has
 * no SCM_RIGHTS buffer space makes the kernel close the fd, so the write end
 * dies once every earlier datagram has been consumed: "synchronize against
 * consumption, not processing". Works with manager-notify.c unchanged.
 * Upstream: 4f07ddfa9b/0de3431871.
 */
int sd_pid_notify_barrier(pid_t pid, int unset_environment, uint64_t timeout) {
        int pipe_fd[2];
        struct pollfd pfd;
        struct timespec ts, *tsp;
        int r, saved_errno = 0;

        if (pipe2(pipe_fd, O_CLOEXEC) < 0) {
                r = -errno;
                unsetenv_notify(unset_environment);
                return r;
        }

        r = notify_internal(pid, "BARRIER=1", &pipe_fd[1], 1);
        close(pipe_fd[1]);

        if (r <= 0) {
                close(pipe_fd[0]);
                unsetenv_notify(unset_environment);
                return r;
        }

        /* timeout is microseconds; UINT64_MAX means wait forever. ppoll()'s
         * nanosecond-precision timespec avoids the truncate-to-zero a
         * millisecond poll() timeout would risk on a sub-millisecond
         * value. */
        if (timeout == UINT64_MAX)
                tsp = NULL;
        else {
                ts.tv_sec = (time_t) (timeout / 1000000ULL);
                ts.tv_nsec = (long) ((timeout % 1000000ULL) * 1000ULL);
                tsp = &ts;
        }

        pfd.fd = pipe_fd[0];
        pfd.events = 0; /* POLLHUP/POLLERR are always reported */
        pfd.revents = 0;

        do {
                r = ppoll(&pfd, 1, tsp, NULL);
        } while (r < 0 && errno == EINTR);
        if (r < 0)
                saved_errno = errno;

        close(pipe_fd[0]);
        unsetenv_notify(unset_environment);

        if (r < 0)
                return -saved_errno;
        if (r == 0)
                return -ETIMEDOUT;

        return 1;
}

int sd_notify_barrier(int unset_environment, uint64_t timeout) {
        return sd_pid_notify_barrier(0, unset_environment, timeout);
}

/* ---------------------------------------------------------------------
 * sd_booted()
 * --------------------------------------------------------------------- */

int sd_booted(void) {
        /*
         * Mirrors PICO_RUNTIME_DIR (src/manager.h), duplicated because this
         * library must not include PID 1's headers.
         *
         * manager_ctrl_setup() creates this directory early in
         * manager_startup(), before any unit starts, and /run is a fresh
         * tmpfs, so it exists only for the current boot. Upstream made the
         * same move from a cgroup-hierarchy check to /run/systemd/system/ in
         * 66e411811b.
         *
         * /run/systemd/system is not created here: "booted with systemd"
         * would be false, as pico-init has none of the D-Bus/systemctl
         * surface a caller checking that path might assume.
         */
        static const char pico_runtime_dir[] = "/run/pico-init/";

        /* trailing slash forces directory-ness */
        if (faccessat(AT_FDCWD, pico_runtime_dir, F_OK, AT_SYMLINK_NOFOLLOW) == 0)
                return 1;

        /* backport 21042737f0: report an unexpected error as -errno rather
         * than a false "not booted". manager_startup() treats a failed
         * mkdir as non-fatal (read-only /run), in which case this returns 0,
         * as upstream's check does. */
        if (errno == ENOENT || errno == ENOTDIR)
                return 0;

        return -errno;
}

/* ---------------------------------------------------------------------
 * sd_watchdog_enabled()
 *
 * Fully client-side protocol. pico-init sets neither WATCHDOG_USEC nor
 * WATCHDOG_PID, so this returns 0 for its services.
 * --------------------------------------------------------------------- */

int sd_watchdog_enabled(int unset_environment, uint64_t *usec) {
        const char *s, *p;
        uint64_t u;
        pid_t pid;
        int r;

        s = getenv("WATCHDOG_USEC");
        if (!s) {
                r = 0;
                goto finish;
        }

        r = parse_strict_u64(s, &u);
        if (r < 0)
                goto finish;

        /* backport caffe412c77: reject a -1/infinity timeout outright
         * instead of handing the caller a nonsense interval. */
        if (u == 0 || u == UINT64_MAX) {
                r = -EINVAL;
                goto finish;
        }

        p = getenv("WATCHDOG_PID");
        if (p) {
                r = parse_strict_pid(p, &pid);
                if (r < 0)
                        goto finish;

                if (getpid() != pid) {
                        r = 0;
                        goto finish;
                }
        }

        if (usec)
                *usec = u;
        r = 1;

finish:
        if (unset_environment) {
                unsetenv("WATCHDOG_USEC");
                unsetenv("WATCHDOG_PID");
        }
        return r;
}
