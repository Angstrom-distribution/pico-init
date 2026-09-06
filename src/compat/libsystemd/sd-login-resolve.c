/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* struct ucred (SO_PEERCRED) is a GNU/glibc extension; -std=gnu17 alone
 * does not imply _GNU_SOURCE (same reasoning src/socket.c already gives
 * for accept4(), and sd-daemon.c for vasprintf()/pipe2()/ppoll()), so
 * this has to be explicit and first. */
#define _GNU_SOURCE

#include "sd-login-resolve.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* /proc/<pid>/cgroup is always tiny (one "N::path" line per controller
 * hierarchy, one line total under the unified v2 hierarchy this project
 * targets); this cap is a defensive backstop against a pathological
 * /proc, not a real limit -- see conf-scan.h's own "unbounded getline()"
 * note for why this project bounds reads like this on principle. */
#define CGROUP_FILE_MAX 65536

static int read_whole_file(const char *path, char **ret) {
        int fd;
        char *buf = NULL;
        size_t len = 0, cap = 0;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;

        for (;;) {
                ssize_t n;

                if (len == cap) {
                        size_t new_cap = cap ? cap * 2 : 4096;
                        char *grown;

                        if (new_cap > CGROUP_FILE_MAX)
                                new_cap = CGROUP_FILE_MAX;
                        if (new_cap == cap) /* already at the cap */
                                break;

                        grown = realloc(buf, new_cap + 1);
                        if (!grown) {
                                free(buf);
                                close(fd);
                                return -ENOMEM;
                        }
                        buf = grown;
                        cap = new_cap;
                }

                n = read(fd, buf + len, cap - len);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;
                        free(buf);
                        close(fd);
                        return -errno;
                }
                if (n == 0)
                        break;
                len += (size_t) n;
        }

        close(fd);

        if (!buf) {
                buf = malloc(1);
                if (!buf)
                        return -ENOMEM;
        }
        buf[len] = '\0';

        *ret = buf;
        return 0;
}

/* ENOENT -> -ESRCH: "process does not exist" is sd-login.c's own errno
 * contract for a pid that has already gone away (HEAD ded83144 :30-36).
 * Any other open()/read() failure passes its errno straight through. */
static int read_proc_cgroup(pid_t pid, char **ret_content) {
        char path[64];
        int r;

        snprintf(path, sizeof path, "/proc/%d/cgroup", (int) pid);

        r = read_whole_file(path, ret_content);
        if (r == -ENOENT)
                return -ESRCH;
        return r;
}

/* Real pidfd_get_pid()'s own contract: -1 means the pid has been reaped
 * (the pidfd outlived it), 0 means it lives in a pid namespace this
 * process cannot see into. Neither is this project's invention. */
static int pidfd_get_pid(int pidfd, pid_t *ret) {
        char path[64];
        char *content;
        const char *field; /* points at the 'P' of "Pid:" within content */
        int r;
        long val;

        if (pidfd < 0)
                return -EBADF;

        snprintf(path, sizeof path, "/proc/self/fdinfo/%d", pidfd);
        r = read_whole_file(path, &content);
        if (r < 0)
                return r == -ENOMEM ? r : -EBADF; /* "unopenable" per the design contract */

        if (strncmp(content, "Pid:", 4) == 0)
                field = content;
        else {
                const char *nl = strstr(content, "\nPid:");
                field = nl ? nl + 1 : NULL;
        }
        if (!field) {
                free(content);
                return -EBADF;
        }

        val = strtol(field + strlen("Pid:"), NULL, 10);
        free(content);

        if (val == -1)
                return -ESRCH;
        if (val == 0)
                return -EREMOTE;

        *ret = (pid_t) val;
        return 0;
}

int login_resolve_pid(pid_t pid, pid_t *ret_pid, char **ret_cgroup_content) {
        char *content;
        int r;

        if (pid < 0)
                return -EINVAL;
        if (pid == 0)
                pid = getpid();

        r = read_proc_cgroup(pid, &content);
        if (r < 0)
                return r;

        *ret_pid = pid;
        *ret_cgroup_content = content;
        return 0;
}

int login_resolve_pidfd(int pidfd, pid_t *ret_pid, char **ret_cgroup_content) {
        pid_t first, second;
        char *content;
        int r;

        r = pidfd_get_pid(pidfd, &first);
        if (r < 0)
                return r;

        r = read_proc_cgroup(first, &content);
        if (r < 0)
                return r;

        /* Close the recycle race pidfd-based lookups exist to avoid: the
         * pid could have exited and been reused by the time the cgroup
         * read above completed. */
        r = pidfd_get_pid(pidfd, &second);
        if (r < 0) {
                free(content);
                return r;
        }
        if (second != first) {
                free(content);
                return -ESRCH;
        }

        *ret_pid = first;
        *ret_cgroup_content = content;
        return 0;
}

int login_resolve_peer(int fd, pid_t *ret_pid, char **ret_cgroup_content) {
        struct ucred cred;
        socklen_t len = sizeof cred;
        char *content;
        int r;

        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) < 0)
                return -errno;
        if (cred.pid == 0)
                return -ENODATA;

        r = read_proc_cgroup(cred.pid, &content);
        if (r < 0)
                return r;

        *ret_pid = cred.pid;
        *ret_cgroup_content = content;
        return 0;
}
