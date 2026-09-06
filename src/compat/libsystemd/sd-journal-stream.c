/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_journal_stream_fd(): real, via logd's OTHER socket -- the same
 * /run/logd/stdout path pico services' own stdout/stderr are wired to
 * (src/logd/logd.h, src/service-exec.c). The bound abstract source address
 * this connects from is the actual stream identity logd's fragment table
 * keys on (logd-recv.c find_or_create_stream()); it comes for free by
 * binding before connect(), and is what gives every returned fd its own
 * line-reassembly stream with correct ucred attribution.
 *
 * Documented degradation: logd's stdout receive path records PRIORITY=6
 * unconditionally (there is no per-stream handshake to say otherwise), so
 * `priority` beyond validation and `identifier` are not transported --
 * _COMM (from the kernel-verified SCM_CREDENTIALS) serves as the real
 * identifier instead. A level_prefix=1 caller's "<N>" line prefixes are
 * recorded literally in MESSAGE: the data survives, only the interpretation
 * upstream's own journald-stream.c would apply to it does not happen here.
 */

#include "sd-journal.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include "../../logd/logd.h"

int sd_journal_stream_fd(const char *identifier, int priority, int level_prefix) {
        static unsigned counter = 0;
        unsigned n;
        int fd;
        struct sockaddr_un local = { .sun_family = AF_UNIX };
        struct sockaddr_un remote = { .sun_family = AF_UNIX };
        socklen_t local_len;
        int name_len;

        (void) identifier;
        (void) level_prefix;

        if (priority < 0 || priority > 7)
                return -EINVAL;

        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        n = (unsigned) __atomic_fetch_add(&counter, 1, __ATOMIC_RELAXED);

        /* sun_path[0] left '\0' by the initializer above: an abstract-
         * namespace address, unforgeable by anything that isn't this
         * process (see sun_path's leading NUL, unix(7)). */
        name_len = snprintf(local.sun_path + 1, sizeof(local.sun_path) - 1, "picoinit-jstream-%d-%u", (int) getpid(),
                             n);
        if (name_len < 0 || (size_t) name_len >= sizeof(local.sun_path) - 1) {
                close(fd);
                return -EINVAL;
        }
        local_len = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + 1 + (size_t) name_len);

        if (bind(fd, (struct sockaddr *) &local, local_len) < 0) {
                int r = -errno;

                close(fd);
                return r;
        }

        strncpy(remote.sun_path, LOGD_STDOUT_SOCKET_PATH, sizeof(remote.sun_path) - 1);
        if (connect(fd, (struct sockaddr *) &remote, sizeof(remote)) < 0) {
                int r = -errno;

                close(fd);
                return r;
        }

        if (shutdown(fd, SHUT_RD) < 0) {
                int r = -errno;

                close(fd);
                return r;
        }

        return fd;
}

int sd_journal_stream_fd_with_namespace(const char *name_space, const char *identifier, int priority,
                                         int level_prefix) {
        if (name_space)
                return -EOPNOTSUPP; /* pico has no log namespaces to cross-wire a caller into */

        return sd_journal_stream_fd(identifier, priority, level_prefix);
}
