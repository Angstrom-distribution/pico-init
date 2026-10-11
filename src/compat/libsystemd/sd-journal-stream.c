/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_journal_stream_fd(): connects to logd's stdout socket, the
 * /run/logd/stdout path that services' stdout/stderr are wired to
 * (src/logd/logd.h, src/service-exec.c). The abstract source address bound
 * before connect() is the stream identity logd keys its fragment table on
 * (logd-recv.c find_or_create_stream()); it gives every returned fd its own
 * line-reassembly stream with correct ucred attribution.
 *
 * Limitations: logd's stdout path records PRIORITY=6 unconditionally (no
 * per-stream handshake), so `priority` (beyond validation) and `identifier`
 * are not transported; _COMM from SCM_CREDENTIALS identifies the sender. With
 * level_prefix=1, "<N>" line prefixes are recorded literally in MESSAGE
 * instead of being interpreted as upstream's journald-stream.c does.
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

        /* sun_path[0] is left '\0' by the initializer: an abstract-namespace
         * address (unix(7)). */
        name_len = snprintf(
                        local.sun_path + 1,
                        sizeof(local.sun_path) - 1,
                        "picoinit-jstream-%d-%u",
                        (int) getpid(),
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

int sd_journal_stream_fd_with_namespace(
                const char *name_space, const char *identifier, int priority, int level_prefix) {
        if (name_space)
                return -EOPNOTSUPP; /* pico has no log namespaces to cross-wire a caller into */

        return sd_journal_stream_fd(identifier, priority, level_prefix);
}
