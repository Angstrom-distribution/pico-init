/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The uevent socket and its parser. devd-uevent.h has the three deltas from
 * netd's rtnetlink socket and why the sender check is not optional.
 */

#include "devd-uevent.h"

#include <errno.h>
#include <limits.h>
#include <linux/netlink.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../util.h"

/*
 * Matching NETD_RTNL_RCVBUF's reasoning: uevents arrive in bursts (a disk and
 * every one of its partitions in one go) and the default socket buffer is
 * small enough that a slow reaction can lose the tail of a burst. Best-effort
 * -- a kernel that refuses the size still works, it just resyncs more often.
 */
#define DEVD_UEVENT_RCVBUF (1024 * 1024)

/* The kernel's own broadcast group. Group 2 is udev's rebroadcast; see the
 * header for why devd never listens there. */
#define DEVD_UEVENT_GROUP 1

/* libudev's group-2 messages start with this, and are not kernel uevents. */
#define DEVD_LIBUDEV_MAGIC "libudev"

static const char * const devd_action_table[_DEVD_ACTION_MAX] = {
        [DEVD_ACTION_ADD] = "add",
        [DEVD_ACTION_REMOVE] = "remove",
        [DEVD_ACTION_OTHER] = "other",
};

const char *devd_action_to_string(DevdAction a) {
        if (a < 0 || a >= _DEVD_ACTION_MAX)
                return "invalid";

        return devd_action_table[a];
}

bool devd_uevent_sender_is_kernel(uint32_t nl_pid, uint32_t nl_groups) {
        return nl_pid == 0 && nl_groups != 0;
}

/* Copy `value` into a fixed field, or say it does not fit. A DEVPATH longer
 * than the field is a device devd cannot name, which is a message to drop
 * rather than one to truncate and then act on the wrong device. */
static int field_set(char *field, size_t size, const char *value) {
        size_t len = strlen(value);

        if (len >= size)
                return -ENAMETOOLONG;

        memcpy(field, value, len + 1);
        return 0;
}

static unsigned parse_unsigned(const char *s) {
        unsigned v = 0;

        for (; *s >= '0' && *s <= '9'; s++) {
                if (v > (UINT_MAX - (unsigned) (*s - '0')) / 10)
                        return 0;

                v = v * 10 + (unsigned) (*s - '0');
        }

        return v;
}

int devd_uevent_parse(const char *buf, size_t n, DevdUevent *ret) {
        DevdUevent u;
        const char *at;
        size_t first, off;

        if (!buf || !ret || n == 0)
                return -EINVAL;

        /*
         * Every field below is read as a C string out of `buf`, so the buffer
         * must end in a NUL for that to be safe at all. The kernel always
         * sends one; a message that does not have one did not come from the
         * kernel, and that is the whole check -- refusing it here means the
         * strlen()/strcmp() calls that follow cannot run off the end.
         */
        if (buf[n - 1] != '\0')
                return -EINVAL;

        /* Group-2 libudev messages, rejected by their own magic rather than
         * silently misparsed as a device named "libudev". */
        if (n >= sizeof(DEVD_LIBUDEV_MAGIC) && memcmp(buf, DEVD_LIBUDEV_MAGIC, sizeof(DEVD_LIBUDEV_MAGIC)) == 0)
                return -EINVAL;

        memset(&u, 0, sizeof(u));
        u.action = DEVD_ACTION_OTHER;

        /* The header line: "action@devpath". Both halves are mandatory. */
        first = strlen(buf);
        at = memchr(buf, '@', first);
        if (!at || at == buf || at[1] == '\0')
                return -EINVAL;

        if (strncmp(buf, "add@", 4) == 0)
                u.action = DEVD_ACTION_ADD;
        else if (strncmp(buf, "remove@", 7) == 0)
                u.action = DEVD_ACTION_REMOVE;

        if (field_set(u.devpath, sizeof(u.devpath), at + 1) < 0)
                return -EINVAL;

        /*
         * The properties. ACTION= and DEVPATH= are repeated here by the kernel
         * and deliberately ignored: the header line already said both, and
         * believing the second copy would mean a message could disagree with
         * itself about which device it is.
         */
        for (off = first + 1; off < n; off += strlen(buf + off) + 1) {
                const char *p = buf + off, *eq;
                size_t len = strlen(p);

                if (*p == '\0')
                        continue;

                eq = strchr(p, '=');
                if (!eq)
                        continue;

                /*
                 * Kept verbatim as well as decoded, for the rule engine. The
                 * bound is applied a whole pair at a time: half a KEY=VALUE is
                 * not a property, and a truncated MODALIAS that still matched a
                 * glob would be worse than one that is simply not there.
                 */
                if (u.props_len + len + 1 <= sizeof(u.props)) {
                        memcpy(u.props + u.props_len, p, len + 1);
                        u.props_len += len + 1;
                }

                if (strncmp(p, "SUBSYSTEM=", 10) == 0)
                        (void) field_set(u.subsystem, sizeof(u.subsystem), eq + 1);
                else if (strncmp(p, "DEVNAME=", 8) == 0)
                        (void) field_set(u.devname, sizeof(u.devname), eq + 1);
                else if (strncmp(p, "DEVTYPE=", 8) == 0)
                        (void) field_set(u.devtype, sizeof(u.devtype), eq + 1);
                else if (strncmp(p, "MAJOR=", 6) == 0) {
                        u.major = parse_unsigned(eq + 1);
                        u.have_devno = true;
                } else if (strncmp(p, "MINOR=", 6) == 0)
                        u.minor = parse_unsigned(eq + 1);
                else if (strncmp(p, "PARTN=", 6) == 0)
                        u.partn = parse_unsigned(eq + 1);
        }

        *ret = u;
        return 0;
}

int devd_uevent_open(void) {
        int fd, rcvbuf = DEVD_UEVENT_RCVBUF, group = DEVD_UEVENT_GROUP, e;
        struct sockaddr_nl addr;

        fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
        if (fd < 0)
                return -errno;

        /* Best-effort, exactly as netd treats its own: see the constant. */
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

        memset(&addr, 0, sizeof(addr));
        addr.nl_family = AF_NETLINK;

        /*
         * nl_groups left at 0 and the membership added afterwards, netd's own
         * shape. Subscribing through bind() would work too; doing it with
         * NETLINK_ADD_MEMBERSHIP keeps the group a thing that can be dropped
         * again, and keeps the two sockets in this project looking alike.
         */
        if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
                e = errno;
                goto fail;
        }

        if (setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
                e = errno;
                goto fail;
        }

        return fd;

fail:
        (void) close(fd);
        return -e;
}

int devd_uevent_recv(int fd, DevdUevent *ret) {
        char buf[DEVD_UEVENT_BUF_MAX];
        struct sockaddr_nl sa;
        struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
        struct msghdr msg = {
                .msg_name = &sa,
                .msg_namelen = sizeof(sa),
                .msg_iov = &iov,
                .msg_iovlen = 1,
        };
        ssize_t k;
        int r;

        if (fd < 0 || !ret)
                return -EINVAL;

        memset(&sa, 0, sizeof(sa));

        k = recvmsg(fd, &msg, 0);
        if (k < 0)
                return -errno;

        if (msg.msg_namelen != sizeof(sa)) {
                pico_log(PICO_LOG_WARNING, "devd: uevent from an address of the wrong size, dropped");
                return 0;
        }

        if (!devd_uevent_sender_is_kernel(sa.nl_pid, sa.nl_groups)) {
                /* The reason this check exists. Worth a line every time: an
                 * unprivileged process aiming forged uevents at devd is not
                 * something to notice only in aggregate. */
                pico_log(PICO_LOG_WARNING,
                         "devd: uevent from pid %u groups %u is not the kernel, dropped",
                         (unsigned) sa.nl_pid,
                         (unsigned) sa.nl_groups);
                return 0;
        }

        if (msg.msg_flags & MSG_TRUNC) {
                pico_log(PICO_LOG_WARNING, "devd: oversized uevent truncated, dropped");
                return 0;
        }

        r = devd_uevent_parse(buf, (size_t) k, ret);
        if (r < 0) {
                pico_log(PICO_LOG_DEBUG, "devd: unparseable uevent, dropped");
                return 0;
        }

        return 1;
}
