/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * sd_device_monitor: a NETLINK_KOBJECT_UEVENT group-1 socket, its
 * receive-side parser, and every filter -- all evaluated in userspace at
 * receive time, since there is no udev daemon here to have installed a
 * kernel BPF filter program in the first place.
 *
 * The socket setup is devd-uevent.c's proven pattern (this project's own
 * code, adapted here rather than shared, since devd and this library are
 * two different binaries): group 1, the kernel's own broadcast group, never
 * group 2 (udev's rebroadcast, which nothing on this image writes to and
 * which carries a magic header this parser correctly refuses to misparse
 * as a device named "libudev").
 *
 * The sender check goes one step further than devd's own, and it is not
 * decoration: checked directly against a real running kernel while writing
 * this (SO_PASSCRED enabled, a real "change" uevent captured), a genuine
 * kernel-origin group-1 message carries an SCM_CREDENTIALS ancillary
 * message with uid/gid/pid all 0, in addition to nl_pid == 0 in the sender
 * address -- so both are checked, matching what was actually observed
 * rather than only what devd's simpler check already covers.
 *
 * Also observed on that real kernel, and load-bearing for the parser: a
 * uevent's body repeats ACTION= and DEVPATH= from the header line, and a
 * synthetic-uuid-capable kernel always sends SYNTH_UUID=, "0" when the
 * event was not synthesized with one. The header-parsed copies go straight
 * onto the struct (dev->action, the devpath device_new_from_devpath_bare()
 * was given) rather than into the property table; the body's own ACTION=/
 * DEVPATH= are what land in the table, via the ordinary KEY=VALUE loop
 * below, and device_ensure_properties()'s later synthesis of ACTION from
 * dev->action is therefore always a first-write-wins no-op in practice --
 * the two copies agree, since the kernel sends them that way.
 * device_id128_from_uuid_string() simply fails to parse "0" as a
 * 36-character uuid, which is exactly "no synthetic uuid on this event".
 */

/* struct ucred/SCM_CREDENTIALS are glibc extensions gated behind
 * _GNU_SOURCE; -std=gnu17 alone does not imply it (see socket.c's own
 * note), so this has to be explicit and first, before any header pulls in
 * features.h. */
#define _GNU_SOURCE

#include "sd-device.h"

#include <errno.h>
#include <limits.h>
#include <linux/netlink.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "device-internal.h"

#define MONITOR_UEVENT_GROUP 1
#define MONITOR_RCVBUF_DEFAULT (256 * 1024)
#define MONITOR_RECV_BUF_MAX 8192
#define MONITOR_DEVPATH_MAX 512
#define LIBUDEV_MAGIC "libudev"

int sd_device_monitor_new(sd_device_monitor **ret) {
        sd_device_monitor *m;
        int fd, val, group = MONITOR_UEVENT_GROUP, e;
        struct sockaddr_nl addr;

        if (!ret)
                return -EINVAL;

        fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_KOBJECT_UEVENT);
        if (fd < 0)
                return -errno;

        val = MONITOR_RCVBUF_DEFAULT;
        (void) setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val));

        val = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &val, sizeof(val)) < 0) {
                e = errno;
                goto fail;
        }

        memset(&addr, 0, sizeof(addr));
        addr.nl_family = AF_NETLINK;
        if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
                e = errno;
                goto fail;
        }

        if (setsockopt(fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) < 0) {
                e = errno;
                goto fail;
        }

        m = calloc(1, sizeof(*m));
        if (!m) {
                e = ENOMEM;
                goto fail;
        }
        m->n_ref = 1;
        m->sock = fd;

        *ret = m;
        return 0;

fail:
        (void) close(fd);
        return -e;
}

sd_device_monitor *sd_device_monitor_ref(sd_device_monitor *m) {
        if (!m)
                return NULL;

        m->n_ref++;
        return m;
}

sd_device_monitor *sd_device_monitor_unref(sd_device_monitor *m) {
        size_t i;

        if (!m)
                return NULL;

        if (--m->n_ref > 0)
                return NULL;

        if (m->sock >= 0)
                (void) close(m->sock);
        free(m->description);

        for (i = 0; i < m->n_subsystem_devtype; i++) {
                free(m->subsystem_devtype[i].subsystem);
                free(m->subsystem_devtype[i].devtype);
        }
        free(m->subsystem_devtype);

        for (i = 0; i < m->n_tags; i++)
                free(m->tags[i]);
        free(m->tags);

        for (i = 0; i < m->n_sysattr_matches; i++) {
                free(m->sysattr_matches[i].sysattr);
                free(m->sysattr_matches[i].value);
        }
        free(m->sysattr_matches);

        for (i = 0; i < m->n_parent_matches; i++)
                free(m->parent_matches[i].syspath);
        free(m->parent_matches);

        free(m);
        return NULL;
}

int sd_device_monitor_get_fd(sd_device_monitor *m) {
        if (!m)
                return -EINVAL;

        return m->sock;
}

int sd_device_monitor_get_events(sd_device_monitor *m) {
        if (!m)
                return -EINVAL;
        if (m->sock < 0)
                return -ESTALE;

        return EPOLLIN;
}

int sd_device_monitor_get_timeout(sd_device_monitor *m, uint64_t *ret) {
        if (!m || !ret)
                return -EINVAL;
        if (m->sock < 0)
                return -ESTALE;

        /* No ratelimiting mechanism exists here to ever produce one. */
        *ret = UINT64_MAX;
        return 0;
}

int sd_device_monitor_set_receive_buffer_size(sd_device_monitor *m, size_t size) {
        int val = size > (size_t) INT_MAX ? INT_MAX : (int) size;

        if (!m)
                return -EINVAL;

        if (setsockopt(m->sock, SOL_SOCKET, SO_RCVBUFFORCE, &val, sizeof(val)) == 0)
                return 0;
        if (errno != EPERM)
                return -errno;

        return setsockopt(m->sock, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val)) == 0 ? 0 : -errno;
}

int sd_device_monitor_set_description(sd_device_monitor *m, const char *description) {
        char *dup = NULL;

        if (!m)
                return -EINVAL;

        if (description) {
                dup = strdup(description);
                if (!dup)
                        return -ENOMEM;
        }

        free(m->description);
        m->description = dup;
        return 0;
}

int sd_device_monitor_get_description(sd_device_monitor *m, const char **ret) {
        if (!m || !ret)
                return -EINVAL;

        *ret = m->description;
        return 0;
}

/* --- filters: installed here, evaluated by device_monitor_filter_matches() --- */

int sd_device_monitor_filter_add_match_subsystem_devtype(
                sd_device_monitor *m, const char *subsystem, const char *devtype) {
        DeviceMonitorSubsystemDevtype *n;

        if (!m || !subsystem)
                return -EINVAL;

        n = realloc(m->subsystem_devtype, (m->n_subsystem_devtype + 1) * sizeof(*n));
        if (!n)
                return -ENOMEM;
        m->subsystem_devtype = n;

        m->subsystem_devtype[m->n_subsystem_devtype].subsystem = strdup(subsystem);
        m->subsystem_devtype[m->n_subsystem_devtype].devtype = devtype ? strdup(devtype) : NULL;
        if (!m->subsystem_devtype[m->n_subsystem_devtype].subsystem)
                return -ENOMEM;
        m->n_subsystem_devtype++;

        return 0;
}

int sd_device_monitor_filter_add_match_tag(sd_device_monitor *m, const char *tag) {
        char **n;

        if (!m || !tag)
                return -EINVAL;

        /* No kernel uevent ever carries TAGS= (that is udev's own
         * addition), so any tag filter passes nothing from here on --
         * the truthful answer, not a bug. */
        n = realloc(m->tags, (m->n_tags + 1) * sizeof(*n));
        if (!n)
                return -ENOMEM;
        m->tags = n;

        m->tags[m->n_tags] = strdup(tag);
        if (!m->tags[m->n_tags])
                return -ENOMEM;
        m->n_tags++;

        return 0;
}

int sd_device_monitor_filter_add_match_sysattr(
                sd_device_monitor *m, const char *sysattr, const char *value, int match) {
        DeviceSysattrMatch *n;

        if (!m || !sysattr)
                return -EINVAL;

        n = realloc(m->sysattr_matches, (m->n_sysattr_matches + 1) * sizeof(*n));
        if (!n)
                return -ENOMEM;
        m->sysattr_matches = n;

        m->sysattr_matches[m->n_sysattr_matches].sysattr = strdup(sysattr);
        m->sysattr_matches[m->n_sysattr_matches].value = value ? strdup(value) : NULL;
        m->sysattr_matches[m->n_sysattr_matches].match = match != 0;
        if (!m->sysattr_matches[m->n_sysattr_matches].sysattr)
                return -ENOMEM;
        m->n_sysattr_matches++;

        return 0;
}

int sd_device_monitor_filter_add_match_parent(sd_device_monitor *m, sd_device *device, int match) {
        const char *syspath;
        DeviceMonitorParentMatch *n;
        int r;

        if (!m || !device)
                return -EINVAL;

        r = sd_device_get_syspath(device, &syspath);
        if (r < 0)
                return r;

        n = realloc(m->parent_matches, (m->n_parent_matches + 1) * sizeof(*n));
        if (!n)
                return -ENOMEM;
        m->parent_matches = n;

        m->parent_matches[m->n_parent_matches].syspath = strdup(syspath);
        m->parent_matches[m->n_parent_matches].match = match != 0;
        if (!m->parent_matches[m->n_parent_matches].syspath)
                return -ENOMEM;
        m->n_parent_matches++;

        return 0;
}

int sd_device_monitor_filter_update(sd_device_monitor *m) {
        if (!m)
                return -EINVAL;

        /*
         * Real purpose: (re)install the kernel BPF filter for the matches
         * added above. This shim evaluates every filter in userspace at
         * receive time instead, so by the time this call returns the
         * filters are already in effect -- the caller-observable contract
         * ("after this call, filters apply") holds exactly, with nothing
         * left to do.
         */
        return 0;
}

int sd_device_monitor_filter_remove(sd_device_monitor *m) {
        size_t i;

        if (!m)
                return -EINVAL;

        for (i = 0; i < m->n_subsystem_devtype; i++) {
                free(m->subsystem_devtype[i].subsystem);
                free(m->subsystem_devtype[i].devtype);
        }
        free(m->subsystem_devtype);
        m->subsystem_devtype = NULL;
        m->n_subsystem_devtype = 0;

        for (i = 0; i < m->n_tags; i++)
                free(m->tags[i]);
        free(m->tags);
        m->tags = NULL;
        m->n_tags = 0;

        for (i = 0; i < m->n_sysattr_matches; i++) {
                free(m->sysattr_matches[i].sysattr);
                free(m->sysattr_matches[i].value);
        }
        free(m->sysattr_matches);
        m->sysattr_matches = NULL;
        m->n_sysattr_matches = 0;

        for (i = 0; i < m->n_parent_matches; i++)
                free(m->parent_matches[i].syspath);
        free(m->parent_matches);
        m->parent_matches = NULL;
        m->n_parent_matches = 0;

        return 0;
}

/*
 * A remove event's sysfs directory is routinely already gone by match
 * time (device-internal.h's struct comment), so sd_device_get_subsystem()/
 * _get_devtype() -- both readlink-/uevent-file-based -- would wrongly
 * reject it. A monitor device already has the message's own SUBSYSTEM=/
 * DEVTYPE= in its property table from parse_and_build(), independent of
 * sysfs, so read that directly instead for a from_monitor device.
 */
static int monitor_get_subsystem(sd_device *dev, const char **ret) {
        if (dev->from_monitor) {
                const char *v = device_get_property_raw(dev, "SUBSYSTEM");

                if (!v)
                        return -ENOENT;
                *ret = v;
                return 0;
        }
        return sd_device_get_subsystem(dev, ret);
}

static int monitor_get_devtype(sd_device *dev, const char **ret) {
        if (dev->from_monitor) {
                const char *v = device_get_property_raw(dev, "DEVTYPE");

                if (!v)
                        return -ENOENT;
                *ret = v;
                return 0;
        }
        return sd_device_get_devtype(dev, ret);
}

bool device_monitor_filter_matches(sd_device_monitor *m, sd_device *dev) {
        size_t i;

        if (m->n_subsystem_devtype > 0) {
                const char *subsystem = NULL, *devtype;
                bool any = false;

                (void) monitor_get_subsystem(dev, &subsystem);

                for (i = 0; i < m->n_subsystem_devtype && !any; i++) {
                        if (!subsystem || strcmp(subsystem, m->subsystem_devtype[i].subsystem) != 0)
                                continue;
                        if (m->subsystem_devtype[i].devtype &&
                            (monitor_get_devtype(dev, &devtype) < 0 ||
                             strcmp(devtype, m->subsystem_devtype[i].devtype) != 0))
                                continue;
                        any = true;
                }
                if (!any)
                        return false;
        }

        if (m->n_tags > 0)
                return false;

        /* sysattr matches still read real sysfs (device-sysattr.c): honestly
         * unavailable (treated as "no value") for a remove event whose
         * directory is already gone, same as any other getter on it. */
        for (i = 0; i < m->n_sysattr_matches; i++) {
                const char *v;
                bool has = sd_device_get_sysattr_value(dev, m->sysattr_matches[i].sysattr, &v) >= 0;
                bool value_matches = has &&
                                (!m->sysattr_matches[i].value || strcmp(m->sysattr_matches[i].value, v) == 0);

                if (m->sysattr_matches[i].match ? !value_matches : value_matches)
                        return false;
        }

        for (i = 0; i < m->n_parent_matches; i++) {
                const char *syspath;
                size_t plen = strlen(m->parent_matches[i].syspath);
                bool under;

                if (sd_device_get_syspath(dev, &syspath) < 0)
                        return false;

                under = strcmp(syspath, m->parent_matches[i].syspath) == 0 ||
                                (strncmp(syspath, m->parent_matches[i].syspath, plen) == 0 &&
                                 syspath[plen] == '/');

                if (m->parent_matches[i].match ? !under : under)
                        return false;
        }

        return true;
}

/* One header line "ACTION@DEVPATH" then a NUL-separated KEY=VALUE tail,
 * exactly devd-uevent.h's wire format (this project's own knowledge of the
 * kernel's uevent broadcast, not systemd's). */
static int parse_and_build(const char *buf, size_t n, sd_device **ret) {
        const char *at, *devpath_start, *nul;
        char action_str[32], devpath[MONITOR_DEVPATH_MAX];
        size_t action_len, devpath_len, off;
        sd_device *dev;
        const char *seqnum_s, *uuid_s;
        int r;

        /* devd-uevent.c's own guard: every field below is read as a C
         * string, so the buffer must end in a NUL for that to be safe.
         * Reachable only in theory -- sd_device_monitor_receive()'s root-
         * credential check already runs first -- but cheap enough to keep
         * as defense in depth. */
        if (n == 0 || buf[n - 1] != '\0')
                return -EINVAL;

        at = memchr(buf, '@', n);
        if (!at || at == buf)
                return -EINVAL;

        action_len = (size_t) (at - buf);
        if (action_len >= sizeof(action_str))
                return -EINVAL;
        memcpy(action_str, buf, action_len);
        action_str[action_len] = '\0';

        devpath_start = at + 1;
        nul = memchr(devpath_start, '\0', n - (size_t) (devpath_start - buf));
        if (!nul)
                return -EINVAL;

        devpath_len = (size_t) (nul - devpath_start);
        if (devpath_len == 0 || devpath_len >= sizeof(devpath))
                return -EINVAL;
        memcpy(devpath, devpath_start, devpath_len);
        devpath[devpath_len] = '\0';

        r = device_new_from_devpath_bare(&dev, devpath);
        if (r < 0)
                return r;

        dev->from_monitor = true;
        dev->action = device_action_from_string(action_str);

        for (off = (size_t) (nul + 1 - buf); off < n; off += strlen(buf + off) + 1) {
                const char *p = buf + off, *eq;

                if (*p == '\0')
                        continue;
                eq = strchr(p, '=');
                if (!eq)
                        continue;

                {
                        char key[128];
                        size_t klen = (size_t) (eq - p);

                        if (klen >= sizeof(key))
                                continue;
                        memcpy(key, p, klen);
                        key[klen] = '\0';
                        (void) device_add_property(dev, key, eq + 1);
                }
        }

        seqnum_s = device_get_property_raw(dev, "SEQNUM");
        if (seqnum_s) {
                dev->has_seqnum = true;
                dev->seqnum = strtoull(seqnum_s, NULL, 10);
        }

        uuid_s = device_get_property_raw(dev, "SYNTH_UUID");
        if (uuid_s && device_id128_from_uuid_string(uuid_s, &dev->synth_uuid) == 0)
                dev->has_synth_uuid = true;

        *ret = dev;
        return 0;
}

int sd_device_monitor_receive(sd_device_monitor *m, sd_device **ret) {
        if (!m || !ret)
                return -EINVAL;

        for (;;) {
                char buf[MONITOR_RECV_BUF_MAX];
                union {
                        char buf[64];
                        struct cmsghdr align;
                } cmsgbuf;
                struct sockaddr_nl sa;
                struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
                struct msghdr msg = {
                        .msg_name = &sa,
                        .msg_namelen = sizeof(sa),
                        .msg_iov = &iov,
                        .msg_iovlen = 1,
                        .msg_control = cmsgbuf.buf,
                        .msg_controllen = sizeof(cmsgbuf.buf),
                };
                struct cmsghdr *cmsg;
                bool cred_ok = false;
                ssize_t k;
                sd_device *dev = NULL;

                memset(&sa, 0, sizeof(sa));

                k = recvmsg(m->sock, &msg, 0);
                if (k < 0)
                        return errno == EAGAIN || errno == EWOULDBLOCK ? -EAGAIN : -errno;

                if (msg.msg_flags & MSG_TRUNC)
                        continue; /* oversized message, dropped */

                if (sa.nl_pid != 0 || sa.nl_groups == 0)
                        continue; /* not the kernel's own broadcast */

                for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
                        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_CREDENTIALS) {
                                struct ucred cred;

                                memcpy(&cred, CMSG_DATA(cmsg), sizeof(cred));
                                if (cred.uid == 0)
                                        cred_ok = true;
                        }
                if (!cred_ok)
                        continue; /* no root-origin credentials: spoofed or malformed */

                if ((size_t) k >= sizeof(LIBUDEV_MAGIC) &&
                    memcmp(buf, LIBUDEV_MAGIC, sizeof(LIBUDEV_MAGIC)) == 0)
                        continue; /* group-2 shaped message; never legitimate here */

                if (parse_and_build(buf, (size_t) k, &dev) < 0)
                        continue; /* unparseable or already-gone device */

                if (!device_monitor_filter_matches(m, dev)) {
                        sd_device_unref(dev);
                        continue;
                }

                *ret = dev;
                return 0;
        }
}

/* --- deferred: sd-event integration --- */

/*
 * Pure sd-event loop-integration -- attach_event() even creates a default
 * event loop when none is given, and is_running() delegates to
 * sd_event_source_get_enabled() on it. None of that exists here yet: this
 * shim's own sd-event family is a separate, not-yet-landed piece of
 * libsystemd-compat. fd-based consumption (get_fd()/get_events()/
 * receive() above) is fully real today, which is the loop-integration
 * path pico-init's own daemons use anyway.
 */

int sd_device_monitor_attach_event(sd_device_monitor *m, sd_event *event) {
        (void) m;
        (void) event;
        return -EOPNOTSUPP;
}

int sd_device_monitor_detach_event(sd_device_monitor *m) {
        (void) m;
        return -EOPNOTSUPP;
}

sd_event *sd_device_monitor_get_event(sd_device_monitor *m) {
        (void) m;
        return NULL;
}

sd_event_source *sd_device_monitor_get_event_source(sd_device_monitor *m) {
        (void) m;
        return NULL;
}

int sd_device_monitor_start(sd_device_monitor *m, sd_device_monitor_handler_t callback, void *userdata) {
        (void) m;
        (void) callback;
        (void) userdata;
        return -EOPNOTSUPP;
}

int sd_device_monitor_stop(sd_device_monitor *m) {
        (void) m;
        return -EOPNOTSUPP;
}

int sd_device_monitor_is_running(sd_device_monitor *m) {
        (void) m;
        return 0; /* "not running", real NULL-tolerant contract */
}
