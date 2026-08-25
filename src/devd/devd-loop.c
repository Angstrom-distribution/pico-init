/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The Devd object's whole lifecycle, the epoll loop, startup and coldplug, and
 * the two reactions themselves.
 *
 * It lives here rather than next to main() for the build-graph reason netd's
 * own loop file documents at length: meson.build links this file into every
 * devd test binary through devd-core, and deliberately never links devd.c --
 * the same exclusion main.c gets from pico-init-core, so no test executable
 * ends up with two main()s. A symbol defined only in devd.c would be invisible
 * to every test. devd.c holds main() and nothing else.
 *
 * The reactions are at the bottom, and the shape they take is the one thing
 * here that is not a copy of netd. A settled disk is read ONCE --
 * gpt_scan_all() over the whole table -- and every partition of it is named and
 * mounted from that one read. That is the debounce paying for itself: reacting
 * per event would mean one open() and one table read per partition, on media
 * that is slow and may be about to be pulled.
 */

#include "devd.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "../gpt-scan.h"
#include "../util.h"
#include "devd-media.h"
#include "devd-probe.h"
#include "devd-symlink.h"
#include "devd-uevent.h"

#define DEVD_EPOLL_MAX_EVENTS 8

/* --- object lifecycle --- */

static int set_string(char **field, const char *value) {
        char *copy;

        if (!field || !value)
                return -EINVAL;

        copy = pico_strdup(value);
        if (!copy)
                return -ENOMEM;

        free(*field);
        *field = copy;
        return 0;
}

int devd_new(Devd **ret) {
        Devd *d;
        int r;

        if (!ret)
                return -EINVAL;

        d = calloc(1, sizeof(*d));
        if (!d)
                return -ENOMEM;

        d->epoll_fd = -1;
        d->uevent_fd = -1;
        d->objective = DEVD_RUNNING;
        d->settle_at = USEC_INFINITY;

        devd_block_init(&d->block, 0, 0);

        r = set_string(&d->sys_root, DEVD_SYS_ROOT);
        if (r < 0)
                goto fail;

        r = set_string(&d->dev_root, DEVD_DEV_ROOT);
        if (r < 0)
                goto fail;

        r = set_string(&d->media_root, DEVD_MEDIA_ROOT);
        if (r < 0)
                goto fail;

        r = pico_signal_new(&d->signal);
        if (r < 0)
                goto fail;

        r = pico_timer_new(&d->timer);
        if (r < 0)
                goto fail;

        r = devd_loop_setup(d);
        if (r < 0)
                goto fail;

        *ret = d;
        return 0;

fail:
        devd_free(d);
        return r;
}

Devd *devd_free(Devd *d) {
        if (!d)
                return NULL;

        /*
         * Mounts are deliberately left mounted. devd stopping is not the card
         * going away, and pulling /media out from under whatever is reading it
         * because a daemon was restarted would be the wrong kind of tidy. The
         * mount table is devd's memory of them, and the next start's coldplug
         * walk rebuilds it -- mount(2) reporting EBUSY for one already there is
         * exactly why devd-media.c treats that as success.
         */

        if (d->settle_event)
                (void) pico_timer_cancel(d->timer, d->settle_event);

        (void) devd_loop_remove_io(d, &d->uevent_tag);
        if (d->uevent_fd >= 0)
                (void) close(d->uevent_fd);

        d->timer = pico_timer_free(d->timer);
        d->signal = pico_signal_free(d->signal);

        if (d->epoll_fd >= 0)
                (void) close(d->epoll_fd);

        free(d->sys_root);
        free(d->dev_root);
        free(d->media_root);

        free(d);
        return NULL;
}

int devd_set_sys_root(Devd *d, const char *path) {
        return d ? set_string(&d->sys_root, path) : -EINVAL;
}

int devd_set_dev_root(Devd *d, const char *path) {
        return d ? set_string(&d->dev_root, path) : -EINVAL;
}

int devd_set_media_root(Devd *d, const char *path) {
        return d ? set_string(&d->media_root, path) : -EINVAL;
}

/* --- the mount table --- */

static const char *mount_find(const Devd *d, const char *devname) {
        for (size_t i = 0; i < d->n_mounts; i++)
                if (strcmp(d->mounts[i].devname, devname) == 0)
                        return d->mounts[i].dir;

        return NULL;
}

static void mount_record(Devd *d, const char *devname, const char *dir) {
        DevdMount *m;

        if (mount_find(d, devname))
                return;

        if (d->n_mounts >= DEVD_MAX_MOUNTS) {
                pico_log(PICO_LOG_WARNING,
                         "devd: mount table full at %d, not recording %s",
                         DEVD_MAX_MOUNTS,
                         dir);
                return;
        }

        m = &d->mounts[d->n_mounts];

        if (strlen(devname) >= sizeof(m->devname) || strlen(dir) >= sizeof(m->dir))
                return;

        strcpy(m->devname, devname);
        strcpy(m->dir, dir);
        d->n_mounts++;
}

static void mount_forget(Devd *d, const char *devname) {
        for (size_t i = 0; i < d->n_mounts; i++)
                if (strcmp(d->mounts[i].devname, devname) == 0) {
                        memmove(&d->mounts[i], &d->mounts[i + 1], (d->n_mounts - i - 1) * sizeof(d->mounts[0]));
                        d->n_mounts--;
                        return;
                }
}

/* --- sysfs lookups --- */

/* The resolved sysfs directory of a block device, e.g. /sys/devices/.../sda. */
static int block_sysfs(const Devd *d, const char *name, char *ret, size_t size) {
        char link[PATH_MAX], real[PATH_MAX];

        if ((size_t) snprintf(link, sizeof(link), "%s/class/block/%s", d->sys_root, name) >= sizeof(link))
                return -ENAMETOOLONG;

        if (!realpath(link, real))
                return -errno;

        if ((size_t) snprintf(ret, size, "%s", real) >= size)
                return -ENAMETOOLONG;

        return 0;
}

/*
 * The partition number of `part`, straight out of sysfs.
 *
 * Asked rather than derived, for the reason gpt-scan.c already gives: "vda2"
 * and "mmcblk0p2" are the same partition under two naming rules, and stripping
 * digits off a node name gets one of them wrong. Returns the number or -errno.
 */
static int part_number(const Devd *d, const char *part) {
        char path[PATH_MAX], buf[32];
        unsigned nr;
        FILE *f;

        if ((size_t) snprintf(path, sizeof(path), "%s/class/block/%s/partition", d->sys_root, part) >=
            sizeof(path))
                return -ENAMETOOLONG;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        if (!fgets(buf, sizeof(buf), f) || sscanf(buf, "%u", &nr) != 1) {
                (void) fclose(f);
                return -EINVAL;
        }

        (void) fclose(f);
        return (int) nr;
}

/* --- the reactions --- */

/*
 * Name and, where policy says so, mount everything on one settled disk.
 *
 * `only_part` restricts it to a single partition, which is the late-arrival
 * path: a partition that turned up after its disk had already settled gets the
 * same treatment without re-running its siblings.
 */
static void react_disk(Devd *d, const char *disk, const char *only_part) {
        char node[PATH_MAX], sysfs[PATH_MAX], id_stem[DEVD_ID_STEM_MAX];
        const char(*names)[DEVD_NAME_MAX] = NULL;
        GptPartition *parts = NULL;
        bool have_id = false;
        size_t n_parts = 0, n_names;
        int r;

        if ((size_t) snprintf(node, sizeof(node), "%s/%s", d->dev_root, disk) >= sizeof(node))
                return;

        id_stem[0] = '\0';

        if (block_sysfs(d, disk, sysfs, sizeof(sysfs)) == 0) {
                r = devd_probe_bus_id(d->sys_root, sysfs, id_stem, sizeof(id_stem));
                have_id = r > 0;
        }

        /* The disk's own by-id link, which has no partition-level families and
         * so is not part of the loop below. */
        if (have_id && !only_part) {
                DevdLinks l;

                memset(&l, 0, sizeof(l));
                (void) snprintf(l.id, sizeof(l.id), "%s", id_stem);
                (void) devd_symlink_create(d->dev_root, disk, &l);
        }

        r = gpt_scan_all(node, &parts, &n_parts);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "devd: %s: cannot read the partition table: %s", node, strerror(-r));
                return;
        }

        if (r == 0)
                /* No GPT. v1 is prepared media only, so there is nothing here
                 * devd can name or mount -- said once, not once per partition,
                 * and at debug because the coldplug walk says it for every
                 * ordinary disk on the machine. */
                pico_log(PICO_LOG_DEBUG, "devd: %s has no GPT, leaving it alone", node);

        n_names = devd_block_partitions(&d->block, disk, &names);

        for (size_t i = 0; i < n_names; i++) {
                const char *part = names[i];
                const GptPartition *p = NULL;
                char part_node[PATH_MAX], dir[PATH_MAX];
                DevdFsInfo fs;
                DevdLinks l;
                int nr;

                if (only_part && strcmp(part, only_part) != 0)
                        continue;

                nr = part_number(d, part);
                if (nr < 0)
                        continue;

                for (size_t j = 0; j < n_parts; j++)
                        if (parts[j].nr == (unsigned) nr) {
                                p = &parts[j];
                                break;
                        }

                if (!p)
                        continue;

                if ((size_t) snprintf(part_node, sizeof(part_node), "%s/%s", d->dev_root, part) >=
                    sizeof(part_node))
                        continue;

                memset(&l, 0, sizeof(l));
                gpt_guid_to_string(&p->uuid, l.partuuid);
                (void) snprintf(l.partlabel, sizeof(l.partlabel), "%s", p->name);

                if (devd_probe_ext(part_node, &fs) > 0) {
                        (void) snprintf(l.fsuuid, sizeof(l.fsuuid), "%s", fs.uuid);
                        (void) snprintf(l.fslabel, sizeof(l.fslabel), "%s", fs.label);
                }

                if (have_id)
                        (void) snprintf(l.id, sizeof(l.id), "%s-part%d", id_stem, nr);

                (void) devd_symlink_create(d->dev_root, part, &l);

                /*
                 * Mount policy, and the three things that stop it. The boot
                 * disk belongs to PID 1 (devd-media.h); a no-auto partition
                 * said not to (the DPS attribute bit, honoured here as well as
                 * in gpt_scan()); a non-data type is somebody else's job.
                 */
                if (strcmp(disk, d->boot_disk) == 0)
                        continue;

                if (p->attributes & GPT_ATTR_NO_AUTO)
                        continue;

                if (!devd_media_is_data_type(&p->type))
                        continue;

                if (mount_find(d, part))
                        continue;

                r = devd_media_mount(
                                d->media_root,
                                part_node,
                                p->name,
                                part,
                                (p->attributes & GPT_ATTR_READ_ONLY) != 0,
                                dir,
                                sizeof(dir));
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING, "devd: cannot mount %s: %s", part_node, strerror(-r));
                        continue;
                }

                if (r > 0)
                        mount_record(d, part, dir);
        }

        free(parts);
}

/* A partition went away: drop its links, and undo the mount if devd made one. */
static void react_part_gone(Devd *d, const char *part) {
        const char *dir = mount_find(d, part);

        if (dir) {
                int r = devd_media_unmount(dir);

                if (r < 0)
                        pico_log(PICO_LOG_WARNING, "devd: cannot unmount %s: %s", dir, strerror(-r));
                else
                        pico_log(PICO_LOG_INFO, "devd: unmounted %s", dir);

                mount_forget(d, part);
        }

        (void) devd_symlink_remove(d->dev_root, part);
}

/*
 * A whole disk went away. The kernel sends a remove for each partition too, but
 * not reliably before the disk's own, and on a surprise removal not necessarily
 * at all -- so this cleans up every partition it knows about rather than
 * waiting for events that may already have been the ones it missed.
 */
static void react_disk_gone(Devd *d, const char *disk) {
        const char(*names)[DEVD_NAME_MAX] = NULL;
        size_t n = devd_block_partitions(&d->block, disk, &names);

        for (size_t i = 0; i < n; i++)
                react_part_gone(d, names[i]);

        (void) devd_symlink_remove(d->dev_root, disk);
        devd_block_forget(&d->block, disk);
}

/* --- settle timer --- */

static void devd_arm_settle(Devd *d);

static void devd_settle_fired(void *userdata, usec_t now) {
        Devd *d = userdata;
        const char *disk;

        /* pico_timer_dispatch() unlinked the event and cleared d->settle_event
         * before calling this, so re-arming below is safe (timer.h). */
        d->settle_at = USEC_INFINITY;

        while ((disk = devd_block_take_settled(&d->block, now)))
                react_disk(d, disk, NULL);

        devd_arm_settle(d);
}

static void devd_arm_settle(Devd *d) {
        usec_t next = devd_block_next_settle(&d->block);
        int r;

        if (next == USEC_INFINITY) {
                if (d->settle_event)
                        (void) pico_timer_cancel(d->timer, d->settle_event);

                d->settle_at = USEC_INFINITY;
                return;
        }

        if (d->settle_event) {
                if (d->settle_at == next)
                        return; /* already armed for exactly this */

                (void) pico_timer_cancel(d->timer, d->settle_event);
        }

        d->settle_at = next;

        r = pico_timer_add(d->timer, next, devd_settle_fired, d, &d->settle_event);
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "devd: cannot arm the settle timer: %s", strerror(-r));
                d->settle_at = USEC_INFINITY;
        }
}

/* --- event processing --- */

static void devd_process_uevent(Devd *d, const DevdUevent *u) {
        DevdBlockOutcome outcome;
        const char *disk = NULL, *part = NULL;
        int r;

        r = devd_block_event(&d->block, u, now_monotonic(), &outcome, &disk, &part);
        if (r < 0) {
                pico_log(PICO_LOG_DEBUG, "devd: unusable block uevent for %s", u->devpath);
                return;
        }

        switch (outcome) {

        case DEVD_BLOCK_PART_LATE:
                react_disk(d, disk, part);
                break;

        case DEVD_BLOCK_PART_GONE:
                react_part_gone(d, part);
                break;

        case DEVD_BLOCK_DISK_GONE:
                react_disk_gone(d, disk);
                break;

        default:
                /* IGNORED, or a window that the settle timer will close. */
                break;
        }
}

/* --- coldplug --- */

/* Build the uevent the kernel would have sent for a device already present. */
static int coldplug_uevent(const Devd *d, const char *name, DevdUevent *u) {
        char real[PATH_MAX], probe[PATH_MAX];
        size_t root_len = strlen(d->sys_root);
        int r;

        r = block_sysfs(d, name, real, sizeof(real));
        if (r < 0)
                return r;

        if (strncmp(real, d->sys_root, root_len) != 0)
                return -EINVAL;

        memset(u, 0, sizeof(*u));
        u->action = DEVD_ACTION_ADD;

        if ((size_t) snprintf(u->subsystem, sizeof(u->subsystem), "block") >= sizeof(u->subsystem))
                return -ENAMETOOLONG;

        if ((size_t) snprintf(u->devpath, sizeof(u->devpath), "%s", real + root_len) >= sizeof(u->devpath))
                return -ENAMETOOLONG;

        if ((size_t) snprintf(u->devname, sizeof(u->devname), "%s", name) >= sizeof(u->devname))
                return -ENAMETOOLONG;

        if ((size_t) snprintf(probe, sizeof(probe), "%s/partition", real) >= sizeof(probe))
                return -ENAMETOOLONG;

        (void) snprintf(u->devtype, sizeof(u->devtype), "%s", access(probe, F_OK) == 0 ? "partition" : "disk");

        return 0;
}

/*
 * The walk. Also the resync path: after an -ENOBUFS the event stream has
 * dropped messages and no amount of reading catches up, but everything those
 * messages would have said is still true of /sys, so redoing this is by
 * construction a full recovery.
 */
static int devd_coldplug(Devd *d) {
        char dir[PATH_MAX];
        const char *disk;
        struct dirent *e;
        usec_t now;
        DIR *dd;
        int r;

        r = devd_symlink_reconcile(d->dev_root);
        if (r < 0)
                pico_log(PICO_LOG_WARNING, "devd: cannot reconcile /dev/disk: %s", strerror(-r));
        else if (r > 0)
                pico_log(PICO_LOG_INFO, "devd: removed %d stale /dev/disk symlink(s)", r);

        if ((size_t) snprintf(dir, sizeof(dir), "%s/class/block", d->sys_root) >= sizeof(dir))
                return -ENAMETOOLONG;

        dd = opendir(dir);
        if (!dd)
                return errno == ENOENT ? 0 : -errno;

        now = now_monotonic();

        while ((e = readdir(dd))) {
                DevdBlockOutcome outcome;
                DevdUevent u;

                if (e->d_name[0] == '.')
                        continue;

                if (coldplug_uevent(d, e->d_name, &u) < 0)
                        continue;

                (void) devd_block_event(&d->block, &u, now, &outcome, NULL, NULL);
        }

        (void) closedir(dd);

        /*
         * Everything already present is settled now, not in a quarter of a
         * second: the burst this window exists to absorb happened before devd
         * started. USEC_INFINITY as the clock is how "close every window" is
         * spelled -- no deadline can be later than it.
         */
        while ((disk = devd_block_take_settled(&d->block, USEC_INFINITY)))
                react_disk(d, disk, NULL);

        devd_arm_settle(d);
        return 0;
}

/* --- startup --- */

/* The whole-disk device the root filesystem sits on, by name. */
static void devd_find_boot_disk(Devd *d) {
        char node[PATH_MAX];
        const char *base;
        int r;

        d->boot_disk[0] = '\0';

        r = gpt_boot_disk("/proc/self/mountinfo", node, sizeof(node), NULL, 0);
        if (r == -ENOENT) {
                pico_log(PICO_LOG_DEBUG, "devd: the root filesystem is not on a block device");
                return;
        }
        if (r < 0) {
                pico_log(PICO_LOG_WARNING, "devd: cannot identify the boot disk: %s", strerror(-r));
                return;
        }

        base = strrchr(node, '/');
        base = base ? base + 1 : node;

        if (strlen(base) >= sizeof(d->boot_disk))
                return;

        strcpy(d->boot_disk, base);
        pico_log(PICO_LOG_DEBUG, "devd: the boot disk is %s, nothing on it will be mounted", base);
}

static int dispatch_uevent_source(Devd *d, struct devd_epoll_tag *tag, uint32_t revents);

int devd_startup(Devd *d) {
        int r;

        if (!d)
                return -EINVAL;

        devd_find_boot_disk(d);

        /*
         * Subscribe first. See devd.h and devd-uevent.h: a card inserted
         * between the walk below and the subscription would be missed by both
         * paths, forever, and there is nothing underneath devd to notice.
         */
        r = devd_uevent_open();
        if (r < 0) {
                pico_log(PICO_LOG_ERR, "devd: cannot open the uevent socket: %s", strerror(-r));
                return r;
        }

        d->uevent_fd = r;

        r = devd_loop_add_io(
                        d, &d->uevent_tag, d->uevent_fd, EPOLLIN, DEVD_EPOLL_UEVENT, dispatch_uevent_source, d);
        if (r < 0)
                return r;

        return devd_coldplug(d);
}

/* --- the epoll loop --- */

static int dispatch_signal_source(Devd *d, struct devd_epoll_tag *tag, uint32_t revents) {
        int r;

        (void) tag;
        (void) revents;

        for (;;) {
                int signo;

                r = pico_signal_read(d->signal, &signo);
                if (r == -EAGAIN)
                        return 0;
                if (r < 0)
                        return r;

                r = devd_loop_dispatch_signal(d, signo);
                if (r < 0)
                        return r;
        }
}

static int dispatch_timer_source(Devd *d, struct devd_epoll_tag *tag, uint32_t revents) {
        int r;

        (void) tag;
        (void) revents;

        r = pico_timer_dispatch(d->timer);
        return r < 0 ? r : 0;
}

static int dispatch_uevent_source(Devd *d, struct devd_epoll_tag *tag, uint32_t revents) {
        (void) tag;
        (void) revents;

        for (;;) {
                DevdUevent u;
                int r = devd_uevent_recv(d->uevent_fd, &u);

                if (r == -EAGAIN || r == -EINTR)
                        break;

                if (r == -ENOBUFS) {
                        pico_log(PICO_LOG_WARNING, "devd: uevent socket overran, re-walking sysfs");
                        (void) devd_coldplug(d);
                        continue;
                }

                if (r < 0)
                        return r;

                if (r == 0)
                        continue; /* dropped and already logged */

                devd_process_uevent(d, &u);
        }

        /* Once per readable batch rather than once per event: a card's whole
         * burst usually arrives in one epoll wakeup, and re-arming inside the
         * loop would cancel and re-add the same timer for every partition. */
        devd_arm_settle(d);
        return 0;
}

int devd_loop_setup(Devd *d) {
        int r;

        if (!d || !d->signal || !d->timer)
                return -EINVAL;

        d->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (d->epoll_fd < 0)
                return -errno;

        r = devd_loop_add_io(
                        d,
                        &d->signal_tag,
                        pico_signal_fd(d->signal),
                        EPOLLIN,
                        DEVD_EPOLL_SIGNAL,
                        dispatch_signal_source,
                        d);
        if (r < 0)
                return r;

        return devd_loop_add_io(
                        d,
                        &d->timer_tag,
                        pico_timer_fd(d->timer),
                        EPOLLIN,
                        DEVD_EPOLL_TIMER,
                        dispatch_timer_source,
                        d);
}

int devd_loop_add_io(
                Devd *d,
                struct devd_epoll_tag *tag,
                int fd,
                uint32_t events,
                DevdEpollSource source,
                devd_io_callback_t callback,
                void *userdata) {

        struct epoll_event ev;

        if (!d || !tag || !callback || fd < 0 || d->epoll_fd < 0)
                return -EINVAL;

        if (tag->registered)
                return -EBUSY;

        tag->source = source;
        tag->fd = fd;
        tag->callback = callback;
        tag->userdata = userdata;
        tag->registered = true;

        memset(&ev, 0, sizeof(ev));
        ev.events = events;
        ev.data.ptr = tag;

        if (epoll_ctl(d->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
                tag->fd = -1;
                tag->registered = false;
                return -errno;
        }

        return 0;
}

int devd_loop_remove_io(Devd *d, struct devd_epoll_tag *tag) {
        if (!d || !tag)
                return -EINVAL;

        if (!tag->registered)
                return 0;

        if (d->epoll_fd >= 0 && epoll_ctl(d->epoll_fd, EPOLL_CTL_DEL, tag->fd, NULL) < 0 &&
            errno != ENOENT && errno != EBADF)
                return -errno;

        tag->fd = -1;
        tag->registered = false;
        tag->callback = NULL;
        tag->userdata = NULL;
        return 0;
}

int devd_loop_dispatch_signal(Devd *d, int signo) {
        if (!d)
                return -EINVAL;

        switch (signo) {

        case SIGTERM:
        case SIGINT:
                pico_log(PICO_LOG_INFO, "devd: %s, shutting down", strsignal(signo));
                d->objective = DEVD_EXIT;
                return 0;

        default:
                pico_log(PICO_LOG_DEBUG, "devd: ignoring signal %d", signo);
                return 0;
        }
}

int devd_loop_run(Devd *d) {
        if (!d || d->epoll_fd < 0)
                return -EINVAL;

        while (d->objective == DEVD_RUNNING) {
                struct epoll_event events[DEVD_EPOLL_MAX_EVENTS];
                int k;

                k = epoll_wait(d->epoll_fd, events, DEVD_EPOLL_MAX_EVENTS, -1);
                if (k < 0) {
                        if (errno == EINTR)
                                continue;

                        return -errno;
                }

                for (int i = 0; i < k; i++) {
                        struct devd_epoll_tag *tag = events[i].data.ptr;
                        int r;

                        if (!tag || !tag->callback || !tag->registered)
                                continue;

                        r = tag->callback(d, tag, events[i].events);
                        if (r < 0)
                                pico_log(PICO_LOG_WARNING,
                                         "devd: %s source failed: %s",
                                         devd_epoll_source_to_string(tag->source),
                                         strerror(-r));
                }
        }

        return 0;
}

static const char * const devd_epoll_source_table[_DEVD_EPOLL_SOURCE_MAX] = {
        [DEVD_EPOLL_SIGNAL] = "signal",
        [DEVD_EPOLL_TIMER] = "timer",
        [DEVD_EPOLL_UEVENT] = "uevent",
};

const char *devd_epoll_source_to_string(DevdEpollSource s) {
        if (s < 0 || s >= _DEVD_EPOLL_SOURCE_MAX)
                return "invalid";

        return devd_epoll_source_table[s];
}
