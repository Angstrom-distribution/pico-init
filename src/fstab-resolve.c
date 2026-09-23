/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * fstab source resolution and the device wait. fstab-resolve.h has why PID 1
 * walks sysfs itself instead of following /dev/disk/by-* links.
 */

#define _GNU_SOURCE

#include "fstab-resolve.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#include "gpt-scan.h"

static const char * const tag_table[_FSTAB_TAG_MAX] = {
        [FSTAB_TAG_UUID] = "UUID",
        [FSTAB_TAG_LABEL] = "LABEL",
        [FSTAB_TAG_PARTUUID] = "PARTUUID",
        [FSTAB_TAG_PARTLABEL] = "PARTLABEL",
};

/* The link directory each tag's udev family lives in. */
static const char * const link_table[_FSTAB_TAG_MAX] = {
        [FSTAB_TAG_UUID] = "/dev/disk/by-uuid/",
        [FSTAB_TAG_LABEL] = "/dev/disk/by-label/",
        [FSTAB_TAG_PARTUUID] = "/dev/disk/by-partuuid/",
        [FSTAB_TAG_PARTLABEL] = "/dev/disk/by-partlabel/",
};

const char *fstab_tag_to_string(FstabTag t) {
        if (t <= FSTAB_TAG_NONE || t >= _FSTAB_TAG_MAX)
                return NULL;
        return tag_table[t];
}

static int hexval(char c) {
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}

/* Copy `in` into `out`, undoing udev's \xNN escapes when `unescape` says so.
 * False when it does not fit or comes out empty. */
static bool copy_value(const char *in, bool unescape, char *out, size_t size) {
        size_t n = 0;

        while (*in) {
                char c = *in++;

                if (unescape && c == '\\' && in[0] == 'x' && hexval(in[1]) >= 0 && hexval(in[2]) >= 0) {
                        c = (char) (hexval(in[1]) << 4 | hexval(in[2]));
                        in += 3;
                }

                if (n + 1 >= size)
                        return false;
                out[n++] = c;
        }

        if (n == 0)
                return false;

        out[n] = '\0';
        return true;
}

FstabTag fstab_source_tag(const char *what, char *value, size_t size) {
        int t;

        if (!what || !value || size == 0)
                return FSTAB_TAG_NONE;

        for (t = FSTAB_TAG_NONE + 1; t < _FSTAB_TAG_MAX; t++) {
                size_t tl = strlen(tag_table[t]), ll = strlen(link_table[t]);

                if (strncmp(what, tag_table[t], tl) == 0 && what[tl] == '=')
                        return copy_value(what + tl + 1, false, value, size) ? (FstabTag) t : FSTAB_TAG_NONE;

                if (strncmp(what, link_table[t], ll) == 0 && !strchr(what + ll, '/'))
                        return copy_value(what + ll, true, value, size) ? (FstabTag) t : FSTAB_TAG_NONE;
        }

        return FSTAB_TAG_NONE;
}

bool fstab_source_needs_device(const char *what) {
        char value[PICO_FS_LABEL_MAX];

        if (!what)
                return false;

        return fstab_source_tag(what, value, sizeof(value)) != FSTAB_TAG_NONE ||
                        strncmp(what, "/dev/", 5) == 0;
}

usec_t fstab_device_timeout(const FstabOptions *o, usec_t dflt, bool *ret_clamped) {
        usec_t t;

        if (ret_clamped)
                *ret_clamped = false;

        if (!o || !o->device_timeout_set)
                return dflt;

        t = o->device_timeout;
        if (t == 0 || t > FSTAB_DEVICE_TIMEOUT_MAX) {
                if (ret_clamped)
                        *ret_clamped = true;
                return FSTAB_DEVICE_TIMEOUT_MAX;
        }

        return t;
}

/* --- the sysfs walk --- */

typedef struct BlockDev {
        char *name;
        char *real;      /* the sysfs directory, symlinks resolved */
        unsigned partno; /* 0: a whole disk */
        bool empty;
        bool has_parts;
} BlockDev;

static void block_free(BlockDev *v, size_t n) {
        for (size_t i = 0; i < n; i++) {
                free(v[i].name);
                free(v[i].real);
        }
        free(v);
}

static bool read_ull(const char *dir, const char *attr, unsigned long long *ret) {
        char path[PATH_MAX], buf[32];
        bool ok = false;
        FILE *f;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", dir, attr) >= sizeof(path))
                return false;

        f = fopen(path, "re");
        if (!f)
                return false;
        if (fgets(buf, sizeof(buf), f)) {
                char *end;

                errno = 0;
                *ret = strtoull(buf, &end, 10);
                ok = errno == 0 && end != buf;
        }
        fclose(f);
        return ok;
}

static int skip_dots(const struct dirent *d) {
        return d->d_name[0] != '.';
}

/*
 * The kernel names udev gives /dev/disk/by-* links to, from systemd's
 * 60-persistent-storage.rules ("mmcblk*[0-9]" and friends must end in a
 * digit), plus dm-* and md*, which get theirs from the device-mapper and md
 * rules. Anything else -- ram disks, MTD flash, floppies -- has no by-uuid
 * link upstream either, so it is not read here.
 */
static bool name_has_links(const char *name) {
        static const struct {
                const char *prefix;
                bool digit_last;
        } table[] = {
                {   "loop", false },
                { "mmcblk",  true },
                {  "msblk",  true },
                { "mspblk",  true },
                {   "nvme", false },
                {     "sd", false },
                {     "sr", false },
                {     "vd", false },
                {    "xvd", false },
                { "bcache", false },
                {  "cciss", false },
                {   "dasd", false },
                {    "ubd", false },
                {    "ubi", false },
                {    "scm", false },
                {   "pmem", false },
                {    "nbd", false },
                {     "zd", false },
                {    "rbd", false },
                {   "zram", false },
                {  "ublkb", false },
                {    "dm-", false },
                {     "md", false },
        };
        size_t len = strlen(name);

        for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++)
                if (strncmp(name, table[i].prefix, strlen(table[i].prefix)) == 0 &&
                    (!table[i].digit_last || (len > 0 && name[len - 1] >= '0' && name[len - 1] <= '9')))
                        return true;

        return false;
}

/* The block devices worth reading, in name order. */
static int block_list(const char *sys_root, BlockDev **ret, size_t *ret_n) {
        struct dirent **names = NULL;
        char dir[PATH_MAX];
        BlockDev *v;
        size_t n = 0;
        int k;

        if ((size_t) snprintf(dir, sizeof(dir), "%s/class/block", sys_root) >= sizeof(dir))
                return -ENAMETOOLONG;

        k = scandir(dir, &names, skip_dots, alphasort);
        if (k < 0)
                return -errno;

        v = calloc(k > 0 ? (size_t) k : 1, sizeof(*v));
        if (!v) {
                for (int i = 0; i < k; i++)
                        free(names[i]);
                free(names);
                return -ENOMEM;
        }

        for (int i = 0; i < k; i++) {
                char link[PATH_MAX], real[PATH_MAX];
                unsigned long long val;
                const char *name = names[i]->d_name;

                if (!name_has_links(name))
                        continue;
                if ((size_t) snprintf(link, sizeof(link), "%s/%s", dir, name) >= sizeof(link) ||
                    !realpath(link, real))
                        continue;

                v[n].name = strdup(name);
                v[n].real = strdup(real);
                if (!v[n].name || !v[n].real) {
                        free(v[n].name);
                        free(v[n].real);
                        continue;
                }

                if (read_ull(real, "partition", &val) && val > 0 && val <= UINT_MAX)
                        v[n].partno = (unsigned) val;
                v[n].empty = read_ull(real, "size", &val) && val == 0;
                n++;
        }

        for (int i = 0; i < k; i++)
                free(names[i]);
        free(names);

        /* A partition's sysfs directory sits inside its disk's. */
        for (size_t i = 0; i < n; i++) {
                const char *slash;

                if (v[i].partno == 0 || !(slash = strrchr(v[i].real, '/')))
                        continue;

                for (size_t j = 0; j < n; j++)
                        if (v[j].partno == 0 && strlen(v[j].real) == (size_t) (slash - v[i].real) &&
                            strncmp(v[j].real, v[i].real, (size_t) (slash - v[i].real)) == 0)
                                v[j].has_parts = true;
        }

        *ret = v;
        *ret_n = n;
        return 0;
}

/* The /dev node for a sysfs name. devtmpfs spells a '!' in the kernel's name
 * as a directory separator (cciss!c0d0 is /dev/cciss/c0d0). */
static bool node_of(const char *dev_root, const char *name, char *ret, size_t size) {
        size_t off;

        if ((size_t) snprintf(ret, size, "%s/%s", dev_root, name) >= size)
                return false;

        for (off = strlen(dev_root) + 1; ret[off]; off++)
                if (ret[off] == '!')
                        ret[off] = '/';
        return true;
}

static bool is_child_of(const BlockDev *part, const BlockDev *disk) {
        const char *slash = strrchr(part->real, '/');
        size_t len;

        if (!slash)
                return false;
        len = (size_t) (slash - part->real);
        return strlen(disk->real) == len && strncmp(disk->real, part->real, len) == 0;
}

/* Record a match: the first one is the answer, any later one is logged. */
static void found(const char *what, const char *node, char *ret, size_t size, bool *have) {
        if (*have) {
                pico_log(PICO_LOG_WARNING,
                         "fstab: %s is also on %s; using %s, the first in sysfs order",
                         what,
                         node,
                         ret);
                return;
        }

        if ((size_t) snprintf(ret, size, "%s", node) < size)
                *have = true;
}

static void resolve_partition(
                const BlockDev *v,
                size_t n,
                const char *dev_root,
                FstabTag tag,
                const char *value,
                const char *what,
                char *ret,
                size_t size,
                bool *have) {

        for (size_t i = 0; i < n; i++) {
                char node[PATH_MAX];
                GptPartition *parts = NULL;
                size_t np = 0;

                if (v[i].partno != 0 || v[i].empty || !node_of(dev_root, v[i].name, node, sizeof(node)))
                        continue;

                if (gpt_scan_all(node, &parts, &np) <= 0)
                        continue;

                for (size_t p = 0; p < np; p++) {
                        char uuid[GPT_GUID_STRING_MAX];
                        const char *id = tag == FSTAB_TAG_PARTUUID ? gpt_guid_to_string(&parts[p].uuid, uuid) :
                                                                     parts[p].name;

                        if (strcmp(id, value) != 0)
                                continue;

                        for (size_t j = 0; j < n; j++) {
                                char pnode[PATH_MAX];

                                if (v[j].partno == parts[p].nr && is_child_of(&v[j], &v[i]) &&
                                    node_of(dev_root, v[j].name, pnode, sizeof(pnode)))
                                        found(what, pnode, ret, size, have);
                        }
                }

                free(parts);
        }
}

static void resolve_filesystem(
                const BlockDev *v,
                size_t n,
                const char *dev_root,
                FstabTag tag,
                const char *value,
                PicoFsKind hint,
                const char *what,
                char *ret,
                size_t size,
                bool *have) {

        for (size_t i = 0; i < n; i++) {
                char node[PATH_MAX];
                PicoFsId id;

                /* A disk with a partition table is read through its
                 * partitions; its own first sectors are the table. */
                if (v[i].empty || (v[i].partno == 0 && v[i].has_parts))
                        continue;
                if (!node_of(dev_root, v[i].name, node, sizeof(node)))
                        continue;

                if (pico_fs_probe(node, hint, &id) <= 0)
                        continue;

                if (strcmp(tag == FSTAB_TAG_UUID ? id.uuid : id.label, value) == 0)
                        found(what, node, ret, size, have);
        }
}

int fstab_resolve(const FstabResolver *r, FstabTag tag, const char *value, PicoFsKind hint, char *ret, size_t size) {

        const char *sys_root = r && r->sys_root ? r->sys_root : "/sys";
        const char *dev_root = r && r->dev_root ? r->dev_root : "/dev";
        char what[PICO_FS_LABEL_MAX + 16];
        bool have = false;
        BlockDev *v = NULL;
        size_t n = 0;
        int k;

        if (tag <= FSTAB_TAG_NONE || tag >= _FSTAB_TAG_MAX || !value || !ret || size == 0)
                return -EINVAL;
        if ((tag == FSTAB_TAG_UUID || tag == FSTAB_TAG_LABEL) &&
            (hint < PICO_FS_NONE || hint >= _PICO_FS_KIND_MAX))
                return -EOPNOTSUPP;

        k = block_list(sys_root, &v, &n);
        if (k < 0)
                return k;

        if (r && r->scans)
                (*r->scans)++;

        snprintf(what, sizeof(what), "%s=%s", tag_table[tag], value);

        if (tag == FSTAB_TAG_PARTUUID || tag == FSTAB_TAG_PARTLABEL)
                resolve_partition(v, n, dev_root, tag, value, what, ret, size, &have);
        else
                resolve_filesystem(v, n, dev_root, tag, value, hint, what, ret, size, &have);

        block_free(v, n);
        return have ? 1 : 0;
}

static void sleep_usec(usec_t u) {
        struct timespec ts = {
                .tv_sec = (time_t) (u / USEC_PER_SEC),
                .tv_nsec = (long) ((u % USEC_PER_SEC) * 1000),
        };

        while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
                ;
}

/*
 * A fingerprint of the readable block devices -- names and sizes -- so that a
 * wait only reads devices again once one has come, gone, or had media put in
 * it. Waiting for a tag nobody carries is then a directory listing per poll,
 * not a read of every disk and a log line per GPT-less one.
 */
static uint32_t block_fingerprint(const char *sys_root) {
        BlockDev *v = NULL;
        uint32_t crc = 0;
        size_t n = 0;

        if (block_list(sys_root, &v, &n) < 0)
                return 0;

        for (size_t i = 0; i < n; i++) {
                crc = gpt_crc32(v[i].name, strlen(v[i].name) + 1) ^ (crc * 31);
                crc ^= v[i].empty ? 0x5a5a5a5au : 0;
                crc += v[i].partno;
        }

        block_free(v, n);
        return crc ^ (uint32_t) n;
}

int fstab_wait_device(
                const FstabResolver *r,
                const char *what,
                PicoFsKind hint,
                usec_t timeout,
                fstab_poll_hook_t hook,
                void *userdata,
                char *ret,
                size_t size) {

        const char *sys_root = r && r->sys_root ? r->sys_root : "/sys";
        char value[PICO_FS_LABEL_MAX];
        uint32_t seen = 0;
        FstabTag tag;
        usec_t deadline;
        unsigned attempt;

        if (!what || !ret || size == 0)
                return -EINVAL;

        tag = fstab_source_tag(what, value, sizeof(value));
        deadline = usec_add(now_monotonic(), timeout);

        for (attempt = 0;; attempt++) {
                usec_t now;
                int k;

                if (attempt > 0 && hook)
                        hook(userdata, attempt);

                if (tag != FSTAB_TAG_NONE) {
                        uint32_t fp = block_fingerprint(sys_root);

                        if (attempt == 0 || fp != seen) {
                                seen = fp;
                                k = fstab_resolve(r, tag, value, hint, ret, size);
                                if (k != 0)
                                        return k;
                        }
                } else {
                        struct stat st;

                        if (stat(what, &st) == 0) {
                                if ((size_t) snprintf(ret, size, "%s", what) >= size)
                                        return -ENAMETOOLONG;
                                return 1;
                        }
                }

                now = now_monotonic();
                if (now >= deadline)
                        return 0;

                sleep_usec(deadline - now < FSTAB_DEVICE_POLL ? deadline - now : FSTAB_DEVICE_POLL);
        }
}
