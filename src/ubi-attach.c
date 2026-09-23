/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The ubi.mtd= parser and the UBI_IOCATT attach state machine. ubi-attach.h
 * has why PID 1 attaches UBI itself, and the states.
 */

#define _GNU_SOURCE

#include "ubi-attach.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/major.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>

/* --- ubi.mtd= --- */

/* The kernel's bytes_str_to_int(): a count in any base, then at most one
 * K/M/G. Like the kernel's, it looks only at the first character after the
 * number, so "4KiB" is 4096 too. */
static int bytes_to_int(const char *s, int *ret) {
        unsigned long long v;
        char *end;

        if (!isdigit((unsigned char) s[0]))
                return -EINVAL;

        errno = 0;
        v = strtoull(s, &end, 0);
        if (errno != 0 || v >= INT_MAX)
                return -EINVAL;

        switch (*end) {
        case 'G':
                v *= 1024;
                /* fall through */
        case 'M':
                v *= 1024;
                /* fall through */
        case 'K':
                v *= 1024;
                break;
        case '\0':
                break;
        default:
                return -EINVAL;
        }

        if (v >= INT_MAX)
                return -EINVAL;

        *ret = (int) v;
        return 0;
}

/* kstrtoint(s, 10): the whole string, an optional sign, nothing else. */
static int decimal_to_int(const char *s, int lo, int hi, int *ret) {
        long v;
        char *end;

        if (!*s)
                return -EINVAL;

        errno = 0;
        v = strtol(s, &end, 10);
        if (errno != 0 || *end != '\0' || isspace((unsigned char) s[0]) || v < lo || v > hi)
                return -EINVAL;

        *ret = (int) v;
        return 0;
}

int ubi_mtd_param_parse(const char *val, UbiMtdParam *ret) {
        char buf[UBI_MTD_PARAM_LEN_MAX], *p, *tok[6] = { 0 };
        size_t len, i;
        int v;

        if (!val || !ret)
                return -EINVAL;

        len = strnlen(val, sizeof(buf));
        if (len == sizeof(buf))
                return -EINVAL;
        if (len == 0)
                return 0;
        memcpy(buf, val, len + 1);
        if (buf[len - 1] == '\n')
                buf[len - 1] = '\0';

        p = buf;
        for (i = 0; i < 6 && p; i++)
                tok[i] = strsep(&p, ",");
        if (p)
                return -EINVAL; /* a seventh field */

        *ret = (UbiMtdParam){ .ubi_num = UBI_DEV_NUM_AUTO };

        /* The kernel copies an empty name and fails the attach later. */
        if (tok[0][0] == '\0')
                return -EINVAL;
        snprintf(ret->mtd, sizeof(ret->mtd), "%s", tok[0]);

        if (tok[1] && bytes_to_int(tok[1], &ret->vid_hdr_offs) < 0)
                return -EINVAL;
        if (tok[2] && decimal_to_int(tok[2], 0, UBI_BEB_LIMIT_MAX, &ret->max_beb_per1024) < 0)
                return -EINVAL;
        if (tok[3] && decimal_to_int(tok[3], UBI_DEV_NUM_AUTO, UBI_ATTACH_MAX - 1, &ret->ubi_num) < 0)
                return -EINVAL;
        if (tok[4]) {
                if (decimal_to_int(tok[4], INT_MIN, INT_MAX, &v) < 0)
                        return -EINVAL;
                ret->enable_fm = v != 0;
        }
        if (tok[5]) {
                if (decimal_to_int(tok[5], INT_MIN, INT_MAX, &v) < 0)
                        return -EINVAL;
                ret->need_resv_pool = v != 0;
        }

        return 1;
}

/*
 * The kernel's next_arg(): one "param" or "param=value" off the front of
 * `args`, with double quotes allowed around the whole of it or around the
 * value and stripped from both. NUL-terminates in place; returns where the
 * next one starts.
 */
static char *next_arg(char *args, char **param, char **val) {
        unsigned i, equals = 0;
        bool in_quote = false, quoted = false;

        if (*args == '"') {
                args++;
                in_quote = quoted = true;
        }

        for (i = 0; args[i]; i++) {
                if (isspace((unsigned char) args[i]) && !in_quote)
                        break;
                if (equals == 0 && args[i] == '=')
                        equals = i;
                if (args[i] == '"')
                        in_quote = !in_quote;
        }

        *param = args;
        if (!equals)
                *val = NULL;
        else {
                args[equals] = '\0';
                *val = args + equals + 1;

                if (**val == '"') {
                        (*val)++;
                        if (args[i - 1] == '"')
                                args[i - 1] = '\0';
                }
        }
        if (quoted && i > 0 && args[i - 1] == '"')
                args[i - 1] = '\0';

        if (args[i]) {
                args[i] = '\0';
                args += i + 1;
        } else
                args += i;

        while (isspace((unsigned char) *args))
                args++;
        return args;
}

size_t ubi_cmdline_params(const char *cmdline, UbiMtdParam *ret, size_t max) {
        char *copy, *args, *param, *val;
        size_t n = 0;
        bool full = false;

        if (!cmdline || !(copy = strdup(cmdline)))
                return 0;

        args = copy;
        while (isspace((unsigned char) *args))
                args++;

        while (*args) {
                args = next_arg(args, &param, &val);

                if (!val && strcmp(param, "--") == 0)
                        break;
                if (strcmp(param, "ubi.mtd") != 0)
                        continue;

                if (n == max) {
                        if (!full)
                                pico_log(PICO_LOG_WARNING,
                                         "ubi: more than %zu ubi.mtd= parameters, ignoring the rest",
                                         max);
                        full = true;
                        continue;
                }

                switch (ubi_mtd_param_parse(val, &ret[n])) {
                case 1:
                        n++;
                        break;
                case 0:
                        pico_log(PICO_LOG_WARNING, "ubi: ignoring an empty ubi.mtd=");
                        break;
                default:
                        pico_log(PICO_LOG_WARNING, "ubi: ignoring malformed ubi.mtd=%s", val ? val : "");
                        break;
                }
        }

        free(copy);
        return n;
}

int ubi_cmdline_load(const char *path, UbiMtdParam *ret, size_t max) {
        char *line = NULL;
        size_t cap = 0;
        FILE *f;
        int n = 0;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        if (getline(&line, &cap, f) >= 0)
                n = (int) ubi_cmdline_params(line, ret, max);

        free(line);
        fclose(f);
        return n;
}

/* --- sysfs --- */

/* The first line of <dir>/<name>, its newline dropped. */
static bool read_attr(const char *dir, const char *name, char *buf, size_t size) {
        char path[PATH_MAX];
        bool ok;
        FILE *f;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", dir, name) >= sizeof(path))
                return false;

        f = fopen(path, "re");
        if (!f)
                return false;
        ok = fgets(buf, (int) size, f) != NULL;
        fclose(f);

        if (ok)
                buf[strcspn(buf, "\n")] = '\0';
        return ok;
}

static bool read_int_attr(const char *dir, const char *name, int *ret) {
        char buf[32];

        return read_attr(dir, name, buf, sizeof(buf)) && decimal_to_int(buf, 0, INT_MAX, ret) == 0;
}

/* The N in "<prefix>N" for a name that is exactly that, else -1. */
static int numbered(const char *name, const char *prefix) {
        size_t pl = strlen(prefix);
        int v;

        if (strncmp(name, prefix, pl) != 0 || !isdigit((unsigned char) name[pl]))
                return -1;
        if (decimal_to_int(name + pl, 0, INT_MAX, &v) < 0)
                return -1;
        return v;
}

static const char *sys_or_default(const char *sys_root) {
        return sys_root ? sys_root : "/sys";
}

int ubi_mtd_num_from_devnum(dev_t d) {
        if (major(d) != MTD_CHAR_MAJOR)
                return -EINVAL;
        return (int) (minor(d) >> 1);
}

int ubi_mtd_find(const char *sys_root, const char *spec) {
        char dir[PATH_MAX], sub[PATH_MAX + 64], name[256];
        const char *sys = sys_or_default(sys_root);
        unsigned long long num;
        struct dirent *de;
        struct stat st;
        char *end;
        int best = -1;
        DIR *d;

        if (!spec || !*spec)
                return -EINVAL;

        if ((size_t) snprintf(dir, sizeof(dir), "%s/class/mtd", sys) >= sizeof(dir))
                return -ENAMETOOLONG;

        /* A number, in any base, as simple_strtoul(.., 0) reads it. */
        if (isdigit((unsigned char) spec[0])) {
                errno = 0;
                num = strtoull(spec, &end, 0);
                if (errno == 0 && *end == '\0') {
                        if (num > INT_MAX)
                                return -ENOENT;
                        snprintf(sub, sizeof(sub), "%s/mtd%llu", dir, num);
                        return stat(sub, &st) == 0 ? (int) num : -ENOENT;
                }
        }

        /* A name: the lowest-numbered device carrying it, as the kernel's
         * get_mtd_device_nm() walks them. mtdNro is the same device again. */
        d = opendir(dir);
        if (d) {
                while ((de = readdir(d))) {
                        int n = numbered(de->d_name, "mtd");

                        if (n < 0 || (best >= 0 && n >= best))
                                continue;
                        if ((size_t) snprintf(sub, sizeof(sub), "%s/%s", dir, de->d_name) >= sizeof(sub))
                                continue;
                        if (read_attr(sub, "name", name, sizeof(name)) && strcmp(name, spec) == 0)
                                best = n;
                }
                closedir(d);
        }
        if (best >= 0)
                return best;

        /* A character device node. */
        if (stat(spec, &st) < 0)
                return errno == ENOENT || errno == ENOTDIR ? -ENOENT : -errno;
        if (!S_ISCHR(st.st_mode))
                return -EINVAL;
        return ubi_mtd_num_from_devnum(st.st_rdev);
}

int ubi_attached_as(const char *sys_root, int mtd_num) {
        char dir[PATH_MAX], sub[PATH_MAX + 64];
        struct dirent *de;
        int found = -ENOENT;
        DIR *d;

        if ((size_t) snprintf(dir, sizeof(dir), "%s/class/ubi", sys_or_default(sys_root)) >= sizeof(dir))
                return -ENAMETOOLONG;

        d = opendir(dir);
        if (!d)
                return -ENOENT; /* no UBI at all */

        while (found < 0 && (de = readdir(d))) {
                int n = numbered(de->d_name, "ubi"), m;

                /* "ubiN" only; a volume's "ubiN_M" is not numbered(). */
                if (n < 0)
                        continue;
                if ((size_t) snprintf(sub, sizeof(sub), "%s/%s", dir, de->d_name) >= sizeof(sub))
                        continue;
                if (read_int_attr(sub, "mtd_num", &m) && m == mtd_num)
                        found = n;
        }

        closedir(d);
        return found;
}

int ubi_device_mtd(const char *sys_root, int ubi_num) {
        char dir[PATH_MAX];
        int m;

        if ((size_t) snprintf(dir, sizeof(dir), "%s/class/ubi/ubi%d", sys_or_default(sys_root), ubi_num) >=
            sizeof(dir))
                return -ENAMETOOLONG;

        return read_int_attr(dir, "mtd_num", &m) ? m : -ENOENT;
}

/* --- the state machine --- */

static const char * const state_table[_UBI_ATTACH_STATE_MAX] = {
        [UBI_ATTACH_WAIT_MTD] = "wait-mtd", [UBI_ATTACH_WAIT_CTRL] = "wait-ctrl",
        [UBI_ATTACH_ATTACH] = "attach",     [UBI_ATTACH_DONE] = "done",
        [UBI_ATTACH_FAILED] = "failed",     [UBI_ATTACH_TIMEOUT] = "timeout",
};

const char *ubi_attach_state_to_string(UbiAttachState s) {
        if ((unsigned) s >= _UBI_ATTACH_STATE_MAX)
                return NULL;
        return state_table[s];
}

void ubi_attach_init(UbiAttach *a, const UbiMtdParam *p) {
        *a = (UbiAttach){
                .param = *p,
                .state = UBI_ATTACH_WAIT_MTD,
                .mtd_num = -1,
                .ubi_num = -1,
        };
}

static void finish(UbiAttach *a, UbiAttachState s, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

static void finish(UbiAttach *a, UbiAttachState s, const char *fmt, ...) {
        va_list ap;

        a->state = s;
        va_start(ap, fmt);
        vsnprintf(a->reason, sizeof(a->reason), fmt, ap);
        va_end(ap);
}

static int attach_ioctl(const char *ctrl, struct ubi_attach_req *req, void *userdata) {
        int fd, r = 0;

        (void) userdata;

        fd = open(ctrl, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;
        if (ioctl(fd, UBI_IOCATT, req) < 0)
                r = -errno;
        close(fd);
        return r;
}

/* Already attached: done when the number is the one asked for, or any
 * number was. */
static bool settle_attached(UbiAttach *a, int ubi_num) {
        if (a->param.ubi_num != UBI_DEV_NUM_AUTO && ubi_num != a->param.ubi_num) {
                finish(a,
                       UBI_ATTACH_FAILED,
                       "mtd%d is attached as ubi%d already, not ubi%d",
                       a->mtd_num,
                       ubi_num,
                       a->param.ubi_num);
                return true;
        }

        a->ubi_num = ubi_num;
        a->already = true;
        finish(a, UBI_ATTACH_DONE, "mtd%d was attached as ubi%d already", a->mtd_num, ubi_num);
        return true;
}

bool ubi_attach_step(UbiAttach *a, const UbiEnv *env) {
        const char *sys = env ? env->sys_root : NULL;
        const char *dev = env && env->dev_root ? env->dev_root : "/dev";
        ubi_attach_ioctl_t attach = env && env->attach ? env->attach : attach_ioctl;
        struct ubi_attach_req req;
        char ctrl[PATH_MAX];
        struct stat st;
        int r;

        if ((size_t) snprintf(ctrl, sizeof(ctrl), "%s/ubi_ctrl", dev) >= sizeof(ctrl)) {
                finish(a, UBI_ATTACH_FAILED, "path too long");
                return true;
        }

        switch (a->state) {
        case UBI_ATTACH_WAIT_MTD:
                r = ubi_mtd_find(sys, a->param.mtd);
                if (r == -ENOENT)
                        return false;
                if (r < 0) {
                        finish(a, UBI_ATTACH_FAILED, "%s is not an MTD device: %s", a->param.mtd, strerror(-r));
                        return true;
                }
                a->mtd_num = r;

                r = ubi_attached_as(sys, a->mtd_num);
                if (r >= 0)
                        return settle_attached(a, r);

                if (a->param.ubi_num != UBI_DEV_NUM_AUTO) {
                        r = ubi_device_mtd(sys, a->param.ubi_num);
                        if (r >= 0) {
                                finish(a,
                                       UBI_ATTACH_FAILED,
                                       "ubi%d is taken by mtd%d already",
                                       a->param.ubi_num,
                                       r);
                                return true;
                        }
                }

                a->state = UBI_ATTACH_WAIT_CTRL;
                /* fall through */

        case UBI_ATTACH_WAIT_CTRL:
                if (stat(ctrl, &st) < 0)
                        return false;
                a->state = UBI_ATTACH_ATTACH;
                /* fall through */

        case UBI_ATTACH_ATTACH:
                memset(&req, 0, sizeof(req));
                req.ubi_num = a->param.ubi_num;
                req.mtd_num = a->mtd_num;
                req.vid_hdr_offset = a->param.vid_hdr_offs;
                req.max_beb_per1024 = (__s16) a->param.max_beb_per1024;
                req.disable_fm = !a->param.enable_fm;
                req.need_resv_pool = a->param.need_resv_pool;

                r = attach(ctrl, &req, env ? env->attach_userdata : NULL);
                if (r == 0) {
                        a->ubi_num = req.ubi_num;
                        finish(a, UBI_ATTACH_DONE, "mtd%d attached as ubi%d", a->mtd_num, a->ubi_num);
                        return true;
                }

                /* Attached meanwhile by someone else, or the number is taken:
                 * sysfs says which. */
                if (r == -EEXIST) {
                        int u = ubi_attached_as(sys, a->mtd_num);

                        if (u >= 0)
                                return settle_attached(a, u);
                }

                finish(a, UBI_ATTACH_FAILED, "UBI_IOCATT on mtd%d: %s", a->mtd_num, strerror(-r));
                return true;

        default:
                return true;
        }
}

static void sleep_usec(usec_t u) {
        struct timespec ts = {
                .tv_sec = (time_t) (u / USEC_PER_SEC),
                .tv_nsec = (long) ((u % USEC_PER_SEC) * 1000),
        };

        while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
                ;
}

size_t ubi_attach_run(UbiAttach *v, size_t n, const UbiEnv *env, usec_t timeout) {
        usec_t deadline = usec_add(now_monotonic(), timeout);
        unsigned attempt = 0;
        size_t done = 0;

        for (size_t i = 0; i < n; i++) {
                UbiAttach *a = &v[i];

                while (!ubi_attach_step(a, env)) {
                        usec_t now = now_monotonic();

                        if (now >= deadline) {
                                if (a->state == UBI_ATTACH_WAIT_MTD)
                                        finish(a,
                                               UBI_ATTACH_TIMEOUT,
                                               "MTD device %s never appeared",
                                               a->param.mtd);
                                else
                                        finish(a,
                                               UBI_ATTACH_TIMEOUT,
                                               "UBI never appeared: no %s/ubi_ctrl",
                                               env && env->dev_root ? env->dev_root : "/dev");
                                break;
                        }

                        sleep_usec(deadline - now < UBI_ATTACH_POLL ? deadline - now : UBI_ATTACH_POLL);
                        if (env && env->poll_hook)
                                env->poll_hook(env->poll_userdata, ++attempt);
                }

                if (a->state == UBI_ATTACH_DONE) {
                        done++;
                        pico_log(a->already ? PICO_LOG_DEBUG : PICO_LOG_INFO, "ubi: %s", a->reason);
                } else
                        pico_log(PICO_LOG_WARNING, "ubi: not attaching ubi.mtd=%s: %s", a->param.mtd, a->reason);
        }

        return done;
}

/* --- ubifs sources --- */

bool ubi_source_parse(const char *what, UbiSource *ret) {
        unsigned long dev, vol;
        const char *s;
        char *end;

        if (!what || !ret)
                return false;

        *ret = (UbiSource){ .vol_id = -1 };

        if (what[0] == '/') {
                s = strrchr(what, '/') + 1;
                if (strncmp(s, "ubi", 3) != 0 || !isdigit((unsigned char) s[3]))
                        return false;
                dev = strtoul(s + 3, &end, 10);
                if (*end != '_' || !isdigit((unsigned char) end[1]))
                        return false;
                vol = strtoul(end + 1, &end, 10);
                if (*end != '\0' || dev >= UBI_ATTACH_MAX || vol > INT_MAX)
                        return false;
                ret->ubi_num = (int) dev;
                ret->vol_id = (int) vol;
                ret->path = true;
                return true;
        }

        if (strncmp(what, "ubi", 3) != 0)
                return false;

        /* ubi:NAME, device 0. */
        if ((what[3] == ':' || what[3] == '!') && what[4] != '\0')
                return (size_t) snprintf(ret->name, sizeof(ret->name), "%s", what + 4) < sizeof(ret->name);

        if (!isdigit((unsigned char) what[3]))
                return false;

        /* The kernel reads these numbers with simple_strtoul(.., 0). */
        dev = strtoul(what + 3, &end, 0);

        /* ubiY: device 0, volume Y. */
        if (*end == '\0') {
                if (dev > INT_MAX)
                        return false;
                ret->vol_id = (int) dev;
                return true;
        }

        if (dev >= UBI_ATTACH_MAX)
                return false;
        ret->ubi_num = (int) dev;

        /* ubiX_Y. */
        if (*end == '_' && isdigit((unsigned char) end[1])) {
                vol = strtoul(end + 1, &end, 0);
                if (*end != '\0' || vol > INT_MAX)
                        return false;
                ret->vol_id = (int) vol;
                return true;
        }

        /* ubiX:NAME. */
        if ((*end == ':' || *end == '!') && end[1] != '\0')
                return (size_t) snprintf(ret->name, sizeof(ret->name), "%s", end + 1) < sizeof(ret->name);

        return false;
}

int ubi_volume_present(const char *sys_root, const UbiSource *s) {
        char dir[PATH_MAX], sub[PATH_MAX + 64], prefix[32], name[UBI_MAX_VOLUME_NAME + 2];
        const char *sys = sys_or_default(sys_root);
        struct dirent *de;
        struct stat st;
        int found = 0;
        DIR *d;

        if ((size_t) snprintf(dir, sizeof(dir), "%s/class/ubi", sys) >= sizeof(dir))
                return -ENAMETOOLONG;

        snprintf(sub, sizeof(sub), "%s/ubi%d", dir, s->ubi_num);
        if (stat(sub, &st) < 0)
                return -ENODEV;

        if (s->vol_id >= 0) {
                snprintf(sub, sizeof(sub), "%s/ubi%d_%d", dir, s->ubi_num, s->vol_id);
                return stat(sub, &st) == 0;
        }

        snprintf(prefix, sizeof(prefix), "ubi%d_", s->ubi_num);

        d = opendir(dir);
        if (!d)
                return -ENODEV;

        while (!found && (de = readdir(d))) {
                if (numbered(de->d_name, prefix) < 0)
                        continue;
                if ((size_t) snprintf(sub, sizeof(sub), "%s/%s", dir, de->d_name) >= sizeof(sub))
                        continue;
                if (read_attr(sub, "name", name, sizeof(name)) && strcmp(name, s->name) == 0)
                        found = 1;
        }

        closedir(d);
        return found;
}

void ubi_source_describe(const UbiSource *s, char *buf, size_t size) {
        if (s->vol_id >= 0)
                snprintf(buf, size, "ubi%d volume %d", s->ubi_num, s->vol_id);
        else
                snprintf(buf, size, "ubi%d volume \"%s\"", s->ubi_num, s->name);
}
