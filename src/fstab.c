/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The /etc/fstab parser, option table and outcome record. fstab.h has the
 * grammar and the three-way option split this implements.
 */

#include "fstab.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>

static const char * const outcome_table[_FSTAB_OUTCOME_MAX] = {
        [FSTAB_PENDING] = "pending", [FSTAB_MOUNTED] = "mounted", [FSTAB_REMOUNTED] = "remounted",
        [FSTAB_PRESENT] = "present", [FSTAB_NOAUTO] = "noauto",   [FSTAB_SKIPPED] = "skipped",
        [FSTAB_FAILED] = "failed",
};

const char *fstab_outcome_to_string(FstabOutcome o) {
        if ((unsigned) o >= _FSTAB_OUTCOME_MAX)
                return "unknown";
        return outcome_table[o];
}

FstabOutcome fstab_outcome_from_string(const char *s) {
        unsigned i;

        for (i = 0; s && i < _FSTAB_OUTCOME_MAX; i++)
                if (strcmp(s, outcome_table[i]) == 0)
                        return (FstabOutcome) i;

        return _FSTAB_OUTCOME_MAX;
}

bool fstab_outcome_is_degraded(FstabOutcome o) {
        return o == FSTAB_SKIPPED || o == FSTAB_FAILED;
}

static bool is_octal(char c) {
        return c >= '0' && c <= '7';
}

void fstab_unescape(char *s) {
        char *r = s, *w = s;

        if (!s)
                return;

        while (*r) {
                if (r[0] == '\\' && is_octal(r[1]) && is_octal(r[2]) && is_octal(r[3])) {
                        *w++ = (char) (((r[1] - '0') << 6) | ((r[2] - '0') << 3) | (r[3] - '0'));
                        r += 4;
                } else
                        *w++ = *r++;
        }

        *w = '\0';
}

int fstab_escape(const char *s, char *buf, size_t size) {
        size_t o = 0;

        for (; *s; s++) {
                bool esc = *s == ' ' || *s == '\t' || *s == '\n' || *s == '\\';
                size_t need = esc ? 4 : 1;

                if (o + need >= size)
                        return -ENAMETOOLONG;

                if (esc) {
                        snprintf(buf + o, 5, "\\%03o", (unsigned char) *s);
                        o += 4;
                } else
                        buf[o++] = *s;
        }

        if (o >= size)
                return -ENAMETOOLONG;

        buf[o] = '\0';
        return 0;
}

/*
 * The per-mount attributes. `invert` names the option that turns the
 * attribute off rather than on. The atime modes are handled apart from this
 * table because they are one three-way field, not three bits.
 */
static const struct {
        const char *name;
        uint64_t attr;
        bool invert;
} attr_table[] = {
        {          "ro",      MOUNT_ATTR_RDONLY, false },
        {          "rw",      MOUNT_ATTR_RDONLY,  true },
        {      "nosuid",      MOUNT_ATTR_NOSUID, false },
        {        "suid",      MOUNT_ATTR_NOSUID,  true },
        {       "nodev",       MOUNT_ATTR_NODEV, false },
        {         "dev",       MOUNT_ATTR_NODEV,  true },
        {      "noexec",      MOUNT_ATTR_NOEXEC, false },
        {        "exec",      MOUNT_ATTR_NOEXEC,  true },
        {  "nodiratime",  MOUNT_ATTR_NODIRATIME, false },
        {    "diratime",  MOUNT_ATTR_NODIRATIME,  true },
        { "nosymfollow", MOUNT_ATTR_NOSYMFOLLOW, false },
        {   "symfollow", MOUNT_ATTR_NOSYMFOLLOW,  true },
};

/*
 * atime: the last option wins, and every one of them -- including the
 * negations, which fall back to the kernel's relatime default the way
 * libmount's optlist.c has them -- claims the whole field.
 */
static const struct {
        const char *name;
        uint64_t mode;
} atime_table[] = {
        {       "noatime",     MOUNT_ATTR_NOATIME },
        {      "relatime",    MOUNT_ATTR_RELATIME },
        {   "strictatime", MOUNT_ATTR_STRICTATIME },
        {         "atime",    MOUNT_ATTR_RELATIME },
        {    "norelatime",    MOUNT_ATTR_RELATIME },
        { "nostrictatime",    MOUNT_ATTR_RELATIME },
};

/* The VFS's own generic superblock flags (fs/fs_context.c), which it accepts
 * as fsconfig() flags for every filesystem type. ro/rw are not listed: they
 * live in attr_set/attr_clr and are sent from there. */
static const char * const sb_flag_table[] = {
        "sync", "async", "dirsync", "lazytime", "nolazytime", "mand", "nomand",
};

/* Options that mean something to mount(8) or to systemd and nothing to the
 * kernel. Whole-token matches; prefixes are handled in is_userspace_option(). */
static const char * const userspace_table[] = {
        "defaults", "auto", "user", "users", "nouser", "owner", "group", "remount", "silent", "loud", "sw",
};

static bool is_userspace_option(const char *name) {
        size_t i;

        for (i = 0; i < sizeof(userspace_table) / sizeof(userspace_table[0]); i++)
                if (strcmp(name, userspace_table[i]) == 0)
                        return true;

        /* x-* is userspace by libmount's own convention, X-* is its older
         * spelling; comment= is systemd's. The loop device parameters only
         * mean something to losetup, which is not here. */
        return strncmp(name, "x-", 2) == 0 || strncmp(name, "X-", 2) == 0 || strcmp(name, "comment") == 0 ||
                        strcmp(name, "uhelper") == 0 || strcmp(name, "helper") == 0 ||
                        strcmp(name, "offset") == 0 || strcmp(name, "sizelimit") == 0 ||
                        strcmp(name, "encryption") == 0;
}

static bool is_propagation_option(const char *name) {
        static const char * const table[] = {
                "shared", "rshared", "private", "rprivate", "slave", "rslave", "unbindable", "runbindable",
        };
        size_t i;

        for (i = 0; i < sizeof(table) / sizeof(table[0]); i++)
                if (strcmp(name, table[i]) == 0)
                        return true;
        return false;
}

/* systemd's time span syntax, the subset fstab lines use: a number with an
 * optional unit, bare meaning seconds. 0 or -EINVAL. */
static int parse_timespan(const char *s, usec_t *ret) {
        static const struct {
                const char *suffix;
                usec_t mult;
        } units[] = {
                {    "",        USEC_PER_SEC },
                {   "s",        USEC_PER_SEC },
                { "sec",        USEC_PER_SEC },
                {  "ms",       USEC_PER_MSEC },
                {  "us",          (usec_t) 1 },
                {   "m",   60 * USEC_PER_SEC },
                { "min",   60 * USEC_PER_SEC },
                {   "h", 3600 * USEC_PER_SEC },
        };
        unsigned long long v;
        char *end;
        size_t i;

        if (strcmp(s, "infinity") == 0) {
                *ret = USEC_INFINITY;
                return 0;
        }

        if (*s < '0' || *s > '9')
                return -EINVAL;

        errno = 0;
        v = strtoull(s, &end, 10);
        if (errno != 0)
                return -EINVAL;

        for (i = 0; i < sizeof(units) / sizeof(units[0]); i++)
                if (strcmp(end, units[i].suffix) == 0) {
                        if (v > USEC_INFINITY / units[i].mult)
                                return -EINVAL;
                        *ret = (usec_t) v * units[i].mult;
                        return 0;
                }

        return -EINVAL;
}

/* Apply one option, `name` NUL-terminated and `value` the text after '=' (NULL
 * when there was none). `raw` is the option as written, for pass-through. */
static int apply_option(FstabOptions *o, const char *name, const char *value, const char *raw) {
        size_t i;

        for (i = 0; i < sizeof(attr_table) / sizeof(attr_table[0]); i++)
                if (!value && strcmp(name, attr_table[i].name) == 0) {
                        if (attr_table[i].invert) {
                                o->attr_clr |= attr_table[i].attr;
                                o->attr_set &= ~attr_table[i].attr;
                        } else {
                                o->attr_set |= attr_table[i].attr;
                                o->attr_clr &= ~attr_table[i].attr;
                        }
                        return 0;
                }

        for (i = 0; i < sizeof(atime_table) / sizeof(atime_table[0]); i++)
                if (!value && strcmp(name, atime_table[i].name) == 0) {
                        o->attr_set = (o->attr_set & ~(uint64_t) MOUNT_ATTR__ATIME) | atime_table[i].mode;
                        o->attr_clr |= MOUNT_ATTR__ATIME;
                        return 0;
                }

        for (i = 0; i < sizeof(sb_flag_table) / sizeof(sb_flag_table[0]); i++)
                if (!value && strcmp(name, sb_flag_table[i]) == 0)
                        return pico_strv_extend(&o->sb_flags, name);

        if (!value && strcmp(name, "noauto") == 0) {
                o->noauto = true;
                return 0;
        }
        if (!value && strcmp(name, "nofail") == 0) {
                o->nofail = true;
                return 0;
        }
        if (!value && strcmp(name, "_netdev") == 0) {
                o->netdev = true;
                return 0;
        }
        if (!value && strcmp(name, "bind") == 0) {
                o->bind = true;
                return 0;
        }
        if (!value && strcmp(name, "rbind") == 0) {
                o->rbind = true;
                return 0;
        }
        if (strcmp(name, "loop") == 0) {
                o->loop = true;
                return 0;
        }
        if (!value && is_propagation_option(name)) {
                o->propagation = true;
                return 0;
        }

        if (!value && strcmp(name, "x-systemd.automount") == 0) {
                o->automount = true;
                return 0;
        }
        if (value && strcmp(name, "x-systemd.device-timeout") == 0) {
                usec_t t;

                if (parse_timespan(value, &t) < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "fstab: ignoring unparsable x-systemd.device-timeout=%s",
                                 value);
                else
                        o->device_timeout = t;
                return 0;
        }

        if (is_userspace_option(name))
                return 0;

        return pico_strv_extend(&o->data, raw);
}

int fstab_options_parse(const char *options, FstabOptions *ret) {
        const char *p = options ? options : "";
        int r = 0;

        memset(ret, 0, sizeof(*ret));
        ret->device_timeout = USEC_INFINITY;

        while (*p) {
                size_t len = strcspn(p, ",");
                char *raw, *eq;

                if (len > 0) {
                        raw = strndup(p, len);
                        if (!raw) {
                                r = -ENOMEM;
                                break;
                        }

                        /* The name is everything before the first '=', so
                         * "key=a=b" hands the filesystem "a=b" as the value. */
                        eq = strchr(raw, '=');
                        if (eq == raw) {
                                free(raw);
                                r = -EINVAL;
                                break;
                        }

                        if (eq) {
                                char *name = strndup(raw, (size_t) (eq - raw));

                                if (!name) {
                                        free(raw);
                                        r = -ENOMEM;
                                        break;
                                }
                                r = apply_option(ret, name, eq + 1, raw);
                                free(name);
                        } else
                                r = apply_option(ret, raw, NULL, raw);

                        free(raw);
                        if (r < 0)
                                break;
                }

                p += len;
                if (*p == ',')
                        p++;
        }

        if (r < 0)
                fstab_options_done(ret);

        return r;
}

void fstab_options_done(FstabOptions *o) {
        if (!o)
                return;

        o->sb_flags = pico_strv_free(o->sb_flags);
        o->data = pico_strv_free(o->data);
}

bool fstab_options_trivial(const FstabOptions *o) {
        if (!o)
                return true;

        return o->attr_set == 0 && (o->attr_clr & ~(uint64_t) MOUNT_ATTR_RDONLY) == 0 && !o->sb_flags &&
                        !o->data;
}

/*
 * Collapse doubled slashes and drop a trailing one, so "/var//volatile/" is
 * the "/var/volatile" mountinfo will call it. Only absolute paths; "none" and
 * "swap" in the mount point field are left as written.
 */
static void normalize_path(char *s) {
        char *r = s, *w = s;

        if (!s || s[0] != '/')
                return;

        while (*r) {
                *w++ = *r;
                if (*r == '/')
                        while (r[1] == '/')
                                r++;
                r++;
        }
        *w = '\0';

        if (w - s > 1 && w[-1] == '/')
                w[-1] = '\0';
}

/* Next whitespace-separated field of *p, NUL-terminated in place. */
static char *next_field(char **p) {
        char *s = *p, *start;

        s += strspn(s, " \t\r\n");
        if (*s == '\0') {
                *p = s;
                return NULL;
        }

        start = s;
        s += strcspn(s, " \t\r\n");
        if (*s)
                *s++ = '\0';

        *p = s;
        return start;
}

static int parse_int_field(const char *s, int *ret) {
        long v;
        char *end;

        errno = 0;
        v = strtol(s, &end, 10);
        if (errno != 0 || *end != '\0' || end == s || v < INT_MIN || v > INT_MAX)
                return -EINVAL;

        *ret = (int) v;
        return 0;
}

int fstab_parse_line(const char *line, FstabEntry *ret) {
        const char *start = line ? line : "";
        char *copy, *p, *f[6];
        size_t n = 0;
        int r;

        memset(ret, 0, sizeof(*ret));

        start += strspn(start, " \t\r\n");
        if (*start == '\0' || *start == '#')
                return 0;

        copy = pico_strdup(start);
        if (!copy)
                return -ENOMEM;

        p = copy;
        while (n < 6 && (f[n] = next_field(&p)))
                n++;

        if (n < 3) {
                free(copy);
                return -EINVAL;
        }

        if ((n >= 5 && parse_int_field(f[4], &ret->freq) < 0) ||
            (n >= 6 && parse_int_field(f[5], &ret->passno) < 0)) {
                free(copy);
                return -EINVAL;
        }

        ret->what = pico_strdup(f[0]);
        ret->where = pico_strdup(f[1]);
        ret->type = pico_strdup(f[2]);
        ret->options = pico_strdup(n >= 4 ? f[3] : "defaults");
        free(copy);

        if (!ret->what || !ret->where || !ret->type || !ret->options) {
                fstab_entry_done(ret);
                return -ENOMEM;
        }

        fstab_unescape(ret->what);
        fstab_unescape(ret->where);
        fstab_unescape(ret->type);
        fstab_unescape(ret->options);
        normalize_path(ret->where);

        r = fstab_options_parse(ret->options, &ret->opts);
        if (r < 0) {
                fstab_entry_done(ret);
                return r;
        }

        return 1;
}

void fstab_entry_done(FstabEntry *e) {
        if (!e)
                return;

        free(e->what);
        free(e->where);
        free(e->type);
        free(e->options);
        free(e->reason);
        fstab_options_done(&e->opts);
        memset(e, 0, sizeof(*e));
}

void fstab_entry_set_outcome(FstabEntry *e, FstabOutcome o, const char *reason_fmt, ...) {
        char buf[512];
        va_list ap;

        if (!e)
                return;

        e->outcome = o;
        e->reason = pico_mfree(e->reason);

        if (!reason_fmt)
                return;

        va_start(ap, reason_fmt);
        vsnprintf(buf, sizeof(buf), reason_fmt, ap);
        va_end(ap);

        e->reason = pico_strdup(buf); /* NULL on OOM just loses the reason */
}

int fstab_load(const char *path, FstabTable *ret) {
        char *line = NULL;
        size_t cap = 0;
        unsigned lineno = 0;
        FILE *f;
        int r = 0;

        ret->entries = NULL;
        ret->n = 0;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        while (getline(&line, &cap, f) >= 0) {
                FstabEntry e, *grown;

                lineno++;

                r = fstab_parse_line(line, &e);
                if (r == 0)
                        continue;
                if (r == -EINVAL) {
                        pico_log(PICO_LOG_WARNING, "%s:%u: malformed line, ignoring it", path, lineno);
                        r = 0;
                        continue;
                }
                if (r < 0)
                        break;

                e.line = lineno;

                grown = realloc(ret->entries, (ret->n + 1) * sizeof(*grown));
                if (!grown) {
                        fstab_entry_done(&e);
                        r = -ENOMEM;
                        break;
                }

                ret->entries = grown;
                ret->entries[ret->n++] = e;
                r = 0;
        }

        free(line);
        fclose(f);

        if (r < 0)
                fstab_table_done(ret);

        return r;
}

void fstab_table_done(FstabTable *t) {
        size_t i;

        if (!t)
                return;

        for (i = 0; i < t->n; i++)
                fstab_entry_done(&t->entries[i]);

        free(t->entries);
        t->entries = NULL;
        t->n = 0;
}

FstabEntry *fstab_find(FstabTable *t, const char *where) {
        FstabEntry *found = NULL;
        size_t i;

        if (!t || !where)
                return NULL;

        for (i = 0; i < t->n; i++)
                if (t->entries[i].where && strcmp(t->entries[i].where, where) == 0)
                        found = &t->entries[i];

        return found;
}

unsigned fstab_path_depth(const char *path) {
        unsigned depth = 0;
        const char *p = path;

        if (!p)
                return 0;

        while (*p) {
                p += strspn(p, "/");
                if (*p == '\0')
                        break;
                depth++;
                p += strcspn(p, "/");
        }

        return depth;
}

int fstab_mount_order(FstabTable *t, FstabEntry ***ret_order) {
        FstabEntry **v;
        size_t i, j;

        *ret_order = NULL;
        if (t->n == 0)
                return 0;

        v = malloc(t->n * sizeof(*v));
        if (!v)
                return -ENOMEM;

        /* Insertion sort: stable, allocation-free, and n is a handful of
         * lines. qsort() is not stable, and file order is the tie-break. */
        for (i = 0; i < t->n; i++) {
                FstabEntry *e = &t->entries[i];
                unsigned d = fstab_path_depth(e->where);

                for (j = i; j > 0 && fstab_path_depth(v[j - 1]->where) > d; j--)
                        v[j] = v[j - 1];
                v[j] = e;
        }

        *ret_order = v;
        return 0;
}

int fstab_record_write(const FstabTable *t, const char *path) {
        char tmp[PATH_MAX];
        FILE *f;
        size_t i;
        int n;

        n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
        if (n < 0 || (size_t) n >= sizeof(tmp))
                return -ENAMETOOLONG;

        f = fopen(tmp, "we");
        if (!f)
                return -errno;

        for (i = 0; t && i < t->n; i++) {
                const FstabEntry *e = &t->entries[i];
                char where[PATH_MAX * 4];
                char reason[512];
                char *c;

                if (fstab_escape(e->where ? e->where : "", where, sizeof(where)) < 0)
                        snprintf(where, sizeof(where), "?");

                /* One line per entry is the format's whole contract, so a
                 * kernel message with a newline in it must not break it. */
                snprintf(reason, sizeof(reason), "%s", e->reason && e->reason[0] ? e->reason : "-");
                for (c = reason; *c; c++)
                        if (*c == '\n' || *c == '\r')
                                *c = ' ';

                fprintf(f, "%s %s %s\n", where, fstab_outcome_to_string(e->outcome), reason);
        }

        if (fclose(f) != 0) {
                int r = -errno;
                (void) remove(tmp);
                return r;
        }

        if (rename(tmp, path) < 0) {
                int r = -errno;
                (void) remove(tmp);
                return r;
        }

        return 0;
}

int fstab_record_count_degraded(const char *path) {
        char *line = NULL;
        size_t cap = 0;
        int count = 0;
        FILE *f;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        while (getline(&line, &cap, f) >= 0) {
                char *p = line, *where, *outcome;

                where = next_field(&p);
                outcome = next_field(&p);
                if (!where || !outcome)
                        continue;

                if (fstab_outcome_is_degraded(fstab_outcome_from_string(outcome)))
                        count++;
        }

        free(line);
        fclose(f);

        return count;
}
