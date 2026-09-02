/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Matching, substitution and what a rule decides. devd-match.h has the two
 * matching details worth stating out loud -- the same-ancestor ATTRS{} rule and
 * what an absent attribute means -- and why $attr{} sanitises.
 */

#include "devd-match.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../util.h"
#include "devd-probe.h"

/* Same bound, and the same reason, as devd-probe.c's by-id walk: a USB block
 * device sits six levels under its usb_device, and a bound is what stops a
 * symlinked or malformed tree from being walked forever. */
#define DEVD_MATCH_WALK_MAX 12

/* Long enough for any sysfs attribute a rule matches on. Descriptor strings are
 * the widest real ones and they are far shorter. */
#define DEVD_MATCH_ATTR_VALUE_MAX 256

/* One line of a sysfs `uevent` file. Wider than a property table entry on
 * purpose: an input device's MODALIAS runs to several hundred bytes, and a
 * short buffer would not truncate it so much as split it into a second,
 * nonsense line. */
#define DEVD_UEVENT_LINE_MAX 1024

/* --- the property table --- */

const char *devd_rule_device_property(const DevdRuleDevice *d, const char *key) {
        if (!d || !key)
                return NULL;

        for (size_t i = 0; i < d->n_props; i++)
                if (strcmp(d->props[i].key, key) == 0)
                        return d->props[i].value;

        return NULL;
}

int devd_rule_device_set_property(DevdRuleDevice *d, const char *key, const char *value, bool append) {
        DevdRuleProperty *p = NULL;

        if (!d || !key || !value || key[0] == '\0')
                return -EINVAL;

        if (strlen(key) >= sizeof(p->key))
                return -ENAMETOOLONG;

        for (size_t i = 0; i < d->n_props; i++)
                if (strcmp(d->props[i].key, key) == 0) {
                        p = &d->props[i];
                        break;
                }

        if (!p) {
                if (d->n_props >= DEVD_PROP_MAX)
                        return -ENOSPC;

                p = &d->props[d->n_props++];
                memset(p, 0, sizeof(*p));
                strcpy(p->key, key);
                append = false;
        }

        if (append && p->value[0] != '\0') {
                size_t have = strlen(p->value);

                /* ENV{K}+= joins with a space, upstream's own shape for it. */
                (void) snprintf(p->value + have, sizeof(p->value) - have, " %s", value);
                return 0;
        }

        (void) snprintf(p->value, sizeof(p->value), "%s", value);
        return 0;
}

/* Take one "KEY=VALUE" as it came off the wire or out of a sysfs uevent file. */
static void property_take(DevdRuleDevice *d, const char *pair) {
        char key[DEVD_PROP_KEY_MAX];
        const char *eq = strchr(pair, '=');
        size_t n;

        if (!eq || eq == pair)
                return;

        n = (size_t) (eq - pair);
        if (n >= sizeof(key)) {
                pico_log(PICO_LOG_DEBUG, "devd: property name too long, ignored");
                return;
        }

        memcpy(key, pair, n);
        key[n] = '\0';

        (void) devd_rule_device_set_property(d, key, eq + 1, false);
}

/* --- building the context --- */

/* The trailing digit run of a sysname, which is what udev calls $number: "sda3"
 * is 3. A name that is all digits has none -- it is a number, not a numbered
 * thing. */
static void set_number(DevdRuleDevice *d) {
        size_t n = strlen(d->kernel), i = n;

        d->number = 0;
        d->have_number = false;

        while (i > 0 && d->kernel[i - 1] >= '0' && d->kernel[i - 1] <= '9')
                i--;

        if (i == 0 || i == n)
                return;

        d->number = (unsigned) strtoul(d->kernel + i, NULL, 10);
        d->have_number = true;
}

static int set_paths(DevdRuleDevice *d, const char *sys_root, const char *dev_root, const char *devpath) {
        const char *slash;

        if ((size_t) snprintf(d->devpath, sizeof(d->devpath), "%s", devpath) >= sizeof(d->devpath))
                return -ENAMETOOLONG;

        if ((size_t) snprintf(d->sysfs, sizeof(d->sysfs), "%s%s", sys_root, devpath) >= sizeof(d->sysfs))
                return -ENAMETOOLONG;

        slash = strrchr(d->devpath, '/');
        if ((size_t) snprintf(d->kernel, sizeof(d->kernel), "%s", slash ? slash + 1 : d->devpath) >=
            sizeof(d->kernel))
                return -ENAMETOOLONG;

        set_number(d);
        d->sys_root = sys_root;
        d->dev_root = dev_root;
        return 0;
}

int devd_rule_device_from_uevent(
                DevdRuleDevice *d, const char *sys_root, const char *dev_root, const DevdUevent *u) {

        const char *action;
        int r;

        if (!d || !sys_root || !dev_root || !u)
                return -EINVAL;

        memset(d, 0, sizeof(*d));

        r = set_paths(d, sys_root, dev_root, u->devpath);
        if (r < 0)
                return r;

        for (size_t off = 0; off < u->props_len; off += strlen(u->props + off) + 1)
                property_take(d, u->props + off);

        /*
         * The action string, not the enum name. devd's own DevdAction collapses
         * change/bind/move/online into _OTHER because none of them creates a
         * block device, but a rule matching ACTION=="change" means the word the
         * kernel sent -- so the property wins, and the enum is only the
         * fallback for a message that somehow lacked one.
         */
        action = devd_rule_device_property(d, "ACTION");
        (void) snprintf(d->action, sizeof(d->action), "%s", action ? action : devd_action_to_string(u->action));

        (void) snprintf(d->subsystem, sizeof(d->subsystem), "%s", u->subsystem);
        (void) snprintf(d->devname, sizeof(d->devname), "%s", u->devname);
        return 0;
}

/* Read <path> and return the basename of what it points at. 1/0/-errno. */
static int link_basename(const char *path, char *ret, size_t size) {
        char target[PATH_MAX];
        const char *slash, *base;
        size_t len;
        ssize_t k;

        k = readlink(path, target, sizeof(target) - 1);
        if (k < 0)
                return errno == ENOENT ? 0 : -errno;

        target[k] = '\0';

        slash = strrchr(target, '/');
        base = slash ? slash + 1 : target;

        /* strlen()+memcpy() rather than snprintf(), even though the truncation
         * IS detected either way. -Wformat-truncation looks through the inline
         * to the caller, and this function's one caller discards the result --
         * on purpose, because an unreadable `subsystem` link just leaves
         * d->subsystem empty. Not reproducible on an -O0 host gate: the
         * diagnostic needs optimisation to run at all. */
        len = strlen(base);
        if (len >= size)
                return -ENAMETOOLONG;

        memcpy(ret, base, len + 1);
        return 1;
}

int devd_rule_device_from_sysfs(
                DevdRuleDevice *d,
                const char *sys_root,
                const char *dev_root,
                const char *sysfs_dir,
                const char *action) {

        char path[DEVD_RULE_SYSFS_MAX + 16], line[DEVD_UEVENT_LINE_MAX];
        const char *devname;
        size_t root_len;
        FILE *f;
        int r;

        if (!d || !sys_root || !dev_root || !sysfs_dir || !action)
                return -EINVAL;

        root_len = strlen(sys_root);
        if (strncmp(sysfs_dir, sys_root, root_len) != 0 || sysfs_dir[root_len] != '/')
                return -EINVAL;

        memset(d, 0, sizeof(*d));

        r = set_paths(d, sys_root, dev_root, sysfs_dir + root_len);
        if (r < 0)
                return r;

        (void) snprintf(d->action, sizeof(d->action), "%s", action);
        (void) devd_rule_device_set_property(d, "ACTION", action, false);
        (void) devd_rule_device_set_property(d, "DEVPATH", d->devpath, false);

        /*
         * The device's own uevent file, which is the coldplug equivalent of the
         * broadcast message: same KEY=VALUE lines, minus the ACTION and DEVPATH
         * only a real event has. SUBSYSTEM is not in it either -- that comes
         * from the `subsystem` symlink, which is where the kernel keeps it.
         */
        if ((size_t) snprintf(path, sizeof(path), "%s/uevent", sysfs_dir) < sizeof(path)) {
                f = fopen(path, "re");
                if (f) {
                        while (fgets(line, sizeof(line), f)) {
                                size_t n = strlen(line);

                                while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
                                        line[--n] = '\0';

                                if (n > 0)
                                        property_take(d, line);
                        }

                        (void) fclose(f);
                }
        }

        if ((size_t) snprintf(path, sizeof(path), "%s/subsystem", sysfs_dir) < sizeof(path))
                (void) link_basename(path, d->subsystem, sizeof(d->subsystem));

        if (d->subsystem[0] != '\0')
                (void) devd_rule_device_set_property(d, "SUBSYSTEM", d->subsystem, false);

        devname = devd_rule_device_property(d, "DEVNAME");
        if (devname)
                (void) snprintf(d->devname, sizeof(d->devname), "%s", devname);

        return 0;
}

/* --- sysfs attribute reads --- */

/*
 * ATTR{queue/rotational} is a real upstream attribute name, so a '/' in one is
 * legitimate; ".." in one is not, and a rules file is data that arrives on
 * devd's own root-privileged read path. Cheap to refuse, and it keeps an
 * attribute name from naming a file outside the device.
 */
static bool attr_name_is_safe(const char *attr) {
        const char *p = attr;

        if (!attr || attr[0] == '\0' || attr[0] == '/')
                return false;

        for (;;) {
                const char *slash = strchr(p, '/');
                size_t n = slash ? (size_t) (slash - p) : strlen(p);

                if (n == 0 || (n == 2 && p[0] == '.' && p[1] == '.'))
                        return false;

                if (!slash)
                        return true;

                p = slash + 1;
        }
}

/* Read one attribute out of `dir`, trailing whitespace trimmed. 1/0/-errno. */
static int sysattr_read(const char *dir, const char *attr, char *ret, size_t size) {
        char path[DEVD_RULE_SYSFS_MAX + DEVD_RULE_ATTR_MAX + 2];
        size_t len;
        FILE *f;

        if (!attr_name_is_safe(attr))
                return 0;

        if ((size_t) snprintf(path, sizeof(path), "%s/%s", dir, attr) >= sizeof(path))
                return 0;

        f = fopen(path, "re");
        if (!f)
                return 0;

        if (!fgets(ret, (int) size, f)) {
                (void) fclose(f);
                return 0;
        }

        (void) fclose(f);

        len = strlen(ret);
        while (len > 0 &&
               (ret[len - 1] == '\n' || ret[len - 1] == '\r' || ret[len - 1] == ' ' || ret[len - 1] == '\t'))
                ret[--len] = '\0';

        return 1;
}

/*
 * The parent chain, as a bounded walk of directory prefixes.
 *
 * A device's parent in sysfs is its parent directory, which is why this needs
 * no device model of its own -- and `sys_root` is what stops the walk leaving
 * sysfs entirely, which in a test is what stops it reaching the host's real
 * /sys. Returns the next directory in *dir, or false at the top.
 */
static bool walk_up(char *dir, const char *sys_root) {
        char *slash = strrchr(dir, '/');

        if (!slash)
                return false;

        *slash = '\0';

        if (strlen(dir) <= strlen(sys_root))
                return false;

        return true;
}

/* $attr{}: the matched ancestor first, then the chain from the device up. */
static int attr_find(const DevdRuleDevice *d, const char *attr, char *ret, size_t size) {
        char dir[DEVD_RULE_SYSFS_MAX];

        if (d->parent_sysfs[0] != '\0' && sysattr_read(d->parent_sysfs, attr, ret, size) > 0)
                return 1;

        if ((size_t) snprintf(dir, sizeof(dir), "%s", d->sysfs) >= sizeof(dir))
                return 0;

        for (unsigned depth = 0; depth < DEVD_MATCH_WALK_MAX; depth++) {
                if (sysattr_read(dir, attr, ret, size) > 0)
                        return 1;

                if (!walk_up(dir, d->sys_root))
                        break;
        }

        return 0;
}

/* --- matching --- */

static bool op_result(DevdRuleOp op, bool matched) {
        return op == DEVD_RULE_OP_NOMATCH ? !matched : matched;
}

/* Every ATTRS{} clause of one rule, evaluated against one candidate ancestor. */
static bool attrs_match_at(const DevdRuleSet *rs, const DevdRuleClause *cl, size_t n, const char *dir) {

        for (size_t i = 0; i < n; i++) {
                char value[DEVD_MATCH_ATTR_VALUE_MAX];
                int r;

                if (cl[i].key != DEVD_RULE_KEY_ATTRS)
                        continue;

                r = sysattr_read(dir, devd_ruleset_string(rs, cl[i].attr), value, sizeof(value));
                if (r <= 0) {
                        /* Absent: fails ==, satisfies !=. Upstream's rule, and
                         * the reason it is not merely convenient is in the
                         * header. */
                        if (cl[i].op != DEVD_RULE_OP_NOMATCH)
                                return false;

                        continue;
                }

                if (!op_result(cl[i].op, devd_rules_pattern_match(devd_ruleset_string(rs, cl[i].value), value)))
                        return false;
        }

        return true;
}

/*
 * Find the one ancestor that satisfies the rule's whole ATTRS{} group, and
 * record it as %b. Returns true when the rule has no ATTRS clauses at all --
 * "nothing to satisfy" is satisfied.
 */
static bool attrs_group_match(const DevdRuleSet *rs, const DevdRuleClause *cl, size_t n, DevdRuleDevice *d) {

        char dir[DEVD_RULE_SYSFS_MAX];
        bool any = false;

        for (size_t i = 0; i < n; i++)
                if (cl[i].key == DEVD_RULE_KEY_ATTRS) {
                        any = true;
                        break;
                }

        if (!any)
                return true;

        if ((size_t) snprintf(dir, sizeof(dir), "%s", d->sysfs) >= sizeof(dir))
                return false;

        for (unsigned depth = 0; depth < DEVD_MATCH_WALK_MAX; depth++) {
                if (attrs_match_at(rs, cl, n, dir)) {
                        const char *slash = strrchr(dir, '/');
                        const char *base = slash ? slash + 1 : dir;

                        /* A sysname too long to record is a %b devd cannot
                         * substitute, and a rule firing with a truncated %b
                         * would hand a tool the wrong device name. Refuse the
                         * match instead -- the safe direction. */
                        if ((size_t) snprintf(d->parent, sizeof(d->parent), "%s", base) >= sizeof(d->parent))
                                return false;

                        (void) snprintf(d->parent_sysfs, sizeof(d->parent_sysfs), "%s", dir);
                        return true;
                }

                if (!walk_up(dir, d->sys_root))
                        break;
        }

        return false;
}

/* Everything except the ATTRS group, which needs its own walk. */
static bool simple_match(const DevdRuleSet *rs, const DevdRuleClause *c, const DevdRuleDevice *d) {
        const char *pattern = devd_ruleset_string(rs, c->value);
        char value[DEVD_MATCH_ATTR_VALUE_MAX];
        const char *subject;

        switch (c->key) {

        case DEVD_RULE_KEY_ACTION:
                subject = d->action;
                break;

        case DEVD_RULE_KEY_SUBSYSTEM:
                subject = d->subsystem;
                break;

        case DEVD_RULE_KEY_KERNEL:
                subject = d->kernel;
                break;

        case DEVD_RULE_KEY_ENV: {
                const char *v = devd_rule_device_property(d, devd_ruleset_string(rs, c->attr));

                /* An unset property is the empty string here, not an absence:
                 * upstream's ENV match does the same, and it is what makes
                 * ENV{K}!="x" true on a device that has no K. */
                subject = v ? v : "";
                break;
        }

        case DEVD_RULE_KEY_ATTR:
                if (sysattr_read(d->sysfs, devd_ruleset_string(rs, c->attr), value, sizeof(value)) <= 0)
                        return c->op == DEVD_RULE_OP_NOMATCH;

                subject = value;
                break;

        default:
                return true; /* not a match clause */
        }

        return op_result(c->op, devd_rules_pattern_match(pattern, subject));
}

/* --- substitution --- */

/* Append to a bounded output buffer, tracking how much really fit. */
static void out_append(char *out, size_t size, size_t *n, const char *s) {
        for (; *s; s++) {
                if (*n + 1 >= size)
                        return;

                out[(*n)++] = *s;
        }
}

/*
 * $env{K} / %E{K} and $attr{F} / %s{F} share a shape: a name in braces. Parse
 * it out of *p, advancing past the closing brace. Returns false when there is
 * no brace group there at all, which makes the escape a literal.
 */
static bool braced_name(const char **p, char *ret, size_t size) {
        const char *s = *p, *end;
        size_t n;

        if (*s != '{')
                return false;

        s++;
        end = strchr(s, '}');
        if (!end)
                return false;

        n = (size_t) (end - s);
        if (n == 0 || n >= size)
                return false;

        memcpy(ret, s, n);
        ret[n] = '\0';
        *p = end + 1;
        return true;
}

static void substitute_env(const DevdRuleDevice *d, const char *name, char *out, size_t size, size_t *n) {
        const char *v = devd_rule_device_property(d, name);

        if (v)
                out_append(out, size, n, v);
}

static void substitute_attr(const DevdRuleDevice *d, const char *name, char *out, size_t size, size_t *n) {
        char raw[DEVD_MATCH_ATTR_VALUE_MAX], clean[DEVD_MATCH_ATTR_VALUE_MAX];

        if (attr_find(d, name, raw, sizeof(raw)) <= 0)
                return;

        if (devd_sanitize(raw, clean, sizeof(clean)) == 0)
                return;

        out_append(out, size, n, clean);
}

size_t devd_rules_substitute(const DevdRuleDevice *d, const char *in, char *out, size_t size) {
        size_t n = 0;
        const char *p;

        if (!out || size == 0)
                return 0;

        out[0] = '\0';

        if (!d || !in)
                return 0;

        for (p = in; *p;) {
                char name[DEVD_PROP_KEY_MAX], num[16];
                char c;

                if (*p != '%' && *p != '$') {
                        if (n + 1 >= size)
                                break;

                        out[n++] = *p++;
                        continue;
                }

                c = *p;

                /* %% and $$ are the literal. */
                if (p[1] == c) {
                        if (n + 1 >= size)
                                break;

                        out[n++] = c;
                        p += 2;
                        continue;
                }

                if (c == '%') {
                        p++;

                        switch (*p) {

                        case 'k':
                                p++;
                                out_append(out, size, &n, d->kernel);
                                continue;

                        case 'p':
                                p++;
                                out_append(out, size, &n, d->devpath);
                                continue;

                        case 'b':
                                p++;
                                out_append(out, size, &n, d->parent);
                                continue;

                        case 'n':
                                p++;
                                if (d->have_number) {
                                        (void) snprintf(num, sizeof(num), "%u", d->number);
                                        out_append(out, size, &n, num);
                                }
                                continue;

                        case 'E':
                                p++;
                                if (braced_name(&p, name, sizeof(name))) {
                                        substitute_env(d, name, out, size, &n);
                                        continue;
                                }

                                out_append(out, size, &n, "%E");
                                continue;

                        case 's':
                                p++;
                                if (braced_name(&p, name, sizeof(name))) {
                                        substitute_attr(d, name, out, size, &n);
                                        continue;
                                }

                                out_append(out, size, &n, "%s");
                                continue;

                        default:
                                /* Copied through rather than dropped: an escape
                                 * devd does not implement should make itself
                                 * visible in the result, not shorten it. */
                                if (n + 1 < size)
                                        out[n++] = '%';

                                continue;
                        }
                }

                p++;

                if (strncmp(p, "kernel", 6) == 0) {
                        p += 6;
                        out_append(out, size, &n, d->kernel);
                } else if (strncmp(p, "devpath", 7) == 0) {
                        p += 7;
                        out_append(out, size, &n, d->devpath);
                } else if (strncmp(p, "number", 6) == 0) {
                        p += 6;
                        if (d->have_number) {
                                (void) snprintf(num, sizeof(num), "%u", d->number);
                                out_append(out, size, &n, num);
                        }
                } else if (strncmp(p, "id", 2) == 0) {
                        p += 2;
                        out_append(out, size, &n, d->parent);
                } else if (strncmp(p, "env", 3) == 0) {
                        p += 3;
                        if (braced_name(&p, name, sizeof(name)))
                                substitute_env(d, name, out, size, &n);
                        else
                                out_append(out, size, &n, "$env");
                } else if (strncmp(p, "attr", 4) == 0) {
                        p += 4;
                        if (braced_name(&p, name, sizeof(name)))
                                substitute_attr(d, name, out, size, &n);
                        else
                                out_append(out, size, &n, "$attr");
                } else if (n + 1 < size)
                        out[n++] = '$';
        }

        out[n] = '\0';
        return n;
}

/* --- actions --- */

static void symlink_add(DevdRuleResult *ret, const char *value) {
        const char *p = value;

        /* One SYMLINK+= value may name several links, whitespace-separated --
         * upstream's own shape, and the reason this splits rather than treating
         * the value as one path. */
        while (*p) {
                char one[DEVD_RULE_LINK_MAX];
                const char *start;
                size_t n;

                while (*p == ' ' || *p == '\t')
                        p++;

                if (*p == '\0')
                        return;

                start = p;
                while (*p && *p != ' ' && *p != '\t')
                        p++;

                n = (size_t) (p - start);
                if (n >= sizeof(one))
                        continue;

                memcpy(one, start, n);
                one[n] = '\0';

                if (ret->n_symlinks >= DEVD_RULE_SYMLINKS_MAX) {
                        pico_log(PICO_LOG_WARNING,
                                 "devd: more than %d symlinks for one device, dropping %s",
                                 DEVD_RULE_SYMLINKS_MAX,
                                 one);
                        return;
                }

                (void) snprintf(ret->symlinks[ret->n_symlinks++], DEVD_RULE_LINK_MAX, "%s", one);
        }
}

static void symlink_remove(DevdRuleResult *ret, const char *value) {
        for (size_t i = 0; i < ret->n_symlinks;)
                if (strcmp(ret->symlinks[i], value) == 0) {
                        memmove(&ret->symlinks[i],
                                &ret->symlinks[i + 1],
                                (ret->n_symlinks - i - 1) * DEVD_RULE_LINK_MAX);
                        ret->n_symlinks--;
                } else
                        i++;
}

static void
                apply_actions(const DevdRuleSet *rs,
                              const DevdRuleClause *cl,
                              size_t n,
                              DevdRuleDevice *d,
                              DevdRuleResult *ret) {

        for (size_t i = 0; i < n; i++) {
                char value[DEVD_RULE_CMD_MAX];
                const char *raw = devd_ruleset_string(rs, cl[i].value);

                switch (cl[i].key) {

                case DEVD_RULE_KEY_ENV:
                        if (cl[i].op != DEVD_RULE_OP_ASSIGN && cl[i].op != DEVD_RULE_OP_ADD)
                                break;

                        (void) devd_rules_substitute(d, raw, value, sizeof(value));
                        (void) devd_rule_device_set_property(
                                        d,
                                        devd_ruleset_string(rs, cl[i].attr),
                                        value,
                                        cl[i].op == DEVD_RULE_OP_ADD);
                        break;

                case DEVD_RULE_KEY_MODE:
                        (void) devd_rules_substitute(d, raw, value, sizeof(value));
                        ret->mode = (unsigned) strtoul(value, NULL, 8) & 07777u;
                        ret->have_mode = true;
                        break;

                case DEVD_RULE_KEY_OWNER:
                        (void) devd_rules_substitute(d, raw, ret->owner, sizeof(ret->owner));
                        break;

                case DEVD_RULE_KEY_GROUP:
                        (void) devd_rules_substitute(d, raw, ret->group, sizeof(ret->group));
                        break;

                case DEVD_RULE_KEY_SYMLINK:
                        /* A truncated symlink name, like a truncated %b,
                         * would point a tool at the wrong device. Refuse
                         * the action instead -- the safe direction. */
                        if (devd_rules_substitute(d, raw, value, sizeof(value)) >= sizeof(value) - 1) {
                                pico_log(PICO_LOG_WARNING,
                                         "devd: SYMLINK+= expansion too long, dropping %s",
                                         raw);
                                break;
                        }

                        if (cl[i].op == DEVD_RULE_OP_ASSIGN)
                                ret->n_symlinks = 0;

                        if (cl[i].op == DEVD_RULE_OP_REMOVE)
                                symlink_remove(ret, value);
                        else
                                symlink_add(ret, value);

                        break;

                case DEVD_RULE_KEY_RUN:
                        /* Same reasoning as SYMLINK+= above: a truncated
                         * command would spawn the wrong thing. Refuse. */
                        if (devd_rules_substitute(d, raw, value, sizeof(value)) >= sizeof(value) - 1) {
                                pico_log(PICO_LOG_WARNING,
                                         "devd: RUN+= expansion too long, dropping %s",
                                         raw);
                                break;
                        }

                        if (cl[i].op == DEVD_RULE_OP_ASSIGN)
                                ret->n_runs = 0;

                        if (ret->n_runs >= DEVD_RULE_RUNS_MAX) {
                                pico_log(PICO_LOG_WARNING,
                                         "devd: more than %d RUN+= for one device, dropping %s",
                                         DEVD_RULE_RUNS_MAX,
                                         value);
                                break;
                        }

                        (void) snprintf(ret->runs[ret->n_runs++], DEVD_RULE_CMD_MAX, "%s", value);
                        break;

                default:
                        break;
                }
        }
}

int devd_rules_apply(const DevdRuleSet *rs, DevdRuleDevice *d, DevdRuleResult *ret) {
        if (!rs || !d || !ret)
                return -EINVAL;

        memset(ret, 0, sizeof(*ret));

        for (size_t i = 0; i < rs->n_rules;) {
                const DevdRuleClause *cl = NULL;
                size_t n = devd_rule_clauses(rs, i, &cl);
                int32_t target = rs->rules[i].goto_target;
                bool matched = true;

                /* A LABEL is a jump destination, not a rule with no conditions
                 * -- which is what a rule of nothing but a LABEL would
                 * otherwise evaluate as, quietly counting itself as a match on
                 * every device that ever reached it. */
                if (n == 1 && cl[0].key == DEVD_RULE_KEY_LABEL) {
                        i++;
                        continue;
                }

                /* Per rule, not per event: %b means "the parent THIS rule
                 * matched", so a previous rule's answer must not leak in. */
                d->parent[0] = '\0';
                d->parent_sysfs[0] = '\0';

                for (size_t j = 0; matched && j < n; j++)
                        if (cl[j].op == DEVD_RULE_OP_MATCH || cl[j].op == DEVD_RULE_OP_NOMATCH)
                                matched = simple_match(rs, &cl[j], d);

                if (matched)
                        matched = attrs_group_match(rs, cl, n, d);

                if (!matched) {
                        i++;
                        continue;
                }

                ret->n_matched++;
                apply_actions(rs, cl, n, d, ret);

                /* Forward-only by construction -- devd-rules.c resolves a GOTO
                 * to a strictly later rule or refuses the file -- and checked
                 * anyway, because a loop here would be an unkillable daemon. */
                i = target > (int32_t) i ? (size_t) target : i + 1;
        }

        return 0;
}

/* --- the child environment --- */

int devd_rules_environment(const DevdRuleDevice *d, char ***ret) {
        char **env = NULL;

        /* Sized off the DEVPATH case rather than off a property, because
         * DEVPATH is the one value here that is not a property-table entry and
         * can be wider than one. */
        char buf[DEVD_DEVPATH_MAX + DEVD_PROP_KEY_MAX + 2];
        int r;

        if (!d || !ret)
                return -EINVAL;

        for (size_t i = 0; i < d->n_props; i++) {
                /* Private names exist for a later $env{} to read back and are
                 * upstream's own idiom for exactly that; they are not part of
                 * what a device looks like to a tool. */
                if (d->props[i].key[0] == '.')
                        continue;

                (void) snprintf(buf, sizeof(buf), "%s=%s", d->props[i].key, d->props[i].value);

                r = pico_strv_extend(&env, buf);
                if (r < 0)
                        goto fail;
        }

        if (!devd_rule_device_property(d, "ACTION")) {
                (void) snprintf(buf, sizeof(buf), "ACTION=%s", d->action);

                r = pico_strv_extend(&env, buf);
                if (r < 0)
                        goto fail;
        }

        if (!devd_rule_device_property(d, "DEVPATH")) {
                (void) snprintf(buf, sizeof(buf), "DEVPATH=%s", d->devpath);

                r = pico_strv_extend(&env, buf);
                if (r < 0)
                        goto fail;
        }

        if (!devd_rule_device_property(d, "SUBSYSTEM") && d->subsystem[0] != '\0') {
                (void) snprintf(buf, sizeof(buf), "SUBSYSTEM=%s", d->subsystem);

                r = pico_strv_extend(&env, buf);
                if (r < 0)
                        goto fail;
        }

        /* A helper exec'd with no PATH at all cannot find anything it shells
         * out to, and every one of these images is usrmerged. */
        r = pico_strv_extend(&env, "PATH=/usr/sbin:/usr/bin:/sbin:/bin");
        if (r < 0)
                goto fail;

        *ret = env;
        return 0;

fail:
        pico_strv_free(env);
        return r;
}

/* --- user and group names --- */

int devd_rules_lookup_id(const char *path, const char *name, unsigned *ret) {
        char line[512];
        size_t n;
        FILE *f;

        if (!path || !name || !ret || name[0] == '\0')
                return -EINVAL;

        n = strspn(name, "0123456789");
        if (name[n] == '\0') {
                *ret = (unsigned) strtoul(name, NULL, 10);
                return 1;
        }

        f = fopen(path, "re");
        if (!f)
                return -errno;

        while (fgets(line, sizeof(line), f)) {
                char *colon = strchr(line, ':'), *id, *end;

                if (!colon)
                        continue;

                *colon = '\0';
                if (strcmp(line, name) != 0)
                        continue;

                /* NAME:password:ID:... -- the third field. */
                id = strchr(colon + 1, ':');
                if (!id) {
                        (void) fclose(f);
                        return 0;
                }

                id++;
                *ret = (unsigned) strtoul(id, &end, 10);

                (void) fclose(f);
                return end == id ? 0 : 1;
        }

        (void) fclose(f);
        return 0;
}
