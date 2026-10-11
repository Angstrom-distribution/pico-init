/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Evaluating a parsed ruleset against one device.
 *
 * devd-rules.c turns text into rules; this file is what a rule means. Three
 * pieces, in the order an event goes through them:
 *
 *  1. The device context -- what the uevent said, plus where in /sys the device
 *     is. Built either from a received uevent or, for the coldplug walk, from a
 *     sysfs directory and its own `uevent` file, which carries the same
 *     KEY=VALUE lines the kernel would have broadcast.
 *  2. Matching. ACTION/SUBSYSTEM/KERNEL/ENV{} are string compares against the
 *     context; ATTR{} is one read of /sys<devpath>/<attr>; ATTRS{} is that read
 *     walked up the parent chain.
 *  3. Substitution and the resulting actions -- MODE/OWNER/GROUP, SYMLINK+= and
 *     RUN+= -- collected rather than performed, so a test can assert what a rule
 *     decided without the test host growing device nodes.
 *
 * Two details of the matching change which devices a rule fires on:
 *
 *  - ALL the ATTRS{} clauses of one rule must be satisfied by the SAME ancestor,
 *    not by any ancestor each. usb-modeswitch's Huawei catch-all is exactly this
 *    -- `ATTRS{idVendor}=="12d1", ATTRS{manufacturer}!="Android"` means "a USB
 *    device that is Huawei's and is not the Android phone", and evaluating the
 *    two independently would let the phone through by finding "not Android"
 *    somewhere else on the chain. That single matched ancestor is also what %b
 *    substitutes to, which is why the two live in one walk.
 *  - An absent attribute fails `==` and satisfies `!=`, which is upstream's own
 *    rule and not a convenient default: a device that does not have the
 *    attribute at all is not the device the rule was written to exclude.
 *
 * `sys_root` and `dev_root` are parameters so tests can build a device out of
 * directories (as in devd-probe.h and devd-symlink.h).
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "devd-rules.h"
#include "devd-uevent.h"

/*
 * The device property table. A kernel uevent carries about a dozen properties;
 * 32 leaves room for the ENV{} assignments rules add on top, including the
 * dot-prefixed private ones (upstream's `.PART_SUFFIX` idiom) that exist only
 * for a later $env{} to read back and are never exported to a
 * RUN+= child.
 */
#define DEVD_PROP_MAX 32
#define DEVD_PROP_KEY_MAX 48
#define DEVD_PROP_VALUE_MAX 256

/* <sys_root> plus a DEVPATH, and <dev_root> plus a DEVNAME. */
#define DEVD_RULE_SYSFS_MAX 640
#define DEVD_RULE_NODE_MAX 256

/* One SYMLINK+= target, and one RUN+= command line after substitution. */
#define DEVD_RULE_LINK_MAX 192
#define DEVD_RULE_CMD_MAX 320
#define DEVD_RULE_SYMLINKS_MAX 8
#define DEVD_RULE_RUNS_MAX 8

typedef struct DevdRuleProperty {
        char key[DEVD_PROP_KEY_MAX];
        char value[DEVD_PROP_VALUE_MAX];
} DevdRuleProperty;

typedef struct DevdRuleDevice {
        const char *sys_root;
        const char *dev_root;

        char action[DEVD_SUBSYSTEM_MAX];
        char subsystem[DEVD_SUBSYSTEM_MAX];
        char devpath[DEVD_DEVPATH_MAX];
        char kernel[DEVD_NAME_MAX];  /* the sysname: the last DEVPATH component */
        char devname[DEVD_NAME_MAX]; /* DEVNAME, relative to dev_root; "" when none */
        char sysfs[DEVD_RULE_SYSFS_MAX];

        /*
         * The ancestor the last rule's ATTRS{} group matched, and what %b
         * substitutes to. Reset per rule, not per event: %b in a rule's own
         * RUN+= means "the parent this rule matched", and carrying a previous
         * rule's answer into it would be a different device.
         */
        char parent[DEVD_NAME_MAX];
        char parent_sysfs[DEVD_RULE_SYSFS_MAX];

        unsigned number; /* %n, the trailing digits of the sysname */
        bool have_number;

        DevdRuleProperty props[DEVD_PROP_MAX];
        size_t n_props;
} DevdRuleDevice;

/* What a whole ruleset decided about one device. Collected, not performed. */
typedef struct DevdRuleResult {
        bool have_mode;
        unsigned mode;

        char owner[DEVD_PROP_VALUE_MAX];
        char group[DEVD_PROP_VALUE_MAX];

        char symlinks[DEVD_RULE_SYMLINKS_MAX][DEVD_RULE_LINK_MAX];
        size_t n_symlinks;

        char runs[DEVD_RULE_RUNS_MAX][DEVD_RULE_CMD_MAX];
        size_t n_runs;

        unsigned n_matched; /* rules that fired, for the debug line */
} DevdRuleResult;

/* Build the context from a received uevent. 0 or -errno. */
int devd_rule_device_from_uevent(
                DevdRuleDevice *d, const char *sys_root, const char *dev_root, const DevdUevent *u);

/*
 * Build it from a device directory instead, reading <sysfs_dir>/uevent for the
 * properties -- the coldplug path. That file carries the same KEY=VALUE lines
 * the kernel broadcasts, minus ACTION and DEVPATH, which are supplied here.
 * Returns 0 or -errno.
 */
int devd_rule_device_from_sysfs(
                DevdRuleDevice *d,
                const char *sys_root,
                const char *dev_root,
                const char *sysfs_dir,
                const char *action);

/* The property's value, or NULL. Private (dot-prefixed) names are ordinary
 * properties here; only the child environment leaves them out. */
const char *devd_rule_device_property(const DevdRuleDevice *d, const char *key);

/* Set or, with `append`, space-join onto an existing value -- ENV{K}= and
 * ENV{K}+= respectively. 0 or -errno (-ENOSPC when the table is full). */
int devd_rule_device_set_property(DevdRuleDevice *d, const char *key, const char *value, bool append);

/*
 * Expand udev's substitutions in `in`. Returns the length written.
 *
 * Implemented: %k/$kernel, %n/$number, %p/$devpath, %b/$id, $env{K} (short form
 * %E{K}), $attr{F} (short form %s{F}), and %%/$$ for a literal. An unknown
 * escape is copied through rather than dropped, which keeps a rules file devd
 * only partly understands from silently producing a shorter symlink name.
 *
 * $attr{} looks at the ATTRS-matched ancestor first when there is one, then
 * walks the chain from the device upwards, and sanitises what it finds with
 * devd_sanitize(). This differs from upstream's $attr{} handling, which only
 * strips trailing whitespace: upstream builds /dev/serial/by-id/ names through
 * the usb_id builtin, which applies this sanitiser, so it is needed to
 * reproduce those link names.
 */
size_t devd_rules_substitute(const DevdRuleDevice *d, const char *in, char *out, size_t size);

/*
 * Run the whole ruleset over the device. ENV{} assignments land in the device's
 * own property table (so a later rule sees them); everything else lands in
 * *ret. Returns 0 or -errno.
 */
int devd_rules_apply(const DevdRuleSet *rs, DevdRuleDevice *d, DevdRuleResult *ret);

/*
 * The environment a RUN+= child gets: every non-private property as KEY=VALUE,
 * with ACTION/DEVPATH/SUBSYSTEM filled in when the source did not carry them,
 * plus a PATH. Caller frees with pico_strv_free(). 0 or -errno.
 */
int devd_rules_environment(const DevdRuleDevice *d, char ***ret);

/*
 * Resolve a user or group name against a passwd/group-shaped file
 * (NAME:x:ID:...). Returns 1 with *ret set, 0 when the name is not in the file,
 * or -errno.
 *
 * A purely numeric name answers itself and the file is not opened at all --
 * which is also what makes MODE/OWNER/GROUP work on an image that has no
 * /etc/passwd, the state every pico image is in today.
 */
int devd_rules_lookup_id(const char *path, const char *name, unsigned *ret);
