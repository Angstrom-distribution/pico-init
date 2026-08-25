/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The udev-rules parser (plans/31, Part 2, milestone H2).
 *
 * devd consumes real udev-rules syntax rather than a pico-invented format, and
 * that is a decision with a stated reason rather than an aesthetic one. This
 * project's standing principle is drop-in systemd compatibility first --
 * deviating requires considering the systemd way and rejecting it out loud --
 * and the concrete consumer is already on the image: usb-modeswitch-data
 * installs /usr/lib/udev/rules.d/40-usb_modeswitch.rules (42,990 bytes, 1,262
 * lines, 420 rules) and it has been sitting there inert since eudev was
 * removed. An mdev-shaped format would mean hand-translating its 415
 * vendor:product pairs, and redoing that on every upgrade of that recipe.
 *
 * What is parsed is a verified subset, not the language. v261.2's
 * src/udev/udev-rules.c defines 49 token kinds; devd implements eleven of them
 * plus GOTO/LABEL, chosen by reading the two real target files rather than by
 * guessing at what looked important:
 *
 *   ACTION, SUBSYSTEM, KERNEL, ENV{}   match, straight off the uevent
 *   ATTR{}                             one read of /sys<devpath>/<attr>
 *   ATTRS{}                            the same read walked up the parent chain
 *   ENV{}                              assignment, including private .names
 *   MODE, OWNER, GROUP                 the device node's permissions
 *   SYMLINK+=                          the alias half
 *   RUN+=                              the run-a-tool half
 *   GOTO / LABEL                       skip-forward only
 *
 * Match values are shell globs run through libc fnmatch(3) with `|` alternation
 * on top -- udev's patterns have never been regular expressions, so there is no
 * regcomp() anywhere in devd.
 *
 * THE SAFETY SEMANTIC, which is the one thing here that is easy to get exactly
 * backwards: a rule containing a key devd does not implement is skipped WHOLE,
 * and logged once at load. Dropping only the unrecognised clause and firing the
 * rest would make the rule match MORE devices than the rule's author intended
 * -- an unimplemented PROGRAM= or TEST!= is usually the clause doing the
 * narrowing -- which inverts the safety property instead of degrading it. The
 * unit-parse.c analogy carries the consume-the-real-format principle across and
 * deliberately leaves its accept-and-ignore failure mode behind.
 *
 * The residue that semantic leaves, named rather than hidden: a skipped rule
 * whose action was GOTO stops jumping, so rules after it are reached where
 * upstream would have skipped them. Neither target file has such a rule (both
 * GOTO guards here are ACTION/SUBSYSTEM matches devd implements), and the
 * alternative -- refusing the whole file -- would silently disable a working
 * usb-modeswitch over one unrelated line. An unresolvable GOTO *is* refused
 * file-wide, because that one really does change the meaning of everything
 * after it.
 *
 * Memory shape, because the target is a 64MiB ARMv5TE machine and the naive
 * representation is not: clauses and rules are fixed-size records in two flat
 * arrays, and every string is interned once into a shared arena and referred to
 * by offset. The real usb-modeswitch file's 415 identical RUN values become one
 * string. Offsets rather than pointers is what lets the arena be realloc()'d
 * while the tables already reference it.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Where the rules files live, in udev's own precedence order: a file in a
 * later directory shadows a same-named file in an earlier one, which is how
 * /etc overrides a vendor rule without editing it. */
#define DEVD_RULES_DIR_LIB "/usr/lib/udev/rules.d"
#define DEVD_RULES_DIR_RUN "/run/udev/rules.d"
#define DEVD_RULES_DIR_ETC "/etc/udev/rules.d"

/*
 * Caps, in the spirit of devd-block.h's: the input is a file on disk rather
 * than a device, but it is still input, and a bound this file sets is worth
 * more than one the file sets. Over any of them the rule is skipped whole --
 * the same outcome an unsupported key gets, and for the same reason.
 *
 * The widest real rule is the Huawei catch-all at five clauses; the longest
 * real value is the gsmmodem PROGRAM at 68 bytes. The headroom is for rules
 * files this project has not read yet.
 */
#define DEVD_RULE_CLAUSES_MAX 16
#define DEVD_RULE_ATTR_MAX 64
#define DEVD_RULE_VALUE_MAX 256
#define DEVD_RULE_LINE_MAX 4096

/*
 * The eleven implemented kinds plus the two control ones. ENV appears once and
 * covers both its match and its assignment form; which one a clause is comes
 * from the operator, not from a second key.
 */
typedef enum DevdRuleKey {
        DEVD_RULE_KEY_ACTION,
        DEVD_RULE_KEY_SUBSYSTEM,
        DEVD_RULE_KEY_KERNEL,
        DEVD_RULE_KEY_ENV,
        DEVD_RULE_KEY_ATTR,
        DEVD_RULE_KEY_ATTRS,
        DEVD_RULE_KEY_MODE,
        DEVD_RULE_KEY_OWNER,
        DEVD_RULE_KEY_GROUP,
        DEVD_RULE_KEY_SYMLINK,
        DEVD_RULE_KEY_RUN,
        DEVD_RULE_KEY_GOTO,
        DEVD_RULE_KEY_LABEL,
        _DEVD_RULE_KEY_MAX,
} DevdRuleKey;

typedef enum DevdRuleOp {
        DEVD_RULE_OP_MATCH,   /* == */
        DEVD_RULE_OP_NOMATCH, /* != */
        DEVD_RULE_OP_ASSIGN,  /* =, and := which devd treats the same: there is
                               * no OPTIONS+="..." to make the final form differ */
        DEVD_RULE_OP_ADD,     /* += */
        DEVD_RULE_OP_REMOVE,  /* -= */
        _DEVD_RULE_OP_MAX,
} DevdRuleOp;

/* One `KEY{attr}op"value"` clause. 12 bytes; `attr` and `value` are arena
 * offsets, and offset 0 is always the empty string. */
typedef struct DevdRuleClause {
        int16_t key;
        int16_t op;
        uint32_t attr;
        uint32_t value;
} DevdRuleClause;

/* One rule line. `goto_target` is the index of the rule to continue at, or -1
 * when the rule has no GOTO; resolution happens at load, so evaluation never
 * searches for a label. */
typedef struct DevdRule {
        uint32_t first_clause;
        uint16_t n_clauses;
        uint16_t line;
        int32_t goto_target;
        uint32_t label; /* arena offset, 0 when the rule is not a label */
} DevdRule;

typedef struct DevdRuleSet {
        char *arena;
        size_t arena_len, arena_size;

        DevdRuleClause *clauses;
        size_t n_clauses, clauses_size;

        DevdRule *rules;
        size_t n_rules, rules_size;

        /* How many rules were skipped whole, for the one summary line devd
         * logs after loading. Each was already logged individually. */
        unsigned n_skipped;
} DevdRuleSet;

int devd_ruleset_new(DevdRuleSet **ret);
DevdRuleSet *devd_ruleset_free(DevdRuleSet *rs);

/*
 * Parse `text` and append its rules. `name` names the source in log lines.
 *
 * Returns the number of rules added, or -errno. -EINVAL specifically means a
 * GOTO named a label that is not ahead of it in this text, in which case
 * nothing at all from `text` is added: a guard rule that silently stops
 * guarding would let every rule below it fire on events it was written to
 * exclude, which is the one parse failure worth refusing a whole file over.
 */
int devd_ruleset_load_string(DevdRuleSet *rs, const char *text, const char *name);

/* The same, reading the file first. Returns the number of rules added, or
 * -errno; -ENOENT is passed through rather than swallowed. */
int devd_ruleset_load_file(DevdRuleSet *rs, const char *path);

/*
 * Load every *.rules file across udev's three directories, in the collated
 * order udev itself uses: sorted by basename, with the later directory's copy
 * of a repeated basename shadowing the earlier one entirely.
 *
 * `dirs` is a NULL-terminated list in increasing precedence, so devd passes
 * {lib, run, etc}. A directory that is not there is not an error -- on a pico
 * image /etc/udev/rules.d usually is not. Returns the number of rules loaded,
 * or -errno.
 */
int devd_ruleset_load_dirs(DevdRuleSet *rs, const char * const *dirs);

/* The interned string at `offset`. Always non-NULL; offset 0 is "". */
const char *devd_ruleset_string(const DevdRuleSet *rs, uint32_t offset);

/* The clauses of rule `i`. Returns the count and points *ret at the first. */
size_t devd_rule_clauses(const DevdRuleSet *rs, size_t i, const DevdRuleClause **ret);

/*
 * The distinct directories SYMLINK+= values in this ruleset name before their
 * first substitution -- "serial/by-id" out of
 * `SYMLINK+="serial/by-id/usb-$attr{manufacturer}..."`.
 *
 * devd sweeps exactly these at coldplug for links whose device is gone, which
 * is the rule-created half of what devd_symlink_reconcile() does for the by-*
 * families. Asking the ruleset rather than hard-coding "serial" is what keeps
 * that true for a rules file this project has not written.
 *
 * Writes at most `max` entries and returns how many.
 */
size_t devd_ruleset_symlink_dirs(const DevdRuleSet *rs, char dirs[][DEVD_RULE_VALUE_MAX], size_t max);

const char *devd_rule_key_to_string(DevdRuleKey k);
const char *devd_rule_op_to_string(DevdRuleOp op);

/*
 * Does `value` satisfy `pattern`? udev match values are shell globs, not
 * regular expressions, so this is fnmatch(3) plus the one thing fnmatch does
 * not do: `|` alternation, where any branch matching is a match.
 *
 * The split is bracket-aware, because `c70[345abce]|c71[34bc]` -- a real
 * pattern out of bluez's hid2hci.rules -- would otherwise be cut inside a
 * character class by a naive strchr('|').
 */
bool devd_rules_pattern_match(const char *pattern, const char *value);
