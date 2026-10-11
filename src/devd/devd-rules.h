/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The udev-rules parser.
 *
 * devd consumes real udev rules syntax rather than a pico-specific format, so
 * rule files shipped by other packages (usb-modeswitch-data's
 * /usr/lib/udev/rules.d/40-usb_modeswitch.rules, for one) work unmodified.
 *
 * What is parsed is a subset of the language, not all of it:
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
 * A rule containing a key devd does not implement is skipped WHOLE, and logged
 * once at load. Dropping only the unrecognised clause and firing the rest would
 * make the rule match more devices than its author intended, since an
 * unimplemented PROGRAM= or TEST!= is usually the clause doing the narrowing.
 *
 * Residue: a skipped rule whose action was GOTO stops jumping, so the rules
 * after it are reached where upstream would have skipped them. An unresolvable
 * GOTO is refused file-wide, because it changes the meaning of everything
 * after it.
 *
 * Memory: clauses and rules are fixed-size records in two flat arrays, and
 * every string is interned once into a shared arena and referred to by offset
 * (so identical RUN values are stored once). Offsets rather than pointers let
 * the arena be realloc()'d while the tables already reference it.
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
 * Caps. Over any of them the rule is skipped whole, as for an unsupported key.
 * The widest rule in usb-modeswitch's file is five clauses and the longest
 * value 68 bytes; the headroom is for other rules files.
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
