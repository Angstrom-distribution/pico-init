/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The tokenizer and the rule tables. devd-rules.h has the subset, the safety
 * semantic and why every string is an arena offset rather than a pointer.
 */

#include "devd-rules.h"

#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../util.h"

/* Growth steps. Small, so a file of a few hundred rules is reached in a
 * handful of reallocs. */
#define DEVD_RULES_ARENA_INITIAL 1024
#define DEVD_RULES_TABLE_INITIAL 64

/* Nothing this project ships comes close; a rules file bigger than this is a
 * file devd should refuse rather than read into a 64MiB machine. */
#define DEVD_RULES_FILE_MAX (1024 * 1024)

/* A rules directory is a directory, so it is input too. */
#define DEVD_RULES_FILES_MAX 128
#define DEVD_RULES_BASENAME_MAX 96
#define DEVD_RULES_PATH_MAX 512

/*
 * How many skipped rules get their own log line before the summary takes over.
 *
 * Skipping is logged per rule; the cap keeps a large foreign rules directory
 * from flooding the console with warnings at boot. The count still comes out
 * in the summary.
 */
#define DEVD_RULES_SKIP_LOG_MAX 16

/* The pending marker a GOTO carries between parse and resolution. */
#define DEVD_RULE_GOTO_PENDING (-2)

/*
 * Which operators each key takes. Named rather than spelled out per row, to
 * keep the table readable. Two of the sets matter:
 *
 *  - ATTR has no assignment form. ATTR{}= writes to sysfs upstream, which devd
 *    does not do, so a rule using it is skipped whole rather than quietly read
 *    as if it had been a match.
 *  - RUN's builtin form is refused separately (below), not here: the operator
 *    is the same, only the {attribute} differs.
 */
#define DEVD_OPS_MATCH ((1u << DEVD_RULE_OP_MATCH) | (1u << DEVD_RULE_OP_NOMATCH))
#define DEVD_OPS_SET (1u << DEVD_RULE_OP_ASSIGN)
#define DEVD_OPS_APPEND (DEVD_OPS_SET | (1u << DEVD_RULE_OP_ADD))
#define DEVD_OPS_ENV (DEVD_OPS_MATCH | DEVD_OPS_APPEND)
#define DEVD_OPS_LIST (DEVD_OPS_APPEND | (1u << DEVD_RULE_OP_REMOVE))

static const struct {
        const char *name;
        DevdRuleKey key;
        bool wants_attr; /* KEY{attr} is required (ENV, ATTR, ATTRS) */
        bool allows_attr;
        uint32_t ops;
} devd_rule_key_table[] = {
        {    "ACTION",    DEVD_RULE_KEY_ACTION, false, false,  DEVD_OPS_MATCH },
        { "SUBSYSTEM", DEVD_RULE_KEY_SUBSYSTEM, false, false,  DEVD_OPS_MATCH },
        {    "KERNEL",    DEVD_RULE_KEY_KERNEL, false, false,  DEVD_OPS_MATCH },
        {       "ENV",       DEVD_RULE_KEY_ENV,  true,  true,    DEVD_OPS_ENV },
        {      "ATTR",      DEVD_RULE_KEY_ATTR,  true,  true,  DEVD_OPS_MATCH },
        {     "ATTRS",     DEVD_RULE_KEY_ATTRS,  true,  true,  DEVD_OPS_MATCH },
        {      "MODE",      DEVD_RULE_KEY_MODE, false, false,    DEVD_OPS_SET },
        {     "OWNER",     DEVD_RULE_KEY_OWNER, false, false,    DEVD_OPS_SET },
        {     "GROUP",     DEVD_RULE_KEY_GROUP, false, false,    DEVD_OPS_SET },
        {   "SYMLINK",   DEVD_RULE_KEY_SYMLINK, false, false,   DEVD_OPS_LIST },
        {       "RUN",       DEVD_RULE_KEY_RUN, false,  true, DEVD_OPS_APPEND },
        {      "GOTO",      DEVD_RULE_KEY_GOTO, false, false,    DEVD_OPS_SET },
        {     "LABEL",     DEVD_RULE_KEY_LABEL, false, false,    DEVD_OPS_SET },
};

#define DEVD_RULE_KEY_COUNT (sizeof(devd_rule_key_table) / sizeof(devd_rule_key_table[0]))

static const char * const devd_rule_key_names[_DEVD_RULE_KEY_MAX] = {
        [DEVD_RULE_KEY_ACTION] = "ACTION", [DEVD_RULE_KEY_SUBSYSTEM] = "SUBSYSTEM",
        [DEVD_RULE_KEY_KERNEL] = "KERNEL", [DEVD_RULE_KEY_ENV] = "ENV",
        [DEVD_RULE_KEY_ATTR] = "ATTR",     [DEVD_RULE_KEY_ATTRS] = "ATTRS",
        [DEVD_RULE_KEY_MODE] = "MODE",     [DEVD_RULE_KEY_OWNER] = "OWNER",
        [DEVD_RULE_KEY_GROUP] = "GROUP",   [DEVD_RULE_KEY_SYMLINK] = "SYMLINK",
        [DEVD_RULE_KEY_RUN] = "RUN",       [DEVD_RULE_KEY_GOTO] = "GOTO",
        [DEVD_RULE_KEY_LABEL] = "LABEL",
};

static const char * const devd_rule_op_names[_DEVD_RULE_OP_MAX] = {
        [DEVD_RULE_OP_MATCH] = "==", [DEVD_RULE_OP_NOMATCH] = "!=", [DEVD_RULE_OP_ASSIGN] = "=",
        [DEVD_RULE_OP_ADD] = "+=",   [DEVD_RULE_OP_REMOVE] = "-=",
};

const char *devd_rule_key_to_string(DevdRuleKey k) {
        if (k < 0 || k >= _DEVD_RULE_KEY_MAX)
                return "invalid";

        return devd_rule_key_names[k];
}

const char *devd_rule_op_to_string(DevdRuleOp op) {
        if (op < 0 || op >= _DEVD_RULE_OP_MAX)
                return "invalid";

        return devd_rule_op_names[op];
}

/* --- the arena --- */

static int arena_grow(DevdRuleSet *rs, size_t need) {
        size_t want = rs->arena_size ? rs->arena_size : DEVD_RULES_ARENA_INITIAL;
        char *p;

        if (rs->arena_len + need <= rs->arena_size)
                return 0;

        while (want < rs->arena_len + need) {
                if (want > SIZE_MAX / 2)
                        return -ENOMEM;

                want *= 2;
        }

        p = realloc(rs->arena, want);
        if (!p)
                return -ENOMEM;

        rs->arena = p;
        rs->arena_size = want;
        return 0;
}

/*
 * Intern one string, reusing an identical one already in the arena.
 *
 * The lookup is linear: it runs once at daemon start and the arena is a few
 * kilobytes. Repeated values (identical RUN strings, `idVendor`/`idProduct`
 * names) become one copy each. Equal strings also become equal offsets, which
 * lets GOTO resolution compare labels as integers.
 */
static int arena_intern(DevdRuleSet *rs, const char *s, size_t len, uint32_t *ret) {
        size_t off;
        int r;

        if (len == 0) {
                *ret = 0;
                return 0;
        }

        for (off = 0; off < rs->arena_len; off += strlen(rs->arena + off) + 1)
                if (strlen(rs->arena + off) == len && memcmp(rs->arena + off, s, len) == 0) {
                        *ret = (uint32_t) off;
                        return 0;
                }

        r = arena_grow(rs, len + 1);
        if (r < 0)
                return r;

        off = rs->arena_len;
        memcpy(rs->arena + off, s, len);
        rs->arena[off + len] = '\0';
        rs->arena_len += len + 1;

        *ret = (uint32_t) off;
        return 0;
}

const char *devd_ruleset_string(const DevdRuleSet *rs, uint32_t offset) {
        if (!rs || !rs->arena || offset >= rs->arena_len)
                return "";

        return rs->arena + offset;
}

/* --- the two tables --- */

static int clauses_reserve(DevdRuleSet *rs, size_t need) {
        size_t want = rs->clauses_size ? rs->clauses_size : DEVD_RULES_TABLE_INITIAL;
        DevdRuleClause *p;

        if (rs->n_clauses + need <= rs->clauses_size)
                return 0;

        while (want < rs->n_clauses + need) {
                if (want > SIZE_MAX / (2 * sizeof(*p)))
                        return -ENOMEM;

                want *= 2;
        }

        p = realloc(rs->clauses, want * sizeof(*p));
        if (!p)
                return -ENOMEM;

        rs->clauses = p;
        rs->clauses_size = want;
        return 0;
}

static int rules_reserve(DevdRuleSet *rs) {
        size_t want = rs->rules_size ? rs->rules_size : DEVD_RULES_TABLE_INITIAL;
        DevdRule *p;

        if (rs->n_rules + 1 <= rs->rules_size)
                return 0;

        while (want < rs->n_rules + 1) {
                if (want > SIZE_MAX / (2 * sizeof(*p)))
                        return -ENOMEM;

                want *= 2;
        }

        p = realloc(rs->rules, want * sizeof(*p));
        if (!p)
                return -ENOMEM;

        rs->rules = p;
        rs->rules_size = want;
        return 0;
}

size_t devd_rule_clauses(const DevdRuleSet *rs, size_t i, const DevdRuleClause **ret) {
        if (!rs || !ret || i >= rs->n_rules)
                return 0;

        *ret = rs->clauses + rs->rules[i].first_clause;
        return rs->rules[i].n_clauses;
}

int devd_ruleset_new(DevdRuleSet **ret) {
        DevdRuleSet *rs;
        int r;

        if (!ret)
                return -EINVAL;

        rs = calloc(1, sizeof(*rs));
        if (!rs)
                return -ENOMEM;

        /* Offset 0 is the empty string, so a zeroed clause field reads as
         * "absent" without every caller checking a flag first. */
        r = arena_grow(rs, 1);
        if (r < 0) {
                free(rs);
                return r;
        }

        rs->arena[0] = '\0';
        rs->arena_len = 1;

        *ret = rs;
        return 0;
}

DevdRuleSet *devd_ruleset_free(DevdRuleSet *rs) {
        if (!rs)
                return NULL;

        free(rs->arena);
        free(rs->clauses);
        free(rs->rules);
        free(rs);
        return NULL;
}

size_t devd_ruleset_symlink_dirs(const DevdRuleSet *rs, char dirs[][DEVD_RULE_VALUE_MAX], size_t max) {
        size_t n = 0;

        if (!rs || !dirs || max == 0)
                return 0;

        for (size_t i = 0; i < rs->n_clauses; i++) {
                const char *value;
                char dir[DEVD_RULE_VALUE_MAX];
                size_t len, cut;
                bool seen = false;

                if (rs->clauses[i].key != DEVD_RULE_KEY_SYMLINK)
                        continue;

                value = devd_ruleset_string(rs, rs->clauses[i].value);

                /* Everything up to the first substitution is fixed text; the
                 * directory part of that is what a sweep can be pointed at. */
                len = strcspn(value, "%$");

                cut = 0;
                for (size_t j = 0; j < len; j++)
                        if (value[j] == '/')
                                cut = j;

                if (cut == 0)
                        continue; /* a link in /dev itself, nothing to sweep */

                memcpy(dir, value, cut);
                dir[cut] = '\0';

                for (size_t j = 0; j < n; j++)
                        if (strcmp(dirs[j], dir) == 0) {
                                seen = true;
                                break;
                        }

                if (seen)
                        continue;

                if (n >= max)
                        return n;

                (void) snprintf(dirs[n++], DEVD_RULE_VALUE_MAX, "%s", dir);
        }

        return n;
}

/* --- pattern matching --- */

bool devd_rules_pattern_match(const char *pattern, const char *value) {
        const char *p;

        if (!pattern || !value)
                return false;

        for (p = pattern;;) {
                char branch[DEVD_RULE_VALUE_MAX];
                const char *end;
                bool in_class = false;
                size_t n;

                /* Bracket- and escape-aware, because `c70[345abce]|c71[34bc]`
                 * out of bluez's hid2hci.rules is a real pattern a naive
                 * strchr('|') would cut inside a character class. */
                for (end = p; *end; end++) {
                        if (*end == '\\' && end[1]) {
                                end++;
                                continue;
                        }

                        if (*end == '[')
                                in_class = true;
                        else if (*end == ']')
                                in_class = false;
                        else if (*end == '|' && !in_class)
                                break;
                }

                n = (size_t) (end - p);
                if (n < sizeof(branch)) {
                        memcpy(branch, p, n);
                        branch[n] = '\0';

                        if (fnmatch(branch, value, 0) == 0)
                                return true;
                }

                if (!*end)
                        return false;

                p = end + 1;
        }
}

/* --- the tokenizer --- */

static bool is_key_char(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

static bool is_space(char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

/* What one clause parsed into, before it is known whether devd implements it. */
typedef struct RawClause {
        char key[32];
        char attr[DEVD_RULE_ATTR_MAX];
        char value[DEVD_RULE_VALUE_MAX];
        DevdRuleOp op;
} RawClause;

/*
 * Parse one clause out of *pos, advancing it. Returns 1 on a clause, 0 at the
 * end of the line, or -EINVAL on something this cannot make sense of.
 *
 * Leading commas and whitespace are consumed first, so a stray double comma
 * (`SUBSYSTEM!="usb", ACTION!="add",, GOTO="..."`) is separator noise rather
 * than a special case.
 */
static int clause_parse(const char **pos, RawClause *ret) {
        const char *p = *pos, *start;
        size_t n;

        while (*p && (is_space(*p) || *p == ','))
                p++;

        if (*p == '\0') {
                *pos = p;
                return 0;
        }

        start = p;
        while (is_key_char(*p))
                p++;

        n = (size_t) (p - start);
        if (n == 0 || n >= sizeof(ret->key))
                return -EINVAL;

        memcpy(ret->key, start, n);
        ret->key[n] = '\0';
        ret->attr[0] = '\0';

        if (*p == '{') {
                p++;
                start = p;

                while (*p && *p != '}')
                        p++;

                if (*p != '}')
                        return -EINVAL;

                n = (size_t) (p - start);
                if (n >= sizeof(ret->attr))
                        return -EINVAL;

                memcpy(ret->attr, start, n);
                ret->attr[n] = '\0';
                p++;
        }

        while (is_space(*p))
                p++;

        if (p[0] == '=' && p[1] == '=') {
                ret->op = DEVD_RULE_OP_MATCH;
                p += 2;
        } else if (p[0] == '!' && p[1] == '=') {
                ret->op = DEVD_RULE_OP_NOMATCH;
                p += 2;
        } else if (p[0] == '+' && p[1] == '=') {
                ret->op = DEVD_RULE_OP_ADD;
                p += 2;
        } else if (p[0] == '-' && p[1] == '=') {
                ret->op = DEVD_RULE_OP_REMOVE;
                p += 2;
        } else if (p[0] == ':' && p[1] == '=') {
                ret->op = DEVD_RULE_OP_ASSIGN;
                p += 2;
        } else if (p[0] == '=') {
                ret->op = DEVD_RULE_OP_ASSIGN;
                p += 1;
        } else
                return -EINVAL;

        while (is_space(*p))
                p++;

        /* Values are plain double-quoted strings. udev's later e"..." C-escape
         * form is not accepted, and reaches the caller as a malformed clause --
         * which makes its rule skipped whole, the safe direction. */
        if (*p != '"')
                return -EINVAL;

        p++;
        start = p;

        while (*p && *p != '"')
                p++;

        if (*p != '"')
                return -EINVAL;

        n = (size_t) (p - start);
        if (n >= sizeof(ret->value))
                return -EINVAL;

        memcpy(ret->value, start, n);
        ret->value[n] = '\0';
        p++;

        *pos = p;
        return 1;
}

/* Find `name` in the key table. Returns its index or -1. */
static int key_lookup(const char *name) {
        for (size_t i = 0; i < DEVD_RULE_KEY_COUNT; i++)
                if (strcmp(devd_rule_key_table[i].name, name) == 0)
                        return (int) i;

        return -1;
}

/*
 * Is this clause one devd implements, with an operator that makes sense for it?
 *
 * Both halves matter equally. `ACTION="add"` is not a match devd should honour
 * as one, and `RUN{builtin}+="kmod load"` names C code no rules engine can
 * supply -- treating either as "close enough" is how a rule ends up firing on
 * devices its author excluded.
 */
static bool clause_is_supported(const RawClause *c, const char **ret_why) {
        int i = key_lookup(c->key);

        if (i < 0) {
                *ret_why = "an unimplemented key";
                return false;
        }

        if (((devd_rule_key_table[i].ops >> c->op) & 1u) == 0) {
                *ret_why = "an operator this key does not take here";
                return false;
        }

        if (devd_rule_key_table[i].wants_attr && c->attr[0] == '\0') {
                *ret_why = "a missing {attribute}";
                return false;
        }

        if (!devd_rule_key_table[i].allows_attr && c->attr[0] != '\0') {
                *ret_why = "an {attribute} this key does not take";
                return false;
        }

        if (devd_rule_key_table[i].key == DEVD_RULE_KEY_RUN && c->attr[0] != '\0' &&
            strcmp(c->attr, "program") != 0) {
                *ret_why = "RUN{builtin}, which is C code and not a rule";
                return false;
        }

        return true;
}

/*
 * Everything one load call needs to know about where it started, so a file that
 * turns out to be unusable can be un-added completely. Interning only ever
 * appends, so rewinding the arena length cannot orphan a string an earlier
 * file still points at.
 */
typedef struct LoadMark {
        size_t n_rules, n_clauses, arena_len;
        unsigned n_skipped;
} LoadMark;

static void load_mark(const DevdRuleSet *rs, LoadMark *m) {
        m->n_rules = rs->n_rules;
        m->n_clauses = rs->n_clauses;
        m->arena_len = rs->arena_len;
        m->n_skipped = rs->n_skipped;
}

static void load_rewind(DevdRuleSet *rs, const LoadMark *m) {
        rs->n_rules = m->n_rules;
        rs->n_clauses = m->n_clauses;
        rs->arena_len = m->arena_len;
        rs->n_skipped = m->n_skipped;
}

/* Append one parsed line's clauses as a rule. Returns 0 or -errno. */
static int rule_append(DevdRuleSet *rs, const RawClause *raw, size_t n_raw, unsigned line) {
        DevdRule *rule;
        int r;

        r = clauses_reserve(rs, n_raw);
        if (r < 0)
                return r;

        r = rules_reserve(rs);
        if (r < 0)
                return r;

        rule = &rs->rules[rs->n_rules];
        memset(rule, 0, sizeof(*rule));
        rule->first_clause = (uint32_t) rs->n_clauses;
        rule->line = (uint16_t) (line > UINT16_MAX ? UINT16_MAX : line);
        rule->goto_target = -1;

        for (size_t i = 0; i < n_raw; i++) {
                DevdRuleClause *c = &rs->clauses[rs->n_clauses + i];
                int k = key_lookup(raw[i].key);

                c->key = (int16_t) devd_rule_key_table[k].key;
                c->op = (int16_t) raw[i].op;

                r = arena_intern(rs, raw[i].attr, strlen(raw[i].attr), &c->attr);
                if (r < 0)
                        return r;

                r = arena_intern(rs, raw[i].value, strlen(raw[i].value), &c->value);
                if (r < 0)
                        return r;

                if (c->key == DEVD_RULE_KEY_LABEL)
                        rule->label = c->value;
                else if (c->key == DEVD_RULE_KEY_GOTO)
                        rule->goto_target = DEVD_RULE_GOTO_PENDING;
        }

        rule->n_clauses = (uint16_t) n_raw;
        rs->n_clauses += n_raw;
        rs->n_rules++;
        return 0;
}

/*
 * Point every pending GOTO at the rule carrying its label.
 *
 * Forward only, and within the same file: a backward jump is a loop this engine
 * has no answer for, and a label in another file is a coupling udev's own
 * per-file GOTO scoping does not create either. Labels are interned, so "does
 * this rule carry that label" is an integer comparison.
 */
static int resolve_gotos(DevdRuleSet *rs, size_t first, const char *name) {
        for (size_t i = first; i < rs->n_rules; i++) {
                const DevdRuleClause *cl = rs->clauses + rs->rules[i].first_clause;
                uint32_t want = 0;
                bool found = false;

                if (rs->rules[i].goto_target != DEVD_RULE_GOTO_PENDING)
                        continue;

                for (size_t j = 0; j < rs->rules[i].n_clauses; j++)
                        if (cl[j].key == DEVD_RULE_KEY_GOTO)
                                want = cl[j].value;

                for (size_t j = i + 1; j < rs->n_rules; j++)
                        if (rs->rules[j].label == want && want != 0) {
                                rs->rules[i].goto_target = (int32_t) j;
                                found = true;
                                break;
                        }

                if (!found) {
                        pico_log(PICO_LOG_ERR,
                                 "devd: %s:%u: GOTO=\"%s\" has no label ahead of it, refusing the file",
                                 name,
                                 rs->rules[i].line,
                                 devd_ruleset_string(rs, want));
                        return -EINVAL;
                }
        }

        return 0;
}

int devd_ruleset_load_string(DevdRuleSet *rs, const char *text, const char *name) {
        const char *p;
        unsigned line = 0;
        LoadMark mark;
        int r;

        if (!rs || !text)
                return -EINVAL;

        if (!name)
                name = "(rules)";

        load_mark(rs, &mark);

        for (p = text; *p;) {
                char logical[DEVD_RULE_LINE_MAX];
                RawClause raw[DEVD_RULE_CLAUSES_MAX];
                const char *cursor, *why = NULL;
                size_t len = 0, n_raw = 0;
                bool skip = false;
                unsigned first_line;

                line++;
                first_line = line;

                /*
                 * Fold continuations here rather than in the clause parser: a
                 * rule split across three lines is one rule, and everything
                 * downstream -- clause counting, the skip-whole decision, the
                 * line number in a log message -- wants to see it that way.
                 */
                for (;;) {
                        const char *eol = p;
                        size_t n;

                        while (*eol && *eol != '\n')
                                eol++;

                        n = (size_t) (eol - p);
                        while (n > 0 && (p[n - 1] == '\r' || p[n - 1] == ' ' || p[n - 1] == '\t'))
                                n--;

                        if (n > 0 && p[n - 1] == '\\') {
                                n--;

                                if (len + n < sizeof(logical)) {
                                        memcpy(logical + len, p, n);
                                        len += n;
                                } else
                                        skip = true;

                                if (*eol == '\0') {
                                        p = eol;
                                        break;
                                }

                                p = eol + 1;
                                line++;
                                continue;
                        }

                        if (len + n < sizeof(logical)) {
                                memcpy(logical + len, p, n);
                                len += n;
                        } else
                                skip = true;

                        p = *eol ? eol + 1 : eol;
                        break;
                }

                logical[len < sizeof(logical) ? len : sizeof(logical) - 1] = '\0';

                cursor = logical;
                while (is_space(*cursor))
                        cursor++;

                if (*cursor == '\0' || *cursor == '#')
                        continue;

                if (skip)
                        why = "a line longer than devd will read";

                while (!why) {
                        RawClause c;

                        r = clause_parse(&cursor, &c);
                        if (r < 0) {
                                why = "a clause devd cannot parse";
                                break;
                        }

                        if (r == 0)
                                break;

                        if (!clause_is_supported(&c, &why))
                                break;

                        if (n_raw >= DEVD_RULE_CLAUSES_MAX) {
                                why = "more clauses than devd will hold";
                                break;
                        }

                        raw[n_raw++] = c;
                }

                if (why) {
                        /* The safety semantic, in one place: the whole rule
                         * goes, never just the clause that was not understood.
                         * See devd-rules.h for why the other way round is
                         * worse than doing nothing. */
                        if (rs->n_skipped < DEVD_RULES_SKIP_LOG_MAX)
                                pico_log(PICO_LOG_WARNING,
                                         "devd: %s:%u: %s, skipping the whole rule",
                                         name,
                                         first_line,
                                         why);

                        rs->n_skipped++;
                        continue;
                }

                if (n_raw == 0)
                        continue;

                r = rule_append(rs, raw, n_raw, first_line);
                if (r < 0)
                        goto fail;
        }

        r = resolve_gotos(rs, mark.n_rules, name);
        if (r < 0)
                goto fail;

        return (int) (rs->n_rules - mark.n_rules);

fail:
        load_rewind(rs, &mark);
        return r;
}

int devd_ruleset_load_file(DevdRuleSet *rs, const char *path) {
        char *text = NULL;
        size_t len = 0, size = 0;
        FILE *f;
        int r;

        if (!rs || !path)
                return -EINVAL;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        for (;;) {
                size_t k;

                if (len + 4096 + 1 > size) {
                        char *p;

                        size = size ? size * 2 : 8192;
                        if (size > DEVD_RULES_FILE_MAX) {
                                r = -EFBIG;
                                goto done;
                        }

                        p = realloc(text, size);
                        if (!p) {
                                r = -ENOMEM;
                                goto done;
                        }

                        text = p;
                }

                k = fread(text + len, 1, 4096, f);
                len += k;

                if (k < 4096) {
                        if (ferror(f)) {
                                r = -EIO;
                                goto done;
                        }

                        break;
                }
        }

        if (!text) {
                r = 0;
                goto done;
        }

        text[len] = '\0';
        r = devd_ruleset_load_string(rs, text, path);

done:
        free(text);
        (void) fclose(f);
        return r;
}

/* --- directory collation --- */

typedef struct RulesFile {
        char base[DEVD_RULES_BASENAME_MAX];
        char path[DEVD_RULES_PATH_MAX];
} RulesFile;

static int rules_file_compare(const void *a, const void *b) {
        return strcmp(((const RulesFile *) a)->base, ((const RulesFile *) b)->base);
}

static bool ends_in_rules(const char *name) {
        size_t n = strlen(name);

        return n > 6 && strcmp(name + n - 6, ".rules") == 0;
}

int devd_ruleset_load_dirs(DevdRuleSet *rs, const char * const *dirs) {
        RulesFile *files;
        size_t n_files = 0;
        int loaded = 0, r = 0;

        if (!rs || !dirs)
                return -EINVAL;

        files = calloc(DEVD_RULES_FILES_MAX, sizeof(*files));
        if (!files)
                return -ENOMEM;

        for (size_t d = 0; dirs[d]; d++) {
                struct dirent *e;
                DIR *dd = opendir(dirs[d]);

                if (!dd)
                        continue; /* /etc/udev/rules.d usually is not there */

                while ((e = readdir(dd))) {
                        size_t i;

                        if (e->d_name[0] == '.' || !ends_in_rules(e->d_name))
                                continue;

                        if (strlen(e->d_name) >= sizeof(files[0].base)) {
                                pico_log(PICO_LOG_WARNING,
                                         "devd: %s/%s: name too long, ignored",
                                         dirs[d],
                                         e->d_name);
                                continue;
                        }

                        /* Later directory wins on a repeated basename: that is
                         * how /etc/udev/rules.d/40-usb_modeswitch.rules
                         * replaces the vendor copy without editing it. */
                        for (i = 0; i < n_files; i++)
                                if (strcmp(files[i].base, e->d_name) == 0)
                                        break;

                        if (i == n_files) {
                                if (n_files >= DEVD_RULES_FILES_MAX) {
                                        pico_log(PICO_LOG_WARNING,
                                                 "devd: more than %d rules files, ignoring %s/%s",
                                                 DEVD_RULES_FILES_MAX,
                                                 dirs[d],
                                                 e->d_name);
                                        continue;
                                }

                                n_files++;

                                /* memcpy, not snprintf: the length was checked
                                 * two branches up, and the compiler can see
                                 * that here where it cannot see it there. */
                                memcpy(files[i].base, e->d_name, strlen(e->d_name) + 1);
                        }

                        if ((size_t) snprintf(files[i].path, sizeof(files[i].path), "%s/%s", dirs[d], e->d_name) >=
                            sizeof(files[i].path))
                                files[i].path[0] = '\0';
                }

                (void) closedir(dd);
        }

        qsort(files, n_files, sizeof(*files), rules_file_compare);

        for (size_t i = 0; i < n_files; i++) {
                if (files[i].path[0] == '\0')
                        continue;

                r = devd_ruleset_load_file(rs, files[i].path);
                if (r < 0) {
                        /* One unusable file is not a reason to run with none:
                         * the others still describe devices this machine has,
                         * and refusing everything would be a bigger outage than
                         * the file that caused it. */
                        pico_log(PICO_LOG_WARNING, "devd: %s: not loaded: %s", files[i].path, strerror(-r));
                        continue;
                }

                loaded += r;
        }

        free(files);
        return loaded;
}
