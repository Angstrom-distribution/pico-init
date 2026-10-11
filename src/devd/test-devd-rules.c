/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The rules tokenizer, against the bytes of the file that is really on the
 * image.
 *
 * The excerpt below is copied verbatim out of usb-modeswitch-data 20251207's
 * own 40-usb_modeswitch.rules, so the fixture can fail in the ways the real
 * file can. It carries every shape that file has: the two GOTO guards -- one of
 * them with a stray double comma -- the one rule that needs parent-chain
 * matching, two of the identical vendor:product lines, the LABEL at the end,
 * and the one rule (PROGRAM=/SYMLINK+="%c") that is out of devd's subset.
 *
 * That last one must be skipped WHOLE: if its SYMLINK+= survived while its
 * PROGRAM= was dropped, devd would create a link on every ttyUSB device rather
 * than only on the modems the rule's author checked for.
 *
 * The rest of the file is not embedded. The real file is run through the same
 * parser by pointing PICO_TEST_USB_MODESWITCH_RULES at it, which the last case
 * below picks up.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../test-util.h"
#include "devd-rules.h"

/* Verbatim: lines 1-12, 14-15, 17-21 and 1259-1262 of the real file. */
static const char usb_modeswitch_excerpt[] =
                "# Part of usb-modeswitch-data, version 20251207\n"
                "#\n"
                "# Works with usb_modeswitch versions >= 2.4.0. Slash before %k parameter\n"
                "# is for compatibility only. Versions >= 2.5.0 don't need it.\n"
                "#\n"
                "ACTION!=\"add|change\", GOTO=\"modeswitch_rules_end\"\n"
                "\n"
                "# Adds a symlink \"gsmmodem[n]\" to the lowest ttyUSB port with interrupt\n"
                "# transfer; checked against a list of known modems, or else no action\n"
                "KERNEL==\"ttyUSB*\", ATTRS{bNumConfigurations}==\"*\", PROGRAM=\"usb_modeswitch "
                "--symlink-name %p %s{idVendor} %s{idProduct} %E{PRODUCT}\", SYMLINK+=\"%c\"\n"
                "\n"
                "SUBSYSTEM!=\"usb\", ACTION!=\"add\",, GOTO=\"modeswitch_rules_end\"\n"
                "\n"
                "# Generic entry for most Huawei devices, excluding Android phones\n"
                "ATTRS{idVendor}==\"12d1\", ATTRS{manufacturer}!=\"Android\", "
                "ATTR{bInterfaceNumber}==\"00\", ATTR{bInterfaceClass}==\"08\", RUN+=\"usb_modeswitch "
                "'%b/%k'\"\n"
                "\n"
                "# HP LaserJet Professional P1102\n"
                "ATTR{idVendor}==\"03f0\", ATTR{idProduct}==\"002a\", RUN+=\"usb_modeswitch '/%k'\"\n"
                "\n"
                "# HP LaserJet Professional P1102w\n"
                "ATTR{idVendor}==\"03f0\", ATTR{idProduct}==\"032a\", RUN+=\"usb_modeswitch '/%k'\"\n"
                "\n"
                "# Aiko 81D, fw with wrong vendor ID\n"
                "ATTR{idVendor}==\"ed09\", ATTR{idProduct}==\"1021\", RUN+=\"usb_modeswitch '/%k'\"\n"
                "\n"
                "LABEL=\"modeswitch_rules_end\"\n";

/* The n-th clause of rule `i`, or NULL. */
static const DevdRuleClause *clause_at(const DevdRuleSet *rs, size_t i, size_t j) {
        const DevdRuleClause *cl = NULL;
        size_t n = devd_rule_clauses(rs, i, &cl);

        return j < n ? &cl[j] : NULL;
}

static bool ruleset_has_key(const DevdRuleSet *rs, DevdRuleKey key) {
        for (size_t i = 0; i < rs->n_rules; i++) {
                const DevdRuleClause *cl = NULL;
                size_t n = devd_rule_clauses(rs, i, &cl);

                for (size_t j = 0; j < n; j++)
                        if (cl[j].key == (int16_t) key)
                                return true;
        }

        return false;
}

static void test_usb_modeswitch_excerpt(void) {
        const DevdRuleClause *c;
        DevdRuleSet *rs = NULL;
        int r;

        ASSERT_EQ_INT(devd_ruleset_new(&rs), 0);

        r = devd_ruleset_load_string(rs, usb_modeswitch_excerpt, "40-usb_modeswitch.rules");

        /* Eight rule lines in the excerpt, one of them out of the subset. */
        ASSERT_EQ_INT(r, 7);
        ASSERT_EQ_INT(rs->n_rules, 7);
        ASSERT_EQ_INT(rs->n_skipped, 1);

        /* Rule 0: the ACTION guard, with its GOTO pointing at the LABEL rule
         * -- resolved at load, so evaluation never searches for a label. */
        c = clause_at(rs, 0, 0);
        ASSERT_EQ_INT(c->key, DEVD_RULE_KEY_ACTION);
        ASSERT_EQ_INT(c->op, DEVD_RULE_OP_NOMATCH);
        ASSERT_STREQ(devd_ruleset_string(rs, c->value), "add|change");
        ASSERT_EQ_INT(rs->rules[0].goto_target, 6);
        ASSERT_STREQ(devd_ruleset_string(rs, rs->rules[6].label), "modeswitch_rules_end");

        /*
         * Rule 1: the guard with the stray double comma. Three clauses, not
         * four and not a parse failure: an empty clause is separator noise.
         */
        ASSERT_EQ_INT(rs->rules[1].n_clauses, 3);
        ASSERT_EQ_INT(clause_at(rs, 1, 0)->key, DEVD_RULE_KEY_SUBSYSTEM);
        ASSERT_STREQ(devd_ruleset_string(rs, clause_at(rs, 1, 0)->value), "usb");
        ASSERT_EQ_INT(clause_at(rs, 1, 1)->key, DEVD_RULE_KEY_ACTION);
        ASSERT_EQ_INT(clause_at(rs, 1, 2)->key, DEVD_RULE_KEY_GOTO);
        ASSERT_EQ_INT(rs->rules[1].goto_target, 6);

        /* Rule 2: the Huawei catch-all, the one rule in the file that needs
         * the parent chain. Two ATTRS, two ATTR, one RUN. */
        ASSERT_EQ_INT(rs->rules[2].n_clauses, 5);
        ASSERT_EQ_INT(clause_at(rs, 2, 0)->key, DEVD_RULE_KEY_ATTRS);
        ASSERT_STREQ(devd_ruleset_string(rs, clause_at(rs, 2, 0)->attr), "idVendor");
        ASSERT_STREQ(devd_ruleset_string(rs, clause_at(rs, 2, 0)->value), "12d1");
        ASSERT_EQ_INT(clause_at(rs, 2, 1)->key, DEVD_RULE_KEY_ATTRS);
        ASSERT_EQ_INT(clause_at(rs, 2, 1)->op, DEVD_RULE_OP_NOMATCH);
        ASSERT_EQ_INT(clause_at(rs, 2, 2)->key, DEVD_RULE_KEY_ATTR);
        ASSERT_EQ_INT(clause_at(rs, 2, 4)->key, DEVD_RULE_KEY_RUN);
        ASSERT_EQ_INT(clause_at(rs, 2, 4)->op, DEVD_RULE_OP_ADD);
        ASSERT_STREQ(devd_ruleset_string(rs, clause_at(rs, 2, 4)->value), "usb_modeswitch '%b/%k'");

        /* Rules 3-5: the shape most of the file's rules share. */
        ASSERT_EQ_INT(rs->rules[3].n_clauses, 3);
        ASSERT_STREQ(devd_ruleset_string(rs, clause_at(rs, 3, 1)->value), "002a");
        ASSERT_STREQ(devd_ruleset_string(rs, clause_at(rs, 3, 2)->value), "usb_modeswitch '/%k'");

        /*
         * The skipped rule left nothing behind. Its SYMLINK+="%c" is the
         * clause that would have done damage on its own: KERNEL=="ttyUSB*"
         * matches every USB serial port, and only the PROGRAM= devd does not
         * implement narrows that to known modems.
         */
        ASSERT_TRUE(!ruleset_has_key(rs, DEVD_RULE_KEY_SYMLINK));
        ASSERT_TRUE(!ruleset_has_key(rs, DEVD_RULE_KEY_KERNEL));

        /*
         * The identical RUN values are one string. Asserted through the
         * interning rather than by measuring the arena, because equal offsets
         * is also what makes GOTO label resolution an integer comparison.
         */
        ASSERT_EQ_INT(clause_at(rs, 3, 2)->value, clause_at(rs, 4, 2)->value);
        ASSERT_EQ_INT(clause_at(rs, 3, 0)->attr, clause_at(rs, 4, 0)->attr);
        ASSERT_TRUE(clause_at(rs, 3, 2)->value != clause_at(rs, 2, 4)->value);

        devd_ruleset_free(rs);
}

static void test_unsupported_keys_skip_whole(void) {
        static const char text[] =
                        /* Every one of these is a key or an operator devd does
                         * not implement, and each is paired with an action that
                         * would fire on far too much if the clause devd did not
                         * understand were dropped. */
                        "PROGRAM==\"/bin/true\", SYMLINK+=\"everything\"\n"
                        "TEST!=\"/run/nope\", RUN+=\"do-it\"\n"
                        "IMPORT{builtin}=\"blkid\", SYMLINK+=\"by-uuid/x\"\n"
                        "SUBSYSTEM==\"tty\", NAME=\"renamed\"\n"
                        "SUBSYSTEM==\"tty\", OPTIONS+=\"last_rule\"\n"
                        "ATTR{power/control}=\"auto\"\n"
                        "SUBSYSTEM==\"usb\", RUN{builtin}+=\"kmod load\"\n"
                        "ACTION=\"add\"\n"
                        "SUBSYSTEM==\"block\", SYMLINK+=\"kept\"\n";

        DevdRuleSet *rs = NULL;

        ASSERT_EQ_INT(devd_ruleset_new(&rs), 0);
        ASSERT_EQ_INT(devd_ruleset_load_string(rs, text, "skip.rules"), 1);
        ASSERT_EQ_INT(rs->n_skipped, 8);

        /* The one supported rule survived, and nothing from the eight did. */
        ASSERT_EQ_INT(rs->n_rules, 1);
        ASSERT_EQ_INT(rs->rules[0].n_clauses, 2);
        ASSERT_STREQ(devd_ruleset_string(rs, clause_at(rs, 0, 1)->value), "kept");
        ASSERT_TRUE(!ruleset_has_key(rs, DEVD_RULE_KEY_RUN));

        devd_ruleset_free(rs);
}

static void test_goto_must_point_forward(void) {
        static const char missing[] =
                        "ACTION!=\"add\", GOTO=\"nowhere\"\n"
                        "SUBSYSTEM==\"usb\", RUN+=\"tool\"\n";
        static const char backward[] =
                        "LABEL=\"top\"\n"
                        "ACTION!=\"add\", GOTO=\"top\"\n";

        DevdRuleSet *rs = NULL;

        ASSERT_EQ_INT(devd_ruleset_new(&rs), 0);

        /*
         * Refusing the whole file, where an unsupported key only loses its own
         * rule. A guard whose GOTO silently stops
         * jumping does not disable one rule, it exposes every rule below it to
         * events the author excluded. Fail closed.
         */
        ASSERT_EQ_INT(devd_ruleset_load_string(rs, missing, "missing.rules"), -EINVAL);
        ASSERT_EQ_INT(rs->n_rules, 0);

        /* Backward jumps are a loop this engine has no answer for, so they are
         * not labels it can see. */
        ASSERT_EQ_INT(devd_ruleset_load_string(rs, backward, "backward.rules"), -EINVAL);
        ASSERT_EQ_INT(rs->n_rules, 0);

        devd_ruleset_free(rs);
}

static void test_comments_continuations_and_noise(void) {
        static const char text[] =
                        "   # indented comment\n"
                        "\n"
                        "\t\n"
                        "SUBSYSTEM==\"tty\", \\\n"
                        "        KERNEL==\"ttyUSB*\", \\\n"
                        "        RUN+=\"tool\"\n"
                        ",,,\n"
                        "ENV{.PRIVATE}=\"x\", ENV{PUBLIC}+=\"y\"\n";

        DevdRuleSet *rs = NULL;

        ASSERT_EQ_INT(devd_ruleset_new(&rs), 0);
        ASSERT_EQ_INT(devd_ruleset_load_string(rs, text, "misc.rules"), 2);
        ASSERT_EQ_INT(rs->n_skipped, 0);

        /* One rule out of three physical lines. */
        ASSERT_EQ_INT(rs->rules[0].n_clauses, 3);
        ASSERT_EQ_INT(clause_at(rs, 0, 2)->key, DEVD_RULE_KEY_RUN);

        ASSERT_EQ_INT(rs->rules[1].n_clauses, 2);
        ASSERT_STREQ(devd_ruleset_string(rs, clause_at(rs, 1, 0)->attr), ".PRIVATE");
        ASSERT_EQ_INT(clause_at(rs, 1, 0)->op, DEVD_RULE_OP_ASSIGN);
        ASSERT_EQ_INT(clause_at(rs, 1, 1)->op, DEVD_RULE_OP_ADD);

        devd_ruleset_free(rs);
}

static void test_pattern_matching(void) {
        /* Globs, not regexes: no regcomp() is reachable from here. */
        ASSERT_TRUE(devd_rules_pattern_match("add|change", "change"));
        ASSERT_TRUE(!devd_rules_pattern_match("add|change", "remove"));
        ASSERT_TRUE(devd_rules_pattern_match("ttyUSB*", "ttyUSB0"));
        ASSERT_TRUE(devd_rules_pattern_match("ttyUSB*|ttyACM*", "ttyACM17"));
        ASSERT_TRUE(!devd_rules_pattern_match("ttyUSB*|ttyACM*", "ttyS0"));
        ASSERT_TRUE(devd_rules_pattern_match("*", ""));
        ASSERT_TRUE(devd_rules_pattern_match("", ""));
        ASSERT_TRUE(!devd_rules_pattern_match("", "x"));
        ASSERT_TRUE(devd_rules_pattern_match("sd?", "sda"));

        /* bluez's hid2hci.rules, where a naive strchr('|') would cut inside
         * the character class and match nothing at all. */
        ASSERT_TRUE(devd_rules_pattern_match("c70[345abce]|c71[34bc]", "c705"));
        ASSERT_TRUE(devd_rules_pattern_match("c70[345abce]|c71[34bc]", "c71b"));
        ASSERT_TRUE(!devd_rules_pattern_match("c70[345abce]|c71[34bc]", "c712"));
}

static void test_directory_shadowing(void) {
        char *root = test_tmpdir_new();
        char lib[PATH_MAX], etc[PATH_MAX];
        const char *dirs[3];
        DevdRuleSet *rs = NULL;

        ASSERT_TRUE(root != NULL);
        ASSERT_EQ_INT(test_mkdir(root, "lib"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "etc"), 0);

        ASSERT_TRUE((size_t) snprintf(lib, sizeof(lib), "%s/lib", root) < sizeof(lib));
        ASSERT_TRUE((size_t) snprintf(etc, sizeof(etc), "%s/etc", root) < sizeof(etc));

        ASSERT_EQ_INT(test_write_file(lib, "40-thing.rules", "SUBSYSTEM==\"usb\", RUN+=\"vendor\"\n"), 0);
        ASSERT_EQ_INT(test_write_file(lib, "60-other.rules", "SUBSYSTEM==\"tty\", RUN+=\"other\"\n"), 0);
        ASSERT_EQ_INT(test_write_file(etc, "40-thing.rules", "SUBSYSTEM==\"usb\", RUN+=\"local\"\n"), 0);
        ASSERT_EQ_INT(test_write_file(lib, "notrules.conf", "garbage that is not a rule at all\n"), 0);

        dirs[0] = lib;
        dirs[1] = etc;
        dirs[2] = NULL;

        ASSERT_EQ_INT(devd_ruleset_new(&rs), 0);
        ASSERT_EQ_INT(devd_ruleset_load_dirs(rs, dirs), 2);

        /* Sorted by basename across both directories, and /etc's copy of
         * 40-thing.rules replaced the vendor one entirely rather than being
         * loaded after it. */
        ASSERT_STREQ(devd_ruleset_string(rs, clause_at(rs, 0, 1)->value), "local");
        ASSERT_STREQ(devd_ruleset_string(rs, clause_at(rs, 1, 1)->value), "other");

        devd_ruleset_free(rs);
        test_rm_rf(root);
        free(root);
}

static void test_symlink_dirs(void) {
        static const char text[] =
                        "SUBSYSTEM==\"tty\", SYMLINK+=\"serial/by-id/usb-$attr{serial}\"\n"
                        "SUBSYSTEM==\"tty\", SYMLINK+=\"serial/by-id/other-%k\"\n"
                        "SUBSYSTEM==\"block\", SYMLINK+=\"flat\"\n";

        char dirs[4][DEVD_RULE_VALUE_MAX];
        DevdRuleSet *rs = NULL;

        ASSERT_EQ_INT(devd_ruleset_new(&rs), 0);
        ASSERT_EQ_INT(devd_ruleset_load_string(rs, text, "links.rules"), 3);

        /* One entry: both links live in the same directory, and the third has
         * no directory to sweep. */
        ASSERT_EQ_INT(devd_ruleset_symlink_dirs(rs, dirs, 4), 1);
        ASSERT_STREQ(dirs[0], "serial/by-id");

        devd_ruleset_free(rs);
}

/*
 * The acceptance case, when the real file is available to point at.
 *
 * `meson test` runs this without the variable set and the case is a no-op;
 * PICO_TEST_USB_MODESWITCH_RULES=/usr/lib/udev/rules.d/40-usb_modeswitch.rules
 * (or the unpacked usb-modeswitch-data tarball's copy) turns it into a check
 * of the real file, run by the code that runs on a board.
 */
static void test_real_file_if_present(void) {
        const char *path = getenv("PICO_TEST_USB_MODESWITCH_RULES");
        DevdRuleSet *rs = NULL;
        int r;

        if (!path || path[0] == '\0')
                return;

        ASSERT_EQ_INT(devd_ruleset_new(&rs), 0);

        r = devd_ruleset_load_file(rs, path);
        ASSERT_TRUE(r > 0);

        printf("real file %s: %d rules loaded, %u skipped, arena %zu bytes\n",
               path,
               r,
               rs->n_skipped,
               rs->arena_len);

        /* 420 rule lines: 415 vendor pairs, two GOTO guards, the Huawei
         * catch-all, the LABEL, and the one PROGRAM= rule that is skipped. */
        ASSERT_EQ_INT(r, 419);
        ASSERT_EQ_INT(rs->n_skipped, 1);
        ASSERT_TRUE(!ruleset_has_key(rs, DEVD_RULE_KEY_SYMLINK));

        devd_ruleset_free(rs);
}

int main(void) {
        test_usb_modeswitch_excerpt();
        test_unsupported_keys_skip_whole();
        test_goto_must_point_forward();
        test_comments_continuations_and_noise();
        test_pattern_matching();
        test_directory_shadowing();
        test_symlink_dirs();
        test_real_file_if_present();

        return 0;
}
