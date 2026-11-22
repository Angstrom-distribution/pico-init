/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * modules-load.d(5) against fixture directories. modprobe is a shell script
 * in the fixture tree that appends the module name it is given to a log and
 * fails for the name "missing", so the real modprobe is never run and the
 * log is the exact list of what would have been loaded, in order. Stand-ins
 * for the kmod and busybox flavours show what -b does on each, and one case
 * runs the real kmod modprobe with --dry-run when it is installed.
 */

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../test-util.h"
#include "../util.h"
#include "modules-load.h"

static char *root;
static char dir_a[PATH_MAX], dir_b[PATH_MAX], dir_c[PATH_MAX];
static char stub[PATH_MAX], loadlog[PATH_MAX], cmdline[PATH_MAX];
static char *dirs[4];

static void reset(void) {
        char cmd[PATH_MAX * 2];

        snprintf(cmd, sizeof(cmd), "rm -rf '%s'/a/* '%s'/b/* '%s'/c/* '%s'", root, root, root, loadlog);
        ASSERT_EQ_INT(system(cmd), 0);
        (void) unlink(cmdline);
}

static void set_cmdline(const char *line) {
        ASSERT_EQ_INT(test_write_file(root, "cmdline", line), 0);
}

/* The names modprobe was run for, one per line, "" when it never ran. */
static const char *loaded(void) {
        static char buf[1024];
        FILE *f = fopen(loadlog, "re");
        size_t n;

        buf[0] = '\0';
        if (!f)
                return buf;
        n = fread(buf, 1, sizeof(buf) - 1, f);
        buf[n] = '\0';
        (void) fclose(f);
        return buf;
}

static int run(size_t *n, size_t *failed) {
        PicoModulesLoad c = { .dirs = dirs, .cmdline = cmdline, .modprobe = stub };

        return pico_modules_load_run(&c, n, failed);
}

static void test_parse_file(void) {
        char **names = NULL, path[PATH_MAX];

        ASSERT_EQ_INT(test_write_file(root,
                                      "p.conf",
                                      "# comment\n"
                                      "\n"
                                      "; another\n"
                                      "   \t\n"
                                      "  # indented comment\n"
                                      "  ; indented too\n"
                                      "alpha\n"
                                      "  beta \t \n"
                                      "alpha\n"
                                      "gamma"),
                      0);
        snprintf(path, sizeof(path), "%s/p.conf", root);
        ASSERT_EQ_INT(pico_modules_load_parse_file(path, &names), 0);
        ASSERT_EQ_INT(pico_strv_length(names), 3);
        ASSERT_STREQ(names[0], "alpha");
        ASSERT_STREQ(names[1], "beta");
        ASSERT_STREQ(names[2], "gamma");
        pico_strv_free(names);

        names = NULL;
        snprintf(path, sizeof(path), "%s/nonexistent.conf", root);
        ASSERT_EQ_INT(pico_modules_load_parse_file(path, &names), -ENOENT);
        ASSERT_TRUE(names == NULL);
}

static void test_parse_cmdline(void) {
        char **names = NULL;

        ASSERT_EQ_INT(pico_modules_load_parse_cmdline(
                                      "root=/dev/sda1 modules_load=a,b quiet rd.modules_load=c,,a "
                                      "modules-load=d rd.modules-load=e\n",
                                      &names),
                      0);
        ASSERT_EQ_INT(pico_strv_length(names), 5);
        ASSERT_STREQ(names[0], "a");
        ASSERT_STREQ(names[1], "b");
        ASSERT_STREQ(names[2], "c");
        ASSERT_STREQ(names[3], "d");
        ASSERT_STREQ(names[4], "e");
        pico_strv_free(names);

        /* Other parameters that merely contain the text are not it. */
        names = NULL;
        ASSERT_EQ_INT(pico_modules_load_parse_cmdline(
                                      "xmodules_load=a modules_loadx=b module_blacklist=c "
                                      "modules_load",
                                      &names),
                      0);
        ASSERT_TRUE(names == NULL);

        /* An unterminated quote costs the rest of the line, not the earlier names. */
        names = NULL;
        ASSERT_EQ_INT(pico_modules_load_parse_cmdline("modules_load=a \"oops modules_load=b", &names), 0);
        ASSERT_EQ_INT(pico_strv_length(names), 1);
        ASSERT_STREQ(names[0], "a");
        pico_strv_free(names);
}

/* Quoted values, '-' and '_' spellings of one module, over-long lines and non-regular files. */
static void test_edge_cases(void) {
        char **names = NULL, fifo[PATH_MAX + 16];
        size_t n, failed;

        ASSERT_EQ_INT(pico_modules_load_parse_cmdline("modules_load=\"a,b\" \"rd.modules_load=c\"", &names),
                      0);
        ASSERT_EQ_INT(pico_strv_length(names), 3);
        ASSERT_STREQ(names[0], "a");
        ASSERT_STREQ(names[2], "c");
        pico_strv_free(names);

        reset();
        set_cmdline("modules_load=snd-dummy\n");
        ASSERT_EQ_INT(test_write_file(dir_a, "d.conf", "snd_dummy\nother\n"), 0);
        ASSERT_EQ_INT(run(&n, &failed), 0);
        ASSERT_EQ_INT(n, 2);
        ASSERT_STREQ(loaded(), "snd-dummy\nother\n");

        /* A line of 4096 bytes or more is skipped, the lines around it are not. */
        reset();
        set_cmdline("\n");
        {
                char *content = malloc(5100);

                ASSERT_TRUE(content != NULL);
                memset(content, 'x', 5100);
                memcpy(content, "before\n", 7);
                content[7 + 4999] = '\n';
                memcpy(content + 7 + 5000, "after\n", 7);
                ASSERT_EQ_INT(test_write_file(dir_a, "big.conf", content), 0);
                free(content);
        }
        ASSERT_EQ_INT(run(&n, &failed), 0);
        ASSERT_STREQ(loaded(), "before\nafter\n");

        /* The newline does not count: 4095 bytes load, 4096 do not. */
        reset();
        set_cmdline("\n");
        {
                char *content = malloc(4096 + 2 + 4097);

                ASSERT_TRUE(content != NULL);
                memset(content, 'y', 4095);
                content[4095] = '\n';
                memset(content + 4096, 'z', 4096);
                content[4096 + 4096] = '\n';
                content[4096 + 4097] = '\0';
                ASSERT_EQ_INT(test_write_file(dir_a, "edge.conf", content), 0);
                free(content);
        }
        ASSERT_EQ_INT(run(&n, &failed), 0);
        ASSERT_EQ_INT(n, 1);

        /* A directory named "*.conf" is not read, and a FIFO does not block. */
        reset();
        ASSERT_EQ_INT(test_mkdir(dir_a, "d.conf"), 0);
        snprintf(fifo, sizeof(fifo), "%s/f.conf", dir_a);
        ASSERT_EQ_INT(mkfifo(fifo, 0600), 0);
        ASSERT_EQ_INT(test_write_file(dir_b, "ok.conf", "fine\n"), 0);
        ASSERT_EQ_INT(run(&n, &failed), 0);
        ASSERT_STREQ(loaded(), "fine\n");

        /* A command line longer than any fixed buffer keeps its last word whole. */
        reset();
        {
                size_t len = 9000;
                char *line = malloc(len + 64);

                ASSERT_TRUE(line != NULL);
                memset(line, 'a', len);
                memcpy(line + len, " modules_load=dm_crypt\n", 24);
                line[len + 24] = '\0';
                set_cmdline(line);
                free(line);
        }
        ASSERT_EQ_INT(run(&n, &failed), 0);
        ASSERT_STREQ(loaded(), "dm_crypt\n");
}

/* The same file name in an earlier directory hides the later one entirely. */
static void test_precedence(void) {
        size_t n, failed;

        reset();
        set_cmdline("quiet\n");
        ASSERT_EQ_INT(test_write_file(dir_a, "x.conf", "from_a\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir_b, "x.conf", "from_b\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir_b, "y.conf", "only_b\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir_c, "x.conf", "from_c\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir_c, "z.conf", "only_c\n"), 0);
        /* Not "*.conf", and hidden: never read. */
        ASSERT_EQ_INT(test_write_file(dir_c, "w.txt", "not_conf\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir_c, ".h.conf", "hidden\n"), 0);

        ASSERT_EQ_INT(run(&n, &failed), 0);
        ASSERT_EQ_INT(n, 3);
        ASSERT_EQ_INT(failed, 0);
        ASSERT_STREQ(loaded(), "from_a\nonly_b\nonly_c\n");

        /* A link to /dev/null in an earlier directory masks the name. */
        reset();
        ASSERT_EQ_INT(test_symlink(dir_a, "x.conf", "/dev/null"), 0);
        ASSERT_EQ_INT(test_write_file(dir_b, "x.conf", "masked\n"), 0);
        ASSERT_EQ_INT(test_write_file(dir_b, "y.conf", "kept\n"), 0);
        ASSERT_EQ_INT(run(&n, &failed), 0);
        ASSERT_EQ_INT(n, 1);
        ASSERT_STREQ(loaded(), "kept\n");
}

static void test_comments_and_blanks(void) {
        size_t n, failed;

        reset();
        set_cmdline("\n");
        ASSERT_EQ_INT(test_write_file(dir_a, "m.conf", "# c\n\n; c\n  \nloop  \n\t# c\n dummy\nloop\n"), 0);
        ASSERT_EQ_INT(run(&n, &failed), 0);
        ASSERT_EQ_INT(n, 2);
        ASSERT_STREQ(loaded(), "loop\ndummy\n");
}

/* A module modprobe refuses is counted and logged; the ones after it still load. */
static void test_failure_continues(void) {
        size_t n, failed;

        reset();
        set_cmdline("\n");
        ASSERT_EQ_INT(test_write_file(dir_a, "f.conf", "first\nmissing\nlast\n"), 0);
        ASSERT_EQ_INT(run(&n, &failed), 0);
        ASSERT_EQ_INT(n, 3);
        ASSERT_EQ_INT(failed, 1);
        ASSERT_STREQ(loaded(), "first\nmissing\nlast\n");

        /* A modprobe that cannot be run fails every module, none stops the others. */
        {
                PicoModulesLoad c = { .dirs = dirs, .cmdline = cmdline, .modprobe = "/nonexistent/modprobe" };

                ASSERT_EQ_INT(pico_modules_load_run(&c, &n, &failed), 0);
                ASSERT_EQ_INT(n, 3);
                ASSERT_EQ_INT(failed, 3);
        }
}

static void test_cmdline(void) {
        size_t n, failed;

        reset();
        set_cmdline("console=ttyS0 modules_load=k1,k2 rd.modules_load=k3,k1\n");
        ASSERT_EQ_INT(test_write_file(dir_a, "f.conf", "k3\nfile1\n"), 0);
        ASSERT_EQ_INT(run(&n, &failed), 0);
        ASSERT_EQ_INT(n, 4);
        ASSERT_EQ_INT(failed, 0);
        /* The command line first, then the files, each name once. */
        ASSERT_STREQ(loaded(), "k1\nk2\nk3\nfile1\n");

        /* A missing command line file is not an error. */
        reset();
        ASSERT_EQ_INT(test_write_file(dir_a, "f.conf", "only\n"), 0);
        ASSERT_EQ_INT(run(&n, &failed), 0);
        ASSERT_EQ_INT(n, 1);
        ASSERT_STREQ(loaded(), "only\n");
}

/* Nothing asked for: modprobe is never started, even one that cannot exist. */
static void test_skip(void) {
        PicoModulesLoad c = { .dirs = dirs, .cmdline = cmdline, .modprobe = "/nonexistent/modprobe" };
        size_t n = 99, failed = 99;

        reset();
        set_cmdline("root=/dev/mmcblk0p2 rw\n");
        ASSERT_EQ_INT(pico_modules_load_run(&c, &n, &failed), 0);
        ASSERT_EQ_INT(n, 0);
        ASSERT_EQ_INT(failed, 0);

        /* Directories that exist but hold no "*.conf" file are the same. */
        ASSERT_EQ_INT(test_write_file(dir_a, "readme.txt", "x\n"), 0);
        ASSERT_EQ_INT(pico_modules_load_run(&c, &n, &failed), 0);
        ASSERT_EQ_INT(n, 0);
        ASSERT_STREQ(loaded(), "");

        /* Directories that do not exist at all. */
        {
                char *none[] = { "/nonexistent/one", "/nonexistent/two", NULL };

                c.dirs = none;
                c.cmdline = "/nonexistent/cmdline";
                ASSERT_EQ_INT(pico_modules_load_run(&c, &n, &failed), 0);
                ASSERT_EQ_INT(n, 0);
        }
}

static void write_script(const char *name, const char *body) {
        char path[PATH_MAX];

        ASSERT_EQ_INT(test_write_file(root, name, body), 0);
        snprintf(path, sizeof(path), "%s/%s", root, name);
        ASSERT_EQ_INT(chmod(path, 0755), 0);
}

static int run_with(const char *modprobe, size_t *n, size_t *failed) {
        PicoModulesLoad c = { .dirs = dirs, .cmdline = cmdline, .modprobe = modprobe };

        return pico_modules_load_run(&c, n, failed);
}

/*
 * What -b does on each flavour of modprobe, with stand-ins. kmod applies a
 * modprobe.d "blacklist" to a module named directly only with -b and then
 * exits 0 without loading it. busybox accepts -b in every build and applies
 * the blacklist only when built with FEATURE_MODPROBE_BLACKLIST; without it
 * the module loads. Both must be run as "modprobe -b -- NAME" and neither
 * result is a failure.
 */
static void test_modprobe_flavours(void) {
        char body[PATH_MAX * 3], path[PATH_MAX];
        size_t n, failed;

        snprintf(body,
                 sizeof(body),
                 "#!/bin/sh\n"
                 "b=0; while [ \"${1#-}\" != \"$1\" ]; do\n"
                 "  case \"$1\" in -b) b=1;; --) shift; break;; *) exit 2;; esac; shift\n"
                 "done\n"
                 "[ \"$#\" = 1 ] || exit 2\n"
                 "[ \"$b\" = 1 ] && [ \"$1\" = blacklisted ] && exit 0\n"
                 "echo \"$1\" >> '%s'\n",
                 loadlog);
        write_script("kmod-modprobe", body);

        snprintf(body,
                 sizeof(body),
                 "#!/bin/sh\n"
                 "b=0; while [ \"${1#-}\" != \"$1\" ]; do\n"
                 "  case \"$1\" in -b) b=1;; --) shift; break;; *) exit 2;; esac; shift\n"
                 "done\n"
                 "[ \"$b\" = 1 ] && [ \"$#\" = 1 ] || exit 2\n"
                 "echo \"$1\" >> '%s'\n",
                 loadlog);
        write_script("busybox-modprobe", body);

        snprintf(body,
                 sizeof(body),
                 "#!/bin/sh\n"
                 "b=0; while [ \"${1#-}\" != \"$1\" ]; do\n"
                 "  case \"$1\" in -b) b=1;; --) shift; break;; *) exit 2;; esac; shift\n"
                 "done\n"
                 "[ \"$#\" = 1 ] || exit 2\n"
                 "[ \"$b\" = 1 ] && [ \"$1\" = blacklisted ] && exit 0\n"
                 "echo \"$1\" >> '%s'\n",
                 loadlog);
        write_script("busybox-blacklist-modprobe", body);

        reset();
        set_cmdline("modules_load=blacklisted,plain\n");

        snprintf(path, sizeof(path), "%s/kmod-modprobe", root);
        ASSERT_EQ_INT(run_with(path, &n, &failed), 0);
        ASSERT_EQ_INT(n, 2);
        ASSERT_EQ_INT(failed, 0);
        ASSERT_STREQ(loaded(), "plain\n");

        (void) unlink(loadlog);
        snprintf(path, sizeof(path), "%s/busybox-modprobe", root);
        ASSERT_EQ_INT(run_with(path, &n, &failed), 0);
        ASSERT_EQ_INT(n, 2);
        ASSERT_EQ_INT(failed, 0);
        ASSERT_STREQ(loaded(), "blacklisted\nplain\n");

        (void) unlink(loadlog);
        snprintf(path, sizeof(path), "%s/busybox-blacklist-modprobe", root);
        ASSERT_EQ_INT(run_with(path, &n, &failed), 0);
        ASSERT_EQ_INT(n, 2);
        ASSERT_EQ_INT(failed, 0);
        ASSERT_STREQ(loaded(), "plain\n");
}

static void test_parse_denylist(void) {
        char **names = NULL;

        ASSERT_EQ_INT(pico_modules_load_parse_denylist(
                                      "quiet module_blacklist=a,b module-blacklist=c,,a "
                                      "xmodule_blacklist=z modules_load=y\n",
                                      &names),
                      0);
        ASSERT_EQ_INT(pico_strv_length(names), 3);
        ASSERT_STREQ(names[0], "a");
        ASSERT_STREQ(names[1], "b");
        ASSERT_STREQ(names[2], "c");
        pico_strv_free(names);
}

/*
 * The kernel refuses a module in module_blacklist=, so modprobe fails for it.
 * That is not counted; a failure for any other module still is.
 */
static void test_kernel_denylist(void) {
        char path[PATH_MAX];
        size_t n, failed;

        write_script("failing-modprobe", "#!/bin/sh\n[ \"$3\" = good ]\n");
        snprintf(path, sizeof(path), "%s/failing-modprobe", root);

        reset();
        set_cmdline("module_blacklist=bad,other-mod modules_load=bad,other_mod,good\n");
        ASSERT_EQ_INT(run_with(path, &n, &failed), 0);
        ASSERT_EQ_INT(n, 3);
        ASSERT_EQ_INT(failed, 0);

        reset();
        set_cmdline("module_blacklist=bad modules_load=bad,ugly,good\n");
        ASSERT_EQ_INT(run_with(path, &n, &failed), 0);
        ASSERT_EQ_INT(n, 3);
        ASSERT_EQ_INT(failed, 1);

        /* a module that loads is loaded, listed or not */
        reset();
        set_cmdline("module_blacklist=good modules_load=good\n");
        ASSERT_EQ_INT(run_with(path, &n, &failed), 0);
        ASSERT_EQ_INT(failed, 0);
}

static bool have_real_kmod(char *modprobe, size_t size) {
        static const char * const candidates[] = {
                "/sbin/modprobe", "/usr/sbin/modprobe", "/bin/modprobe", "/usr/bin/modprobe"
        };
        char cmd[PATH_MAX + 64];

        for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
                snprintf(cmd,
                         sizeof(cmd),
                         "%s --version 2>&1 | grep -q '^kmod version' >/dev/null 2>&1",
                         candidates[i]);
                if (access(candidates[i], X_OK) == 0 && system(cmd) == 0) {
                        snprintf(modprobe, size, "%s", candidates[i]);
                        return true;
                }
        }
        return false;
}

/*
 * The real kmod modprobe with --dry-run, against a fixture tree: modules
 * foo and bar (compiled .modinfo-only objects, which is all depmod needs),
 * "blacklist foo" in modprobe.d. With -b the blacklisted module is skipped
 * with exit 0, the other one is "inserted" (printed by -v), an alias of the
 * blacklisted module is skipped, and an unknown name fails. Returns false
 * when kmod, depmod or a C compiler is missing.
 */
static bool test_real_kmod(void) {
        char modprobe[PATH_MAX], kdir[PATH_MAX], cmd[PATH_MAX * 8], wrapper[PATH_MAX * 5];
        size_t n, failed;
        int status;

        if (!have_real_kmod(modprobe, sizeof(modprobe)))
                return false;

        snprintf(kdir, sizeof(kdir), "%s/kmod", root);
        ASSERT_EQ_INT(test_mkdir(root, "kmod"), 0);
        ASSERT_EQ_INT(test_write_file(kdir,
                                      "foo.c",
                                      "__attribute__((section(\".modinfo\"), used)) static const char m[] = "
                                      "\"license=GPL\\0alias=fooalias\\0\";\n"),
                      0);
        ASSERT_EQ_INT(test_write_file(kdir,
                                      "bar.c",
                                      "__attribute__((section(\".modinfo\"), used)) static const char m[] = "
                                      "\"license=GPL\\0alias=baralias\\0\";\n"),
                      0);
        snprintf(cmd,
                 sizeof(cmd),
                 "command -v depmod >/dev/null && command -v cc >/dev/null || exit 77; "
                 "cd '%s' && mkdir -p lib/modules/1.0/kernel etc/modprobe.d && "
                 "for m in foo bar; do cc -c -o lib/modules/1.0/kernel/$m.ko $m.c || exit 77; done && "
                 "depmod -b . 1.0 >/dev/null 2>&1 || exit 77; "
                 "echo 'blacklist foo' > etc/modprobe.d/bl.conf",
                 kdir);
        status = system(cmd);
        if (WIFEXITED(status) && WEXITSTATUS(status) == 77)
                return false;
        ASSERT_EQ_INT(status, 0);

        snprintf(wrapper,
                 sizeof(wrapper),
                 "#!/bin/sh\nexec '%s' -d '%s' -S 1.0 -C '%s/etc/modprobe.d' -n -v \"$@\" >> '%s'\n",
                 modprobe,
                 kdir,
                 kdir,
                 loadlog);
        write_script("real-modprobe", wrapper);
        snprintf(cmd, sizeof(cmd), "%s/real-modprobe", root);

        reset();
        snprintf(wrapper, sizeof(wrapper), "%.*s foo", (int) (sizeof(wrapper) - 8), cmd);
        ASSERT_EQ_INT(system(wrapper), 0);
        ASSERT_TRUE(strstr(loaded(), "/foo.ko") != NULL);

        reset();
        set_cmdline("modules_load=foo,bar,fooalias\n");
        ASSERT_EQ_INT(run_with(cmd, &n, &failed), 0);
        ASSERT_EQ_INT(n, 3);
        ASSERT_EQ_INT(failed, 0);
        ASSERT_TRUE(strstr(loaded(), "insmod ") != NULL);
        ASSERT_TRUE(strstr(loaded(), "/bar.ko") != NULL);
        ASSERT_TRUE(strstr(loaded(), "/foo.ko") == NULL);

        reset();
        set_cmdline("modules_load=nosuch\n");
        ASSERT_EQ_INT(run_with(cmd, &n, &failed), 0);
        ASSERT_EQ_INT(failed, 1);

        return true;
}

static void test_defaults(void) {
        ASSERT_STREQ(pico_modules_load_dirs[0], "/etc/modules-load.d");
        ASSERT_STREQ(pico_modules_load_dirs[1], "/run/modules-load.d");
        ASSERT_STREQ(pico_modules_load_dirs[2], "/usr/local/lib/modules-load.d");
        ASSERT_STREQ(pico_modules_load_dirs[3], "/usr/lib/modules-load.d");
        ASSERT_STREQ(pico_modules_load_dirs[4], "/lib/modules-load.d");
        ASSERT_TRUE(pico_modules_load_dirs[5] == NULL);
}

int main(void) {
        char cmd[PATH_MAX * 2];
        bool real_kmod_ran;

        root = test_tmpdir_new();
        ASSERT_TRUE(root != NULL);
        snprintf(dir_a, sizeof(dir_a), "%s/a", root);
        snprintf(dir_b, sizeof(dir_b), "%s/b", root);
        snprintf(dir_c, sizeof(dir_c), "%s/c", root);
        snprintf(stub, sizeof(stub), "%s/modprobe", root);
        snprintf(loadlog, sizeof(loadlog), "%s/loaded", root);
        snprintf(cmdline, sizeof(cmdline), "%s/cmdline", root);
        ASSERT_EQ_INT(test_mkdir(root, "a"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "b"), 0);
        ASSERT_EQ_INT(test_mkdir(root, "c"), 0);
        dirs[0] = dir_a;
        dirs[1] = dir_b;
        dirs[2] = dir_c;
        dirs[3] = NULL;

        snprintf(cmd,
                 sizeof(cmd),
                 "#!/bin/sh\n"
                 "[ \"$1\" = -b ] && [ \"$2\" = -- ] || exit 2\n"
                 "echo \"$3\" >> '%s'\n"
                 "[ \"$3\" != missing ]\n",
                 loadlog);
        ASSERT_EQ_INT(test_write_file(root, "modprobe", cmd), 0);
        ASSERT_EQ_INT(chmod(stub, 0755), 0);

        test_parse_file();
        test_parse_cmdline();
        test_precedence();
        test_edge_cases();
        test_comments_and_blanks();
        test_failure_continues();
        test_cmdline();
        test_skip();
        test_defaults();
        test_modprobe_flavours();
        test_parse_denylist();
        test_kernel_denylist();
        real_kmod_ran = test_real_kmod();

        test_rm_rf(root);
        free(root);
        if (!real_kmod_ran) {
                fprintf(stderr,
                        "test-modules-load: no kmod modprobe, depmod and cc, real modprobe case skipped\n");
                return 77;
        }
        printf("test-modules-load: OK\n");
        return 0;
}
