/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "modules-load.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../dropin-files.h"
#include "../util.h"

/* A module name is far shorter; longer lines are discarded as they are read. */
#define MODULES_LOAD_LINE_MAX 4096

char * const pico_modules_load_dirs[] = {
        "/etc/modules-load.d",     "/run/modules-load.d", "/usr/local/lib/modules-load.d",
        "/usr/lib/modules-load.d", "/lib/modules-load.d", NULL,
};

/* The kernel treats '-' and '_' in a module name alike. */
static bool same_module(const char *a, const char *b) {
        for (; *a && *b; a++, b++) {
                char x = *a == '-' ? '_' : *a, y = *b == '-' ? '_' : *b;

                if (x != y)
                        return false;
        }
        return *a == *b;
}

static bool names_has(char * const *names, const char *name) {
        for (; names && *names; names++)
                if (same_module(*names, name))
                        return true;
        return false;
}

/* Distinct modules only: one named twice, in either spelling, is asked for once. */
static int names_add(char ***names, const char *name) {
        if (names_has(*names, name))
                return 0;
        return pico_strv_extend(names, name);
}

static char *strip(char *s) {
        char *e;

        while (isspace((unsigned char) *s))
                s++;
        e = s + strlen(s);
        while (e > s && isspace((unsigned char) e[-1]))
                *--e = '\0';
        return s;
}

int pico_modules_load_parse_file(const char *path, char ***names) {
        char line[MODULES_LOAD_LINE_MAX + 1];
        struct stat st;
        FILE *f;
        int fd, r = 0;

        if (!path || !names)
                return -EINVAL;

        /* O_NONBLOCK so a FIFO cannot hold the boot; it is never read. */
        fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
                return -errno;
        if (fstat(fd, &st) < 0) {
                r = -errno;
                (void) close(fd);
                return r;
        }
        /* A link to /dev/null is how a file is masked: it names nothing. */
        if (!S_ISREG(st.st_mode)) {
                (void) close(fd);
                if (S_ISCHR(st.st_mode))
                        return 0;
                pico_log(PICO_LOG_WARNING, "modules-load: %s: not a regular file, skipped", path);
                return 0;
        }
        f = fdopen(fd, "r");
        if (!f) {
                r = -errno;
                (void) close(fd);
                return r;
        }

        for (;;) {
                char *s;
                size_t n;

                if (!fgets(line, sizeof(line), f))
                        break;
                n = strlen(line);
                if (n == MODULES_LOAD_LINE_MAX && line[n - 1] != '\n') {
                        int c;

                        while ((c = getc(f)) != EOF && c != '\n')
                                ;
                        pico_log(PICO_LOG_WARNING, "modules-load: %s: line too long, skipped", path);
                        continue;
                }

                s = strip(line);
                if (*s == '\0' || *s == '#' || *s == ';')
                        continue;

                r = names_add(names, s);
                if (r < 0)
                        break;
        }

        if (r == 0 && ferror(f))
                r = -EIO;
        (void) fclose(f);
        return r;
}

/* The value of a "key=value" word whose key is one of keys[], or NULL. The
 * kernel treats '-' and '_' in a parameter name alike, so the keys are listed
 * in both spellings. */
static const char *word_value(const char *word, const char * const *keys) {
        for (; *keys; keys++) {
                size_t len = strlen(*keys);

                if (strncmp(word, *keys, len) == 0)
                        return word + len;
        }
        return NULL;
}

/* Every comma-separated item of every word whose key is in keys[], appended to *names. */
static int cmdline_list(const char *line, const char * const *keys, char ***names) {
        const char *state = line;
        int r = 0;

        if (!line || !names)
                return -EINVAL;

        for (;;) {
                char *word = NULL, *list, *tok;
                const char *value;

                r = pico_extract_first_word(&state, &word);
                if (r == -EINVAL) {
                        /* An unterminated quote loses the rest of the line only. */
                        r = 0;
                        break;
                }
                if (r <= 0)
                        break;

                value = word_value(word, keys);
                if (value) {
                        list = (char *) value;
                        while ((tok = strsep(&list, ","))) {
                                tok = strip(tok);
                                if (*tok == '\0')
                                        continue;
                                r = names_add(names, tok);
                                if (r < 0)
                                        break;
                        }
                }
                free(word);
                if (r < 0)
                        return r;
        }

        return r < 0 ? r : 0;
}

int pico_modules_load_parse_cmdline(const char *line, char ***names) {
        static const char * const keys[] = {
                "modules_load=", "modules-load=", "rd.modules_load=", "rd.modules-load=", NULL,
        };

        return cmdline_list(line, keys, names);
}

int pico_modules_load_parse_denylist(const char *line, char ***names) {
        static const char * const keys[] = { "module_blacklist=", "module-blacklist=", NULL };

        return cmdline_list(line, keys, names);
}

/* The command line file's text, newlines as spaces, in *text (owned, "" when
 * the file does not exist). 0 or -errno. */
static int read_cmdline(const char *path, char **text) {
        char *buf = NULL;
        size_t cap = 0;
        ssize_t n;
        int r;
        FILE *f = fopen(path, "re");

        *text = NULL;
        if (!f)
                return errno == ENOENT ? 0 : -errno;

        /* To the end, whatever the length; a cut-off last word would name a wrong module. */
        n = getdelim(&buf, &cap, '\0', f);
        r = ferror(f) ? -EIO : 0;
        (void) fclose(f);
        if (n < 0 || r < 0) {
                free(buf);
                return r;
        }
        for (char *p = buf; *p; p++)
                if (*p == '\n')
                        *p = ' ';

        *text = buf;
        return 0;
}

/* 0 when modprobe loaded it, otherwise what to say about why not. */
static int run_modprobe(const char *modprobe, const char *name, char *why, size_t why_size) {
        /* Built before the fork: nothing in the child allocates. */
        char * const argv[] = { (char *) modprobe, (char *) "-b", (char *) "--", (char *) name, NULL };
        int status;
        pid_t pid = fork();

        if (pid < 0) {
                snprintf(why, why_size, "fork: %s", strerror(errno));
                return -1;
        }
        if (pid == 0) {
                execv(modprobe, argv);
                _exit(127);
        }

        while (waitpid(pid, &status, 0) < 0) {
                if (errno == EINTR)
                        continue;
                snprintf(why, why_size, "waitpid: %s", strerror(errno));
                return -1;
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
                return 0;
        if (WIFEXITED(status))
                snprintf(why,
                         why_size,
                         WEXITSTATUS(status) == 127 ? "cannot run %s" : "%s exited with status %d",
                         modprobe,
                         WEXITSTATUS(status));
        else
                snprintf(why, why_size, "%s killed by signal %d", modprobe, WTERMSIG(status));
        return -1;
}

int pico_modules_load_run(const PicoModulesLoad *c, size_t *n_modules, size_t *n_failed) {
        char **files = NULL, **names = NULL, **denied = NULL;
        char *text = NULL;
        size_t failed = 0;
        int r;

        if (n_modules)
                *n_modules = 0;
        if (n_failed)
                *n_failed = 0;
        if (!c || !c->dirs || !c->modprobe)
                return -EINVAL;

        r = pico_dropin_files(c->dirs, &files);
        if (r < 0)
                return r;

        /* The command line first, as systemd-modules-load does. */
        if (c->cmdline) {
                r = read_cmdline(c->cmdline, &text);
                if (r == 0 && text)
                        r = pico_modules_load_parse_cmdline(text, &names);
                if (r == 0 && text)
                        r = pico_modules_load_parse_denylist(text, &denied);
                if (r < 0)
                        goto out;
        }

        for (char **f = files; f && *f; f++) {
                r = pico_modules_load_parse_file(*f, &names);
                if (r == -ENOMEM)
                        goto out;
                if (r < 0)
                        pico_log(PICO_LOG_WARNING, "modules-load: cannot read %s: %s", *f, strerror(-r));
        }

        for (char **n = names; n && *n; n++) {
                char why[160];

                if (run_modprobe(c->modprobe, *n, why, sizeof(why)) == 0)
                        continue;
                /*
                 * The kernel refuses a module named in module_blacklist= and
                 * modprobe reports that like any failure; systemd tells the
                 * two apart by errno and counts it as deny-listed.
                 */
                if (names_has(denied, *n)) {
                        pico_log(PICO_LOG_INFO,
                                 "modules-load: '%s' is deny-listed by the kernel command line",
                                 *n);
                        continue;
                }
                pico_log(PICO_LOG_WARNING, "modules-load: failed to load '%s': %s", *n, why);
                failed++;
        }

        if (n_modules)
                *n_modules = pico_strv_length(names);
        if (n_failed)
                *n_failed = failed;
        r = 0;
out:
        free(text);
        pico_strv_free(files);
        pico_strv_free(names);
        pico_strv_free(denied);
        return r;
}
