/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "condition.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "util.h"

/* A kernel command line is a few KiB at most; a longer one is cut. */
#define CONDITION_CMDLINE_MAX 16384

const char *pico_condition_cmdline_path = "/proc/cmdline";

static const char * const condition_names[_CONDITION_TYPE_MAX] = {
        [CONDITION_PATH_EXISTS] = "ConditionPathExists",
        [CONDITION_PATH_IS_DIRECTORY] = "ConditionPathIsDirectory",
        [CONDITION_DIRECTORY_NOT_EMPTY] = "ConditionDirectoryNotEmpty",
        [CONDITION_KERNEL_COMMAND_LINE] = "ConditionKernelCommandLine",
};

const char *condition_type_to_string(ConditionType t) {
        return t >= 0 && t < _CONDITION_TYPE_MAX ? condition_names[t] : NULL;
}

ConditionType condition_type_from_string(const char *name) {
        if (!name)
                return _CONDITION_TYPE_INVALID;

        for (ConditionType t = 0; t < _CONDITION_TYPE_MAX; t++)
                if (strcmp(condition_names[t], name) == 0)
                        return t;
        return _CONDITION_TYPE_INVALID;
}

bool condition_type_is_path(ConditionType t) {
        return t != CONDITION_KERNEL_COMMAND_LINE;
}

int condition_add(Condition **list, size_t *n, ConditionType type, const char *parameter, bool trigger, bool negate) {
        Condition *l;
        char *p;

        if (!list || !n || !parameter || type < 0 || type >= _CONDITION_TYPE_MAX)
                return -EINVAL;

        p = pico_strdup(parameter);
        if (!p)
                return -ENOMEM;

        l = realloc(*list, (*n + 1) * sizeof(Condition));
        if (!l) {
                free(p);
                return -ENOMEM;
        }

        l[*n] = (Condition){ .type = type, .parameter = p, .negate = negate, .trigger = trigger };
        *list = l;
        (*n)++;
        return 0;
}

Condition *condition_free_list(Condition *list, size_t n) {
        for (size_t i = 0; list && i < n; i++)
                free(list[i].parameter);
        free(list);
        return NULL;
}

bool condition_cmdline_has(const char *cmdline, const char *parameter) {
        const char *state = cmdline;
        bool equal;
        size_t len;

        if (!cmdline || !parameter || parameter[0] == '\0')
                return false;

        equal = strchr(parameter, '=') != NULL;
        len = strlen(parameter);

        for (;;) {
                char *word = NULL;
                bool found;
                int r;

                r = pico_extract_first_word(&state, &word);
                if (r <= 0)
                        return false;

                found = equal ? strcmp(word, parameter) == 0 :
                                strncmp(word, parameter, len) == 0 && (word[len] == '\0' || word[len] == '=');
                free(word);
                if (found)
                        return true;
        }
}

/* The cmdline file's text, owned, with every white space byte a plain space.
 * A file that is missing or unreadable is an empty command line. */
static char *read_cmdline(void) {
        char *buf = malloc(CONDITION_CMDLINE_MAX + 1);
        size_t len = 0;
        int fd;

        if (!buf)
                return NULL;

        /* O_NONBLOCK so a FIFO in a test fixture cannot hold the start job. */
        fd = open(pico_condition_cmdline_path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd >= 0) {
                while (len < CONDITION_CMDLINE_MAX) {
                        ssize_t n = read(fd, buf + len, CONDITION_CMDLINE_MAX - len);

                        if (n < 0 && errno == EINTR)
                                continue;
                        if (n <= 0)
                                break;
                        len += (size_t) n;
                }
                (void) close(fd);
        }
        buf[len] = '\0';

        for (size_t i = 0; i < len; i++)
                if (buf[i] == '\n' || buf[i] == '\r' || buf[i] == '\v' || buf[i] == '\f')
                        buf[i] = ' ';
        return buf;
}

/* systemd's hidden_or_backup_file() (src/basic/path-util.c). */
static bool hidden_or_backup_file(const char *name) {
        static const char * const suffixes[] = {
                "ignore",   "rpmnew",    "rpmsave",  "rpmorig",     "dpkg-old",    "dpkg-new",
                "dpkg-tmp", "dpkg-dist", "dpkg-bak", "dpkg-backup", "dpkg-remove", "ucf-new",
                "ucf-old",  "ucf-dist",  "swp",      "bak",         "old",         "new",
        };
        const char *dot;
        size_t len = strlen(name);

        if (name[0] == '.' || strcmp(name, "lost+found") == 0 || strcmp(name, "aquota.user") == 0 ||
            strcmp(name, "aquota.group") == 0 || (len > 0 && name[len - 1] == '~'))
                return true;

        dot = strrchr(name, '.');
        if (!dot)
                return false;

        for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); i++)
                if (strcmp(dot + 1, suffixes[i]) == 0)
                        return true;
        return false;
}

bool condition_directory_not_empty(const char *path) {
        struct dirent *de;
        bool not_empty = false;
        DIR *d;
        int fd;

        if (!path)
                return false;

        fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0)
                return errno != ENOENT && errno != ENOTDIR;

        d = fdopendir(fd);
        if (!d) {
                (void) close(fd);
                return true;
        }

        errno = 0;
        while ((de = readdir(d))) {
                if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
                        continue;
                if (!hidden_or_backup_file(de->d_name)) {
                        not_empty = true;
                        break;
                }
        }
        /* A read error is "cannot tell", which systemd counts as not empty. */
        if (!de && errno != 0)
                not_empty = true;

        (void) closedir(d);
        return not_empty;
}

bool condition_test(const Condition *c) {
        struct stat st;
        bool r = false;

        if (!c || !c->parameter)
                return false;

        switch (c->type) {
        case CONDITION_PATH_EXISTS:
                r = stat(c->parameter, &st) == 0;
                break;
        case CONDITION_PATH_IS_DIRECTORY:
                r = stat(c->parameter, &st) == 0 && S_ISDIR(st.st_mode);
                break;
        case CONDITION_DIRECTORY_NOT_EMPTY:
                r = condition_directory_not_empty(c->parameter);
                break;
        case CONDITION_KERNEL_COMMAND_LINE: {
                char *line = read_cmdline();

                r = line && condition_cmdline_has(line, c->parameter);
                free(line);
                break;
        }
        case _CONDITION_TYPE_MAX:
        case _CONDITION_TYPE_INVALID:
                break;
        }

        return r != c->negate;
}

bool condition_test_list(const Condition *list, size_t n, const Condition **failed) {
        bool has_trigger = false, trigger_ok = false;

        if (failed)
                *failed = NULL;

        for (size_t i = 0; list && i < n; i++) {
                bool r = condition_test(&list[i]);

                if (list[i].trigger) {
                        has_trigger = true;
                        trigger_ok = trigger_ok || r;
                } else if (!r) {
                        if (failed)
                                *failed = &list[i];
                        return false;
                }
        }

        if (has_trigger && !trigger_ok) {
                if (failed)
                        for (size_t i = 0; i < n; i++)
                                if (list[i].trigger) {
                                        *failed = &list[i];
                                        break;
                                }
                return false;
        }
        return true;
}
