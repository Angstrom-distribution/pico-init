/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The RUN+= child. devd-run.h has why nothing here ever waits, and the two
 * things a fork/exec out of a signalfd daemon must undo before exec'ing.
 */

#include "devd-run.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../util.h"

void devd_run_init(DevdRun *r) {
        if (!r)
                return;

        memset(r, 0, sizeof(*r));
        (void) snprintf(r->helper_dir, sizeof(r->helper_dir), "%s", DEVD_RUN_HELPER_DIR);
}

int devd_run_set_helper_dir(DevdRun *r, const char *dir) {
        if (!r || !dir)
                return -EINVAL;

        if ((size_t) snprintf(r->helper_dir, sizeof(r->helper_dir), "%s", dir) >= sizeof(r->helper_dir))
                return -ENAMETOOLONG;

        return 0;
}

size_t devd_run_pending(const DevdRun *r) {
        return r ? r->n_children : 0;
}

int devd_run_split(const char *cmd, char argv[][DEVD_RUN_ARG_MAX], size_t max) {
        const char *p = cmd;
        size_t n = 0;

        if (!cmd || !argv || max == 0)
                return -EINVAL;

        while (*p) {
                char quote = '\0';
                size_t len = 0;

                while (*p == ' ' || *p == '\t')
                        p++;

                if (*p == '\0')
                        break;

                if (n >= max)
                        return -EINVAL;

                for (; *p; p++) {
                        if (quote != '\0') {
                                if (*p == quote) {
                                        quote = '\0';
                                        continue;
                                }
                        } else if (*p == '\'' || *p == '"') {
                                quote = *p;
                                continue;
                        } else if (*p == ' ' || *p == '\t')
                                break;

                        if (len + 1 >= DEVD_RUN_ARG_MAX)
                                return -EINVAL;

                        argv[n][len++] = *p;
                }

                if (quote != '\0')
                        return -EINVAL;

                argv[n][len] = '\0';
                n++;
        }

        return (int) n;
}

static void child_record(DevdRun *r, pid_t pid, const char *path) {
        const char *slash = strrchr(path, '/');
        const char *base = slash ? slash + 1 : path;
        DevdRunChild *c = &r->children[r->n_children++];
        size_t len = strlen(base);

        /* Clamped, not checked: this name is only ever printed on the exit
         * line, so a truncated one costs a vaguer log record and nothing else
         * -- unlike the paths d55275e had to make fail closed, which named a
         * different file when they truncated. Written as a memcpy rather than
         * an ignored snprintf() so -Wformat-truncation, which needs
         * optimisation to run and so never fires on an -O0 host gate, has
         * nothing to say about it. */
        if (len >= sizeof(c->name))
                len = sizeof(c->name) - 1;

        c->pid = pid;
        memcpy(c->name, base, len);
        c->name[len] = '\0';
}

int devd_run_spawn(DevdRun *r, const char *cmd, char * const *env) {
        static char * const empty_env[] = { NULL };

        char args[DEVD_RUN_ARGV_MAX][DEVD_RUN_ARG_MAX];
        char *argv[DEVD_RUN_ARGV_MAX + 1];
        char path[DEVD_RUN_PATH_MAX + DEVD_RUN_ARG_MAX + 2];
        sigset_t empty;
        pid_t pid;
        int n;

        if (!r || !cmd)
                return -EINVAL;

        n = devd_run_split(cmd, args, DEVD_RUN_ARGV_MAX);
        if (n < 0)
                return n;

        if (n == 0)
                return -EINVAL;

        /* Reap first: a table that is only full of already-exited children is
         * not full, and finding that out costs one non-blocking syscall. */
        if (r->n_children >= DEVD_RUN_CHILDREN_MAX)
                (void) devd_run_reap(r);

        if (r->n_children >= DEVD_RUN_CHILDREN_MAX) {
                pico_log(PICO_LOG_WARNING,
                         "devd: %d RUN+= children already running, not starting %s",
                         DEVD_RUN_CHILDREN_MAX,
                         args[0]);
                return -EAGAIN;
        }

        /* udev's own rule: a program named without a leading slash lives in the
         * helper directory, which is where this image's usb_modeswitch
         * dispatcher really is. */
        if (args[0][0] == '/')
                (void) snprintf(path, sizeof(path), "%s", args[0]);
        else
                (void) snprintf(path, sizeof(path), "%s/%s", r->helper_dir, args[0]);

        for (int i = 0; i < n; i++)
                argv[i] = args[i];

        argv[n] = NULL;

        pid = fork();
        if (pid < 0)
                return -errno;

        if (pid == 0) {
                int fd;

                /* See devd-run.h: execve preserves the signal mask, and this
                 * daemon's mask has SIGTERM in it. */
                sigemptyset(&empty);
                (void) sigprocmask(SIG_SETMASK, &empty, NULL);

                fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
                if (fd >= 0) {
                        (void) dup2(fd, STDIN_FILENO);
                        (void) close(fd);
                }

                (void) execve(path, argv, env ? env : empty_env);

                /* Deliberately not pico_log(): the sink may be /dev/kmsg, and
                 * this is a failed exec in a forked child, not the daemon. 127
                 * is the shell's own "not found", which is what the parent's
                 * exit line will report. */
                _exit(127);
        }

        child_record(r, pid, path);
        r->n_started++;

        pico_log(PICO_LOG_DEBUG, "devd: started %s as pid %d", path, (int) pid);
        return (int) pid;
}

int devd_run_reap(DevdRun *r) {
        int reaped = 0;

        if (!r)
                return 0;

        for (;;) {
                char name[DEVD_RUN_NAME_MAX];
                int status;
                pid_t pid;
                size_t i;

                pid = waitpid(-1, &status, WNOHANG);
                if (pid <= 0)
                        break;

                (void) snprintf(name, sizeof(name), "%s", "a child");

                for (i = 0; i < r->n_children; i++)
                        if (r->children[i].pid == pid) {
                                (void) snprintf(name, sizeof(name), "%s", r->children[i].name);
                                memmove(&r->children[i],
                                        &r->children[i + 1],
                                        (r->n_children - i - 1) * sizeof(r->children[0]));
                                r->n_children--;
                                break;
                        }

                r->n_reaped++;
                reaped++;

                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                        pico_log(PICO_LOG_DEBUG, "devd: %s (pid %d) finished", name, (int) pid);
                        continue;
                }

                r->n_failed++;

                if (WIFSIGNALED(status))
                        pico_log(PICO_LOG_WARNING,
                                 "devd: %s (pid %d) killed by signal %d",
                                 name,
                                 (int) pid,
                                 WTERMSIG(status));
                else
                        pico_log(PICO_LOG_WARNING,
                                 "devd: %s (pid %d) exited with %d",
                                 name,
                                 (int) pid,
                                 WIFEXITED(status) ? WEXITSTATUS(status) : -1);
        }

        return reaped;
}
