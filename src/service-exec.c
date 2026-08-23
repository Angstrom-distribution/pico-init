/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * fork/exec + fd/cgroup child-side setup, quarried from the child-process
 * portion of systemd's ~2011-era src/execute.c (tag v30, commit 501c92c,
 * copyright 2010 Lennart Poettering, GPL-2.0-or-later). Structural context:
 * 75689fb2d4 (2023-09-01) later split this child-side path out of
 * execute.c into exec-invoke.c, and b30e2f4c18 (2012-04-11) moved src/ to
 * src/core/ -- neither changes the actual ordering rules below, which have
 * been stable since 2011. systemd's later systemd-executor architecture
 * (bb5232b6a3) is deliberately NOT adopted: it solves a problem a ~3000-line
 * PID1 does not have. What IS kept is the constraint that motivated it: the
 * post-fork/pre-execve region is as close to async-signal-safe as this
 * project gets -- no malloc, no NSS, no dlopen, no allocating logger
 * (pico_log() uses vfprintf(), which is not async-signal-safe, so it is
 * never called after fork() below). Everything that can be computed in the
 * parent is computed there instead.
 *
 * Backports (commit hashes from github.com/systemd/systemd), each at the
 * step of child_exec() it applies to:
 *
 *  - 7e0e6b50b4 -- take a start timestamp before fork(), not after: not
 *    plumbed through to a Service field in this MVP (no field exists to
 *    hold it and nothing yet consumes it), but the ordering itself costs
 *    nothing, so service_spawn() still calls fork() as its very next
 *    statement rather than doing any parent-side setup in between.
 *  - 69339ae9f7 (CVE-2021-4034/PwnKit class) -- refuse to execve() with a
 *    NULL or empty argv[0]. Checked twice: once in the parent
 *    (service_spawn(), where a caller mistake never even forks) and once
 *    in the child (belt-and-braces, since a service.c bug could otherwise
 *    reach here directly).
 *  - ce30c8dcb4 -- reset every SIG_IGN'd signal to SIG_DFL. Both the
 *    process-wide signal mask (see signal.c) and a SIG_IGN disposition
 *    survive fork() *and* execve() -- only a *handled* signal is demoted to
 *    SIG_DFL by execve(). Skipping this step means every service starts
 *    with whatever pico-init itself happened to ignore, silently.
 *  - 353e12c2f4 -- (re-)ignore SIGPIPE after the reset above, matching
 *    systemd's own long-standing IgnoreSIGPIPE=yes default.
 *  - 4c253ed1ca -- sigprocmask(SIG_SETMASK, empty) after the signal-
 *    disposition reset: the signalfd block set in signal.c also survives
 *    fork()+execve(); without clearing it, every service starts with
 *    SIGTERM blocked and shutdown silently breaks.
 *  - 74129a1276 -- a failed fork() returns -errno, never a stale success
 *    value; the bug this fixes made the caller believe a child existed
 *    when fork() had actually failed.
 *  - 171ceb4a00 -- open the console O_RDWR, not O_RDONLY: a read-only fd
 *    dup'd onto stdout/stderr gives every write() a silent EBADF.
 *  - 43efbc3959 -- never vhangup()/reset/lock the console. Every unit here
 *    shares PICO_CONSOLE_PATH, which makes clearing it out from under a
 *    concurrent writer a real boot deadlock, not a hypothetical one.
 *  - 1fb0682e78 -- TIOCSCTTY only on an actual tty (isatty() == 1 first):
 *    Linux reuses ioctl numbers across subsystems, so issuing it on
 *    anything else can hit an unrelated driver.
 *
 * Deliberately not backported here: 78d17fa09/b5d742138 (UTF-8 argv
 * validation -- no specifier expansion exists in this MVP to need it) and
 * everything socket-activation/notify-protocol/PAM/SELinux-shaped, none of
 * which service.h has fields for.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "service.h"

/*
 * Reopens the unit's cgroup.procs by path rather than reusing any fd the
 * parent had open for it: everything this process inherited is closed in
 * the fd sweep before this runs (see child_exec() step 5), so there is
 * nothing to keep a list of in the first place. cg->path is a valid
 * copy-on-write pointer into the parent's heap; strings survive fork() even
 * though live fds do not.
 */
static void child_attach_cgroup(const struct pico_cgroup *cg) {
        char path[PATH_MAX];
        char buf[32];
        int fd, n;

        if (!cg || !cg->path)
                return;

        n = snprintf(path, sizeof(path), "%s/cgroup.procs", cg->path);
        if (n < 0 || (size_t) n >= sizeof(path))
                _exit(PICO_EXIT_CGROUP);

        fd = open(path, O_WRONLY | O_CLOEXEC);
        if (fd < 0)
                _exit(PICO_EXIT_CGROUP);

        n = snprintf(buf, sizeof(buf), "%d", (int) getpid());
        if (n < 0 || (size_t) n >= sizeof(buf) || write(fd, buf, (size_t) n) != n) {
                close(fd);
                _exit(PICO_EXIT_CGROUP);
        }

        close(fd);
}

/*
 * Everything from here down runs only in the forked child, between fork()
 * and execve(). No pico_log() (stdio is not async-signal-safe), no malloc,
 * no NSS, no dlopen: a failure has exactly one channel back to the parent,
 * _exit() with one of the codes in service.h, matching systemd.exec(5)
 * numerically. Never returns.
 */
static _Noreturn void child_exec(Service *s, char **argv) {
        sigset_t empty;
        int sig, fd;
        long max_fd;

        /* 1. 69339ae9f7: never execve() with a NULL/empty argv[0]. */
        if (!argv || !argv[0] || argv[0][0] == '\0')
                _exit(PICO_EXIT_EXEC);

        /* 2. ce30c8dcb4: SIG_IGN survives execve() (only *handled* signals
         * are demoted to SIG_DFL) -- reset every one back to SIG_DFL so a
         * service does not inherit whatever pico-init itself ignores. */
        for (sig = 1; sig <= 64; sig++) {
                struct sigaction old;

                if (sigaction(sig, NULL, &old) < 0)
                        continue; /* not a real signal number on this arch */

                if (old.sa_handler == SIG_IGN) {
                        struct sigaction dfl = { .sa_handler = SIG_DFL };
                        sigaction(sig, &dfl, NULL);
                }
        }

        /* 3. 353e12c2f4: systemd's own long-standing IgnoreSIGPIPE=yes default. */
        signal(SIGPIPE, SIG_IGN);

        /* 4. 4c253ed1ca: the signalfd block set in signal.c survives
         * fork()+execve() too -- clear it or the service starts with SIGTERM
         * (among others) blocked and shutdown silently breaks. */
        sigemptyset(&empty);
        if (sigprocmask(SIG_SETMASK, &empty, NULL) < 0)
                _exit(PICO_EXIT_SIGNAL_MASK);

        /* 5. Close everything this process inherited. No keep-list: the
         * cgroup control file (step 7) and the console (step 8) are both
         * reopened fresh by path below, so nothing needs to survive this. */
        max_fd = sysconf(_SC_OPEN_MAX);
        if (max_fd < 0)
                max_fd = 1024; /* sane fallback if the syscall itself fails */
        for (fd = 0; fd < (int) max_fd; fd++)
                close(fd); /* EBADF for an fd that was never open is expected */

        /* 6. Session leader with no controlling terminal -- the exact
         * precondition TIOCSCTTY checks for at step 9. Must come after the
         * fd sweep, before stdio is set up. */
        if (setsid() < 0)
                _exit(PICO_EXIT_SETSID);

        /* 7. Attach to the unit's cgroup, if service.c managed to set one up
         * (cgroup setup is best-effort there -- see service_ensure_cgroup()). */
        if (s->cgroup)
                child_attach_cgroup(s->cgroup);

        /*
         * 8. O_RDWR, not O_RDONLY (171ceb4a00): a read-only console dup'd
         * onto stdout/stderr gives every write() a silent EBADF. Never
         * vhangu()/reset/lock it (43efbc3959): every unit here shares this
         * same console, and clearing it out from under a concurrent writer
         * is a real boot deadlock in pico-init's design, not a hypothetical
         * one. stdout before stderr, matching the order every failure code
         * below reports.
         */
        fd = open(PICO_CONSOLE_PATH, O_RDWR | O_NOCTTY);
        if (fd < 0)
                _exit(PICO_EXIT_STDIN);
        if (dup2(fd, STDIN_FILENO) < 0)
                _exit(PICO_EXIT_STDIN);
        if (dup2(fd, STDOUT_FILENO) < 0)
                _exit(PICO_EXIT_STDOUT);
        if (dup2(fd, STDERR_FILENO) < 0)
                _exit(PICO_EXIT_STDERR);
        if (fd > STDERR_FILENO)
                close(fd);

        /*
         * 9. 1fb0682e78: TIOCSCTTY is a real ioctl on a real tty; issuing it
         * on anything else can hit an unrelated driver, because Linux
         * reuses ioctl numbers across subsystems. isatty() == 1 is the
         * guard; setsid() at step 6 is the other half of the precondition
         * (session leader, no controlling terminal yet). Not fatal on
         * failure -- there is simply no job control for this service, and
         * there is no async-signal-safe way to log that here, so it is
         * silently tolerated rather than reported.
         */
        if (isatty(STDIN_FILENO) == 1)
                ioctl(STDIN_FILENO, TIOCSCTTY, 0);

        /* 10. Does not return on success. Its failure is reported purely by
         * exit code -- there is no other channel back to the parent. Uses
         * the inherited `environ` rather than a constructed envp: pico-init
         * has no Environment= directive to honour in this MVP. */
        execv(argv[0], argv);
        _exit(PICO_EXIT_EXEC);
}

int service_spawn(Service *s, char **argv, pid_t *ret_pid) {
        pid_t pid;

        if (!s || !ret_pid)
                return -EINVAL;

        *ret_pid = 0;

        /* 69339ae9f7: catch the empty-argv case in the parent too, so a
         * caller mistake never even forks. */
        if (!argv || !argv[0] || argv[0][0] == '\0')
                return -ENOEXEC;

        pid = fork();
        if (pid < 0)
                return -errno; /* 74129a1276: never a stale success value */

        if (pid == 0)
                child_exec(s, argv); /* never returns */

        *ret_pid = pid;
        return 0;
}
