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
 * everything notify-protocol/PAM/SELinux-shaped, none of which service.h has
 * fields for.
 *
 * Socket activation (plan §1.6, S1) landed on top of the above rather than
 * beside it, because it touches the exact region the constraint above is
 * about -- LISTEN_PID has to be the CHILD's own pid, so it is the one
 * variable-length string this file ever builds after fork(), and it is
 * built the only async-signal-safe way available: snprintf() into automatic
 * (stack) storage, no malloc. Everything else -- fd collection
 * (socket_collect_fds()), the LISTEN_FDS=<n> string, and the envp array
 * itself -- is built in the PARENT, before fork(), same as argv always was.
 * shift_fds()/flags_fds() below are v30's own execute.c:63-101, ported
 * verbatim (the algorithm, not just the citation: F_DUPFD's "lowest free fd
 * >= target" guarantee is what makes the restart-from-collision loop in
 * shift_fds() converge, and reimplementing it differently would be the kind
 * of edit this file's own opening paragraph warns against). This is also
 * why `execv()` becomes `execve()` here: passing fds by inherited-and-
 * renumbered file descriptor plus an explicit envp is the entire
 * LISTEN_FDS/LISTEN_PID protocol, and there is no third way to hand a
 * pre-opened listening socket to a process that has not yet called exec.
 *
 * One more thing found and fixed while landing S1, not from the quarry:
 * step 5's fd sweep was a `close()` per fd number up to
 * sysconf(_SC_OPEN_MAX). That is fine at a traditional RLIMIT_NOFILE
 * (1024-4096), but a good few modern distros default it far higher --
 * measured at 1,048,576 in this project's own Ubuntu 24.04 container image
 * -- which turns EVERY service start (not just a socket-activated one) into
 * that many close() syscalls, several real seconds each, discovered because
 * it made this milestone's own multi-cycle S2 tests impractically slow, not
 * from inspection. close_all_except() below uses close_range() (Linux 5.9+,
 * glibc >= 2.34, so no new floor beyond what this project already assumes)
 * to close whole gaps between kept fds in one syscall each, falling back to
 * the original per-fd loop if close_range() itself is unavailable at
 * runtime (an older kernel/glibc pairing) -- same fd set closed either way,
 * just not one syscall per number. The insertion sort it needs first is
 * hand-rolled rather than qsort(3): glibc's qsort can malloc a scratch
 * buffer for large-enough inputs, which this async-signal-safe region must
 * never do; n is at most PICO_MAX_SOCKET_FDS, where O(n^2) costs nothing.
 *
 * logd stdout/stderr capture (plan §3.2/§3.6, milestone J2) landed on top
 * of the above the same way S1 did: new pico-original code (not a
 * backport -- upstream's own equivalent, exec-invoke.c's SOCK_STREAM
 * handshake plus fd-store, is deliberately not adopted; see logd-write.h's
 * header for why) sharing the exact fork/exec region the file's opening
 * paragraph constrains. create_stdout_socket() runs in the PARENT, before
 * fork(): it creates a datagram socket, binds it to a unique Linux
 * abstract-namespace name (never a filesystem path -- no cleanup needed,
 * cannot collide with a real file), then connect()s it to logd's stdout
 * socket. Binding before connecting is the load-bearing step, not
 * decoration: the child cannot rebind an already-bound AF_UNIX socket (a
 * second bind() returns EINVAL), so every datagram this socket -- and
 * everything the child forks that inherits fd 1/2 from it -- ever sends
 * reports that SAME source address to logd's recvfrom(), which is the
 * whole basis logd-recv.h's corrected design rests on: fragment tails
 * keyed by stream identity, not by PID, immune to PID reuse and correct
 * for a service that spans several PIDs on one stream. child_exec() then
 * dup2()s it over stdout AND stderr in the exact slot the console fd used
 * to go alone -- stdin is unaffected, still the console always. Any
 * failure anywhere in this chain (socket()/bind()/connect() all
 * best-effort, logd not installed, its socket not present yet, whatever)
 * yields stdout_fd == -1 and child_exec() falls straight back to the
 * console path unmodified: degradation, never a spawn failure, so an
 * image without logd behaves exactly as one that never shipped this
 * feature would.
 */

/* close_range() is a glibc >= 2.34 wrapper; -std=gnu17 alone does not imply
 * _GNU_SOURCE (same reasoning as socket.c's own note), and this has to be
 * defined before any header is pulled in for it to take effect at all. */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "service.h"
#include "socket.h"

/* Declared explicitly rather than relying on <unistd.h> to have pulled it
 * in under whatever feature-test macros happen to be active -- environ is
 * used exactly once below, to build a service's inherited-plus-LISTEN_FDS
 * envp. */
extern char **environ;

/* A generous, fixed bound on how many fds one paired socket unit (or several
 * pairing to the same service) can hand to a single service start. No
 * pico-init consumer needs more than a handful; a fixed stack array here
 * keeps fd collection entirely allocation-free in the parent too. */
#define PICO_MAX_SOCKET_FDS 16

/*
 * Renumber every fd in `fds` to a contiguous run starting at 3, in place --
 * v30's execute.c:63-101, ported verbatim. F_DUPFD(fd, i+3) always returns
 * the LOWEST free descriptor >= i+3, so when that target is already occupied
 * by one of our OWN not-yet-processed fds, the dup lands somewhere higher
 * instead; `restart_from` remembers the earliest index that happened to and
 * the outer loop retries from there once the rest of the pass has freed up
 * more of the low numbers. Converges because each retry pass strictly
 * shrinks the set of fds not yet at their target. Async-signal-safe:
 * fcntl()/close() only, no malloc. 0 or -errno.
 */

/* Hand-rolled ascending insertion sort -- see this file's header for why
 * qsort(3) is not used here. `n` is at most PICO_MAX_SOCKET_FDS + 1 (the
 * socket-activation set plus the logd stdout socket, J2). */
static void sort_fds_ascending(int *a, unsigned n) {
        unsigned i, j;

        for (i = 1; i < n; i++) {
                int v = a[i];

                j = i;
                while (j > 0 && a[j - 1] > v) {
                        a[j] = a[j - 1];
                        j--;
                }
                a[j] = v;
        }
}

/*
 * Closes every fd in [0, max_fd) except those in `keep` -- one close_range()
 * syscall per gap between kept fds, rather than one close() per fd number.
 * See this file's header for why: at a traditional RLIMIT_NOFILE this
 * hardly matters, but several modern distros default it into the six
 * figures, turning the naive loop into that many syscalls on every single
 * service start. Falls back to the original per-fd loop, from wherever
 * close_range() itself first failed, if the kernel does not have it
 * (pre-5.9) -- same fds end up closed either way. Async-signal-safe:
 * close_range()/close() only, plus the insertion sort above (no malloc).
 * `keep` may hold up to PICO_MAX_SOCKET_FDS + 1 entries -- the socket-
 * activation set plus the logd stdout socket (J2); anything beyond that
 * is silently clamped rather than overflowing `sorted` below, which
 * cannot happen in practice since every caller already bounds n_keep
 * itself, but the clamp is the honest contract regardless. */
static void close_all_except(const int *keep, unsigned n_keep, long max_fd) {
        int sorted[PICO_MAX_SOCKET_FDS + 1];
        unsigned i, n, next;
        bool use_close_range = true;

        n = n_keep < PICO_MAX_SOCKET_FDS + 1 ? n_keep : PICO_MAX_SOCKET_FDS + 1;
        for (i = 0; i < n; i++)
                sorted[i] = keep[i];
        sort_fds_ascending(sorted, n);

        next = 0;
        for (i = 0; i < n; i++) {
                unsigned target = (unsigned) sorted[i];

                if (target < next)
                        continue; /* duplicate entry, already covered */

                if (use_close_range && target > next && close_range(next, target - 1, 0) < 0)
                        use_close_range = false;

                if (!use_close_range)
                        for (; next < target; next++)
                                close((int) next);

                next = target + 1;
        }

        if (use_close_range && close_range(next, UINT_MAX, 0) < 0)
                use_close_range = false;

        if (!use_close_range)
                for (; (long) next < max_fd; next++)
                        close((int) next);
}

static int shift_fds(int *fds, unsigned n_fds) {
        int start, restart_from;

        if (n_fds == 0)
                return 0;

        start = 0;
        for (;;) {
                int i;

                restart_from = -1;

                for (i = start; i < (int) n_fds; i++) {
                        int nfd;

                        if (fds[i] == i + 3)
                                continue;

                        nfd = fcntl(fds[i], F_DUPFD, i + 3);
                        if (nfd < 0)
                                return -errno;

                        close(fds[i]);
                        fds[i] = nfd;

                        if (nfd != i + 3 && restart_from < 0)
                                restart_from = i;
                }

                if (restart_from < 0)
                        break;

                start = restart_from;
        }

        return 0;
}

/*
 * Clears O_NONBLOCK and FD_CLOEXEC on every renumbered fd. O_NONBLOCK:
 * socket_open_fds() opens every listening socket SOCK_NONBLOCK for PID 1's
 * own epoll loop, but sd_listen_fds()'s documented default hands a consumer
 * a BLOCKING fd unless it asks otherwise (no NonBlocking= directive exists
 * in this MVP to override that). FD_CLOEXEC: opened SOCK_CLOEXEC for the
 * same PID-1-hygiene reason execute.c:63-101's own fd sweep exists at all --
 * cleared here because this is the one fd this exact execve() must keep.
 * Async-signal-safe: fcntl() only. 0 or -errno.
 */
static int flags_fds(const int *fds, unsigned n_fds) {
        unsigned i;

        for (i = 0; i < n_fds; i++) {
                int fl;

                fl = fcntl(fds[i], F_GETFL, 0);
                if (fl < 0)
                        return -errno;
                if ((fl & O_NONBLOCK) && fcntl(fds[i], F_SETFL, fl & ~O_NONBLOCK) < 0)
                        return -errno;

                fl = fcntl(fds[i], F_GETFD, 0);
                if (fl < 0)
                        return -errno;
                if ((fl & FD_CLOEXEC) && fcntl(fds[i], F_SETFD, fl & ~FD_CLOEXEC) < 0)
                        return -errno;
        }

        return 0;
}

/*
 * Builds the child's envp: environ's own pointers (borrowed -- those strings
 * outlive both fork() and this process's own execve(), so copying the
 * pointer array is enough, minus any inherited LISTEN_* entry, see the scrub
 * below) plus "LISTEN_FDS=<n>", plus one reserved trailing
 * slot child_exec() fills in with LISTEN_PID after fork(). *ret_pid_slot is
 * that slot's index. Called only in the parent, before fork() -- malloc here
 * is fine, this is exactly the "everything that can be computed in the
 * parent is computed there instead" this file's header promises. NULL on
 * OOM.
 */
static bool is_listen_var(const char *e) {
        static const char *const names[] = {
                "LISTEN_FDS=",
                "LISTEN_PID=",
                "LISTEN_FDNAMES=",
        };
        size_t i;

        for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
                if (strncmp(e, names[i], strlen(names[i])) == 0)
                        return true;

        return false;
}

static char **build_socket_envp(unsigned n_fds, size_t *ret_pid_slot) {
        size_t n = 0, i, kept = 0;
        char **envp;
        char buf[32];
        int r;

        while (environ[n])
                n++;

        /* +1 LISTEN_FDS, +1 reserved LISTEN_PID slot, +1 NUL terminator */
        envp = calloc(n + 3, sizeof(char *));
        if (!envp)
                return NULL;

        /*
         * Drop any INHERITED LISTEN_* entry while copying (upstream scrubs
         * the same three names for the same reason). PID 1's own environment
         * really can contain one: the kernel hands init every unrecognised
         * name=value boot-cmdline parameter as an environment variable, so a
         * stray LISTEN_FDS=1 on the command line lands here. Left in place it
         * would be the entry getenv() in the child returns (getenv() takes
         * the FIRST match, and the real value is appended after), and the
         * entry free_socket_envp() later frees -- a pointer into the initial
         * stack's env block, never malloc()'d. After this loop each name
         * appears exactly once: the one built below.
         */
        for (i = 0; i < n; i++) {
                if (is_listen_var(environ[i]))
                        continue;

                envp[kept++] = environ[i];
        }
        n = kept;

        r = snprintf(buf, sizeof(buf), "LISTEN_FDS=%u", n_fds);
        if (r < 0 || (size_t) r >= sizeof(buf)) {
                free(envp);
                return NULL;
        }

        envp[n] = pico_strdup(buf);
        if (!envp[n]) {
                free(envp);
                return NULL;
        }

        *ret_pid_slot = n + 1;
        envp[n + 1] = NULL; /* filled by the child, post-fork -- see child_exec() */
        envp[n + 2] = NULL; /* terminator */

        return envp;
}

/* Frees only what build_socket_envp() itself allocated: the LISTEN_FDS
 * string and the array. Every other slot is either borrowed from environ or
 * (the reserved one) never written by the parent at all. Safe to call from
 * the parent right after fork() returns -- the child already has its own
 * COW copy of this same memory, so freeing the parent's does not touch it. */
static void free_socket_envp(char **envp) {
        size_t i;

        if (!envp)
                return;

        for (i = 0; envp[i]; i++)
                if (strncmp(envp[i], "LISTEN_FDS=", strlen("LISTEN_FDS=")) == 0) {
                        free(envp[i]);
                        break;
                }

        free(envp);
}

/*
 * PID 1's own hardcoded knowledge of where logd listens for captured
 * stdout/stderr -- deliberately duplicated from logd.h's
 * LOGD_STDOUT_SOCKET_PATH rather than #include-d, so pico-init-core never
 * gains a build-time dependency on logd's own headers or library (plan
 * §3.2's whole point: logd runs completely independently of PID 1). Both
 * sides agree on this one path by convention; nothing else couples them.
 */
#define PICO_LOGD_STDOUT_SOCKET_PATH "/run/logd/stdout"

/*
 * See this file's header for the full design. Best-effort throughout:
 * returns -1 (never fatal to the spawn) on any failure. `unit_id` is used
 * only to make the bound name legible in a socket listing for debugging --
 * logd itself never parses it, only compares the raw address bytes for
 * equality (logd-recv.h) -- so truncating a long one costs nothing real.
 */
static int create_stdout_socket(const char *unit_id) {
        static unsigned invocation_counter = 0;
        struct sockaddr_un addr, target;
        size_t target_len;
        int fd, n, sndbuf;

        fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -1;

        /* Abstract namespace: sun_path[0] == '\0', unique per invocation via
         * the counter -- unbind()/unlink() concerns simply do not apply. */
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        n = snprintf(addr.sun_path + 1,
                     sizeof(addr.sun_path) - 1,
                     "pico-init-stdout/%.48s/%u",
                     unit_id ? unit_id : "?",
                     invocation_counter++);
        if (n < 0) {
                close(fd);
                return -1;
        }
        if ((size_t) n >= sizeof(addr.sun_path) - 1)
                n = (int) sizeof(addr.sun_path) - 2;

        if (bind(fd,
                 (struct sockaddr *) &addr,
                 (socklen_t) (offsetof(struct sockaddr_un, sun_path) + 1 + (size_t) n)) < 0) {
                close(fd);
                return -1;
        }

        target_len = strlen(PICO_LOGD_STDOUT_SOCKET_PATH);
        if (target_len >= sizeof(target.sun_path)) {
                close(fd);
                return -1;
        }
        memset(&target, 0, sizeof(target));
        target.sun_family = AF_UNIX;
        memcpy(target.sun_path, PICO_LOGD_STDOUT_SOCKET_PATH, target_len);

        if (connect(fd, (struct sockaddr *) &target, sizeof(target)) < 0) {
                close(fd);
                return -1;
        }

        /* Matches J1's own measured real receive-side default (212992
         * bytes); SO_RCVBUF was found to have no effect on AF_UNIX
         * SOCK_DGRAM's actual queue depth (net.unix.max_dgram_qlen governs
         * that instead), so this is parity/hygiene, not load-bearing. */
        sndbuf = 212992;
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

        return fd;
}

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
 *
 * `sock_fds`/`n_sock_fds` (computed and owned by the PARENT, in
 * service_spawn(), before fork()) are the fds this start is passing via
 * LISTEN_FDS -- excluded from the close-everything sweep at step 5, then
 * renumbered and unflagged at step 5b. `envp`/`pid_slot` are likewise
 * parent-built (build_socket_envp()); NULL/0 together mean "no fds, use the
 * inherited environ unchanged", the same behaviour this function always had.
 * `stdout_fd` (create_stdout_socket(), also parent-built) is likewise
 * excluded from the sweep, then dup2()'d over stdout/stderr at step 8;
 * -1 means "logd unavailable", the console fallback (plan §3.6).
 */
static _Noreturn void
                child_exec(Service *s,
                           char **argv,
                           char **envp,
                           int *sock_fds,
                           unsigned n_sock_fds,
                           size_t pid_slot,
                           int stdout_fd) {
        char pidbuf[32];
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

        /* 5. Close everything this process inherited, except the fds being
         * passed for socket activation (sock_fds -- LISTEN_FDS) and the
         * logd stdout socket (stdout_fd, if create_stdout_socket()
         * succeeded). The cgroup control file (step 7) and the console
         * (step 8) are both reopened fresh by path below, so nothing else
         * needs to survive this. See close_all_except()'s own comment for
         * why this is not simply a close() per fd number any more. */
        {
                int keep_fds[PICO_MAX_SOCKET_FDS + 1];
                unsigned n_keep = 0, i;

                for (i = 0; i < n_sock_fds && n_keep < PICO_MAX_SOCKET_FDS; i++)
                        keep_fds[n_keep++] = sock_fds[i];
                if (stdout_fd >= 0)
                        keep_fds[n_keep++] = stdout_fd;

                max_fd = sysconf(_SC_OPEN_MAX);
                if (max_fd < 0)
                        max_fd = 1024; /* sane fallback if the syscall itself fails */
                close_all_except(keep_fds, n_keep, max_fd);
        }

        /* 5b. LISTEN_FDS/sd_listen_fds(): renumber the kept fds to a
         * contiguous run starting at 3, then clear the flags PID 1 needed
         * but this child's own consumer does not (O_NONBLOCK, FD_CLOEXEC).
         * Fatal on failure -- a partially-renumbered or still-CLOEXEC'd fd
         * is worse than not starting at all, since a consumer trusting
         * LISTEN_FDS would silently read or write the wrong descriptor. */
        if (n_sock_fds > 0) {
                /*
                 * shift_fds() renumbers into [3, n_sock_fds + 2] and assumes
                 * every fd still open in that range is one of its OWN. The
                 * logd stdout socket (step 5 keeps it open, step 8 needs it)
                 * is not, and if it happens to sit inside that range F_DUPFD
                 * can never place the last socket into the slot it occupies:
                 * the restart-from-collision loop then spins forever. Move it
                 * above the range first -- one fcntl(), no effect at all when
                 * it already sits high enough. A failure here is treated the
                 * same as create_stdout_socket() having failed in the parent:
                 * fall back to the console (step 8) rather than fail the
                 * start or, worse, enter shift_fds() with the collision
                 * still in place.
                 */
                if (stdout_fd >= 0 && stdout_fd < (int) n_sock_fds + 3) {
                        int nfd = fcntl(stdout_fd, F_DUPFD, (int) n_sock_fds + 3);

                        close(stdout_fd);
                        stdout_fd = nfd; /* -1 on failure: console fallback */
                }

                if (shift_fds(sock_fds, n_sock_fds) < 0)
                        _exit(PICO_EXIT_FDS);
                if (flags_fds(sock_fds, n_sock_fds) < 0)
                        _exit(PICO_EXIT_FDS);

                /*
                 * LISTEN_PID has to be THIS process's own pid, which does
                 * not exist until after fork() -- the one variable-length
                 * string this file ever builds post-fork, and the reason
                 * this whole function's constraint (no malloc past this
                 * point) matters: snprintf() into automatic (stack) storage
                 * is async-signal-safe, a heap string built the same way
                 * would not be.
                 */
                snprintf(pidbuf, sizeof(pidbuf), "LISTEN_PID=%d", (int) getpid());
                envp[pid_slot] = pidbuf;
        }

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
         * onto stdin gives every read() a silent EBADF. Never
         * vhangu()/reset/lock it (43efbc3959): every unit here shares this
         * same console, and clearing it out from under a concurrent writer
         * is a real boot deadlock in pico-init's design, not a hypothetical
         * one. stdin always comes from the console (plan §3.6) -- opened
         * first regardless of what stdout/stderr end up as below.
         */
        fd = open(PICO_CONSOLE_PATH, O_RDWR | O_NOCTTY);
        if (fd < 0)
                _exit(PICO_EXIT_STDIN);
        if (dup2(fd, STDIN_FILENO) < 0)
                _exit(PICO_EXIT_STDIN);

        /*
         * stdout/stderr: logd's socket when create_stdout_socket() (the
         * PARENT, before fork()) succeeded, else the same console fd stdin
         * just got -- the pre-J2 behaviour, unchanged, so an image without
         * logd (or one where it simply is not listening yet) behaves
         * exactly as before (plan §3.6). Either way both descriptors point
         * at the SAME open file description, matching upstream's own
         * stdout==stderr default and this file's pre-J2 console behaviour.
         */
        if (stdout_fd >= 0) {
                if (dup2(stdout_fd, STDOUT_FILENO) < 0)
                        _exit(PICO_EXIT_STDOUT);
                if (dup2(stdout_fd, STDERR_FILENO) < 0)
                        _exit(PICO_EXIT_STDERR);
                if (stdout_fd > STDERR_FILENO)
                        close(stdout_fd);
        } else {
                if (dup2(fd, STDOUT_FILENO) < 0)
                        _exit(PICO_EXIT_STDOUT);
                if (dup2(fd, STDERR_FILENO) < 0)
                        _exit(PICO_EXIT_STDERR);
        }
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
         * exit code -- there is no other channel back to the parent. envp is
         * NULL exactly when this start passes no fds (no Environment=
         * directive exists in this MVP to need one otherwise), in which case
         * the inherited `environ` is used unchanged, same as always. */
        execve(argv[0], argv, envp ? envp : environ);
        _exit(PICO_EXIT_EXEC);
}

int service_spawn(Service *s, char **argv, pid_t *ret_pid) {
        int sock_fds[PICO_MAX_SOCKET_FDS];
        int n_sock_fds = 0;
        char **envp = NULL;
        size_t pid_slot = 0;
        int stdout_fd;
        pid_t pid;
        int r;

        if (!s || !ret_pid)
                return -EINVAL;

        *ret_pid = 0;

        /* 69339ae9f7: catch the empty-argv case in the parent too, so a
         * caller mistake never even forks. */
        if (!argv || !argv[0] || argv[0][0] == '\0')
                return -ENOEXEC;

        /*
         * Only the main command inherits socket-activation fds, matching
         * v30: an ExecStartPre= control command never gets LISTEN_FDS, only
         * ExecStart= does. Fd collection happens on ANY service start, not
         * just a socket-triggered one -- this call does not care whether
         * socket_trigger() ran or the socket was merely already listening
         * when boot order reached this service.
         */
        if (argv == s->exec_start) {
                r = socket_collect_fds(UNIT(s), sock_fds, PICO_MAX_SOCKET_FDS);
                if (r < 0) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: could not collect socket fds (%s), starting without them",
                                 UNIT(s)->id,
                                 strerror(-r));
                } else
                        n_sock_fds = r;
        }

        if (n_sock_fds > 0) {
                /* d137a488af: before fork(), synchronously -- see
                 * socket_notify_service_starting()'s own header comment for
                 * why this matters for a boot-ordered (non-triggered) start. */
                socket_notify_service_starting(UNIT(s));

                envp = build_socket_envp((unsigned) n_sock_fds, &pid_slot);
                if (!envp) {
                        pico_log(PICO_LOG_WARNING,
                                 "%s: could not build a LISTEN_FDS environment, starting without it",
                                 UNIT(s)->id);
                        n_sock_fds = 0;
                }
        }

        /* Every start, not only ExecStart= (plan §3.6: nothing scopes stdout
         * capture to the main command the way LISTEN_FDS is scoped above).
         * Best-effort: -1 on any failure just means "no logd, use the
         * console" below, never a reason to fail the spawn itself. */
        stdout_fd = create_stdout_socket(UNIT(s)->id);

        pid = fork();
        if (pid < 0) {
                r = -errno; /* 74129a1276: never a stale success value */
                free_socket_envp(envp);
                if (stdout_fd >= 0)
                        close(stdout_fd);
                return r;
        }

        if (pid == 0)
                child_exec(s, argv, envp, sock_fds, (unsigned) n_sock_fds, pid_slot, stdout_fd); /* never returns */

        /* COW: the child already has its own copy of everything envp/
         * stdout_fd point to, made at fork() -- freeing/closing the
         * parent's copies here cannot affect it. See build_socket_envp()'s
         * and free_socket_envp()'s own notes; same reasoning for stdout_fd. */
        free_socket_envp(envp);
        if (stdout_fd >= 0)
                close(stdout_fd);

        *ret_pid = pid;
        return 0;
}
