/* SPDX-FileCopyrightText: 2010 Lennart Poettering */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * fork/exec + fd/cgroup child-side setup, quarried from the child-process
 * portion of systemd's ~2011-era src/execute.c (tag v30, commit 501c92c,
 * copyright 2010 Lennart Poettering, GPL-2.0-or-later). Upstream later moved
 * this path to exec-invoke.c (75689fb2d4) and src/ to src/core/ (b30e2f4c18);
 * neither changes the ordering rules below. systemd's later systemd-executor
 * architecture (bb5232b6a3) is not adopted: it solves a problem a small PID 1
 * does not have. What is kept is the constraint that motivated it: the
 * post-fork/pre-execve region is as close to async-signal-safe as this
 * project gets -- no malloc, no NSS, no dlopen, no allocating logger
 * (pico_log() uses vfprintf(), so it is never called after fork() below).
 * Everything that can be computed in the parent is computed there.
 *
 * Backports (commit hashes from github.com/systemd/systemd), each at the
 * step of child_exec() it applies to:
 *
 *  - 7e0e6b50b4 -- take a start timestamp before fork(), not after. No
 *    Service field holds it, but service_spawn() still calls fork() as its
 *    very next statement rather than doing parent-side setup in between.
 *  - 69339ae9f7 (CVE-2021-4034/PwnKit class) -- refuse to execve() with a
 *    NULL or empty argv[0]. Checked in the parent (service_spawn(), so a
 *    caller mistake never forks) and again in the child.
 *  - ce30c8dcb4 -- reset every SIG_IGN'd signal to SIG_DFL. A SIG_IGN
 *    disposition and the signal mask both survive fork() and execve() (only
 *    a *handled* signal is demoted to SIG_DFL), so without this every
 *    service starts with whatever pico-init itself ignores.
 *  - 353e12c2f4 -- re-ignore SIGPIPE after the reset above, matching
 *    systemd's IgnoreSIGPIPE=yes default.
 *  - 4c253ed1ca -- clear the signal mask after the disposition reset: the
 *    signalfd block set from signal.c survives fork()+execve(), and without
 *    clearing it every service starts with SIGTERM blocked.
 *  - 74129a1276 -- a failed fork() returns -errno, never a stale success
 *    value.
 *  - 171ceb4a00 -- open the console O_RDWR, not O_RDONLY: a read-only fd
 *    dup'd onto stdout/stderr makes every write() fail with EBADF.
 *  - 43efbc3959 -- never vhangup()/reset/lock the console. Every unit shares
 *    PICO_CONSOLE_PATH, so clearing it under a concurrent writer can
 *    deadlock boot.
 *  - 1fb0682e78 -- TIOCSCTTY only on an actual tty (isatty() == 1 first):
 *    Linux reuses ioctl numbers across subsystems, so issuing it on anything
 *    else can hit an unrelated driver.
 *
 * Not backported: 78d17fa09/b5d742138 (UTF-8 argv validation; there is no
 * specifier expansion in exec lines to need it) and the notify-protocol, PAM
 * and SELinux parts of upstream's exec path.
 *
 * Socket activation touches the same region. LISTEN_PID has to be the
 * child's own pid, so it is the one string built after fork(), by snprintf()
 * into stack storage. Everything else -- fd collection (socket_collect_fds()),
 * the LISTEN_FDS=<n> string and the envp array -- is built in the parent.
 * shift_fds()/flags_fds() are v30's execute.c:63-101 verbatim: F_DUPFD's
 * "lowest free fd >= target" guarantee is what makes the restart loop in
 * shift_fds() converge. execv() becomes execve() because the fds are passed
 * as inherited, renumbered descriptors plus an explicit envp (the
 * LISTEN_FDS/LISTEN_PID protocol).
 *
 * The step 5 fd sweep uses close_range() (Linux 5.9+, glibc >= 2.34) to
 * close whole gaps between kept fds in one syscall. A close() per fd number
 * up to sysconf(_SC_OPEN_MAX) costs seconds on every service start when
 * RLIMIT_NOFILE defaults to 1048576, as in common container images. It falls
 * back to the per-fd loop if close_range() is unavailable at runtime. The
 * insertion sort it needs is hand-rolled because glibc's qsort can malloc a
 * scratch buffer, which this region must never do; n is at most
 * PICO_MAX_SOCKET_FDS + 2, where O(n^2) costs nothing.
 *
 * logd stdout/stderr capture is pico-original code, not a backport
 * (upstream's SOCK_STREAM handshake plus fd-store is not adopted; see
 * logd/logd-write.h). create_stdout_socket() runs in the parent: it creates
 * a datagram socket, binds it to a unique abstract-namespace name (no
 * filesystem path to clean up or collide with), then connect()s it to logd's
 * stdout socket. Binding first matters: a bound AF_UNIX socket cannot
 * be rebound (EINVAL), so every datagram sent through it, including from
 * children that inherit fd 1/2, carries the same source address in logd's
 * recvfrom(). logd keys fragment tails on that stream identity rather than
 * on the PID, which is immune to PID reuse and correct for a service that
 * spans several PIDs. child_exec() dup2()s the socket over stdout and stderr;
 * stdin stays the console. Any failure (logd not installed, its socket not
 * yet present) yields stdout_fd == -1 and the console path is used instead,
 * so a missing logd never fails a spawn.
 *
 * $VAR/${VAR} expansion in exec lines (v30's replace_env_argv()) runs in the
 * parent against the finished envp and produces a freshly owned argv for the
 * child. v30 expands in the child (execute.c:1377), which the no-malloc rule
 * forbids; the result is the same. argv[0] is kept verbatim: it is also the
 * exec path, which v30 never expanded either.
 */

/* close_range() is a glibc >= 2.34 wrapper; -std=gnu17 alone does not imply
 * _GNU_SOURCE (same reasoning as socket.c's own note), and this has to be
 * defined before any header is pulled in for it to take effect at all. */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "manager-notify.h"
#include "service.h"
#include "socket.h"

/* Hand-rolled ascending insertion sort -- see this file's header for why
 * qsort(3) is not used here. `n` is at most PICO_MAX_SOCKET_FDS + 2 (the
 * socket-activation set, the logd stdout socket, the Type=exec pipe). */
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
 * See this file's header for why. Falls back to a per-fd loop, from wherever
 * close_range() first failed, on kernels without it (pre-5.9). Async-signal-safe:
 * close_range()/close() only, plus the insertion sort above (no malloc).
 * `keep` may hold up to PICO_MAX_SOCKET_FDS + 2 entries -- the socket-
 * activation set, the logd stdout socket and the Type=exec pipe; anything
 * beyond that is clamped so `sorted` cannot overflow. */
void pico_close_all_except(const int *keep, unsigned n_keep, long max_fd) {
        int sorted[PICO_MAX_SOCKET_FDS + 2];
        unsigned i, n, next;
        bool use_close_range = true;

        n = n_keep < PICO_MAX_SOCKET_FDS + 2 ? n_keep : PICO_MAX_SOCKET_FDS + 2;
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
 * to override that). FD_CLOEXEC: opened SOCK_CLOEXEC for the
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

/* The manager's default PATH, and the search list for a bare Exec name. */
#define PICO_DEFAULT_PATH "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin"

/*
 * v30's exec_context_load_environment(): every EnvironmentFile= is read
 * afresh on each spawn, in the PARENT, so a file one ExecStartPre= writes is
 * seen by the next command (8c7be95e5). A later file overrides an earlier
 * one. A '-'-prefixed file is skipped on any load failure, as in v30; any
 * other failure fails the spawn. *ret is NULL when there is nothing to load.
 * 0 or -errno.
 */
static int load_environment_files(Service *s, char ***ret) {
        char **i, **acc = NULL;

        *ret = NULL;

        for (i = s->environment_files; i && *i; i++) {
                const char *fn = *i;
                bool ignore = fn[0] == '-';
                char **loaded = NULL, **merged;
                int r;

                if (ignore)
                        fn++;

                r = fn[0] == '/' ? pico_load_env_file(fn, &loaded) : -EINVAL;
                if (r < 0) {
                        if (ignore) {
                                pico_log(PICO_LOG_DEBUG,
                                         "%s: EnvironmentFile=-%s: %s, skipping",
                                         UNIT(s)->id,
                                         fn,
                                         strerror(-r));
                                continue;
                        }
                        pico_log(PICO_LOG_ERR,
                                 "%s: failed to load EnvironmentFile=%s: %s",
                                 UNIT(s)->id,
                                 fn,
                                 strerror(-r));
                        pico_strv_free(acc);
                        return r;
                }

                merged = pico_strv_env_merge(2, acc, loaded);
                pico_strv_free(acc);
                pico_strv_free(loaded);
                if (!merged)
                        return -ENOMEM;
                acc = merged;
        }

        *ret = acc;
        return 0;
}

/*
 * Builds the child's whole envp in the PARENT, before fork() -- malloc here
 * is fine, this is exactly the "everything that can be computed in the
 * parent is computed there instead" this file's header promises.
 *
 * Merge order, a later NAME= replacing an earlier one: the manager's default
 * environment, then NOTIFY_SOCKET=/LISTEN_FDS=, then the User= account's
 * USER=/LOGNAME=/HOME=/SHELL=, then Environment=, then EnvironmentFile=
 * contents. The order matters: a file beats Environment= (oe-core's
 * read-only-rootfs hook overrides a unit's default that way), and both beat
 * the account defaults.
 *
 * Like systemd's system manager the default environment is clean: PATH
 * only, plus TERM for a tty-attached unit. PID 1's own environ is what the
 * kernel built (HOME=/, TERM=linux, and every unrecognised name=value
 * boot-cmdline parameter), none of which a service should inherit.
 *
 * LAYOUT INVARIANT: [merged entries, every one malloc'd][reserved LISTEN_PID
 * slot, NULL in the parent, iff n_fds>0][NUL terminator]. Every entry is
 * owned, environ's included, so pico_strv_free() is the single free path; it
 * stops at the first NULL, which is why the reserved slot stays last. A
 * LISTEN_PID= from Environment=/EnvironmentFile= is dropped when the slot is
 * reserved -- the child's own pid is the only value that protocol allows,
 * and a second entry would be the one getenv() finds first. n_fds == 0 means
 * no LISTEN_FDS entry and no reserved slot (*ret_pid_slot left untouched --
 * child_exec() only reads it when n_fds>0). NULL on OOM.
 */
static char **
                build_exec_envp(char **creds_env,
                                char **unit_env,
                                char **file_env,
                                bool tty,
                                unsigned n_fds,
                                const char *notify_socket,
                                size_t *ret_pid_slot) {
        char *ours[3] = { NULL, NULL, NULL };
        char *base[3] = { "PATH=" PICO_DEFAULT_PATH, NULL, NULL };
        char fds_buf[32], term_buf[64];
        char **envp = NULL;
        size_t idx = 0;

        if (tty) {
                const char *term = getenv("TERM");

                if (term && *term &&
                    snprintf(term_buf, sizeof(term_buf), "TERM=%s", term) < (int) sizeof(term_buf))
                        base[1] = term_buf;
        }

        if (notify_socket) {
                size_t len = strlen("NOTIFY_SOCKET=") + strlen(notify_socket) + 1;

                ours[idx] = malloc(len);
                if (!ours[idx])
                        goto finish;
                snprintf(ours[idx++], len, "NOTIFY_SOCKET=%s", notify_socket);
        }
        if (n_fds > 0) {
                int r = snprintf(fds_buf, sizeof(fds_buf), "LISTEN_FDS=%u", n_fds);

                if (r < 0 || (size_t) r >= sizeof(fds_buf))
                        goto finish;
                ours[idx++] = fds_buf;
        }

        envp = pico_strv_env_merge(5, base, ours, creds_env, unit_env, file_env);
        if (!envp || n_fds == 0)
                goto finish;

        {
                size_t j, w;
                char **grown;

                for (j = w = 0; envp[j]; j++) {
                        if (strncmp(envp[j], "LISTEN_PID=", strlen("LISTEN_PID=")) == 0) {
                                free(envp[j]);
                                continue;
                        }
                        envp[w++] = envp[j];
                }
                envp[w] = NULL;

                grown = realloc(envp, (w + 2) * sizeof(char *));
                if (!grown) {
                        envp = pico_strv_free(envp);
                        goto finish;
                }
                envp = grown;

                *ret_pid_slot = w;
                envp[w] = NULL; /* filled by the child, post-fork -- see child_exec() */
                envp[w + 1] = NULL;
        }

finish:
        if (notify_socket)
                free(ours[0]);
        return envp;
}

/*
 * *ret is a freshly owned copy of `argv` with $VAR/${VAR} expanded against
 * `env`, or NULL when no argument contains a '$' and `argv` can be used as
 * is. 0 or -errno.
 */
static int expand_exec_argv(char **argv, char * const *env, char ***ret) {
        char **i, **copy = NULL;
        int r;

        *ret = NULL;

        for (i = argv + 1; *i; i++)
                if (strchr(*i, '$'))
                        break;
        if (!*i)
                return 0;

        r = pico_strv_extend(&copy, argv[0]);
        if (r >= 0)
                r = pico_replace_env_argv(argv + 1, env, &copy);
        if (r < 0) {
                pico_strv_free(copy);
                return r;
        }

        *ret = copy;
        return 0;
}

/*
 * Where logd listens for captured stdout/stderr. Duplicated from logd.h's
 * LOGD_STDOUT_SOCKET_PATH rather than included, so PID 1 has no build-time
 * dependency on logd, which runs independently of it. The two sides agree on
 * this one path by convention.
 */
#define PICO_LOGD_STDOUT_SOCKET_PATH "/run/logd/stdout"

/*
 * See this file's header for the design. Returns -1 on any failure (never
 * fatal to the spawn). `unit_id` only makes the bound name legible in a
 * socket listing; logd compares the raw address bytes (logd-recv.h), so
 * truncating a long one is harmless.
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
         * the counter, so there is nothing to unlink. */
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

        /* Matches the usual receive-side default (212992 bytes). The queue
         * depth of an AF_UNIX SOCK_DGRAM is governed by
         * net.unix.max_dgram_qlen, so this is optional. */
        sndbuf = 212992;
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));

        return fd;
}

/*
 * User=/Group=/SupplementaryGroups=: the integers that cross fork(). Resolved by exec_creds_resolve() in the
 * PARENT -- getpwnam()/getgrnam()/getgrouplist() go through NSS, allocate, and are nowhere near
 * async-signal-safe -- and applied by child_exec() at step 10, which reads nothing but these. `groups` is
 * malloc'd here and freed by the parent after fork(); the child sees it through its copy-on-write mapping,
 * same as argv and cg->path. `set` is false when the unit names none of the
 * three directives, in which case the child never touches its ids at all.
 */
typedef struct ExecCreds {
        bool set;
        uid_t uid;
        gid_t gid;
        gid_t *groups;
        int n_groups;
        char **env; /* USER=/LOGNAME=/HOME=/SHELL= for a User= with a passwd entry */
} ExecCreds;

/* An all-digits User=/Group= is an id, not a name to look up (systemd
 * accepts both spellings). (uid_t) -1 is the sentinel the setuid() family
 * treats as "unchanged", never a real id. */
static bool parse_id(const char *v, unsigned long *ret) {
        const char *p;
        unsigned long n;
        char *end;

        if (!v || !*v)
                return false;
        for (p = v; *p; p++)
                if (*p < '0' || *p > '9')
                        return false;

        errno = 0;
        n = strtoul(v, &end, 10);
        if (errno != 0 || *end != '\0' || n >= (unsigned long) UINT_MAX)
                return false;

        *ret = n;
        return true;
}

/*
 * Resolves a SupplementaryGroups= entry (name or numeric gid, same shape
 * convention parse_id()/getgrnam() already use above for Group=) to a gid_t.
 * 0 on success, -ESRCH for a named group that does not exist (logged here,
 * with the name) -- matching the existing User=/Group= failure mode exactly,
 * per upstream's own get_group_creds(): an unresolvable name fails the spawn,
 * never silently drops the entry.
 */
static int supplementary_group_to_gid(Service *s, const char *tok, gid_t *ret) {
        unsigned long id;
        struct group *gr;

        if (parse_id(tok, &id)) {
                *ret = (gid_t) id;
                return 0;
        }

        errno = 0;
        gr = getgrnam(tok);
        if (!gr) {
                pico_log(PICO_LOG_ERR,
                         "%s: SupplementaryGroups=%s: no such group%s%s",
                         UNIT(s)->id,
                         tok,
                         errno ? ": " : "",
                         errno ? strerror(errno) : "");
                return -ESRCH;
        }
        *ret = gr->gr_gid;
        return 0;
}

/*
 * Group= alone keeps the caller's uid and changes only the gid; User= alone
 * takes the account's primary group; both set, Group= wins; NEITHER set
 * keeps both the caller's uid AND gid (for SupplementaryGroups=-only units;
 * upstream's get_supplementary_groups()/enforce_groups() run unconditionally
 * in exec-invoke.c too). The supplementary list starts as the account's full membership
 * from the group database, initgroups(3)-style, computed against the FINAL
 * gid exactly as systemd's own exec path does -- so a Group= override is in
 * the list and the passwd primary group is not, unless the database says
 * so -- or just [gid] with no User= (a numeric User= with no passwd entry
 * behaves the same way: its own number as gid, no membership to look up).
 * SupplementaryGroups= entries are then appended on top of that base list,
 * never a replacement for it (upstream's enforce_groups() does the same:
 * initgroups()/[gid] first, SupplementaryGroups= second). 0 on success,
 * -ESRCH when a named account or group does not exist (logged here, with the
 * name), -E2BIG past NGROUPS_MAX, -ENOMEM.
 */
static int creds_env_from_passwd(ExecCreds *c, const struct passwd *pw) {
        const char *shell = pw->pw_shell && *pw->pw_shell ? pw->pw_shell : "/bin/sh";
        const char *home = pw->pw_dir && *pw->pw_dir ? pw->pw_dir : "/";
        char *e[4] = { NULL, NULL, NULL, NULL };
        int i, r = 0;

        if (asprintf(&e[0], "USER=%s", pw->pw_name) < 0)
                e[0] = NULL;
        if (asprintf(&e[1], "LOGNAME=%s", pw->pw_name) < 0)
                e[1] = NULL;
        if (asprintf(&e[2], "HOME=%s", home) < 0)
                e[2] = NULL;
        if (asprintf(&e[3], "SHELL=%s", shell) < 0)
                e[3] = NULL;

        for (i = 0; i < 4; i++)
                if (!e[i])
                        r = -ENOMEM;
        if (r == 0) {
                c->env = calloc(5, sizeof(char *));
                if (!c->env)
                        r = -ENOMEM;
        }
        for (i = 0; i < 4; i++) {
                if (r == 0)
                        c->env[i] = e[i];
                else
                        free(e[i]);
        }
        return r;
}

static int exec_creds_resolve(Service *s, ExecCreds *c) {
        const char *pw_name = NULL;
        struct passwd *pw = NULL;
        unsigned long id;
        gid_t group_gid = 0;
        long ngroups_max;
        char **it;

        memset(c, 0, sizeof(*c));

        if (!s->user && !s->group && !s->supplementary_groups)
                return 0;
        c->set = true;

        if (s->group) {
                if (parse_id(s->group, &id))
                        group_gid = (gid_t) id;
                else {
                        struct group *gr;

                        errno = 0;
                        gr = getgrnam(s->group);
                        if (!gr) {
                                pico_log(PICO_LOG_ERR,
                                         "%s: Group=%s: no such group%s%s",
                                         UNIT(s)->id,
                                         s->group,
                                         errno ? ": " : "",
                                         errno ? strerror(errno) : "");
                                return -ESRCH;
                        }
                        group_gid = gr->gr_gid;
                }
        }

        if (s->user) {
                if (parse_id(s->user, &id)) {
                        c->uid = (uid_t) id;
                        pw = getpwuid(c->uid);
                        c->gid = pw ? pw->pw_gid : (gid_t) id;
                } else {
                        errno = 0;
                        pw = getpwnam(s->user);
                        if (!pw) {
                                pico_log(PICO_LOG_ERR,
                                         "%s: User=%s: no such user%s%s",
                                         UNIT(s)->id,
                                         s->user,
                                         errno ? ": " : "",
                                         errno ? strerror(errno) : "");
                                return -ESRCH;
                        }
                        c->uid = pw->pw_uid;
                        c->gid = pw->pw_gid;
                }
                if (pw) {
                        int er = creds_env_from_passwd(c, pw);

                        if (er < 0)
                                return er;
                        pw_name = pw->pw_name;
                }
        } else
                c->uid = geteuid();

        if (s->group)
                c->gid = group_gid;
        else if (!s->user)
                c->gid = getegid(); /* neither directive: keep the caller's own gid too */

        if (pw_name) {
                int tries, n = 0;

                /* getgrouplist() reports the size it needed through `n`
                 * when the buffer is too small; the retry loop covers the
                 * database growing between the sizing call and the real
                 * one, which is not worth failing a start over. */
                (void) getgrouplist(pw_name, c->gid, NULL, &n);
                for (tries = 0; tries < 4; tries++) {
                        gid_t *g;

                        if (n < 1)
                                n = 1;
                        g = realloc(c->groups, (size_t) n * sizeof(gid_t));
                        if (!g)
                                return -ENOMEM;
                        c->groups = g;

                        if (getgrouplist(pw_name, c->gid, c->groups, &n) >= 0) {
                                c->n_groups = n;
                                break;
                        }
                }
                if (c->n_groups < 1) {
                        pico_log(PICO_LOG_ERR,
                                 "%s: User=%s: cannot determine group membership",
                                 UNIT(s)->id,
                                 s->user);
                        return -ESRCH;
                }
        } else {
                c->groups = malloc(sizeof(gid_t));
                if (!c->groups)
                        return -ENOMEM;
                c->groups[0] = c->gid;
                c->n_groups = 1;
        }

        /*
         * SupplementaryGroups=: appended on top of the base list above,
         * never replacing it (see this function's own header comment).
         * NGROUPS_MAX is the kernel's own setgroups(2) ceiling -- checked
         * here so a too-long list fails the spawn with a clear -E2BIG
         * instead of setgroups() itself failing with EINVAL deep inside
         * child_exec(), where there is no channel to say why.
         */
        ngroups_max = sysconf(_SC_NGROUPS_MAX);
        for (it = s->supplementary_groups; it && *it; it++) {
                gid_t gid, *g;
                int r;

                if (ngroups_max > 0 && c->n_groups >= ngroups_max)
                        return -E2BIG;

                r = supplementary_group_to_gid(s, *it, &gid);
                if (r < 0)
                        return r;

                g = realloc(c->groups, (size_t) (c->n_groups + 1) * sizeof(gid_t));
                if (!g)
                        return -ENOMEM;
                c->groups = g;
                c->groups[c->n_groups++] = gid;
        }

        return 0;
}

static void exec_creds_free(ExecCreds *c) {
        free(c->groups);
        c->groups = NULL;
        c->n_groups = 0;
        c->env = pico_strv_free(c->env);
}

/*
 * Reopens the unit's cgroup.procs by path rather than reusing any fd the
 * parent had open for it: everything this process inherited is closed in
 * the fd sweep before this runs (see child_exec() step 5), so there is
 * nothing to keep a list of in the first place. dir is a valid
 * copy-on-write pointer into the parent's memory; strings survive fork() even
 * though live fds do not.
 */
static void child_attach_cgroup(const char *dir) {
        char path[PATH_MAX];
        char buf[32];
        int fd, n;

        if (!dir)
                return;

        n = snprintf(path, sizeof(path), "%s/cgroup.procs", dir);
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
 * Bare (slash-free) ExecStart=/ExecStop=/... name resolution (systemd since
 * v239, 7c891d53b "load-fragment: when parsing paths for Exec*=, be more
 * liberal" + exec-invoke.c's find_executable_full()): search a fixed
 * directory list for `name`, matching upstream's DEFAULT_PATH_WITH_FULL_SBIN
 * order (src/basic/path-util.c's default_PATH()/dir_is_split()) -- this
 * project assumes usrmerge with /usr/sbin kept separate from /usr/bin
 * (upstream's "split sbin" case), so a static list is correct and needs none
 * of upstream's runtime inode_same() layout detection. Not searched: $PATH
 * and the unit's own Environment=PATH= (upstream passes use_path_envvar=false
 * too: PID 1 must not let a unit's environment redirect what it execs) and
 * ExecSearchPath= (no field for it).
 *
 * A stat()+access() probe per candidate rather than upstream's
 * open_and_check_executable(): both are async-signal-safe, and this runs in
 * the no-malloc region (`buf` is the caller's stack buffer). A directory
 * (or other non-regular match, S_ISREG) does not stop the search, matching
 * upstream's own open_and_check_executable()+fd_verify_regular() behavior:
 * only a real, executable, regular file ends it. Writes the candidate into
 * `buf` (size `bufsize`, always NUL-terminated on the 0 return) and returns
 * 0 on a match, -1 when nothing in the list matches (ENOENT-equivalent) --
 * the caller falls back to execve()ing the bare name itself in that case,
 * which fails exactly the way a missing absolute path already does today
 * (see child_exec() step 11's own comment).
 */
static int find_in_default_path(const char *name, char *buf, size_t bufsize) {
        static const char * const dirs[] = {
                "/usr/local/sbin",
                "/usr/local/bin",
                "/usr/sbin",
                "/usr/bin",
        };
        size_t i;

        for (i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
                struct stat st;
                int n = snprintf(buf, bufsize, "%s/%s", dirs[i], name);

                if (n < 0 || (size_t) n >= bufsize)
                        continue; /* name too long for this prefix; try the next */
                if (stat(buf, &st) < 0)
                        continue;
                if (!S_ISREG(st.st_mode))
                        continue; /* a directory etc: keep searching, as upstream does */
                if (access(buf, X_OK) < 0)
                        continue;

                return 0;
        }

        return -1;
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
 * parent-built (build_exec_envp()); pid_slot is meaningful only when n_sock_fds > 0 (see
 * build_exec_envp()'s own layout-invariant comment).
 * `stdout_fd` (create_stdout_socket(), also parent-built) is likewise
 * excluded from the sweep, then dup2()'d over stdout/stderr at step 8;
 * -1 means "logd unavailable", the console fallback. `creds`
 * (exec_creds_resolve(), parent-built too) is the User=/Group= result the
 * child applies at step 10 -- integers only, nothing left to look up.
 * `exec_fd` is the write end of a Type=exec service's O_CLOEXEC readiness
 * pipe (see service.h), -1 for every other type: kept across the sweep,
 * written at step 11, and closed by a successful execve() itself.
 * `tty_stdin` (parent-computed from the state the spawning enter_* function
 * already set) is true when this command gets the StandardInput=tty* terminal
 * on stdin; false for a tty* unit's ExecStop=/ExecStopPost=, which get it on
 * stdout/stderr only (step 8).
 */
static _Noreturn void
                child_exec(Service *s,
                           char **argv,
                           char **envp,
                           int *sock_fds,
                           unsigned n_sock_fds,
                           size_t pid_slot,
                           int stdout_fd,
                           int exec_fd,
                           const ExecCreds *creds,
                           bool tty_stdin,
                           const char *cgroup_dir) {
        char pidbuf[32];
        sigset_t empty;
        int sig, fd;
        long max_fd;
        bool is_tty = service_standard_input_is_tty(s->standard_input);
        const char *tty_path = s->tty_path ? s->tty_path : PICO_CONSOLE_PATH;

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

        /*
         * StandardInput=socket (service.h's ServiceStandardInput comment):
         * the one accepted connection goes to fd 0/1 directly, never
         * through LISTEN_FDS -- the two mechanisms are mutually exclusive
         * in upstream too, a consumer using this one never calls
         * sd_listen_fds(). n_sock_fds == 1 is socket.c's own invariant for
         * an Accept=yes instance (exactly one connection fd); anything else
         * here is a real bug upstream of this function, not something to
         * paper over by picking fd 0 of several.
         */
        bool stdin_socket = s->standard_input == SERVICE_STANDARD_INPUT_SOCKET && n_sock_fds == 1;

        /* 5. Close everything this process inherited, except the fds being
         * passed for socket activation (sock_fds -- LISTEN_FDS) and the
         * logd stdout socket (stdout_fd, if create_stdout_socket()
         * succeeded). The cgroup control file (step 7) and the console
         * (step 8) are both reopened fresh by path below, so nothing else
         * needs to survive this. See pico_close_all_except()'s own comment for
         * why this is not simply a close() per fd number any more. */
        {
                int keep_fds[PICO_MAX_SOCKET_FDS + 2];
                unsigned n_keep = 0, i;

                for (i = 0; i < n_sock_fds && n_keep < PICO_MAX_SOCKET_FDS; i++)
                        keep_fds[n_keep++] = sock_fds[i];
                if (stdout_fd >= 0)
                        keep_fds[n_keep++] = stdout_fd;
                if (exec_fd >= 0)
                        keep_fds[n_keep++] = exec_fd;

                max_fd = sysconf(_SC_OPEN_MAX);
                if (max_fd < 0)
                        max_fd = 1024; /* sane fallback if the syscall itself fails */
                pico_close_all_except(keep_fds, n_keep, max_fd);
        }

        /* 5b. LISTEN_FDS/sd_listen_fds(): renumber the kept fds to a
         * contiguous run starting at 3, then clear the flags PID 1 needed
         * but this child's own consumer does not (O_NONBLOCK, FD_CLOEXEC).
         * Fatal on failure -- a partially-renumbered or still-CLOEXEC'd fd
         * is worse than not starting at all, since a consumer trusting
         * LISTEN_FDS would silently read or write the wrong descriptor.
         * Skipped entirely for stdin_socket -- see its own comment above. */
        if (n_sock_fds > 0 && !stdin_socket) {
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

                /* Same collision, same fix, but F_DUPFD_CLOEXEC: plain
                 * F_DUPFD drops the flag the whole protocol rests on. A
                 * failure here leaves the parent seeing EOF without the 1,
                 * which it treats as "not confirmed" and lets SIGCHLD
                 * decide -- never a false success. */
                if (exec_fd >= 0 && exec_fd < (int) n_sock_fds + 3) {
                        int nfd = fcntl(exec_fd, F_DUPFD_CLOEXEC, (int) n_sock_fds + 3);

                        close(exec_fd);
                        exec_fd = nfd;
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
        if (cgroup_dir)
                child_attach_cgroup(cgroup_dir);

        /*
         * 8. StandardInput=socket: the accepted connection replaces the
         * console on all three of 0/1/2, matching upstream's own
         * StandardOutput=inherit-from-stdin default for this case (classic
         * inetd nowait semantics -- dropbear's own per-connection mode just
         * reads/writes fd 0). Real systemd's own split (stdin=socket,
         * stdout/stderr independently settable) is not carried: no consumer
         * here wants anything else, and keeping the regular console path
         * entirely separate from this one is what keeps both simple.
         *
         * Otherwise: O_RDWR, not O_RDONLY (171ceb4a00): a read-only console
         * dup'd onto stdin gives every read() a silent EBADF. Never
         * vhangup()/reset/lock it (43efbc3959): every unit shares this
         * console, and clearing it under a concurrent writer can deadlock
         * boot. stdin always comes from the console, opened first
         * regardless of what stdout/stderr end up as below.
         */
        if (stdin_socket) {
                int cfd = sock_fds[0];

                if (dup2(cfd, STDIN_FILENO) < 0)
                        _exit(PICO_EXIT_STDIN);
                if (dup2(cfd, STDOUT_FILENO) < 0)
                        _exit(PICO_EXIT_STDOUT);
                if (dup2(cfd, STDERR_FILENO) < 0)
                        _exit(PICO_EXIT_STDERR);
                if (cfd > STDERR_FILENO)
                        close(cfd);
        } else if (is_tty) {
                /*
                 * StandardInput=tty*: TTYPath= on all three for the commands
                 * upstream gives the terminal to (EXEC_APPLY_TTY_STDIN:
                 * ExecCondition=/ExecStartPre=/ExecStart=); every other
                 * command gets stdin downgraded to /dev/null and the
                 * terminal write-only on 1/2, as exec-invoke.c's
                 * fixup_input()/maybe_inherit_stdout_from_stdin(). stdout
                 * goes to the terminal rather than logd because upstream's
                 * StandardOutput= default is inherit when stdin is a tty;
                 * service_spawn() therefore never makes a logd socket for
                 * these units, so stdout_fd is -1 here. O_NOCTTY: step 9
                 * decides about the controlling terminal explicitly.
                 */
                int ofd;

                if (tty_stdin) {
                        fd = open(tty_path, O_RDWR | O_NOCTTY);
                        if (fd < 0)
                                _exit(PICO_EXIT_STDIN);
                        ofd = fd;
                } else {
                        fd = open("/dev/null", O_RDONLY | O_NOCTTY);
                        if (fd < 0)
                                _exit(PICO_EXIT_STDIN);
                        ofd = open(tty_path, O_WRONLY | O_NOCTTY);
                        if (ofd < 0)
                                _exit(PICO_EXIT_STDOUT);
                }

                if (dup2(fd, STDIN_FILENO) < 0)
                        _exit(PICO_EXIT_STDIN);
                if (dup2(ofd, STDOUT_FILENO) < 0)
                        _exit(PICO_EXIT_STDOUT);
                if (dup2(ofd, STDERR_FILENO) < 0)
                        _exit(PICO_EXIT_STDERR);
                if (ofd != fd && ofd > STDERR_FILENO)
                        close(ofd);
                if (fd > STDERR_FILENO)
                        close(fd);
        } else {
                fd = open(PICO_CONSOLE_PATH, O_RDWR | O_NOCTTY);
                if (fd < 0)
                        _exit(PICO_EXIT_STDIN);
                if (dup2(fd, STDIN_FILENO) < 0)
                        _exit(PICO_EXIT_STDIN);

                /*
                 * stdout/stderr: logd's socket when create_stdout_socket()
                 * (the PARENT, before fork()) succeeded, else the same
                 * console fd stdin just got, so an image
                 * without logd (or one where it is not listening yet) logs
                 * to the console. Either way both descriptors share one
                 * open file description, matching upstream's
                 * stdout==stderr default.
                 */
                if (stdout_fd >= 0) {
                        if (dup2(stdout_fd, STDOUT_FILENO) < 0)
                                _exit(PICO_EXIT_STDOUT);
                        if (dup2(stdout_fd, STDERR_FILENO) < 0)
                                _exit(PICO_EXIT_STDERR);
                } else {
                        if (dup2(fd, STDOUT_FILENO) < 0)
                                _exit(PICO_EXIT_STDOUT);
                        if (dup2(fd, STDERR_FILENO) < 0)
                                _exit(PICO_EXIT_STDERR);
                }
                if (fd > STDERR_FILENO)
                        close(fd);
        }

        /*
         * 8b. An explicit StandardOutput=/StandardError= overrides whatever
         * step 8 chose: journal goes to logd even when stdin is a tty (the
         * parent made the socket for exactly that case), null discards.
         * StandardError= inherits from StandardOutput= when unset, as
         * upstream, but only an explicit stdout setting is followed; the
         * default stays what step 8 did. The logd fd is closed here, once,
         * for every branch above.
         */
        {
                ServiceStdioOutput out = s->standard_output;
                ServiceStdioOutput err = s->standard_error != SERVICE_STDIO_OUTPUT_INHERIT ?
                                s->standard_error :
                                out;

                if (out == SERVICE_STDIO_OUTPUT_JOURNAL && stdout_fd >= 0) {
                        if (dup2(stdout_fd, STDOUT_FILENO) < 0)
                                _exit(PICO_EXIT_STDOUT);
                } else if (out == SERVICE_STDIO_OUTPUT_NULL) {
                        int nfd = open("/dev/null", O_WRONLY | O_NOCTTY);

                        if (nfd < 0 || dup2(nfd, STDOUT_FILENO) < 0)
                                _exit(PICO_EXIT_STDOUT);
                        if (nfd > STDERR_FILENO)
                                close(nfd);
                }

                if (err == SERVICE_STDIO_OUTPUT_JOURNAL && stdout_fd >= 0) {
                        if (dup2(stdout_fd, STDERR_FILENO) < 0)
                                _exit(PICO_EXIT_STDERR);
                } else if (err == SERVICE_STDIO_OUTPUT_NULL) {
                        int nfd = open("/dev/null", O_WRONLY | O_NOCTTY);

                        if (nfd < 0 || dup2(nfd, STDERR_FILENO) < 0)
                                _exit(PICO_EXIT_STDERR);
                        if (nfd > STDERR_FILENO)
                                close(nfd);
                }

                if (stdout_fd > STDERR_FILENO)
                        close(stdout_fd);
        }

        /*
         * 9. 1fb0682e78: TIOCSCTTY is a real ioctl on a real tty; issuing it
         * on anything else can hit an unrelated driver, because Linux
         * reuses ioctl numbers across subsystems. isatty() == 1 is the
         * guard; setsid() at step 6 is the other half of the precondition
         * (session leader, no controlling terminal yet). Not fatal on
         * failure -- the service just has no job control, and there is no
         * async-signal-safe way to log it here.
         *
         * StandardInput= refines that, as upstream's acquire_terminal():
         * tty-force passes 1, stealing the terminal from another session
         * (root still holds CAP_SYS_ADMIN here, before step 10); tty-fail
         * turns a failure into EXIT_STDIN. Plain tty diverges from
         * upstream, which waits (inotify, ACQUIRE_TERMINAL_WAIT) for the
         * current controlling process to let go: here it proceeds without
         * job control instead, because blocking a child indefinitely in
         * this region, with no way to report why, is worse.
         */
        if (isatty(STDIN_FILENO) == 1) {
                int force = s->standard_input == SERVICE_STANDARD_INPUT_TTY_FORCE && tty_stdin;

                if (ioctl(STDIN_FILENO, TIOCSCTTY, force) < 0 &&
                    s->standard_input == SERVICE_STANDARD_INPUT_TTY_FAIL && tty_stdin)
                        _exit(PICO_EXIT_STDIN);
        }

        /*
         * 9a. A tty* unit with User= needs to own its terminal for the VT
         * ioctls weston and friends issue: upstream fchmod_and_chown()s it
         * to 0620 and the user (exec-invoke.c), failing with EXIT_STDIN.
         * Done here, still as root, on the fd rather than the path so no
         * rename can redirect it. service_revert_tty() (service.c) hands it
         * back to root once the unit is dead.
         */
        if (is_tty && tty_stdin && creds->set && creds->uid != 0) {
                if (fchown(STDIN_FILENO, creds->uid, (gid_t) -1) < 0)
                        _exit(PICO_EXIT_STDIN);
                if (fchmod(STDIN_FILENO, 0620) < 0)
                        _exit(PICO_EXIT_STDIN);
        }

        /*
         * 10. User=/Group=/SupplementaryGroups=: setgroups() -> setgid() ->
         * setuid(), in exactly that order -- once the uid is unprivileged
         * the first two are no longer permitted, so the reverse order
         * silently keeps root's groups (the classic privilege-retention
         * bug). creds->set covers all three directives, including
         * SupplementaryGroups= alone with neither User= nor Group= given
         * (neither User= nor Group=): setgid()/setuid() then just
         * reassert this process's own current ids. Placed after the cgroup attach (7) and the console open
         * (8), both of which may need the privilege being given up here. Fatal: a unit that asked to drop
         * privilege, or to add a supplementary group, must never run with more or less than it asked for.
         */
        if (creds->set) {
                if (setgroups((size_t) creds->n_groups, creds->groups) < 0)
                        _exit(PICO_EXIT_GROUP);
                if (setgid(creds->gid) < 0)
                        _exit(PICO_EXIT_GROUP);
                if (setuid(creds->uid) < 0)
                        _exit(PICO_EXIT_USER);
        }

        /* 11. Does not return on success. Its failure is reported purely by
         * exit code -- there is no other channel back to the parent.
         *
         * Bare (slash-free) argv[0]: resolved against find_in_default_path()
         * above into `exec_path`, a stack buffer -- argv[0] ITSELF stays the
         * original bare name (upstream's own cosmetic choice too: a `ps`
         * listing shows "seatd", not "/usr/bin/seatd"), only the execve()
         * target changes. Parser-accepted-but-unresolvable (find_in_default_
         * path() returns -1) falls back to execve()ing argv[0] unchanged:
         * with no '/' in it, execve() resolves that relative to this
         * process's cwd (always "/" here), which essentially never matches,
         * so it fails with ENOENT the exact same way an absolute missing
         * path already does -- no separate failure path needed.
         *
         * Type=exec (upstream's exec_fd, exec-invoke.c): a 1 goes down the
         * pipe right before execve(), a 0 right after a failed one. Success
         * never writes the 0 -- O_CLOEXEC closes the pipe, and that EOF
         * after the 1 is the parent's signal. A failed write is not fatal:
         * the parent then sees EOF with nothing before it and lets SIGCHLD
         * decide, which is the pre-exec verdict anyway. */
        {
                const char *exec_path = argv[0];
                char resolved[PATH_MAX];

                if (argv[0][0] != '/' && find_in_default_path(argv[0], resolved, sizeof(resolved)) == 0)
                        exec_path = resolved;

                if (exec_fd >= 0) {
                        const uint8_t hot = 1;

                        (void) !write(exec_fd, &hot, sizeof(hot));
                }

                execve(exec_path, argv, envp);
        }

        if (exec_fd >= 0) {
                const uint8_t cold = 0;

                (void) !write(exec_fd, &cold, sizeof(cold));
        }
        _exit(PICO_EXIT_EXEC);
}

int service_spawn(Service *s, char **argv, pid_t *ret_pid) {
        int sock_fds[PICO_MAX_SOCKET_FDS];
        int n_sock_fds = 0;
        char **envp = NULL;
        size_t pid_slot = 0;
        const char *notify_socket;
        char **file_env = NULL, **expanded_argv = NULL;
        bool is_main, tty_stdin;
        ExecCreds creds;
        char subgroup_path[PATH_MAX];
        const char *cgroup_dir = NULL;
        int stdout_fd;
        int exec_pipe[2] = { -1, -1 };
        pid_t pid;
        int r;

        if (!s || !ret_pid)
                return -EINVAL;

        *ret_pid = 0;

        /* 69339ae9f7: catch the empty-argv case in the parent too, so a
         * caller mistake never even forks. */
        if (!argv || !argv[0] || argv[0][0] == '\0')
                return -ENOEXEC;

        /* The main command is recognized by pointer identity, so decide it
         * from the caller's argv: the $VAR-expanded copy below is never
         * s->exec_start. */
        is_main = argv == s->exec_start;

        /* User=/Group= resolution: NSS, so parent-only, and before any
         * side effect (socket_notify_service_starting() below) so an
         * unknown account is a plain start failure with nothing to undo. */
        r = exec_creds_resolve(s, &creds);
        if (r < 0) {
                exec_creds_free(&creds);
                return r;
        }

        /* Delegate=yes for a non-root User=: the service must own its cgroup to manage the subtree
         * below it. Done here, not in the child, so a failure can be logged; the unit still starts. */
        if (s->delegate && s->cgroup && creds.set && creds.uid != 0 && creds.uid != (uid_t) -1) {
                int dr = cgroup_v2_delegate_to(s->cgroup->path, creds.uid, creds.gid);

                if (dr < 0)
                        pico_log(PICO_LOG_WARNING,
                                 "%s: Delegate=: cannot hand %s to uid %u: %s",
                                 UNIT(s)->id,
                                 s->cgroup->path,
                                 (unsigned) creds.uid,
                                 strerror(-dr));
        }

        /* DelegateSubgroup=: the main process goes into <unit cgroup>/<name>, every other process
         * of the unit into <unit cgroup>/.control, so the unit cgroup itself stays empty and the
         * service may enable controllers in it. A subgroup that cannot be made falls back to the
         * unit cgroup. */
        if (s->cgroup) {
                cgroup_dir = s->cgroup->path;

                if (s->delegate && s->delegate_subgroup) {
                        int sr = cgroup_v2_make_subgroup(
                                        s->cgroup->path,
                                        is_main ? s->delegate_subgroup : CGROUP_CONTROL_SUBGROUP,
                                        subgroup_path,
                                        sizeof(subgroup_path));

                        if (sr < 0) {
                                pico_log(PICO_LOG_WARNING,
                                         "%s: DelegateSubgroup=: cannot create %s under %s: %s",
                                         UNIT(s)->id,
                                         is_main ? s->delegate_subgroup : CGROUP_CONTROL_SUBGROUP,
                                         s->cgroup->path,
                                         strerror(-sr));
                        } else {
                                cgroup_dir = subgroup_path;
                                if (is_main && creds.set && creds.uid != 0 && creds.uid != (uid_t) -1)
                                        (void) cgroup_v2_delegate_to(subgroup_path, creds.uid, creds.gid);
                        }
                }
        }

        /* Same placement reasoning: a required EnvironmentFile= that cannot
         * be read fails the start before any side effect. */
        r = load_environment_files(s, &file_env);
        if (r < 0) {
                exec_creds_free(&creds);
                return r;
        }

        /*
         * Only the main command inherits socket-activation fds, matching
         * v30: an ExecStartPre= control command never gets LISTEN_FDS, only
         * ExecStart= does. Fd collection happens on ANY service start, not
         * just a socket-triggered one -- this call does not care whether
         * socket_trigger() ran or the socket was merely already listening
         * when boot order reached this service.
         */
        if (is_main) {
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
        }

        /* NOTIFY_SOCKET= for every spawn, ExecStartPre= included (matching
         * upstream, and consistent with the listener accepting a
         * control_pid sender too) -- unlike LISTEN_FDS, not scoped to
         * the main command. NULL when the listener never came up
         * (manager_notify_setup() failed or has not run), in which case the
         * scrub below still runs so an inherited value cannot leak through. */
        notify_socket = manager_notify_socket_path(UNIT(s)->manager);

        envp = build_exec_envp(
                        creds.env,
                        s->environment,
                        file_env,
                        service_standard_input_is_tty(s->standard_input),
                        (unsigned) n_sock_fds,
                        notify_socket,
                        &pid_slot);
        if (!envp) {
                pico_log(PICO_LOG_ERR, "%s: could not build the child environment", UNIT(s)->id);
                pico_strv_free(file_env);
                exec_creds_free(&creds);
                return -ENOMEM;
        }
        file_env = pico_strv_free(file_env);

        /* Against exactly what the child will see. */
        r = expand_exec_argv(argv, envp, &expanded_argv);
        if (r < 0) {
                pico_log(PICO_LOG_ERR,
                         "%s: could not expand $ variables in %s: %s",
                         UNIT(s)->id,
                         argv[0],
                         strerror(-r));
                pico_strv_free(envp);
                exec_creds_free(&creds);
                return r;
        }
        if (expanded_argv)
                argv = expanded_argv;

        /* Every start, not only ExecStart=: stdout capture is not scoped to
         * the main command the way LISTEN_FDS is above. -1 on any failure
         * means "no logd, use the console". Not for
         * a tty* unit: its stdout follows stdin to the terminal (child_exec()
         * step 8). */
        stdout_fd = service_standard_input_is_tty(s->standard_input) &&
                                        s->standard_output != SERVICE_STDIO_OUTPUT_JOURNAL &&
                                        s->standard_error != SERVICE_STDIO_OUTPUT_JOURNAL ?
                        -1 :
                        create_stdout_socket(UNIT(s)->id);

        /* Every enter_* function sets the state before it spawns, so the
         * state names the command: upstream's EXEC_APPLY_TTY_STDIN set. */
        tty_stdin = service_standard_input_is_tty(s->standard_input) &&
                        (s->state == SERVICE_CONDITION || s->state == SERVICE_START_PRE ||
                         s->state == SERVICE_EXEC_START);

        /* Type=exec's readiness pipe (service.h), for the main command
         * only: ExecStartPre= completes by exiting, not by exec'ing. Both
         * ends O_CLOEXEC -- the child's end closing on execve() IS the
         * signal. A pipe failure is a real spawn failure, not a fallback to
         * simple: the unit asked for exec semantics. */
        if (is_main && s->type == SERVICE_TYPE_EXEC) {
                if (pipe2(exec_pipe, O_CLOEXEC | O_NONBLOCK) < 0) {
                        r = -errno;
                        pico_strv_free(expanded_argv);
                        pico_strv_free(envp);
                        exec_creds_free(&creds);
                        if (stdout_fd >= 0)
                                close(stdout_fd);
                        return r;
                }
        }

        pid = fork();
        if (pid < 0) {
                r = -errno; /* 74129a1276: never a stale success value */
                pico_strv_free(expanded_argv);
                pico_strv_free(envp);
                exec_creds_free(&creds);
                if (stdout_fd >= 0)
                        close(stdout_fd);
                if (exec_pipe[0] >= 0) {
                        close(exec_pipe[0]);
                        close(exec_pipe[1]);
                }
                return r;
        }

        if (pid == 0)
                child_exec(s,
                           argv,
                           envp,
                           sock_fds,
                           (unsigned) n_sock_fds,
                           pid_slot,
                           stdout_fd,
                           exec_pipe[1],
                           &creds,
                           tty_stdin,
                           cgroup_dir); /* never returns */

        /* COW: the child already has its own copy of everything argv/envp/
         * creds/stdout_fd point to, made at fork() -- freeing/closing the
         * parent's copies here cannot affect it. See build_exec_envp()'s own
         * layout note; same reasoning for the rest. */
        pico_strv_free(expanded_argv);
        pico_strv_free(envp);
        exec_creds_free(&creds);
        if (stdout_fd >= 0)
                close(stdout_fd);

        /* The parent must hold no copy of the write end, or EOF never
         * arrives. The read end is service.c's to watch and close. */
        if (exec_pipe[1] >= 0)
                close(exec_pipe[1]);
        s->exec_fd = exec_pipe[0];

        *ret_pid = pid;
        return 0;
}
