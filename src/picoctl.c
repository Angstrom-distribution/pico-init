/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * picoctl -- the on-device systemctl equivalent (plan §1.7, milestone C1).
 *
 * Two independent halves, per the plan: read verbs (status/list-units/
 * is-active/is-failed/show) source purely from the state files C0 publishes
 * under <root><runtime_dir>/units/ -- no IPC, no live manager, so these work
 * even when PID 1's loop is wedged. Symlink verbs (enable/disable/
 * is-enabled/preset) operate on <root>/etc/systemd/system's .wants/.requires
 * and preset files exactly as unit-enable.c reads them at boot, reusing
 * unit-load.c/unit-parse.c (via a throwaway Manager) and unit-enable.c's own
 * manager_preset_query() rather than a parallel implementation -- the two
 * halves of "enabled" must never be able to disagree.
 *
 * --root DIR (matching systemctl --root=) prefixes every filesystem path
 * this program touches, defaulting to "" (the real root) in production; it
 * is what lets the symlink verbs be tested against fixture trees without
 * root and without touching the host's real /etc, exactly as systemctl
 * --root is this project's compliance oracle for the same operations.
 *
 * start/stop/restart/reset-failed (plan §1.7, milestone C2) are the third
 * half: a client for manager-ctrl.c's control socket. They are the only
 * verbs that need a live, unwedged manager -- everything above keeps
 * working even when PID 1's loop is stuck, which is the whole reason the
 * other two halves exist as files rather than IPC.
 */

/* accept4()'s AF_UNIX peers pull in struct sockaddr_un; -std=gnu17 alone
 * does not imply _GNU_SOURCE for every glibc extension this needs
 * (manager-ctrl.c's own note), so this has to be explicit and first. */
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "logd-read.h"
#include "logd.h"
#include "manager.h"
#include "unit-enable.h"
#include "unit.h"

/* --- --root plumbing --- */

static const char *arg_root = "";

/* Join arg_root and an absolute suffix (a PICO_* macro, always "/..."). */
static int path_join(char *buf, size_t bufsize, const char *suffix) {
        int n;

        if (arg_root && arg_root[0])
                n = snprintf(buf, bufsize, "%s%s", arg_root, suffix);
        else
                n = snprintf(buf, bufsize, "%s", suffix);

        if (n < 0 || (size_t) n >= bufsize)
                return -ENAMETOOLONG;
        return 0;
}

/* The inverse of path_join(): a fragment_path read back off a root-prefixed
 * Manager already carries arg_root as a literal prefix (unit_load() built it
 * by joining a root-prefixed search-path entry), so a symlink's target must
 * have that prefix stripped -- exactly install.c's skip_root(), which is why
 * `systemctl --root=X enable` writes symlinks pointing at the REAL absolute
 * path, not one still carrying X. Verified empirically against systemctl
 * --root in the verification container (see test-picoctl.c). */
static const char *strip_root(const char *path) {
        size_t len;

        if (!arg_root || !arg_root[0])
                return path;

        len = strlen(arg_root);
        if (strncmp(path, arg_root, len) == 0 && path[len] == '/')
                return path + len;

        return path;
}

/* --- state file reading (the no-IPC read verbs) --- */

struct unit_state {
        bool found;
        char active_state[32];
        char sub_state[32];
        char load_state[16];
        char fragment_path[PATH_MAX];
        char description[256];
        char unit_file_state[16];
        int main_pid;
        char result[24];
        char exec_main_code[16];
        int exec_main_status;
        unsigned n_restarts;
        char job[64];
};

static void unit_state_set(char *field, size_t field_size, const char *value) {
        snprintf(field, field_size, "%s", value);
}

/*
 * A missing file means the manager never published this unit -- either it
 * was never loaded (unit_load() failing leaves load_state UNIT_ERROR without
 * ever reaching a vtable start/stop call, so unit_notify() -- the sole
 * publish point -- never fires for it) or PID 1 simply is not running. Both
 * read as systemd's own "not-found": 0 with *st left at its not-found
 * defaults, never a hard failure the read verbs would have to special-case.
 */
static int read_unit_state(const char *unit_id, struct unit_state *st) {
        char rt[PATH_MAX];
        char path[PATH_MAX];
        char line[1024];
        FILE *f;
        int n;

        memset(st, 0, sizeof(*st));
        unit_state_set(st->active_state, sizeof(st->active_state), "inactive");
        unit_state_set(st->sub_state, sizeof(st->sub_state), "dead");
        unit_state_set(st->load_state, sizeof(st->load_state), "not-found");
        unit_state_set(st->result, sizeof(st->result), "success");

        if (path_join(rt, sizeof(rt), PICO_RUNTIME_DIR) < 0)
                return 0;

        n = snprintf(path, sizeof(path), "%s/units/%s", rt, unit_id);
        if (n < 0 || (size_t) n >= sizeof(path))
                return 0;

        f = fopen(path, "re");
        if (!f)
                return 0;

        while (fgets(line, sizeof(line), f)) {
                char *nl = strchr(line, '\n');
                char *eq;
                const char *key, *val;

                if (nl)
                        *nl = '\0';

                eq = strchr(line, '=');
                if (!eq)
                        continue;
                *eq = '\0';
                key = line;
                val = eq + 1;

                if (strcmp(key, "ActiveState") == 0)
                        unit_state_set(st->active_state, sizeof(st->active_state), val);
                else if (strcmp(key, "SubState") == 0)
                        unit_state_set(st->sub_state, sizeof(st->sub_state), val);
                else if (strcmp(key, "LoadState") == 0)
                        unit_state_set(st->load_state, sizeof(st->load_state), val);
                else if (strcmp(key, "FragmentPath") == 0)
                        unit_state_set(st->fragment_path, sizeof(st->fragment_path), val);
                else if (strcmp(key, "Description") == 0)
                        unit_state_set(st->description, sizeof(st->description), val);
                else if (strcmp(key, "UnitFileState") == 0)
                        unit_state_set(st->unit_file_state, sizeof(st->unit_file_state), val);
                else if (strcmp(key, "MainPID") == 0)
                        st->main_pid = atoi(val);
                else if (strcmp(key, "Result") == 0)
                        unit_state_set(st->result, sizeof(st->result), val);
                else if (strcmp(key, "ExecMainCode") == 0)
                        unit_state_set(st->exec_main_code, sizeof(st->exec_main_code), val);
                else if (strcmp(key, "ExecMainStatus") == 0)
                        st->exec_main_status = atoi(val);
                else if (strcmp(key, "NRestarts") == 0)
                        st->n_restarts = (unsigned) strtoul(val, NULL, 10);
                else if (strcmp(key, "Job") == 0)
                        unit_state_set(st->job, sizeof(st->job), val);
        }

        fclose(f);
        st->found = true;
        return 0;
}

/* --- show: nearly cat --- */

static int cmd_show(int argc, char *argv[]) {
        int i;

        if (argc < 1) {
                fprintf(stderr, "picoctl show: missing unit name\n");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                char rt[PATH_MAX];
                char path[PATH_MAX];
                FILE *f;
                int n;

                if (i > 0)
                        printf("\n");

                printf("Id=%s\n", argv[i]);

                if (path_join(rt, sizeof(rt), PICO_RUNTIME_DIR) < 0)
                        continue;
                n = snprintf(path, sizeof(path), "%s/units/%s", rt, argv[i]);
                if (n < 0 || (size_t) n >= sizeof(path))
                        continue;

                f = fopen(path, "re");
                if (!f) {
                        /* Matches read_unit_state()'s not-found defaults: a
                         * unit never published reads as not-found/inactive,
                         * the same as systemd's own "show" on an unknown
                         * unit -- never a hard error. */
                        printf("LoadState=not-found\n"
                               "ActiveState=inactive\n"
                               "SubState=dead\n");
                        continue;
                }

                {
                        char buf[4096];
                        size_t got;

                        while ((got = fread(buf, 1, sizeof(buf), f)) > 0)
                                fwrite(buf, 1, got, stdout);
                }
                fclose(f);
        }

        return 0;
}

/* --- list-units --- */

static int name_cmp(const void *a, const void *b) {
        return strcmp(*(const char * const *) a, *(const char * const *) b);
}

static int cmd_list_units(int argc, char *argv[]) {
        char rt[PATH_MAX];
        char unitsdir[PATH_MAX + 16];
        DIR *d;
        struct dirent *de;
        char **names = NULL;
        size_t n = 0, cap = 0;
        size_t i;

        (void) argc;
        (void) argv;

        if (path_join(rt, sizeof(rt), PICO_RUNTIME_DIR) < 0)
                return 1;
        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rt);

        d = opendir(unitsdir);
        if (!d) {
                fprintf(stderr, "picoctl: no published state at %s: %s\n", unitsdir, strerror(errno));
                return 1;
        }

        while ((de = readdir(d))) {
                if (de->d_name[0] == '.')
                        continue;
                if (n == cap) {
                        char **grown;

                        cap = cap ? cap * 2 : 8;
                        grown = realloc(names, cap * sizeof(char *));
                        if (!grown) {
                                closedir(d);
                                for (i = 0; i < n; i++)
                                        free(names[i]);
                                free(names);
                                return 1;
                        }
                        names = grown;
                }
                names[n] = strdup(de->d_name);
                if (!names[n]) {
                        closedir(d);
                        for (i = 0; i < n; i++)
                                free(names[i]);
                        free(names);
                        return 1;
                }
                n++;
        }
        closedir(d);

        if (names && n > 1)
                qsort(names, n, sizeof(char *), name_cmp);

        printf("%-32s %-8s %-10s %-13s %s\n", "UNIT", "LOAD", "ACTIVE", "SUB", "DESCRIPTION");
        for (i = 0; i < n; i++) {
                struct unit_state st;

                read_unit_state(names[i], &st);
                printf("%-32s %-8s %-10s %-13s %s\n",
                       names[i],
                       st.load_state,
                       st.active_state,
                       st.sub_state,
                       st.description);
                free(names[i]);
        }
        free(names);

        return 0;
}

/* --- is-active / is-failed: LSB init-script exit codes --- */

/*
 * Shared by both verbs -- upstream's own check_unit_generic() is one
 * function for the same reason: both print every unit's ActiveState and
 * both use the same "any counts, then not-found, then the LSB code" exit
 * logic, only the target state and the LSB code differ. LSB (via
 * systemctl-util.h in the real source): 0 running/ok, 1 dead, 3 not
 * running, 4 status unknown (unit never published == not-found here).
 */
static int cmd_is_state_generic(int argc, char *argv[], const char *want_state, int not_this_state_code) {
        bool ok = false, not_found = true;
        int i;

        if (argc < 1) {
                fprintf(stderr, "picoctl: missing unit name\n");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                struct unit_state st;

                read_unit_state(argv[i], &st);
                printf("%s\n", st.active_state);

                if (st.found)
                        not_found = false;
                if (strcmp(st.active_state, want_state) == 0)
                        ok = true;
        }

        if (ok)
                return 0;
        return not_found ? 4 : not_this_state_code;
}

static int cmd_is_active(int argc, char *argv[]) {
        return cmd_is_state_generic(argc, argv, "active", 3); /* LSB 3: not running */
}

static int cmd_is_failed(int argc, char *argv[]) {
        return cmd_is_state_generic(argc, argv, "failed", 1); /* LSB 1: dead */
}

/* --- status --- */

/* The process list, read from cgroup.procs under the unit's cgroup -- the
 * same source upstream's own status block uses (plan §1.7). Best-effort: no
 * cgroup (never started, or supervision degraded per manager-state.h's own
 * "never cost the boot" rule) just means nothing to print here, not a
 * failure of the whole verb. */
static void print_cgroup_procs(const char *unit_id) {
        char cgroup_root[PATH_MAX];
        char path[PATH_MAX + 64];
        FILE *f;
        char line[32];
        bool header = false;

        if (path_join(cgroup_root, sizeof(cgroup_root), PICO_CGROUP_ROOT) < 0)
                return;
        snprintf(path, sizeof(path), "%s/system.slice/%s/cgroup.procs", cgroup_root, unit_id);

        f = fopen(path, "re");
        if (!f)
                return;

        while (fgets(line, sizeof(line), f)) {
                pid_t pid = (pid_t) atoi(line);
                char comm_path[64];
                char comm[256] = "";
                FILE *cf;

                if (!header) {
                        printf("     CGroup: %s/system.slice/%s\n", PICO_CGROUP_ROOT, unit_id);
                        header = true;
                }

                snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", (int) pid);
                cf = fopen(comm_path, "re");
                if (cf) {
                        if (fgets(comm, sizeof(comm), cf)) {
                                char *nl = strchr(comm, '\n');

                                if (nl)
                                        *nl = '\0';
                        }
                        fclose(cf);
                }
                printf("             |- %d %s\n", (int) pid, comm);
        }

        fclose(f);
}

/* --- status: per-unit log tail --- */

/* systemctl status's own default depth; picolog's -n exists for the
 * interactive case, this one is fixed since status has no flag for it. */
#define PICOCTL_STATUS_LOG_LINES 10

/*
 * journalctl's short format, matching picolog.c's print_short() field for
 * field -- deliberately not shared code (logd-read.h's own header explains
 * why the reader and the formatter live in separate translation units).
 * There is no -a here: plain `systemctl status`'s own log tail never passes
 * journalctl -a either, so a binary-safe MESSAGE always prints the "blob
 * data" placeholder, matching real journalctl's default rather than ever
 * writing raw bytes to a TTY.
 */
static void print_log_line(const LogdEntry *e) {
        const LogdReadField *rt = logd_entry_field(e, "__REALTIME_TIMESTAMP");
        const LogdReadField *msg = logd_entry_field(e, "MESSAGE");
        const LogdReadField *ident = logd_entry_field(e, "SYSLOG_IDENTIFIER");
        const LogdReadField *comm = logd_entry_field(e, "_COMM");
        const LogdReadField *pid = logd_entry_field(e, "_PID");
        char host[256];
        char timebuf[32];
        struct tm tmv;
        time_t sec = 0;

        if (gethostname(host, sizeof(host)) < 0 || host[0] == '\0')
                snprintf(host, sizeof(host), "(none)");
        host[sizeof(host) - 1] = '\0';

        if (rt && !rt->binary && rt->value_len > 0 && rt->value_len < 24) {
                char numbuf[24];
                unsigned long long usec;

                memcpy(numbuf, rt->value, rt->value_len);
                numbuf[rt->value_len] = '\0';
                usec = strtoull(numbuf, NULL, 10);
                sec = (time_t) (usec / 1000000ULL);
        }

        if (sec > 0 && localtime_r(&sec, &tmv))
                strftime(timebuf, sizeof(timebuf), "%b %e %H:%M:%S", &tmv);
        else
                snprintf(timebuf, sizeof(timebuf), "(no timestamp)");

        printf("%s %s ", timebuf, host);

        if (ident)
                fwrite(ident->value, 1, ident->value_len, stdout);
        else if (comm)
                fwrite(comm->value, 1, comm->value_len, stdout);
        else
                fputs("-", stdout);

        if (pid && !pid->binary) {
                putchar('[');
                fwrite(pid->value, 1, pid->value_len, stdout);
                putchar(']');
        }

        fputs(": ", stdout);

        if (msg && !msg->binary)
                fwrite(msg->value, 1, msg->value_len, stdout);
        else if (msg)
                fputs("blob data", stdout);

        putchar('\n');
}

/*
 * An absent or empty ring -- an image without logd, a supported
 * configuration -- degrades to printing nothing, never an error: this is
 * exactly manager-state.h's own "never cost the boot" rule applied to a
 * read verb rather than to startup.
 */
static void print_log_tail(const char *unit_id) {
        char rt[PATH_MAX];
        LogdRing *ring;
        size_t n, i;
        int r;

        if (path_join(rt, sizeof(rt), LOGD_RUNTIME_DIR) < 0)
                return;

        r = logd_ring_read_filtered(rt, unit_id, PICOCTL_STATUS_LOG_LINES, &ring);
        if (r < 0)
                return;

        n = logd_ring_n_entries(ring);
        for (i = 0; i < n; i++)
                print_log_line(logd_ring_entry(ring, i));

        logd_ring_free(ring);
}

static int cmd_status(int argc, char *argv[]) {
        int i, worst = 0;

        if (argc < 1) {
                fprintf(stderr, "picoctl status: missing unit name\n");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                struct unit_state st;

                if (i > 0)
                        printf("\n");

                read_unit_state(argv[i], &st);

                if (!st.found) {
                        printf("%s\n", argv[i]);
                        printf("     Loaded: not-found\n");
                        fprintf(stderr, "Unit %s could not be found.\n", argv[i]);
                        if (worst < 4)
                                worst = 4;
                        continue;
                }

                printf("%s - %s\n", argv[i], st.description[0] ? st.description : argv[i]);
                printf("     Loaded: %s (%s; %s)\n",
                       st.load_state,
                       st.fragment_path[0] ? st.fragment_path : "n/a",
                       st.unit_file_state[0] ? st.unit_file_state : "n/a");
                printf("     Active: %s (%s)\n", st.active_state, st.sub_state);

                if (st.main_pid > 0)
                        printf("   Main PID: %d\n", st.main_pid);
                if (strcmp(st.result, "success") != 0)
                        printf("     Result: %s\n", st.result);
                if (st.exec_main_code[0])
                        printf("  Main Exit: code=%s, status=%d\n", st.exec_main_code, st.exec_main_status);
                if (st.n_restarts > 0)
                        printf("  NRestarts: %u\n", st.n_restarts);
                if (st.job[0])
                        printf("        Job: %s\n", st.job);

                print_cgroup_procs(argv[i]);
                print_log_tail(argv[i]);

                if (strcmp(st.active_state, "active") != 0 && strcmp(st.active_state, "reloading") != 0) {
                        if (worst < 3)
                                worst = 3;
                }
        }

        return worst;
}

/* --- symlink verbs: enable/disable/is-enabled/preset --- */

/*
 * Load a unit's [Install] data the exact way boot does: a throwaway Manager
 * whose search paths are root-prefixed, manager_load_unit() to find and
 * parse the real fragment via unit-load.c/unit-parse.c. This is what keeps
 * picoctl and unit-enable.c's boot-time reader agreeing about what a
 * WantedBy= line means -- they read it with the same code.
 *
 * On success *ret_m and *ret_u are set and the caller must manager_free(*ret_m)
 * (which frees *ret_u too). On failure nothing is allocated.
 */
static int load_install_info(const char *unit_name, Manager **ret_m, Unit **ret_u) {
        Manager *m = NULL;
        Unit *u = NULL;
        char updir[PATH_MAX], pkgdir[PATH_MAX];
        char presetdir[PATH_MAX], pkgpresetdir[PATH_MAX];
        int r;

        r = manager_new(&m);
        if (r < 0)
                return r;

        if (path_join(updir, sizeof(updir), PICO_UNIT_DIR) < 0 ||
            path_join(pkgdir, sizeof(pkgdir), PICO_PACKAGED_UNIT_DIR) < 0 ||
            path_join(presetdir, sizeof(presetdir), PICO_PRESET_DIR) < 0 ||
            path_join(pkgpresetdir, sizeof(pkgpresetdir), PICO_PACKAGED_PRESET_DIR) < 0) {
                manager_free(m);
                return -ENAMETOOLONG;
        }

        {
                const char * const up[] = { updir, pkgdir, NULL };
                const char * const pd[] = { presetdir, pkgpresetdir, NULL };

                r = manager_set_unit_path(m, up);
                if (r >= 0)
                        r = manager_set_preset_path(m, pd);
        }
        if (r < 0) {
                manager_free(m);
                return r;
        }

        r = manager_load_unit(m, unit_name, &u);
        if (r < 0 || !u || u->load_state != UNIT_LOADED) {
                manager_free(m);
                return r < 0 ? r : -ENOENT;
        }

        *ret_m = m;
        *ret_u = u;
        return 0;
}

/* Every directory component of `path` except its own basename, created if
 * missing -- install.c's mkdir_parents_label(), which real `systemctl
 * enable` also runs before every symlink it creates. A read-only /etc fails
 * here with a clear -EROFS/-EACCES, exactly as upstream's would. */
static int mkdir_parents(const char *path) {
        char buf[PATH_MAX];
        size_t len = strlen(path);
        char *p;

        if (len == 0 || len >= sizeof(buf))
                return -ENAMETOOLONG;
        memcpy(buf, path, len + 1);

        for (p = buf + 1; *p; p++) {
                if (*p != '/')
                        continue;
                *p = '\0';
                if (mkdir(buf, 0755) < 0 && errno != EEXIST)
                        return -errno;
                *p = '/';
        }

        return 0;
}

static int enable_symlink_path(
                const char *target, const char *suffix, const char *unit_id, char *out, size_t out_size) {
        char etcdir[PATH_MAX];
        int n;

        if (path_join(etcdir, sizeof(etcdir), PICO_UNIT_DIR) < 0)
                return -ENAMETOOLONG;

        n = snprintf(out, out_size, "%s/%s%s/%s", etcdir, target, suffix, unit_id);
        if (n < 0 || (size_t) n >= out_size)
                return -ENAMETOOLONG;
        return 0;
}

/*
 * Create (or repair) one <target>.wants|.requires/<unit> symlink pointing at
 * the unit's real absolute fragment path -- install.c's create_symlink(),
 * always force=true for .wants/.requires entries (install_info_symlink_
 * wants() passes force unconditionally; only linking the unit file itself
 * respects the CLI --force flag, which picoctl does not need since it never
 * links the fragment itself). Verified byte-identical to `systemctl --root
 * enable` in the verification container, absolute target included -- see
 * test-picoctl.c.
 */
static int create_enable_symlink(const char *target, const char *suffix, Unit *u) {
        char linkpath[PATH_MAX];
        char destbuf[PATH_MAX];
        const char *frag;
        ssize_t rl;
        int r;

        r = enable_symlink_path(target, suffix, u->id, linkpath, sizeof(linkpath));
        if (r < 0)
                return r;

        r = mkdir_parents(linkpath);
        if (r < 0)
                return r;

        frag = strip_root(u->fragment_path);

        rl = readlink(linkpath, destbuf, sizeof(destbuf) - 1);
        if (rl >= 0) {
                destbuf[rl] = '\0';
                if (strcmp(destbuf, frag) == 0)
                        return 0; /* already correct: idempotent, not an error */
                unlink(linkpath);
        } else if (errno != ENOENT)
                unlink(linkpath); /* something else there (e.g. a plain file); force it */

        if (symlink(frag, linkpath) < 0)
                return -errno;

        return 0;
}

static void remove_enable_symlink(const char *target, const char *suffix, const char *unit_id) {
        char linkpath[PATH_MAX];

        if (enable_symlink_path(target, suffix, unit_id, linkpath, sizeof(linkpath)) < 0)
                return;
        unlink(linkpath); /* ENOENT is not an error: nothing to remove */
}

static bool enable_symlink_exists(const char *target, const char *suffix, const char *unit_id) {
        char linkpath[PATH_MAX];
        struct stat st;

        if (enable_symlink_path(target, suffix, unit_id, linkpath, sizeof(linkpath)) < 0)
                return false;
        return lstat(linkpath, &st) == 0;
}

/* -ENOEXEC: no [Install] data at all -- matches real systemctl's "unit not
 * meant to be enabled" refusal. 0 or -errno otherwise, first error wins
 * (matching unit-enable.c's own convention) but every target is still
 * attempted, not just the first. */
static int do_enable_unit(Unit *u) {
        size_t i;
        int ret = 0;

        if (!u->wanted_by && !u->required_by)
                return -ENOEXEC;

        for (i = 0; u->wanted_by && u->wanted_by[i]; i++) {
                int r = create_enable_symlink(u->wanted_by[i], ".wants", u);

                if (r < 0 && ret == 0)
                        ret = r;
        }
        for (i = 0; u->required_by && u->required_by[i]; i++) {
                int r = create_enable_symlink(u->required_by[i], ".requires", u);

                if (r < 0 && ret == 0)
                        ret = r;
        }

        return ret;
}

/* No install data means nothing was ever created to remove: a no-op
 * success, not an error, matching real systemctl's "not enabled" case. */
static void do_disable_unit(Unit *u) {
        size_t i;

        for (i = 0; u->wanted_by && u->wanted_by[i]; i++)
                remove_enable_symlink(u->wanted_by[i], ".wants", u->id);
        for (i = 0; u->required_by && u->required_by[i]; i++)
                remove_enable_symlink(u->required_by[i], ".requires", u->id);
}

static int cmd_enable(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                fprintf(stderr, "picoctl enable: missing unit name\n");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                Manager *m = NULL;
                Unit *u = NULL;
                int r = load_install_info(argv[i], &m, &u);

                if (r < 0) {
                        fprintf(stderr, "Failed to enable unit, unit %s does not exist.\n", argv[i]);
                        status = 1;
                        continue;
                }

                r = do_enable_unit(u);
                if (r == -ENOEXEC) {
                        fprintf(stderr,
                                "The unit files have no installation config, %s is not meant to be enabled.\n",
                                argv[i]);
                        status = 1;
                } else if (r < 0) {
                        fprintf(stderr, "Failed to enable unit %s: %s\n", argv[i], strerror(-r));
                        status = 1;
                } else
                        printf("Enabled %s.\n", argv[i]);

                manager_free(m);
        }

        return status;
}

static int cmd_disable(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                fprintf(stderr, "picoctl disable: missing unit name\n");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                Manager *m = NULL;
                Unit *u = NULL;
                int r = load_install_info(argv[i], &m, &u);

                if (r < 0) {
                        fprintf(stderr, "Failed to disable unit, unit %s does not exist.\n", argv[i]);
                        status = 1;
                        continue;
                }

                do_disable_unit(u);
                printf("Disabled %s.\n", argv[i]);

                manager_free(m);
        }

        return status;
}

static int cmd_is_enabled(int argc, char *argv[]) {
        bool enabled = false, not_found = true;
        int i;

        if (argc < 1) {
                fprintf(stderr, "picoctl is-enabled: missing unit name\n");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                Manager *m = NULL;
                Unit *u = NULL;
                int r = load_install_info(argv[i], &m, &u);
                bool this_enabled = false;

                if (r < 0) {
                        printf("not-found\n");
                        continue;
                }
                not_found = false;

                if (!u->wanted_by && !u->required_by) {
                        printf("static\n");
                        this_enabled = true;
                } else {
                        size_t j;

                        for (j = 0; u->wanted_by && u->wanted_by[j] && !this_enabled; j++)
                                if (enable_symlink_exists(u->wanted_by[j], ".wants", u->id))
                                        this_enabled = true;
                        for (j = 0; u->required_by && u->required_by[j] && !this_enabled; j++)
                                if (enable_symlink_exists(u->required_by[j], ".requires", u->id))
                                        this_enabled = true;

                        printf("%s\n", this_enabled ? "enabled" : "disabled");
                }

                if (this_enabled)
                        enabled = true;

                manager_free(m);
        }

        if (enabled)
                return 0;
        return not_found ? 4 : 1;
}

/*
 * manager_preset_query() (unit-enable.c) is the exact function boot-time
 * manager_apply_presets() calls -- reusing it, rather than re-reading the
 * preset files here, is what keeps `picoctl preset` and a real boot from
 * ever disagreeing about a preset rule. -ENOENT ("no rule matched") means
 * enable, matching systemd.preset(5) and manager_apply_presets()'s own
 * documented reasoning.
 */
static int cmd_preset(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                fprintf(stderr, "picoctl preset: missing unit name\n");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                Manager *m = NULL;
                Unit *u = NULL;
                int r = load_install_info(argv[i], &m, &u);
                int decision;

                if (r < 0) {
                        fprintf(stderr, "Failed to preset unit, unit %s does not exist.\n", argv[i]);
                        status = 1;
                        continue;
                }

                decision = manager_preset_query(m, u->id);
                if (decision < 0 && decision != -ENOENT) {
                        fprintf(stderr, "Failed to query preset for %s: %s\n", argv[i], strerror(-decision));
                        status = 1;
                        manager_free(m);
                        continue;
                }

                if (decision == 1 || decision == -ENOENT) {
                        r = do_enable_unit(u);
                        if (r < 0 && r != -ENOEXEC) {
                                fprintf(stderr, "Failed to preset unit %s: %s\n", argv[i], strerror(-r));
                                status = 1;
                        } else
                                printf("Enabled %s (preset).\n", argv[i]);
                } else {
                        do_disable_unit(u);
                        printf("Disabled %s (preset).\n", argv[i]);
                }

                manager_free(m);
        }

        return status;
}

/* --- start/stop/restart/reset-failed: the control-socket client half --- */

/* Reply buffer: generous against manager-ctrl.c's own PICO_CTRL_LINE_MAX --
 * the two are not required to agree on an exact number, only for this one
 * to be at least as large as any reply the server actually sends, which is
 * always a single short line. */
#define PICOCTL_CTRL_REPLY_MAX 512

/*
 * Connect to <root><runtime_dir>/control -- manager-ctrl.c's own path,
 * exactly. A missing socket (an image with no C2 control socket, or one
 * whose setup failed at boot) is a supported configuration, per manager-
 * ctrl.h -- this just fails with -ENOENT/-ECONNREFUSED like any other
 * connect() to nothing there, and the caller reports it like any other
 * error rather than treating it as special.
 */
static int ctrl_connect(void) {
        char rt[PATH_MAX];
        struct sockaddr_un addr;
        int fd, n, r;

        if (path_join(rt, sizeof(rt), PICO_RUNTIME_DIR) < 0)
                return -ENAMETOOLONG;

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        n = snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/control", rt);
        if (n < 0 || (size_t) n >= sizeof(addr.sun_path))
                return -ENAMETOOLONG;

        fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
                r = -errno;
                close(fd);
                return r;
        }

        return fd;
}

/*
 * One request/reply round trip: connect, send exactly "PICO1 <verb> <unit>
 * [--no-block]" (manager-ctrl.c's wire grammar, no trailing newline --
 * SOCK_SEQPACKET preserves the message boundary, so none is needed), block
 * for the single reply line, NUL-terminate it into `reply`. 0 or -errno;
 * *reply is only meaningful on success.
 */
static int ctrl_roundtrip(const char *verb, const char *unit, bool no_block, char *reply, size_t reply_size) {
        char line[16 + UNIT_NAME_MAX + 16];
        int fd, n;
        ssize_t r;

        fd = ctrl_connect();
        if (fd < 0)
                return fd;

        n = snprintf(line, sizeof(line), "PICO1 %s %s%s", verb, unit, no_block ? " --no-block" : "");
        if (n < 0 || (size_t) n >= sizeof(line)) {
                close(fd);
                return -ENAMETOOLONG;
        }

        r = send(fd, line, (size_t) n, MSG_NOSIGNAL);
        if (r < 0) {
                int e = -errno;

                close(fd);
                return e;
        }

        r = recv(fd, reply, reply_size - 1, 0);
        close(fd);
        if (r < 0)
                return -errno;

        reply[r] = '\0';
        return 0;
}

/* start/stop/restart share everything except the wire verb; reset-failed
 * (below) does not take --no-block, so it stays a separate, simpler
 * function rather than a fourth case squeezed in here. */
static int cmd_verb_generic(int argc, char *argv[], const char *verb) {
        bool no_block = false;
        bool any_unit = false;
        int i, status = 0;

        if (argc < 1) {
                fprintf(stderr, "picoctl %s: missing unit name\n", verb);
                return 1;
        }

        for (i = 0; i < argc; i++)
                if (strcmp(argv[i], "--no-block") == 0)
                        no_block = true;

        for (i = 0; i < argc; i++) {
                char reply[PICOCTL_CTRL_REPLY_MAX];
                int r;

                if (strcmp(argv[i], "--no-block") == 0)
                        continue;
                any_unit = true;

                r = ctrl_roundtrip(verb, argv[i], no_block, reply, sizeof(reply));
                if (r < 0) {
                        fprintf(stderr, "picoctl %s: %s: %s\n", verb, argv[i], strerror(-r));
                        status = 1;
                        continue;
                }

                if (strncmp(reply, "ok", 2) == 0)
                        printf("%s\n", argv[i]);
                else {
                        fprintf(stderr, "picoctl %s: %s: %s", verb, argv[i], reply);
                        status = 1;
                }
        }

        if (!any_unit) {
                fprintf(stderr, "picoctl %s: missing unit name\n", verb);
                return 1;
        }

        return status;
}

static int cmd_start(int argc, char *argv[]) {
        return cmd_verb_generic(argc, argv, "start");
}

static int cmd_stop(int argc, char *argv[]) {
        return cmd_verb_generic(argc, argv, "stop");
}

static int cmd_restart(int argc, char *argv[]) {
        return cmd_verb_generic(argc, argv, "restart");
}

static int cmd_reset_failed(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                fprintf(stderr, "picoctl reset-failed: missing unit name\n");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                char reply[PICOCTL_CTRL_REPLY_MAX];
                int r = ctrl_roundtrip("reset-failed", argv[i], false, reply, sizeof(reply));

                if (r < 0) {
                        fprintf(stderr, "picoctl reset-failed: %s: %s\n", argv[i], strerror(-r));
                        status = 1;
                } else if (strncmp(reply, "ok", 2) != 0) {
                        fprintf(stderr, "picoctl reset-failed: %s: %s", argv[i], reply);
                        status = 1;
                }
        }

        return status;
}

/* --- main --- */

static void usage(void) {
        fprintf(stderr,
                "usage: picoctl [--root DIR] VERB [UNIT...] [--no-block]\n"
                "verbs: status list-units is-active is-failed show enable disable is-enabled "
                "preset start stop restart reset-failed\n");
}

int main(int argc, char *argv[]) {
        static const struct {
                const char *name;
                int (*fn)(int, char **);
        } verbs[] = {
                {       "status",       cmd_status },
                {   "list-units",   cmd_list_units },
                {    "is-active",    cmd_is_active },
                {    "is-failed",    cmd_is_failed },
                {         "show",         cmd_show },
                {       "enable",       cmd_enable },
                {      "disable",      cmd_disable },
                {   "is-enabled",   cmd_is_enabled },
                {       "preset",       cmd_preset },
                {        "start",        cmd_start },
                {         "stop",         cmd_stop },
                {      "restart",      cmd_restart },
                { "reset-failed", cmd_reset_failed },
        };
        int argi = 1;
        size_t i;

        while (argi < argc) {
                if (strcmp(argv[argi], "--root") == 0 && argi + 1 < argc) {
                        arg_root = argv[argi + 1];
                        argi += 2;
                        continue;
                }
                if (strncmp(argv[argi], "--root=", 7) == 0) {
                        arg_root = argv[argi] + 7;
                        argi += 1;
                        continue;
                }
                break;
        }

        if (argi >= argc) {
                usage();
                return 1;
        }

        for (i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++)
                if (strcmp(argv[argi], verbs[i].name) == 0)
                        return verbs[i].fn(argc - argi - 1, argv + argi + 1);

        fprintf(stderr, "picoctl: unknown verb '%s'\n", argv[argi]);
        usage();
        return 1;
}
