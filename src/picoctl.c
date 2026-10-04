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
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
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

#include "fstab.h"
#include "logd-read.h"
#include "logd.h"
#include "manager.h"
#include "status.h"
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

/* "foo.service" -> "service"; NULL for a name with no '.' (never happens
 * for anything read_unit_state() publishes, but checked rather than
 * assumed). */
static const char *unit_type_suffix(const char *name) {
        const char *dot = strrchr(name, '.');

        return dot ? dot + 1 : NULL;
}

/* One substring of a comma-separated --type=/--state= value matches `word`
 * exactly -- strv_contains()'s own comma-split semantics (systemctl-util.c),
 * reimplemented narrowly rather than pulled in as a dependency for one
 * flag each. */
static bool csv_contains(const char *csv, const char *word) {
        const char *p = csv;

        while (*p) {
                const char *comma = strchr(p, ',');
                size_t len = comma ? (size_t) (comma - p) : strlen(p);

                if (len == strlen(word) && strncmp(p, word, len) == 0)
                        return true;
                if (!comma)
                        break;
                p = comma + 1;
        }
        return false;
}

static int cmd_list_units(int argc, char *argv[]) {
        char rt[PATH_MAX];
        char unitsdir[PATH_MAX + 16];
        DIR *d;
        struct dirent *de;
        char **names = NULL;
        size_t n = 0, cap = 0;
        size_t i;
        bool no_legend = false;
        const char *type_csv = NULL, *state_csv = NULL;

        /*
         * --all/-a is accepted but is a true no-op here, not a pretended
         * one: the published units/ directory this verb reads from already
         * holds every unit the live manager knows about (there is no
         * separate "inactive, hide by default" set to additionally reveal
         * -- unlike upstream, which always knows about every *installed*
         * unit file and hides the never-started ones without -a). --no-
         * pager is a no-op for the same honest reason: there is no pager
         * to ever invoke.
         *
         * --type=/--state= only, not the separate-token "-t VALUE" form:
         * main()'s own mangle_unit_arg() runs over every verb's argv
         * uniformly and would append ".service" to a bare filter value like
         * "service,target" before this function ever saw it, the same
         * collision cmd_kill()'s own comment explains for "-s VALUE".
         */
        for (i = 0; i < (size_t) argc; i++) {
                if (strcmp(argv[i], "--no-legend") == 0)
                        no_legend = true;
                else if (strncmp(argv[i], "--type=", 7) == 0)
                        type_csv = argv[i] + 7;
                else if (strncmp(argv[i], "--state=", 8) == 0)
                        state_csv = argv[i] + 8;
        }

        if (path_join(rt, sizeof(rt), PICO_RUNTIME_DIR) < 0)
                return 1;
        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rt);

        d = opendir(unitsdir);
        if (!d) {
                fprintf(stderr, "picoctl: no published state at %s: %s\n", unitsdir, strerror(errno));
                return 1;
        }

        while ((de = readdir(d))) {
                struct stat lst;

                if (de->d_name[0] == '.')
                        continue;
                /* an alias's file is a symlink to its unit's; list the unit once, as
                 * systemctl list-units does */
                if (fstatat(dirfd(d), de->d_name, &lst, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(lst.st_mode))
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

        /* real output_units_list() has a JOB column between SUB and DESCRIPTION
         * (systemctl-list-units.c table_new()); struct unit_state already
         * carries job, it was just never shown here. */
        if (!no_legend)
                printf("%-32s %-8s %-10s %-13s %-8s %s\n", "UNIT", "LOAD", "ACTIVE", "SUB", "JOB", "DESCRIPTION");
        for (i = 0; i < n; i++) {
                struct unit_state st;
                const char *suffix;

                if (type_csv && (!(suffix = unit_type_suffix(names[i])) || !csv_contains(type_csv, suffix))) {
                        free(names[i]);
                        continue;
                }

                read_unit_state(names[i], &st);

                if (state_csv && !csv_contains(state_csv, st.active_state) &&
                    !csv_contains(state_csv, st.sub_state) && !csv_contains(state_csv, st.load_state)) {
                        free(names[i]);
                        continue;
                }

                printf("%-32s %-8s %-10s %-13s %-8s %s\n",
                       names[i],
                       st.load_state,
                       st.active_state,
                       st.sub_state,
                       st.job,
                       st.description);
                free(names[i]);
        }
        free(names);

        return 0;
}

/* --- is-system-running --- */

/*
 * Real systemctl's own state machine (src/systemctl/systemctl.c
 * determine_ambiguous_result()) has more states than this -- initializing,
 * stopping, offline -- that all need info PID 1 does not publish yet
 * (a distinct pre-jobs-queued phase, a shutdown flag). What IS published is
 * enough for the two states that matter for a health check: NJobs>0 means
 * the boot's own start job (or any other job) has not settled yet, and a
 * failed unit among the published ones means degraded -- matching upstream's
 * own precedence (any job running trumps any failure, since a failure seen
 * mid-boot may still resolve). "offline" covers PID 1 not running at all
 * (no manager file), the same not-a-unit-problem case read_unit_state()'s
 * own not-found default already models for a single unit.
 *
 * An /etc/fstab line PID 1 skipped or failed to mount degrades the system
 * too, as a failed .mount unit does upstream. Those lines never become units
 * here -- the pass runs before the manager exists -- so they are read from the
 * pass's own record rather than from units/.
 */
/* Split from cmd_is_system_running() so is-failed's own no-unit case
 * (cmd_is_failed(), below) can compute and report the exact same word
 * under its own -q, rather than re-deriving "degraded" a second way. */
static int is_system_running_compute(bool quiet) {
        char rt[PATH_MAX];
        char manager_path[PATH_MAX + 16];
        char unitsdir[PATH_MAX + 16];
        FILE *f;
        char line[256];
        DIR *d;
        struct dirent *de;
        unsigned n_jobs = 0;
        bool any_failed = false;

        if (path_join(rt, sizeof(rt), PICO_RUNTIME_DIR) < 0) {
                if (!quiet)
                        printf("offline\n");
                return 1;
        }

        snprintf(manager_path, sizeof(manager_path), "%s/manager", rt);
        f = fopen(manager_path, "re");
        if (!f) {
                if (!quiet)
                        printf("offline\n");
                return 1;
        }
        while (fgets(line, sizeof(line), f)) {
                unsigned v;

                if (sscanf(line, "NJobs=%u", &v) == 1)
                        n_jobs = v;
        }
        fclose(f);

        if (n_jobs > 0) {
                if (!quiet)
                        printf("starting\n");
                return 1;
        }

        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rt);
        d = opendir(unitsdir);
        if (d) {
                while ((de = readdir(d))) {
                        struct unit_state st;

                        if (de->d_name[0] == '.')
                                continue;
                        read_unit_state(de->d_name, &st);
                        if (strcmp(st.active_state, "failed") == 0)
                                any_failed = true;
                }
                closedir(d);
        }

        if (!any_failed) {
                char record[PATH_MAX];

                if (path_join(record, sizeof(record), PICO_FSTAB_RECORD) == 0 &&
                    fstab_record_count_degraded(record) > 0)
                        any_failed = true;
        }

        if (any_failed) {
                if (!quiet)
                        printf("degraded\n");
                return 1;
        }

        if (!quiet)
                printf("running\n");
        return 0;
}

static int cmd_is_system_running(int argc, char *argv[]) {
        (void) argc;
        (void) argv;

        return is_system_running_compute(false);
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
        bool ok = false, not_found = true, quiet = false;
        int i, n_units = 0;

        for (i = 0; i < argc; i++)
                if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0)
                        quiet = true;

        for (i = 0; i < argc; i++) {
                struct unit_state st;

                if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0)
                        continue;
                n_units++;

                read_unit_state(argv[i], &st);
                if (!quiet)
                        printf("%s\n", st.active_state);

                if (st.found)
                        not_found = false;
                if (strcmp(st.active_state, want_state) == 0)
                        ok = true;
        }

        if (n_units == 0) {
                fprintf(stderr, "picoctl: missing unit name\n");
                return 1;
        }

        if (ok)
                return 0;
        return not_found ? 4 : not_this_state_code;
}

static int cmd_is_active(int argc, char *argv[]) {
        return cmd_is_state_generic(argc, argv, "active", 3); /* LSB 3: not running */
}

/*
 * With a unit argument, this is check_unit_generic() like is-active. With
 * none at all, real is-failed instead reports the manager's own SystemState
 * property (verb_is_failed(), systemctl-is-active.c) -- the exact same
 * degraded/running/... word is-system-running prints, success (exit 0)
 * only for "degraded". Reusing cmd_is_system_running()'s own computation
 * keeps the two from ever being able to disagree about what "degraded"
 * means; -q suppresses the word, never the exit code, same as the per-unit
 * case above.
 */
static int cmd_is_failed(int argc, char *argv[]) {
        bool quiet = false;
        int i, n_units = 0;

        for (i = 0; i < argc; i++) {
                if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0)
                        quiet = true;
                else
                        n_units++;
        }

        if (n_units > 0)
                return cmd_is_state_generic(argc, argv, "failed", 1); /* LSB 1: dead */

        return is_system_running_compute(quiet);
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

        /* real output_timestamp_realtime() skips the entry entirely when no
         * valid realtime timestamp exists (logs-show.c), never prints a
         * placeholder in its place. */
        if (sec <= 0 || !localtime_r(&sec, &tmv))
                return;
        strftime(timebuf, sizeof(timebuf), "%b %d %H:%M:%S", &tmv);

        printf("%s %s ", timebuf, host);

        if (ident)
                fwrite(ident->value, 1, ident->value_len, stdout);
        else if (comm)
                fwrite(comm->value, 1, comm->value_len, stdout);
        else
                fputs("unknown", stdout); /* real's fallback text (logs-show.c), not "-" */

        if (pid && !pid->binary) {
                putchar('[');
                fwrite(pid->value, 1, pid->value_len, stdout);
                putchar(']');
        }

        fputs(": ", stdout);

        if (msg && !msg->binary)
                fwrite(msg->value, 1, msg->value_len, stdout);
        else if (msg)
                printf("[%zu bytes blob data]",
                       msg->value_len); /* real's FORMAT_BYTES() wording (logs-show.c) */

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
                        /* real print_status_info() still runs the full path for a
                         * not-found unit and prints Active: too (systemctl-show.c). */
                        printf("     Active: %s (%s)\n", st.active_state, st.sub_state);
                        fprintf(stderr, "Unit %s could not be found.\n", argv[i]);
                        if (worst < 4)
                                worst = 4;
                        continue;
                }

                /* real systemctl only adds "- description" when it differs from
                 * the unit id itself (systemctl-show.c print_description()). */
                if (st.description[0] && strcmp(st.description, argv[i]) != 0)
                        printf("%s - %s\n", argv[i], st.description);
                else
                        printf("%s\n", argv[i]);
                printf("     Loaded: %s (%s; %s)\n",
                       st.load_state,
                       st.fragment_path[0] ? st.fragment_path : "n/a",
                       st.unit_file_state[0] ? st.unit_file_state : "n/a");
                /* Result folds onto the Active: line itself upstream, never a
                 * separate field (systemctl-show.c print_status_info()). */
                if (strcmp(st.result, "success") != 0)
                        printf("     Active: %s (%s) (Result: %s)\n", st.active_state, st.sub_state, st.result);
                else
                        printf("     Active: %s (%s)\n", st.active_state, st.sub_state);

                /* exit code/status is a parenthetical on Main PID itself upstream;
                 * there is no standalone "Main Exit:" field, and NRestarts is a
                 * bus property never shown in human status output at all. */
                if (st.main_pid > 0) {
                        if (st.exec_main_code[0])
                                printf("   Main PID: %d (code=%s, status=%d)\n",
                                       st.main_pid,
                                       st.exec_main_code,
                                       st.exec_main_status);
                        else
                                printf("   Main PID: %d\n", st.main_pid);
                }
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

/* --- symlink verbs: enable/disable/is-enabled/preset/mask/unmask/cat/list-unit-files --- */

/*
 * <etcdir>/<unit_id> itself (not a .wants/.requires subdirectory) is
 * `systemctl mask`'s own symlink target: a symlink there pointing at
 * /dev/null shadows the real unit everywhere, exactly as unit_find_
 * fragment() (unit-load.c) already honors at boot -- confirmed there
 * already sets UNIT_MASKED, so masking needs no engine change, only the
 * picoctl verbs to create/remove the symlink and read verbs that report it
 * correctly. Checked directly on the filesystem rather than through a
 * throwaway Manager: unlike enable/disable/preset, masking needs no
 * [Install] data and must work even for a unit no fragment exists for.
 */
static bool unit_is_masked(const char *unit_id) {
        char etcdir[PATH_MAX];
        char linkpath[PATH_MAX + 64];
        char target[16];
        ssize_t rl;

        if (path_join(etcdir, sizeof(etcdir), PICO_UNIT_DIR) < 0)
                return false;
        snprintf(linkpath, sizeof(linkpath), "%s/%s", etcdir, unit_id);

        rl = readlink(linkpath, target, sizeof(target) - 1);
        if (rl < 0)
                return false;
        target[rl] = '\0';
        return strcmp(target, "/dev/null") == 0;
}

/*
 * Current upstream's exact log_notice() wording for carries_install_info ==
 * 0 (systemctl-enable.c verb_enable()): a plain informational line on
 * stderr, not a failure -- the one real behavior bug this audit found.
 * picoctl's previous text ("...is not meant to be enabled.", exit 1) dates
 * to an older systemd where this truly was an error; current systemctl
 * enable/disable/preset on a unit with no [Install] data succeeds (exit 0)
 * and creates no symlinks, it just explains why nothing happened.
 */
static void print_no_install_info_notice(void) {
        fprintf(stderr,
                "The unit files have no installation config (WantedBy=, RequiredBy=, UpheldBy=,\n"
                "Also=, or Alias= settings in the [Install] section, and DefaultInstance= for\n"
                "template units). This means they are not meant to be enabled or disabled using systemctl.\n"
                " \n"
                "Possible reasons for having these kinds of units are:\n"
                "\xe2\x80\xa2 A unit may be statically enabled by being symlinked from another unit's\n"
                "  .wants/, .requires/, or .upholds/ directory.\n"
                "\xe2\x80\xa2 A unit's purpose may be to act as a helper for some other unit which has\n"
                "  a requirement dependency on it.\n"
                "\xe2\x80\xa2 A unit may be started when needed via activation (socket, path, timer,\n"
                "  D-Bus, udev, scripted systemctl call, ...).\n"
                "\xe2\x80\xa2 In case of template units, the unit is meant to be enabled with some\n"
                "  instance name specified.\n");
}

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
 * links the fragment itself). The actual mkdir/readlink/symlink work is
 * unit-enable.c's unit_enable_create_symlink(), shared with boot-time
 * preset persistence so the two can never disagree about what a symlink
 * looks like. Verified byte-identical to `systemctl --root enable` in the
 * verification container, absolute target included -- see test-picoctl.c.
 */
static int create_enable_symlink(const char *target, const char *suffix, Unit *u) {
        char etcdir[PATH_MAX];
        const char *frag;
        int r;

        if (path_join(etcdir, sizeof(etcdir), PICO_UNIT_DIR) < 0)
                return -ENAMETOOLONG;

        frag = strip_root(u->fragment_path);

        r = unit_enable_create_symlink(etcdir, target, suffix, u->id, frag);
        if (r < 0)
                return r;

        if (r == 1) {
                char linkpath[PATH_MAX];

                /* real install_change_dump_success() logs one line per
                 * symlink actually created, naming both paths
                 * (src/shared/install.c). */
                if (enable_symlink_path(target, suffix, u->id, linkpath, sizeof(linkpath)) == 0)
                        printf("Created symlink '%s' \xe2\x86\x92 '%s'.\n", linkpath, frag);
        }

        return 0;
}

static void remove_enable_symlink(const char *target, const char *suffix, const char *unit_id) {
        char linkpath[PATH_MAX];

        if (enable_symlink_path(target, suffix, unit_id, linkpath, sizeof(linkpath)) < 0)
                return;
        /* real install_change_dump_success() logs "Removed '%s'." per symlink
         * actually removed (src/shared/install.c); nothing to log if absent. */
        if (unlink(linkpath) == 0)
                printf("Removed '%s'.\n", linkpath);
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
                        /* NOT a failure in current upstream (see
                         * print_no_install_info_notice()'s own comment):
                         * explain and move on, exit 0. */
                        print_no_install_info_notice();
                } else if (r < 0) {
                        fprintf(stderr, "Failed to enable unit %s: %s\n", argv[i], strerror(-r));
                        status = 1;
                }
                /* no per-unit summary line: real systemctl's only output here
                 * is the per-symlink "Created symlink" lines above, if any. */

                manager_free(m);
        }

        return status;
}

/* reenable: disable then enable, in one step -- upstream's own
 * unit_file_reenable() (install.c) is exactly that pair, so this is too,
 * rather than a third parallel symlink implementation. */
static int cmd_reenable(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                fprintf(stderr, "picoctl reenable: missing unit name\n");
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

                do_disable_unit(u);
                r = do_enable_unit(u);
                if (r == -ENOEXEC)
                        print_no_install_info_notice();
                else if (r < 0) {
                        fprintf(stderr, "Failed to enable unit %s: %s\n", argv[i], strerror(-r));
                        status = 1;
                }

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

                if (!u->wanted_by && !u->required_by)
                        print_no_install_info_notice(); /* same non-error notice as enable */
                else
                        do_disable_unit(u);
                /* no per-unit summary line: real systemctl's only output here
                 * is the per-symlink "Removed" lines above, if any. */

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
                int r;
                bool this_enabled = false;

                /* Checked before load_install_info(): a masked unit fails
                 * that call (its load_state is UNIT_MASKED, never UNIT_
                 * LOADED), which used to read indistinguishably from
                 * "not-found" here -- wrong, since real is-enabled reports
                 * "masked" (and exit 1, not 4: the unit is known, just
                 * disabled by mask, which does not count as "enabled"). */
                if (unit_is_masked(argv[i])) {
                        printf("masked\n");
                        not_found = false;
                        continue;
                }

                r = load_install_info(argv[i], &m, &u);
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

                /* no per-unit summary line here either: same per-symlink
                 * "Created symlink"/"Removed" output as enable/disable. */
                if (decision == 1 || decision == -ENOENT) {
                        r = do_enable_unit(u);
                        if (r == -ENOEXEC)
                                print_no_install_info_notice(); /* same non-error notice as enable */
                        else if (r < 0) {
                                fprintf(stderr, "Failed to preset unit %s: %s\n", argv[i], strerror(-r));
                                status = 1;
                        }
                } else
                        do_disable_unit(u);

                manager_free(m);
        }

        return status;
}

/*
 * mask: a symlink at <etcdir>/<unit_id> (not under a .wants/.requires
 * subdirectory) pointing at /dev/null. Built directly on the filesystem via
 * unit-enable.c's own unit_enable_create_symlink() -- the same shared
 * helper create_enable_symlink() uses above, called with an empty
 * target/suffix pair so its "<etcdir>/<target><suffix>/<unit_id>" path
 * collapses to plain "<etcdir>/<unit_id>" -- never through a throwaway
 * Manager: masking needs no [Install] data, and must work even for a unit
 * no fragment exists for at all, exactly as real `systemctl mask` allows.
 * Idempotent: already-masked prints nothing, matching create_enable_
 * symlink()'s own "already correct" convention.
 */
static int cmd_mask(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                fprintf(stderr, "picoctl mask: missing unit name\n");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                char etcdir[PATH_MAX];
                int r;

                if (!unit_name_is_valid(argv[i])) {
                        fprintf(stderr, "Failed to mask unit: Invalid unit name \"%s\".\n", argv[i]);
                        status = 1;
                        continue;
                }

                if (path_join(etcdir, sizeof(etcdir), PICO_UNIT_DIR) < 0) {
                        status = 1;
                        continue;
                }

                r = unit_enable_create_symlink(etcdir, "", "", argv[i], "/dev/null");
                if (r < 0) {
                        fprintf(stderr, "Failed to mask unit %s: %s\n", argv[i], strerror(-r));
                        status = 1;
                        continue;
                }
                if (r == 1) {
                        char linkpath[PATH_MAX + 64];

                        snprintf(linkpath, sizeof(linkpath), "%s/%s", etcdir, argv[i]);
                        /* real install_change_dump_success() wording, same as
                         * create_enable_symlink()'s own (src/shared/install.c). */
                        printf("Created symlink '%s' \xe2\x86\x92 '/dev/null'.\n", linkpath);
                }
        }

        return status;
}

/*
 * unmask: the inverse -- unlink <etcdir>/<unit_id> only when it is really a
 * mask (points at /dev/null), never a real unit file that merely happens
 * to live directly in <etcdir>. Not masked at all is a harmless no-op,
 * matching real `systemctl unmask` on an already-unmasked unit.
 */
static int cmd_unmask(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                fprintf(stderr, "picoctl unmask: missing unit name\n");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                char etcdir[PATH_MAX];
                char linkpath[PATH_MAX + 64];

                if (!unit_is_masked(argv[i]))
                        continue;

                if (path_join(etcdir, sizeof(etcdir), PICO_UNIT_DIR) < 0) {
                        status = 1;
                        continue;
                }
                snprintf(linkpath, sizeof(linkpath), "%s/%s", etcdir, argv[i]);

                if (unlink(linkpath) == 0)
                        printf("Removed '%s'.\n", linkpath); /* install_change_dump_success()'s own wording */
                else {
                        fprintf(stderr, "Failed to unmask unit %s: %s\n", argv[i], strerror(errno));
                        status = 1;
                }
        }

        return status;
}

/*
 * cat: upstream's exact "# /path\n" header (cat_file(), src/shared/pretty-
 * print.c -- ansi_highlight_blue()/ansi_normal() are both empty off a tty,
 * which picoctl always is) followed by the fragment verbatim. A masked
 * unit gets upstream's own "# <path> is a mask." line instead of trying to
 * cat /dev/null as a unit file. pico-init has no drop-ins to also cat.
 *
 * Known gap: load_install_info() requires a fragment that actually parsed
 * (UNIT_LOADED), so `cat` on a syntactically-broken unit file reports
 * not-found rather than showing the broken content real systemctl would
 * still display -- cat is meant to work on exactly that case upstream, and
 * doesn't here; a real fragment-finding path independent of a full parse
 * would be needed to fix it properly.
 */
static int cmd_cat(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                fprintf(stderr, "picoctl cat: missing unit name\n");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                char etcdir[PATH_MAX];
                char linkpath[PATH_MAX + 64];
                Manager *m = NULL;
                Unit *u = NULL;
                int r;

                if (i > 0)
                        putchar('\n');

                if (path_join(etcdir, sizeof(etcdir), PICO_UNIT_DIR) == 0) {
                        snprintf(linkpath, sizeof(linkpath), "%s/%s", etcdir, argv[i]);
                        if (unit_is_masked(argv[i])) {
                                printf("# %s is a mask.\n", linkpath);
                                continue;
                        }
                }

                r = load_install_info(argv[i], &m, &u);
                if (r < 0) {
                        fprintf(stderr, "Failed to cat unit: Unit %s not found.\n", argv[i]);
                        status = 1;
                        continue;
                }

                printf("# %s\n", u->fragment_path);
                {
                        FILE *f = fopen(u->fragment_path, "re");
                        char buf[4096];
                        size_t got;

                        if (f) {
                                while ((got = fread(buf, 1, sizeof(buf), f)) > 0)
                                        fwrite(buf, 1, got, stdout);
                                fclose(f);
                        }
                }

                manager_free(m);
        }

        return status;
}

/* --- list-unit-files --- */

struct unit_file_entry {
        char name[256];
};

static int unit_file_entry_cmp(const void *a, const void *b) {
        return strcmp(((const struct unit_file_entry *) a)->name, ((const struct unit_file_entry *) b)->name);
}

/* Both PICO_UNIT_DIR and PICO_PACKAGED_UNIT_DIR scanned, etc-over-lib
 * dedup, same precedence manager_load_units_one_dir() (manager.c) gives
 * the real search path -- a name already recorded from a higher-priority
 * directory shadows the same name turning up in a lower one. Best-effort:
 * a dir that fails to realloc just stops growing rather than erroring the
 * whole listing. */
static void collect_unit_files_from(const char *dir, struct unit_file_entry **entries, size_t *n, size_t *cap) {
        DIR *d = opendir(dir);
        struct dirent *de;

        if (!d)
                return;

        while ((de = readdir(d))) {
                size_t i;
                bool dup = false;

                if (!unit_name_is_valid(de->d_name))
                        continue;

                for (i = 0; i < *n; i++)
                        if (strcmp((*entries)[i].name, de->d_name) == 0) {
                                dup = true;
                                break;
                        }
                if (dup)
                        continue;

                if (*n == *cap) {
                        size_t newcap = *cap ? *cap * 2 : 16;
                        struct unit_file_entry *grown = realloc(*entries, newcap * sizeof(**entries));

                        if (!grown)
                                continue;
                        *entries = grown;
                        *cap = newcap;
                }
                snprintf((*entries)[*n].name, sizeof((*entries)[*n].name), "%s", de->d_name);
                (*n)++;
        }
        closedir(d);
}

/*
 * STATE: masked (a /dev/null symlink shadows it), static (no [Install]
 * data at all -- never enabled/disabled, matches is-enabled's own
 * "static" case), or enabled/disabled, decided by whether a .wants/
 * .requires symlink exists -- the exact same check cmd_is_enabled() makes,
 * so the two verbs can never disagree. A fragment present but failed to
 * parse reads as "bad" (upstream's own UNIT_FILE_BAD). PRESET is shown
 * only for "disabled" (the one state a preset rule could still flip,
 * matching show_preset_for_state() upstream); every other row prints "-".
 */
static int cmd_list_unit_files(int argc, char *argv[]) {
        char updir[PATH_MAX], pkgdir[PATH_MAX];
        struct unit_file_entry *entries = NULL;
        size_t n = 0, cap = 0, i;
        bool no_legend = false;

        for (i = 0; i < (size_t) argc; i++)
                if (strcmp(argv[i], "--no-legend") == 0)
                        no_legend = true;

        if (path_join(updir, sizeof(updir), PICO_UNIT_DIR) == 0)
                collect_unit_files_from(updir, &entries, &n, &cap);
        if (path_join(pkgdir, sizeof(pkgdir), PICO_PACKAGED_UNIT_DIR) == 0)
                collect_unit_files_from(pkgdir, &entries, &n, &cap);

        if (entries && n > 1)
                qsort(entries, n, sizeof(*entries), unit_file_entry_cmp);

        if (!no_legend)
                printf("%-40s %-10s %s\n", "UNIT FILE", "STATE", "PRESET");

        for (i = 0; i < n; i++) {
                const char *state;
                const char *preset = "-";
                Manager *m = NULL;
                Unit *u = NULL;

                if (unit_is_masked(entries[i].name))
                        state = "masked";
                else if (load_install_info(entries[i].name, &m, &u) == 0) {
                        if (!u->wanted_by && !u->required_by)
                                state = "static";
                        else {
                                bool en = false;
                                size_t j;

                                for (j = 0; u->wanted_by && u->wanted_by[j] && !en; j++)
                                        if (enable_symlink_exists(u->wanted_by[j], ".wants", u->id))
                                                en = true;
                                for (j = 0; u->required_by && u->required_by[j] && !en; j++)
                                        if (enable_symlink_exists(u->required_by[j], ".requires", u->id))
                                                en = true;

                                if (en)
                                        state = "enabled";
                                else {
                                        int decision = manager_preset_query(m, u->id);

                                        state = "disabled";
                                        preset = (decision == 1 || decision == -ENOENT) ? "enabled" :
                                                                                          "disabled";
                                }
                        }
                        manager_free(m);
                } else
                        state = "bad";

                printf("%-40s %-10s %s\n", entries[i].name, state, preset);
        }

        if (!no_legend)
                printf("\n%zu unit files listed.\n", n);

        free(entries);
        return 0;
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

/*
 * explanations[] in bus-wait-for-jobs.c (upstream) is what
 * log_job_error_with_service_result() looks a failed job's Result property
 * up in, verbatim, to explain *why*. Every row here is a result string
 * service_result_to_string() (service.c) can actually produce -- core-
 * dump/watchdog/oom-kill exist upstream but have no pico-init ServiceResult
 * counterpart, so (as upstream's own lookup does for any result string its
 * table does not list) a result without a row here just falls through to
 * the generic message in print_job_failed() below.
 */
static const char *job_failure_explanation(const char *result) {
        static const struct {
                const char *result;
                const char *explanation;
        } table[] = {
                {       "resources",                      "of unavailable resources or another system error" },
                {        "protocol", "the service did not take the steps required by its unit configuration" },
                {         "timeout",                                                "a timeout was exceeded" },
                {       "exit-code",                            "the control process exited with error code" },
                {          "signal",                   "a fatal signal was delivered to the control process" },
                { "start-limit-hit",                          "start of the service was attempted too often" },
        };
        size_t i;

        for (i = 0; i < sizeof(table) / sizeof(table[0]); i++)
                if (strcmp(result, table[i].result) == 0)
                        return table[i].explanation;
        return NULL;
}

/* "systemctl status"/"journalctl" below are not a typo for picoctl/picolog
 * -- picoctl.c's own header explains both are ALTERNATIVES-aliased to land
 * at those exact names on a real image, so upstream's literal hint text is
 * also literally correct advice here. */
static void print_job_failed(const char *unit) {
        struct unit_state st;
        const char *expl;

        read_unit_state(unit, &st);
        expl = job_failure_explanation(st.result);
        if (expl)
                fprintf(stderr,
                        "Job for %s failed because %s.\n"
                        "See \"systemctl status %s\" and \"journalctl -xeu %s\" for details.\n",
                        unit,
                        expl,
                        unit,
                        unit);
        else
                fprintf(stderr,
                        "Job for %s failed.\n"
                        "See \"systemctl status %s\" and \"journalctl -xeu %s\" for details.\n",
                        unit,
                        unit,
                        unit);
}

/*
 * The handful of reasons manager-ctrl.c's wire protocol can send back
 * (its own header comment lists every one). "no-such-unit" has a clean
 * upstream equivalent and gets it; the rest (shutting-down, out-of-memory,
 * too-many-connections, enqueue-failed, permission-denied) are pico-init-
 * internal conditions a D-Bus-based systemctl has no equivalent single
 * error string for, so they are relayed honestly as themselves rather than
 * dressed up as an upstream quote that would not actually be one.
 */
static void print_verb_failure(const char *verb, const char *unit, const char *reason) {
        if (strcmp(reason, "no-such-unit") == 0)
                fprintf(stderr, "Failed to %s %s: Unit %s not found.\n", verb, unit, unit);
        else
                fprintf(stderr, "Failed to %s %s: %s\n", verb, unit, reason);
}

/*
 * start/stop/restart share everything except the wire verb sent to
 * manager-ctrl.c; `display_verb` is what upstream's own job_type string
 * (systemctl-start-unit.c's unit_actions[] table) would be for the verb the
 * person actually typed, which the error text uses -- for a plain verb the
 * two are the same string, for an alias (try-restart's own callers, below)
 * they differ. reset-failed (further down) does not take --no-block and
 * never fails with a job result, so it stays separate rather than a fourth
 * case squeezed in here.
 *
 * Silent on success, exit 0: real start/stop/restart print NOTHING when
 * the job finishes (or is merely queued, under --no-block) -- picoctl used
 * to printf the unit name here, which real systemctl never does.
 */
static int cmd_verb_generic(int argc, char *argv[], const char *wire_verb, const char *display_verb) {
        bool no_block = false;
        bool any_unit = false;
        int i, status = 0;

        if (argc < 1) {
                fprintf(stderr, "picoctl %s: missing unit name\n", display_verb);
                return 1;
        }

        for (i = 0; i < argc; i++)
                if (strcmp(argv[i], "--no-block") == 0)
                        no_block = true;

        for (i = 0; i < argc; i++) {
                char reply[PICOCTL_CTRL_REPLY_MAX];
                char *nl;
                const char *reason;
                int r;

                if (strcmp(argv[i], "--no-block") == 0)
                        continue;
                any_unit = true;

                r = ctrl_roundtrip(wire_verb, argv[i], no_block, reply, sizeof(reply));
                if (r < 0) {
                        /* A transport-level failure (no control socket at
                         * all, a permission problem, ...): there is no bus
                         * call to have failed, so this is picoctl's own
                         * honest wording, not a claimed upstream quote. */
                        fprintf(stderr, "Failed to %s %s: %s\n", display_verb, argv[i], strerror(-r));
                        status = 1;
                        continue;
                }

                if (strncmp(reply, "ok", 2) == 0)
                        continue; /* silent success -- see this function's own header */

                nl = strchr(reply, '\n');
                if (nl)
                        *nl = '\0';
                reason = strncmp(reply, "err ", 4) == 0 ? reply + 4 : reply;

                if (strcmp(reason, "canceled") == 0)
                        fprintf(stderr, "Job for %s canceled.\n", argv[i]);
                else if (strcmp(reason, "timeout") == 0)
                        fprintf(stderr, "Job for %s timed out.\n", argv[i]);
                else if (strcmp(reason, "failed") == 0)
                        print_job_failed(argv[i]);
                else
                        print_verb_failure(display_verb, argv[i], reason);

                status = 1;
        }

        if (!any_unit) {
                fprintf(stderr, "picoctl %s: missing unit name\n", display_verb);
                return 1;
        }

        return status;
}

static int cmd_start(int argc, char *argv[]) {
        return cmd_verb_generic(argc, argv, "start", "start");
}

static int cmd_stop(int argc, char *argv[]) {
        return cmd_verb_generic(argc, argv, "stop", "stop");
}

static int cmd_restart(int argc, char *argv[]) {
        return cmd_verb_generic(argc, argv, "restart", "restart");
}

/* condstop: legacy RH/ALTLinux alias, job_type "stop" (systemctl-start-
 * unit.c's unit_actions[] table) -- identical to plain stop. */
static int cmd_condstop(int argc, char *argv[]) {
        return cmd_verb_generic(argc, argv, "stop", "stop");
}

/*
 * try-restart (TryRestartUnit)/condrestart (its legacy RH alias, same job
 * type): restart only a unit that is currently active; an inactive one is
 * left alone, silently, exit 0 -- never started, unlike plain restart.
 *
 * The honest gap: upstream can tell "loadable, but currently inactive"
 * apart from "no such unit at all", because it resolves the unit file
 * itself before deciding. picoctl's read verbs only ever see what the live
 * manager has already published a state file for (read_unit_state()'s own
 * not-found-default comment) -- a unit that is merely unpublished (loaded
 * at boot but never yet started) reads identically to one that does not
 * exist. So a try-restart/condrestart on a name that genuinely does not
 * exist is also, here, a silent no-op rather than the "Unit not found"
 * error real systemctl would give -- a narrow, documented simplification,
 * not a pretended success.
 */
static int cmd_try_restart_as(int argc, char *argv[], const char *display_verb) {
        char **active;
        int i, n_active = 0, rc;

        if (argc < 1) {
                fprintf(stderr, "picoctl %s: missing unit name\n", display_verb);
                return 1;
        }

        active = calloc((size_t) argc, sizeof(char *));
        if (!active)
                return 1;

        for (i = 0; i < argc; i++) {
                struct unit_state st;

                if (strcmp(argv[i], "--no-block") == 0) {
                        active[n_active++] = argv[i];
                        continue;
                }

                read_unit_state(argv[i], &st);
                if (strcmp(st.active_state, "active") == 0 || strcmp(st.active_state, "activating") == 0 ||
                    strcmp(st.active_state, "reloading") == 0)
                        active[n_active++] = argv[i];
        }

        rc = n_active > 0 ? cmd_verb_generic(n_active, active, "restart", display_verb) : 0;
        free(active);
        return rc;
}

static int cmd_try_restart(int argc, char *argv[]) {
        return cmd_try_restart_as(argc, argv, "try-restart");
}

static int cmd_condrestart(int argc, char *argv[]) {
        return cmd_try_restart_as(argc, argv, "try-restart");
}

/*
 * reload-or-restart (ReloadOrRestartUnit): reload if the unit supports it,
 * else restart. ExecReload= is never implemented in pico-init (no unit
 * ever "can reload" -- see cmd_reload()'s own comment), so the "else"
 * branch is the only branch that can ever run: this always, unconditionally,
 * restarts. That is the real, faithful behavior for this engine, not a
 * shortcut -- it is upstream's own fallback, just taken every time because
 * the other branch never applies here.
 */
static int cmd_reload_or_restart(int argc, char *argv[]) {
        return cmd_verb_generic(argc, argv, "restart", "reload-or-restart");
}

/*
 * try-reload-or-restart (ReloadOrTryRestartUnit) and its three legacy
 * spellings -- reload-or-try-restart, condreload, force-reload -- all share
 * one job_type string upstream ("reload-or-try-restart",
 * systemctl-start-unit.c's unit_actions[] table) and one behavior: reload if
 * supported, else try-restart. Same reasoning as reload-or-restart() above:
 * ExecReload= never exists here, so this always takes the try-restart
 * branch.
 */
static int cmd_try_reload_or_restart(int argc, char *argv[]) {
        return cmd_try_restart_as(argc, argv, "reload-or-try-restart");
}

/*
 * reload (ReloadUnit): ExecReload= is not implemented anywhere in pico-init
 * -- no service ever reports being reloadable, and there is no JOB_RELOAD
 * in job.h to even enqueue (only START/STOP/RESTART) -- so this must fail
 * honestly, not pretend. This is exactly upstream's own error for a unit
 * with no ExecReload=: unit_can_reload() returning false maps to -EBADR,
 * which the bus layer turns into BUS_ERROR_JOB_TYPE_NOT_APPLICABLE, whose
 * text is "Job type %s is not applicable for unit %s." (src/core/
 * transaction.c) -- reachable live by running `systemctl reload` against
 * any real service with no ExecReload=.
 */
static int cmd_reload(int argc, char *argv[]) {
        int i;

        if (argc < 1) {
                fprintf(stderr, "picoctl reload: missing unit name\n");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                if (strcmp(argv[i], "--no-block") == 0)
                        continue;
                fprintf(stderr,
                        "Failed to reload %s: Job type reload is not applicable for unit %s.\n",
                        argv[i],
                        argv[i]);
        }

        return 1;
}

static int cmd_reset_failed(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                fprintf(stderr, "picoctl reset-failed: missing unit name\n");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                char reply[PICOCTL_CTRL_REPLY_MAX];
                char *nl;
                int r = ctrl_roundtrip("reset-failed", argv[i], false, reply, sizeof(reply));

                if (r < 0) {
                        fprintf(stderr, "Failed to reset failed state of unit %s: %s\n", argv[i], strerror(-r));
                        status = 1;
                        continue;
                }

                if (strncmp(reply, "ok", 2) == 0)
                        continue; /* silent success, like every other action verb */

                nl = strchr(reply, '\n');
                if (nl)
                        *nl = '\0';
                fprintf(stderr,
                        "Failed to reset failed state of unit %s: %s\n",
                        argv[i],
                        strncmp(reply, "err ", 4) == 0 ? reply + 4 : reply);
                status = 1;
        }

        return status;
}

/*
 * daemon-reload: the one action verb with no unit argument at all. manager-
 * ctrl.c's wire grammar for it is just "PICO1 daemon-reload" (see its own
 * header), so this talks the socket directly rather than through
 * ctrl_roundtrip(), which always sends a unit token. Silent on success,
 * exit 0, matching daemon_reload()'s own bare `return 0;` on success
 * (systemctl-daemon-reload.c) -- and its error text, "%s daemon failed:
 * %s" with method "Reload", i.e. "Reload daemon failed: %s".
 */
static int cmd_daemon_reload(int argc, char *argv[]) {
        static const char line[] = "PICO1 daemon-reload";
        char reply[PICOCTL_CTRL_REPLY_MAX];
        int fd;
        ssize_t r;

        (void) argv;
        if (argc > 0) {
                fprintf(stderr, "picoctl: daemon-reload takes no arguments\n");
                return 1;
        }

        fd = ctrl_connect();
        if (fd < 0) {
                fprintf(stderr, "Reload daemon failed: %s\n", strerror(-fd));
                return 1;
        }

        r = send(fd, line, sizeof(line) - 1, MSG_NOSIGNAL);
        if (r < 0) {
                fprintf(stderr, "Reload daemon failed: %s\n", strerror(errno));
                close(fd);
                return 1;
        }

        r = recv(fd, reply, sizeof(reply) - 1, 0);
        close(fd);
        if (r < 0) {
                fprintf(stderr, "Reload daemon failed: %s\n", strerror(errno));
                return 1;
        }
        reply[r] = '\0';

        if (strncmp(reply, "ok", 2) == 0)
                return 0;

        {
                char *nl = strchr(reply, '\n');

                if (nl)
                        *nl = '\0';
        }
        fprintf(stderr, "Reload daemon failed: %s\n", strncmp(reply, "err ", 4) == 0 ? reply + 4 : reply);
        return 1;
}

/*
 * kill (KillUnit): signal the unit's processes directly. Self-contained in
 * picoctl rather than a new manager-ctrl.c wire verb -- everything it needs
 * (the published MainPID, the cgroup's cgroup.procs) is already read-only
 * state picoctl already reads for `status` (print_cgroup_procs()), so no
 * engine change is needed to make this real rather than a no-op.
 *
 * --kill-who=all (upstream's own default) signals every pid in the unit's
 * cgroup; --kill-who=main signals only the published MainPID. --signal/-s
 * takes SIGTERM (upstream's default), SIGKILL, SIGHUP, SIGINT or a bare
 * number -- the signals this project's own units actually get sent
 * (manager-loop.c, service.c); anything else is refused rather than guessed
 * at.
 */
static int signal_from_name(const char *s, int *ret) {
        if (strcmp(s, "SIGTERM") == 0 || strcmp(s, "TERM") == 0) {
                *ret = SIGTERM;
                return 0;
        }
        if (strcmp(s, "SIGKILL") == 0 || strcmp(s, "KILL") == 0) {
                *ret = SIGKILL;
                return 0;
        }
        if (strcmp(s, "SIGHUP") == 0 || strcmp(s, "HUP") == 0) {
                *ret = SIGHUP;
                return 0;
        }
        if (strcmp(s, "SIGINT") == 0 || strcmp(s, "INT") == 0) {
                *ret = SIGINT;
                return 0;
        }
        if (s[0] >= '0' && s[0] <= '9') {
                *ret = atoi(s);
                return *ret > 0 ? 0 : -EINVAL;
        }
        return -EINVAL;
}

static int cmd_kill(int argc, char *argv[]) {
        int sig = SIGTERM;
        bool kill_main_only = false;
        int i, status = 0;
        bool any_unit = false;

        /*
         * --signal=NAME only, not the two-token "-s NAME" form: main()'s
         * own unit-name auto-mangling (mangle_unit_arg()) runs over every
         * verb's argv uniformly and would append ".service" to a bare
         * signal name like "KILL" before cmd_kill() ever saw it, since
         * mangle_unit_arg() only skips arguments that already start with
         * '-' or contain '.' -- true of "--signal=KILL" but not of a
         * separate "KILL" token. Documented here rather than worked around
         * by special-casing kill's own argv in main(), which every other
         * verb shares.
         */
        for (i = 0; i < argc; i++) {
                if (strncmp(argv[i], "--signal=", 9) == 0) {
                        if (signal_from_name(argv[i] + 9, &sig) < 0) {
                                fprintf(stderr, "picoctl kill: unknown signal '%s'\n", argv[i] + 9);
                                return 1;
                        }
                } else if (strcmp(argv[i], "--kill-who=main") == 0)
                        kill_main_only = true;
                else if (strcmp(argv[i], "--kill-who=all") == 0)
                        kill_main_only = false;
        }

        for (i = 0; i < argc; i++) {
                struct unit_state st;
                char cgroup_root[PATH_MAX];
                char path[PATH_MAX + 64];
                FILE *f;
                char line[32];
                bool signalled_anything = false;

                if (argv[i][0] == '-' || argv[i][0] == '\0')
                        continue;
                any_unit = true;

                read_unit_state(argv[i], &st);
                if (!st.found) {
                        fprintf(stderr, "Failed to kill unit %s: Unit %s not loaded.\n", argv[i], argv[i]);
                        status = 1;
                        continue;
                }

                if (kill_main_only || st.main_pid <= 0) {
                        if (st.main_pid > 0) {
                                if (kill(st.main_pid, sig) == 0)
                                        signalled_anything = true;
                        }
                } else if (path_join(cgroup_root, sizeof(cgroup_root), PICO_CGROUP_ROOT) == 0) {
                        snprintf(path, sizeof(path), "%s/system.slice/%s/cgroup.procs", cgroup_root, argv[i]);
                        f = fopen(path, "re");
                        if (f) {
                                while (fgets(line, sizeof(line), f)) {
                                        pid_t pid = (pid_t) atoi(line);

                                        if (pid > 0 && kill(pid, sig) == 0)
                                                signalled_anything = true;
                                }
                                fclose(f);
                        }
                }

                /* Nothing running is a harmless no-op upstream too (killing
                 * an empty cgroup signals zero processes, successfully). */
                (void) signalled_anything;
        }

        if (!any_unit) {
                fprintf(stderr, "picoctl kill: missing unit name\n");
                return 1;
        }

        return status;
}

/* --- main --- */

static void usage(void) {
        fprintf(stderr,
                "usage: picoctl [--root DIR] [VERB] [UNIT...] [--no-block]\n"
                "verbs: status list-units list-unit-files is-active is-failed is-system-running\n"
                "       show cat enable disable reenable is-enabled preset mask unmask\n"
                "       start stop restart try-restart condrestart condstop reload\n"
                "       reload-or-restart try-reload-or-restart reload-or-try-restart\n"
                "       condreload force-reload kill reset-failed daemon-reload\n"
                "       reboot poweroff halt\n"
                "no VERB: same as list-units\n"
                "invoked as reboot/poweroff/halt/shutdown (no verb): same, immediately\n");
}

/*
 * Real systemctl auto-appends ".service" to a bare unit name with no type
 * suffix (unit_name_mangle() in systemd's own src/shared/unit-name.c).
 * picoctl never did this: unit-name.c's unit_name_is_valid() requires a
 * recognised suffix and every verb below passes argv straight through to it
 * (via manager_load_unit(), load_install_info(), ctrl_roundtrip(), ...), so
 * "picoctl status bt-pan-client" looked for a unit literally named
 * "bt-pan-client" and reported not-found even with bt-pan-client.service
 * genuinely installed. Confirmed live on h2200 -- status, start and restart
 * all hit this identically, for bt-pan-client, usb-multi-gadget and gpe-dm.
 *
 * Returns NULL (meaning: use `arg` unchanged) for anything that is not a
 * bare identifier -- a flag (leading '-'), or an argument that already names
 * a type (contains '.': foo.service, a glob pattern, foo.target...). A
 * caller-owned, malloc'd ".service"-suffixed copy otherwise.
 */
static char *mangle_unit_arg(const char *arg) {
        char *out;
        size_t len;

        if (!arg || arg[0] == '-' || strchr(arg, '.'))
                return NULL;

        len = strlen(arg);
        out = malloc(len + sizeof(".service"));
        if (!out)
                return NULL;

        memcpy(out, arg, len);
        memcpy(out + len, ".service", sizeof(".service"));
        return out;
}

/*
 * reboot/poweroff/halt/shutdown: a deliberate simplification, not what real
 * systemctl/reboot(8)/halt(8) actually do -- those go logind first, then a
 * D-Bus StartUnit on halt/poweroff/reboot.target, and only reach a raw
 * syscall with --force (src/systemctl/systemctl-compat-halt.c). kill(1, sig)
 * is PID 1's own signal convention (manager-loop.c's manager_dispatch_
 * signal(): SIGINT -> MANAGER_REBOOT, SIGRTMIN+3/+4 -> MANAGER_POWEROFF,
 * matching manager.c's target_table), reachable by anyone sending it, not
 * something systemctl itself calls -- picoctl goes straight there since it
 * has no logind/D-Bus to call through. No --force/--wtmp-only/--no-wall
 * flags either: every invocation acts immediately regardless (see usage()).
 *
 * /sbin/reboot, /sbin/poweroff, /sbin/halt and /sbin/shutdown are meant to
 * be ALTERNATIVE-aliased straight at this binary (the recipe's own
 * ALTERNATIVE_TARGET[reboot] etc., same mechanism as systemctl itself) --
 * main() below dispatches on argv[0]'s basename before any verb parsing,
 * exactly as real systemctl does for these same four names.
 */
static int send_pid1_signal(int sig, const char *what) {
        if (kill(1, sig) < 0) {
                fprintf(stderr, "picoctl: %s: kill(1, %d): %s\n", what, sig, strerror(errno));
                return 1;
        }
        return 0;
}

static int cmd_reboot(int argc, char *argv[]) {
        (void) argc;
        (void) argv;
        return send_pid1_signal(SIGINT, "reboot");
}

static int cmd_poweroff(int argc, char *argv[]) {
        (void) argc;
        (void) argv;
        return send_pid1_signal(SIGRTMIN + 4, "poweroff");
}

static int cmd_halt(int argc, char *argv[]) {
        (void) argc;
        (void) argv;
        return send_pid1_signal(SIGRTMIN + 3, "halt");
}

/*
 * No scheduler and no wall(1) broadcast exist here -- `shutdown` only ever
 * accepts the immediate case, same spirit as every other "not implemented,
 * refuse rather than silently do something else" choice in this codebase.
 * -h/-P means poweroff (the default, matching real shutdown(8)), -r reboot.
 */
static int cmd_shutdown(int argc, char *argv[]) {
        bool do_reboot = false;
        int i;

        for (i = 0; i < argc; i++) {
                if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--reboot") == 0)
                        do_reboot = true;
                else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-P") == 0 ||
                         strcmp(argv[i], "--poweroff") == 0)
                        do_reboot = false;
                else if (strcmp(argv[i], "now") == 0)
                        continue;
                else {
                        fprintf(stderr,
                                "picoctl: shutdown: no scheduler or wall message here, only "
                                "'shutdown [-r|-h|-P] [now]'\n");
                        return 1;
                }
        }

        return do_reboot ? cmd_reboot(0, NULL) : cmd_poweroff(0, NULL);
}

int main(int argc, char *argv[]) {
        static const struct {
                const char *name;
                int (*fn)(int, char **);
        } verbs[] = {
                {                "status",                cmd_status },
                {            "list-units",            cmd_list_units },
                {       "list-unit-files",       cmd_list_unit_files },
                {             "is-active",             cmd_is_active },
                {             "is-failed",             cmd_is_failed },
                {                 "check",             cmd_is_active }, /* deprecated alias, same job */
                {     "is-system-running",     cmd_is_system_running },
                {                  "show",                  cmd_show },
                {                   "cat",                   cmd_cat },
                {                "enable",                cmd_enable },
                {              "reenable",              cmd_reenable },
                {               "disable",               cmd_disable },
                {            "is-enabled",            cmd_is_enabled },
                {                "preset",                cmd_preset },
                {                  "mask",                  cmd_mask },
                {                "unmask",                cmd_unmask },
                {                 "start",                 cmd_start },
                {                  "stop",                  cmd_stop },
                {              "condstop",              cmd_condstop }, /* legacy alias of stop */
                {               "restart",               cmd_restart },
                {           "try-restart",           cmd_try_restart },
                {           "condrestart",           cmd_condrestart }, /* legacy alias of try-restart */
                {     "reload-or-restart",     cmd_reload_or_restart },
                { "try-reload-or-restart", cmd_try_reload_or_restart },
                { "reload-or-try-restart", cmd_try_reload_or_restart }, /* legacy spelling, systemctl <= 228  */
                {            "condreload", cmd_try_reload_or_restart }, /* legacy alias, ALTLinux */
                {          "force-reload", cmd_try_reload_or_restart }, /* legacy alias, SysV */
                {                "reload",                cmd_reload },
                {                  "kill",                  cmd_kill },
                {          "reset-failed",          cmd_reset_failed },
                {         "daemon-reload",         cmd_daemon_reload },
                {                "reboot",                cmd_reboot },
                {              "poweroff",              cmd_poweroff },
                {                  "halt",                  cmd_halt },
                /*
                 * Deliberately NOT in this table, so they fall through to
                 * "Unknown command verb" below rather than a pretended
                 * success: get-default/set-default (no persisted "default
                 * target" concept exists -- manager_startup()'s own
                 * default_target is a boot-time argument, never written or
                 * read back by picoctl) and isolate (would need a JOB_
                 * ISOLATE job.h does not have, and the all-other-units-stop
                 * transaction semantics that go with it -- out of scope
                 * for this milestone, not merely unimplemented by oversight).
                 * daemon-reexec, set-environment/unset-environment/show-
                 * environment, edit, link, add-wants/add-requires,
                 * list-dependencies/list-jobs/list-sockets/list-timers/
                 * list-machines, and the various service-log-level/
                 * watchdog/bind/mount-image/set-property verbs: no faithful
                 * backing in pico-init at all (no D-Bus properties to set,
                 * no sockets/timers/mounts tracked the way those verbs need).
                 */
        };
        const char *prog0;
        int argi = 1;
        size_t i;

        /* argv[0] dispatch, before --root/verb parsing: a real reboot(8)/
         * poweroff(8)/halt(8)/shutdown(8) invocation never passes a verb. */
        prog0 = strrchr(argv[0], '/');
        prog0 = prog0 ? prog0 + 1 : argv[0];
        if (strcmp(prog0, "reboot") == 0)
                return cmd_reboot(argc - 1, argv + 1);
        if (strcmp(prog0, "poweroff") == 0)
                return cmd_poweroff(argc - 1, argv + 1);
        if (strcmp(prog0, "halt") == 0)
                return cmd_halt(argc - 1, argv + 1);
        if (strcmp(prog0, "shutdown") == 0)
                return cmd_shutdown(argc - 1, argv + 1);

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
                if (strcmp(argv[argi], "--version") == 0) {
                        printf("picoctl " PICO_INIT_VERSION_STRING
                               " (pico-init; not systemd, see picoctl.c)\n");
                        return 0;
                }
                if (strcmp(argv[argi], "--help") == 0 || strcmp(argv[argi], "-h") == 0) {
                        usage();
                        return 0;
                }
                break;
        }

        /* No verb at all: VERB_DEFAULT upstream (systemctl.c's own verb
         * table) is list-units, not an error -- bare `systemctl` lists
         * units, it does not print usage and fail. */
        if (argi >= argc)
                return cmd_list_units(0, NULL);

        for (i = 0; i < sizeof(verbs) / sizeof(verbs[0]); i++)
                if (strcmp(argv[argi], verbs[i].name) == 0) {
                        int n = argc - argi - 1;
                        char **orig = argv + argi + 1;
                        char **mangled;
                        int rc, j;

                        mangled = n > 0 ? calloc((size_t) n, sizeof(char *)) : NULL;
                        if (n > 0 && !mangled)
                                return verbs[i].fn(n, orig); /* OOM: fall back unmangled */

                        for (j = 0; j < n; j++) {
                                char *m = mangle_unit_arg(orig[j]);
                                mangled[j] = m ? m : orig[j];
                        }

                        rc = verbs[i].fn(n, n > 0 ? mangled : orig);

                        for (j = 0; j < n; j++)
                                if (mangled[j] != orig[j])
                                        free(mangled[j]);
                        free(mangled);

                        return rc;
                }

        /* Exact upstream wording and exit code (src/shared/verbs.c
         * dispatch_verb()): "Unknown command verb 'X'.", no usage dump --
         * real systemctl does not print its help text on a typo either. */
        fprintf(stderr, "Unknown command verb '%s'.\n", argv[argi]);
        return 1;
}
