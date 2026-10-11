/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * picoctl -- the on-device systemctl equivalent.
 *
 * Three independent parts. Read verbs (status/list-units/is-active/is-failed/
 * show) source purely from the state files manager-state.c publishes
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
 * root and without touching the host's real /etc.
 *
 * start/stop/restart/reset-failed are the third part: a client for
 * manager-ctrl.c's control socket. They are the only verbs that need a live,
 * unwedged manager; the others keep working when PID 1's loop is stuck, which
 * is why they are files rather than IPC.
 */

/* accept4()'s AF_UNIX peers pull in struct sockaddr_un; -std=gnu17 alone
 * does not imply _GNU_SOURCE for every glibc extension this needs
 * (manager-ctrl.c's own note), so this has to be explicit and first. */
#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
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
#include "pico-color.h"
#include "status.h"
#include "unit-enable.h"
#include "unit.h"

/* --- colour helpers ---
 *
 * Every accessor below (pico_ansi_*()) returns "" when colours are off, so
 * every call site that uses them degrades to plain text
 * with no branching of its own -- same contract pico-color.h documents for
 * netctl/picolog.
 *
 * picoctl_error()/picoctl_notice() mirror systemctl's stderr colouring
 * (write_to_console(), src/basic/log.c): the colour wraps the message text
 * only and is reset before the line's trailing newline. get_log_colors()
 * (src/basic/terminal-util.c) colours LOG_ERR messages red and LOG_NOTICE
 * messages bold/white. LOG_INFO messages, such as the per-symlink "Created
 * symlink" lines, stay uncoloured, so picoctl prints those plain.
 */
static void picoctl_error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void picoctl_notice(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void picoctl_error(const char *fmt, ...) {
        va_list ap;

        fputs(pico_ansi_highlight_red(), stderr);
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fputs(pico_ansi_normal(), stderr);
        fputc('\n', stderr);
}

static void picoctl_notice(const char *fmt, ...) {
        va_list ap;

        fputs(pico_ansi_highlight(), stderr);
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        fputs(pico_ansi_normal(), stderr);
        fputc('\n', stderr);
}

/* systemctl status's own default depth for the embedded log tail (-n/--lines
 * overrides it, see the getopt_long table below). */
#define PICOCTL_STATUS_LOG_LINES 10

/* --- global options ---
 *
 * One getopt_long() pass over the whole command line, in main(), fills
 * these in before any verb runs -- matching systemctl's single flat option
 * parser (systemctl_parse_argv()): an option is global, so it may appear
 * before, between or after the verb and unit arguments. Each cmd_*() reads
 * the variable it needs directly rather than re-scanning its own argv.
 */
static const char *arg_root = "";
static bool arg_no_block = false;
static bool arg_no_legend = false;
static bool arg_quiet = false;
static const char *arg_type = NULL;
static const char *arg_state = NULL;
static unsigned arg_lines = PICOCTL_STATUS_LOG_LINES;
static const char *arg_signal_name = NULL;
static const char *arg_kill_who = "all";

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
 * path, not one still carrying X (see test-picoctl.c). */
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
 * A missing file means the manager never published this unit (it was never
 * loaded) or PID 1 is not running. Both read as systemd's "not-found": 0 with
 * *st left at its not-found defaults, never a hard failure.
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

/* Defined below, next to cmd_is_enabled() which it also backs: one
 * source of truth for "is this unit enabled on disk", read fresh every
 * call rather than out of the manager's own load-time snapshot. */
static const char *compute_unit_file_state(const char *unit_id);

static int cmd_show(int argc, char *argv[]) {
        int i;

        if (argc < 1) {
                picoctl_error("picoctl show: missing unit name");
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
                        /* Every field prints byte-for-byte from the
                         * manager's published file, except UnitFileState:
                         * that one field is re-derived live, same as
                         * is-enabled, rather than trusted from the file --
                         * the file only reflects the enablement state as
                         * of this unit's *load* time, and a later `picoctl
                         * disable`/enable never rewrites it. */
                        char line[1024];
                        const char *live_ufs = compute_unit_file_state(argv[i]);

                        while (fgets(line, sizeof(line), f)) {
                                if (strncmp(line, "UnitFileState=", 14) == 0)
                                        printf("UnitFileState=%s\n", live_ufs);
                                else
                                        fputs(line, stdout);
                        }
                }
                fclose(f);
        }

        return 0;
}

/* --- list-units --- */

static int name_cmp(const void *a, const void *b) {
        return strcmp(*(const char * const *) a, *(const char * const *) b);
}

/* "foo.service" -> "service"; NULL for a name with no '.'. */
static const char *unit_type_suffix(const char *name) {
        const char *dot = strrchr(name, '.');

        return dot ? dot + 1 : NULL;
}

/* One substring of a comma-separated --type=/--state= value matches `word`
 * exactly. */
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

/*
 * Per-field colouring as in output_units_list() (systemctl-list-units.c),
 * minus the glyph/underline columns: on_loaded colours LOAD, on_active colours both UNIT and
 * ACTIVE, on_sub colours SUB. load_state and active_state are decided
 * independently, as upstream computes on_loaded/on_active.
 */
static void list_units_row_colors(
                const char *unit_id,
                const char *load_state,
                const char *active_state,
                const char *sub_state,
                const char **on_loaded,
                const char **off_loaded,
                const char **on_active,
                const char **off_active,
                const char **on_sub,
                const char **off_sub) {
        const char *normal = pico_ansi_normal();
        const char *suffix;

        *on_loaded = *off_loaded = *on_active = *off_active = *on_sub = *off_sub = "";

        if (strcmp(load_state, "not-found") == 0)
                *on_loaded = pico_ansi_highlight_yellow();
        else if (strcmp(load_state, "error") == 0 || strcmp(load_state, "masked") == 0)
                *on_loaded = pico_ansi_highlight_red();
        if ((*on_loaded)[0])
                *off_loaded = normal;

        if (strcmp(active_state, "failed") == 0)
                *on_active = pico_ansi_highlight_red();
        else if (strcmp(active_state, "activating") == 0 || strcmp(active_state, "deactivating") == 0 ||
                 strcmp(active_state, "reloading") == 0 || strcmp(active_state, "refreshing") == 0)
                *on_active = pico_ansi_highlight();
        else if (strcmp(active_state, "inactive") == 0)
                *on_active = pico_ansi_grey();
        *on_sub = *on_active;
        if ((*on_active)[0])
                *off_active = *off_sub = normal;

        /* "greyed-out exited service" special case: only when active_state
         * itself left SUB uncoloured above. */
        suffix = unit_type_suffix(unit_id);
        if (!(*on_sub)[0] && suffix && strcmp(suffix, "service") == 0 && strcmp(sub_state, "exited") == 0) {
                *on_sub = pico_ansi_grey();
                *off_sub = normal;
        }
}

static int cmd_list_units(int argc, char *argv[]) {
        char rt[PATH_MAX];
        char unitsdir[PATH_MAX + 16];
        DIR *d;
        struct dirent *de;
        char **names = NULL;
        size_t n = 0, cap = 0;
        size_t i;
        const char *type_csv = arg_type, *state_csv = arg_state;

        /* every option this verb takes is global */
        (void) argc;
        (void) argv;

        /*
         * --all/-a is accepted but a no-op: the published units/ directory
         * already holds every unit the live manager knows about, with no
         * hidden "inactive" set to reveal. --no-pager is a no-op because
         * there is no pager.
         *
         * --type/--state come from main()'s getopt_long() pass (arg_type/
         * arg_state), so both "--type=VALUE" and "-t VALUE" work.
         */

        if (path_join(rt, sizeof(rt), PICO_RUNTIME_DIR) < 0)
                return 1;
        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rt);

        d = opendir(unitsdir);
        if (!d) {
                picoctl_error("picoctl: no published state at %s: %s", unitsdir, strerror(errno));
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
         * (systemctl-list-units.c table_new()). */
        if (!arg_no_legend)
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

                {
                        const char *on_loaded, *off_loaded, *on_active, *off_active, *on_sub, *off_sub;

                        list_units_row_colors(
                                        names[i],
                                        st.load_state,
                                        st.active_state,
                                        st.sub_state,
                                        &on_loaded,
                                        &off_loaded,
                                        &on_active,
                                        &off_active,
                                        &on_sub,
                                        &off_sub);

                        printf("%s%-32s%s %s%-8s%s %s%-10s%s %s%-13s%s %-8s %s\n",
                               on_active,
                               names[i],
                               off_active,
                               on_loaded,
                               st.load_state,
                               off_loaded,
                               on_active,
                               st.active_state,
                               off_active,
                               on_sub,
                               st.sub_state,
                               off_sub,
                               st.job,
                               st.description);
                }
                free(names[i]);
        }
        free(names);

        return 0;
}

/* --- is-system-running --- */

/*
 * systemctl's state machine (src/systemctl/systemctl.c
 * determine_ambiguous_result()) has more states than this -- initializing,
 * stopping -- that need info PID 1 does not publish (a pre-jobs-queued phase,
 * a shutdown flag). What is published covers the states a health check needs:
 * NJobs>0 means a job has not settled yet, and a failed unit means degraded,
 * with upstream's precedence (a running job trumps a failure, since a failure
 * seen mid-boot may still resolve). "offline" is PID 1 not running (no
 * manager file).
 *
 * An /etc/fstab line PID 1 skipped or failed to mount degrades the system
 * too, as a failed .mount unit does upstream. Those lines never become units
 * here -- the pass runs before the manager exists -- so they are read from the
 * pass's own record rather than from units/.
 *
 * Manager-file fields both this and the system-status overview need
 * (manager-state.c's manager_state_notify_manager()): read once, here, so
 * the two can never parse "NUnits="/"NJobs=" two different ways.
 */
struct manager_state_info {
        bool found;
        unsigned n_units;
        unsigned n_jobs;
};

static void read_manager_state(const char *runtime_dir, struct manager_state_info *out) {
        char path[PATH_MAX + 16];
        FILE *f;
        char line[256];

        memset(out, 0, sizeof(*out));

        snprintf(path, sizeof(path), "%s/manager", runtime_dir);
        f = fopen(path, "re");
        if (!f)
                return;
        out->found = true;

        while (fgets(line, sizeof(line), f)) {
                unsigned v;

                if (sscanf(line, "NUnits=%u", &v) == 1)
                        out->n_units = v;
                else if (sscanf(line, "NJobs=%u", &v) == 1)
                        out->n_jobs = v;
        }
        fclose(f);
}

/* The one scan for ActiveState=failed under <runtime>/units -- shared by
 * is_system_running_compute()'s any-failed check and the system-status
 * overview's own "Failed: N units" row, so the two never drift apart. */
static unsigned count_failed_units(const char *units_dir) {
        DIR *d = opendir(units_dir);
        struct dirent *de;
        unsigned n = 0;

        if (!d)
                return 0;

        while ((de = readdir(d))) {
                struct unit_state st;

                if (de->d_name[0] == '.')
                        continue;
                read_unit_state(de->d_name, &st);
                if (strcmp(st.active_state, "failed") == 0)
                        n++;
        }
        closedir(d);
        return n;
}

/* Print `word` unless quiet, copy it to word_out when the caller wants it
 * (print_system_status()'s "State:" row does; is-system-running/is-failed's
 * own plain output does not), return systemd's own exit code for it. */
static int report_running_word(bool quiet, char *word_out, size_t word_out_size, const char *word, int code) {
        if (!quiet)
                printf("%s\n", word);
        if (word_out && word_out_size)
                snprintf(word_out, word_out_size, "%s", word);
        return code;
}

/* Split from cmd_is_system_running() so is-failed's own no-unit case
 * (cmd_is_failed(), below) and print_system_status()'s "State:" row
 * can all read and report the exact same word, rather than re-deriving
 * "degraded" a second way. word_out/word_out_size are optional (NULL/0): the
 * two LSB-exit-code callers below don't need the word back, only its exit
 * code and (unless quiet) its stdout line. */
static int is_system_running_compute(bool quiet, char *word_out, size_t word_out_size) {
        char rt[PATH_MAX];
        char unitsdir[PATH_MAX + 16];
        struct manager_state_info ms;
        bool any_failed;

        if (path_join(rt, sizeof(rt), PICO_RUNTIME_DIR) < 0)
                return report_running_word(quiet, word_out, word_out_size, "offline", 1);

        read_manager_state(rt, &ms);
        if (!ms.found)
                return report_running_word(quiet, word_out, word_out_size, "offline", 1);

        if (ms.n_jobs > 0)
                return report_running_word(quiet, word_out, word_out_size, "starting", 1);

        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rt);
        any_failed = count_failed_units(unitsdir) > 0;

        if (!any_failed) {
                char record[PATH_MAX];

                if (path_join(record, sizeof(record), PICO_FSTAB_RECORD) == 0 &&
                    fstab_record_count_degraded(record) > 0)
                        any_failed = true;
        }

        if (any_failed)
                return report_running_word(quiet, word_out, word_out_size, "degraded", 1);

        return report_running_word(quiet, word_out, word_out_size, "running", 0);
}

static int cmd_is_system_running(int argc, char *argv[]) {
        (void) argc;
        (void) argv;

        return is_system_running_compute(false, NULL, 0);
}

/* --- is-active / is-failed: LSB init-script exit codes --- */

/*
 * Shared by both verbs, as upstream's check_unit_generic() is: both print
 * every unit's ActiveState and use the same "any counts, then not-found, then
 * the LSB code" exit logic; only the target state and the LSB code differ. LSB (via
 * systemctl-util.h in the real source): 0 running/ok, 1 dead, 3 not
 * running, 4 status unknown (unit never published == not-found here).
 */
static int cmd_is_state_generic(int argc, char *argv[], const char *want_state, int not_this_state_code) {
        bool ok = false, not_found = true;
        int i;

        /* -q/--quiet is global (arg_quiet, from main()'s getopt_long() pass)
         * and never reaches this argv, so every entry here is a unit name. */
        if (argc == 0) {
                picoctl_error("picoctl: missing unit name");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                struct unit_state st;

                read_unit_state(argv[i], &st);
                if (!arg_quiet)
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

/*
 * With a unit argument, this is check_unit_generic() like is-active. With
 * none, real is-failed reports the manager's SystemState property
 * (verb_is_failed(), systemctl-is-active.c): the same degraded/running/...
 * word is-system-running prints, exit 0 only for "degraded", computed by the
 * same code so the two cannot disagree. -q suppresses the word, never the
 * exit code. arg_quiet is global (main()'s getopt_long() pass), so argc here
 * counts only unit names.
 */
static int cmd_is_failed(int argc, char *argv[]) {
        if (argc > 0)
                return cmd_is_state_generic(argc, argv, "failed", 1); /* LSB 1: dead */

        return is_system_running_compute(arg_quiet, NULL, 0);
}

/* --- status --- */

/*
 * Tree glyphs, byte for byte from upstream's glyph-util.c UTF-8 table
 * (GLYPH_TREE_BRANCH/_RIGHT/_VERTICAL), which cgroup-show.c draws with.
 * Upstream falls back to ASCII "`-"/"|-" by locale/$TERM (glyph_full()); this
 * always emits UTF-8.
 */
#define PICOCTL_TREE_BRANCH "\xe2\x94\x9c\xe2\x94\x80" /* UTF8("├─") */
#define PICOCTL_TREE_RIGHT "\xe2\x94\x94\xe2\x94\x80"  /* UTF8("└─") */
#define PICOCTL_TREE_VERTICAL "\xe2\x94\x82 "          /* UTF8("│ ") */

/*
 * The cgroup walk reads live cgroupfs state of a shape nothing here controls
 * (a misbehaving delegate could nest arbitrarily), hence caps on depth, on
 * children read per directory, and on total lines printed. Upstream has none.
 */
#define PICOCTL_CGROUP_MAX_DEPTH 8
#define PICOCTL_CGROUP_MAX_CHILDREN 256
#define PICOCTL_CGROUP_MAX_LINES 4096

static unsigned cgroup_lines_printed;

/* Mirrors upstream's cg_is_empty() (src/basic/cgroup-util.c), so dead
 * cgroups left on disk do not clutter the tree. The "populated" field of
 * cgroup.events is recursive (1 if this cgroup or any descendant holds a live
 * process), so one read decides whether to show and recurse into a child.
 * Missing cgroup.events (ENOENT, as upstream) means empty: a child
 * mid-removal is not one to show. */
static bool cgroup_is_populated(const char *path) {
        char events_path[PATH_MAX + 32];
        FILE *f;
        char line[64];
        bool populated = false;

        snprintf(events_path, sizeof(events_path), "%s/cgroup.events", path);
        f = fopen(events_path, "re");
        if (!f)
                return false;

        while (fgets(line, sizeof(line), f)) {
                int v;

                if (sscanf(line, "populated %d", &v) == 1) {
                        populated = v != 0;
                        break;
                }
        }
        fclose(f);
        return populated;
}

/* strlen+memcpy+clamp, not snprintf(dir "/" name): `name` is a dirent's
 * fixed-size d_name (cgroupfs child names are workload-controlled), which
 * gcc -Os's format-truncation check flags; a child that does not fit is
 * skipped rather than truncated into a wrong path. */
static bool cgroup_path_join(char *out, size_t out_size, const char *dir, const char *name) {
        size_t dlen = strlen(dir), nlen = strlen(name);

        if (dlen + 1 + nlen + 1 > out_size)
                return false;
        memcpy(out, dir, dlen);
        out[dlen] = '/';
        memcpy(out + dlen + 1, name, nlen);
        out[dlen + 1 + nlen] = '\0';
        return true;
}

/* upstream's show_pid_array(): every pid in one cgroup.procs, in the same
 * fixed-capacity read-then-print shape -- `more_after` is true when child cgroups will be printed
 * below these pids, which is what decides branch-vs-corner glyph on the
 * last one. */
static void print_cgroup_pids(const char *path, const char *prefix, bool more_after) {
        char procs_path[PATH_MAX + 32];
        FILE *f;
        char line[32];
        pid_t pids[PICOCTL_CGROUP_MAX_CHILDREN];
        size_t n = 0, i;

        if (cgroup_lines_printed >= PICOCTL_CGROUP_MAX_LINES)
                return;

        snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", path);
        f = fopen(procs_path, "re");
        if (!f)
                return;

        while (n < PICOCTL_CGROUP_MAX_CHILDREN && fgets(line, sizeof(line), f))
                pids[n++] = (pid_t) atoi(line);
        fclose(f);

        for (i = 0; i < n && cgroup_lines_printed < PICOCTL_CGROUP_MAX_LINES; i++) {
                char comm_path[64];
                char comm[256] = "";
                FILE *cf;
                bool last_line = !more_after && i + 1 == n;

                snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", (int) pids[i]);
                cf = fopen(comm_path, "re");
                if (cf) {
                        if (fgets(comm, sizeof(comm), cf)) {
                                char *nl = strchr(comm, '\n');

                                if (nl)
                                        *nl = '\0';
                        }
                        fclose(cf);
                }
                printf("%s%s%d %s\n",
                       prefix,
                       last_line ? PICOCTL_TREE_RIGHT : PICOCTL_TREE_BRANCH,
                       (int) pids[i],
                       comm);
                cgroup_lines_printed++;
        }
}

/*
 * upstream's show_cgroup_by_path() (src/shared/cgroup-show.c): this cgroup's
 * own pids, then every child cgroup depth-first, branch glyph on every line
 * but the very last at that level. Shared by print_cgroup_procs() (a single
 * unit's cgroup) and print_system_status()'s CGroup row (the root cgroup).
 */
static void print_cgroup_tree(const char *path, const char *prefix, unsigned depth) {
        DIR *d;
        struct dirent *de;
        char *children[PICOCTL_CGROUP_MAX_CHILDREN];
        size_t n_children = 0, i;

        if (depth >= PICOCTL_CGROUP_MAX_DEPTH || cgroup_lines_printed >= PICOCTL_CGROUP_MAX_LINES)
                return;

        d = opendir(path);
        if (!d)
                return;

        while (n_children < PICOCTL_CGROUP_MAX_CHILDREN && (de = readdir(d))) {
                char childpath[PATH_MAX];
                struct stat st;

                if (de->d_name[0] == '.')
                        continue;
                if (!cgroup_path_join(childpath, sizeof(childpath), path, de->d_name))
                        continue;
                if (stat(childpath, &st) < 0 || !S_ISDIR(st.st_mode))
                        continue;
                if (!cgroup_is_populated(childpath))
                        continue;

                children[n_children] = strdup(de->d_name);
                if (children[n_children])
                        n_children++;
        }
        closedir(d);

        print_cgroup_pids(path, prefix, n_children > 0);

        for (i = 0; i < n_children && cgroup_lines_printed < PICOCTL_CGROUP_MAX_LINES; i++) {
                bool last = (i + 1 == n_children);
                char childpath[PATH_MAX];
                char newprefix[PATH_MAX];

                if (cgroup_path_join(childpath, sizeof(childpath), path, children[i])) {
                        printf("%s%s%s\n", prefix, last ? PICOCTL_TREE_RIGHT : PICOCTL_TREE_BRANCH, children[i]);
                        cgroup_lines_printed++;

                        snprintf(newprefix,
                                 sizeof(newprefix),
                                 "%s%s",
                                 prefix,
                                 last ? "  " : PICOCTL_TREE_VERTICAL);
                        print_cgroup_tree(childpath, newprefix, depth + 1);
                }
        }

        for (i = 0; i < n_children; i++)
                free(children[i]);
}

/* The process list, read from cgroup.procs under the unit's cgroup -- the
 * same source upstream's status block uses. Best-effort: no cgroup (never
 * started, or supervision degraded) means nothing to print, not a failure of
 * the verb. */
static void print_cgroup_procs(const char *unit_id) {
        char cgroup_root[PATH_MAX];
        char unit_cgroup[PATH_MAX + 64];
        DIR *d;

        if (path_join(cgroup_root, sizeof(cgroup_root), PICO_CGROUP_ROOT) < 0)
                return;
        snprintf(unit_cgroup, sizeof(unit_cgroup), "%s/system.slice/%s", cgroup_root, unit_id);

        d = opendir(unit_cgroup);
        if (!d)
                return;
        closedir(d);

        printf("     CGroup: %s/system.slice/%s\n", PICO_CGROUP_ROOT, unit_id);
        cgroup_lines_printed = 0;
        print_cgroup_tree(unit_cgroup, "             ", 0);
}

/* --- status: per-unit log tail --- */

/*
 * journalctl's short format, matching picolog.c's print_short() field for
 * field -- not shared code, since logd-read.h formats nothing. There is
 * no -a: `systemctl status` never passes journalctl -a either, so a
 * binary-safe MESSAGE prints the "blob data" placeholder rather than raw
 * bytes to a TTY.
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

        r = logd_ring_read_filtered(rt, unit_id, arg_lines, &ring);
        if (r < 0)
                return;

        n = logd_ring_n_entries(ring);
        for (i = 0; i < n; i++)
                print_log_line(logd_ring_entry(ring, i));

        logd_ring_free(ring);
}

/* --- status: no-argument system overview --- */

/*
 * Boot time from /proc/stat's "btime" field, the kernel's own record of when
 * it booted (upstream reads UserspaceTimestamp over the bus). Not
 * --root-relative, as in systemctl: `--root` retargets the filesystem picoctl
 * reads unit/manager state from, never the live kernel.
 */
static bool read_proc_stat_btime(time_t *out) {
        FILE *f = fopen("/proc/stat", "re");
        char line[256];
        bool found = false;

        if (!f)
                return false;

        while (fgets(line, sizeof(line), f)) {
                long long v;

                if (sscanf(line, "btime %lld", &v) == 1) {
                        *out = (time_t) v;
                        found = true;
                        break;
                }
        }
        fclose(f);
        return found;
}

/*
 * format_timestamp_style(TIMESTAMP_PRETTY) + format_timestamp_relative()
 * (src/basic/time-util.c), reimplemented in whole seconds since /proc/stat's
 * btime has no finer resolution. Thresholds and wording are copied from
 * format_timestamp_relative_full() with the usec constants converted to
 * seconds (USEC_PER_YEAR=31557600s, USEC_PER_MONTH=2629800s).
 */
static void format_since_relative(time_t boot, char *buf, size_t size) {
        long long d = (long long) time(NULL) - (long long) boot;
        long long a, b;

        if (d < 0)
                d = 0;

        if (d >= 31557600LL) {
                a = d / 31557600LL;
                b = (d % 31557600LL) / 2629800LL;
                snprintf(buf,
                         size,
                         "%lld %s %lld %s ago",
                         a,
                         a == 1 ? "year" : "years",
                         b,
                         b == 1 ? "month" : "months");
        } else if (d >= 2629800LL) {
                a = d / 2629800LL;
                b = (d % 2629800LL) / 86400LL;
                snprintf(buf,
                         size,
                         "%lld %s %lld %s ago",
                         a,
                         a == 1 ? "month" : "months",
                         b,
                         b == 1 ? "day" : "days");
        } else if (d >= 604800LL) {
                a = d / 604800LL;
                b = (d % 604800LL) / 86400LL;
                snprintf(buf, size, "%lld %s %lld %s ago", a, a == 1 ? "week" : "weeks", b, b == 1 ? "day" : "days");
        } else if (d >= 2 * 86400LL) {
                snprintf(buf, size, "%lld days ago", d / 86400LL);
        } else if (d >= 25 * 3600LL) {
                snprintf(buf, size, "1 day %lldh ago", (d - 86400LL) / 3600LL);
        } else if (d >= 6 * 3600LL) {
                snprintf(buf, size, "%lldh ago", d / 3600LL);
        } else if (d >= 3600LL) {
                snprintf(buf, size, "%lldh %lldmin ago", d / 3600LL, (d % 3600LL) / 60LL);
        } else if (d >= 5 * 60LL) {
                snprintf(buf, size, "%lldmin ago", d / 60LL);
        } else if (d >= 60LL) {
                snprintf(buf, size, "%lldmin %llds ago", d / 60LL, d % 60LL);
        } else if (d >= 1) {
                snprintf(buf, size, "%llds ago", d);
        } else {
                snprintf(buf, size, "now");
        }
}

/* "    Since: %s; %s\n" row: the absolute timestamp, upstream's own weekday
 * + date + time + zone shape, then format_since_relative() above. */
static void print_since_row(time_t boot) {
        struct tm tmv;
        char datebuf[64];
        char relbuf[64];

        if (!localtime_r(&boot, &tmv))
                return;
        /* upstream prefixes the 3-letter weekday itself (weekday_to_string())
         * rather than trusting the current locale's %a, so this project's
         * build does not have to be run under the C locale to match it. */
        strftime(datebuf, sizeof(datebuf), "%a %Y-%m-%d %H:%M:%S %Z", &tmv);
        format_since_relative(boot, relbuf, sizeof(relbuf));
        printf("    Since: %s; %s\n", datebuf, relbuf);
}

/*
 * format_active_state()/format_enable_state() (systemctl-show.c): the
 * colour bracketing one state word, on both ends -- off is always
 * ANSI_NORMAL when on is non-empty, and both are "" together when the state
 * does not match any coloured case, so a plain-mode call site never has to
 * special-case "no colour" itself.
 */
static void active_state_colors(const char *active_state, const char **on, const char **off) {
        if (strcmp(active_state, "failed") == 0) {
                *on = pico_ansi_highlight_red();
                *off = pico_ansi_normal();
        } else if (strcmp(active_state, "active") == 0 || strcmp(active_state, "reloading") == 0 ||
                   strcmp(active_state, "refreshing") == 0) {
                *on = pico_ansi_highlight_green();
                *off = pico_ansi_normal();
        } else
                *on = *off = "";
}

static void load_state_colors(const char *load_state, const char **on, const char **off) {
        if (strcmp(load_state, "error") == 0 || strcmp(load_state, "not-found") == 0) {
                *on = pico_ansi_highlight_red();
                *off = pico_ansi_normal();
        } else
                *on = *off = "";
}

static void enable_state_colors(const char *enable_state, const char **on, const char **off) {
        if (strcmp(enable_state, "disabled") == 0) {
                *on = pico_ansi_highlight_yellow();
                *off = pico_ansi_normal();
        } else if (strcmp(enable_state, "enabled") == 0) {
                *on = pico_ansi_highlight_green();
                *off = pico_ansi_normal();
        } else
                *on = *off = "";
}

/*
 * systemctl-show.c's show_system_status(): the manager overview real
 * `systemctl status` (no unit, no filter) prints. Every row has a real
 * source (the manager's published state, /proc, or uname/gethostname); an
 * upstream row with none is left out.
 *
 * Always exits 0: like upstream, a degraded or even offline system is
 * reported on successfully, not a picoctl failure.
 */
static void print_system_status(void) {
        char rt[PATH_MAX];
        char unitsdir[PATH_MAX + 16];
        char cgroup_root[PATH_MAX];
        struct manager_state_info ms;
        char hostname[256];
        char word[16] = "";
        unsigned n_failed = 0;
        time_t boot;

        memset(&ms, 0, sizeof(ms));
        if (path_join(rt, sizeof(rt), PICO_RUNTIME_DIR) == 0) {
                read_manager_state(rt, &ms);
                snprintf(unitsdir, sizeof(unitsdir), "%s/units", rt);
                n_failed = count_failed_units(unitsdir);
        }

        if (gethostname(hostname, sizeof(hostname)) < 0 || hostname[0] == '\0')
                snprintf(hostname, sizeof(hostname), "(none)");
        hostname[sizeof(hostname) - 1] = '\0';

        /* show_system_status()'s own bullet/State colouring (systemctl-show.c):
         * red for degraded, green for running, yellow for anything else
         * (picoctl's own "starting"/"offline") -- computed from the word
         * itself, so the bullet and the State: row can never disagree. */
        is_system_running_compute(/* quiet= */ true, word, sizeof(word));
        {
                const char *on, *off = pico_ansi_normal();

                if (strcmp(word, "degraded") == 0)
                        on = pico_ansi_highlight_red();
                else if (strcmp(word, "running") == 0)
                        on = pico_ansi_highlight_green();
                else
                        on = pico_ansi_highlight_yellow();

                /* glyph-util.c's GLYPH_BLACK_CIRCLE, UTF8("●"). */
                printf("%s\xe2\x97\x8f%s %s\n", on, off, hostname);
                printf("    State: %s%s%s\n", on, word, off);
        }

        /* Only printed once a manager has published something: an offline
         * system has no loaded/queued count, not a "0". */
        if (ms.found) {
                printf("    Units: %u loaded (incl. loaded aliases)\n", ms.n_units);
                printf("     Jobs: %u queued\n", ms.n_jobs);
                printf("   Failed: %u units\n", n_failed);
        }

        if (read_proc_stat_btime(&boot))
                print_since_row(boot);

        /* main.c's boot banner and `picoctl --version` use this label too,
         * not "systemd"; "pico-init:" happens to have the 10-column width
         * upstream right-aligns every row label to. */
        printf("pico-init: %s\n", PICO_INIT_VERSION_STRING);

        /* Tainted: pico-init tracks no taint flags, and real systemctl only
         * prints this row when non-empty, so omitting it matches upstream. */

        if (path_join(cgroup_root, sizeof(cgroup_root), PICO_CGROUP_ROOT) == 0) {
                DIR *d = opendir(cgroup_root);

                if (d) {
                        closedir(d);
                        /* pico-init only ever creates system.slice under this
                         * root (cgroups-v2.h); the root cgroup itself is what
                         * upstream's own control_group empty-string case
                         * prints as "/" (empty_to_root()), so this matches
                         * that literally, not just in spirit. */
                        printf("   CGroup: /\n");
                        cgroup_lines_printed = 0;
                        print_cgroup_tree(cgroup_root, "             ", 0);
                }
        }
}

static int cmd_status(int argc, char *argv[]) {
        int i, worst = 0;

        /* real verb_show()'s own argc<=1 dispatch (systemctl-show.c):
         * no unit name inspects the manager itself, it is not an error. */
        if (argc < 1) {
                print_system_status();
                return 0;
        }

        for (i = 0; i < argc; i++) {
                struct unit_state st;

                if (i > 0)
                        printf("\n");

                read_unit_state(argv[i], &st);

                if (!st.found) {
                        const char *load_on, *load_off, *active_on, *active_off;

                        load_state_colors("not-found", &load_on, &load_off);
                        active_state_colors(st.active_state, &active_on, &active_off);

                        printf("%s\n", argv[i]);
                        printf("     Loaded: %snot-found%s\n", load_on, load_off);
                        /* real print_status_info() still runs the full path for a
                         * not-found unit and prints Active: too (systemctl-show.c). */
                        printf("     Active: %s%s (%s)%s\n", active_on, st.active_state, st.sub_state, active_off);
                        picoctl_error("Unit %s could not be found.", argv[i]);
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
                {
                        const char *load_on, *load_off, *enable_on, *enable_off;
                        const char *ufs = st.unit_file_state[0] ? st.unit_file_state : "n/a";

                        load_state_colors(st.load_state, &load_on, &load_off);
                        enable_state_colors(ufs, &enable_on, &enable_off);

                        printf("     Loaded: %s%s%s (%s; %s%s%s)\n",
                               load_on,
                               st.load_state,
                               load_off,
                               st.fragment_path[0] ? st.fragment_path : "n/a",
                               enable_on,
                               ufs,
                               enable_off);
                }

                /* Result folds onto the Active: line itself upstream, never a
                 * separate field (systemctl-show.c print_status_info()). */
                {
                        const char *active_on, *active_off;

                        active_state_colors(st.active_state, &active_on, &active_off);

                        if (strcmp(st.result, "success") != 0)
                                printf("     Active: %s%s (%s)%s (Result: %s)\n",
                                       active_on,
                                       st.active_state,
                                       st.sub_state,
                                       active_off,
                                       st.result);
                        else
                                printf("     Active: %s%s (%s)%s\n",
                                       active_on,
                                       st.active_state,
                                       st.sub_state,
                                       active_off);
                }

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
 * `systemctl mask`'s symlink target: a symlink there pointing at /dev/null
 * shadows the real unit everywhere, and unit_find_fragment() (unit-load.c)
 * already sets UNIT_MASKED for it at boot. Checked directly on the
 * filesystem rather than through a throwaway Manager, since masking needs no
 * [Install] data and must work even for a unit with no fragment.
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
 * Current upstream's log_notice() wording for carries_install_info == 0
 * (systemctl-enable.c verb_enable()): enable/disable/preset on a unit with
 * no [Install] data succeeds (exit 0), creates no symlinks, and explains why
 * on stderr.
 */
static void print_no_install_info_notice(void) {
        /* LOG_NOTICE, not LOG_ERR: picoctl_notice() (bold/white), not
         * picoctl_error() (red); this is not a failure. */
        picoctl_notice("The unit files have no installation config (WantedBy=, RequiredBy=, UpheldBy=,\n"
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
                       "  instance name specified.");
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
 * always force=true for .wants/.requires entries (only linking the unit file
 * itself respects --force, which picoctl never does). The mkdir/readlink/
 * symlink work is unit-enable.c's unit_enable_create_symlink(), shared with
 * boot-time preset persistence so the two cannot disagree about what a
 * symlink looks like (see test-picoctl.c).
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
                picoctl_error("picoctl enable: missing unit name");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                Manager *m = NULL;
                Unit *u = NULL;
                int r = load_install_info(argv[i], &m, &u);

                if (r < 0) {
                        picoctl_error("Failed to enable unit, unit %s does not exist.", argv[i]);
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
                        picoctl_error("Failed to enable unit %s: %s", argv[i], strerror(-r));
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
                picoctl_error("picoctl reenable: missing unit name");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                Manager *m = NULL;
                Unit *u = NULL;
                int r = load_install_info(argv[i], &m, &u);

                if (r < 0) {
                        picoctl_error("Failed to enable unit, unit %s does not exist.", argv[i]);
                        status = 1;
                        continue;
                }

                do_disable_unit(u);
                r = do_enable_unit(u);
                if (r == -ENOEXEC)
                        print_no_install_info_notice();
                else if (r < 0) {
                        picoctl_error("Failed to enable unit %s: %s", argv[i], strerror(-r));
                        status = 1;
                }

                manager_free(m);
        }

        return status;
}

static int cmd_disable(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                picoctl_error("picoctl disable: missing unit name");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                Manager *m = NULL;
                Unit *u = NULL;
                int r = load_install_info(argv[i], &m, &u);

                if (r < 0) {
                        picoctl_error("Failed to disable unit, unit %s does not exist.", argv[i]);
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

/*
 * One source of truth for "is this unit enabled on disk", read fresh from
 * the filesystem every call -- shared by is-enabled and cmd_show()'s
 * UnitFileState= field. The published state file only reflects what the
 * manager saw at load time and is not updated by a later `picoctl
 * disable`/enable.
 *
 * Returns one of "masked"/"static"/"enabled"/"disabled"/"not-found",
 * never NULL.
 */
static const char *compute_unit_file_state(const char *unit_id) {
        Manager *m = NULL;
        Unit *u = NULL;
        const char *state;
        int r;

        /* Checked before load_install_info(): a masked unit fails that call
         * (its load_state is UNIT_MASKED, never UNIT_LOADED), which would
         * otherwise read indistinguishably from "not-found". */
        if (unit_is_masked(unit_id))
                return "masked";

        r = load_install_info(unit_id, &m, &u);
        if (r < 0)
                return "not-found";

        if (!u->wanted_by && !u->required_by)
                state = "static";
        else {
                bool this_enabled = false;
                size_t j;

                for (j = 0; u->wanted_by && u->wanted_by[j] && !this_enabled; j++)
                        if (enable_symlink_exists(u->wanted_by[j], ".wants", u->id))
                                this_enabled = true;
                for (j = 0; u->required_by && u->required_by[j] && !this_enabled; j++)
                        if (enable_symlink_exists(u->required_by[j], ".requires", u->id))
                                this_enabled = true;

                state = this_enabled ? "enabled" : "disabled";
        }

        manager_free(m);
        return state;
}

static int cmd_is_enabled(int argc, char *argv[]) {
        bool enabled = false, not_found = true;
        int i;

        if (argc < 1) {
                picoctl_error("picoctl is-enabled: missing unit name");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                const char *state = compute_unit_file_state(argv[i]);

                printf("%s\n", state);

                if (strcmp(state, "not-found") != 0)
                        not_found = false;
                /* "masked"/"disabled" exit 1, not 4: the unit is known,
                 * just not enabled (masked counts as known-but-disabled,
                 * not as "enabled"). */
                if (strcmp(state, "enabled") == 0 || strcmp(state, "static") == 0)
                        enabled = true;
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
                picoctl_error("picoctl preset: missing unit name");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                Manager *m = NULL;
                Unit *u = NULL;
                int r = load_install_info(argv[i], &m, &u);
                int decision;

                if (r < 0) {
                        picoctl_error("Failed to preset unit, unit %s does not exist.", argv[i]);
                        status = 1;
                        continue;
                }

                decision = manager_preset_query(m, u->id);
                if (decision < 0 && decision != -ENOENT) {
                        picoctl_error("Failed to query preset for %s: %s", argv[i], strerror(-decision));
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
                                picoctl_error("Failed to preset unit %s: %s", argv[i], strerror(-r));
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
 * subdirectory) pointing at /dev/null. Built via unit-enable.c's
 * unit_enable_create_symlink(), the helper create_enable_symlink() uses,
 * called with an empty target/suffix pair so its
 * "<etcdir>/<target><suffix>/<unit_id>" path collapses to
 * "<etcdir>/<unit_id>". No throwaway Manager: masking needs no [Install]
 * data and must work for a unit with no fragment. Idempotent: already-masked
 * prints nothing.
 */
static int cmd_mask(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                picoctl_error("picoctl mask: missing unit name");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                char etcdir[PATH_MAX];
                int r;

                if (!unit_name_is_valid(argv[i])) {
                        picoctl_error("Failed to mask unit: Invalid unit name \"%s\".", argv[i]);
                        status = 1;
                        continue;
                }

                if (path_join(etcdir, sizeof(etcdir), PICO_UNIT_DIR) < 0) {
                        status = 1;
                        continue;
                }

                r = unit_enable_create_symlink(etcdir, "", "", argv[i], "/dev/null");
                if (r < 0) {
                        picoctl_error("Failed to mask unit %s: %s", argv[i], strerror(-r));
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
                picoctl_error("picoctl unmask: missing unit name");
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
                        picoctl_error("Failed to unmask unit %s: %s", argv[i], strerror(errno));
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
                picoctl_error("picoctl cat: missing unit name");
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
                        picoctl_error("Failed to cat unit: Unit %s not found.", argv[i]);
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
 * STATE: masked (a /dev/null symlink shadows it), static (no [Install] data
 * at all), or enabled/disabled, decided by whether a .wants/.requires symlink
 * exists -- the same check cmd_is_enabled() makes. A fragment present but
 * failed to parse reads as "bad" (upstream's UNIT_FILE_BAD). PRESET is shown
 * only for "disabled", the one state a preset rule could still flip (as
 * show_preset_for_state() upstream); every other row prints "-".
 */
/*
 * STATE/PRESET colouring as in output_unit_file_list() (systemctl-list-
 * unit-files.c), minus its underline case: masked/disabled/bad red, enabled
 * green, "static" uncoloured. PRESET is coloured only when a verdict is
 * shown; the "-" shown otherwise is grey.
 */
static void list_unit_files_colors(
                const char *state,
                const char *preset,
                const char **on_state,
                const char **off_state,
                const char **on_preset,
                const char **off_preset) {
        const char *normal = pico_ansi_normal();

        *on_state = *off_state = *on_preset = *off_preset = "";

        if (strcmp(state, "masked") == 0 || strcmp(state, "disabled") == 0 || strcmp(state, "bad") == 0)
                *on_state = pico_ansi_highlight_red();
        else if (strcmp(state, "enabled") == 0)
                *on_state = pico_ansi_highlight_green();
        if ((*on_state)[0])
                *off_state = normal;

        if (strcmp(state, "disabled") == 0) {
                if (strcmp(preset, "enabled") == 0)
                        *on_preset = pico_ansi_highlight_green();
                else if (strcmp(preset, "disabled") == 0)
                        *on_preset = pico_ansi_highlight_red();
        } else
                *on_preset = pico_ansi_grey();
        if ((*on_preset)[0])
                *off_preset = normal;
}

static int cmd_list_unit_files(int argc, char *argv[]) {
        char updir[PATH_MAX], pkgdir[PATH_MAX];
        struct unit_file_entry *entries = NULL;
        size_t n = 0, cap = 0, i;

        /* --no-legend comes from main()'s getopt_long() pass (arg_no_legend);
         * this verb takes no other option, hence argc/argv going unused. */
        (void) argc;
        (void) argv;

        if (path_join(updir, sizeof(updir), PICO_UNIT_DIR) == 0)
                collect_unit_files_from(updir, &entries, &n, &cap);
        if (path_join(pkgdir, sizeof(pkgdir), PICO_PACKAGED_UNIT_DIR) == 0)
                collect_unit_files_from(pkgdir, &entries, &n, &cap);

        if (entries && n > 1)
                qsort(entries, n, sizeof(*entries), unit_file_entry_cmp);

        if (!arg_no_legend)
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

                {
                        const char *on_state, *off_state, *on_preset, *off_preset;

                        list_unit_files_colors(state, preset, &on_state, &off_state, &on_preset, &off_preset);

                        printf("%-40s %s%-10s%s %s%s%s\n",
                               entries[i].name,
                               on_state,
                               state,
                               off_state,
                               on_preset,
                               preset,
                               off_preset);
                }
        }

        if (!arg_no_legend)
                printf("\n%zu unit files listed.\n", n);

        free(entries);
        return 0;
}

/* --- start/stop/restart/reset-failed: the control-socket client half --- */

/* Reply buffer: at least as large as any reply the server sends, which is a
 * single short line (manager-ctrl.c's PICO_CTRL_LINE_MAX). */
#define PICOCTL_CTRL_REPLY_MAX 512

/*
 * Connect to <root><runtime_dir>/control (manager-ctrl.c's path). A missing
 * socket (setup failed at boot, or an image without it) is a supported
 * configuration: this fails with -ENOENT/-ECONNREFUSED like any connect() to
 * nothing, and the caller reports it like any other error.
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

/* "systemctl status"/"journalctl" below are not a typo for picoctl/picolog:
 * both are aliased to those names on a real image, so upstream's literal hint
 * text is correct advice here. */
static void print_job_failed(const char *unit) {
        struct unit_state st;
        const char *expl;

        read_unit_state(unit, &st);
        expl = job_failure_explanation(st.result);
        if (expl)
                picoctl_error("Job for %s failed because %s.\n"
                              "See \"systemctl status %s\" and \"journalctl -xeu %s\" for details.",
                              unit,
                              expl,
                              unit,
                              unit);
        else
                picoctl_error("Job for %s failed.\n"
                              "See \"systemctl status %s\" and \"journalctl -xeu %s\" for details.",
                              unit,
                              unit,
                              unit);
}

/*
 * The reasons manager-ctrl.c's wire protocol can send back. "no-such-unit"
 * has a clean upstream equivalent and gets it; the rest (shutting-down,
 * out-of-memory, too-many-connections, enqueue-failed, permission-denied)
 * have no single systemctl error string, so they are relayed as themselves.
 */
static void print_verb_failure(const char *verb, const char *unit, const char *reason) {
        if (strcmp(reason, "no-such-unit") == 0)
                picoctl_error("Failed to %s %s: Unit %s not found.", verb, unit, unit);
        else
                picoctl_error("Failed to %s %s: %s", verb, unit, reason);
}

/*
 * start/stop/restart share everything except the wire verb sent to
 * manager-ctrl.c; `display_verb` is upstream's job_type string
 * (systemctl-start-unit.c's unit_actions[] table) for the verb the person
 * typed, used in the error text. It differs from the plain verb for aliases
 * (try-restart's callers, below). reset-failed takes no --no-block and never
 * fails with a job result, so it stays separate.
 *
 * Silent on success, exit 0, like real start/stop/restart.
 */
static int cmd_verb_generic(int argc, char *argv[], const char *wire_verb, const char *display_verb) {
        int i, status = 0;

        /* --no-block is global (arg_no_block, from main()'s getopt_long()
         * pass) and never reaches this argv, so every entry here is a
         * unit name. */
        if (argc < 1) {
                picoctl_error("picoctl %s: missing unit name", display_verb);
                return 1;
        }

        for (i = 0; i < argc; i++) {
                char reply[PICOCTL_CTRL_REPLY_MAX];
                char *nl;
                const char *reason;
                int r;

                r = ctrl_roundtrip(wire_verb, argv[i], arg_no_block, reply, sizeof(reply));
                if (r < 0) {
                        /* A transport-level failure (no control socket at
                         * all, a permission problem, ...): there is no bus
                         * call to have failed, so this is picoctl's own
                         * wording, not an upstream quote. */
                        picoctl_error("Failed to %s %s: %s", display_verb, argv[i], strerror(-r));
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
                        picoctl_error("Job for %s canceled.", argv[i]);
                else if (strcmp(reason, "timeout") == 0)
                        picoctl_error("Job for %s timed out.", argv[i]);
                else if (strcmp(reason, "failed") == 0)
                        print_job_failed(argv[i]);
                else if (strcmp(reason, "dependency") == 0)
                        picoctl_error("A dependency job for %s failed. See 'journalctl -xe' for details.",
                                      argv[i]);
                else
                        print_verb_failure(display_verb, argv[i], reason);

                status = 1;
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
 * unit.c's unit_actions[] table), identical to plain stop. */
static int cmd_condstop(int argc, char *argv[]) {
        return cmd_verb_generic(argc, argv, "stop", "stop");
}

/*
 * try-restart (TryRestartUnit)/condrestart (its legacy RH alias, same job
 * type): restart only a unit that is currently active; an inactive one is
 * left alone, silently, exit 0.
 *
 * Gap: upstream tells "loadable, but inactive" from "no such unit" by
 * resolving the unit file; picoctl only sees units the manager has published
 * a state file for, so a loaded-but-never-started unit reads like a missing
 * one. A try-restart on a name that does not exist is therefore a silent
 * no-op rather than upstream's "Unit not found" error.
 */
static int cmd_try_restart_as(int argc, char *argv[], const char *display_verb) {
        char **active;
        int i, n_active = 0, rc;

        if (argc < 1) {
                picoctl_error("picoctl %s: missing unit name", display_verb);
                return 1;
        }

        active = calloc((size_t) argc, sizeof(char *));
        if (!active)
                return 1;

        /* --no-block is global (arg_no_block) and never reaches this argv;
         * cmd_verb_generic() below reads it itself, so no passthrough is
         * needed here. */
        for (i = 0; i < argc; i++) {
                struct unit_state st;

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
 * else restart. ExecReload= is not implemented (see cmd_reload()), so this
 * always restarts, which is upstream's own fallback.
 */
static int cmd_reload_or_restart(int argc, char *argv[]) {
        return cmd_verb_generic(argc, argv, "restart", "reload-or-restart");
}

/*
 * try-reload-or-restart (ReloadOrTryRestartUnit) and its three legacy
 * spellings -- reload-or-try-restart, condreload, force-reload -- all share
 * one upstream job_type string ("reload-or-try-restart",
 * systemctl-start-unit.c's unit_actions[] table) and behaviour: reload if
 * supported, else try-restart. ExecReload= does not exist here, so this
 * always takes the try-restart branch.
 */
static int cmd_try_reload_or_restart(int argc, char *argv[]) {
        return cmd_try_restart_as(argc, argv, "reload-or-try-restart");
}

/*
 * reload (ReloadUnit): ExecReload= is not implemented in pico-init and job.h
 * has no JOB_RELOAD (only START/STOP/RESTART), so this fails like upstream
 * does for a unit with no ExecReload=: "Job type %s is not applicable for
 * unit %s." (BUS_ERROR_JOB_TYPE_NOT_APPLICABLE, src/core/transaction.c).
 */
static int cmd_reload(int argc, char *argv[]) {
        int i;

        if (argc < 1) {
                picoctl_error("picoctl reload: missing unit name");
                return 1;
        }

        /* --no-block is global and never reaches this argv; every entry
         * here is a real unit name. */
        for (i = 0; i < argc; i++)
                picoctl_error("Failed to reload %s: Job type reload is not applicable for unit %s.",
                              argv[i],
                              argv[i]);

        return 1;
}

static int cmd_reset_failed(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                picoctl_error("picoctl reset-failed: missing unit name");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                char reply[PICOCTL_CTRL_REPLY_MAX];
                char *nl;
                int r = ctrl_roundtrip("reset-failed", argv[i], false, reply, sizeof(reply));

                if (r < 0) {
                        picoctl_error("Failed to reset failed state of unit %s: %s", argv[i], strerror(-r));
                        status = 1;
                        continue;
                }

                if (strncmp(reply, "ok", 2) == 0)
                        continue; /* silent success, like every other action verb */

                nl = strchr(reply, '\n');
                if (nl)
                        *nl = '\0';
                picoctl_error("Failed to reset failed state of unit %s: %s",
                              argv[i],
                              strncmp(reply, "err ", 4) == 0 ? reply + 4 : reply);
                status = 1;
        }

        return status;
}

/*
 * daemon-reload: the one action verb with no unit argument. The wire grammar
 * is just "PICO1 daemon-reload" (manager-ctrl.h), so this talks the socket
 * directly rather than through ctrl_roundtrip(), which always sends a unit
 * token. Silent on success, exit 0, as daemon_reload() (systemctl-daemon-
 * reload.c); the error text is "Reload daemon failed: %s".
 */
static int cmd_daemon_reload(int argc, char *argv[]) {
        static const char line[] = "PICO1 daemon-reload";
        char reply[PICOCTL_CTRL_REPLY_MAX];
        int fd;
        ssize_t r;

        (void) argv;
        if (argc > 0) {
                picoctl_error("picoctl: daemon-reload takes no arguments");
                return 1;
        }

        fd = ctrl_connect();
        if (fd < 0) {
                picoctl_error("Reload daemon failed: %s", strerror(-fd));
                return 1;
        }

        r = send(fd, line, sizeof(line) - 1, MSG_NOSIGNAL);
        if (r < 0) {
                picoctl_error("Reload daemon failed: %s", strerror(errno));
                close(fd);
                return 1;
        }

        r = recv(fd, reply, sizeof(reply) - 1, 0);
        close(fd);
        if (r < 0) {
                picoctl_error("Reload daemon failed: %s", strerror(errno));
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
        picoctl_error("Reload daemon failed: %s", strncmp(reply, "err ", 4) == 0 ? reply + 4 : reply);
        return 1;
}

/*
 * kill (KillUnit): signal the unit's processes directly. Self-contained in
 * picoctl rather than a manager-ctrl.c wire verb: the published MainPID and
 * the cgroup's cgroup.procs are already read-only state picoctl reads for
 * `status` (print_cgroup_procs()).
 *
 * --kill-who=all (upstream's default) signals every pid in the unit's
 * cgroup; --kill-who=main signals only the published MainPID. --signal/-s
 * takes SIGTERM (upstream's default), SIGKILL, SIGHUP, SIGINT or a bare
 * number; anything else is refused rather than guessed at. Both options are
 * global (arg_signal_name/arg_kill_who, from main()'s getopt_long() pass), so
 * "-s KILL", "--signal KILL" and "--signal=KILL" are equivalent.
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
        bool kill_main_only = strcmp(arg_kill_who, "main") == 0;
        int i, status = 0;

        if (arg_signal_name && signal_from_name(arg_signal_name, &sig) < 0) {
                picoctl_error("picoctl kill: unknown signal '%s'", arg_signal_name);
                return 1;
        }

        if (argc < 1) {
                picoctl_error("picoctl kill: missing unit name");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                struct unit_state st;
                char cgroup_root[PATH_MAX];
                char path[PATH_MAX + 64];
                FILE *f;
                char line[32];
                bool signalled_anything = false;

                read_unit_state(argv[i], &st);
                if (!st.found) {
                        picoctl_error("Failed to kill unit %s: Unit %s not loaded.", argv[i], argv[i]);
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
 * suffix (unit_name_mangle() in systemd's src/shared/unit-name.c). Without
 * it, unit-name.c's unit_name_is_valid() rejects the bare name and
 * "picoctl status bt-pan-client" reports not-found even with
 * bt-pan-client.service installed.
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
 * reboot/poweroff/halt/shutdown: a simplification of what real systemctl/
 * reboot(8)/halt(8) do -- those go through logind and a D-Bus StartUnit on
 * halt/poweroff/reboot.target, reaching a raw syscall only with --force
 * (src/systemctl/systemctl-compat-halt.c). Here kill(1, sig) uses PID 1's own
 * signal convention (manager-loop.c's manager_dispatch_signal(): SIGINT ->
 * MANAGER_REBOOT, SIGRTMIN+3/+4 -> MANAGER_POWEROFF, matching manager.c's
 * target_table), since there is no logind/D-Bus to call. No
 * --force/--wtmp-only/--no-wall flags: every invocation acts immediately
 * (see usage()).
 *
 * /sbin/reboot, /sbin/poweroff, /sbin/halt and /sbin/shutdown are meant to
 * be symlinked straight at this binary, like systemctl itself; main()
 * dispatches on argv[0]'s basename before any verb parsing.
 */
static int send_pid1_signal(int sig, const char *what) {
        if (kill(1, sig) < 0) {
                picoctl_error("picoctl: %s: kill(1, %d): %s", what, sig, strerror(errno));
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
 * No scheduler and no wall(1) broadcast exist here, so `shutdown` only
 * accepts the immediate case. -h/-P means poweroff (the default, as in real
 * shutdown(8)), -r reboot.
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
                        picoctl_error("picoctl: shutdown: no scheduler or wall message here, only "
                                      "'shutdown [-r|-h|-P] [now]'");
                        return 1;
                }
        }

        return do_reboot ? cmd_reboot(0, NULL) : cmd_poweroff(0, NULL);
}

/*
 * One getopt_long() pass, permuting (no leading '+' in the optstring,
 * POSIXLY_CORRECT not set), over the whole argv, as systemctl_parse_argv()
 * does: an option may sit before, between or after the verb and unit
 * arguments, "--" ends option parsing, and both "--opt=value" and "--opt
 * value"/"-o value" work. Unknown options and missing arguments get
 * getopt_long's own stderr message (opterr is left at 1) and exit 1.
 *
 * --system/--user/--global/-H/--host/-M/--machine are accepted so they never
 * fall through to "Unknown command verb", but only --system matches reality:
 * pico-init has one manager, PID 1, with no user instance or remote/container
 * transport, so the other five refuse. -f/--force and --no-pager/--no-wall
 * are accepted and ignored: force/no-wall behaviour for reboot/poweroff/halt/
 * shutdown exists only through the argv[0] alias dispatch (see
 * cmd_shutdown()), and there is no pager.
 */
static int picoctl_parse_options(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_ROOT,
                ARG_NO_BLOCK,
                ARG_NO_LEGEND,
                ARG_NO_PAGER,
                ARG_NO_WALL,
                ARG_STATE,
                ARG_KILL_WHO,
                ARG_SYSTEM,
                ARG_USER,
                ARG_GLOBAL,
        };
        static const struct option options[] = {
                {      "help",       no_argument, NULL,           'h' },
                {   "version",       no_argument, NULL,   ARG_VERSION },
                {      "root", required_argument, NULL,      ARG_ROOT },
                {  "no-block",       no_argument, NULL,  ARG_NO_BLOCK },
                { "no-legend",       no_argument, NULL, ARG_NO_LEGEND },
                {  "no-pager",       no_argument, NULL,  ARG_NO_PAGER },
                {   "no-wall",       no_argument, NULL,   ARG_NO_WALL },
                {     "quiet",       no_argument, NULL,           'q' },
                {       "all",       no_argument, NULL,           'a' },
                {      "type", required_argument, NULL,           't' },
                {     "state", required_argument, NULL,     ARG_STATE },
                {     "lines", required_argument, NULL,           'n' },
                {    "signal", required_argument, NULL,           's' },
                {  "kill-who", required_argument, NULL,  ARG_KILL_WHO },
                { "kill-whom", required_argument, NULL,  ARG_KILL_WHO },
                {     "force",       no_argument, NULL,           'f' },
                {    "system",       no_argument, NULL,    ARG_SYSTEM },
                {      "user",       no_argument, NULL,      ARG_USER },
                {    "global",       no_argument, NULL,    ARG_GLOBAL },
                {      "host", required_argument, NULL,           'H' },
                {   "machine", required_argument, NULL,           'M' },
                {        NULL,                 0, NULL,             0 },
        };
        int c;

        while ((c = getopt_long(argc, argv, "hqat:n:s:H:M:f", options, NULL)) >= 0) {
                switch (c) {
                case 'h':
                        usage();
                        return 0;

                case ARG_VERSION:
                        printf("picoctl " PICO_INIT_VERSION_STRING
                               " (pico-init; not systemd, see picoctl.c)\n");
                        return 0;

                case ARG_ROOT:
                        arg_root = optarg;
                        break;

                case ARG_NO_BLOCK:
                        arg_no_block = true;
                        break;

                case ARG_NO_LEGEND:
                        arg_no_legend = true;
                        break;

                case ARG_NO_PAGER: /* no pager exists to disable */
                case ARG_NO_WALL:  /* see this function's own header */
                case 'f':          /* --force: ditto */
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case 'a': /* --all: a true no-op, see cmd_list_units() */
                        break;

                case 't':
                        arg_type = optarg;
                        break;

                case ARG_STATE:
                        arg_state = optarg;
                        break;

                case 'n': {
                        char *end;
                        unsigned long v;

                        /* strtoul() itself accepts a leading '-' (and wraps
                         * around); safe_atou()'s own contract upstream does
                         * not, so reject it explicitly here too. */
                        errno = 0;
                        v = strtoul(optarg, &end, 10);
                        if (optarg[0] == '\0' || optarg[0] == '-' || *end != '\0' || errno != 0) {
                                picoctl_error("picoctl: invalid --lines value '%s'", optarg);
                                return 1;
                        }
                        arg_lines = (unsigned) v;
                        break;
                }

                case 's':
                        arg_signal_name = optarg;
                        break;

                case ARG_KILL_WHO:
                        arg_kill_who = optarg;
                        break;

                case ARG_SYSTEM: /* already the only mode */
                        break;

                case ARG_USER:
                        picoctl_error("Running in user mode is not supported: pico-init has no "
                                      "per-user service manager.");
                        return 1;

                case ARG_GLOBAL:
                        picoctl_error("--global is not supported: pico-init has no per-user "
                                      "service manager to apply it to.");
                        return 1;

                case 'H':
                        picoctl_error("-H/--host is not supported: picoctl has no remote transport.");
                        return 1;

                case 'M':
                        picoctl_error("-M/--machine is not supported: picoctl has no container transport.");
                        return 1;

                case '?':
                default:
                        /* getopt_long already printed its own diagnostic. */
                        return 1;
                }
        }

        return -1; /* keep going: optind now points at VERB [UNIT...] */
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
                 * Not in this table, so they fall through to "Unknown command verb" below
                 * rather than a pretended success: get-default/set-default (no persisted
                 * default target; manager_startup()'s default_target is a boot-time
                 * argument), isolate (would need a JOB_ISOLATE and the stop-everything-else
                 * transaction semantics), daemon-reexec, set-environment/unset-environment/
                 * show-environment, edit, link, add-wants/add-requires, list-dependencies/
                 * list-jobs/list-sockets/list-timers/list-machines, and the service-log-
                 * level/watchdog/bind/mount-image/set-property verbs, which have no backing
                 * in pico-init (no D-Bus properties, no sockets/timers/mounts tracked the
                 * way those verbs need).
                 */
        };
        const char *prog0;
        int argi, rc_opts;
        size_t i;

        /* argv[0] dispatch, before any option/verb parsing: a real reboot(8)/
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

        rc_opts = picoctl_parse_options(argc, argv);
        if (rc_opts >= 0)
                return rc_opts; /* --help/--version, or a parse error */
        argi = optind;

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
        picoctl_error("Unknown command verb '%s'.", argv[argi]);
        return 1;
}
