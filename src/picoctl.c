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
#include <fnmatch.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
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
static int arg_legend = -1; /* -1: unset, then on unless -q; 0/1 from --legend=/--no-legend */
static bool arg_quiet = false;
static bool arg_all = false;
static bool arg_now = false;
static bool arg_dry_run = false;
static bool arg_wait = false;
static bool arg_value = false;
static const char *arg_type = NULL;
static const char *arg_state = NULL;
static const char *arg_properties = NULL; /* comma-separated, from -p/-P (repeatable) */
static unsigned arg_lines = PICOCTL_STATUS_LOG_LINES;
static const char *arg_signal_name = NULL;
static const char *arg_kill_whom = "all";
static const char *arg_kill_subgroup = NULL;
static bool arg_kill_value_set = false;
static int arg_kill_value = 0;
static const char *arg_preset_mode = "full";

/* -o/--output: only the json modes and "cat" change anything here, see
 * picoctl_parse_options(). */
enum output_mode {
        OUTPUT_SHORT,
        OUTPUT_CAT,
        OUTPUT_JSON,
        OUTPUT_JSON_PRETTY,
        OUTPUT_JSON_SSE,
        OUTPUT_JSON_SEQ,
};
static enum output_mode arg_output = OUTPUT_SHORT;

enum timestamp_style {
        TIMESTAMP_PRETTY,
        TIMESTAMP_UNIX,
        TIMESTAMP_US,
        TIMESTAMP_UTC,
        TIMESTAMP_US_UTC,
};
static enum timestamp_style arg_timestamp_style = TIMESTAMP_PRETTY;

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

/* --- JSON output (-o json and friends) ---
 *
 * The shape table_print_json() gives a systemctl table: an array with one
 * object per row, field names the lower-cased column headings. Compact for
 * json, tab-indented with "key" : value for json-pretty (sd-json.c's
 * json_format()); json-sse and json-seq only add their framing around the
 * compact form.
 */
struct json_out {
        bool pretty;
        unsigned n_rows;
        unsigned n_fields;
};

static bool output_is_json(void) {
        return arg_output >= OUTPUT_JSON;
}

static void json_string(const char *s) {
        putchar('"');
        for (; *s; s++) {
                unsigned char c = (unsigned char) *s;

                switch (c) {
                case '"':
                        fputs("\\\"", stdout);
                        break;
                case '\\':
                        fputs("\\\\", stdout);
                        break;
                case '\n':
                        fputs("\\n", stdout);
                        break;
                case '\t':
                        fputs("\\t", stdout);
                        break;
                case '\r':
                        fputs("\\r", stdout);
                        break;
                default:
                        if (c < 0x20)
                                printf("\\u%04x", c);
                        else
                                putchar(c);
                }
        }
        putchar('"');
}

static void json_begin(struct json_out *j) {
        memset(j, 0, sizeof(*j));
        j->pretty = arg_output == OUTPUT_JSON_PRETTY;

        if (arg_output == OUTPUT_JSON_SSE)
                fputs("data: ", stdout);
        else if (arg_output == OUTPUT_JSON_SEQ)
                putchar(0x1e);
        putchar('[');
}

static void json_row_begin(struct json_out *j) {
        if (j->n_rows++)
                putchar(',');
        if (j->pretty)
                fputs("\n\t", stdout);
        putchar('{');
        j->n_fields = 0;
}

/* value NULL is an empty cell, which the table code renders as null. */
static void json_field(struct json_out *j, const char *key, const char *value) {
        if (j->n_fields++)
                putchar(',');
        if (j->pretty)
                fputs("\n\t\t", stdout);
        json_string(key);
        fputs(j->pretty ? " : " : ":", stdout);
        if (value)
                json_string(value);
        else
                fputs("null", stdout);
}

static void json_field_uint(struct json_out *j, const char *key, unsigned value) {
        if (j->n_fields++)
                putchar(',');
        if (j->pretty)
                fputs("\n\t\t", stdout);
        json_string(key);
        printf("%s%u", j->pretty ? " : " : ":", value);
}

static void json_row_end(struct json_out *j) {
        if (j->pretty)
                fputs("\n\t", stdout);
        putchar('}');
}

static void json_end(struct json_out *j) {
        if (j->pretty && j->n_rows)
                putchar('\n');
        putchar(']');
        fputs(arg_output == OUTPUT_JSON_SSE ? "\n\n" : "\n", stdout);
}

/* strv_fnmatch_or_empty(): no pattern at all matches everything. */
static bool pattern_matches(int n_patterns, char **patterns, const char *name) {
        int i;

        if (n_patterns == 0)
                return true;
        for (i = 0; i < n_patterns; i++)
                if (fnmatch(patterns[i], name, FNM_NOESCAPE) == 0)
                        return true;
        return false;
}

static char *mangle_unit_arg_suffix(const char *arg, const char *suffix);

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

static bool csv_contains(const char *csv, const char *word);

/* -p/-P: only the named properties; an unnamed run prints all of them. */
static void show_emit(const char *key, const char *value) {
        if (arg_properties && !csv_contains(arg_properties, key))
                return;
        if (arg_value)
                printf("%s\n", value);
        else
                printf("%s=%s\n", key, value);
}

static void show_emit_line(char *line) {
        char *nl = strchr(line, '\n');
        char *eq;

        if (nl)
                *nl = '\0';
        eq = strchr(line, '=');
        if (!eq)
                return;
        *eq = '\0';
        show_emit(line, eq + 1);
}

/* `show` without a unit is the manager's own properties: the manager file
 * is exactly that set. */
static int show_manager(void) {
        char rt[PATH_MAX];
        char path[PATH_MAX + 16];
        char line[1024];
        FILE *f;

        if (path_join(rt, sizeof(rt), PICO_RUNTIME_DIR) < 0)
                return 1;
        snprintf(path, sizeof(path), "%s/manager", rt);
        f = fopen(path, "re");
        if (!f) {
                picoctl_error("Failed to read manager state: %s", strerror(errno));
                return 1;
        }
        while (fgets(line, sizeof(line), f))
                show_emit_line(line);
        fclose(f);
        return 0;
}

static int cmd_show(int argc, char *argv[]) {
        int i;

        if (argc < 1)
                return show_manager();

        for (i = 0; i < argc; i++) {
                char rt[PATH_MAX];
                char path[PATH_MAX];
                FILE *f;
                int n;

                if (i > 0 && !arg_value)
                        printf("\n");

                show_emit("Id", argv[i]);

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
                        show_emit("LoadState", "not-found");
                        show_emit("ActiveState", "inactive");
                        show_emit("SubState", "dead");
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

                        while (fgets(line, sizeof(line), f)) {
                                if (strncmp(line, "UnitFileState=", 14) == 0)
                                        show_emit("UnitFileState", compute_unit_file_state(argv[i]));
                                else
                                        show_emit_line(line);
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

/* output_show_unit() (systemctl-util.c): without --all or a --state filter,
 * inactive units with no pending job stay hidden. */
static bool unit_listed(const char *name, const struct unit_state *st, int n_patterns, char **patterns) {
        const char *suffix;

        if (!pattern_matches(n_patterns, patterns, name))
                return false;
        if (arg_type && (!(suffix = unit_type_suffix(name)) || !csv_contains(arg_type, suffix)))
                return false;
        if (arg_all)
                return true;
        if (arg_state)
                return csv_contains(arg_state, st->active_state) || csv_contains(arg_state, st->sub_state) ||
                                csv_contains(arg_state, st->load_state);
        return st->job[0] || strcmp(st->active_state, "inactive") != 0;
}

/* The trailing block output_units_list() prints; the arrow is always UTF-8
 * here, as in the "Created symlink" lines. */
static void list_units_legend(size_t records, bool any_job) {
        const char *on = records > 0 ? pico_ansi_highlight() : pico_ansi_highlight_red();
        const char *grey = pico_ansi_grey(), *normal = pico_ansi_normal();

        if (records > 0) {
                printf("\n%sLegend: LOAD   \xe2\x86\x92 Reflects whether the unit definition was properly loaded.%s\n"
                       "%s        ACTIVE \xe2\x86\x92 The high-level unit activation state, i.e. generalization of SUB.%s\n"
                       "%s        SUB    \xe2\x86\x92 The low-level unit activation state, values depend on unit type.%s\n",
                       grey,
                       normal,
                       grey,
                       normal,
                       grey,
                       normal);
                if (any_job)
                        printf("%s        JOB    \xe2\x86\x92 Pending job for the unit.%s\n", grey, normal);
        }
        putchar('\n');

        if (arg_all || (arg_state && csv_contains(arg_state, "inactive")))
                printf("%s%zu loaded units listed.%s\n%sTo show all installed unit files use 'systemctl "
                       "list-unit-files'.%s\n",
                       on,
                       records,
                       normal,
                       grey,
                       normal);
        else if (!arg_state)
                printf("%s%zu loaded units listed.%s %sPass --all to see loaded but inactive units, too.%s\n"
                       "%sTo show all installed unit files use 'systemctl list-unit-files'.%s\n",
                       on,
                       records,
                       normal,
                       grey,
                       normal,
                       grey,
                       normal);
        else
                printf("%zu loaded units listed.\n", records);
}

/* Header-only output for a unit type pico-init does not have (timers,
 * paths, automounts): the empty table systemctl prints, not an error. */
static int list_empty_table(const char *type, const char * const *columns, size_t n_columns) {
        size_t i;

        if (output_is_json()) {
                struct json_out j;

                json_begin(&j);
                json_end(&j);
                return 0;
        }

        if (arg_legend == 0)
                return 0;

        for (i = 0; i < n_columns; i++)
                printf("%s%s", i ? " " : "", columns[i]);
        printf("\n\n%s0 %ss listed.%s\n", pico_ansi_highlight_red(), type, pico_ansi_normal());
        if (!arg_all)
                printf("Pass --all to see loaded but inactive %ss, too.\n", type);
        return 0;
}

static int cmd_list_timers(int argc, char *argv[]) {
        static const char * const columns[] = { "NEXT", "LEFT", "LAST", "PASSED", "UNIT", "ACTIVATES" };

        (void) argc;
        (void) argv;
        return list_empty_table("timer", columns, 6);
}

static int cmd_list_paths(int argc, char *argv[]) {
        static const char * const columns[] = { "PATH", "CONDITION", "UNIT", "ACTIVATES" };

        (void) argc;
        (void) argv;
        return list_empty_table("path", columns, 4);
}

static int cmd_list_automounts(int argc, char *argv[]) {
        static const char * const columns[] = { "WHAT", "WHERE", "MOUNTED", "IDLE TIMEOUT", "UNIT" };

        (void) argc;
        (void) argv;
        return list_empty_table("automount", columns, 5);
}

static int cmd_list_units(int argc, char *argv[]) {
        char rt[PATH_MAX];
        char unitsdir[PATH_MAX + 16];
        DIR *d;
        struct dirent *de;
        char **names = NULL;
        size_t n = 0, cap = 0;
        size_t i, records = 0, job_count = 0;
        struct json_out j;

        /*
         * --all/-a un-hides inactive units, as upstream does. --no-pager is a
         * no-op because there is no pager. --type/--state/--failed come from
         * main()'s getopt_long() pass (arg_type/arg_state), so both
         * "--type=VALUE" and "-t VALUE" work; the remaining arguments are
         * glob patterns on the unit name.
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

        /* Pass 0 only counts: the JOB column exists only when some listed
         * unit has a job (output_units_list() hides it otherwise), and the
         * header has to know before the first row. */
        for (i = 0; i < n; i++) {
                struct unit_state st;

                read_unit_state(names[i], &st);
                if (!unit_listed(names[i], &st, argc, argv))
                        continue;
                records++;
                if (st.job[0])
                        job_count++;
        }

        if (output_is_json())
                json_begin(&j);
        else if (arg_legend != 0) {
                if (job_count)
                        printf("%-32s %-8s %-10s %-13s %-8s %s\n",
                               "UNIT",
                               "LOAD",
                               "ACTIVE",
                               "SUB",
                               "JOB",
                               "DESCRIPTION");
                else
                        printf("%-32s %-8s %-10s %-13s %s\n", "UNIT", "LOAD", "ACTIVE", "SUB", "DESCRIPTION");
        }

        for (i = 0; i < n; i++) {
                struct unit_state st;

                read_unit_state(names[i], &st);
                if (!unit_listed(names[i], &st, argc, argv)) {
                        free(names[i]);
                        continue;
                }

                if (output_is_json()) {
                        json_row_begin(&j);
                        json_field(&j, "unit", names[i]);
                        json_field(&j, "load", st.load_state);
                        json_field(&j, "active", st.active_state);
                        json_field(&j, "sub", st.sub_state);
                        if (job_count)
                                json_field(&j, "job", st.job);
                        json_field(&j, "description", st.description);
                        json_row_end(&j);
                } else {
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

                        printf("%s%-32s%s %s%-8s%s %s%-10s%s %s%-13s%s ",
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
                               off_sub);
                        if (job_count)
                                printf("%-8s ", st.job);
                        printf("%s\n", st.description);
                }
                free(names[i]);
        }
        free(names);

        if (output_is_json())
                json_end(&j);
        else if (arg_legend != 0)
                list_units_legend(records, job_count > 0);

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

/* --wait: poll until startup has settled, the state files being the only
 * thing to wait on (upstream waits for the StartupFinished signal). */
static int cmd_is_system_running(int argc, char *argv[]) {
        char word[16] = "";
        int rc;

        (void) argv;
        if (argc > 0) {
                picoctl_error("Too many arguments.");
                return 1;
        }

        for (;;) {
                static const struct timespec step = { .tv_nsec = 100 * 1000 * 1000 };

                rc = is_system_running_compute(true, word, sizeof(word));
                if (!arg_wait || strcmp(word, "starting") != 0)
                        break;
                nanosleep(&step, NULL);
        }

        if (!arg_quiet)
                printf("%s\n", word);
        return rc;
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

        if (arg_output == OUTPUT_CAT) {
                if (msg && !msg->binary) {
                        fwrite(msg->value, 1, msg->value_len, stdout);
                        putchar('\n');
                }
                return;
        }

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
        char datebuf[80];
        char relbuf[64];
        const char *fmt;
        bool utc = arg_timestamp_style == TIMESTAMP_UTC || arg_timestamp_style == TIMESTAMP_US_UTC;

        if (arg_timestamp_style == TIMESTAMP_UNIX) {
                format_since_relative(boot, relbuf, sizeof(relbuf));
                printf("    Since: @%lld; %s\n", (long long) boot, relbuf);
                return;
        }

        if (!(utc ? gmtime_r(&boot, &tmv) : localtime_r(&boot, &tmv)))
                return;
        /* upstream prefixes the 3-letter weekday itself (weekday_to_string())
         * rather than trusting the current locale's %a, so this project's
         * build does not have to be run under the C locale to match it.
         * /proc/stat's btime has whole seconds only, so the microsecond
         * styles print zeros. */
        if (arg_timestamp_style == TIMESTAMP_US || arg_timestamp_style == TIMESTAMP_US_UTC)
                fmt = "%a %Y-%m-%d %H:%M:%S.000000 %Z";
        else
                fmt = "%a %Y-%m-%d %H:%M:%S %Z";
        strftime(datebuf, sizeof(datebuf), fmt, &tmv);
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

/* --now: start (enable, reenable) or stop (disable, mask) the same units
 * once the symlinks are in place, and only if they were. */
static int cmd_verb_generic(int argc, char *argv[], const char *wire_verb, const char *display_verb);

static int now_after(int status, int argc, char *argv[], const char *wire_verb) {
        if (!arg_now || status != 0)
                return status;
        return cmd_verb_generic(argc, argv, wire_verb, wire_verb);
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

        return now_after(status, argc, argv, "start");
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

        return now_after(status, argc, argv, "start");
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

        return now_after(status, argc, argv, "stop");
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
/* One unit through the preset rules; *ret_enable is the verdict, whether or
 * not --preset-mode let it be acted on. */
static int preset_unit(const char *name, bool *ret_enable) {
        Manager *m = NULL;
        Unit *u = NULL;
        int r = load_install_info(name, &m, &u);
        int decision, status = 0;
        bool enable;

        if (r < 0) {
                picoctl_error("Failed to preset unit, unit %s does not exist.", name);
                return 1;
        }

        decision = manager_preset_query(m, u->id);
        if (decision < 0 && decision != -ENOENT) {
                picoctl_error("Failed to query preset for %s: %s", name, strerror(-decision));
                manager_free(m);
                return 1;
        }

        enable = decision == 1 || decision == -ENOENT;
        *ret_enable = enable;

        /* no per-unit summary line here either: same per-symlink
         * "Created symlink"/"Removed" output as enable/disable. */
        if (enable && strcmp(arg_preset_mode, "disable-only") != 0) {
                r = do_enable_unit(u);
                if (r == -ENOEXEC)
                        print_no_install_info_notice(); /* same non-error notice as enable */
                else if (r < 0) {
                        picoctl_error("Failed to preset unit %s: %s", name, strerror(-r));
                        status = 1;
                }
        } else if (!enable && strcmp(arg_preset_mode, "enable-only") != 0)
                do_disable_unit(u);

        manager_free(m);
        return status;
}

static int cmd_preset(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                picoctl_error("picoctl preset: missing unit name");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                bool enable = false;
                int r = preset_unit(argv[i], &enable);

                status |= r;
                if (arg_now && r == 0 &&
                    cmd_verb_generic(1, &argv[i], enable ? "start" : "stop", enable ? "start" : "stop"))
                        status = 1;
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

        return now_after(status, argc, argv, "stop");
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

/*
 * STATE: masked (a /dev/null symlink shadows it), static (no [Install] data
 * at all), or enabled/disabled, decided by whether a .wants/.requires symlink
 * exists -- the same check cmd_is_enabled() makes. A fragment present but
 * failed to parse reads as "bad" (upstream's UNIT_FILE_BAD). PRESET is shown
 * only for "disabled", the one state a preset rule could still flip (as
 * show_preset_for_state() upstream); every other row prints "-".
 */
static const char *unit_file_state_of(const char *name, const char **ret_preset) {
        const char *state;
        Manager *m = NULL;
        Unit *u = NULL;

        *ret_preset = "-";
        if (unit_is_masked(name))
                return "masked";
        if (load_install_info(name, &m, &u) < 0)
                return "bad";

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
                        *ret_preset = (decision == 1 || decision == -ENOENT) ? "enabled" : "disabled";
                }
        }
        manager_free(m);
        return state;
}

static int cmd_list_unit_files(int argc, char *argv[]) {
        char updir[PATH_MAX], pkgdir[PATH_MAX];
        struct unit_file_entry *entries = NULL;
        size_t n = 0, cap = 0, i, listed = 0;
        struct json_out j;

        /* --no-legend, --type and --state come from main()'s getopt_long()
         * pass; the arguments are glob patterns on the file name. */

        if (path_join(updir, sizeof(updir), PICO_UNIT_DIR) == 0)
                collect_unit_files_from(updir, &entries, &n, &cap);
        if (path_join(pkgdir, sizeof(pkgdir), PICO_PACKAGED_UNIT_DIR) == 0)
                collect_unit_files_from(pkgdir, &entries, &n, &cap);

        if (entries && n > 1)
                qsort(entries, n, sizeof(*entries), unit_file_entry_cmp);

        if (output_is_json())
                json_begin(&j);
        else if (arg_legend != 0)
                printf("%-40s %-10s %s\n", "UNIT FILE", "STATE", "PRESET");

        for (i = 0; i < n; i++) {
                const char *preset;
                const char *state;
                const char *suffix;

                if (!pattern_matches(argc, argv, entries[i].name))
                        continue;
                if (arg_type &&
                    (!(suffix = unit_type_suffix(entries[i].name)) || !csv_contains(arg_type, suffix)))
                        continue;

                state = unit_file_state_of(entries[i].name, &preset);
                if (arg_state && !csv_contains(arg_state, state))
                        continue;
                listed++;

                if (output_is_json()) {
                        json_row_begin(&j);
                        json_field(&j, "unit_file", entries[i].name);
                        json_field(&j, "state", state);
                        json_field(&j, "preset", strcmp(preset, "-") == 0 ? NULL : preset);
                        json_row_end(&j);
                } else {
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

        if (output_is_json())
                json_end(&j);
        else if (arg_legend != 0)
                printf("\n%zu unit files listed.\n", listed);

        free(entries);
        return 0;
}

/* preset-all: every unit file through the preset rules, as `preset` would. */
static int cmd_preset_all(int argc, char *argv[]) {
        char updir[PATH_MAX], pkgdir[PATH_MAX];
        struct unit_file_entry *entries = NULL;
        size_t n = 0, cap = 0, i;
        int status = 0;

        (void) argv;
        if (argc > 0) {
                picoctl_error("picoctl: preset-all takes no arguments");
                return 1;
        }

        if (path_join(updir, sizeof(updir), PICO_UNIT_DIR) == 0)
                collect_unit_files_from(updir, &entries, &n, &cap);
        if (path_join(pkgdir, sizeof(pkgdir), PICO_PACKAGED_UNIT_DIR) == 0)
                collect_unit_files_from(pkgdir, &entries, &n, &cap);
        if (entries && n > 1)
                qsort(entries, n, sizeof(*entries), unit_file_entry_cmp);

        for (i = 0; i < n; i++) {
                bool enable;

                if (unit_is_masked(entries[i].name))
                        continue;
                /* a unit that does not parse is list-unit-files' "bad", not a
                 * reason to abandon the sweep */
                if (preset_unit(entries[i].name, &enable) != 0)
                        status = 1;
        }

        free(entries);
        return status;
}

/*
 * add-wants/add-requires TARGET UNIT...: a .wants/.requires symlink in the
 * etc directory, the same one enable creates from a unit's own [Install]
 * section.
 */
static int add_dependency(int argc, char *argv[], const char *suffix) {
        char *target;
        int i, status = 0;

        if (argc < 2) {
                picoctl_error("picoctl: a target and at least one unit are required");
                return 1;
        }

        /* a bare target is a .target, a bare unit a .service */
        target = mangle_unit_arg_suffix(argv[0], ".target");
        for (i = 1; i < argc; i++) {
                Manager *m = NULL;
                Unit *u = NULL;
                char *name = mangle_unit_arg_suffix(argv[i], ".service");
                int r = load_install_info(name ? name : argv[i], &m, &u);

                if (r < 0) {
                        picoctl_error("Failed to add dependency, unit %s does not exist.", argv[i]);
                        status = 1;
                } else {
                        r = create_enable_symlink(target ? target : argv[0], suffix, u);
                        if (r < 0) {
                                picoctl_error("Failed to add dependency on %s: %s", argv[i], strerror(-r));
                                status = 1;
                        }
                        manager_free(m);
                }
                free(name);
        }
        free(target);

        return status;
}

static int cmd_add_wants(int argc, char *argv[]) {
        return add_dependency(argc, argv, ".wants");
}

static int cmd_add_requires(int argc, char *argv[]) {
        return add_dependency(argc, argv, ".requires");
}

/* link PATH...: symlink a unit file from outside the search path into the
 * etc directory, as mask does with /dev/null. */
static int cmd_link(int argc, char *argv[]) {
        int i, status = 0;

        if (argc < 1) {
                picoctl_error("picoctl link: missing unit file path");
                return 1;
        }

        for (i = 0; i < argc; i++) {
                char etcdir[PATH_MAX];
                char linkpath[PATH_MAX + 64];
                const char *base = strrchr(argv[i], '/');
                struct stat st;
                int r;

                base = base ? base + 1 : argv[i];
                if (argv[i][0] != '/') {
                        picoctl_error("Failed to link unit: Path \"%s\" is not absolute.", argv[i]);
                        status = 1;
                        continue;
                }
                if (!unit_name_is_valid(base)) {
                        picoctl_error("Failed to link unit: Invalid unit name \"%s\".", base);
                        status = 1;
                        continue;
                }
                if (stat(argv[i], &st) < 0 || !S_ISREG(st.st_mode)) {
                        picoctl_error("Failed to link unit: Unit file %s not found.", argv[i]);
                        status = 1;
                        continue;
                }
                if (path_join(etcdir, sizeof(etcdir), PICO_UNIT_DIR) < 0) {
                        status = 1;
                        continue;
                }

                r = unit_enable_create_symlink(etcdir, "", "", base, argv[i]);
                if (r < 0) {
                        picoctl_error("Failed to link unit %s: %s", argv[i], strerror(-r));
                        status = 1;
                        continue;
                }
                if (r == 1) {
                        snprintf(linkpath, sizeof(linkpath), "%s/%s", etcdir, base);
                        printf("Created symlink '%s' \xe2\x86\x92 '%s'.\n", linkpath, argv[i]);
                }
        }

        return status;
}

/* get-default: what the manager published as its default target. The
 * target is fixed at boot, so this has no set-default counterpart. */
static int cmd_get_default(int argc, char *argv[]) {
        char rt[PATH_MAX];
        char path[PATH_MAX + 16];
        char line[256];
        const char *name = PICO_DEFAULT_TARGET;
        char found[256] = "";
        FILE *f;

        (void) argc;
        (void) argv;

        if (path_join(rt, sizeof(rt), PICO_RUNTIME_DIR) == 0) {
                snprintf(path, sizeof(path), "%s/manager", rt);
                f = fopen(path, "re");
                if (f) {
                        while (fgets(line, sizeof(line), f))
                                if (strncmp(line, "DefaultTarget=", 14) == 0) {
                                        snprintf(found, sizeof(found), "%s", line + 14);
                                        found[strcspn(found, "\n")] = '\0';
                                }
                        fclose(f);
                }
        }
        if (found[0])
                name = found;

        printf("%s\n", name);
        return 0;
}

/* The unit a process belongs to, from the system.slice/<unit> component of
 * its unified-hierarchy cgroup path. */
static int whoami_pid(pid_t pid) {
        char path[64];
        char line[PATH_MAX + 8];
        FILE *f;
        char unit[UNIT_NAME_MAX + 1] = "";

        snprintf(path, sizeof(path), "/proc/%d/cgroup", (int) pid);
        f = fopen(path, "re");
        if (!f) {
                picoctl_error("Failed to get unit for PID %d: %s", (int) pid, strerror(errno));
                return 1;
        }
        while (fgets(line, sizeof(line), f)) {
                char *p = strstr(line, "/system.slice/");
                size_t len;

                if (strncmp(line, "0::", 3) != 0 || !p)
                        continue;
                p += strlen("/system.slice/");
                len = strcspn(p, "/\n");
                if (len > 0 && len <= UNIT_NAME_MAX) {
                        memcpy(unit, p, len);
                        unit[len] = '\0';
                }
        }
        fclose(f);

        if (!unit[0]) {
                picoctl_error("Failed to get unit for PID %d: PID %d does not belong to any loaded unit.",
                              (int) pid,
                              (int) pid);
                return 1;
        }
        printf("%s\n", unit);
        return 0;
}

static int cmd_whoami(int argc, char *argv[]) {
        int i, status = 0;

        if (argc == 0)
                return whoami_pid(getpid());

        for (i = 0; i < argc; i++) {
                char *end;
                long v;

                errno = 0;
                v = strtol(argv[i], &end, 10);
                if (argv[i][0] == '\0' || *end != '\0' || errno != 0 || v <= 0) {
                        picoctl_error("Failed to parse PID \"%s\".", argv[i]);
                        status = 1;
                        continue;
                }
                status |= whoami_pid((pid_t) v);
        }
        return status;
}

struct job_row {
        unsigned id;
        char name[UNIT_NAME_MAX + 1];
        char type[16];
        bool running;
};

static int job_row_cmp(const void *a, const void *b) {
        const struct job_row *x = a, *y = b;

        return x->id < y->id ? -1 : x->id > y->id;
}

/* list-jobs: the Job= each unit's state file carries; a job is "running"
 * once its unit has left inactive/active, "waiting" before that. */
static int cmd_list_jobs(int argc, char *argv[]) {
        char rt[PATH_MAX];
        char unitsdir[PATH_MAX + 16];
        struct job_row *rows = NULL;
        size_t n = 0, cap = 0, i;
        struct dirent *de;
        struct json_out j;
        DIR *d;

        if (path_join(rt, sizeof(rt), PICO_RUNTIME_DIR) < 0)
                return 1;
        snprintf(unitsdir, sizeof(unitsdir), "%s/units", rt);
        d = opendir(unitsdir);
        if (!d) {
                picoctl_error("picoctl: no published state at %s: %s", unitsdir, strerror(errno));
                return 1;
        }

        while ((de = readdir(d))) {
                struct unit_state st;
                struct job_row *row;
                unsigned id;
                char type[16];

                if (de->d_name[0] == '.')
                        continue;
                read_unit_state(de->d_name, &st);
                if (!st.job[0] || sscanf(st.job, "%u %15s", &id, type) != 2)
                        continue;
                if (!pattern_matches(argc, argv, de->d_name))
                        continue;
                if (n == cap) {
                        struct job_row *grown = realloc(rows, (cap ? cap * 2 : 8) * sizeof(*rows));

                        if (!grown)
                                break;
                        rows = grown;
                        cap = cap ? cap * 2 : 8;
                }
                row = &rows[n];
                row->id = id;
                snprintf(row->name, sizeof(row->name), "%s", de->d_name);
                snprintf(row->type, sizeof(row->type), "%s", type);
                row->running = strcmp(st.active_state, "activating") == 0 ||
                                strcmp(st.active_state, "deactivating") == 0 ||
                                strcmp(st.active_state, "reloading") == 0;
                /* an alias reads as the same unit; list its job once */
                for (i = 0; i < n; i++)
                        if (rows[i].id == id)
                                break;
                if (i == n)
                        n++;
        }
        closedir(d);

        if (n > 1)
                qsort(rows, n, sizeof(*rows), job_row_cmp);

        if (output_is_json()) {
                json_begin(&j);
                for (i = 0; i < n; i++) {
                        json_row_begin(&j);
                        json_field_uint(&j, "job", rows[i].id);
                        json_field(&j, "unit", rows[i].name);
                        json_field(&j, "type", rows[i].type);
                        json_field(&j, "state", rows[i].running ? "running" : "waiting");
                        json_row_end(&j);
                }
                json_end(&j);
        } else if (n == 0) {
                if (arg_legend != 0)
                        printf("%sNo jobs running.%s\n", pico_ansi_highlight_green(), pico_ansi_normal());
        } else {
                if (arg_legend != 0)
                        printf("%-4s %-32s %-10s %s\n", "JOB", "UNIT", "TYPE", "STATE");
                for (i = 0; i < n; i++) {
                        const char *on = rows[i].running ? pico_ansi_highlight() : "";
                        const char *off = rows[i].running ? pico_ansi_normal() : "";

                        printf("%-4u %s%-32s%s %-10s %s%s%s\n",
                               rows[i].id,
                               on,
                               rows[i].name,
                               off,
                               rows[i].type,
                               on,
                               rows[i].running ? "running" : "waiting",
                               off);
                }
                if (arg_legend != 0)
                        printf("\n%s%zu jobs listed%s.\n", pico_ansi_highlight(), n, pico_ansi_normal());
        }

        free(rows);
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
 * --kill-whom=all (upstream's default) signals every pid in the unit's
 * cgroup, or in its --kill-subgroup= below it; --kill-whom=main signals only
 * the published MainPID. --signal/-s takes any Linux signal name or number
 * (SIGTERM by default); --kill-value= queues it with sigqueue() instead.
 * The options are global (arg_signal_name/arg_kill_whom, from main()'s
 * getopt_long() pass), so "-s KILL", "--signal KILL" and "--signal=KILL" are
 * equivalent.
 */
static const struct {
        const char *name;
        int sig;
} signal_table[] = {
        {    "HUP",    SIGHUP },
        {    "INT",    SIGINT },
        {   "QUIT",   SIGQUIT },
        {    "ILL",    SIGILL },
        {   "TRAP",   SIGTRAP },
        {   "ABRT",   SIGABRT },
        {    "BUS",    SIGBUS },
        {    "FPE",    SIGFPE },
        {   "KILL",   SIGKILL },
        {   "USR1",   SIGUSR1 },
        {   "SEGV",   SIGSEGV },
        {   "USR2",   SIGUSR2 },
        {   "PIPE",   SIGPIPE },
        {   "ALRM",   SIGALRM },
        {   "TERM",   SIGTERM },
#ifdef SIGSTKFLT
        { "STKFLT", SIGSTKFLT },
#endif
        {   "CHLD",   SIGCHLD },
        {   "CONT",   SIGCONT },
        {   "STOP",   SIGSTOP },
        {   "TSTP",   SIGTSTP },
        {   "TTIN",   SIGTTIN },
        {   "TTOU",   SIGTTOU },
        {    "URG",    SIGURG },
        {   "XCPU",   SIGXCPU },
        {   "XFSZ",   SIGXFSZ },
        { "VTALRM", SIGVTALRM },
        {   "PROF",   SIGPROF },
        {  "WINCH",  SIGWINCH },
        {     "IO",     SIGIO },
        {    "PWR",    SIGPWR },
        {    "SYS",    SIGSYS },
};

/* SIGTERM/TERM, a number, or SIGRTMIN+n / SIGRTMAX-n (signal_from_string()). */
static int signal_from_name(const char *s, int *ret) {
        size_t i;
        char *end;

        if (s[0] >= '0' && s[0] <= '9') {
                long v = strtol(s, &end, 10);

                if (*end != '\0' || v <= 0 || v > SIGRTMAX)
                        return -EINVAL;
                *ret = (int) v;
                return 0;
        }

        if (strncasecmp(s, "SIG", 3) == 0)
                s += 3;

        for (i = 0; i < sizeof(signal_table) / sizeof(signal_table[0]); i++)
                if (strcasecmp(s, signal_table[i].name) == 0) {
                        *ret = signal_table[i].sig;
                        return 0;
                }

        if (strncasecmp(s, "RTMIN", 5) == 0 || strncasecmp(s, "RTMAX", 5) == 0) {
                bool is_min = (s[2] == 'M' || s[2] == 'm') && (s[3] == 'I' || s[3] == 'i');
                int base = is_min ? SIGRTMIN : SIGRTMAX;
                long off = 0;

                if (s[5] != '\0') {
                        if ((s[5] != '+' && s[5] != '-') || s[6] == '\0')
                                return -EINVAL;
                        off = strtol(s + 5, &end, 10);
                        if (*end != '\0')
                                return -EINVAL;
                }
                if ((is_min && off < 0) || (!is_min && off > 0) || base + off < SIGRTMIN ||
                    base + off > SIGRTMAX)
                        return -EINVAL;
                *ret = base + (int) off;
                return 0;
        }

        return -EINVAL;
}

static void signal_help(void) {
        size_t i;

        for (i = 0; i < sizeof(signal_table) / sizeof(signal_table[0]); i++)
                printf("SIG%s\n", signal_table[i].name);
}

/* --kill-value= turns kill(2) into sigqueue(3), carrying the integer. */
static int signal_pid(pid_t pid, int sig) {
        if (arg_kill_value_set) {
                union sigval v = { .sival_int = arg_kill_value };

                return sigqueue(pid, sig, v);
        }
        return kill(pid, sig);
}

static bool subgroup_is_safe(const char *path) {
        const char *p = path;

        while (*p) {
                size_t len;

                while (*p == '/')
                        p++;
                len = strcspn(p, "/");
                if ((len == 2 && p[0] == '.' && p[1] == '.') || (len == 1 && p[0] == '.'))
                        return false;
                p += len;
        }
        return true;
}

static int cmd_kill(int argc, char *argv[]) {
        int sig = SIGTERM;
        bool kill_main_only = strcmp(arg_kill_whom, "main") == 0;
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
                char path[PATH_MAX + 128];
                FILE *f;
                char line[32];

                read_unit_state(argv[i], &st);
                if (!st.found) {
                        picoctl_error("Failed to kill unit %s: Unit %s not loaded.", argv[i], argv[i]);
                        status = 1;
                        continue;
                }

                if (kill_main_only || st.main_pid <= 0) {
                        if (st.main_pid > 0)
                                signal_pid(st.main_pid, sig);
                } else if (path_join(cgroup_root, sizeof(cgroup_root), PICO_CGROUP_ROOT) == 0) {
                        const char *sub = arg_kill_subgroup ? arg_kill_subgroup : "";

                        while (*sub == '/')
                                sub++;
                        snprintf(path,
                                 sizeof(path),
                                 "%s/system.slice/%s%s%s/cgroup.procs",
                                 cgroup_root,
                                 argv[i],
                                 sub[0] ? "/" : "",
                                 sub);
                        f = fopen(path, "re");
                        if (f) {
                                while (fgets(line, sizeof(line), f)) {
                                        pid_t pid = (pid_t) atoi(line);

                                        if (pid > 0)
                                                signal_pid(pid, sig);
                                }
                                fclose(f);
                        }
                }

                /* Nothing running is a harmless no-op upstream too (killing
                 * an empty cgroup signals zero processes, successfully). */
        }

        return status;
}

/* --- main --- */

static void usage(void) {
        fputs("picoctl [OPTIONS...] COMMAND [UNIT...]\n"
              "\n"
              "Query or send control commands to the pico-init service manager.\n"
              "\n"
              "Unit Commands:\n"
              "  list-units [PATTERN...]     List units currently in memory\n"
              "  list-timers, list-paths, list-automounts [PATTERN...]\n"
              "                              List units of those types (always empty)\n"
              "  is-active, is-failed UNIT...  Check whether units are active or failed\n"
              "  status [UNIT...]            Show runtime status of one or more units\n"
              "  show [UNIT...]              Show properties of units, or of the manager\n"
              "  cat UNIT...                 Show the files of the specified units\n"
              "  start, stop, restart, try-restart, reload-or-restart,\n"
              "  try-reload-or-restart UNIT...  Queue a job for one or more units\n"
              "  reload UNIT...              Always refused: there is no ExecReload=\n"
              "  kill UNIT...                Send a signal to the processes of a unit\n"
              "  reset-failed [UNIT...]      Reset failed state\n"
              "  whoami [PID...]             Show the unit a process belongs to\n"
              "\n"
              "Unit File Commands:\n"
              "  list-unit-files [PATTERN...]  List installed unit files\n"
              "  enable, disable, reenable, preset, mask, unmask UNIT...\n"
              "  preset-all                  Apply the preset rules to every unit file\n"
              "  is-enabled UNIT...          Check whether unit files are enabled\n"
              "  link PATH...                Link unit files into the search path\n"
              "  add-wants, add-requires TARGET UNIT...\n"
              "  get-default                 Show the default target\n"
              "\n"
              "Job Commands:\n"
              "  list-jobs [PATTERN...]      List jobs\n"
              "\n"
              "Manager and System Commands:\n"
              "  daemon-reload               Re-read the unit files\n"
              "  is-system-running           Check whether the system is fully running\n"
              "  reboot, poweroff, halt      Signal PID 1 to shut down\n"
              "\n"
              "Verbs that need a bus, a scheduler or a target switch (isolate, edit, list-dependencies,\n"
              "set-default, rescue, suspend, ...) are refused.\n"
              "\n"
              "Options:\n"
              "  -h --help              Show this help\n"
              "     --version           Show package version\n"
              "  -t --type=TYPE         List units of a particular type\n"
              "     --state=STATE       List units with particular LOAD, SUB or ACTIVE state\n"
              "     --failed            Shortcut for --state=failed\n"
              "  -p --property=NAME     Show only properties by this name\n"
              "  -P NAME                Equivalent to --value --property=NAME\n"
              "  -a --all               Show all units, including inactive ones\n"
              "  -l --full, --plain     Accepted; output is never ellipsized\n"
              "     --value             When showing properties, only print the value\n"
              "     --job-mode=MODE     replace or fail\n"
              "  -s --signal=SIGNAL     Which signal to send (help lists them)\n"
              "     --kill-whom=WHOM    main or all\n"
              "     --kill-value=INT    Signal value to enqueue\n"
              "     --kill-subgroup=PATH  Send the signal to a cgroup sub-path only\n"
              "     --now               Start or stop the unit after enabling or disabling it\n"
              "     --preset-mode=MODE  full, enable-only or disable-only\n"
              "     --dry-run           Only print what would be done (reboot, poweroff, halt)\n"
              "  -q --quiet             Suppress output\n"
              "     --wait              For is-system-running, wait until startup is completed\n"
              "     --no-block          Do not wait until the operation finished\n"
              "     --legend=BOOL      Enable or disable the legend\n"
              "     --no-legend         Do not show the headers and footers\n"
              "     --no-pager, --no-wall, --no-ask-password, --no-warn, --no-reload,\n"
              "     -v, -T, -i, -f, --message=, --check-inhibitors=  Accepted; nothing to do here\n"
              "  -n --lines=INTEGER     Number of log lines to show\n"
              "  -o --output=STRING     json, json-pretty, json-sse, json-seq for the list verbs;\n"
              "                         cat for the log lines of status\n"
              "     --timestamp=FORMAT  pretty, unix, us, utc or us+utc\n"
              "     --root=PATH         Operate on the unit files and state below PATH\n"
              "     --system            The only mode there is\n"
              "\n"
              "Invoked as reboot, poweroff, halt or shutdown, picoctl takes that command's options.\n",
              stdout);
}

/* The sysvinit-style personalities' own --help. */
static void usage_compat(const char *name) {
        printf("%s [OPTIONS...]%s\n"
               "\n"
               "Shut down or restart the system.\n"
               "\n"
               "     --help      Show this help\n"
               "     --halt      Halt the machine\n"
               "  -p --poweroff  Switch off the machine\n"
               "     --reboot    Reboot the machine\n"
               "  -f --force     Force immediate halt/power-off/reboot\n"
               "  -w --wtmp-only Don't halt/power-off/reboot, do nothing\n"
               "  -d --no-wtmp   Accepted, there is no wtmp record\n"
               "     --no-wall   Accepted, there is no wall message\n",
               name,
               strcmp(name, "reboot") == 0 ? " [ARG]" : "");
}

static void usage_shutdown(void) {
        fputs("shutdown [OPTIONS...] [now|+0] [MESSAGE...]\n"
              "\n"
              "Shut down the system immediately.\n"
              "\n"
              "     --help      Show this help\n"
              "  -H --halt      Halt the machine\n"
              "  -P --poweroff  Power-off the machine\n"
              "  -r --reboot    Reboot the machine\n"
              "  -h             Equivalent to --poweroff, overridden by --halt\n"
              "  -k             Don't halt/power-off/reboot, do nothing\n"
              "     --no-wall   Accepted, there is no wall message\n"
              "  -c             Cancel a pending shutdown (there never is one)\n"
              "     --show      Show pending shutdown (there never is one)\n",
              stdout);
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
 * caller-owned, malloc'd suffixed copy otherwise.
 */
static char *mangle_unit_arg_suffix(const char *arg, const char *suffix) {
        char *out;
        size_t len;

        if (!arg || arg[0] == '-' || strchr(arg, '.'))
                return NULL;

        len = strlen(arg);
        out = malloc(len + strlen(suffix) + 1);
        if (!out)
                return NULL;

        memcpy(out, arg, len);
        strcpy(out + len, suffix);
        return out;
}

/*
 * reboot/poweroff/halt/shutdown: a simplification of what real systemctl/
 * reboot(8)/halt(8) do -- those go through logind and a D-Bus StartUnit on
 * halt/poweroff/reboot.target, reaching a raw syscall only with --force
 * (src/systemctl/systemctl-compat-halt.c). Here kill(1, sig) uses PID 1's own
 * signal convention (manager-loop.c's manager_dispatch_signal(): SIGINT ->
 * MANAGER_REBOOT, SIGRTMIN+3/+4 -> MANAGER_POWEROFF, matching manager.c's
 * target_table), since there is no logind/D-Bus to call. Every invocation
 * acts immediately: there is no scheduler, no wall message and no wtmp.
 *
 * /sbin/reboot, /sbin/poweroff, /sbin/halt and /sbin/shutdown are meant to
 * be symlinked straight at this binary, like systemctl itself; main()
 * dispatches on argv[0]'s basename before any verb parsing.
 */
enum power_action {
        POWER_HALT,
        POWER_POWEROFF,
        POWER_REBOOT,
};

static int send_pid1_signal(int sig, const char *what) {
        if (kill(1, sig) < 0) {
                picoctl_error("picoctl: %s: kill(1, %d): %s", what, sig, strerror(errno));
                return 1;
        }
        return 0;
}

static int power_do(enum power_action action, bool dry_run) {
        if (dry_run)
                return 0;

        switch (action) {
        case POWER_REBOOT:
                return send_pid1_signal(SIGINT, "reboot");
        case POWER_POWEROFF:
                return send_pid1_signal(SIGRTMIN + 4, "poweroff");
        default:
                return send_pid1_signal(SIGRTMIN + 3, "halt");
        }
}

static int power_verb(enum power_action action, int argc) {
        if (argc > 0) {
                picoctl_error("Too many arguments.");
                return 1;
        }
        return power_do(action, arg_dry_run);
}

static int cmd_reboot(int argc, char *argv[]) {
        (void) argv;
        return power_verb(POWER_REBOOT, argc);
}

static int cmd_poweroff(int argc, char *argv[]) {
        (void) argv;
        return power_verb(POWER_POWEROFF, argc);
}

static int cmd_halt(int argc, char *argv[]) {
        (void) argv;
        return power_verb(POWER_HALT, argc);
}

/*
 * halt_parse_argv() (systemctl-compat-halt.c): the options the halt, poweroff
 * and reboot names have always taken. -f and -n only matter to a daemon that
 * syncs and unmounts itself, and -d, -i, -h and --no-wall have nothing to
 * suppress; -w asks for the wtmp record alone, which leaves nothing to do.
 */
static int compat_halt(enum power_action action, int argc, char *argv[]) {
        enum {
                ARG_HELP = 0x100,
                ARG_HALT,
                ARG_REBOOT,
                ARG_NO_WALL,
        };
        static const struct option options[] = {
                {      "help", no_argument, NULL,    ARG_HELP },
                {      "halt", no_argument, NULL,    ARG_HALT },
                {  "poweroff", no_argument, NULL,         'p' },
                {    "reboot", no_argument, NULL,  ARG_REBOOT },
                {     "force", no_argument, NULL,         'f' },
                { "wtmp-only", no_argument, NULL,         'w' },
                {   "no-wtmp", no_argument, NULL,         'd' },
                {   "no-wall", no_argument, NULL, ARG_NO_WALL },
                {   "no-sync", no_argument, NULL,         'n' },
                {        NULL,           0, NULL,           0 },
        };
        const char *name = strrchr(argv[0], '/');
        bool dry_run = false;
        int c, remaining;

        name = name ? name + 1 : argv[0];
        optind = 1;
        while ((c = getopt_long(argc, argv, "pfwdnih", options, NULL)) >= 0) {
                switch (c) {
                case ARG_HELP:
                        usage_compat(name);
                        return 0;
                case ARG_HALT:
                        action = POWER_HALT;
                        break;
                case 'p':
                        if (action != POWER_REBOOT)
                                action = POWER_POWEROFF;
                        break;
                case ARG_REBOOT:
                        action = POWER_REBOOT;
                        break;
                case 'w':
                        dry_run = true;
                        break;
                case 'f':
                case 'd':
                case 'n':
                case 'i':
                case 'h':
                case ARG_NO_WALL:
                        break;
                default:
                        return 1;
                }
        }

        remaining = argc - optind;
        if (action == POWER_REBOOT && remaining <= 1) {
                if (remaining == 1 && argv[optind][0]) {
                        picoctl_error("A reboot argument is not supported: there is nothing to pass it to.");
                        return 1;
                }
        } else if (remaining > 0) {
                picoctl_error("Too many arguments.");
                return 1;
        }

        return power_do(action, dry_run);
}

/* "now", "+0" and the unparsed rest: only the immediate forms can be done. */
static int shutdown_time_check(const char *spec) {
        int a, b;
        char c;

        if (strcmp(spec, "now") == 0 || strcmp(spec, "+0") == 0)
                return 0;
        if ((sscanf(spec, "+%d%c", &a, &c) == 1 && a > 0) || sscanf(spec, "%d:%d%c", &a, &b, &c) == 2) {
                picoctl_error("shutdown: there is no scheduler here, only 'now' and '+0' are supported.");
                return 1;
        }
        picoctl_error("Failed to parse time specification: %s", spec);
        return 1;
}

/*
 * shutdown_parse_argv() (systemctl-compat-shutdown.c). Without a time
 * argument real shutdown waits a minute through logind; here that wait does
 * not exist and the shutdown is immediate, as with every other spelling.
 */
static int compat_shutdown(int argc, char *argv[]) {
        enum {
                ARG_HELP = 0x100,
                ARG_NO_WALL,
                ARG_SHOW,
        };
        static const struct option options[] = {
                {     "help", no_argument, NULL,    ARG_HELP },
                {     "halt", no_argument, NULL,         'H' },
                { "poweroff", no_argument, NULL,         'P' },
                {   "reboot", no_argument, NULL,         'r' },
                {    "kexec", no_argument, NULL,         'K' },
                {  "no-wall", no_argument, NULL, ARG_NO_WALL },
                {     "show", no_argument, NULL,    ARG_SHOW },
                {       NULL,           0, NULL,           0 },
        };
        enum power_action action = POWER_POWEROFF;
        bool dry_run = false, cancel = false, show = false;
        int c;

        optind = 1;
        while ((c = getopt_long(argc, argv, "HPrhkcKafFt:", options, NULL)) >= 0) {
                switch (c) {
                case ARG_HELP:
                        usage_shutdown();
                        return 0;
                case 'H':
                        action = POWER_HALT;
                        break;
                case 'P':
                        action = POWER_POWEROFF;
                        break;
                case 'r':
                        action = POWER_REBOOT;
                        break;
                case 'h':
                        if (action != POWER_HALT)
                                action = POWER_POWEROFF;
                        break;
                case 'k':
                        dry_run = true;
                        break;
                case 'c':
                        cancel = true;
                        break;
                case ARG_SHOW:
                        show = true;
                        break;
                case 'K':
                        picoctl_error("shutdown: kexec is not supported.");
                        return 1;
                case 'a':
                case 'f':
                case 'F':
                case 't':
                case ARG_NO_WALL:
                        break;
                default:
                        return 1;
                }
        }

        /* nothing is ever scheduled, so there is nothing to show or cancel */
        if (show) {
                puts("No scheduled shutdown.");
                return 0;
        }
        if (cancel)
                return 0;

        if (optind < argc && shutdown_time_check(argv[optind]) != 0)
                return 1;

        return power_do(action, dry_run);
}

/*
 * One getopt_long() pass, permuting (no leading '+' in the optstring,
 * POSIXLY_CORRECT not set), over the whole argv, as systemctl_parse_argv()
 * does: an option may sit before, between or after the verb and unit
 * arguments, "--" ends option parsing, and both "--opt=value" and "--opt
 * value"/"-o value" work. Unknown options and missing arguments get
 * getopt_long's own stderr message (opterr is left at 1) and exit 1.
 *
 * Every option v262's systemctl takes is recognised, so none falls through
 * to getopt's "unrecognized option". They sort three ways:
 *
 *  - real: it changes what picoctl does;
 *  - accepted and ignored, where there is nothing for it to act on --
 *    --no-pager (no pager), --no-wall/--message (no wall), --no-ask-password,
 *    --no-warn, --no-reload (picoctl never reloads), -v, -T, -i and
 *    --check-inhibitors (no inhibitors), -l/--full/--plain (output is never
 *    ellipsized), and the options only a verb pico-init lacks would read;
 *  - refused, because acting as if they were honoured would be wrong: --user,
 *    --global, -C, -H, -M, --image, -r (no other manager or machine to talk
 *    to), --runtime, --with-dependencies, --irreversible, --ignore-dependencies
 *    and the other job modes, --marked, and the boot loader, firmware and
 *    kernel command line options of reboot.
 */
static void csv_append(char *buf, size_t size, const char *word) {
        size_t len = strlen(buf);

        snprintf(buf + len, size - len, "%s%s", len ? "," : "", word);
}

static int parse_bool_arg(const char *name, const char *value, int *ret) {
        static const char * const yes[] = { "1", "yes", "true", "on", "y", "t" };
        static const char * const no[] = { "0", "no", "false", "off", "n", "f" };
        size_t i;

        for (i = 0; i < sizeof(yes) / sizeof(yes[0]); i++) {
                if (strcasecmp(value, yes[i]) == 0) {
                        *ret = 1;
                        return 0;
                }
                if (strcasecmp(value, no[i]) == 0) {
                        *ret = 0;
                        return 0;
                }
        }
        picoctl_error("Failed to parse %s argument: %s", name, value);
        return -EINVAL;
}

static int refuse_option(const char *what, const char *why) {
        picoctl_error("%s is not supported: %s", what, why);
        return 1;
}

static int picoctl_parse_options(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
                ARG_ROOT,
                ARG_NO_BLOCK,
                ARG_NO_LEGEND,
                ARG_LEGEND,
                ARG_NO_PAGER,
                ARG_NO_WALL,
                ARG_STATE,
                ARG_FAILED,
                ARG_KILL_WHOM,
                ARG_KILL_VALUE,
                ARG_KILL_SUBGROUP,
                ARG_SYSTEM,
                ARG_USER,
                ARG_GLOBAL,
                ARG_VALUE,
                ARG_JOB_MODE,
                ARG_FAIL,
                ARG_IRREVERSIBLE,
                ARG_IGNORE_DEPENDENCIES,
                ARG_CHECK_INHIBITORS,
                ARG_IGNORE_INHIBITORS,
                ARG_NOW,
                ARG_DRY_RUN,
                ARG_NO_WARN,
                ARG_NO_RELOAD,
                ARG_NO_ASK_PASSWORD,
                ARG_WAIT,
                ARG_MESSAGE,
                ARG_RUNTIME,
                ARG_PRESET_MODE,
                ARG_IMAGE,
                ARG_IMAGE_POLICY,
                ARG_TIMESTAMP,
                ARG_PLAIN,
                ARG_WITH_DEPENDENCIES,
                ARG_REVERSE,
                ARG_BEFORE,
                ARG_AFTER,
                ARG_SHOW_TYPES,
                ARG_WHAT,
                ARG_FIRMWARE_SETUP,
                ARG_BOOT_LOADER_MENU,
                ARG_BOOT_LOADER_ENTRY,
                ARG_REBOOT_ARGUMENT,
                ARG_KERNEL_CMDLINE,
                ARG_KERNEL_CMDLINE_REUSE,
                ARG_READ_ONLY,
                ARG_MKDIR,
                ARG_MARKED,
                ARG_DROP_IN,
                ARG_WHEN,
                ARG_STDIN,
        };
        static const struct option options[] = {
                {                 "help",       no_argument, NULL,                      'h' },
                {              "version",       no_argument, NULL,              ARG_VERSION },
                {                 "root", required_argument, NULL,                 ARG_ROOT },
                {             "no-block",       no_argument, NULL,             ARG_NO_BLOCK },
                {            "no-legend",       no_argument, NULL,            ARG_NO_LEGEND },
                {               "legend", required_argument, NULL,               ARG_LEGEND },
                {             "no-pager",       no_argument, NULL,             ARG_NO_PAGER },
                {              "no-wall",       no_argument, NULL,              ARG_NO_WALL },
                {                "quiet",       no_argument, NULL,                      'q' },
                {                  "all",       no_argument, NULL,                      'a' },
                {                 "full",       no_argument, NULL,                      'l' },
                {                 "type", required_argument, NULL,                      't' },
                {                "state", required_argument, NULL,                ARG_STATE },
                {               "failed",       no_argument, NULL,               ARG_FAILED },
                {             "property", required_argument, NULL,                      'p' },
                {                "value",       no_argument, NULL,                ARG_VALUE },
                {                "lines", required_argument, NULL,                      'n' },
                {               "output", required_argument, NULL,                      'o' },
                {               "signal", required_argument, NULL,                      's' },
                {             "kill-who", required_argument, NULL,            ARG_KILL_WHOM },
                {            "kill-whom", required_argument, NULL,            ARG_KILL_WHOM },
                {           "kill-value", required_argument, NULL,           ARG_KILL_VALUE },
                {        "kill-subgroup", required_argument, NULL,        ARG_KILL_SUBGROUP },
                {                "force",       no_argument, NULL,                      'f' },
                {               "system",       no_argument, NULL,               ARG_SYSTEM },
                {                 "user",       no_argument, NULL,                 ARG_USER },
                {               "global",       no_argument, NULL,               ARG_GLOBAL },
                {                 "host", required_argument, NULL,                      'H' },
                {              "machine", required_argument, NULL,                      'M' },
                {              "capsule", required_argument, NULL,                      'C' },
                {            "recursive",       no_argument, NULL,                      'r' },
                {             "job-mode", required_argument, NULL,             ARG_JOB_MODE },
                {                 "fail",       no_argument, NULL,                 ARG_FAIL },
                {         "irreversible",       no_argument, NULL,         ARG_IRREVERSIBLE },
                {  "ignore-dependencies",       no_argument, NULL,  ARG_IGNORE_DEPENDENCIES },
                {     "check-inhibitors", required_argument, NULL,     ARG_CHECK_INHIBITORS },
                {    "ignore-inhibitors",       no_argument, NULL,    ARG_IGNORE_INHIBITORS },
                {                  "now",       no_argument, NULL,                  ARG_NOW },
                {              "dry-run",       no_argument, NULL,              ARG_DRY_RUN },
                {              "verbose",       no_argument, NULL,                      'v' },
                {              "no-warn",       no_argument, NULL,              ARG_NO_WARN },
                {            "no-reload",       no_argument, NULL,            ARG_NO_RELOAD },
                {      "no-ask-password",       no_argument, NULL,      ARG_NO_ASK_PASSWORD },
                {                 "wait",       no_argument, NULL,                 ARG_WAIT },
                {              "message", required_argument, NULL,              ARG_MESSAGE },
                {              "runtime",       no_argument, NULL,              ARG_RUNTIME },
                {          "preset-mode", required_argument, NULL,          ARG_PRESET_MODE },
                {                "image", required_argument, NULL,                ARG_IMAGE },
                {         "image-policy", required_argument, NULL,         ARG_IMAGE_POLICY },
                {            "timestamp", required_argument, NULL,            ARG_TIMESTAMP },
                {                "plain",       no_argument, NULL,                ARG_PLAIN },
                {    "with-dependencies",       no_argument, NULL,    ARG_WITH_DEPENDENCIES },
                {              "reverse",       no_argument, NULL,              ARG_REVERSE },
                {               "before",       no_argument, NULL,               ARG_BEFORE },
                {                "after",       no_argument, NULL,                ARG_AFTER },
                {     "show-transaction",       no_argument, NULL,                      'T' },
                {           "show-types",       no_argument, NULL,           ARG_SHOW_TYPES },
                {                 "what", required_argument, NULL,                 ARG_WHAT },
                {       "firmware-setup",       no_argument, NULL,       ARG_FIRMWARE_SETUP },
                {     "boot-loader-menu", required_argument, NULL,     ARG_BOOT_LOADER_MENU },
                {    "boot-loader-entry", required_argument, NULL,    ARG_BOOT_LOADER_ENTRY },
                {      "reboot-argument", required_argument, NULL,      ARG_REBOOT_ARGUMENT },
                {       "kernel-cmdline", required_argument, NULL,       ARG_KERNEL_CMDLINE },
                { "kernel-cmdline-reuse",       no_argument, NULL, ARG_KERNEL_CMDLINE_REUSE },
                {            "read-only",       no_argument, NULL,            ARG_READ_ONLY },
                {                "mkdir",       no_argument, NULL,                ARG_MKDIR },
                {               "marked",       no_argument, NULL,               ARG_MARKED },
                {              "drop-in", required_argument, NULL,              ARG_DROP_IN },
                {                 "when", required_argument, NULL,                 ARG_WHEN },
                {                "stdin",       no_argument, NULL,                ARG_STDIN },
                {                   NULL,                 0, NULL,                        0 },
        };
        static char type_buf[128], state_buf[256], props_buf[512];
        int c;

        while ((c = getopt_long(argc, argv, "hqalt:p:P:n:o:s:H:M:C:rTivf", options, NULL)) >= 0) {
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
                        arg_legend = 0;
                        break;

                case ARG_LEGEND:
                        if (parse_bool_arg("--legend", optarg, &arg_legend) < 0)
                                return 1;
                        break;

                case ARG_NO_PAGER:        /* no pager exists to disable */
                case ARG_NO_WALL:         /* no wall message to suppress */
                case ARG_MESSAGE:         /* ditto: nobody to deliver it to */
                case ARG_NO_ASK_PASSWORD: /* no authorisation prompt exists */
                case ARG_NO_WARN:
                case ARG_NO_RELOAD: /* nothing here reloads after enable/disable */
                case 'v':           /* extra unit logs while waiting */
                case 'T':           /* extra transaction listing */
                case 'i':           /* no inhibitors exist */
                case ARG_IGNORE_INHIBITORS:
                case 'f': /* --force: every shutdown is immediate anyway */
                case 'l': /* output is never ellipsized */
                case ARG_PLAIN:
                case ARG_SHOW_TYPES:
                /* read only by verbs pico-init does not have */
                case ARG_REVERSE:
                case ARG_BEFORE:
                case ARG_AFTER:
                case ARG_WHAT:
                case ARG_READ_ONLY:
                case ARG_MKDIR:
                case ARG_DROP_IN:
                case ARG_STDIN:
                case ARG_SYSTEM: /* already the only mode */
                        break;

                case ARG_CHECK_INHIBITORS: {
                        int unused;

                        if (strcmp(optarg, "auto") != 0 &&
                            parse_bool_arg("--check-inhibitors=", optarg, &unused) < 0)
                                return 1;
                        break;
                }

                case 'q':
                        arg_quiet = true;
                        if (arg_legend < 0)
                                arg_legend = 0;
                        break;

                case 'a':
                        arg_all = true;
                        break;

                case 't':
                        csv_append(type_buf, sizeof(type_buf), optarg);
                        arg_type = type_buf;
                        break;

                case ARG_STATE:
                        csv_append(state_buf, sizeof(state_buf), optarg);
                        arg_state = state_buf;
                        break;

                case ARG_FAILED:
                        csv_append(state_buf, sizeof(state_buf), "failed");
                        arg_state = state_buf;
                        break;

                case 'p':
                case 'P':
                        csv_append(props_buf, sizeof(props_buf), optarg);
                        arg_properties = props_buf;
                        if (c == 'P')
                                arg_value = true;
                        break;

                case ARG_VALUE:
                        arg_value = true;
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

                case 'o': {
                        static const char * const names[] = {
                                "short",         "short-full",      "short-iso",   "short-iso-precise",
                                "short-precise", "short-monotonic", "short-delta", "short-unix",
                                "verbose",       "export",          "json",        "json-pretty",
                                "json-sse",      "json-seq",        "cat",         "with-unit",
                        };
                        size_t i;

                        if (strcmp(optarg, "help") == 0) {
                                for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
                                        puts(names[i]);
                                return 0;
                        }
                        for (i = 0; i < sizeof(names) / sizeof(names[0]); i++)
                                if (strcmp(optarg, names[i]) == 0)
                                        break;
                        if (i == sizeof(names) / sizeof(names[0])) {
                                picoctl_error("Unknown output '%s'.", optarg);
                                return 1;
                        }

                        /* The modes that format journal entries differently
                         * keep the short layout: the log tail of status is
                         * the only entry output there is. */
                        arg_output = OUTPUT_SHORT;
                        if (strcmp(optarg, "cat") == 0)
                                arg_output = OUTPUT_CAT;
                        else if (strcmp(optarg, "json") == 0)
                                arg_output = OUTPUT_JSON;
                        else if (strcmp(optarg, "json-pretty") == 0)
                                arg_output = OUTPUT_JSON_PRETTY;
                        else if (strcmp(optarg, "json-sse") == 0)
                                arg_output = OUTPUT_JSON_SSE;
                        else if (strcmp(optarg, "json-seq") == 0)
                                arg_output = OUTPUT_JSON_SEQ;
                        if (output_is_json())
                                arg_legend = 0;
                        break;
                }

                case ARG_TIMESTAMP: {
                        static const struct {
                                const char *name;
                                enum timestamp_style style;
                        } styles[] = {
                                { "pretty", TIMESTAMP_PRETTY },
                                {   "unix",   TIMESTAMP_UNIX },
                                {     "us",     TIMESTAMP_US },
                                {    "utc",    TIMESTAMP_UTC },
                                { "us+utc", TIMESTAMP_US_UTC },
                        };
                        size_t i;

                        if (strcmp(optarg, "help") == 0) {
                                for (i = 0; i < sizeof(styles) / sizeof(styles[0]); i++)
                                        puts(styles[i].name);
                                return 0;
                        }
                        for (i = 0; i < sizeof(styles) / sizeof(styles[0]); i++)
                                if (strcmp(optarg, styles[i].name) == 0) {
                                        arg_timestamp_style = styles[i].style;
                                        break;
                                }
                        if (i == sizeof(styles) / sizeof(styles[0])) {
                                picoctl_error("Invalid value: %s.", optarg);
                                return 1;
                        }
                        break;
                }

                case 's': {
                        int sig;

                        if (strcmp(optarg, "help") == 0) {
                                signal_help();
                                return 0;
                        }
                        if (signal_from_name(optarg, &sig) < 0) {
                                picoctl_error("Failed to parse signal string %s.", optarg);
                                return 1;
                        }
                        arg_signal_name = optarg;
                        break;
                }

                case ARG_KILL_WHOM:
                        if (strcmp(optarg, "main") != 0 && strcmp(optarg, "all") != 0)
                                return refuse_option("--kill-whom=", "only 'main' and 'all' exist");
                        arg_kill_whom = optarg;
                        break;

                case ARG_KILL_VALUE: {
                        char *end;
                        long v;

                        if (optarg[0] == '\0') {
                                arg_kill_value_set = false;
                                break;
                        }
                        errno = 0;
                        v = strtol(optarg, &end, 0);
                        if (*end != '\0' || errno != 0 || v < INT_MIN || v > INT_MAX) {
                                picoctl_error("Unable to parse signal queue value: %s", optarg);
                                return 1;
                        }
                        arg_kill_value = (int) v;
                        arg_kill_value_set = true;
                        break;
                }

                case ARG_KILL_SUBGROUP:
                        if (optarg[0] == '\0' || strcmp(optarg, "/") == 0) {
                                arg_kill_subgroup = NULL;
                                break;
                        }
                        if (!subgroup_is_safe(optarg)) {
                                picoctl_error("Control group sub-path '%s' is not valid.", optarg);
                                return 1;
                        }
                        arg_kill_subgroup = optarg;
                        break;

                case ARG_NOW:
                        arg_now = true;
                        break;

                case ARG_DRY_RUN:
                        arg_dry_run = true;
                        break;

                case ARG_WAIT:
                        arg_wait = true;
                        break;

                case ARG_JOB_MODE:
                        /* the manager has one queueing mode, which is what both of these ask for */
                        if (strcmp(optarg, "replace") != 0 && strcmp(optarg, "fail") != 0)
                                return refuse_option("--job-mode", "only 'replace' and 'fail' exist");
                        break;

                case ARG_FAIL:
                        break;

                case ARG_IRREVERSIBLE:
                        return refuse_option("--irreversible", "the manager has no irreversible jobs");

                case ARG_IGNORE_DEPENDENCIES:
                        return refuse_option("--ignore-dependencies", "jobs always pull in their dependencies");

                case ARG_PRESET_MODE:
                        if (strcmp(optarg, "help") == 0) {
                                puts("full\nenable-only\ndisable-only");
                                return 0;
                        }
                        if (strcmp(optarg, "full") != 0 && strcmp(optarg, "enable-only") != 0 &&
                            strcmp(optarg, "disable-only") != 0) {
                                picoctl_error("Failed to parse preset mode: %s.", optarg);
                                return 1;
                        }
                        arg_preset_mode = optarg;
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

                case 'C':
                        return refuse_option("-C/--capsule", "pico-init has no capsules");

                case 'r':
                        return refuse_option("-r/--recursive", "there are no containers to list");

                case ARG_IMAGE:
                case ARG_IMAGE_POLICY:
                        return refuse_option("--image", "picoctl cannot open disk images, use --root");

                case ARG_RUNTIME:
                        return refuse_option("--runtime", "there is no runtime unit file directory");

                case ARG_WITH_DEPENDENCIES:
                        return refuse_option("--with-dependencies", "dependency listing does not exist");

                case ARG_MARKED:
                        return refuse_option("--marked", "units cannot be marked for restart");

                case ARG_WHEN:
                        return refuse_option("--when", "there is no scheduler");

                case ARG_FIRMWARE_SETUP:
                case ARG_BOOT_LOADER_MENU:
                case ARG_BOOT_LOADER_ENTRY:
                case ARG_REBOOT_ARGUMENT:
                case ARG_KERNEL_CMDLINE:
                case ARG_KERNEL_CMDLINE_REUSE:
                        return refuse_option(
                                        "The boot loader, firmware and kernel command line options",
                                        "a reboot only restarts the machine");

                case '?':
                default:
                        /* getopt_long already printed its own diagnostic. */
                        return 1;
                }
        }

        if (arg_wait && arg_no_block) {
                picoctl_error("--wait may not be combined with --no-block.");
                return 1;
        }

        return -1; /* keep going: optind now points at VERB [UNIT...] */
}

/* Verbs that exist in systemctl but have nothing behind them here. Refusing
 * by name tells a script why, where "Unknown command verb" would read as a
 * typo; either way the exit status is 1 and no state changes. */
static const struct {
        const char *name;
        const char *reason;
} refused_verbs[] = {
        {                "isolate", "the boot target is fixed, no unit can be isolated" },
        {                "default", "the boot target is fixed, no unit can be isolated" },
        {                 "rescue", "the boot target is fixed, no unit can be isolated" },
        {              "emergency", "the boot target is fixed, no unit can be isolated" },
        {                   "exit",     "there is no user manager or container to exit" },
        {            "set-default",              "the default target is chosen at boot" },
        {                  "kexec",              "only reboot, poweroff and halt exist" },
        {            "soft-reboot",              "only reboot, poweroff and halt exist" },
        {            "switch-root",              "only reboot, poweroff and halt exist" },
        {                  "sleep",                      "there is no power management" },
        {                "suspend",                      "there is no power management" },
        {              "hibernate",                      "there is no power management" },
        {           "hybrid-sleep",                      "there is no power management" },
        { "suspend-then-hibernate",                      "there is no power management" },
        {      "list-dependencies",   "dependencies are not tracked in a listable form" },
        {           "list-sockets",                "socket addresses are not published" },
        {          "list-machines",                           "there are no containers" },
        {                 "cancel",                   "queued jobs cannot be cancelled" },
        {             "clear-jobs",                   "queued jobs cannot be cancelled" },
        {         "enqueue-marked",                "units cannot be marked for restart" },
        {                   "edit",                     "there are no drop-ins to edit" },
        {                 "revert",                   "there are no drop-ins to revert" },
        {                   "help",               "there are no manual pages for units" },
        {       "show-environment",            "the manager environment is not exposed" },
        {        "set-environment",            "the manager environment is not exposed" },
        {      "unset-environment",            "the manager environment is not exposed" },
        {     "import-environment",            "the manager environment is not exposed" },
        {          "daemon-reexec",              "the manager cannot re-execute itself" },
        {              "log-level",           "the manager log level cannot be changed" },
        {             "log-target",          "the manager log target cannot be changed" },
        {      "service-log-level",                "services have no runtime log level" },
        {     "service-log-target",               "services have no runtime log target" },
        {      "service-watchdogs",                  "watchdog state cannot be changed" },
        {           "set-property",                   "there are no runtime properties" },
        {                   "bind",        "units have no mount namespace to bind into" },
        {            "mount-image",       "units have no mount namespace to mount into" },
        {                  "clean",            "unit state directories are not managed" },
        {                 "freeze",                            "units cannot be frozen" },
        {                   "thaw",                            "units cannot be frozen" },
};

int main(int argc, char *argv[]) {
        static const struct {
                const char *name;
                int (*fn)(int, char **);
                bool mangle; /* append .service to a bare argument */
        } verbs[] = {
                {                "status",cmd_status,  true                                          },
                {            "list-units",            cmd_list_units, false },
                {       "list-unit-files",       cmd_list_unit_files, false },
                {           "list-timers",           cmd_list_timers, false },
                {            "list-paths",            cmd_list_paths, false },
                {       "list-automounts",       cmd_list_automounts, false },
                {             "list-jobs",             cmd_list_jobs, false },
                {             "is-active",             cmd_is_active,  true },
                {             "is-failed",             cmd_is_failed,  true },
                {                 "check",             cmd_is_active,  true }, /* deprecated alias, same job */
                {     "is-system-running",     cmd_is_system_running, false },
                {                "whoami",                cmd_whoami, false },
                {                  "show",                  cmd_show,  true },
                {                   "cat",                   cmd_cat,  true },
                {                "enable",                cmd_enable,  true },
                {              "reenable",              cmd_reenable,  true },
                {               "disable",               cmd_disable,  true },
                {            "is-enabled",            cmd_is_enabled,  true },
                {                "preset",                cmd_preset,  true },
                {            "preset-all",            cmd_preset_all, false },
                {                  "mask",                  cmd_mask,  true },
                {                "unmask",                cmd_unmask,  true },
                {                  "link",                  cmd_link, false },
                {             "add-wants",             cmd_add_wants, false },
                {          "add-requires",          cmd_add_requires, false },
                {           "get-default",           cmd_get_default, false },
                {                 "start",                 cmd_start,  true },
                {                  "stop",                  cmd_stop,  true },
                {              "condstop",              cmd_condstop,  true }, /* legacy alias of stop */
                {               "restart",               cmd_restart,  true },
                {           "try-restart",           cmd_try_restart,  true },
                {           "condrestart",           cmd_condrestart,  true }, /* legacy alias of try-restart */
                {     "reload-or-restart",     cmd_reload_or_restart,  true },
                { "try-reload-or-restart", cmd_try_reload_or_restart,  true },
                { "reload-or-try-restart",
                 cmd_try_reload_or_restart,  true                          }, /* legacy spelling, systemctl <= 228  */
                {            "condreload", cmd_try_reload_or_restart,  true }, /* legacy alias, ALTLinux */
                {          "force-reload", cmd_try_reload_or_restart,  true }, /* SysV alias */
                {                "reload",                cmd_reload,  true },
                {                  "kill",                  cmd_kill,  true },
                {          "reset-failed",          cmd_reset_failed,  true },
                {         "daemon-reload",         cmd_daemon_reload, false },
                {                "reboot",                cmd_reboot, false },
                {              "poweroff",              cmd_poweroff, false },
                {                  "halt",                  cmd_halt, false },
        };
        const char *prog0;
        int argi, rc_opts;
        size_t i;

        /* argv[0] dispatch, before any option/verb parsing: a real reboot(8)/
         * poweroff(8)/halt(8)/shutdown(8) invocation never passes a verb. */
        prog0 = strrchr(argv[0], '/');
        prog0 = prog0 ? prog0 + 1 : argv[0];
        if (strcmp(prog0, "reboot") == 0)
                return compat_halt(POWER_REBOOT, argc, argv);
        if (strcmp(prog0, "poweroff") == 0)
                return compat_halt(POWER_POWEROFF, argc, argv);
        if (strcmp(prog0, "halt") == 0)
                return compat_halt(POWER_HALT, argc, argv);
        if (strcmp(prog0, "shutdown") == 0)
                return compat_shutdown(argc, argv);

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

                        /* waiting for a job to end has no wire support; only
                         * the state files can be waited on */
                        if (arg_wait && verbs[i].fn != cmd_is_system_running) {
                                picoctl_error("--wait is only supported by is-system-running.");
                                return 1;
                        }

                        mangled = n > 0 ? calloc((size_t) n, sizeof(char *)) : NULL;
                        if (n > 0 && !mangled)
                                return verbs[i].fn(n, orig); /* OOM: fall back unmangled */

                        for (j = 0; j < n; j++) {
                                char *m = verbs[i].mangle ? mangle_unit_arg_suffix(orig[j], ".service") : NULL;

                                mangled[j] = m ? m : orig[j];
                        }

                        rc = verbs[i].fn(n, n > 0 ? mangled : orig);

                        for (j = 0; j < n; j++)
                                if (mangled[j] != orig[j])
                                        free(mangled[j]);
                        free(mangled);

                        return rc;
                }

        for (i = 0; i < sizeof(refused_verbs) / sizeof(refused_verbs[0]); i++)
                if (strcmp(argv[argi], refused_verbs[i].name) == 0) {
                        picoctl_error("Verb '%s' is not supported by pico-init: %s.",
                                      argv[argi],
                                      refused_verbs[i].reason);
                        return 1;
                }

        /* Exact upstream wording and exit code (src/shared/verbs.c
         * dispatch_verb()): "Unknown command verb 'X'.", no usage dump --
         * real systemctl does not print its help text on a typo either. */
        picoctl_error("Unknown command verb '%s'.", argv[argi]);
        return 1;
}
