/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The tmpfiles.d(5) reader: which files apply, and what each line means.
 *
 * Two rules that are easy to get subtly wrong, taken from systemd's code
 * rather than its prose:
 *
 *  - A basename found in an earlier directory hides the same basename in
 *    every later one *entirely* (conf-files.c files_add(): "Skipping
 *    overridden file"). /etc/tmpfiles.d/foo.conf does not merge with
 *    /usr/lib/tmpfiles.d/foo.conf, it replaces it. A symlink to /dev/null
 *    is a mask.
 *  - The surviving files are applied in lexicographic order of basename,
 *    across directories, and within one path the first line parsed wins
 *    (tmpfiles.c parse_line(): "Duplicate line for path, ignoring").
 */

#include "tmpfiles.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "../os-release.h"
#include "../util.h"

/* --- small path helpers ------------------------------------------------ */

char *pico_tmpfiles_path_simplify(char *path) {
        char *f = path;
        const char *p = path;
        bool add_slash = false;
        bool absolute;

        if (!path || !*path)
                return path;

        absolute = path[0] == '/';
        if (absolute) {
                f++;
                p++;
        }

        for (;;) {
                const char *e;
                size_t n;

                while (*p == '/')
                        p++;
                if (!*p)
                        break;

                e = p;
                while (*e && *e != '/')
                        e++;
                n = (size_t) (e - p);

                if (n == 1 && p[0] == '.') {
                        p = e;
                        continue;
                }

                if (add_slash)
                        *f++ = '/';
                memmove(f, p, n);
                f += n;
                add_slash = true;
                p = e;
        }

        if (f == path)
                *f++ = '.';

        *f = '\0';
        return path;
}

const char *pico_tmpfiles_path_startswith(const char *path, const char *prefix) {
        if (!path || !prefix)
                return NULL;

        if ((path[0] == '/') != (prefix[0] == '/'))
                return NULL;

        for (;;) {
                size_t a, b;

                while (*path == '/')
                        path++;
                while (*prefix == '/')
                        prefix++;

                if (!*prefix)
                        return path;
                if (!*path)
                        return NULL;

                a = strcspn(path, "/");
                b = strcspn(prefix, "/");
                if (a != b || memcmp(path, prefix, a) != 0)
                        return NULL;

                path += a;
                prefix += b;
        }
}

static char *path_join(const char *a, const char *b) {
        size_t la, lb;
        char *r;

        la = strlen(a);
        lb = strlen(b);
        r = malloc(la + 1 + lb + 1);
        if (!r)
                return NULL;

        memcpy(r, a, la);
        if (la > 0 && a[la - 1] != '/' && b[0] != '/')
                r[la++] = '/';
        memcpy(r + la, b, lb + 1);
        return r;
}

/* --- word extraction: EXTRACT_UNQUOTE | EXTRACT_CUNESCAPE ---------------- */

static int utf8_encode(uint32_t u, char *out) {
        if (u < 0x80) {
                out[0] = (char) u;
                return 1;
        }
        if (u < 0x800) {
                out[0] = (char) (0xc0 | (u >> 6));
                out[1] = (char) (0x80 | (u & 0x3f));
                return 2;
        }
        if (u < 0x10000) {
                out[0] = (char) (0xe0 | (u >> 12));
                out[1] = (char) (0x80 | ((u >> 6) & 0x3f));
                out[2] = (char) (0x80 | (u & 0x3f));
                return 3;
        }
        if (u < 0x110000) {
                out[0] = (char) (0xf0 | (u >> 18));
                out[1] = (char) (0x80 | ((u >> 12) & 0x3f));
                out[2] = (char) (0x80 | ((u >> 6) & 0x3f));
                out[3] = (char) (0x80 | (u & 0x3f));
                return 4;
        }
        return -EINVAL;
}

static int hexval(char c) {
        if (c >= '0' && c <= '9')
                return c - '0';
        if (c >= 'a' && c <= 'f')
                return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
                return c - 'A' + 10;
        return -1;
}

/*
 * One escape sequence, `p` pointing just past the backslash. Writes the
 * decoded bytes to `out` (at most 4), returns the number of input characters
 * consumed, or -EINVAL. The accepted set is escape.c cunescape_one()'s.
 */
static int cunescape_one(const char *p, char *out, int *out_len) {
        uint32_t u;
        int i, r;

        switch (p[0]) {
        case 'a':
                *out = '\a';
                *out_len = 1;
                return 1;
        case 'b':
                *out = '\b';
                *out_len = 1;
                return 1;
        case 'f':
                *out = '\f';
                *out_len = 1;
                return 1;
        case 'n':
                *out = '\n';
                *out_len = 1;
                return 1;
        case 'r':
                *out = '\r';
                *out_len = 1;
                return 1;
        case 't':
                *out = '\t';
                *out_len = 1;
                return 1;
        case 'v':
                *out = '\v';
                *out_len = 1;
                return 1;
        case '\\':
        case '"':
        case '\'':
                *out = p[0];
                *out_len = 1;
                return 1;
        case 's':
                *out = ' ';
                *out_len = 1;
                return 1;

        case 'x': {
                int a = hexval(p[1]), b = p[1] ? hexval(p[2]) : -1;

                if (a < 0 || b < 0)
                        return -EINVAL;
                u = (uint32_t) ((a << 4) | b);
                if (u == 0)
                        return -EINVAL;
                *out = (char) u;
                *out_len = 1;
                return 3;
        }

        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7': {
                if (p[1] < '0' || p[1] > '7' || p[2] < '0' || p[2] > '7')
                        return -EINVAL;
                u = (uint32_t) (((p[0] - '0') << 6) | ((p[1] - '0') << 3) | (p[2] - '0'));
                if (u == 0 || u > 255)
                        return -EINVAL;
                *out = (char) u;
                *out_len = 1;
                return 3;
        }

        case 'u':
        case 'U': {
                int n = p[0] == 'u' ? 4 : 8;

                u = 0;
                for (i = 1; i <= n; i++) {
                        int h = p[i] ? hexval(p[i]) : -1;

                        if (h < 0)
                                return -EINVAL;
                        u = (u << 4) | (uint32_t) h;
                }
                if (u == 0)
                        return -EINVAL;
                r = utf8_encode(u, out);
                if (r < 0)
                        return r;
                *out_len = r;
                return n + 1;
        }

        default:
                return -EINVAL;
        }
}

static int buf_push(char **buf, size_t *len, size_t *cap, const char *bytes, size_t n) {
        if (*len + n + 1 > *cap) {
                size_t nc = *cap ? *cap * 2 : 64;
                char *nb;

                while (nc < *len + n + 1)
                        nc *= 2;
                nb = realloc(*buf, nc);
                if (!nb)
                        return -ENOMEM;
                *buf = nb;
                *cap = nc;
        }
        memcpy(*buf + *len, bytes, n);
        *len += n;
        (*buf)[*len] = '\0';
        return 0;
}

/*
 * extract_first_word() with whitespace separators, quotes removed, escapes
 * decoded. *p advances past the word and the separators after it, so after
 * the last field it points at the argument's first non-blank character.
 * Returns 1 with *ret set, 0 at end of input, -EINVAL on an unbalanced quote
 * or bad escape, -ENOMEM.
 */
static int extract_word(const char **p, char **ret) {
        const char *s = *p;
        char *buf = NULL;
        size_t len = 0, cap = 0;
        char quote = 0;
        int r;

        while (*s == ' ' || *s == '\t')
                s++;
        if (!*s) {
                *p = s;
                *ret = NULL;
                return 0;
        }

        /* always return a string once a non-blank was seen, even "" */
        r = buf_push(&buf, &len, &cap, "", 0);
        if (r < 0)
                return r;

        for (;;) {
                char c = *s;

                if (c == '\0') {
                        if (quote) {
                                free(buf);
                                return -EINVAL;
                        }
                        break;
                }

                if (c == '\\') {
                        char dec[4];
                        int dl;

                        if (s[1] == '\0') {
                                free(buf);
                                return -EINVAL;
                        }
                        r = cunescape_one(s + 1, dec, &dl);
                        if (r < 0) {
                                free(buf);
                                return -EINVAL;
                        }
                        if (buf_push(&buf, &len, &cap, dec, (size_t) dl) < 0) {
                                free(buf);
                                return -ENOMEM;
                        }
                        s += 1 + r;
                        continue;
                }

                if (quote) {
                        if (c == quote)
                                quote = 0;
                        else if (buf_push(&buf, &len, &cap, &c, 1) < 0) {
                                free(buf);
                                return -ENOMEM;
                        }
                        s++;
                        continue;
                }

                if (c == '"' || c == '\'') {
                        quote = c;
                        s++;
                        continue;
                }

                if (c == ' ' || c == '\t') {
                        while (*s == ' ' || *s == '\t')
                                s++;
                        break;
                }

                if (buf_push(&buf, &len, &cap, &c, 1) < 0) {
                        free(buf);
                        return -ENOMEM;
                }
                s++;
        }

        *p = s;
        *ret = buf;
        return 1;
}

/* Full-string C unescape, for the argument field. 0 or -EINVAL/-ENOMEM. */
static int cunescape(const char *s, char **ret) {
        char *buf = NULL;
        size_t len = 0, cap = 0;
        int r;

        r = buf_push(&buf, &len, &cap, "", 0);
        if (r < 0)
                return r;

        while (*s) {
                if (*s == '\\') {
                        char dec[4];
                        int dl;

                        if (s[1] == '\0') {
                                free(buf);
                                return -EINVAL;
                        }
                        r = cunescape_one(s + 1, dec, &dl);
                        if (r < 0) {
                                free(buf);
                                return r;
                        }
                        if (buf_push(&buf, &len, &cap, dec, (size_t) dl) < 0) {
                                free(buf);
                                return -ENOMEM;
                        }
                        s += 1 + r;
                        continue;
                }
                if (buf_push(&buf, &len, &cap, s, 1) < 0) {
                        free(buf);
                        return -ENOMEM;
                }
                s++;
        }

        *ret = buf;
        return 0;
}

/* --- specifiers ------------------------------------------------------- */

static int read_first_line(const char *path, char **ret) {
        FILE *f;
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        n = getline(&line, &cap, f);
        fclose(f);
        if (n < 0) {
                free(line);
                return -ENODATA;
        }

        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
                line[--n] = '\0';

        *ret = line;
        return 0;
}

static const char *arch_name(const char *machine) {
        static const struct {
                const char *uname;
                const char *name;
        } table[] = {
                {     "aarch64",       "arm64" },
                {  "aarch64_be",    "arm64-be" },
                {         "arm",         "arm" },
                {    "armv5tel",         "arm" },
                {      "armv6l",         "arm" },
                {      "armv7l",         "arm" },
                {     "armv7ml",         "arm" },
                {      "armv8l",         "arm" },
                {      "x86_64",      "x86-64" },
                {        "i386",         "x86" },
                {        "i486",         "x86" },
                {        "i586",         "x86" },
                {        "i686",         "x86" },
                {     "riscv64",     "riscv64" },
                {     "riscv32",     "riscv32" },
                {      "mips64",      "mips64" },
                {        "mips",        "mips" },
                {     "ppc64le",    "ppc64-le" },
                {       "ppc64",       "ppc64" },
                {         "ppc",         "ppc" },
                {       "s390x",       "s390x" },
                {        "s390",        "s390" },
                { "loongarch64", "loongarch64" },
        };
        size_t i;

        for (i = 0; i < sizeof(table) / sizeof(table[0]); i++)
                if (strcmp(machine, table[i].uname) == 0)
                        return table[i].name;

        return NULL;
}

static int rooted_path(const PicoTmpfiles *t, const char *path, char **ret) {
        char *p;

        if (t->root)
                p = path_join(t->root, path);
        else
                p = strdup(path);
        if (!p)
                return -ENOMEM;

        *ret = p;
        return 0;
}

/* The os-release keys behind %o %w %W %A %B %M, read from under --root. */
static int os_release_specifier(const PicoTmpfiles *t, const char *key, char **ret) {
        char *path = NULL;
        int r;

        r = rooted_path(t, OS_RELEASE_PATH, &path);
        if (r < 0)
                return r;

        r = os_release_get(path, key, ret);
        free(path);
        return r;
}

/*
 * One %c. Returns 0 with *ret set, -EBADSLT for a specifier tmpfiles.d(5)
 * does not define (invalid configuration), -ENOENT/-ENODATA when the value
 * is not resolvable on this system (the line is skipped), or -ENOMEM.
 */
static int specifier_lookup(const PicoTmpfiles *t, char c, char **ret) {
        const char *fixed = NULL;
        struct passwd *pw;
        struct group *gr;
        struct utsname u;
        char buf[HOST_NAME_MAX + 1];
        char *s;
        int r;

        switch (c) {
        case 'C':
                fixed = "/var/cache";
                break;
        case 'L':
                fixed = "/var/log";
                break;
        case 'S':
                fixed = "/var/lib";
                break;
        case 't':
                fixed = "/run";
                break;
        case 'T':
                fixed = "/tmp";
                break;
        case 'V':
                fixed = "/var/tmp";
                break;

        case 'h':
                pw = getpwuid(getuid());
                fixed = pw && pw->pw_dir ? pw->pw_dir : "/root";
                break;
        case 'u':
                pw = getpwuid(getuid());
                fixed = pw && pw->pw_name ? pw->pw_name : "root";
                break;
        case 'g':
                gr = getgrgid(getgid());
                fixed = gr && gr->gr_name ? gr->gr_name : "root";
                break;
        case 'U':
                if (snprintf(buf, sizeof(buf), "%u", (unsigned) getuid()) < 0)
                        return -EINVAL;
                fixed = buf;
                break;
        case 'G':
                if (snprintf(buf, sizeof(buf), "%u", (unsigned) getgid()) < 0)
                        return -EINVAL;
                fixed = buf;
                break;

        case 'a':
                if (uname(&u) < 0)
                        return -errno;
                fixed = arch_name(u.machine);
                if (!fixed)
                        return -ENOENT;
                break;
        case 'v':
                if (uname(&u) < 0)
                        return -errno;
                s = strdup(u.release);
                if (!s)
                        return -ENOMEM;
                *ret = s;
                return 0;

        case 'H':
        case 'l':
                if (gethostname(buf, sizeof(buf)) < 0)
                        return -errno;
                buf[sizeof(buf) - 1] = '\0';
                if (c == 'l')
                        buf[strcspn(buf, ".")] = '\0';
                fixed = buf;
                break;

        case 'm': {
                char *path = NULL;

                r = rooted_path(t, "/etc/machine-id", &path);
                if (r < 0)
                        return r;
                r = read_first_line(path, &s);
                free(path);
                if (r < 0)
                        return r;
                if (strlen(s) != 32) {
                        free(s);
                        return -ENODATA;
                }
                *ret = s;
                return 0;
        }
        case 'b':
                r = read_first_line("/proc/sys/kernel/random/boot_id", &s);
                if (r < 0)
                        return r;
                /* the kernel prints it with dashes; systemd's %b has none */
                {
                        char *w = s;
                        const char *rd = s;

                        for (; *rd; rd++)
                                if (*rd != '-')
                                        *w++ = *rd;
                        *w = '\0';
                }
                *ret = s;
                return 0;

        case 'o':
                return os_release_specifier(t, "ID", ret);
        case 'w':
                return os_release_specifier(t, "VERSION_ID", ret);
        case 'W':
                return os_release_specifier(t, "VARIANT_ID", ret);
        case 'A':
                return os_release_specifier(t, "IMAGE_VERSION", ret);
        case 'B':
                return os_release_specifier(t, "BUILD_ID", ret);
        case 'M':
                return os_release_specifier(t, "IMAGE_ID", ret);

        case 'q': {
                char *path = NULL;

                r = rooted_path(t, "/etc/machine-info", &path);
                if (r < 0)
                        return r;
                r = os_release_get(path, "PRETTY_HOSTNAME", ret);
                free(path);
                if (r == 0)
                        return 0;
                /* upstream falls back to the plain hostname */
                if (gethostname(buf, sizeof(buf)) < 0)
                        return -errno;
                buf[sizeof(buf) - 1] = '\0';
                fixed = buf;
                break;
        }

        default:
                return -EBADSLT;
        }

        s = strdup(fixed);
        if (!s)
                return -ENOMEM;
        *ret = s;
        return 0;
}

static int expand_specifiers(const PicoTmpfiles *t, const char *text, char **ret) {
        char *buf = NULL;
        size_t len = 0, cap = 0;
        int r;

        r = buf_push(&buf, &len, &cap, "", 0);
        if (r < 0)
                return r;

        while (*text) {
                char *v = NULL;

                if (*text != '%') {
                        if (buf_push(&buf, &len, &cap, text, 1) < 0) {
                                free(buf);
                                return -ENOMEM;
                        }
                        text++;
                        continue;
                }

                if (text[1] == '%') {
                        if (buf_push(&buf, &len, &cap, "%", 1) < 0) {
                                free(buf);
                                return -ENOMEM;
                        }
                        text += 2;
                        continue;
                }

                if (text[1] == '\0') {
                        free(buf);
                        return -EBADSLT;
                }

                r = specifier_lookup(t, text[1], &v);
                if (r < 0) {
                        free(buf);
                        return r;
                }
                r = buf_push(&buf, &len, &cap, v, strlen(v));
                free(v);
                if (r < 0) {
                        free(buf);
                        return r;
                }
                text += 2;
        }

        *ret = buf;
        return 0;
}

/* --- mode / user / group ----------------------------------------------- */

static int parse_mode(const char *s, mode_t *ret) {
        unsigned long m;
        char *end;

        if (!*s || *s == '+' || *s == '-' || *s == ' ')
                return -EINVAL;

        errno = 0;
        m = strtoul(s, &end, 8);
        if (errno != 0 || *end != '\0')
                return -EINVAL;
        if (m > 07777)
                return -ERANGE;

        *ret = (mode_t) m;
        return 0;
}

/* parse_uid(): decimal digits only, no sign, no leading zero, valid id. */
static int parse_id(const char *s, uint32_t *ret) {
        unsigned long v;
        char *end;

        if (!*s || (s[0] == '0' && s[1] != '\0'))
                return -EINVAL;
        for (const char *p = s; *p; p++)
                if (*p < '0' || *p > '9')
                        return -EINVAL;

        errno = 0;
        v = strtoul(s, &end, 10);
        if (errno != 0 || *end != '\0' || v > UINT32_MAX)
                return -EINVAL;
        if (v == UINT32_MAX || v == 0xFFFF)
                return -ENXIO;

        *ret = (uint32_t) v;
        return 0;
}

static int find_uid(const char *name, uid_t *ret) {
        struct passwd *pw;
        uint32_t id;

        if (parse_id(name, &id) == 0) {
                *ret = (uid_t) id;
                return 0;
        }

        errno = 0;
        pw = getpwnam(name);
        if (!pw)
                return errno > 0 ? -errno : -ESRCH;

        *ret = pw->pw_uid;
        return 0;
}

static int find_gid(const char *name, gid_t *ret) {
        struct group *gr;
        uint32_t id;

        if (parse_id(name, &id) == 0) {
                *ret = (gid_t) id;
                return 0;
        }

        errno = 0;
        gr = getgrnam(name);
        if (!gr)
                return errno > 0 ? -errno : -ESRCH;

        *ret = gr->gr_gid;
        return 0;
}

/* --- age ------------------------------------------------------------------ */

/*
 * time-util.c's unit table, in its order: the first prefix that matches
 * wins, which is why "minutes"/"msec" precede "m". Nanoseconds are left out,
 * the one unit finer than the microseconds everything here counts in.
 */
static const struct {
        const char *suffix;
        uint64_t usec;
} time_units[] = {
        {   "seconds",        1000000ULL },
        {    "second",        1000000ULL },
        {       "sec",        1000000ULL },
        {         "s",        1000000ULL },
        {   "minutes",       60000000ULL },
        {    "minute",       60000000ULL },
        {       "min",       60000000ULL },
        {    "months",  2629800000000ULL },
        {     "month",  2629800000000ULL },
        {         "M",  2629800000000ULL },
        {      "msec",           1000ULL },
        {        "ms",           1000ULL },
        {         "m",       60000000ULL },
        {     "hours",     3600000000ULL },
        {      "hour",     3600000000ULL },
        {        "hr",     3600000000ULL },
        {         "h",     3600000000ULL },
        {      "days",    86400000000ULL },
        {       "day",    86400000000ULL },
        {         "d",    86400000000ULL },
        {     "weeks",   604800000000ULL },
        {      "week",   604800000000ULL },
        {         "w",   604800000000ULL },
        {     "years", 31557600000000ULL },
        {      "year", 31557600000000ULL },
        {         "y", 31557600000000ULL },
        {      "usec",              1ULL },
        {        "us",              1ULL },
        { "\xce\xbcs",              1ULL },
        { "\xc2\xb5s",              1ULL },
};

int pico_tmpfiles_parse_sec(const char *s, uint64_t *ret) {
        uint64_t total = 0;
        bool any = false;

        if (!s || !ret)
                return -EINVAL;

        while (*s == ' ' || *s == '\t')
                s++;
        if (strcmp(s, "infinity") == 0) {
                *ret = UINT64_MAX;
                return 0;
        }

        for (;;) {
                unsigned long long whole = 0;
                uint64_t mult = 1000000ULL, frac = 0, frac_div = 1, v;
                const char *start;
                char *end;
                size_t k;

                while (*s == ' ' || *s == '\t')
                        s++;
                if (!*s)
                        break;

                /* strtoull() would take a sign and leading blanks; neither is valid here */
                if (*s != '.' && (*s < '0' || *s > '9'))
                        return -EINVAL;

                start = s;
                if (*s != '.') {
                        errno = 0;
                        whole = strtoull(s, &end, 10);
                        if (errno != 0)
                                return -ERANGE;
                        s = end;
                }
                if (*s == '.') {
                        s++;
                        for (; *s >= '0' && *s <= '9'; s++)
                                if (frac_div < 1000000ULL) {
                                        frac = frac * 10 + (uint64_t) (*s - '0');
                                        frac_div *= 10;
                                }
                }
                if (s == start || (s == start + 1 && *start == '.'))
                        return -EINVAL;

                while (*s == ' ' || *s == '\t')
                        s++;
                for (k = 0; k < sizeof(time_units) / sizeof(time_units[0]); k++) {
                        size_t l = strlen(time_units[k].suffix);

                        if (strncmp(s, time_units[k].suffix, l) == 0) {
                                mult = time_units[k].usec;
                                s += l;
                                break;
                        }
                }

                if (whole > (UINT64_MAX - 1) / mult)
                        return -ERANGE;
                v = (uint64_t) whole * mult;
                /* frac * mult can overflow; frac < frac_div <= 1e6 keeps both halves in range */
                v += frac * (mult / frac_div) + (frac * (mult % frac_div)) / frac_div;
                if (v >= UINT64_MAX - total)
                        return -ERANGE;
                total += v;
                any = true;
        }

        if (!any)
                return -EINVAL;

        *ret = total;
        return 0;
}

/* parse_age_by_from_arg(): lower case for files, upper case for directories. */
static int parse_age_by(const char *s, PicoTmpfilesItem *i) {
        static const char letters[] = "abcm";
        static const unsigned flags[] = {
                PICO_TMPFILES_AGE_BY_ATIME,
                PICO_TMPFILES_AGE_BY_BTIME,
                PICO_TMPFILES_AGE_BY_CTIME,
                PICO_TMPFILES_AGE_BY_MTIME,
        };
        unsigned f = 0, d = 0;

        if (!*s)
                return -EINVAL;

        for (; *s; s++) {
                const char *hit;

                if (*s == ' ' || *s == '\t')
                        continue;

                hit = strchr(letters, *s);
                if (hit)
                        f |= flags[hit - letters];
                else if (*s >= 'A' && *s <= 'Z' && (hit = strchr(letters, *s - 'A' + 'a')))
                        d |= flags[hit - letters];
                else
                        return -EINVAL;
        }

        if (f == 0 && d == 0)
                return -EINVAL;

        i->age_by_file = f ? f : PICO_TMPFILES_AGE_BY_DEFAULT_FILE;
        i->age_by_dir = d ? d : PICO_TMPFILES_AGE_BY_DEFAULT_DIR;
        return 0;
}

/* "[~][age-by:]span". 0, or -EINVAL with *what naming the part that failed. */
static int parse_age(PicoTmpfilesItem *i, const char *age, const char **what) {
        const char *a = age, *colon;
        int r;

        i->age_by_file = PICO_TMPFILES_AGE_BY_DEFAULT_FILE;
        i->age_by_dir = PICO_TMPFILES_AGE_BY_DEFAULT_DIR;

        if (*a == '~') {
                if (i->type == 'r') {
                        *what = "age modifier '~' is not supported for r lines";
                        return -EINVAL;
                }
                i->keep_first_level = true;
                a++;
        }

        colon = strchr(a, ':');
        if (colon) {
                char *by = strndup(a, (size_t) (colon - a));

                if (!by)
                        return -ENOMEM;
                r = parse_age_by(by, i);
                free(by);
                if (r < 0) {
                        *what = "invalid age-by";
                        return r;
                }
                a = colon + 1;
        }

        r = pico_tmpfiles_parse_sec(a, &i->age_usec);
        if (r < 0) {
                *what = "invalid age";
                return -EINVAL;
        }

        i->age_set = true;
        return 0;
}

/* --- item bookkeeping ------------------------------------------------- */

static bool needs_glob(char type) {
        return strchr("wetThHaAxXrRzZ", type) != NULL;
}

static bool takes_ownership(char type) {
        return strchr("fFdDvqQpLcbCwexXrR", type) != NULL;
}

static bool empty_or_dash(const char *s) {
        return !s || !*s || strcmp(s, "-") == 0;
}

static void item_free_contents(PicoTmpfilesItem *i) {
        free(i->path);
        free(i->argument);
        free(i->age);
}

static PicoTmpfilesArray *array_free(PicoTmpfilesArray *a) {
        size_t k;

        if (!a)
                return NULL;

        for (k = 0; k < a->n_items; k++)
                item_free_contents(&a->items[k]);
        free(a->items);
        free(a->path);
        free(a);
        return NULL;
}

static PicoTmpfilesArray *find_in(PicoTmpfilesArray **arrays, size_t n, const char *path) {
        size_t k;

        for (k = 0; k < n; k++)
                if (strcmp(arrays[k]->path, path) == 0)
                        return arrays[k];

        return NULL;
}

PicoTmpfilesArray *pico_tmpfiles_find(PicoTmpfiles *t, const char *path) {
        PicoTmpfilesArray *a;

        if (!t || !path)
                return NULL;

        a = find_in(t->items, t->n_items, path);
        if (a)
                return a;
        return find_in(t->globs, t->n_globs, path);
}

/* item_compatible(): two ownership-taking lines must agree on everything. */
static bool item_compatible(const PicoTmpfilesItem *a, const PicoTmpfilesItem *b) {
        if (!(takes_ownership(a->type) && takes_ownership(b->type)))
                return true;

        if ((a->argument == NULL) != (b->argument == NULL))
                return false;
        if (a->argument && strcmp(a->argument, b->argument) != 0)
                return false;
        if ((a->age == NULL) != (b->age == NULL))
                return false;
        if (a->age && strcmp(a->age, b->age) != 0)
                return false;

        return a->uid_set == b->uid_set && a->uid == b->uid && a->uid_only_create == b->uid_only_create &&
                        a->gid_set == b->gid_set && a->gid == b->gid &&
                        a->gid_only_create == b->gid_only_create && a->mode_set == b->mode_set &&
                        a->mode == b->mode && a->mode_only_create == b->mode_only_create &&
                        a->mask_perms == b->mask_perms;
}

static bool is_duplicated_item(const PicoTmpfilesArray *existing, const PicoTmpfilesItem *i) {
        size_t k;

        for (k = 0; k < existing->n_items; k++) {
                const PicoTmpfilesItem *e = &existing->items[k];

                if (item_compatible(e, i))
                        continue;

                /* only several w+ lines may pile up on one path */
                if (e->type != 'w' || !e->append_or_force || i->type != 'w' || !i->append_or_force)
                        return true;
        }

        return false;
}

static int item_compare(const void *pa, const void *pb) {
        const PicoTmpfilesItem *a = pa, *b = pb;
        bool oa = takes_ownership(a->type), ob = takes_ownership(b->type);

        if (oa && !ob)
                return -1;
        if (!oa && ob)
                return 1;
        return (int) a->type - (int) b->type;
}

static int add_item(PicoTmpfiles *t, PicoTmpfilesItem *i, const char *fname, unsigned line) {
        PicoTmpfilesArray ***set, *a;
        size_t *n;
        PicoTmpfilesItem *grown;

        if (needs_glob(i->type)) {
                set = &t->globs;
                n = &t->n_globs;
        } else {
                set = &t->items;
                n = &t->n_items;
        }

        a = find_in(*set, *n, i->path);
        if (a) {
                if (is_duplicated_item(a, i)) {
                        pico_log(PICO_LOG_INFO,
                                 "%s:%u: duplicate line for path \"%s\", ignoring",
                                 fname,
                                 line,
                                 i->path);
                        item_free_contents(i);
                        memset(i, 0, sizeof(*i));
                        return 0;
                }
        } else {
                PicoTmpfilesArray **grown_set;

                a = calloc(1, sizeof(*a));
                if (!a)
                        return -ENOMEM;
                a->path = strdup(i->path);
                if (!a->path) {
                        free(a);
                        return -ENOMEM;
                }

                grown_set = realloc(*set, (*n + 1) * sizeof(**set));
                if (!grown_set) {
                        array_free(a);
                        return -ENOMEM;
                }
                *set = grown_set;
                (*set)[(*n)++] = a;
        }

        grown = realloc(a->items, (a->n_items + 1) * sizeof(*grown));
        if (!grown)
                return -ENOMEM;
        a->items = grown;
        a->items[a->n_items++] = *i;
        memset(i, 0, sizeof(*i));

        qsort(a->items, a->n_items, sizeof(*a->items), item_compare);
        return 0;
}

/* --- the line parser --------------------------------------------------- */

static bool should_include_path(const PicoTmpfiles *t, const char *path) {
        char **p;

        for (p = t->exclude_prefixes; p && *p; p++)
                if (pico_tmpfiles_path_startswith(path, *p))
                        return false;

        for (p = t->prefixes; p && *p; p++)
                if (pico_tmpfiles_path_startswith(path, *p))
                        return true;

        return pico_strv_length(t->prefixes) == 0;
}

/* /var/run/X is the legacy spelling of /run/X; fold it so both dedup. */
static int patch_var_run(char **path) {
        const char *k;
        char *n;

        k = pico_tmpfiles_path_startswith(*path, "/var/run");
        if (!k || !*k)
                return 0;

        n = path_join("/run", k);
        if (!n)
                return -ENOMEM;

        free(*path);
        *path = n;
        return 0;
}

#define log_line(level, fname, line, ...) pico_log_line_internal((level), (fname), (line), __VA_ARGS__)

static void pico_log_line_internal(PicoLogLevel level, const char *fname, unsigned line, const char *fmt, ...)
                __attribute__((format(printf, 4, 5)));

static void pico_log_line_internal(PicoLogLevel level, const char *fname, unsigned line, const char *fmt, ...) {
        char msg[768];
        va_list ap;

        va_start(ap, fmt);
        (void) vsnprintf(msg, sizeof(msg), fmt, ap);
        va_end(ap);

        pico_log(level, "%s:%u: %s", fname, line, msg);
}

static int invalid(PicoTmpfiles *t, const char *fname, unsigned line, const char *what) {
        t->invalid_config = true;
        log_line(PICO_LOG_ERR, fname, line, "%s", what);
        return -EBADMSG;
}

int pico_tmpfiles_parse_line(PicoTmpfiles *t, const char *fname, unsigned line, const char *buffer) {
        char *action = NULL, *path = NULL, *mode = NULL, *user = NULL, *group = NULL, *age = NULL;
        char *fields[6];
        const char *p = buffer;
        PicoTmpfilesItem i = { 0 };
        bool boot = false, try_replace = false, unbase64 = false, from_cred = false, purge = false;
        bool missing_user_or_group = false;
        int nfields = 0, r, ret = 0;
        size_t k;

        if (!t || !fname || !buffer)
                return -EINVAL;

        for (nfields = 0; nfields < 6; nfields++) {
                r = extract_word(&p, &fields[nfields]);
                if (r < 0) {
                        for (k = 0; k < (size_t) nfields; k++)
                                free(fields[k]);
                        if (r == -ENOMEM)
                                return r;
                        return invalid(t, fname, line, "failed to parse line: bad quoting or escape");
                }
                if (r == 0)
                        break;
        }
        for (k = (size_t) nfields; k < 6; k++)
                fields[k] = NULL;
        action = fields[0];
        path = fields[1];
        mode = fields[2];
        user = fields[3];
        group = fields[4];
        age = fields[5];

        if (nfields < 2) {
                ret = invalid(t, fname, line, "syntax error: type and path are required");
                goto finish;
        }

        if (!empty_or_dash(p)) {
                i.argument = strdup(p);
                if (!i.argument) {
                        ret = -ENOMEM;
                        goto finish;
                }
        }

        if (!action[0]) {
                ret = invalid(t, fname, line, "command too short");
                goto finish;
        }

        for (int pos = 1; action[pos]; pos++)
                if (action[pos] == '!' && !boot)
                        boot = true;
                else if (action[pos] == '+' && !i.append_or_force)
                        i.append_or_force = true;
                else if (action[pos] == '-' && !i.allow_failure)
                        i.allow_failure = true;
                else if (action[pos] == '=' && !try_replace)
                        try_replace = true;
                else if (action[pos] == '~' && !unbase64)
                        unbase64 = true;
                else if (action[pos] == '^' && !from_cred)
                        from_cred = true;
                else if (action[pos] == '$' && !purge)
                        purge = true;
                else if (action[pos] == '?' && !i.ignore_if_target_missing)
                        i.ignore_if_target_missing = true;
                else {
                        char what[64];

                        (void) snprintf(what, sizeof(what), "unknown modifiers in command: %.16s", action);
                        ret = invalid(t, fname, line, what);
                        goto finish;
                }

        i.type = action[0];

        if (!strchr("fFwdDevqQpLcbCxXrRzZtThHaA", i.type)) {
                char what[64];

                (void) snprintf(what, sizeof(what), "unknown command type '%c'", i.type);
                ret = invalid(t, fname, line, what);
                goto finish;
        }

        if (boot && !t->boot) {
                log_line(PICO_LOG_DEBUG,
                         fname,
                         line,
                         "ignoring entry %s \"%s\": --boot not specified",
                         action,
                         path);
                goto finish;
        }

        if (purge && !strchr("fFdDvqQpLcbCwe", i.type)) {
                ret = invalid(t, fname, line, "purge flag '$' on a line type that does not support it");
                goto finish;
        }

        if (i.ignore_if_target_missing && i.type != 'L') {
                ret = invalid(t, fname, line, "modifier '?' is only valid on L lines");
                goto finish;
        }

        /* Syntax this implementation reads correctly but cannot honour. One
         * warning each, so the gap shows in the boot log. */
        if (strchr("wpcbtThHaA", i.type)) {
                log_line(PICO_LOG_WARNING,
                         fname,
                         line,
                         "line type '%c' is not implemented by pico-tmpfiles, skipping \"%s\"",
                         i.type,
                         path);
                goto finish;
        }
        if (try_replace || unbase64 || from_cred) {
                log_line(PICO_LOG_WARNING,
                         fname,
                         line,
                         "modifier '%c' is not implemented by pico-tmpfiles, skipping \"%s\"",
                         try_replace              ? '=' :
                                         unbase64 ? '~' :
                                                    '^',
                         path);
                goto finish;
        }

        r = expand_specifiers(t, path, &i.path);
        if (r == -ENOENT || r == -ENODATA) {
                log_line(PICO_LOG_INFO, fname, line, "unresolvable specifier in \"%s\", skipping", path);
                goto finish;
        }
        if (r == -EBADSLT) {
                ret = invalid(t, fname, line, "unknown specifier in path");
                goto finish;
        }
        if (r < 0) {
                ret = r;
                goto finish;
        }

        r = patch_var_run(&i.path);
        if (r < 0) {
                ret = r;
                goto finish;
        }

        if (i.path[0] != '/') {
                ret = invalid(t, fname, line, "path is not absolute");
                goto finish;
        }

        pico_tmpfiles_path_simplify(i.path);

        switch (i.type) {
        case 'd':
        case 'D':
        case 'v':
        case 'q':
        case 'Q':
        case 'e':
        case 'x':
        case 'X':
        case 'r':
        case 'R':
        case 'z':
        case 'Z':
                if (i.argument)
                        log_line(PICO_LOG_WARNING,
                                 fname,
                                 line,
                                 "%c lines don't take argument fields, ignoring",
                                 i.type);
                break;
        default:
                break;
        }

        if (!should_include_path(t, i.path))
                goto finish;

        /* argument: unescaped, then specifier-expanded, for the types that use it */
        if (i.argument && strchr("CLfF", i.type)) {
                char *unescaped = NULL, *expanded = NULL;

                r = cunescape(i.argument, &unescaped);
                if (r == -ENOMEM) {
                        ret = r;
                        goto finish;
                }
                if (r < 0) {
                        ret = invalid(t, fname, line, "bad escape sequence in argument");
                        goto finish;
                }

                r = expand_specifiers(t, unescaped, &expanded);
                free(unescaped);
                if (r == -ENOENT || r == -ENODATA) {
                        log_line(PICO_LOG_INFO, fname, line, "unresolvable specifier in argument, skipping");
                        goto finish;
                }
                if (r == -EBADSLT) {
                        ret = invalid(t, fname, line, "unknown specifier in argument");
                        goto finish;
                }
                if (r < 0) {
                        ret = r;
                        goto finish;
                }
                free(i.argument);
                i.argument = expanded;
        }

        if (i.type == 'L' && !i.argument) {
                i.argument = path_join(PICO_TMPFILES_FACTORY_DIR, i.path);
                if (!i.argument) {
                        ret = -ENOMEM;
                        goto finish;
                }
        }

        if (i.type == 'C') {
                char *src;

                if (!i.argument) {
                        i.argument = path_join(PICO_TMPFILES_FACTORY_DIR, i.path);
                        if (!i.argument) {
                                ret = -ENOMEM;
                                goto finish;
                        }
                } else if (i.argument[0] != '/') {
                        ret = invalid(t, fname, line, "copy source path is not absolute");
                        goto finish;
                }

                r = rooted_path(t, i.argument, &src);
                if (r < 0) {
                        ret = r;
                        goto finish;
                }
                free(i.argument);
                i.argument = pico_tmpfiles_path_simplify(src);

                {
                        struct stat st;

                        if (fstatat(AT_FDCWD, i.argument, &st, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT) {
                                log_line(PICO_LOG_DEBUG,
                                         fname,
                                         line,
                                         "copy source \"%s\" does not exist, skipping",
                                         i.argument);
                                goto finish;
                        }
                }
        }

        if (t->root) {
                char *rooted;

                r = rooted_path(t, i.path, &rooted);
                if (r < 0) {
                        ret = r;
                        goto finish;
                }
                free(i.path);
                i.path = pico_tmpfiles_path_simplify(rooted);
        }

        if (!empty_or_dash(user)) {
                const char *u = user;

                if (*u == ':') {
                        i.uid_only_create = true;
                        u++;
                }

                r = find_uid(u, &i.uid);
                if (r == -ESRCH && t->graceful) {
                        log_line(PICO_LOG_DEBUG, fname, line, "user '%s' not found, not adjusting ownership", u);
                        missing_user_or_group = true;
                } else if (r < 0) {
                        char what[128];

                        (void) snprintf(what,
                                        sizeof(what),
                                        "failed to resolve user '%.64s': %s",
                                        u,
                                        strerror(-r));
                        ret = invalid(t, fname, line, what);
                        goto finish;
                } else
                        i.uid_set = true;
        }

        if (!empty_or_dash(group)) {
                const char *g = group;

                if (*g == ':') {
                        i.gid_only_create = true;
                        g++;
                }

                r = find_gid(g, &i.gid);
                if (r == -ESRCH && t->graceful) {
                        log_line(PICO_LOG_DEBUG, fname, line, "group '%s' not found, not adjusting ownership", g);
                        missing_user_or_group = true;
                } else if (r < 0) {
                        char what[128];

                        (void) snprintf(what,
                                        sizeof(what),
                                        "failed to resolve group '%.64s': %s",
                                        g,
                                        strerror(-r));
                        ret = invalid(t, fname, line, what);
                        goto finish;
                } else
                        i.gid_set = true;
        }

        if (!empty_or_dash(mode)) {
                const char *mm = mode;

                for (;; mm++)
                        if (*mm == '~')
                                i.mask_perms = true;
                        else if (*mm == ':')
                                i.mode_only_create = true;
                        else
                                break;

                r = parse_mode(mm, &i.mode);
                if (r < 0) {
                        ret = invalid(t, fname, line, "invalid mode");
                        goto finish;
                }
                i.mode_set = true;
        } else
                i.mode = strchr("dDvqQ", i.type) ? 0755 : 0644;

        /* no special bits on a node whose ownership could not be resolved */
        if (missing_user_or_group && (i.mode & ~(mode_t) 0777) != 0)
                i.mode &= 0777;

        if (!empty_or_dash(age)) {
                const char *what = NULL;

                r = parse_age(&i, age, &what);
                if (r == -ENOMEM) {
                        ret = r;
                        goto finish;
                }
                if (r < 0) {
                        char msg[128];

                        (void) snprintf(msg, sizeof(msg), "%s: '%.64s'", what, age);
                        ret = invalid(t, fname, line, msg);
                        goto finish;
                }

                i.age = strdup(age);
                if (!i.age) {
                        ret = -ENOMEM;
                        goto finish;
                }
        }

        ret = add_item(t, &i, fname, line);

finish:
        item_free_contents(&i);
        free(action);
        free(path);
        free(mode);
        free(user);
        free(group);
        free(age);
        return ret;
}

/* --- file reading ------------------------------------------------------ */

int pico_tmpfiles_read_file(PicoTmpfiles *t, const char *path) {
        FILE *f;
        char *line = NULL;
        size_t cap = 0;
        ssize_t n;
        unsigned v = 0;

        if (!t || !path)
                return -EINVAL;

        f = fopen(path, "re");
        if (!f)
                return -errno;

        pico_log(PICO_LOG_DEBUG, "reading %s", path);

        while ((n = getline(&line, &cap, f)) >= 0) {
                char *s = line;
                size_t len = (size_t) n;

                v++;

                while (len > 0 &&
                       (s[len - 1] == '\n' || s[len - 1] == '\r' || s[len - 1] == ' ' || s[len - 1] == '\t'))
                        s[--len] = '\0';
                while (*s == ' ' || *s == '\t')
                        s++;

                if (*s == '\0' || *s == '#')
                        continue;

                /* per-line failures are already logged and recorded */
                (void) pico_tmpfiles_parse_line(t, path, v, s);
        }

        free(line);
        fclose(f);
        return 0;
}

static int is_dev_null_mask(int dfd, const char *name, const char *full) {
        struct stat st;
        char target[PATH_MAX];
        ssize_t n;

        if (fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) < 0)
                return -errno;

        if (S_ISLNK(st.st_mode)) {
                n = readlinkat(dfd, name, target, sizeof(target) - 1);
                if (n < 0)
                        return -errno;
                target[n] = '\0';
                pico_tmpfiles_path_simplify(target);
                if (strcmp(target, "/dev/null") == 0)
                        return 1;
        }

        /* a symlink resolving elsewhere, or a node: follow it */
        if (stat(full, &st) < 0)
                return -errno;

        if (S_ISCHR(st.st_mode) && major(st.st_rdev) == 1 && minor(st.st_rdev) == 3)
                return 1;

        return S_ISREG(st.st_mode) ? 0 : -ENOENT;
}

static int compare_basename(const void *pa, const void *pb) {
        const char *a = *(const char * const *) pa, *b = *(const char * const *) pb;
        const char *ba = strrchr(a, '/'), *bb = strrchr(b, '/');

        ba = ba ? ba + 1 : a;
        bb = bb ? bb + 1 : b;
        return strcmp(ba, bb);
}

static bool strv_contains(char * const *v, const char *s) {
        for (; v && *v; v++)
                if (strcmp(*v, s) == 0)
                        return true;
        return false;
}

int pico_tmpfiles_list_config_files(PicoTmpfiles *t, char ***ret) {
        static const char * const dirs[] = { PICO_TMPFILES_CONF_DIRS };
        char **files = NULL, **seen = NULL, **masked = NULL;
        size_t d;
        int r = 0;

        if (!t || !ret)
                return -EINVAL;

        for (d = 0; d < sizeof(dirs) / sizeof(dirs[0]); d++) {
                char *dirpath = NULL;
                DIR *dir;
                struct dirent *de;

                r = rooted_path(t, dirs[d], &dirpath);
                if (r < 0)
                        goto fail;

                dir = opendir(dirpath);
                if (!dir) {
                        free(dirpath);
                        continue;
                }

                while ((de = readdir(dir))) {
                        size_t nl = strlen(de->d_name);
                        char *full;
                        int m;

                        if (nl < 5 || strcmp(de->d_name + nl - 5, ".conf") != 0)
                                continue;

                        if (strv_contains(seen, de->d_name)) {
                                pico_log(PICO_LOG_DEBUG, "skipping overridden file %s/%s", dirpath, de->d_name);
                                continue;
                        }
                        if (strv_contains(masked, de->d_name)) {
                                pico_log(PICO_LOG_DEBUG, "skipping masked file %s/%s", dirpath, de->d_name);
                                continue;
                        }

                        full = path_join(dirpath, de->d_name);
                        if (!full) {
                                r = -ENOMEM;
                                closedir(dir);
                                free(dirpath);
                                goto fail;
                        }

                        m = is_dev_null_mask(dirfd(dir), de->d_name, full);
                        if (m > 0) {
                                pico_log(PICO_LOG_DEBUG, "%s is a mask (symlink to /dev/null)", full);
                                r = pico_strv_extend(&masked, de->d_name);
                                free(full);
                                if (r < 0) {
                                        closedir(dir);
                                        free(dirpath);
                                        goto fail;
                                }
                                continue;
                        }
                        if (m < 0) {
                                pico_log(PICO_LOG_DEBUG, "skipping %s: %s", full, strerror(-m));
                                free(full);
                                continue;
                        }

                        r = pico_strv_extend(&seen, de->d_name);
                        if (r >= 0)
                                r = pico_strv_extend(&files, full);
                        free(full);
                        if (r < 0) {
                                closedir(dir);
                                free(dirpath);
                                goto fail;
                        }
                }

                closedir(dir);
                free(dirpath);
        }

        if (files)
                qsort(files, pico_strv_length(files), sizeof(*files), compare_basename);
        else {
                files = calloc(1, sizeof(*files));
                if (!files) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        pico_strv_free(seen);
        pico_strv_free(masked);
        *ret = files;
        return 0;

fail:
        pico_strv_free(files);
        pico_strv_free(seen);
        pico_strv_free(masked);
        return r;
}

int pico_tmpfiles_read_config(PicoTmpfiles *t) {
        char **files = NULL, **f;
        int r;

        r = pico_tmpfiles_list_config_files(t, &files);
        if (r < 0)
                return r;

        for (f = files; *f; f++) {
                r = pico_tmpfiles_read_file(t, *f);
                if (r < 0)
                        pico_log(PICO_LOG_WARNING, "failed to read %s: %s", *f, strerror(-r));
        }

        pico_strv_free(files);
        return 0;
}

/* --- object lifecycle -------------------------------------------------- */

int pico_tmpfiles_new(PicoTmpfiles **ret) {
        PicoTmpfiles *t;

        if (!ret)
                return -EINVAL;

        t = calloc(1, sizeof(*t));
        if (!t)
                return -ENOMEM;

        *ret = t;
        return 0;
}

PicoTmpfiles *pico_tmpfiles_free(PicoTmpfiles *t) {
        size_t k;

        if (!t)
                return NULL;

        for (k = 0; k < t->n_items; k++)
                array_free(t->items[k]);
        free(t->items);
        for (k = 0; k < t->n_globs; k++)
                array_free(t->globs[k]);
        free(t->globs);

        pico_strv_free(t->prefixes);
        pico_strv_free(t->exclude_prefixes);
        free(t->root);
        free(t);
        return NULL;
}

int pico_tmpfiles_set_root(PicoTmpfiles *t, const char *root) {
        char *r;

        if (!t)
                return -EINVAL;

        if (!root || !*root || strcmp(root, "/") == 0) {
                free(t->root);
                t->root = NULL;
                return 0;
        }

        if (root[0] != '/')
                return -EINVAL;

        r = strdup(root);
        if (!r)
                return -ENOMEM;
        pico_tmpfiles_path_simplify(r);

        free(t->root);
        t->root = r;
        return 0;
}

int pico_tmpfiles_add_prefix(PicoTmpfiles *t, const char *prefix) {
        if (!t || !prefix)
                return -EINVAL;
        return pico_strv_extend(&t->prefixes, prefix);
}

int pico_tmpfiles_add_exclude_prefix(PicoTmpfiles *t, const char *prefix) {
        if (!t || !prefix)
                return -EINVAL;
        return pico_strv_extend(&t->exclude_prefixes, prefix);
}
