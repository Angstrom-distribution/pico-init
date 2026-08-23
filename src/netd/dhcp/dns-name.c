/* SPDX-FileCopyrightText: The systemd project */
/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Ported subset of src/shared/dns-domain.c (~200 of 1,376 lines): see
 * dns-name.h for exactly what and why.
 *
 * Quarry point: systemd v261.2, commit 4925d9f07f. History review
 * (4925d9f07f..main, plan §2.2): no fix in the 26-commit lift-set window
 * touches dns-domain.c.
 *
 * dns_label_unescape()/dns_label_escape()/dns_name_concat() are carried
 * near-verbatim (the escape-sequence and length-limit rules are RFC 1035
 * text, not something to improvise); ascii_isalpha()/ascii_isdigit()/
 * valid_ldh_char()/ascii_strcasecmp_n() are small helpers pulled in from
 * src/basic/{string-util,hostname-util}.c inline rather than as separate
 * files, since each is a handful of lines and neither source file is
 * otherwise in this lift.
 *
 * Assertion policy: dns_label_unescape()/dns_name_concat() below parse
 * option-12/15 string data that ultimately comes off the wire (through
 * dhcp_message_get_option_dns_name() in dhcp-message.c), so every length
 * and syntax check in them is a real -EINVAL/-ENOBUFS return, never
 * assert() -- matching netd-compat.h's rule for externally-supplied data.
 */

#include "netd-compat.h"

#include "dns-name.h"

/* Not in netd-compat.h; a one-line macro three files in this lift need. */
#define FLAGS_SET(flags, flag) (((flags) & (flag)) == (flag))


#define DNS_LABEL_MAX 63
#define DNS_LABEL_ESCAPED_MAX (DNS_LABEL_MAX * 4 + 1)
#define DNS_HOSTNAME_MAX 253

typedef enum DNSLabelFlags {
        DNS_LABEL_LDH = 1 << 0,
} DNSLabelFlags;

static bool ascii_isdigit(char c) {
        return c >= '0' && c <= '9';
}

static bool ascii_isalpha(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static char ascii_tolower(char c) {
        return (c >= 'A' && c <= 'Z') ? (char) (c - 'A' + 'a') : c;
}

static bool valid_ldh_char(char c) {
        return ascii_isalpha(c) || ascii_isdigit(c) || c == '-';
}

static int ascii_strcasecmp_n(const char *a, const char *b, size_t n) {
        for (; n > 0; a++, b++, n--) {
                int x = (int) (uint8_t) ascii_tolower(*a);
                int y = (int) (uint8_t) ascii_tolower(*b);

                if (x != y)
                        return x - y;
        }

        return 0;
}

/*
 * Unescape one DNS label from *name (a "." separated presentation-format
 * name) into dest, advancing *name past it (and past the separating dot,
 * if any). Returns the label length, 0 at the end of the name, or a
 * negative errno on a syntax violation -- ported near-verbatim from
 * dns_label_unescape(), trimmed to the flag netd actually passes (LDH is
 * unused by netd's own call sites but kept since dns_name_is_valid_ldh()
 * needs it; DNS_LABEL_NO_ESCAPES and DNS_LABEL_LEAVE_TRAILING_DOT, which
 * upstream's option 119 decoder and reverse-lookup helpers used, are cut).
 */
static int dns_label_unescape(const char **name, char *dest, size_t sz, DNSLabelFlags flags) {
        const char *n;
        char *d, last_char = 0;
        int r = 0;

        assert(name);

        if (isempty(*name)) {
                if (dest && sz >= 1)
                        dest[0] = 0;
                return 0;
        }

        n = *name;
        d = dest;

        for (;;) {
                if (n[0] == 0 || n[0] == '.') {
                        if (FLAGS_SET(flags, DNS_LABEL_LDH) && last_char == '-')
                                return -EINVAL; /* trailing dash */

                        if (n[0] == '.' && n[1] != 0)
                                n++;

                        break;
                }

                if (r >= DNS_LABEL_MAX)
                        return -EINVAL;
                if (sz == 0)
                        return -ENOBUFS;

                if (n[0] == '\\') {
                        n++;

                        if (n[0] == 0)
                                return -EINVAL;

                        if (n[0] == '\\' || n[0] == '.') {
                                if (FLAGS_SET(flags, DNS_LABEL_LDH))
                                        return -EINVAL;

                                last_char = n[0];
                                if (d)
                                        *(d++) = n[0];
                                sz--;
                                r++;
                                n++;

                        } else if (n[0] >= '0' && n[0] <= '9') {
                                unsigned k;

                                if (!(n[1] >= '0' && n[1] <= '9') || !(n[2] >= '0' && n[2] <= '9'))
                                        return -EINVAL;

                                k = ((unsigned) (n[0] - '0') * 100) + ((unsigned) (n[1] - '0') * 10) +
                                                ((unsigned) (n[2] - '0'));
                                if (k > 255)
                                        return -EINVAL;

                                if (FLAGS_SET(flags, DNS_LABEL_LDH) && !valid_ldh_char((char) k))
                                        return -EINVAL;

                                last_char = (char) k;
                                if (d)
                                        *(d++) = (char) k;
                                sz--;
                                r++;
                                n += 3;
                        } else
                                return -EINVAL;

                } else if ((uint8_t) n[0] >= (uint8_t) ' ' && n[0] != 127) {
                        if (FLAGS_SET(flags, DNS_LABEL_LDH)) {
                                if (!valid_ldh_char(n[0]))
                                        return -EINVAL;
                                if (r == 0 && n[0] == '-')
                                        return -EINVAL; /* leading dash */
                        }

                        last_char = n[0];
                        if (d)
                                *(d++) = n[0];
                        sz--;
                        r++;
                        n++;
                } else
                        return -EINVAL;
        }

        if (r == 0 && n[0] != 0) /* empty label that is not at the end */
                return -EINVAL;

        if (n[0] == '.') /* more than one trailing dot */
                return -EINVAL;

        if (sz >= 1 && d)
                *d = 0;

        *name = n;
        return r;
}

/* Ported near-verbatim from dns_label_escape(). Static: netd's only caller
 * is dns_name_concat()'s normalize round-trip (see dns-name.h's header). */
static int dns_label_escape(const char *p, size_t l, char *dest, size_t sz) {
        char *q;

        if (l == 0 || l > DNS_LABEL_MAX)
                return -EINVAL;
        if (sz < 1)
                return -ENOBUFS;

        assert(p);
        assert(dest);

        q = dest;
        while (l > 0) {
                if (*p == '.' || *p == '\\') {
                        if (sz < 3)
                                return -ENOBUFS;
                        *(q++) = '\\';
                        *(q++) = *p;
                        sz -= 2;
                } else if (*p == '_' || *p == '-' || ascii_isdigit(*p) || ascii_isalpha(*p)) {
                        if (sz < 2)
                                return -ENOBUFS;
                        *(q++) = *p;
                        sz -= 1;
                } else {
                        if (sz < 5)
                                return -ENOBUFS;
                        *(q++) = '\\';
                        *(q++) = (char) ('0' + (char) ((uint8_t) *p / 100));
                        *(q++) = (char) ('0' + (char) (((uint8_t) *p / 10) % 10));
                        *(q++) = (char) ('0' + (char) ((uint8_t) *p % 10));
                        sz -= 4;
                }

                p++;
                l--;
        }

        *q = 0;
        return (int) (q - dest);
}

/*
 * Ported near-verbatim from dns_name_concat(). Validates `a` label-by-label
 * (unescape then re-escape each one) and, if `ret` is non-NULL, builds the
 * normalized string. dns_name_normalize()/dns_name_is_valid()/
 * dns_name_is_valid_ldh() are all this one function with different `flags`
 * and `ret`, exactly as upstream's static-inline wrappers in dns-domain.h.
 */
static int dns_name_concat(const char *a, DNSLabelFlags flags, char **ret) {
        _cleanup_free_ char *result = NULL;
        size_t n_result = 0, n_unescaped = 0, result_allocated = 0;
        const char *p = a;
        bool first = true;
        int r;

        for (;;) {
                char label[DNS_LABEL_MAX + 1];

                r = dns_label_unescape(&p, label, sizeof label, flags);
                if (r < 0)
                        return r;
                if (r == 0) {
                        if (p[0] != 0)
                                return -EINVAL;
                        break;
                }
                n_unescaped += (size_t) r + !first;

                char escaped[DNS_LABEL_ESCAPED_MAX];
                r = dns_label_escape(label, (size_t) r, escaped, sizeof escaped);
                if (r < 0)
                        return r;

                if (ret) {
                        if (!GREEDY_REALLOC(result, n_result + !first + (size_t) r + 1))
                                return -ENOMEM;
                        if (!first)
                                result[n_result++] = '.';
                        memcpy(result + n_result, escaped, (size_t) r);
                        n_result += (size_t) r;
                }

                first = false;
        }

        if (n_unescaped == 0) {
                if (ret) {
                        if (!GREEDY_REALLOC(result, n_result + 2))
                                return -ENOMEM;
                        result[n_result++] = '.';
                }
                n_unescaped++;
        }

        if (n_unescaped > DNS_HOSTNAME_MAX)
                return -EINVAL;

        if (ret) {
                if (!GREEDY_REALLOC(result, n_result + 1))
                        return -ENOMEM;
                result[n_result] = 0;
                *ret = TAKE_PTR(result);
        }

        return 0;
}

int dns_name_is_valid(const char *s) {
        int r = dns_name_concat(s, 0, NULL);
        if (r == -EINVAL)
                return 0;
        if (r < 0)
                return r;
        return 1;
}

int dns_name_is_valid_ldh(const char *s) {
        int r = dns_name_concat(s, DNS_LABEL_LDH, NULL);
        if (r == -EINVAL)
                return 0;
        if (r < 0)
                return r;
        return 1;
}

int dns_name_normalize(const char *name, char **ret) {
        return dns_name_concat(name, 0, ret);
}

bool dns_name_is_root(const char *name) {
        assert(name);
        return streq(name, "") || streq(name, ".");
}

bool dns_name_is_single_label(const char *name) {
        const char *p = name;
        int r = dns_label_unescape(&p, NULL, DNS_LABEL_MAX, 0);
        if (r <= 0)
                return false;

        return dns_name_is_root(p);
}

int dns_name_equal(const char *x, const char *y) {
        assert(x);
        assert(y);

        for (;;) {
                char la[DNS_LABEL_MAX + 1], lb[DNS_LABEL_MAX + 1];

                int r = dns_label_unescape(&x, la, sizeof la, 0);
                if (r < 0)
                        return r;

                int q = dns_label_unescape(&y, lb, sizeof lb, 0);
                if (q < 0)
                        return q;

                if (r != q)
                        return false;
                if (r == 0)
                        return true;

                if (ascii_strcasecmp_n(la, lb, (size_t) r) != 0)
                        return false;
        }
}
