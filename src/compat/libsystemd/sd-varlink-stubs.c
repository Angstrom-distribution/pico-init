/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * The part of sd-varlink.h and sd-varlink-idl.h that needs a Varlink
 * engine: connecting, creating a server, and formatting or parsing an
 * interface description. There is no engine in this build, so every
 * constructor fails with -EOPNOTSUPP and no sd_varlink or
 * sd_varlink_server can ever exist. Programs that reference the interface
 * load, and take their failure path.
 *
 * Each function first applies the argument checks upstream makes before it
 * touches anything (a NULL output, command, address or interface is
 * -EINVAL, a negative fd is -EBADF) and the URL checks that need no
 * connection. What is left is -EOPNOTSUPP, never success. Output
 * parameters are not touched on failure, as upstream.
 *
 * The handle-based calls are in sd-varlink-noop.c.
 */

#include "sd-varlink.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

int sd_varlink_connect_address(sd_varlink **ret, const char *address) {
        if (!ret || !address)
                return -EINVAL;
        return -EOPNOTSUPP;
}

int sd_varlink_connect_exec(sd_varlink **ret, const char *command, char **argv) {
        (void) argv;
        if (!ret || !command)
                return -EINVAL;
        return -EOPNOTSUPP;
}

int sd_varlink_connect_fd_pair(sd_varlink **ret, int input_fd, int output_fd, const struct ucred *override_ucred) {
        (void) override_ucred;
        if (!ret)
                return -EINVAL;
        if (input_fd < 0 || output_fd < 0)
                return -EBADF;
        return -EOPNOTSUPP;
}

int sd_varlink_connect_fd(sd_varlink **ret, int fd) {
        return sd_varlink_connect_fd_pair(ret, fd, fd, /* override_ucred= */ NULL);
}

/* The path of a unix: or exec: URL has to be absolute and normalized. */
static bool path_ok(const char *p) {
        if (p[0] != '/')
                return false;

        for (const char *c = p; *c;) {
                size_t n = strcspn(c, "/");

                if ((n == 1 && c[0] == '.') || (n == 2 && c[0] == '.' && c[1] == '.'))
                        return false;
                c += n;
                c += strspn(c, "/");
        }

        return true;
}

int sd_varlink_connect_url(sd_varlink **ret, const char *url) {
        static const char * const prefixes[] = { "unix:", "exec:", "ssh:", "ssh-unix:", "ssh-exec:" };
        const char *p = NULL;
        bool is_ssh = false, is_exec = false;

        if (!ret || !url)
                return -EINVAL;

        for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]) && !p; i++)
                if (strncmp(url, prefixes[i], strlen(prefixes[i])) == 0) {
                        p = url + strlen(prefixes[i]);
                        is_exec = i == 1;
                        is_ssh = i >= 2;
                }

        /* Any other scheme needs a bridge helper to run, and none is looked for. */
        if (!p)
                return -EPROTONOSUPPORT;

        if (p[strcspn(p, ";?#")] != '\0')
                return -EPROTONOSUPPORT;

        if (!is_ssh && (is_exec || p[0] != '@') && !path_ok(p))
                return -EINVAL;

        return -EOPNOTSUPP;
}

int sd_varlink_server_new(sd_varlink_server **ret, sd_varlink_server_flags_t flags) {
        const uint64_t known = SD_VARLINK_SERVER_ROOT_ONLY | SD_VARLINK_SERVER_MYSELF_ONLY |
                        SD_VARLINK_SERVER_ACCOUNT_UID | SD_VARLINK_SERVER_INHERIT_USERDATA |
                        SD_VARLINK_SERVER_INPUT_SENSITIVE | SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT |
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT |
                        SD_VARLINK_SERVER_FD_PASSING_INPUT_STRICT | SD_VARLINK_SERVER_HANDLE_SIGINT |
                        SD_VARLINK_SERVER_HANDLE_SIGTERM | SD_VARLINK_SERVER_UPGRADABLE;

        if (!ret || ((uint64_t) flags & ~known) != 0)
                return -EINVAL;
        return -EOPNOTSUPP;
}

/* Describing an interface needs the formatter, which is not implemented. */
int sd_varlink_idl_dump(
                FILE *f, const sd_varlink_interface *interface, sd_varlink_idl_format_flags_t flags, size_t cols) {
        (void) f;
        (void) flags;
        (void) cols;
        if (!interface)
                return -EINVAL;
        return -EOPNOTSUPP;
}

int sd_varlink_idl_format_full(
                const sd_varlink_interface *interface,
                sd_varlink_idl_format_flags_t flags,
                size_t cols,
                char **ret) {
        (void) ret;
        return sd_varlink_idl_dump(NULL, interface, flags, cols);
}

int sd_varlink_idl_format(const sd_varlink_interface *interface, char **ret) {
        return sd_varlink_idl_format_full(interface, 0, SIZE_MAX, ret);
}

/* No parser either, so no interface is ever allocated; see
 * sd_varlink_interface_free(). */
int sd_varlink_idl_parse(
                const char *text, unsigned *reterr_line, unsigned *reterr_column, sd_varlink_interface **ret) {
        (void) text;
        (void) reterr_line;
        (void) reterr_column;
        (void) ret;
        return -EOPNOTSUPP;
}

/* Nothing the parser allocated can exist, and a static description must not
 * be freed, so there is never anything to release. */
sd_varlink_interface *sd_varlink_interface_free(sd_varlink_interface *interface) {
        (void) interface;
        return NULL;
}
