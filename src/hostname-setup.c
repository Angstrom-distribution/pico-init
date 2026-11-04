/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "hostname-setup.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int hostname_read(const char *path, char *buf, size_t size) {
        FILE *f;
        size_t len;

        f = fopen(path, "re");
        if (!f)
                /* No file at all is not an error -- same as systemd's own
                 * hostname_setup() falling back to the kernel's compiled-in
                 * default ("(none)") when /etc/hostname does not exist. */
                return errno == ENOENT ? 0 : -errno;

        if (!fgets(buf, (int) size, f)) {
                fclose(f);
                buf[0] = '\0';
                return 0; /* empty file: nothing to apply, not an error */
        }
        fclose(f);

        /* /etc/hostname is one line, no trailing newline required; strip
         * whatever line ending and surrounding whitespace it does have. */
        len = strcspn(buf, "\r\n");
        buf[len] = '\0';
        while (len > 0 && (buf[len - 1] == ' ' || buf[len - 1] == '\t'))
                buf[--len] = '\0';

        return (int) len;
}

int hostname_setup(char *name) {
        char current[HOST_NAME_MAX + 1];
        int len;

        name[0] = '\0';

        len = hostname_read("/etc/hostname", name, HOST_NAME_MAX + 1);
        if (len < 0) {
                name[0] = '\0';
                return len;
        }
        if (len == 0)
                return 0;

        /* Only a change is worth a line, and an unchanged name needs no syscall. */
        if (gethostname(current, sizeof current) == 0 && strcmp(current, name) == 0) {
                name[0] = '\0';
                return 0;
        }

        if (sethostname(name, (size_t) len) < 0)
                return -errno;

        return 1;
}
