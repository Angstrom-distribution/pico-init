/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "hostname-setup.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

int hostname_setup(void) {
        char buf[HOST_NAME_MAX + 1];
        FILE *f;
        size_t len;

        f = fopen("/etc/hostname", "re");
        if (!f)
                /* No file at all is not an error -- same as systemd's own
                 * hostname_setup() falling back to the kernel's compiled-in
                 * default ("(none)") when /etc/hostname does not exist. */
                return errno == ENOENT ? 0 : -errno;

        if (!fgets(buf, sizeof buf, f)) {
                fclose(f);
                return 0; /* empty file: nothing to apply, not an error */
        }
        fclose(f);

        /* /etc/hostname is one line, no trailing newline required; strip
         * whatever line ending and surrounding whitespace it does have. */
        len = strcspn(buf, "\r\n");
        buf[len] = '\0';
        while (len > 0 && (buf[len - 1] == ' ' || buf[len - 1] == '\t'))
                buf[--len] = '\0';

        if (len == 0)
                return 0;

        if (sethostname(buf, (int) len) < 0) {
                pico_log(PICO_LOG_WARNING, "sethostname(\"%s\"): %s", buf, strerror(errno));
                return -errno;
        }

        pico_log(PICO_LOG_INFO, "hostname set to '%s'", buf);
        return 0;
}
