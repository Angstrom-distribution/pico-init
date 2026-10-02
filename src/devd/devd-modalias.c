/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "devd-modalias.h"

#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "../util.h"
#include "devd-run.h"
#include "devd-uevent.h"
#include "devd.h"

#define MODPROBE_PATH "/sbin/modprobe"

/* Long enough for any real MODALIAS (devd-match.c's own "several hundred
 * bytes" note); devd_run_spawn()'s own DEVD_RUN_ARG_MAX (192) is the real
 * ceiling an overlong one is clamped against -- see spawn_modprobe(). */
#define MODALIAS_BUF_MAX 256

/* Pull MODALIAS=<value> out of a uevent's raw NUL-separated props blob.
 * Returns NULL if absent, same "not every uevent has one" case
 * devd-uevent.c's own parser already expects. */
static const char *uevent_modalias(const DevdUevent *u, char *buf, size_t bufsize) {
        size_t off = 0;

        while (off < u->props_len) {
                size_t len = strlen(u->props + off);

                if (strncmp(u->props + off, "MODALIAS=", 9) == 0) {
                        (void) snprintf(buf, bufsize, "%s", u->props + off + 9);
                        return buf;
                }

                off += len + 1;
        }

        return NULL;
}

static void spawn_modprobe(Devd *d, const char *alias) {
        char cmd[sizeof(MODPROBE_PATH) + MODALIAS_BUF_MAX];
        int r;

        if ((size_t) snprintf(cmd, sizeof(cmd), MODPROBE_PATH " %s", alias) >= sizeof(cmd)) {
                pico_log(PICO_LOG_WARNING, "devd: modalias too long to modprobe: %s", alias);
                return;
        }

        /* devd_run_spawn() itself logs and returns -EINVAL if `alias` still
         * does not fit inside its own DEVD_RUN_ARG_MAX once split -- nothing
         * further to do here either way, same best-effort discipline every
         * other RUN+= caller already has. */
        r = devd_run_spawn(&d->run, cmd, NULL);
        if (r < 0 && r != -EAGAIN)
                pico_log(PICO_LOG_DEBUG, "devd: modprobe %s: %s", alias, strerror(-r));
}

void devd_modalias_autoload_uevent(Devd *d, const DevdUevent *u) {
        char buf[MODALIAS_BUF_MAX];
        const char *alias;

        if (!d || !u || u->action != DEVD_ACTION_ADD)
                return;

        alias = uevent_modalias(u, buf, sizeof(buf));
        if (alias)
                spawn_modprobe(d, alias);
}

void devd_coldplug_modalias(Devd *d) {
        char busdir[PATH_MAX];
        struct dirent *be;
        DIR *bd;

        if (!d)
                return;

        if ((size_t) snprintf(busdir, sizeof(busdir), "%s/bus", d->sys_root) >= sizeof(busdir))
                return;

        bd = opendir(busdir);
        if (!bd)
                return;

        while ((be = readdir(bd))) {
                char devdir[PATH_MAX];
                struct dirent *de;
                DIR *dd;

                if (be->d_name[0] == '.')
                        continue;

                if ((size_t) snprintf(devdir, sizeof(devdir), "%s/%s/devices", busdir, be->d_name) >=
                    sizeof(devdir))
                        continue;

                dd = opendir(devdir);
                if (!dd)
                        continue;

                while ((de = readdir(dd))) {
                        char path[PATH_MAX], alias[MODALIAS_BUF_MAX];
                        FILE *f;

                        if (de->d_name[0] == '.')
                                continue;

                        if ((size_t) snprintf(path, sizeof(path), "%s/%s/modalias", devdir, de->d_name) >=
                            sizeof(path))
                                continue;

                        f = fopen(path, "re");
                        if (!f)
                                continue; /* no modalias attribute: not every device has one */

                        if (fgets(alias, sizeof(alias), f)) {
                                alias[strcspn(alias, "\n")] = '\0';
                                if (alias[0] != '\0')
                                        spawn_modprobe(d, alias);
                        }

                        fclose(f);
                }

                closedir(dd);
        }

        closedir(bd);
}
