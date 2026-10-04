/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/* See clock-persist.h for the contract and the rules. */

#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "clock-persist.h"

static bool valid_candidate(int64_t sec) {
        return sec > 0 && sec <= CLOCK_PERSIST_MAX_SEC;
}

int clock_persist_parse(const char *text, int64_t *ret_sec) {
        struct tm tm = { 0 };
        int digits[14];
        const char *p;
        int i, year, mon, day, hour, min, sec;
        time_t t;

        if (!text || !ret_sec)
                return -EINVAL;

        for (i = 0; i < 14; i++) {
                if (!isdigit((unsigned char) text[i]))
                        return -EINVAL;
                digits[i] = text[i] - '0';
        }
        for (p = text + 14; *p; p++)
                if (!isspace((unsigned char) *p))
                        return -EINVAL;

        year = digits[0] * 1000 + digits[1] * 100 + digits[2] * 10 + digits[3];
        mon = digits[4] * 10 + digits[5];
        day = digits[6] * 10 + digits[7];
        hour = digits[8] * 10 + digits[9];
        min = digits[10] * 10 + digits[11];
        sec = digits[12] * 10 + digits[13];

        if (year < 1970 || mon < 1 || mon > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 60)
                return -EINVAL;

        tm.tm_year = year - 1900;
        tm.tm_mon = mon - 1;
        tm.tm_mday = day;
        tm.tm_hour = hour;
        tm.tm_min = min;
        tm.tm_sec = sec;

        t = timegm(&tm);
        if (t == (time_t) -1)
                return -EINVAL;

        /* timegm() normalises 31 February to early March; reject what does not round-trip. */
        if (tm.tm_year != year - 1900 || tm.tm_mon != mon - 1 || tm.tm_mday != day)
                return -EINVAL;

        *ret_sec = (int64_t) t;
        return 0;
}

int clock_persist_format(int64_t sec, char out[CLOCK_PERSIST_TEXT_MAX]) {
        struct tm tm;
        time_t t = (time_t) sec;

        if (sec < 0 || (int64_t) t != sec || !gmtime_r(&t, &tm) || tm.tm_year + 1900 > 9999)
                return -EINVAL;

        return snprintf(out,
                        CLOCK_PERSIST_TEXT_MAX,
                        "%04d%02d%02d%02d%02d%02d\n",
                        tm.tm_year + 1900,
                        tm.tm_mon + 1,
                        tm.tm_mday,
                        tm.tm_hour,
                        tm.tm_min,
                        tm.tm_sec);
}

bool clock_persist_decide(int64_t file_sec, int64_t mtime_sec, int64_t now_sec, int64_t *ret_target) {
        int64_t floor = CLOCK_PERSIST_EPOCH_SEC;

        if (valid_candidate(file_sec) && file_sec > floor)
                floor = file_sec;
        if (valid_candidate(mtime_sec) && mtime_sec > floor)
                floor = mtime_sec;

        if (now_sec >= floor)
                return false;

        *ret_target = floor;
        return true;
}

/* The saved time and the file's mtime; either is 0 when it cannot be had. */
static void read_state(const char *path, int64_t *ret_file_sec, int64_t *ret_mtime_sec) {
        char buf[64];
        struct stat st;
        ssize_t n;
        int fd;

        *ret_file_sec = 0;
        *ret_mtime_sec = 0;

        fd = open(path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
        if (fd < 0)
                return;

        if (fstat(fd, &st) == 0)
                *ret_mtime_sec = (int64_t) st.st_mtim.tv_sec;

        n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
                buf[n] = '\0';
                if (clock_persist_parse(buf, ret_file_sec) < 0)
                        *ret_file_sec = 0;
        }
}

int clock_persist_restore(const char *path, int64_t now_sec, int (*set)(int64_t sec)) {
        int64_t file_sec, mtime_sec, target;
        int r;

        if (!path || !set)
                return -EINVAL;

        read_state(path, &file_sec, &mtime_sec);

        if (!clock_persist_decide(file_sec, mtime_sec, now_sec, &target))
                return 0;

        r = set(target);
        if (r < 0)
                return r;
        return 1;
}

int clock_persist_save(const char *path, int64_t now_sec) {
        char text[CLOCK_PERSIST_TEXT_MAX];
        char tmp[PATH_MAX];
        int64_t file_sec, mtime_sec;
        int len, fd, r;

        if (!path)
                return -EINVAL;
        if (now_sec < CLOCK_PERSIST_EPOCH_SEC || now_sec > CLOCK_PERSIST_MAX_SEC)
                return 0;

        read_state(path, &file_sec, &mtime_sec);
        if (file_sec >= now_sec)
                return 0;

        len = clock_persist_format(now_sec, text);
        if (len < 0)
                return len;

        if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int) sizeof(tmp))
                return -ENAMETOOLONG;

        fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOCTTY, 0644);
        if (fd < 0)
                return -errno;

        if (write(fd, text, (size_t) len) != (ssize_t) len || fsync(fd) < 0) {
                r = -errno;
                close(fd);
                unlink(tmp);
                return r ? r : -EIO;
        }
        if (close(fd) < 0) {
                r = -errno;
                unlink(tmp);
                return r;
        }

        if (rename(tmp, path) < 0) {
                r = -errno;
                unlink(tmp);
                return r;
        }
        return 1;
}

int clock_persist_set_realtime(int64_t sec) {
        struct timespec ts = { .tv_sec = (time_t) sec, .tv_nsec = 0 };

        if ((int64_t) ts.tv_sec != sec)
                return -ERANGE; /* a 32-bit time_t cannot hold it */

        if (clock_settime(CLOCK_REALTIME, &ts) < 0)
                return -errno;
        return 0;
}
