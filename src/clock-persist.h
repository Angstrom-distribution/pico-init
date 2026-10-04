/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Keeping the wall clock roughly right across reboots on a board whose RTC is
 * dead or reset by every reboot (the iPAQ h2200's PXA RTC reads 1970 at boot).
 *
 * The time is kept in /etc/timestamp, the OpenEmbedded file (initscripts'
 * save-rtc.sh and bootmisc.sh): fourteen digits, YYYYMMDDHHMMSS, UTC. PID 1
 * restores it before any service starts and writes it periodically and at
 * shutdown. The saved time is only ever a lower bound for the clock:
 *
 *   - the clock moves forward to the largest of the saved time, the file's
 *     mtime and the build epoch, never backwards (Debian's fake-hwclock,
 *     systemd's clock-epoch and timesyncd's clock file all do the same), and
 *     a later NTP sync corrects whatever is left;
 *   - a candidate beyond CLOCK_PERSIST_MAX_SEC is ignored, so a file carried
 *     over from a machine with a broken clock cannot throw this one into the
 *     far future;
 *   - nothing is saved while the clock is still below the epoch (it was never
 *     set), and a save never replaces a later saved time with an earlier one.
 *
 * netd keeps its own floor in /var/lib/netd/clock, touched on NTP syncs; the
 * two are independent and both only move the clock forward.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define CLOCK_PERSIST_FILE "/etc/timestamp"

/* 2026-01-01T00:00:00Z: no image is built, so no clock is right, before this. */
#define CLOCK_PERSIST_EPOCH_SEC ((int64_t) 1767225600)

/* 2100-01-01T00:00:00Z: anything later is a bad file, not a time. */
#define CLOCK_PERSIST_MAX_SEC ((int64_t) 4102444800)

/* Longest string clock_persist_format() writes, NUL included. */
#define CLOCK_PERSIST_TEXT_MAX 16

/* How often PID 1 saves while running, in seconds. */
#define CLOCK_PERSIST_INTERVAL_SEC 600

/*
 * "YYYYMMDDHHMMSS" with optional trailing whitespace (the file ends in a
 * newline) into seconds since the epoch. 0, or -EINVAL for anything else:
 * wrong length, a non-digit, a date that does not exist.
 */
int clock_persist_parse(const char *text, int64_t *ret_sec);

/* The inverse, with a trailing newline. Returns the length, or -EINVAL outside 0..9999-12-31. */
int clock_persist_format(int64_t sec, char out[CLOCK_PERSIST_TEXT_MAX]);

/*
 * The decision as a value. file_sec and mtime_sec are 0 when absent or
 * unreadable. Returns true and sets *ret_target when the clock at now_sec is
 * below the floor and should be moved to it.
 */
bool clock_persist_decide(int64_t file_sec, int64_t mtime_sec, int64_t now_sec, int64_t *ret_target);

/*
 * Reads `path`, decides, and calls set(target) when the clock needs to move
 * forward. A missing or garbled file is not an error: the epoch still applies.
 * 1 when set() ran and succeeded, 0 when nothing needed doing, -errno when
 * set() failed (its own return value).
 */
int clock_persist_restore(const char *path, int64_t now_sec, int (*set)(int64_t sec));

/*
 * Writes now_sec to `path`, atomically (temp file in the same directory,
 * fsync, rename). Skips with 0 while now_sec is below the epoch or below what
 * the file already holds; 1 when written; -errno when the write failed, for
 * instance on a read-only root.
 */
int clock_persist_save(const char *path, int64_t now_sec);

/* The real setter: clock_settime(CLOCK_REALTIME). */
int clock_persist_set_realtime(int64_t sec);
