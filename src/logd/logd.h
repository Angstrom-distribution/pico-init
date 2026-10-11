/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * logd -- the pico-init log daemon. Shared internal declarations.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* Where the ring lives. /run is tmpfs, so flash is never written and the RAM
 * cost is bounded by the cap. */
#define LOGD_RUNTIME_DIR "/run/logd"

/* Two-file ring: an active file and one rotated predecessor, rotation at half
 * the cap. */
#define LOGD_DEFAULT_MAX_BYTES ((size_t) (2 * 1024 * 1024))

/* Ring filenames only -- joined against whatever directory the writer is
 * configured with (settable, logd-write.h), never against LOGD_RUNTIME_DIR
 * directly, so tests need neither root nor a real /run. picolog reads
 * rotated-then-active, in that order, using these same two names. */
#define LOGD_RING_ACTIVE_NAME "active.export"
#define LOGD_RING_ROTATED_NAME "rotated.export"

/* The bound datagram sockets logd receives on, both handed over by PID 1
 * through LISTEN_FDS in declared order (LISTEN_FDNAMES is not set). */
#define LOGD_STDOUT_SOCKET_PATH LOGD_RUNTIME_DIR "/stdout"
#define LOGD_SYSLOG_SOCKET_PATH "/dev/log"

/*
 * The per-line cap before a forced split, tagged _LINE_BREAK=line-max --
 * upstream's own field and value (journald-stream.c), so journalctl renders
 * it correctly after conversion. Upstream's own LineMax= defaults to 48K;
 * pico's whole ring defaults to 2 MiB (24x smaller), so a proportionally
 * smaller line cap keeps one pathological line from dominating it.
 */
#define LOGD_LINE_MAX ((size_t) 8192)

/*
 * The bounded per-stream fragment-tail table: keyed by stream identity -- the sender's bound source
 * address on the stdout socket -- not by PID, which neither survives a
 * service that spans several PIDs on one stream (an ordinary
 * ExecStart=/bin/sh -c '...' has the shell and its children sharing one
 * fd) nor resists PID reuse corrupting an unrelated later stream. LRU-
 * evicted, so a burst of distinct senders never grows this past a fixed
 * bound regardless of how many connect.
 */
#define LOGD_MAX_STREAMS ((size_t) 64)
