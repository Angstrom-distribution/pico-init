/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * logd -- the pico-init log daemon (plan §3). Shared internal declarations.
 *
 * Scaffolding: milestone J0-J2 owns this file and lands the real body. It is
 * registered in the build now so that milestone adds code to a file that
 * already exists and is already compiled, rather than editing meson.build
 * while another milestone is also editing it.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

/* Where the ring lives. /run is tmpfs, so flash is never written and the RAM
 * cost is bounded by the cap -- the same volatile posture the journald-pico.conf
 * this component replaces already chose. */
#define LOGD_RUNTIME_DIR "/run/logd"

/* Two-file ring: an active file and one rotated predecessor, rotation at half
 * the cap. 2 MiB matches the incumbent RuntimeMaxUse=2M budget exactly. */
#define LOGD_DEFAULT_MAX_BYTES ((size_t) (2 * 1024 * 1024))

/* Ring filenames only -- joined against whatever directory the writer is
 * configured with (settable, logd-write.h), never against LOGD_RUNTIME_DIR
 * directly, so tests need neither root nor a real /run. picolog (J3) reads
 * rotated-then-active, in that order, using these same two names. */
#define LOGD_RING_ACTIVE_NAME "active.export"
#define LOGD_RING_ROTATED_NAME "rotated.export"

/* The bound datagram sockets logd receives on, both handed over by PID 1
 * through LISTEN_FDS in declared order (plan §1.6: no LISTEN_FDNAMES). */
#define LOGD_STDOUT_SOCKET_PATH LOGD_RUNTIME_DIR "/stdout"
#define LOGD_SYSLOG_SOCKET_PATH "/dev/log"
