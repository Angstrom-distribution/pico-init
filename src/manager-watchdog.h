/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * PID 1's hardware watchdog feeder: opens /dev/watchdog0 (falling back to
 * /dev/watchdog), negotiates a timeout, and feeds it from a dedicated
 * sd_event time source at EVENT_PRIORITY_WATCHDOG -- the loop's highest
 * priority, so a hung PID 1 resets the board instead of leaving it silently
 * dead. Shape borrowed from upstream src/shared/watchdog.c (quarry read for
 * the API contract only; this implementation is independently written).
 *
 * No device is a fully supported, non-fatal outcome: qemu/dev images have
 * none, manager_watchdog_setup() returns -ENOENT, m->watchdog stays NULL,
 * and boot proceeds exactly as it does today. Every other entry point
 * no-ops on a NULL watchdog, the same contract as m->notify/m->ctrl.
 *
 * SHUTDOWN: the feed timer is never stopped by manager_shutdown() -- it
 * keeps firing through the stop-job drain, and manager_watchdog_done() as
 * called from manager_free() when m->is_system is true closes the fd
 * WITHOUT disarming it (no WDIOS_DISABLECARD, no magic-close 'V'). main.c
 * calls manager_free() before sync()+reboot(), so the device stays armed
 * across exactly the part of shutdown a software deadline cannot protect.
 * A non-system manager (tests) gets a full disarm on done() instead, so a
 * privileged test run on real hardware never leaves a ticking watchdog
 * behind -- though a nowayout kernel driver can still refuse it; see
 * manager-watchdog.c's close_sequence comment.
 *
 * DEFERRED SCOPE (each also named in manager-watchdog.c and the landing
 * commit message):
 *   - Per-service software watchdog (systemd's WatchdogSec=/Type=notify,
 *     sd_notify WATCHDOG=1 keepalive with restart-on-silence). Explicitly
 *     out of scope for this task; manager-notify.c already logs WATCHDOG*
 *     keys as diagnosable-but-inert, tied to SERVICE_TYPE_NOTIFY not
 *     existing. This feeder does not touch that path.
 *   - A separate, longer shutdown timeout (upstream's ShutdownWatchdogSec=)
 *     or a true disarm-on-shutdown: deferred because it needs a second
 *     configured value and pico-init has no config-file mechanism. A future
 *     knob would be a meson option pair re-armed at manager_shutdown()'s
 *     pending_objective choke point.
 *   - Tunability of the 30s compiled-in request, and of the device path
 *     beyond the test-only setter below: deferred until a board needs it,
 *     future shape is a 'watchdog-timeout' meson option (0 = compile the
 *     feeder out).
 *   - Pretimeout/pretimeout-governor support (WDIOC_SETPRETIMEOUT): no pico
 *     target has expressed a need.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "sd-event.h"
#include "util.h"

typedef struct Manager Manager;

/* Opaque; defined in manager-watchdog.c so manager.h need not know its shape. */
struct pico_manager_watchdog;

/* Open the device, negotiate the timeout, arm the feed timer. 0 or -errno;
 * failure is documented non-fatal-to-boot (see this header's own note and
 * manager-startup.c's call site). */
int manager_watchdog_setup(Manager *m);

/* Disable the feed timer; disarm the device (WDIOS_DISABLECARD + magic-close
 * 'V') iff !m->is_system -- see this header's SHUTDOWN note for why PID 1
 * itself never disarms. Idempotent on an already-torn-down or NULL watchdog. */
void manager_watchdog_done(Manager *m);

bool manager_watchdog_armed(Manager *m);

/* 0 when not armed. */
usec_t manager_watchdog_ping_interval(Manager *m);

/* Pure helper, exposed for tests: timeout_usec / 4 -- the missed-feed-margin
 * contract manager-watchdog.c's timeout_negotiation argues for. */
usec_t manager_watchdog_interval_from_timeout(usec_t timeout_usec);

/* manager_set_watchdog_device() (the device-path test override) lives in
 * manager.h/manager.c beside the other search-path setters, not here --
 * m->watchdog_device is a Manager-owned field, same as runtime_dir. */

/* Test-only: the underlying event source, NULL when not armed. Exposed
 * solely so a test can assert its priority directly (sd_event_source_get_
 * priority()) without the opaque struct itself needing to be public --
 * nothing else should ever reach into it this way. */
sd_event_source *manager_watchdog_debug_source(Manager *m);

/* Test-only: arm the real time source at the real priority with no device fd
 * (fd == -1) -- feeds become counter increments instead of a WDIOC_KEEPALIVE
 * ioctl, so the event-integration/starvation properties are testable without
 * real watchdog hardware. 0 or -errno. */
int manager_watchdog_debug_arm(Manager *m, usec_t interval);

/* Test-only: how many feeds have fired since setup/debug_arm. 0 when not armed. */
size_t manager_watchdog_debug_n_pings(Manager *m);
