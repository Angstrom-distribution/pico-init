#!/bin/sh
# SPDX-FileCopyrightText: 2026 Koen Kooi
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Smoke test: the binary links, runs, exits 0 when not PID1, and
# every public entry point from the src/*.h API surface is actually present
# in the linked binary (stub bodies returning -ENOSYS are fine -- absence
# is not).
set -eu

bin="$1"

# 1. Linkable binary that runs and exits cleanly (not PID1 here, so a stub
#    main must detect that and exit 0 rather than loop or reboot()).
"$bin"

# 1b. The version and help text, and a refusal that must not look like success.
"$bin" --version | grep -q '^pico-init '
"$bin" --help | grep -q 'Kernel command line'
if "$bin" --test >/dev/null 2>&1; then
        echo "FAIL: --test must be refused" >&2
        exit 1
fi

# 2. Symbol presence. Leading underscore is optional (Mach-O vs ELF).
symbols=$(nm "$bin")

missing=0
for sym in \
        manager_new manager_free manager_load_units manager_get_unit \
        manager_load_unit manager_add_job manager_dispatch_run_queue \
        manager_loop manager_dispatch_signal manager_shutdown \
        unit_new unit_free unit_active_state unit_start unit_stop \
        unit_load unit_parse_file unit_add_dependency \
        unit_dependency_detect_cycles \
        service_start service_stop service_sigchld_event \
        service_cgroup_empty_event service_spawn \
        job_new job_free job_run job_finish \
        transaction_new transaction_free transaction_add_job \
        transaction_activate \
        cgroup_v2_new cgroup_v2_add_process cgroup_v2_monitor \
        cgroup_v2_kill cgroup_v2_is_empty cgroup_v2_free \
        pico_timer_new pico_timer_fd pico_timer_add pico_timer_cancel \
        pico_timer_dispatch pico_timer_free \
        pico_signal_new pico_signal_fd pico_signal_read pico_signal_free \
        now_monotonic pico_log_internal compat_noop \
; do
        if ! printf '%s\n' "$symbols" | grep -qE "[Tt] _?${sym}\$"; then
                echo "MISSING: $sym" >&2
                missing=1
        fi
done

[ "$missing" -eq 0 ] || exit 1
echo "M0 symbol-presence test: all symbols present"
