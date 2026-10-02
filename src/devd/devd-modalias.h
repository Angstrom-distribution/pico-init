/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Kernel module autoloading from a device's own MODALIAS -- the one thing
 * real systemd-udevd does unconditionally for every device, independent of
 * any rule file. devd's rule engine (devd-match.c's ENV{} matching) can read
 * a MODALIAS a rule already matched on, but nothing made the module load in
 * the first place: devd_rules_react() is a no-op with zero rules loaded or
 * zero rules matched, and DEVD_COLDPLUG_BLOCK/DEVD_COLDPLUG_USB (devd.h) are
 * the only two subsystems the coldplug walk ever looks at.
 *
 * Confirmed missing live on h2200: resistive-adc-touch.ko and hamcop-adc.ko
 * both present under /lib/modules, neither loaded, `xinput list` showing no
 * touchscreen device at all and xinput-calibrator correctly reporting zero
 * calibratable devices -- not a calibration bug, a module that never loaded.
 * The HAMCOP ADC/touchscreen are devicetree platform devices, so their
 * kernel ADD uevent fires before devd's own socket is even open (same
 * ordering risk devd-uevent.h already documents for the block coldplug
 * walk) -- coldplug is the only path that ever sees them, not live hotplug.
 *
 * /sbin/modprobe is BusyBox's own applet (CONFIG_MODPROBE=y in oe-core's
 * default busybox defconfig; busybox is already on every pico image), so
 * this adds no new RDEPENDS. modprobe is idempotent for an already-loaded
 * or built-in symbol, so calling it redundantly costs a wasted fork and
 * nothing else -- this does not try to track what has already loaded.
 */

#pragma once

typedef struct Devd Devd;
typedef struct DevdUevent DevdUevent;

/*
 * Live hotplug: an ADD action carrying a MODALIAS property. No-op for any
 * other action, or a uevent with no MODALIAS. Fire-and-forget through the
 * same DevdRun child table RUN+= actions already use -- never blocks the
 * event loop.
 */
void devd_modalias_autoload_uevent(Devd *d, const DevdUevent *u);

/*
 * Coldplug: every device already present under every <sys_root>/bus/<bus>/
 * devices/ directory that carries a modalias sysfs attribute, which covers
 * platform devices
 * (the HAMCOP ADC/touchscreen included) as well as every other bus devd's
 * own block/USB-only coldplug walk never looked at. Called once from
 * devd_coldplug(), before the block/USB-specific walks: a module a rule or
 * the block core is about to depend on should already be requested by the
 * time either runs, even though neither currently depends on one.
 */
void devd_coldplug_modalias(Devd *d);
