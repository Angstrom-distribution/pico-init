/* SPDX-FileCopyrightText: 2026 Koen Kooi */
/* SPDX-License-Identifier: GPL-2.0-or-later */

/*
 * Kernel module autoloading from a device's own MODALIAS, which systemd-udevd
 * does for every device independent of any rule file. devd's rule engine can
 * match a MODALIAS but nothing else loads the module: devd_rules_react() is a
 * no-op with zero rules loaded, and the coldplug walks (devd.h's
 * DEVD_COLDPLUG_*) only look at block, USB and input devices.
 *
 * Platform devices (devicetree-described ones, e.g. an ADC or touchscreen) get
 * their kernel ADD uevent before devd's socket is open, so coldplug is the only
 * path that ever sees them.
 *
 * /sbin/modprobe is BusyBox's applet (oe-core's default busybox defconfig). It
 * is idempotent for an already-loaded or built-in symbol, so a redundant call
 * costs a wasted fork and nothing else; devd does not track what has loaded.
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
 * devices/ directory that carries a modalias sysfs attribute: platform devices
 * and every other bus the block/USB coldplug walks do not cover. Called once
 * from devd_coldplug(), before those walks.
 */
void devd_coldplug_modalias(Devd *d);
