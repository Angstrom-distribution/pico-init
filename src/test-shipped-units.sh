#!/bin/sh
# SPDX-FileCopyrightText: 2026 Koen Kooi
# SPDX-License-Identifier: GPL-2.0-or-later
#
# The units the build installs, linted as one tree the way an image would see
# them: every unit loads with nothing dropped or degraded, and default.target
# resolves to multi-user.target, which wants the other targets.
set -eu

lint="$1"
src="$2"

tree=$(mktemp -d)
trap 'rm -rf "$tree"' EXIT
mkdir "$tree/system"

cp "$src"/units/*.target "$src"/src/netd/netd.service "$src"/src/netd/network.target \
   "$src"/src/devd/devd.service "$src"/src/logd/logd.service "$src"/src/logd/logd.socket \
   "$src"/src/tmpfiles/pico-tmpfiles.service "$src"/src/modules-load/systemd-modules-load.service \
   "$tree/system/"
ln -s multi-user.target "$tree/system/default.target"

out=$("$lint" "$tree/system" 2>&1) && rc=0 || rc=$?
echo "$out"
[ "$rc" = 0 ] || { echo "pico-unit-lint exited $rc"; exit 1; }
echo "$out" | grep -q ', 0 failed to load$' || { echo "a shipped unit failed to load"; exit 1; }

# The modules-load unit's triggering conditions are parsed, not dropped, and
# name the five directories and the four spellings systemd's unit does.
mod="$src/src/modules-load/systemd-modules-load.service"
for d in /lib /usr/lib /usr/local/lib /etc /run; do
	grep -qxF "ConditionDirectoryNotEmpty=|$d/modules-load.d" "$mod" || { echo "modules-load: no condition for $d"; exit 1; }
done
for w in modules-load modules_load rd.modules-load rd.modules_load; do
	grep -qxF "ConditionKernelCommandLine=|$w" "$mod" || { echo "modules-load: no condition for $w"; exit 1; }
done

for t in sockets.target sysinit.target bluetooth.target; do
	grep -q "^Wants=$t$" "$src/units/multi-user.target" || { echo "multi-user.target does not want $t"; exit 1; }
done
echo "test-shipped-units: OK"
