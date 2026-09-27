#!/bin/sh
# SPDX-FileCopyrightText: 2026 Koen Kooi
# SPDX-License-Identifier: GPL-2.0-or-later
#
# pico-unit-lint against a fixture tree: the two worked examples from the
# design (an iiotool-shaped sandboxed service, a volatile-binds-shaped
# template), a clean unit, a unit whose only condition is a now-honoured
# negation (E2.5), and a Type= the parser refuses. Every expected line is
# asserted verbatim, and so are the three exit statuses.
set -eu

lint="$1"

tree=$(mktemp -d)
trap 'rm -rf "$tree"' EXIT
mkdir "$tree/system"

cat > "$tree/system/iiotool.service" <<'UNIT'
[Unit]
Description=IIO tool
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/iiotool
DynamicUser=yes
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_NETLINK
RestrictNamespaces=yes
SystemCallFilter=@system-service
MemoryHigh=48M
MemoryMax=64M
TasksMax=32

[Install]
WantedBy=multi-user.target
UNIT

cat > "$tree/system/volatile-binds@.service" <<'UNIT'
[Unit]
Description=Bind mount volatile %i
DefaultDependencies=no
RequiresMountsFor=/var/volatile
ConditionPathIsReadWrite=!/var/lib
ConditionPathIsReadWrite=/var/volatile

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=/sbin/mount-copybind /var/volatile/lib /var/lib
ExecStop=/bin/umount /var/lib

[Install]
WantedBy=local-fs.target
UNIT

cat > "$tree/system/clean.service" <<'UNIT'
[Unit]
Description=Nothing dropped
After=iiotool.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/bin/true
ExecStart=/bin/true
Restart=no

[Install]
WantedBy=multi-user.target
UNIT

cat > "$tree/system/cond.service" <<'UNIT'
[Unit]
Description=Negated condition, honoured (E2.5), not degraded
ConditionPathExists=!/etc/skip-cond

[Service]
ExecStart=/bin/true
UNIT

cat > "$tree/system/forking.service" <<'UNIT'
[Unit]
Description=Implemented type, honoured in full

[Service]
Type=forking
PIDFile=/run/forking.pid
GuessMainPID=no
ExecStart=/usr/sbin/forkingd
UNIT

cat > "$tree/system/refused.service" <<'UNIT'
[Unit]
Description=Refused type

[Service]
Type=daemon
ExecStart=/usr/sbin/refusedd
UNIT

out=$("$lint" "$tree/system" 2>/dev/null) && rc=0 || rc=$?

echo "$out"

expect() {
        if ! printf '%s\n' "$out" | grep -qxF "$1"; then
                echo "MISSING: $1" >&2
                exit 1
        fi
}

expect "iiotool.service: 14 dropped: DynamicUser NoNewPrivileges PrivateTmp PrivateDevices ProtectSystem ProtectHome ProtectKernelTunables ProtectControlGroups RestrictAddressFamilies RestrictNamespaces SystemCallFilter MemoryHigh MemoryMax TasksMax"
expect "volatile-binds@.service: 3 dropped: DefaultDependencies RequiresMountsFor ConditionPathIsReadWrite"
expect "refused.service: FAILED TO LOAD"
expect "pico-unit-lint: 6 units in tree, 2 degraded (17 directives dropped), 1 failed to load"

# network.target and multi-user.target were referenced, never in the tree,
# and must not be reported as anything.
if printf '%s\n' "$out" | grep -q "network.target\|multi-user.target\|local-fs.target"; then
        echo "referenced-only units leaked into the report" >&2
        exit 1
fi

# cond.service's negated ConditionPathExists= is honoured (E2.5), not
# degraded, so it reports the same as any other clean unit: nothing without
# --verbose.
if printf '%s\n' "$out" | grep -q "^clean.service\|^forking.service\|^cond.service"; then
        echo "clean unit reported without --verbose" >&2
        exit 1
fi

[ "$rc" -eq 1 ] || { echo "expected exit 1 with findings, got $rc" >&2; exit 1; }

"$lint" --warn-only "$tree/system" >/dev/null 2>&1 || { echo "--warn-only must exit 0" >&2; exit 1; }

"$lint" --verbose "$tree/system" 2>/dev/null | grep -qxF "clean.service: ok" || {
        echo "--verbose did not list the clean unit" >&2
        exit 1
}
"$lint" --verbose "$tree/system" 2>/dev/null | grep -qxF "forking.service: ok" || {
        echo "--verbose did not list the forking unit as clean" >&2
        exit 1
}

if "$lint" "$tree/does-not-exist" >/dev/null 2>&1; then
        echo "missing directory must fail" >&2
        exit 1
else
        [ $? -eq 2 ] || { echo "missing directory must exit 2" >&2; exit 1; }
fi

# a tree with nothing to report exits 0 and says so
mkdir "$tree/clean"
cp "$tree/system/clean.service" "$tree/clean/"
cout=$("$lint" "$tree/clean" 2>/dev/null) || { echo "clean tree must exit 0" >&2; exit 1; }
[ "$cout" = "pico-unit-lint: 1 units in tree, 0 degraded (0 directives dropped), 0 failed to load" ] || {
        echo "unexpected clean summary: $cout" >&2
        exit 1
}

echo "test-unit-lint: all cases passed"
