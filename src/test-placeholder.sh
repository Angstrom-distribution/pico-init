#!/bin/sh
# SPDX-FileCopyrightText: 2026 Koen Kooi
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Placeholder test so `meson test` has something real to run from the first
# commit. Replace with real tests as soon as there is real behavior to test.
set -eu
"$1" | grep -q "pico-init"
