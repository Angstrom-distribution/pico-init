#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Koen Kooi
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check a generated pkg-config file against real systemd's template.

A recipe that does `pkg-config --variable=systemdsystemunitdir systemd`
gets an empty string, not an error, when the variable is missing, so a
drifted systemd.pc breaks consumers silently. This pins the generated
file to the vendored upstream template: the same variables in the same
order, the same keyword lines (Name:, Version:, ...), byte-identical
values wherever upstream's value carries no {{placeholder}}, an identical
Name:, and no unexpanded placeholder left in the output.
"""

import argparse
import re
import sys

VAR_RE = re.compile(r"^(\w+)=(.*)$")
KEYWORD_RE = re.compile(r"^([A-Z][\w.]*):\s*(.*)$")


def parse(path):
    variables = []
    keywords = []
    for line in open(path):
        line = line.rstrip("\n")
        if not line or line.startswith("#"):
            continue
        m = VAR_RE.match(line)
        if m:
            variables.append((m.group(1), m.group(2)))
            continue
        m = KEYWORD_RE.match(line)
        if m:
            keywords.append((m.group(1), m.group(2)))
            continue
        print(f"{path}: unparsed line: {line!r}", file=sys.stderr)
        sys.exit(1)
    return variables, keywords


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--upstream", required=True, help="real systemd's .pc.in at the pinned tag")
    ap.add_argument("--generated", required=True, help="the .pc this build produced")
    args = ap.parse_args()

    up_vars, up_kw = parse(args.upstream)
    gen_vars, gen_kw = parse(args.generated)
    errors = []

    up_names = [n for n, _ in up_vars]
    gen_names = [n for n, _ in gen_vars]
    if up_names != gen_names:
        errors.append(f"variable list differs:\n  upstream:  {up_names}\n  generated: {gen_names}")

    up_values = dict(up_vars)
    for name, value in gen_vars:
        expected = up_values.get(name)
        if expected is not None and "{{" not in expected and value != expected:
            errors.append(f"{name}: {value!r} != upstream {expected!r}")
        if "@" in value or "{{" in value:
            errors.append(f"{name}: unexpanded placeholder in {value!r}")

    if [k for k, _ in up_kw] != [k for k, _ in gen_kw]:
        errors.append(f"keyword lines differ: upstream {[k for k, _ in up_kw]}, generated {[k for k, _ in gen_kw]}")
    for (name, expected), (_, value) in zip(up_kw, gen_kw):
        if name == "Name" and value != expected:
            errors.append(f"Name: {value!r} != upstream {expected!r}")
        if "@" in value or "{{" in value:
            errors.append(f"{name}: unexpanded placeholder in {value!r}")

    for e in errors:
        print(f"check-pc: {args.generated}: {e}", file=sys.stderr)
    if errors:
        sys.exit(1)
    print(f"check-pc: {args.generated}: {len(gen_vars)} variables, {len(gen_kw)} keywords match {args.upstream}")


if __name__ == "__main__":
    main()
