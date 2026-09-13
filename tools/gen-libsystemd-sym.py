#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Koen Kooi
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate libsystemd-compat's linker version script from real systemd's.

The ABI contract is "a binary built against real libsystemd links and runs
against ours", and a versioned symbol request (sd_bus_message_append@
LIBSYSTEMD_209) can only be answered by a library whose version script
assigns that symbol that exact node. So the nodes are not designed here:
they are copied from the pinned upstream libsystemd.sym, intersected with
what libsystemd-compat actually defines.

Inputs:
  --upstream  real systemd's src/libsystemd/libsystemd.sym at the pinned tag
  --archive   the built libsystemd-compat static archive (read with --nm)
  --header    every installed public sd-*.h (repeatable)

Rules:
  * a defined sd_* symbol declared in a public header and present upstream
    gets its upstream node, in upstream's order;
  * a defined sd_* symbol declared in a public header but absent upstream
    (the sd_network_* family, which upstream ships in libsystemd-shared)
    goes into one trailing PICO_LIBSYSTEMD_0 node, which no LIBSYSTEMD_*
    name present or future can collide with;
  * everything else is local.

Two conditions are errors, not warnings: a public header declaring a
function the archive does not define (a promise the library cannot keep),
and the archive defining an sd_* symbol no public header declares (an
internal helper wearing a public name). Both must be fixed in the source,
never papered over here.

Regenerate with `ninja -C build regen-libsystemd-sym`; the test
test-libsystemd-sym fails whenever the committed file is stale.
"""

import argparse
import difflib
import re
import subprocess
import sys

PICO_NODE = "PICO_LIBSYSTEMD_0"


def die(msg):
    print(f"gen-libsystemd-sym: error: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_upstream(path):
    """-> ([(node, parent, [symbols...])...] in file order)."""
    text = re.sub(r"/\*.*?\*/", "", open(path).read(), flags=re.S)
    nodes = []
    cur = None
    for line in text.splitlines():
        line = line.strip()
        if not line or line in ("global:", "local:", "*;"):
            continue
        m = re.fullmatch(r"(\w+)\s*\{", line)
        if m:
            if cur:
                die(f"{path}: nested node {m.group(1)}")
            cur = [m.group(1), None, []]
            continue
        m = re.fullmatch(r"\}\s*(\w+)?\s*;", line)
        if m:
            if not cur:
                die(f"{path}: stray node end")
            cur[1] = m.group(1)
            nodes.append(tuple(cur))
            cur = None
            continue
        m = re.fullmatch(r"(\w+)\s*;", line)
        if m and cur:
            cur[2].append(m.group(1))
            continue
        die(f"{path}: unparsed line: {line!r}")
    if cur:
        die(f"{path}: unterminated node {cur[0]}")
    if not nodes:
        die(f"{path}: no version nodes found")
    return nodes


def parse_header_prototypes(path):
    """Names of the non-inline functions a header declares.

    Comments, preprocessor lines (macros included) and every brace-delimited
    body (inline functions, structs, enums) are stripped first, so what is
    left is a sequence of ';'-terminated declarations. Typedefs and
    anything marked static/inline are skipped; the rest are prototypes.
    """
    text = open(path).read()
    text = re.sub(r"\\\n", " ", text)
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    # The extern "C" wrapper lives inside #ifdef __cplusplus blocks; dropping
    # those whole keeps its braces from swallowing the header body below.
    kept, skipping = [], False
    for l in text.splitlines():
        d = l.lstrip()
        if d.startswith("#ifdef __cplusplus"):
            skipping = True
        elif skipping and d.startswith("#endif"):
            skipping = False
        elif not skipping and not d.startswith("#"):
            kept.append(l)
    text = "\n".join(kept)
    out, depth = [], 0
    for ch in text:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth < 0:
                die(f"{path}: unbalanced braces")
            if depth == 0:
                out.append(";")  # an inline function body ends a statement too
        elif depth == 0:
            out.append(ch)
    names = set()
    for decl in "".join(out).split(";"):
        toks = decl.split()
        if not toks or "typedef" in toks or "static" in toks:
            continue
        if any(t in ("inline", "__inline__", "_sd_inline_") for t in toks):
            continue
        m = re.search(r"\b(sd_\w+)\s*\(", decl)
        if m:
            names.add(m.group(1))
        elif toks[0] == "extern":
            m = re.search(r"\b(sd_\w+)\s*(\[[^\]]*\])?\s*$", decl)
            if m:
                names.add(m.group(1))
    return names


def defined_symbols(nm, archive):
    r = subprocess.run([nm, "--defined-only", "-g", archive], capture_output=True, text=True)
    if r.returncode != 0:
        die(f"{nm} failed on {archive}: {r.stderr.strip()}")
    syms = set()
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "TDBRWV":
            syms.add(parts[2])
    if not syms:
        die(f"{archive}: nm reported no defined global symbols")
    return syms


def render(upstream_nodes, exported, upstream_name):
    in_upstream = {s for _, _, syms in upstream_nodes for s in syms}
    node_of = {}
    for node, _, syms in upstream_nodes:
        for s in syms:
            node_of.setdefault(s, node)
    # REUSE-IgnoreStart -- these tags describe the generated file, not this one
    lines = [
        "/* SPDX-FileCopyrightText: 2026 Koen Kooi */",
        "/* SPDX-License-Identifier: LGPL-2.1-or-later */",
        "",
        f"/* Generated by tools/gen-libsystemd-sym.py from {upstream_name}. Do not edit;",
        " * run `ninja -C build regen-libsystemd-sym` instead. */",
        "",
    ]
    # REUSE-IgnoreEnd
    first = True
    for node, parent, syms in upstream_nodes:
        ours = [s for s in syms if s in exported]
        lines.append(f"{node} {{")
        if ours:
            lines.append("global:")
            lines.extend(f"        {s};" for s in ours)
        if first:
            lines.append("local:")
            lines.append("        *;")
            first = False
        lines.append(f"}}{' ' + parent if parent else ''};")
        lines.append("")
    pico = sorted(s for s in exported if s not in in_upstream)
    last = upstream_nodes[-1][0]
    lines.append(f"{PICO_NODE} {{")
    if pico:
        lines.append("global:")
        lines.extend(f"        {s};" for s in pico)
    lines.append(f"}} {last};")
    return "\n".join(lines) + "\n", node_of, pico


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--upstream", required=True, help="real libsystemd.sym at the pinned tag")
    ap.add_argument("--archive", required=True, help="built libsystemd-compat static archive")
    ap.add_argument("--nm", default="nm")
    ap.add_argument("--header", action="append", default=[], help="installed public header (repeatable)")
    ap.add_argument("-o", "--output", help="write the version script here (default: stdout)")
    ap.add_argument("--check", metavar="FILE", help="exit 1 with a diff if FILE differs from the output")
    ap.add_argument("--summary", action="store_true", help="print per-node counts to stderr")
    args = ap.parse_args()

    upstream_nodes = parse_upstream(args.upstream)
    declared = set()
    for h in args.header:
        declared |= parse_header_prototypes(h)
    if not declared:
        die("no prototypes found in the given headers")
    defined = {s for s in defined_symbols(args.nm, args.archive) if s.startswith("sd_")}

    missing = sorted(declared - defined)
    if missing:
        die("public headers declare functions the archive does not define:\n  " + "\n  ".join(missing))
    leaked = sorted(defined - declared)
    if leaked:
        die("archive defines sd_* symbols no public header declares (rename them, see docstring):\n  " + "\n  ".join(leaked))

    text, node_of, pico = render(upstream_nodes, declared, args.upstream.rsplit("/", 1)[-1])

    if args.summary:
        counts = {}
        for s in declared:
            counts[node_of.get(s, PICO_NODE)] = counts.get(node_of.get(s, PICO_NODE), 0) + 1
        for node, _, _ in upstream_nodes:
            print(f"{node}: {counts.get(node, 0)}", file=sys.stderr)
        print(f"{PICO_NODE}: {len(pico)}", file=sys.stderr)
        print(f"total exported: {len(declared)} (upstream-node {len(declared) - len(pico)}, pico {len(pico)})", file=sys.stderr)

    if args.check:
        current = open(args.check).read()
        if current != text:
            sys.stdout.writelines(difflib.unified_diff(
                current.splitlines(True), text.splitlines(True),
                fromfile=args.check, tofile="generated"))
            die(f"{args.check} is stale; run `ninja -C build regen-libsystemd-sym`")
        print(f"{args.check}: up to date ({len(declared)} symbols)")
        return
    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
