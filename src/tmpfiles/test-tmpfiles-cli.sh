#!/bin/sh
# SPDX-FileCopyrightText: 2026 Koen Kooi
# SPDX-License-Identifier: GPL-2.0-or-later
#
# pico-tmpfiles' command line against a fixture --root: --cat-config, --tldr,
# --inline, --replace, the accepted --no-pager, and the refusals, which must
# fail without touching anything.
set -eu

tf="$1"

root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
lib="$root/usr/lib/tmpfiles.d"
etc="$root/etc/tmpfiles.d"
mkdir -p "$lib" "$etc" "$root/out"

printf '# first\nd /out/a 0755 - - -\n\nd /out/a2 0755 - - -\n' > "$lib/a.conf"
printf 'd /out/b-lib 0755 - - -\n' > "$lib/b.conf"
printf 'd /out/c-lib 0755 - - -\n' > "$lib/c.conf"

fail() {
        echo "FAIL: $*" >&2
        exit 1
}

# a ';' comment is only cat's business: the line reader does not take it
cat_root="$root/cat"
mkdir -p "$cat_root/usr/lib/tmpfiles.d"
printf '# first\nd /out/a 0755 - - -\n\n; note\nd /out/a2 0755 - - -\n' > "$cat_root/usr/lib/tmpfiles.d/a.conf"
printf 'd /out/b-lib 0755 - - -\n' > "$cat_root/usr/lib/tmpfiles.d/b.conf"
lib="$cat_root/usr/lib/tmpfiles.d"

# --cat-config: header, verbatim body, blank line between files
out=$("$tf" --root="$cat_root" --cat-config)
exp="# $lib/a.conf
# first
d /out/a 0755 - - -

; note
d /out/a2 0755 - - -

# $lib/b.conf
d /out/b-lib 0755 - - -"
[ "$out" = "$exp" ] || fail "--cat-config output: $out"

# --tldr drops comments and empty lines
out=$("$tf" --root="$cat_root" --tldr)
exp="# $lib/a.conf
d /out/a 0755 - - -
d /out/a2 0755 - - -

# $lib/b.conf
d /out/b-lib 0755 - - -"
[ "$out" = "$exp" ] || fail "--tldr output: $out"

lib="$root/usr/lib/tmpfiles.d"
"$tf" --root="$root" --cat-config --inline x 2>/dev/null && fail "--cat-config --inline must fail"
"$tf" --root="$root" --tldr --replace=/etc/tmpfiles.d/x.conf x 2>/dev/null && fail "--tldr --replace must fail"

# --inline: arguments are lines, the files on disk are not read
"$tf" --root="$root" --create --no-pager --inline 'd /out/i1 0755 - - -' '  d /out/i2 0755 - - -'
[ -d "$root/out/i1" ] && [ -d "$root/out/i2" ] || fail "--inline did not create"
[ ! -d "$root/out/a" ] || fail "--inline read the configuration directories"

# an invalid inline line exits EX_DATAERR
rc=0
"$tf" --root="$root" --create --inline 'Q' 2>/dev/null || rc=$?
[ "$rc" -eq 65 ] || fail "invalid inline line exited $rc, wanted 65"

# --replace: the argument stands in for b.conf, everything else still applies
"$tf" --root="$root" --create --replace=/usr/lib/tmpfiles.d/b.conf --inline 'd /out/b-new 0755 - - -'
[ -d "$root/out/b-new" ] || fail "--replace did not apply the argument"
[ -d "$root/out/a" ] && [ -d "$root/out/c-lib" ] || fail "--replace skipped the other files"
[ ! -d "$root/out/b-lib" ] || fail "--replace applied the file it replaces"

# a same-named file in a directory searched earlier still wins
printf 'd /out/b-etc 0755 - - -\n' > "$etc/b.conf"
"$tf" --root="$root" --create --replace=/usr/lib/tmpfiles.d/b.conf --inline 'd /out/b-new2 0755 - - -'
[ -d "$root/out/b-etc" ] || fail "earlier directory did not win"
[ ! -d "$root/out/b-new2" ] || fail "replacement beat an earlier directory"

# --replace as a file argument
printf 'd /out/from-file 0755 - - -\n' > "$root/extra.conf"
"$tf" --root="$root" --create --replace=/usr/lib/tmpfiles.d/z.conf "$root/extra.conf"
[ -d "$root/out/from-file" ] || fail "--replace with a file argument"

# --replace argument errors
for bad in --replace=relative.conf --replace=/etc/tmpfiles.d/x.txt; do
        "$tf" --root="$root" --create "$bad" x 2>/dev/null && fail "$bad must fail"
done
"$tf" --root="$root" --create --replace=/etc/tmpfiles.d/x.conf 2>/dev/null && fail "--replace without arguments must fail"
"$tf" --root="$root" --create --replace=/tmp/x.conf --inline 'd /out/x 0755 - - -' 2>/dev/null &&
        fail "--replace outside tmpfiles.d must fail"
[ ! -d "$root/out/x" ] || fail "--replace outside tmpfiles.d applied"

# refusals fail with 1 and do nothing
for opt in --purge --dry-run -n --user --image=/x --image-policy=y; do
        rc=0
        "$tf" --root="$root" --create --inline 'd /out/refused 0755 - - -' "$opt" 2>/dev/null || rc=$?
        [ "$rc" -eq 1 ] || fail "$opt exited $rc, wanted 1"
        [ ! -d "$root/out/refused" ] || fail "$opt was accepted"
done

# no operation at all
"$tf" --root="$root" 2>/dev/null && fail "no operation must fail"

"$tf" --help | grep -q -- '--cat-config' || fail "--help does not list --cat-config"

echo "test-tmpfiles-cli: all cases passed"
