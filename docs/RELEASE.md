# Making a release

A pico-init release is a version in meson.build, a matching section at the
top of NEWS, an annotated git tag on the commit that carries both, and a
GitHub release whose body is that NEWS section. The tag is made only from a
commit whose CI run is green. This document lists the steps and the format
of each artifact.

## Version

The version is the `version:` argument of `project()` in meson.build:

```meson
project(
  'pico-init', 'c',
  version: '0.2.0',
```

It is a plain dotted number without a `v` prefix. meson.build passes it to
the compiler as `PICO_INIT_VERSION`. PID 1 announces it on the console
together with the output of `git describe --always --dirty --tags`, which
`vcs_tag()` regenerates at build time (`PICO_INIT_VERSION_STRING` in
src/status.h):

```
<version> (<git describe>)
```

A build from the tagged commit therefore reports `<version> (v<version>)`.
A tree exported without a `.git` directory reports `unknown` as the git
half.

## NEWS

NEWS at the top level of the repository follows the layout of systemd's
NEWS. The newest release comes first. Each release has one block:

```
# CHANGES WITH 0.2.0:

        <introductory paragraph>

##        PID 1 and unit files:

        * First item. Continuation lines are indented by ten spaces.

        * Second item.

##        Contributions from:

        Koen Kooi
```

- The block starts with `# CHANGES WITH <version>:`, using the version from
  meson.build without the `v`.
- Text under a heading is indented by eight spaces. Items start with
  `* `, are separated by blank lines and wrap at about 78 columns.
- Sections are titled with `##` followed by eight spaces. The 0.2.0 block
  uses PID 1 and unit files, cgroups, picoctl, netd, logd, devd,
  libsystemd and libudev compatibility, Build and tests, and Miscellaneous.
- The last section is `Contributions from:`, a list of names.
- NEWS describes what the release does, not the sequence of commits that
  led to it.

NEWS is covered by REUSE.toml, so a release commit must keep `reuse lint`
clean (see the CI section below).

## Tag

The tag is annotated, named `v<version>`, and its message is
`pico-init v<version>`:

```
$ git cat-file -p v0.2.0 | tail -2

pico-init v0.2.0
```

The tag object does not carry a PGP signature. It points at a commit whose
meson.build has `version: '0.2.0'` and whose NEWS starts with
`# CHANGES WITH 0.2.0:`, so the version bump and the NEWS section are
already committed when the tag is made:

```sh
git tag -a v0.3.0 -m 'pico-init v0.3.0'
git push origin v0.3.0
```

## GitHub release

The GitHub release is named after the tag, `pico-init v<version>`, and
its body is the NEWS block for that version. The project URL is
https://github.com/Angstrom-distribution/pico-init, which is also the
`origin` remote and the `PROJECT_URL` set in meson.build.

## CI

The workflow .github/workflows/ci.yml runs on pushes to `main` and on pull
requests. It has three jobs, all of which must pass on the commit that is
tagged:

- `build`: `meson setup build`, `ninja -C build`, then
  `sudo -E meson test -C build --print-errorlogs`.
- `format`: `clang-format-18 --dry-run --Werror` over every `.c` and `.h`
  file in `src`.
- `reuse`: `fsfe/reuse-action@v5`, the SPDX/REUSE license compliance check.

The tests run as root; the workflow comment gives the reason as real cgroups
and veth pairs, and that unprivileged they fail rather than skip. clang-format
is pinned to version 18 so a runner image update cannot change the
formatting rules.

`werror=true` and `warning_level=3` are project defaults in meson.build,
so a warning breaks the `build` job.

To check the same things before tagging:

```sh
meson setup build && ninja -C build
sudo -E meson test -C build --print-errorlogs
find src -name '*.c' -o -name '*.h' | \
    xargs -r clang-format-18 --dry-run --Werror
reuse lint
```

## Checklist

1. Set `version:` in meson.build.
2. Add the `# CHANGES WITH <version>:` block at the top of NEWS.
3. Commit both, push, and wait for the CI run on that commit to be green.
4. Create and push the annotated tag `v<version>` on that commit.
5. Create the GitHub release `pico-init v<version>` from the tag, with the
   NEWS block as the body.
6. Update the OpenEmbedded recipe, see below.

After the tag, `git describe` on later commits reports
`v<version>-<n>-g<hash>`, which is what PID 1 announces for untagged
builds.

## OpenEmbedded recipe

The OpenEmbedded recipe is not part of this repository, so its layout is
not described here. A recipe consuming a release needs the new version,
or the tagged commit, as its source revision. The build has no
dependencies beyond the C library and uses meson 0.62 or newer, which is
what the recipe has to provide (see [DISTRO_PORTING.md](DISTRO_PORTING.md)).
Build a target image with the new revision before announcing the release.
