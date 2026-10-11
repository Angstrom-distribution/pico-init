# Contributing to pico-init

## Reporting bugs / requesting features

Use [GitHub Issues](../../issues). There are templates for bug reports and
feature requests; pick whichever fits, or open a blank issue if neither does.

## Submitting changes

1. Fork or branch, and open a
   [pull request](../../pulls) against `main`. The PR template will prompt
   for what changed and why.
2. Every new or modified source file needs an
   [SPDX license identifier](https://spdx.dev/learn/handling-license-info/)
   on its first line — see [`LICENSES/`](LICENSES/).
   `reuse lint` runs in CI and will fail the build if one is missing.
3. Keep commits scoped to one logical change. Commit messages should explain
   *why*, not restate the diff.
4. CI (meson build, `clang-format --dry-run`, `reuse lint`) must pass before
   a PR is merged.

## Code style

- C, `gnu17`, formatted per [`.clang-format`](.clang-format) (based on
  systemd's own style, since a meaningful amount of this project's source is
  quarried from systemd — keeping the style close reduces diff noise when
  comparing against upstream).
- PID1 code specifically: no unbounded recursion, no unchecked allocation
  failures, prefer explicit error returns over anything that can bring the
  process down. If PID 1 crashes, the kernel panics — see
  [`SECURITY.md`](SECURITY.md).

## Design discussions

Anything that changes scope (what gets quarried vs. written fresh, which
systemd behaviors get kept or dropped) should be discussed in an issue
before a PR, not land silently in a diff.
