# Agent guide for pico-init

Pico-init is a small PID 1 for embedded Linux that reads systemd unit files, with its own netd, devd and logd and libsystemd and libudev compatibility libraries. Read the README for the scope, `CONTRIBUTING.md` for how changes are proposed, and `docs/HACKING.md` for the build, the tests and the source layout.

## Git

Commit locally. Never run `git push`, rewrite history or tag a release without the owner's permission. Stage exact paths, one logical change per commit.

- Changes go on a branch and reach `main` through a pull request, opened ready for review, never as a draft. Merging is the owner's decision.
- Decisions and evidence (test logs, measurements, why an option was chosen) go on the issue or the pull request.
- A change of scope (what is quarried from systemd and what is written fresh, which systemd behaviours are kept or dropped) is raised in an issue before the pull request.

## Commit messages

- Subject: `component: summary`, imperative, for example `netctl: show LLDP neighbours in status` or `meson: bump version to 0.3.2`.
- Body: a sentence or two of why, in plain prose. Leave it out when the subject says it.
- End with `Signed-off-by:` read from `git config user.name` and `user.email`, never made up. Add `Assisted-by: <tool>:<model>` when an AI assisted. Never a `Co-Authored-By:` or session trailer.
- Code and its documentation are separate commits in the same pull request, for example `service: run ExecReload= and add the reload job` followed by `docs: document ExecReload= and the reload verbs`.

## Public text

READMEs, documents, NEWS, comments and commit messages are read by experienced developers who know nothing of how the work was done.

- Keep them short and factual. No marketing and no filler such as "honest", "load-bearing", "robust", "carefully", "comprehensive", "seamless" or "deliberately".
- State what is decided. Mark a plan as a plan.
- Use generic wording for the hardware: boards with 200 MHz-class CPUs and about 64 MiB of RAM. Name a device only as an example or as a tested device.
- A tool name that starts a sentence takes a capital, like any other word: "Pico-init reads ...". Inline code stays as typed.
- Notes about how an image was made go in an HTML comment, not in visible text.
- Do not refer to files, repositories or sessions the reader cannot open, or to history ("was X, now Y").
- Never write "Yocto" for the build system or ecosystem: say OpenEmbedded or bitbake. Never use Poky.

## Code

- C is `gnu17`, formatted by `.clang-format` with clang-format 18. The rules beyond formatting, the PID 1 rules (never block, no unbounded recursion, no `assert()` or `abort()` on input, no `malloc` between `fork()` and `execve()`) and the quarried, lifted and reimplemented tiers are in `docs/CODING_STYLE.md`.
- Format only the files you touched; a reformat of unrelated files does not go into a functional change.
- Lifted code under `src/netd/dhcp/`, `src/netd/netd-sntp.c` and `src/netd/netd-time.c` stays close to upstream; what it needs goes into `src/netd/netd-compat.h`.
- Every new file carries the two SPDX lines, or an entry in `REUSE.toml`. Verbatim upstream files are covered there and never edited. Do not remove an existing copyright or license line. Check with `reuse lint`.
- Comments say why, never what the next line does. No `//` comments, no `TODO` or `FIXME`.

## Build and test

```sh
meson setup build
ninja -C build
sudo -E meson test -C build --print-errorlogs
find src -name '*.c' -o -name '*.h' | xargs -r clang-format-18 --dry-run --Werror
reuse lint
```

- These are the three CI jobs in `.github/workflows/ci.yml` (`build`, `format`, `reuse`); all must pass before a merge. `werror=true` is a project default, so a new warning breaks the build.
- List new sources and tests in `meson.build` (`pico_tests`, `netd_tests`, `devd_tests`, `logd_tests`, `tmpfiles_tests`); nothing is globbed. `docs/HACKING.md` says how to add a test with `src/test-util.h`.
- Run one test with `meson test -C build <name> --print-errorlogs`, as a normal user and as root. A test that exits with 77 is a skip, not a pass: report it as one with its reason. The netd namespace tests exit 1, not 77, when the host refuses user namespaces.
- Tests build against fixtures in a temporary tree, never against the host's real configuration.
- After a change to the symbols the compatibility libraries export, run `ninja -C build regen-libsystemd-sym regen-libudev-sym` and commit the regenerated version scripts.
- Say whether a result came from the host or from a booted device.
- Documentation in `docs/` is updated in the same pull request as the behaviour it describes, and states current facts. A change to unit-file behaviour updates `docs/INCOMPATIBILITIES.md`.

## Releases

Releases are made from `main` as described in `docs/RELEASE.md`: the version in `meson.build` and a `# CHANGES WITH <version>:` block at the top of NEWS, committed and green in CI, then an annotated tag `v<version>` on that commit and a GitHub release `pico-init v<version>` whose body is the NEWS block. NEWS describes what the release does, not the sequence of commits.

A pull request, NEWS and the GitHub release show a changed behaviour with a before and after capture, for example boot console, `picoctl` or `netctl` output, annotated when the difference is subtle. A change that cannot be shown in a capture says so. Say whether a capture comes from qemu or a device.
