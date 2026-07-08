# Branch Protection

`main` must require the single stable `ci-ok` status check from
`.github/workflows/ci.yml`. `ci-ok` depends on every matrix leg and fails unless
all of these required jobs succeeded:

- `pins / subtree state`
- `cbm lint / clang-tidy cppcheck format`
- `cbm tests / linux-x64-gcc`
- `cbm tests / linux-x64-clang`
- `cbm tests / macos-arm64-clang`
- `cbm tests / windows-x64-mingw`
- `rust / linux-x64`
- `rust / macos-arm64`
- `rust / windows-x64-gnu`

Required branch-protection policy:

- Require pull request before merging.
- Require branches to be up to date before merging.
- Require status checks to pass before merging.
- Required check: `ci-ok`.
- Do not allow bypasses except repository administrators performing emergency
  recovery with a follow-up issue.
