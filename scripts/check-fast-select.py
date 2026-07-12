#!/usr/bin/env python3
"""#263 Tier-0 blast-radius crate selector.

Reads `cargo metadata --format-version 1` JSON (stdin or --metadata FILE) and a
list of changed repo-relative file paths (args, forward-slash). Emits the minimal
set of workspace packages whose tests cover the change's blast radius = the
directly-touched packages UNION every workspace package that (transitively)
depends on them. Fails closed; never certifies vacuously.

Exit codes / contract (fail-closed, {code,message,remediation}):
  0  -> selection printed to stdout as `-p A -p B ...` (+ human summary on stderr)
  3  -> ASTRO_FASTGATE_NO_CHANGES: no changed files given
  4  -> ASTRO_FASTGATE_UNMAPPED: a changed file maps to no workspace package and
        is not foundational -> ambiguous, Tier-0 cannot certify it
  10 -> ASTRO_FASTGATE_ESCALATE: a changed path is foundational surface -> the
        full native aggregate (Tier 2) is required; Tier-0 must not certify alone
"""
import json
import sys
from pathlib import PurePosixPath

# Foundational surface (CLAUDE.md "Fast feedback loops"): a change touching any of
# these forces Tier 2. Prefixes are repo-relative, forward-slash. Declared knob.
FOUNDATIONAL_PREFIXES = (
    "crates/astrolabe-domain/",     # identity spine
    "crates/cbm-sys/",              # FFI boundary
    "crates/astrolabe-bridge/",     # FFI boundary / libcbm
    "scripts/",                     # gate scripts
    "vendor/codebase-memory-mcp/",  # the C half
    "patches/cbm/",                 # C overlays
    "vendor/calyx/",                # pinned cross-cutting parent
    "Cargo.toml", "Cargo.lock",     # workspace-wide manifests (root)
    ".cargo/", ".config/nextest.toml", "rust-toolchain.toml",  # build/test config
)


def fail(code_str, exit_code, message, remediation):
    print(f"ERROR[{code_str}]: {message}", file=sys.stderr)
    print(f"  remediation: {remediation}", file=sys.stderr)
    sys.exit(exit_code)


def load_metadata(path):
    raw = open(path, encoding="utf-8").read() if path else sys.stdin.read()
    return json.loads(raw)


def workspace_member_dirs(md):
    """Map each workspace-member package dir (repo-relative posix) -> package name."""
    root = PurePosixPath(md["workspace_root"].replace("\\", "/"))
    members = set(md.get("workspace_members", []))
    dirs = {}
    names = set()
    for pkg in md["packages"]:
        if pkg["id"] not in members:
            continue
        names.add(pkg["name"])
        manifest = PurePosixPath(pkg["manifest_path"].replace("\\", "/"))
        try:
            rel = manifest.parent.relative_to(root)
        except ValueError:
            rel = manifest.parent  # out-of-root member (path dep) -> keep absolute-ish
        dirs[str(rel).rstrip("/") + "/"] = pkg["name"]
    return dirs, names


def reverse_dep_closure(md, seed_names, member_names):
    """All workspace packages that transitively depend on any seed (seed included)."""
    # edge dep_name -> {packages that directly depend on dep_name}
    dependents = {n: set() for n in member_names}
    members = set(md.get("workspace_members", []))
    for pkg in md["packages"]:
        if pkg["id"] not in members:
            continue
        for dep in pkg.get("dependencies", []):
            if dep["name"] in member_names:
                dependents[dep["name"]].add(pkg["name"])
    closure, stack = set(seed_names), list(seed_names)
    while stack:
        cur = stack.pop()
        for parent in dependents.get(cur, ()):  # parent depends on cur
            if parent not in closure:
                closure.add(parent)
                stack.append(parent)
    return closure


def main(argv):
    metadata_path = None
    changed = []
    it = iter(argv)
    for a in it:
        if a == "--metadata":
            metadata_path = next(it)
        else:
            changed.append(a.replace("\\", "/").lstrip("./"))

    if not changed:
        fail("ASTRO_FASTGATE_NO_CHANGES", 3,
             "no changed files were provided; Tier-0 has nothing to verify and will not pass vacuously",
             "pass the changed file list (git diff --name-only <base>), or run the full aggregate")

    foundational = [c for c in changed if any(c == p or c.startswith(p) for p in FOUNDATIONAL_PREFIXES)]
    if foundational:
        fail("ASTRO_FASTGATE_ESCALATE", 10,
             "change touches foundational surface: " + ", ".join(sorted(foundational)[:8]),
             "run the full native aggregate (Tier 2); Tier-0 cannot certify a foundational change alone")

    md = load_metadata(metadata_path)
    dirs, member_names = workspace_member_dirs(md)

    matched, unmapped = set(), []
    for c in changed:
        # longest-prefix package dir wins
        best = None
        for d, name in dirs.items():
            if c.startswith(d) and (best is None or len(d) > len(best[0])):
                best = (d, name)
        if best:
            matched.add(best[1])
        else:
            unmapped.append(c)

    if unmapped:
        fail("ASTRO_FASTGATE_UNMAPPED", 4,
             "changed file(s) map to no workspace package and are not foundational: " + ", ".join(unmapped[:8]),
             "if non-code (docs), verify manually and choose the tier; otherwise fix the path mapping")

    selected = sorted(reverse_dep_closure(md, matched, member_names))
    print(f"blast radius: touched={sorted(matched)} -> selected(+reverse-deps)={selected}", file=sys.stderr)
    print(" ".join(f"-p {name}" for name in selected))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
