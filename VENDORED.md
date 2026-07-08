# Vendored Parent Systems

Astrolabe vendors its two parent systems as Git subtrees, not submodules. The
current import was provided as local source directories and is pinned by the
exact Git tree bytes recorded below. The tree SHA is the binding pin for this
repository state.

| System | Path | Source | Binding tree SHA |
|---|---|---|---|
| Calyx | `vendor/calyx` | local import from `./Calyx` | `004140a9d37221e54a19747bbc9f883657109c48` |
| codebase-memory-mcp | `vendor/codebase-memory-mcp` | local import from `./codebasememorymcp` | `cb56032bd1d439e9d1e7863305f7171c0473059c` |

## Update Procedure

1. Update a parent with `git subtree pull --prefix <path> <remote> <ref>
   --squash`, or replace the path with a user-provided parent tree when that
   local tree is the intended source of truth.
2. Stage the updated vendor tree with `git add vendor/<name>`.
3. Read the staged tree SHA:
   `git rev-parse "$(git write-tree):vendor/<name>"`.
4. Update the table above with the new binding tree SHA and source note.
5. Run `bash scripts/verify-pins.sh`.

Submodules are forbidden for these parents. `scripts/verify-pins.sh` fails if a
`.gitmodules` file or a vendor gitlink appears.
