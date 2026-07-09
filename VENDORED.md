# Vendored Parent Systems

Astrolabe vendors its two parent systems as Git subtrees, not submodules. The
current import was provided as local source directories and is pinned by the
exact Git tree bytes recorded below. The tree SHA is the binding pin for this
repository state.

| System | Path | Source | Binding tree SHA |
|---|---|---|---|
| Calyx | `vendor/calyx` | local import from `./Calyx` | `6e0e3444e9543b8de03ba943e0d376947f533530` |
| codebase-memory-mcp | `vendor/codebase-memory-mcp` | local import from `./codebasememorymcp` | `49358971c30820dac674b8e036877e3b6c0ff172` |

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
