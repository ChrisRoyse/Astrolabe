/* rust_cargo.h — Cargo.toml parser for the Rust LSP.
 *
 * Per RUST_LSP_FOLLOWUP §A3: we don't run Cargo or build, but we CAN
 * parse `Cargo.toml` and `[workspace] members` to learn:
 *   - the crate name (`[package].name`)
 *   - declared dependencies (`[dependencies]` + `[dev-dependencies]`)
 *   - workspace members + their relative paths
 *
 * The pipeline uses this to map `other_member::foo` → that member's
 * module QN, and to mark calls into known external deps as "external,
 * not local" rather than fully unresolved.
 *
 * The parser is a tiny hand-written TOML subset: handles `[section]`
 * headers, `key = "value"`, `key = { path = "...", … }` (the relevant
 * subset for our needs), arrays `members = ["a", "b"]`. It IGNORES
 * everything it doesn't understand — that's safe because Cargo.toml
 * is much richer than what we use. */

#ifndef CBM_LSP_RUST_CARGO_H
#define CBM_LSP_RUST_CARGO_H

#include "../arena.h"
#include <stdbool.h>

#define CBM_CARGO_MAX_DEPS 256
#define CBM_CARGO_MAX_MEMBERS 64
#define CBM_CARGO_MAX_TARGETS 256

typedef struct {
    const char *name; /* declared dependency name */
    const char *path; /* path = "../foo" if local, else NULL */
} CBMCargoDep;

typedef struct {
    const char *member_name; /* directory name */
    const char *member_path; /* relative path inside workspace root */
    const char *edition;     /* exact effective member edition, or NULL */
} CBMCargoMember;

typedef enum {
    CBM_CARGO_TARGET_LIB = 0,
    CBM_CARGO_TARGET_BIN,
    CBM_CARGO_TARGET_EXAMPLE,
    CBM_CARGO_TARGET_TEST,
    CBM_CARGO_TARGET_BENCH,
} CBMCargoTargetKind;

typedef struct {
    CBMCargoTargetKind kind;
    const char *name;
    const char *path;
} CBMCargoTarget;

typedef struct {
    const char *package_dir; /* repository-relative directory containing Cargo.toml */
    const char *edition;     /* exact effective package edition */
} CBMCargoPackage;

typedef struct CBMCargoManifest {
    const char *package_name;              /* [package].name, NULL if missing */
    const char *package_version;           /* [package].version, NULL if missing */
    const char *package_edition;           /* [package].edition, NULL if inherited/absent */
    const char *workspace_package_edition; /* [workspace.package].edition */
    const char *active_edition;            /* edition selected for the file being analyzed */
    bool package_edition_inherits_workspace;
    bool is_workspace_root; /* [workspace] section seen */

    const char *package_workspace;
    const char *package_build_path;
    bool package_build_declared;
    bool package_build_enabled;
    bool autolib;
    bool autobins;
    bool autoexamples;
    bool autotests;
    bool autobenches;
    bool autolib_declared;
    bool autobins_declared;
    bool autoexamples_declared;
    bool autotests_declared;
    bool autobenches_declared;

    CBMCargoTarget targets[CBM_CARGO_MAX_TARGETS];
    int target_count;

    /* Repository-wide package/target context assembled once by the pipeline
     * from every discovered Cargo.toml. Arrays are arena-owned and sorted. */
    CBMCargoPackage *packages;
    int package_count;
    const char **crate_roots;
    int crate_root_count;

    CBMCargoDep deps[CBM_CARGO_MAX_DEPS];
    int dep_count;

    CBMCargoMember members[CBM_CARGO_MAX_MEMBERS];
    int member_count;
} CBMCargoManifest;

/* Parse a Cargo.toml-formatted string. The output strings are
 * arena-allocated (so the caller doesn't need to keep `src` alive). */
void cbm_cargo_parse(CBMArena *arena, const char *src, int src_len, CBMCargoManifest *out);

/* Convenience: does a given path-prefix look like one of the listed
 * dependency names? Used by the resolver to recognise external crate
 * paths. */
bool cbm_cargo_is_known_dep(const CBMCargoManifest *m, const char *head);

/* Find a workspace member by crate name. Returns NULL if absent. */
const CBMCargoMember *cbm_cargo_find_member(const CBMCargoManifest *m, const char *name);

/* Resolve the exact Cargo edition for a repository-relative source path.
 * Returns NULL when the path belongs to a workspace member whose edition
 * could not be read or inherited exactly. */
const char *cbm_cargo_edition_for_path(const CBMCargoManifest *m, const char *relative_path);

/* True only when relative_path is one of Cargo's exact crate source roots. */
bool cbm_cargo_is_crate_root(const CBMCargoManifest *m, const char *relative_path);

#endif /* CBM_LSP_RUST_CARGO_H */
