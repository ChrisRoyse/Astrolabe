# Configuration Reference

This page documents the configuration files that `codebase-memory-mcp` reads or writes today.

## At a Glance

| Purpose | Path | Format | Notes |
|---|---|---|---|
| Global custom extension mapping | `$XDG_CONFIG_HOME/codebase-memory-mcp/config.json` | JSON | Falls back to `~/.config/codebase-memory-mcp/config.json` when `XDG_CONFIG_HOME` is unset. |
| Per-project custom extension mapping | `{repo_root}/.codebase-memory.json` | JSON | Overrides conflicting global `extra_extensions` entries. |
| CLI-managed runtime settings | `${CBM_CACHE_DIR:-~/.cache/codebase-memory-mcp}/_config.db` | SQLite | Written by `codebase-memory-mcp config set/reset`. |
| UI settings | `${CBM_CACHE_DIR:-~/.cache/codebase-memory-mcp}/config.json` | JSON | Stores `ui_enabled` and `ui_port`. |

Project stores do not use `_config.db` as an alias registry. A query name is
bound only to the exact `${CBM_CACHE_DIR}/<project>.db` family. Before query
admission, a source-frozen derivative must prove the supported schema, the sole
internal project name, and an existing canonical `root_path`. The server never
scans the cache to adopt a differently named database as a fallback.

`list_projects` returns valid projects plus `store_refusals` and
`refused_store_count`. A legacy, corrupt, drifted, or source-less candidate is
therefore visible with its exact path/operation/remediation but cannot prevent
unrelated valid projects from being listed or queried.

Canonicalization is not permission to persist build scratch. Roots inside the
Astrolabe native launcher namespace `.tmp/windows-gnu-toolchain-*` are refused
before indexing starts and again at query admission, even if a caller supplies
a stable-looking alias. This prevents a currently-live launcher generation from
becoming durable registry authority and then drifting when exact-owner cleanup
removes it.

## 1. Custom File Extension Mapping

Two optional JSON files let you map additional file extensions to built-in languages.

### Global config

Default path:

```text
$XDG_CONFIG_HOME/codebase-memory-mcp/config.json
```

Fallback when `XDG_CONFIG_HOME` is unset:

```text
~/.config/codebase-memory-mcp/config.json
```

### Per-project config

Place this file in the repository root:

```text
.codebase-memory.json
```

### Format

```json
{
  "extra_extensions": {
    ".blade.php": "php",
    ".mjs": "javascript",
    ".twig": "html"
  }
}
```

Notes:

- Extension keys must include the leading dot.
- Language names are case-insensitive.
- Unknown language names are skipped.
- Missing files are ignored.
- If the same extension appears in both files, the per-project file wins.

## 2. CLI-Managed Runtime Settings

The `config` subcommand stores runtime settings in a small SQLite database:

```text
${CBM_CACHE_DIR:-~/.cache/codebase-memory-mcp}/_config.db
```

Inspect or change values with the CLI:

```bash
codebase-memory-mcp config list
codebase-memory-mcp config get auto_index
codebase-memory-mcp config set auto_index true
codebase-memory-mcp config set auto_index_limit 50000
codebase-memory-mcp config reset auto_index
```

Current keys:

| Key | Default | Meaning |
|---|---|---|
| `auto_index` | `false` | Automatically index new projects when an MCP session starts. |
| `auto_index_limit` | `50000` | Maximum file count allowed for automatic indexing of a new project. |

## 3. UI Settings

The optional built-in graph UI stores its settings in:

```text
${CBM_CACHE_DIR:-~/.cache/codebase-memory-mcp}/config.json
```

Current format:

```json
{
  "ui_enabled": false,
  "ui_port": 9749
}
```

Notes:

- If the UI-enabled binary has embedded assets and no UI config file exists yet, the UI auto-enables on first run.
- `CBM_CACHE_DIR` changes both the UI config location and the runtime settings database location.

## 4. Environment Variables

These environment variables affect runtime behavior:

| Variable | Default | Description |
|---|---|---|
| `CBM_ALLOWED_ROOT` | *(unset)* | Restrict `index_repository` to paths within this directory. When set, a `repo_path` that resolves (after symlink / `..` resolution) outside this root is refused; unset imposes no restriction. Useful when the server may be driven by an untrusted caller (agentic or multi-tenant deployments). |
| `CBM_CACHE_DIR` | `~/.cache/codebase-memory-mcp` | Override the cache directory used for indexes, `_config.db`, and UI `config.json`. |
| `CBM_DIAGNOSTICS` | `false` | Enable periodic diagnostics output to `/tmp/cbm-diagnostics-<pid>.json`. |
| `CBM_DOWNLOAD_URL` | GitHub releases | Override the update download URL. |
| `CBM_LOG_LEVEL` | `info` | Set stderr log level to `debug`, `info`, `warn`, `error`, or `none` (or `0`-`4`). |
| `CBM_WORKERS` | auto-detected | Override the indexing worker count. When present, this must be an exact decimal integer from 1 through 256; malformed, unreadable, or out-of-range values fail closed with `CBM_WORKERS_INVALID`/`CBM_WORKERS_UNREADABLE` instead of falling back to auto-detection. |

## 5. Agent and Editor Integration Files

The `install` command can also write MCP entries and instruction blocks into agent/editor config files such as Claude Code, Codex, Gemini, VS Code, Cursor, Zed, and others.

Those target paths vary by tool and platform, so the easiest way to inspect the exact files for your machine is:

```bash
codebase-memory-mcp install --dry-run
```

That prints the specific config files the installer would modify without writing anything.

## 6. Explicit Legacy Store Migration (Astrolabe native Windows)

Never rename, delete, upgrade, or reindex over an integrity/provenance-refused
store by hand. From the canonical Astrolabe checkout, use the tracker-bound
archive transaction with hashes measured from the exact current files and the
reviewed native binary:

```powershell
.\scripts\migrate-cbm-store.ps1 `
  -Issue 719 `
  -Operation ArchiveAndReindex `
  -LegacyDbPath 'C:\path\to\cache\legacy.db' `
  -ExpectedDbSha256 '<64 lowercase hex characters>' `
  -RepositoryPath 'C:\path\to\canonical\repository' `
  -Project 'stable-alias' `
  -BinaryPath 'C:\path\to\codebase-memory-mcp.exe' `
  -ExpectedBinarySha256 '<64 lowercase hex characters>' `
  -ExpectedSchemaVersion '<reviewed CBM_GRAPH_SCHEMA_VERSION integer>'
```

The command retains exact no-write/no-delete-share handles over the complete
DB/WAL/SHM family, publishes durable hash-linked intent/transition records,
renames each exact file without replacement into a content-addressed
issue-bound archive, proves the source namespace absent and archive bytes
unchanged, and only then invokes a real `index_repository` from the canonical
source root under the explicit alias. A separate native process must then admit
and query that exact alias. Completion freezes and hashes the complete new
DB/WAL/SHM family, re-reads every archived hash plus source absence, and records
both process identities and outputs. Any ambiguity fails closed and preserves
the transaction directory for diagnosis.

The Win32 handle interop compiler is also transaction-owned: only after the
issue/hash directory exists does the script create its `compiler-scope`, bind
the exact PowerShell owner identity, redirect compiler TEMP there, and publish
durable compiler intent/inventory/completion or fault records. It never creates
an anonymous compiler child in workspace `.tmp`, and an existing transaction is
never modified by a new refusal attempt.
