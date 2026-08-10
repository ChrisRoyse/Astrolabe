# ADR 0001: Fence installed MCP mutations by activation epoch

- Status: Accepted
- Date: 2026-08-10
- Issue: #1072

## Context

Astrolabe publishes immutable global MCP generations and updates the Codex and
Claude client configurations to select one generation. Client reconfiguration
does not end existing stdio sessions. A resident from an earlier generation can
therefore remain alive while a later generation is active.

A process-lifetime background-lane lock serializes writers, but serialization
alone does not establish which generation is eligible to write. Without a
separate activation authority, an older resident can retain the lane and
publish watcher, project, configuration, or store state using an obsolete
schema.

## Decision

The fixed install-root file `active-generation.json` is the durable selection
authority. Each successful activation publishes a strictly increasing epoch
and the exact immutable generation, publication receipt, artifact, and client
configuration hashes. The two client configurations are committed and read
back before this authority is atomically replaced.

Every installed worker derives its immutable generation from its executable
path and publication receipt. It observes the fixed authority at request,
watcher-tick, lane-acquisition, and publication boundaries.

- Pure reads remain available on a retired resident.
- Every mutation requires an active-generation fence and retains a read/share
  lease over the authority until the mutation has committed or failed.
- Activation must acquire incompatible write/delete sharing before replacing
  the authority. It never commits through a live mutation fence.
- A changed generation or epoch retires existing background ownership. Lane
  status observation never acquires or creates a lock.
- Generation classification validates the active record's own immutable
  layout and hashes before comparing active-worker invocation hashes. A
  different generation is retired, including when its executable bytes are
  identical.
- Path equality uses canonical physical Windows identity so `C:\...` and the
  corresponding `\\?\C:\...` spelling cannot produce false skew.
- Malformed, missing, drifting, or unreadable authority state is a named hard
  error with exact path/hash context. It is never interpreted as source
  movement and never schedules indexing.

The epoch transition is deliberately event-driven. No retry timer, alternate
cache, executable substitution, or process termination participates in the
correctness contract.

## Cost boundary

The production graph measurement was N=84,459 nodes and E=169,752 edges on
2026-08-10. Activation admission reads one bounded authority record and opens
no graph/store column family. Its cost is O(A), where A is the fixed record
size, independent of N, E, and project count. The already-elected watcher is
the only component that scans registered projects. This decision addresses
PC-03, PC-06, PC-14, PC-18, PC-34, PC-37, PC-38, PC-41, and PC-43 from #1064.

## Consequences

An activation is a coordinated writer handoff rather than a configuration-only
edit. Old transports can finish reads, but no obsolete resident can retain or
regain mutation authority. The new generation becomes the sole eligible writer
and converges through the existing watcher lane.

Manual full-state verification must read the authority bytes, both client
configurations, immutable publication/artifact hashes, live process
generations, lane ownership, and SQLite state. At least one transition should
use byte-identical reproducible executables under different immutable tree
identities to prove that epoch identity—not accidental binary difference—is
the fence.

The design follows the holder/transition identity pattern used by Kubernetes
Leases and etcd elections, the atomic replacement semantics documented for
Windows `ReplaceFile`, and SQLite's requirement to begin a fresh read
transaction to observe committed state.
