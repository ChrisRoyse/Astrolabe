#ifndef CBM_SCHEMA_VERSION_H
#define CBM_SCHEMA_VERSION_H

/* One compatibility boundary for every C-side representation of the persisted
 * graph. The ordinary SQLite store, direct page writer, and compressed artifact
 * metadata must stamp and require this exact value. Keeping the contract here
 * prevents a writer from publishing bytes that the reader rejects.
 *
 * v5: edge identity independently preserves both IMPORTS local_name and C
 *     preprocessing-context id; both generated columns are type-checked.
 * v4: exact-path File QNs; same-stem polyglot files cannot collapse onto one
 *     extensionless module alias.
 * v3: stable atom identity, non-unique QNs, and byte-exact source payloads.
 * v2: edge uniqueness includes local_name_gen. */
enum { CBM_GRAPH_SCHEMA_VERSION = 5 };

#endif /* CBM_SCHEMA_VERSION_H */
