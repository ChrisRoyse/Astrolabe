use super::*;

pub(crate) fn ledger_entry_status_json(entry: &calyx_ledger::LedgerEntry) -> Value {
    json!({
        "seq": entry.seq,
        "kind": entry.kind.as_str(),
        "subject": ledger_subject_json(&entry.subject),
        "actor": ledger_actor_json(&entry.actor),
        "ts": entry.ts,
        "entry_hash": hex_lower(&entry.entry_hash),
        "prev_hash": hex_lower(&entry.prev_hash),
        "payload_sha256": hex_lower(&Sha256::digest(&entry.payload)),
        "payload_bytes": entry.payload.len(),
        "verified_hash": entry.verify(),
    })
}

pub(crate) fn ledger_ref_json(ledger_ref: &LedgerRef) -> Value {
    json!({
        "seq": ledger_ref.seq,
        "entry_hash": hex_lower(&ledger_ref.hash),
    })
}

pub(crate) fn ledger_subject_json(subject: &SubjectId) -> Value {
    match subject {
        SubjectId::Cx(id) => json!({"kind": "cx", "id": id.to_string()}),
        SubjectId::Lens(id) => json!({"kind": "lens", "id": id.to_string()}),
        SubjectId::Kernel(bytes) => json!({"kind": "kernel", "id_hex": hex_lower(bytes)}),
        SubjectId::Guard(bytes) => json!({"kind": "guard", "id_hex": hex_lower(bytes)}),
        SubjectId::Query(bytes) => json!({"kind": "query", "id_hex": hex_lower(bytes)}),
    }
}

pub(crate) fn ledger_actor_json(actor: &ActorId) -> Value {
    match actor {
        ActorId::Agent(value) => json!({"kind": "agent", "id": value}),
        ActorId::Service(value) => json!({"kind": "service", "id": value}),
        ActorId::System => json!({"kind": "system"}),
    }
}
