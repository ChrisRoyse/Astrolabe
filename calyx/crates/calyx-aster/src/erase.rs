//! Lawful/user-requested erasure for Aster vault content (PH61 T01).
//!
//! Erasure is a two-source-of-truth operation: Aster core CFs (tombstoned
//! atomically under the durable commit lock) and derived state owned by external
//! [`EraseHandler`]s. Issue #561 splits handler work into an explicit two-phase
//! contract run **outside** the durable commit lock, with a durable
//! [intent record](intent) written before any handler side effect so an
//! interrupted erase resumes deterministically and never reports partial work as
//! success.
//!
//! Issue #562 layers the compression-erase policy onto that selection. A slot
//! carrying a live compressed generation manifest is classified during Phase A
//! selection (and revalidated in Phase C): a Constellation/Subject-scoped erase
//! fails closed with [`CompressionErasePolicy::RouteReseal`] — before any handler
//! prepare — routing the caller to a reseal, while a full-vault erase takes
//! [`CompressionErasePolicy::CoordinatedDelete`], staging the manifest tombstone,
//! every compressed primary/raw row tombstone, and exactly one append-only
//! `DeleteGeneration` lifecycle record per generation. Those lifecycle records
//! ride the Phase C core commit in the same batch as the tombstones so the MVCC
//! lifecycle guard admits the manifest tombstone. Every ledger write — the
//! erase-intent tombstone entry included — flows through the single durable-lock
//! acquisition commit path (issue #560).
//!
//! The implementation is split across submodules: [`handler`] holds the erase
//! scopes/result and the handler registry, [`collect`] walks the vault snapshot
//! to select every tombstone target and applies the compression-erase policy,
//! and [`orchestrate`] drives the four erase phases and the resume path.
//! `CompressionErasePolicy` referenced above lives in [`collect`].

mod collect;
mod handler;
mod intent;
mod ledger;
mod orchestrate;

pub use collect::{erase_cf_records, subject_metadata_value};
pub use handler::{
    CALYX_ERASE_HANDLER_COMMIT_INCOMPLETE, CALYX_ERASE_HANDLER_PREPARE_FAILED,
    CALYX_ERASE_SEQUENCE_CONFLICT, EraseHandler, EraseRegistry, EraseResult, EraseScope,
    METADATA_SUBJECT_ID, NoopEraseHandler,
};
pub use orchestrate::erase;
