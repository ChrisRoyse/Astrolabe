//! Compile-time thread-model contract for the CBM bridge handles (#382, #59).
//!
//! The runtime guards (`ASTRO_CBM_ROW_SINK_THREAD`,
//! `row_sink_state_rejects_callback_thread_drift`) reject cross-thread use at
//! run time; this suite pins the stronger *compile-time* contract that the
//! FFI-owning handles and the row-sink callback state are neither `Send` nor
//! `Sync`. Each case below moves a handle into another thread and MUST fail to
//! compile — trybuild's `compile_fail` asserts exactly that. Making any handle
//! `Send` (e.g. a stray `unsafe impl Send`) would let these programs compile and
//! turn the expected-failure cases red, which is the point of the edge case.
//!
//! This suite was deleted in b05fd4c (#280 "sub-3min test suite" — dropped as
//! "slow/redundant") and restored here after that whole gate-suite premise was
//! retired by the 2026-07-13 FSV-only owner directive; the compile-time
//! not-Send contract is load-bearing and cheap to keep.
//!
//! The `tests/trybuild/*.stderr` baselines were recovered from `b05fd4c^` and
//! are rustc-version-sensitive. If a compiler bump reformats the `E0277` output,
//! regenerate them once with
//! `TRYBUILD=overwrite cargo test -p astrolabe-bridge --test thread_model` and
//! review the diff (the errors must still be "cannot be sent between threads").
#[test]
fn cbm_handles_are_not_send() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/trybuild/cbm_tool_runner_send.rs");
    tests.compile_fail("tests/trybuild/cbm_watcher_send.rs");
    tests.compile_fail("tests/trybuild/cbm_pipeline_send.rs");
}
