#[test]
fn cbm_tool_runner_is_not_send() {
    let tests = trybuild::TestCases::new();
    tests.compile_fail("tests/trybuild/cbm_tool_runner_send.rs");
    tests.compile_fail("tests/trybuild/cbm_watcher_send.rs");
}
