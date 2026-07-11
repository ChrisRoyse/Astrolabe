#[path = "../build_support.rs"]
mod build_support;

use build_support::{normalize_bindings, strip_layout_tests};

#[test]
fn platform_equivalent_enum_aliases_and_whitespace_compare_equal() {
    let linux = r#"
        pub const Demo_DemoFirst: Demo = 0;
        pub const Demo_DemoSecond: Demo = 1;
        pub type Demo = ::std::os::raw::c_uint;
        unsafe extern "C" {
            pub fn cbm_demo(value: Demo)
                -> ::std::os::raw::c_int;
        }
    "#;
    let windows = r#"
        pub const Demo_DemoFirst: Demo = 0;
        pub const Demo_DemoSecond: Demo = 1;
        pub type Demo = ::std::os::raw::c_int;
        unsafe extern "C" { pub fn cbm_demo(value: Demo) -> ::std::os::raw::c_int; }
    "#;

    assert_eq!(normalize_bindings(linux), normalize_bindings(windows));
}

#[test]
fn missing_or_changed_api_still_compares_unequal() {
    let committed = r#"
        pub const Demo_DemoFirst: Demo = 0;
        pub type Demo = ::std::os::raw::c_uint;
        unsafe extern "C" { pub fn cbm_demo(value: Demo) -> ::std::os::raw::c_int; }
    "#;
    let missing_function = r#"
        pub const Demo_DemoFirst: Demo = 0;
        pub type Demo = ::std::os::raw::c_int;
    "#;
    let changed_return = r#"
        pub const Demo_DemoFirst: Demo = 0;
        pub type Demo = ::std::os::raw::c_int;
        unsafe extern "C" { pub fn cbm_demo(value: Demo) -> ::std::os::raw::c_long; }
    "#;

    assert_ne!(
        normalize_bindings(committed),
        normalize_bindings(missing_function)
    );
    assert_ne!(
        normalize_bindings(committed),
        normalize_bindings(changed_return)
    );
}

#[test]
fn non_enum_integer_aliases_remain_signedness_sensitive() {
    let signed = "pub type Count = ::std::os::raw::c_int;";
    let unsigned = "pub type Count = ::std::os::raw::c_uint;";

    assert_ne!(normalize_bindings(signed), normalize_bindings(unsigned));
}

#[test]
fn strip_layout_tests_removes_only_bindgen_layout_blocks() {
    let generated = "#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct demo_t {
    pub value: ::std::os::raw::c_int,
}
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
const _: () = {
    [\"Size of demo_t\"][::std::mem::size_of::<demo_t>() - 4usize];
    [\"Alignment of demo_t\"][::std::mem::align_of::<demo_t>() - 4usize];
    [\"Offset of field: demo_t::value\"][::std::mem::offset_of!(demo_t, value) - 0usize];
};
unsafe extern \"C\" {
    pub fn cbm_demo(value: demo_t) -> ::std::os::raw::c_int;
}
";
    let expected = "#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct demo_t {
    pub value: ::std::os::raw::c_int,
}
unsafe extern \"C\" {
    pub fn cbm_demo(value: demo_t) -> ::std::os::raw::c_int;
}
";

    assert_eq!(strip_layout_tests(generated), expected);
}

#[test]
fn strip_layout_tests_keeps_unrelated_const_blocks_and_attributes() {
    // A const block without the layout-test allow attribute must survive, and
    // the allow attribute on a non-const item must survive.
    let generated = "const _: () = {
    let _probe = 1;
};
#[allow(clippy::unnecessary_operation, clippy::identity_op)]
fn not_a_layout_test() {}
";
    assert_eq!(strip_layout_tests(generated), generated);
}
