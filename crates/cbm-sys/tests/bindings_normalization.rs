#[path = "../build_support.rs"]
mod build_support;

use build_support::normalize_bindings;

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
