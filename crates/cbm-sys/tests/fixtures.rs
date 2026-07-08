use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

use cbm_sys::{CBMDefinition, CBMLanguage_CBM_LANG_C, cbm_extract_file, cbm_free_result, cbm_init};

#[derive(Debug, PartialEq, serde::Deserialize)]
struct ExpectedDefinition {
    name: String,
    qualified_name: String,
    label: String,
    start_line: u32,
    end_line: u32,
}

#[test]
fn extracts_c_fixture_against_golden() {
    let source = include_str!("../fixtures/simple.c");
    let expected: Vec<ExpectedDefinition> =
        serde_json::from_str(include_str!("golden/simple_c.json")).expect("golden fixture JSON");
    let project = CString::new("astrolabe_fixture").unwrap();
    let rel_path = CString::new("src/simple.c").unwrap();

    unsafe {
        assert_eq!(cbm_init(), 0);
        let result = cbm_extract_file(
            source.as_ptr().cast::<c_char>(),
            source.len() as i32,
            CBMLanguage_CBM_LANG_C,
            project.as_ptr(),
            rel_path.as_ptr(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        assert!(!result.is_null(), "cbm_extract_file returned NULL");

        let defs = (*result).defs;
        let actual = std::slice::from_raw_parts(defs.items, defs.count as usize)
            .iter()
            .map(definition_to_expected)
            .collect::<Vec<_>>();

        cbm_free_result(result);
        assert_eq!(actual.len(), expected.len());
        assert_eq!(actual, expected);
    }
}

fn definition_to_expected(def: &CBMDefinition) -> ExpectedDefinition {
    ExpectedDefinition {
        name: unsafe { c_string(def.name) },
        qualified_name: unsafe { c_string(def.qualified_name) },
        label: unsafe { c_string(def.label) },
        start_line: def.start_line,
        end_line: def.end_line,
    }
}

unsafe fn c_string(ptr: *const c_char) -> String {
    assert!(!ptr.is_null(), "fixture field pointer was NULL");
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}
