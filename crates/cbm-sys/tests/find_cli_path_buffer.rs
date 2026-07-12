#![cfg(windows)]
//! #267 runtime FSV — `cbm_find_cli` must resolve an executable through a PATH
//! longer than the retired 4096-byte fixed buffer.
//!
//! Source of truth: the C runtime `environ` table (exactly what `cli.c`
//! `find_in_path` reads) plus the real marker file on disk. The PATH is set via
//! the CRT `_putenv` — NOT Rust's `std::env::set_var`, which writes only the
//! Win32 environment block that the CRT array does not reflect (the #240 trap).
//! A real `astro267.cmd` is created in a temp dir placed LAST in PATH, so a
//! copy truncated at 4096 bytes drops exactly the segment we need: under the old
//! fixed buffer `cbm_find_cli` returned "" for an oversized PATH; under the fix
//! it resolves the marker in full. Every case prints PATH byte length and the
//! read-back result so the log shows the actual persisted outcome (X+X=Y).

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

// `cbm_find_cli` is exported (non-static) by libcbm's cli.c but is not in the
// bindgen allowlist output, so declare it directly; libcbm.a is linked by
// cbm-sys, so the symbol resolves at link time.
extern "C" {
    fn cbm_find_cli(name: *const c_char, home_dir: *const c_char) -> *const c_char;
    // `_putenv` updates the CRT `environ`/`_environ` table that `find_in_path`
    // reads. It copies the string, so the CString may drop afterwards.
    fn _putenv(envstring: *const c_char) -> c_int;
}

fn set_path(value: &str) {
    let s = CString::new(format!("PATH={value}")).expect("PATH has no interior NUL");
    let rc = unsafe { _putenv(s.as_ptr()) };
    assert_eq!(rc, 0, "_putenv(PATH=...) failed rc={rc}");
}

fn find_cli(name: &str, home: &str) -> String {
    let cname = CString::new(name).unwrap();
    let chome = CString::new(home).unwrap();
    unsafe {
        let p = cbm_find_cli(cname.as_ptr(), chome.as_ptr());
        // Contract: cbm_find_cli returns "" (never NULL) when not found.
        assert!(!p.is_null(), "cbm_find_cli returned NULL; contract is \"\"");
        CStr::from_ptr(p).to_string_lossy().into_owned()
    }
}

/// Build a PATH of at least `target_len` bytes with `real_dir` as the LAST
/// segment — the segment a copy truncated below `target_len` would drop.
fn padded_path(target_len: usize, real_dir: &str) -> String {
    let mut s = String::new();
    let mut i = 0usize;
    while s.len() + real_dir.len() + 1 < target_len {
        s.push_str(&format!("C:\\astro267pad\\d{i:08};"));
        i += 1;
    }
    s.push_str(real_dir);
    s
}

#[test]
fn find_cli_resolves_through_oversized_path() {
    // A real marker executable in a fresh temp dir (under the launcher, temp_dir
    // is the workspace-local .tmp child, never the operator %TEMP%).
    let dir = std::env::temp_dir().join(format!("astro267_{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let exe = dir.join("astro267.cmd");
    std::fs::write(&exe, b"@echo astro267\r\n").expect("write marker exe");

    // PATH stores the dir in native (backslash) form; find_in_path joins it to
    // the name with a forward slash, so the resolved string is "<dir>/astro267.cmd".
    let real_dir = dir.to_string_lossy().replace('/', "\\");
    let expected = format!("{real_dir}/astro267.cmd");
    // A guaranteed-absent home so the home-dir fallback probes cannot mask a
    // find_in_path failure — the old buffer would land here and return "".
    let nonexistent_home = "C:/astro267-no-such-home-4f1e9";

    let run = |label: &str, path: &str, query: &str| -> String {
        set_path(path);
        let got = find_cli(query, nonexistent_home);
        println!("[{label}] PATH_bytes={} query={query:?} -> {got:?}", path.len());
        got
    };

    // Case A — operator-size PATH (~4226 B, the real value that trips the bug).
    // This is the core regression proof: the old 4096-byte buffer returned "".
    let path_a = padded_path(4226, &real_dir);
    assert!(path_a.len() > 4096, "case A PATH must exceed the old 4096 buffer");
    assert_eq!(run("A/4226B", &path_a, "astro267"), expected, "oversized PATH must resolve the marker");

    // Case B — much larger PATH (~8 KB): still resolved, no artificial cap left.
    let path_b = padded_path(8192, &real_dir);
    assert!(path_b.len() > 8000, "case B PATH must be ~8 KB");
    assert_eq!(run("B/8KB", &path_b, "astro267"), expected, "8 KB PATH must resolve the marker");

    // Case C — boundary around the retired 4096-byte buffer.
    let path_c = padded_path(4096, &real_dir);
    assert_eq!(run("C/4096B", &path_c, "astro267"), expected, "boundary PATH must resolve the marker");

    // Case D — big PATH but a name that is absent: must NOT false-positive.
    assert_eq!(run("D/absent-name", &path_a, "astro267_absent_xyz"), "", "absent name must return \"\"");

    // Case E — short PATH sanity: the common case still resolves (no regression).
    assert_eq!(run("E/short", &real_dir, "astro267"), expected, "short PATH must still resolve");

    std::fs::remove_dir_all(&dir).ok();
}
