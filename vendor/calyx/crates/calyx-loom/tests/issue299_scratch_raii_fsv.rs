//! FSV: the #260 `ScratchDir` guard used by the converted calyx-loom test
//! producers self-cleans on a panic unwind (ASTROLABE #299).
//!
//! Before #299 the loom reactive/agreement FSV tests resolved scratch roots via
//! `env::temp_dir().join(..)` and removed them only on the happy path (via a
//! `clean`/`cleanup` helper), so a panicking test leaked the durable vault tree
//! into the operator's real `%TEMP%`. These tests prove the RAII replacement
//! removes the tree on the panic/early-return path, with independent readback.

use calyx_fsv::scratch::{ScratchDir, scratch_or_temp};

/// Mirrors the converted `root()` helpers (issue572/issue755): an unset env var
/// arms a self-cleaning fallback that must survive neither drop nor a panic.
#[test]
fn loom_root_scratch_is_removed_on_panic_unwind() {
    let probe = std::sync::Arc::new(std::sync::Mutex::new(std::path::PathBuf::new()));
    let probe_inner = probe.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let scratch = scratch_or_temp(
            "CALYX_LOOM_ISSUE299_UNSET_KEY",
            "calyx-issue755-reactive-fsv",
        );
        assert!(!scratch.is_kept(), "unset env var must arm the fallback");
        let vault_dir = scratch.join("vault");
        std::fs::create_dir_all(vault_dir.join("cf/recurrence")).expect("create durable vault");
        std::fs::write(vault_dir.join("cf/recurrence/000.row"), b"row").expect("write row");
        *probe_inner.lock().unwrap() = scratch.path().to_path_buf();
        assert!(scratch.path().is_dir());
        panic!("intentional unwind through a live loom ScratchDir");
    }));
    assert!(result.is_err(), "closure was expected to panic");
    let leaked = probe.lock().unwrap().clone();
    assert!(
        !leaked.as_os_str().is_empty(),
        "probe never captured the path"
    );
    assert!(
        !leaked.exists(),
        "loom scratch leaked after panic unwind: {}",
        leaked.display()
    );
}

/// Mirrors the converted `test_dir(..)` helpers (agreement_graph / issue573 /
/// issue755): a direct `ScratchDir::new_temp` producer self-cleans on drop.
#[test]
fn loom_test_dir_scratch_is_removed_on_drop() {
    let path;
    {
        let dir = ScratchDir::new_temp("calyx-loom-issue299").expect("scratch");
        path = dir.path().to_path_buf();
        std::fs::write(path.join("xterm.cf"), b"x").expect("write");
        assert!(path.is_dir());
    }
    assert!(
        !path.exists(),
        "loom test_dir scratch leaked after drop: {}",
        path.display()
    );
}
