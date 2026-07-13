//! FSV: the #260 `ScratchDir` guard used by the converted calyx-ledger test
//! producers self-cleans on a panic unwind (ASTROLABE #299).
//!
//! Before #299 the ledger FSV helpers resolved a scratch root via
//! `env::temp_dir().join("calyx-ph3x-...")` and removed it only on the happy
//! path, so a panicking test leaked the durable-ledger tree into the operator's
//! real `%TEMP%`. These tests prove the RAII replacement removes the tree on the
//! panic/early-return path, with an independent filesystem readback.

use calyx_fsv::scratch::{ScratchDir, scratch_or_temp};

/// Mirrors the converted `fsv_root()` helpers: an unset `CALYX_FSV_ROOT` yields
/// an armed fallback that must self-clean even when the test unwinds.
#[test]
fn ledger_fsv_scratch_is_removed_on_panic_unwind() {
    let probe = std::sync::Arc::new(std::sync::Mutex::new(std::path::PathBuf::new()));
    let probe_inner = probe.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Same call the converted producers make (env unset -> armed fallback).
        let scratch = scratch_or_temp(
            "CALYX_LEDGER_ISSUE299_UNSET_KEY",
            "calyx-ph35-ledger-issue299",
        );
        assert!(!scratch.is_kept(), "unset env var must arm the fallback");
        let ledger_dir = scratch.join("ledger-cf");
        std::fs::create_dir_all(&ledger_dir).expect("create durable ledger dir");
        std::fs::write(ledger_dir.join("0000000000000000.ledger"), b"row").expect("write row");
        *probe_inner.lock().unwrap() = scratch.path().to_path_buf();
        assert!(scratch.path().is_dir());
        panic!("intentional unwind through a live ledger ScratchDir");
    }));
    assert!(result.is_err(), "closure was expected to panic");
    let leaked = probe.lock().unwrap().clone();
    assert!(
        !leaked.as_os_str().is_empty(),
        "probe never captured the path"
    );
    // FSV: independent readback — the non-empty durable tree must be GONE.
    assert!(
        !leaked.exists(),
        "ledger scratch leaked after panic unwind: {}",
        leaked.display()
    );
}

/// The `temp_root`-style direct producer (`ScratchDir::new_temp`) likewise
/// removes a non-empty tree on drop at end of scope.
#[test]
fn ledger_directory_scratch_is_removed_on_drop() {
    let path;
    {
        let root = ScratchDir::new_temp("calyx-directory-ledger-issue299").expect("scratch");
        path = root.path().to_path_buf();
        std::fs::write(path.join("anchor.head"), b"anchor").expect("write anchor");
        assert!(path.is_dir());
    }
    assert!(
        !path.exists(),
        "directory-ledger scratch leaked after drop: {}",
        path.display()
    );
}
