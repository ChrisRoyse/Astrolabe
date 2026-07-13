//! FSV for #260: the `fsv_support` scratch helpers now hand back RAII
//! `calyx_fsv::ScratchDir` guards, so an unset evidence-root variable yields a
//! fallback scratch directory that is removed on drop — including while the
//! stack unwinds through a panicking test. This is the exact leak class that
//! intermittently reddened the native aggregate (#237/#278): a scratch dir
//! surviving a panic straight into the operator's real `%TEMP%`.
//!
//! Source of truth is the filesystem itself, read back independently after the
//! guard has dropped — not a return value.

mod fsv_support;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// A panicking test that owns a `fsv_support` fallback scratch must leave
/// nothing behind: the RAII guard removes the (non-empty) directory during
/// unwind.
#[test]
fn fsv_support_fallback_scratch_is_removed_on_panic_unwind() {
    let probe: Arc<Mutex<PathBuf>> = Arc::new(Mutex::new(PathBuf::new()));
    let probe_inner = Arc::clone(&probe);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Unset variable -> armed fallback scratch under env::temp_dir().
        let scratch = fsv_support::temp_root("calyx-issue260", "panic-probe");
        assert!(
            !scratch.is_kept(),
            "an unset key must yield an armed fallback"
        );
        *probe_inner.lock().unwrap() = scratch.path().to_path_buf();

        // Populate it so we prove recursive removal, not an empty rmdir.
        std::fs::create_dir_all(scratch.join("nested")).unwrap();
        std::fs::write(scratch.join("nested/evidence.bin"), b"payload").unwrap();
        assert!(scratch.path().is_dir());

        panic!("intentional unwind while a fsv_support scratch guard is live");
    }));

    assert!(result.is_err(), "the closure was expected to panic");
    let leaked = probe.lock().unwrap().clone();
    assert!(
        !leaked.as_os_str().is_empty(),
        "probe never captured the scratch path"
    );
    // FSV: independent filesystem readback — the directory must be GONE.
    assert!(
        !leaked.exists(),
        "fsv_support fallback scratch leaked after panic unwind: {}",
        leaked.display()
    );
}

/// The happy path also self-cleans: a fallback scratch is removed once its
/// guard drops at end of scope.
#[test]
fn fsv_support_fallback_scratch_is_removed_on_drop() {
    let path;
    {
        let scratch = fsv_support::temp_root("calyx-issue260", "drop-probe");
        path = scratch.path().to_path_buf();
        std::fs::write(scratch.join("evidence.bin"), b"payload").unwrap();
        assert!(path.is_dir());
    }
    assert!(
        !path.exists(),
        "fsv_support fallback scratch leaked after drop: {}",
        path.display()
    );
}
