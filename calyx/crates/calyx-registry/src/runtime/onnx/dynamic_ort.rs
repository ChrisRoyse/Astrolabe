use std::path::PathBuf;

#[cfg(not(windows))]
use std::{env, fs};

#[cfg(not(windows))]
use calyx_core::CalyxError;
use calyx_core::Result;

use super::OnnxProviderPolicy;

#[cfg(not(windows))]
const ORT_DYLIB_PATH: &str = "ORT_DYLIB_PATH";
#[cfg(not(windows))]
const CALYX_ORT_CAPI: &str = "CALYX_ORT_CAPI";

pub(super) fn ensure_dynamic_ort(provider_policy: OnnxProviderPolicy) -> Result<PathBuf> {
    #[cfg(windows)]
    {
        return super::runtime_bundle::ensure_runtime(provider_policy);
    }
    #[cfg(not(windows))]
    {
        let path = resolve_ort_dylib_path()?;
        ensure_file(&path)?;
        let _ = provider_policy;
        Ok(path)
    }
}

#[cfg(not(windows))]
fn resolve_ort_dylib_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os(ORT_DYLIB_PATH) {
        return Ok(PathBuf::from(path));
    }
    if let Some(capi) = env::var_os(CALYX_ORT_CAPI) {
        let path = PathBuf::from(capi).join("onnxruntime.dll");
        ensure_file(&path).map_err(|error| {
            CalyxError::lens_unreachable(format!(
                "{CALYX_ORT_CAPI} is set but {} is not a usable ORT dynamic library: {}",
                path.display(),
                error.message
            ))
        })?;
        unsafe {
            env::set_var(ORT_DYLIB_PATH, &path);
        }
        return Ok(path);
    }
    Err(CalyxError::lens_unreachable(format!(
        "{ORT_DYLIB_PATH} must point to a sm_120-capable ONNX Runtime dynamic library; \
         this build uses ort/load-dynamic and has no bundled ORT fallback. On Windows, \
         set {ORT_DYLIB_PATH} directly or set {CALYX_ORT_CAPI} to the ONNX Runtime capi \
         directory before starting GPU resident/search/ingest commands"
    )))
}

#[cfg(not(windows))]
fn ensure_file(path: &PathBuf) -> Result<()> {
    let metadata = fs::metadata(path).map_err(|err| {
        CalyxError::lens_unreachable(format!(
            "stat {ORT_DYLIB_PATH}={} failed: {err}",
            path.display()
        ))
    })?;
    if metadata.is_file() {
        Ok(())
    } else {
        Err(CalyxError::lens_unreachable(format!(
            "{ORT_DYLIB_PATH}={} is not a file",
            path.display()
        )))
    }
}
