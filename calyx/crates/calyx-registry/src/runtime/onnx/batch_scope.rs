use calyx_core::Result;

use super::config_invalid;
use crate::runtime::common::scoped_runtime_batch_limit;

pub(in crate::runtime::onnx) fn scoped_max_batch(spec_max: Option<usize>) -> Result<Option<usize>> {
    if spec_max == Some(0) {
        return Err(config_invalid("LensSpec max_batch must be > 0"));
    }
    let scoped = scoped_runtime_batch_limit();
    let out = match (spec_max, scoped) {
        (Some(spec), Some(limit)) => Some(spec.min(limit)),
        (Some(spec), None) => Some(spec),
        (None, Some(limit)) => Some(limit),
        (None, None) => None,
    };
    Ok(out)
}
