#[cfg(feature = "ml-runtime")]
use std::collections::{BTreeMap, BTreeSet};
#[cfg(feature = "ml-runtime")]
use std::fmt;
#[cfg(feature = "ml-runtime")]
use std::fs::File;
#[cfg(feature = "ml-runtime")]
use std::io::Read;
#[cfg(feature = "ml-runtime")]
use std::path::Path;

use calyx_core::{CalyxError, Result};
#[cfg(feature = "ml-runtime")]
use safetensors::tensor::Metadata;
#[cfg(feature = "ml-runtime")]
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::frozen::LengthDelimitedSha256;

const PROFILE_FORMAT: &str = "safetensors";
const PROFILE_REVISION: &[u8] = b"calyx-safetensors-source-dtype-profile-v1";
#[cfg(feature = "ml-runtime")]
const SAFETENSORS_HEADER_PREFIX_BYTES: u64 = 8;
#[cfg(feature = "ml-runtime")]
const SAFETENSORS_MAX_HEADER_BYTES: u64 = 100_000_000;

/// Aggregate tensor and element counts for one safetensors source dtype.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LensForgeSourceDtypeSummary {
    /// Canonical safetensors dtype token, such as `F16`, `BF16`, or `F32`.
    pub dtype: String,
    /// Number of source tensors stored with this dtype.
    pub tensor_count: u64,
    /// Total number of source elements stored with this dtype.
    pub element_count: u64,
}

/// Canonical profile derived from the physical safetensors weight set.
///
/// The fingerprint is length-delimited and covers the format, file count, and
/// sorted dtype summaries. It describes source bytes, not the loader target
/// dtype used for execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LensForgeSourceTensorDtypeProfile {
    /// Physical source format. Version 1 profiles require `safetensors`.
    pub format: String,
    /// Number of safetensors files included in the complete weight set.
    pub file_count: u64,
    /// Total number of uniquely named tensors across the weight set.
    pub tensor_count: u64,
    /// Total number of tensor elements across the weight set.
    pub element_count: u64,
    /// Strictly dtype-sorted aggregate tensor and element counts.
    pub dtypes: Vec<LensForgeSourceDtypeSummary>,
    /// Canonical length-delimited SHA-256 fingerprint of this profile.
    pub fingerprint_sha256: String,
}

impl LensForgeSourceTensorDtypeProfile {
    /// Returns a compact diagnostic representation of the frozen profile.
    pub fn summary(&self) -> String {
        let dtypes = self
            .dtypes
            .iter()
            .map(|item| {
                format!(
                    "{}:{}/{}",
                    item.dtype, item.tensor_count, item.element_count
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "format={} files={} tensors={} elements={} dtypes=[{}] fingerprint_sha256={}",
            self.format,
            self.file_count,
            self.tensor_count,
            self.element_count,
            dtypes,
            self.fingerprint_sha256
        )
    }

    fn validate(&self) -> Result<()> {
        if self.format != PROFILE_FORMAT {
            return Err(config_invalid(format!(
                "source tensor dtype profile format {} is unsupported; expected {PROFILE_FORMAT}",
                self.format
            )));
        }
        if self.file_count == 0 || self.dtypes.is_empty() {
            return Err(config_invalid(
                "source tensor dtype profile must contain at least one file and dtype",
            ));
        }
        let mut previous = None;
        let mut tensor_count = 0_u64;
        let mut element_count = 0_u64;
        for item in &self.dtypes {
            if item.dtype.trim().is_empty() || item.tensor_count == 0 {
                return Err(config_invalid(
                    "source tensor dtype profile entries require a dtype and tensor_count > 0",
                ));
            }
            if previous.is_some_and(|value: &str| value >= item.dtype.as_str()) {
                return Err(config_invalid(
                    "source tensor dtype profile entries must be strictly dtype-sorted and unique",
                ));
            }
            previous = Some(item.dtype.as_str());
            tensor_count = tensor_count.checked_add(item.tensor_count).ok_or_else(|| {
                config_invalid("source tensor dtype profile tensor count overflow")
            })?;
            element_count = element_count
                .checked_add(item.element_count)
                .ok_or_else(|| {
                    config_invalid("source tensor dtype profile element count overflow")
                })?;
        }
        if tensor_count != self.tensor_count || element_count != self.element_count {
            return Err(config_invalid(format!(
                "source tensor dtype profile totals disagree with entries: declared={}/{} computed={tensor_count}/{element_count}",
                self.tensor_count, self.element_count
            )));
        }
        let expected = profile_fingerprint(&self.format, self.file_count, &self.dtypes);
        if expected != self.fingerprint_sha256 {
            return Err(config_invalid(format!(
                "source tensor dtype profile fingerprint is not canonical or does not match: declared={} computed={expected}",
                self.fingerprint_sha256
            )));
        }
        Ok(())
    }
}

pub(super) fn validate_manifest_source_tensor_profile(
    runtime: &str,
    profile: Option<&LensForgeSourceTensorDtypeProfile>,
) -> Result<()> {
    let local_learned = matches!(
        runtime,
        "candle" | "candle-fp16" | "candle-local" | "fastembed-qwen3"
    );
    match (local_learned, profile) {
        (true, Some(profile)) => profile.validate(),
        (true, None) => Err(config_invalid(
            "local learned manifest requires source_tensor_dtype_profile from verified safetensors bytes",
        )),
        (false, Some(_)) => Err(config_invalid(format!(
            "runtime {runtime} does not consume source_tensor_dtype_profile; remove the inert declaration"
        ))),
        (false, None) => Ok(()),
    }
}

#[cfg(feature = "ml-runtime")]
/// Resolves and validates the complete safetensors weight topology for a local runtime.
///
/// Candle accepts exactly one monolithic file. Qwen accepts either one monolith
/// or one complete, gap-free `model-NNNNN-of-NNNNN.safetensors` shard set.
/// Mixed, duplicate, incomplete, and unsupported sets fail closed.
pub fn resolve_safetensors_weight_set(
    runtime: &str,
    artifact_paths: &[std::path::PathBuf],
) -> Result<Vec<std::path::PathBuf>> {
    let mut weights = artifact_paths
        .iter()
        .filter(|path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("safetensors"))
        })
        .cloned()
        .collect::<Vec<_>>();
    weights.sort();
    let mut identities = BTreeMap::<std::path::PathBuf, std::path::PathBuf>::new();
    for path in &weights {
        let canonical = std::fs::canonicalize(path).map_err(|error| {
            config_invalid(format!(
                "canonicalize safetensors weight {} failed: {error}",
                path.display()
            ))
        })?;
        if let Some(previous) = identities.insert(canonical.clone(), path.clone()) {
            return Err(config_invalid(format!(
                "duplicate safetensors weight identity {} is declared through {} and {}",
                canonical.display(),
                previous.display(),
                path.display()
            )));
        }
    }
    if weights.is_empty() {
        return Err(config_invalid(format!(
            "runtime {runtime} requires at least one safetensors weight file"
        )));
    }
    match runtime {
        "candle" | "candle-fp16" | "candle-local" => {
            if weights.len() != 1 {
                return Err(CalyxError {
                    code: "CALYX_LENS_CONFIG_INVALID",
                    message: format!(
                        "Candle requires exactly one monolithic safetensors weight file; observed {}",
                        weights.len()
                    ),
                    remediation: "consolidate the checkpoint to one immutable model.safetensors file or implement multi-shard Candle loading end to end",
                });
            }
        }
        "fastembed-qwen3" => validate_qwen_shards(&weights)?,
        other => {
            return Err(config_invalid(format!(
                "runtime {other} does not define a local safetensors weight topology"
            )));
        }
    }
    Ok(weights)
}

#[cfg(feature = "ml-runtime")]
fn validate_qwen_shards(weights: &[std::path::PathBuf]) -> Result<()> {
    let parsed = weights
        .iter()
        .map(|path| parse_qwen_shard(path))
        .collect::<Vec<_>>();
    if weights.len() == 1 && parsed[0].is_none() {
        return Ok(());
    }
    if parsed.iter().any(Option::is_none) {
        return Err(config_invalid(
            "fastembed-qwen3 safetensors set mixes a monolith or sidecar with standard shards",
        ));
    }
    let shards = parsed.into_iter().flatten().collect::<Vec<_>>();
    let total = shards[0].1;
    if total == 0 || usize::try_from(total).ok() != Some(weights.len()) {
        return Err(config_invalid(format!(
            "fastembed-qwen3 shard total {total} disagrees with {} files",
            weights.len()
        )));
    }
    if shards.iter().any(|(_, item_total)| *item_total != total) {
        return Err(config_invalid(
            "fastembed-qwen3 shard filenames declare inconsistent totals",
        ));
    }
    let mut indices = shards.iter().map(|(index, _)| *index).collect::<Vec<_>>();
    indices.sort_unstable();
    let expected = (1..=total).collect::<Vec<_>>();
    if indices != expected {
        return Err(config_invalid(format!(
            "fastembed-qwen3 shard indices are incomplete or duplicated: observed={indices:?} expected={expected:?}"
        )));
    }
    Ok(())
}

#[cfg(feature = "ml-runtime")]
fn parse_qwen_shard(path: &Path) -> Option<(u32, u32)> {
    let name = path.file_name()?.to_str()?;
    let body = name.strip_prefix("model-")?.strip_suffix(".safetensors")?;
    let (index, total) = body.split_once("-of-")?;
    if index.len() != 5
        || total.len() != 5
        || !index.bytes().all(|byte| byte.is_ascii_digit())
        || !total.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some((index.parse().ok()?, total.parse().ok()?))
}

#[cfg(feature = "ml-runtime")]
/// Profiles one physical safetensors source with structured format validation.
pub fn profile_safetensors_source(
    path: impl AsRef<Path>,
) -> Result<LensForgeSourceTensorDtypeProfile> {
    profile_safetensors_sources(&[path.as_ref().to_path_buf()])
}

#[cfg(feature = "ml-runtime")]
/// Profiles a deterministic multi-file safetensors set.
///
/// Files are path-sorted, duplicate tensor names are rejected, and all counts
/// use checked arithmetic. Call [`resolve_safetensors_weight_set`] first when
/// runtime-specific shard topology must be enforced.
pub fn profile_safetensors_sources(
    paths: &[std::path::PathBuf],
) -> Result<LensForgeSourceTensorDtypeProfile> {
    if paths.is_empty() {
        return Err(config_invalid("safetensors source list is empty"));
    }
    let mut paths = paths.to_vec();
    paths.sort();
    let mut counts = BTreeMap::<String, (u64, u64)>::new();
    let mut names = BTreeMap::<String, std::path::PathBuf>::new();
    for path in &paths {
        let mut file = File::open(path).map_err(|error| {
            config_invalid(format!(
                "open safetensors source {} failed: {error}",
                path.display()
            ))
        })?;
        let file_len = file
            .metadata()
            .map_err(|error| {
                config_invalid(format!(
                    "stat safetensors source {} failed: {error}",
                    path.display()
                ))
            })?
            .len();
        let mut prefix = [0_u8; SAFETENSORS_HEADER_PREFIX_BYTES as usize];
        file.read_exact(&mut prefix).map_err(|error| {
            config_invalid(format!(
                "read safetensors header prefix {} failed: {error}",
                path.display()
            ))
        })?;
        let header_len = u64::from_le_bytes(prefix);
        if header_len > SAFETENSORS_MAX_HEADER_BYTES
            || header_len
                .checked_add(SAFETENSORS_HEADER_PREFIX_BYTES)
                .is_none_or(|end| end > file_len)
        {
            return Err(config_invalid(format!(
                "safetensors header length {header_len} is invalid for {} bytes in {}",
                file_len,
                path.display()
            )));
        }
        let header_len_usize = usize::try_from(header_len)
            .map_err(|_| config_invalid("safetensors header length exceeds usize"))?;
        let mut header = vec![0_u8; header_len_usize];
        file.read_exact(&mut header).map_err(|error| {
            config_invalid(format!(
                "read safetensors header {} failed: {error}",
                path.display()
            ))
        })?;
        let _: DuplicateRejectingJsonValue = serde_json::from_slice(&header).map_err(|error| {
            config_invalid(format!(
                "validate unique safetensors metadata keys {} failed: {error}",
                path.display()
            ))
        })?;
        let metadata = serde_json::from_slice::<Metadata>(&header).map_err(|error| {
            config_invalid(format!(
                "parse safetensors metadata {} failed: {error}",
                path.display()
            ))
        })?;
        let expected_len = SAFETENSORS_HEADER_PREFIX_BYTES
            .checked_add(header_len)
            .and_then(|value| value.checked_add(metadata.data_len() as u64))
            .ok_or_else(|| config_invalid("safetensors file length overflow"))?;
        if expected_len != file_len {
            return Err(config_invalid(format!(
                "safetensors metadata describes {expected_len} bytes but {} contains {file_len}",
                path.display()
            )));
        }
        for (name, tensor) in metadata.tensors() {
            if let Some(previous) = names.insert(name.clone(), path.clone()) {
                return Err(config_invalid(format!(
                    "duplicate safetensors tensor name {name} in {} and {}",
                    previous.display(),
                    path.display()
                )));
            }
            let elements = tensor.shape.iter().try_fold(1_u64, |product, dim| {
                let dim = u64::try_from(*dim)
                    .map_err(|_| config_invalid("safetensors dimension exceeds u64"))?;
                product
                    .checked_mul(dim)
                    .ok_or_else(|| config_invalid("safetensors tensor element count overflow"))
            })?;
            let entry = counts
                .entry(format!("{:?}", tensor.dtype))
                .or_insert((0, 0));
            entry.0 = entry
                .0
                .checked_add(1)
                .ok_or_else(|| config_invalid("safetensors tensor count overflow"))?;
            entry.1 = entry
                .1
                .checked_add(elements)
                .ok_or_else(|| config_invalid("safetensors element count overflow"))?;
        }
    }
    let dtypes = counts
        .into_iter()
        .map(
            |(dtype, (tensor_count, element_count))| LensForgeSourceDtypeSummary {
                dtype,
                tensor_count,
                element_count,
            },
        )
        .collect::<Vec<_>>();
    if dtypes.is_empty() {
        return Err(config_invalid("safetensors sources contain no tensors"));
    }
    let tensor_count = dtypes.iter().try_fold(0_u64, |total, item| {
        total
            .checked_add(item.tensor_count)
            .ok_or_else(|| config_invalid("safetensors tensor count overflow"))
    })?;
    let element_count = dtypes.iter().try_fold(0_u64, |total, item| {
        total
            .checked_add(item.element_count)
            .ok_or_else(|| config_invalid("safetensors element count overflow"))
    })?;
    let file_count = u64::try_from(paths.len())
        .map_err(|_| config_invalid("safetensors source file count exceeds u64"))?;
    Ok(LensForgeSourceTensorDtypeProfile {
        format: PROFILE_FORMAT.to_string(),
        file_count,
        tensor_count,
        element_count,
        fingerprint_sha256: profile_fingerprint(PROFILE_FORMAT, file_count, &dtypes),
        dtypes,
    })
}

#[cfg(feature = "ml-runtime")]
struct DuplicateRejectingJsonValue;

#[cfg(feature = "ml-runtime")]
impl<'de> Deserialize<'de> for DuplicateRejectingJsonValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateRejectingJsonVisitor)
    }
}

#[cfg(feature = "ml-runtime")]
struct DuplicateRejectingJsonVisitor;

#[cfg(feature = "ml-runtime")]
impl<'de> Visitor<'de> for DuplicateRejectingJsonVisitor {
    type Value = DuplicateRejectingJsonValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON with unique object keys")
    }

    fn visit_bool<E>(self, _value: bool) -> std::result::Result<Self::Value, E> {
        Ok(DuplicateRejectingJsonValue)
    }

    fn visit_i64<E>(self, _value: i64) -> std::result::Result<Self::Value, E> {
        Ok(DuplicateRejectingJsonValue)
    }

    fn visit_u64<E>(self, _value: u64) -> std::result::Result<Self::Value, E> {
        Ok(DuplicateRejectingJsonValue)
    }

    fn visit_f64<E>(self, _value: f64) -> std::result::Result<Self::Value, E> {
        Ok(DuplicateRejectingJsonValue)
    }

    fn visit_str<E>(self, _value: &str) -> std::result::Result<Self::Value, E> {
        Ok(DuplicateRejectingJsonValue)
    }

    fn visit_unit<E>(self) -> std::result::Result<Self::Value, E> {
        Ok(DuplicateRejectingJsonValue)
    }

    fn visit_seq<A>(self, mut sequence: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        while sequence
            .next_element::<DuplicateRejectingJsonValue>()?
            .is_some()
        {}
        Ok(DuplicateRejectingJsonValue)
    }

    fn visit_map<A>(self, mut map: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(<A::Error as serde::de::Error>::custom(format!(
                    "duplicate JSON object key {key:?}"
                )));
            }
            let _: DuplicateRejectingJsonValue = map.next_value()?;
        }
        Ok(DuplicateRejectingJsonValue)
    }
}

fn profile_fingerprint(
    format: &str,
    file_count: u64,
    dtypes: &[LensForgeSourceDtypeSummary],
) -> String {
    let mut hasher = LengthDelimitedSha256::new();
    hasher.update_part(PROFILE_REVISION);
    hasher.update_part(format.as_bytes());
    hasher.update_part(&file_count.to_be_bytes());
    for item in dtypes {
        hasher.update_part(item.dtype.as_bytes());
        hasher.update_part(&item.tensor_count.to_be_bytes());
        hasher.update_part(&item.element_count.to_be_bytes());
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn config_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_LENS_CONFIG_INVALID",
        message: message.into(),
        remediation: "regenerate the manifest from the immutable safetensors source artifact",
    }
}
