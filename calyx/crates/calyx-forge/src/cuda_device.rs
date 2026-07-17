use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::ForgeError;

const CUDA_TOKEN_PREFIX: &str = "cuda:pci=";
const CUDA_UUID_SEPARATOR: &str = ";uuid=";
pub const CUDA_DEVICE_ENV: &str = "CALYX_CUDA_DEVICE";
const LEGACY_CUDA_DEVICE_ENVS: [&str; 2] =
    ["CALYX_ONNX_CUDA_DEVICE", "CALYX_CANDLE_CUDA_DEVICE"];

/// Stable physical CUDA-device identity used by frozen neural-lens contracts.
///
/// CUDA Runtime and CUDA Driver ordinals are process-local selectors and may be
/// remapped independently. PCI identity plus the NVIDIA GPU UUID identifies the
/// physical device across those ordinal spaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PinnedCudaDeviceIdentity {
    pci_domain: u16,
    pci_bus: u8,
    pci_device: u8,
    pci_function: u8,
    uuid: [u8; 16],
}

impl PinnedCudaDeviceIdentity {
    pub fn from_pci_and_uuid(pci_bus_id: &str, uuid: &str) -> Result<Self, String> {
        let (pci_domain, pci_bus, pci_device, pci_function) = parse_pci_bus_id(pci_bus_id)?;
        let uuid = parse_gpu_uuid(uuid)?;
        Ok(Self::from_parts(
            pci_domain,
            pci_bus,
            pci_device,
            pci_function,
            uuid,
        ))
    }

    pub fn from_pci_and_uuid_bytes(pci_bus_id: &str, uuid: [u8; 16]) -> Result<Self, String> {
        let (pci_domain, pci_bus, pci_device, pci_function) = parse_pci_bus_id(pci_bus_id)?;
        Ok(Self::from_parts(
            pci_domain,
            pci_bus,
            pci_device,
            pci_function,
            uuid,
        ))
    }

    const fn from_parts(
        pci_domain: u16,
        pci_bus: u8,
        pci_device: u8,
        pci_function: u8,
        uuid: [u8; 16],
    ) -> Self {
        Self {
            pci_domain,
            pci_bus,
            pci_device,
            pci_function,
            uuid,
        }
    }

    pub fn parse_execution_token(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let prefix = raw
            .get(..CUDA_TOKEN_PREFIX.len())
            .filter(|prefix| prefix.eq_ignore_ascii_case(CUDA_TOKEN_PREFIX))
            .ok_or_else(|| {
                format!(
                    "unsupported CUDA execution device {raw:?}; expected cuda:pci=<domain:bus:device.function>;uuid=GPU-<uuid>"
                )
            })?;
        let body = &raw[prefix.len()..];
        let separator =
            find_ascii_case_insensitive(body, CUDA_UUID_SEPARATOR).ok_or_else(|| {
                format!("CUDA execution device {raw:?} is missing the ;uuid=GPU-<uuid> identity")
            })?;
        let pci_bus_id = &body[..separator];
        let uuid = &body[separator + CUDA_UUID_SEPARATOR.len()..];
        if uuid.contains(';') {
            return Err(format!(
                "CUDA execution device {raw:?} contains unexpected fields after the GPU UUID"
            ));
        }
        Self::from_pci_and_uuid(pci_bus_id, uuid)
    }

    pub fn canonical_execution_token(self) -> String {
        format!(
            "cuda:pci={};uuid={}",
            self.canonical_pci_bus_id(),
            self.canonical_uuid()
        )
    }

    pub fn canonical_pci_bus_id(self) -> String {
        format!(
            "{:04x}:{:02x}:{:02x}.{:x}",
            self.pci_domain, self.pci_bus, self.pci_device, self.pci_function
        )
    }

    pub fn canonical_uuid(self) -> String {
        let bytes = self.uuid;
        format!(
            "GPU-{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            bytes[0],
            bytes[1],
            bytes[2],
            bytes[3],
            bytes[4],
            bytes[5],
            bytes[6],
            bytes[7],
            bytes[8],
            bytes[9],
            bytes[10],
            bytes[11],
            bytes[12],
            bytes[13],
            bytes[14],
            bytes[15]
        )
    }

    pub const fn uuid_bytes(self) -> [u8; 16] {
        self.uuid
    }
}

impl fmt::Display for PinnedCudaDeviceIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical_execution_token())
    }
}

impl FromStr for PinnedCudaDeviceIdentity {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Self::parse_execution_token(raw)
    }
}

impl TryFrom<String> for PinnedCudaDeviceIdentity {
    type Error = String;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::parse_execution_token(&raw)
    }
}

impl From<PinnedCudaDeviceIdentity> for String {
    fn from(identity: PinnedCudaDeviceIdentity) -> Self {
        identity.canonical_execution_token()
    }
}

/// Resolve the single CUDA Runtime-visible ordinal used by every process-local runtime.
///
/// The runtime-specific variables remain accepted as compatibility inputs, but every supplied
/// selector must agree. This lets startup health/math code select the same physical device before
/// ONNX or Candle is constructed without silently making visible device 0 process-global.
pub fn configured_cuda_runtime_ordinal() -> crate::Result<u32> {
    let mut configured = Vec::new();
    for name in std::iter::once(CUDA_DEVICE_ENV).chain(LEGACY_CUDA_DEVICE_ENVS) {
        let Some(raw) = std::env::var_os(name) else {
            continue;
        };
        let raw = raw.to_string_lossy();
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(cuda_selector_error(format!(
                "{name} is empty; a supplied CUDA Runtime-visible ordinal must be a non-negative integer"
            )));
        }
        let ordinal = trimmed.parse::<u32>().map_err(|_| {
            cuda_selector_error(format!(
                "{name}={trimmed:?} is not a non-negative CUDA Runtime-visible ordinal"
            ))
        })?;
        configured.push((name, ordinal));
    }
    let Some((first_name, first_ordinal)) = configured.first().copied() else {
        return Ok(0);
    };
    if let Some((name, ordinal)) = configured
        .iter()
        .copied()
        .find(|(_, ordinal)| *ordinal != first_ordinal)
    {
        return Err(cuda_selector_error(format!(
            "CUDA device selectors disagree: {first_name}={first_ordinal}, {name}={ordinal}"
        )));
    }
    Ok(first_ordinal)
}

fn cuda_selector_error(detail: String) -> ForgeError {
    ForgeError::RuntimeBoundary {
        code: "CALYX_CUDA_DEVICE_SELECTOR_INVALID",
        detail,
        remediation: "set CALYX_CUDA_DEVICE to one CUDA Runtime-visible ordinal and remove runtime-specific overrides, or make CALYX_ONNX_CUDA_DEVICE and CALYX_CANDLE_CUDA_DEVICE exactly equal",
    }
}

fn parse_pci_bus_id(value: &str) -> Result<(u16, u8, u8, u8), String> {
    let parsed = (|| {
        let (domain, rest) = value.split_once(':')?;
        let (bus, rest) = rest.split_once(':')?;
        let (device, function) = rest.split_once('.')?;
        Some((
            u32::from_str_radix(domain, 16).ok()?,
            u32::from_str_radix(bus, 16).ok()?,
            u32::from_str_radix(device, 16).ok()?,
            u32::from_str_radix(function, 16).ok()?,
        ))
    })()
    .ok_or_else(|| format!("malformed CUDA PCI identity {value:?}"))?;
    if parsed.0 > u16::MAX as u32 || parsed.1 > u8::MAX as u32 || parsed.2 > 0x1f || parsed.3 > 7 {
        return Err(format!("out-of-range CUDA PCI identity {value:?}"));
    }
    Ok((
        parsed.0 as u16,
        parsed.1 as u8,
        parsed.2 as u8,
        parsed.3 as u8,
    ))
}

fn parse_gpu_uuid(value: &str) -> Result<[u8; 16], String> {
    let value = value.trim();
    let prefix = value
        .get(..4)
        .filter(|prefix| prefix.eq_ignore_ascii_case("GPU-"))
        .ok_or_else(|| format!("malformed NVIDIA GPU UUID {value:?}; expected GPU-<uuid>"))?;
    let uuid = &value[prefix.len()..];
    if uuid.len() != 36
        || uuid.as_bytes().get(8) != Some(&b'-')
        || uuid.as_bytes().get(13) != Some(&b'-')
        || uuid.as_bytes().get(18) != Some(&b'-')
        || uuid.as_bytes().get(23) != Some(&b'-')
    {
        return Err(format!("malformed NVIDIA GPU UUID {value:?}"));
    }
    let mut compact = [0u8; 32];
    let mut written = 0usize;
    for byte in uuid.bytes() {
        if byte == b'-' {
            continue;
        }
        if !byte.is_ascii_hexdigit() || written == compact.len() {
            return Err(format!("malformed NVIDIA GPU UUID {value:?}"));
        }
        compact[written] = byte;
        written += 1;
    }
    if written != compact.len() {
        return Err(format!("malformed NVIDIA GPU UUID {value:?}"));
    }
    let mut out = [0u8; 16];
    for (index, pair) in compact.chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair)
            .map_err(|_| format!("malformed NVIDIA GPU UUID {value:?}"))?;
        out[index] = u8::from_str_radix(pair, 16)
            .map_err(|_| format!("malformed NVIDIA GPU UUID {value:?}"))?;
    }
    Ok(out)
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    haystack
        .as_bytes()
        .windows(needle.len())
        .position(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}
