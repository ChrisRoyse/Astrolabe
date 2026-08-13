use super::*;

pub(crate) const ROOT_IDENTITY_SCHEMA: &str = "astrolabe.windows-root-identity.v1";
pub(crate) const GIT_SOURCE_ROOT_IDENTITY_KEY: &str = "git_source_root_identity_json";

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WindowsRootIdentity {
    pub(crate) schema: String,
    pub(crate) volume_serial_hex: String,
    pub(crate) file_id_128_hex: String,
    pub(crate) final_handle_path: String,
}

impl WindowsRootIdentity {
    pub(crate) fn record_json(&self) -> Result<String, DynError> {
        self.validate()?;
        Ok(serde_json::to_string(self)?)
    }

    pub(crate) fn validate(&self) -> Result<(), DynError> {
        let lower_hex = |value: &str, bytes: usize| {
            value.len() == bytes * 2
                && value.bytes().all(|byte| byte.is_ascii_hexdigit())
                && value == value.to_ascii_lowercase()
        };
        if self.schema != ROOT_IDENTITY_SCHEMA
            || !lower_hex(&self.volume_serial_hex, 8)
            || !lower_hex(&self.file_id_128_hex, 16)
            || self.final_handle_path.trim().is_empty()
        {
            return Err(format!(
                "ASTRO_WATCHER_ROOT_IDENTITY_INVALID: root identity has schema={:?}, volume_serial_hex={:?}, file_id_128_hex={:?}, final_handle_path={:?}; remediation: preserve the published generation and explicitly reindex the readable source root so one complete identity is committed",
                self.schema,
                self.volume_serial_hex,
                self.file_id_128_hex,
                self.final_handle_path,
            )
            .into());
        }
        Ok(())
    }

    pub(crate) fn same_object(&self, other: &Self) -> bool {
        self.volume_serial_hex == other.volume_serial_hex
            && self.file_id_128_hex == other.file_id_128_hex
    }
}

#[derive(Debug)]
struct RootCaptureFailure {
    step: &'static str,
    raw_os_error: Option<i32>,
    message: String,
}

impl RootCaptureFailure {
    fn missing(&self) -> bool {
        matches!(self.raw_os_error, Some(2 | 3))
    }

    fn message(&self, path: &Path) -> String {
        format!(
            "root identity step {:?} failed for {}: {} (raw_os_error={:?})",
            self.step,
            path.display(),
            self.message,
            self.raw_os_error,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RootIdentityObservation {
    Exact(WindowsRootIdentity),
    Missing {
        message: String,
    },
    Mismatch {
        actual: Option<WindowsRootIdentity>,
        message: String,
    },
    Unevaluable {
        message: String,
    },
}

pub(crate) fn parse_root_identity(raw: &str) -> Result<WindowsRootIdentity, DynError> {
    let identity: WindowsRootIdentity = serde_json::from_str(raw).map_err(|error| -> DynError {
        format!(
            "ASTRO_WATCHER_ROOT_IDENTITY_MALFORMED: persisted root identity is not valid {ROOT_IDENTITY_SCHEMA} JSON: {error}; remediation: preserve every published artifact and explicitly reindex the readable source root"
        )
        .into()
    })?;
    identity.validate()?;
    Ok(identity)
}

pub(crate) fn capture_root_identity(path: &Path) -> Result<WindowsRootIdentity, DynError> {
    capture_root_identity_inner(path).map_err(|failure| {
        format!(
            "ASTRO_WATCHER_ROOT_IDENTITY_CAPTURE_FAILED: {}; remediation: keep the prior generation unchanged and retry only after the exact directory identity is readable",
            failure.message(path)
        )
        .into()
    })
}

pub(crate) fn observe_root_identity(
    path: &Path,
    expected: &WindowsRootIdentity,
) -> RootIdentityObservation {
    match capture_root_identity_inner(path) {
        Ok(actual) if expected.same_object(&actual) => RootIdentityObservation::Exact(actual),
        Ok(actual) => RootIdentityObservation::Mismatch {
            message: format!(
                "directory object at {} has volume/file identity {}/{}, expected {}/{}",
                path.display(),
                actual.volume_serial_hex,
                actual.file_id_128_hex,
                expected.volume_serial_hex,
                expected.file_id_128_hex,
            ),
            actual: Some(actual),
        },
        Err(failure) if failure.missing() => RootIdentityObservation::Missing {
            message: failure.message(path),
        },
        Err(failure) if failure.step == "directory_kind" => RootIdentityObservation::Mismatch {
            message: failure.message(path),
            actual: None,
        },
        Err(failure) => RootIdentityObservation::Unevaluable {
            message: failure.message(path),
        },
    }
}

fn capture_root_identity_inner(path: &Path) -> Result<WindowsRootIdentity, RootCaptureFailure> {
    let raw = astrolabe_bridge::capture_windows_directory_identity(path).map_err(|error| {
        RootCaptureFailure {
            step: error.step,
            raw_os_error: error.raw_os_error,
            message: error.message,
        }
    })?;
    let identity = WindowsRootIdentity {
        schema: ROOT_IDENTITY_SCHEMA.to_string(),
        volume_serial_hex: format!("{:016x}", raw.volume_serial),
        file_id_128_hex: raw
            .file_id_128
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        final_handle_path: raw.final_handle_path,
    };
    identity.validate().map_err(|error| RootCaptureFailure {
        step: "identity_contract",
        raw_os_error: None,
        message: error.to_string(),
    })?;
    Ok(identity)
}
