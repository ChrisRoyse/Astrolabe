//! Canonical transport-security and authentication types (PRD 30 §2).
//!
//! These types live in `calyx-core` so both `calyx-aster` and `calyxd` can
//! reference them without a circular dependency. The central invariant is
//! [`no_anonymous_write`]: every mutation entry point must present an [`AuthN`]
//! identity or be rejected with [`CALYX_AUTHN_REQUIRED`] before any write
//! reaches the vault — fail-closed (A16), never a silent allow.
//!
//! Error codes here are module-local `pub const` strings (the same pattern as
//! [`crate::temporal`]); they are intentionally *not* part of the closed PRD-18
//! catalog (`CALYX_ERROR_CODES`), which `catalog_matches_prd_18_exactly` pins to
//! PRD 18 exactly. See PR/issue notes for the governance follow-up.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{CalyxError, Result};

/// A mutation was attempted without an authenticated principal (PRD 30 §2,
/// "no anonymous writes"). Fail-closed (A16).
pub const CALYX_AUTHN_REQUIRED: &str = "CALYX_AUTHN_REQUIRED";
/// A TLS configuration references a cert/key/CA path that does not exist or is
/// not readable (PRD 30 §2, "crypto in transit").
pub const CALYX_TLS_CONFIG_INVALID: &str = "CALYX_TLS_CONFIG_INVALID";

/// Server-mode TLS material. When `ca_pem_path` is present the server can verify
/// client certificates, i.e. run mutual TLS (see [`MtlsConfig`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the server certificate chain (PEM).
    pub cert_pem_path: PathBuf,
    /// Path to the server private key (PEM).
    pub key_pem_path: PathBuf,
    /// Optional path to the CA bundle used to verify client certs (PEM).
    /// `Some` enables mutual TLS; `None` is server-auth-only TLS.
    pub ca_pem_path: Option<PathBuf>,
}

impl TlsConfig {
    /// Verifies that the configured PEM paths exist and are readable.
    ///
    /// Metadata-only — this does **not** parse the PEM contents (that is the
    /// TLS stack's job at bind time). Returns [`CALYX_TLS_CONFIG_INVALID`] naming
    /// the first offending path so the operator knows exactly what to fix.
    pub fn validate(&self) -> Result<()> {
        Self::check_readable("cert_pem_path", &self.cert_pem_path)?;
        Self::check_readable("key_pem_path", &self.key_pem_path)?;
        if let Some(ca) = &self.ca_pem_path {
            Self::check_readable("ca_pem_path", ca)?;
        }
        Ok(())
    }

    fn check_readable(field: &str, path: &PathBuf) -> Result<()> {
        match std::fs::metadata(path) {
            Ok(meta) if meta.is_file() => Ok(()),
            Ok(_) => Err(tls_config_invalid(format!(
                "{field} {} is not a regular file",
                path.display()
            ))),
            Err(error) => Err(tls_config_invalid(format!(
                "{field} {} is not readable: {error}",
                path.display()
            ))),
        }
    }
}

/// Mutual-TLS configuration: a [`TlsConfig`] plus the policy switch that decides
/// whether a missing/invalid client certificate is rejected at connect time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtlsConfig {
    /// Underlying TLS material.
    pub tls: TlsConfig,
    /// When `true`, connections without a valid client certificate are rejected.
    pub require_client_cert: bool,
}

/// The three permitted identity modes for a calling principal (PRD 30 §2).
///
/// Embedded vaults always supply [`AuthN::InProcess`] (the host application owns
/// identity). Server mode (`calyxd`) must supply [`AuthN::MtlsToken`] or
/// [`AuthN::CloudflareAccess`]; anonymous access is never an `AuthN` value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthN {
    /// In-process embedded caller; `host_app_id` identifies the host application.
    InProcess {
        /// Opaque identifier the host application assigns to itself.
        host_app_id: String,
    },
    /// Verified mTLS client identity, keyed by certificate fingerprint.
    MtlsToken {
        /// SHA-256 fingerprint of the verified client certificate.
        fingerprint: [u8; 32],
    },
    /// Cloudflare Access service token identity.
    CloudflareAccess {
        /// The Cloudflare Access service token id presented by the caller.
        service_token_id: String,
    },
}

impl AuthN {
    /// `true` for the network-facing identity modes (mTLS / Cloudflare Access),
    /// `false` for [`AuthN::InProcess`]. `calyxd` uses this to enforce that a
    /// server-mode principal is never in-process.
    pub fn is_server_mode(&self) -> bool {
        matches!(
            self,
            AuthN::MtlsToken { .. } | AuthN::CloudflareAccess { .. }
        )
    }
}

/// The no-anonymous-write predicate every mutation entry point must satisfy.
///
/// Returns `Ok(())` when an identity is present and [`CALYX_AUTHN_REQUIRED`] when
/// it is absent. This is deliberately the *only* gate on identity *presence*;
/// validating the identity's *contents* (fingerprint trust, token validity) is
/// the caller's responsibility. It must never return `Ok(())` for `None`.
pub fn no_anonymous_write(authn: Option<&AuthN>) -> Result<()> {
    match authn {
        Some(_) => Ok(()),
        None => Err(authn_required(
            "mutation rejected: no authenticated principal (mTLS, Cloudflare Access, \
             or in-process host identity required)",
        )),
    }
}

fn authn_required(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_AUTHN_REQUIRED,
        message: message.into(),
        remediation: "present a valid mTLS, Cloudflare Access, or in-process identity before writing",
    }
}

fn tls_config_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_TLS_CONFIG_INVALID,
        message: message.into(),
        remediation: "point cert_pem_path/key_pem_path/ca_pem_path at existing, readable PEM files",
    }
}
