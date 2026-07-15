//! Consent and purpose-tag checks for privacy-governed Calyx processing.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{CalyxError, Result, Ts};

/// Module-local consent violation code for PH61 privacy gates.
pub const CALYX_CONSENT_VIOLATION: &str = "CALYX_CONSENT_VIOLATION";

/// Consent timestamps use Calyx server timestamp units: Unix milliseconds.
pub type Timestamp = Ts;

/// Lawful basis attached to a consent tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LawfulBasis {
    Consent,
    LegitimateInterest,
    ContractPerformance,
    LegalObligation,
    VitalInterests,
    PublicTask,
}

impl fmt::Display for LawfulBasis {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Consent => "consent",
            Self::LegitimateInterest => "legitimate_interest",
            Self::ContractPerformance => "contract_performance",
            Self::LegalObligation => "legal_obligation",
            Self::VitalInterests => "vital_interests",
            Self::PublicTask => "public_task",
        })
    }
}

/// Declared purpose for a Calyx operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    Search,
    Intelligence,
    Reranking,
    Analytics,
    Export,
    AuditOnly,
}

/// Consent metadata carried by a constellation or vault-wide default policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsentTag {
    pub lawful_basis: LawfulBasis,
    pub permitted_purposes: Vec<Purpose>,
    pub expires_at: Option<Timestamp>,
}

/// Returns true when a consent tag is past its validity window.
pub fn consent_expired(tag: &ConsentTag, now: Timestamp) -> bool {
    tag.expires_at.is_some_and(|expires_at| now >= expires_at)
}

/// Fail-closed purpose check for downstream processing.
pub fn check_consent(tag: &ConsentTag, requested_purpose: Purpose, now: Timestamp) -> Result<()> {
    if requested_purpose == Purpose::AuditOnly {
        return Ok(());
    }
    if consent_expired(tag, now) {
        return Err(consent_violation(format!(
            "consent for lawful basis {} expired before purpose {:?}",
            tag.lawful_basis, requested_purpose
        )));
    }
    if tag.permitted_purposes.contains(&requested_purpose) {
        Ok(())
    } else {
        Err(consent_violation(format!(
            "purpose {:?} is not permitted by consent tag",
            requested_purpose
        )))
    }
}

fn consent_violation(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: CALYX_CONSENT_VIOLATION,
        message: message.into(),
        remediation: "request only permitted purposes or refresh consent before processing",
    }
}
