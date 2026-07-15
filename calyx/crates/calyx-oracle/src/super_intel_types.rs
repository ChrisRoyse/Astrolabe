//! PH50 super-intelligence predicate and reverse-query data contracts.

use std::fmt;

use calyx_core::LedgerRef;
use serde::{Deserialize, Serialize};

use crate::types::DomainId;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    OracleClean,
    PanelSufficient,
    KernelExists,
    Calibrated,
    GoodhartDefended,
    MistakeClosed,
}

impl Tier {
    pub const ORDER: [Tier; 6] = [
        Tier::OracleClean,
        Tier::PanelSufficient,
        Tier::KernelExists,
        Tier::Calibrated,
        Tier::GoodhartDefended,
        Tier::MistakeClosed,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Tier::OracleClean => "oracle_clean",
            Tier::PanelSufficient => "panel_sufficient",
            Tier::KernelExists => "kernel_exists",
            Tier::Calibrated => "calibrated",
            Tier::GoodhartDefended => "goodhart_defended",
            Tier::MistakeClosed => "mistake_closed",
        }
    }

    pub fn predicate_order() -> &'static [Tier; 6] {
        &Self::ORDER
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TierResult {
    pub tier: Tier,
    pub passed: bool,
    pub measured_value: f32,
    pub threshold: f32,
    pub cheapest_fix: Option<String>,
}

impl TierResult {
    pub fn new(
        tier: Tier,
        passed: bool,
        measured_value: f32,
        threshold: f32,
        cheapest_fix: Option<String>,
    ) -> Self {
        Self {
            tier,
            passed,
            measured_value,
            threshold,
            cheapest_fix,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SuperIntelReport {
    pub domain: DomainId,
    pub tiers: Vec<TierResult>,
    pub failing_tier: Option<Tier>,
    pub cheapest_fix: Option<String>,
    pub overall: bool,
}

impl SuperIntelReport {
    pub fn new(domain: DomainId, tiers: Vec<TierResult>) -> Self {
        let overall = tiers.iter().all(|tier| tier.passed);
        let failing_tier = first_failing_tier(&tiers);
        let cheapest_fix = failing_tier.and_then(|failing| {
            tiers
                .iter()
                .find(|tier| tier.tier == failing)
                .and_then(|tier| tier.cheapest_fix.clone())
        });

        Self {
            domain,
            tiers,
            failing_tier,
            cheapest_fix,
            overall,
        }
    }

    pub fn failing_tier_report(&self) -> Option<&TierResult> {
        let failing_tier = self.failing_tier?;
        self.tiers.iter().find(|tier| tier.tier == failing_tier)
    }

    pub fn passed_count(&self) -> usize {
        self.tiers.iter().filter(|tier| tier.passed).count()
    }

    pub fn failed_count(&self) -> usize {
        self.tiers.len().saturating_sub(self.passed_count())
    }
}

impl fmt::Display for SuperIntelReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let failing = self
            .failing_tier
            .map(|tier| tier.to_string())
            .unwrap_or_else(|| "none".to_string());
        write!(
            formatter,
            "super_intelligence({}): {} passed/{} failed across {} tiers; failing_tier={}",
            self.domain,
            self.passed_count(),
            self.failed_count(),
            self.tiers.len(),
            failing
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cause {
    pub action_or_event: String,
    pub domain: DomainId,
    pub confidence: f32,
    pub provisional: bool,
    pub provenance: LedgerRef,
}

fn first_failing_tier(tiers: &[TierResult]) -> Option<Tier> {
    Tier::predicate_order().iter().copied().find(|ordered| {
        tiers
            .iter()
            .any(|tier| tier.tier == *ordered && !tier.passed)
    })
}
