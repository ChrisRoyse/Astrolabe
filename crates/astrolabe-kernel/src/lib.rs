#![forbid(unsafe_code)]

use std::str::FromStr;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
pub const SEARCH_SCALE_SCHEMA: &str = "astrolabe.search_scale_plan.v1";
pub const SEARCH_SCALE_KNOB_REGISTRY_VERSION: &str = "astro.kernel.search_scale_knobs.v1";
pub const FUNNEL_ACTIVATION_RECORDS_KNOB: &str = "search.funnel.activation_records";
pub const ASTRO_SEARCH_INDEX_BUDGET_EXCEEDED: &str = "ASTRO_SEARCH_INDEX_BUDGET_EXCEEDED";
pub const DEFAULT_FUNNEL_ACTIVATION_RECORDS: u64 = 10_000_000;
pub const MIN_FUNNEL_ACTIVATION_RECORDS: u64 = 1_000;
pub const MAX_FUNNEL_ACTIVATION_RECORDS: u64 = 1_000_000_000;

pub fn parent_system() -> astrolabe_domain::ParentSystem {
    astrolabe_domain::ParentSystem::Calyx
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct U64KnobDeclaration {
    pub registry_version: &'static str,
    pub name: &'static str,
    pub default: u64,
    pub min: u64,
    pub max: u64,
    pub unit: &'static str,
    pub source: &'static str,
    pub rationale: &'static str,
}

pub const SEARCH_SCALE_KNOBS: &[U64KnobDeclaration] = &[U64KnobDeclaration {
    registry_version: SEARCH_SCALE_KNOB_REGISTRY_VERSION,
    name: FUNNEL_ACTIVATION_RECORDS_KNOB,
    default: DEFAULT_FUNNEL_ACTIVATION_RECORDS,
    min: MIN_FUNNEL_ACTIVATION_RECORDS,
    max: MAX_FUNNEL_ACTIVATION_RECORDS,
    unit: "records",
    source: "docs/astrolabe-blueprint.md#12-search-unification",
    rationale: "activate kernel-first funnel above the documented giant-monorepo threshold; tune later from replay/bench evidence",
}];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SearchIndexBackend {
    InMemoryHnsw,
    DiskAnn,
    Spann,
}

impl SearchIndexBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InMemoryHnsw => "in_memory_hnsw",
            Self::DiskAnn => "diskann",
            Self::Spann => "spann",
        }
    }

    pub fn is_disk_backed(self) -> bool {
        matches!(self, Self::DiskAnn | Self::Spann)
    }
}

impl FromStr for SearchIndexBackend {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "in_memory_hnsw" => Ok(Self::InMemoryHnsw),
            "diskann" => Ok(Self::DiskAnn),
            "spann" => Ok(Self::Spann),
            _ => Err("unknown search index backend"),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SearchFunnelMode {
    Direct,
    KernelFirst,
}

impl SearchFunnelMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::KernelFirst => "kernel_first",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SearchScaleConfig {
    pub total_records: u64,
    pub funnel_activation_records: u64,
    pub index_backend: SearchIndexBackend,
    pub estimated_index_rss_bytes: u64,
    pub master_budget_bytes: u64,
}

impl SearchScaleConfig {
    pub fn with_registry_defaults(
        total_records: u64,
        estimated_index_rss_bytes: u64,
        master_budget_bytes: u64,
    ) -> Self {
        Self {
            total_records,
            funnel_activation_records: DEFAULT_FUNNEL_ACTIVATION_RECORDS,
            index_backend: SearchIndexBackend::InMemoryHnsw,
            estimated_index_rss_bytes,
            master_budget_bytes,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SearchScalePlan {
    pub schema: &'static str,
    pub knob_registry_version: &'static str,
    pub total_records: u64,
    pub funnel_activation_records: u64,
    pub funnel_mode: SearchFunnelMode,
    pub activation_label: String,
    pub index_backend: SearchIndexBackend,
    pub index_backend_label: String,
    pub estimated_index_rss_bytes: u64,
    pub master_budget_bytes: u64,
    pub freshness: &'static str,
    pub trust: &'static str,
}

pub fn plan_search_scale(config: &SearchScaleConfig) -> astrolabe_domain::Result<SearchScalePlan> {
    validate_funnel_threshold(config.funnel_activation_records)?;
    validate_ram_budget(config)?;

    let funnel_mode = if config.total_records > config.funnel_activation_records {
        SearchFunnelMode::KernelFirst
    } else {
        SearchFunnelMode::Direct
    };
    Ok(SearchScalePlan {
        schema: SEARCH_SCALE_SCHEMA,
        knob_registry_version: SEARCH_SCALE_KNOB_REGISTRY_VERSION,
        total_records: config.total_records,
        funnel_activation_records: config.funnel_activation_records,
        funnel_mode,
        activation_label: format!(
            "funnel={} because total_records={} and {}={}",
            funnel_mode.as_str(),
            config.total_records,
            FUNNEL_ACTIVATION_RECORDS_KNOB,
            config.funnel_activation_records
        ),
        index_backend: config.index_backend,
        index_backend_label: format!(
            "index_backend={}{}",
            config.index_backend.as_str(),
            if config.index_backend.is_disk_backed() {
                " (operator opt-in)"
            } else {
                " (default)"
            }
        ),
        estimated_index_rss_bytes: config.estimated_index_rss_bytes,
        master_budget_bytes: config.master_budget_bytes,
        freshness: "fresh",
        trust: "verified",
    })
}

fn validate_funnel_threshold(value: u64) -> astrolabe_domain::Result<()> {
    let knob = SEARCH_SCALE_KNOBS
        .iter()
        .find(|knob| knob.name == FUNNEL_ACTIVATION_RECORDS_KNOB)
        .expect("funnel threshold knob is declared");
    if value < knob.min || value > knob.max {
        return Err(astrolabe_domain::DomainError::new(
            "ASTRO_SEARCH_SCALE_KNOB_RANGE",
            format!(
                "{}={} is outside declared bounds {}..={}",
                knob.name, value, knob.min, knob.max
            ),
            "set the search funnel activation threshold through the registered knob bounds",
        ));
    }
    Ok(())
}

fn validate_ram_budget(config: &SearchScaleConfig) -> astrolabe_domain::Result<()> {
    if config.estimated_index_rss_bytes <= config.master_budget_bytes {
        return Ok(());
    }
    Err(astrolabe_domain::DomainError::new(
        ASTRO_SEARCH_INDEX_BUDGET_EXCEEDED,
        format!(
            "estimated per-slot index RSS {} bytes exceeds master budget {} bytes for backend {}",
            config.estimated_index_rss_bytes,
            config.master_budget_bytes,
            config.index_backend.as_str()
        ),
        "enable diskann/spann indexes, opt out high-cost slots, or increase the configured CBM master memory budget before loading the index",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_calyx_parent() {
        assert_eq!(parent_system(), astrolabe_domain::ParentSystem::Calyx);
    }

    #[test]
    fn funnel_threshold_is_registry_declared_with_bounds() {
        let knob = SEARCH_SCALE_KNOBS
            .iter()
            .find(|knob| knob.name == FUNNEL_ACTIVATION_RECORDS_KNOB)
            .expect("funnel threshold knob");
        assert_eq!(knob.registry_version, SEARCH_SCALE_KNOB_REGISTRY_VERSION);
        assert_eq!(knob.default, DEFAULT_FUNNEL_ACTIVATION_RECORDS);
        assert_eq!(knob.default, 10_000_000);
        assert!(knob.min < knob.default);
        assert!(knob.default < knob.max);
        assert_eq!(knob.unit, "records");
    }

    #[test]
    fn funnel_activation_is_labeled_and_uses_strict_threshold() {
        let direct = plan_search_scale(&SearchScaleConfig::with_registry_defaults(
            DEFAULT_FUNNEL_ACTIVATION_RECORDS,
            1024,
            2048,
        ))
        .expect("direct plan");
        assert_eq!(direct.funnel_mode, SearchFunnelMode::Direct);
        assert!(direct.activation_label.contains("funnel=direct"));
        assert!(
            direct
                .activation_label
                .contains(FUNNEL_ACTIVATION_RECORDS_KNOB)
        );
        assert_eq!(direct.trust, "verified");

        let funnel = plan_search_scale(&SearchScaleConfig::with_registry_defaults(
            DEFAULT_FUNNEL_ACTIVATION_RECORDS + 1,
            1024,
            2048,
        ))
        .expect("funnel plan");
        assert_eq!(funnel.funnel_mode, SearchFunnelMode::KernelFirst);
        assert!(funnel.activation_label.contains("funnel=kernel_first"));
        assert!(funnel.activation_label.contains("total_records=10000001"));
    }

    #[test]
    fn disk_backends_round_trip_through_config_strings() {
        for backend in [
            SearchIndexBackend::InMemoryHnsw,
            SearchIndexBackend::DiskAnn,
            SearchIndexBackend::Spann,
        ] {
            assert_eq!(backend.as_str().parse::<SearchIndexBackend>(), Ok(backend));
        }
        assert!("flat_scan".parse::<SearchIndexBackend>().is_err());

        let mut config = SearchScaleConfig::with_registry_defaults(20_000_000, 1024, 2048);
        config.index_backend = "diskann".parse().expect("parse diskann");
        let plan = plan_search_scale(&config).expect("diskann plan");
        assert_eq!(plan.index_backend, SearchIndexBackend::DiskAnn);
        assert!(plan.index_backend_label.contains("operator opt-in"));
    }

    #[test]
    fn over_budget_index_load_fails_closed_before_allocation() {
        let err = plan_search_scale(&SearchScaleConfig::with_registry_defaults(1, 4096, 1024))
            .expect_err("over budget index load refused");
        assert_eq!(err.code(), ASTRO_SEARCH_INDEX_BUDGET_EXCEEDED);
        assert!(err.message().contains("exceeds master budget"));
        assert!(err.remediation().contains("enable diskann/spann"));
    }

    #[test]
    fn out_of_range_knob_is_refused_with_remediation() {
        let mut config = SearchScaleConfig::with_registry_defaults(1, 1024, 2048);
        config.funnel_activation_records = MIN_FUNNEL_ACTIVATION_RECORDS - 1;
        let err = plan_search_scale(&config).expect_err("invalid threshold refused");
        assert_eq!(err.code(), "ASTRO_SEARCH_SCALE_KNOB_RANGE");
        assert!(err.message().contains(FUNNEL_ACTIVATION_RECORDS_KNOB));
        assert!(err.remediation().contains("registered knob bounds"));
    }
}
