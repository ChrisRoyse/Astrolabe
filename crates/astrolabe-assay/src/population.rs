//! The typed subject population the scheduler samples over.
//!
//! A [`Population`] is a validated, deterministically ordered set of
//! [`AssaySubject`]s. Order-independence is enforced at construction time: the
//! constructor sorts subjects into a canonical order and rejects duplicate
//! identities, so every downstream computation (fingerprint, stratification,
//! selection) is a pure function of the *set*, never of the order the caller
//! happened to supply. That is the property that makes the sampler
//! worker-count invariant: two callers that assemble the same subjects in
//! different orders — as parallel workers naturally would — build the identical
//! `Population`.

use astrolabe_domain::SeriesId;
use serde::{Deserialize, Serialize};

use crate::error::{ASTRO_ASSAY_DUPLICATE_SUBJECT, ASTRO_ASSAY_EMPTY_STRATUM, AssayError, Result};

/// One subject eligible for assay sampling.
///
/// The subject carries its stable [`SeriesId`], the deterministic stratum label
/// it belongs to, and a 32-byte content fingerprint of the exact input bytes
/// the downstream measurement (KSG MI, #32) will consume. The content
/// fingerprint is what makes the cache invalidate when a symbol's measured
/// input changes even though its identity is stable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssaySubject {
    /// Stable series identity, unique within a population.
    pub series_id: SeriesId,
    /// Deterministic partition label. Two subjects share a stratum iff these are equal.
    pub stratum: String,
    /// 32-byte content fingerprint of the subject's measured input bytes.
    pub content_fingerprint: [u8; 32],
}

impl AssaySubject {
    /// Builds a subject, rejecting an empty stratum label fail-closed.
    pub fn new(
        series_id: SeriesId,
        stratum: impl Into<String>,
        content_fingerprint: [u8; 32],
    ) -> Result<Self> {
        let stratum = stratum.into();
        if stratum.is_empty() {
            return Err(AssayError::new(
                ASTRO_ASSAY_EMPTY_STRATUM,
                format!("subject {series_id} has an empty stratum label"),
                "assign every subject a non-empty deterministic stratum label before sampling",
            ));
        }
        Ok(Self {
            series_id,
            stratum,
            content_fingerprint,
        })
    }
}

/// A validated, canonically ordered subject population.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Population {
    subjects: Vec<AssaySubject>,
}

impl Population {
    /// Builds a population from any subject iterator.
    ///
    /// Subjects are sorted into canonical `(stratum, series_id)` order so the
    /// result is independent of input order. A duplicate `SeriesId` is rejected
    /// fail-closed: identity must be unique or a sampled row is ambiguous.
    pub fn new(subjects: impl IntoIterator<Item = AssaySubject>) -> Result<Self> {
        let mut subjects: Vec<AssaySubject> = subjects.into_iter().collect();
        subjects.sort_by(|a, b| {
            a.stratum
                .cmp(&b.stratum)
                .then_with(|| a.series_id.as_bytes().cmp(b.series_id.as_bytes()))
        });
        for window in subjects.windows(2) {
            if window[0].series_id == window[1].series_id {
                return Err(AssayError::new(
                    ASTRO_ASSAY_DUPLICATE_SUBJECT,
                    format!("duplicate subject identity {}", window[0].series_id),
                    "deduplicate the population so every SeriesId appears at most once",
                ));
            }
        }
        Ok(Self { subjects })
    }

    /// Total number of subjects.
    pub fn len(&self) -> usize {
        self.subjects.len()
    }

    /// Whether the population is empty.
    pub fn is_empty(&self) -> bool {
        self.subjects.is_empty()
    }

    /// The canonically ordered subjects.
    pub fn subjects(&self) -> &[AssaySubject] {
        &self.subjects
    }

    /// The distinct stratum labels present, in ascending order, each paired with
    /// its subject count.
    pub fn strata_sizes(&self) -> Vec<(String, usize)> {
        let mut out: Vec<(String, usize)> = Vec::new();
        for subject in &self.subjects {
            match out.last_mut() {
                Some((label, count)) if *label == subject.stratum => *count += 1,
                _ => out.push((subject.stratum.clone(), 1)),
            }
        }
        out
    }
}
