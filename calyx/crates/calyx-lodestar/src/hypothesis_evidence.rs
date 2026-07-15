//! Deterministic bridge from chain-walk hypotheses to evaluator inputs.

use std::collections::{BTreeMap, BTreeSet};

use calyx_core::CxId;

use crate::{
    AbcHypothesis, ChainWalkReport, HypothesisEvaluationInput, LodestarError, Result,
    RetrievedEvidence,
};

pub const HYPOTHESIS_EVIDENCE_ASSEMBLER_VERSION: u32 = 1;

#[derive(Clone, Debug, PartialEq)]
pub struct EvidenceSource {
    pub cx_id: CxId,
    pub title: String,
    pub abstract_text: String,
    pub grounding_confidence: f32,
    pub provenance: Vec<String>,
}

pub fn chain_report_evidence_cx_ids(report: &ChainWalkReport) -> Vec<CxId> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for result in &report.results {
        for hypothesis in &result.hypotheses {
            for cx_id in hypothesis_evidence_cx_ids(hypothesis) {
                if seen.insert(cx_id) {
                    out.push(cx_id);
                }
            }
        }
    }
    out
}

pub fn hypothesis_evidence_cx_ids(hypothesis: &AbcHypothesis) -> Vec<CxId> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for cx_id in [hypothesis.a, hypothesis.b, hypothesis.c] {
        if seen.insert(cx_id) {
            out.push(cx_id);
        }
    }
    for cx_id in &hypothesis.terminal_path {
        if seen.insert(*cx_id) {
            out.push(*cx_id);
        }
    }
    out
}

pub fn assemble_hypothesis_evaluation_inputs(
    report: &ChainWalkReport,
    sources: &BTreeMap<CxId, EvidenceSource>,
) -> Result<Vec<HypothesisEvaluationInput>> {
    let mut inputs = Vec::new();
    for result in &report.results {
        for (index, hypothesis) in result.hypotheses.iter().enumerate() {
            inputs.push(assemble_one(hypothesis, index + 1, sources)?);
        }
    }
    if inputs.is_empty() {
        return Err(LodestarError::HypothesisEvidenceInvalid {
            detail: "chain-walk report contained no hypotheses to assemble".to_string(),
        });
    }
    Ok(inputs)
}

fn assemble_one(
    hypothesis: &AbcHypothesis,
    one_based_index: usize,
    sources: &BTreeMap<CxId, EvidenceSource>,
) -> Result<HypothesisEvaluationInput> {
    if !score_is_valid(hypothesis.terminal_confidence) {
        return Err(LodestarError::HypothesisEvidenceInvalid {
            detail: format!(
                "hypothesis {} terminal_confidence must be finite and in [0,1]",
                hypothesis.seed_id
            ),
        });
    }
    let hypothesis_id = format!("{}::{one_based_index:02}", hypothesis.seed_id);
    let mut retrieved_evidence = Vec::new();
    for (index, cx_id) in hypothesis_evidence_cx_ids(hypothesis)
        .into_iter()
        .enumerate()
    {
        let source = sources
            .get(&cx_id)
            .ok_or(LodestarError::HypothesisEvidenceMissingProvenance { cx_id })?;
        validate_source(source)?;
        retrieved_evidence.push(RetrievedEvidence {
            evidence_id: format!("{hypothesis_id}::evidence::{:02}", index + 1),
            source_cx_id: source.cx_id,
            title: source.title.clone(),
            abstract_text: source.abstract_text.clone(),
            grounding_confidence: source.grounding_confidence,
            provenance: source.provenance.clone(),
        });
    }
    let mut chain_provenance = hypothesis.provenance.clone();
    chain_provenance.push(format!(
        "hypothesis_evidence_assembler_schema={HYPOTHESIS_EVIDENCE_ASSEMBLER_VERSION}"
    ));
    chain_provenance.push(format!(
        "retrieved_evidence_count={}",
        retrieved_evidence.len()
    ));
    Ok(HypothesisEvaluationInput {
        hypothesis_id,
        a: hypothesis.a,
        b: hypothesis.b,
        c: hypothesis.c,
        claim: hypothesis.testable_claim.clone(),
        grounded_confidence: hypothesis.terminal_confidence,
        chain_provenance,
        retrieved_evidence,
        evaluator_runs: Vec::new(),
    })
}

fn validate_source(source: &EvidenceSource) -> Result<()> {
    if source.title.trim().is_empty() {
        return Err(LodestarError::HypothesisEvidenceInvalid {
            detail: format!("evidence title for {} must not be empty", source.cx_id),
        });
    }
    if source.abstract_text.trim().is_empty() {
        return Err(LodestarError::HypothesisEvidenceEmptyAbstract {
            cx_id: source.cx_id,
        });
    }
    if !score_is_valid(source.grounding_confidence) {
        return Err(LodestarError::HypothesisEvidenceInvalid {
            detail: format!(
                "evidence grounding_confidence for {} must be finite and in [0,1]",
                source.cx_id
            ),
        });
    }
    if !source
        .provenance
        .iter()
        .any(|entry| entry.starts_with("source_sha256="))
    {
        return Err(LodestarError::HypothesisEvidenceMissingProvenance {
            cx_id: source.cx_id,
        });
    }
    Ok(())
}

fn score_is_valid(score: f32) -> bool {
    score.is_finite() && (0.0..=1.0).contains(&score)
}
