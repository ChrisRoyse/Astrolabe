use std::collections::{BTreeMap, BTreeSet};

use calyx_core::CxId;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub(crate) struct IrMetrics {
    pub(crate) ndcg_at_k: f64,
    pub(crate) recall_at_k: f64,
    pub(crate) mrr: f64,
}

impl IrMetrics {
    pub(crate) fn add(self, other: Self) -> Self {
        Self {
            ndcg_at_k: self.ndcg_at_k + other.ndcg_at_k,
            recall_at_k: self.recall_at_k + other.recall_at_k,
            mrr: self.mrr + other.mrr,
        }
    }

    pub(crate) fn div(self, denominator: f64) -> Self {
        Self {
            ndcg_at_k: self.ndcg_at_k / denominator,
            recall_at_k: self.recall_at_k / denominator,
            mrr: self.mrr / denominator,
        }
    }
}

pub(crate) fn ranking_metrics(
    ranking: &[CxId],
    relevant: &BTreeMap<CxId, u32>,
    k: usize,
) -> IrMetrics {
    if relevant.is_empty() {
        return IrMetrics::default();
    }
    let cutoff = ranking.len().min(k);
    let mut seen_relevant = BTreeSet::new();
    let mut dcg = 0.0;
    let mut first_relevant_rank = None;
    for (idx, cx_id) in ranking.iter().take(cutoff).enumerate() {
        let rank = idx + 1;
        if let Some(&rel) = relevant.get(cx_id) {
            seen_relevant.insert(*cx_id);
            dcg += gain(rel) / discount(rank);
            first_relevant_rank.get_or_insert(rank);
        }
    }
    let mut ideal = relevant.values().copied().collect::<Vec<_>>();
    ideal.sort_by(|a, b| b.cmp(a));
    let idcg = ideal
        .into_iter()
        .take(k)
        .enumerate()
        .map(|(idx, rel)| gain(rel) / discount(idx + 1))
        .sum::<f64>();
    let relevant_at_k = seen_relevant.len() as f64;
    IrMetrics {
        ndcg_at_k: if idcg > 0.0 { dcg / idcg } else { 0.0 },
        recall_at_k: relevant_at_k / relevant.len() as f64,
        mrr: first_relevant_rank.map_or(0.0, |rank| 1.0 / rank as f64),
    }
}

fn gain(relevance: u32) -> f64 {
    2_f64.powi(relevance as i32) - 1.0
}

fn discount(rank: usize) -> f64 {
    ((rank + 1) as f64).log2()
}

