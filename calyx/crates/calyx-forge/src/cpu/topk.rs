use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

use crate::cpu::guard::check_finite;
use crate::{ForgeError, Result};

pub fn topk_f32(scores: &[f32], k: usize) -> Result<Vec<(usize, f32)>> {
    if k == 0 || scores.is_empty() {
        return Ok(Vec::new());
    }
    check_finite(scores, "topk")?;

    let capacity = k.min(scores.len());
    let mut heap: BinaryHeap<Reverse<RankedScore>> = BinaryHeap::new();
    heap.try_reserve_exact(capacity)
        .map_err(|error| ForgeError::CapacityExhausted {
            operation: "topk_f32".to_string(),
            detail: format!("top-k heap reserve failed: requested_items={capacity}: {error}"),
            remediation: "Free host memory or reduce the requested top-k breadth".to_string(),
        })?;
    for (index, score) in scores.iter().copied().enumerate() {
        let ranked = RankedScore { index, score };
        if heap.len() < k {
            heap.push(Reverse(ranked));
        } else if heap.peek().is_some_and(|worst| ranked > worst.0) {
            heap.pop();
            heap.push(Reverse(ranked));
        }
    }

    let mut ranked: Vec<_> = heap.into_iter().map(|Reverse(score)| score).collect();
    ranked.sort_by(|left, right| right.cmp(left));
    Ok(ranked
        .into_iter()
        .map(|score| (score.index, score.score))
        .collect())
}

#[derive(Clone, Copy, Debug)]
struct RankedScore {
    index: usize,
    score: f32,
}

impl PartialEq for RankedScore {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && self.score.to_bits() == other.score.to_bits()
    }
}

impl Eq for RankedScore {}

impl PartialOrd for RankedScore {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RankedScore {
    fn cmp(&self, other: &Self) -> Ordering {
        self.score
            .total_cmp(&other.score)
            .then_with(|| other.index.cmp(&self.index))
    }
}
