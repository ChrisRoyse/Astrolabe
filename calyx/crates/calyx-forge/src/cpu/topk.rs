use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;

use crate::Result;
use crate::cpu::guard::check_finite;

pub fn topk_f32(scores: &[f32], k: usize) -> Result<Vec<(usize, f32)>> {
    if k == 0 || scores.is_empty() {
        return Ok(Vec::new());
    }
    check_finite(scores, "topk")?;

    let mut heap: BinaryHeap<Reverse<RankedScore>> = BinaryHeap::with_capacity(k.min(scores.len()));
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
