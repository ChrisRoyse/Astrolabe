use std::path::Path;

use calyx_core::Result;
use rayon::prelude::*;

use crate::error::{CALYX_INDEX_CORRUPT, sextant_error};
use crate::index::{SpannCentroidIndex, build_centroids};

use super::assignment::{AssignmentRegion, read_ids};
use super::{IDX_MIX, PartitionDistanceMetric, VectorSource, normalize};

const MAX_RECLUSTER_DEPTH: usize = 4;
const MAX_SPLIT_SAMPLE: usize = 50_000;

/// Balance persisted provisional assignment files and return final routing
/// centroids. This is the production path: it reads one region assignment file at
/// a time and computes split centroids from the real vector source.
pub(super) fn balance_region_files(
    root: &Path,
    initial: &SpannCentroidIndex,
    regions: &[AssignmentRegion],
    source: &dyn VectorSource,
    seed: u64,
    cap: usize,
    distance_metric: PartitionDistanceMetric,
) -> Result<Vec<Vec<f32>>> {
    let initial_centroids = initial.centroids();
    let balanced: Vec<Vec<Vec<f32>>> = regions
        .par_iter()
        .map(|region| -> Result<Vec<Vec<f32>>> {
            let members = read_ids(&root.join(&region.ids_rel))?;
            if members.len() != region.count {
                return Err(sextant_error(
                    CALYX_INDEX_CORRUPT,
                    format!(
                        "provisional region {} ids count {} != assignment count {}",
                        region.id,
                        members.len(),
                        region.count
                    ),
                ));
            }
            if members.is_empty() {
                return Ok(Vec::new());
            }
            if members.len() <= cap {
                let Some(centroid) = initial_centroids.get(region.id as usize) else {
                    return Err(sextant_error(
                        CALYX_INDEX_CORRUPT,
                        format!("missing initial centroid {}", region.id),
                    ));
                };
                return Ok(vec![centroid.clone()]);
            }
            split_oversized(
                &members,
                source,
                seed,
                cap,
                region.id as u64,
                0,
                distance_metric,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(balanced.into_iter().flatten().collect())
}

fn split_oversized(
    members: &[u64],
    source: &dyn VectorSource,
    seed: u64,
    cap: usize,
    salt: u64,
    depth: usize,
    distance_metric: PartitionDistanceMetric,
) -> Result<Vec<Vec<f32>>> {
    if members.len() <= cap {
        return Ok(vec![centroid_for_source_members(
            members,
            source,
            distance_metric,
        )]);
    }
    if depth >= MAX_RECLUSTER_DEPTH {
        return Ok(chunk_centroids_by_cap(
            members,
            source,
            cap,
            distance_metric,
        ));
    }
    let sample = sample_rows(members, source);
    let k_sub = members.len().div_ceil(cap).max(2).min(sample.len().max(1));
    let sub = build_centroids(&sample, k_sub, seed ^ salt.wrapping_mul(IDX_MIX));
    let mut sub_buckets: Vec<Vec<u64>> = vec![Vec::new(); sub.centroid_count()];
    for &idx in members {
        let row = source.row(idx);
        sub_buckets[sub.assign(&row)? as usize].push(idx);
    }
    let largest = sub_buckets.iter().map(Vec::len).max().unwrap_or(0);
    if largest >= members.len() {
        return Ok(chunk_centroids_by_cap(
            members,
            source,
            cap,
            distance_metric,
        ));
    }
    let mut out = Vec::new();
    for (sub_idx, bucket) in sub_buckets.into_iter().enumerate() {
        if bucket.is_empty() {
            continue;
        }
        if bucket.len() <= cap {
            out.push(sub.centroids()[sub_idx].clone());
        } else {
            out.extend(split_oversized(
                &bucket,
                source,
                seed,
                cap,
                salt ^ (sub_idx as u64).wrapping_mul(IDX_MIX),
                depth + 1,
                distance_metric,
            )?);
        }
    }
    Ok(out)
}

fn sample_rows(members: &[u64], source: &dyn VectorSource) -> Vec<(u32, Vec<f32>)> {
    let sample_len = members.len().clamp(1, MAX_SPLIT_SAMPLE);
    let stride = members.len().div_ceil(sample_len).max(1);
    members
        .iter()
        .step_by(stride)
        .take(sample_len)
        .enumerate()
        .map(|(i, &idx)| (i as u32, source.row(idx)))
        .collect()
}

fn chunk_centroids_by_cap(
    members: &[u64],
    source: &dyn VectorSource,
    cap: usize,
    distance_metric: PartitionDistanceMetric,
) -> Vec<Vec<f32>> {
    members
        .chunks(cap.max(1))
        .map(|chunk| centroid_for_source_members(chunk, source, distance_metric))
        .collect()
}

fn centroid_for_source_members(
    members: &[u64],
    source: &dyn VectorSource,
    distance_metric: PartitionDistanceMetric,
) -> Vec<f32> {
    let dim = source.dim();
    let mut center = vec![0.0; dim];
    for &idx in members {
        let row = source.row(idx);
        for (c, v) in center.iter_mut().zip(row) {
            *c += v;
        }
    }
    let inv = 1.0 / members.len().max(1) as f32;
    for value in &mut center {
        *value *= inv;
    }
    if distance_metric == PartitionDistanceMetric::UnitL2 {
        normalize(&mut center);
    }
    center
}
