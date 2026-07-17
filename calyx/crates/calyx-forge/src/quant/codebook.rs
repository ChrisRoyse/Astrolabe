use std::collections::BTreeMap;
use std::sync::{OnceLock, RwLock};

use crate::quant::QuantLevel;
use crate::{ForgeError, Result};

const QUADRATURE_POINTS: usize = 32_768;
const MAX_LLOYD_ITERATIONS: usize = 256;
const CONVERGENCE: f64 = 1.0e-13;
static CODEBOOK_CACHE: OnceLock<RwLock<BTreeMap<(usize, usize), Vec<f32>>>> = OnceLock::new();

pub(crate) struct LloydMaxCodebook {
    dim: usize,
    bits: usize,
    centroids: Vec<f32>,
}

impl LloydMaxCodebook {
    pub(crate) fn new(dim: usize, bits: usize, level: QuantLevel) -> Result<Self> {
        if dim == 0 || !(1..=3).contains(&bits) {
            return Err(codebook_error(
                level,
                format!("invalid Lloyd-Max geometry dim={dim} bits={bits}"),
            ));
        }
        if let Some(centroids) = cached_centroids(dim, bits, level)? {
            return Ok(Self {
                dim,
                bits,
                centroids,
            });
        }
        let levels = 1usize << bits;
        if dim == 1 {
            let half = levels / 2;
            let centroids = (0..levels)
                .map(|index| if index < half { -1.0 } else { 1.0 })
                .collect::<Vec<f32>>();
            cache_centroids(dim, bits, &centroids, level)?;
            return Ok(Self {
                dim,
                bits,
                centroids,
            });
        }

        // x = sin(theta) converts the endpoint-singular sphere density into
        // the smooth weight cos(theta)^(dim-2) on [-pi/2, pi/2].
        let exponent = dim as f64 - 2.0;
        let step = std::f64::consts::PI / QUADRATURE_POINTS as f64;
        let mut points = Vec::new();
        let mut log_weights = Vec::new();
        points
            .try_reserve_exact(QUADRATURE_POINTS)
            .map_err(|error| {
                codebook_error(level, format!("cannot allocate quadrature points: {error}"))
            })?;
        log_weights
            .try_reserve_exact(QUADRATURE_POINTS)
            .map_err(|error| {
                codebook_error(
                    level,
                    format!("cannot allocate quadrature weights: {error}"),
                )
            })?;
        let mut max_log_weight = f64::NEG_INFINITY;
        for index in 0..QUADRATURE_POINTS {
            let theta = -std::f64::consts::FRAC_PI_2 + (index as f64 + 0.5) * step;
            let point = theta.sin();
            let log_weight = exponent * theta.cos().ln();
            max_log_weight = max_log_weight.max(log_weight);
            points.push(point);
            log_weights.push(log_weight);
        }
        let weights = log_weights
            .into_iter()
            .map(|weight| (weight - max_log_weight).exp())
            .collect::<Vec<_>>();
        let total_weight = weights.iter().sum::<f64>();
        if !total_weight.is_finite() || total_weight <= 0.0 {
            return Err(codebook_error(
                level,
                "sphere-density quadrature has zero mass",
            ));
        }

        let mut centroids = equal_mass_initializers(&points, &weights, total_weight, levels);
        let mut converged = false;
        for _ in 0..MAX_LLOYD_ITERATIONS {
            let mut weighted_sum = vec![0.0_f64; levels];
            let mut mass = vec![0.0_f64; levels];
            let mut region = 0usize;
            for (&point, &weight) in points.iter().zip(&weights) {
                while region + 1 < levels
                    && point > (centroids[region] + centroids[region + 1]) * 0.5
                {
                    region += 1;
                }
                weighted_sum[region] += point * weight;
                mass[region] += weight;
            }
            if let Some(index) = mass
                .iter()
                .position(|value| *value == 0.0 || !value.is_finite())
            {
                return Err(codebook_error(
                    level,
                    format!("empty Lloyd-Max decision region at index {index}"),
                ));
            }
            let next = weighted_sum
                .iter()
                .zip(&mass)
                .map(|(sum, weight)| sum / weight)
                .collect::<Vec<_>>();
            let delta = next
                .iter()
                .zip(&centroids)
                .map(|(next, prior)| (next - prior).abs())
                .fold(0.0_f64, f64::max);
            centroids = next;
            if delta <= CONVERGENCE {
                converged = true;
                break;
            }
        }
        if !converged {
            return Err(codebook_error(
                level,
                format!("Lloyd-Max solver did not converge in {MAX_LLOYD_ITERATIONS} iterations"),
            ));
        }

        for index in 0..levels / 2 {
            let magnitude = (centroids[levels - 1 - index] - centroids[index]) * 0.5;
            centroids[index] = -magnitude;
            centroids[levels - 1 - index] = magnitude;
        }
        let centroids = centroids
            .into_iter()
            .map(|value| value as f32)
            .collect::<Vec<f32>>();
        cache_centroids(dim, bits, &centroids, level)?;
        Ok(Self {
            dim,
            bits,
            centroids,
        })
    }

    /// Reconstructs the exact Lloyd-Max solver used by persisted TQPR-v1 rows.
    ///
    /// The v1 solver integrated directly in coordinate space. Current rows use
    /// the endpoint-stable angular quadrature above, so migration must retain
    /// this implementation instead of silently interpreting old codes with new
    /// centroids.
    pub(crate) fn new_legacy_v1(dim: usize, bits: usize, level: QuantLevel) -> Result<Self> {
        if dim == 0 || !(1..=3).contains(&bits) {
            return Err(codebook_error(
                level,
                format!("invalid legacy Lloyd-Max geometry dim={dim} bits={bits}"),
            ));
        }
        let levels = 1usize << bits;
        if dim == 1 {
            let half = levels / 2;
            let centroids = (0..levels)
                .map(|index| if index < half { -1.0 } else { 1.0 })
                .collect();
            return Ok(Self {
                dim,
                bits,
                centroids,
            });
        }

        let alpha = (dim as f64 - 3.0) * 0.5;
        let step = 2.0 / QUADRATURE_POINTS as f64;
        let mut points = Vec::with_capacity(QUADRATURE_POINTS);
        let mut log_weights = Vec::with_capacity(QUADRATURE_POINTS);
        let mut max_log_weight = f64::NEG_INFINITY;
        for index in 0..QUADRATURE_POINTS {
            let point = -1.0 + (index as f64 + 0.5) * step;
            let log_weight = alpha * (1.0 - point * point).ln();
            max_log_weight = max_log_weight.max(log_weight);
            points.push(point);
            log_weights.push(log_weight);
        }
        let weights = log_weights
            .into_iter()
            .map(|weight| (weight - max_log_weight).exp())
            .collect::<Vec<_>>();
        let total_weight = weights.iter().sum::<f64>();
        if !total_weight.is_finite() || total_weight <= 0.0 {
            return Err(codebook_error(
                level,
                "legacy sphere-density quadrature has zero mass",
            ));
        }

        let mut centroids = equal_mass_initializers(&points, &weights, total_weight, levels);
        let mut converged = false;
        for _ in 0..MAX_LLOYD_ITERATIONS {
            let mut weighted_sum = vec![0.0_f64; levels];
            let mut mass = vec![0.0_f64; levels];
            let mut region = 0usize;
            for (&point, &weight) in points.iter().zip(&weights) {
                while region + 1 < levels
                    && point > (centroids[region] + centroids[region + 1]) * 0.5
                {
                    region += 1;
                }
                weighted_sum[region] += point * weight;
                mass[region] += weight;
            }
            if let Some(index) = mass
                .iter()
                .position(|value| *value == 0.0 || !value.is_finite())
            {
                return Err(codebook_error(
                    level,
                    format!("empty legacy Lloyd-Max decision region at index {index}"),
                ));
            }
            let next = weighted_sum
                .iter()
                .zip(&mass)
                .map(|(sum, mass)| sum / mass)
                .collect::<Vec<_>>();
            let delta = next
                .iter()
                .zip(&centroids)
                .map(|(next, current)| (next - current).abs())
                .fold(0.0_f64, f64::max);
            centroids = next;
            if delta <= CONVERGENCE {
                converged = true;
                break;
            }
        }
        if !converged {
            return Err(codebook_error(
                level,
                format!(
                    "legacy Lloyd-Max solver did not converge in {MAX_LLOYD_ITERATIONS} iterations"
                ),
            ));
        }

        for index in 0..levels / 2 {
            let magnitude = (centroids[levels - 1 - index] - centroids[index]) * 0.5;
            centroids[index] = -magnitude;
            centroids[levels - 1 - index] = magnitude;
        }
        Ok(Self {
            dim,
            bits,
            centroids: centroids.into_iter().map(|value| value as f32).collect(),
        })
    }

    pub(crate) fn bits(&self) -> usize {
        self.bits
    }

    pub(crate) fn quantize(&self, value: f32) -> u8 {
        let mut best_index = 0usize;
        let mut best_distance = f32::INFINITY;
        for (index, centroid) in self.centroids.iter().enumerate() {
            let distance = (value - *centroid).abs();
            if distance < best_distance {
                best_distance = distance;
                best_index = index;
            }
        }
        best_index as u8
    }

    pub(crate) fn centroid(&self, code: u8) -> Option<f32> {
        self.centroids.get(usize::from(code)).copied()
    }

    pub(crate) fn is_canonical_code(&self, code: u8) -> bool {
        self.dim != 1 || code == 0 || usize::from(code) == self.centroids.len() / 2
    }

    pub(crate) fn centroids(&self) -> &[f32] {
        &self.centroids
    }
}

fn cached_centroids(dim: usize, bits: usize, level: QuantLevel) -> Result<Option<Vec<f32>>> {
    let cache = CODEBOOK_CACHE.get_or_init(|| RwLock::new(BTreeMap::new()));
    let guard = cache
        .read()
        .map_err(|_| codebook_error(level, "codebook cache read lock poisoned"))?;
    Ok(guard.get(&(dim, bits)).cloned())
}

fn cache_centroids(dim: usize, bits: usize, centroids: &[f32], level: QuantLevel) -> Result<()> {
    let cache = CODEBOOK_CACHE.get_or_init(|| RwLock::new(BTreeMap::new()));
    let mut guard = cache
        .write()
        .map_err(|_| codebook_error(level, "codebook cache write lock poisoned"))?;
    guard
        .entry((dim, bits))
        .or_insert_with(|| centroids.to_vec());
    Ok(())
}

fn equal_mass_initializers(
    points: &[f64],
    weights: &[f64],
    total_weight: f64,
    levels: usize,
) -> Vec<f64> {
    let mut centroids = Vec::with_capacity(levels);
    let mut cumulative = 0.0_f64;
    let mut point_index = 0usize;
    for level in 0..levels {
        let target = total_weight * (level as f64 + 0.5) / levels as f64;
        while point_index + 1 < points.len() && cumulative + weights[point_index] < target {
            cumulative += weights[point_index];
            point_index += 1;
        }
        centroids.push(points[point_index]);
    }
    centroids
}

fn codebook_error(level: QuantLevel, detail: impl Into<String>) -> ForgeError {
    ForgeError::QuantError {
        op: "lloyd_max_setup".to_string(),
        level: level.to_string(),
        detail: detail.into(),
        remediation: "Use a supported TurboQuant level and dimension in 1..=4096".to_string(),
    }
}
