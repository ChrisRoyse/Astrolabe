use wide::f32x8;

use crate::quant::rotation::{DeterministicNormal, domain_seed};
use crate::quant::{QuantLevel, RotationSeed};
use crate::{ForgeError, Result};

const QJL_DOMAIN: &[u8] = b"calyx/turboquant/qjl-gaussian/v1\0";
const QJL_FACTOR: f64 = 1.253_314_137_315_500_1;
const BIPOLAR_BYTE_LANES: [[f32; 8]; 256] = bipolar_byte_lanes();

#[derive(Clone, Debug, PartialEq)]
/// One-bit Gaussian sketch of a TurboQuant scalar residual.
pub struct QjlResidual {
    /// Canonical little-endian signs, one bit per projected coordinate.
    pub bits: Vec<u8>,
    /// `rho * ||e||_2`, where `e` is the unit-vector scalar residual.
    pub gamma: f32,
}

pub(crate) struct GaussianProjection {
    dim: usize,
    values: Vec<f32>,
}

impl GaussianProjection {
    pub(crate) fn new(seed: &RotationSeed) -> Result<Self> {
        seed.validate()?;
        let count = seed
            .dim
            .checked_mul(seed.dim)
            .ok_or_else(|| qjl_error("setup", "Gaussian matrix size overflow"))?;
        let mut normal = DeterministicNormal::new(domain_seed(QJL_DOMAIN, &seed.id, seed.dim));
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(normal.next_f32());
        }
        Ok(Self {
            dim: seed.dim,
            values,
        })
    }

    pub(crate) fn project(&self, input: &[f32]) -> Result<Vec<f32>> {
        if input.len() != self.dim {
            return Err(ForgeError::ShapeMismatch {
                expected: vec![self.dim],
                got: vec![input.len()],
                remediation: "Project vectors with the codec dimension".to_string(),
            });
        }
        if let Some(index) = input.iter().position(|value| !value.is_finite()) {
            return Err(qjl_error(
                "project",
                format!("non-finite input coefficient at index {index}"),
            ));
        }
        let mut output = Vec::with_capacity(self.dim);
        for (row_index, row) in self.values.chunks_exact(self.dim).enumerate() {
            let value = simd_dot(row, input);
            if !value.is_finite() {
                return Err(qjl_error(
                    "project",
                    format!("Gaussian projection overflowed at row {row_index}"),
                ));
            }
            output.push(value);
        }
        Ok(output)
    }

    pub(crate) fn encode_residual(
        &self,
        residual: &[f32],
        source_norm: f32,
    ) -> Result<QjlResidual> {
        if residual.len() != self.dim {
            return Err(ForgeError::ShapeMismatch {
                expected: vec![self.dim],
                got: vec![residual.len()],
                remediation: "Encode a QJL residual with the codec dimension".to_string(),
            });
        }
        if !source_norm.is_finite() || source_norm <= 0.0 {
            return Err(qjl_error(
                "encode",
                "nonzero QJL residuals require a finite positive source norm",
            ));
        }
        let residual_norm = residual
            .iter()
            .map(|value| f64::from(*value) * f64::from(*value))
            .sum::<f64>()
            .sqrt();
        let gamma_f64 = f64::from(source_norm) * residual_norm;
        if !gamma_f64.is_finite() || gamma_f64 > f64::from(f32::MAX) {
            return Err(qjl_error(
                "encode",
                "scaled residual norm cannot be represented as finite f32",
            ));
        }
        let gamma = gamma_f64 as f32;
        if gamma == 0.0 {
            return Ok(QjlResidual {
                bits: vec![0u8; bitstream_len(self.dim)],
                gamma: 0.0,
            });
        }
        let mut bits = vec![0u8; bitstream_len(self.dim)];
        for (index, row) in self.values.chunks_exact(self.dim).enumerate() {
            let value = simd_dot(row, residual);
            if !value.is_finite() {
                return Err(qjl_error(
                    "encode",
                    format!("Gaussian residual projection overflowed at row {index}"),
                ));
            }
            if value >= 0.0 {
                bits[index / 8] |= 1 << (index % 8);
            }
        }
        Ok(QjlResidual {
            bits,
            gamma,
        })
    }

    pub(crate) fn correction_parts(
        &self,
        projected_query: &[f32],
        bits: &[u8],
        gamma: f32,
    ) -> Result<f32> {
        self.validate_parts(bits, gamma, "score")?;
        if projected_query.len() != self.dim {
            return Err(ForgeError::ShapeMismatch {
                expected: vec![self.dim],
                got: vec![projected_query.len()],
                remediation: "Score with a query prepared by the same codec".to_string(),
            });
        }
        let signed_dot = sign_dot(projected_query, bits);
        let correction = QJL_FACTOR * f64::from(gamma) * signed_dot / self.dim as f64;
        finite_f32(correction, "score", "QJL correction")
    }

    pub(crate) fn inverse_parts(&self, bits: &[u8], gamma: f32) -> Result<Vec<f32>> {
        self.validate_parts(bits, gamma, "decode")?;
        let factor = QJL_FACTOR * f64::from(gamma) / self.dim as f64;
        let mut sums = vec![0.0_f64; self.dim];
        for (row_index, row) in self.values.chunks_exact(self.dim).enumerate() {
            let sign = if read_bit(bits, row_index) {
                1.0_f64
            } else {
                -1.0_f64
            };
            for (sum, value) in sums.iter_mut().zip(row) {
                *sum += f64::from(*value) * sign;
            }
        }
        sums.into_iter()
            .map(|sum| finite_f32(factor * sum, "decode", "QJL inverse coefficient"))
            .collect()
    }

    fn validate_parts(&self, bits: &[u8], gamma: f32, op: &str) -> Result<()> {
        if bits.len() != bitstream_len(self.dim) {
            return Err(qjl_error(
                op,
                format!(
                    "QJL bitstream length mismatch: expected {} got {}",
                    bitstream_len(self.dim),
                    bits.len()
                ),
            ));
        }
        if !gamma.is_finite() || gamma < 0.0 {
            return Err(qjl_error(op, "gamma must be finite and non-negative"));
        }
        if has_nonzero_padding(bits, self.dim) {
            return Err(qjl_error(op, "QJL sign bitstream has non-zero padding"));
        }
        Ok(())
    }
}

pub(crate) fn bitstream_len(dim: usize) -> usize {
    dim.div_ceil(8)
}

pub(crate) fn has_nonzero_padding(bytes: &[u8], bits: usize) -> bool {
    let used_in_last = bits % 8;
    if used_in_last == 0 || bytes.is_empty() {
        return false;
    }
    let mask = !((1u16 << used_in_last) - 1) as u8;
    bytes.last().is_some_and(|last| *last & mask != 0)
}

pub(crate) fn read_bit(bytes: &[u8], index: usize) -> bool {
    ((bytes[index / 8] >> (index % 8)) & 1) != 0
}

fn sign_dot(values: &[f32], bits: &[u8]) -> f64 {
    let mut sum = 0.0_f64;
    let mut base = 0usize;
    for byte in bits {
        let remaining = values.len() - base;
        let lanes = remaining.min(8);
        if lanes == 8 {
            let mut value_lanes = [0.0_f32; 8];
            value_lanes.copy_from_slice(&values[base..base + 8]);
            sum += f64::from(
                (f32x8::from(value_lanes)
                    * f32x8::from(BIPOLAR_BYTE_LANES[usize::from(*byte)]))
                .reduce_add(),
            );
            base += 8;
            continue;
        }
        for lane in 0..lanes {
            let value = f64::from(values[base + lane]);
            sum += if byte & (1 << lane) != 0 {
                value
            } else {
                -value
            };
        }
        base += lanes;
    }
    sum
}

const fn bipolar_byte_lanes() -> [[f32; 8]; 256] {
    let mut table = [[-1.0_f32; 8]; 256];
    let mut byte = 0usize;
    while byte < table.len() {
        let mut lane = 0usize;
        while lane < 8 {
            if byte & (1usize << lane) != 0 {
                table[byte][lane] = 1.0;
            }
            lane += 1;
        }
        byte += 1;
    }
    table
}

fn simd_dot(left: &[f32], right: &[f32]) -> f32 {
    let mut sum = 0.0_f32;
    let mut offset = 0usize;
    while offset + 8 <= left.len() {
        let mut lhs = [0.0; 8];
        let mut rhs = [0.0; 8];
        lhs.copy_from_slice(&left[offset..offset + 8]);
        rhs.copy_from_slice(&right[offset..offset + 8]);
        sum += (f32x8::from(lhs) * f32x8::from(rhs)).reduce_add();
        offset += 8;
    }
    while offset < left.len() {
        sum += left[offset] * right[offset];
        offset += 1;
    }
    sum
}

fn finite_f32(value: f64, op: &str, subject: &str) -> Result<f32> {
    if !value.is_finite() || value.abs() > f64::from(f32::MAX) {
        return Err(qjl_error(
            op,
            format!("{subject} cannot be represented as finite f32"),
        ));
    }
    Ok(value as f32)
}

fn qjl_error(op: &str, detail: impl Into<String>) -> ForgeError {
    ForgeError::QuantError {
        op: format!("qjl_{op}"),
        level: QuantLevel::Bits3p5.to_string(),
        detail: detail.into(),
        remediation:
            "Use the exact current TurboQuant payload, seed geometry, and finite query vector"
                .to_string(),
    }
}
