use crate::quant::{QuantLevel, QuantizedVec, Quantizer, SeedId};
use crate::{ForgeError, Result};

const ZERO_SEED: SeedId = [0; 32];
const INT8_REMEDIATION: &str =
    "Use finite dense vectors, matching dimensions, Bits8 payload bytes, and zero seed_id";

#[derive(Clone, Debug)]
pub struct ScalarInt8Codec {
    dim: usize,
}

impl ScalarInt8Codec {
    pub fn new(dim: usize) -> Self {
        Self { dim }
    }
}

impl Quantizer for ScalarInt8Codec {
    fn encode(&self, vec: &[f32]) -> Result<QuantizedVec> {
        if vec.len() != self.dim {
            return Err(ForgeError::ShapeMismatch {
                expected: vec![self.dim],
                got: vec![vec.len()],
                remediation: "Encode scalar INT8 vectors with the codec dimension".to_string(),
            });
        }
        if let Some(idx) = vec.iter().position(|value| !value.is_finite()) {
            return Err(quant_error(
                "encode",
                format!("non-finite input coefficient at index {idx}"),
            ));
        }
        let max_abs = vec.iter().map(|value| value.abs()).fold(0.0_f32, f32::max);
        let scale = if max_abs == 0.0 { 0.0 } else { max_abs / 127.0 };
        let bytes = if scale == 0.0 {
            vec![0; self.dim]
        } else {
            vec.iter()
                .map(|value| ((*value / scale).round_ties_even()).clamp(-127.0, 127.0) as i8 as u8)
                .collect()
        };
        Ok(QuantizedVec {
            level: QuantLevel::Bits8,
            dim: self.dim,
            bytes,
            scale,
            seed_id: ZERO_SEED,
        })
    }

    fn decode(&self, qv: &QuantizedVec) -> Result<Vec<f32>> {
        validate_quantized(qv, self.dim, "decode")?;
        if qv.scale == 0.0 {
            return Ok(vec![0.0; self.dim]);
        }
        Ok(qv
            .bytes
            .iter()
            .map(|byte| (*byte as i8 as f32) * qv.scale)
            .collect())
    }

    fn dot_estimate(&self, query: &[f32], candidate: &QuantizedVec) -> Result<f32> {
        if query.len() != self.dim {
            return Err(ForgeError::ShapeMismatch {
                expected: vec![self.dim],
                got: vec![query.len()],
                remediation: "Score scalar INT8 vectors with a raw query of the codec dimension"
                    .to_string(),
            });
        }
        if let Some(index) = query.iter().position(|value| !value.is_finite()) {
            return Err(quant_error(
                "dot_estimate",
                format!("non-finite raw query coefficient at index {index}"),
            ));
        }
        validate_quantized(candidate, self.dim, "dot_estimate")?;
        let sum = query
            .iter()
            .zip(&candidate.bytes)
            .map(|(value, code)| {
                f64::from(*value) * f64::from(*code as i8) * f64::from(candidate.scale)
            })
            .sum::<f64>();
        if !sum.is_finite() || sum.abs() > f64::from(f32::MAX) {
            return Err(quant_error(
                "dot_estimate",
                "dot estimate cannot be represented as finite f32",
            ));
        }
        Ok(sum as f32)
    }

    fn level(&self) -> QuantLevel {
        QuantLevel::Bits8
    }

    fn dim(&self) -> usize {
        self.dim
    }
}

fn validate_quantized(qv: &QuantizedVec, dim: usize, op: &str) -> Result<()> {
    if qv.level != QuantLevel::Bits8 {
        return Err(quant_error(
            op,
            format!("ScalarInt8Codec only supports Bits8, got {:?}", qv.level),
        ));
    }
    if qv.dim != dim {
        return Err(ForgeError::ShapeMismatch {
            expected: vec![dim],
            got: vec![qv.dim],
            remediation: "Decode scalar INT8 vectors with the codec dimension".to_string(),
        });
    }
    if qv.bytes.len() != qv.dim {
        return Err(quant_error(
            op,
            format!(
                "encoded byte length mismatch: expected {} got {}",
                qv.dim,
                qv.bytes.len()
            ),
        ));
    }
    if !qv.scale.is_finite() || qv.scale < 0.0 {
        return Err(quant_error(op, "scale must be finite and non-negative"));
    }
    if qv.seed_id != ZERO_SEED {
        return Err(quant_error(op, "scalar INT8 codec expects zero seed_id"));
    }
    if qv.scale == 0.0 && qv.bytes.iter().any(|byte| *byte != 0) {
        return Err(quant_error(
            op,
            "zero scale requires every encoded INT8 code to be zero",
        ));
    }
    Ok(())
}

fn quant_error(op: &str, detail: impl Into<String>) -> ForgeError {
    ForgeError::QuantError {
        op: op.to_string(),
        level: "Bits8".to_string(),
        detail: detail.into(),
        remediation: INT8_REMEDIATION.to_string(),
    }
}
