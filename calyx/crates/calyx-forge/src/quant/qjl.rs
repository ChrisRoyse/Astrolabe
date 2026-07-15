use crate::quant::{QuantLevel, QuantizedVec, Quantizer, RotationSeed, SeedId, TurboQuantCodec};
use crate::{ForgeError, Result};

pub const QJL_SECTION_TAG: u8 = 0x01;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QjlResidual {
    pub bits: Vec<u8>,
    pub rademacher_seed: SeedId,
}

pub fn encode_qjl_residual(
    rotated: &[f32],
    scalar_decoded: &[f32],
    rademacher: &RotationSeed,
) -> QjlResidual {
    assert_eq!(
        rotated.len(),
        scalar_decoded.len(),
        "QJL residual dimension mismatch: rotated={} scalar_decoded={}",
        rotated.len(),
        scalar_decoded.len()
    );
    assert_eq!(
        rotated.len(),
        rademacher.dim,
        "QJL rademacher dimension mismatch: expected {} got {}",
        rademacher.dim,
        rotated.len()
    );
    let mut bits = vec![0; qjl_bits_len(rotated.len())];
    for (idx, ((rotated, decoded), sign)) in rotated
        .iter()
        .zip(scalar_decoded.iter())
        .zip(rademacher.diagonal.iter())
        .enumerate()
    {
        let residual = (rotated - decoded) * sign;
        if residual > 0.0 {
            bits[idx / 8] |= 1 << (idx % 8);
        }
    }
    QjlResidual {
        bits,
        rademacher_seed: rademacher.id,
    }
}

pub fn dot_qjl_correction(
    qa: &QjlResidual,
    qb: &QjlResidual,
    rademacher: &RotationSeed,
    scale_a: f32,
    scale_b: f32,
) -> f32 {
    assert_eq!(
        qa.rademacher_seed, rademacher.id,
        "QJL rademacher seed mismatch"
    );
    assert_eq!(
        qb.rademacher_seed, rademacher.id,
        "QJL rademacher seed mismatch"
    );
    assert_eq!(
        qa.bits.len(),
        qjl_bits_len(rademacher.dim),
        "QJL bit length mismatch"
    );
    assert_eq!(
        qb.bits.len(),
        qjl_bits_len(rademacher.dim),
        "QJL bit length mismatch"
    );
    if rademacher.dim == 0 {
        return 0.0;
    }
    let mut sum = 0.0_f32;
    for idx in 0..rademacher.dim {
        sum += bipolar_bit(&qa.bits, idx) * bipolar_bit(&qb.bits, idx);
    }
    scale_a * scale_b * sum / rademacher.dim as f32
}

pub fn dot_estimate_unbiased(
    codec: &TurboQuantCodec,
    qv_a: &QuantizedVec,
    qv_b: &QuantizedVec,
) -> Result<f32> {
    if qv_a.seed_id != qv_b.seed_id {
        return Err(qjl_error(
            "dot_estimate",
            qv_a.level,
            "seed_id mismatch in dot_estimate",
        ));
    }
    let scalar_a = codec.decode(qv_a)?;
    let scalar_b = codec.decode(qv_b)?;
    let scalar_dot = scalar_a
        .iter()
        .zip(scalar_b.iter())
        .map(|(a, b)| a * b)
        .sum::<f32>();
    let scalar_len = super::turboquant::packed_len(qv_a.dim, qv_a.level);
    let qa = required_qjl_section(qv_a, scalar_len)?;
    let qb = required_qjl_section(qv_b, scalar_len)?;
    if qa.rademacher_seed != codec.rademacher().id || qb.rademacher_seed != codec.rademacher().id {
        return Err(qjl_error(
            "dot_estimate",
            qv_a.level,
            "rademacher_seed mismatch in dot_estimate",
        ));
    }
    Ok(scalar_dot + dot_qjl_correction(&qa, &qb, codec.rademacher(), qv_a.scale, qv_b.scale))
}

pub(crate) fn append_qjl_section(bytes: &mut Vec<u8>, residual: &QjlResidual) {
    bytes.push(QJL_SECTION_TAG);
    bytes.extend_from_slice(&residual.rademacher_seed);
    bytes.extend_from_slice(&residual.bits);
}

pub(crate) fn read_qjl_section(
    bytes: &[u8],
    scalar_len: usize,
    dim: usize,
) -> Result<Option<QjlResidual>> {
    if bytes.len() == scalar_len {
        return Ok(None);
    }
    let expected_total = scalar_len + qjl_section_len(dim);
    if bytes.len() != expected_total {
        return Err(qjl_error(
            "decode",
            QuantLevel::Bits3p5,
            format!(
                "QJL section length mismatch: expected {expected_total} got {}",
                bytes.len()
            ),
        ));
    }
    if bytes[scalar_len] != QJL_SECTION_TAG {
        return Err(qjl_error(
            "decode",
            QuantLevel::Bits3p5,
            "missing QJL section tag",
        ));
    }
    let seed_start = scalar_len + 1;
    let bits_start = seed_start + 32;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes[seed_start..bits_start]);
    Ok(Some(QjlResidual {
        bits: bytes[bits_start..].to_vec(),
        rademacher_seed: seed,
    }))
}

fn required_qjl_section(qv: &QuantizedVec, scalar_len: usize) -> Result<QjlResidual> {
    read_qjl_section(&qv.bytes, scalar_len, qv.dim)?.ok_or_else(|| {
        qjl_error(
            "dot_estimate",
            qv.level,
            "missing QJL residual section in dot_estimate",
        )
    })
}

fn qjl_bits_len(dim: usize) -> usize {
    dim.div_ceil(8)
}

fn qjl_section_len(dim: usize) -> usize {
    1 + 32 + qjl_bits_len(dim)
}

fn bipolar_bit(bits: &[u8], idx: usize) -> f32 {
    if ((bits[idx / 8] >> (idx % 8)) & 1) == 1 {
        1.0
    } else {
        -1.0
    }
}

fn qjl_error(op: &str, level: QuantLevel, detail: impl Into<String>) -> ForgeError {
    ForgeError::QuantError {
        op: op.to_string(),
        level: format!("{level:?}"),
        detail: detail.into(),
        remediation: "Use matching quantizer seeds and encoded QJL residual sections".to_string(),
    }
}
