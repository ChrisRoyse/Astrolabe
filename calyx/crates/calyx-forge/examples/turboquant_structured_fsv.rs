//! Manual full-state verification for #565.
//!
//! The corpus is made from real Rust source bytes in this repository. The
//! driver persists structured TQPR rows, independently restarts itself, reads
//! the bytes back, regenerates bit-exact geometry, and searches them directly.

use std::cmp::Ordering;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use calyx_forge::{
    QuantLevel, QuantizedVec, Quantizer, TurboQuantCodec, TurboQuantGeometryKind, new_seed,
};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"TQFSV1\0\0";
const DIM: usize = 768;
const ROWS: usize = 96;
const QUERIES: usize = 8;
const K: usize = 10;
const SCAN_ITERS: usize = 80;
const ENTROPY: &[u8] = b"calyx-565-structured-fsv-real-corpus";

fn main() {
    if let Err(error) = run() {
        println!(
            "{{\"event\":\"fsv_failure\",\"error\":\"{}\"}}",
            safe(&error.to_string())
        );
        std::process::exit(1);
    }
}

fn run() -> AnyResult<()> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.get(1).map(String::as_str) == Some("--child") {
        return child_restart(Path::new(args.get(2).ok_or("missing child bundle path")?));
    }

    let root = fsv_root()?;
    fs::create_dir_all(&root)?;
    let bundle_path = root.join("structured.tqfsv");
    let source_files = real_source_files()?;
    let vectors = real_corpus_vectors(&source_files, DIM, ROWS + QUERIES)?;
    let (rows, queries) = vectors.split_at(ROWS);
    let executable_sha = sha256(&fs::read(std::env::current_exe()?)?);
    println!(
        "{{\"event\":\"context\",\"os\":\"{}\",\"arch\":\"{}\",\"dim\":{DIM},\"rows\":{ROWS},\"queries\":{QUERIES},\"k\":{K},\"source_files\":{},\"root\":\"{}\",\"executable_sha256\":\"{}\"}}",
        std::env::consts::OS,
        std::env::consts::ARCH,
        source_files.len(),
        safe(&root.display().to_string()),
        hex(&executable_sha)
    );

    let seed = new_seed(DIM, ENTROPY);
    let rss_before = working_set_bytes()?;
    let dense_start = Instant::now();
    let dense = TurboQuantCodec::new(seed.clone(), QuantLevel::Bits3p5)?;
    let dense_setup = dense_start.elapsed();
    let rss_after_dense = working_set_bytes()?;
    let structured_start = Instant::now();
    let structured = TurboQuantCodec::new_structured(seed.clone(), QuantLevel::Bits3p5)?;
    let structured_setup = structured_start.elapsed();
    let rss_after_structured = working_set_bytes()?;
    require(
        dense.geometry_kind() == TurboQuantGeometryKind::DenseHaarGaussianV2
            && structured.geometry_kind() == TurboQuantGeometryKind::StructuredHadamardV1
            && dense.geometry_id() != structured.geometry_id(),
        "dense and structured geometries must have distinct frozen identities",
    )?;
    println!(
        "{{\"event\":\"geometry_setup\",\"dense_id\":\"{}\",\"structured_id\":\"{}\",\"dense_bytes\":{},\"structured_bytes\":{},\"dense_setup_us\":{},\"structured_setup_us\":{},\"rss_before\":{},\"rss_after_dense\":{},\"rss_after_structured\":{}}}",
        hex(&dense.geometry_id()),
        hex(&structured.geometry_id()),
        dense.geometry_physical_bytes(),
        structured.geometry_physical_bytes(),
        dense_setup.as_micros(),
        structured_setup.as_micros(),
        rss_before,
        rss_after_dense,
        rss_after_structured
    );

    let dense_measurement = measure_codec("dense", &dense, rows, queries)?;
    let structured_measurement = measure_codec("structured", &structured, rows, queries)?;
    println!("{}", dense_measurement.json());
    println!("{}", structured_measurement.json());

    let encoded = rows
        .iter()
        .map(|row| structured.encode(row))
        .collect::<Result<Vec<_>, _>>()?;
    let bundle = encode_bundle(structured.geometry_id(), &encoded, queries)?;
    write_atomic(&bundle_path, &bundle)?;
    let bundle_readback = fs::read(&bundle_path)?;
    require(
        bundle_readback == bundle,
        "final bundle bytes differ after atomic publish",
    )?;
    let bundle_sha = sha256(&bundle_readback);
    let expected_hits = search_hits(&structured, &encoded, queries)?;
    println!(
        "{{\"event\":\"persisted_bundle\",\"path\":\"{}\",\"bytes\":{},\"sha256\":\"{}\",\"tqpr_magic_rows\":{},\"geometry_id\":\"{}\",\"first_query_hits\":\"{}\"}}",
        safe(&bundle_path.display().to_string()),
        bundle_readback.len(),
        hex(&bundle_sha),
        encoded
            .iter()
            .filter(|row| row.bytes.starts_with(b"TQPR"))
            .count(),
        hex(&structured.geometry_id()),
        hit_string(&expected_hits[0])
    );

    let child = Command::new(std::env::current_exe()?)
        .arg("--child")
        .arg(&bundle_path)
        .current_dir(std::env::current_dir()?)
        .output()?;
    require(
        child.status.success(),
        &format!(
            "restart child failed: stdout={} stderr={}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        ),
    )?;
    let child_stdout = String::from_utf8(child.stdout)?;
    require(
        child_stdout.contains(&hex(&bundle_sha))
            && child_stdout.contains(&hit_string(&expected_hits[0])),
        "restart child did not read the same persisted bytes and ranking",
    )?;
    print!("{child_stdout}");

    verify_cache(seed.clone())?;
    verify_max_dimension(&source_files)?;
    verify_edges(&root, &bundle_path, &bundle_readback, queries)?;
    println!("{{\"event\":\"fsv_success\",\"issue\":565}}");
    Ok(())
}

fn child_restart(path: &Path) -> AnyResult<()> {
    let bytes = fs::read(path)?;
    let sha = sha256(&bytes);
    let bundle = decode_bundle(&bytes)?;
    let codec = TurboQuantCodec::new_structured(new_seed(bundle.dim, ENTROPY), bundle.level)?;
    require(
        codec.geometry_id() == bundle.geometry_id,
        "restart geometry identity mismatch",
    )?;
    for row in &bundle.rows {
        codec.validate_candidate(row)?;
    }
    let hits = search_hits(&codec, &bundle.rows, &bundle.queries)?;
    println!(
        "{{\"event\":\"restart_readback\",\"bundle_sha256\":\"{}\",\"geometry_id\":\"{}\",\"validated_rows\":{},\"queries\":{},\"first_query_hits\":\"{}\"}}",
        hex(&sha),
        hex(&codec.geometry_id()),
        bundle.rows.len(),
        bundle.queries.len(),
        hit_string(&hits[0])
    );
    Ok(())
}

struct Measurement {
    name: &'static str,
    recall: f64,
    mean_abs_error: f64,
    max_abs_error: f64,
    decode_cosine: f64,
    encode_ns: f64,
    prepare_ns: f64,
    scan_ns: f64,
    reference_ns: f64,
}

impl Measurement {
    fn json(&self) -> String {
        format!(
            "{{\"event\":\"codec_measurement\",\"codec\":\"{}\",\"recall_at_10\":{:.6},\"mean_abs_score_error\":{:.9},\"max_abs_score_error\":{:.9},\"decode_cosine\":{:.6},\"encode_ns_per_row\":{:.1},\"prepare_ns_per_query\":{:.1},\"simd_lut_scan_ns\":{:.1},\"reference_scan_ns\":{:.1},\"scan_speedup\":{:.3}}}",
            self.name,
            self.recall,
            self.mean_abs_error,
            self.max_abs_error,
            self.decode_cosine,
            self.encode_ns,
            self.prepare_ns,
            self.scan_ns,
            self.reference_ns,
            self.reference_ns / self.scan_ns
        )
    }
}

fn measure_codec(
    name: &'static str,
    codec: &TurboQuantCodec,
    rows: &[Vec<f32>],
    queries: &[Vec<f32>],
) -> AnyResult<Measurement> {
    let started = Instant::now();
    let encoded = rows
        .iter()
        .map(|row| codec.encode(row))
        .collect::<Result<Vec<_>, _>>()?;
    let encode_ns = started.elapsed().as_nanos() as f64 / rows.len() as f64;
    let validated = encoded
        .iter()
        .map(|row| codec.validate_candidate(row))
        .collect::<Result<Vec<_>, _>>()?;
    let started = Instant::now();
    let prepared = queries
        .iter()
        .map(|query| codec.prepare_query(query))
        .collect::<Result<Vec<_>, _>>()?;
    let prepare_ns = started.elapsed().as_nanos() as f64 / queries.len() as f64;

    let mut recalled = 0_usize;
    let mut error_sum = 0.0_f64;
    let mut max_error = 0.0_f64;
    for (query_index, query) in queries.iter().enumerate() {
        let exact = top_k(rows.iter().map(|row| dot(query, row)).collect(), K);
        let approximate = top_k(
            validated
                .iter()
                .map(|candidate| codec.dot_estimate_validated(&prepared[query_index], candidate))
                .collect::<Result<Vec<_>, _>>()?,
            K,
        );
        recalled += exact
            .iter()
            .filter(|index| approximate.contains(index))
            .count();
        for (row_index, candidate) in validated.iter().enumerate() {
            let score = codec.dot_estimate_validated(&prepared[query_index], candidate)?;
            let error = (f64::from(score) - f64::from(dot(query, &rows[row_index]))).abs();
            error_sum += error;
            max_error = max_error.max(error);
        }
    }
    let decoded = encoded
        .iter()
        .zip(rows)
        .map(|(row, raw)| {
            codec
                .decode(row)
                .map(|decoded| f64::from(cosine(&decoded, raw)))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut sink = 0.0_f64;
    let started = Instant::now();
    for _ in 0..SCAN_ITERS {
        for query in &prepared {
            for candidate in &validated {
                sink += f64::from(codec.dot_estimate_validated(query, candidate)?);
            }
        }
    }
    let scan_ns = started.elapsed().as_nanos() as f64
        / (SCAN_ITERS * prepared.len() * validated.len()) as f64;
    let started = Instant::now();
    for _ in 0..SCAN_ITERS {
        for query in &prepared {
            for candidate in &validated {
                sink += f64::from(codec.dot_estimate_reference(query, candidate)?);
            }
        }
    }
    let reference_ns = started.elapsed().as_nanos() as f64
        / (SCAN_ITERS * prepared.len() * validated.len()) as f64;
    require(sink.is_finite(), "benchmark sink became non-finite")?;
    Ok(Measurement {
        name,
        recall: recalled as f64 / (queries.len() * K) as f64,
        mean_abs_error: error_sum / (queries.len() * rows.len()) as f64,
        max_abs_error: max_error,
        decode_cosine: decoded.iter().sum::<f64>() / decoded.len() as f64,
        encode_ns,
        prepare_ns,
        scan_ns,
        reference_ns,
    })
}

fn verify_cache(seed: calyx_forge::RotationSeed) -> AnyResult<()> {
    let first = TurboQuantCodec::shared_structured(seed.clone(), QuantLevel::Bits3p5)?;
    let second = TurboQuantCodec::shared_structured(seed.clone(), QuantLevel::Bits3p5)?;
    require(
        Arc::ptr_eq(&first, &second),
        "shared structured cache is not pointer-identical",
    )?;
    let handles = (0..8)
        .map(|_| {
            let seed = seed.clone();
            std::thread::spawn(move || {
                TurboQuantCodec::shared_structured(seed, QuantLevel::Bits3p5)
            })
        })
        .collect::<Vec<_>>();
    for handle in handles {
        let observed = handle.join().map_err(|_| "cache worker panicked")??;
        require(
            Arc::ptr_eq(&first, &observed),
            "concurrent cache returned different geometry",
        )?;
    }
    let while_held = TurboQuantCodec::shared_geometry_cache_len();
    drop(first);
    drop(second);
    let after_drop = TurboQuantCodec::shared_geometry_cache_len();
    require(
        after_drop < while_held,
        "weak cache retained dead structured geometry",
    )?;
    println!(
        "{{\"event\":\"cache_readback\",\"concurrent_opens\":8,\"pointer_identical\":true,\"live_while_held\":{while_held},\"live_after_drop\":{after_drop}}}"
    );
    Ok(())
}

fn verify_max_dimension(source_files: &[PathBuf]) -> AnyResult<()> {
    let dim = 4096_usize;
    let vector = real_corpus_vectors(source_files, dim, 1)?.remove(0);
    let rss_before = working_set_bytes()?;
    let started = Instant::now();
    let codec = TurboQuantCodec::new_structured(new_seed(dim, ENTROPY), QuantLevel::Bits3p5)?;
    let setup_us = started.elapsed().as_micros();
    let rss_after = working_set_bytes()?;
    let started = Instant::now();
    let row = codec.encode(&vector)?;
    let encode_us = started.elapsed().as_micros();
    let started = Instant::now();
    let query = codec.prepare_query(&vector)?;
    let prepare_us = started.elapsed().as_micros();
    let candidate = codec.validate_candidate(&row)?;
    let score = codec.dot_estimate_validated(&query, &candidate)?;
    require(score.is_finite(), "max-dimension score is non-finite")?;
    println!(
        "{{\"event\":\"max_dimension\",\"dim\":4096,\"geometry_bytes\":{},\"rss_before\":{rss_before},\"rss_after\":{rss_after},\"setup_us\":{setup_us},\"encode_us\":{encode_us},\"prepare_us\":{prepare_us},\"payload_bytes\":{},\"score\":{score}}}",
        codec.geometry_physical_bytes(),
        row.bytes.len()
    );
    Ok(())
}

fn verify_edges(
    root: &Path,
    bundle_path: &Path,
    bundle_before: &[u8],
    queries: &[Vec<f32>],
) -> AnyResult<()> {
    let before_hash = sha256(bundle_before);
    let before_files = file_count(root)?;
    println!(
        "{{\"event\":\"edges_before\",\"files\":{before_files},\"bundle_sha256\":\"{}\",\"bundle_bytes\":{}}}",
        hex(&before_hash),
        bundle_before.len()
    );
    let codec = TurboQuantCodec::new_structured(new_seed(DIM, ENTROPY), QuantLevel::Bits3p5)?;
    let decoded = decode_bundle(bundle_before)?;
    let mut corrupt = decoded.rows[0].clone();
    let last = corrupt.bytes.len() - 1;
    corrupt.bytes[last] ^= 1;
    let corrupt_error = codec
        .validate_candidate(&corrupt)
        .err()
        .ok_or("corrupt row was accepted")?;
    let foreign = TurboQuantCodec::new_structured(
        new_seed(DIM, b"calyx-565-foreign-geometry"),
        QuantLevel::Bits3p5,
    )?;
    let foreign_query = foreign.prepare_query(&queries[0])?;
    let candidate = codec.validate_candidate(&decoded.rows[0])?;
    let foreign_error = codec
        .dot_estimate_validated(&foreign_query, &candidate)
        .err()
        .ok_or("foreign prepared query was accepted")?;
    let oversize_error =
        TurboQuantCodec::new_structured(new_seed(4097, ENTROPY), QuantLevel::Bits3p5)
            .err()
            .ok_or("dimension 4097 was accepted")?;
    let unsupported_error =
        TurboQuantCodec::new_structured(new_seed(DIM, ENTROPY), QuantLevel::Bits8)
            .err()
            .ok_or("unsupported Bits8 geometry was accepted")?;

    let mut corrupt_bundle = bundle_before.to_vec();
    let last = corrupt_bundle.len() - 1;
    corrupt_bundle[last] ^= 1;
    let corrupt_path = root.join("corrupt.tqfsv");
    write_atomic(&corrupt_path, &corrupt_bundle)?;
    let child = Command::new(std::env::current_exe()?)
        .arg("--child")
        .arg(&corrupt_path)
        .output()?;
    require(
        !child.status.success(),
        "corrupted persisted bundle restart unexpectedly succeeded",
    )?;

    let after = fs::read(bundle_path)?;
    require(
        after == bundle_before,
        "valid source-of-truth bundle changed during edge probes",
    )?;
    println!(
        "{{\"event\":\"edges_after\",\"files\":{},\"valid_bundle_unchanged\":true,\"bundle_sha256\":\"{}\",\"corrupt_row_error\":\"{}\",\"foreign_geometry_error\":\"{}\",\"oversize_error\":\"{}\",\"unsupported_error\":\"{}\",\"corrupt_restart_exit\":{}}}",
        file_count(root)?,
        hex(&sha256(&after)),
        safe(&corrupt_error.to_string()),
        safe(&foreign_error.to_string()),
        safe(&oversize_error.to_string()),
        safe(&unsupported_error.to_string()),
        child.status.code().unwrap_or(-1)
    );
    Ok(())
}

struct Bundle {
    level: QuantLevel,
    dim: usize,
    geometry_id: [u8; 32],
    rows: Vec<QuantizedVec>,
    queries: Vec<Vec<f32>>,
}

fn encode_bundle(
    geometry_id: [u8; 32],
    rows: &[QuantizedVec],
    queries: &[Vec<f32>],
) -> AnyResult<Vec<u8>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(MAGIC);
    bytes.extend_from_slice(&(DIM as u32).to_le_bytes());
    bytes.push(2); // Bits3p5
    bytes.extend_from_slice(&[0; 3]);
    bytes.extend_from_slice(&geometry_id);
    bytes.extend_from_slice(&(rows.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(queries.len() as u32).to_le_bytes());
    for row in rows {
        bytes.extend_from_slice(&row.scale.to_bits().to_le_bytes());
        bytes.extend_from_slice(&(row.bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&row.bytes);
    }
    for query in queries {
        for value in query {
            bytes.extend_from_slice(&value.to_bits().to_le_bytes());
        }
    }
    let digest = sha256(&bytes);
    bytes.extend_from_slice(&digest);
    Ok(bytes)
}

fn decode_bundle(bytes: &[u8]) -> AnyResult<Bundle> {
    require(
        bytes.len() >= 88,
        "bundle is shorter than its bounded header/footer",
    )?;
    let body_end = bytes.len() - 32;
    require(
        sha256(&bytes[..body_end]) == bytes[body_end..],
        "bundle SHA-256 mismatch",
    )?;
    require(&bytes[..8] == MAGIC, "bundle magic mismatch")?;
    let dim = u32_at(bytes, 8)? as usize;
    require(
        (1..=4096).contains(&dim),
        "bundle dimension outside 1..=4096",
    )?;
    let level = match bytes[12] {
        2 => QuantLevel::Bits3p5,
        _ => return Err("bundle level is unsupported".into()),
    };
    require(
        bytes[13..16] == [0; 3],
        "bundle reserved bytes are non-zero",
    )?;
    let mut geometry_id = [0_u8; 32];
    geometry_id.copy_from_slice(&bytes[16..48]);
    let row_count = u32_at(bytes, 48)? as usize;
    let query_count = u32_at(bytes, 52)? as usize;
    require(
        row_count <= 10_000 && query_count <= 1_000,
        "bundle count exceeds FSV bounds",
    )?;
    let mut cursor = 56_usize;
    let mut rows = Vec::with_capacity(row_count);
    for _ in 0..row_count {
        let scale = f32::from_bits(u32_at(bytes, cursor)?);
        let len = u32_at(bytes, cursor + 4)? as usize;
        cursor += 8;
        require(
            len <= 16_384 && cursor + len <= body_end,
            "bundle row length is invalid",
        )?;
        rows.push(QuantizedVec {
            level,
            dim,
            bytes: bytes[cursor..cursor + len].to_vec(),
            scale,
            seed_id: geometry_id,
        });
        cursor += len;
    }
    let query_bytes = query_count
        .checked_mul(dim)
        .and_then(|v| v.checked_mul(4))
        .ok_or("query length overflow")?;
    require(
        cursor + query_bytes == body_end,
        "bundle query/body length mismatch",
    )?;
    let mut queries = Vec::with_capacity(query_count);
    for _ in 0..query_count {
        let mut query = Vec::with_capacity(dim);
        for _ in 0..dim {
            query.push(f32::from_bits(u32_at(bytes, cursor)?));
            cursor += 4;
        }
        queries.push(query);
    }
    Ok(Bundle {
        level,
        dim,
        geometry_id,
        rows,
        queries,
    })
}

fn search_hits(
    codec: &TurboQuantCodec,
    rows: &[QuantizedVec],
    queries: &[Vec<f32>],
) -> AnyResult<Vec<Vec<usize>>> {
    let validated = rows
        .iter()
        .map(|row| codec.validate_candidate(row))
        .collect::<Result<Vec<_>, _>>()?;
    queries
        .iter()
        .map(|query| {
            let prepared = codec.prepare_query(query)?;
            let scores = validated
                .iter()
                .map(|row| codec.dot_estimate_validated(&prepared, row))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(top_k(scores, K))
        })
        .collect()
}

fn real_source_files() -> AnyResult<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![PathBuf::from("calyx/crates/calyx-forge/src")];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    require(!files.is_empty(), "real source corpus is empty")?;
    Ok(files)
}

fn real_corpus_vectors(files: &[PathBuf], dim: usize, count: usize) -> AnyResult<Vec<Vec<f32>>> {
    let mut vectors = Vec::new();
    'files: for path in files {
        let bytes = fs::read(path)?;
        for chunk in bytes.chunks(4096) {
            if chunk.len() < 512 {
                continue;
            }
            let mut vector = vec![0.0_f32; dim];
            for (index, pair) in chunk.windows(2).enumerate() {
                let token = (usize::from(pair[0]) * 257 + usize::from(pair[1]) * 17 + index) % dim;
                vector[token] += 1.0;
            }
            let mean = vector.iter().sum::<f32>() / dim as f32;
            for value in &mut vector {
                *value -= mean;
            }
            normalize(&mut vector)?;
            vectors.push(vector);
            if vectors.len() == count {
                break 'files;
            }
        }
    }
    require(
        vectors.len() == count,
        &format!("real corpus yielded {} of {count} vectors", vectors.len()),
    )?;
    Ok(vectors)
}

fn normalize(values: &mut [f32]) -> AnyResult<()> {
    let norm = values
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum::<f64>()
        .sqrt();
    require(
        norm.is_finite() && norm > 0.0,
        "real corpus vector has invalid norm",
    )?;
    for value in values {
        *value = (f64::from(*value) / norm) as f32;
    }
    Ok(())
}

fn dot(left: &[f32], right: &[f32]) -> f32 {
    left.iter().zip(right).map(|(a, b)| *a * *b).sum()
}

fn cosine(left: &[f32], right: &[f32]) -> f32 {
    let product = dot(left, right);
    let ln = dot(left, left).sqrt();
    let rn = dot(right, right).sqrt();
    product / (ln * rn)
}

fn top_k(scores: Vec<f32>, k: usize) -> Vec<usize> {
    let mut indices = (0..scores.len()).collect::<Vec<_>>();
    indices.sort_by(|left, right| {
        scores[*right]
            .partial_cmp(&scores[*left])
            .unwrap_or(Ordering::Equal)
            .then_with(|| left.cmp(right))
    });
    indices.truncate(k.min(indices.len()));
    indices
}

fn hit_string(hits: &[usize]) -> String {
    hits.iter()
        .map(usize::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn write_atomic(path: &Path, bytes: &[u8]) -> AnyResult<()> {
    let temporary = path.with_extension("tmp");
    let mut file = fs::File::create(&temporary)?;
    std::io::Write::write_all(&mut file, bytes)?;
    file.sync_all()?;
    drop(file);
    if path.exists() {
        fs::remove_file(path)?;
    }
    fs::rename(&temporary, path)?;
    require(
        fs::read(path)? == bytes,
        "atomic file final readback differs",
    )?;
    Ok(())
}

fn working_set_bytes() -> AnyResult<u64> {
    let command = format!("(Get-Process -Id {}).WorkingSet64", std::process::id());
    let output = Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &command])
        .output()?;
    require(
        output.status.success(),
        "Get-Process working-set read failed",
    )?;
    Ok(String::from_utf8(output.stdout)?.trim().parse()?)
}

fn fsv_root() -> AnyResult<PathBuf> {
    if let Some(root) = std::env::var_os("CALYX_FSV_ROOT") {
        return Ok(root.into());
    }
    Ok(PathBuf::from(format!(
        ".tmp/fsv-565/tq-{}",
        std::process::id()
    )))
}

fn file_count(path: &Path) -> AnyResult<usize> {
    Ok(fs::read_dir(path)?.collect::<Result<Vec<_>, _>>()?.len())
}

fn u32_at(bytes: &[u8], offset: usize) -> AnyResult<u32> {
    let end = offset.checked_add(4).ok_or("offset overflow")?;
    let slice = bytes.get(offset..end).ok_or("truncated u32")?;
    Ok(u32::from_le_bytes(slice.try_into()?))
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn safe(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('"', "'")
        .replace(['\r', '\n'], " ")
}
fn require(condition: bool, message: &str) -> AnyResult<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;
