use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use calyx_core::{CalyxError, CxId, SlotId, SlotVector, SparseEntry};
use calyx_sextant::{
    SextantIndex, SpannCentroidIndex, SpannPostingLimits, SpannPostingPhysicalStats, SpannSearch,
    build_centroids, decode_posting_block,
};
use serde_json::{Value, json};

const SLOT: SlotId = SlotId::new(23);
const DIM: u32 = 16;
const CLUSTERS: usize = 4;

fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let result = match args.as_slice() {
        [_, mode, root, report] if mode == "build" => build(Path::new(root), Path::new(report)),
        [_, mode, root, report] if mode == "open" => open(Path::new(root), Path::new(report)),
        [_, mode, root, report] if mode == "empty" => empty(Path::new(root), Path::new(report)),
        [_, mode, root, report] if mode == "maximum" => maximum(Path::new(root), Path::new(report)),
        [_, mode, root, report] if mode == "update" => update(Path::new(root), Path::new(report)),
        [_, mode, root, report] if mode == "codec-edges" => {
            codec_edges(Path::new(root), Path::new(report))
        }
        [_, mode, root, ready, release, report] if mode == "hold-open" => hold_open(
            Path::new(root),
            Path::new(ready),
            Path::new(release),
            Path::new(report),
        ),
        _ => Err(driver_error(
            "usage: spann_compression_fsv <build|open|empty|maximum|update|codec-edges> <store-root> <report.json> OR hold-open <store-root> <ready.json> <release.signal> <report.json>",
        )),
    };
    match result {
        Ok(report) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).expect("JSON value serializes")
            );
        }
        Err(error) => {
            eprintln!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "status": "error",
                    "code": error.code,
                    "message": error.message,
                    "remediation": error.remediation,
                }))
                .expect("JSON value serializes")
            );
            std::process::exit(1);
        }
    }
}

fn build(root: &Path, report_path: &Path) -> Result<Value, CalyxError> {
    let build_started = Instant::now();
    require_absent(root)?;
    fs::create_dir_all(root).map_err(|error| io_error("create FSV store", error))?;
    let before = filesystem_state(root)?;
    let limits = fsv_limits();
    let centroids = build_known_centroids();
    centroids.save(root)?;
    let centroid_hash = hex(&centroids.content_hash());
    let mut search = SpannSearch::new_with_limits(SLOT, centroids, root, limits.clone())?;
    let mut receipt_count = 0_u64;
    let mut total_logical_bytes = 0_u64;
    let mut total_physical_bytes = 0_u64;
    let mut total_compaction_bytes = 0_u64;
    let mut total_reclaimed_bytes = 0_u64;
    let mut total_reclaimed_files = 0_u64;
    let mut compaction_events = 0_u64;
    let mut ids = Vec::new();
    for ordinal in 0..128_u32 {
        let cx_id = known_cx(ordinal);
        let vector = known_vector((ordinal as usize) % CLUSTERS, ordinal);
        search.insert(cx_id, vector, u64::from(ordinal) + 1)?;
        ids.push(cx_id);
        let receipt = search.last_write().expect("insert writes receipt");
        receipt_count += 1;
        total_logical_bytes += receipt.logical_decoded_bytes;
        total_physical_bytes += receipt.physical_bytes_written;
        total_compaction_bytes += receipt.compaction_bytes_written;
        total_reclaimed_bytes += receipt.reclaimed_bytes;
        total_reclaimed_files += u64::from(receipt.reclaimed_files);
        if receipt.compacted_postings > 0 || receipt.state_compacted {
            compaction_events += 1;
        }
    }
    let index_build_elapsed_ms = build_started.elapsed().as_millis();
    let query0 = known_vector(0, 0);
    let before_update = SextantIndex::search(&search, &query0, 5, Some(4))?;
    if before_update.first().map(|hit| hit.cx_id) != Some(ids[0]) {
        return Err(driver_error(format!(
            "known cluster-0 query returned {:?}, expected {}",
            before_update.first().map(|hit| hit.cx_id),
            ids[0]
        )));
    }
    search.insert(ids[0], known_vector(3, 0), 10_000)?;
    let update_receipt = search.last_write().cloned().expect("update writes receipt");
    let after_old_cluster = SextantIndex::search(&search, &query0, 5, Some(4))?;
    if after_old_cluster.iter().any(|hit| hit.cx_id == ids[0]) {
        return Err(driver_error(
            "updated record remains in its old centroid membership",
        ));
    }
    let query3 = known_vector(3, 0);
    let after_new_cluster = SextantIndex::search(&search, &query3, 5, Some(4))?;
    if after_new_cluster.first().map(|hit| hit.cx_id) != Some(ids[0]) {
        return Err(driver_error(
            "updated record is not first in its new exact cluster",
        ));
    }
    search.verify_storage()?;
    let warm_stats = search.physical_stats()?;
    let latency = measure_queries(&search, &query3, 1_000)?;
    let vector_readback = search
        .vector(ids[0])
        .ok_or_else(|| driver_error("updated record vector is absent before restart"))?;
    if vector_readback != known_vector(3, 0) {
        return Err(driver_error(
            "updated vector readback changed before restart",
        ));
    }
    drop(search);

    let reopened = SpannSearch::open_with_limits(SLOT, root, root, limits.clone())?;
    reopened.verify_storage()?;
    if reopened.vector(ids[0]) != Some(known_vector(3, 0)) {
        return Err(driver_error(
            "updated vector/local CxId map did not survive restart",
        ));
    }
    let cold_hits = SextantIndex::search(&reopened, &query3, 5, Some(4))?;
    if cold_hits.first().map(|hit| hit.cx_id) != Some(ids[0]) {
        return Err(driver_error(
            "known query result changed after cold restart",
        ));
    }
    let cold_stats = reopened.physical_stats()?;
    let after = filesystem_state(root)?;
    let report = json!({
        "status": "ok",
        "mode": "build",
        "source_of_truth": root,
        "centroid_hash": centroid_hash,
        "limits": limits_json(&limits),
        "before": before,
        "after": after,
        "before_update_top5": hits_json(&before_update),
        "after_old_cluster_top5": hits_json(&after_old_cluster),
        "after_new_cluster_top5": hits_json(&after_new_cluster),
        "cold_restart_top5": hits_json(&cold_hits),
        "update_receipt": receipt_json(&update_receipt),
        "warm_physical": stats_json(&warm_stats),
        "cold_physical": stats_json(&cold_stats),
        "latency": latency,
        "rss_bytes": process_rss_bytes()?,
        "index_build_elapsed_ms": index_build_elapsed_ms,
        "insert_receipts": {
            "count": receipt_count,
            "incoming_logical_bytes": total_logical_bytes,
            "physical_bytes_written": total_physical_bytes,
            "compaction_bytes_written": total_compaction_bytes,
            "reclaimed_files": total_reclaimed_files,
            "reclaimed_bytes": total_reclaimed_bytes,
            "compaction_events": compaction_events,
            "physical_to_incoming_logical": total_physical_bytes as f64 / total_logical_bytes.max(1) as f64,
        },
    });
    write_report(report_path, &report)?;
    Ok(report)
}

fn open(root: &Path, report_path: &Path) -> Result<Value, CalyxError> {
    let before = filesystem_state(root)?;
    let limits = fsv_limits();
    let search = SpannSearch::open_with_limits(SLOT, root, root, limits)?;
    search.verify_storage()?;
    let query = known_vector(3, 0);
    let hits = SextantIndex::search(&search, &query, 5, Some(4))?;
    let after = filesystem_state(root)?;
    let report = json!({
        "status": "ok",
        "mode": "open",
        "before": before,
        "after": after,
        "top5": hits_json(&hits),
        "physical": stats_json(&search.physical_stats()?),
        "rss_bytes": process_rss_bytes()?,
    });
    write_report(report_path, &report)?;
    Ok(report)
}

fn empty(root: &Path, report_path: &Path) -> Result<Value, CalyxError> {
    require_absent(root)?;
    fs::create_dir_all(root).map_err(|error| io_error("create empty FSV store", error))?;
    let before = filesystem_state(root)?;
    let limits = fsv_limits();
    let centroids = build_known_centroids();
    centroids.save(root)?;
    let search = SpannSearch::new_with_limits(SLOT, centroids, root, limits.clone())?;
    let hits = SextantIndex::search(&search, &known_vector(0, 0), 10, Some(4))?;
    if !hits.is_empty() {
        return Err(driver_error(
            "explicitly empty postings returned candidates",
        ));
    }
    drop(search);
    let reopened = SpannSearch::open_with_limits(SLOT, root, root, limits)?;
    reopened.verify_storage()?;
    let cold_hits = SextantIndex::search(&reopened, &known_vector(0, 0), 10, Some(4))?;
    if !cold_hits.is_empty() {
        return Err(driver_error("empty postings changed after restart"));
    }
    let after = filesystem_state(root)?;
    let report = json!({
        "status": "ok",
        "mode": "empty",
        "before": before,
        "after": after,
        "warm_hits": hits_json(&hits),
        "cold_hits": hits_json(&cold_hits),
        "physical": stats_json(&reopened.physical_stats()?),
    });
    write_report(report_path, &report)?;
    Ok(report)
}

fn maximum(root: &Path, report_path: &Path) -> Result<Value, CalyxError> {
    require_absent(root)?;
    fs::create_dir_all(root).map_err(|error| io_error("create maximum FSV store", error))?;
    let before = filesystem_state(root)?;
    let mut limits = fsv_limits();
    limits.max_members_per_segment = 4;
    limits.max_segments_per_posting = 1;
    limits.max_state_segments = 4;
    limits.max_replication = 1;
    limits.boundary_epsilon_bits = 0.0_f32.to_bits();
    limits.validate()?;
    let centroids = single_centroid();
    centroids.save(root)?;
    let mut search = SpannSearch::new_with_limits(SLOT, centroids, root, limits.clone())?;
    for ordinal in 0..4_u32 {
        search.insert(
            known_cx(ordinal),
            known_vector(0, ordinal),
            u64::from(ordinal + 1),
        )?;
    }
    let pointer = root.join("postings.active");
    let pointer_before = file_hash(&pointer)?;
    let state_before = filesystem_state(root)?;
    let over_limit = search
        .insert(known_cx(4), known_vector(0, 4), 5)
        .expect_err("fifth record must exceed the exact four-member bound");
    let pointer_after = file_hash(&pointer)?;
    let state_after = filesystem_state(root)?;
    if pointer_before != pointer_after {
        return Err(driver_error(
            "failed over-limit insert changed the active generation pointer",
        ));
    }
    let hits = SextantIndex::search(&search, &known_vector(0, 0), 10, Some(1))?;
    if hits.len() != 4 {
        return Err(driver_error(format!(
            "maximum bounded posting contains {} records, expected 4",
            hits.len()
        )));
    }
    drop(search);
    let reopened = SpannSearch::open_with_limits(SLOT, root, root, limits.clone())?;
    reopened.verify_storage()?;
    let report = json!({
        "status": "ok",
        "mode": "maximum",
        "before": before,
        "state_before_over_limit": state_before,
        "state_after_over_limit": state_after,
        "pointer_hash_before": pointer_before,
        "pointer_hash_after": pointer_after,
        "over_limit_error": error_json(&over_limit),
        "persisted_count": reopened.stats().len,
        "top10": hits_json(&hits),
        "limits": limits_json(&limits),
    });
    write_report(report_path, &report)?;
    Ok(report)
}

fn codec_edges(root: &Path, report_path: &Path) -> Result<Value, CalyxError> {
    require_absent(root)?;
    fs::create_dir_all(root).map_err(|error| io_error("create codec edge store", error))?;
    let before = filesystem_state(root)?;
    let cases = [
        ("empty", vec![0, 0, 0, 0]),
        ("noncanonical", vec![1, 0, 0, 0, 0x80, 0x00, 0x02]),
        (
            "overflow",
            vec![1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0x10, 0x02],
        ),
        ("trailing", vec![0, 0, 0, 0, 0]),
    ];
    let mut outcomes = serde_json::Map::new();
    for (name, bytes) in cases {
        let path = root.join(format!("{name}.raw"));
        fs::write(&path, &bytes).map_err(|error| io_error("write codec edge file", error))?;
        let persisted = fs::read(&path).map_err(|error| io_error("read codec edge file", error))?;
        let outcome = match decode_posting_block(&persisted) {
            Ok(entries) => json!({
                "status": "ok",
                "entries": entries.len(),
                "hex": hex(&persisted),
            }),
            Err(error) => json!({
                "status": "error",
                "error": error_json(&error),
                "hex": hex(&persisted),
            }),
        };
        outcomes.insert(name.to_string(), outcome);
    }
    if outcomes["empty"]["status"] != "ok"
        || outcomes["noncanonical"]["status"] != "error"
        || outcomes["overflow"]["status"] != "error"
        || outcomes["trailing"]["status"] != "error"
    {
        return Err(driver_error(
            "codec edge outcomes differ from the fail-closed contract",
        ));
    }
    let after = filesystem_state(root)?;
    let report = json!({
        "status": "ok",
        "mode": "codec-edges",
        "before": before,
        "after": after,
        "outcomes": outcomes,
    });
    write_report(report_path, &report)?;
    Ok(report)
}

fn update(root: &Path, report_path: &Path) -> Result<Value, CalyxError> {
    let before = filesystem_state(root)?;
    let pointer = root.join("postings.active");
    let pointer_before = file_hash(&pointer)?;
    let mut search = SpannSearch::open_with_limits(SLOT, root, root, fsv_limits())?;
    for (offset, cluster) in [0, 3, 0, 3, 0].into_iter().enumerate() {
        search.insert(
            known_cx(0),
            known_vector(cluster, 0),
            20_000 + offset as u64,
        )?;
    }
    search.verify_storage()?;
    let query0 = SextantIndex::search(&search, &known_vector(0, 0), 5, Some(4))?;
    let query3 = SextantIndex::search(&search, &known_vector(3, 0), 5, Some(4))?;
    if query0.first().map(|hit| hit.cx_id) != Some(known_cx(0))
        || query3.iter().any(|hit| hit.cx_id == known_cx(0))
    {
        return Err(driver_error(
            "concurrent update did not relocate the known record exactly",
        ));
    }
    let pointer_after = file_hash(&pointer)?;
    if pointer_before == pointer_after {
        return Err(driver_error(
            "successful concurrent update did not advance the active pointer",
        ));
    }
    let after = filesystem_state(root)?;
    let report = json!({
        "status": "ok",
        "mode": "update",
        "before": before,
        "after": after,
        "pointer_before": pointer_before,
        "pointer_after": pointer_after,
        "top_cluster0": hits_json(&query0),
        "top_cluster3": hits_json(&query3),
        "physical": stats_json(&search.physical_stats()?),
        "write_receipt": receipt_json(search.last_write().expect("update writes receipt")),
    });
    write_report(report_path, &report)?;
    Ok(report)
}

fn hold_open(
    root: &Path,
    ready_path: &Path,
    release_path: &Path,
    report_path: &Path,
) -> Result<Value, CalyxError> {
    if ready_path.exists() || release_path.exists() || report_path.exists() {
        return Err(driver_error(
            "hold-open ready/release/report paths must start absent",
        ));
    }
    let before = filesystem_state(root)?;
    let search = SpannSearch::open_with_limits(SLOT, root, root, fsv_limits())?;
    let generation = search.physical_stats()?.generation;
    let initial_hits = SextantIndex::search(&search, &known_vector(3, 0), 5, Some(4))?;
    if initial_hits.first().map(|hit| hit.cx_id) != Some(known_cx(0)) {
        return Err(driver_error(
            "held reader did not open the expected pre-update generation",
        ));
    }
    write_report(
        ready_path,
        &json!({
            "status": "ready",
            "generation": generation,
            "pid": std::process::id(),
            "top_cluster3": hits_json(&initial_hits),
        }),
    )?;
    let wait_started = Instant::now();
    while !release_path.exists() {
        if wait_started.elapsed() > Duration::from_secs(60) {
            return Err(driver_error(
                "hold-open release signal was not observed within 60 seconds",
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let held_hits = SextantIndex::search(&search, &known_vector(3, 0), 5, Some(4))?;
    if held_hits.first().map(|hit| hit.cx_id) != Some(known_cx(0)) {
        return Err(driver_error(
            "held generation changed after concurrent publication",
        ));
    }
    search.verify_storage()?;
    let after = filesystem_state(root)?;
    let report = json!({
        "status": "ok",
        "mode": "hold-open",
        "held_generation": generation,
        "before": before,
        "after": after,
        "initial_top_cluster3": hits_json(&initial_hits),
        "held_top_cluster3": hits_json(&held_hits),
        "physical": stats_json(&search.physical_stats()?),
        "waited_ms": wait_started.elapsed().as_millis(),
    });
    write_report(report_path, &report)?;
    Ok(report)
}

fn build_known_centroids() -> SpannCentroidIndex {
    let rows = (0..64_u32)
        .map(|ordinal| {
            let cluster = (ordinal as usize) % CLUSTERS;
            (ordinal, dense_known(cluster, ordinal))
        })
        .collect::<Vec<_>>();
    build_centroids(&rows, CLUSTERS, 0x5555_2026)
}

fn single_centroid() -> SpannCentroidIndex {
    build_centroids(&[(0, dense_known(0, 0))], 1, 0x5555_2026)
}

fn dense_known(cluster: usize, ordinal: u32) -> Vec<f32> {
    let mut dense = vec![0.0_f32; DIM as usize];
    dense[cluster] = 10.0;
    dense[8 + cluster] = 1.0 + (ordinal % 7) as f32 * 0.001;
    dense
}

fn known_vector(cluster: usize, ordinal: u32) -> SlotVector {
    SlotVector::Sparse {
        dim: DIM,
        entries: vec![
            SparseEntry {
                idx: cluster as u32,
                val: 10.0,
            },
            SparseEntry {
                idx: (8 + cluster) as u32,
                val: 1.0 + (ordinal % 7) as f32 * 0.001,
            },
        ],
    }
}

fn known_cx(ordinal: u32) -> CxId {
    CxId::from_input(
        format!("issue-555-real-record-{ordinal:06}").as_bytes(),
        3,
        b"issue-555-fsv-vault-salt",
    )
}

fn fsv_limits() -> SpannPostingLimits {
    let mut limits = SpannPostingLimits::production();
    limits.max_members_per_segment = 64;
    limits.max_nnz_per_member = DIM;
    limits.max_decoded_segment_bytes = 1024 * 1024;
    limits.max_compressed_segment_bytes = 1024 * 1024;
    limits.max_segments_per_posting = 4;
    limits.max_state_segments = 8;
    limits.max_manifest_chain = 16;
    limits.max_reader_leases = 16;
    limits.max_manifest_bytes = 8 * 1024 * 1024;
    limits.max_centroid_file_bytes = 1024 * 1024;
    limits.max_query_decoded_bytes = 4 * 1024 * 1024;
    limits.cache_capacity_bytes = 2 * 1024 * 1024;
    limits.zstd_window_log_max = 20;
    limits.boundary_epsilon_bits = 0.0_f32.to_bits();
    limits.max_replication = 1;
    limits.max_reclaim_files = 4096;
    limits
}

fn measure_queries(
    search: &SpannSearch,
    query: &SlotVector,
    count: usize,
) -> Result<Value, CalyxError> {
    let mut samples = Vec::with_capacity(count);
    let started = Instant::now();
    for _ in 0..count {
        let one = Instant::now();
        let hits = SextantIndex::search(search, query, 10, Some(4))?;
        if hits.is_empty() {
            return Err(driver_error("measured query returned no known candidates"));
        }
        samples.push(one.elapsed().as_micros() as u64);
    }
    let elapsed = started.elapsed();
    samples.sort_unstable();
    Ok(json!({
        "queries": count,
        "elapsed_us": elapsed.as_micros(),
        "qps": count as f64 / elapsed.as_secs_f64(),
        "p50_us": percentile(&samples, 50),
        "p99_us": percentile(&samples, 99),
    }))
}

fn percentile(samples: &[u64], percentile: usize) -> u64 {
    let index = ((samples.len() - 1) * percentile) / 100;
    samples[index]
}

fn filesystem_state(root: &Path) -> Result<Value, CalyxError> {
    let mut files = Vec::new();
    if root.exists() {
        for entry in fs::read_dir(root).map_err(|error| io_error("scan FSV store", error))? {
            let entry = entry.map_err(|error| io_error("read FSV store entry", error))?;
            let metadata = entry
                .metadata()
                .map_err(|error| io_error("stat FSV store entry", error))?;
            if metadata.is_file() {
                files.push(json!({
                    "name": entry.file_name().to_string_lossy(),
                    "bytes": metadata.len(),
                    "blake3": file_hash(&entry.path())?,
                }));
            }
        }
    }
    files.sort_by(|left, right| left["name"].as_str().cmp(&right["name"].as_str()));
    Ok(json!({
        "exists": root.exists(),
        "file_count": files.len(),
        "files": files,
    }))
}

fn file_hash(path: &Path) -> Result<String, CalyxError> {
    let bytes = fs::read(path).map_err(|error| io_error("read file for BLAKE3", error))?;
    Ok(hex(blake3::hash(&bytes).as_bytes()))
}

fn write_report(path: &Path, report: &Value) -> Result<(), CalyxError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| io_error("create report parent", error))?;
    }
    let bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| driver_error(format!("serialize report: {error}")))?;
    fs::write(path, bytes).map_err(|error| io_error("write report", error))
}

fn require_absent(root: &Path) -> Result<(), CalyxError> {
    if root.exists() {
        return Err(driver_error(format!(
            "FSV root must be absent before creation: {}",
            root.display()
        )));
    }
    Ok(())
}

fn hits_json(hits: &[calyx_sextant::IndexSearchHit]) -> Value {
    Value::Array(
        hits.iter()
            .map(|hit| {
                json!({
                    "cx_id": hit.cx_id.to_string(),
                    "score": hit.score,
                    "rank": hit.rank,
                })
            })
            .collect(),
    )
}

fn stats_json(stats: &SpannPostingPhysicalStats) -> Value {
    json!({
        "generation": stats.generation,
        "records": stats.records,
        "declared_postings": stats.declared_postings,
        "posting_segments": stats.posting_segments,
        "state_segments": stats.state_segments,
        "posting_segment_bytes": stats.posting_segment_bytes,
        "state_segment_bytes": stats.state_segment_bytes,
        "manifest_chain_bytes": stats.manifest_chain_bytes,
        "active_pointer_bytes": stats.active_pointer_bytes,
        "active_physical_bytes": stats.active_physical_bytes,
        "directory_physical_bytes": stats.directory_physical_bytes,
        "retained_generation_bytes": stats.retained_generation_bytes,
        "reader_lease_bytes": stats.reader_lease_bytes,
        "temporary_bytes": stats.temporary_bytes,
        "orphan_bytes": stats.orphan_bytes,
        "cache_bytes": stats.cache_bytes,
        "cache_hits": stats.cache_hits,
        "cache_misses": stats.cache_misses,
    })
}

fn receipt_json(receipt: &calyx_sextant::SpannPostingWriteReceipt) -> Value {
    json!({
        "generation": receipt.generation,
        "logical_decoded_bytes": receipt.logical_decoded_bytes,
        "physical_bytes_written": receipt.physical_bytes_written,
        "compaction_bytes_written": receipt.compaction_bytes_written,
        "write_amplification": receipt.write_amplification,
        "compacted_postings": receipt.compacted_postings,
        "state_compacted": receipt.state_compacted,
        "reclaimed_files": receipt.reclaimed_files,
        "reclaimed_bytes": receipt.reclaimed_bytes,
    })
}

fn limits_json(limits: &SpannPostingLimits) -> Value {
    json!({
        "max_members_per_segment": limits.max_members_per_segment,
        "max_nnz_per_member": limits.max_nnz_per_member,
        "max_decoded_segment_bytes": limits.max_decoded_segment_bytes,
        "max_compressed_segment_bytes": limits.max_compressed_segment_bytes,
        "max_segments_per_posting": limits.max_segments_per_posting,
        "max_state_segments": limits.max_state_segments,
        "max_manifest_chain": limits.max_manifest_chain,
        "max_reader_leases": limits.max_reader_leases,
        "max_manifest_bytes": limits.max_manifest_bytes,
        "max_centroid_file_bytes": limits.max_centroid_file_bytes,
        "max_query_decoded_bytes": limits.max_query_decoded_bytes,
        "cache_capacity_bytes": limits.cache_capacity_bytes,
        "zstd_level": limits.zstd_level,
        "zstd_window_log_max": limits.zstd_window_log_max,
        "boundary_epsilon": f32::from_bits(limits.boundary_epsilon_bits),
        "max_replication": limits.max_replication,
        "max_reclaim_files": limits.max_reclaim_files,
    })
}

fn error_json(error: &CalyxError) -> Value {
    json!({
        "code": error.code,
        "message": error.message,
        "remediation": error.remediation,
    })
}

#[cfg(windows)]
fn process_rss_bytes() -> Result<u64, CalyxError> {
    use std::mem::{size_of, zeroed};
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // SAFETY: the structure size is initialized as required and both pointers
    // remain valid for the duration of the Windows API call.
    unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS = zeroed();
        counters.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(
            GetCurrentProcess(),
            &mut counters,
            size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ) == 0
        {
            return Err(io_error(
                "read process RSS",
                std::io::Error::last_os_error(),
            ));
        }
        Ok(counters.WorkingSetSize as u64)
    }
}

#[cfg(not(windows))]
fn process_rss_bytes() -> Result<u64, CalyxError> {
    Err(driver_error(
        "RSS FSV is implemented for the shipping Windows target",
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn driver_error(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: "CALYX_SPANN_FSV_FAILED",
        message: message.into(),
        remediation: "inspect the persisted FSV store and fix the production SPANN path",
    }
}

fn io_error(stage: &str, error: std::io::Error) -> CalyxError {
    CalyxError {
        code: "CALYX_SPANN_FSV_IO",
        message: format!("{stage}: {error}"),
        remediation: "inspect the exact FSV path, permissions, and persisted bytes",
    }
}
