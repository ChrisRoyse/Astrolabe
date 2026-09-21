//! Manual Full State Verification for atomic fleet kernel generations (#1151).
//!
//! This driver consumes two operator-supplied genuine external-query captures
//! and real, already-indexed repository vaults. It never invents queries,
//! relevance judgments, vectors, repository rows, or evaluator evidence.
//!
//! Run it only through the native launcher/manual-FSV artifact protocol against
//! a dedicated fleet catalog scope. `--evidence-root` must be a new ordinary
//! issue-scoped directory (for example
//! `.tmp\manual-fsv\issue-1151\fleet-generation-g1`), while `--catalog-root`
//! and `--store-root` must name real prepared fleet state. The catalog must
//! contain every `--repo` and the `--missing-repo`; the latter must deliberately
//! have no repository vault so the production missing-source refusal can be
//! observed without deleting anything.
//!
//! The bounded run performs four real compose admissions (A, B, A, unchanged
//! A), complete atomic/source readback after each publication, explicit deep
//! retention/tombstone verification, one missing-repository refusal, two warm
//! `O(C log C + sum(open_i) + R)` catalog/open/header passes, two isolated legacy-pointer
//! refusals, and checked arithmetic/cache-clock edges. At production
//! `N=192,873/E=328,899` (2026-08-20), each publication/readback pays the full
//! production compose cost; fleet totals remain unknown and are reported only
//! from the selected persisted generation (PC-02/03/04/07/14/15/24/28/32/35/
//! 37/38/41/43; #1064).

use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use astrolabe_fleet::compose::{
    ASTRO_FLEET_KERNEL_MISSING, ComposeConfig, compose_fleet_kernel, load_repo_kernel,
    manual_fsv_arithmetic_overflow_edges, read_verified_fleet_kernel_generation,
    verify_fleet_kernel_generation_sources,
};
use astrolabe_fleet::kernel_generation::{
    FleetKernelAdmissionInput, read_current_fleet_kernel_generation_header,
    verify_fleet_kernel_generation_retention,
};
use astrolabe_fleet::orchestrator::{SHADOW_VAULT_ID, catalog_store_identity};
use astrolabe_fleet::{CurrentFleetKernelGeneration, FleetCatalog};
use astrolabe_server::migration::manual_fsv_cache_clock_overflow;
use astrolabe_weave::{ASTRO_KERNEL_GENERATION_CORRUPT, read_current_kernel_generation_header};
use calyx_aster::cf::{ColumnFamily, ledger_key};
use calyx_aster::mvcc::tombstone_value;
use calyx_aster::vault::{AsterVault, PhysicalCommitInventory, VaultOptions};
use calyx_core::{CalyxError, VaultId};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

type AnyError = Box<dyn Error + Send + Sync + 'static>;
type AnyResult<T> = Result<T, AnyError>;

const FSV_ERROR: &str = "ISSUE_1151_FLEET_GENERATION_FSV_FAILED";
const REPORT_SCHEMA: &str = "astrolabe.issue_1151.fleet_generation_fsv.v1";

#[derive(Debug)]
struct Args {
    catalog_root: PathBuf,
    store_root: PathBuf,
    evidence_root: PathBuf,
    scope: String,
    admission_a: PathBuf,
    admission_b: PathBuf,
    repos: Vec<String>,
    missing_repo: String,
}

fn failure(message: impl Into<String>) -> AnyError {
    Box::new(CalyxError {
        code: FSV_ERROR,
        message: message.into(),
        remediation: "preserve every input/output byte, repair the exact failed contract, and rerun the complete native manual FSV from a new evidence root",
    })
}

fn require(condition: bool, message: impl Into<String>) -> AnyResult<()> {
    if condition {
        Ok(())
    } else {
        Err(failure(message))
    }
}

fn required_value(
    iter: &mut impl Iterator<Item = String>,
    name: &'static str,
) -> AnyResult<String> {
    iter.next()
        .ok_or_else(|| failure(format!("{name} requires one value")))
}

fn parse_args() -> AnyResult<Args> {
    let mut catalog_root = None;
    let mut store_root = None;
    let mut evidence_root = None;
    let mut scope = None;
    let mut admission_a = None;
    let mut admission_b = None;
    let mut repos = Vec::new();
    let mut missing_repo = None;
    let mut iter = env::args().skip(1);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--catalog-root" => {
                catalog_root = Some(PathBuf::from(required_value(&mut iter, "--catalog-root")?));
            }
            "--store-root" => {
                store_root = Some(PathBuf::from(required_value(&mut iter, "--store-root")?));
            }
            "--evidence-root" => {
                evidence_root = Some(PathBuf::from(required_value(&mut iter, "--evidence-root")?));
            }
            "--scope" => scope = Some(required_value(&mut iter, "--scope")?),
            "--admission-a" => {
                admission_a = Some(PathBuf::from(required_value(&mut iter, "--admission-a")?));
            }
            "--admission-b" => {
                admission_b = Some(PathBuf::from(required_value(&mut iter, "--admission-b")?));
            }
            "--repo" => repos.push(required_value(&mut iter, "--repo")?),
            "--missing-repo" => {
                missing_repo = Some(required_value(&mut iter, "--missing-repo")?);
            }
            _ => return Err(failure(format!("unknown argument {arg:?}"))),
        }
    }
    let args = Args {
        catalog_root: catalog_root.ok_or_else(|| failure("--catalog-root is required"))?,
        store_root: store_root.ok_or_else(|| failure("--store-root is required"))?,
        evidence_root: evidence_root.ok_or_else(|| failure("--evidence-root is required"))?,
        scope: scope.ok_or_else(|| failure("--scope is required"))?,
        admission_a: admission_a.ok_or_else(|| failure("--admission-a is required"))?,
        admission_b: admission_b.ok_or_else(|| failure("--admission-b is required"))?,
        repos,
        missing_repo: missing_repo.ok_or_else(|| failure("--missing-repo is required"))?,
    };
    require(!args.repos.is_empty(), "at least one --repo is required")?;
    require(
        !args.repos.iter().any(|repo| repo == &args.missing_repo),
        "--missing-repo must not duplicate the complete publication roster",
    )?;
    require(
        !args.scope.trim().is_empty(),
        "--scope must be a nonempty dedicated fleet scope",
    )?;
    Ok(args)
}

fn read_admission(path: &Path) -> AnyResult<(FleetKernelAdmissionInput, Vec<u8>)> {
    let bytes = fs::read(path)?;
    let admission: FleetKernelAdmissionInput = serde_json::from_slice(&bytes)?;
    admission.validate()?;
    require(
        admission.source_kind == "external_operator_query_log",
        format!(
            "admission {} is not an external operator query capture",
            path.display()
        ),
    )?;
    require(
        !admission.queries.is_empty(),
        format!("admission {} has no genuine query rows", path.display()),
    )?;
    Ok((admission, bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex(value: &str, label: &str) -> AnyResult<Vec<u8>> {
    let bytes = value.as_bytes();
    require(
        bytes.len().is_multiple_of(2),
        format!("{label} has an odd-length hex encoding"),
    )?;
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = decode_hex_nibble(pair[0])
            .ok_or_else(|| failure(format!("{label} contains non-hex bytes")))?;
        let low = decode_hex_nibble(pair[1])
            .ok_or_else(|| failure(format!("{label} contains non-hex bytes")))?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn physical_bound_row_receipt(
    inventory: &PhysicalCommitInventory,
    logical_name: &str,
    key: &[u8],
    logical_bytes: &[u8],
    manifest_bytes: u64,
    manifest_blake3: &str,
) -> AnyResult<Value> {
    let matches = inventory
        .rows
        .iter()
        .filter(|row| row.cf == ColumnFamily::Kernel && row.key == key)
        .collect::<Vec<_>>();
    require(
        matches.len() == 1,
        format!(
            "bound generation row {logical_name:?} occurs {} times in physical commit {}",
            matches.len(),
            inventory.seq,
        ),
    )?;
    let row = matches[0];
    let observed_sha256: [u8; 32] = Sha256::digest(logical_bytes).into();
    let observed_blake3 = blake3::hash(logical_bytes).to_hex().to_string();
    require(
        !row.tombstoned
            && row.value_length == manifest_bytes
            && row.value_length as u128 == logical_bytes.len() as u128
            && row.value_sha256 == observed_sha256
            && observed_blake3 == manifest_blake3,
        format!(
            "bound generation row {logical_name:?} physical/logical/manifest digest mismatch: ordinal={} tombstoned={} physical_bytes={} logical_bytes={} manifest_bytes={manifest_bytes} physical_sha256={} logical_sha256={} manifest_blake3={manifest_blake3} logical_blake3={observed_blake3}",
            row.ordinal,
            row.tombstoned,
            row.value_length,
            logical_bytes.len(),
            row.value_sha256_hex(),
            hex_lower(&observed_sha256),
        ),
    )?;
    Ok(json!({
        "logical_name": logical_name,
        "key_hex": hex_lower(key),
        "physical_ordinal": row.ordinal,
        "bytes": row.value_length,
        "key_sha256": row.key_sha256_hex(),
        "value_sha256": row.value_sha256_hex(),
        "manifest_blake3": manifest_blake3,
        "tombstoned": row.tombstoned,
    }))
}

fn physical_retired_tombstone_receipts(
    catalog: &FleetCatalog,
    inventory: &PhysicalCommitInventory,
    retired: &CurrentFleetKernelGeneration,
) -> AnyResult<Vec<Value>> {
    let mut expected = retired
        .manifest
        .rows
        .iter()
        .map(|row| (row.logical_name.clone(), row.key_hex.clone()))
        .collect::<Vec<_>>();
    expected.push((
        "manifest.json".to_string(),
        retired.pointer.current.manifest_key_hex.clone(),
    ));
    require(
        expected.len() == 12,
        format!(
            "retired generation {} does not name the expected 11 rows plus manifest",
            retired.manifest.generation_id,
        ),
    )?;

    let exact_tombstone = tombstone_value();
    let exact_tombstone_sha256: [u8; 32] = Sha256::digest(&exact_tombstone).into();
    let mut receipts = Vec::with_capacity(expected.len());
    for (logical_name, key_hex) in expected {
        let key = decode_hex(&key_hex, "retired generation key")?;
        require(
            catalog
                .vault()
                .read_cf_at(inventory.seq, ColumnFamily::Kernel, &key)?
                .is_none(),
            format!(
                "retired generation row {logical_name:?} remains logically visible at commit {}",
                inventory.seq,
            ),
        )?;
        let matches = inventory
            .rows
            .iter()
            .filter(|row| row.cf == ColumnFamily::Kernel && row.key == key)
            .collect::<Vec<_>>();
        require(
            matches.len() == 1,
            format!(
                "retired generation row {logical_name:?} occurs {} times in physical commit {}",
                matches.len(),
                inventory.seq,
            ),
        )?;
        let row = matches[0];
        require(
            row.tombstoned
                && row.value_length == exact_tombstone.len() as u64
                && row.value_sha256 == exact_tombstone_sha256,
            format!(
                "retired generation row {logical_name:?} is not the exact physical tombstone: ordinal={} tombstoned={} bytes={} sha256={}",
                row.ordinal,
                row.tombstoned,
                row.value_length,
                row.value_sha256_hex(),
            ),
        )?;
        receipts.push(json!({
            "logical_name": logical_name,
            "key_hex": key_hex,
            "physical_ordinal": row.ordinal,
            "bytes": row.value_length,
            "key_sha256": row.key_sha256_hex(),
            "value_sha256": row.value_sha256_hex(),
            "tombstoned": row.tombstoned,
        }));
    }
    Ok(receipts)
}

fn physical_time_index_receipt(
    catalog: &FleetCatalog,
    inventory: &PhysicalCommitInventory,
) -> AnyResult<Value> {
    let rows = inventory
        .rows
        .iter()
        .filter(|row| row.cf == ColumnFamily::TimeIndex)
        .collect::<Vec<_>>();
    require(
        rows.len() == 1,
        format!(
            "generation commit {} contains {} physical TimeIndex rows instead of one",
            inventory.seq,
            rows.len(),
        ),
    )?;
    let row = rows[0];
    require(
        row.key.len() == 16,
        format!(
            "generation TimeIndex key has {} bytes instead of 16",
            row.key.len(),
        ),
    )?;
    let observed_millis = u64::from_be_bytes(
        row.key[..8]
            .try_into()
            .map_err(|_| failure("generation TimeIndex millis is not eight bytes"))?,
    );
    let observed_seq = u64::from_be_bytes(
        row.key[8..]
            .try_into()
            .map_err(|_| failure("generation TimeIndex sequence is not eight bytes"))?,
    );
    let logical_bytes = catalog
        .vault()
        .read_cf_at(inventory.seq, ColumnFamily::TimeIndex, &row.key)?
        .ok_or_else(|| failure("generation TimeIndex row is absent at its commit"))?;
    let logical_sha256: [u8; 32] = Sha256::digest(&logical_bytes).into();
    require(
        observed_millis > 0
            && observed_seq == inventory.seq
            && !row.tombstoned
            && logical_bytes == [0_u8]
            && row.value_length == 1
            && row.value_sha256 == logical_sha256,
        format!(
            "generation TimeIndex physical/logical row mismatch: millis={observed_millis} indexed_seq={observed_seq} commit_seq={} ordinal={} tombstoned={} physical_bytes={} logical_bytes={} physical_sha256={} logical_sha256={}",
            inventory.seq,
            row.ordinal,
            row.tombstoned,
            row.value_length,
            logical_bytes.len(),
            row.value_sha256_hex(),
            hex_lower(&logical_sha256),
        ),
    )?;
    Ok(json!({
        "millis_utc": observed_millis,
        "seq": observed_seq,
        "key_hex": hex_lower(&row.key),
        "physical_ordinal": row.ordinal,
        "bytes": row.value_length,
        "key_sha256": row.key_sha256_hex(),
        "value_sha256": row.value_sha256_hex(),
        "tombstoned": row.tombstoned,
    }))
}

fn physical_generation_evidence(
    catalog: &FleetCatalog,
    generation: &CurrentFleetKernelGeneration,
    retired: Option<&CurrentFleetKernelGeneration>,
) -> AnyResult<Value> {
    let commit_seq = generation.pointer.current.commit_seq;
    let inventory = catalog.vault().physical_commit_inventory(
        commit_seq,
        &[
            ColumnFamily::Kernel,
            ColumnFamily::Ledger,
            ColumnFamily::TimeIndex,
        ],
    )?;
    require(
        inventory.seq == commit_seq
            && inventory.column_families.len() == 3
            && inventory.column_families.contains(&ColumnFamily::Kernel)
            && inventory.column_families.contains(&ColumnFamily::Ledger)
            && inventory.column_families.contains(&ColumnFamily::TimeIndex),
        format!(
            "physical commit inventory selected the wrong generation/CF set: wanted_seq={commit_seq} observed_seq={} cfs={:?}",
            inventory.seq, inventory.column_families,
        ),
    )?;

    let mut bound_rows = Vec::with_capacity(generation.manifest.rows.len());
    for binding in &generation.manifest.rows {
        let key = decode_hex(&binding.key_hex, "bound generation key")?;
        let logical_bytes = catalog
            .vault()
            .read_cf_at(commit_seq, ColumnFamily::Kernel, &key)?
            .ok_or_else(|| {
                failure(format!(
                    "bound generation row {:?} is absent at its commit",
                    binding.logical_name,
                ))
            })?;
        bound_rows.push(physical_bound_row_receipt(
            &inventory,
            &binding.logical_name,
            &key,
            &logical_bytes,
            binding.bytes,
            &binding.blake3,
        )?);
    }
    require(
        bound_rows.len() == 11,
        format!(
            "physical generation receipt bound {} immutable rows instead of 11",
            bound_rows.len(),
        ),
    )?;

    let wanted_ledger = BTreeSet::from([generation.manifest.ledger_ref.seq]);
    let (ledger_rows, ledger_trace) = catalog.vault().read_physical_ledger_seqs(&wanted_ledger)?;
    let ledger = ledger_rows
        .get(&generation.manifest.ledger_ref.seq)
        .ok_or_else(|| failure("fresh physical Ledger read omitted the generation Ledger row"))?;
    let expected_ledger_key = ledger_key(generation.manifest.ledger_ref.seq);
    let ledger_sha256: [u8; 32] = Sha256::digest(&ledger.bytes).into();
    let ledger_row_count = inventory
        .rows
        .iter()
        .filter(|row| row.cf == ColumnFamily::Ledger)
        .count();
    let physical_ledger_rows = inventory
        .rows
        .iter()
        .filter(|row| row.cf == ColumnFamily::Ledger && row.key == expected_ledger_key)
        .collect::<Vec<_>>();
    require(
        ledger_row_count == 1 && physical_ledger_rows.len() == 1,
        format!(
            "generation commit {} contains {ledger_row_count} physical Ledger rows and {} exact-key matches instead of one of each",
            commit_seq,
            physical_ledger_rows.len(),
        ),
    )?;
    let physical_ledger = physical_ledger_rows[0];
    require(
        !physical_ledger.tombstoned
            && physical_ledger.value_length as u128 == ledger.bytes.len() as u128
            && physical_ledger.value_sha256 == ledger_sha256,
        format!(
            "generation Ledger physical inventory differs from fresh point read: ordinal={} tombstoned={} physical_bytes={} read_bytes={} physical_sha256={} read_sha256={}",
            physical_ledger.ordinal,
            physical_ledger.tombstoned,
            physical_ledger.value_length,
            ledger.bytes.len(),
            physical_ledger.value_sha256_hex(),
            hex_lower(&ledger_sha256),
        ),
    )?;
    let time_index = physical_time_index_receipt(catalog, &inventory)?;

    let retired_tombstones = match (
        generation.manifest.retired_generation_id.as_deref(),
        retired,
    ) {
        (None, None) => Vec::new(),
        (Some(expected), Some(retired)) if expected == retired.manifest.generation_id => {
            physical_retired_tombstone_receipts(catalog, &inventory, retired)?
        }
        (expected, observed) => {
            return Err(failure(format!(
                "physical retirement input differs from manifest: expected={expected:?} observed={:?}",
                observed.map(|generation| generation.manifest.generation_id.as_str()),
            )));
        }
    };
    let kernel_row_count = inventory
        .rows
        .iter()
        .filter(|row| row.cf == ColumnFamily::Kernel)
        .count();
    let kernel_tombstone_count = inventory
        .rows
        .iter()
        .filter(|row| row.cf == ColumnFamily::Kernel && row.tombstoned)
        .count();
    let expected_kernel_rows = 13 + retired_tombstones.len();
    require(
        kernel_row_count == expected_kernel_rows
            && kernel_tombstone_count == retired_tombstones.len(),
        format!(
            "physical fleet commit has an unexpected Kernel write set: rows={kernel_row_count} expected={expected_kernel_rows} tombstones={kernel_tombstone_count} expected_tombstones={}",
            retired_tombstones.len(),
        ),
    )?;
    let components = inventory
        .components
        .iter()
        .map(|component| {
            json!({
                "role": format!("{:?}", component.role),
                "container": component.container.name(),
                "identity": component.canonical_identity(),
                "relative_path": component.relative_path,
                "offset": component.offset,
                "bytes": component.length,
                "sha256": component.sha256_hex(),
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "schema": "astrolabe.issue_1151.physical_generation_receipt.v1",
        "commit_seq": commit_seq,
        "manifest_seq": inventory.manifest_seq,
        "column_families": inventory.column_families.iter().map(ColumnFamily::name).collect::<Vec<_>>(),
        "physical_rows_in_commit": inventory.rows.len(),
        "physical_kernel_rows_in_commit": kernel_row_count,
        "physical_kernel_tombstones_in_commit": kernel_tombstone_count,
        "total_physical_bytes": inventory.total_physical_bytes,
        "components": components,
        "bound_generation_row_count": bound_rows.len(),
        "bound_generation_rows": bound_rows,
        "ledger": {
            "seq": ledger.seq,
            "hash_hex": hex_lower(&generation.manifest.ledger_ref.hash),
            "key_hex": hex_lower(&expected_ledger_key),
            "physical_ordinal": physical_ledger.ordinal,
            "bytes": physical_ledger.value_length,
            "key_sha256": physical_ledger.key_sha256_hex(),
            "value_sha256": physical_ledger.value_sha256_hex(),
            "tombstoned": physical_ledger.tombstoned,
            "point_read_trace": ledger_trace,
        },
        "time_index": time_index,
        "retired_generation_id": generation.manifest.retired_generation_id,
        "retired_tombstone_count": retired_tombstones.len(),
        "retired_tombstones": retired_tombstones,
    }))
}

fn generation_evidence(generation: &CurrentFleetKernelGeneration) -> Value {
    json!({
        "manifest": &generation.manifest,
        "pointer": &generation.pointer,
        "rows_verified": generation.rows_verified,
        "ledger_physical_tiers": &generation.ledger_physical_tiers,
        "source_roster": &generation.source_roster,
        "query_count": generation.query_corpus.queries.len(),
        "report_hash": &generation.graph_routed_report.report_hash,
    })
}

fn verify_selected_generation(
    catalog: &FleetCatalog,
    store_root: &Path,
    scope: &str,
) -> AnyResult<CurrentFleetKernelGeneration> {
    let generation = read_verified_fleet_kernel_generation(catalog, store_root, scope)?;
    let retained = verify_fleet_kernel_generation_retention(catalog.vault(), scope)?
        .ok_or_else(|| failure("explicit retention verifier found no current generation"))?;
    require(
        retained == generation.pointer,
        "explicit retention verifier selected a different pointer",
    )?;
    require(
        generation.rows_verified == generation.manifest.rows.len()
            && generation.rows_verified == 11,
        format!(
            "atomic immutable-row readback was incomplete: verified={} manifest_rows={}",
            generation.rows_verified,
            generation.manifest.rows.len(),
        ),
    )?;
    require(
        !generation.ledger_physical_tiers.is_empty()
            && generation.manifest.ledger_ref == generation.pointer.current.ledger_ref,
        "atomic physical Ledger/pointer readback is incomplete",
    )?;
    Ok(generation)
}

fn append_part(out: &mut Vec<u8>, part: &[u8]) {
    out.extend_from_slice(&(part.len() as u64).to_be_bytes());
    out.extend_from_slice(part);
}

fn legacy_current_key(prefix: &[u8], project: &str, scope: &str) -> Vec<u8> {
    let mut key = prefix.to_vec();
    append_part(&mut key, project.as_bytes());
    append_part(&mut key, scope.as_bytes());
    append_part(&mut key, b"current.json");
    key
}

fn verify_legacy_pointer_refusal(root: &Path, version: &str) -> AnyResult<Value> {
    let prefix = match version {
        "v1" => b"astrolabe:kernel-generation-current:v1:".as_slice(),
        "v2" => b"astrolabe:kernel-generation-current:v2:".as_slice(),
        _ => return Err(failure(format!("unsupported legacy probe {version:?}"))),
    };
    let project = format!("issue-1151-legacy-{version}");
    let scope = format!("kernel:{project}");
    let vault_id = VaultId::from_str(SHADOW_VAULT_ID)?;
    let vault = AsterVault::open(
        root,
        vault_id,
        format!("astrolabe-issue-1151-legacy-{version}").into_bytes(),
        VaultOptions {
            restore_mvcc_rows: false,
            restore_ledger_hook: true,
            writable_selected_cfs: true,
            selected_cfs: Some(vec![
                ColumnFamily::Kernel,
                ColumnFamily::Ledger,
                ColumnFamily::TimeIndex,
            ]),
            ..VaultOptions::default()
        },
    )?;
    let key = legacy_current_key(prefix, &project, &scope);
    let commit_seq = vault.write_cf(
        ColumnFamily::Kernel,
        key.clone(),
        br#"{"schema":"deliberately-legacy-pointer-probe"}"#.to_vec(),
    )?;
    let flush = vault.flush_with_report()?;
    let error = match read_current_kernel_generation_header(&vault, &project, &scope) {
        Ok(_) => {
            return Err(failure(format!(
                "repository {version} legacy pointer was not refused"
            )));
        }
        Err(error) => error,
    };
    require(
        error.code() == ASTRO_KERNEL_GENERATION_CORRUPT
            && error.message().contains("stage=legacy_pointer_schema")
            && error.message().contains("v1/v2"),
        format!(
            "repository {version} legacy-pointer refusal was not exact: code={} message={:?}",
            error.code(),
            error.message(),
        ),
    )?;
    Ok(json!({
        "version": version,
        "key_hex": hex_lower(&key),
        "commit_seq": commit_seq,
        "flush_sst_files": flush.sst_files(),
        "code": error.code(),
        "message": error.message(),
    }))
}

fn same_header(
    left: &astrolabe_fleet::FleetKernelGenerationHeader,
    right: &astrolabe_fleet::FleetKernelGenerationHeader,
) -> bool {
    left.manifest == right.manifest && left.pointer == right.pointer
}

fn run() -> AnyResult<()> {
    let args = parse_args()?;
    require(
        !args.evidence_root.try_exists()?,
        format!(
            "evidence root {} already exists; manual FSV never overwrites an earlier run",
            args.evidence_root.display()
        ),
    )?;
    fs::create_dir_all(&args.evidence_root)?;
    let report_path = args.evidence_root.join("report.json");

    let (admission_a, admission_a_bytes) = read_admission(&args.admission_a)?;
    let (admission_b, admission_b_bytes) = read_admission(&args.admission_b)?;
    let admission_a_identity = admission_a.identity_blake3()?;
    let admission_b_identity = admission_b.identity_blake3()?;
    require(
        admission_a_identity != admission_b_identity,
        "A and B genuine external-query captures have the same canonical identity",
    )?;

    let catalog = FleetCatalog::open(&args.catalog_root)?;
    require(
        read_current_fleet_kernel_generation_header(catalog.vault(), &args.scope)?.is_none(),
        format!(
            "dedicated genesis scope {:?} already has an atomic current generation",
            args.scope
        ),
    )?;
    let missing_identity = catalog_store_identity(&catalog, &args.missing_repo)?;
    require(
        load_repo_kernel(
            &args.store_root,
            &missing_identity.store_key,
            &missing_identity.index_project,
        )?
        .is_none(),
        format!(
            "--missing-repo {:?} unexpectedly has a current repository generation; refusing before a compose call could publish it",
            args.missing_repo
        ),
    )?;

    let config = ComposeConfig::with_registry_defaults();
    let publish_a = compose_fleet_kernel(
        &catalog,
        &args.store_root,
        &args.scope,
        &args.repos,
        &config,
        &admission_a,
    )?;
    let generation_a = verify_selected_generation(&catalog, &args.store_root, &args.scope)?;
    let generation_a_physical = physical_generation_evidence(&catalog, &generation_a, None)?;
    require(
        generation_a.pointer.previous.is_none()
            && generation_a.pointer.retained_generation_count == 1
            && generation_a.manifest.previous_generation_id.is_none()
            && generation_a.manifest.retired_generation_id.is_none(),
        "genesis publication did not produce the exact one-generation retention state",
    )?;

    let publish_b = compose_fleet_kernel(
        &catalog,
        &args.store_root,
        &args.scope,
        &args.repos,
        &config,
        &admission_b,
    )?;
    let generation_b = verify_selected_generation(&catalog, &args.store_root, &args.scope)?;
    let generation_b_physical = physical_generation_evidence(&catalog, &generation_b, None)?;
    require(
        generation_b.manifest.generation_id != generation_a.manifest.generation_id
            && generation_b.manifest.source_generation_identity
                != generation_a.manifest.source_generation_identity
            && generation_b.manifest.previous_generation_id.as_deref()
                == Some(generation_a.manifest.generation_id.as_str())
            && generation_b
                .pointer
                .previous
                .as_ref()
                .map(|target| target.generation_id.as_str())
                == Some(generation_a.manifest.generation_id.as_str())
            && generation_b.manifest.retired_generation_id.is_none()
            && generation_b.pointer.retained_generation_count == 2,
        "B publication did not retain exact A lineage",
    )?;

    let publish_a_return = compose_fleet_kernel(
        &catalog,
        &args.store_root,
        &args.scope,
        &args.repos,
        &config,
        &admission_a,
    )?;
    let generation_a_return = verify_selected_generation(&catalog, &args.store_root, &args.scope)?;
    let generation_a_return_physical =
        physical_generation_evidence(&catalog, &generation_a_return, Some(&generation_a))?;
    require(
        generation_a_return.manifest.source_generation_identity
            == generation_a.manifest.source_generation_identity
            && generation_a_return.manifest.generation_id != generation_a.manifest.generation_id
            && generation_a_return.manifest.generation_id != generation_b.manifest.generation_id
            && generation_a_return
                .manifest
                .previous_generation_id
                .as_deref()
                == Some(generation_b.manifest.generation_id.as_str())
            && generation_a_return
                .manifest
                .retired_generation_id
                .as_deref()
                == Some(generation_a.manifest.generation_id.as_str())
            && generation_a_return.pointer.retained_generation_count == 2,
        "A->B->A recurrence reused an old id or lost predecessor/tombstone lineage",
    )?;

    let catalog_rows = catalog.query(None, None)?.len();
    let warm_source_verification =
        verify_fleet_kernel_generation_sources(&catalog, &args.store_root, &generation_a_return)?;
    let expected_warm_cfs = vec![
        ColumnFamily::Base.name(),
        ColumnFamily::Blob.name(),
        ColumnFamily::Kernel.name(),
        ColumnFamily::Ledger.name(),
    ];
    require(
        warm_source_verification.passes.len() == 2
            && warm_source_verification.passes.iter().all(|pass| {
                pass.catalog_scans == 1
                    && pass.catalog_rows_scanned == catalog_rows
                    && pass.repository_bindings_checked
                        == generation_a_return.source_roster.repositories.len()
                    && pass.repository_vault_opens == pass.repository_bindings_checked
                    && pass.selected_column_families == expected_warm_cfs
            }),
        format!("warm source-verification telemetry is incomplete: {warm_source_verification:?}"),
    )?;
    let warm_header = read_current_fleet_kernel_generation_header(catalog.vault(), &args.scope)?
        .ok_or_else(|| failure("warm source verification lost the current fleet header"))?;
    require(
        warm_header.manifest == generation_a_return.manifest
            && warm_header.pointer == generation_a_return.pointer
            && generation_a_return
                .source_roster
                .repositories
                .iter()
                .all(|binding| {
                    binding.kernel_header_blake3.len() == 64
                        && binding.base_content_generation > 0
                        && binding.blob_content_generation > 0
                }),
        "warm catalog/open/header/Base+Blob generation binding readback is incomplete",
    )?;

    let no_op_seq_before = catalog.vault().latest_seq();
    let no_op_header_before = warm_header;
    let no_op = compose_fleet_kernel(
        &catalog,
        &args.store_root,
        &args.scope,
        &args.repos,
        &config,
        &admission_a,
    )?;
    let no_op_header_after =
        read_current_fleet_kernel_generation_header(catalog.vault(), &args.scope)?
            .ok_or_else(|| failure("no-op compose removed the fleet current header"))?;
    require(
        catalog.vault().latest_seq() == no_op_seq_before
            && same_header(&no_op_header_before, &no_op_header_after),
        "same-current compose was not an exact no-write operation",
    )?;

    let missing_seq_before = catalog.vault().latest_seq();
    let missing_header_before = no_op_header_after;
    let mut incomplete_roster = args.repos.clone();
    incomplete_roster.push(args.missing_repo.clone());
    let missing_error = match compose_fleet_kernel(
        &catalog,
        &args.store_root,
        &args.scope,
        &incomplete_roster,
        &config,
        &admission_a,
    ) {
        Ok(_) => return Err(failure("missing-repository compose unexpectedly succeeded")),
        Err(error) => error,
    };
    let missing_header_after =
        read_current_fleet_kernel_generation_header(catalog.vault(), &args.scope)?.ok_or_else(
            || failure("missing-repository refusal removed the fleet current header"),
        )?;
    require(
        missing_error.code == ASTRO_FLEET_KERNEL_MISSING
            && catalog.vault().latest_seq() == missing_seq_before
            && same_header(&missing_header_before, &missing_header_after),
        format!(
            "missing-repository path was not fail-closed/no-write: code={} seq_before={missing_seq_before} seq_after={}",
            missing_error.code,
            catalog.vault().latest_seq(),
        ),
    )?;

    let legacy_v1 = verify_legacy_pointer_refusal(&args.evidence_root.join("legacy-v1"), "v1")?;
    let legacy_v2 = verify_legacy_pointer_refusal(&args.evidence_root.join("legacy-v2"), "v2")?;
    let arithmetic_edges = manual_fsv_arithmetic_overflow_edges()?;
    let cache_clock_edge = manual_fsv_cache_clock_overflow()?;

    let report = json!({
        "schema": REPORT_SCHEMA,
        "scope": args.scope,
        "catalog_root": args.catalog_root,
        "store_root": args.store_root,
        "repositories": args.repos,
        "missing_repository": args.missing_repo,
        "admissions": {
            "a": {
                "path": args.admission_a,
                "capture_sha256": sha256_hex(&admission_a_bytes),
                "identity_blake3": admission_a_identity,
                "source_kind": admission_a.source_kind,
                "query_count": admission_a.queries.len(),
            },
            "b": {
                "path": args.admission_b,
                "capture_sha256": sha256_hex(&admission_b_bytes),
                "identity_blake3": admission_b_identity,
                "source_kind": admission_b.source_kind,
                "query_count": admission_b.queries.len(),
            },
            "synthesized": false,
        },
        "genesis_a": {
            "compose": publish_a,
            "readback": generation_evidence(&generation_a),
            "physical_commit": generation_a_physical,
        },
        "generation_b": {
            "compose": publish_b,
            "readback": generation_evidence(&generation_b),
            "physical_commit": generation_b_physical,
        },
        "return_a": {
            "compose": publish_a_return,
            "readback": generation_evidence(&generation_a_return),
            "physical_commit": generation_a_return_physical,
            "original_source_identity_reused": true,
            "original_generation_id_reused": false,
        },
        "no_op": {
            "compose": no_op,
            "catalog_seq_unchanged": true,
            "pointer_unchanged": true,
        },
        "warm_source_verification": {
            "receipt": warm_source_verification,
            "cost": "O(C log C + sum(open_i) + R): one ordered C-row catalog scan/materialization plus each repository latest-state open and exact current pointer/manifest/Ledger and Base+Blob content-generation checks for R selected repositories; no N/E/K*D or fleet projection rebuild",
            "verified": true,
        },
        "missing_repository_refusal": {
            "code": missing_error.code,
            "catalog_seq_unchanged": true,
            "pointer_unchanged": true,
            "partial_generation_published": false,
        },
        "legacy_repository_pointer_refusals": [legacy_v1, legacy_v2],
        "numeric_edges": arithmetic_edges,
        "cache_clock_edge": cache_clock_edge,
        "production_cost_contract": {
            "measurement_date": "2026-08-20",
            "measured_repository_n": 192_873,
            "measured_repository_e": 328_899,
            "global_fleet_totals": "unknown; no fixture extrapolation",
            "pc_classes": ["PC-02", "PC-03", "PC-04", "PC-07", "PC-14", "PC-15", "PC-24", "PC-28", "PC-32", "PC-35", "PC-37", "PC-38", "PC-41", "PC-43"],
        },
        "verdict": "verified",
    });
    let report_bytes = serde_json::to_vec_pretty(&report)?;
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&report_path)?;
    output.write_all(&report_bytes)?;
    output.sync_all()?;
    let readback = fs::read(&report_path)?;
    require(
        readback == report_bytes,
        "manual FSV report readback differs byte-for-byte",
    )?;
    println!(
        "ISSUE_1151_FLEET_GENERATION_FSV_SOURCE_OF_TRUTH path={} bytes={} sha256={}",
        report_path.display(),
        readback.len(),
        sha256_hex(&readback),
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{FSV_ERROR}: {error}");
        std::process::exit(1);
    }
}
