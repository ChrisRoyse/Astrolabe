use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, Instant};

use calyx_aster::cf::{
    ColumnFamily, compression_lifecycle_prefix_range, compression_manifest_key,
};
use calyx_aster::mvcc::tombstone_value;
use calyx_aster::vault::{AsterVault, VaultOptions, encode};
use calyx_core::{
    Asymmetry, Constellation, CxFlags, CxId, FixedClock, Input, InputRef, LedgerRef, Modality,
    QuantPolicy, Slot, SlotId, SlotResource, SlotShape, SlotState, SlotVector, VaultId, VaultStore,
};
use calyx_forge::{
    QuantLevel, QuantizedVec, Quantizer, TURBOQUANT_FORMAT_HEADER_BYTES, TurboQuantCodec, new_seed,
};
use calyx_registry::{
    AlgorithmicLens, CompressionQuery, LensRuntime, LensSpec, REGISTRY_ENVELOPE_HEADER_BYTES,
    Registry, SlotCompressionReport, StoredSlotCodec, compress_slot_batch,
    inspect_unbound_stored_slot_envelope, matryoshka_truncate_renormalize,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FIXED_TS: u64 = 1_783_987_200_000;
const PANEL_VERSION: u32 = 1;
const HAPPY_DIM: u32 = 128;
const MAX_DIM: u32 = 4096;
const OVER_LIMIT_DIM: u32 = 4097;
const MANIFEST_BYTES: usize = 148;
const MANIFEST_PREFIX_BYTES: usize = 116;
const CURRENT_OUTER_V3_PREFIX_BYTES: usize = 137;
const LEGACY_OUTER_V2_HEADER_BYTES: usize = 85;
const LEGACY_TQPR_V1_HEADER_BYTES: usize = 88;
const LEGACY_TQPR_V1_PREFIX_BYTES: usize = 56;
const LEGACY_WRITER_COMMIT: &str = "f6c8d778e1e73f2adc60e822ec0c2e8693ff0a99";
const LEGACY_WRITER_SOURCE_BLOBS: &[(&str, &str, &str)] = &[
    (
        "calyx/crates/calyx-forge/src/quant/turboquant.rs",
        "f76b929ae3c6dbe2052b6fcb2cb700912b9e7867",
        "8a1d11a23147c5b1bbac42dcb89e70d54103c160bbfa26b8e0f7ae95469052f5",
    ),
    (
        "calyx/crates/calyx-forge/src/quant/codebook.rs",
        "620fce1baaf42f84fd022f9dc1bd2ec2102c1287",
        "39c7f659c32770dd0643b3134d8aa0de926cadb44292c6c0f81daa87cf5c8806",
    ),
    (
        "calyx/crates/calyx-forge/src/quant/qjl.rs",
        "8e44eaf557fd0be1299bc054dc9dacfc5b13a557",
        "951d699a1f4f2333c2011973657dcbbf01d79d5b11b1d7d936b876032c65ea5f",
    ),
    (
        "calyx/crates/calyx-forge/src/quant/rotation.rs",
        "3c0c504606eb3c1470bdbace6b856444626d5664",
        "7edba36641b21281dc1ac1898e4c9dff8bdf47a86dc9ed1293d686d1c5262dc0",
    ),
    (
        "calyx/crates/calyx-registry/src/compression/codec.rs",
        "d137c1b2b19e6dfe4f1ddf079af2456eef0fc869",
        "bcd347e0e585c2a391b79a0d3bbca3a6c0889273fc4f1eaffaeb896f6041fa7d",
    ),
];
const LEGACY_TQ25_128_SHA256: &str =
    "25f572987afd1c2606ad9761c72c65d79e098535dfee9150bcc4a78c65b4d18e";
const LEGACY_TQ35_128_SHA256: &str =
    "add912589e02c71b9ea91f884993b7330352753ec81d5a2f676fe8613cc74bd0";
const LEGACY_TQ25_64_SHA256: &str =
    "d60a82a7df86888bf305e6eb9f183fb9e2428195943b1e6db8ac04a4c0483ba3";
const LEGACY_TQ25_128_ROWS: &[(&str, &str)] = &[
    (
        "8253d0cbc1b657329879d6e6aa011d24",
        "100202050000008000000080003f8000009f04ae112afa8d3e85629067e619d9004028d1bf2ebd04e1816c684e4f7da8f200000080d978aacee9c8475de5a9cbcaf0747eb06785c49fc3ecd81a29d67adb9bf9fc9b545150520101000080000000c000000080000000cb3ef13e9f04ae112afa8d3e85629067e619d9004028d1bf2ebd04e1816c684e4f7da8f2f3aa636592c2b2a3986d5700ac90d08f457c0d0ca586cbd04be04660bee14d4b960ba3f50e5837f5289d23168393ccf5afb476e3d024342dd43648084c9db40b8b08910f3c097a77",
    ),
    (
        "90ab579cef31f9b1d2bd6382dcea7512",
        "100202050000008000000080003f8000009f04ae112afa8d3e85629067e619d9004028d1bf2ebd04e1816c684e4f7da8f200000080370ad31cdfee4693335547be1465db5c04fda047e1558a28adac6a5197aabcb4545150520101000080000000c000000080000000178bf23e9f04ae112afa8d3e85629067e619d9004028d1bf2ebd04e1816c684e4f7da8f2855f1f6df9a02c27fc0d2c9266395800e602e0402a6428bda7658b04aed4c8bd451ac6771e272d96aa904118a5968add048b722f4d936b37da405d267c0bb78dea0725a8b796eed3",
    ),
    (
        "d62233d29935f3a153b49d39cc480b95",
        "100202050000008000000080003f8000009f04ae112afa8d3e85629067e619d9004028d1bf2ebd04e1816c684e4f7da8f2000000809a77e8ac1647b3dff2ce66be2e3b6bb79acf9604e44469c916b1323ebfe5bd4a545150520101000080000000c000000080000000520efc3e9f04ae112afa8d3e85629067e619d9004028d1bf2ebd04e1816c684e4f7da8f2a7abbca68e2eb30bbba10113f2f13cae53bb0b1b35f33972b98a20627d4c9319ea6f7f289dcf757b030d266816d41854e63bb5d346b32a9de081e3bdf3b72319bf7fd2523dc3cf27",
    ),
    (
        "ea451c0f9b3693c62968f22b8bbcd24f",
        "100202050000008000000080003f8000009f04ae112afa8d3e85629067e619d9004028d1bf2ebd04e1816c684e4f7da8f2000000803704d1dbb394e6c568e12663c81091a93b93d0b1a0db3701a520fe2103cdbdee545150520101000080000000c0000000800000003e58033f9f04ae112afa8d3e85629067e619d9004028d1bf2ebd04e1816c684e4f7da8f2ec1ed4df2ac6eec66d403078509ebca5ef1923fd327fd04f1a7db763b30afee6a211924a564a94bf447f9b414d97a09b8dd28a00482a544efcc33131f13708d3ad6b564ea5a45835",
    ),
];
const LEGACY_TQ35_128_ROWS: &[(&str, &str)] = &[
    (
        "8253d0cbc1b657329879d6e6aa011d24",
        "100201040000008000000080003f800000524ea7fe18609bde23d66f818940e35ed43ae8a8f47163586b3d7c64f0c40e9400000090c6eb0d36c0638dc24b639e953da010f2d57827a505292729dbca59e67d7b4e645451505201020000800000004001000080000000fa93853e524ea7fe18609bde23d66f818940e35ed43ae8a8f47163586b3d7c64f0c40e94253fe347c09b8bd9f8e9846d0f6a8f5c5f1c961ba8734a7ad3f1c5386024227c5356cb1593c5f73be8f4bfbae6795592add5aa6d7ab1fd64a4a4ae070789558b0593d3848e122d9dddb0e5321803e4b5fa3f60c501341cfa",
    ),
    (
        "90ab579cef31f9b1d2bd6382dcea7512",
        "100201040000008000000080003f800000524ea7fe18609bde23d66f818940e35ed43ae8a8f47163586b3d7c64f0c40e94000000908ef83ab0022e351673fc06ca9f82ddc593d6a9b1ba81e6477f8694666ab48d655451505201020000800000004001000080000000ce3a803e524ea7fe18609bde23d66f818940e35ed43ae8a8f47163586b3d7c64f0c40e9441ef6db02b73b99f5a48721ff0ab5bccbd7349ad59cdf9cbc04545d3b07de536bf0c35e5e0448e16370f57925a758acc33ffad4eac6a39a952aa08b2a84a4dccb2f97c7d943d888c47eb463b754dbf2a6c1579608aad87f4",
    ),
    (
        "d62233d29935f3a153b49d39cc480b95",
        "100201040000008000000080003f800000524ea7fe18609bde23d66f818940e35ed43ae8a8f47163586b3d7c64f0c40e9400000090f32b61705d56d6cc1ad7a44dcacf39398f565950a41975fe73072e571c8883d25451505201020000800000004001000080000000f6e3943e524ea7fe18609bde23d66f818940e35ed43ae8a8f47163586b3d7c64f0c40e9427a4d1846c21ddc15f359bf4ec4a1ea5f14884f90a47609b263f347bf81791982a4eaed665cb2b75eb816db36591a766dbb64d289325d96b7174bd9914f33192c7b9a495253a7b219fd790856983cbf7a1ad9746a40167e0",
    ),
    (
        "ea451c0f9b3693c62968f22b8bbcd24f",
        "100201040000008000000080003f800000524ea7fe18609bde23d66f818940e35ed43ae8a8f47163586b3d7c64f0c40e9400000090bab9cc44421d9d40a827c5e037a678759b85453439fcad3252376968fa44d3b254515052010200008000000040010000800000001554923e524ea7fe18609bde23d66f818940e35ed43ae8a8f47163586b3d7c64f0c40e948980981a173f813266cf45e18a207c56d27ee9f976028f0af8246d360e36d6b615f3d6d48e6273ac9934b22ea726ab2c75c944a17d73dd69757309c5a7b0d37597f2a6755d6bdd627e2ee4aade0048404c1ea07a00732be4",
    ),
];
const LEGACY_TQ25_64_ROWS: &[(&str, &str)] = &[
    (
        "8253d0cbc1b657329879d6e6aa011d24",
        "100202050000008000000040023f800000978b49c2d287b90b5eef21dd7fa289f6b9a54209115e10755ffdbbeeacfe2d0e0000006c5e73ed9098f42def8f24e76bf526325328ef271611ef5c527d62baab08220fcb5451505201010000400000006000000040000000d970103f978b49c2d287b90b5eef21dd7fa289f6b9a54209115e10755ffdbbeeacfe2d0e9697f6afb275018fde330717848ca88cb1c8184068438988f1de239349239fabee624a0fdfc869c558a9c538df736cf0fca4f7f2",
    ),
    (
        "90ab579cef31f9b1d2bd6382dcea7512",
        "100202050000008000000040023f800000978b49c2d287b90b5eef21dd7fa289f6b9a54209115e10755ffdbbeeacfe2d0e0000006ce4d8725b0aff889b0de5a91ece6377b03872cf822170667ac9d815e00125cafd54515052010100004000000060000000400000003cd7f23e978b49c2d287b90b5eef21dd7fa289f6b9a54209115e10755ffdbbeeacfe2d0e1b890476ac797c89584f711f90cff09a14070e419508c697a54922b0d28d9ad7b693f6c021e49ba54852e5876be2aed4435a7c69",
    ),
    (
        "d62233d29935f3a153b49d39cc480b95",
        "100202050000008000000040023f800000978b49c2d287b90b5eef21dd7fa289f6b9a54209115e10755ffdbbeeacfe2d0e0000006c2127de77fff0cb4698db4f584703fefecd7e24a88e5fe4839776bfdacb21a1575451505201010000400000006000000040000000c9f3003f978b49c2d287b90b5eef21dd7fa289f6b9a54209115e10755ffdbbeeacfe2d0e1fa4ef543f39e6df8dee59fd59a993b2bca44dec24d448160d1843dea64f5ca5b02eab9202b14a07c7906b443a55e7e4a153026e",
    ),
    (
        "ea451c0f9b3693c62968f22b8bbcd24f",
        "100202050000008000000040023f800000978b49c2d287b90b5eef21dd7fa289f6b9a54209115e10755ffdbbeeacfe2d0e0000006c90b9f0cc2da91c7dd0eed1c3395bcd9ac95e6a48a6c821249b464566d4fdfbca54515052010100004000000060000000400000001ad3ee3e978b49c2d287b90b5eef21dd7fa289f6b9a54209115e10755ffdbbeeacfe2d0ef21d305266dedeb937619f7a86a1a9f70b7b042eb934ed38697c9346592d63e7aa926ac10389156b3c508ce67831920e119f1c2a",
    ),
];
const VAULT_SALT: &[u8] = b"issue-551-fsv-vault-salt-v1";
const VAULT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

type AnyResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct FsvFailure {
    code: &'static str,
    message: String,
    remediation: &'static str,
}

impl fmt::Display for FsvFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}; remediation: {}",
            self.code, self.message, self.remediation
        )
    }
}

impl Error for FsvFailure {}

#[derive(Clone)]
struct RegisteredSlot {
    lens_id: calyx_core::LensId,
    slot: Slot,
    bits_per_channel_x2: u8,
    truncate_dim: Option<u32>,
}

struct Corpus {
    inputs: Vec<Vec<u8>>,
    cx_ids: Vec<CxId>,
    rows_by_slot: BTreeMap<SlotId, Vec<(CxId, Vec<f32>)>>,
    queries_by_slot: BTreeMap<SlotId, CompressionQuery>,
    expected_top1: CxId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PhysicalDigest {
    files: usize,
    bytes: u64,
    sha256: String,
}

fn main() {
    if let Err(error) = run() {
        println!(
            "{}",
            json!({
                "event": "fsv_failure",
                "error": error.to_string(),
            })
        );
        std::process::exit(1);
    }
}

fn run() -> AnyResult<()> {
    let workspace = std::env::current_dir()?;
    let root = workspace.join("target").join("issue-551-compression-fsv");
    ensure_fixture_boundary(&workspace, &root)?;
    if root.exists() {
        fs::remove_dir_all(&root)?;
    }
    fs::create_dir_all(&root)?;

    let artifact = std::env::current_exe()?;
    let tree_head = required_hex_env("ASTRO_FSV_TREE_HEAD", 40)?;
    let tree_state_sha256 = required_hex_env("ASTRO_FSV_TREE_STATE_SHA256", 64)?;
    log(json!({
        "event": "fsv_context",
        "platform": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "workspace": workspace,
        "fixture_root": root,
        "source_of_truth": "durable Aster Base/slot/slot_raw/compression CF values plus WAL/SST files reopened through an independent read-only handle",
        "tree_head": tree_head.clone(),
        "tree_state_sha256": tree_state_sha256.clone(),
        "artifact": artifact,
        "artifact_sha256": sha256_file(&artifact)?,
    }));

    let mut registry = Registry::new();
    let happy_slots = vec![
        register_slot(&mut registry, "issue551-tq25", HAPPY_DIM, 31, 5)?,
        register_slot(&mut registry, "issue551-tq35", HAPPY_DIM, 32, 7)?,
        register_truncated_slot(
            &mut registry,
            "issue551-tq25-truncated",
            HAPPY_DIM,
            35,
            5,
            HAPPY_DIM / 2,
        )?,
    ];
    let tie_slot = register_slot(&mut registry, "issue551-tq25-boundary-tie", 8, 36, 5)?;
    compressed_boundary_tie_edge(&root, &registry, &tie_slot)?;
    let corpus = build_mixed_one_hot_corpus(&registry, &happy_slots, 4, "happy")?;

    let vault_a = root.join("happy-a");
    let reports_a = populate_and_compress(&vault_a, &registry, &happy_slots, &corpus, true)?;
    let physical_a = physical_digest(&vault_a)?;
    log(json!({
        "event": "happy_physical_state",
        "vault": "a",
        "files": physical_a.files,
        "bytes": physical_a.bytes,
        "sha256": physical_a.sha256,
    }));
    inspect_happy_vault(&vault_a, &registry, &happy_slots, &corpus, &reports_a)?;

    let vault_b = root.join("happy-b");
    let reports_b = populate_and_compress(&vault_b, &registry, &happy_slots, &corpus, false)?;
    compare_replays(&vault_a, &vault_b, &happy_slots)?;
    inspect_report_replay(&reports_a, &reports_b)?;

    legacy_migration_edge(&root, &vault_a, &registry, &happy_slots[0], &corpus)?;
    legacy_migration_edge(&root, &vault_a, &registry, &happy_slots[1], &corpus)?;
    legacy_migration_edge(&root, &vault_a, &registry, &happy_slots[2], &corpus)?;
    wrong_context_edge(&vault_a, &registry, &happy_slots[0])?;
    current_metadata_edge(&vault_a, &happy_slots[0])?;
    corruption_edge(&root, &vault_a, &registry, &happy_slots[0])?;
    raw_corruption_edge(&root, &vault_a, &registry, &happy_slots[0])?;
    maximum_dimension_edge(&root)?;
    over_limit_edge(&root)?;

    log(json!({
        "event": "fsv_success",
        "happy_rows": corpus.cx_ids.len(),
        "operating_points": [2.5, 3.5],
        "edge_cases": ["empty_full_column", "recall_same_positive_ray", "compressed_recall_boundary_tie", "legacy_v2_bits2p5_atomic_upgrade", "legacy_v2_bits3p5_atomic_upgrade", "legacy_v2_truncated_atomic_upgrade", "legacy_wrong_seed_rehashed", "legacy_raw_body_mismatch_rehashed", "legacy_swapped_rows", "legacy_paired_primary_raw_swap", "wrong_codec_context", "wrong_slot_asymmetry", "wrong_slot_key_id", "current_wrong_version", "current_wrong_seed", "current_wrong_dimension", "persisted_primary_corruption", "persisted_raw_corruption", "zero_query", "maximum_dimension_4096", "over_limit_dimension_4097"],
        "source_truth_readback": "complete",
        "tree_head": tree_head,
        "tree_state_sha256": tree_state_sha256,
    }));
    Ok(())
}

fn required_hex_env(name: &str, expected_len: usize) -> AnyResult<String> {
    let value = std::env::var(name)
        .map_err(|_| failure(format!("required provenance variable {name} is missing")))?;
    require(
        value.len() == expected_len && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        format!(
            "provenance variable {name} must contain exactly {expected_len} hexadecimal characters"
        ),
    )?;
    Ok(value.to_ascii_lowercase())
}

fn register_slot(
    registry: &mut Registry,
    name: &str,
    dim: u32,
    slot_id: u16,
    bits_per_channel_x2: u8,
) -> AnyResult<RegisteredSlot> {
    let lens = AlgorithmicLens::one_hot(name, Modality::Text, dim);
    register_algorithmic_slot(
        registry,
        lens,
        name,
        dim,
        slot_id,
        bits_per_channel_x2,
        format!("one_hot:{dim}"),
        None,
    )
}

fn register_truncated_slot(
    registry: &mut Registry,
    name: &str,
    dim: u32,
    slot_id: u16,
    bits_per_channel_x2: u8,
    truncate_dim: u32,
) -> AnyResult<RegisteredSlot> {
    let lens = AlgorithmicLens::one_hot(name, Modality::Text, dim);
    register_algorithmic_slot(
        registry,
        lens,
        name,
        dim,
        slot_id,
        bits_per_channel_x2,
        format!("one_hot:{dim}"),
        Some(truncate_dim),
    )
}

fn register_algorithmic_slot(
    registry: &mut Registry,
    lens: AlgorithmicLens,
    name: &str,
    dim: u32,
    slot_id: u16,
    bits_per_channel_x2: u8,
    runtime_kind: String,
    truncate_dim: Option<u32>,
) -> AnyResult<RegisteredSlot> {
    let contract = lens.contract().clone();
    let quant = QuantPolicy::TurboQuant {
        bits_per_channel_x2,
    };
    let spec = LensSpec {
        name: contract.name().to_string(),
        runtime: LensRuntime::Algorithmic { kind: runtime_kind },
        output: contract.shape(),
        modality: contract.modality(),
        weights_sha256: contract.weights_sha256(),
        corpus_hash: contract.corpus_hash(),
        norm_policy: contract.norm_policy(),
        max_batch: None,
        axis: Some("issue551-turboquant-fsv".to_string()),
        asymmetry: Asymmetry::None,
        quant_default: quant,
        truncate_dim,
        recall_delta: 0.0,
        retrieval_only: false,
        excluded_from_dedup: false,
    };
    let lens_id = registry.register_frozen_with_spec(lens, contract, spec)?;
    let id = SlotId::new(slot_id);
    Ok(RegisteredSlot {
        lens_id,
        slot: Slot {
            slot_id: id,
            slot_key: id.with_key(format!("{name}-slot")),
            lens_id,
            shape: SlotShape::Dense(dim),
            modality: Modality::Text,
            asymmetry: Asymmetry::None,
            quant,
            resource: SlotResource::default(),
            axis: Some("issue551-turboquant-fsv".to_string()),
            retrieval_only: false,
            excluded_from_dedup: false,
            bits_about: BTreeMap::new(),
            state: SlotState::Active,
            added_at_panel_version: PANEL_VERSION,
        },
        bits_per_channel_x2,
        truncate_dim,
    })
}

fn build_corpus(
    registry: &Registry,
    slots: &[RegisteredSlot],
    row_count: usize,
    prefix: &str,
) -> AnyResult<Corpus> {
    require(
        !slots.is_empty(),
        "corpus requires at least one registered slot",
    )?;
    require(row_count >= 2, "corpus requires at least two rows")?;
    let mut inputs = Vec::with_capacity(row_count);
    let mut buckets_by_slot = slots
        .iter()
        .map(|registered| (registered.slot.slot_id, BTreeSet::new()))
        .collect::<BTreeMap<_, _>>();
    for ordinal in 0..100_000_u32 {
        let bytes = format!("{prefix}-row-{ordinal}").into_bytes();
        let candidate_buckets = slots
            .iter()
            .map(|registered| {
                let vector = measure_dense(registry, registered.lens_id, &bytes)?;
                Ok((
                    registered.slot.slot_id,
                    one_hot_bucket(&vector)?,
                    stored_dim_for(registry, registered)?,
                ))
            })
            .collect::<AnyResult<Vec<_>>>()?;
        if candidate_buckets
            .iter()
            .any(|(_, bucket, stored_dim)| *bucket >= *stored_dim)
            || candidate_buckets.iter().any(|(slot_id, bucket, _)| {
                buckets_by_slot
                    .get(slot_id)
                    .is_some_and(|buckets| buckets.contains(bucket))
            })
        {
            continue;
        }
        for (slot_id, bucket, _) in candidate_buckets {
            buckets_by_slot
                .get_mut(&slot_id)
                .ok_or_else(|| failure("registered slot disappeared during corpus selection"))?
                .insert(bucket);
        }
        inputs.push(bytes);
        if inputs.len() == row_count {
            break;
        }
    }
    require(
        inputs.len() == row_count,
        "could not find enough distinct real one-hot lens outputs",
    )?;
    let target_buckets = slots
        .iter()
        .map(|registered| {
            let vector = measure_dense(registry, registered.lens_id, &inputs[0])?;
            Ok((registered.slot.slot_id, one_hot_bucket(&vector)?))
        })
        .collect::<AnyResult<BTreeMap<_, _>>>()?;
    let mut query_input = None;
    for ordinal in 0..1_000_000_u32 {
        let bytes = format!("{prefix}-query-{ordinal}").into_bytes();
        if inputs.contains(&bytes) {
            continue;
        }
        let matches_every_slot = slots.iter().try_fold(true, |matches, registered| {
            if !matches {
                return Ok(false);
            }
            let vector = measure_dense(registry, registered.lens_id, &bytes)?;
            let bucket = one_hot_bucket(&vector)?;
            Ok::<_, Box<dyn Error>>(target_buckets.get(&registered.slot.slot_id) == Some(&bucket))
        })?;
        if matches_every_slot {
            query_input = Some(bytes);
            break;
        }
    }
    let query_input = query_input.ok_or_else(|| {
        failure("could not find a disjoint real query mapping to the target one-hot bucket")
    })?;

    assemble_corpus(registry, slots, inputs, query_input, 0, "one_hot")
}

fn build_mixed_one_hot_corpus(
    registry: &Registry,
    slots: &[RegisteredSlot],
    row_count: usize,
    prefix: &str,
) -> AnyResult<Corpus> {
    let mut corpus = build_corpus(registry, slots, row_count, prefix)?;
    let descriptor = format!("{prefix}-synthetic-query:normalize(4*row0+row1)");
    let vault = AsterVault::with_clock(
        VaultId::from_str(VAULT_ID)?,
        VAULT_SALT,
        FixedClock::new(FIXED_TS),
    );
    let query_cx_id = vault.cx_id_for_input(descriptor.as_bytes(), PANEL_VERSION);
    require(
        !corpus.cx_ids.contains(&query_cx_id),
        "synthetic query identity overlaps a persisted row identity",
    )?;

    let mut slot_evidence = Vec::with_capacity(slots.len());
    for registered in slots {
        let rows = corpus
            .rows_by_slot
            .get(&registered.slot.slot_id)
            .ok_or_else(|| failure("mixed-query corpus is missing registered slot rows"))?;
        require(rows.len() >= 2, "mixed query requires two real lens rows")?;
        let mut values = rows[0]
            .1
            .iter()
            .zip(&rows[1].1)
            .map(|(&primary, &secondary)| 4.0_f64 * f64::from(primary) + f64::from(secondary))
            .collect::<Vec<_>>();
        let norm = values.iter().map(|value| value * value).sum::<f64>().sqrt();
        require(
            norm.is_finite() && norm > 0.0,
            "mixed query norm is invalid",
        )?;
        let values = values
            .drain(..)
            .map(|value| (value / norm) as f32)
            .collect::<Vec<_>>();
        require(
            rows.iter()
                .all(|(_, row)| !same_positive_ray_exact(row, &values)),
            "mixed query duplicated a persisted row direction",
        )?;

        let exact_cosines = rows
            .iter()
            .map(|(_, row)| cosine(&values, row))
            .collect::<AnyResult<Vec<_>>>()?;
        let mut ranked = exact_cosines
            .iter()
            .copied()
            .enumerate()
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| right.1.total_cmp(&left.1).then(left.0.cmp(&right.0)));
        require(
            ranked.first().is_some_and(|(index, _)| *index == 0),
            "known mixed query did not rank row zero first",
        )?;
        let exact_margin = ranked[0].1 - ranked[1].1;
        require(
            exact_margin > 0.0,
            "known mixed query did not produce a unique exact top-1",
        )?;
        corpus.queries_by_slot.insert(
            registered.slot.slot_id,
            CompressionQuery {
                cx_id: query_cx_id,
                values,
            },
        );
        slot_evidence.push(json!({
            "slot_id": registered.slot.slot_id.get(),
            "exact_cosines": exact_cosines,
            "exact_top1_margin": exact_margin,
        }));
    }
    corpus.expected_top1 = corpus.cx_ids[0];
    log(json!({
        "event": "synthetic_mixed_query",
        "construction": "normalize(4 * real_lens_row_0 + real_lens_row_1)",
        "descriptor": descriptor,
        "query_cx_id": query_cx_id.to_string(),
        "expected_top1_cx_id": corpus.expected_top1.to_string(),
        "slot_evidence": slot_evidence,
    }));
    Ok(corpus)
}

fn assemble_corpus(
    registry: &Registry,
    slots: &[RegisteredSlot],
    inputs: Vec<Vec<u8>>,
    query_input: Vec<u8>,
    expected_index: usize,
    lens_kind: &str,
) -> AnyResult<Corpus> {
    require(
        expected_index < inputs.len(),
        "expected top-1 index is outside the real corpus",
    )?;

    let vault_id = VaultId::from_str(VAULT_ID)?;
    let vault = AsterVault::with_clock(vault_id, VAULT_SALT, FixedClock::new(FIXED_TS));
    let cx_ids = inputs
        .iter()
        .map(|bytes| vault.cx_id_for_input(bytes, PANEL_VERSION))
        .collect::<Vec<_>>();
    let query_cx_id = vault.cx_id_for_input(&query_input, PANEL_VERSION);
    require(
        !cx_ids.contains(&query_cx_id),
        "query identity must be disjoint from persisted row identities",
    )?;
    let expected_top1 = cx_ids[expected_index];

    let mut rows_by_slot = BTreeMap::new();
    let mut queries_by_slot = BTreeMap::new();
    for registered in slots {
        let rows = inputs
            .iter()
            .zip(cx_ids.iter().copied())
            .map(|(bytes, cx_id)| {
                measure_dense(registry, registered.lens_id, bytes).map(|values| (cx_id, values))
            })
            .collect::<AnyResult<Vec<_>>>()?;
        let query_values = measure_dense(registry, registered.lens_id, &query_input)?;
        rows_by_slot.insert(registered.slot.slot_id, rows);
        queries_by_slot.insert(
            registered.slot.slot_id,
            CompressionQuery {
                cx_id: query_cx_id,
                values: query_values,
            },
        );
    }
    log(json!({
        "event": "real_lens_corpus",
        "lens_kind": lens_kind,
        "query_relation": "temporary disjoint input identity used only to locate the target bucket; every admission path replaces it with the logged directionally distinct synthetic mixture",
        "dim": slots[0].slot.shape,
        "row_inputs": inputs.iter().map(|bytes| String::from_utf8_lossy(bytes).to_string()).collect::<Vec<_>>(),
        "row_cx_ids": cx_ids.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "query_input": String::from_utf8_lossy(&query_input),
        "query_cx_id": query_cx_id.to_string(),
        "expected_top1_cx_id": expected_top1.to_string(),
        "exact_cosines": rows_by_slot[&slots[0].slot.slot_id].iter().map(|(_, row)| cosine(&queries_by_slot[&slots[0].slot.slot_id].values, row)).collect::<AnyResult<Vec<_>>>()?,
    }));
    Ok(Corpus {
        inputs,
        cx_ids,
        rows_by_slot,
        queries_by_slot,
        expected_top1,
    })
}

fn populate_and_compress(
    directory: &Path,
    registry: &Registry,
    slots: &[RegisteredSlot],
    corpus: &Corpus,
    exercise_empty_edge: bool,
) -> AnyResult<Vec<SlotCompressionReport>> {
    fs::create_dir_all(directory)?;
    let vault = open_writer(directory)?;
    for (row_index, (bytes, cx_id)) in corpus
        .inputs
        .iter()
        .zip(corpus.cx_ids.iter().copied())
        .enumerate()
    {
        let mut vectors = BTreeMap::new();
        for registered in slots {
            let values = corpus
                .rows_by_slot
                .get(&registered.slot.slot_id)
                .and_then(|rows| rows.get(row_index))
                .map(|(_, values)| values.clone())
                .ok_or_else(|| failure("corpus row is missing registered slot values"))?;
            vectors.insert(
                registered.slot.slot_id,
                SlotVector::Dense {
                    dim: values.len() as u32,
                    data: values,
                },
            );
        }
        let stored = vault.put(Constellation {
            cx_id,
            vault_id: vault.vault_id(),
            panel_version: PANEL_VERSION,
            created_at: FIXED_TS,
            input_ref: InputRef {
                hash: sha256_array(bytes),
                pointer: Some(format!("fsv://issue551/row/{row_index}")),
                redacted: false,
            },
            modality: Modality::Text,
            slots: vectors,
            scalars: BTreeMap::new(),
            metadata: BTreeMap::from([("issue".to_string(), "551-turboquant-fsv".to_string())]),
            anchors: Vec::new(),
            provenance: LedgerRef {
                seq: 0,
                hash: [0; 32],
            },
            flags: CxFlags {
                ungrounded: true,
                ..CxFlags::default()
            },
        })?;
        require(stored == cx_id, "vault returned a different persisted CxId")?;
    }

    let source_seq = vault.latest_seq();
    log(json!({
        "event": "source_rows_persisted",
        "directory": directory,
        "seq": source_seq,
        "state": logical_state(&vault, source_seq, slots)?,
    }));

    if exercise_empty_edge {
        let before = logical_state(&vault, source_seq, slots)?;
        log(json!({
            "event": "edge_empty_before",
            "seq": source_seq,
            "state": before,
        }));
        let query = corpus
            .queries_by_slot
            .get(&slots[0].slot.slot_id)
            .ok_or_else(|| failure("empty edge query is missing"))?;
        let error = expect_calyx_error(registry.write_compressed_slot_batch(
            &vault,
            &slots[0].slot,
            &[],
            std::slice::from_ref(query),
            1,
        ))?;
        let after_seq = vault.latest_seq();
        let after = logical_state(&vault, after_seq, slots)?;
        require(
            source_seq == after_seq,
            "empty compression attempt advanced vault seq",
        )?;
        require(
            before == after,
            "empty compression attempt mutated logical CF state",
        )?;
        log(json!({
            "event": "edge_empty_after",
            "trigger_error": calyx_error_json(&error),
            "seq": after_seq,
            "state": after,
            "mutation": false,
        }));
        recall_identity_edges(&vault, registry, slots, corpus)?;
    }

    let mut reports = Vec::with_capacity(slots.len());
    for registered in slots {
        let rows = corpus
            .rows_by_slot
            .get(&registered.slot.slot_id)
            .ok_or_else(|| failure("compression source rows are missing"))?;
        let query = corpus
            .queries_by_slot
            .get(&registered.slot.slot_id)
            .ok_or_else(|| failure("compression query is missing"))?;
        let started = Instant::now();
        let report = registry.write_compressed_slot_batch(
            &vault,
            &registered.slot,
            rows,
            std::slice::from_ref(query),
            1,
        )?;
        let elapsed = started.elapsed();
        validate_report(&report, registered, rows.len())?;
        log(json!({
            "event": "compression_write",
            "slot": registered.slot.slot_key.key(),
            "snapshot": report.snapshot,
            "rows": rows.len(),
            "elapsed_ms": elapsed.as_secs_f64() * 1_000.0,
            "rows_per_second": throughput(rows.len(), elapsed),
            "logical_data_bpc": report.logical_data_bits_per_channel,
            "codec_payload_bpc": report.codec_payload_bits_per_channel,
            "written_value_bpc": report.written_value_bits_per_channel,
            "raw_value_bytes": report.raw_bytes_total,
            "compressed_envelope_bytes": report.stored_bytes_total,
            "codec_payload_bytes": report.codec_payload_bytes_total,
            "registry_envelope_bytes": report.registry_envelope_bytes_total,
            "codec_header_bytes": report.codec_header_bytes_total,
            "manifest_bytes": report.generation_manifest_bytes_total,
            "recall_at_1_raw": report.recall_at_k_raw,
            "recall_at_1_compressed": report.recall_at_k_compressed,
            "recall_drop": report.recall_drop,
        }));
        reports.push(report);
    }
    vault.flush()?;
    log(json!({
        "event": "writer_flush_complete",
        "directory": directory,
        "seq": vault.latest_seq(),
        "state": logical_state(&vault, vault.latest_seq(), slots)?,
    }));
    drop(vault);
    Ok(reports)
}

fn recall_identity_edges(
    vault: &AsterVault<FixedClock>,
    registry: &Registry,
    slots: &[RegisteredSlot],
    corpus: &Corpus,
) -> AnyResult<()> {
    let registered = slots
        .first()
        .ok_or_else(|| failure("recall identity edge has no registered slot"))?;
    let rows = corpus
        .rows_by_slot
        .get(&registered.slot.slot_id)
        .ok_or_else(|| failure("recall identity edge has no rows"))?;
    let row = rows
        .first()
        .ok_or_else(|| failure("recall identity edge has no first row"))?;

    let mut signed_zero = row.1.clone();
    let zero_index = signed_zero
        .iter()
        .position(|value| *value == 0.0)
        .ok_or_else(|| failure("recall signed-zero edge needs a zero coordinate"))?;
    signed_zero[zero_index] = -0.0;
    require(
        signed_zero
            .iter()
            .zip(&row.1)
            .all(|(left, right)| left == right),
        "signed-zero edge is not numerically identical to its source row",
    )?;
    require(
        signed_zero
            .iter()
            .zip(&row.1)
            .any(|(left, right)| left.to_bits() != right.to_bits()),
        "signed-zero edge did not create a bitwise distinction",
    )?;
    let signed_zero_query = CompressionQuery {
        cx_id: vault.cx_id_for_input(b"issue551-recall-signed-zero", PANEL_VERSION),
        values: signed_zero,
    };
    verify_recall_refusal(
        vault,
        registry,
        slots,
        registered,
        rows,
        std::slice::from_ref(&signed_zero_query),
        "signed-zero-numeric-identity",
        "same positive ray as stored row",
    )?;

    let scaled_query = CompressionQuery {
        cx_id: vault.cx_id_for_input(b"issue551-recall-scaled-row", PANEL_VERSION),
        values: row.1.iter().map(|value| *value * 2.0).collect(),
    };
    require(
        same_positive_ray_exact(&scaled_query.values, &row.1),
        "scaled-row edge is not exactly collinear with its source row",
    )?;
    verify_recall_refusal(
        vault,
        registry,
        slots,
        registered,
        rows,
        std::slice::from_ref(&scaled_query),
        "scaled-stored-row",
        "same positive ray as stored row",
    )?;

    let valid = corpus
        .queries_by_slot
        .get(&registered.slot.slot_id)
        .ok_or_else(|| failure("recall duplicate-query edge has no valid query"))?;
    let repeated = CompressionQuery {
        cx_id: vault.cx_id_for_input(b"issue551-recall-duplicate-query", PANEL_VERSION),
        values: valid.values.iter().map(|value| *value * 2.0).collect(),
    };
    require(
        same_positive_ray_exact(&valid.values, &repeated.values),
        "duplicate-query edge is not exactly collinear",
    )?;
    let duplicate_queries = vec![
        CompressionQuery {
            cx_id: valid.cx_id,
            values: valid.values.clone(),
        },
        repeated,
    ];
    verify_recall_refusal(
        vault,
        registry,
        slots,
        registered,
        rows,
        &duplicate_queries,
        "scaled-duplicate-query",
        "duplicates the positive ray of prior query",
    )?;
    Ok(())
}

fn compressed_boundary_tie_edge(
    root: &Path,
    registry: &Registry,
    registered: &RegisteredSlot,
) -> AnyResult<()> {
    let SlotShape::Dense(dim) = registered.slot.shape else {
        return Err(failure("compressed tie edge requires a dense slot").into());
    };
    let level = expected_level(registered.bits_per_channel_x2)?;
    let seed = current_shared_seed(registered, dim as usize, level);
    let codec = TurboQuantCodec::new(seed, level)?;
    let query_values = normalized_fsv(&[1.0, -0.75, 0.5, -0.375, 0.25, -0.1875, 0.125, -0.0625])?;
    let prepared_query = codec.prepare_query(&query_values)?;
    let query_norm = query_values
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum::<f64>()
        .sqrt();
    let mut seen = BTreeMap::<u32, (Vec<f32>, f32, String)>::new();
    let mut rng = 0x6a09_e667_f3bc_c909_u64;
    let mut collision = None;
    for attempt in 1..=200_000_u32 {
        let mut values = Vec::with_capacity(dim as usize);
        for _ in 0..dim {
            rng = rng
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let signed = (rng >> 32) as u32 as i32;
            values.push(signed as f32 / i32::MAX as f32);
        }
        let values = normalized_fsv(&values)?;
        if same_positive_ray_exact(&query_values, &values) {
            continue;
        }
        let qv = codec.encode(&values)?;
        let dot = codec.dot_estimate_prepared(&prepared_query, &qv)?;
        let approximate = (f64::from(dot) / (query_norm * f64::from(qv.scale))) as f32;
        let exact = cosine(&query_values, &values)? as f32;
        let qv_sha256 = sha256_hex(&qv.bytes);
        if let Some((previous, previous_exact, previous_qv_sha256)) =
            seen.get(&approximate.to_bits())
        {
            if previous_exact.total_cmp(&exact).is_ne()
                && !same_positive_ray_exact(previous, &values)
            {
                collision = Some((
                    previous.clone(),
                    values,
                    *previous_exact,
                    exact,
                    approximate,
                    previous_qv_sha256.clone(),
                    qv_sha256,
                    attempt,
                ));
                break;
            }
        } else {
            seen.insert(approximate.to_bits(), (values, exact, qv_sha256));
        }
    }
    let (
        first_values,
        second_values,
        first_exact,
        second_exact,
        approximate,
        first_qv_sha256,
        second_qv_sha256,
        attempts,
    ) = collision.ok_or_else(|| {
        failure("could not construct a deterministic compressed-score boundary collision")
    })?;
    require(
        first_exact.total_cmp(&second_exact).is_ne(),
        "compressed tie edge exact scores are also tied",
    )?;

    let directory = root.join("compressed-boundary-tie");
    fs::create_dir_all(&directory)?;
    let vault = open_writer(&directory)?;
    let row_inputs = [
        b"issue551-tie-row-a".as_slice(),
        b"issue551-tie-row-b".as_slice(),
    ];
    let row_values = [first_values, second_values];
    let mut rows = Vec::with_capacity(row_values.len());
    for (index, (input, values)) in row_inputs.iter().zip(row_values).enumerate() {
        let cx_id = vault.cx_id_for_input(input, PANEL_VERSION);
        let stored = vault.put(Constellation {
            cx_id,
            vault_id: vault.vault_id(),
            panel_version: PANEL_VERSION,
            created_at: FIXED_TS,
            input_ref: InputRef {
                hash: sha256_array(input),
                pointer: Some(format!("fsv://issue551/compressed-tie/{index}")),
                redacted: false,
            },
            modality: Modality::Text,
            slots: BTreeMap::from([(
                registered.slot.slot_id,
                SlotVector::Dense {
                    dim,
                    data: values.clone(),
                },
            )]),
            scalars: BTreeMap::new(),
            metadata: BTreeMap::from([(
                "issue".to_string(),
                "551-compressed-boundary-tie".to_string(),
            )]),
            anchors: Vec::new(),
            provenance: LedgerRef {
                seq: 0,
                hash: [0; 32],
            },
            flags: CxFlags {
                ungrounded: true,
                ..CxFlags::default()
            },
        })?;
        require(
            stored == cx_id,
            "compressed tie edge persisted the wrong CxId",
        )?;
        rows.push((cx_id, values));
    }
    vault.flush()?;
    let query = CompressionQuery {
        cx_id: vault.cx_id_for_input(b"issue551-tie-query", PANEL_VERSION),
        values: query_values,
    };
    let pure_error = match compress_slot_batch(
        &registered.slot,
        registry
            .lens_spec(registered.lens_id)
            .ok_or_else(|| failure("compressed tie edge lens spec is missing"))?,
        &rows,
        std::slice::from_ref(&query),
        1,
    ) {
        Err(error) => error,
        Ok(report) => {
            let production_rows = report
                .rows
                .iter()
                .map(|row| {
                    let envelope = inspect_unbound_stored_slot_envelope(&row.compressed_bytes)?;
                    let payload = row
                        .compressed_bytes
                        .get(REGISTRY_ENVELOPE_HEADER_BYTES..)
                        .ok_or_else(|| failure("production tie envelope has no codec payload"))?;
                    Ok(json!({
                        "cx_id": row.cx_id.to_string(),
                        "scale_bits": format!("0x{:08x}", envelope.quant_scale.to_bits()),
                        "seed_id": envelope.seed_id,
                        "payload_sha256": sha256_hex(payload),
                    }))
                })
                .collect::<AnyResult<Vec<_>>>()?;
            log(json!({
                "event": "edge_compressed_boundary_tie_production_mismatch",
                "locally_computed_payload_sha256": [first_qv_sha256, second_qv_sha256],
                "production_rows": production_rows,
                "production_recall_at_k": report.recall_at_k_compressed,
                "production_recall_drop": report.recall_drop,
            }));
            return Err(failure(
                "locally computed compressed-score collision was not a collision in the production compression path",
            )
            .into());
        }
    };
    require(
        pure_error
            .message
            .contains("compressed recall score is tied"),
        format!(
            "pure production compressed boundary tie reported the wrong root cause: {}",
            pure_error.message
        ),
    )?;
    let before_seq = vault.latest_seq();
    let before = logical_state(&vault, before_seq, std::slice::from_ref(registered))?;
    let before_physical = physical_digest(&directory)?;
    log(json!({
        "event": "edge_compressed_boundary_tie_before",
        "attempts_to_smallest_collision": attempts,
        "exact_scores": [first_exact, second_exact],
        "compressed_score": approximate,
        "candidate_qv_sha256": [first_qv_sha256, second_qv_sha256],
        "seq": before_seq,
        "state": before,
        "physical": physical_json(&before_physical),
    }));
    let error = expect_calyx_error(registry.write_compressed_slot_batch(
        &vault,
        &registered.slot,
        &rows,
        std::slice::from_ref(&query),
        1,
    ))?;
    require(
        error.message.contains("compressed recall score is tied"),
        format!(
            "compressed boundary tie reported the wrong root cause: {}",
            error.message
        ),
    )?;
    let after_seq = vault.latest_seq();
    let after = logical_state(&vault, after_seq, std::slice::from_ref(registered))?;
    let after_physical = physical_digest(&directory)?;
    require(
        before_seq == after_seq,
        "compressed tie refusal advanced durable seq",
    )?;
    require(
        before == after,
        "compressed tie refusal mutated durable state",
    )?;
    log(json!({
        "event": "edge_compressed_boundary_tie_after",
        "trigger_error": calyx_error_json(&error),
        "seq": after_seq,
        "state": after,
        "physical": physical_json(&after_physical),
        "mutation": false,
    }));
    drop(vault);
    Ok(())
}

fn normalized_fsv(values: &[f32]) -> AnyResult<Vec<f32>> {
    let squared_norm = values
        .iter()
        .map(|value| f64::from(*value) * f64::from(*value))
        .sum::<f64>();
    require(
        squared_norm.is_finite() && squared_norm > 0.0,
        "FSV normalization requires a finite non-zero vector",
    )?;
    let norm = squared_norm.sqrt();
    let normalized = values
        .iter()
        .map(|value| (f64::from(*value) / norm) as f32)
        .collect::<Vec<_>>();
    require(
        normalized.iter().all(|value| value.is_finite()),
        "FSV normalization produced a non-finite coefficient",
    )?;
    Ok(normalized)
}

#[allow(clippy::too_many_arguments)]
fn verify_recall_refusal(
    vault: &AsterVault<FixedClock>,
    registry: &Registry,
    slots: &[RegisteredSlot],
    registered: &RegisteredSlot,
    rows: &[(CxId, Vec<f32>)],
    queries: &[CompressionQuery],
    label: &str,
    expected_error: &str,
) -> AnyResult<()> {
    let before_seq = vault.latest_seq();
    let before = logical_state(vault, before_seq, slots)?;
    log(json!({
        "event": "edge_recall_identity_before",
        "case": label,
        "seq": before_seq,
        "query_ids": queries.iter().map(|query| query.cx_id.to_string()).collect::<Vec<_>>(),
        "state": before,
    }));
    let error = expect_calyx_error(registry.write_compressed_slot_batch(
        vault,
        &registered.slot,
        rows,
        queries,
        1,
    ))?;
    require(
        error.message.contains(expected_error),
        format!(
            "recall identity case {label} reported the wrong error: {}",
            error.message
        ),
    )?;
    let after_seq = vault.latest_seq();
    let after = logical_state(vault, after_seq, slots)?;
    require(
        before_seq == after_seq,
        format!("recall identity case {label} advanced durable seq"),
    )?;
    require(
        before == after,
        format!("recall identity case {label} mutated durable state"),
    )?;
    log(json!({
        "event": "edge_recall_identity_after",
        "case": label,
        "trigger_error": calyx_error_json(&error),
        "seq": after_seq,
        "state": after,
        "mutation": false,
    }));
    Ok(())
}

fn same_positive_ray_exact(left: &[f32], right: &[f32]) -> bool {
    let Some(pivot) = left
        .iter()
        .zip(right)
        .position(|(&left, &right)| left != 0.0 || right != 0.0)
    else {
        return true;
    };
    let left_pivot = left[pivot];
    let right_pivot = right[pivot];
    if left_pivot == 0.0
        || right_pivot == 0.0
        || left_pivot.is_sign_negative() != right_pivot.is_sign_negative()
    {
        return false;
    }
    left.iter().zip(right).all(|(&left, &right)| {
        f64::from(left) * f64::from(right_pivot) == f64::from(right) * f64::from(left_pivot)
    })
}

fn inspect_happy_vault(
    directory: &Path,
    registry: &Registry,
    slots: &[RegisteredSlot],
    corpus: &Corpus,
    reports: &[SlotCompressionReport],
) -> AnyResult<()> {
    let vault = open_reader(directory)?;
    let snapshot = vault.latest_seq();
    require(snapshot > 0, "reopened vault has no committed state")?;
    log(json!({
        "event": "independent_reopen",
        "directory": directory,
        "recovered_seq": vault.recovery_report().last_recovered_seq,
        "snapshot": snapshot,
        "state": logical_state(&vault, snapshot, slots)?,
    }));

    let raw_error = expect_calyx_error(vault.get(corpus.cx_ids[0], snapshot))?;
    require(
        raw_error.message.contains("compression-aware read path"),
        "ordinary vault read did not identify the required compression-aware path",
    )?;
    log(json!({
        "event": "raw_fallback_refused",
        "cx_id": corpus.cx_ids[0].to_string(),
        "error": calyx_error_json(&raw_error),
    }));

    for (registered, report) in slots.iter().zip(reports) {
        inspect_persisted_slot(&vault, registry, registered, corpus, report)?;
    }
    drop(vault);
    Ok(())
}

fn inspect_persisted_slot<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    registry: &Registry,
    registered: &RegisteredSlot,
    corpus: &Corpus,
    report: &SlotCompressionReport,
) -> AnyResult<()> {
    let snapshot = vault.latest_seq();
    let primary = vault.scan_cf_at(snapshot, ColumnFamily::slot(registered.slot.slot_id))?;
    let raw = vault.scan_cf_at(snapshot, ColumnFamily::slot_raw(registered.slot.slot_id))?;
    let manifest = vault
        .read_cf_at(
            snapshot,
            ColumnFamily::Compression,
            &compression_manifest_key(registered.slot.slot_id),
        )?
        .ok_or_else(|| failure("compression manifest missing after independent reopen"))?;
    require(
        primary.len() == corpus.cx_ids.len(),
        "primary row count mismatch",
    )?;
    require(
        raw.len() == corpus.cx_ids.len(),
        "raw-sidecar row count mismatch",
    )?;
    require(
        manifest.len() == MANIFEST_BYTES,
        "manifest physical length mismatch",
    )?;
    require(&manifest[..4] == b"CSMF", "manifest magic mismatch")?;
    require(
        sha256_hex(&manifest) == sha256_hex(&report.generation_manifest_bytes),
        "persisted manifest differs from the committed report bytes",
    )?;

    let expected_rows = corpus
        .rows_by_slot
        .get(&registered.slot.slot_id)
        .ok_or_else(|| failure("expected rows missing for slot inspection"))?
        .iter()
        .cloned()
        .collect::<BTreeMap<_, _>>();
    let mut payload_bytes = 0_usize;
    let mut envelope_bytes = 0_usize;
    let mut data_bits = 0_usize;
    for (key, bytes) in &primary {
        let cx_id = cx_id_from_key(key)?;
        require(
            bytes.first().copied() == Some(16),
            "compressed row tag mismatch",
        )?;
        let envelope = inspect_unbound_stored_slot_envelope(bytes)?;
        require(
            envelope.format_version == 3,
            "outer envelope is not version 3",
        )?;
        require(envelope.cx_id == cx_id, "envelope CxId differs from CF key")?;
        require(
            envelope.generation_rows as usize == primary.len(),
            "envelope generation row count mismatch",
        )?;
        require(
            bytes.len() == REGISTRY_ENVELOPE_HEADER_BYTES + envelope.payload_bytes,
            "outer envelope byte accounting mismatch",
        )?;
        let payload = &bytes[REGISTRY_ENVELOPE_HEADER_BYTES..];
        require(&payload[..4] == b"TQPR", "inner TQPR magic mismatch")?;
        require(payload[4] == 2, "inner TQPR payload is not version 2")?;
        require(
            payload.len() >= TURBOQUANT_FORMAT_HEADER_BYTES,
            "inner TQPR payload is shorter than its fixed header",
        )?;
        let qv = QuantizedVec {
            level: expected_level(registered.bits_per_channel_x2)?,
            dim: envelope.stored_dim as usize,
            bytes: payload.to_vec(),
            scale: envelope.quant_scale,
            seed_id: decode_hex_32(&envelope.seed_id)?,
        };
        let storage = TurboQuantCodec::inspect(&qv)?;
        let expected_payload =
            expected_payload_bytes(envelope.stored_dim as usize, registered.bits_per_channel_x2)?;
        require(
            storage.payload_bytes == expected_payload,
            "TQPR payload size mismatch",
        )?;
        require(
            storage.data_bits
                == expected_data_bits(
                    envelope.stored_dim as usize,
                    registered.bits_per_channel_x2,
                )?,
            "TQPR logical data-bit count mismatch",
        )?;
        payload_bytes += storage.payload_bytes;
        envelope_bytes += bytes.len();
        data_bits += storage.data_bits;
    }

    let raw_by_key = raw.into_iter().collect::<BTreeMap<_, _>>();
    for (cx_id, expected) in &expected_rows {
        let raw_bytes = raw_by_key
            .get(cx_id.as_bytes().as_slice())
            .ok_or_else(|| failure("raw sidecar is missing an expected CxId"))?;
        let decoded = encode::decode_slot_vector(raw_bytes)?;
        require(
            decoded
                == (SlotVector::Dense {
                    dim: expected.len() as u32,
                    data: expected.clone(),
                }),
            "independently decoded raw sidecar differs from source lens output",
        )?;
    }
    require(
        payload_bytes == report.codec_payload_bytes_total,
        "payload total mismatch",
    )?;
    require(
        envelope_bytes == report.stored_bytes_total,
        "envelope total mismatch",
    )?;
    require(
        data_bits as u64 == report.logical_data_bits_total,
        "data-bit total mismatch",
    )?;

    let index = registry.compressed_slot_index(vault, &registered.slot)?;
    index.verify_at(snapshot)?;
    let mut min_reconstruction_cosine = f64::INFINITY;
    let mut max_reconstruction_rmse = 0.0_f64;
    for (cx_id, source) in &expected_rows {
        let decoded = index.read_at(*cx_id, snapshot)?;
        let reconstructed = decoded
            .as_dense()
            .ok_or_else(|| failure("compression-aware read returned a non-dense vector"))?;
        let prepared_source = match registered.truncate_dim {
            Some(truncate_dim) => matryoshka_truncate_renormalize(source, truncate_dim)?,
            None => source.clone(),
        };
        let cosine = cosine(&prepared_source, reconstructed)?;
        let rmse = rmse(&prepared_source, reconstructed)?;
        min_reconstruction_cosine = min_reconstruction_cosine.min(cosine);
        max_reconstruction_rmse = max_reconstruction_rmse.max(rmse);
        let envelope = index.envelope_at(*cx_id, snapshot)?;
        require(
            envelope.cx_id == *cx_id,
            "index envelope readback CxId mismatch",
        )?;
    }

    let query = corpus
        .queries_by_slot
        .get(&registered.slot.slot_id)
        .ok_or_else(|| failure("slot query missing during persisted search"))?;
    let hits = index.search_at(&query.values, 1, snapshot)?;
    require(
        hits.len() == 1,
        "persisted top-1 search returned the wrong hit count",
    )?;
    require(
        hits[0].cx_id == corpus.expected_top1,
        "persisted compressed search returned the wrong top-1 CxId",
    )?;
    let exact_source = expected_rows
        .get(&corpus.expected_top1)
        .ok_or_else(|| failure("expected top-1 source row missing"))?;
    let (exact_query, exact_source) = match registered.truncate_dim {
        Some(truncate_dim) => (
            matryoshka_truncate_renormalize(&query.values, truncate_dim)?,
            matryoshka_truncate_renormalize(exact_source, truncate_dim)?,
        ),
        None => (query.values.clone(), exact_source.clone()),
    };
    let exact_score = cosine(&exact_query, &exact_source)?;
    let score_abs_error = (f64::from(hits[0].score) - exact_score).abs();

    if registered.bits_per_channel_x2 == 5 {
        let before = logical_state(vault, snapshot, std::slice::from_ref(registered))?;
        log(json!({
            "event": "edge_zero_query_before",
            "snapshot": snapshot,
            "state": before,
        }));
        let zero = vec![0.0_f32; query.values.len()];
        let error = expect_calyx_error(index.search_at(&zero, 1, snapshot))?;
        let after = logical_state(vault, vault.latest_seq(), std::slice::from_ref(registered))?;
        require(
            before == after,
            "zero-query rejection mutated persisted state",
        )?;
        log(json!({
            "event": "edge_zero_query_after",
            "trigger_error": calyx_error_json(&error),
            "state": after,
            "mutation": false,
        }));
    }

    let repetitions = 100_usize;
    let started = Instant::now();
    let mut score_accumulator = 0.0_f64;
    for _ in 0..repetitions {
        let current = index.search_at(black_box(&query.values), 1, snapshot)?;
        score_accumulator += f64::from(current[0].score);
    }
    let elapsed = started.elapsed();
    black_box(score_accumulator);
    log(json!({
        "event": "persisted_slot_readback",
        "slot": registered.slot.slot_key.key(),
        "codec": format!("{:?}", report.stored_codec),
        "primary_rows": primary.len(),
        "primary_value_bytes": envelope_bytes,
        "primary_sha256": digest_rows(&primary),
        "raw_rows": raw_by_key.len(),
        "raw_sha256": digest_map(&raw_by_key),
        "manifest_bytes": manifest.len(),
        "manifest_sha256": sha256_hex(&manifest),
        "logical_data_bits": data_bits,
        "logical_data_bpc": data_bits as f64 / (primary.len() * registered_stored_dim(registered)?) as f64,
        "codec_payload_bytes": payload_bytes,
        "min_reconstruction_cosine": min_reconstruction_cosine,
        "max_reconstruction_rmse": max_reconstruction_rmse,
        "expected_top1": corpus.expected_top1.to_string(),
        "actual_top1": hits[0].cx_id.to_string(),
        "exact_top1_cosine": exact_score,
        "compressed_top1_score": hits[0].score,
        "top1_score_abs_error": score_abs_error,
        "search_repetitions": repetitions,
        "search_elapsed_ms": elapsed.as_secs_f64() * 1_000.0,
        "queries_per_second": throughput(repetitions, elapsed),
    }));
    Ok(())
}

fn validate_report(
    report: &SlotCompressionReport,
    registered: &RegisteredSlot,
    rows: usize,
) -> AnyResult<()> {
    let expected_codec = match registered.bits_per_channel_x2 {
        5 => StoredSlotCodec::TurboQuantBits2p5,
        7 => StoredSlotCodec::TurboQuantBits3p5,
        other => return Err(failure(format!("unexpected FSV TurboQuant level {other}"))),
    };
    let expected_bpc = f32::from(registered.bits_per_channel_x2) / 2.0;
    let expected_payload = expected_payload_bytes(
        registered_stored_dim(registered)?,
        registered.bits_per_channel_x2,
    )?;
    require(
        report.stored_codec == expected_codec,
        "stored codec differs from requested codec",
    )?;
    require(
        report.fallback_reason.is_none(),
        "compression reported a fallback",
    )?;
    require(
        report.rows.len() == rows,
        "compression report row count mismatch",
    )?;
    require(
        report.truncate_dim == registered.truncate_dim,
        "compression report truncation contract mismatch",
    )?;
    require(
        report.logical_data_bits_per_channel.to_bits() == expected_bpc.to_bits(),
        "logical bits-per-channel report is not exact",
    )?;
    require(
        report.codec_payload_bytes_total == rows * expected_payload,
        "codec payload report is not exact",
    )?;
    require(
        report.registry_envelope_bytes_total == rows * REGISTRY_ENVELOPE_HEADER_BYTES,
        "registry envelope report is not exact",
    )?;
    require(
        report.codec_header_bytes_total == rows * TURBOQUANT_FORMAT_HEADER_BYTES,
        "TQPR header report is not exact",
    )?;
    require(
        report.generation_manifest_bytes_total == MANIFEST_BYTES,
        "manifest report is not exact",
    )?;
    require(
        report.recall_at_k_raw.to_bits() == 1.0_f32.to_bits()
            && report.recall_at_k_compressed.to_bits() == 1.0_f32.to_bits()
            && report.recall_drop.to_bits() == 0.0_f32.to_bits(),
        "persisted scorer failed the declared zero-recall-drop contract",
    )?;
    require(
        report.snapshot.is_some(),
        "persisted report has no committed snapshot",
    )?;
    Ok(())
}

fn compare_replays(
    first_directory: &Path,
    second_directory: &Path,
    slots: &[RegisteredSlot],
) -> AnyResult<()> {
    let first = open_reader(first_directory)?;
    let second = open_reader(second_directory)?;
    let first_seq = first.latest_seq();
    let second_seq = second.latest_seq();
    for registered in slots {
        let slot = registered.slot.slot_id;
        let first_primary = first.scan_cf_at(first_seq, ColumnFamily::slot(slot))?;
        let second_primary = second.scan_cf_at(second_seq, ColumnFamily::slot(slot))?;
        let first_raw = first.scan_cf_at(first_seq, ColumnFamily::slot_raw(slot))?;
        let second_raw = second.scan_cf_at(second_seq, ColumnFamily::slot_raw(slot))?;
        let key = compression_manifest_key(slot);
        let first_manifest = first.read_cf_at(first_seq, ColumnFamily::Compression, &key)?;
        let second_manifest = second.read_cf_at(second_seq, ColumnFamily::Compression, &key)?;
        require(
            first_primary == second_primary,
            "deterministic replay primary bytes differ",
        )?;
        require(
            first_raw == second_raw,
            "deterministic replay raw bytes differ",
        )?;
        require(
            first_manifest == second_manifest,
            "deterministic replay manifest bytes differ",
        )?;
        log(json!({
            "event": "deterministic_replay",
            "slot": registered.slot.slot_key.key(),
            "primary_sha256_a": digest_rows(&first_primary),
            "primary_sha256_b": digest_rows(&second_primary),
            "raw_sha256_a": digest_rows(&first_raw),
            "raw_sha256_b": digest_rows(&second_raw),
            "manifest_sha256": first_manifest.as_deref().map(sha256_hex),
            "byte_identical": true,
        }));
    }
    drop(second);
    drop(first);
    Ok(())
}

fn inspect_report_replay(
    first: &[SlotCompressionReport],
    second: &[SlotCompressionReport],
) -> AnyResult<()> {
    require(first.len() == second.len(), "replay report count differs")?;
    for (left, right) in first.iter().zip(second) {
        require(
            left.generation_manifest_bytes == right.generation_manifest_bytes,
            "replay report manifest bytes differ",
        )?;
        require(left.rows == right.rows, "replay report row bytes differ")?;
    }
    Ok(())
}

fn legacy_migration_edge(
    root: &Path,
    source_directory: &Path,
    registry: &Registry,
    registered: &RegisteredSlot,
    corpus: &Corpus,
) -> AnyResult<()> {
    let directory = root.join(format!(
        "legacy-v2-migration-slot-{}",
        registered.slot.slot_id.get()
    ));
    copy_tree(source_directory, &directory)?;
    let writer = open_writer(&directory)?;
    let slot_id = registered.slot.slot_id;
    let initial_seq = writer.latest_seq();
    let primary = writer.scan_cf_at(initial_seq, ColumnFamily::slot(slot_id))?;
    let raw = writer.scan_cf_at(initial_seq, ColumnFamily::slot_raw(slot_id))?;
    let manifest_key = compression_manifest_key(slot_id);
    let manifest = writer
        .read_cf_at(initial_seq, ColumnFamily::Compression, &manifest_key)?
        .ok_or_else(|| failure("legacy migration fixture manifest missing"))?;
    let rows = corpus
        .rows_by_slot
        .get(&slot_id)
        .ok_or_else(|| failure("legacy migration source rows missing"))?;
    let query = corpus
        .queries_by_slot
        .get(&slot_id)
        .ok_or_else(|| failure("legacy migration query missing"))?;
    let raw_dim = match registered.slot.shape {
        SlotShape::Dense(dim) => dim,
        _ => return Err(failure("legacy migration fixture requires a dense slot").into()),
    };
    let stored_dim = stored_dim_for(registry, registered)?;
    let golden = legacy_golden_set(registered.bits_per_channel_x2, raw_dim, stored_dim)?;
    let legacy_primary_by_key = golden
        .rows
        .iter()
        .map(|(key, value)| Ok((decode_hex(key)?, decode_hex(value)?)))
        .collect::<AnyResult<BTreeMap<_, _>>>()?;
    require(
        legacy_primary_by_key.len() == golden.rows.len(),
        "historical writer golden contains duplicate keyed rows",
    )?;
    require(
        digest_map(&legacy_primary_by_key) == golden.aggregate_sha256,
        format!(
            "historical writer golden digest differs from pinned source: expected={} actual={}",
            golden.aggregate_sha256,
            digest_map(&legacy_primary_by_key),
        ),
    )?;
    let persisted_keys = primary
        .iter()
        .map(|(key, _)| key.clone())
        .collect::<BTreeSet<_>>();
    let reconstructed_keys = legacy_primary_by_key
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    require(
        primary.len() == legacy_primary_by_key.len() && persisted_keys == reconstructed_keys,
        format!(
            "historical reconstruction keyset differs from the persisted source column: persisted_rows={} reconstructed_rows={} persisted_keyset_sha256={} reconstructed_keyset_sha256={}",
            primary.len(),
            legacy_primary_by_key.len(),
            digest_keyset(&persisted_keys),
            digest_keyset(&reconstructed_keys),
        ),
    )?;
    let legacy_primary = legacy_primary_by_key.into_iter().collect::<Vec<_>>();
    let (first_key, first_value) = legacy_primary
        .first()
        .ok_or_else(|| failure("historical writer golden has no rows"))?;
    let pinned_first = parse_legacy_fixture_row(first_key, first_value)?;
    let legacy_seed_id = hex(&pinned_first.qv.seed_id);
    let legacy_manifest = legacy_staging_manifest(&manifest, &legacy_primary, &raw)?;
    require(
        legacy_manifest[80..112] == manifest[80..112],
        "legacy staging manifest raw root differs despite byte-identical raw sidecars",
    )?;
    // Reconstruct the pre-#562 legacy on-disk generation (unmanifested v2 column
    // + raw sidecar) in one reconstruction-ingress batch. The lawful compression
    // guard refuses to synthesize an unmanifested compressed column, so this is
    // how the fixture reproduces the exact bytes a pre-lifecycle binary left and
    // that WAL recovery replays — the input the production `Migrate` upgrade path
    // consumes. `legacy_manifest` is retained only as reference evidence for the
    // v2 generation roots; it is never persisted.
    let legacy_seq =
        reconstruct_legacy_generation(&writer, slot_id, &legacy_primary, &raw, initial_seq)?;
    writer.flush()?;
    let before = logical_state(&writer, legacy_seq, std::slice::from_ref(registered))?;
    require(
        writer
            .read_cf_at(legacy_seq, ColumnFamily::Compression, &manifest_key)?
            .is_none(),
        "legacy fixture still exposes a generation manifest",
    )?;
    require(
        writer
            .scan_cf_at(legacy_seq, ColumnFamily::slot(slot_id))?
            .iter()
            .all(|(_, bytes)| bytes.get(1).copied() == Some(2)),
        "legacy fixture does not contain only v2 envelopes",
    )?;
    log(json!({
        "event": "edge_legacy_migration_before",
        "seq": legacy_seq,
        "outer_version": 2,
        "inner_version": 1,
        "raw_dim": raw_dim,
        "stored_dim": stored_dim,
        "legacy_seed_id": legacy_seed_id,
        "historical_writer_commit": LEGACY_WRITER_COMMIT,
        "historical_writer_sources": LEGACY_WRITER_SOURCE_BLOBS.iter().map(
            |(path, git_blob, sha256)| json!({
                "path": path,
                "git_blob": git_blob,
                "sha256": sha256,
            }),
        ).collect::<Vec<_>>(),
        "pinned_golden_sha256": golden.aggregate_sha256,
        "reference_legacy_manifest_sha256": sha256_hex(&legacy_manifest),
        "reference_generation_root": hex(&legacy_manifest[48..80]),
        "reference_raw_generation_root": hex(&legacy_manifest[80..112]),
        "reconstruction_ingress": "commit_legacy_generation_reconstruction_if_seq",
        "manifest_present": false,
        "legacy_primary_sha256": digest_rows(&legacy_primary),
        "legacy_primary_rows": legacy_primary.iter().map(|(key, value)| json!({
            "key_hex": hex(key),
            "outer_v2_hex": hex(value),
        })).collect::<Vec<_>>(),
        "state": before,
    }));
    drop(writer);

    legacy_refusal_edge(
        root,
        &directory,
        registry,
        registered,
        corpus,
        &manifest,
        LegacyFixtureMutation::WrongSeed,
    )?;
    legacy_refusal_edge(
        root,
        &directory,
        registry,
        registered,
        corpus,
        &manifest,
        LegacyFixtureMutation::BodyMismatch,
    )?;
    legacy_refusal_edge(
        root,
        &directory,
        registry,
        registered,
        corpus,
        &manifest,
        LegacyFixtureMutation::SwapRows,
    )?;
    legacy_refusal_edge(
        root,
        &directory,
        registry,
        registered,
        corpus,
        &manifest,
        LegacyFixtureMutation::PairedPrimaryRawSwap,
    )?;

    let writer = open_writer(&directory)?;
    let report = registry.write_compressed_slot_batch(
        &writer,
        &registered.slot,
        rows,
        std::slice::from_ref(query),
        1,
    )?;
    let migrated_seq = report
        .snapshot
        .ok_or_else(|| failure("legacy migration returned no committed snapshot"))?;
    writer.flush()?;
    drop(writer);

    let reader = open_reader(&directory)?;
    require(
        reader.latest_seq() == migrated_seq,
        "legacy migration reopen seq mismatch",
    )?;
    let index = registry.compressed_slot_index(&reader, &registered.slot)?;
    index.verify_at(migrated_seq)?;
    let hits = index.search_at(&query.values, 1, migrated_seq)?;
    require(
        hits.first().map(|hit| hit.cx_id) == Some(corpus.expected_top1),
        "legacy migration compressed search returned the wrong top-1 row",
    )?;
    let migrated_primary = reader.scan_cf_at(migrated_seq, ColumnFamily::slot(slot_id))?;
    require(
        migrated_primary.iter().all(|(_, bytes)| {
            bytes.get(1).copied() == Some(3)
                && bytes.get(REGISTRY_ENVELOPE_HEADER_BYTES + 4).copied() == Some(2)
        }),
        "legacy migration did not atomically replace every row with v3/TQPR-v2 bytes",
    )?;
    let after = logical_state(&reader, migrated_seq, std::slice::from_ref(registered))?;
    log(json!({
        "event": "edge_legacy_migration_after",
        "seq": migrated_seq,
        "outer_version": 3,
        "inner_version": 2,
        "raw_dim": raw_dim,
        "stored_dim": stored_dim,
        "manifest_bytes": report.generation_manifest_bytes_total,
        "expected_top1": corpus.expected_top1.to_string(),
        "actual_top1": hits[0].cx_id.to_string(),
        "state": after,
        "atomic_upgrade": true,
    }));
    drop(reader);
    Ok(())
}

struct LegacyGoldenSet {
    aggregate_sha256: &'static str,
    rows: &'static [(&'static str, &'static str)],
}

fn legacy_golden_set(
    bits_per_channel_x2: u8,
    raw_dim: u32,
    stored_dim: usize,
) -> AnyResult<LegacyGoldenSet> {
    match (bits_per_channel_x2, raw_dim, stored_dim) {
        (5, 128, 128) => Ok(LegacyGoldenSet {
            aggregate_sha256: LEGACY_TQ25_128_SHA256,
            rows: LEGACY_TQ25_128_ROWS,
        }),
        (7, 128, 128) => Ok(LegacyGoldenSet {
            aggregate_sha256: LEGACY_TQ35_128_SHA256,
            rows: LEGACY_TQ35_128_ROWS,
        }),
        (5, 128, 64) => Ok(LegacyGoldenSet {
            aggregate_sha256: LEGACY_TQ25_64_SHA256,
            rows: LEGACY_TQ25_64_ROWS,
        }),
        geometry => Err(failure(format!(
            "no immutable historical writer golden is pinned for geometry {geometry:?}"
        ))
        .into()),
    }
}

struct LegacyFixtureRow {
    cx_id: CxId,
    codec_code: u8,
    manifest_level_code: u8,
    raw_dim: u32,
    stored_dim: u32,
    qv: QuantizedVec,
}

/// Reconstructs a pre-#562 legacy on-disk generation for `slot_id` in ONE batch:
/// the v2 primary column and its raw sidecar (put), plus tombstones for the
/// existing #562 manifest and every existing append-only lifecycle record. The
/// lawful compression guard deliberately refuses to synthesize an unmanifested
/// compressed column, so this fixture stages the legacy shape the way WAL recovery
/// replays a pre-lifecycle binary's bytes, through the dedicated reconstruction
/// ingress (which fail-closed-validates the legacy shape before committing).
/// Returns the committed sequence.
fn reconstruct_legacy_generation(
    writer: &AsterVault<FixedClock>,
    slot_id: SlotId,
    primary: &[(Vec<u8>, Vec<u8>)],
    raw: &[(Vec<u8>, Vec<u8>)],
    base_seq: u64,
) -> AnyResult<u64> {
    let mut batch: Vec<(ColumnFamily, Vec<u8>, Vec<u8>)> =
        Vec::with_capacity(primary.len() + raw.len() + 4);
    batch.extend(
        primary
            .iter()
            .cloned()
            .map(|(key, value)| (ColumnFamily::slot(slot_id), key, value)),
    );
    batch.extend(
        raw.iter()
            .cloned()
            .map(|(key, value)| (ColumnFamily::slot_raw(slot_id), key, value)),
    );
    batch.push((
        ColumnFamily::Compression,
        compression_manifest_key(slot_id),
        tombstone_value(),
    ));
    for (key, _) in writer.scan_cf_range_at(
        base_seq,
        ColumnFamily::Compression,
        &compression_lifecycle_prefix_range(slot_id),
    )? {
        batch.push((ColumnFamily::Compression, key, tombstone_value()));
    }
    Ok(writer.commit_generation_injection_if_seq(base_seq, batch)?)
}

fn legacy_staging_manifest(
    template: &[u8],
    primary: &[(Vec<u8>, Vec<u8>)],
    raw: &[(Vec<u8>, Vec<u8>)],
) -> AnyResult<Vec<u8>> {
    require(
        template.len() == MANIFEST_BYTES
            && &template[..4] == b"CSMF"
            && template[4] == 1
            && template[7] == 0,
        "legacy staging manifest template is not canonical CSMF-v1",
    )?;
    require(
        template[MANIFEST_PREFIX_BYTES..]
            == legacy_manifest_digest(&template[..MANIFEST_PREFIX_BYTES]),
        "legacy staging manifest template digest is invalid",
    )?;
    require(
        !primary.is_empty() && primary.len() == raw.len(),
        "legacy staging manifest requires matching non-empty primary/raw rows",
    )?;
    let primary_keys = primary
        .iter()
        .map(|(key, _)| key.as_slice())
        .collect::<BTreeSet<_>>();
    let raw_keys = raw
        .iter()
        .map(|(key, _)| key.as_slice())
        .collect::<BTreeSet<_>>();
    require(
        primary_keys == raw_keys && primary_keys.len() == primary.len(),
        "legacy staging manifest primary/raw keysets differ or contain duplicates",
    )?;

    let rows = primary
        .iter()
        .map(|(key, value)| parse_legacy_fixture_row(key, value))
        .collect::<AnyResult<Vec<_>>>()?;
    let first = rows
        .first()
        .ok_or_else(|| failure("legacy staging manifest has no parsed rows"))?;
    require(
        rows.iter().all(|row| {
            row.codec_code == first.codec_code
                && row.manifest_level_code == first.manifest_level_code
                && row.raw_dim == first.raw_dim
                && row.stored_dim == first.stored_dim
        }),
        "legacy staged rows disagree on codec or geometry",
    )?;
    let generation_rows = u32::try_from(rows.len())?;
    require(
        template[5] == first.codec_code
            && template[6] == first.manifest_level_code
            && u32::from_be_bytes(template[8..12].try_into()?) == first.raw_dim
            && u32::from_be_bytes(template[12..16].try_into()?) == first.stored_dim
            && u32::from_be_bytes(template[112..116].try_into()?) == generation_rows,
        "legacy staged rows disagree with the frozen CSMF codec geometry",
    )?;
    let mut codec_context_id = [0_u8; 32];
    codec_context_id.copy_from_slice(&template[16..48]);
    let generation_root =
        legacy_fixture_generation_root(&codec_context_id, generation_rows, &rows)?;
    let raw_generation_root =
        legacy_fixture_raw_generation_root(&codec_context_id, generation_rows, raw)?;

    let mut manifest = template[..MANIFEST_PREFIX_BYTES].to_vec();
    manifest[48..80].copy_from_slice(&generation_root);
    manifest[80..112].copy_from_slice(&raw_generation_root);
    manifest[112..116].copy_from_slice(&generation_rows.to_be_bytes());
    let digest = legacy_manifest_digest(&manifest);
    manifest.extend_from_slice(&digest);
    require(
        manifest.len() == MANIFEST_BYTES,
        "legacy staging manifest length mismatch",
    )?;
    Ok(manifest)
}

fn parse_legacy_fixture_row(key: &[u8], envelope: &[u8]) -> AnyResult<LegacyFixtureRow> {
    let cx_id = cx_id_from_key(key)?;
    require(
        envelope.len() >= LEGACY_OUTER_V2_HEADER_BYTES + LEGACY_TQPR_V1_HEADER_BYTES
            && envelope[0] == 16
            && envelope[1] == 2,
        "legacy staging row is not an outer-v2/TQPR-v1 envelope",
    )?;
    let raw_dim = u32::from_be_bytes(envelope[4..8].try_into()?);
    let stored_dim = u32::from_be_bytes(envelope[8..12].try_into()?);
    require(
        raw_dim > 0 && stored_dim > 0 && stored_dim <= raw_dim && stored_dim <= MAX_DIM,
        "legacy staging row dimensions are outside the frozen 1..=4096 contract",
    )?;
    let flags = envelope[12];
    require(
        flags & !0b10 == 0 && (flags & 0b10 != 0) == (stored_dim < raw_dim),
        "legacy staging row truncation flags are not canonical",
    )?;
    let scale = f32::from_bits(u32::from_be_bytes(envelope[13..17].try_into()?));
    require(
        scale.is_finite() && !scale.is_sign_negative(),
        "legacy staging row scale is not canonical",
    )?;
    let mut seed_id = [0_u8; 32];
    seed_id.copy_from_slice(&envelope[17..49]);
    let payload_len = u32::from_be_bytes(envelope[49..53].try_into()?) as usize;
    require(
        envelope.len() == LEGACY_OUTER_V2_HEADER_BYTES + payload_len,
        "legacy staging row outer payload length mismatch",
    )?;
    let payload = &envelope[LEGACY_OUTER_V2_HEADER_BYTES..];
    let outer_digest = domain_digest(
        b"calyx-registry-slot-envelope-v2",
        &envelope[..53],
        payload,
        false,
        None,
    );
    require(
        envelope[53..LEGACY_OUTER_V2_HEADER_BYTES] == outer_digest,
        "legacy staging row outer digest mismatch",
    )?;
    require(
        &payload[..4] == b"TQPR" && payload[4] == 1,
        "legacy staging row inner payload is not TQPR-v1",
    )?;
    let (codec_code, manifest_level_code, level, inner_level_code, scalar_low_bits) =
        match (envelope[2], envelope[3]) {
            (1, 4) => (1, 4, QuantLevel::Bits3p5, 2, 2_usize),
            (2, 5) => (2, 5, QuantLevel::Bits2p5, 1, 1_usize),
            other => {
                return Err(failure(format!(
                    "legacy staging row has unsupported codec/level bytes {other:?}"
                ))
                .into());
            }
        };
    require(
        payload[5] == inner_level_code && u16::from_le_bytes(payload[6..8].try_into()?) == 0,
        "legacy staging row inner level or reserved flags are invalid",
    )?;
    let inner_dim = u32::from_le_bytes(payload[8..12].try_into()?) as usize;
    let scalar_bits = inner_dim
        .checked_mul(scalar_low_bits)
        .and_then(|base| base.checked_add(inner_dim.div_ceil(2)))
        .ok_or_else(|| failure("legacy staging scalar bit count overflow"))?;
    let header_scalar_bits = u32::from_le_bytes(payload[12..16].try_into()?) as usize;
    let header_qjl_bits = u32::from_le_bytes(payload[16..20].try_into()?) as usize;
    require(
        inner_dim == stored_dim as usize
            && header_scalar_bits == scalar_bits
            && header_qjl_bits == inner_dim,
        "legacy staging row inner geometry is not canonical",
    )?;
    let gamma = f32::from_bits(u32::from_le_bytes(payload[20..24].try_into()?));
    require(
        gamma.is_finite()
            && !gamma.is_sign_negative()
            && payload[24..LEGACY_TQPR_V1_PREFIX_BYTES] == seed_id,
        "legacy staging row inner gamma or seed is not canonical",
    )?;
    let scalar_bytes = scalar_bits.div_ceil(8);
    let qjl_bytes = inner_dim.div_ceil(8);
    let exact_payload_len = LEGACY_TQPR_V1_HEADER_BYTES
        .checked_add(scalar_bytes)
        .and_then(|bytes| bytes.checked_add(qjl_bytes))
        .ok_or_else(|| failure("legacy staging payload length overflow"))?;
    require(
        payload.len() == exact_payload_len,
        "legacy staging row inner payload length is not canonical",
    )?;
    let scalar = &payload[LEGACY_TQPR_V1_HEADER_BYTES..LEGACY_TQPR_V1_HEADER_BYTES + scalar_bytes];
    let qjl = &payload[LEGACY_TQPR_V1_HEADER_BYTES + scalar_bytes..];
    require(
        !legacy_nonzero_padding(scalar, scalar_bits)
            && !legacy_nonzero_padding(qjl, header_qjl_bits),
        "legacy staging row contains non-zero padding bits",
    )?;
    let inner_digest = domain_digest(
        b"calyx/turboquant/tqpr/payload/v1\0",
        &payload[..LEGACY_TQPR_V1_PREFIX_BYTES],
        &payload[LEGACY_TQPR_V1_HEADER_BYTES..],
        true,
        Some(scale),
    );
    require(
        payload[LEGACY_TQPR_V1_PREFIX_BYTES..LEGACY_TQPR_V1_HEADER_BYTES] == inner_digest,
        "legacy staging row inner digest mismatch",
    )?;
    Ok(LegacyFixtureRow {
        cx_id,
        codec_code,
        manifest_level_code,
        raw_dim,
        stored_dim,
        qv: QuantizedVec {
            level,
            dim: inner_dim,
            bytes: payload.to_vec(),
            scale,
            seed_id,
        },
    })
}

fn legacy_fixture_generation_root(
    codec_context_id: &[u8; 32],
    generation_rows: u32,
    rows: &[LegacyFixtureRow],
) -> AnyResult<[u8; 32]> {
    let mut rows = rows.iter().collect::<Vec<_>>();
    rows.sort_by(|left, right| left.cx_id.as_bytes().cmp(right.cx_id.as_bytes()));
    require(
        rows.len() == generation_rows as usize
            && rows.windows(2).all(|pair| pair[0].cx_id != pair[1].cx_id),
        "legacy staging generation root has duplicate or mismatched rows",
    )?;
    let mut hasher = Sha256::new();
    hasher.update(b"calyx-registry-compression-generation-v1");
    hasher.update(codec_context_id);
    hasher.update(generation_rows.to_be_bytes());
    for row in rows {
        hasher.update(row.cx_id.as_bytes());
        hasher.update([row.manifest_level_code]);
        hasher.update((row.qv.dim as u64).to_be_bytes());
        hasher.update(row.qv.scale.to_bits().to_be_bytes());
        hasher.update(row.qv.seed_id);
        hasher.update((row.qv.bytes.len() as u64).to_be_bytes());
        hasher.update(&row.qv.bytes);
    }
    Ok(hasher.finalize().into())
}

fn legacy_fixture_raw_generation_root(
    codec_context_id: &[u8; 32],
    generation_rows: u32,
    raw: &[(Vec<u8>, Vec<u8>)],
) -> AnyResult<[u8; 32]> {
    let mut rows = raw
        .iter()
        .map(|(key, value)| Ok((cx_id_from_key(key)?, value.as_slice())))
        .collect::<AnyResult<Vec<_>>>()?;
    rows.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    require(
        rows.len() == generation_rows as usize
            && rows.windows(2).all(|pair| pair[0].0 != pair[1].0),
        "legacy staging raw generation root has duplicate or mismatched rows",
    )?;
    let mut hasher = Sha256::new();
    hasher.update(b"calyx-registry-compression-raw-generation-v1");
    hasher.update(codec_context_id);
    hasher.update(generation_rows.to_be_bytes());
    for (cx_id, bytes) in rows {
        hasher.update(cx_id.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Ok(hasher.finalize().into())
}

fn legacy_manifest_digest(prefix: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"calyx-registry-compression-manifest-v1");
    hasher.update((prefix.len() as u64).to_be_bytes());
    hasher.update(prefix);
    hasher.finalize().into()
}

fn legacy_nonzero_padding(bytes: &[u8], bits: usize) -> bool {
    let used = bits % 8;
    if used == 0 || bytes.is_empty() {
        return false;
    }
    let mask = !((1_u16 << used) - 1) as u8;
    bytes.last().is_some_and(|last| last & mask != 0)
}

fn current_shared_seed(
    registered: &RegisteredSlot,
    dim: usize,
    level: QuantLevel,
) -> calyx_forge::RotationSeed {
    shared_seed_for_domain(registered, dim, level, b"turboquant-tqpr-v2")
}

fn shared_seed_for_domain(
    registered: &RegisteredSlot,
    dim: usize,
    level: QuantLevel,
    codec_domain: &[u8],
) -> calyx_forge::RotationSeed {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"calyx-registry-shared-codec-v2");
    hasher.update(&(codec_domain.len() as u64).to_be_bytes());
    hasher.update(codec_domain);
    hasher.update(registered.lens_id.as_bytes());
    hasher.update(&registered.slot.slot_id.get().to_be_bytes());
    hasher.update(&(registered.slot.slot_key.key().len() as u64).to_be_bytes());
    hasher.update(registered.slot.slot_key.key().as_bytes());
    hasher.update(&(dim as u64).to_be_bytes());
    hasher.update(&[match level {
        QuantLevel::Bits3p5 => 4,
        QuantLevel::Bits2p5 => 5,
        _ => 0,
    }]);
    new_seed(dim, hasher.finalize().as_bytes())
}

#[derive(Clone, Copy)]
enum LegacyFixtureMutation {
    WrongSeed,
    BodyMismatch,
    SwapRows,
    PairedPrimaryRawSwap,
}

impl LegacyFixtureMutation {
    fn label(self) -> &'static str {
        match self {
            Self::WrongSeed => "wrong-seed-rehashed",
            Self::BodyMismatch => "raw-body-mismatch-rehashed",
            Self::SwapRows => "swapped-key-rows",
            Self::PairedPrimaryRawSwap => "paired-primary-raw-swap",
        }
    }

    fn expected_error(self) -> &'static str {
        match self {
            Self::WrongSeed => "seed does not match the frozen slot/lens geometry",
            Self::BodyMismatch | Self::SwapRows => {
                "do not match deterministic raw-source re-encoding"
            }
            Self::PairedPrimaryRawSwap => "does not match the immutable Base slot hash",
        }
    }

    fn apply(
        self,
        primary: &mut [(Vec<u8>, Vec<u8>)],
        raw: &mut [(Vec<u8>, Vec<u8>)],
    ) -> AnyResult<()> {
        match self {
            Self::WrongSeed => {
                let row = primary
                    .first_mut()
                    .ok_or_else(|| failure("wrong-seed legacy fixture has no rows"))?;
                require(
                    row.1.len() > LEGACY_OUTER_V2_HEADER_BYTES + LEGACY_TQPR_V1_PREFIX_BYTES
                        && row.1[1] == 2
                        && row.1[LEGACY_OUTER_V2_HEADER_BYTES + 4] == 1,
                    "wrong-seed fixture is not outer-v2/TQPR-v1",
                )?;
                row.1[17] ^= 0x80;
                row.1[LEGACY_OUTER_V2_HEADER_BYTES + 24] ^= 0x80;
                rebuild_legacy_digests(&mut row.1)?;
            }
            Self::BodyMismatch => {
                let row = primary
                    .first_mut()
                    .ok_or_else(|| failure("body-mismatch legacy fixture has no rows"))?;
                require(
                    row.1.len() > LEGACY_OUTER_V2_HEADER_BYTES + LEGACY_TQPR_V1_HEADER_BYTES,
                    "body-mismatch fixture has no scalar payload byte",
                )?;
                row.1[LEGACY_OUTER_V2_HEADER_BYTES + LEGACY_TQPR_V1_HEADER_BYTES] ^= 0x01;
                rebuild_legacy_digests(&mut row.1)?;
            }
            Self::SwapRows => {
                require(
                    primary.len() >= 2,
                    "swapped-row legacy fixture needs two rows",
                )?;
                let (first, remaining) = primary.split_at_mut(1);
                std::mem::swap(&mut first[0].1, &mut remaining[0].1);
            }
            Self::PairedPrimaryRawSwap => {
                require(
                    primary.len() >= 2 && raw.len() >= 2,
                    "paired-swap legacy fixture needs two primary and raw rows",
                )?;
                let (first_primary, remaining_primary) = primary.split_at_mut(1);
                std::mem::swap(&mut first_primary[0].1, &mut remaining_primary[0].1);
                let (first_raw, remaining_raw) = raw.split_at_mut(1);
                std::mem::swap(&mut first_raw[0].1, &mut remaining_raw[0].1);
            }
        }
        Ok(())
    }

    fn request_rows(
        self,
        rows: &[(CxId, Vec<f32>)],
        raw: &[(Vec<u8>, Vec<u8>)],
    ) -> AnyResult<Vec<(CxId, Vec<f32>)>> {
        let mut requested = rows.to_vec();
        if matches!(self, Self::PairedPrimaryRawSwap) {
            require(
                requested.len() >= 2 && raw.len() >= 2,
                "paired-swap request needs two source and raw rows",
            )?;
            let first_cx_id = cx_id_from_key(&raw[0].0)?;
            let second_cx_id = cx_id_from_key(&raw[1].0)?;
            let first_index = requested
                .iter()
                .position(|(cx_id, _)| *cx_id == first_cx_id)
                .ok_or_else(|| failure("paired-swap first raw key is absent from source rows"))?;
            let second_index = requested
                .iter()
                .position(|(cx_id, _)| *cx_id == second_cx_id)
                .ok_or_else(|| failure("paired-swap second raw key is absent from source rows"))?;
            let first_values = requested[first_index].1.clone();
            requested[first_index].1 = requested[second_index].1.clone();
            requested[second_index].1 = first_values;
        }
        Ok(requested)
    }
}

fn rebuild_legacy_digests(envelope: &mut [u8]) -> AnyResult<()> {
    require(
        envelope.len() > LEGACY_OUTER_V2_HEADER_BYTES + LEGACY_TQPR_V1_HEADER_BYTES
            && envelope[0] == 16
            && envelope[1] == 2,
        "legacy digest rebuild requires an outer-v2 envelope",
    )?;
    let scale = f32::from_bits(u32::from_be_bytes(envelope[13..17].try_into()?));
    let payload = &mut envelope[LEGACY_OUTER_V2_HEADER_BYTES..];
    require(
        &payload[..4] == b"TQPR" && payload[4] == 1,
        "legacy digest rebuild requires TQPR-v1",
    )?;
    let inner_digest = domain_digest(
        b"calyx/turboquant/tqpr/payload/v1\0",
        &payload[..LEGACY_TQPR_V1_PREFIX_BYTES],
        &payload[LEGACY_TQPR_V1_HEADER_BYTES..],
        true,
        Some(scale),
    );
    payload[LEGACY_TQPR_V1_PREFIX_BYTES..LEGACY_TQPR_V1_HEADER_BYTES]
        .copy_from_slice(&inner_digest);
    let outer_digest = domain_digest(
        b"calyx-registry-slot-envelope-v2",
        &envelope[..53],
        &envelope[LEGACY_OUTER_V2_HEADER_BYTES..],
        false,
        None,
    );
    envelope[53..LEGACY_OUTER_V2_HEADER_BYTES].copy_from_slice(&outer_digest);
    Ok(())
}

fn legacy_refusal_edge(
    root: &Path,
    valid_legacy_directory: &Path,
    registry: &Registry,
    registered: &RegisteredSlot,
    corpus: &Corpus,
    manifest_template: &[u8],
    mutation: LegacyFixtureMutation,
) -> AnyResult<()> {
    let directory = root.join(format!(
        "legacy-refusal-slot-{}-{}",
        registered.slot.slot_id.get(),
        mutation.label()
    ));
    copy_tree(valid_legacy_directory, &directory)?;
    let writer = open_writer(&directory)?;
    let slot_id = registered.slot.slot_id;
    let injection_base_seq = writer.latest_seq();
    let mut primary = writer.scan_cf_at(injection_base_seq, ColumnFamily::slot(slot_id))?;
    let mut raw = writer.scan_cf_at(injection_base_seq, ColumnFamily::slot_raw(slot_id))?;
    mutation.apply(&mut primary, &mut raw)?;
    // Reference-only evidence for the mutated v2 generation roots; never persisted.
    let staging_manifest = legacy_staging_manifest(manifest_template, &primary, &raw)?;
    let manifest_key = compression_manifest_key(slot_id);
    // Reconstruct the mutated pre-#562 legacy on-disk generation through the
    // reconstruction ingress (the lawful guard refuses an unmanifested compressed
    // column). The mutations preserve the primary/raw key sets and the v2
    // compressed tag, so the reconstruction's legacy-shape contract admits them;
    // the corruption is caught downstream by the production `Migrate` verifier.
    let injection_seq =
        reconstruct_legacy_generation(&writer, slot_id, &primary, &raw, injection_base_seq)?;
    writer.flush()?;
    require(
        writer
            .read_cf_at(injection_seq, ColumnFamily::Compression, &manifest_key)?
            .is_none(),
        format!(
            "legacy {} refusal fixture still exposes a generation manifest",
            mutation.label()
        ),
    )?;
    drop(writer);

    let writer = open_writer(&directory)?;
    require(
        writer.latest_seq() == injection_seq,
        "reopened legacy refusal fixture lost its injected state",
    )?;
    let before = logical_state(&writer, injection_seq, std::slice::from_ref(registered))?;
    log(json!({
        "event": "edge_legacy_refusal_before",
        "mutation_kind": mutation.label(),
        "seq": injection_seq,
        "reference_legacy_manifest_sha256": sha256_hex(&staging_manifest),
        "reference_generation_root": hex(&staging_manifest[48..80]),
        "reference_raw_generation_root": hex(&staging_manifest[80..112]),
        "reconstruction_ingress": "commit_legacy_generation_reconstruction_if_seq",
        "state": before,
    }));
    let rows = corpus
        .rows_by_slot
        .get(&slot_id)
        .ok_or_else(|| failure("legacy refusal source rows missing"))?;
    let requested_rows = mutation.request_rows(rows, &raw)?;
    let query = corpus
        .queries_by_slot
        .get(&slot_id)
        .ok_or_else(|| failure("legacy refusal query missing"))?;
    let error = expect_calyx_error(registry.write_compressed_slot_batch(
        &writer,
        &registered.slot,
        &requested_rows,
        std::slice::from_ref(query),
        1,
    ))?;
    require(
        error.message.contains(mutation.expected_error()),
        format!(
            "legacy {} refusal reported the wrong root cause: {}",
            mutation.label(),
            error.message
        ),
    )?;
    let after_seq = writer.latest_seq();
    let after = logical_state(&writer, after_seq, std::slice::from_ref(registered))?;
    require(
        after_seq == injection_seq,
        format!("legacy {} refusal advanced durable seq", mutation.label()),
    )?;
    require(
        before == after,
        format!("legacy {} refusal mutated durable state", mutation.label()),
    )?;
    log(json!({
        "event": "edge_legacy_refusal_after",
        "mutation_kind": mutation.label(),
        "trigger_error": calyx_error_json(&error),
        "seq": after_seq,
        "state": after,
        "physical": physical_json(&physical_digest(&directory)?),
        "mutation_after_trigger": false,
    }));
    drop(writer);
    Ok(())
}

fn domain_digest(
    domain: &[u8],
    prefix: &[u8],
    body: &[u8],
    little_endian_lengths: bool,
    scale: Option<f32>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    if little_endian_lengths {
        hasher.update((prefix.len() as u64).to_le_bytes());
    } else {
        hasher.update((prefix.len() as u64).to_be_bytes());
    }
    hasher.update(prefix);
    if little_endian_lengths {
        hasher.update((body.len() as u64).to_le_bytes());
    } else {
        hasher.update((body.len() as u64).to_be_bytes());
    }
    hasher.update(body);
    if let Some(scale) = scale {
        hasher.update(scale.to_bits().to_le_bytes());
    }
    hasher.finalize().into()
}

fn wrong_context_edge(
    directory: &Path,
    registry: &Registry,
    registered: &RegisteredSlot,
) -> AnyResult<()> {
    let vault = open_reader(directory)?;
    let snapshot = vault.latest_seq();
    let before = logical_state(&vault, snapshot, std::slice::from_ref(registered))?;
    let mut wrong_slot = registered.slot.clone();
    wrong_slot.slot_key = wrong_slot
        .slot_id
        .with_key(format!("{}-wrong-context", wrong_slot.slot_key.key()));
    log(json!({
        "event": "edge_wrong_context_before",
        "snapshot": snapshot,
        "requested_slot_key": wrong_slot.slot_key.key(),
        "state": before,
    }));
    let index = registry.compressed_slot_index(&vault, &wrong_slot)?;
    let key_error = expect_calyx_error(index.verify_at(snapshot))?;

    let mut wrong_asymmetry = registered.slot.clone();
    wrong_asymmetry.asymmetry = Asymmetry::Dual {
        a: wrong_asymmetry.slot_id,
        b: SlotId::new(wrong_asymmetry.slot_id.get() + 1),
    };
    let asymmetry_error =
        expect_calyx_error(registry.compressed_slot_index(&vault, &wrong_asymmetry))?;
    require(
        asymmetry_error.message.contains("slot asymmetry"),
        "wrong-asymmetry context did not fail the duplicated contract check",
    )?;

    let mut wrong_key_id = registered.slot.clone();
    wrong_key_id.slot_key = SlotId::new(wrong_key_id.slot_id.get() + 1_000)
        .with_key(wrong_key_id.slot_key.key().to_string());
    let key_id_error = expect_calyx_error(registry.compressed_slot_index(&vault, &wrong_key_id))?;
    require(
        key_id_error.message.contains("slot key id"),
        "wrong SlotKey id did not fail the duplicated identity check",
    )?;
    let after = logical_state(&vault, vault.latest_seq(), std::slice::from_ref(registered))?;
    require(
        before == after,
        "wrong-context verification mutated persisted state",
    )?;
    log(json!({
        "event": "edge_wrong_context_after",
        "wrong_persisted_context_error": calyx_error_json(&key_error),
        "wrong_asymmetry_error": calyx_error_json(&asymmetry_error),
        "wrong_slot_key_id_error": calyx_error_json(&key_id_error),
        "state": after,
        "mutation": false,
    }));
    drop(vault);
    Ok(())
}

fn current_metadata_edge(directory: &Path, registered: &RegisteredSlot) -> AnyResult<()> {
    let vault = open_reader(directory)?;
    let snapshot = vault.latest_seq();
    let before = logical_state(&vault, snapshot, std::slice::from_ref(registered))?;
    let primary = vault.scan_cf_at(snapshot, ColumnFamily::slot(registered.slot.slot_id))?;
    let bytes = primary
        .first()
        .map(|(_, bytes)| bytes)
        .ok_or_else(|| failure("current metadata edge has no persisted row"))?;
    let envelope = inspect_unbound_stored_slot_envelope(bytes)?;
    let payload = bytes
        .get(REGISTRY_ENVELOPE_HEADER_BYTES..)
        .ok_or_else(|| failure("current metadata edge has no TQPR payload"))?;
    let current = QuantizedVec {
        level: expected_level(registered.bits_per_channel_x2)?,
        dim: envelope.stored_dim as usize,
        bytes: payload.to_vec(),
        scale: envelope.quant_scale,
        seed_id: decode_hex_32(&envelope.seed_id)?,
    };

    let mut wrong_version = current.clone();
    wrong_version.bytes[4] = 99;
    rebuild_current_tqpr_digest(&mut wrong_version)?;
    let version_error = expect_forge_error(TurboQuantCodec::inspect(&wrong_version))?;
    require(
        version_error.to_string().contains("version"),
        "wrong current TQPR version reported the wrong root cause",
    )?;

    let mut wrong_seed = current.clone();
    wrong_seed.bytes[24] ^= 0x80;
    rebuild_current_tqpr_digest(&mut wrong_seed)?;
    let seed_error = expect_forge_error(TurboQuantCodec::inspect(&wrong_seed))?;
    require(
        seed_error.to_string().contains("seed ID"),
        "wrong current TQPR seed reported the wrong root cause",
    )?;

    let mut wrong_dimension = current.clone();
    let header_dim = u32::from_le_bytes(wrong_dimension.bytes[8..12].try_into()?);
    wrong_dimension.bytes[8..12].copy_from_slice(&(header_dim + 1).to_le_bytes());
    rebuild_current_tqpr_digest(&mut wrong_dimension)?;
    let dimension_error = expect_forge_error(TurboQuantCodec::inspect(&wrong_dimension))?;
    require(
        dimension_error.to_string().contains("dimension"),
        "wrong current TQPR dimension reported the wrong root cause",
    )?;

    let mut oversized_outer = bytes.clone();
    oversized_outer[4..8].copy_from_slice(&OVER_LIMIT_DIM.to_be_bytes());
    oversized_outer[8..12].copy_from_slice(&OVER_LIMIT_DIM.to_be_bytes());
    oversized_outer[12] = 0;
    rebuild_current_outer_digest(&mut oversized_outer)?;
    let oversized_error =
        expect_calyx_error(inspect_unbound_stored_slot_envelope(&oversized_outer))?;
    require(
        oversized_error
            .message
            .contains("before payload allocation")
            && oversized_error.message.contains("4096"),
        "oversized current outer envelope was not refused before payload allocation",
    )?;

    let after_seq = vault.latest_seq();
    let after = logical_state(&vault, after_seq, std::slice::from_ref(registered))?;
    require(
        snapshot == after_seq,
        "metadata inspection edge changed snapshot",
    )?;
    require(
        before == after,
        "metadata inspection edge mutated persisted state",
    )?;
    log(json!({
        "event": "edge_current_metadata_after",
        "source": "independently reopened persisted v3 envelope/TQPR-v2 payload",
        "snapshot": after_seq,
        "wrong_version_error": forge_error_json(&version_error),
        "wrong_seed_error": forge_error_json(&seed_error),
        "wrong_dimension_error": forge_error_json(&dimension_error),
        "oversized_outer_error": calyx_error_json(&oversized_error),
        "state": after,
        "mutation": false,
    }));
    drop(vault);
    Ok(())
}

fn rebuild_current_outer_digest(envelope: &mut [u8]) -> AnyResult<()> {
    require(
        envelope.len() >= REGISTRY_ENVELOPE_HEADER_BYTES && envelope[0] == 16 && envelope[1] == 3,
        "current outer digest rebuild requires a v3 compressed envelope",
    )?;
    let digest = domain_digest(
        b"calyx-registry-slot-envelope-v3",
        &envelope[..CURRENT_OUTER_V3_PREFIX_BYTES],
        &envelope[REGISTRY_ENVELOPE_HEADER_BYTES..],
        false,
        None,
    );
    envelope[CURRENT_OUTER_V3_PREFIX_BYTES..REGISTRY_ENVELOPE_HEADER_BYTES]
        .copy_from_slice(&digest);
    Ok(())
}

fn rebuild_current_tqpr_digest(qv: &mut QuantizedVec) -> AnyResult<()> {
    require(
        qv.bytes.len() > TURBOQUANT_FORMAT_HEADER_BYTES,
        "current TQPR digest rebuild requires a body",
    )?;
    let digest = domain_digest(
        b"calyx/turboquant/tqpr/payload/v2\0",
        &qv.bytes[..56],
        &qv.bytes[TURBOQUANT_FORMAT_HEADER_BYTES..],
        true,
        Some(qv.scale),
    );
    qv.bytes[56..TURBOQUANT_FORMAT_HEADER_BYTES].copy_from_slice(&digest);
    Ok(())
}

fn corruption_edge(
    root: &Path,
    source_directory: &Path,
    registry: &Registry,
    registered: &RegisteredSlot,
) -> AnyResult<()> {
    let corrupt_directory = root.join("corrupt-copy");
    copy_tree(source_directory, &corrupt_directory)?;
    let writer = open_writer(&corrupt_directory)?;
    let before_seq = writer.latest_seq();
    let before_state = logical_state(&writer, before_seq, std::slice::from_ref(registered))?;
    let before_physical = physical_digest(&corrupt_directory)?;
    log(json!({
        "event": "edge_corruption_before",
        "seq": before_seq,
        "state": before_state,
        "physical": physical_json(&before_physical),
    }));
    let slot_id = registered.slot.slot_id;
    let mut primary = writer.scan_cf_at(before_seq, ColumnFamily::slot(slot_id))?;
    let raw = writer.scan_cf_at(before_seq, ColumnFamily::slot_raw(slot_id))?;
    let manifest_key = compression_manifest_key(slot_id);
    let manifest = writer
        .read_cf_at(before_seq, ColumnFamily::Compression, &manifest_key)?
        .ok_or_else(|| failure("corruption fixture manifest missing"))?;
    let corrupt_row = primary
        .first_mut()
        .ok_or_else(|| failure("corruption fixture primary row missing"))?;
    require(
        corrupt_row.1.len() > REGISTRY_ENVELOPE_HEADER_BYTES,
        "corruption fixture row has no codec payload",
    )?;
    let last = corrupt_row.1.len() - 1;
    corrupt_row.1[last] ^= 0x01;

    // Persisted-corruption injection: tamper one compressed primary byte and
    // rewrite the full column in place through the generation-injection ingress.
    // The lawful compression guard refuses any row mutation of a manifested
    // generation outside a lifecycle transition, so this simulates on-disk
    // corruption the way a bit-rot event would — leaving the manifest untouched so
    // the index's generation-root verification still runs against it. `manifest`
    // is read only to confirm the fixture starts manifested; it is not rewritten.
    let _ = &manifest;
    let mut writes = Vec::with_capacity(primary.len() + raw.len());
    writes.extend(
        primary
            .iter()
            .cloned()
            .map(|(key, value)| (ColumnFamily::slot(slot_id), key, value)),
    );
    writes.extend(
        raw.iter()
            .cloned()
            .map(|(key, value)| (ColumnFamily::slot_raw(slot_id), key, value)),
    );
    let corrupt_seq = writer.commit_generation_injection_if_seq(before_seq, writes)?;
    require(
        corrupt_seq > before_seq,
        "corruption injection did not advance durable seq",
    )?;
    writer.flush()?;
    let injected_state = logical_state(&writer, corrupt_seq, std::slice::from_ref(registered))?;
    require(
        before_state != injected_state,
        "corruption injection did not change persisted logical bytes",
    )?;
    drop(writer);

    let after_physical = physical_digest(&corrupt_directory)?;
    let reader = open_reader(&corrupt_directory)?;
    let readback_seq = reader.latest_seq();
    let readback_state = logical_state(&reader, readback_seq, std::slice::from_ref(registered))?;
    require(
        injected_state == readback_state,
        "reopened corruption state differs from the injected committed state",
    )?;
    let index = registry.compressed_slot_index(&reader, &registered.slot)?;
    let error = expect_calyx_error(index.verify_at(readback_seq))?;
    require(
        error.message.contains("SHA-256 mismatch"),
        "corrupted persisted payload did not fail its cryptographic digest",
    )?;
    log(json!({
        "event": "edge_corruption_after",
        "trigger_error": calyx_error_json(&error),
        "seq": readback_seq,
        "state": readback_state,
        "physical": physical_json(&after_physical),
        "physical_changed": before_physical != after_physical,
        "corruption_persisted": true,
        "corruption_detected": true,
    }));
    drop(reader);
    Ok(())
}

fn raw_corruption_edge(
    root: &Path,
    source_directory: &Path,
    registry: &Registry,
    registered: &RegisteredSlot,
) -> AnyResult<()> {
    let directory = root.join("raw-corrupt-copy");
    copy_tree(source_directory, &directory)?;
    let writer = open_writer(&directory)?;
    let slot_id = registered.slot.slot_id;
    let before_seq = writer.latest_seq();
    let primary = writer.scan_cf_at(before_seq, ColumnFamily::slot(slot_id))?;
    let mut raw = writer.scan_cf_at(before_seq, ColumnFamily::slot_raw(slot_id))?;
    let manifest_key = compression_manifest_key(slot_id);
    let manifest = writer
        .read_cf_at(before_seq, ColumnFamily::Compression, &manifest_key)?
        .ok_or_else(|| failure("raw-corruption fixture manifest missing"))?;
    let before = logical_state(&writer, before_seq, std::slice::from_ref(registered))?;
    log(json!({
        "event": "edge_raw_corruption_before",
        "seq": before_seq,
        "state": before,
    }));
    let corrupt_row = raw
        .first_mut()
        .ok_or_else(|| failure("raw-corruption fixture sidecar row missing"))?;
    let last = corrupt_row.1.len() - 1;
    corrupt_row.1[last] ^= 0x01;
    // Persisted raw-sidecar corruption injected in place through the
    // generation-injection ingress (see `corruption_edge`); the manifest is read
    // only to confirm the fixture starts manifested and is left untouched so the
    // authenticated raw-generation-root check still runs against it.
    let _ = &manifest;
    let mut writes = Vec::with_capacity(primary.len() + raw.len());
    writes.extend(
        primary
            .iter()
            .cloned()
            .map(|(key, value)| (ColumnFamily::slot(slot_id), key, value)),
    );
    writes.extend(
        raw.iter()
            .cloned()
            .map(|(key, value)| (ColumnFamily::slot_raw(slot_id), key, value)),
    );
    let corrupt_seq = writer.commit_generation_injection_if_seq(before_seq, writes)?;
    writer.flush()?;
    drop(writer);

    let reader = open_reader(&directory)?;
    let after = logical_state(&reader, corrupt_seq, std::slice::from_ref(registered))?;
    require(before != after, "raw-sidecar corruption did not persist")?;
    let index = registry.compressed_slot_index(&reader, &registered.slot)?;
    let error = expect_calyx_error(index.verify_at(corrupt_seq))?;
    require(
        error
            .message
            .contains("raw-sidecar whole-column generation root mismatch"),
        "raw-sidecar corruption did not fail its authenticated generation root",
    )?;
    log(json!({
        "event": "edge_raw_corruption_after",
        "trigger_error": calyx_error_json(&error),
        "seq": corrupt_seq,
        "state": after,
        "primary_sha256_unchanged": before["slots"][0]["primary_sha256"]
            == after["slots"][0]["primary_sha256"],
        "raw_sha256_changed": before["slots"][0]["raw_sha256"]
            != after["slots"][0]["raw_sha256"],
        "corruption_persisted": true,
        "corruption_detected": true,
    }));
    drop(reader);
    Ok(())
}

fn maximum_dimension_edge(root: &Path) -> AnyResult<()> {
    let mut registry = Registry::new();
    let registered = register_slot(&mut registry, "issue551-max4096", MAX_DIM, 33, 5)?;
    let slots = vec![registered.clone()];
    let corpus = build_mixed_one_hot_corpus(&registry, &slots, 2, "max4096")?;
    let directory = root.join("max-dimension");
    let reports = populate_and_compress(&directory, &registry, &slots, &corpus, false)?;
    let physical = physical_digest(&directory)?;
    let reader = open_reader(&directory)?;
    let snapshot = reader.latest_seq();
    let index = registry.compressed_slot_index(&reader, &registered.slot)?;
    index.verify_at(snapshot)?;
    let query = corpus
        .queries_by_slot
        .get(&registered.slot.slot_id)
        .ok_or_else(|| failure("maximum-dimension query missing"))?;
    let started = Instant::now();
    let hits = index.search_at(&query.values, 1, snapshot)?;
    let search_elapsed = started.elapsed();
    require(
        hits.first().map(|hit| hit.cx_id) == Some(corpus.expected_top1),
        "maximum-dimension persisted search returned the wrong top-1 row",
    )?;
    let read = index.read_at(corpus.cx_ids[0], snapshot)?;
    require(
        read.as_dense()
            .is_some_and(|values| values.len() == MAX_DIM as usize),
        "maximum-dimension readback has the wrong shape",
    )?;
    let report = reports
        .first()
        .ok_or_else(|| failure("maximum-dimension report missing"))?;
    require(
        report.logical_data_bits_per_channel.to_bits() == 2.5_f32.to_bits(),
        "maximum-dimension report lost the exact 2.5 bpc contract",
    )?;
    log(json!({
        "event": "edge_maximum_dimension_after",
        "dimension": MAX_DIM,
        "snapshot": snapshot,
        "primary_rows": reader.scan_cf_at(snapshot, ColumnFamily::slot(registered.slot.slot_id))?.len(),
        "manifest_bytes": reader.read_cf_at(snapshot, ColumnFamily::Compression, &compression_manifest_key(registered.slot.slot_id))?.map(|bytes| bytes.len()),
        "actual_top1": hits[0].cx_id.to_string(),
        "expected_top1": corpus.expected_top1.to_string(),
        "search_elapsed_ms": search_elapsed.as_secs_f64() * 1_000.0,
        "logical_data_bpc": report.logical_data_bits_per_channel,
        "codec_payload_bytes": report.codec_payload_bytes_total,
        "physical": physical_json(&physical),
    }));
    drop(reader);
    Ok(())
}

fn over_limit_edge(root: &Path) -> AnyResult<()> {
    let mut registry = Registry::new();
    let registered = register_slot(
        &mut registry,
        "issue551-overlimit4097",
        OVER_LIMIT_DIM,
        34,
        5,
    )?;
    let slots = vec![registered.clone()];
    let corpus = build_mixed_one_hot_corpus(&registry, &slots, 2, "overlimit4097")?;
    let directory = root.join("over-limit");
    fs::create_dir_all(&directory)?;
    let vault = open_writer(&directory)?;
    persist_source_rows(&vault, &slots, &corpus)?;
    vault.flush()?;
    let before_seq = vault.latest_seq();
    let before = logical_state(&vault, before_seq, &slots)?;
    log(json!({
        "event": "edge_over_limit_before",
        "dimension": OVER_LIMIT_DIM,
        "seq": before_seq,
        "state": before,
    }));
    let query = corpus
        .queries_by_slot
        .get(&registered.slot.slot_id)
        .ok_or_else(|| failure("over-limit query missing"))?;
    let rows = corpus
        .rows_by_slot
        .get(&registered.slot.slot_id)
        .ok_or_else(|| failure("over-limit rows missing"))?;
    let error = expect_calyx_error(registry.write_compressed_slot_batch(
        &vault,
        &registered.slot,
        rows,
        std::slice::from_ref(query),
        1,
    ))?;
    require(
        error.message.contains("1..=4096"),
        "over-limit error did not report the supported dimension boundary",
    )?;
    let after_seq = vault.latest_seq();
    let after = logical_state(&vault, after_seq, &slots)?;
    require(
        before_seq == after_seq,
        "over-limit failure advanced vault seq",
    )?;
    require(
        before == after,
        "over-limit failure mutated persisted state",
    )?;
    require(
        vault
            .read_cf_at(
                after_seq,
                ColumnFamily::Compression,
                &compression_manifest_key(registered.slot.slot_id),
            )?
            .is_none(),
        "over-limit failure persisted a compression manifest",
    )?;
    require(
        vault
            .scan_cf_at(after_seq, ColumnFamily::slot_raw(registered.slot.slot_id))?
            .is_empty(),
        "over-limit failure persisted raw sidecars",
    )?;
    log(json!({
        "event": "edge_over_limit_after",
        "trigger_error": calyx_error_json(&error),
        "seq": after_seq,
        "state": after,
        "mutation": false,
    }));
    drop(vault);
    Ok(())
}

fn persist_source_rows<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    slots: &[RegisteredSlot],
    corpus: &Corpus,
) -> AnyResult<()> {
    for (row_index, (bytes, cx_id)) in corpus
        .inputs
        .iter()
        .zip(corpus.cx_ids.iter().copied())
        .enumerate()
    {
        let mut vectors = BTreeMap::new();
        for registered in slots {
            let values = corpus
                .rows_by_slot
                .get(&registered.slot.slot_id)
                .and_then(|rows| rows.get(row_index))
                .map(|(_, values)| values.clone())
                .ok_or_else(|| failure("source persistence row values missing"))?;
            vectors.insert(
                registered.slot.slot_id,
                SlotVector::Dense {
                    dim: values.len() as u32,
                    data: values,
                },
            );
        }
        vault.put(Constellation {
            cx_id,
            vault_id: vault.vault_id(),
            panel_version: PANEL_VERSION,
            created_at: FIXED_TS,
            input_ref: InputRef {
                hash: sha256_array(bytes),
                pointer: Some(format!("fsv://issue551/edge/{row_index}")),
                redacted: false,
            },
            modality: Modality::Text,
            slots: vectors,
            scalars: BTreeMap::new(),
            metadata: BTreeMap::new(),
            anchors: Vec::new(),
            provenance: LedgerRef {
                seq: 0,
                hash: [0; 32],
            },
            flags: CxFlags {
                ungrounded: true,
                ..CxFlags::default()
            },
        })?;
    }
    Ok(())
}

fn logical_state<C: calyx_core::Clock>(
    vault: &AsterVault<C>,
    snapshot: u64,
    slots: &[RegisteredSlot],
) -> AnyResult<Value> {
    let base = vault.scan_cf_at(snapshot, ColumnFamily::Base)?;
    let mut slot_states = Vec::with_capacity(slots.len());
    for registered in slots {
        let slot_id = registered.slot.slot_id;
        let primary = vault.scan_cf_at(snapshot, ColumnFamily::slot(slot_id))?;
        let raw = vault.scan_cf_at(snapshot, ColumnFamily::slot_raw(slot_id))?;
        let manifest = vault.read_cf_at(
            snapshot,
            ColumnFamily::Compression,
            &compression_manifest_key(slot_id),
        )?;
        slot_states.push(json!({
            "slot_id": slot_id.get(),
            "primary_rows": primary.len(),
            "primary_value_bytes": value_bytes(&primary),
            "primary_sha256": digest_rows(&primary),
            "raw_rows": raw.len(),
            "raw_value_bytes": value_bytes(&raw),
            "raw_sha256": digest_rows(&raw),
            "manifest_bytes": manifest.as_ref().map(Vec::len).unwrap_or(0),
            "manifest_sha256": manifest.as_deref().map(sha256_hex),
        }));
    }
    Ok(json!({
        "snapshot": snapshot,
        "base_rows": base.len(),
        "base_value_bytes": value_bytes(&base),
        "base_sha256": digest_rows(&base),
        "slots": slot_states,
    }))
}

fn open_writer(directory: &Path) -> AnyResult<AsterVault<FixedClock>> {
    Ok(AsterVault::new_durable_with_clock(
        directory,
        VaultId::from_str(VAULT_ID)?,
        VAULT_SALT,
        VaultOptions::default(),
        FixedClock::new(FIXED_TS),
    )?)
}

fn open_reader(directory: &Path) -> AnyResult<AsterVault<FixedClock>> {
    let options = VaultOptions {
        read_only: true,
        restore_ledger_hook: false,
        ..VaultOptions::default()
    };
    Ok(AsterVault::open_with_clock(
        directory,
        VaultId::from_str(VAULT_ID)?,
        VAULT_SALT,
        options,
        FixedClock::new(FIXED_TS),
    )?)
}

fn measure_dense(
    registry: &Registry,
    lens_id: calyx_core::LensId,
    bytes: &[u8],
) -> AnyResult<Vec<f32>> {
    let vector = registry.measure(lens_id, &Input::new(Modality::Text, bytes.to_vec()))?;
    vector
        .as_dense()
        .map(<[f32]>::to_vec)
        .ok_or_else(|| failure("registered one-hot lens returned a non-dense vector"))
}

fn stored_dim_for(registry: &Registry, registered: &RegisteredSlot) -> AnyResult<usize> {
    let spec = registry
        .lens_spec(registered.lens_id)
        .ok_or_else(|| failure("registered compression lens spec is missing"))?;
    require(
        spec.truncate_dim == registered.truncate_dim,
        "registered compression fixture truncation differs from frozen lens spec",
    )?;
    registered_stored_dim(registered)
}

fn registered_stored_dim(registered: &RegisteredSlot) -> AnyResult<usize> {
    let SlotShape::Dense(raw_dim) = registered.slot.shape else {
        return Err(failure("registered compression slot is not dense").into());
    };
    let stored_dim = registered.truncate_dim.unwrap_or(raw_dim);
    require(
        stored_dim > 0 && stored_dim <= raw_dim,
        format!(
            "registered compression stored dimension {stored_dim} is invalid for raw dimension {raw_dim}"
        ),
    )?;
    Ok(stored_dim as usize)
}

fn one_hot_bucket(values: &[f32]) -> AnyResult<usize> {
    let ones = values
        .iter()
        .enumerate()
        .filter_map(|(index, value)| (value.to_bits() == 1.0_f32.to_bits()).then_some(index))
        .collect::<Vec<_>>();
    require(ones.len() == 1, "real one-hot lens output is not canonical")?;
    require(
        values
            .iter()
            .enumerate()
            .all(|(index, value)| index == ones[0] || value.to_bits() == 0.0_f32.to_bits()),
        "real one-hot lens output contains a non-binary coefficient",
    )?;
    Ok(ones[0])
}

fn expected_level(bits_per_channel_x2: u8) -> AnyResult<QuantLevel> {
    match bits_per_channel_x2 {
        5 => Ok(QuantLevel::Bits2p5),
        7 => Ok(QuantLevel::Bits3p5),
        other => Err(failure(format!(
            "unsupported FSV bits_per_channel_x2 {other}"
        ))),
    }
}

fn expected_data_bits(dim: usize, bits_per_channel_x2: u8) -> AnyResult<usize> {
    dim.checked_mul(bits_per_channel_x2 as usize)
        .and_then(|twice| twice.checked_add(1))
        .map(|twice| twice / 2)
        .ok_or_else(|| failure("expected TurboQuant data-bit count overflow"))
}

fn expected_payload_bytes(dim: usize, bits_per_channel_x2: u8) -> AnyResult<usize> {
    let data_bits = expected_data_bits(dim, bits_per_channel_x2)?;
    let scalar_bits = data_bits
        .checked_sub(dim)
        .ok_or_else(|| failure("expected TurboQuant scalar bit count underflow"))?;
    TURBOQUANT_FORMAT_HEADER_BYTES
        .checked_add(scalar_bits.div_ceil(8))
        .and_then(|bytes| bytes.checked_add(dim.div_ceil(8)))
        .ok_or_else(|| failure("expected TurboQuant payload byte count overflow"))
}

fn cosine(left: &[f32], right: &[f32]) -> AnyResult<f64> {
    require(left.len() == right.len(), "cosine dimension mismatch")?;
    let mut dot = 0.0_f64;
    let mut left_norm = 0.0_f64;
    let mut right_norm = 0.0_f64;
    for (&left, &right) in left.iter().zip(right) {
        let left = f64::from(left);
        let right = f64::from(right);
        dot += left * right;
        left_norm += left * left;
        right_norm += right * right;
    }
    require(
        left_norm > 0.0 && right_norm > 0.0,
        "cosine requires non-zero vectors",
    )?;
    Ok(dot / (left_norm.sqrt() * right_norm.sqrt()))
}

fn rmse(left: &[f32], right: &[f32]) -> AnyResult<f64> {
    require(left.len() == right.len(), "RMSE dimension mismatch")?;
    let mse = left
        .iter()
        .zip(right)
        .map(|(&left, &right)| {
            let delta = f64::from(left) - f64::from(right);
            delta * delta
        })
        .sum::<f64>()
        / left.len() as f64;
    Ok(mse.sqrt())
}

fn physical_digest(root: &Path) -> AnyResult<PhysicalDigest> {
    let mut files = Vec::new();
    collect_files(root, &mut files)?;
    files.sort();
    let mut hasher = Sha256::new();
    let mut bytes = 0_u64;
    for path in &files {
        let relative = path.strip_prefix(root)?;
        let relative = relative.to_string_lossy().replace('\\', "/");
        let data = fs::read(path)?;
        bytes = bytes
            .checked_add(data.len() as u64)
            .ok_or_else(|| failure("physical vault byte count overflow"))?;
        hasher.update((relative.len() as u64).to_be_bytes());
        hasher.update(relative.as_bytes());
        hasher.update((data.len() as u64).to_be_bytes());
        hasher.update(&data);
    }
    Ok(PhysicalDigest {
        files: files.len(),
        bytes,
        sha256: hex(&hasher.finalize()),
    })
}

fn collect_files(root: &Path, files: &mut Vec<PathBuf>) -> AnyResult<()> {
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_files(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn copy_tree(source: &Path, destination: &Path) -> AnyResult<()> {
    require(!destination.exists(), "copy destination already exists")?;
    fs::create_dir_all(destination)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_tree(&source_path, &destination_path)?;
        } else if source_path.is_file() {
            fs::copy(source_path, destination_path)?;
        }
    }
    Ok(())
}

fn ensure_fixture_boundary(workspace: &Path, root: &Path) -> AnyResult<()> {
    let target = workspace.join("target");
    require(
        root.starts_with(&target),
        "FSV fixture root escaped workspace target",
    )
}

fn cx_id_from_key(key: &[u8]) -> AnyResult<CxId> {
    let bytes: [u8; 16] = key
        .try_into()
        .map_err(|_| failure(format!("slot key has {} bytes, expected 16", key.len())))?;
    Ok(CxId::from_bytes(bytes))
}

fn decode_hex(value: &str) -> AnyResult<Vec<u8>> {
    require(
        value.len() % 2 == 0,
        format!("hex input has odd length {}", value.len()),
    )?;
    (0..value.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&value[offset..offset + 2], 16).map_err(|error| {
                failure(format!(
                    "invalid hexadecimal byte at character offset {offset}: {error}"
                ))
            })
        })
        .collect()
}

fn decode_hex_32(value: &str) -> AnyResult<[u8; 32]> {
    require(value.len() == 64, "seed id hex length is not 64")?;
    let mut bytes = [0_u8; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|error| failure(format!("invalid seed id hex at byte {index}: {error}")))?;
    }
    Ok(bytes)
}

fn digest_rows(rows: &[(Vec<u8>, Vec<u8>)]) -> String {
    let map = rows.iter().cloned().collect::<BTreeMap<_, _>>();
    digest_map(&map)
}

fn digest_keyset(keys: &BTreeSet<Vec<u8>>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"issue551-compression-fsv-keyset-v1");
    for key in keys {
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(key);
    }
    hex(&hasher.finalize())
}

fn digest_map(rows: &BTreeMap<Vec<u8>, Vec<u8>>) -> String {
    let mut hasher = Sha256::new();
    for (key, value) in rows {
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(key);
        hasher.update((value.len() as u64).to_be_bytes());
        hasher.update(value);
    }
    hex(&hasher.finalize())
}

fn value_bytes(rows: &[(Vec<u8>, Vec<u8>)]) -> usize {
    rows.iter().map(|(_, value)| value.len()).sum()
}

fn sha256_array(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn sha256_file(path: &Path) -> AnyResult<String> {
    Ok(sha256_hex(&fs::read(path)?))
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn throughput(items: usize, elapsed: Duration) -> f64 {
    if elapsed.is_zero() {
        return f64::INFINITY;
    }
    items as f64 / elapsed.as_secs_f64()
}

fn physical_json(digest: &PhysicalDigest) -> Value {
    json!({
        "files": digest.files,
        "bytes": digest.bytes,
        "sha256": digest.sha256,
    })
}

fn calyx_error_json(error: &calyx_core::CalyxError) -> Value {
    json!({
        "code": error.code,
        "message": error.message,
        "remediation": error.remediation,
    })
}

fn forge_error_json(error: &calyx_forge::ForgeError) -> Value {
    json!({
        "code": error.code(),
        "message": error.to_string(),
    })
}

fn expect_calyx_error<T>(result: calyx_core::Result<T>) -> AnyResult<calyx_core::CalyxError> {
    result
        .map(|_| ())
        .err()
        .ok_or_else(|| failure("operation unexpectedly succeeded"))
}

fn expect_forge_error<T>(result: calyx_forge::Result<T>) -> AnyResult<calyx_forge::ForgeError> {
    result
        .map(|_| ())
        .err()
        .ok_or_else(|| failure("Forge operation unexpectedly succeeded"))
}

fn require(condition: bool, message: impl Into<String>) -> AnyResult<()> {
    if condition {
        return Ok(());
    }
    Err(failure(message))
}

fn failure(message: impl Into<String>) -> Box<dyn Error> {
    Box::new(FsvFailure {
        code: "ASTRO_FSV_INVARIANT_FAILED",
        message: message.into(),
        remediation: "inspect the emitted before/after source-of-truth state and fix the production path before rerunning FSV",
    })
}

fn log(value: Value) {
    println!("{value}");
}
