use super::*;
pub(crate) const KERNEL_CONTEXT_SCHEMA: &str = "astrolabe.kernel_context.v1";
pub(crate) const SCOPE_SUMMARY_COLLECTION_SCHEMA: &str = "astrolabe.scope_summary_collection.v1";

/// Schema tag for the index-time persisted-kernel-artifact summary surfaced on the
/// shadow import outcome (#365).
pub(crate) const KERNEL_ARTIFACT_PERSIST_SCHEMA: &str =
    "astrolabe.complete_kernel_generation_persist.v1";

/// Stable fault returned when any stage of the kernel generation fails.
///
/// A kernel artifact and its member index are one serving contract.  Publishing
/// an `unavailable` summary after either half failed allowed the enclosing shadow
/// transaction to continue and made an incomplete generation look intentional.
/// Every failure now escapes as this typed fault, so shadow publication preserves
/// the prior live generation and `get_kernel mode="build"` returns an actionable
/// MCP error instead of a degraded success value.
pub(crate) const ASTRO_KERNEL_GENERATION_FAILED: &str = "ASTRO_KERNEL_GENERATION_FAILED";
/// A shadow-published project has no readable persisted kernel-context row.
pub(crate) const ASTRO_KERNEL_CONTEXT_METADATA_MISSING: &str =
    "ASTRO_KERNEL_CONTEXT_METADATA_MISSING";
/// The persisted kernel-context row is not the exact current schema/shape.
pub(crate) const ASTRO_KERNEL_CONTEXT_METADATA_INVALID: &str =
    "ASTRO_KERNEL_CONTEXT_METADATA_INVALID";

/// The stable scope identity a shadow-imported project's whole-repo kernel is
/// persisted and served under (#365). One serializer for the index-time persist
/// hook and every serve-time readback so the artifact key never diverges.
pub(crate) fn kernel_artifact_scope_id(project: &str) -> String {
    format!("repo:{project}")
}

fn stable_identity_by_cx<C>(
    vault: &AsterVault<C>,
    project: &str,
) -> Result<BTreeMap<String, (String, String)>, DynError>
where
    C: Clock,
{
    let snapshot = astrolabe_ingest::read_cbm_graph_snapshot(vault, project)?;
    let mut identity_by_cx = BTreeMap::new();
    let mut seen_atoms = BTreeSet::new();
    for node in snapshot.nodes {
        let Some(cx_id) = node.cx_id else {
            continue;
        };
        if node.atom_id.trim().is_empty() {
            return Err(format!(
                "ASTRO_KERNEL_IDENTITY_MISSING: CxId {cx_id} has no stable source atom (qualified_name={:?})",
                node.qualified_name
            )
            .into());
        }
        if !seen_atoms.insert(node.atom_id.clone()) {
            return Err(format!(
                "ASTRO_KERNEL_IDENTITY_DUPLICATE_ATOM: stable source atom {} maps to multiple CxIds",
                node.atom_id
            )
            .into());
        }
        if identity_by_cx
            .insert(
                cx_id.to_string(),
                (node.atom_id.clone(), node.qualified_name.clone()),
            )
            .is_some()
        {
            return Err(format!(
                "ASTRO_KERNEL_IDENTITY_DUPLICATE_CX: CxId {cx_id} maps to multiple source atoms"
            )
            .into());
        }
    }
    if identity_by_cx.is_empty() {
        return Err(format!(
            "ASTRO_KERNEL_IDENTITY_EMPTY: project {project:?} has no CxId-to-atom identity rows"
        )
        .into());
    }
    Ok(identity_by_cx)
}

/// Index-time hook (#365/#1148): prepares the real artifact, universal S20 member
/// HNSW, external-query corpus, and graph-routed admission report from one
/// retained snapshot. Shadow import may persist the derived label graph from
/// these exact prepared bytes before a final source-revalidated publication.
///
/// The artifact and member index are mandatory parts of a successful shadow
/// generation.  Any source, build, readback, vector-coverage, or persistence
/// failure aborts the caller with a typed stage-specific fault; it is never
/// converted into an `unavailable` success value.  During shadow indexing that
/// refusal occurs inside the private staged vault, so the prior live generation
/// remains the source of truth.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KernelAdmissionContract {
    /// An explicit real-query corpus is mandatory. Used by an operator-requested
    /// `get_kernel mode="build"`; an older corpus is never silently inherited.
    ExplicitRequired,
    /// An explicit corpus replaces the current one, while omission may reuse
    /// only the byte-validated corpus of the current complete generation. Used
    /// by shadow reindex so an unchanged operator corpus survives source refresh.
    ReuseCurrentExact,
}

/// Complete kernel bytes selected by the publisher's independent current-pointer
/// readback and reused by later index-time consumers without reopening legacy
/// fixed aliases or repeating the HNSW/corpus scan.
pub(crate) struct IndexTimeKernelPublication {
    pub(crate) receipt: Value,
    pub(crate) artifact: astrolabe_kernel::KernelArtifact,
}

/// Mutation-free kernel preparation retained across the label-graph write.
/// The expensive `N/E`, HNSW, and real-query evaluation work occurs exactly
/// once; final publication revalidates its narrow source identities at the
/// post-label sequence before committing any kernel generation row.
pub(crate) struct PreparedIndexTimeKernel {
    scope_id: String,
    prepared_seq: Seq,
    anchors_content_generation: Seq,
    anchor_trust: BTreeMap<CxId, astrolabe_anchors::TrustTag>,
    projection_manifest: astrolabe_ingest::GraphProjectionManifestIdentity,
    trusted_anchor_count: usize,
    query_corpus_reused: bool,
    artifact: astrolabe_kernel::KernelArtifact,
    projection: astrolabe_ingest::GraphProjectionCsr,
    graph: astrolabe_kernel::KernelGraph,
    member_index: astrolabe_weave::KernelMemberIndex,
    complete_vectors: BTreeMap<CxId, Vec<f32>>,
    query_corpus: astrolabe_weave::KernelRecallQueryCorpus,
    graph_routed_report: astrolabe_kernel::GraphRoutedRecallReport,
}

impl PreparedIndexTimeKernel {
    pub(crate) fn artifact(&self) -> &astrolabe_kernel::KernelArtifact {
        &self.artifact
    }

    pub(crate) fn projection(&self) -> &astrolabe_ingest::GraphProjectionCsr {
        &self.projection
    }
}

pub(crate) fn prepare_index_time_kernel_artifact<C>(
    vault: &AsterVault<C>,
    vault_dir: &Path,
    project: &str,
    admission: Option<&KernelAdmissionRequest>,
    admission_contract: KernelAdmissionContract,
) -> Result<PreparedIndexTimeKernel, DynError>
where
    C: Clock,
{
    let scope_id = kernel_artifact_scope_id(project);
    // #1064 PC-03/04/07/14/15/28/35/37/38/41/43: one retained snapshot owns
    // the entire mutation-free preparation. Against measured production
    // N=192,873, E=328,899 this path costs O(N+E)+O(N*D)+O(K*D)+O(Q*N*D).
    // base_seq, graph/source identity, the ascending full S20 roster, and the
    // external-query roster remain invariant until all eight rows are ready.
    // Final prepublication performs point-bound identities plus O(B+K*D+Q*D)
    // serialization. Its existing independent FSV re-reads the persisted CSR
    // once in O(N+E), but it never repeats kernel construction, HNSW K*D, or
    // graph-routed Q*N*D after label propagation (PC-03/04/07/16/38/41/43).
    let source_lease = vault.retain_latest_snapshot();
    let base_seq = source_lease.seq();
    let anchor_trust = astrolabe_anchors::effective_anchor_trust_map_at(vault, base_seq).map_err(
        |error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "anchor_trust",
            Some(error.code),
            error.message,
            Some(error.remediation),
            "repair the persisted Anchors and their ledger pairing, then rebuild the unchanged shadow generation",
        )
    },
    )?;
    let trusted_anchor_count = anchor_trust
        .values()
        .filter(|tag| matches!(tag, astrolabe_anchors::TrustTag::Trusted))
        .count();
    source_lease.record_progress();

    let projection = astrolabe_ingest::read_graph_projection_csr_at(
        vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        base_seq,
    )
    .map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "projection_read",
            error.code(),
            error.message(),
            error.remediation(),
            "repair and materialize the composite KernelGraph projection before requesting a kernel generation; this path never rebuilds a missing projection implicitly",
        )
    })?
    .ok_or_else(|| {
        kernel_generation_fault(
            project,
            &scope_id,
            "projection_read",
            None,
            format!(
                "the composite KernelGraph projection is absent at retained sequence {base_seq}"
            ),
            None,
            "materialize the complete typed-plus-similarity KernelGraph projection during shadow indexing, then retry the unchanged generation",
        )
    })?;
    let anchors_content_generation = vault.cf_content_generation(ColumnFamily::Anchors)?;
    let projection_manifest = astrolabe_ingest::read_graph_projection_manifest_identity_at(
        vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        base_seq,
    )?
    .ok_or_else(|| {
        kernel_generation_fault(
            project,
            &scope_id,
            "projection_manifest_read",
            None,
            "the current KernelGraph projection has no point-readable manifest identity",
            None,
            "materialize the complete KernelGraph projection before preparing the kernel generation",
        )
    })?;
    let graph = astrolabe_ingest::kernel_graph_from_projection_csr(&projection, &anchor_trust)
        .map_err(|error| {
            kernel_generation_fault(
                project,
                &scope_id,
                "graph_adapter",
                error.code(),
                error.message(),
                error.remediation(),
                "repair the retained composite projection or anchor roster and restart generation from one exact snapshot",
            )
        })?;
    let config = astrolabe_kernel::KernelBuildConfig::with_registry_defaults();
    let artifact = astrolabe_kernel::build_kernel(&graph, &scope_id, &config).map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "artifact_build",
            Some(error.code()),
            error.message(),
            error.remediation(),
            "repair the graph, anchor inputs, full-graph FVS proof, or compactness refusal named by the underlying error, then rebuild the unchanged generation",
        )
    })?;
    source_lease.record_progress();

    let member_ids = artifact
        .members
        .iter()
        .map(|member| member.id)
        .collect::<Vec<_>>();
    if member_ids.is_empty() || !member_ids.windows(2).all(|pair| pair[0] < pair[1]) {
        return Err(kernel_generation_fault(
            project,
            &scope_id,
            "artifact_member_roster",
            None,
            format!(
                "kernel member roster must be nonempty and strictly ascending, observed {} member(s)",
                member_ids.len()
            ),
            None,
            "repair deterministic kernel member selection before any index or generation row is prepared",
        ));
    }
    let member_index = astrolabe_weave::build_kernel_member_index_at(
        vault,
        vault_dir,
        project,
        &member_ids,
        &artifact.members_hash,
        astrolabe_weave::search_index::IndexKnobs::defaults(0x4B45_524E_454C_0001),
        base_seq,
    )
    .map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "member_index_build",
            Some(error.code()),
            error.message().to_string(),
            Some(error.remediation()),
            "materialize one valid universal S20 name-semantic vector for every kernel member at one bound Slot/Compression generation, then rebuild the unchanged generation",
        )
    })?;
    source_lease.record_progress();

    let mut graph_node_ids = graph.nodes().iter().map(|node| node.id).collect::<Vec<_>>();
    graph_node_ids.sort_unstable();
    if graph_node_ids.is_empty()
        || !graph_node_ids.windows(2).all(|pair| pair[0] < pair[1])
        || graph_node_ids.len() != artifact.source_identity.node_count
    {
        return Err(kernel_generation_fault(
            project,
            &scope_id,
            "graph_vector_roster",
            None,
            format!(
                "full graph identity roster is invalid: observed_count={}, source_identity_count={}, strict_order={}",
                graph_node_ids.len(),
                artifact.source_identity.node_count,
                graph_node_ids.windows(2).all(|pair| pair[0] < pair[1])
            ),
            None,
            "repair graph identity canonicalization before graph-routed admission; no subset vector roster is accepted",
        ));
    }
    let semantic_dim = member_index.semantic_dim.ok_or_else(|| {
        kernel_generation_fault(
            project,
            &scope_id,
            "member_index_dimension",
            None,
            "the complete S20 member index established no semantic dimension",
            None,
            "repair the universal S20 source and rebuild the complete member index",
        )
    })?;
    let complete_vectors = astrolabe_weave::read_complete_kernel_s20_vectors_at(
        vault,
        vault_dir,
        member_index.panel_version,
        &graph_node_ids,
        &member_index.source_binding,
        semantic_dim,
        base_seq,
    )
    .map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "complete_s20_roster",
            Some(error.code()),
            error.message().to_string(),
            Some(error.remediation()),
            "materialize one valid universal S20 name-semantic vector for every KernelGraph node, then restart generation from one exact snapshot",
        )
    })?;
    source_lease.record_progress();

    let (query_corpus, query_corpus_reused) = match admission {
        Some(admission) => (
            astrolabe_weave::build_kernel_recall_query_corpus(
                project,
                &scope_id,
                member_index.panel_version,
                &admission.queries,
                admission.params.clone(),
            )
            .map_err(|error| {
                kernel_generation_fault(
                    project,
                    &scope_id,
                    "query_corpus_build",
                    Some(error.code()),
                    error.message().to_string(),
                    Some(error.remediation()),
                    "supply independently authored, nonempty real queries and the exact complete S20 graph-routed admission controls",
                )
            })?,
            false,
        ),
        None if admission_contract == KernelAdmissionContract::ReuseCurrentExact => {
            let current =
                astrolabe_weave::read_current_kernel_generation(vault, project, &scope_id)
            .map_err(|error| {
                kernel_generation_fault(
                    project,
                    &scope_id,
                    "query_corpus_reuse_read",
                    Some(error.code()),
                    error.message().to_string(),
                    Some(error.remediation()),
                    "repair the current complete generation or supply an explicit real kernel_admission corpus; corrupt current state is never bypassed",
                )
            })?
            .ok_or_else(|| {
                kernel_generation_fault(
                    project,
                    &scope_id,
                    "query_corpus_required",
                    Some(astrolabe_weave::ASTRO_KERNEL_ADMISSION_REQUIRED),
                    "no current complete kernel generation exists from which an exact real-query corpus can be reused",
                    Some("supply kernel_admission with real external queries and every explicit graph-routed work/admission control"),
                    "supply kernel_admission with real external queries and every explicit graph-routed work/admission control",
                )
            })?;
            astrolabe_weave::validate_kernel_recall_query_corpus_encoder(&current.query_corpus)
                .map_err(|error| {
                    kernel_generation_fault(
                        project,
                        &scope_id,
                        "query_corpus_reuse_validate",
                        Some(error.code()),
                        error.message().to_string(),
                        Some(error.remediation()),
                        "supply a new explicit real kernel_admission corpus encoded by the current production S20 contract",
                    )
                })?;
            (current.query_corpus, true)
        }
        None => {
            return Err(kernel_generation_fault(
                project,
                &scope_id,
                "query_corpus_required",
                Some(astrolabe_weave::ASTRO_KERNEL_ADMISSION_REQUIRED),
                "this explicit kernel build omitted kernel_admission",
                Some("supply kernel_admission with real external queries and every explicit graph-routed work/admission control"),
                "supply kernel_admission with real external queries and every explicit graph-routed work/admission control",
            ));
        }
    };
    let graph_queries = query_corpus.graph_routed_queries();
    let graph_routed_report = astrolabe_kernel::evaluate_graph_routed_recall(
        &graph,
        &artifact,
        &complete_vectors,
        &graph_queries,
        &query_corpus.params,
    )
    .map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "graph_routed_admission",
            Some(error.code()),
            error.message(),
            error.remediation(),
            "repair the named S20/query/route identity or explicit work/recall/compactness control; failed admission publishes no generation",
        )
    })?;
    if vault.latest_seq() != base_seq {
        return Err(kernel_generation_fault(
            project,
            &scope_id,
            "prepublication_source_check",
            None,
            format!(
                "vault moved from retained generation {base_seq} to {} during preparation",
                vault.latest_seq()
            ),
            None,
            "discard every prepared byte and restart from one fresh retained snapshot",
        ));
    }
    drop(source_lease);

    Ok(PreparedIndexTimeKernel {
        scope_id,
        prepared_seq: base_seq,
        anchors_content_generation,
        anchor_trust,
        projection_manifest,
        trusted_anchor_count,
        query_corpus_reused,
        artifact,
        projection,
        graph,
        member_index,
        complete_vectors,
        query_corpus,
        graph_routed_report,
    })
}

pub(crate) fn persist_prepared_index_time_kernel_artifact<C>(
    vault: &AsterVault<C>,
    project: &str,
    prepared: PreparedIndexTimeKernel,
) -> Result<IndexTimeKernelPublication, DynError>
where
    C: Clock,
{
    let PreparedIndexTimeKernel {
        scope_id,
        prepared_seq,
        anchors_content_generation,
        anchor_trust,
        projection_manifest,
        trusted_anchor_count,
        query_corpus_reused,
        artifact,
        projection,
        graph,
        member_index,
        complete_vectors,
        query_corpus,
        graph_routed_report,
    } = prepared;
    let expected_scope_id = kernel_artifact_scope_id(project);
    if scope_id != expected_scope_id {
        return Err(kernel_generation_fault(
            project,
            &expected_scope_id,
            "prepared_scope_join",
            None,
            format!(
                "prepared kernel scope {scope_id:?} differs from project scope {expected_scope_id:?}"
            ),
            None,
            "discard the prepared bytes and restart preparation for the exact project",
        ));
    }
    let publication_lease = vault.retain_latest_snapshot();
    let base_seq = publication_lease.seq();
    let current_anchors = vault.cf_content_generation(ColumnFamily::Anchors)?;
    let current_anchor_trust = astrolabe_anchors::effective_anchor_trust_map_at(vault, base_seq)
        .map_err(|error| {
            kernel_generation_fault(
                project,
                &scope_id,
                "prepared_anchor_revalidation",
                Some(error.code),
                error.message,
                Some(error.remediation),
                "repair the exact anchor/promotion rows before final kernel publication",
            )
        })?;
    let current_projection = astrolabe_ingest::read_graph_projection_manifest_identity_at(
        vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        base_seq,
    )?
    .ok_or_else(|| {
        kernel_generation_fault(
            project,
            &scope_id,
            "prepared_projection_revalidation",
            None,
            "the prepared KernelGraph projection manifest disappeared before publication",
            None,
            "discard the prepared bytes and restart from one complete projection generation",
        )
    })?;
    if current_anchors != anchors_content_generation
        || current_anchor_trust != anchor_trust
        || current_projection != projection_manifest
    {
        return Err(kernel_generation_fault(
            project,
            &scope_id,
            "prepared_source_revalidation",
            None,
            format!(
                "kernel preparation source changed before final publication: prepared_seq={prepared_seq} publication_seq={base_seq} anchors={anchors_content_generation}->{current_anchors} anchor_trust_equal={} projection_equal={}",
                current_anchor_trust == anchor_trust,
                current_projection == projection_manifest,
            ),
            None,
            "discard every prepared byte and rebuild from the current anchors/projection/S20 generation",
        ));
    }
    publication_lease.record_progress();
    drop(publication_lease);

    let report = astrolabe_weave::persist_complete_kernel_generation(
        vault,
        astrolabe_weave::KernelGenerationPublishRequest {
            project,
            scope_id: &scope_id,
            artifact: &artifact,
            index: &member_index,
            query_corpus: &query_corpus,
            graph_routed_report: &graph_routed_report,
            graph: &graph,
            complete_vectors: &complete_vectors,
            base_seq,
        },
    )
    .map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "atomic_generation_persist",
            Some(error.code()),
            error.message().to_string(),
            Some(error.remediation()),
            "repair the named atomic publication, Ledger, pointer, manifest, retention, or physical-readback mismatch, then rebuild from one unchanged source generation",
        )
    })?;

    // Do not trust the publisher's return value. Resolve the fixed current
    // pointer again, decode every content-addressed row and alias, reload the
    // HNSW, recompute the query encoder, source identity, and graph-routed report,
    // and require exact equality with the staged generation.
    let readback_lease = vault.retain_latest_snapshot();
    let readback_seq = readback_lease.seq();
    let current = astrolabe_weave::read_current_kernel_generation(vault, project, &scope_id)
        .map_err(|error| {
            kernel_generation_fault(
                project,
                &scope_id,
                "complete_generation_readback",
                Some(error.code()),
                error.message().to_string(),
                Some(error.remediation()),
                "repair the current pointer or any bound generation row and rebuild; no legacy artifact/index aliases are served as a substitute",
            )
        })?
        .ok_or_else(|| {
            kernel_generation_fault(
                project,
                &scope_id,
                "complete_generation_readback",
                None,
                "the current complete kernel generation was absent immediately after publication",
                None,
                "repair the atomic pointer publication path and rebuild the unchanged generation",
            )
        })?;
    if current.artifact != artifact
        || current.index.descriptor != report.descriptor
        || current.index.bindings != member_index.member_bindings
        || current.query_corpus != query_corpus
        || current.graph_routed_report != graph_routed_report
        || current.manifest != report.manifest
        || current.pointer != report.pointer
    {
        return Err(kernel_generation_fault(
            project,
            &scope_id,
            "complete_generation_equality",
            None,
            format!(
                "current generation {:?} differs from the staged/publisher-bound artifact, index, query corpus, report, manifest, or pointer",
                current.manifest.generation_id
            ),
            None,
            "preserve the vault and repair atomic complete-generation serialization/readback before retrying",
        ));
    }
    astrolabe_weave::validate_kernel_recall_query_corpus_encoder(&current.query_corpus).map_err(
        |error| {
            kernel_generation_fault(
                project,
                &scope_id,
                "query_encoder_readback",
                Some(error.code()),
                error.message().to_string(),
                Some(error.remediation()),
                "repair the persisted query corpus or production S20 encoder identity and rebuild the generation",
            )
        },
    )?;
    let current_projection = astrolabe_ingest::read_graph_projection_csr_bound_at(
        vault,
        astrolabe_ingest::GraphProjectionKind::KernelGraph,
        readback_seq,
        &astrolabe_ingest::GraphProjectionReadBinding {
            graph_content_generation: current
                .manifest
                .generation_source_binding
                .graph_content_generation,
            manifest: current
                .manifest
                .generation_source_binding
                .projection_manifest
                .clone(),
        },
    )
    .map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "source_identity_readback",
            error.code(),
            error.message(),
            error.remediation(),
            "repair the persisted composite graph projection and rebuild the unchanged shadow generation",
        )
    })?;
    if current_projection != projection {
        return Err(kernel_generation_fault(
            project,
            &scope_id,
            "prepared_projection_equality",
            None,
            "the post-label point-bound KernelGraph CSR differs from the prepared CSR",
            None,
            "discard the prepared artifact and rebuild from the changed projection; no stale prepared graph is published",
        ));
    }
    let bounded_source_readback = bounded_kernel_source_evidence(
        &current_projection,
        &current.artifact,
        &current.manifest,
        readback_seq,
    )
    .map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "source_binding_readback",
            None,
            error.to_string(),
            None,
            "repair the exact generation source binding and rebuild the unchanged shadow generation",
        )
    })?;
    let readback_anchor_trust =
        astrolabe_anchors::effective_anchor_trust_map_at(vault, readback_seq).map_err(|error| {
            kernel_generation_fault(
                project,
                &scope_id,
                "source_anchor_readback",
                Some(error.code),
                error.message,
                Some(error.remediation),
                "repair the physical anchor/promotion rows and rebuild the complete generation",
            )
        })?;
    let readback_graph = astrolabe_ingest::kernel_graph_from_projection_csr(
        &current_projection,
        &readback_anchor_trust,
    )
    .map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "source_graph_readback",
            error.code(),
            error.message(),
            error.remediation(),
            "repair the physical composite projection rows and rebuild the complete generation",
        )
    })?;
    astrolabe_kernel::verify_kernel_source_projection_identity(
        &readback_graph,
        &current.artifact.config,
        &current.artifact.source_identity,
    )
    .map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "source_projection_identity_readback",
            Some(error.code()),
            error.message(),
            error.remediation(),
            "rebuild from one exact graph/config identity; no stale projection identity is admitted",
        )
    })?;
    let observed_source_identity =
        astrolabe_kernel::kernel_source_identity(&readback_graph, &current.artifact.config)
            .map_err(|error| {
                kernel_generation_fault(
                    project,
                    &scope_id,
                    "source_identity_readback",
                    Some(error.code()),
                    error.message(),
                    error.remediation(),
                    "repair the physical graph/anchor rows and rebuild the complete generation",
                )
            })?;
    if observed_source_identity != current.artifact.source_identity {
        return Err(kernel_generation_fault(
            project,
            &scope_id,
            "source_identity_readback",
            Some(ASTRO_KERNEL_SOURCE_IDENTITY_STALE),
            format!(
                "recomputed source identity {} differs from persisted {}",
                observed_source_identity.combined_hash,
                current.artifact.source_identity.combined_hash,
            ),
            Some("rebuild the complete generation from the exact current graph and anchor roster"),
            "preserve the mismatched generation and repair source identity construction before retrying",
        ));
    }
    let source_readback = json!({
        "schema": "astrolabe.kernel_source_publication_readback.v1",
        "bounded_source": bounded_source_readback,
        "recomputed_source_identity": observed_source_identity,
        "verified": true,
    });
    let readback_queries = current.query_corpus.graph_routed_queries();
    astrolabe_kernel::validate_graph_routed_recall_report(
        &current.graph_routed_report,
        &readback_graph,
        &current.artifact,
        &complete_vectors,
        &readback_queries,
        &current.query_corpus.params,
    )
    .map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "graph_routed_report_readback",
            Some(error.code()),
            error.message(),
            error.remediation(),
            "repair the persisted corpus/report or their exact graph/S20 source identity and rebuild the complete generation",
        )
    })?;
    if vault.latest_seq() != readback_seq {
        return Err(kernel_generation_fault(
            project,
            &scope_id,
            "complete_generation_readback_stability",
            None,
            format!(
                "vault moved from retained readback sequence {readback_seq} to {}",
                vault.latest_seq()
            ),
            None,
            "discard the readback claim and retry generation against one stable current state",
        ));
    }
    drop(readback_lease);
    let receipt = json!({
        "schema": KERNEL_ARTIFACT_PERSIST_SCHEMA,
        "status": "persisted",
        "published": report.published,
        "preparation": {
            "prepared_seq": prepared_seq,
            "publication_base_seq": base_seq,
            "expensive_graph_hnsw_query_passes": 1,
            "postpublication_projection_fsv_readbacks": 1,
            "post_prepare_mutation": "label graph plus Oracle-owned Kv corpus; exact projection/S20/effective-Anchor identities revalidated before final publication",
        },
        "scope_id": &current.artifact.scope_id,
        "generation_id": &current.manifest.generation_id,
        "source_generation_identity": &current.manifest.source_generation_identity,
        "members_hash": &current.artifact.members_hash,
        "member_count": current.artifact.member_count,
        "node_count": current.artifact.node_count,
        "graph_coverage": &current.artifact.graph_coverage,
        "compactness": &current.artifact.compactness,
        "fvs_validity": &current.artifact.fvs_validity,
        "anchor_grounded": current.artifact.anchor_grounded,
        "source_identity": &current.artifact.source_identity,
        "source_identity_readback": source_readback,
        "trusted_anchor_count": trusted_anchor_count,
        "rows_readback_verified": report.rows_readback_verified,
        "readback_rows": &report.readback_rows,
        "decoded_rows_verified": current.rows_verified,
        "ledger_paired": true,
        "commit_seq": report.commit_seq,
        "ledger_ref": {
            "seq": report.ledger_ref.seq,
            "entry_hash": hex_lower(&report.ledger_ref.hash),
        },
        "ledger_physical_tiers": report.ledger_physical_tiers,
        "manifest": &current.manifest,
        "pointer": &current.pointer,
        "retired_generation_id": &report.retired_generation_id,
        "query_admission": {
            "corpus_reused": query_corpus_reused,
            "corpus": &current.query_corpus,
            "graph_routed_report": &current.graph_routed_report,
        },
        "member_index": {
            "descriptor": &current.index.descriptor,
            "binding_count": current.index.bindings.len(),
        },
        "flush": {
            "sst_files": report.flush_sst_files,
            "sst_entries": report.flush_sst_entries,
            "sst_bytes": report.flush_sst_bytes,
        },
        "trust": &current.artifact.trust,
        "freshness": "fresh",
        "provenance": [
            format!("kernel-generation:{}", report.generation_id),
            "vault:ColumnFamily::Kernel+Ledger atomic pointer publication".to_string(),
            "anchors:effective_anchor_trust_map_at(retained_snapshot)".to_string(),
            "slot:S20 name_semantic complete KernelGraph roster".to_string(),
            "astrolabe-kernel:graph_routed_recall(real_external_queries)".to_string(),
        ],
    });
    Ok(IndexTimeKernelPublication {
        receipt,
        artifact: current.artifact,
    })
}

pub(crate) fn persist_index_time_kernel_artifact<C>(
    vault: &AsterVault<C>,
    vault_dir: &Path,
    project: &str,
    admission: Option<&KernelAdmissionRequest>,
    admission_contract: KernelAdmissionContract,
) -> Result<IndexTimeKernelPublication, DynError>
where
    C: Clock,
{
    let prepared = prepare_index_time_kernel_artifact(
        vault,
        vault_dir,
        project,
        admission,
        admission_contract,
    )?;
    persist_prepared_index_time_kernel_artifact(vault, project, prepared)
}

pub(crate) fn kernel_generation_fault(
    project: &str,
    scope_id: &str,
    stage: &str,
    underlying_code: Option<&str>,
    underlying_message: impl Into<String>,
    underlying_remediation: Option<&str>,
    remediation: &str,
) -> DynError {
    Box::new(
        ToolFault::new(
            ASTRO_KERNEL_GENERATION_FAILED,
            format!(
                "kernel generation for project {project:?} scope {scope_id:?} failed during {stage}"
            ),
            remediation,
        )
        .with_detail("project", project)
        .with_detail("scope_id", scope_id)
        .with_detail("failed_stage", stage)
        .with_detail("underlying_code", json!(underlying_code))
        .with_detail("underlying_message", underlying_message.into())
        .with_detail("underlying_remediation", json!(underlying_remediation)),
    )
}

/// #390 index-time hook (lane E): the grounded-label **seed producer** + live
/// propagation, run against real persisted data.
///
/// The served `kernel_context.label_propagation` was computed from the CBM
/// row-sink node properties (`label_seeds`/`grounded_labels`), which a real
/// corpus like `cbm/` never emits — so it always starved to `zero_seed_scope`.
/// This derives grounded seeds from data that genuinely exists after an index:
///
/// 1. the persisted `KernelArtifact` members (persisted immediately above by
///    [`persist_index_time_kernel_artifact`]) — the measured kernel core, each a
///    grounded, provenance-carrying seed of the `kernel-core` label; and
/// 2. any persisted `AnchorKind::Label(..)` anchors — genuine grounded labels
///    (the blueprint 5.9 / P7 source), folded in as caller seeds.
///
/// The ingest producer persists the seed graph and runs live propagation over
/// the persisted association graph (both ledger-paired and readback-verified),
/// then this reads the persisted propagated-label rows back **independently** and
/// builds the label_propagation block from those bytes. The complete composite
/// artifact/projection is mandatory. Any anchor read, source-identity,
/// propagation, persisted-row, or identity-join failure aborts the staged
/// publication; no `unavailable` substitute is emitted.
pub(crate) fn persist_index_time_label_propagation<C>(
    vault: &AsterVault<C>,
    project: &str,
    artifact: &astrolabe_kernel::KernelArtifact,
    projection: &astrolabe_ingest::GraphProjectionCsr,
) -> Result<Value, DynError>
where
    C: Clock,
{
    let scope_id = kernel_artifact_scope_id(project);
    let extra_seeds = label_anchor_seeds(vault).map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "label_anchor_read",
            None,
            error.to_string(),
            None,
            "repair the exact persisted anchor rows before rebuilding label propagation",
        )
    })?;
    let projection_nodes = projection
        .nodes
        .iter()
        .map(|node| node.id.to_string())
        .collect::<BTreeSet<_>>();
    if let Some(stale) = extra_seeds
        .iter()
        .find(|seed| !projection_nodes.contains(&seed.symbol_id))
    {
        return Err(kernel_generation_fault(
            project,
            &scope_id,
            "label_anchor_projection_binding",
            Some("ASTRO_KERNEL_LABEL_ANCHOR_SOURCE_INVALID"),
            format!(
                "label anchor seed symbol_id={:?} label={:?} is absent from the exact current KernelGraph projection",
                stale.symbol_id, stale.label
            ),
            Some(
                "remove or repair the superseded label anchor so every retained seed names a current KernelGraph CxId",
            ),
            "repair the persisted anchor roster and retry the unchanged staged publication",
        ));
    }
    // Persisted propagation rows key on CxId. Resolve each one through the
    // current graph snapshot to the stable source atom used by search; qualified
    // name remains display metadata and may legitimately be shared.
    let identity_by_cx_hex = stable_identity_by_cx(vault, project).map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "label_identity_read",
            None,
            error.to_string(),
            None,
            "repair the complete graph CxId-to-source-atom roster before rebuilding label propagation",
        )
    })?;
    let report = astrolabe_ingest::derive_and_propagate_index_time_labels(
        vault,
        &scope_id,
        artifact,
        projection,
        &extra_seeds,
        &LabelPropagationConfig::default(),
        astrolabe_ingest::LABEL_SEED_ACTOR,
    )
    .map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "label_propagation",
            error.code(),
            error.to_string(),
            error.remediation(),
            "repair the exact composite artifact/projection, label graph, or propagation rows and retry the unchanged staged publication",
        )
    })?;
    let rows = astrolabe_ingest::read_propagated_label_rows(vault).map_err(|error| {
        kernel_generation_fault(
            project,
            &scope_id,
            "label_propagation_readback",
            error.code(),
            error.to_string(),
            error.remediation(),
            "repair the persisted propagated-label rows and their Ledger pairing before retrying",
        )
    })?;
    persisted_label_propagation_json(project, &scope_id, &report, &rows, &identity_by_cx_hex)
}

/// Derives caller seeds from persisted `AnchorKind::Label(..)` anchors. Each
/// labeled symbol becomes one grounded seed carrying its highest-confidence
/// anchor as provenance. Read or confidence drift is an error; dropping the
/// anchor dimension would change the produced label generation.
fn label_anchor_seeds<C>(vault: &AsterVault<C>) -> Result<Vec<LabelSeed>, DynError>
where
    C: Clock,
{
    let rows = astrolabe_anchors::read_anchor_rows(vault).map_err(|error| -> DynError {
        format!(
            "ASTRO_KERNEL_LABEL_ANCHOR_READ_FAILED: code={} message={:?} remediation={:?}",
            error.code, error.message, error.remediation
        )
        .into()
    })?;
    let mut seeds = Vec::new();
    for persisted in rows {
        let calyx_core::AnchorKind::Label(name) = &persisted.row.kind else {
            continue;
        };
        if let Some(invalid) = persisted.row.anchors.iter().find(|anchor| {
            !anchor.confidence.is_finite() || anchor.confidence <= 0.0 || anchor.confidence > 1.0
        }) {
            return Err(format!(
                "ASTRO_KERNEL_LABEL_ANCHOR_CONFIDENCE_INVALID: cx_id={} label={name:?} source={:?} confidence={}; expected a finite confidence in (0,1]; remediation: repair the persisted anchor row before deriving label seeds",
                persisted.row.cx_id, invalid.source, invalid.confidence
            )
            .into());
        }
        let best = persisted
            .row
            .anchors
            .iter()
            .max_by(|left, right| left.confidence.total_cmp(&right.confidence))
            .ok_or_else(|| -> DynError {
                format!(
                    "ASTRO_KERNEL_LABEL_ANCHOR_EMPTY: cx_id={} label={name:?} has no retained anchor; remediation: repair the anchor readback invariant before deriving label seeds",
                    persisted.row.cx_id
                )
                .into()
            })?;
        let rounded_millipoints = (f64::from(best.confidence) * 1_000.0).round();
        if !(1.0..=1_000.0).contains(&rounded_millipoints) {
            return Err(format!(
                "ASTRO_KERNEL_LABEL_ANCHOR_CONFIDENCE_UNREPRESENTABLE: cx_id={} label={name:?} source={:?} confidence={} rounds to {rounded_millipoints} millipoints; remediation: repair the anchor with a positive confidence representable by the persisted 1..=1000 millipoint contract",
                persisted.row.cx_id, best.source, best.confidence
            )
            .into());
        }
        let millipoints = rounded_millipoints as u64;
        let symbol_id = persisted.row.cx_id.to_string();
        let provenance = format!("anchor:label:{name}:{}", best.source);
        seeds.push(LabelSeed::new(
            symbol_id,
            name.clone(),
            millipoints,
            provenance,
        ));
    }
    Ok(seeds)
}

/// Builds the served `label_propagation` block from the **independently
/// read-back** persisted propagated-label rows (never from the producer's own
/// return value). Same field shape as [`label_propagation_json`] so the
/// `propagated_label` search filter ([`propagated_label_symbol_ids`]) consumes it
/// unchanged.
///
/// Each row's persisted `symbol_id` is a CxId hex. The served `symbol_id` is the
/// corresponding stable source atom; `qualified_name` is non-unique metadata.
fn persisted_label_propagation_json(
    project: &str,
    scope_id: &str,
    report: &astrolabe_ingest::IndexTimeLabelReport,
    rows: &[astrolabe_ingest::PersistedPropagatedLabel],
    identity_by_cx_hex: &BTreeMap<String, (String, String)>,
) -> Result<Value, DynError> {
    let propagation = &report.propagation;
    if let Some(missing) = rows
        .iter()
        .find(|persisted| !identity_by_cx_hex.contains_key(&persisted.row.symbol_id))
    {
        return Err(kernel_generation_fault(
            project,
            scope_id,
            "label_identity_join",
            None,
            format!(
                "propagated label CxId {} has no live stable source-atom identity",
                missing.row.symbol_id
            ),
            None,
            "repair the complete graph identity roster and rebuild label propagation from the unchanged composite generation",
        ));
    }
    if rows.is_empty() {
        return Err(kernel_generation_fault(
            project,
            scope_id,
            "label_propagation_empty",
            None,
            format!(
                "nonempty composite kernel seed roster produced zero propagated rows: seed_count={} kernel_member_seed_count={} edge_count={}",
                report.seed_count, report.kernel_member_seed_count, report.edge_count
            ),
            None,
            "repair the label graph/propagation producer; do not publish an unavailable kernel-context substitute",
        ));
    }
    let mut labels = Vec::with_capacity(rows.len());
    for persisted in rows {
        let row = &persisted.row;
        let (symbol_id, qualified_name) = identity_by_cx_hex
            .get(&row.symbol_id)
            .cloned()
            .ok_or_else(|| {
                kernel_generation_fault(
                    project,
                    scope_id,
                    "label_identity_join",
                    None,
                    format!(
                        "propagated label CxId {} disappeared after complete prevalidation",
                        row.symbol_id
                    ),
                    None,
                    "preserve the staged generation and repair the stable identity reader",
                )
            })?;
        labels.push(json!({
            "symbol_id": symbol_id,
            "cx_id": row.symbol_id,
            "qualified_name": qualified_name,
            "label": row.label,
            "confidence_millipoints": row.confidence_millipoints,
            "seed_symbol_id": row.seed_symbol_id,
            "seed_confidence_millipoints": row.seed_confidence_millipoints,
            "distance": row.distance,
            "provenance": {
                "seed_provenance_ref": row.seed_provenance_ref,
                "graph_provenance_refs": row.graph_provenance_refs,
                "math": row.math,
            },
            "freshness": row.freshness,
            "trust": row.trust,
        }));
    }
    Ok(json!({
        "schema": LABEL_PROPAGATION_SCHEMA,
        "status": "built",
        "knob_registry_version": LABEL_PROPAGATION_KNOB_REGISTRY_VERSION,
        "decay_milliper_step": LabelPropagationConfig::default().decay_milliper_step,
        "seed_count": report.seed_count,
        "kernel_member_seed_count": report.kernel_member_seed_count,
        "extra_seed_count": report.extra_seed_count,
        "edge_count": report.edge_count,
        "seed_source_empty_reason": report.seed_source_empty_reason,
        "label_count": labels.len(),
        "empty_reason": propagation.empty_reason,
        "seeds_read": propagation.seeds_read,
        "edges_read": propagation.edges_read,
        "rows_written": propagation.rows_written,
        "ledger_seq": propagation.ledger_seq,
        "labels": labels,
        "freshness": propagation.freshness,
        "trust": propagation.trust,
        "provenance": propagation.provenance,
    }))
}

/// #390: replace the row-sink-derived `label_propagation` on `base_kernel_context`
/// with the persisted-propagation block, keeping the existing `scope_summaries`,
/// and recompute the rolled-up kernel_context status/trust. The mandatory
/// persisted block must be `built`; no row-sink fallback is accepted.
pub(crate) fn kernel_context_with_persisted_labels(
    base_kernel_context: Value,
    persisted_label_propagation: Value,
) -> Result<Value, DynError> {
    if persisted_label_propagation
        .get("status")
        .and_then(Value::as_str)
        != Some("built")
    {
        return Err(format!(
            "ASTRO_KERNEL_LABEL_PROPAGATION_NOT_BUILT: mandatory persisted label propagation has status {:?}; remediation: preserve the staged generation and repair the label producer rather than serving row-sink fallback state",
            persisted_label_propagation.get("status")
        )
        .into());
    }
    let scope_summaries = base_kernel_context
        .get("scope_summaries")
        .cloned()
        .ok_or_else(|| -> DynError {
            "ASTRO_KERNEL_CONTEXT_BASE_SCOPE_MISSING: row-sink kernel context has no scope_summaries object before mandatory persisted replacement; remediation: repair the closed context producer"
                .into()
        })?;
    Ok(kernel_context_json(
        persisted_label_propagation,
        scope_summaries,
    ))
}

/// #400 index-time hook: builds the served `kernel_context.scope_summaries` block
/// from the persisted `KernelArtifact` for `project`, read back **independently**
/// of the write path.
///
/// The base `scope_summaries` (from [`scope_summaries_from_row_sink_rows`]) is
/// derived from the CBM row-sink node properties `kernel_scopes`/`summary_scopes`/
/// `scopes`, which a real corpus like `cbm/` never emits — so it always resolved
/// to the labeled `unavailable` block, and both `get_kernel mode=read` and the
/// `grounding_gaps` architecture aspect refused fail-closed even on a fully
/// indexed corpus (#400). This derives the scope summary from data that genuinely
/// exists after an index: the persisted `KernelArtifact` members — the measured
/// kernel core, each carrying a real kernel weight (`score_permille`), a
/// per-member groundedness flag, and artifact provenance. Member source atoms
/// and qualified names are resolved exactly from the persisted graph identity
/// map; an absent or ambiguous join refuses. The single scope is the whole-repo
/// kernel scope (`repo:<project>`),
/// the same scope `get_kernel mode=gaps`/`quadrant` already serve from the
/// artifact.
///
/// Builds the whole-repository scope summary from an artifact that the caller
/// already selected through one complete-generation pointer read.
///
/// `get_kernel mode="read"` uses this form while its retained snapshot and
/// loaded S20 index are still live, so the member view and index evidence cannot
/// come from different current generations. The caller remains responsible for
/// source-identity and snapshot-stability verification around this identity join.
pub(crate) fn scope_summaries_from_kernel_artifact<C>(
    vault: &AsterVault<C>,
    project: &str,
    artifact: &astrolabe_kernel::KernelArtifact,
) -> Result<Value, DynError>
where
    C: Clock,
{
    let scope_id = kernel_artifact_scope_id(project);
    if artifact.scope_id != scope_id {
        return Err(kernel_generation_fault(
            project,
            &scope_id,
            "scope_summary_scope_join",
            Some(astrolabe_weave::ASTRO_KERNEL_GENERATION_CORRUPT),
            format!(
                "current artifact scope {:?} does not equal the project scope {scope_id:?}",
                artifact.scope_id
            ),
            Some("repair the complete generation pointer/manifest/artifact scope binding"),
            "repair the complete generation pointer/manifest/artifact scope binding",
        ));
    }
    if artifact.members.is_empty() {
        return Err(kernel_generation_fault(
            project,
            &scope_id,
            "scope_summary_member_roster",
            Some(astrolabe_weave::ASTRO_KERNEL_GENERATION_INCOMPLETE),
            "the mandatory current complete kernel generation carries no members",
            Some("repair kernel selection and republish the complete generation"),
            "repair kernel selection and republish the complete generation",
        ));
    }
    let identity_by_cx = stable_identity_by_cx(vault, project)?;
    let mut members = Vec::with_capacity(artifact.members.len());
    for member in &artifact.members {
        let cx_id = member.id.to_string();
        let Some((symbol_id, qualified_name)) = identity_by_cx.get(&cx_id).cloned() else {
            return Err(kernel_generation_fault(
                project,
                &scope_id,
                "scope_summary_identity_join",
                None,
                format!("persisted kernel member {cx_id} has no stable source-atom identity"),
                None,
                "repair the graph identity roster and rebuild the complete project kernel",
            ));
        };
        let provenance = format!(
            "kernel-artifact:scope={};member={symbol_id};cx_id={cx_id};members_hash={}",
            artifact.scope_id, artifact.members_hash
        );
        members.push(ScopeSummaryMember::new(
            symbol_id,
            qualified_name,
            member.score_permille,
            member.grounded,
            provenance,
        ));
    }
    let graph_coverage = Some(ScopeGraphCoverageMeasurement {
        covered: artifact.graph_coverage.covered,
        total: artifact.graph_coverage.total,
    });
    let input = ScopeSummaryInput::new(
        artifact.scope_id.clone(),
        artifact.members_hash.clone(),
        artifact.anchor_grounded,
        members,
        graph_coverage,
    );
    let summary = summarize_scope_kernel(&input);
    Ok(scope_summaries_json(&[summary], 0))
}

/// #400: replace the row-sink-derived `scope_summaries` on `base_kernel_context`
/// with the persisted-`KernelArtifact`-derived block, keeping the existing
/// `label_propagation`, and recompute the rolled-up kernel_context status/trust.
/// The persisted block must be `built`; a missing/broken mandatory composite
/// generation cannot inherit row-sink fallback state.
pub(crate) fn kernel_context_with_persisted_scope_summaries(
    base_kernel_context: Value,
    persisted_scope_summaries: Value,
) -> Result<Value, DynError> {
    if persisted_scope_summaries
        .get("status")
        .and_then(Value::as_str)
        != Some("built")
    {
        return Err(format!(
            "ASTRO_KERNEL_SCOPE_SUMMARIES_NOT_BUILT: mandatory persisted scope summaries have status {:?}; remediation: preserve the staged generation and repair the composite artifact reader",
            persisted_scope_summaries.get("status")
        )
        .into());
    }
    let label_propagation = base_kernel_context
        .get("label_propagation")
        .cloned()
        .ok_or_else(|| -> DynError {
            "ASTRO_KERNEL_CONTEXT_LABEL_MISSING: mandatory built label propagation disappeared before scope-summary merge; remediation: preserve the staged generation and repair the closed context merge"
                .into()
        })?;
    if label_propagation.get("status").and_then(Value::as_str) != Some("built") {
        return Err(format!(
            "ASTRO_KERNEL_CONTEXT_LABEL_NOT_BUILT: mandatory label propagation has status {:?} before scope-summary merge; remediation: preserve the staged generation and repair the label producer",
            label_propagation.get("status")
        )
        .into());
    }
    Ok(kernel_context_json(
        label_propagation,
        persisted_scope_summaries,
    ))
}

pub(crate) fn kernel_context_from_row_sink_rows(rows: &CbmPipelineRows) -> Value {
    let label_propagation = label_propagation_from_row_sink_rows(rows);
    let scope_summaries = scope_summaries_from_row_sink_rows(rows);
    kernel_context_json(label_propagation, scope_summaries)
}

pub(crate) fn label_propagation_from_row_sink_rows(rows: &CbmPipelineRows) -> Value {
    let (seeds, tombstones, skipped_properties) = label_seed_inputs_from_rows(rows);
    let edges = label_graph_edges_from_rows(rows);
    match propagate_labels(
        &seeds,
        &edges,
        &tombstones,
        &LabelPropagationConfig::default(),
    ) {
        Ok(report) => label_propagation_json(
            &report,
            seeds.len(),
            edges.len(),
            tombstones.len(),
            skipped_properties,
        ),
        Err(error) => {
            label_propagation_unavailable_json(&format!("label propagation failed: {error}"))
        }
    }
}

pub(crate) fn label_seed_inputs_from_rows(
    rows: &CbmPipelineRows,
) -> (Vec<LabelSeed>, Vec<LabelTombstone>, usize) {
    let mut seeds = Vec::new();
    let mut tombstones = Vec::new();
    let mut skipped_properties = 0;

    for node in &rows.nodes {
        if node.qualified_name.trim().is_empty() || node.label.eq_ignore_ascii_case("project") {
            continue;
        }
        let properties = match serde_json::from_str::<Value>(&node.properties_json) {
            Ok(properties) => properties,
            Err(_) => {
                skipped_properties += 1;
                continue;
            }
        };
        if let Some(values) = properties
            .get("label_seeds")
            .or_else(|| properties.get("grounded_labels"))
            .and_then(Value::as_array)
        {
            for value in values {
                let Some(label) = value
                    .get("label")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|label| !label.is_empty())
                else {
                    skipped_properties += 1;
                    continue;
                };
                let confidence = value
                    .get("confidence_millipoints")
                    .and_then(Value::as_u64)
                    .unwrap_or(1_000);
                if confidence == 0 {
                    skipped_properties += 1;
                    continue;
                }
                let provenance = value
                    .get("provenance_ref")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| format!("row_sink:{}:{}#label_seed", node.project, node.id));
                seeds.push(LabelSeed::new(
                    node.atom_id.clone(),
                    label.to_string(),
                    confidence,
                    provenance,
                ));
            }
        }
        if let Some(values) = properties.get("label_tombstones").and_then(Value::as_array) {
            for value in values {
                let symbol_id = value
                    .get("symbol_id")
                    .and_then(Value::as_str)
                    .unwrap_or(&node.atom_id);
                let provenance = value
                    .get("provenance_ref")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned)
                    .unwrap_or_else(|| {
                        format!("row_sink:{}:{}#label_tombstone", node.project, node.id)
                    });
                tombstones.push(LabelTombstone::new(symbol_id.to_string(), provenance));
            }
        }
    }

    (seeds, tombstones, skipped_properties)
}

pub(crate) fn label_graph_edges_from_rows(rows: &CbmPipelineRows) -> Vec<LabelGraphEdge> {
    let node_ids = rows
        .nodes
        .iter()
        .filter(|node| !node.atom_id.trim().is_empty())
        .map(|node| (node.id, node.atom_id.clone()))
        .collect::<BTreeMap<_, _>>();
    rows.edges
        .iter()
        .filter_map(|edge| {
            let left = node_ids.get(&edge.source_id)?;
            let right = node_ids.get(&edge.target_id)?;
            Some(LabelGraphEdge::new(
                left.clone(),
                right.clone(),
                label_edge_provenance(edge),
            ))
        })
        .collect()
}

pub(crate) fn label_edge_provenance(edge: &astrolabe_bridge::CbmPipelineEdgeRow) -> String {
    serde_json::from_str::<Value>(&edge.properties_json)
        .ok()
        .and_then(|properties| {
            properties
                .get("provenance_ref")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| format!("row_sink:edge:{}:{}", edge.id, edge.edge_type))
}

pub(crate) fn label_propagation_json(
    report: &LabelPropagationReport,
    seed_count: usize,
    edge_count: usize,
    tombstone_count: usize,
    skipped_properties: usize,
) -> Value {
    let artifact_bytes = label_propagation_artifact_bytes(report);
    let status = if skipped_properties > 0 {
        "partial"
    } else if report.empty_reason.is_some() {
        "empty"
    } else {
        "built"
    };
    json!({
        "schema": report.schema,
        "status": status,
        "knob_registry_version": report.knob_registry_version,
        "decay_milliper_step": report.decay_milliper_step,
        "seed_count": seed_count,
        "edge_count": edge_count,
        "tombstone_count": tombstone_count,
        "skipped_count": skipped_properties,
        "label_count": report.labels.len(),
        "empty_reason": report.empty_reason,
        "artifact_sha256": hex_lower(&Sha256::digest(&artifact_bytes)),
        "labels": report.labels.iter().map(propagated_label_json).collect::<Vec<_>>(),
        "freshness": report.freshness,
        "trust": if skipped_properties == 0 { report.trust } else { "provisional" },
    })
}

pub(crate) fn propagated_label_json(label: &astrolabe_kernel::PropagatedLabel) -> Value {
    json!({
        "symbol_id": label.symbol_id,
        "label": label.label,
        "confidence_millipoints": label.confidence_millipoints,
        "seed_symbol_id": label.seed_symbol_id,
        "seed_confidence_millipoints": label.seed_confidence_millipoints,
        "distance": label.distance,
        "provenance": {
            "seed_provenance_ref": label.provenance.seed_provenance_ref,
            "graph_provenance_refs": label.provenance.graph_provenance_refs,
            "math": label.provenance.math,
        },
        "freshness": label.freshness,
        "trust": label.trust.as_str(),
    })
}

pub(crate) fn label_propagation_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": LABEL_PROPAGATION_SCHEMA,
        "status": "unavailable",
        "knob_registry_version": LABEL_PROPAGATION_KNOB_REGISTRY_VERSION,
        "freshness": "not_evaluated",
        "trust": "provisional",
        "reason": reason,
        "remediation": "rerun index_repository with label seed metadata and graph edges available before using propagated-label filters",
    })
}

pub(crate) fn scope_summaries_from_row_sink_rows(rows: &CbmPipelineRows) -> Value {
    let (inputs, skipped_properties) = scope_summary_inputs_from_rows(rows);
    if inputs.is_empty() {
        return scope_summaries_unavailable_json(
            "scope summary metadata missing; row-sink nodes must declare kernel_scopes/summary_scopes/scopes",
        );
    }
    let summaries = inputs
        .iter()
        .map(summarize_scope_kernel)
        .collect::<Vec<_>>();
    scope_summaries_json(&summaries, skipped_properties)
}

pub(crate) fn scope_summary_inputs_from_rows(
    rows: &CbmPipelineRows,
) -> (Vec<ScopeSummaryInput>, usize) {
    let fingerprint = hex_lower(&row_sink_fingerprint(rows));
    let mut by_scope = BTreeMap::<String, Vec<ScopeSummaryMember>>::new();
    let mut grounded_by_scope = BTreeMap::<String, bool>::new();
    let mut graph_coverage_by_scope = BTreeMap::<String, ScopeGraphCoverageMeasurement>::new();
    let mut skipped_properties = 0;

    for node in &rows.nodes {
        if node.qualified_name.trim().is_empty() || node.label.eq_ignore_ascii_case("project") {
            continue;
        }
        let properties = match serde_json::from_str::<Value>(&node.properties_json) {
            Ok(properties) => properties,
            Err(_) => {
                skipped_properties += 1;
                continue;
            }
        };
        let scopes = scope_summary_scopes_for_node(&properties);
        if scopes.is_empty() {
            continue;
        }
        let grounded = properties
            .get("kernel_grounded")
            .or_else(|| properties.get("grounded"))
            .and_then(Value::as_bool)
            .unwrap_or(true);

        for scope in scopes {
            let member = ScopeSummaryMember::new(
                node.atom_id.clone(),
                node.qualified_name.clone(),
                bridge_node_kernel_weight(&properties, &scope),
                grounded,
                scope_node_provenance(node, &properties, &scope),
            );
            by_scope.entry(scope.clone()).or_default().push(member);
            grounded_by_scope
                .entry(scope.clone())
                .and_modify(|scope_grounded| *scope_grounded = *scope_grounded && grounded)
                .or_insert(grounded);
            if let Some(graph_coverage) = scope_graph_coverage_for_node(&properties, &scope) {
                graph_coverage_by_scope
                    .entry(scope)
                    .or_insert(graph_coverage);
            }
        }
    }

    let inputs = by_scope
        .into_iter()
        .map(|(scope_id, members)| {
            ScopeSummaryInput::new(
                scope_id.clone(),
                format!("row-sink:{fingerprint}:{scope_id}"),
                grounded_by_scope.get(&scope_id).copied().unwrap_or(false),
                members,
                graph_coverage_by_scope.get(&scope_id).copied(),
            )
        })
        .collect();
    (inputs, skipped_properties)
}

pub(crate) fn scope_summary_scopes_for_node(properties: &Value) -> Vec<String> {
    let mut scopes = BTreeSet::new();
    for field in ["kernel_scopes", "summary_scopes", "scope_ids", "scopes"] {
        if let Some(values) = properties.get(field).and_then(Value::as_array) {
            for value in values {
                if let Some(scope) = value
                    .as_str()
                    .map(str::trim)
                    .filter(|scope| !scope.is_empty())
                {
                    scopes.insert(scope.to_string());
                }
            }
        }
    }
    if let Some(scope) = properties
        .get("scope")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
    {
        scopes.insert(scope.to_string());
    }
    scopes.into_iter().collect()
}

pub(crate) fn scope_node_provenance(
    node: &astrolabe_bridge::CbmPipelineNodeRow,
    properties: &Value,
    scope: &str,
) -> String {
    properties
        .get("kernel_scope_provenance")
        .or_else(|| properties.get("scope_provenance"))
        .and_then(Value::as_object)
        .and_then(|provenance| provenance.get(scope))
        .and_then(Value::as_str)
        .or_else(|| properties.get("provenance_ref").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| {
            format!(
                "row_sink:{}:{}#scope_summary:{scope}",
                node.project, node.id
            )
        })
}

pub(crate) fn scope_graph_coverage_for_node(
    properties: &Value,
    scope: &str,
) -> Option<ScopeGraphCoverageMeasurement> {
    let graph_coverage = properties.get("scope_graph_coverage")?;
    let direct = graph_coverage
        .get("covered")
        .and_then(Value::as_u64)
        .zip(graph_coverage.get("total").and_then(Value::as_u64));
    let scoped = graph_coverage
        .get(scope)
        .and_then(Value::as_object)
        .and_then(|value| {
            value
                .get("covered")
                .and_then(Value::as_u64)
                .zip(value.get("total").and_then(Value::as_u64))
        });
    direct.or(scoped).and_then(|(covered, total)| {
        (total > 0).then_some(ScopeGraphCoverageMeasurement { covered, total })
    })
}

pub(crate) fn scope_summaries_json(summaries: &[ScopeSummary], skipped_properties: usize) -> Value {
    let mut artifact_bytes = Vec::new();
    for summary in summaries {
        artifact_bytes.extend(scope_summary_artifact_bytes(summary));
    }
    let all_verified =
        skipped_properties == 0 && summaries.iter().all(|summary| summary.trust == "verified");
    json!({
        "schema": SCOPE_SUMMARY_COLLECTION_SCHEMA,
        "summary_schema": SCOPE_SUMMARY_SCHEMA,
        "status": if skipped_properties == 0 { "built" } else { "partial" },
        "summary_count": summaries.len(),
        "skipped_count": skipped_properties,
        "artifact_sha256": hex_lower(&Sha256::digest(&artifact_bytes)),
        "summaries": summaries.iter().map(scope_summary_json).collect::<Vec<_>>(),
        "freshness": "fresh",
        "trust": if all_verified { "verified" } else { "provisional" },
    })
}

pub(crate) fn scope_summary_json(summary: &ScopeSummary) -> Value {
    json!({
        "schema": summary.schema,
        "scope_id": summary.scope_id,
        "dirty_region_hash": summary.dirty_region_hash,
        "summary_hash": summary.summary_hash,
        "graph_coverage": summary.graph_coverage.map(|coverage| json!({
            "covered": coverage.covered,
            "total": coverage.total,
        })),
        "graph_coverage_millipoints": summary.graph_coverage_millipoints,
        "grounded_member_count": summary.grounded_member_count,
        "total_member_count": summary.total_member_count,
        "grounded_fraction_millipoints": summary.grounded_fraction_millipoints,
        "members": summary.members.iter().map(|member| {
            json!({
                "symbol_id": member.symbol_id,
                "qualified_name": member.qualified_name,
                "kernel_weight": member.kernel_weight,
                "grounded": member.grounded,
                "provenance_ref": member.provenance_ref,
            })
        }).collect::<Vec<_>>(),
        "freshness": summary.freshness,
        "trust": summary.trust,
    })
}

pub(crate) fn scope_summaries_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": SCOPE_SUMMARY_COLLECTION_SCHEMA,
        "summary_schema": SCOPE_SUMMARY_SCHEMA,
        "status": "unavailable",
        "freshness": "not_evaluated",
        "trust": "provisional",
        "reason": reason,
        "remediation": "rerun index_repository with explicit scope metadata before using kernel summary architecture aspects",
    })
}

pub(crate) fn kernel_context_json(label_propagation: Value, scope_summaries: Value) -> Value {
    let label_status = label_propagation
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    let scope_status = scope_summaries
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    let status = if label_status == "unavailable" && scope_status == "unavailable" {
        "unavailable"
    } else if matches!(label_status, "built" | "empty") && scope_status == "built" {
        "built"
    } else {
        "partial"
    };
    let trust =
        if label_propagation["trust"] == "verified" && scope_summaries["trust"] == "verified" {
            "verified"
        } else {
            "provisional"
        };
    json!({
        "schema": KERNEL_CONTEXT_SCHEMA,
        "status": status,
        "label_propagation": label_propagation,
        "scope_summaries": scope_summaries,
        "freshness": if status == "unavailable" { "not_evaluated" } else { "fresh" },
        "trust": trust,
    })
}

/// Honest absence for a project whose migration dial is not shadow. A
/// shadow-published project must never reach this serializer: missing or corrupt
/// context there is broken mandatory state and [`read_kernel_context_metadata`]
/// returns a coded error.
pub(crate) fn kernel_context_unavailable_json(reason: &str) -> Value {
    json!({
        "schema": KERNEL_CONTEXT_SCHEMA,
        "status": "unavailable",
        "label_propagation": label_propagation_unavailable_json(reason),
        "scope_summaries": scope_summaries_unavailable_json(reason),
        "freshness": "not_evaluated",
        "trust": "provisional",
        "reason": reason,
        "remediation": "rerun index_repository with row-sink label and scope metadata before using kernel context surfaces",
    })
}

/// #69 box 5 — exact set of match keys carrying `label` as a *propagated* label in
/// the persisted kernel context. Fails closed (coded) when propagation is
/// unavailable so the search filter never silently degrades into an unfiltered or
/// spuriously empty result. Same exact-match semantics as the kernel's
/// [`astrolabe_kernel::filter_symbols_by_propagated_label`]. The returned key is
/// the served stable source-atom `symbol_id`; qualified name is display metadata
/// and is never used as an identity key.
pub(crate) fn propagated_label_symbol_ids(
    kernel_context: &Value,
    label: &str,
) -> Result<BTreeSet<String>, String> {
    let propagation = kernel_context
        .get("label_propagation")
        .unwrap_or(&Value::Null);
    let status = propagation
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unavailable");
    if status == "unavailable" {
        let reason = propagation
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("label propagation metadata unavailable");
        return Err(format!(
            "ASTRO_SEARCH_GRAPH_PROPAGATED_LABEL_UNAVAILABLE: cannot apply propagated_label filter {label:?}: {reason}; remediation: rerun index_repository with calyx=\"shadow\" so label seeds and graph edges are propagated before filtering search_graph by a propagated label"
        ));
    }
    let mut ids = BTreeSet::new();
    if let Some(labels) = propagation.get("labels").and_then(Value::as_array) {
        for entry in labels {
            // Exact stable source-atom identity; never a qualified-name guess.
            if entry.get("label").and_then(Value::as_str) == Some(label)
                && let Some(candidate) = entry
                    .get("symbol_id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|candidate| !candidate.is_empty())
            {
                ids.insert(candidate.to_string());
            }
        }
    }
    Ok(ids)
}

/// #69 box 5 — rewrite a raw `search_graph` tool result, keeping only hits whose
/// symbol id is in `labeled_symbols` (exact match, original hit order preserved).
/// Annotates both the `structuredContent` and the mirrored `content[0].text`
/// payload with the applied filter, at provisional trust (propagated labels are
/// inferences, never trusted).
pub(crate) fn filter_search_graph_result_by_label(
    raw_result: &str,
    label: &str,
    labeled_symbols: &BTreeSet<String>,
) -> Result<String, DynError> {
    let mut value: Value = serde_json::from_str(raw_result)?;

    if let Some(structured) = value
        .get_mut("structuredContent")
        .and_then(Value::as_object_mut)
    {
        let (input_count, matched_count) = retain_labeled_results(structured, labeled_symbols)?;
        structured.insert(
            "astrolabe_propagated_label_filter".to_string(),
            search_graph_filter_meta_json(label, input_count, matched_count),
        );
    }

    if let Some(text) = value
        .get_mut("content")
        .and_then(Value::as_array_mut)
        .and_then(|items| items.first_mut())
        .and_then(|item| item.get_mut("text"))
    {
        let raw_text = text.as_str().ok_or_else(|| -> DynError {
            "ASTRO_SEARCH_LABEL_FILTER_TEXT_TYPE: content[0].text is not a string"
                .to_string()
                .into()
        })?;
        let mut text_value = serde_json::from_str::<Value>(raw_text).map_err(|error| -> DynError {
            format!(
                "ASTRO_SEARCH_LABEL_FILTER_TEXT_JSON: content[0].text is not valid search JSON: {error}"
            )
            .into()
        })?;
        let text_obj = text_value.as_object_mut().ok_or_else(|| -> DynError {
            "ASTRO_SEARCH_LABEL_FILTER_TEXT_OBJECT: content[0].text search JSON is not an object"
                .to_string()
                .into()
        })?;
        let (input_count, matched_count) = retain_labeled_results(text_obj, labeled_symbols)?;
        text_obj.insert(
            "astrolabe_propagated_label_filter".to_string(),
            search_graph_filter_meta_json(label, input_count, matched_count),
        );
        *text = Value::String(serde_json::to_string(&text_value)?);
    }

    Ok(serde_json::to_string(&value)?)
}

/// Retain only the `results[]` entries whose symbol id is in `labeled_symbols`.
/// Returns `(input_count, matched_count)` and rewrites any mirrored count field so
/// the surfaced total never lies about the post-filter hit count.
fn retain_labeled_results(
    obj: &mut Map<String, Value>,
    labeled_symbols: &BTreeSet<String>,
) -> Result<(usize, usize), DynError> {
    let mut input_count = 0;
    let mut matched_count = 0;
    for result_field in ["results", "semantic_results"] {
        let Some(results) = obj.get_mut(result_field).and_then(Value::as_array_mut) else {
            continue;
        };
        input_count += results.len();
        let mut retained = Vec::with_capacity(results.len());
        for (index, hit) in std::mem::take(results).into_iter().enumerate() {
            let candidate = hit
                .get("atom_id")
                .or_else(|| hit.get("symbol_id"))
                .and_then(Value::as_str)
                .filter(|identity| !identity.is_empty())
                .ok_or_else(|| -> DynError {
                    format!(
                        "ASTRO_SEARCH_LABEL_FILTER_IDENTITY: {result_field}[{index}] has no stable atom_id"
                    )
                    .into()
                })?;
            if labeled_symbols.contains(candidate) {
                retained.push(hit);
            }
        }
        matched_count += retained.len();
        *results = retained;
    }
    for key in ["result_count", "count", "total_results", "returned"] {
        if let Some(existing) = obj.get_mut(key)
            && existing.as_u64() == Some(input_count as u64)
        {
            *existing = json!(matched_count);
        }
    }
    Ok((input_count, matched_count))
}

fn search_graph_filter_meta_json(label: &str, input_count: usize, matched_count: usize) -> Value {
    json!({
        "schema": "astrolabe.search_graph_propagated_label_filter.v1",
        "label": label,
        "input_count": input_count,
        "matched_count": matched_count,
        "trust": "provisional",
        "freshness": "fresh",
        "provenance": "kernel_context.label_propagation (astrolabe.label_propagation.v1)",
    })
}

pub(crate) fn read_kernel_context_metadata(
    cache_dir: &Path,
    project: &str,
) -> Result<Value, DynError> {
    let key = metadata_key(project, "kernel_context_json");
    let dial = read_dial_at(cache_dir, project)?;
    let Some(raw) = read_config_value(cache_dir, &key)? else {
        if dial == MigrationDial::Shadow {
            return Err(format!(
                "{ASTRO_KERNEL_CONTEXT_METADATA_MISSING}: shadow-published project {project:?} has no persisted row {key:?}; remediation: preserve the project generation and rerun the exact shadow publisher so the complete kernel generation and its context metadata commit together"
            )
            .into());
        }
        return Ok(kernel_context_unavailable_json(
            "kernel context is not present because this project is not shadow-indexed",
        ));
    };
    let value = serde_json::from_str::<Value>(&raw).map_err(|error| -> DynError {
        format!(
            "{ASTRO_KERNEL_CONTEXT_METADATA_INVALID}: project {project:?} persisted row {key:?} is not valid JSON: {error}; remediation: preserve the corrupt row and rebuild it from the authoritative shadow source"
        )
        .into()
    })?;
    let object = value.as_object().ok_or_else(|| -> DynError {
        format!(
            "{ASTRO_KERNEL_CONTEXT_METADATA_INVALID}: project {project:?} persisted row {key:?} is not a JSON object; remediation: preserve the corrupt row and rebuild it from the authoritative shadow source"
        )
        .into()
    })?;
    if object.get("schema").and_then(Value::as_str) != Some(KERNEL_CONTEXT_SCHEMA) {
        return Err(format!(
            "{ASTRO_KERNEL_CONTEXT_METADATA_INVALID}: project {project:?} persisted row {key:?} has schema {:?}, expected {KERNEL_CONTEXT_SCHEMA:?}; remediation: preserve the incompatible row and rebuild it with the current shadow producer",
            object.get("schema")
        )
        .into());
    }
    let status = object
        .get("status")
        .and_then(Value::as_str)
        .ok_or_else(|| -> DynError {
            format!(
                "{ASTRO_KERNEL_CONTEXT_METADATA_INVALID}: project {project:?} persisted row {key:?} has no string status; remediation: preserve the corrupt row and rebuild it with the current shadow producer"
            )
            .into()
        })?;
    if !matches!(status, "built" | "partial" | "unavailable") {
        return Err(format!(
            "{ASTRO_KERNEL_CONTEXT_METADATA_INVALID}: project {project:?} persisted row {key:?} has unknown status {status:?}; remediation: preserve the incompatible row and rebuild it with the current shadow producer"
        )
        .into());
    }
    if dial == MigrationDial::Shadow {
        let scope_summaries = object
            .get("scope_summaries")
            .and_then(Value::as_object)
            .ok_or_else(|| -> DynError {
                format!(
                    "{ASTRO_KERNEL_CONTEXT_METADATA_INVALID}: shadow-published project {project:?} row {key:?} has no scope_summaries object; remediation: preserve the incomplete publication and rebuild the mandatory complete kernel generation/context"
                )
                .into()
            })?;
        if scope_summaries.get("schema").and_then(Value::as_str)
            != Some(SCOPE_SUMMARY_COLLECTION_SCHEMA)
            || scope_summaries.get("status").and_then(Value::as_str) != Some("built")
        {
            return Err(format!(
                "{ASTRO_KERNEL_CONTEXT_METADATA_INVALID}: shadow-published project {project:?} row {key:?} does not contain a built {SCOPE_SUMMARY_COLLECTION_SCHEMA} scope summary (schema={:?}, status={:?}); remediation: preserve the incomplete publication and rebuild the complete composite kernel generation before serving context",
                scope_summaries.get("schema"),
                scope_summaries.get("status")
            )
            .into());
        }
    }
    Ok(value)
}
