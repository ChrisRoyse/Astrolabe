use std::collections::{BTreeMap, BTreeSet};

use astrolabe_domain::ASTRO_SYMBOL_NON_FINITE;
use calyx_core::{
    AbsentReason, CalyxError, Input, Lens, LensId, Modality, SlotId, SlotShape, SlotVector,
    SparseEntry, content_address,
};
use serde::{Deserialize, Serialize};

use crate::{
    ASTRO_PANEL_CONTRACT_INVALID, ASTRO_PANEL_VECTOR_INVALID, FrozenLensContract, PanelError,
    PanelResult, seed_spec_for_lens, slot_spec,
};

const AST_PROFILE_DIM: u32 = 25;
const COMPLEXITY_LOG_DIM: u32 = 8;
const COMPLEXITY_PLE_DIM: u32 = 56;
const GRAPH_POSITION_DIM: u32 = 16;

const STRUCT_TRIGRAM_DIM: u32 = 65_536;
const API_CALLEES_DIM: u32 = 262_144;
const TYPE_SURFACE_DIM: u32 = 65_536;
const DECORATORS_DIM: u32 = 4_096;
const IDENTIFIER_LEXICAL_DIM: u32 = 131_072;
const PATH_HIERARCHY_DIM: u32 = 16_384;

const AST_PROFILE_MAXIMA: [f32; AST_PROFILE_DIM as usize] = [
    100.0, 100.0, 100.0, 100.0, 100.0, 100.0, 20.0, 200.0, 100.0, 100.0, 100.0, 100.0, 100.0,
    100.0, 100.0, 20.0, 100.0, 100.0, 100.0, 200.0, 200.0, 200.0, 200.0, 2_000.0, 2_000.0,
];

const COMPLEXITY_PLE_THRESHOLDS: [f32; 6] = [1.0, 2.0, 4.0, 8.0, 16.0, 32.0];
const GRAPH_EDGE_CLASSES: &[&str] = &["call", "dataflow", "type", "service"];
const SEE_S8_DIMENSION_ISSUE: &str = "https://github.com/ChrisRoyse/Astrolabe/issues/66";

/// CBM AST profile counters in the exact `cbm_ast_profile_to_vector` field order.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct AstProfile {
    /// `if_statement` / `if_expression` counter.
    pub if_count: f32,
    /// `for_statement` / equivalent counter.
    pub for_count: f32,
    /// `while_statement` / equivalent counter.
    pub while_count: f32,
    /// `switch` / `match` counter.
    pub switch_count: f32,
    /// `try` / `catch` counter.
    pub try_count: f32,
    /// Return statement/expression counter.
    pub return_count: f32,
    /// Maximum nesting depth.
    pub max_nesting_depth: f32,
    /// Average nesting depth multiplied by ten.
    pub avg_nesting_depth_x10: f32,
    /// Comparison operator count.
    pub comparison_ops: f32,
    /// Arithmetic operator count.
    pub arithmetic_ops: f32,
    /// Logical operator count.
    pub logical_ops: f32,
    /// Assignment count.
    pub assignment_count: f32,
    /// String literal count.
    pub string_literals: f32,
    /// Number literal count.
    pub number_literals: f32,
    /// Boolean literal count.
    pub bool_literals: f32,
    /// Parameter count.
    pub param_count: f32,
    /// Parameters observed in returns.
    pub params_in_returns: f32,
    /// Parameters observed in conditions.
    pub params_in_conditions: f32,
    /// Variable reassignment count.
    pub variable_reassigns: f32,
    /// Halstead-lite unique operator count.
    pub unique_operators: f32,
    /// Halstead-lite unique operand count.
    pub unique_operands: f32,
    /// Halstead-lite total operator count.
    pub total_operators: f32,
    /// Halstead-lite total operand count.
    pub total_operands: f32,
    /// Body line count.
    pub body_lines: f32,
    /// Body token count.
    pub body_tokens: f32,
}

impl AstProfile {
    fn fields(self) -> [f32; AST_PROFILE_DIM as usize] {
        [
            self.if_count,
            self.for_count,
            self.while_count,
            self.switch_count,
            self.try_count,
            self.return_count,
            self.max_nesting_depth,
            self.avg_nesting_depth_x10,
            self.comparison_ops,
            self.arithmetic_ops,
            self.logical_ops,
            self.assignment_count,
            self.string_literals,
            self.number_literals,
            self.bool_literals,
            self.param_count,
            self.params_in_returns,
            self.params_in_conditions,
            self.variable_reassigns,
            self.unique_operators,
            self.unique_operands,
            self.total_operators,
            self.total_operands,
            self.body_lines,
            self.body_tokens,
        ]
    }
}

/// One structurally weighted AST-node-type trigram.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StructuralTrigram {
    /// First node type.
    pub a: String,
    /// Second node type.
    pub b: String,
    /// Third node type.
    pub c: String,
    /// Structural weight. Frozen v1 accepts the CBM range `[0, 3]`; zero is skipped.
    pub weight: f32,
}

/// Eight CBM complexity counters used by S2/S3.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct ComplexityMetrics {
    /// Cyclomatic complexity.
    pub cyclomatic: f32,
    /// Cognitive complexity.
    pub cognitive: f32,
    /// Loop count.
    pub loop_count: f32,
    /// Maximum loop nesting depth.
    pub loop_depth: f32,
    /// Maximum member/access chain depth.
    pub max_access_depth: f32,
    /// Parameter count.
    pub param_count: f32,
    /// Body line count.
    pub body_lines: f32,
    /// Body token count.
    pub body_tokens: f32,
}

impl ComplexityMetrics {
    fn fields(self) -> [f32; COMPLEXITY_LOG_DIM as usize] {
        [
            self.cyclomatic,
            self.cognitive,
            self.loop_count,
            self.loop_depth,
            self.max_access_depth,
            self.param_count,
            self.body_lines,
            self.body_tokens,
        ]
    }
}

/// One API callee observation for S4.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ApiCall {
    /// Resolved qualified callee name, or best unresolved name.
    pub callee: String,
    /// Observed call count. Resolved calls use `log1p(call_count)`.
    pub call_count: f32,
    /// Whether `callee` is fully resolved.
    pub resolved: bool,
}

/// Type-surface sets used by S5.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeSurfaceInput {
    /// Parameter type names.
    pub param_types: Vec<String>,
    /// Return type names.
    pub return_types: Vec<String>,
    /// Types referenced by the body.
    pub uses_types: Vec<String>,
    /// Types instantiated by the body.
    pub instantiates: Vec<String>,
}

/// Identifier fields used by S7.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentifierLexicalInput {
    /// Local symbol name.
    pub name: String,
    /// Qualified symbol name.
    pub qualified_name: String,
    /// Body-local identifiers.
    pub body_identifiers: Vec<String>,
}

/// Woven graph features used by S8.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct GraphPositionInput {
    /// Incoming call-edge degree.
    pub call_in: f32,
    /// Outgoing call-edge degree.
    pub call_out: f32,
    /// Incoming dataflow-edge degree.
    pub dataflow_in: f32,
    /// Outgoing dataflow-edge degree.
    pub dataflow_out: f32,
    /// Incoming type-edge degree.
    pub type_in: f32,
    /// Outgoing type-edge degree.
    pub type_out: f32,
    /// Incoming service-edge degree.
    pub service_in: f32,
    /// Outgoing service-edge degree.
    pub service_out: f32,
    /// Sampled betweenness score.
    pub sampled_betweenness: f32,
    /// PageRank score.
    pub pagerank: f32,
    /// Clustering coefficient.
    pub clustering_coeff: f32,
    /// Neighbor-label entropy.
    pub neighbor_label_entropy: f32,
}

/// Path hierarchy input for S9.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathHierarchyInput {
    /// Repository-relative source path.
    pub path: String,
}

/// Combined deterministic encoder input. Missing slot-specific fields emit explicit absence.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct EncoderLensInput {
    /// S0 input.
    pub ast_profile: Option<AstProfile>,
    /// S1 input.
    pub struct_trigrams: Option<Vec<StructuralTrigram>>,
    /// S2/S3 input.
    pub complexity: Option<ComplexityMetrics>,
    /// S4 input.
    pub api_calls: Option<Vec<ApiCall>>,
    /// S5 input.
    pub type_surface: Option<TypeSurfaceInput>,
    /// S6 input.
    pub decorators: Option<Vec<String>>,
    /// S7 input.
    pub identifiers: Option<IdentifierLexicalInput>,
    /// S8 input.
    pub graph_position: Option<GraphPositionInput>,
    /// S9 input.
    pub path_hierarchy: Option<PathHierarchyInput>,
}

/// Runtime lens implementation for deterministic panel v1 encoder slots S0-S9.
#[derive(Clone, Debug, PartialEq)]
pub struct DeterministicEncoderLens {
    slot_id: SlotId,
    contract: FrozenLensContract,
}

impl DeterministicEncoderLens {
    /// Builds a deterministic encoder lens for one S0-S9 slot.
    pub fn new(slot_id: SlotId) -> PanelResult<Self> {
        let slot = slot_spec(slot_id).ok_or_else(|| {
            PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!("slot {slot_id} is not in the frozen panel roster"),
                "Use one of the frozen panel v1 slot ids.",
            )
        })?;
        if slot.slot > 9 {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!("slot {slot_id} is outside the deterministic S0-S9 encoder range"),
                "Use S0-S9 for deterministic CBM-derived encoder lenses.",
            ));
        }
        Ok(Self {
            slot_id,
            contract: FrozenLensContract::for_slot(slot),
        })
    }

    /// Returns the slot this lens measures.
    pub const fn slot_id(&self) -> SlotId {
        self.slot_id
    }

    /// Builds the registration probe input for this lens.
    pub fn probe_input(&self) -> PanelResult<Input> {
        probe_input_for_slot(self.slot_id)
    }
}

impl Lens for DeterministicEncoderLens {
    fn id(&self) -> LensId {
        self.contract.lens_id()
    }

    fn shape(&self) -> SlotShape {
        self.contract.shape
    }

    fn modality(&self) -> Modality {
        self.contract.modality
    }

    fn measure(&self, input: &Input) -> calyx_core::Result<SlotVector> {
        if input.modality != self.contract.modality {
            return Err(CalyxError::lens_dim_mismatch(format!(
                "slot {} expected {:?} input, got {:?}",
                self.slot_id, self.contract.modality, input.modality
            )));
        }
        let decoded: EncoderLensInput = serde_json::from_slice(&input.bytes).map_err(|err| {
            CalyxError::lens_frozen_violation(format!(
                "slot {} probe/input JSON is not an EncoderLensInput: {err}",
                self.slot_id
            ))
        })?;
        encode_slot(self.slot_id, &decoded).map_err(calyx_from_panel_error)
    }
}

/// Returns deterministic S0-S9 encoder lens runtimes.
pub fn s0_s9_lenses() -> PanelResult<Vec<DeterministicEncoderLens>> {
    (0_u16..=9)
        .map(|slot| DeterministicEncoderLens::new(SlotId::new(slot)))
        .collect()
}

/// Deterministically encodes one S0-S9 slot from the combined input.
pub fn encode_slot(slot_id: SlotId, input: &EncoderLensInput) -> PanelResult<SlotVector> {
    match slot_id.get() {
        0 => input
            .ast_profile
            .as_ref()
            .map(encode_ast_profile)
            .unwrap_or_else(absent),
        1 => input
            .struct_trigrams
            .as_ref()
            .map(|trigrams| encode_struct_trigrams(trigrams))
            .unwrap_or_else(absent),
        2 => input
            .complexity
            .as_ref()
            .map(encode_complexity_log)
            .unwrap_or_else(absent),
        3 => input
            .complexity
            .as_ref()
            .map(encode_complexity_ple)
            .unwrap_or_else(absent),
        4 => input
            .api_calls
            .as_ref()
            .map(|calls| encode_api_callees(calls))
            .unwrap_or_else(absent),
        5 => input
            .type_surface
            .as_ref()
            .map(encode_type_surface)
            .unwrap_or_else(absent),
        6 => input
            .decorators
            .as_ref()
            .map(|decorators| encode_decorators(decorators))
            .unwrap_or_else(absent),
        7 => input
            .identifiers
            .as_ref()
            .map(encode_identifier_lexical)
            .unwrap_or_else(absent),
        8 => input
            .graph_position
            .as_ref()
            .map(encode_graph_position)
            .unwrap_or_else(absent),
        9 => input
            .path_hierarchy
            .as_ref()
            .map(encode_path_hierarchy)
            .unwrap_or_else(absent),
        _ => Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!("slot {slot_id} is not implemented by deterministic S0-S9 lenses"),
            "Use slot ids 0 through 9 for this encoder family.",
        )),
    }
}

/// Fixture input committed into golden vector tests and determinism probes.
pub fn fixture_encoder_input() -> EncoderLensInput {
    EncoderLensInput {
        ast_profile: Some(AstProfile {
            if_count: 5.0,
            for_count: 3.0,
            while_count: 1.0,
            switch_count: 2.0,
            try_count: 0.0,
            return_count: 4.0,
            max_nesting_depth: 3.0,
            avg_nesting_depth_x10: 15.0,
            comparison_ops: 10.0,
            arithmetic_ops: 8.0,
            logical_ops: 2.0,
            assignment_count: 7.0,
            string_literals: 3.0,
            number_literals: 5.0,
            bool_literals: 1.0,
            param_count: 4.0,
            params_in_returns: 2.0,
            params_in_conditions: 1.0,
            variable_reassigns: 3.0,
            unique_operators: 12.0,
            unique_operands: 20.0,
            total_operators: 45.0,
            total_operands: 60.0,
            body_lines: 30.0,
            body_tokens: 200.0,
        }),
        struct_trigrams: Some(vec![
            StructuralTrigram {
                a: "function_definition".to_string(),
                b: "parameters".to_string(),
                c: "identifier".to_string(),
                weight: 1.0,
            },
            StructuralTrigram {
                a: "if_statement".to_string(),
                b: "comparison_operator".to_string(),
                c: "identifier".to_string(),
                weight: 2.0,
            },
            StructuralTrigram {
                a: "call_expression".to_string(),
                b: "member_expression".to_string(),
                c: "argument_list".to_string(),
                weight: 3.0,
            },
            StructuralTrigram {
                a: "zero".to_string(),
                b: "weight".to_string(),
                c: "skipped".to_string(),
                weight: 0.0,
            },
        ]),
        complexity: Some(ComplexityMetrics {
            cyclomatic: 7.0,
            cognitive: 11.0,
            loop_count: 2.0,
            loop_depth: 1.0,
            max_access_depth: 4.0,
            param_count: 4.0,
            body_lines: 30.0,
            body_tokens: 200.0,
        }),
        api_calls: Some(vec![
            ApiCall {
                callee: "crate::service::UserStore::load".to_string(),
                call_count: 3.0,
                resolved: true,
            },
            ApiCall {
                callee: "serde_json::from_slice".to_string(),
                call_count: 1.0,
                resolved: true,
            },
            ApiCall {
                callee: "unknown.helper".to_string(),
                call_count: 2.0,
                resolved: false,
            },
        ]),
        type_surface: Some(TypeSurfaceInput {
            param_types: vec!["Request".to_string(), "UserId".to_string()],
            return_types: vec!["Result<User>".to_string()],
            uses_types: vec!["HashMap".to_string(), "Option<User>".to_string()],
            instantiates: vec!["UserDto".to_string()],
        }),
        decorators: Some(vec![
            "route:get:/users/{id}".to_string(),
            "instrument".to_string(),
            "derive:Debug".to_string(),
        ]),
        identifiers: Some(IdentifierLexicalInput {
            name: "loadUserHTTP2".to_string(),
            qualified_name: "crate::service::UserStore::loadUserHTTP2".to_string(),
            body_identifiers: vec![
                "user_id".to_string(),
                "HTTPResponseCode".to_string(),
                "mañanaHTTPServer42".to_string(),
            ],
        }),
        graph_position: Some(GraphPositionInput {
            call_in: 4.0,
            call_out: 9.0,
            dataflow_in: 2.0,
            dataflow_out: 5.0,
            type_in: 1.0,
            type_out: 3.0,
            service_in: 0.0,
            service_out: 2.0,
            sampled_betweenness: 0.125,
            pagerank: 0.03125,
            clustering_coeff: 0.5,
            neighbor_label_entropy: 1.75,
        }),
        path_hierarchy: Some(PathHierarchyInput {
            path: "src/service/user_store.rs".to_string(),
        }),
    }
}

/// Mirrors CBM's SQLite `cbm_camel_split` helper: original text, a space, then an
/// ASCII-only camel/acronym split copy.
pub fn cbm_camel_split_text(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(2).saturating_add(1));
    out.extend_from_slice(bytes);
    out.push(b' ');
    for (idx, byte) in bytes.iter().copied().enumerate() {
        if idx > 0 {
            let prev = bytes[idx - 1];
            let next = bytes.get(idx + 1).copied();
            if camel_should_split(prev, byte, next) {
                out.push(b' ');
            }
        }
        out.push(byte);
    }
    String::from_utf8(out).expect("valid UTF-8 input plus inserted ASCII spaces")
}

/// Token stream produced by applying CBM camel splitting, underscore splitting, and
/// unicode lowercase tokenization.
pub fn cbm_camel_split_tokens(input: &str) -> Vec<String> {
    tokenize_like_unicode61(&cbm_camel_split_text(input))
}

fn probe_input_for_slot(slot_id: SlotId) -> PanelResult<Input> {
    let slot = slot_spec(slot_id).ok_or_else(|| {
        PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!("slot {slot_id} is not in the frozen panel roster"),
            "Use one of the frozen panel v1 slot ids.",
        )
    })?;
    let bytes = serde_json::to_vec(&fixture_encoder_input()).map_err(|err| {
        PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            format!("fixture EncoderLensInput did not serialize: {err}"),
            "Keep deterministic probe fixtures serializable.",
        )
    })?;
    Ok(Input::new(slot.modality, bytes))
}

fn encode_ast_profile(profile: &AstProfile) -> PanelResult<SlotVector> {
    let fields = profile.fields();
    ensure_finite_values("ast_profile", &fields)?;
    dense(
        SlotId::new(0),
        fields
            .iter()
            .zip(AST_PROFILE_MAXIMA)
            .map(|(value, max)| value / max)
            .collect(),
    )
}

fn encode_struct_trigrams(trigrams: &[StructuralTrigram]) -> PanelResult<SlotVector> {
    let mut terms = Vec::with_capacity(trigrams.len());
    for trigram in trigrams {
        ensure_finite_scalar("struct_trigrams.weight", trigram.weight)?;
        if trigram.weight == 0.0 {
            continue;
        }
        if !(0.0..=3.0).contains(&trigram.weight) {
            return Err(PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!(
                    "structural trigram weight {} is outside [0, 3]",
                    trigram.weight
                ),
                "Use CBM structural trigram weights 1, 2, or 3; reserve 0 for skipped terms.",
            ));
        }
        terms.push((
            format!(
                "trigram:{}>{}>{}",
                trigram.a.trim(),
                trigram.b.trim(),
                trigram.c.trim()
            ),
            trigram.weight,
        ));
    }
    hashed_sparse("struct_trigrams", STRUCT_TRIGRAM_DIM, terms)
}

fn encode_complexity_log(metrics: &ComplexityMetrics) -> PanelResult<SlotVector> {
    let fields = metrics.fields();
    ensure_finite_values("complexity_log", &fields)?;
    dense(
        SlotId::new(2),
        fields
            .iter()
            .copied()
            .map(signed_log)
            .collect::<PanelResult<Vec<_>>>()?,
    )
}

fn encode_complexity_ple(metrics: &ComplexityMetrics) -> PanelResult<SlotVector> {
    let fields = metrics.fields();
    ensure_finite_values("complexity_ple", &fields)?;
    let mut data = Vec::with_capacity(COMPLEXITY_PLE_DIM as usize);
    for value in fields {
        let value = signed_log(value)?;
        data.push(1.0);
        for (idx, upper_raw) in COMPLEXITY_PLE_THRESHOLDS.iter().copied().enumerate() {
            let lower = if idx == 0 {
                0.0
            } else {
                signed_log(COMPLEXITY_PLE_THRESHOLDS[idx - 1])?
            };
            let upper = signed_log(upper_raw)?;
            data.push(((value - lower) / (upper - lower)).clamp(0.0, 1.0));
        }
    }
    l2_normalize(&mut data)?;
    dense(SlotId::new(3), data)
}

fn encode_api_callees(calls: &[ApiCall]) -> PanelResult<SlotVector> {
    let mut terms = Vec::with_capacity(calls.len());
    for call in calls {
        ensure_finite_scalar("api_callees.call_count", call.call_count)?;
        if call.call_count < 0.0 {
            return Err(PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!(
                    "callee {} has negative call_count {}",
                    call.callee, call.call_count
                ),
                "Emit non-negative CBM call counts for API callee hashing.",
            ));
        }
        let trimmed = call.callee.trim();
        if trimmed.is_empty() {
            continue;
        }
        if call.resolved {
            let weight = call.call_count.ln_1p();
            if weight != 0.0 {
                terms.push((format!("resolved:{trimmed}"), weight));
            }
        } else {
            terms.push((format!("unresolved:{}", bare_callee_name(trimmed)), 0.5));
        }
    }
    hashed_sparse("api_callees", API_CALLEES_DIM, terms)
}

fn encode_type_surface(input: &TypeSurfaceInput) -> PanelResult<SlotVector> {
    let mut terms = BTreeSet::new();
    insert_prefixed(&mut terms, "param", &input.param_types);
    insert_prefixed(&mut terms, "return", &input.return_types);
    insert_prefixed(&mut terms, "uses_type", &input.uses_types);
    insert_prefixed(&mut terms, "instantiates", &input.instantiates);
    hashed_sparse(
        "type_surface",
        TYPE_SURFACE_DIM,
        terms.into_iter().map(|term| (term, 1.0)),
    )
}

fn encode_decorators(decorators: &[String]) -> PanelResult<SlotVector> {
    let terms = decorators
        .iter()
        .map(|decorator| decorator.trim())
        .filter(|decorator| !decorator.is_empty())
        .collect::<BTreeSet<_>>();
    hashed_sparse(
        "decorators",
        DECORATORS_DIM,
        terms
            .into_iter()
            .map(|decorator| (format!("decorator:{decorator}"), 1.0)),
    )
}

fn encode_identifier_lexical(input: &IdentifierLexicalInput) -> PanelResult<SlotVector> {
    let mut counts: BTreeMap<String, f32> = BTreeMap::new();
    for identifier in std::iter::once(&input.name)
        .chain(std::iter::once(&input.qualified_name))
        .chain(input.body_identifiers.iter())
    {
        for token in cbm_camel_split_tokens(identifier) {
            *counts.entry(format!("token:{token}")).or_insert(0.0) += 1.0;
        }
    }
    hashed_sparse("identifier_lexical", IDENTIFIER_LEXICAL_DIM, counts)
}

fn encode_graph_position(input: &GraphPositionInput) -> PanelResult<SlotVector> {
    let degrees = [
        input.call_in,
        input.call_out,
        input.dataflow_in,
        input.dataflow_out,
        input.type_in,
        input.type_out,
        input.service_in,
        input.service_out,
    ];
    ensure_finite_values("graph_position.degrees", &degrees)?;
    for (idx, value) in degrees.iter().copied().enumerate() {
        if value < 0.0 {
            return Err(PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!(
                    "graph_position {} degree {} is negative; see {SEE_S8_DIMENSION_ISSUE}",
                    graph_degree_name(idx),
                    value
                ),
                "Emit non-negative woven graph degrees.",
            ));
        }
    }
    let scalars = [
        input.sampled_betweenness,
        input.pagerank,
        input.clustering_coeff,
        input.neighbor_label_entropy,
    ];
    ensure_finite_values("graph_position.centrality", &scalars)?;
    for value in scalars {
        if value < 0.0 {
            return Err(PanelError::new(
                ASTRO_PANEL_VECTOR_INVALID,
                format!(
                    "graph_position centrality scalar {value} is negative; see {SEE_S8_DIMENSION_ISSUE}"
                ),
                "Emit non-negative woven graph centrality/entropy features.",
            ));
        }
    }

    let total_in = input.call_in + input.dataflow_in + input.type_in + input.service_in;
    let total_out = input.call_out + input.dataflow_out + input.type_out + input.service_out;
    let total = total_in + total_out;
    let balance = if total > 0.0 {
        (total_out - total_in) / total
    } else {
        0.0
    };
    let mut data = Vec::with_capacity(GRAPH_POSITION_DIM as usize);
    data.extend([
        input.call_in.ln_1p(),
        input.call_out.ln_1p(),
        input.dataflow_in.ln_1p(),
        input.dataflow_out.ln_1p(),
        input.type_in.ln_1p(),
        input.type_out.ln_1p(),
        input.service_in.ln_1p(),
        input.service_out.ln_1p(),
        input.sampled_betweenness,
        input.pagerank,
        input.clustering_coeff,
        input.neighbor_label_entropy,
        total_in.ln_1p(),
        total_out.ln_1p(),
        total.ln_1p(),
        balance,
    ]);

    // S8 Dense(16) dimension order:
    // 0-7: log1p in/out degree for call, dataflow, type, service;
    // 8-11: sampled betweenness, PageRank, clustering coefficient, neighbor-label entropy;
    // 12-15: derived totals pending the explicit contract clarification in issue #66.
    dense(SlotId::new(8), data)
}

fn encode_path_hierarchy(input: &PathHierarchyInput) -> PanelResult<SlotVector> {
    let components = input
        .path
        .split(['/', '\\'])
        .map(str::trim)
        .filter(|component| !component.is_empty() && *component != ".")
        .collect::<Vec<_>>();
    let mut terms = Vec::new();
    for depth in 1..=components.len() {
        terms.push((format!("ancestor:{}", components[..depth].join("/")), 1.0));
    }
    if !components.is_empty() {
        terms.push((
            format!("depth:{}", components.len()),
            (components.len() as f32).ln_1p(),
        ));
    }
    hashed_sparse("path_hierarchy", PATH_HIERARCHY_DIM, terms)
}

fn absent() -> PanelResult<SlotVector> {
    Ok(SlotVector::Absent {
        reason: AbsentReason::LensUnavailable,
    })
}

fn dense(slot_id: SlotId, data: Vec<f32>) -> PanelResult<SlotVector> {
    let slot = slot_spec(slot_id).ok_or_else(|| {
        PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!("slot {slot_id} is not in the frozen panel roster"),
            "Use one of the frozen panel v1 slot ids.",
        )
    })?;
    let dim = match slot.shape {
        SlotShape::Dense(dim) => dim,
        _ => {
            return Err(PanelError::new(
                ASTRO_PANEL_CONTRACT_INVALID,
                format!("slot {slot_id} is not a dense slot"),
                "Emit dense vectors only for dense panel slots.",
            ));
        }
    };
    if data.len() != dim as usize {
        return Err(PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            format!(
                "slot {slot_id} expected {dim} dense values, got {}",
                data.len()
            ),
            "Emit exactly the frozen dense slot dimension.",
        ));
    }
    ensure_finite_values("dense slot", &data)?;
    let vector = SlotVector::Dense { dim, data };
    validate_slot(slot_id, &vector)?;
    Ok(vector)
}

fn hashed_sparse<I>(lens_key: &str, dim: u32, terms: I) -> PanelResult<SlotVector>
where
    I: IntoIterator<Item = (String, f32)>,
{
    assert_hash_contract(lens_key, dim)?;
    let mut accum = BTreeMap::<u32, f32>::new();
    for (term, weight) in terms {
        ensure_finite_scalar("hashed_sparse.weight", weight)?;
        if weight == 0.0 {
            continue;
        }
        let (idx, sign) = signed_feature_index(lens_key, dim, &term)?;
        *accum.entry(idx).or_insert(0.0) += sign * weight;
    }
    let entries = accum
        .into_iter()
        .filter(|(_, val)| *val != 0.0)
        .map(|(idx, val)| SparseEntry { idx, val })
        .collect::<Vec<_>>();
    let vector = SlotVector::Sparse { dim, entries };
    let slot_id = seed_spec_for_lens(lens_key)
        .map(|spec| SlotId::new(spec.slot))
        .ok_or_else(|| missing_seed(lens_key))?;
    validate_slot(slot_id, &vector)?;
    Ok(vector)
}

fn signed_feature_index(lens_key: &str, dim: u32, term: &str) -> PanelResult<(u32, f32)> {
    let seed = seed_spec_for_lens(lens_key).ok_or_else(|| missing_seed(lens_key))?;
    let hash = content_address([
        seed.seed_hex.as_bytes(),
        lens_key.as_bytes(),
        term.as_bytes(),
    ]);
    let mut idx = [0_u8; 4];
    idx.copy_from_slice(&hash[..4]);
    let index = u32::from_be_bytes(idx) % dim;
    let sign = if hash[4] & 1 == 0 { 1.0 } else { -1.0 };
    Ok((index, sign))
}

fn assert_hash_contract(lens_key: &str, dim: u32) -> PanelResult<()> {
    let seed = seed_spec_for_lens(lens_key).ok_or_else(|| missing_seed(lens_key))?;
    if seed.dim != dim {
        return Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!(
                "seed registry dim {} for {lens_key} does not match encoder dim {dim}",
                seed.dim
            ),
            "Route hashing dimensions through the frozen seed registry.",
        ));
    }
    let slot = slot_spec(SlotId::new(seed.slot)).ok_or_else(|| {
        PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!(
                "seed registry points {lens_key} at unknown slot {}",
                seed.slot
            ),
            "Keep seed registry slot ids aligned with the frozen panel roster.",
        )
    })?;
    if slot.key != lens_key || slot.shape != SlotShape::Sparse(dim) {
        return Err(PanelError::new(
            ASTRO_PANEL_CONTRACT_INVALID,
            format!(
                "seed registry {lens_key} maps to slot {} {:?} key {}",
                seed.slot, slot.shape, slot.key
            ),
            "Keep hashing lens keys, dimensions, and slots frozen together.",
        ));
    }
    Ok(())
}

fn validate_slot(slot_id: SlotId, vector: &SlotVector) -> PanelResult<()> {
    let slot = slot_spec(slot_id).expect("validated slot id");
    crate::validate_slot_shape(*slot, vector)
}

fn insert_prefixed(terms: &mut BTreeSet<String>, prefix: &str, values: &[String]) {
    for value in values {
        let value = value.trim();
        if !value.is_empty() {
            terms.insert(format!("{prefix}:{value}"));
        }
    }
}

fn signed_log(value: f32) -> PanelResult<f32> {
    ensure_finite_scalar("signed_log", value)?;
    Ok(value.signum() * value.abs().ln_1p())
}

fn l2_normalize(data: &mut [f32]) -> PanelResult<()> {
    let norm = data.iter().map(|value| value * value).sum::<f32>().sqrt();
    ensure_finite_scalar("l2_norm", norm)?;
    if norm == 0.0 {
        return Err(PanelError::new(
            ASTRO_PANEL_VECTOR_INVALID,
            "unit-normalized vector has zero norm",
            "Emit at least one non-zero feature before L2 normalization.",
        ));
    }
    for value in data {
        *value /= norm;
    }
    Ok(())
}

fn ensure_finite_values(field: &str, values: &[f32]) -> PanelResult<()> {
    for value in values {
        ensure_finite_scalar(field, *value)?;
    }
    Ok(())
}

fn ensure_finite_scalar(field: &str, value: f32) -> PanelResult<()> {
    if value.is_finite() {
        Ok(())
    } else {
        Err(PanelError::new(
            ASTRO_SYMBOL_NON_FINITE,
            format!("{field} contains non-finite value {value}"),
            "Drop or repair the symbol before measuring deterministic panel lenses.",
        ))
    }
}

fn missing_seed(lens_key: &str) -> PanelError {
    PanelError::new(
        ASTRO_PANEL_CONTRACT_INVALID,
        format!("{lens_key} has no frozen seed registry entry"),
        "Add hash-bearing deterministic lenses to ASTRO_SEED_SPECS before use.",
    )
}

fn bare_callee_name(callee: &str) -> &str {
    callee
        .rsplit([':', '.', '/', '#'])
        .find(|part| !part.is_empty())
        .unwrap_or(callee)
}

fn camel_should_split(prev: u8, curr: u8, next: Option<u8>) -> bool {
    curr.is_ascii_uppercase()
        && (prev.is_ascii_lowercase()
            || (prev.is_ascii_uppercase() && next.is_some_and(|byte| byte.is_ascii_lowercase())))
}

fn tokenize_like_unicode61(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() {
            current.extend(ch.to_lowercase());
        } else if !current.is_empty() {
            tokens.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn graph_degree_name(idx: usize) -> String {
    let class = GRAPH_EDGE_CLASSES[idx / 2];
    let direction = if idx.is_multiple_of(2) { "in" } else { "out" };
    format!("{class}_{direction}")
}

fn calyx_from_panel_error(err: PanelError) -> CalyxError {
    CalyxError::lens_numerical_invariant(format!("{}: {}", err.code(), err.message()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const GOLDEN_HEX_BY_SLOT: [&str; 10] = [
        "44000000193d4ccccd3cf5c28f3c23d70a3ca3d70a000000003d23d70a3e19999a3d99999a3dcccccd3da3d70a3ca3d70a3d8f5c293cf5c28f3d4ccccd3c23d70a3e4ccccd3ca3d70a3c23d70a3cf5c28f3d75c28f3dcccccd3e6666663e99999a3c75c28f3dcccccd",
        "53000100000000000300007f77bf80000000009cfa400000000000bba5c0400000",
        "440000000840051592401f08b63f8c9f543f3172183fce02103fce0210405bc67240a9b4ac",
        "44000000383e291d043e291d043e291d043e291d043e0739ca00000000000000003e291d043e291d043e291d043e291d043e291d043d98fe2e000000003e291d043e291d043e291d04000000000000000000000000000000003e291d043e291d0400000000000000000000000000000000000000003e291d043e291d043e291d043e291d040000000000000000000000003e291d043e291d043e291d043e291d040000000000000000000000003e291d043e291d043e291d043e291d043e291d043e291d043e192c533e291d043e291d043e291d043e291d043e291d043e291d043e291d04",
        "53000400000000000300028d133f000000000369ae3fb172180003f5863f317218",
        "5300010000000000060000074a3f80000000001605bf80000000001c243f8000000000cdb3bf8000000000d95c3f8000000000df18bf800000",
        "53000010000000000300000019bf8000000000046cbf80000000000daebf800000",
        "53000200000000001000002cdc400000000000613f3f8000000000d28b40a0000000010171bf800000000119ae3f8000000001219740000000000138b4400000000001411fc0000000000146b5c00000000001576e3f800000000160303f8000000001781d3f80000000017eb24000000000018b7bc00000000001be463f8000000001dc773f800000",
        "44000000103fce021040135d8e3f8c9f543fe558603f3172183fb17218000000003f8c9f543e0000003d0000003f0000003fe0000040051592403fba144052eefe3eec4ec5",
        "530000400000000004000025f7bf80000000002cae3fb1721800003c933f80000000003ee03f800000",
    ];

    #[test]
    fn golden_vectors_s0_s9_are_byte_exact() {
        let input = fixture_encoder_input();
        for slot in 0_u16..=9 {
            let vector = encode_slot(SlotId::new(slot), &input).expect("encode fixture slot");
            let actual = hex_lower(&slot_vector_bytes(&vector));
            assert_eq!(
                actual, GOLDEN_HEX_BY_SLOT[slot as usize],
                "slot {slot} golden drifted; actual={actual}"
            );
        }
    }

    #[test]
    fn determinism_probes_pass_registration_gate_for_s0_s9() {
        for lens in s0_s9_lenses().expect("build deterministic lenses") {
            let slot = slot_spec(lens.slot_id()).expect("slot spec");
            let contract = FrozenLensContract::for_slot(slot);
            let proof = contract
                .verify_determinism_probe(&lens, &lens.probe_input().expect("probe input"))
                .expect("determinism proof");
            assert_eq!(proof.lens_id, lens.id());
        }
    }

    #[test]
    fn tokenizer_matches_cbm_camel_split_adversarial_semantics() {
        let cases = [
            (
                "parseUserInput",
                vec!["parseuserinput", "parse", "user", "input"],
            ),
            ("HTMLParser", vec!["htmlparser", "html", "parser"]),
            (
                "handle_http_request",
                vec!["handle", "http", "request", "handle", "http", "request"],
            ),
            (
                "SCREAMING_CASE",
                vec!["screaming", "case", "screaming", "case"],
            ),
            (
                "IPv6RouteID42",
                vec!["ipv6routeid42", "i", "pv6route", "id42"],
            ),
            (
                "mañanaHTTPServer42",
                vec!["mañanahttpserver42", "mañana", "http", "server42"],
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(cbm_camel_split_tokens(input), expected);
        }

        assert_eq!(cbm_camel_split_text("HTMLParser"), "HTMLParser HTML Parser");
    }

    #[test]
    fn s8_graph_position_dimension_order_is_frozen() {
        let input = GraphPositionInput {
            call_in: 1.0,
            call_out: 2.0,
            dataflow_in: 3.0,
            dataflow_out: 4.0,
            type_in: 5.0,
            type_out: 6.0,
            service_in: 7.0,
            service_out: 8.0,
            sampled_betweenness: 0.25,
            pagerank: 0.125,
            clustering_coeff: 0.5,
            neighbor_label_entropy: 1.5,
        };
        let SlotVector::Dense { data, .. } = encode_graph_position(&input).expect("graph vector")
        else {
            panic!("S8 must be dense");
        };
        let total_in: f32 = 1.0 + 3.0 + 5.0 + 7.0;
        let total_out: f32 = 2.0 + 4.0 + 6.0 + 8.0;
        let total = total_in + total_out;
        assert_eq!(
            data,
            vec![
                1.0_f32.ln_1p(),
                2.0_f32.ln_1p(),
                3.0_f32.ln_1p(),
                4.0_f32.ln_1p(),
                5.0_f32.ln_1p(),
                6.0_f32.ln_1p(),
                7.0_f32.ln_1p(),
                8.0_f32.ln_1p(),
                0.25,
                0.125,
                0.5,
                1.5,
                total_in.ln_1p(),
                total_out.ln_1p(),
                total.ln_1p(),
                (total_out - total_in) / total,
            ]
        );
    }

    #[test]
    fn hash_dimensions_and_seed_registry_are_the_only_seed_source() {
        let hashed = [
            ("struct_trigrams", STRUCT_TRIGRAM_DIM),
            ("api_callees", API_CALLEES_DIM),
            ("type_surface", TYPE_SURFACE_DIM),
            ("decorators", DECORATORS_DIM),
            ("identifier_lexical", IDENTIFIER_LEXICAL_DIM),
            ("path_hierarchy", PATH_HIERARCHY_DIM),
        ];
        for (lens_key, dim) in hashed {
            assert_hash_contract(lens_key, dim).expect("hash contract");
        }

        let source = include_str!("lenses.rs");
        let forbidden_seed_prefix =
            String::from_utf8(vec![48, 120, 65, 53, 55, 48]).expect("ASCII seed prefix");
        assert!(
            !source.contains(&forbidden_seed_prefix),
            "hash seeds must come from ASTRO_SEED_SPECS, not lenses.rs"
        );
    }

    #[test]
    fn non_finite_inputs_fail_closed_with_symbol_error() {
        let mut input = fixture_encoder_input();
        input.ast_profile.as_mut().unwrap().if_count = f32::NAN;
        let err = encode_slot(SlotId::new(0), &input).expect_err("NaN refused");
        assert_eq!(err.code(), ASTRO_SYMBOL_NON_FINITE);

        let mut input = fixture_encoder_input();
        input.struct_trigrams.as_mut().unwrap()[0].weight = f32::INFINITY;
        let err = encode_slot(SlotId::new(1), &input).expect_err("Inf refused");
        assert_eq!(err.code(), ASTRO_SYMBOL_NON_FINITE);

        let mut input = fixture_encoder_input();
        input.complexity.as_mut().unwrap().cyclomatic = f32::NEG_INFINITY;
        let err = encode_slot(SlotId::new(2), &input).expect_err("Inf refused");
        assert_eq!(err.code(), ASTRO_SYMBOL_NON_FINITE);

        let mut input = fixture_encoder_input();
        input.complexity.as_mut().unwrap().body_tokens = f32::NAN;
        let err = encode_slot(SlotId::new(3), &input).expect_err("NaN refused");
        assert_eq!(err.code(), ASTRO_SYMBOL_NON_FINITE);

        let mut input = fixture_encoder_input();
        input.api_calls.as_mut().unwrap()[0].call_count = f32::NAN;
        let err = encode_slot(SlotId::new(4), &input).expect_err("NaN refused");
        assert_eq!(err.code(), ASTRO_SYMBOL_NON_FINITE);

        let mut input = fixture_encoder_input();
        input.graph_position.as_mut().unwrap().pagerank = f32::INFINITY;
        let err = encode_slot(SlotId::new(8), &input).expect_err("Inf refused");
        assert_eq!(err.code(), ASTRO_SYMBOL_NON_FINITE);
    }

    proptest! {
        #[test]
        fn declared_norm_invariants_hold_for_finite_inputs(
            ast_values in proptest::collection::vec(0.0_f32..5000.0, AST_PROFILE_DIM as usize),
            complexity_values in proptest::collection::vec(0.0_f32..5000.0, COMPLEXITY_LOG_DIM as usize),
            graph_values in proptest::collection::vec(0.0_f32..5000.0, 12),
        ) {
            let ast = ast_from_slice(&ast_values);
            let SlotVector::Dense { data: ast_data, .. } = encode_ast_profile(&ast).expect("ast profile") else {
                panic!("S0 dense");
            };
            prop_assert!(ast_data.iter().all(|value| value.is_finite()));

            let metrics = complexity_from_slice(&complexity_values);
            let SlotVector::Dense { data: log_data, .. } = encode_complexity_log(&metrics).expect("complexity log") else {
                panic!("S2 dense");
            };
            prop_assert!(log_data.iter().all(|value| value.is_finite()));

            let SlotVector::Dense { data: ple_data, .. } = encode_complexity_ple(&metrics).expect("complexity ple") else {
                panic!("S3 dense");
            };
            prop_assert!(ple_data.iter().all(|value| value.is_finite()));
            let norm = ple_data.iter().map(|value| value * value).sum::<f32>().sqrt();
            prop_assert!((norm - 1.0).abs() <= 1.0e-3);

            let sparse_input = EncoderLensInput {
                struct_trigrams: Some(vec![StructuralTrigram {
                    a: "a".to_string(),
                    b: "b".to_string(),
                    c: "c".to_string(),
                    weight: 1.0,
                }]),
                api_calls: Some(vec![ApiCall {
                    callee: "pkg::call".to_string(),
                    call_count: complexity_values[0],
                    resolved: true,
                }]),
                type_surface: Some(TypeSurfaceInput {
                    param_types: vec!["T".to_string()],
                    return_types: vec!["U".to_string()],
                    uses_types: vec!["V".to_string()],
                    instantiates: vec!["W".to_string()],
                }),
                decorators: Some(vec!["memoize".to_string()]),
                identifiers: Some(IdentifierLexicalInput {
                    name: "parseHTTP2".to_string(),
                    qualified_name: "mod::parseHTTP2".to_string(),
                    body_identifiers: vec!["snake_case42".to_string()],
                }),
                path_hierarchy: Some(PathHierarchyInput {
                    path: "src/a/b.rs".to_string(),
                }),
                ..EncoderLensInput::default()
            };
            for slot in [1_u16, 4, 5, 6, 7, 9] {
                let vector = encode_slot(SlotId::new(slot), &sparse_input).expect("sparse vector");
                let SlotVector::Sparse { entries, .. } = vector else {
                    panic!("sparse slot");
                };
                prop_assert!(entries.iter().all(|entry| entry.val.is_finite()));
            }

            let graph = GraphPositionInput {
                call_in: graph_values[0],
                call_out: graph_values[1],
                dataflow_in: graph_values[2],
                dataflow_out: graph_values[3],
                type_in: graph_values[4],
                type_out: graph_values[5],
                service_in: graph_values[6],
                service_out: graph_values[7],
                sampled_betweenness: graph_values[8],
                pagerank: graph_values[9],
                clustering_coeff: graph_values[10],
                neighbor_label_entropy: graph_values[11],
            };
            let SlotVector::Dense { data: graph_data, .. } = encode_graph_position(&graph).expect("S8 graph vector") else {
                panic!("S8 dense");
            };
            prop_assert!(graph_data.iter().all(|value| value.is_finite()));
        }
    }

    fn ast_from_slice(values: &[f32]) -> AstProfile {
        AstProfile {
            if_count: values[0],
            for_count: values[1],
            while_count: values[2],
            switch_count: values[3],
            try_count: values[4],
            return_count: values[5],
            max_nesting_depth: values[6],
            avg_nesting_depth_x10: values[7],
            comparison_ops: values[8],
            arithmetic_ops: values[9],
            logical_ops: values[10],
            assignment_count: values[11],
            string_literals: values[12],
            number_literals: values[13],
            bool_literals: values[14],
            param_count: values[15],
            params_in_returns: values[16],
            params_in_conditions: values[17],
            variable_reassigns: values[18],
            unique_operators: values[19],
            unique_operands: values[20],
            total_operators: values[21],
            total_operands: values[22],
            body_lines: values[23],
            body_tokens: values[24],
        }
    }

    fn complexity_from_slice(values: &[f32]) -> ComplexityMetrics {
        ComplexityMetrics {
            cyclomatic: values[0],
            cognitive: values[1],
            loop_count: values[2],
            loop_depth: values[3],
            max_access_depth: values[4],
            param_count: values[5],
            body_lines: values[6],
            body_tokens: values[7],
        }
    }

    fn slot_vector_bytes(vector: &SlotVector) -> Vec<u8> {
        let mut out = Vec::new();
        match vector {
            SlotVector::Dense { dim, data } => {
                out.extend_from_slice(b"D");
                out.extend_from_slice(&dim.to_be_bytes());
                for value in data {
                    out.extend_from_slice(&value.to_bits().to_be_bytes());
                }
            }
            SlotVector::Sparse { dim, entries } => {
                out.extend_from_slice(b"S");
                out.extend_from_slice(&dim.to_be_bytes());
                out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
                for entry in entries {
                    out.extend_from_slice(&entry.idx.to_be_bytes());
                    out.extend_from_slice(&entry.val.to_bits().to_be_bytes());
                }
            }
            SlotVector::Multi { .. } | SlotVector::Absent { .. } => {
                panic!("S0-S9 golden fixtures must be dense or sparse")
            }
        }
        out
    }

    fn hex_lower(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}
