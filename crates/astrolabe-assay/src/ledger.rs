//! Append-only, hash-chained ledger of assay cards, with reproduce (08 §8).
//!
//! Every card the bits pipeline emits is ledgered as an entry that records the
//! *exact* inputs needed to re-derive it: the card seed, a content fingerprint of
//! the slot/axis observations, and the card itself with its per-slot estimator,
//! `n`, interval, and trust. Entries are chained — each carries the previous
//! entry's hash — so a reader can verify the log has not been rewritten, and each
//! write is proven by reading the bytes back (FSV). `reproduce` re-runs the
//! measurement from the recorded seed and inputs and asserts the result matches
//! the ledgered card bit-for-bit, which is exactly the reproducibility contract
//! the blueprint requires (`reproduce` re-derives within tolerance).

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::bits::{
    AxisValues, BitsConfig, SignalRankingCard, SlotObservations, build_signal_ranking,
};
use crate::error::{
    ASTRO_ASSAY_INPUT_FINGERPRINT_COLLISION, ASTRO_ASSAY_INPUT_FINGERPRINT_INVALID,
    ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID, ASTRO_ASSAY_READBACK_MISMATCH,
    ASTRO_ASSAY_REPRODUCE_MISMATCH, ASTRO_ASSAY_STORE_CORRUPT, ASTRO_ASSAY_STORE_IO, AssayError,
    Result,
};

/// Domain-separation tag for the ledger entry hash.
pub const ASSAY_LEDGER_TAG: &str = "astro-assay-card-ledger-v1";

/// The hex hash that seeds an empty chain (the genesis previous-hash).
pub const GENESIS_PREV_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

fn valid_input_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid_input_fingerprint(value: &str) -> AssayError {
    AssayError::new(
        ASTRO_ASSAY_INPUT_FINGERPRINT_INVALID,
        format!(
            "assay card input fingerprint {value:?} is not 64 lowercase hexadecimal characters"
        ),
        "recompute the fingerprint from the canonical measurement inputs before appending",
    )
}

fn input_fingerprint_collision(message: impl Into<String>) -> AssayError {
    AssayError::new(
        ASTRO_ASSAY_INPUT_FINGERPRINT_COLLISION,
        message,
        "preserve the ledger, identify the two input preimages, and rebuild only after assigning distinct canonical fingerprints",
    )
}

/// One ledgered assay card entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssayCardEntry {
    /// Zero-based sequence number in the chain.
    pub seq: u64,
    /// Hex hash of the previous entry (genesis constant for the first entry).
    pub prev_hash: String,
    /// Hex hash of this entry's canonical payload.
    pub entry_hash: String,
    /// Seed that drove the card's stochastic steps.
    pub seed: u64,
    /// Hex blake3 fingerprint of the exact `(slots, axis)` inputs.
    pub input_fingerprint: String,
    /// The ledgered card.
    pub card: SignalRankingCard,
}

/// One owned card request admitted to a lock-bound ledger batch.
#[derive(Debug, Clone, PartialEq)]
pub struct AssayCardAppendRequest {
    /// Fully computed card bytes.
    pub card: SignalRankingCard,
    /// Deterministic measurement seed.
    pub seed: u64,
    /// Canonical lowercase input fingerprint.
    pub input_fingerprint: String,
}

/// Physical location and digest of one newline-terminated ledger record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssayCardLineReceipt {
    /// Ledger sequence encoded by this line.
    pub seq: u64,
    /// Entry hash encoded by this line.
    pub entry_hash: String,
    /// Byte offset from the start of the ledger file.
    pub offset: u64,
    /// Exact newline-terminated line length.
    pub bytes: u64,
    /// BLAKE3 of the exact newline-terminated line bytes.
    pub line_blake3: String,
}

/// A verified ledger batch whose exact file lock remains held until publish or
/// drop. Persist the external prepared marker while this value is alive, then
/// consume it with [`PreparedAssayCardBatch::publish`].
#[derive(Debug)]
pub struct PreparedAssayCardBatch {
    file: File,
    path: PathBuf,
    append_bytes: Vec<u8>,
    /// Entries this batch will append, or the exact entries found during an
    /// idempotent resume.
    pub entries: Vec<AssayCardEntry>,
    /// Exact physical line identities for `entries`.
    pub lines: Vec<AssayCardLineReceipt>,
    /// Bytes preceding this batch in the append-only ledger.
    pub prior_file_bytes: u64,
    /// BLAKE3 of the exact prefix preceding this batch.
    pub prior_file_blake3: String,
}

/// Durable batch publication read back from the still-locked ledger file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssayCardBatchReceipt {
    /// Published entries in request order.
    pub entries: Vec<AssayCardEntry>,
    /// Exact physical line identities in request order.
    pub lines: Vec<AssayCardLineReceipt>,
    /// Complete ledger length after publication.
    pub file_bytes: u64,
    /// BLAKE3 of the complete verified ledger after publication.
    pub file_blake3: String,
    /// True when all entries already existed and no bytes were appended.
    pub idempotent_replay: bool,
}

struct ParsedLedgerLine {
    entry: AssayCardEntry,
    offset: usize,
    bytes: usize,
}

fn parse_ledger_bytes(path: &Path, bytes: &[u8]) -> Result<Vec<ParsedLedgerLine>> {
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(AssayError::new(
            ASTRO_ASSAY_STORE_CORRUPT,
            format!(
                "ledger {} ends with a partial non-newline-terminated record",
                path.display()
            ),
            "preserve the incomplete ledger and its transaction marker, then repair it through the explicit recovery protocol",
        ));
    }
    let mut entries = Vec::new();
    let mut previous_hash = GENESIS_PREV_HASH.to_string();
    let mut input_identities: BTreeMap<String, u64> = BTreeMap::new();
    let mut offset = 0usize;
    for (line_index, terminated) in bytes.split_inclusive(|byte| *byte == b'\n').enumerate() {
        let line_bytes = terminated.len();
        let line = &terminated[..line_bytes - 1];
        if line.is_empty() {
            offset = offset.checked_add(line_bytes).ok_or_else(|| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_CORRUPT,
                    format!("ledger {} byte offset exceeded usize", path.display()),
                    "preserve the ledger and repair its physical record layout",
                )
            })?;
            continue;
        }
        let line = std::str::from_utf8(line).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!(
                    "{}:{} is not UTF-8: {error}",
                    path.display(),
                    line_index + 1
                ),
                "preserve the corrupt ledger and rebuild it through the explicit recovery protocol",
            )
        })?;
        let entry: AssayCardEntry = serde_json::from_str(line).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!(
                    "{}:{} did not parse: {error}",
                    path.display(),
                    line_index + 1
                ),
                "preserve the corrupt ledger and rebuild it through the explicit recovery protocol",
            )
        })?;
        if !valid_input_fingerprint(&entry.input_fingerprint) {
            return Err(invalid_input_fingerprint(&entry.input_fingerprint));
        }
        let expected_seq = u64::try_from(entries.len()).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("ledger {} sequence exceeds u64: {error}", path.display()),
                "preserve the ledger and repair its sequence representation",
            )
        })?;
        if entry.seq != expected_seq {
            return Err(AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!(
                    "ledger sequence gap at line {}: expected {expected_seq} got {}",
                    line_index + 1,
                    entry.seq
                ),
                "preserve the corrupt ledger and rebuild it through the explicit recovery protocol",
            ));
        }
        if entry.prev_hash != previous_hash {
            return Err(AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!(
                    "ledger chain break at seq {}: prev_hash does not match",
                    entry.seq
                ),
                "preserve the corrupt ledger and rebuild it through the explicit recovery protocol",
            ));
        }
        let card_json = serde_json::to_vec(&entry.card).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("could not re-serialize card at seq {}: {error}", entry.seq),
                "preserve the corrupt ledger and repair the canonical card serializer",
            )
        })?;
        let recomputed = entry_hash(
            entry.seq,
            &entry.prev_hash,
            entry.seed,
            &entry.input_fingerprint,
            &card_json,
        );
        if recomputed != entry.entry_hash {
            return Err(AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("ledger entry hash mismatch at seq {}", entry.seq),
                "preserve the corrupt ledger and rebuild it through the explicit recovery protocol",
            ));
        }
        if let Some(first_seq) = input_identities.insert(entry.input_fingerprint.clone(), entry.seq)
        {
            return Err(input_fingerprint_collision(format!(
                "ledger reuses input fingerprint {} at seq {} after seq {}; every canonical input identity must occur exactly once",
                entry.input_fingerprint, entry.seq, first_seq
            )));
        }
        previous_hash = entry.entry_hash.clone();
        entries.push(ParsedLedgerLine {
            entry,
            offset,
            bytes: line_bytes,
        });
        offset = offset.checked_add(line_bytes).ok_or_else(|| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("ledger {} byte offset exceeded usize", path.display()),
                "preserve the ledger and repair its physical record layout",
            )
        })?;
    }
    Ok(entries)
}

fn physical_line_receipt(bytes: &[u8], parsed: &ParsedLedgerLine) -> Result<AssayCardLineReceipt> {
    let end = parsed.offset.checked_add(parsed.bytes).ok_or_else(|| {
        AssayError::new(
            ASTRO_ASSAY_STORE_CORRUPT,
            "ledger line byte range overflowed usize",
            "preserve the ledger and repair its physical record layout",
        )
    })?;
    let line = bytes.get(parsed.offset..end).ok_or_else(|| {
        AssayError::new(
            ASTRO_ASSAY_STORE_CORRUPT,
            format!(
                "ledger line for seq {} falls outside the physical file",
                parsed.entry.seq
            ),
            "preserve the ledger and repair its physical record layout",
        )
    })?;
    Ok(AssayCardLineReceipt {
        seq: parsed.entry.seq,
        entry_hash: parsed.entry.entry_hash.clone(),
        offset: u64::try_from(parsed.offset).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("ledger line offset cannot be represented as u64: {error}"),
                "preserve the ledger and repair its physical record layout",
            )
        })?,
        bytes: u64::try_from(parsed.bytes).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("ledger line length cannot be represented as u64: {error}"),
                "preserve the ledger and repair its physical record layout",
            )
        })?,
        line_blake3: blake3::hash(line).to_hex().to_string(),
    })
}

/// Computes the content fingerprint of a slot/axis input set.
///
/// Canonical JSON of the ordered inputs is hashed, so two callers that assemble
/// the same observations produce the same fingerprint. Fails closed if the inputs
/// cannot be serialized.
pub fn input_fingerprint(slots: &[SlotObservations], axis: &AxisValues) -> Result<String> {
    let bytes = serde_json::to_vec(&(slots, axis)).map_err(|error| {
        AssayError::new(
            ASTRO_ASSAY_STORE_CORRUPT,
            format!("could not serialize measurement inputs: {error}"),
            "this is an internal serialization fault; report it with the failing inputs",
        )
    })?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(ASSAY_LEDGER_TAG.as_bytes());
    hasher.update(b"inputs");
    hasher.update(&bytes);
    Ok(hasher.finalize().to_hex().to_string())
}

fn entry_hash(
    seq: u64,
    prev_hash: &str,
    seed: u64,
    input_fingerprint: &str,
    card_json: &[u8],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ASSAY_LEDGER_TAG.as_bytes());
    hasher.update(&seq.to_le_bytes());
    hasher.update(prev_hash.as_bytes());
    hasher.update(&seed.to_le_bytes());
    hasher.update(input_fingerprint.as_bytes());
    hasher.update(card_json);
    hasher.finalize().to_hex().to_string()
}

/// A filesystem-backed, append-only assay card ledger.
#[derive(Debug, Clone)]
pub struct CardLedger {
    path: PathBuf,
}

impl PreparedAssayCardBatch {
    /// Physical append-only ledger path retained by this prepared batch.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Publish the prepared bytes once, force file content and metadata to disk,
    /// then re-read and chain-verify the complete file through the retained lock.
    pub fn publish(mut self) -> Result<AssayCardBatchReceipt> {
        let idempotent_replay = self.append_bytes.is_empty();
        let outcome = (|| {
            if !self.append_bytes.is_empty() {
                self.file.write_all(&self.append_bytes).map_err(|error| {
                    AssayError::new(
                        ASTRO_ASSAY_STORE_IO,
                        format!(
                            "could not append prepared batch to {}: {error}",
                            self.path.display()
                        ),
                        "preserve the prepared marker and ledger bytes; diagnose the exact append failure before recovery",
                    )
                })?;
                self.file.sync_all().map_err(|error| {
                    AssayError::new(
                        ASTRO_ASSAY_STORE_IO,
                        format!(
                            "could not sync prepared ledger batch {}: {error}",
                            self.path.display()
                        ),
                        "preserve the prepared marker and ledger bytes; diagnose the filesystem durability failure before recovery",
                    )
                })?;
            }

            self.file.seek(SeekFrom::Start(0)).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!(
                        "could not seek ledger {} for batch readback: {error}",
                        self.path.display()
                    ),
                    "preserve the prepared marker and ledger bytes; inspect the retained file handle",
                )
            })?;
            let mut readback = Vec::new();
            self.file.read_to_end(&mut readback).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!(
                        "could not read ledger {} after batch append: {error}",
                        self.path.display()
                    ),
                    "preserve the prepared marker and ledger bytes; inspect the physical ledger before recovery",
                )
            })?;
            let parsed = parse_ledger_bytes(&self.path, &readback)?;
            if self.entries.len() != self.lines.len() {
                return Err(AssayError::new(
                    ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                    "prepared ledger entry and line-receipt counts differ",
                    "preserve the prepared marker and repair the immutable batch plan",
                ));
            }
            for (expected_entry, expected_line) in self.entries.iter().zip(&self.lines) {
                let position = usize::try_from(expected_entry.seq).map_err(|error| {
                    AssayError::new(
                        ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                        format!("ledger sequence cannot index the readback: {error}"),
                        "preserve the prepared marker and repair the sequence representation",
                    )
                })?;
                let observed = parsed.get(position).ok_or_else(|| {
                    AssayError::new(
                        ASTRO_ASSAY_READBACK_MISMATCH,
                        format!(
                            "ledger readback has no entry at prepared sequence {}",
                            expected_entry.seq
                        ),
                        "preserve the prepared marker and incomplete ledger; use the explicit recovery protocol",
                    )
                })?;
                if observed.entry != *expected_entry
                    || physical_line_receipt(&readback, observed)? != *expected_line
                {
                    return Err(AssayError::new(
                        ASTRO_ASSAY_READBACK_MISMATCH,
                        format!(
                            "ledger sequence {} differs from its prepared entry or physical line receipt",
                            expected_entry.seq
                        ),
                        "preserve the prepared marker and divergent ledger; use the explicit recovery protocol",
                    ));
                }
            }
            Ok(AssayCardBatchReceipt {
                entries: self.entries.clone(),
                lines: self.lines.clone(),
                file_bytes: u64::try_from(readback.len()).map_err(|error| {
                    AssayError::new(
                        ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                        format!("ledger readback length cannot be represented as u64: {error}"),
                        "preserve the ledger and repair its physical size representation",
                    )
                })?,
                file_blake3: blake3::hash(&readback).to_hex().to_string(),
                idempotent_replay,
            })
        })();

        let unlock = self.file.unlock();
        match (outcome, unlock) {
            (Ok(receipt), Ok(())) => Ok(receipt),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(unlock_error)) => Err(AssayError::new(
                ASTRO_ASSAY_STORE_IO,
                format!(
                    "published ledger {} but could not release its exact file lock: {unlock_error}",
                    self.path.display()
                ),
                "preserve the committed bytes and inspect the exact process/file-lock state before continuing",
            )),
            (Err(error), Err(unlock_error)) => Err(AssayError::new(
                ASTRO_ASSAY_STORE_IO,
                format!(
                    "{error}; additionally could not release ledger lock {}: {unlock_error}",
                    self.path.display()
                ),
                "preserve the prepared marker and ledger bytes; inspect the exact process/file-lock state before recovery",
            )),
        }
    }
}

impl CardLedger {
    /// Opens (creating the parent directory if needed) a ledger at `path`.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!("could not create ledger dir {}: {error}", parent.display()),
                    "ensure the ledger root is writable before appending cards",
                )
            })?;
        }
        Ok(Self { path })
    }

    /// Reads and chain-verifies every ledgered entry, in sequence order.
    ///
    /// A broken chain (a `prev_hash` that does not match the prior entry's
    /// `entry_hash`, a recomputed hash that does not match, or a sequence gap)
    /// fails closed rather than being served.
    pub fn read_all(&self) -> Result<Vec<AssayCardEntry>> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!("could not read ledger {}: {error}", self.path.display()),
                    "check the ledger filesystem before retrying",
                ));
            }
        };
        Ok(parse_ledger_bytes(&self.path, &bytes)?
            .into_iter()
            .map(|line| line.entry)
            .collect())
    }

    /// Prepare one append-only batch while retaining an exclusive OS file lock.
    ///
    /// The existing chain is read and verified once. A caller may persist its
    /// database-side prepared marker from the public metadata on the returned
    /// value while the lock remains held, then consume it with `publish`.
    pub fn prepare_batch(
        &self,
        requests: &[AssayCardAppendRequest],
    ) -> Result<PreparedAssayCardBatch> {
        // Request-only validation must complete before opening the ledger with
        // `create(true)`: a malformed batch is a pre-I/O refusal and must not
        // materialize a durable ledger path.
        let mut request_identities = BTreeMap::new();
        for (ordinal, request) in requests.iter().enumerate() {
            if !valid_input_fingerprint(&request.input_fingerprint) {
                return Err(invalid_input_fingerprint(&request.input_fingerprint));
            }
            if let Some(first_ordinal) =
                request_identities.insert(request.input_fingerprint.as_str(), ordinal)
            {
                return Err(input_fingerprint_collision(format!(
                    "batch request repeats input fingerprint {} at ordinal {ordinal} after ordinal {first_ordinal}",
                    request.input_fingerprint
                )));
            }
        }

        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(&self.path)
            .map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!(
                        "could not open ledger {} for locked batch append: {error}",
                        self.path.display()
                    ),
                    "ensure the ledger file is readable and writable before preparing the transaction",
                )
            })?;
        file.lock().map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_IO,
                format!(
                    "could not lock ledger {} for batch append: {error}",
                    self.path.display()
                ),
                "wait for the exact current ledger owner to finish, then retry the unchanged transaction",
            )
        })?;

        let prepared = (|| {
            file.seek(SeekFrom::Start(0)).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!(
                        "could not seek locked ledger {}: {error}",
                        self.path.display()
                    ),
                    "preserve the ledger and inspect its filesystem handle before retrying",
                )
            })?;
            let mut physical = Vec::new();
            file.read_to_end(&mut physical).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!(
                        "could not read locked ledger {}: {error}",
                        self.path.display()
                    ),
                    "preserve the ledger and inspect its filesystem state before retrying",
                )
            })?;
            let parsed = parse_ledger_bytes(&self.path, &physical)?;

            let mut existing_positions = Vec::with_capacity(requests.len());
            for request in requests {
                let position = parsed
                    .iter()
                    .position(|line| line.entry.input_fingerprint == request.input_fingerprint);
                if let Some(position) = position {
                    let existing = &parsed[position].entry;
                    if existing.seed != request.seed || existing.card != request.card {
                        return Err(input_fingerprint_collision(format!(
                            "input fingerprint {} already identifies seq {} with different seed/card bytes",
                            request.input_fingerprint, existing.seq
                        )));
                    }
                }
                existing_positions.push(position);
            }
            let present = existing_positions.iter().flatten().count();
            if present != 0 && present != requests.len() {
                return Err(AssayError::new(
                    ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                    format!(
                        "ledger {} contains {present}/{} entries from one requested batch",
                        self.path.display(),
                        requests.len()
                    ),
                    "preserve the prepared marker and partial ledger; diagnose the interrupted append before any new transaction",
                ));
            }

            if present == requests.len() && !requests.is_empty() {
                let mut positions = Vec::new();
                positions.try_reserve_exact(existing_positions.len()).map_err(|error| {
                    AssayError::new(
                        ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                        format!("could not reserve idempotent batch positions: {error}"),
                        "reduce the requested batch only at the producer's deterministic partition boundary",
                    )
                })?;
                for position in existing_positions {
                    let position = position.ok_or_else(|| {
                        AssayError::new(
                            ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                            "ledger present-count invariant disagreed with an idempotent batch position",
                            "preserve the ledger and prepared marker; inspect the exact batch identity",
                        )
                    })?;
                    positions.push(position);
                }
                let first = positions.first().copied().ok_or_else(|| {
                    AssayError::new(
                        ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                        "non-empty idempotent batch produced no ledger positions",
                        "preserve the ledger and prepared marker; inspect the exact batch identity",
                    )
                })?;
                let end = first.checked_add(positions.len()).ok_or_else(|| {
                    AssayError::new(
                        ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                        "idempotent ledger batch range exceeded usize",
                        "preserve the ledger and repair its physical sequence representation",
                    )
                })?;
                if positions.iter().copied().ne(first..end) || end != parsed.len() {
                    return Err(AssayError::new(
                        ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                        "idempotent batch entries are not one contiguous ledger tail",
                        "preserve the ledger and prepared marker; only the exact terminal batch tail can resume",
                    ));
                }
                let prefix_bytes = parsed[first].offset;
                let mut entries = Vec::with_capacity(positions.len());
                let mut lines = Vec::with_capacity(positions.len());
                for position in positions {
                    entries.push(parsed[position].entry.clone());
                    lines.push(physical_line_receipt(&physical, &parsed[position])?);
                }
                return Ok((
                    entries,
                    lines,
                    prefix_bytes,
                    Vec::new(),
                    blake3::hash(&physical[..prefix_bytes]).to_hex().to_string(),
                ));
            }

            let mut entries = Vec::with_capacity(requests.len());
            let mut lines = Vec::with_capacity(requests.len());
            let mut append_bytes = Vec::new();
            let mut sequence = u64::try_from(parsed.len()).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                    format!("ledger sequence cannot be represented as u64: {error}"),
                    "preserve the ledger and repair its sequence representation",
                )
            })?;
            let mut previous_hash = parsed
                .last()
                .map(|line| line.entry.entry_hash.clone())
                .unwrap_or_else(|| GENESIS_PREV_HASH.to_string());
            for request in requests {
                let card_json = serde_json::to_vec(&request.card).map_err(|error| {
                    AssayError::new(
                        ASTRO_ASSAY_STORE_CORRUPT,
                        format!("could not serialize card for ledger batch: {error}"),
                        "repair the canonical card serializer before retrying",
                    )
                })?;
                let hash = entry_hash(
                    sequence,
                    &previous_hash,
                    request.seed,
                    &request.input_fingerprint,
                    &card_json,
                );
                let entry = AssayCardEntry {
                    seq: sequence,
                    prev_hash: previous_hash,
                    entry_hash: hash,
                    seed: request.seed,
                    input_fingerprint: request.input_fingerprint.clone(),
                    card: request.card.clone(),
                };
                let mut line = serde_json::to_vec(&entry).map_err(|error| {
                    AssayError::new(
                        ASTRO_ASSAY_STORE_CORRUPT,
                        format!("could not serialize ledger batch entry: {error}"),
                        "repair the canonical ledger serializer before retrying",
                    )
                })?;
                line.push(b'\n');
                let offset = physical
                    .len()
                    .checked_add(append_bytes.len())
                    .ok_or_else(|| {
                        AssayError::new(
                            ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                            "ledger append offset exceeded usize",
                            "preserve the ledger and repair its physical size representation",
                        )
                    })?;
                lines.push(AssayCardLineReceipt {
                    seq: entry.seq,
                    entry_hash: entry.entry_hash.clone(),
                    offset: u64::try_from(offset).map_err(|error| {
                        AssayError::new(
                            ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                            format!("ledger append offset cannot be represented as u64: {error}"),
                            "preserve the ledger and repair its physical size representation",
                        )
                    })?,
                    bytes: u64::try_from(line.len()).map_err(|error| {
                        AssayError::new(
                            ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                            format!("ledger line length cannot be represented as u64: {error}"),
                            "preserve the ledger and repair its physical size representation",
                        )
                    })?,
                    line_blake3: blake3::hash(&line).to_hex().to_string(),
                });
                append_bytes.extend_from_slice(&line);
                previous_hash = entry.entry_hash.clone();
                entries.push(entry);
                sequence = sequence.checked_add(1).ok_or_else(|| {
                    AssayError::new(
                        ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                        "ledger sequence exceeded u64 while preparing a batch",
                        "preserve the ledger and repair its sequence representation",
                    )
                })?;
            }
            Ok((
                entries,
                lines,
                physical.len(),
                append_bytes,
                blake3::hash(&physical).to_hex().to_string(),
            ))
        })();

        match prepared {
            Ok((entries, lines, prior_file_bytes, append_bytes, prior_file_blake3)) => {
                Ok(PreparedAssayCardBatch {
                    file,
                    path: self.path.clone(),
                    append_bytes,
                    entries,
                    lines,
                    prior_file_bytes: u64::try_from(prior_file_bytes).map_err(|error| {
                        AssayError::new(
                            ASTRO_ASSAY_LEDGER_BATCH_STATE_INVALID,
                            format!("ledger prefix cannot be represented as u64: {error}"),
                            "preserve the ledger and repair its physical size representation",
                        )
                    })?,
                    prior_file_blake3,
                })
            }
            Err(error) => {
                let unlock = file.unlock();
                if let Err(unlock_error) = unlock {
                    return Err(AssayError::new(
                        ASTRO_ASSAY_STORE_IO,
                        format!(
                            "{}; additionally could not unlock ledger {}: {unlock_error}",
                            error,
                            self.path.display()
                        ),
                        "preserve the ledger and inspect the exact file-lock owner before retrying",
                    ));
                }
                Err(error)
            }
        }
    }

    /// Appends a card through the same lock-bound, synced batch transaction used
    /// by multi-card publication and proves the physical readback.
    pub fn append(
        &self,
        card: &SignalRankingCard,
        seed: u64,
        input_fingerprint: &str,
    ) -> Result<AssayCardEntry> {
        let request = AssayCardAppendRequest {
            card: card.clone(),
            seed,
            input_fingerprint: input_fingerprint.to_string(),
        };
        let receipt = self.prepare_batch(&[request])?.publish()?;
        receipt.entries.into_iter().next().ok_or_else(|| {
            AssayError::new(
                ASTRO_ASSAY_READBACK_MISMATCH,
                "single-card batch returned no durable entry",
                "preserve the ledger and inspect the batch publication receipt",
            )
        })
    }

    /// Re-derives the card at `seq` from its recorded seed and the supplied inputs
    /// and asserts the result matches the ledgered card bit-for-bit.
    ///
    /// The supplied inputs must fingerprint to the value recorded in the entry
    /// (so the same observations are being reproduced), and the re-derived card
    /// must equal the ledgered one. Because every stochastic step is seeded, the
    /// match is exact, not merely within tolerance. Returns the re-derived card.
    pub fn reproduce(
        &self,
        seq: u64,
        slots: &[SlotObservations],
        axis: &AxisValues,
        cfg: &BitsConfig,
    ) -> Result<SignalRankingCard> {
        let entries = self.read_all()?;
        let entry = entries.get(seq as usize).ok_or_else(|| {
            AssayError::new(
                ASTRO_ASSAY_REPRODUCE_MISMATCH,
                format!("no ledger entry at seq {seq}"),
                "reproduce an entry that exists in the ledger",
            )
        })?;
        let fp = input_fingerprint(slots, axis)?;
        if fp != entry.input_fingerprint {
            return Err(AssayError::new(
                ASTRO_ASSAY_REPRODUCE_MISMATCH,
                format!(
                    "reproduce inputs fingerprint {fp} does not match ledgered {}",
                    entry.input_fingerprint
                ),
                "reproduce with the exact observations the card was measured over",
            ));
        }
        let rederived =
            build_signal_ranking(entry.card.axis.clone(), slots, axis, entry.seed, cfg)?;
        if rederived != entry.card {
            return Err(AssayError::new(
                ASTRO_ASSAY_REPRODUCE_MISMATCH,
                format!("re-derived card at seq {seq} did not match the ledgered card"),
                "the measurement is not reproducible from its recorded seed and inputs; investigate non-determinism",
            ));
        }
        Ok(rederived)
    }
}
