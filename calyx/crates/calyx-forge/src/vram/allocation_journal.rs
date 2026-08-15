//! Durable append-only journal for GPU allocation ownership transitions.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{ForgeError, Result};

const JOURNAL_SCHEMA: &str = "calyx.forge.gpu-allocation-journal.v1";
const GENESIS_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const JOURNAL_REMEDIATION: &str = "preserve the allocation, journal, and CUDA process; repair the exact journal I/O or hash-chain fault before retrying the same generation";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
/// Durable identity and physical readback for one allocation decision boundary.
pub struct AllocationJournalEvent {
    /// Lifecycle transition name.
    pub transition: String,
    /// Logical block identifier.
    pub block_id: u64,
    /// Nonzero physical-allocation generation.
    pub allocation_generation: u64,
    /// Allocation owner.
    pub owner: String,
    /// Canonical physical CUDA device UUID.
    pub device_uuid: String,
    /// Exact CUDA device pointer token.
    pub device_ptr: u64,
    /// Physical allocation length.
    pub size_bytes: usize,
    /// Registry state when the event was committed.
    pub state: String,
    /// Underlying operation failure code, when any.
    pub failure_code: Option<String>,
    /// Operation or failure detail.
    pub detail: String,
    /// Device UUID read during the transition, when observable.
    pub observed_device_uuid: Option<String>,
    /// Driver-reported free bytes, when observable.
    pub device_free_bytes: Option<u64>,
    /// Driver-reported total bytes, when observable.
    pub device_total_bytes: Option<u64>,
    /// Exact device-observation failure code, when observation failed.
    pub observation_failure_code: Option<String>,
    /// Exact device-observation failure detail, when observation failed.
    pub observation_failure_detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AllocationJournalEntry {
    schema: String,
    seq: u64,
    previous_sha256: String,
    event: AllocationJournalEvent,
    entry_sha256: String,
}

#[derive(Debug)]
/// Append-only, hash-chained allocation ownership journal.
pub struct AllocationJournal {
    path: PathBuf,
    file: File,
    next_seq: u64,
    head_sha256: String,
    fault: Option<String>,
}

impl AllocationJournal {
    /// Open or create a journal and stream-validate every existing record.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.as_os_str().is_empty() {
            return Err(journal_error(&path, "journal path is empty"));
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|error| {
                journal_error(
                    &path,
                    format!("create journal parent {} failed: {error}", parent.display()),
                )
            })?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .map_err(|error| journal_error(&path, format!("open failed: {error}")))?;
        let (next_seq, head_sha256) = validate_existing(&path, &mut file)?;
        Ok(Self {
            path,
            file,
            next_seq,
            head_sha256,
            fault: None,
        })
    }

    /// Return the journal source-of-truth path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Return the sequence that the next append must use.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// Return the current terminal entry digest or the genesis digest.
    pub fn head_sha256(&self) -> &str {
        &self.head_sha256
    }

    /// Durably append and independently read back one allocation transition.
    pub fn append(&mut self, event: AllocationJournalEvent) -> Result<()> {
        if let Some(fault) = &self.fault {
            return Err(journal_error(
                &self.path,
                format!("journal is write-poisoned after an ambiguous append: {fault}"),
            ));
        }
        let seq = self.next_seq;
        let next_seq = seq
            .checked_add(1)
            .ok_or_else(|| journal_error(&self.path, "journal sequence overflow before append"))?;
        let previous_sha256 = self.head_sha256.clone();
        let entry_sha256 = entry_sha256(seq, &previous_sha256, &event)?;
        let entry = AllocationJournalEntry {
            schema: JOURNAL_SCHEMA.to_string(),
            seq,
            previous_sha256,
            event,
            entry_sha256: entry_sha256.clone(),
        };
        let mut encoded = serde_json::to_vec(&entry).map_err(|error| {
            journal_error(&self.path, format!("encode seq {seq} failed: {error}"))
        })?;
        encoded.push(b'\n');
        let offset = self
            .file
            .seek(SeekFrom::End(0))
            .map_err(|error| journal_error(&self.path, format!("seek failed: {error}")))?;
        if let Err(error) = self.file.write_all(&encoded) {
            return Err(self.poisoned_append_error(seq, format!("append failed: {error}")));
        }
        if let Err(error) = self.file.sync_all() {
            return Err(
                self.poisoned_append_error(seq, format!("durability flush failed: {error}"))
            );
        }

        let mut readback = vec![0_u8; encoded.len()];
        let mut reader = match File::open(&self.path) {
            Ok(reader) => reader,
            Err(error) => {
                return Err(
                    self.poisoned_append_error(seq, format!("readback open failed: {error}"))
                );
            }
        };
        if let Err(error) = reader
            .seek(SeekFrom::Start(offset))
            .and_then(|_| reader.read_exact(&mut readback))
        {
            return Err(self.poisoned_append_error(seq, format!("readback failed: {error}")));
        }
        if readback != encoded {
            return Err(self.poisoned_append_error(
                seq,
                format!(
                    "append readback mismatch at seq {seq}: expected_bytes={} observed_bytes={}",
                    encoded.len(),
                    readback.len()
                ),
            ));
        }
        self.next_seq = next_seq;
        self.head_sha256 = entry_sha256;
        Ok(())
    }

    fn poisoned_append_error(&mut self, seq: u64, detail: String) -> ForgeError {
        let fault = format!("seq={seq} {detail}");
        self.fault = Some(fault.clone());
        journal_error(
            &self.path,
            format!("{fault}; no later append is permitted until reopen validates exact bytes"),
        )
    }
}

fn validate_existing(path: &Path, file: &mut File) -> Result<(u64, String)> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| journal_error(path, format!("initial seek failed: {error}")))?;
    let mut reader = BufReader::new(&mut *file);
    let mut expected_seq = 0_u64;
    let mut previous_sha256 = GENESIS_SHA256.to_string();
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line).map_err(|error| {
            journal_error(path, format!("read seq {expected_seq} failed: {error}"))
        })?;
        if read == 0 {
            break;
        }
        if line.last() != Some(&b'\n') {
            return Err(journal_error(
                path,
                "journal ends with a partial record; preserve it for exact recovery",
            ));
        }
        line.pop();
        if line.is_empty() {
            return Err(journal_error(
                path,
                format!("empty record at seq {expected_seq}"),
            ));
        }
        let entry: AllocationJournalEntry = serde_json::from_slice(&line).map_err(|error| {
            journal_error(path, format!("decode seq {expected_seq} failed: {error}"))
        })?;
        if entry.schema != JOURNAL_SCHEMA
            || entry.seq != expected_seq
            || entry.previous_sha256 != previous_sha256
        {
            return Err(journal_error(
                path,
                format!(
                    "chain mismatch at seq {expected_seq}: schema={:?} observed_seq={} previous={:?}",
                    entry.schema, entry.seq, entry.previous_sha256
                ),
            ));
        }
        let expected_sha = entry_sha256(entry.seq, &entry.previous_sha256, &entry.event)?;
        if entry.entry_sha256 != expected_sha {
            return Err(journal_error(
                path,
                format!(
                    "entry digest mismatch at seq {}: expected={} observed={}",
                    entry.seq, expected_sha, entry.entry_sha256
                ),
            ));
        }
        previous_sha256 = entry.entry_sha256;
        expected_seq = expected_seq
            .checked_add(1)
            .ok_or_else(|| journal_error(path, "journal sequence overflow while opening"))?;
    }
    drop(reader);
    file.seek(SeekFrom::End(0))
        .map_err(|error| journal_error(path, format!("terminal seek failed: {error}")))?;
    Ok((expected_seq, previous_sha256))
}

fn entry_sha256(seq: u64, previous_sha256: &str, event: &AllocationJournalEvent) -> Result<String> {
    let canonical =
        serde_json::to_vec(&(JOURNAL_SCHEMA, seq, previous_sha256, event)).map_err(|error| {
            ForgeError::RuntimeBoundary {
                code: "CALYX_FORGE_GPU_ALLOCATION_JOURNAL",
                detail: format!("encode canonical allocation journal identity failed: {error}"),
                remediation: JOURNAL_REMEDIATION,
            }
        })?;
    Ok(hex_lower(&Sha256::digest(canonical)))
}

fn journal_error(path: &Path, detail: impl Into<String>) -> ForgeError {
    ForgeError::RuntimeBoundary {
        code: "CALYX_FORGE_GPU_ALLOCATION_JOURNAL",
        detail: format!("path={} {}", path.display(), detail.into()),
        remediation: JOURNAL_REMEDIATION,
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
