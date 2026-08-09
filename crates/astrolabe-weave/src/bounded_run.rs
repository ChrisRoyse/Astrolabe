//! Durable, hash-bound sorted spill runs for bounded weave reconciliation.
//!
//! The run is an ephemeral stage artifact, not a second source of truth. A
//! producer writes strictly increasing key/value frames, seals the count/byte
//! totals and BLAKE3 digest into the file, flushes it durably, and publishes a
//! small manifest that binds every run to the exact source generation. A
//! consumer must stream every frame and validate the trailer before the
//! workspace may remove its exact manifest-listed files. Any mismatch leaves
//! the unpublished workspace intact for diagnosis.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use calyx_core::{CalyxError, Result};
use serde::{Deserialize, Serialize};

pub(crate) const ASTRO_WEAVE_RUN_INVALID: &str = "ASTRO_WEAVE_RUN_INVALID";
pub(crate) const ASTRO_WEAVE_RUN_RESOURCE_EXHAUSTED: &str = "ASTRO_WEAVE_RUN_RESOURCE_EXHAUSTED";

pub(crate) const MAX_MUTATION_ROWS_PER_COMMIT: usize = 50_000;
pub(crate) const MAX_MUTATION_BYTES_PER_COMMIT: usize = 8 * 1024 * 1024;

const RUN_MAGIC: &[u8; 8] = b"ASTRUN01";
const RECORD_TAG: u8 = 1;
const TRAILER_TAG: u8 = 0;
const RUN_HASH_DOMAIN: &[u8] = b"astrolabe.weave.sorted-run.v1";
const MANIFEST_SCHEMA: &str = "astrolabe.weave.sorted-run-manifest.v1";
const MANIFEST_FILE: &str = "manifest.json";
const RUN_REMEDIATION: &str = "preserve the unpublished shadow generation and inspect the exact run path, source binding, frame order, trailer, and manifest before starting a fresh generation";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RunReceipt {
    pub file_name: String,
    pub record_count: u64,
    pub content_bytes: u64,
    pub file_bytes: u64,
    pub content_blake3: String,
    pub max_record_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RunManifest {
    pub schema: String,
    pub scope: String,
    pub source_binding: String,
    pub runs: Vec<RunReceipt>,
}

pub(crate) struct SortedRunWriter {
    file_name: String,
    writer: BufWriter<File>,
    hasher: blake3::Hasher,
    last_key: Option<Vec<u8>>,
    record_count: u64,
    content_bytes: u64,
    max_record_bytes: u64,
}

impl SortedRunWriter {
    fn create(path: &Path, file_name: String, max_record_bytes: u64) -> Result<Self> {
        if max_record_bytes == 0 {
            return Err(run_invalid(format!(
                "run {file_name:?} requested a zero record-byte limit"
            )));
        }
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(path)
            .map_err(|error| run_io("create", path, error))?;
        let mut writer = BufWriter::new(file);
        writer
            .write_all(RUN_MAGIC)
            .map_err(|error| run_io("write header", path, error))?;
        let hasher = run_content_hasher();
        Ok(Self {
            file_name,
            writer,
            hasher,
            last_key: None,
            record_count: 0,
            content_bytes: 0,
            max_record_bytes,
        })
    }

    pub(crate) fn push(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if self.last_key.as_deref().is_some_and(|last| last >= key) {
            return Err(run_invalid(format!(
                "run {:?} received a non-increasing or duplicate key after record {}",
                self.file_name, self.record_count
            )));
        }
        let key_len = u32::try_from(key.len()).map_err(|_| {
            run_resource_exhausted(format!(
                "run {:?} key length {} exceeds the u32 frame format",
                self.file_name,
                key.len()
            ))
        })?;
        let value_len = u32::try_from(value.len()).map_err(|_| {
            run_resource_exhausted(format!(
                "run {:?} value length {} exceeds the u32 frame format",
                self.file_name,
                value.len()
            ))
        })?;
        let record_bytes = (key.len() as u64)
            .checked_add(value.len() as u64)
            .ok_or_else(|| run_resource_exhausted("run record byte count overflow"))?;
        if record_bytes > self.max_record_bytes {
            return Err(run_resource_exhausted(format!(
                "run {:?} record {} retains {record_bytes} bytes, exceeding its source-bound limit {}",
                self.file_name, self.record_count, self.max_record_bytes
            )));
        }

        self.writer
            .write_all(&[RECORD_TAG])
            .and_then(|()| self.writer.write_all(&key_len.to_be_bytes()))
            .and_then(|()| self.writer.write_all(&value_len.to_be_bytes()))
            .and_then(|()| self.writer.write_all(key))
            .and_then(|()| self.writer.write_all(value))
            .map_err(|error| {
                run_invalid(format!(
                    "write run {:?} record {}: {error}",
                    self.file_name, self.record_count
                ))
            })?;
        update_run_content_hash(&mut self.hasher, key, value);
        self.last_key = Some(key.to_vec());
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or_else(|| run_resource_exhausted("run record count overflow"))?;
        self.content_bytes = self
            .content_bytes
            .checked_add(record_bytes)
            .ok_or_else(|| run_resource_exhausted("run content byte count overflow"))?;
        Ok(())
    }

    pub(crate) fn finish(mut self, path: &Path) -> Result<RunReceipt> {
        let digest = self.hasher.finalize();
        self.writer
            .write_all(&[TRAILER_TAG])
            .and_then(|()| self.writer.write_all(&self.record_count.to_be_bytes()))
            .and_then(|()| self.writer.write_all(&self.content_bytes.to_be_bytes()))
            .and_then(|()| self.writer.write_all(digest.as_bytes()))
            .and_then(|()| self.writer.flush())
            .map_err(|error| run_io("seal", path, error))?;
        let file = self.writer.into_inner().map_err(|error| {
            run_io(
                "release buffered writer",
                path,
                std::io::Error::new(error.error().kind(), error.error().to_string()),
            )
        })?;
        file.sync_all()
            .map_err(|error| run_io("sync sealed", path, error))?;
        let file_bytes = file
            .metadata()
            .map_err(|error| run_io("stat sealed", path, error))?
            .len();
        Ok(RunReceipt {
            file_name: self.file_name,
            record_count: self.record_count,
            content_bytes: self.content_bytes,
            file_bytes,
            content_blake3: digest.to_hex().to_string(),
            max_record_bytes: self.max_record_bytes,
        })
    }
}

pub(crate) struct SortedRunReader {
    path: PathBuf,
    receipt: RunReceipt,
    reader: BufReader<File>,
    hasher: blake3::Hasher,
    last_key: Option<Vec<u8>>,
    record_count: u64,
    content_bytes: u64,
    terminal_verified: bool,
}

impl SortedRunReader {
    pub(crate) fn open(directory: &Path, receipt: &RunReceipt) -> Result<Self> {
        validate_file_name(&receipt.file_name)?;
        let path = directory.join(&receipt.file_name);
        let file = File::open(&path).map_err(|error| run_io("open for readback", &path, error))?;
        let observed_len = file
            .metadata()
            .map_err(|error| run_io("stat for readback", &path, error))?
            .len();
        if observed_len != receipt.file_bytes {
            return Err(run_invalid(format!(
                "run {:?} length drifted: manifest={}, observed={observed_len}",
                receipt.file_name, receipt.file_bytes
            )));
        }
        let mut reader = BufReader::new(file);
        let mut magic = [0u8; RUN_MAGIC.len()];
        reader
            .read_exact(&mut magic)
            .map_err(|error| run_io("read header", &path, error))?;
        if &magic != RUN_MAGIC {
            return Err(run_invalid(format!(
                "run {:?} has an invalid header",
                receipt.file_name
            )));
        }
        let hasher = run_content_hasher();
        Ok(Self {
            path,
            receipt: receipt.clone(),
            reader,
            hasher,
            last_key: None,
            record_count: 0,
            content_bytes: 0,
            terminal_verified: false,
        })
    }

    pub(crate) fn next_record(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        if self.terminal_verified {
            return Ok(None);
        }
        let mut tag = [0u8; 1];
        self.reader
            .read_exact(&mut tag)
            .map_err(|error| run_io("read frame tag", &self.path, error))?;
        match tag[0] {
            RECORD_TAG => self.read_record().map(Some),
            TRAILER_TAG => {
                self.read_and_verify_trailer()?;
                Ok(None)
            }
            other => Err(run_invalid(format!(
                "run {:?} contains unknown frame tag {other} after {} records",
                self.receipt.file_name, self.record_count
            ))),
        }
    }

    fn read_record(&mut self) -> Result<(Vec<u8>, Vec<u8>)> {
        let key_len = read_u32(&mut self.reader, &self.path, "key length")? as usize;
        let value_len = read_u32(&mut self.reader, &self.path, "value length")? as usize;
        let record_bytes = (key_len as u64)
            .checked_add(value_len as u64)
            .ok_or_else(|| run_resource_exhausted("run readback record byte count overflow"))?;
        if record_bytes > self.receipt.max_record_bytes {
            return Err(run_resource_exhausted(format!(
                "run {:?} frame {} declares {record_bytes} bytes, exceeding the manifest limit {}",
                self.receipt.file_name, self.record_count, self.receipt.max_record_bytes
            )));
        }
        let mut key = Vec::new();
        key.try_reserve_exact(key_len).map_err(|error| {
            run_resource_exhausted(format!(
                "reserve {key_len} key bytes for run {:?} frame {}: {error}",
                self.receipt.file_name, self.record_count
            ))
        })?;
        key.resize(key_len, 0);
        let mut value = Vec::new();
        value.try_reserve_exact(value_len).map_err(|error| {
            run_resource_exhausted(format!(
                "reserve {value_len} value bytes for run {:?} frame {}: {error}",
                self.receipt.file_name, self.record_count
            ))
        })?;
        value.resize(value_len, 0);
        self.reader
            .read_exact(&mut key)
            .and_then(|()| self.reader.read_exact(&mut value))
            .map_err(|error| run_io("read record payload", &self.path, error))?;
        if self
            .last_key
            .as_deref()
            .is_some_and(|last| last >= key.as_slice())
        {
            return Err(run_invalid(format!(
                "run {:?} readback is not strictly key-ordered at frame {}",
                self.receipt.file_name, self.record_count
            )));
        }
        update_run_content_hash(&mut self.hasher, &key, &value);
        self.last_key = Some(key.clone());
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or_else(|| run_resource_exhausted("run readback record count overflow"))?;
        self.content_bytes = self
            .content_bytes
            .checked_add(record_bytes)
            .ok_or_else(|| run_resource_exhausted("run readback content byte count overflow"))?;
        Ok((key, value))
    }

    fn read_and_verify_trailer(&mut self) -> Result<()> {
        let trailer_count = read_u64(&mut self.reader, &self.path, "trailer record count")?;
        let trailer_bytes = read_u64(&mut self.reader, &self.path, "trailer content bytes")?;
        let mut trailer_digest = [0u8; 32];
        self.reader
            .read_exact(&mut trailer_digest)
            .map_err(|error| run_io("read trailer digest", &self.path, error))?;
        let mut extra = [0u8; 1];
        let extra_len = self
            .reader
            .read(&mut extra)
            .map_err(|error| run_io("read trailer EOF", &self.path, error))?;
        let digest = self.hasher.finalize().to_hex().to_string();
        if trailer_count != self.record_count
            || trailer_bytes != self.content_bytes
            || trailer_digest != *self.hasher.finalize().as_bytes()
            || self.record_count != self.receipt.record_count
            || self.content_bytes != self.receipt.content_bytes
            || digest != self.receipt.content_blake3
            || extra_len != 0
        {
            return Err(run_invalid(format!(
                "run {:?} trailer/readback mismatch: manifest_count={}, observed_count={}, trailer_count={trailer_count}, manifest_bytes={}, observed_bytes={}, trailer_bytes={trailer_bytes}, manifest_hash={}, observed_hash={digest}, trailing_bytes={extra_len}",
                self.receipt.file_name,
                self.receipt.record_count,
                self.record_count,
                self.receipt.content_bytes,
                self.content_bytes,
                self.receipt.content_blake3,
            )));
        }
        self.terminal_verified = true;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<RunReceipt> {
        if !self.terminal_verified {
            return Err(run_invalid(format!(
                "run {:?} was not consumed through its verified trailer",
                self.receipt.file_name
            )));
        }
        Ok(self.receipt)
    }
}

pub(crate) struct RunWorkspace {
    directory: PathBuf,
    scope: String,
    source_binding: String,
    manifest: Option<RunManifest>,
    manifest_bytes: Option<Vec<u8>>,
    consumed: BTreeSet<String>,
}

impl RunWorkspace {
    pub(crate) fn create(
        directory: impl Into<PathBuf>,
        scope: impl Into<String>,
        source_binding: impl Into<String>,
    ) -> Result<Self> {
        let directory = directory.into();
        match directory.try_exists() {
            Ok(false) => {}
            Ok(true) => {
                return Err(run_invalid(format!(
                    "run workspace {} already exists; ordinary admission never overwrites preserved run state",
                    directory.display()
                )));
            }
            Err(error) => return Err(run_io("probe workspace", &directory, error)),
        }
        fs::create_dir(&directory)
            .map_err(|error| run_io("create workspace", &directory, error))?;
        Ok(Self {
            directory,
            scope: scope.into(),
            source_binding: source_binding.into(),
            manifest: None,
            manifest_bytes: None,
            consumed: BTreeSet::new(),
        })
    }

    pub(crate) fn directory(&self) -> &Path {
        &self.directory
    }

    pub(crate) fn writer(&self, file_name: &str, max_record_bytes: u64) -> Result<SortedRunWriter> {
        if self.manifest.is_some() {
            return Err(run_invalid(format!(
                "run workspace {} is already sealed",
                self.directory.display()
            )));
        }
        validate_file_name(file_name)?;
        SortedRunWriter::create(
            &self.directory.join(file_name),
            file_name.to_string(),
            max_record_bytes,
        )
    }

    pub(crate) fn seal(&mut self, mut runs: Vec<RunReceipt>) -> Result<RunManifest> {
        if self.manifest.is_some() {
            return Err(run_invalid(format!(
                "run workspace {} was sealed more than once",
                self.directory.display()
            )));
        }
        runs.sort_by(|left, right| left.file_name.cmp(&right.file_name));
        if runs.is_empty()
            || runs
                .windows(2)
                .any(|pair| pair[0].file_name == pair[1].file_name)
        {
            return Err(run_invalid(
                "run manifest requires a non-empty set of unique run files",
            ));
        }
        for run in &runs {
            validate_file_name(&run.file_name)?;
        }
        let manifest = RunManifest {
            schema: MANIFEST_SCHEMA.to_string(),
            scope: self.scope.clone(),
            source_binding: self.source_binding.clone(),
            runs,
        };
        let bytes = serde_json::to_vec(&manifest).map_err(|error| {
            run_invalid(format!("encode run manifest for {:?}: {error}", self.scope))
        })?;
        let path = self.directory.join(MANIFEST_FILE);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|error| run_io("create manifest", &path, error))?;
        file.write_all(&bytes)
            .and_then(|()| file.flush())
            .map_err(|error| run_io("write manifest", &path, error))?;
        file.sync_all()
            .map_err(|error| run_io("sync manifest", &path, error))?;
        drop(file);
        let readback =
            fs::read(&path).map_err(|error| run_io("read back manifest", &path, error))?;
        if readback != bytes {
            return Err(run_invalid(format!(
                "run manifest {} did not read back byte-identical",
                path.display()
            )));
        }
        let decoded: RunManifest = serde_json::from_slice(&readback).map_err(|error| {
            run_invalid(format!("decode run manifest {}: {error}", path.display()))
        })?;
        if decoded != manifest {
            return Err(run_invalid(format!(
                "run manifest {} semantic readback differs",
                path.display()
            )));
        }
        self.manifest = Some(manifest.clone());
        self.manifest_bytes = Some(bytes);
        Ok(manifest)
    }

    pub(crate) fn open_reader(&self, receipt: &RunReceipt) -> Result<SortedRunReader> {
        let manifest = self.manifest.as_ref().ok_or_else(|| {
            run_invalid(format!(
                "run workspace {} was consumed before its manifest was sealed",
                self.directory.display()
            ))
        })?;
        if !manifest.runs.contains(receipt) {
            return Err(run_invalid(format!(
                "run {:?} is not bound by workspace manifest {}",
                receipt.file_name,
                self.directory.display()
            )));
        }
        SortedRunReader::open(&self.directory, receipt)
    }

    /// Opens a just-sealed run while the workspace manifest is still being
    /// constructed. This is used only to merge bounded producer chunks into the
    /// final desired run; the chunk receipt is subsequently included in the one
    /// immutable manifest and marked consumed before cleanup.
    pub(crate) fn open_unsealed_reader(&self, receipt: &RunReceipt) -> Result<SortedRunReader> {
        if self.manifest.is_some() {
            return Err(run_invalid(format!(
                "run workspace {} cannot use an unsealed reader after manifest publication",
                self.directory.display()
            )));
        }
        SortedRunReader::open(&self.directory, receipt)
    }

    pub(crate) fn mark_consumed(&mut self, receipt: RunReceipt) -> Result<()> {
        let manifest = self.manifest.as_ref().ok_or_else(|| {
            run_invalid(format!(
                "run workspace {} was marked consumed before sealing",
                self.directory.display()
            ))
        })?;
        if !manifest.runs.contains(&receipt) || !self.consumed.insert(receipt.file_name.clone()) {
            return Err(run_invalid(format!(
                "run {:?} was unmanifested or consumed more than once",
                receipt.file_name
            )));
        }
        Ok(())
    }

    pub(crate) fn cleanup(self) -> Result<()> {
        let manifest = self.manifest.as_ref().ok_or_else(|| {
            run_invalid(format!(
                "run workspace {} cannot clean an unsealed generation",
                self.directory.display()
            ))
        })?;
        let expected_runs = manifest
            .runs
            .iter()
            .map(|run| run.file_name.clone())
            .collect::<BTreeSet<_>>();
        if self.consumed != expected_runs {
            return Err(run_invalid(format!(
                "run workspace {} cannot clean before every run is consumed: expected={expected_runs:?}, consumed={:?}",
                self.directory.display(),
                self.consumed
            )));
        }
        let manifest_path = self.directory.join(MANIFEST_FILE);
        let observed_manifest = fs::read(&manifest_path)
            .map_err(|error| run_io("re-read manifest for cleanup", &manifest_path, error))?;
        if Some(&observed_manifest) != self.manifest_bytes.as_ref() {
            return Err(run_invalid(format!(
                "run manifest {} changed before cleanup",
                manifest_path.display()
            )));
        }
        let mut observed = BTreeSet::new();
        for entry in fs::read_dir(&self.directory)
            .map_err(|error| run_io("inventory workspace", &self.directory, error))?
        {
            let entry =
                entry.map_err(|error| run_io("read workspace entry", &self.directory, error))?;
            let file_type = entry
                .file_type()
                .map_err(|error| run_io("classify workspace entry", &entry.path(), error))?;
            if !file_type.is_file() {
                return Err(run_invalid(format!(
                    "run workspace {} contains non-file entry {}",
                    self.directory.display(),
                    entry.path().display()
                )));
            }
            let name = entry.file_name().into_string().map_err(|_| {
                run_invalid(format!(
                    "run workspace {} contains a non-Unicode file name",
                    self.directory.display()
                ))
            })?;
            observed.insert(name);
        }
        let mut expected = expected_runs.clone();
        expected.insert(MANIFEST_FILE.to_string());
        if observed != expected {
            return Err(run_invalid(format!(
                "run workspace {} inventory mismatch: expected={expected:?}, observed={observed:?}",
                self.directory.display()
            )));
        }
        for name in expected_runs {
            let path = self.directory.join(name);
            fs::remove_file(&path).map_err(|error| run_io("remove consumed run", &path, error))?;
        }
        fs::remove_file(&manifest_path)
            .map_err(|error| run_io("remove consumed manifest", &manifest_path, error))?;
        fs::remove_dir(&self.directory)
            .map_err(|error| run_io("remove empty workspace", &self.directory, error))?;
        if self
            .directory
            .try_exists()
            .map_err(|error| run_io("read back workspace absence", &self.directory, error))?
        {
            return Err(run_invalid(format!(
                "run workspace {} remained present after exact cleanup",
                self.directory.display()
            )));
        }
        Ok(())
    }
}

pub(crate) fn run_content_hasher() -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RUN_HASH_DOMAIN);
    hasher
}

pub(crate) fn update_run_content_hash(hasher: &mut blake3::Hasher, key: &[u8], value: &[u8]) {
    hasher.update(&(key.len() as u64).to_be_bytes());
    hasher.update(key);
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn read_u32(reader: &mut impl Read, path: &Path, field: &str) -> Result<u32> {
    let mut bytes = [0u8; 4];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| run_io(&format!("read {field}"), path, error))?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64(reader: &mut impl Read, path: &Path, field: &str) -> Result<u64> {
    let mut bytes = [0u8; 8];
    reader
        .read_exact(&mut bytes)
        .map_err(|error| run_io(&format!("read {field}"), path, error))?;
    Ok(u64::from_be_bytes(bytes))
}

fn validate_file_name(file_name: &str) -> Result<()> {
    let path = Path::new(file_name);
    if file_name.is_empty()
        || file_name == MANIFEST_FILE
        || path.components().count() != 1
        || path.file_name().and_then(|name| name.to_str()) != Some(file_name)
    {
        return Err(run_invalid(format!(
            "run file name {file_name:?} is not one ordinary workspace child"
        )));
    }
    Ok(())
}

fn run_resource_exhausted(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: ASTRO_WEAVE_RUN_RESOURCE_EXHAUSTED,
        message: message.into(),
        remediation: RUN_REMEDIATION,
    }
}

fn run_invalid(message: impl Into<String>) -> CalyxError {
    CalyxError {
        code: ASTRO_WEAVE_RUN_INVALID,
        message: message.into(),
        remediation: RUN_REMEDIATION,
    }
}

fn run_io(action: &str, path: &Path, error: std::io::Error) -> CalyxError {
    run_invalid(format!("{action} {}: {error}", path.display()))
}
