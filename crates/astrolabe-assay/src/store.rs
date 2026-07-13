//! Real filesystem-backed store for sampled results, strata rows, and cache
//! entries, with independent read-back verification (FSV).
//!
//! Persistence is deliberately concrete: every sample writes real bytes to real
//! files under a store root, and the store proves the write by re-reading those
//! bytes through a *fresh* file handle and comparing them to what it intended to
//! write. A writer return value is never treated as evidence — only the
//! read-back bytes are. Two artifacts are written per fingerprint so a reader
//! can verify one against the other:
//!
//! * `<fp>.result.json` — the full [`SampleResult`] blob (the cache entry).
//! * `<fp>.rows.ndjson`  — one [`SelectedSubject`] per line (the assay rows),
//!   written independently so a later reader can confirm the rows in the cache
//!   blob match the rows persisted as their own records.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::{
    ASTRO_ASSAY_READBACK_MISMATCH, ASTRO_ASSAY_STORE_CORRUPT, ASTRO_ASSAY_STORE_IO, AssayError,
    Result,
};
use crate::fingerprint::InputFingerprint;
use crate::strata::{SampleResult, SelectedSubject};

const CACHE_SUBDIR: &str = "cache";
const RESULT_SUFFIX: &str = ".result.json";
const ROWS_SUFFIX: &str = ".rows.ndjson";

/// A store rooted at a real directory on disk.
#[derive(Debug, Clone)]
pub struct AssayStore {
    cache_dir: PathBuf,
}

impl AssayStore {
    /// Opens (creating if needed) a store under `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let cache_dir = root.as_ref().join(CACHE_SUBDIR);
        fs::create_dir_all(&cache_dir).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_IO,
                format!(
                    "could not create cache dir {}: {error}",
                    cache_dir.display()
                ),
                "ensure the store root is writable before scheduling assay jobs",
            )
        })?;
        Ok(Self { cache_dir })
    }

    fn result_path(&self, fp: &InputFingerprint) -> PathBuf {
        self.cache_dir
            .join(format!("{}{RESULT_SUFFIX}", fp.to_hex()))
    }

    fn rows_path(&self, fp: &InputFingerprint) -> PathBuf {
        self.cache_dir.join(format!("{}{ROWS_SUFFIX}", fp.to_hex()))
    }

    /// Persists a sampled result and its strata rows, then verifies both writes
    /// by reading the bytes back through fresh handles.
    pub fn put(&self, result: &SampleResult) -> Result<()> {
        let fp = result.fingerprint;

        let result_bytes = serde_json::to_vec(result).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("could not serialize sample result: {error}"),
                "this is an internal serialization fault; report it with the failing fingerprint",
            )
        })?;
        self.write_and_verify(&self.result_path(&fp), &result_bytes)?;

        let mut rows_bytes = Vec::new();
        for row in &result.rows {
            let line = serde_json::to_vec(row).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_CORRUPT,
                    format!("could not serialize strata row: {error}"),
                    "this is an internal serialization fault; report it with the failing fingerprint",
                )
            })?;
            rows_bytes.extend_from_slice(&line);
            rows_bytes.push(b'\n');
        }
        self.write_and_verify(&self.rows_path(&fp), &rows_bytes)?;
        Ok(())
    }

    fn write_and_verify(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        fs::write(path, bytes).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_IO,
                format!("could not write {}: {error}", path.display()),
                "ensure the store root is writable before scheduling assay jobs",
            )
        })?;
        // FSV: re-read through a fresh handle and compare bytes, never trust the
        // write's Ok return as evidence of persisted state.
        let observed = fs::read(path).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_IO,
                format!("could not read back {}: {error}", path.display()),
                "the store root became unreadable immediately after a write; check the filesystem",
            )
        })?;
        if observed != bytes {
            return Err(AssayError::new(
                ASTRO_ASSAY_READBACK_MISMATCH,
                format!(
                    "{} read back {} bytes that did not match the {} written",
                    path.display(),
                    observed.len(),
                    bytes.len()
                ),
                "the persisted bytes diverge from the committed content; quarantine the store root and rebuild the sample",
            ));
        }
        Ok(())
    }

    /// Loads a cached result if one is persisted for `fp`.
    ///
    /// Returns `Ok(None)` on a clean miss. A persisted blob whose own embedded
    /// fingerprint does not equal `fp` is a corrupt entry and fails closed
    /// rather than being served as a hit.
    pub fn get(&self, fp: &InputFingerprint) -> Result<Option<SampleResult>> {
        let path = self.result_path(fp);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!("could not read {}: {error}", path.display()),
                    "check the store root filesystem before retrying the assay job",
                ));
            }
        };
        let result: SampleResult = serde_json::from_slice(&bytes).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("cached entry {} did not parse: {error}", path.display()),
                "delete the corrupt cache entry so the next schedule recomputes it",
            )
        })?;
        if result.fingerprint != *fp {
            return Err(AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!(
                    "cached entry {} embeds fingerprint {} but is keyed as {fp}",
                    path.display(),
                    result.fingerprint
                ),
                "delete the mis-keyed cache entry so the next schedule recomputes it",
            ));
        }
        Ok(Some(result))
    }

    /// Independently reads the persisted strata rows for `fp`.
    ///
    /// This parses the standalone `.rows.ndjson` artifact, not the cache blob,
    /// so a caller can confirm the rows were durably written as their own
    /// records and match the rows inside the cached result.
    pub fn read_rows(&self, fp: &InputFingerprint) -> Result<Vec<SelectedSubject>> {
        let path = self.rows_path(fp);
        let bytes = fs::read(&path).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_IO,
                format!("could not read {}: {error}", path.display()),
                "check the store root filesystem before retrying the assay job",
            )
        })?;
        let text = String::from_utf8(bytes).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_CORRUPT,
                format!("rows artifact {} is not utf-8: {error}", path.display()),
                "delete the corrupt rows artifact so the next schedule rewrites it",
            )
        })?;
        let mut rows = Vec::new();
        for (line_no, line) in text.lines().enumerate() {
            if line.is_empty() {
                continue;
            }
            let row: SelectedSubject = serde_json::from_str(line).map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_CORRUPT,
                    format!("{}:{} did not parse: {error}", path.display(), line_no + 1),
                    "delete the corrupt rows artifact so the next schedule rewrites it",
                )
            })?;
            rows.push(row);
        }
        Ok(rows)
    }

    /// Lists the fingerprints of every persisted cache entry, ascending.
    pub fn list_fingerprints(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let entries = fs::read_dir(&self.cache_dir).map_err(|error| {
            AssayError::new(
                ASTRO_ASSAY_STORE_IO,
                format!("could not scan {}: {error}", self.cache_dir.display()),
                "check the store root filesystem before retrying the assay job",
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                AssayError::new(
                    ASTRO_ASSAY_STORE_IO,
                    format!("could not read a cache dir entry: {error}"),
                    "check the store root filesystem before retrying the assay job",
                )
            })?;
            if let Some(name) = entry.file_name().to_str()
                && let Some(hex) = name.strip_suffix(RESULT_SUFFIX)
            {
                out.push(hex.to_string());
            }
        }
        out.sort();
        Ok(out)
    }

    /// Removes every persisted entry whose fingerprint differs from `keep`, and
    /// returns the removed fingerprint hexes ascending.
    ///
    /// This is the invalidation scan: when a panel bump, shard change, or
    /// content edit moves the current fingerprint, the stale entries keyed under
    /// the old fingerprints no longer match and are swept. The removal is proven
    /// by re-listing the directory afterward, not by the unlink returning `Ok`.
    pub fn invalidate_except(&self, keep: &InputFingerprint) -> Result<Vec<String>> {
        let keep_hex = keep.to_hex();
        let mut removed = Vec::new();
        for hex in self.list_fingerprints()? {
            if hex == keep_hex {
                continue;
            }
            for suffix in [RESULT_SUFFIX, ROWS_SUFFIX] {
                let path = self.cache_dir.join(format!("{hex}{suffix}"));
                match fs::remove_file(&path) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(AssayError::new(
                            ASTRO_ASSAY_STORE_IO,
                            format!("could not remove {}: {error}", path.display()),
                            "check the store root filesystem before retrying invalidation",
                        ));
                    }
                }
            }
            removed.push(hex);
        }
        // Prove the residue is gone by an independent re-scan.
        let survivors = self.list_fingerprints()?;
        for hex in &removed {
            if survivors.contains(hex) {
                return Err(AssayError::new(
                    ASTRO_ASSAY_READBACK_MISMATCH,
                    format!("invalidated entry {hex} still present after removal"),
                    "the store did not durably remove a stale entry; quarantine the store root",
                ));
            }
        }
        removed.sort();
        Ok(removed)
    }
}
