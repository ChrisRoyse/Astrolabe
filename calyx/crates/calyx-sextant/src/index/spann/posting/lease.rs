use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use calyx_core::Result;

use super::config::{SPANN_POSTING_FORMAT_VERSION, SpannIndexIdentity, SpannPostingLimits};
use super::manifest::ActivePointer;
use super::{corrupt, io};

const LEASE_MAGIC: [u8; 8] = *b"CLXSPL03";
const LEASE_BYTES: usize = 128;
const LEASE_SEAL_OFFSET: usize = 96;
const LEASE_PREFIX: &str = "postings.reader-p";
const LEASE_SUFFIX: &str = ".lease";
static NEXT_LEASE_ID: AtomicU64 = AtomicU64::new(1);

/// An OS-backed pin on one exact manifest generation. On Windows the open
/// handle permits readers but denies delete/write sharing, so reclamation can
/// distinguish a live reader from a lease file left by a crashed process.
#[derive(Debug)]
pub(super) struct ReaderLease {
    path: PathBuf,
    file: Option<File>,
}

impl ReaderLease {
    pub(super) fn acquire(
        dir: &Path,
        identity: &SpannIndexIdentity,
        active: &ActivePointer,
    ) -> Result<Self> {
        #[cfg(not(windows))]
        {
            let _ = (dir, identity, active);
            return Err(super::invalid(
                "SPANN generation leases require the shipping Windows target",
            ));
        }

        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;

            if active.index_id != identity.index_id {
                return Err(corrupt("cannot lease a manifest for another SPANN index"));
            }
            let process_id = std::process::id();
            let lease_id = NEXT_LEASE_ID.fetch_add(1, Ordering::Relaxed);
            let name = format!("{LEASE_PREFIX}{process_id:08x}-n{lease_id:016x}{LEASE_SUFFIX}");
            let path = dir.join(name);
            let bytes = encode_lease(identity, active, process_id);
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create_new(true)
                .share_mode(FILE_SHARE_READ);
            let mut file = options
                .open(&path)
                .map_err(|error| io(&format!("create reader lease {}", path.display()), error))?;
            let result = (|| {
                file.write_all(&bytes)
                    .map_err(|error| io("write reader lease", error))?;
                file.sync_all()
                    .map_err(|error| io("fsync reader lease", error))?;
                file.seek(SeekFrom::Start(0))
                    .map_err(|error| io("rewind reader lease", error))?;
                let mut readback = [0_u8; LEASE_BYTES];
                file.read_exact(&mut readback)
                    .map_err(|error| io("read back reader lease", error))?;
                let decoded = decode_lease(&readback, identity)?;
                if decoded.generation != active.generation
                    || decoded.manifest_len != active.manifest_len
                    || decoded.manifest_hash != active.manifest_hash
                {
                    return Err(corrupt("reader lease readback changed"));
                }
                Ok(())
            })();
            if let Err(error) = result {
                drop(file);
                if let Err(remove_error) = fs::remove_file(&path) {
                    tracing::error!(
                        path = %path.display(),
                        %remove_error,
                        "failed to remove invalid SPANN reader lease"
                    );
                }
                return Err(error);
            }
            Ok(Self {
                path,
                file: Some(file),
            })
        }
    }
}

impl Drop for ReaderLease {
    fn drop(&mut self) {
        drop(self.file.take());
        if let Err(error) = fs::remove_file(&self.path)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::error!(
                path = %self.path.display(),
                %error,
                "failed to remove released SPANN reader lease"
            );
        }
    }
}

pub(super) fn live_lease_targets(
    dir: &Path,
    identity: &SpannIndexIdentity,
    limits: &SpannPostingLimits,
) -> Result<Vec<ActivePointer>> {
    #[cfg(not(windows))]
    {
        let _ = (dir, identity, limits);
        return Err(super::invalid(
            "SPANN generation lease reclamation requires the shipping Windows target",
        ));
    }

    #[cfg(windows)]
    {
        let mut live = Vec::new();
        let mut inspected = 0_u32;
        for entry in fs::read_dir(dir).map_err(|error| io("scan reader leases", error))? {
            let entry = entry.map_err(|error| io("read reader lease entry", error))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !is_lease_name(&name) {
                continue;
            }
            inspected = inspected
                .checked_add(1)
                .ok_or_else(|| corrupt("reader lease count overflow"))?;
            if inspected > u32::from(limits.max_reclaim_files) {
                return Err(corrupt(format!(
                    "reader lease entries exceed registry reclaim-file limit {}",
                    limits.max_reclaim_files
                )));
            }
            let path = entry.path();
            if !entry
                .file_type()
                .map_err(|error| io("stat reader lease entry", error))?
                .is_file()
            {
                return Err(corrupt(format!(
                    "reader lease path is not a file: {}",
                    path.display()
                )));
            }
            if !lease_is_live(&path)? {
                fs::remove_file(&path).map_err(|error| {
                    io(
                        &format!("remove stale reader lease {}", path.display()),
                        error,
                    )
                })?;
                continue;
            }
            if live.len() >= limits.max_reader_leases as usize {
                return Err(corrupt(format!(
                    "live reader leases exceed registry limit {}",
                    limits.max_reader_leases
                )));
            }
            let bytes = fs::read(&path).map_err(|error| {
                io(&format!("read live reader lease {}", path.display()), error)
            })?;
            if bytes.len() != LEASE_BYTES {
                return Err(corrupt(format!(
                    "live reader lease {} length {} != {LEASE_BYTES}",
                    path.display(),
                    bytes.len()
                )));
            }
            live.push(decode_lease(&bytes, identity)?);
        }
        Ok(live)
    }
}

#[cfg(windows)]
fn lease_is_live(path: &Path) -> Result<bool> {
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Foundation::ERROR_SHARING_VIOLATION;

    let mut options = OpenOptions::new();
    options.read(true).write(true).share_mode(0);
    match options.open(path) {
        Ok(file) => {
            drop(file);
            Ok(false)
        }
        Err(error) if error.raw_os_error() == Some(ERROR_SHARING_VIOLATION as i32) => Ok(true),
        Err(error) => Err(io(
            &format!("probe reader lease liveness {}", path.display()),
            error,
        )),
    }
}

fn is_lease_name(name: &str) -> bool {
    name.starts_with(LEASE_PREFIX) && name.ends_with(LEASE_SUFFIX)
}

fn encode_lease(
    identity: &SpannIndexIdentity,
    active: &ActivePointer,
    process_id: u32,
) -> [u8; LEASE_BYTES] {
    let mut bytes = [0_u8; LEASE_BYTES];
    bytes[0..8].copy_from_slice(&LEASE_MAGIC);
    bytes[8..10].copy_from_slice(&SPANN_POSTING_FORMAT_VERSION.to_le_bytes());
    bytes[10..12].copy_from_slice(&(LEASE_BYTES as u16).to_le_bytes());
    bytes[12..44].copy_from_slice(&identity.index_id);
    bytes[44..52].copy_from_slice(&active.generation.to_le_bytes());
    bytes[52..60].copy_from_slice(&active.manifest_len.to_le_bytes());
    bytes[60..92].copy_from_slice(&active.manifest_hash);
    bytes[92..96].copy_from_slice(&process_id.to_le_bytes());
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"calyx-spann-reader-lease-v3");
    hasher.update(&bytes[..LEASE_SEAL_OFFSET]);
    bytes[LEASE_SEAL_OFFSET..].copy_from_slice(hasher.finalize().as_bytes());
    bytes
}

fn decode_lease(bytes: &[u8], identity: &SpannIndexIdentity) -> Result<ActivePointer> {
    if bytes.len() != LEASE_BYTES
        || bytes[0..8] != LEASE_MAGIC
        || u16::from_le_bytes(bytes[8..10].try_into().expect("2B")) != SPANN_POSTING_FORMAT_VERSION
        || u16::from_le_bytes(bytes[10..12].try_into().expect("2B")) != LEASE_BYTES as u16
        || bytes[12..44] != identity.index_id
    {
        return Err(corrupt("reader lease identity/header invalid"));
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"calyx-spann-reader-lease-v3");
    hasher.update(&bytes[..LEASE_SEAL_OFFSET]);
    if hasher.finalize().as_bytes() != &bytes[LEASE_SEAL_OFFSET..] {
        return Err(corrupt("reader lease seal mismatch"));
    }
    let generation = u64::from_le_bytes(bytes[44..52].try_into().expect("8B"));
    let manifest_len = u64::from_le_bytes(bytes[52..60].try_into().expect("8B"));
    let manifest_hash = bytes[60..92].try_into().expect("32B");
    if generation == 0 || manifest_len == 0 || manifest_hash == [0; 32] {
        return Err(corrupt("reader lease generation/manifest target is empty"));
    }
    Ok(ActivePointer {
        generation,
        manifest_len,
        manifest_hash,
        index_id: identity.index_id,
    })
}
