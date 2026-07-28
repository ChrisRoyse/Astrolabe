use calyx_core::{CalyxError, Result};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions, TryLockError as FileTryLockError};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Condvar, Mutex, MutexGuard, OnceLock, TryLockError as MutexTryLockError, Weak,
};

static PROCESS_LOCKS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<ProcessRwLock>>>> = OnceLock::new();

#[derive(Debug)]
struct ProcessRwLock {
    state: Mutex<ProcessRwState>,
    ready: Condvar,
}

#[derive(Debug, Default)]
struct ProcessRwState {
    readers: usize,
    writer: bool,
    waiting_writers: usize,
}

#[derive(Debug, Clone, Copy)]
enum ProcessLockMode {
    Exclusive,
    Shared,
}

#[derive(Debug)]
struct ProcessLockGuard {
    lock: Arc<ProcessRwLock>,
    mode: ProcessLockMode,
}

#[derive(Debug)]
pub(crate) struct FileLockGuard {
    _file: File,
    _process_guard: ProcessLockGuard,
}

impl FileLockGuard {
    pub(crate) fn acquire(path: &Path) -> Result<Self> {
        let key = lock_key(path)?;
        let process_guard = ProcessLockGuard::acquire_exclusive(process_lock(&key)?)?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)
            .map_err(|error| CalyxError::disk_pressure(format!("open lock file: {error}")))?;
        file.lock()
            .map_err(|error| CalyxError::backpressure(format!("lock file: {error}")))?;
        Ok(Self {
            _file: file,
            _process_guard: process_guard,
        })
    }

    pub(crate) fn try_acquire(path: &Path, locked_error: fn(String) -> CalyxError) -> Result<Self> {
        let key = lock_key(path)?;
        let process_guard =
            ProcessLockGuard::try_acquire_exclusive(process_lock(&key)?, &key, locked_error)?;
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)
            .map_err(|error| CalyxError::disk_pressure(format!("open lock file: {error}")))?;
        match file.try_lock() {
            Ok(()) => Ok(Self {
                _file: file,
                _process_guard: process_guard,
            }),
            Err(FileTryLockError::WouldBlock) => Err(locked_error(format!(
                "another process holds {}",
                key.display()
            ))),
            Err(FileTryLockError::Error(error)) => Err(CalyxError::backpressure(format!(
                "try lock file {}: {error}",
                key.display()
            ))),
        }
    }

    /// Acquires a shared lock without creating the lock file or any parent.
    ///
    /// Durable read snapshots use this path so concurrent readers coexist while
    /// the ordinary exclusive writer lock remains excluded. A missing lock is
    /// an incomplete durable store, not permission to manufacture write-path
    /// state during a read.
    pub(crate) fn acquire_shared_existing(path: &Path) -> Result<Self> {
        let key = existing_lock_key(path)?;
        let process_guard = ProcessLockGuard::acquire_shared(process_lock(&key)?)?;
        let file = File::open(&key).map_err(|error| {
            if error.kind() == ErrorKind::NotFound {
                missing_read_lock(&key)
            } else {
                CalyxError::disk_pressure(format!(
                    "open existing shared lock {}: {error}",
                    key.display()
                ))
            }
        })?;
        file.lock_shared().map_err(|error| {
            CalyxError::backpressure(format!("shared-lock file {}: {error}", key.display()))
        })?;
        Ok(Self {
            _file: file,
            _process_guard: process_guard,
        })
    }
}

impl ProcessRwLock {
    fn new() -> Self {
        Self {
            state: Mutex::new(ProcessRwState::default()),
            ready: Condvar::new(),
        }
    }

    fn state(&self) -> Result<MutexGuard<'_, ProcessRwState>> {
        self.state
            .lock()
            .map_err(|_| CalyxError::backpressure("file lock process state poisoned"))
    }
}

impl ProcessLockGuard {
    fn acquire_exclusive(lock: Arc<ProcessRwLock>) -> Result<Self> {
        let mut state = lock.state()?;
        state.waiting_writers = state.waiting_writers.saturating_add(1);
        while state.writer || state.readers != 0 {
            state = lock
                .ready
                .wait(state)
                .map_err(|_| CalyxError::backpressure("file lock process state poisoned"))?;
        }
        state.waiting_writers = state.waiting_writers.saturating_sub(1);
        state.writer = true;
        drop(state);
        Ok(Self {
            lock,
            mode: ProcessLockMode::Exclusive,
        })
    }

    fn try_acquire_exclusive(
        lock: Arc<ProcessRwLock>,
        key: &Path,
        locked_error: fn(String) -> CalyxError,
    ) -> Result<Self> {
        let mut state = match lock.state.try_lock() {
            Ok(state) => state,
            Err(MutexTryLockError::WouldBlock) => {
                return Err(locked_error(format!(
                    "another thread in this process is changing lock state for {}",
                    key.display()
                )));
            }
            Err(MutexTryLockError::Poisoned(_)) => {
                return Err(CalyxError::backpressure("file lock process state poisoned"));
            }
        };
        if state.writer || state.readers != 0 {
            return Err(locked_error(format!(
                "another thread in this process holds {}",
                key.display()
            )));
        }
        state.writer = true;
        drop(state);
        Ok(Self {
            lock,
            mode: ProcessLockMode::Exclusive,
        })
    }

    fn acquire_shared(lock: Arc<ProcessRwLock>) -> Result<Self> {
        let mut state = lock.state()?;
        while state.writer || state.waiting_writers != 0 {
            state = lock
                .ready
                .wait(state)
                .map_err(|_| CalyxError::backpressure("file lock process state poisoned"))?;
        }
        state.readers = state.readers.checked_add(1).ok_or_else(|| CalyxError {
            code: "CALYX_FILE_LOCK_READER_OVERFLOW",
            message: "process-local shared file-lock reader count overflowed".to_string(),
            remediation: "inspect leaked read handles before reopening the vault",
        })?;
        drop(state);
        Ok(Self {
            lock,
            mode: ProcessLockMode::Shared,
        })
    }
}

impl Drop for ProcessLockGuard {
    fn drop(&mut self) {
        let Ok(mut state) = self.lock.state.lock() else {
            return;
        };
        match self.mode {
            ProcessLockMode::Exclusive => state.writer = false,
            ProcessLockMode::Shared => state.readers = state.readers.saturating_sub(1),
        }
        self.lock.ready.notify_all();
    }
}

fn process_lock(path: &Path) -> Result<Arc<ProcessRwLock>> {
    let locks = PROCESS_LOCKS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut locks = locks
        .lock()
        .map_err(|_| CalyxError::backpressure("file lock registry poisoned"))?;
    if let Some(lock) = locks.get(path).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    locks.retain(|_, lock| lock.strong_count() != 0);
    let lock = Arc::new(ProcessRwLock::new());
    locks.insert(path.to_path_buf(), Arc::downgrade(&lock));
    Ok(lock)
}

fn lock_key(path: &Path) -> Result<PathBuf> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| CalyxError::disk_pressure(format!("create lock dir: {error}")))?;
        let parent = parent.canonicalize().map_err(|error| {
            CalyxError::disk_pressure(format!("canonicalize lock dir: {error}"))
        })?;
        let name = path
            .file_name()
            .ok_or_else(|| CalyxError::disk_pressure("lock path has no file name"))?;
        return Ok(parent.join(name));
    }
    Ok(path.to_path_buf())
}

fn existing_lock_key(path: &Path) -> Result<PathBuf> {
    let Some(parent) = path.parent() else {
        return Err(missing_read_lock(path));
    };
    if !parent.is_dir() {
        return Err(missing_read_lock(path));
    }
    let parent = parent.canonicalize().map_err(|error| {
        CalyxError::disk_pressure(format!(
            "canonicalize existing shared-lock directory {}: {error}",
            parent.display()
        ))
    })?;
    let name = path.file_name().ok_or_else(|| missing_read_lock(path))?;
    let key = parent.join(name);
    if !key.is_file() {
        return Err(missing_read_lock(&key));
    }
    Ok(key)
}

fn missing_read_lock(path: &Path) -> CalyxError {
    CalyxError {
        code: "CALYX_READ_ONLY_LOCK_MISSING",
        message: format!(
            "read-only snapshot lock {} is absent; refusing to create write-path state",
            path.display()
        ),
        remediation: "open a fully initialized durable vault, or initialize it through a write-capable handle before reading",
    }
}
