use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::process::Child;

use calyx_core::CalyxError;
use ulid::Ulid;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, ERROR_MORE_DATA, GetLastError, HANDLE, SetLastError,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_PROCESS_ID_LIST, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, OpenJobObjectW,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::error::{CliError, CliResult};

const JOB_CREATE_FAILED: &str = "CALYX_PANEL_RESIDENT_JOB_CREATE_FAILED";
const JOB_CONFIGURE_FAILED: &str = "CALYX_PANEL_RESIDENT_JOB_CONFIGURE_FAILED";
const JOB_ASSIGN_FAILED: &str = "CALYX_PANEL_RESIDENT_JOB_ASSIGN_FAILED";
const JOB_QUERY_FAILED: &str = "CALYX_PANEL_RESIDENT_JOB_QUERY_FAILED";
const JOB_QUERY_INVALID: &str = "CALYX_PANEL_RESIDENT_JOB_QUERY_INVALID";
const JOB_TERMINATE_FAILED: &str = "CALYX_PANEL_RESIDENT_JOB_TERMINATE_FAILED";
const JOB_IDENTITY_INVALID: &str = "CALYX_PANEL_RESIDENT_JOB_IDENTITY_INVALID";

const JOB_CREATE_REMEDIATION: &str = "confirm the Astrolabe process may create Windows Job Objects, then restart the resident supervisor";
const JOB_CONFIGURE_REMEDIATION: &str = "do not start an unguarded resident worker; inspect the \
     Windows error and host Job Object policy, then restart the resident supervisor";
const JOB_ASSIGN_REMEDIATION: &str = "kill and wait for the just-spawned resident worker, inspect \
     whether the process is already in a non-nestable Job Object, then restart the resident supervisor";
const JOB_QUERY_REMEDIATION: &str = "keep the Job Object handle open, inspect the Windows error and \
     resident worker process state, then retry the lifecycle readback";
const JOB_QUERY_INVALID_REMEDIATION: &str = "treat the resident generation as faulted, terminate its \
     Job Object, and inspect the recorded lifecycle state before restarting it";
const JOB_TERMINATE_REMEDIATION: &str = "keep the Job Object guard alive, kill and wait for the owned \
     worker if it is still reachable, then query job membership until every descendant has exited";
const JOB_IDENTITY_REMEDIATION: &str = "start the hidden worker only through the resident supervisor; \
     preserve the generation logs and reject any worker that cannot prove exact named Job membership";

const INITIAL_PROCESS_CAPACITY: usize = 8;
const PROCESS_LIST_OFFSET: usize = offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList);
const JOB_OBJECT_QUERY_ACCESS: u32 = 0x0004;

/// Owns one resident generation's Windows Job Object.
///
/// The job is configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so dropping
/// the guard terminates the worker and every descendant still assigned to the
/// generation. The caller continues to own the [`Child`]; if
/// [`Self::assign_child`] fails, it must kill and wait for that child before
/// returning the failure.
#[derive(Debug)]
pub(crate) struct ResidentGenerationJob {
    handle: HANDLE,
    name: String,
    nonce: String,
}

// SAFETY: Windows kernel handles may be used and closed from any process
// thread. Ownership remains unique in `ResidentGenerationJob`, while the
// query and termination APIs accept shared handles and are thread-safe.
unsafe impl Send for ResidentGenerationJob {}
// SAFETY: see the `Send` implementation; shared access never mutates Rust
// memory behind the raw handle.
unsafe impl Sync for ResidentGenerationJob {}

impl ResidentGenerationJob {
    /// Creates a uniquely named, kill-on-close job before the worker exists.
    ///
    /// The name binds a random nonce to the supervisor identity, generation,
    /// and frozen source fingerprint. The worker must open this exact kernel
    /// object and prove membership before it may inspect source bytes.
    pub(crate) fn create(
        supervisor_pid: u32,
        generation: u64,
        frozen_fingerprint: &str,
    ) -> CliResult<Self> {
        let nonce = format!("{}{}", Ulid::new(), Ulid::new());
        let name = bound_job_name(supervisor_pid, generation, frozen_fingerprint, &nonce);
        let wide_name = wide_job_name(&name)?;
        // SAFETY: null attributes request the caller's default security
        // descriptor. `wide_name` is terminated and remains live for the call.
        // Resetting last-error lets us distinguish a new object from collision
        // with a pre-existing named object on the successful path.
        unsafe { SetLastError(0) };
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), wide_name.as_ptr()) };
        if handle.is_null() {
            return Err(last_win32_error(
                JOB_CREATE_FAILED,
                "CreateJobObjectW failed for the resident generation",
                JOB_CREATE_REMEDIATION,
            ));
        }
        // SAFETY: read immediately after CreateJobObjectW, before another
        // Win32 call can overwrite the result.
        let create_status = unsafe { GetLastError() };
        if create_status == ERROR_ALREADY_EXISTS {
            // SAFETY: `handle` is the live handle returned above and has not
            // been transferred into an owning Rust guard yet.
            unsafe { CloseHandle(handle) };
            return Err(job_error(
                JOB_IDENTITY_INVALID,
                format!("resident generation Job Object name collision for {name}"),
                JOB_IDENTITY_REMEDIATION,
            ));
        }
        let job = Self {
            handle,
            name,
            nonce,
        };

        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: `job.handle` is live, and `limits` is a fully initialized POD
        // whose address and exact byte length remain valid for the call.
        let configured = unsafe {
            SetInformationJobObject(
                job.handle,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(last_win32_error(
                JOB_CONFIGURE_FAILED,
                "SetInformationJobObject(KILL_ON_JOB_CLOSE) failed for the resident generation",
                JOB_CONFIGURE_REMEDIATION,
            ));
        }

        Ok(job)
    }

    /// Assigns the spawned worker and immediately proves the exact initial
    /// membership snapshot. The gate must not be published before this passes.
    pub(crate) fn assign_child(&self, child: &Child) -> CliResult {
        // SAFETY: the job handle is live and exclusively owned; the process
        // handle is borrowed from a live Child for only the duration of this
        // call. The caller retains ownership of the Child on every path.
        let assigned = unsafe { AssignProcessToJobObject(self.handle, child.as_raw_handle()) };
        if assigned == 0 {
            return Err(last_win32_error(
                JOB_ASSIGN_FAILED,
                &format!(
                    "AssignProcessToJobObject failed for resident worker PID {}",
                    child.id()
                ),
                JOB_ASSIGN_REMEDIATION,
            ));
        }
        self.verify_exact_members(&[child.id()])
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn nonce(&self) -> &str {
        &self.nonce
    }

    pub(crate) fn verify_exact_members(&self, expected: &[u32]) -> CliResult {
        let observed = self.member_process_ids()?;
        if observed != expected {
            return Err(job_error(
                JOB_IDENTITY_INVALID,
                format!(
                    "resident Job Object {} membership mismatch: expected {expected:?}, observed {observed:?}",
                    self.name
                ),
                JOB_IDENTITY_REMEDIATION,
            ));
        }
        Ok(())
    }

    /// Re-opens the supervisor's bound named job inside the worker and proves
    /// that the current process is its sole initial member.
    pub(crate) fn verify_current_worker(
        job_name: &str,
        nonce: &str,
        supervisor_pid: u32,
        generation: u64,
        frozen_fingerprint: &str,
    ) -> CliResult {
        let expected_name = bound_job_name(supervisor_pid, generation, frozen_fingerprint, nonce);
        if job_name != expected_name {
            return Err(job_error(
                JOB_IDENTITY_INVALID,
                format!(
                    "resident worker gate Job identity mismatch: supplied {job_name}, bound {expected_name}"
                ),
                JOB_IDENTITY_REMEDIATION,
            ));
        }
        let wide_name = wide_job_name(job_name)?;
        // SAFETY: the name is terminated and valid for the call. The returned
        // query handle is owned by `opened` and never inherited.
        let handle = unsafe { OpenJobObjectW(JOB_OBJECT_QUERY_ACCESS, 0, wide_name.as_ptr()) };
        if handle.is_null() {
            return Err(last_win32_error(
                JOB_IDENTITY_INVALID,
                format!("open bound resident Job Object {job_name}"),
                JOB_IDENTITY_REMEDIATION,
            ));
        }
        let opened = JobQueryHandle(handle);
        let mut is_member = 0;
        // SAFETY: both handles are live and the result pointer is valid for the
        // duration of the call.
        if unsafe { IsProcessInJob(GetCurrentProcess(), opened.0, &mut is_member) } == 0 {
            return Err(last_win32_error(
                JOB_IDENTITY_INVALID,
                format!("query current-process membership in {job_name}"),
                JOB_IDENTITY_REMEDIATION,
            ));
        }
        if is_member == 0 {
            return Err(job_error(
                JOB_IDENTITY_INVALID,
                format!(
                    "resident worker PID {} is not a member of bound Job Object {job_name}",
                    std::process::id()
                ),
                JOB_IDENTITY_REMEDIATION,
            ));
        }
        let observed = member_process_ids_for(opened.0)?;
        let expected = vec![std::process::id()];
        if observed != expected {
            return Err(job_error(
                JOB_IDENTITY_INVALID,
                format!(
                    "resident worker initial Job membership is not exact: expected {expected:?}, observed {observed:?}"
                ),
                JOB_IDENTITY_REMEDIATION,
            ));
        }
        // `opened` is intentionally dropped here. The worker must never retain
        // a Job handle: the supervisor's handle must remain the last controller
        // so supervisor death triggers KILL_ON_JOB_CLOSE for the generation.
        Ok(())
    }

    /// Terminates every process currently owned by this generation.
    ///
    /// Windows termination is asynchronous; the supervisor must wait for the
    /// worker and verify [`Self::member_process_ids`] becomes empty before it
    /// records the generation as unloaded.
    pub(crate) fn terminate(&self, exit_code: u32) -> CliResult {
        // SAFETY: the guard owns a live Job Object handle.
        if unsafe { TerminateJobObject(self.handle, exit_code) } == 0 {
            return Err(last_win32_error(
                JOB_TERMINATE_FAILED,
                "TerminateJobObject failed for the resident generation",
                JOB_TERMINATE_REMEDIATION,
            ));
        }
        Ok(())
    }

    /// Returns a complete, deterministically ordered snapshot of job members.
    ///
    /// `JOBOBJECT_BASIC_PROCESS_ID_LIST` has a trailing variable-length array.
    /// The backing allocation uses `usize` words to preserve the structure's
    /// native alignment, and grows on `ERROR_MORE_DATA` until Windows reports a
    /// complete snapshot. Any malformed count or unrepresentable PID fails
    /// closed instead of returning a partial list.
    pub(crate) fn member_process_ids(&self) -> CliResult<Vec<u32>> {
        member_process_ids_for(self.handle)
    }
}

struct JobQueryHandle(HANDLE);

impl Drop for JobQueryHandle {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns the non-null query handle.
        unsafe { CloseHandle(self.0) };
    }
}

fn member_process_ids_for(handle: HANDLE) -> CliResult<Vec<u32>> {
    let mut process_capacity = INITIAL_PROCESS_CAPACITY;
    loop {
        let mut buffer = process_id_buffer(process_capacity)?;
        let byte_len =
            u32::try_from(buffer.len().saturating_mul(size_of::<usize>())).map_err(|_| {
                job_error(
                    JOB_QUERY_INVALID,
                    "resident Job Object PID buffer exceeds the Win32 query size limit",
                    JOB_QUERY_INVALID_REMEDIATION,
                )
            })?;
        let mut returned_len = 0_u32;
        // SAFETY: the `usize` buffer is aligned for the queried structure,
        // zero-initialized, writable for `byte_len`, and lives through all
        // reads below. The job handle remains live for the call.
        let queried = unsafe {
            QueryInformationJobObject(
                handle,
                JobObjectBasicProcessIdList,
                buffer.as_mut_ptr().cast(),
                byte_len,
                &mut returned_len,
            )
        };
        let header = buffer.as_ptr().cast::<JOBOBJECT_BASIC_PROCESS_ID_LIST>();
        if queried == 0 {
            // SAFETY: GetLastError is read immediately after the failed query,
            // before any other Win32 call can overwrite it.
            let os_code = unsafe { GetLastError() };
            if os_code != ERROR_MORE_DATA {
                return Err(win32_error(
                    JOB_QUERY_FAILED,
                    "QueryInformationJobObject(ProcessIdList) failed",
                    JOB_QUERY_REMEDIATION,
                    os_code,
                ));
            }
            // On ERROR_MORE_DATA Windows still initializes the fixed header,
            // including the number required for a complete list.
            // SAFETY: every allocated buffer includes the complete fixed
            // header and is aligned for this read.
            let assigned = unsafe { (*header).NumberOfAssignedProcesses as usize };
            process_capacity = next_process_capacity(process_capacity, assigned)?;
            continue;
        }

        // SAFETY: a successful query initialized the fixed header.
        let assigned = unsafe { (*header).NumberOfAssignedProcesses as usize };
        // SAFETY: a successful query initialized the fixed header.
        let listed = unsafe { (*header).NumberOfProcessIdsInList as usize };
        if listed > process_capacity || listed > assigned {
            return Err(job_error(
                JOB_QUERY_INVALID,
                format!(
                    "resident Job Object returned invalid PID counts: assigned={assigned}, listed={listed}, capacity={process_capacity}, bytes={returned_len}"
                ),
                JOB_QUERY_INVALID_REMEDIATION,
            ));
        }
        if listed < assigned {
            // A successful query may still report a partial list. The
            // structure contract requires resizing whenever the listed count
            // is smaller than the assigned count.
            process_capacity = next_process_capacity(process_capacity, assigned)?;
            continue;
        }

        // SAFETY: the validated `listed` count is within the variable array
        // capacity supplied to Windows, and the offset is native-layout
        // derived rather than assumed.
        let raw_ids = unsafe {
            std::slice::from_raw_parts(
                buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(PROCESS_LIST_OFFSET)
                    .cast::<usize>(),
                listed,
            )
        };
        let mut ids = Vec::with_capacity(listed);
        for raw_id in raw_ids {
            let process_id = u32::try_from(*raw_id).map_err(|_| {
                job_error(
                    JOB_QUERY_INVALID,
                    format!("resident Job Object returned an unrepresentable process id {raw_id}"),
                    JOB_QUERY_INVALID_REMEDIATION,
                )
            })?;
            if process_id == 0 {
                return Err(job_error(
                    JOB_QUERY_INVALID,
                    "resident Job Object returned process id zero",
                    JOB_QUERY_INVALID_REMEDIATION,
                ));
            }
            ids.push(process_id);
        }
        ids.sort_unstable();
        return Ok(ids);
    }
}

impl Drop for ResidentGenerationJob {
    fn drop(&mut self) {
        // SAFETY: this guard exclusively owns the non-null handle, which is
        // closed exactly once here. KILL_ON_JOB_CLOSE provides the final
        // descendant cleanup if normal termination did not complete.
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

fn bound_job_name(
    supervisor_pid: u32,
    generation: u64,
    frozen_fingerprint: &str,
    nonce: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hash_job_identity_part(&mut hasher, b"calyx-panel-resident-generation-job-v1");
    hash_job_identity_part(&mut hasher, &supervisor_pid.to_le_bytes());
    hash_job_identity_part(&mut hasher, &generation.to_le_bytes());
    hash_job_identity_part(&mut hasher, frozen_fingerprint.as_bytes());
    hash_job_identity_part(&mut hasher, nonce.as_bytes());
    format!("Local\\CalyxPanelResident-{}", hasher.finalize().to_hex())
}

fn hash_job_identity_part(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn wide_job_name(name: &str) -> CliResult<Vec<u16>> {
    if name.contains('\0') {
        return Err(job_error(
            JOB_IDENTITY_INVALID,
            "resident Job Object name contains an embedded NUL",
            JOB_IDENTITY_REMEDIATION,
        ));
    }
    Ok(std::ffi::OsStr::new(name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect())
}

fn process_id_buffer(process_capacity: usize) -> CliResult<Vec<usize>> {
    let pid_bytes = process_capacity
        .checked_mul(size_of::<usize>())
        .and_then(|bytes| PROCESS_LIST_OFFSET.checked_add(bytes))
        .ok_or_else(|| {
            job_error(
                JOB_QUERY_INVALID,
                "resident Job Object PID buffer size overflowed",
                JOB_QUERY_INVALID_REMEDIATION,
            )
        })?;
    let words = pid_bytes.div_ceil(size_of::<usize>());
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(words).map_err(|error| {
        job_error(
            JOB_QUERY_FAILED,
            format!("reserve resident Job Object PID buffer: {error}"),
            JOB_QUERY_REMEDIATION,
        )
    })?;
    buffer.resize(words, 0_usize);
    Ok(buffer)
}

fn next_process_capacity(current: usize, assigned: usize) -> CliResult<usize> {
    let doubled = current.checked_mul(2).ok_or_else(|| {
        job_error(
            JOB_QUERY_INVALID,
            "resident Job Object PID capacity overflowed while retrying the query",
            JOB_QUERY_INVALID_REMEDIATION,
        )
    })?;
    Ok(assigned.max(doubled))
}

fn last_win32_error(
    code: &'static str,
    operation: impl Into<String>,
    remediation: &'static str,
) -> CliError {
    // SAFETY: callers invoke this immediately after a failing Win32 API.
    let os_code = unsafe { GetLastError() };
    win32_error(code, operation, remediation, os_code)
}

fn win32_error(
    code: &'static str,
    operation: impl Into<String>,
    remediation: &'static str,
    os_code: u32,
) -> CliError {
    job_error(
        code,
        format!(
            "{}: {} (Win32 error {os_code})",
            operation.into(),
            io::Error::from_raw_os_error(os_code as i32)
        ),
        remediation,
    )
}

fn job_error(
    code: &'static str,
    message: impl Into<String>,
    remediation: &'static str,
) -> CliError {
    CliError::Calyx(CalyxError {
        code,
        message: message.into(),
        remediation,
    })
}
