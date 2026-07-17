use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::time::{Duration, Instant};

use calyx_core::CalyxError;
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use windows_sys::Win32::Foundation::{
    CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ALREADY_EXISTS,
    ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER, ERROR_MORE_DATA,
    FILETIME, GetLastError, HANDLE, SetLastError, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Globalization::{
    CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN, CompareStringOrdinal,
};
use windows_sys::Win32::System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW};
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_PROCESS_ID_LIST, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicProcessIdList, JobObjectExtendedLimitInformation, OpenJobObjectW,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DeleteProcThreadAttributeList,
    EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess, GetProcessTimes,
    InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
    PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

use crate::error::{CliError, CliResult};

const JOB_CREATE_FAILED: &str = "CALYX_PANEL_RESIDENT_JOB_CREATE_FAILED";
const JOB_CONFIGURE_FAILED: &str = "CALYX_PANEL_RESIDENT_JOB_CONFIGURE_FAILED";
const JOB_ATOMIC_SPAWN_FAILED: &str = "CALYX_PANEL_RESIDENT_JOB_ATOMIC_SPAWN_FAILED";
const JOB_QUERY_FAILED: &str = "CALYX_PANEL_RESIDENT_JOB_QUERY_FAILED";
const JOB_QUERY_INVALID: &str = "CALYX_PANEL_RESIDENT_JOB_QUERY_INVALID";
const JOB_TERMINATE_FAILED: &str = "CALYX_PANEL_RESIDENT_JOB_TERMINATE_FAILED";
const JOB_IDENTITY_INVALID: &str = "CALYX_PANEL_RESIDENT_JOB_IDENTITY_INVALID";
const JOB_RECOVERY_FAILED: &str = "CALYX_PANEL_RESIDENT_JOB_RECOVERY_FAILED";
// The supervisor already treats this public code as proof that generation
// cleanup was not established and preserves durable ownership for recovery.
const JOB_ATOMIC_SPAWN_CLEANUP_FAILED: &str = "CALYX_PANEL_RESIDENT_WORKER_STOP_FAILED";

const JOB_CREATE_REMEDIATION: &str = "confirm the Astrolabe process may create Windows Job Objects, then restart the resident supervisor";
const JOB_CONFIGURE_REMEDIATION: &str = "do not start an unguarded resident worker; inspect the \
     Windows error and host Job Object policy, then restart the resident supervisor";
const JOB_ATOMIC_SPAWN_REMEDIATION: &str = "preserve the generation logs, inspect native process \
     creation and host Job Object policy, and do not load a worker outside atomic Job ownership";
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
const JOB_OBJECT_TERMINATE_ACCESS: u32 = 0x0008;
const RESTART_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);
const RESTART_RECOVERY_POLL: Duration = Duration::from_millis(10);
const PROCESS_ATTRIBUTE_COUNT: u32 = 2;
const MAX_WINDOWS_COMMAND_LINE_UNITS: usize = 32_767;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResidentProcessIdentity {
    pub(super) process_id: u32,
    pub(super) creation_time_filetime: u64,
}

/// Owns the stable process handle returned by the same `CreateProcessW` call
/// that atomically assigned the worker to its generation Job Object.
#[derive(Debug)]
pub(crate) struct ResidentChild {
    handle: HANDLE,
    process_id: u32,
    identity: ResidentProcessIdentity,
}

// SAFETY: the uniquely owned process handle may be waited, queried, and closed
// from any process thread. No Rust memory is reachable through the raw handle.
unsafe impl Send for ResidentChild {}
// SAFETY: shared access only reads the immutable PID/identity. Mutating process
// operations require `&mut self` or are synchronized by the Windows kernel.
unsafe impl Sync for ResidentChild {}

impl ResidentChild {
    fn from_created(handle: OwnedKernelHandle, process_id: u32) -> CliResult<Self> {
        if process_id == 0 {
            return Err(job_error(
                JOB_ATOMIC_SPAWN_FAILED,
                "CreateProcessW returned process id zero for the resident worker",
                JOB_ATOMIC_SPAWN_REMEDIATION,
            ));
        }
        let identity = ResidentProcessIdentity {
            process_id,
            creation_time_filetime: process_creation_time_for(
                handle.raw(),
                process_id,
                JOB_ATOMIC_SPAWN_FAILED,
                JOB_ATOMIC_SPAWN_REMEDIATION,
            )?,
        };
        Ok(Self {
            handle: handle.into_raw(),
            process_id,
            identity,
        })
    }

    pub(crate) fn id(&self) -> u32 {
        self.process_id
    }

    pub(crate) fn try_wait(&mut self) -> io::Result<Option<u32>> {
        // SAFETY: `self.handle` is a live waitable process handle.
        match unsafe { WaitForSingleObject(self.handle, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut exit_code = 0_u32;
                // SAFETY: the process is signaled, the handle remains live, and
                // `exit_code` is writable for the duration of the call.
                if unsafe { GetExitCodeProcess(self.handle, &mut exit_code) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(Some(exit_code))
            }
            WAIT_FAILED => Err(io::Error::last_os_error()),
            status => Err(io::Error::other(format!(
                "WaitForSingleObject for resident worker PID {} returned unexpected status {status}",
                self.process_id
            ))),
        }
    }

    pub(crate) fn kill(&mut self) -> io::Result<()> {
        // SAFETY: this guard owns the exact process handle returned by
        // CreateProcessW. The caller waits and verifies Job emptiness after it.
        if unsafe { TerminateProcess(self.handle, 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn identity(&self) -> ResidentProcessIdentity {
        self.identity.clone()
    }
}

impl Drop for ResidentChild {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns the non-null process handle.
        unsafe { CloseHandle(self.handle) };
    }
}

/// Owns one resident generation's Windows Job Object.
///
/// The job is configured with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, so dropping
/// the guard terminates the worker and every descendant still assigned to the
/// generation. Workers are created with `PROC_THREAD_ATTRIBUTE_JOB_LIST`, so no
/// process can run in the pre-assignment gap of a spawn-then-assign sequence.
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
            let os_code = unsafe { GetLastError() };
            return Err(win32_error(
                JOB_CREATE_FAILED,
                "CreateJobObjectW failed for the resident generation",
                JOB_CREATE_REMEDIATION,
                os_code,
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
            let os_code = unsafe { GetLastError() };
            return Err(win32_error(
                JOB_CONFIGURE_FAILED,
                "SetInformationJobObject(KILL_ON_JOB_CLOSE) failed for the resident generation",
                JOB_CONFIGURE_REMEDIATION,
                os_code,
            ));
        }

        Ok(job)
    }

    /// Creates the hidden worker already owned by this generation Job Object.
    ///
    /// The Job and inherited-standard-handle lists are applied by the kernel as
    /// part of `CreateProcessW`; there is no runnable pre-assignment interval.
    pub(crate) fn spawn_child_atomic(
        &self,
        executable: &Path,
        arguments: &[OsString],
        environment_name: &OsStr,
        environment_value: &OsStr,
        stdout: &File,
        stderr: &File,
    ) -> CliResult<ResidentChild> {
        let application =
            nul_terminated_wide(executable.as_os_str(), "resident worker executable path")?;
        let mut command_line = windows_command_line(executable.as_os_str(), arguments)?;
        let environment = unicode_environment_block(environment_name, environment_value)?;
        let stdin = File::open("NUL").map_err(|error| {
            job_error(
                JOB_ATOMIC_SPAWN_FAILED,
                format!("open Windows NUL device for resident worker stdin: {error}"),
                JOB_ATOMIC_SPAWN_REMEDIATION,
            )
        })?;
        let inherited_stdin =
            duplicate_inheritable_handle(stdin.as_raw_handle() as HANDLE, "resident worker stdin")?;
        let inherited_stdout = duplicate_inheritable_handle(
            stdout.as_raw_handle() as HANDLE,
            "resident worker stdout",
        )?;
        let inherited_stderr = duplicate_inheritable_handle(
            stderr.as_raw_handle() as HANDLE,
            "resident worker stderr",
        )?;
        let inherited_handles = [
            inherited_stdin.raw(),
            inherited_stdout.raw(),
            inherited_stderr.raw(),
        ];
        let job_handles = [self.handle];
        let mut attributes = ProcThreadAttributeList::new(PROCESS_ATTRIBUTE_COUNT)?;
        attributes.update_handle_list(
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            &job_handles,
            "resident generation Job list",
        )?;
        attributes.update_handle_list(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            &inherited_handles,
            "resident worker inherited handle list",
        )?;

        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = inherited_stdin.raw();
        startup.StartupInfo.hStdOutput = inherited_stdout.raw();
        startup.StartupInfo.hStdError = inherited_stderr.raw();
        startup.lpAttributeList = attributes.raw();
        let mut process_info = PROCESS_INFORMATION::default();
        // SAFETY: all pointer-backed UTF-16 buffers and the initialized
        // STARTUPINFOEXW/attribute lists live through the call. Only the three
        // duplicated standard handles are inheritable, and both process/thread
        // security descriptors use the caller defaults.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
                environment.as_ptr().cast(),
                std::ptr::null(),
                std::ptr::from_ref(&startup).cast::<STARTUPINFOW>(),
                &mut process_info,
            )
        };
        if created == 0 {
            let os_code = unsafe { GetLastError() };
            return Err(win32_error(
                JOB_ATOMIC_SPAWN_FAILED,
                format!(
                    "CreateProcessW failed to create resident worker atomically in Job Object {} from {}",
                    self.name,
                    executable.display()
                ),
                JOB_ATOMIC_SPAWN_REMEDIATION,
                os_code,
            ));
        }
        let process_handle = OwnedKernelHandle::new(process_info.hProcess);
        let thread_handle = OwnedKernelHandle::new(process_info.hThread);
        let child = match (process_handle, thread_handle) {
            (Some(process_handle), Some(_thread_handle)) => {
                ResidentChild::from_created(process_handle, process_info.dwProcessId)
            }
            (process_handle, thread_handle) => Err(job_error(
                JOB_ATOMIC_SPAWN_FAILED,
                format!(
                    "CreateProcessW succeeded with invalid returned handles: process_handle={} thread_handle={}",
                    process_handle.is_some(),
                    thread_handle.is_some()
                ),
                JOB_ATOMIC_SPAWN_REMEDIATION,
            )),
        };
        child.map_err(|error| self.cleanup_atomic_spawn_failure(error))
    }

    fn cleanup_atomic_spawn_failure(&self, primary: CliError) -> CliError {
        let terminated = self.terminate(91).err();
        let deadline = Instant::now()
            .checked_add(RESTART_RECOVERY_TIMEOUT)
            .ok_or_else(|| {
                job_error(
                    JOB_ATOMIC_SPAWN_FAILED,
                    "resident atomic-spawn cleanup deadline exceeds the monotonic clock",
                    JOB_ATOMIC_SPAWN_REMEDIATION,
                )
            });
        let emptied = deadline.and_then(|deadline| {
            wait_for_job_empty(self.handle, &self.name, deadline).map_err(|error| {
                job_error(
                    JOB_ATOMIC_SPAWN_FAILED,
                    format!(
                        "atomic resident spawn failed and Job emptiness was not proven: {}: {}",
                        error.code(),
                        error.message()
                    ),
                    JOB_ATOMIC_SPAWN_REMEDIATION,
                )
            })
        });
        match emptied {
            Ok(()) => primary,
            Err(cleanup) => job_error(
                JOB_ATOMIC_SPAWN_CLEANUP_FAILED,
                format!(
                    "atomic resident spawn and cleanup both failed: primary_code={} primary_message={}; terminate_error={}; cleanup_code={} cleanup_message={}",
                    primary.code(),
                    primary.message(),
                    terminated.as_ref().map_or_else(
                        || "none".to_string(),
                        |error| format!("{} {}", error.code(), error.message())
                    ),
                    cleanup.code(),
                    cleanup.message()
                ),
                JOB_ATOMIC_SPAWN_REMEDIATION,
            ),
        }
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
            let os_code = unsafe { GetLastError() };
            return Err(win32_error(
                JOB_IDENTITY_INVALID,
                format!("open bound resident Job Object {job_name}"),
                JOB_IDENTITY_REMEDIATION,
                os_code,
            ));
        }
        let opened = JobQueryHandle(handle);
        let mut is_member = 0;
        // SAFETY: both handles are live and the result pointer is valid for the
        // duration of the call.
        if unsafe { IsProcessInJob(GetCurrentProcess(), opened.0, &mut is_member) } == 0 {
            let os_code = unsafe { GetLastError() };
            return Err(win32_error(
                JOB_IDENTITY_INVALID,
                format!("query current-process membership in {job_name}"),
                JOB_IDENTITY_REMEDIATION,
                os_code,
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
            let os_code = unsafe { GetLastError() };
            return Err(win32_error(
                JOB_TERMINATE_FAILED,
                "TerminateJobObject failed for the resident generation",
                JOB_TERMINATE_REMEDIATION,
                os_code,
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

    /// Captures a stable identity snapshot for the root worker and every Job
    /// descendant. The root identity is sourced from the original process
    /// handle, then independently checked through a PID re-open; Job membership
    /// must remain byte-for-byte stable around the capture.
    pub(crate) fn member_process_identities(
        &self,
        root: &ResidentChild,
    ) -> CliResult<Vec<ResidentProcessIdentity>> {
        let before = self.member_process_ids()?;
        if !before.contains(&root.id()) {
            return Err(job_error(
                JOB_IDENTITY_INVALID,
                format!(
                    "resident Job Object {} does not contain stable root worker PID {}: members={before:?}",
                    self.name,
                    root.id()
                ),
                JOB_IDENTITY_REMEDIATION,
            ));
        }
        let mut identities = Vec::with_capacity(before.len());
        for process_id in &before {
            let reopened = capture_process_identity(*process_id)?;
            if *process_id == root.id() {
                let stable = root.identity();
                let current_stable_time = process_creation_time_for(
                    root.handle,
                    root.id(),
                    JOB_IDENTITY_INVALID,
                    JOB_IDENTITY_REMEDIATION,
                )?;
                if current_stable_time != stable.creation_time_filetime || reopened != stable {
                    return Err(job_error(
                        JOB_IDENTITY_INVALID,
                        format!(
                            "resident root worker identity changed during Job capture: stable={stable:?} current_stable_time={current_stable_time} reopened={reopened:?}"
                        ),
                        JOB_IDENTITY_REMEDIATION,
                    ));
                }
                identities.push(stable);
            } else {
                identities.push(reopened);
            }
        }
        let after = self.member_process_ids()?;
        if after != before {
            return Err(job_error(
                JOB_IDENTITY_INVALID,
                format!(
                    "resident Job Object {} membership changed during identity capture: before={before:?} after={after:?}",
                    self.name
                ),
                JOB_IDENTITY_REMEDIATION,
            ));
        }
        Ok(identities)
    }
}

/// Reconciles a generation left by a previous supervisor before a new
/// supervisor may publish an unloaded state. The named Job is authoritative
/// when it still exists; exact process creation times independently distinguish
/// the recorded processes from PID reuse after the Job object has disappeared.
pub(super) fn recover_recorded_generation(
    job_name: &str,
    recorded_process_ids: &[u32],
    identities: &[ResidentProcessIdentity],
) -> CliResult {
    validate_recorded_process_identities(recorded_process_ids, identities)?;
    let deadline = Instant::now()
        .checked_add(RESTART_RECOVERY_TIMEOUT)
        .ok_or_else(|| {
            job_error(
                JOB_RECOVERY_FAILED,
                "resident restart-recovery deadline exceeds the monotonic clock",
                JOB_QUERY_INVALID_REMEDIATION,
            )
        })?;
    let job = open_recorded_job(job_name)?;
    if let Some(job) = job.as_ref() {
        let members = member_process_ids_for(job.0)?;
        if !members.is_empty() {
            let _member_handles = open_exact_job_members(&members, identities)?;
            // SAFETY: `job` owns the exact named generation handle recovered
            // from the hash-chained lifecycle state, and every current member
            // was just proven against its recorded process creation time.
            if unsafe { TerminateJobObject(job.0, 90) } == 0 {
                let os_code = unsafe { GetLastError() };
                return Err(win32_error(
                    JOB_RECOVERY_FAILED,
                    format!("terminate recorded resident Job Object {job_name}"),
                    JOB_TERMINATE_REMEDIATION,
                    os_code,
                ));
            }
            wait_for_job_empty(job.0, job_name, deadline)?;
        }
    }

    for identity in identities {
        let Some(process) = open_exact_process(identity)? else {
            continue;
        };
        if wait_process(&process, identity, Some(Duration::ZERO))? {
            continue;
        }
        // The Job may already have disappeared while its kill-on-close
        // termination is still draining. Exact creation time makes direct
        // termination safe from PID reuse.
        // SAFETY: `process` is a live handle whose creation time exactly
        // matches the hash-chained lifecycle identity.
        let terminated = unsafe { TerminateProcess(process.0, 90) };
        // SAFETY: capture immediately; the following wait necessarily changes
        // the thread's last-error slot on some paths.
        let terminate_error = (terminated == 0).then(|| unsafe { GetLastError() });
        if let Some(os_code) = terminate_error
            && !wait_process(&process, identity, Some(Duration::ZERO))?
        {
            return Err(win32_error(
                JOB_RECOVERY_FAILED,
                format!(
                    "terminate recorded resident process PID {} creation_time_filetime={}",
                    identity.process_id, identity.creation_time_filetime
                ),
                JOB_TERMINATE_REMEDIATION,
                os_code,
            ));
        }
        wait_process_until(&process, identity, deadline)?;
    }

    if let Some(job) = job.as_ref() {
        wait_for_job_empty(job.0, job_name, deadline)?;
    }
    for identity in identities {
        if let Some(process) = open_exact_process(identity)?
            && !wait_process(&process, identity, Some(Duration::ZERO))?
        {
            return Err(job_error(
                JOB_RECOVERY_FAILED,
                format!(
                    "recorded resident process PID {} creation_time_filetime={} remained live after restart recovery",
                    identity.process_id, identity.creation_time_filetime
                ),
                JOB_TERMINATE_REMEDIATION,
            ));
        }
    }
    Ok(())
}

/// Recovers the durable boundary after Job creation but before the root worker
/// identity was journaled. The hash-chained unique Job name is authoritative;
/// every member is terminated through that exact kernel object, so no PID guess
/// or unsafe PID-only termination is required.
pub(super) fn recover_recorded_preassignment_job(job_name: &str) -> CliResult {
    let Some(job) = open_recorded_job(job_name)? else {
        return Ok(());
    };
    let deadline = Instant::now()
        .checked_add(RESTART_RECOVERY_TIMEOUT)
        .ok_or_else(|| {
            job_error(
                JOB_RECOVERY_FAILED,
                "resident pre-assignment Job recovery deadline exceeds the monotonic clock",
                JOB_QUERY_INVALID_REMEDIATION,
            )
        })?;
    let members = member_process_ids_for(job.0)?;
    if !members.is_empty() {
        // SAFETY: the exact unique Job name was read from the hash-chained v5
        // load_job_created row. Termination is scoped to that kernel object.
        if unsafe { TerminateJobObject(job.0, 90) } == 0 {
            let os_code = unsafe { GetLastError() };
            return Err(win32_error(
                JOB_RECOVERY_FAILED,
                format!("terminate pre-assignment resident Job Object {job_name}"),
                JOB_TERMINATE_REMEDIATION,
                os_code,
            ));
        }
        wait_for_job_empty(job.0, job_name, deadline)?;
    }
    Ok(())
}

struct OwnedKernelHandle(HANDLE);

impl OwnedKernelHandle {
    fn new(handle: HANDLE) -> Option<Self> {
        (!handle.is_null()).then_some(Self(handle))
    }

    fn raw(&self) -> HANDLE {
        self.0
    }

    fn into_raw(self) -> HANDLE {
        let handle = self.0;
        std::mem::forget(self);
        handle
    }
}

impl Drop for OwnedKernelHandle {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns the non-null kernel handle.
        unsafe { CloseHandle(self.0) };
    }
}

struct ProcThreadAttributeList {
    buffer: Vec<usize>,
}

impl ProcThreadAttributeList {
    fn new(attribute_count: u32) -> CliResult<Self> {
        let mut byte_len = 0_usize;
        // SAFETY: the documented sizing call takes a null list and writes only
        // the required byte count.
        unsafe { SetLastError(0) };
        let sized = unsafe {
            InitializeProcThreadAttributeList(
                std::ptr::null_mut(),
                attribute_count,
                0,
                &mut byte_len,
            )
        };
        // SAFETY: read immediately after the sizing call.
        let size_error = unsafe { GetLastError() };
        if sized != 0 || size_error != ERROR_INSUFFICIENT_BUFFER || byte_len == 0 {
            return Err(win32_error(
                JOB_ATOMIC_SPAWN_FAILED,
                format!(
                    "size resident worker process attribute list returned success={sized} bytes={byte_len}"
                ),
                JOB_ATOMIC_SPAWN_REMEDIATION,
                size_error,
            ));
        }
        let words = byte_len.div_ceil(size_of::<usize>());
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(words).map_err(|error| {
            job_error(
                JOB_ATOMIC_SPAWN_FAILED,
                format!("reserve {byte_len} bytes for resident worker process attributes: {error}"),
                JOB_ATOMIC_SPAWN_REMEDIATION,
            )
        })?;
        buffer.resize(words, 0_usize);
        let list = buffer.as_mut_ptr().cast();
        // SAFETY: the aligned writable buffer has at least `byte_len` bytes and
        // remains owned by the returned guard.
        if unsafe { InitializeProcThreadAttributeList(list, attribute_count, 0, &mut byte_len) }
            == 0
        {
            let os_code = unsafe { GetLastError() };
            return Err(win32_error(
                JOB_ATOMIC_SPAWN_FAILED,
                "initialize resident worker process attribute list",
                JOB_ATOMIC_SPAWN_REMEDIATION,
                os_code,
            ));
        }
        Ok(Self { buffer })
    }

    fn raw(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_ptr().cast_mut().cast()
    }

    fn update_handle_list(
        &mut self,
        attribute: usize,
        handles: &[HANDLE],
        label: &str,
    ) -> CliResult {
        if handles.is_empty() || handles.iter().any(|handle| handle.is_null()) {
            return Err(job_error(
                JOB_ATOMIC_SPAWN_FAILED,
                format!("{label} is empty or contains a null handle"),
                JOB_ATOMIC_SPAWN_REMEDIATION,
            ));
        }
        let byte_len = handles
            .len()
            .checked_mul(size_of::<HANDLE>())
            .ok_or_else(|| {
                job_error(
                    JOB_ATOMIC_SPAWN_FAILED,
                    format!("{label} byte length overflowed"),
                    JOB_ATOMIC_SPAWN_REMEDIATION,
                )
            })?;
        // SAFETY: the initialized attribute list is writable, `handles` lives
        // through CreateProcessW, and the exact handle-array size is supplied.
        if unsafe {
            UpdateProcThreadAttribute(
                self.raw(),
                0,
                attribute,
                handles.as_ptr().cast(),
                byte_len,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            let os_code = unsafe { GetLastError() };
            return Err(win32_error(
                JOB_ATOMIC_SPAWN_FAILED,
                format!("apply {label} to resident worker process attributes"),
                JOB_ATOMIC_SPAWN_REMEDIATION,
                os_code,
            ));
        }
        Ok(())
    }
}

impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        // SAFETY: the buffer contains one successfully initialized attribute
        // list and remains alive for this call.
        unsafe { DeleteProcThreadAttributeList(self.raw()) };
    }
}

struct JobQueryHandle(HANDLE);

impl Drop for JobQueryHandle {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns the non-null query handle.
        unsafe { CloseHandle(self.0) };
    }
}

struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        // SAFETY: this guard uniquely owns the non-null process handle.
        unsafe { CloseHandle(self.0) };
    }
}

fn validate_recorded_process_identities(
    recorded_process_ids: &[u32],
    identities: &[ResidentProcessIdentity],
) -> CliResult {
    let mut recorded = recorded_process_ids.to_vec();
    recorded.sort_unstable();
    let mut identified = identities
        .iter()
        .map(|identity| identity.process_id)
        .collect::<Vec<_>>();
    identified.sort_unstable();
    if recorded.is_empty()
        || recorded.iter().any(|process_id| *process_id == 0)
        || recorded.windows(2).any(|pair| pair[0] == pair[1])
        || identities
            .iter()
            .any(|identity| identity.creation_time_filetime == 0)
        || identified != recorded
    {
        return Err(job_error(
            JOB_IDENTITY_INVALID,
            format!(
                "recorded resident process identities do not exactly cover the generation: pids={recorded_process_ids:?} identities={identities:?}"
            ),
            JOB_IDENTITY_REMEDIATION,
        ));
    }
    Ok(())
}

fn open_recorded_job(name: &str) -> CliResult<Option<JobQueryHandle>> {
    let wide_name = wide_job_name(name)?;
    // SAFETY: the validated name is terminated and remains live for the call.
    unsafe { SetLastError(0) };
    let handle = unsafe {
        OpenJobObjectW(
            JOB_OBJECT_QUERY_ACCESS | JOB_OBJECT_TERMINATE_ACCESS,
            0,
            wide_name.as_ptr(),
        )
    };
    if handle.is_null() {
        // SAFETY: read immediately after the failed OpenJobObjectW call.
        let os_code = unsafe { GetLastError() };
        if os_code == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        return Err(win32_error(
            JOB_RECOVERY_FAILED,
            format!("open recorded resident Job Object {name}"),
            JOB_TERMINATE_REMEDIATION,
            os_code,
        ));
    }
    Ok(Some(JobQueryHandle(handle)))
}

fn capture_process_identity(process_id: u32) -> CliResult<ResidentProcessIdentity> {
    let handle = open_process(process_id)?.ok_or_else(|| {
        job_error(
            JOB_IDENTITY_INVALID,
            format!("resident Job member PID {process_id} exited before identity capture"),
            JOB_IDENTITY_REMEDIATION,
        )
    })?;
    Ok(ResidentProcessIdentity {
        process_id,
        creation_time_filetime: process_creation_time_for(
            handle.0,
            process_id,
            JOB_IDENTITY_INVALID,
            JOB_IDENTITY_REMEDIATION,
        )?,
    })
}

fn open_exact_process(identity: &ResidentProcessIdentity) -> CliResult<Option<ProcessHandle>> {
    let Some(handle) = open_process(identity.process_id)? else {
        return Ok(None);
    };
    let observed = process_creation_time_for(
        handle.0,
        identity.process_id,
        JOB_RECOVERY_FAILED,
        JOB_TERMINATE_REMEDIATION,
    )?;
    if observed != identity.creation_time_filetime {
        return Ok(None);
    }
    Ok(Some(handle))
}

fn open_exact_job_members(
    member_process_ids: &[u32],
    identities: &[ResidentProcessIdentity],
) -> CliResult<Vec<ProcessHandle>> {
    let mut handles = Vec::with_capacity(member_process_ids.len());
    for process_id in member_process_ids {
        let identity = identities
            .iter()
            .find(|identity| identity.process_id == *process_id)
            .ok_or_else(|| {
                job_error(
                    JOB_RECOVERY_FAILED,
                    format!(
                        "recorded resident Job contains unowned PID {process_id}; members={member_process_ids:?} identities={identities:?}"
                    ),
                    JOB_TERMINATE_REMEDIATION,
                )
            })?;
        let handle = open_process(*process_id)?.ok_or_else(|| {
            job_error(
                JOB_RECOVERY_FAILED,
                format!(
                    "recorded resident Job member PID {process_id} disappeared before its creation identity could be proven"
                ),
                JOB_TERMINATE_REMEDIATION,
            )
        })?;
        let observed = process_creation_time_for(
            handle.0,
            *process_id,
            JOB_RECOVERY_FAILED,
            JOB_TERMINATE_REMEDIATION,
        )?;
        if observed != identity.creation_time_filetime {
            return Err(job_error(
                JOB_RECOVERY_FAILED,
                format!(
                    "recorded resident Job member PID {process_id} creation time changed: expected {}, observed {observed}",
                    identity.creation_time_filetime
                ),
                JOB_TERMINATE_REMEDIATION,
            ));
        }
        handles.push(handle);
    }
    Ok(handles)
}

fn open_process(process_id: u32) -> CliResult<Option<ProcessHandle>> {
    // SAFETY: OpenProcess receives a nonzero PID and requests only query,
    // synchronization, and termination rights needed for exact recovery.
    unsafe { SetLastError(0) };
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
            0,
            process_id,
        )
    };
    if handle.is_null() {
        // SAFETY: read immediately after the failed OpenProcess call.
        let os_code = unsafe { GetLastError() };
        if os_code == ERROR_INVALID_PARAMETER {
            return Ok(None);
        }
        return Err(win32_error(
            JOB_RECOVERY_FAILED,
            format!("open recorded resident process PID {process_id}"),
            JOB_TERMINATE_REMEDIATION,
            os_code,
        ));
    }
    Ok(Some(ProcessHandle(handle)))
}

fn process_creation_time_for(
    handle: HANDLE,
    process_id: u32,
    error_code: &'static str,
    remediation: &'static str,
) -> CliResult<u64> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all output pointers refer to initialized writable FILETIME
    // values and `handle` remains live for the call.
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        let os_code = unsafe { GetLastError() };
        return Err(win32_error(
            error_code,
            format!("read creation time for resident process PID {process_id}"),
            remediation,
            os_code,
        ));
    }
    let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    if value == 0 {
        return Err(job_error(
            error_code,
            format!("resident process PID {process_id} reported a zero creation time"),
            remediation,
        ));
    }
    Ok(value)
}

fn wait_for_job_empty(handle: HANDLE, name: &str, deadline: Instant) -> CliResult {
    loop {
        let members = member_process_ids_for(handle)?;
        if members.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(job_error(
                JOB_RECOVERY_FAILED,
                format!(
                    "recorded resident Job Object {name} retained process IDs {members:?} after termination"
                ),
                JOB_TERMINATE_REMEDIATION,
            ));
        }
        std::thread::sleep(RESTART_RECOVERY_POLL);
    }
}

fn wait_process_until(
    process: &ProcessHandle,
    identity: &ResidentProcessIdentity,
    deadline: Instant,
) -> CliResult {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() || !wait_process(process, identity, Some(remaining))? {
        return Err(job_error(
            JOB_RECOVERY_FAILED,
            format!(
                "recorded resident process PID {} creation_time_filetime={} did not exit within {:?}",
                identity.process_id, identity.creation_time_filetime, RESTART_RECOVERY_TIMEOUT
            ),
            JOB_TERMINATE_REMEDIATION,
        ));
    }
    Ok(())
}

fn wait_process(
    process: &ProcessHandle,
    identity: &ResidentProcessIdentity,
    timeout: Option<Duration>,
) -> CliResult<bool> {
    let timeout_ms = timeout.map_or(u32::MAX, |duration| {
        u32::try_from(duration.as_millis()).unwrap_or(u32::MAX)
    });
    // SAFETY: `process` owns a live waitable process handle.
    match unsafe { WaitForSingleObject(process.0, timeout_ms) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        WAIT_FAILED => {
            let os_code = unsafe { GetLastError() };
            Err(win32_error(
                JOB_RECOVERY_FAILED,
                format!(
                    "wait for recorded resident process PID {} creation_time_filetime={}",
                    identity.process_id, identity.creation_time_filetime
                ),
                JOB_TERMINATE_REMEDIATION,
                os_code,
            ))
        }
        status => Err(job_error(
            JOB_RECOVERY_FAILED,
            format!(
                "wait for recorded resident process PID {} returned unexpected status {status}",
                identity.process_id
            ),
            JOB_TERMINATE_REMEDIATION,
        )),
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

fn nul_terminated_wide(value: &OsStr, label: &str) -> CliResult<Vec<u16>> {
    let mut wide = value.encode_wide().collect::<Vec<_>>();
    if wide.is_empty() || wide.contains(&0) {
        return Err(job_error(
            JOB_ATOMIC_SPAWN_FAILED,
            format!("{label} is empty or contains an embedded NUL"),
            JOB_ATOMIC_SPAWN_REMEDIATION,
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn windows_command_line(executable: &OsStr, arguments: &[OsString]) -> CliResult<Vec<u16>> {
    let mut command_line = Vec::new();
    append_quoted_windows_argument(&mut command_line, executable)?;
    for argument in arguments {
        command_line.push(b' ' as u16);
        append_quoted_windows_argument(&mut command_line, argument)?;
    }
    command_line.push(0);
    if command_line.len() > MAX_WINDOWS_COMMAND_LINE_UNITS {
        return Err(job_error(
            JOB_ATOMIC_SPAWN_FAILED,
            format!(
                "resident worker command line is {} UTF-16 units, Windows limit is {}",
                command_line.len(),
                MAX_WINDOWS_COMMAND_LINE_UNITS
            ),
            JOB_ATOMIC_SPAWN_REMEDIATION,
        ));
    }
    Ok(command_line)
}

fn append_quoted_windows_argument(command_line: &mut Vec<u16>, argument: &OsStr) -> CliResult {
    let wide = argument.encode_wide().collect::<Vec<_>>();
    if wide.contains(&0) {
        return Err(job_error(
            JOB_ATOMIC_SPAWN_FAILED,
            "resident worker argument contains an embedded NUL",
            JOB_ATOMIC_SPAWN_REMEDIATION,
        ));
    }
    command_line.push(b'"' as u16);
    let mut backslashes = 0_usize;
    for unit in wide {
        if unit == b'\\' as u16 {
            backslashes = backslashes.checked_add(1).ok_or_else(|| {
                job_error(
                    JOB_ATOMIC_SPAWN_FAILED,
                    "resident worker argument backslash count overflowed",
                    JOB_ATOMIC_SPAWN_REMEDIATION,
                )
            })?;
            continue;
        }
        if unit == b'"' as u16 {
            extend_windows_backslashes(command_line, backslashes, true, true)?;
            command_line.push(unit);
        } else {
            extend_windows_backslashes(command_line, backslashes, false, false)?;
            command_line.push(unit);
        }
        backslashes = 0;
    }
    extend_windows_backslashes(command_line, backslashes, true, false)?;
    command_line.push(b'"' as u16);
    Ok(())
}

fn extend_windows_backslashes(
    command_line: &mut Vec<u16>,
    count: usize,
    double: bool,
    escape_quote: bool,
) -> CliResult {
    let mut count = if double {
        count.checked_mul(2).ok_or_else(|| {
            job_error(
                JOB_ATOMIC_SPAWN_FAILED,
                "resident worker argument quoting length overflowed",
                JOB_ATOMIC_SPAWN_REMEDIATION,
            )
        })?
    } else {
        count
    };
    if escape_quote {
        count = count.checked_add(1).ok_or_else(|| {
            job_error(
                JOB_ATOMIC_SPAWN_FAILED,
                "resident worker argument quote escaping length overflowed",
                JOB_ATOMIC_SPAWN_REMEDIATION,
            )
        })?;
    }
    command_line.extend(std::iter::repeat_n(b'\\' as u16, count));
    Ok(())
}

fn unicode_environment_block(name: &OsStr, value: &OsStr) -> CliResult<Vec<u16>> {
    let name = name.encode_wide().collect::<Vec<_>>();
    let value = value.encode_wide().collect::<Vec<_>>();
    if name.is_empty() || name.contains(&(b'=' as u16)) || name.contains(&0) || value.contains(&0) {
        return Err(job_error(
            JOB_ATOMIC_SPAWN_FAILED,
            "resident worker environment override name is empty or invalid",
            JOB_ATOMIC_SPAWN_REMEDIATION,
        ));
    }
    let native = NativeEnvironmentBlock::capture()?;
    let mut entries = native.entries()?;
    let mut replacement = name.clone();
    replacement.push(b'=' as u16);
    replacement.extend(value);

    let mut output = Vec::new();
    let mut inserted = false;
    for entry in entries.drain(..) {
        let key = environment_entry_key(&entry)?;
        match compare_environment_keys(key, &name)? {
            CSTR_EQUAL => {
                if !inserted {
                    output.push(replacement.clone());
                    inserted = true;
                }
            }
            CSTR_GREATER_THAN if !inserted => {
                output.push(replacement.clone());
                output.push(entry);
                inserted = true;
            }
            CSTR_LESS_THAN | CSTR_GREATER_THAN => output.push(entry),
            result => {
                return Err(job_error(
                    JOB_ATOMIC_SPAWN_FAILED,
                    format!(
                        "CompareStringOrdinal returned unexpected environment ordering result {result}"
                    ),
                    JOB_ATOMIC_SPAWN_REMEDIATION,
                ));
            }
        }
    }
    if !inserted {
        output.push(replacement);
    }
    let units = output
        .iter()
        .try_fold(1_usize, |total, entry| {
            total
                .checked_add(entry.len())
                .and_then(|sum| sum.checked_add(1))
        })
        .ok_or_else(|| {
            job_error(
                JOB_ATOMIC_SPAWN_FAILED,
                "resident worker Unicode environment block length overflowed",
                JOB_ATOMIC_SPAWN_REMEDIATION,
            )
        })?;
    let mut block = Vec::new();
    block.try_reserve_exact(units).map_err(|error| {
        job_error(
            JOB_ATOMIC_SPAWN_FAILED,
            format!("reserve resident worker Unicode environment block: {error}"),
            JOB_ATOMIC_SPAWN_REMEDIATION,
        )
    })?;
    for entry in output {
        block.extend(entry);
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

struct NativeEnvironmentBlock(*mut u16);

impl NativeEnvironmentBlock {
    fn capture() -> CliResult<Self> {
        // SAFETY: GetEnvironmentStringsW returns an immutable process snapshot
        // owned by the caller until FreeEnvironmentStringsW.
        let block = unsafe { GetEnvironmentStringsW() };
        if block.is_null() {
            let os_code = unsafe { GetLastError() };
            return Err(win32_error(
                JOB_ATOMIC_SPAWN_FAILED,
                "capture the native Unicode environment block for the resident worker",
                JOB_ATOMIC_SPAWN_REMEDIATION,
                os_code,
            ));
        }
        Ok(Self(block))
    }

    fn entries(&self) -> CliResult<Vec<Vec<u16>>> {
        let mut entries = Vec::new();
        let mut cursor = self.0.cast_const();
        loop {
            // SAFETY: the OS-owned environment block is a sequence of
            // NUL-terminated entries followed by a second NUL.
            if unsafe { *cursor } == 0 {
                break;
            }
            let mut len = 0_usize;
            // SAFETY: same block contract; checked arithmetic prevents pointer
            // offset wrap while locating the entry terminator.
            while unsafe { *cursor.add(len) } != 0 {
                len = len.checked_add(1).ok_or_else(|| {
                    job_error(
                        JOB_ATOMIC_SPAWN_FAILED,
                        "native Unicode environment entry length overflowed",
                        JOB_ATOMIC_SPAWN_REMEDIATION,
                    )
                })?;
            }
            // SAFETY: `len` was measured within this NUL-terminated entry.
            entries.push(unsafe { std::slice::from_raw_parts(cursor, len) }.to_vec());
            // SAFETY: advance past the validated entry and its terminator.
            cursor = unsafe { cursor.add(len + 1) };
        }
        Ok(entries)
    }
}

impl Drop for NativeEnvironmentBlock {
    fn drop(&mut self) {
        // SAFETY: this pointer is released exactly once with its matching API.
        unsafe {
            FreeEnvironmentStringsW(self.0);
        }
    }
}

fn environment_entry_key(entry: &[u16]) -> CliResult<&[u16]> {
    let search_from = if entry.first() == Some(&(b'=' as u16)) {
        1
    } else {
        0
    };
    let separator = entry[search_from..]
        .iter()
        .position(|unit| *unit == b'=' as u16)
        .map(|offset| search_from + offset)
        .ok_or_else(|| {
            job_error(
                JOB_ATOMIC_SPAWN_FAILED,
                "native Unicode environment entry has no key/value separator",
                JOB_ATOMIC_SPAWN_REMEDIATION,
            )
        })?;
    if separator == 0 {
        return Err(job_error(
            JOB_ATOMIC_SPAWN_FAILED,
            "native Unicode environment entry has an empty key",
            JOB_ATOMIC_SPAWN_REMEDIATION,
        ));
    }
    Ok(&entry[..separator])
}

fn compare_environment_keys(left: &[u16], right: &[u16]) -> CliResult<i32> {
    let left_len = i32::try_from(left.len()).map_err(|_| {
        job_error(
            JOB_ATOMIC_SPAWN_FAILED,
            "native environment key exceeds CompareStringOrdinal length",
            JOB_ATOMIC_SPAWN_REMEDIATION,
        )
    })?;
    let right_len = i32::try_from(right.len()).map_err(|_| {
        job_error(
            JOB_ATOMIC_SPAWN_FAILED,
            "resident environment key exceeds CompareStringOrdinal length",
            JOB_ATOMIC_SPAWN_REMEDIATION,
        )
    })?;
    // SAFETY: both slices are readable for their explicit lengths; the API
    // does not require NUL termination when counts are nonnegative.
    let result =
        unsafe { CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) };
    if result == 0 {
        let os_code = unsafe { GetLastError() };
        return Err(win32_error(
            JOB_ATOMIC_SPAWN_FAILED,
            "order native resident worker environment keys",
            JOB_ATOMIC_SPAWN_REMEDIATION,
            os_code,
        ));
    }
    Ok(result)
}

fn duplicate_inheritable_handle(source: HANDLE, label: &str) -> CliResult<OwnedKernelHandle> {
    if source.is_null() {
        return Err(job_error(
            JOB_ATOMIC_SPAWN_FAILED,
            format!("{label} source handle is null"),
            JOB_ATOMIC_SPAWN_REMEDIATION,
        ));
    }
    let current = unsafe { GetCurrentProcess() };
    let mut duplicate = std::ptr::null_mut();
    // SAFETY: the current process owns `source`; output storage is valid, and
    // the duplicate is explicitly inheritable for the HANDLE_LIST contract.
    if unsafe {
        DuplicateHandle(
            current,
            source,
            current,
            &mut duplicate,
            0,
            1,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        let os_code = unsafe { GetLastError() };
        return Err(win32_error(
            JOB_ATOMIC_SPAWN_FAILED,
            format!("duplicate {label} as an inheritable worker handle"),
            JOB_ATOMIC_SPAWN_REMEDIATION,
            os_code,
        ));
    }
    OwnedKernelHandle::new(duplicate).ok_or_else(|| {
        job_error(
            JOB_ATOMIC_SPAWN_FAILED,
            format!("DuplicateHandle returned a null handle for {label}"),
            JOB_ATOMIC_SPAWN_REMEDIATION,
        )
    })
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
