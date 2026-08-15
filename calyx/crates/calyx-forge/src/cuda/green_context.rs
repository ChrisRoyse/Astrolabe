use std::mem::MaybeUninit;
use std::ptr;

use cudarc::driver::{result, sys};

use crate::{ForgeError, Result};

use super::{CudaContext, init_cuda_by_pci_bus_id};

const GREEN_CONTEXT_REMEDIATION: &str = "Unset CALYX_ONNX_GREEN_CONTEXT_SMS, lower the requested SM count, or verify CUDA 13.3 green-context driver support";

#[derive(Debug)]
pub struct CudaGreenContextStream {
    _primary: CudaContext,
    green_ctx: sys::CUgreenCtx,
    green_cu_ctx: sys::CUcontext,
    stream: sys::CUstream,
    driver_device_idx: u32,
    green_ctx_id: u64,
    requested_sm_count: u32,
    actual_sm_count: u32,
    total_sm_count: u32,
    workqueue_balanced: bool,
}

// CUDA driver handles may move between host threads. Teardown explicitly pushes the
// stream's attested green CUcontext before destroying the stream.
unsafe impl Send for CudaGreenContextStream {}

impl CudaGreenContextStream {
    pub fn create_serving_by_pci_bus_id(pci_bus_id: &str, requested_sm_count: u32) -> Result<Self> {
        if requested_sm_count == 0 {
            return Err(green_context_error(
                "requested_sm_count must be greater than zero",
            ));
        }
        let primary = init_cuda_by_pci_bus_id(pci_bus_id, false)?;
        let priority = serving_priority(&primary)?;
        create_stream(primary, requested_sm_count, priority)
    }

    pub fn driver_device_idx(&self) -> u32 {
        self.driver_device_idx
    }

    pub fn stream_ptr(&self) -> *mut () {
        self.stream.cast()
    }

    pub fn physical_identity(&self) -> crate::PinnedCudaDeviceIdentity {
        self._primary.physical_identity()
    }

    pub fn attest_identity(&self) -> Result<()> {
        let expected_device = result::device::get(self.driver_device_idx as i32).map_err(
            driver_error("get CUDA device for green stream re-attestation"),
        )?;
        let observed = attest_stream_identity(
            self.stream,
            self.green_ctx,
            self.green_cu_ctx,
            expected_device,
            self._primary.inner().cu_ctx(),
        )?;
        if observed != self.driver_device_idx {
            return Err(green_context_error(format!(
                "green stream Driver ordinal changed from {} to {observed}",
                self.driver_device_idx
            )));
        }
        super::attest_cudarc_context(
            self._primary.inner().as_ref(),
            self.driver_device_idx,
            self._primary.physical_identity(),
        )
    }

    /// Wait until every operation queued on this exact green-context stream has completed.
    ///
    /// The caller must serialize access to this handle. The stream identifies its owning green
    /// context, so synchronization does not make that context current on another host thread.
    pub fn synchronize(&self) -> Result<()> {
        unsafe { result::stream::synchronize(self.stream) }
            .map_err(driver_error("synchronize retained green-context stream"))
    }

    pub const fn green_ctx_id(&self) -> u64 {
        self.green_ctx_id
    }

    pub const fn requested_sm_count(&self) -> u32 {
        self.requested_sm_count
    }

    pub const fn actual_sm_count(&self) -> u32 {
        self.actual_sm_count
    }

    pub const fn total_sm_count(&self) -> u32 {
        self.total_sm_count
    }

    pub const fn workqueue_balanced(&self) -> bool {
        self.workqueue_balanced
    }
}

impl Drop for CudaGreenContextStream {
    fn drop(&mut self) {
        let stream = std::mem::replace(&mut self.stream, ptr::null_mut());
        let green_ctx = std::mem::replace(&mut self.green_ctx, ptr::null_mut());
        let green_cu_ctx = std::mem::replace(&mut self.green_cu_ctx, ptr::null_mut());
        cleanup_green_context_resources(
            stream,
            green_ctx,
            green_cu_ctx,
            Some(self.green_ctx_id),
            self.driver_device_idx,
            "drop",
        );
    }
}

fn create_stream(
    primary: CudaContext,
    requested_sm_count: u32,
    priority: i32,
) -> Result<CudaGreenContextStream> {
    primary
        .inner()
        .bind_to_thread()
        .map_err(driver_error("bind primary context"))?;
    let device = result::device::get(primary.device_idx() as i32)
        .map_err(driver_error("get CUDA device"))?;
    let device_sm = device_sm_resource(device)?;
    let total_sm_count = sm_count(&device_sm);
    if requested_sm_count > total_sm_count {
        return Err(green_context_error(format!(
            "requested_sm_count={requested_sm_count} exceeds total_sm_count={total_sm_count}"
        )));
    }

    let mut selected_sm = zeroed_resource();
    let mut remaining_sm = zeroed_resource();
    let mut groups = 1_u32;
    unsafe {
        sys::cuDevSmResourceSplitByCount(
            &mut selected_sm,
            &mut groups,
            &device_sm,
            &mut remaining_sm,
            0,
            requested_sm_count,
        )
        .result()
    }
    .map_err(driver_error("split SM resources"))?;
    if groups == 0 {
        return Err(green_context_error(
            "CUDA returned zero SM resource groups for green context",
        ));
    }

    let mut resources = vec![selected_sm, balanced_workqueue_resource(device)?];
    let mut desc: sys::CUdevResourceDesc = ptr::null_mut();
    unsafe {
        sys::cuDevResourceGenerateDesc(&mut desc, resources.as_mut_ptr(), resources.len() as u32)
            .result()
    }
    .map_err(driver_error("generate resource descriptor"))?;
    if desc.is_null() {
        return Err(green_context_error(
            "CUDA returned a null green-context resource descriptor",
        ));
    }

    let mut green_ctx: sys::CUgreenCtx = ptr::null_mut();
    if let Err(err) = unsafe { sys::cuGreenCtxCreate(&mut green_ctx, desc, device, 0).result() } {
        return Err(driver_error("create green context")(err));
    }
    if green_ctx.is_null() {
        return Err(green_context_error("CUDA returned a null green context"));
    }
    let green_cu_ctx = match green_context_as_cuda_context(green_ctx) {
        Ok(context) => context,
        Err(error) => {
            cleanup_green_context_resources(
                ptr::null_mut(),
                green_ctx,
                ptr::null_mut(),
                None,
                primary.device_idx(),
                "convert_green_context",
            );
            return Err(error);
        }
    };

    let mut actual_sm = zeroed_resource();
    let actual_sm_count = unsafe {
        match sys::cuGreenCtxGetDevResource(
            green_ctx,
            &mut actual_sm,
            sys::CUdevResourceType::CU_DEV_RESOURCE_TYPE_SM,
        )
        .result()
        {
            Ok(()) => sm_count(&actual_sm),
            Err(err) => {
                cleanup_green_context_resources(
                    ptr::null_mut(),
                    green_ctx,
                    green_cu_ctx,
                    None,
                    primary.device_idx(),
                    "query_green_context_sm_resources",
                );
                return Err(driver_error("query green context SM resources")(err));
            }
        }
    };

    let mut green_ctx_id = 0_u64;
    unsafe {
        if let Err(err) = sys::cuGreenCtxGetId(green_ctx, &mut green_ctx_id).result() {
            cleanup_green_context_resources(
                ptr::null_mut(),
                green_ctx,
                green_cu_ctx,
                None,
                primary.device_idx(),
                "query_green_context_id",
            );
            return Err(driver_error("query green context id")(err));
        }
    }

    let mut stream: sys::CUstream = ptr::null_mut();
    unsafe {
        if let Err(err) = sys::cuGreenCtxStreamCreate(
            &mut stream,
            green_ctx,
            sys::CUstream_flags::CU_STREAM_NON_BLOCKING as u32,
            priority,
        )
        .result()
        {
            cleanup_green_context_resources(
                ptr::null_mut(),
                green_ctx,
                green_cu_ctx,
                Some(green_ctx_id),
                primary.device_idx(),
                "create_green_context_stream",
            );
            return Err(driver_error("create green context stream")(err));
        }
    }
    if stream.is_null() {
        cleanup_green_context_resources(
            stream,
            green_ctx,
            green_cu_ctx,
            Some(green_ctx_id),
            primary.device_idx(),
            "null_green_context_stream",
        );
        return Err(green_context_error(
            "CUDA returned a null green-context stream",
        ));
    }
    let driver_device_idx = match attest_stream_identity(
        stream,
        green_ctx,
        green_cu_ctx,
        device,
        primary.inner().cu_ctx(),
    ) {
        Ok(driver_device_idx) => driver_device_idx,
        Err(error) => {
            cleanup_green_context_resources(
                stream,
                green_ctx,
                green_cu_ctx,
                Some(green_ctx_id),
                primary.device_idx(),
                "attest_stream_identity",
            );
            return Err(error);
        }
    };

    Ok(CudaGreenContextStream {
        _primary: primary,
        green_ctx,
        green_cu_ctx,
        stream,
        driver_device_idx,
        green_ctx_id,
        requested_sm_count,
        actual_sm_count,
        total_sm_count,
        workqueue_balanced: true,
    })
}

fn green_context_as_cuda_context(green_ctx: sys::CUgreenCtx) -> Result<sys::CUcontext> {
    let mut green_cu_ctx: sys::CUcontext = ptr::null_mut();
    unsafe { sys::cuCtxFromGreenCtx(&mut green_cu_ctx, green_ctx).result() }
        .map_err(driver_error("convert green context to CUcontext"))?;
    if green_cu_ctx.is_null() {
        return Err(green_context_error(
            "CUDA returned a null CUcontext for the green context",
        ));
    }
    Ok(green_cu_ctx)
}

fn attest_stream_identity(
    stream: sys::CUstream,
    expected_green_ctx: sys::CUgreenCtx,
    expected_green_cu_ctx: sys::CUcontext,
    expected_device: sys::CUdevice,
    expected_primary_ctx: sys::CUcontext,
) -> Result<u32> {
    let mut observed_green_ctx: sys::CUgreenCtx = ptr::null_mut();
    unsafe { sys::cuStreamGetGreenCtx(stream, &mut observed_green_ctx).result() }
        .map_err(driver_error("read back stream green context"))?;
    if observed_green_ctx.is_null() || observed_green_ctx != expected_green_ctx {
        return Err(green_context_error(format!(
            "CUDA stream green-context identity mismatch: expected={expected_green_ctx:p} observed={observed_green_ctx:p}"
        )));
    }

    let mut observed_device: sys::CUdevice = -1;
    unsafe { sys::cuStreamGetDevice(stream, &mut observed_device).result() }
        .map_err(driver_error("read back stream device"))?;
    if observed_device != expected_device {
        return Err(green_context_error(format!(
            "CUDA stream device identity mismatch: expected_driver_device={expected_device} observed_driver_device={observed_device}"
        )));
    }
    let driver_device_idx = u32::try_from(observed_device).map_err(|_| {
        green_context_error(format!(
            "CUDA stream returned invalid driver device ordinal {observed_device}"
        ))
    })?;

    let mut observed_green_cu_ctx: sys::CUcontext = ptr::null_mut();
    unsafe { sys::cuStreamGetCtx(stream, &mut observed_green_cu_ctx).result() }
        .map_err(driver_error("read back stream CUcontext"))?;
    if observed_green_cu_ctx.is_null() || observed_green_cu_ctx != expected_green_cu_ctx {
        return Err(green_context_error(format!(
            "CUDA stream CUcontext identity mismatch: expected_green_context={expected_green_cu_ctx:p} observed_context={observed_green_cu_ctx:p}"
        )));
    }

    let mut observed_primary_ctx: sys::CUcontext = ptr::null_mut();
    let mut observed_v2_green_ctx: sys::CUgreenCtx = ptr::null_mut();
    unsafe {
        sys::cuStreamGetCtx_v2(
            stream,
            &mut observed_primary_ctx,
            &mut observed_v2_green_ctx,
        )
        .result()
    }
    .map_err(driver_error("read back stream primary and green contexts"))?;
    if observed_primary_ctx.is_null()
        || observed_primary_ctx != expected_primary_ctx
        || observed_v2_green_ctx != expected_green_ctx
    {
        return Err(green_context_error(format!(
            "CUDA stream context-v2 identity mismatch: expected_primary={expected_primary_ctx:p} observed_primary={observed_primary_ctx:p} expected_green={expected_green_ctx:p} observed_green={observed_v2_green_ctx:p}"
        )));
    }

    Ok(driver_device_idx)
}

fn cleanup_green_context_resources(
    stream: sys::CUstream,
    green_ctx: sys::CUgreenCtx,
    green_cu_ctx: sys::CUcontext,
    green_ctx_id: Option<u64>,
    driver_device_idx: u32,
    origin: &'static str,
) {
    let mut context_pushed = false;
    if !stream.is_null() {
        if green_cu_ctx.is_null() {
            tracing::error!(
                code = "CALYX_FORGE_GREEN_CONTEXT_CLEANUP_FAILED",
                cleanup_stage = "bind_green_context",
                cleanup_origin = origin,
                driver_device_idx,
                green_ctx_id = green_ctx_id.unwrap_or_default(),
                green_ctx_id_known = green_ctx_id.is_some(),
                stream_address = stream as usize,
                green_ctx_address = green_ctx as usize,
                "cannot bind a null green CUcontext before destroying its stream"
            );
        } else {
            match unsafe { sys::cuCtxPushCurrent_v2(green_cu_ctx).result() } {
                Ok(()) => context_pushed = true,
                Err(error) => tracing::error!(
                    code = "CALYX_FORGE_GREEN_CONTEXT_CLEANUP_FAILED",
                    cleanup_stage = "bind_green_context",
                    cleanup_origin = origin,
                    driver_device_idx,
                    green_ctx_id = green_ctx_id.unwrap_or_default(),
                    green_ctx_id_known = green_ctx_id.is_some(),
                    stream_address = stream as usize,
                    green_ctx_address = green_ctx as usize,
                    green_cu_ctx_address = green_cu_ctx as usize,
                    error = %error,
                    "failed to bind the green CUcontext before destroying its stream"
                ),
            }
        }

        if let Err(error) = unsafe { sys::cuStreamDestroy_v2(stream).result() } {
            tracing::error!(
                code = "CALYX_FORGE_GREEN_CONTEXT_CLEANUP_FAILED",
                cleanup_stage = "destroy_stream",
                cleanup_origin = origin,
                driver_device_idx,
                green_ctx_id = green_ctx_id.unwrap_or_default(),
                green_ctx_id_known = green_ctx_id.is_some(),
                stream_address = stream as usize,
                green_ctx_address = green_ctx as usize,
                green_cu_ctx_address = green_cu_ctx as usize,
                context_pushed,
                error = %error,
                "failed to destroy a CUDA green-context stream"
            );
        }

        if context_pushed {
            let mut popped_context: sys::CUcontext = ptr::null_mut();
            match unsafe { sys::cuCtxPopCurrent_v2(&mut popped_context).result() } {
                Ok(()) if popped_context == green_cu_ctx => {}
                Ok(()) => tracing::error!(
                    code = "CALYX_FORGE_GREEN_CONTEXT_CLEANUP_FAILED",
                    cleanup_stage = "restore_previous_context",
                    cleanup_origin = origin,
                    driver_device_idx,
                    green_ctx_id = green_ctx_id.unwrap_or_default(),
                    green_ctx_id_known = green_ctx_id.is_some(),
                    expected_green_cu_ctx_address = green_cu_ctx as usize,
                    popped_context_address = popped_context as usize,
                    "CUDA popped a different context after green-context stream destruction"
                ),
                Err(error) => tracing::error!(
                    code = "CALYX_FORGE_GREEN_CONTEXT_CLEANUP_FAILED",
                    cleanup_stage = "restore_previous_context",
                    cleanup_origin = origin,
                    driver_device_idx,
                    green_ctx_id = green_ctx_id.unwrap_or_default(),
                    green_ctx_id_known = green_ctx_id.is_some(),
                    green_cu_ctx_address = green_cu_ctx as usize,
                    error = %error,
                    "failed to pop the green CUcontext after stream destruction"
                ),
            }
        }
    }

    if !green_ctx.is_null()
        && let Err(error) = unsafe { sys::cuGreenCtxDestroy(green_ctx).result() }
    {
        tracing::error!(
            code = "CALYX_FORGE_GREEN_CONTEXT_CLEANUP_FAILED",
            cleanup_stage = "destroy_green_context",
            cleanup_origin = origin,
            driver_device_idx,
            green_ctx_id = green_ctx_id.unwrap_or_default(),
            green_ctx_id_known = green_ctx_id.is_some(),
            green_ctx_address = green_ctx as usize,
            green_cu_ctx_address = green_cu_ctx as usize,
            error = %error,
            "failed to destroy a CUDA green context"
        );
    }
}

fn serving_priority(ctx: &CudaContext) -> Result<i32> {
    ctx.inner()
        .bind_to_thread()
        .map_err(driver_error("bind primary context"))?;
    let (_least_priority, greatest_priority) = result::stream::get_priority_range()
        .map_err(driver_error("query stream priority range"))?;
    Ok(greatest_priority)
}

fn device_sm_resource(device: sys::CUdevice) -> Result<sys::CUdevResource> {
    let mut resource = zeroed_resource();
    unsafe {
        sys::cuDeviceGetDevResource(
            device,
            &mut resource,
            sys::CUdevResourceType::CU_DEV_RESOURCE_TYPE_SM,
        )
        .result()
    }
    .map_err(driver_error("query device SM resources"))?;
    Ok(resource)
}

fn balanced_workqueue_resource(device: sys::CUdevice) -> Result<sys::CUdevResource> {
    let mut resource = zeroed_resource();
    unsafe {
        sys::cuDeviceGetDevResource(
            device,
            &mut resource,
            sys::CUdevResourceType::CU_DEV_RESOURCE_TYPE_WORKQUEUE_CONFIG,
        )
        .result()
    }
    .map_err(driver_error("query device workqueue resources"))?;
    resource.__bindgen_anon_1.wqConfig.sharingScope =
        sys::CUdevWorkqueueConfigScope::CU_WORKQUEUE_SCOPE_GREEN_CTX_BALANCED;
    Ok(resource)
}

fn zeroed_resource() -> sys::CUdevResource {
    unsafe { MaybeUninit::<sys::CUdevResource>::zeroed().assume_init() }
}

fn sm_count(resource: &sys::CUdevResource) -> u32 {
    unsafe { resource.__bindgen_anon_1.sm.smCount }
}

fn driver_error(stage: &'static str) -> impl FnOnce(result::DriverError) -> ForgeError {
    move |err| green_context_error(format!("CUDA green-context {stage} failed: {err}"))
}

fn green_context_error(detail: impl Into<String>) -> ForgeError {
    ForgeError::GpuError {
        detail: detail.into(),
        remediation: GREEN_CONTEXT_REMEDIATION.to_string(),
    }
}
