//! Exact-version CUDA Driver API dispatch for physical memory ownership.
//!
//! The CUDA driver can expose multiple ABI generations for one base symbol.
//! Forge resolves the four memory-lifecycle entries together, at the ABI
//! version that introduced their `_v2` typedefs, and retains that dispatch for
//! the lifetime of the allocation owner. A missing, mismatched, or null entry
//! refuses construction; there is no direct-export fallback.

use std::ffi::{CStr, c_void};

use cudarc::driver::{result::DriverError, sys};
use serde::Serialize;

use crate::{ForgeError, Result};

const CUDA_MEMORY_ABI_VERSION: i32 = 3020;
const DRIVER_ENTRY_REMEDIATION: &str = "install a CUDA driver that exposes cuMemGetInfo, cuMemAlloc, cuMemFree, and cuMemGetAddressRange at ABI version 3020 through cuGetProcAddress_v2; do not substitute direct exports or a different ABI version";

type CuMemGetInfo = unsafe extern "C" fn(*mut usize, *mut usize) -> sys::CUresult;
type CuMemAlloc = unsafe extern "C" fn(*mut sys::CUdeviceptr, usize) -> sys::CUresult;
type CuMemFree = unsafe extern "C" fn(sys::CUdeviceptr) -> sys::CUresult;
type CuMemGetAddressRange =
    unsafe extern "C" fn(*mut sys::CUdeviceptr, *mut usize, sys::CUdeviceptr) -> sys::CUresult;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
/// Physical receipt for one CUDA driver entry resolved at an exact ABI.
pub struct CudaDriverEntryReceipt {
    /// Base symbol passed to `cuGetProcAddress_v2`.
    pub symbol: String,
    /// Exact ABI version requested for this symbol.
    pub requested_abi_version: i32,
    /// Numeric `CUdriverProcAddressQueryResult` returned by the driver.
    pub query_status: u32,
    /// Process-local function address returned by the driver.
    pub function_address: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
/// Read-only provenance for Forge's coherent CUDA memory dispatch table.
pub struct CudaDriverMemoryApiReceipt {
    /// Receipt schema.
    pub schema: &'static str,
    /// Driver API version read from the loaded CUDA driver.
    pub driver_version: i32,
    /// Exact ABI version requested for every memory entry.
    pub requested_abi_version: i32,
    /// Numeric `CU_GET_PROC_ADDRESS_DEFAULT` flag value.
    pub flags: u64,
    /// Resolved entries in deterministic lifecycle order.
    pub entries: Vec<CudaDriverEntryReceipt>,
}

#[derive(Clone)]
pub(crate) struct CudaDriverMemoryApi {
    get_info: CuMemGetInfo,
    alloc: CuMemAlloc,
    free: CuMemFree,
    get_address_range: CuMemGetAddressRange,
    receipt: CudaDriverMemoryApiReceipt,
}

impl CudaDriverMemoryApi {
    pub(crate) fn resolve() -> Result<Self> {
        let mut driver_version = 0_i32;
        let version_status = unsafe { sys::cuDriverGetVersion(&mut driver_version) };
        if version_status != sys::CUresult::CUDA_SUCCESS {
            return Err(driver_entry_error(format!(
                "cuDriverGetVersion failed: status={version_status:?} numeric={}",
                version_status as i32
            )));
        }
        if driver_version < CUDA_MEMORY_ABI_VERSION {
            return Err(driver_entry_error(format!(
                "loaded CUDA driver version {driver_version} is below required memory ABI {CUDA_MEMORY_ABI_VERSION}"
            )));
        }

        let (get_info_ptr, get_info_receipt) = resolve_entry(c"cuMemGetInfo")?;
        let (alloc_ptr, alloc_receipt) = resolve_entry(c"cuMemAlloc")?;
        let (free_ptr, free_receipt) = resolve_entry(c"cuMemFree")?;
        let (get_address_range_ptr, get_address_range_receipt) =
            resolve_entry(c"cuMemGetAddressRange")?;

        Ok(Self {
            get_info: unsafe { std::mem::transmute::<*mut c_void, CuMemGetInfo>(get_info_ptr) },
            alloc: unsafe { std::mem::transmute::<*mut c_void, CuMemAlloc>(alloc_ptr) },
            free: unsafe { std::mem::transmute::<*mut c_void, CuMemFree>(free_ptr) },
            get_address_range: unsafe {
                std::mem::transmute::<*mut c_void, CuMemGetAddressRange>(get_address_range_ptr)
            },
            receipt: CudaDriverMemoryApiReceipt {
                schema: "calyx.forge.cuda-driver-memory-api.v1",
                driver_version,
                requested_abi_version: CUDA_MEMORY_ABI_VERSION,
                flags: sys::CUdriverProcAddress_flags::CU_GET_PROC_ADDRESS_DEFAULT as u64,
                entries: vec![
                    get_info_receipt,
                    alloc_receipt,
                    free_receipt,
                    get_address_range_receipt,
                ],
            },
        })
    }

    pub(crate) fn receipt(&self) -> &CudaDriverMemoryApiReceipt {
        &self.receipt
    }

    pub(crate) fn get_info(&self) -> std::result::Result<(usize, usize), DriverError> {
        let mut free_bytes = 0_usize;
        let mut total_bytes = 0_usize;
        let status = unsafe { (self.get_info)(&mut free_bytes, &mut total_bytes) };
        driver_result(status, (free_bytes, total_bytes))
    }

    pub(crate) fn allocate(
        &self,
        size_bytes: usize,
    ) -> std::result::Result<sys::CUdeviceptr, DriverError> {
        let mut ptr = 0_u64;
        let status = unsafe { (self.alloc)(&mut ptr, size_bytes) };
        driver_result(status, ptr)
    }

    pub(crate) fn free(&self, ptr: sys::CUdeviceptr) -> std::result::Result<(), DriverError> {
        let status = unsafe { (self.free)(ptr) };
        driver_result(status, ())
    }

    pub(crate) fn get_address_range(
        &self,
        ptr: sys::CUdeviceptr,
    ) -> std::result::Result<(sys::CUdeviceptr, usize), DriverError> {
        let mut base = 0_u64;
        let mut size_bytes = 0_usize;
        let status = unsafe { (self.get_address_range)(&mut base, &mut size_bytes, ptr) };
        driver_result(status, (base, size_bytes))
    }
}

fn resolve_entry(symbol: &CStr) -> Result<(*mut c_void, CudaDriverEntryReceipt)> {
    let mut function = std::ptr::null_mut();
    let mut query_status =
        sys::CUdriverProcAddressQueryResult::CU_GET_PROC_ADDRESS_SYMBOL_NOT_FOUND;
    let status = unsafe {
        sys::cuGetProcAddress_v2(
            symbol.as_ptr(),
            &mut function,
            CUDA_MEMORY_ABI_VERSION,
            sys::CUdriverProcAddress_flags::CU_GET_PROC_ADDRESS_DEFAULT as u64,
            &mut query_status,
        )
    };
    let symbol = symbol.to_string_lossy().into_owned();
    if status != sys::CUresult::CUDA_SUCCESS
        || query_status != sys::CUdriverProcAddressQueryResult::CU_GET_PROC_ADDRESS_SUCCESS
        || function.is_null()
    {
        return Err(driver_entry_error(format!(
            "symbol={symbol} requested_abi={CUDA_MEMORY_ABI_VERSION} driver_status={status:?} driver_status_numeric={} query_status={query_status:?} query_status_numeric={} null={}",
            status as i32,
            query_status as u32,
            function.is_null()
        )));
    }
    let function_address = u64::try_from(function.addr()).map_err(|_| {
        driver_entry_error(format!(
            "symbol={symbol} returned a function address that exceeds u64"
        ))
    })?;
    Ok((
        function,
        CudaDriverEntryReceipt {
            symbol,
            requested_abi_version: CUDA_MEMORY_ABI_VERSION,
            query_status: query_status as u32,
            function_address,
        },
    ))
}

fn driver_result<T>(status: sys::CUresult, value: T) -> std::result::Result<T, DriverError> {
    if status == sys::CUresult::CUDA_SUCCESS {
        Ok(value)
    } else {
        Err(DriverError(status))
    }
}

fn driver_entry_error(detail: String) -> ForgeError {
    ForgeError::RuntimeBoundary {
        code: "CALYX_FORGE_CUDA_DRIVER_ENTRY_POINT",
        detail,
        remediation: DRIVER_ENTRY_REMEDIATION,
    }
}
