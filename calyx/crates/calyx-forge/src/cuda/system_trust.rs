use std::collections::BTreeSet;
use std::ffi::{OsString, c_void};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::path::{Component, Path, PathBuf};
use std::ptr;
use std::slice;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    ERROR_NOT_FOUND, ERROR_SUCCESS, GetLastError, HANDLE, SetLastError,
};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_SHA256_ALGORITHM, CERT_CONTEXT, CERT_NAME_ATTR_TYPE, CertGetNameStringW,
    szOID_COMMON_NAME, szOID_ORGANIZATION_NAME,
};
use windows_sys::Win32::Security::WinTrust::{
    DRIVER_ACTION_VERIFY, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA,
    WINTRUST_DATA_0, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_DISABLE_MD2_MD4,
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
    WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_EXECUTE, WTHelperGetProvCertFromChain,
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrustEx,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_SHARE_READ, GetFileVersionInfoSizeW, GetFileVersionInfoW,
    GetFinalPathNameByHandleW, VerQueryValueW,
};

use crate::{ForgeError, Result};

const TRUST_SCHEMA: &str = "calyx-system-module-trust-v1";
const TRUST_REMEDIATION: &str =
    "repair or reinstall the signed NVIDIA Windows driver, then restart Astrolabe";
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024 * 1024;
const MAX_FINAL_PATH_CHARS: usize = 32_768;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemModuleTrustPolicy {
    pub module_name: String,
    pub required_root: PathBuf,
    pub authenticode_signer_organization: String,
    pub signed_company_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemModuleVersionTranslation {
    pub language: u16,
    pub code_page: u16,
    pub company_name: String,
    pub file_version: String,
    pub product_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemModuleTrustAttestation {
    pub schema: String,
    pub module_name: String,
    pub module_path: PathBuf,
    pub file_bytes: u64,
    pub file_sha256: String,
    pub signature_kind: String,
    pub catalog_path: PathBuf,
    pub catalog_candidate_count: usize,
    pub catalog_member_hash_algorithm: String,
    pub catalog_member_sha256: String,
    pub winverifytrust_status: i32,
    pub signer_common_name: String,
    pub signer_organization: String,
    pub signer_certificate_sha256: String,
    pub signed_company_name: String,
    pub signed_file_version: String,
    pub signed_product_name: String,
    pub version_translations: Vec<SystemModuleVersionTranslation>,
}

#[must_use = "the file lock must remain alive through LoadLibraryExW"]
#[derive(Debug)]
pub struct VerifiedSystemFile {
    file: File,
    attestation: SystemModuleTrustAttestation,
}

impl VerifiedSystemFile {
    pub fn path(&self) -> &Path {
        &self.attestation.module_path
    }

    pub fn attestation(&self) -> &SystemModuleTrustAttestation {
        &self.attestation
    }
}

impl AsRawHandle for VerifiedSystemFile {
    fn as_raw_handle(&self) -> RawHandle {
        self.file.as_raw_handle()
    }
}

struct CatalogAdmin {
    handle: isize,
}

impl CatalogAdmin {
    fn acquire() -> Result<Self> {
        let mut handle = 0isize;
        let ok = unsafe {
            CryptCATAdminAcquireContext2(
                &mut handle,
                &DRIVER_ACTION_VERIFY,
                BCRYPT_SHA256_ALGORITHM,
                ptr::null(),
                0,
            )
        };
        if ok == 0 {
            return Err(last_windows_error(
                "CALYX_CUDA_DRIVER_CATALOG_CONTEXT_FAILED",
                "CryptCATAdminAcquireContext2(SHA256)",
            ));
        }
        if handle == 0 {
            return Err(trust_error(
                "CALYX_CUDA_DRIVER_CATALOG_CONTEXT_FAILED",
                "CryptCATAdminAcquireContext2 succeeded with a null handle",
            ));
        }
        Ok(Self { handle })
    }

    fn release(&mut self) -> Result<()> {
        let handle = std::mem::replace(&mut self.handle, 0);
        if handle == 0 {
            return Ok(());
        }
        if unsafe { CryptCATAdminReleaseContext(handle, 0) } == 0 {
            return Err(last_windows_error(
                "CALYX_CUDA_DRIVER_CATALOG_CLEANUP_FAILED",
                "CryptCATAdminReleaseContext",
            ));
        }
        Ok(())
    }
}

impl Drop for CatalogAdmin {
    fn drop(&mut self) {
        if self.handle == 0 {
            return;
        }
        let handle = std::mem::replace(&mut self.handle, 0);
        if unsafe { CryptCATAdminReleaseContext(handle, 0) } == 0 {
            let windows_error = unsafe { GetLastError() };
            tracing::error!(
                code = "CALYX_CUDA_DRIVER_CATALOG_CLEANUP_FAILED",
                windows_error,
                "CryptCATAdminReleaseContext failed during unwind cleanup"
            );
        }
    }
}

struct CatalogTrustProof {
    catalog_path: PathBuf,
    signer_common_name: String,
    signer_organization: String,
    signer_certificate_sha256: String,
}

struct SignedVersionInfo {
    company_name: String,
    file_version: String,
    product_name: String,
    translations: Vec<SystemModuleVersionTranslation>,
}

pub fn verify_system_module(
    path: &Path,
    policy: &SystemModuleTrustPolicy,
) -> Result<VerifiedSystemFile> {
    validate_policy(policy)?;

    reject_reparse(path, "system module path")?;
    let required_root = canonical_existing_dir(&policy.required_root, "system module root")?;
    let module_path = canonical_existing_file(path, "system module")?;
    reject_reparse(&module_path, "canonical system module")?;

    let observed_name = module_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            trust_error(
                "CALYX_CUDA_DRIVER_PATH_INVALID",
                format!(
                    "module path has no UTF-8 basename: {}",
                    module_path.display()
                ),
            )
        })?;
    if !observed_name.eq_ignore_ascii_case(&policy.module_name) {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_NAME_MISMATCH",
            format!(
                "module basename is {observed_name}; policy requires {}",
                policy.module_name
            ),
        ));
    }

    let parent = module_path.parent().ok_or_else(|| {
        trust_error(
            "CALYX_CUDA_DRIVER_PATH_INVALID",
            format!("module has no parent: {}", module_path.display()),
        )
    })?;
    if !same_path(parent, &required_root) {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_ROOT_MISMATCH",
            format!(
                "{} is outside required root {}",
                module_path.display(),
                required_root.display()
            ),
        ));
    }

    // Existing handles with write/delete access prevent this open from succeeding.
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(&module_path)
        .map_err(|error| {
            trust_error(
                "CALYX_CUDA_DRIVER_OPEN_FAILED",
                format!(
                    "open {} with read-only sharing failed: {error}",
                    module_path.display()
                ),
            )
        })?;

    let handle_path = final_path(&file)?;
    if !same_path(&handle_path, &module_path) {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_PATH_RACE",
            format!(
                "opened handle resolves to {}; expected {}",
                handle_path.display(),
                module_path.display()
            ),
        ));
    }

    let version_info = signed_version_info(&module_path)?;
    if version_info.company_name != policy.signed_company_name {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_PUBLISHER_MISMATCH",
            format!(
                "{} signed CompanyName is {:?}; policy requires exactly {:?}",
                module_path.display(),
                version_info.company_name,
                policy.signed_company_name
            ),
        ));
    }

    let mut admin = CatalogAdmin::acquire()?;
    let operation = verify_with_catalog_admin(
        &file,
        &module_path,
        &required_root,
        &policy.authenticode_signer_organization,
        admin.handle,
    );
    let cleanup = admin.release();
    let (proof, catalog_count, member_hash) = merge_cleanup(operation, cleanup)?;

    let metadata = file.metadata().map_err(|error| {
        trust_error(
            "CALYX_CUDA_DRIVER_FILE_UNREADABLE",
            format!("stat {} failed: {error}", module_path.display()),
        )
    })?;
    let file_sha256 = sha256_open_file(&file, metadata.len())?;

    Ok(VerifiedSystemFile {
        file,
        attestation: SystemModuleTrustAttestation {
            schema: TRUST_SCHEMA.to_string(),
            module_name: policy.module_name.clone(),
            module_path,
            file_bytes: metadata.len(),
            file_sha256,
            signature_kind: "windows-catalog-authenticode".to_string(),
            catalog_path: proof.catalog_path,
            catalog_candidate_count: catalog_count,
            catalog_member_hash_algorithm: "SHA256".to_string(),
            catalog_member_sha256: hex_lower(&member_hash),
            winverifytrust_status: 0,
            signer_common_name: proof.signer_common_name,
            signer_organization: proof.signer_organization,
            signer_certificate_sha256: proof.signer_certificate_sha256,
            signed_company_name: version_info.company_name,
            signed_file_version: version_info.file_version,
            signed_product_name: version_info.product_name,
            version_translations: version_info.translations,
        },
    })
}

fn verify_with_catalog_admin(
    file: &File,
    module_path: &Path,
    system32: &Path,
    expected_signer_organization: &str,
    admin: isize,
) -> Result<(CatalogTrustProof, usize, Vec<u8>)> {
    let member_hash = catalog_member_hash(admin, file)?;
    let catalogs = enumerate_catalog_paths(admin, &member_hash, system32)?;
    let mut failures = Vec::new();

    for catalog in &catalogs {
        match verify_catalog_member(
            admin,
            file,
            module_path,
            catalog,
            &member_hash,
            expected_signer_organization,
        ) {
            Ok(proof) => return Ok((proof, catalogs.len(), member_hash)),
            Err(error) => failures.push(format!("{}: {error}", catalog.display())),
        }
    }

    Err(trust_error(
        "CALYX_CUDA_DRIVER_TRUST_FAILED",
        format!(
            "no catalog produced the required trust proof for {}; candidates: {}",
            module_path.display(),
            failures.join(" | ")
        ),
    ))
}

fn catalog_member_hash(admin: isize, file: &File) -> Result<Vec<u8>> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut bytes = 0u32;
    if unsafe {
        CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut bytes, ptr::null_mut(), 0)
    } == 0
    {
        return Err(last_windows_error(
            "CALYX_CUDA_DRIVER_CATALOG_HASH_FAILED",
            "CryptCATAdminCalcHashFromFileHandle2(size)",
        ));
    }
    if bytes != 32 {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_CATALOG_HASH_INVALID",
            format!("SHA256 catalog member hash has {bytes} bytes; expected 32"),
        ));
    }

    let mut hash = vec![0u8; bytes as usize];
    if unsafe {
        CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut bytes, hash.as_mut_ptr(), 0)
    } == 0
    {
        return Err(last_windows_error(
            "CALYX_CUDA_DRIVER_CATALOG_HASH_FAILED",
            "CryptCATAdminCalcHashFromFileHandle2(data)",
        ));
    }
    if bytes != 32 {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_CATALOG_HASH_INVALID",
            format!("catalog hash call returned {bytes} bytes; expected 32"),
        ));
    }
    Ok(hash)
}

fn enumerate_catalog_paths(admin: isize, hash: &[u8], system32: &Path) -> Result<Vec<PathBuf>> {
    let cat_root = canonical_existing_dir(&system32.join("CatRoot"), "Windows CatRoot")?;

    unsafe { SetLastError(ERROR_SUCCESS) };
    let mut current = unsafe {
        CryptCATAdminEnumCatalogFromHash(
            admin,
            hash.as_ptr(),
            hash.len() as u32,
            0,
            ptr::null_mut(),
        )
    };
    if current == 0 {
        let windows_error = unsafe { GetLastError() };
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_CATALOG_MISSING",
            format!(
                "no SHA256 catalog contains the system module hash; Windows error {windows_error}"
            ),
        ));
    }

    let mut paths = Vec::new();
    loop {
        let path_result = catalog_path_from_context(current).and_then(|path| {
            reject_reparse(&path, "catalog path")?;
            let canonical = canonical_existing_file(&path, "catalog")?;
            reject_reparse(&canonical, "canonical catalog")?;
            if !path_is_within(&canonical, &cat_root) {
                return Err(trust_error(
                    "CALYX_CUDA_DRIVER_CATALOG_ROOT_MISMATCH",
                    format!(
                        "{} is outside Windows CatRoot {}",
                        canonical.display(),
                        cat_root.display()
                    ),
                ));
            }
            Ok(canonical)
        });

        let path = match path_result {
            Ok(path) => path,
            Err(primary) => {
                let cleanup = release_catalog_context(admin, current);
                return merge_cleanup::<Vec<PathBuf>>(Err(primary), cleanup);
            }
        };
        paths.push(path);

        // Passing the previous context transfers it back to the enumerator.
        // Do not release it separately after this call.
        let mut previous = current;
        unsafe { SetLastError(ERROR_SUCCESS) };
        current = unsafe {
            CryptCATAdminEnumCatalogFromHash(
                admin,
                hash.as_ptr(),
                hash.len() as u32,
                0,
                &mut previous,
            )
        };
        if current == 0 {
            let windows_error = unsafe { GetLastError() };
            if windows_error != ERROR_SUCCESS && windows_error != ERROR_NOT_FOUND {
                return Err(trust_error(
                    "CALYX_CUDA_DRIVER_CATALOG_ENUM_FAILED",
                    format!("catalog enumeration ended with Windows error {windows_error}"),
                ));
            }
            break;
        }
    }

    paths.sort_by_key(|path| normalized_path(path));
    paths.dedup_by(|left, right| same_path(left, right));
    if paths.is_empty() {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_CATALOG_MISSING",
            "catalog enumeration returned no usable paths",
        ));
    }
    Ok(paths)
}

fn catalog_path_from_context(context: isize) -> Result<PathBuf> {
    let mut info = CATALOG_INFO {
        cbStruct: size_of::<CATALOG_INFO>() as u32,
        ..Default::default()
    };
    if unsafe { CryptCATCatalogInfoFromContext(context, &mut info, 0) } == 0 {
        return Err(last_windows_error(
            "CALYX_CUDA_DRIVER_CATALOG_INFO_FAILED",
            "CryptCATCatalogInfoFromContext",
        ));
    }
    let end = info
        .wszCatalogFile
        .iter()
        .position(|unit| *unit == 0)
        .ok_or_else(|| {
            trust_error(
                "CALYX_CUDA_DRIVER_CATALOG_INFO_INVALID",
                "catalog path is not NUL-terminated",
            )
        })?;
    if end == 0 {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_CATALOG_INFO_INVALID",
            "catalog path is empty",
        ));
    }
    Ok(PathBuf::from(OsString::from_wide(
        &info.wszCatalogFile[..end],
    )))
}

fn release_catalog_context(admin: isize, context: isize) -> Result<()> {
    if unsafe { CryptCATAdminReleaseCatalogContext(admin, context, 0) } == 0 {
        return Err(last_windows_error(
            "CALYX_CUDA_DRIVER_CATALOG_CLEANUP_FAILED",
            "CryptCATAdminReleaseCatalogContext",
        ));
    }
    Ok(())
}

fn verify_catalog_member(
    admin: isize,
    file: &File,
    module_path: &Path,
    catalog_path: &Path,
    hash: &[u8],
    expected_signer_organization: &str,
) -> Result<CatalogTrustProof> {
    let module_wide = wide_path(module_path)?;
    let catalog_wide = wide_path(catalog_path)?;
    let member_tag = wide_text(&hex_upper(hash))?;
    let mut mutable_hash = hash.to_vec();

    let mut catalog = WINTRUST_CATALOG_INFO {
        cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
        pcwszCatalogFilePath: catalog_wide.as_ptr(),
        pcwszMemberTag: member_tag.as_ptr(),
        pcwszMemberFilePath: module_wide.as_ptr(),
        hMemberFile: file.as_raw_handle() as HANDLE,
        pbCalculatedFileHash: mutable_hash.as_mut_ptr(),
        cbCalculatedFileHash: mutable_hash.len() as u32,
        hCatAdmin: admin,
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_CATALOG,
        Anonymous: WINTRUST_DATA_0 {
            pCatalog: &mut catalog,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
            | WTD_DISABLE_MD2_MD4
            | WTD_CACHE_ONLY_URL_RETRIEVAL,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe { WinVerifyTrustEx(ptr::null_mut(), &mut action, &mut data) };

    let primary = if status == 0 {
        signer_proof(&data, catalog_path, expected_signer_organization)
    } else {
        Err(trust_error(
            "CALYX_CUDA_DRIVER_TRUST_FAILED",
            format!(
                "WinVerifyTrustEx rejected {} through {} with status 0x{:08X}",
                module_path.display(),
                catalog_path.display(),
                status as u32
            ),
        ))
    };

    data.dwStateAction = WTD_STATEACTION_CLOSE;
    let close_status = unsafe { WinVerifyTrustEx(ptr::null_mut(), &mut action, &mut data) };
    let cleanup = if close_status == 0 {
        Ok(())
    } else {
        Err(trust_error(
            "CALYX_CUDA_DRIVER_TRUST_CLEANUP_FAILED",
            format!(
                "WinVerifyTrustEx(WTD_STATEACTION_CLOSE) returned 0x{:08X}",
                close_status as u32
            ),
        ))
    };
    merge_cleanup(primary, cleanup)
}

fn signer_proof(
    data: &WINTRUST_DATA,
    catalog_path: &Path,
    expected_organization: &str,
) -> Result<CatalogTrustProof> {
    if data.hWVTStateData.is_null() {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_SIGNER_STATE_MISSING",
            "WinVerifyTrustEx returned no provider state",
        ));
    }
    let provider = unsafe { WTHelperProvDataFromStateData(data.hWVTStateData) };
    if provider.is_null() {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_SIGNER_STATE_MISSING",
            "WTHelperProvDataFromStateData returned null",
        ));
    }
    let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
    if signer.is_null() {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_SIGNER_STATE_MISSING",
            "WTHelperGetProvSignerFromChain returned null",
        ));
    }
    let provider_cert = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
    if provider_cert.is_null() {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_SIGNER_STATE_MISSING",
            "WTHelperGetProvCertFromChain returned null",
        ));
    }
    let cert = unsafe { (*provider_cert).pCert };
    if cert.is_null() {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_SIGNER_STATE_MISSING",
            "catalog signer has no certificate context",
        ));
    }

    let organization = certificate_attribute(cert, szOID_ORGANIZATION_NAME)?;
    if organization != expected_organization {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_SIGNER_MISMATCH",
            format!(
                "catalog signer organization is {organization:?}; policy requires {expected_organization:?}"
            ),
        ));
    }
    let common_name = certificate_attribute(cert, szOID_COMMON_NAME)?;
    let certificate_sha256 = certificate_sha256(cert)?;

    Ok(CatalogTrustProof {
        catalog_path: catalog_path.to_path_buf(),
        signer_common_name: common_name,
        signer_organization: organization,
        signer_certificate_sha256: certificate_sha256,
    })
}

fn certificate_attribute(cert: *const CERT_CONTEXT, oid: *const u8) -> Result<String> {
    let needed = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_ATTR_TYPE,
            0,
            oid.cast::<c_void>(),
            ptr::null_mut(),
            0,
        )
    };
    if needed <= 1 {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_SIGNER_NAME_MISSING",
            "catalog signer certificate attribute is absent",
        ));
    }

    let mut value = vec![0u16; needed as usize];
    let written = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_ATTR_TYPE,
            0,
            oid.cast::<c_void>(),
            value.as_mut_ptr(),
            value.len() as u32,
        )
    };
    if written != needed || value.last() != Some(&0) || value[..value.len() - 1].contains(&0) {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_SIGNER_NAME_INVALID",
            "catalog signer certificate attribute is malformed",
        ));
    }
    value.pop();
    String::from_utf16(&value).map_err(|error| {
        trust_error(
            "CALYX_CUDA_DRIVER_SIGNER_NAME_INVALID",
            format!("catalog signer name is invalid UTF-16: {error}"),
        )
    })
}

fn certificate_sha256(cert: *const CERT_CONTEXT) -> Result<String> {
    let cert = unsafe { &*cert };
    let bytes = cert.cbCertEncoded as usize;
    if cert.pbCertEncoded.is_null() || bytes == 0 || bytes > MAX_CERTIFICATE_BYTES {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_SIGNER_CERT_INVALID",
            format!("catalog signer certificate has invalid encoded size {bytes}"),
        ));
    }
    let encoded = unsafe { slice::from_raw_parts(cert.pbCertEncoded, bytes) };
    Ok(format!("{:x}", Sha256::digest(encoded)))
}

fn signed_version_info(path: &Path) -> Result<SignedVersionInfo> {
    let wide = wide_path(path)?;
    let mut ignored = 0u32;
    let size = unsafe { GetFileVersionInfoSizeW(wide.as_ptr(), &mut ignored) };
    if size == 0 {
        return Err(last_windows_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_MISSING",
            format!("GetFileVersionInfoSizeW({})", path.display()),
        ));
    }

    let size = size as usize;
    let words = size
        .checked_add(size_of::<usize>() - 1)
        .and_then(|value| value.checked_div(size_of::<usize>()))
        .ok_or_else(|| {
            trust_error(
                "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
                "version-information allocation overflow",
            )
        })?;
    let mut storage = vec![0usize; words];
    if unsafe {
        GetFileVersionInfoW(
            wide.as_ptr(),
            0,
            size as u32,
            storage.as_mut_ptr().cast::<c_void>(),
        )
    } == 0
    {
        return Err(last_windows_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            format!("GetFileVersionInfoW({})", path.display()),
        ));
    }

    let (translations, translation_bytes) =
        query_version_value(&storage, size, "\\VarFileInfo\\Translation")?;
    if translation_bytes == 0 || translation_bytes % 4 != 0 {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            format!("translation table has {translation_bytes} bytes"),
        ));
    }
    checked_region(&storage, size, translations, translation_bytes)?;

    let mut pairs = BTreeSet::new();
    for offset in (0..translation_bytes).step_by(4) {
        let language = unsafe { ptr::read_unaligned(translations.add(offset).cast::<u16>()) };
        let codepage = unsafe { ptr::read_unaligned(translations.add(offset + 2).cast::<u16>()) };
        if !pairs.insert((language, codepage)) {
            return Err(trust_error(
                "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
                format!("duplicate version translation {language:04X}{codepage:04X}"),
            ));
        }
    }

    let mut company_names = BTreeSet::new();
    let mut file_versions = BTreeSet::new();
    let mut product_names = BTreeSet::new();
    let mut version_translations = Vec::with_capacity(pairs.len());
    for (language, codepage) in pairs {
        let prefix = format!("\\StringFileInfo\\{language:04X}{codepage:04X}");
        let company_name = version_string(&storage, size, &prefix, "CompanyName")?;
        let file_version = version_string(&storage, size, &prefix, "FileVersion")?;
        let product_name = version_string(&storage, size, &prefix, "ProductName")?;

        company_names.insert(company_name.clone());
        file_versions.insert(file_version.clone());
        product_names.insert(product_name.clone());
        version_translations.push(SystemModuleVersionTranslation {
            language,
            code_page: codepage,
            company_name,
            file_version,
            product_name,
        });
    }

    Ok(SignedVersionInfo {
        company_name: require_consistent_version_value(company_names, "CompanyName")?,
        file_version: require_consistent_version_value(file_versions, "FileVersion")?,
        product_name: require_consistent_version_value(product_names, "ProductName")?,
        translations: version_translations,
    })
}

fn version_string(
    storage: &[usize],
    used_bytes: usize,
    prefix: &str,
    field: &str,
) -> Result<String> {
    let key = format!("{prefix}\\{field}");
    let (value, characters) = query_version_value(storage, used_bytes, &key)?;
    let value_bytes = characters.checked_mul(2).ok_or_else(|| {
        trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            format!("{field} byte length overflow"),
        )
    })?;
    if characters < 2 {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            format!("{key} is empty"),
        ));
    }
    checked_region(storage, used_bytes, value, value_bytes)?;

    let mut units = Vec::with_capacity(characters);
    for index in 0..characters {
        units.push(unsafe { ptr::read_unaligned(value.add(index * 2).cast::<u16>()) });
    }
    if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            format!("{key} is not a single NUL-terminated string"),
        ));
    }
    units.pop();
    let value = String::from_utf16(&units).map_err(|error| {
        trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            format!("{key} is invalid UTF-16: {error}"),
        )
    })?;
    if value.trim().is_empty() {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            format!("{key} is blank"),
        ));
    }
    Ok(value)
}

fn require_consistent_version_value(values: BTreeSet<String>, field: &str) -> Result<String> {
    if values.is_empty() {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            format!("{field} is absent from every version translation"),
        ));
    }
    if values.len() > 1 {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INCONSISTENT",
            format!("{field} differs across version translations: {values:?}"),
        ));
    }
    values.into_iter().next().ok_or_else(|| {
        trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            format!("{field} is absent from every version translation"),
        )
    })
}

fn query_version_value(
    storage: &[usize],
    used_bytes: usize,
    key: &str,
) -> Result<(*const u8, usize)> {
    let key = wide_text(key)?;
    let mut value = ptr::null_mut::<c_void>();
    let mut length = 0u32;
    if unsafe {
        VerQueryValueW(
            storage.as_ptr().cast::<c_void>(),
            key.as_ptr(),
            &mut value,
            &mut length,
        )
    } == 0
    {
        return Err(last_windows_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            "VerQueryValueW",
        ));
    }
    if value.is_null() {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            "VerQueryValueW returned a null value",
        ));
    }
    let pointer = value.cast::<u8>();
    let length = length as usize;

    // Length is bytes for Translation and UTF-16 characters for StringFileInfo.
    // The caller performs the correctly scaled full-region check.
    let base = storage.as_ptr() as usize;
    let end = base.checked_add(used_bytes).ok_or_else(|| {
        trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            "version-information address overflow",
        )
    })?;
    let address = pointer as usize;
    if address < base || address > end {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            "VerQueryValueW returned a pointer outside its source block",
        ));
    }
    Ok((pointer, length))
}

fn checked_region(
    storage: &[usize],
    used_bytes: usize,
    pointer: *const u8,
    bytes: usize,
) -> Result<()> {
    let base = storage.as_ptr() as usize;
    let end = base.checked_add(used_bytes).ok_or_else(|| {
        trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            "version-information address overflow",
        )
    })?;
    let start = pointer as usize;
    let value_end = start.checked_add(bytes).ok_or_else(|| {
        trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            "version-information value overflow",
        )
    })?;
    if start < base || start > end || value_end > end {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_VERSION_INFO_INVALID",
            "version-information value lies outside its source block",
        ));
    }
    Ok(())
}

fn final_path(file: &File) -> Result<PathBuf> {
    let handle = file.as_raw_handle() as HANDLE;
    let mut capacity = 512usize;
    loop {
        let mut buffer = vec![0u16; capacity];
        let written = unsafe {
            GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0)
        } as usize;
        if written == 0 {
            return Err(last_windows_error(
                "CALYX_CUDA_DRIVER_PATH_QUERY_FAILED",
                "GetFinalPathNameByHandleW",
            ));
        }
        if written < buffer.len() {
            buffer.truncate(written);
            if buffer.contains(&0) {
                return Err(trust_error(
                    "CALYX_CUDA_DRIVER_PATH_QUERY_FAILED",
                    "handle path contains an interior NUL",
                ));
            }
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        capacity = written.checked_add(1).ok_or_else(|| {
            trust_error(
                "CALYX_CUDA_DRIVER_PATH_QUERY_FAILED",
                "handle path length overflow",
            )
        })?;
        if capacity > MAX_FINAL_PATH_CHARS {
            return Err(trust_error(
                "CALYX_CUDA_DRIVER_PATH_QUERY_FAILED",
                format!("handle path requires {capacity} UTF-16 characters"),
            ));
        }
    }
}

fn sha256_open_file(file: &File, expected_bytes: u64) -> Result<String> {
    let mut hasher = Sha256::new();
    let mut offset = 0u64;
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let count = file.seek_read(&mut buffer, offset).map_err(|error| {
            trust_error(
                "CALYX_CUDA_DRIVER_FILE_UNREADABLE",
                format!("read system module at offset {offset} failed: {error}"),
            )
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        offset = offset.checked_add(count as u64).ok_or_else(|| {
            trust_error(
                "CALYX_CUDA_DRIVER_FILE_UNREADABLE",
                "system module length overflow",
            )
        })?;
    }
    if offset != expected_bytes {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_FILE_CHANGED",
            format!("read {offset} bytes; metadata reports {expected_bytes}"),
        ));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_policy(policy: &SystemModuleTrustPolicy) -> Result<()> {
    let name = Path::new(&policy.module_name);
    if policy.module_name.is_empty()
        || name.is_absolute()
        || name
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || name.components().count() != 1
        || policy.authenticode_signer_organization.is_empty()
        || policy.signed_company_name.is_empty()
    {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_POLICY_INVALID",
            "system module trust policy is incomplete or unsafe",
        ));
    }
    Ok(())
}

fn canonical_existing_file(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        trust_error(
            "CALYX_CUDA_DRIVER_FILE_MISSING",
            format!("canonicalize {label} {} failed: {error}", path.display()),
        )
    })?;
    if !canonical.is_file() {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_FILE_MISSING",
            format!("{label} {} is not a file", canonical.display()),
        ));
    }
    Ok(canonical)
}

fn canonical_existing_dir(path: &Path, label: &str) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path).map_err(|error| {
        trust_error(
            "CALYX_CUDA_DRIVER_ROOT_MISSING",
            format!("canonicalize {label} {} failed: {error}", path.display()),
        )
    })?;
    if !canonical.is_dir() {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_ROOT_MISSING",
            format!("{label} {} is not a directory", canonical.display()),
        ));
    }
    Ok(canonical)
}

fn reject_reparse(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        trust_error(
            "CALYX_CUDA_DRIVER_PATH_UNREADABLE",
            format!(
                "read {label} metadata for {} failed: {error}",
                path.display()
            ),
        )
    })?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_REPARSE_REFUSED",
            format!("{label} {} is a reparse point", path.display()),
        ));
    }
    Ok(())
}

fn wide_path(path: &Path) -> Result<Vec<u16>> {
    let mut value = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if value.contains(&0) {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_PATH_INVALID",
            format!("path contains an interior NUL: {}", path.display()),
        ));
    }
    value.push(0);
    Ok(value)
}

fn wide_text(value: &str) -> Result<Vec<u16>> {
    let mut value = value.encode_utf16().collect::<Vec<_>>();
    if value.contains(&0) {
        return Err(trust_error(
            "CALYX_CUDA_DRIVER_DATA_INVALID",
            "Win32 string contains an interior NUL",
        ));
    }
    value.push(0);
    Ok(value)
}

fn normalized_path(path: &Path) -> String {
    let mut value = path.to_string_lossy().replace('/', "\\");
    if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
        value = format!(r"\\{rest}");
    } else if let Some(rest) = value.strip_prefix(r"\\?\") {
        value = rest.to_string();
    }
    value.trim_end_matches('\\').to_ascii_lowercase()
}

fn same_path(left: &Path, right: &Path) -> bool {
    normalized_path(left) == normalized_path(right)
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    let path = normalized_path(path);
    let root = normalized_path(root);
    path == root || path.starts_with(&(root + "\\"))
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02X}");
    }
    out
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn merge_cleanup<T>(primary: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (primary, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(trust_error(
            "CALYX_CUDA_DRIVER_CLEANUP_FAILED",
            format!("primary failure: {primary}; cleanup failure: {cleanup}"),
        )),
    }
}

fn last_windows_error(code: &'static str, operation: impl Into<String>) -> ForgeError {
    let windows_error = unsafe { GetLastError() };
    let message = io::Error::from_raw_os_error(windows_error as i32);
    trust_error(
        code,
        format!(
            "{} failed with Windows error {windows_error}: {message}",
            operation.into()
        ),
    )
}

fn trust_error(code: &'static str, detail: impl Into<String>) -> ForgeError {
    ForgeError::RuntimeBoundary {
        code,
        detail: detail.into(),
        remediation: TRUST_REMEDIATION,
    }
}
