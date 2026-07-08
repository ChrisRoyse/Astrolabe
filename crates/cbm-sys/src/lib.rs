#![forbid(unsafe_code)]

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
pub const CBM_VENDOR_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vendor/codebase-memory-mcp"
);

pub fn vendor_root() -> &'static str {
    CBM_VENDOR_ROOT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_cbm_vendor_root() {
        assert!(vendor_root().ends_with("vendor/codebase-memory-mcp"));
    }
}
