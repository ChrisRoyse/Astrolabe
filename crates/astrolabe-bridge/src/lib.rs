#![forbid(unsafe_code)]

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub fn parent_roots() -> (&'static str, &'static str) {
    (
        astrolabe_domain::calyx_vendor_root(),
        cbm_sys::vendor_root(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_both_parent_roots() {
        let (calyx, cbm) = parent_roots();
        assert!(calyx.ends_with("vendor/calyx"));
        assert!(cbm.ends_with("vendor/codebase-memory-mcp"));
    }
}
