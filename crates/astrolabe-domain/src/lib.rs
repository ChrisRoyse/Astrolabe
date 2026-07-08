#![forbid(unsafe_code)]

pub use calyx_core as calyx;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
pub const CALYX_VENDOR_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vendor/calyx");

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ParentSystem {
    Calyx,
    CodebaseMemoryMcp,
}

pub fn calyx_vendor_root() -> &'static str {
    CALYX_VENDOR_ROOT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_calyx_vendor_root() {
        assert!(calyx_vendor_root().ends_with("vendor/calyx"));
    }
}
