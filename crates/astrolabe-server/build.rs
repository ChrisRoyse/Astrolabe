use std::path::PathBuf;

mod worker_source_generation;

use worker_source_generation::{
    SOURCE_GENERATION_SCHEMA, SOURCE_INPUTS, git_rerun_inputs, source_generation_sha256,
};

fn main() {
    let manifest = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is required"),
    );
    let root = manifest
        .parent()
        .and_then(std::path::Path::parent)
        .expect("astrolabe-server must remain under <workspace>/crates")
        .to_path_buf();
    for input in SOURCE_INPUTS {
        println!("cargo:rerun-if-changed={}", root.join(input).display());
    }
    for input in git_rerun_inputs(&root)
        .unwrap_or_else(|error| panic!("could not resolve exact Git rerun inputs: {error}"))
    {
        println!("cargo:rerun-if-changed={}", input.display());
    }
    println!(
        "cargo:rustc-env=ASTROLABE_WORKER_SOURCE_GENERATION_SCHEMA={SOURCE_GENERATION_SCHEMA}"
    );
    println!(
        "cargo:rustc-env=ASTROLABE_WORKER_SOURCE_GENERATION_SHA256={}",
        source_generation_sha256(&root)
            .unwrap_or_else(|error| panic!("could not derive worker source generation: {error}"))
    );
}
