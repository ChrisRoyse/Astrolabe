//! Strict shared-object checkout materializer for the Rust kernel farm (#907).
//!
//! Output is one JSON object on stdout. Failures are one structured
//! `{code,message,remediation}` object on stderr and exit 1.

use std::path::PathBuf;
use std::process;

use calyx_core::CalyxError;
use serde_json::json;

const USAGE: &str = "usage: astrolabe-fleet-shared-checkout --source-repo <dir> --dest <dir> [--commit <rev>] [--path <repo-relative-path> ...]";

fn main() {
    process::exit(astrolabe_fleet::run_on_sized_host_thread(run_from_env));
}

fn run_from_env() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!(
                "{}",
                json!({
                    "code": error.code,
                    "message": error.message,
                    "remediation": error.remediation,
                })
            );
            1
        }
    }
}

fn run(args: &[String]) -> Result<(), CalyxError> {
    let opts = Options::parse(args)?;
    opts.reject_unknown(&["source-repo", "dest", "commit", "path"])?;
    let config = astrolabe_fleet::SharedCheckoutConfig {
        source_repo: PathBuf::from(opts.require("source-repo")?),
        destination: PathBuf::from(opts.require("dest")?),
        commit: opts.get("commit").map(str::to_string),
        paths: opts
            .get_all("path")
            .into_iter()
            .map(str::to_string)
            .collect(),
    };
    let report = astrolabe_fleet::create_shared_checkout(&config)?;
    let value = serde_json::to_value(&report).map_err(|error| CalyxError {
        code: astrolabe_fleet::ASTRO_FLEET_SHARED_CHECKOUT_OUTPUT,
        message: format!("failed to serialize shared checkout report: {error}"),
        remediation: astrolabe_fleet::REMEDIATE_OUTPUT,
    })?;
    println!("{value}");
    Ok(())
}

struct Options {
    pairs: Vec<(String, String)>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, CalyxError> {
        let mut pairs = Vec::new();
        let mut idx = 0;
        while idx < args.len() {
            let flag = args[idx]
                .strip_prefix("--")
                .ok_or_else(|| usage(&format!("expected --flag, got {:?}", args[idx])))?;
            let value = args
                .get(idx + 1)
                .ok_or_else(|| usage(&format!("--{flag} needs a value")))?;
            pairs.push((flag.to_string(), value.clone()));
            idx += 2;
        }
        Ok(Self { pairs })
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(flag, _)| flag == name)
            .map(|(_, value)| value.as_str())
    }

    fn get_all(&self, name: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(flag, _)| flag == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    fn require(&self, name: &str) -> Result<&str, CalyxError> {
        self.get(name)
            .ok_or_else(|| usage(&format!("--{name} is required")))
    }

    fn reject_unknown(&self, known: &[&str]) -> Result<(), CalyxError> {
        for (flag, _) in &self.pairs {
            if !known.contains(&flag.as_str()) {
                return Err(usage(&format!("unknown flag --{flag}")));
            }
        }
        Ok(())
    }
}

fn usage(what: &str) -> CalyxError {
    CalyxError {
        code: astrolabe_fleet::ASTRO_FLEET_SHARED_CHECKOUT_CONFIG,
        message: format!("{what}; {USAGE}"),
        remediation: "invoke with a valid source repo, absent destination, optional commit, and optional repo-relative paths",
    }
}
