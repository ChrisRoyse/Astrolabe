use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use astrolabe_bridge::{CbmIndexMode, CbmPipeline};
use serde_json::json;

const ISSUE_59_SMALL_MEDIUM_MAX_RATIO: f64 = 1.30;
const DEFAULT_REPEATS: usize = 3;
const DEFAULT_GENERATED_FILES: usize = 12;

struct Config {
    repo: Option<PathBuf>,
    mode: CbmIndexMode,
    mode_name: String,
    repeats: usize,
    generated_files: usize,
    gate_ratio: f64,
    project: String,
}

struct RunTiming {
    baseline_us: u128,
    row_sink_us: u128,
    row_sink_nodes: usize,
    row_sink_edges: usize,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("bench_row_sink_overhead: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let config = Config::from_args(std::env::args().skip(1).collect())?;
    let work_dir = temp_root("astrolabe-row-sink-bench")?;
    let repo_path = match &config.repo {
        Some(path) => path.clone(),
        None => {
            let repo = work_dir.join("repo");
            write_generated_c_fixture(&repo, config.generated_files)?;
            repo
        }
    };

    let mut timings = Vec::with_capacity(config.repeats);
    for run in 0..config.repeats {
        let baseline_db = work_dir.join(format!("baseline-{run}.db"));
        let row_sink_db = work_dir.join(format!("row-sink-{run}.db"));

        let baseline_us = time_pipeline_run(
            &repo_path,
            &baseline_db,
            config.mode,
            &format!("{}-baseline-{run}", config.project),
        )?;
        let (row_sink_us, row_sink_nodes, row_sink_edges) = time_row_sink_run(
            &repo_path,
            &row_sink_db,
            config.mode,
            &format!("{}-row-sink-{run}", config.project),
        )?;
        timings.push(RunTiming {
            baseline_us,
            row_sink_us,
            row_sink_nodes,
            row_sink_edges,
        });
    }

    let baseline_median_us = median_us(timings.iter().map(|timing| timing.baseline_us));
    let row_sink_median_us = median_us(timings.iter().map(|timing| timing.row_sink_us));
    let ratio = row_sink_median_us as f64 / baseline_median_us.max(1) as f64;
    let status = if ratio <= config.gate_ratio {
        "pass"
    } else {
        "fail"
    };

    let report = json!({
        "schema": "astrolabe-row-sink-overhead-bench-v1",
        "issue": 59,
        "status": status,
        "mode": config.mode_name,
        "repo": repo_path.display().to_string(),
        "source": if config.repo.is_some() { "provided_repo" } else { "generated_c_fixture" },
        "generated_files": if config.repo.is_some() { 0 } else { config.generated_files },
        "repeats": config.repeats,
        "gate": {
            "row_sink_overhead_max_ratio": config.gate_ratio,
            "source": "GitHub issue #59 DoD: <=1.3x S/M, <=1.5x L",
            "applied_corpus_class": "small_or_medium",
        },
        "baseline_median_us": baseline_median_us,
        "row_sink_median_us": row_sink_median_us,
        "row_sink_overhead_ratio": ratio,
        "runs": timings.iter().map(|timing| {
            json!({
                "baseline_us": timing.baseline_us,
                "row_sink_us": timing.row_sink_us,
                "row_sink_nodes": timing.row_sink_nodes,
                "row_sink_edges": timing.row_sink_edges,
            })
        }).collect::<Vec<_>>(),
    });
    println!("{}", serde_json::to_string_pretty(&report)?);

    fs::remove_dir_all(&work_dir).ok();
    if status == "pass" {
        Ok(())
    } else {
        Err(format!(
            "row-sink overhead ratio {ratio:.3} exceeded gate {:.3}",
            config.gate_ratio
        )
        .into())
    }
}

impl Config {
    fn from_args(args: Vec<String>) -> Result<Self, Box<dyn Error>> {
        let mut repo = None;
        let mut mode = CbmIndexMode::Full;
        let mut mode_name = "full".to_string();
        let mut repeats = DEFAULT_REPEATS;
        let mut generated_files = DEFAULT_GENERATED_FILES;
        let mut gate_ratio = ISSUE_59_SMALL_MEDIUM_MAX_RATIO;
        let mut project = format!("row-sink-bench-{}-{}", std::process::id(), now_nanos());

        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "--repo" => {
                    index += 1;
                    repo = Some(PathBuf::from(required_arg(&args, index, "--repo")?));
                }
                "--mode" => {
                    index += 1;
                    mode_name = required_arg(&args, index, "--mode")?;
                    mode = parse_mode(&mode_name)?;
                }
                "--repeats" => {
                    index += 1;
                    repeats = parse_positive_usize(&required_arg(&args, index, "--repeats")?)?;
                }
                "--files" => {
                    index += 1;
                    generated_files =
                        parse_positive_usize(&required_arg(&args, index, "--files")?)?;
                }
                "--gate-ratio" => {
                    index += 1;
                    gate_ratio = required_arg(&args, index, "--gate-ratio")?.parse::<f64>()?;
                    if !gate_ratio.is_finite() || gate_ratio <= 0.0 {
                        return Err("--gate-ratio must be a positive finite number".into());
                    }
                }
                "--project" => {
                    index += 1;
                    project = required_arg(&args, index, "--project")?;
                }
                "--help" | "-h" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => return Err(format!("unknown argument {other}").into()),
            }
            index += 1;
        }

        Ok(Self {
            repo,
            mode,
            mode_name,
            repeats,
            generated_files,
            gate_ratio,
            project,
        })
    }
}

fn time_pipeline_run(
    repo_path: &Path,
    db_path: &Path,
    mode: CbmIndexMode,
    project: &str,
) -> Result<u128, Box<dyn Error>> {
    cleanup_db_path(db_path);
    let mut pipeline = CbmPipeline::new(path_str(repo_path)?, path_str(db_path)?, mode)?;
    pipeline.set_project_name(project)?;
    let started = Instant::now();
    pipeline.run_to_sqlite()?;
    Ok(started.elapsed().as_micros())
}

fn time_row_sink_run(
    repo_path: &Path,
    db_path: &Path,
    mode: CbmIndexMode,
    project: &str,
) -> Result<(u128, usize, usize), Box<dyn Error>> {
    cleanup_db_path(db_path);
    let mut pipeline = CbmPipeline::new(path_str(repo_path)?, path_str(db_path)?, mode)?;
    pipeline.set_project_name(project)?;
    let started = Instant::now();
    let rows = pipeline.collect_rows()?;
    Ok((
        started.elapsed().as_micros(),
        rows.nodes.len(),
        rows.edges.len(),
    ))
}

fn write_generated_c_fixture(repo: &Path, files: usize) -> Result<(), Box<dyn Error>> {
    let src = repo.join("src");
    fs::create_dir_all(&src)?;
    for index in 0..files {
        fs::write(
            src.join(format!("unit_{index}.c")),
            format!(
                "int helper_{index}(void) {{ return {index}; }}\n\
                 int entry_{index}(void) {{ return helper_{index}(); }}\n"
            ),
        )?;
    }
    Ok(())
}

fn median_us(values: impl Iterator<Item = u128>) -> u128 {
    let mut values = values.collect::<Vec<_>>();
    values.sort_unstable();
    values[values.len() / 2]
}

fn temp_root(prefix: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path =
        std::env::temp_dir().join(format!("{prefix}-{}-{}", std::process::id(), now_nanos()));
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}

fn cleanup_db_path(path: &Path) {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut raw = path.as_os_str().to_os_string();
        raw.push(suffix);
        fs::remove_file(PathBuf::from(raw)).ok();
    }
}

fn path_str(path: &Path) -> Result<&str, Box<dyn Error>> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()).into())
}

fn required_arg(args: &[String], index: usize, flag: &str) -> Result<String, Box<dyn Error>> {
    args.get(index)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_positive_usize(value: &str) -> Result<usize, Box<dyn Error>> {
    let parsed = value.parse::<usize>()?;
    if parsed == 0 {
        return Err("value must be greater than zero".into());
    }
    Ok(parsed)
}

fn parse_mode(value: &str) -> Result<CbmIndexMode, Box<dyn Error>> {
    match value {
        "full" => Ok(CbmIndexMode::Full),
        "moderate" => Ok(CbmIndexMode::Moderate),
        "fast" => Ok(CbmIndexMode::Fast),
        _ => Err(format!("unsupported mode {value}; expected full, moderate, or fast").into()),
    }
}

fn print_usage() {
    eprintln!(
        "usage: cargo run -p astrolabe-bridge --release --example bench_row_sink_overhead -- \\\n\
         [--repo PATH] [--mode full|moderate|fast] [--repeats N] [--files N] \\\n\
         [--gate-ratio R] [--project NAME]"
    );
}
