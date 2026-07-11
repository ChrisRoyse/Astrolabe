use super::*;

pub(crate) const HOOK_AUGMENT_BUDGET_MS: u64 = 300;
pub(crate) const HOOK_STDIN_CAP_BYTES: u64 = 256 * 1024;
pub(crate) const HOOK_MIN_TOKEN_BYTES: usize = 4;
pub(crate) const HOOK_MAX_TOKEN_BYTES: usize = 96;
pub(crate) const HOOK_RESULT_LIMIT: u64 = 5;
pub(crate) const HOOK_MAX_WALKUP: usize = 8;

pub(crate) fn is_hook_augment_invocation(args: &[String]) -> bool {
    args.get(1).is_some_and(|arg| arg == "hook-augment")
}

pub(crate) fn run_hook_augment() -> Result<i32, DynError> {
    let output = hook_augment_output().ok().flatten();
    if let Some(output) = output {
        println!("{output}");
    }
    Ok(0)
}

pub(crate) fn hook_augment_output() -> Result<Option<String>, DynError> {
    let mut input = String::new();
    io::stdin()
        .take(HOOK_STDIN_CAP_BYTES + 1)
        .read_to_string(&mut input)?;
    if input.len() > HOOK_STDIN_CAP_BYTES as usize {
        return Ok(None);
    }

    let payload = serde_json::from_str::<serde_json::Value>(&input)?;
    let tool = payload
        .get("tool_name")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    if tool != "Grep" && tool != "Glob" {
        return Ok(None);
    }

    let pattern = payload
        .get("tool_input")
        .and_then(|input| input.get("pattern"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let Some(token) = hook_extract_token(pattern) else {
        return Ok(None);
    };

    let cwd = payload
        .get("cwd")
        .and_then(serde_json::Value::as_str)
        .map(normalize_hook_path)
        .or_else(|| {
            env::current_dir()
                .ok()
                .and_then(|path| path.into_os_string().into_string().ok())
                .map(|path| normalize_hook_path(&path))
        });
    let Some(cwd) = cwd else {
        return Ok(None);
    };
    if !hook_path_is_abs(&cwd) {
        return Ok(None);
    }

    let runner = CbmToolRunner::new_default()?;
    let Some(context) = hook_resolve_context(&runner, &cwd, &token)? else {
        return Ok(None);
    };
    Ok(Some(
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": context
            }
        })
        .to_string(),
    ))
}

pub(crate) fn normalize_hook_path(path: &str) -> String {
    path.replace('\\', "/")
}

pub(crate) fn hook_extract_token(pattern: &str) -> Option<String> {
    let bytes = pattern.as_bytes();
    let mut best_start = 0;
    let mut best_len = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let len = i - start;
            if len > best_len {
                best_start = start;
                best_len = len;
            }
        } else {
            i += 1;
        }
    }
    if best_len < HOOK_MIN_TOKEN_BYTES {
        return None;
    }
    let len = best_len.min(HOOK_MAX_TOKEN_BYTES);
    Some(pattern[best_start..best_start + len].to_string())
}

pub(crate) fn hook_path_is_abs(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.first() == Some(&b'/') {
        return true;
    }
    bytes.len() >= 2
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes.len() == 2 || bytes[2] == b'/')
}

pub(crate) fn hook_parent(path: &str) -> Option<String> {
    let slash = path.rfind('/')?;
    if slash == 0 {
        return None;
    }
    let bytes = path.as_bytes();
    if slash == 2 && bytes.get(1) == Some(&b':') {
        return None;
    }
    Some(path[..slash].to_string())
}

pub(crate) fn hook_resolve_context(
    runner: &CbmToolRunner,
    cwd: &str,
    token: &str,
) -> Result<Option<String>, DynError> {
    let mut dir = cwd.to_string();
    for _ in 0..HOOK_MAX_WALKUP {
        if !hook_path_is_abs(&dir) {
            break;
        }
        if let Ok(project) = astrolabe_bridge::cbm_project_name_from_path(&dir) {
            let args = serde_json::json!({
                "project": project,
                "name_pattern": format!(".*{token}.*"),
                "limit": HOOK_RESULT_LIMIT
            })
            .to_string();
            let raw = migration::handle_tool_raw(runner, "search_graph", &args)?;
            match hook_context_from_search_graph(&raw, token)? {
                HookSearch::Hits(context) => return Ok(Some(context)),
                HookSearch::NoHits => return Ok(None),
                HookSearch::ToolError => {}
            }
        }
        let Some(parent) = hook_parent(&dir) else {
            break;
        };
        dir = parent;
    }
    Ok(None)
}

pub(crate) enum HookSearch {
    Hits(String),
    NoHits,
    ToolError,
}

pub(crate) fn hook_context_from_search_graph(
    raw: &str,
    token: &str,
) -> Result<HookSearch, DynError> {
    let value = serde_json::from_str::<serde_json::Value>(raw)?;
    if value
        .get("isError")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
    {
        return Ok(HookSearch::ToolError);
    }

    let inner = value
        .get("structuredContent")
        .cloned()
        .or_else(|| {
            value
                .get("content")
                .and_then(serde_json::Value::as_array)
                .and_then(|items| items.first())
                .and_then(|item| item.get("text"))
                .and_then(serde_json::Value::as_str)
                .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        })
        .unwrap_or(serde_json::Value::Null);

    let Some(results) = inner.get("results").and_then(serde_json::Value::as_array) else {
        return Ok(HookSearch::NoHits);
    };
    if results.is_empty() {
        return Ok(HookSearch::NoHits);
    }

    let mut context = format!(
        "[astrolabe] {} graph symbol(s) match \"{}\" (advisory, freshness=best_effort, trust=provisional; normal search results are unaffected):",
        results.len(),
        token
    );
    for result in results.iter().take(HOOK_RESULT_LIMIT as usize) {
        let qualified_name = result
            .get("qualified_name")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.is_empty());
        let name = result
            .get("name")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let display = qualified_name.unwrap_or(name);
        let file_path = result
            .get("file_path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let label = result
            .get("label")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        context.push_str("\n- ");
        context.push_str(display);
        if !file_path.is_empty() {
            context.push_str("  ");
            context.push_str(file_path);
        }
        if !label.is_empty() {
            context.push_str("  ");
            context.push_str(label);
        }
    }
    Ok(HookSearch::Hits(context))
}

pub(crate) struct HookDeadline {
    pub(crate) done: Arc<AtomicBool>,
}

impl HookDeadline {
    fn start(budget_ms: u64) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let thread_done = Arc::clone(&done);
        let _ = thread::spawn(move || {
            thread::sleep(Duration::from_millis(budget_ms));
            if !thread_done.load(Ordering::Relaxed) {
                process::exit(0);
            }
        });
        Self { done }
    }
}

impl Drop for HookDeadline {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
    }
}
