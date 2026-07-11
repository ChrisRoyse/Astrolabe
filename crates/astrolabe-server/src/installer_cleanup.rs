use super::*;

pub(crate) fn run_installer_command(command: &str, args: &[String]) -> Result<i32, DynError> {
    let code = astrolabe_bridge::run_cbm_installer_command(command, args)?;
    if command == "uninstall" && code == 0 {
        cleanup_installer_leftovers()?;
    }
    Ok(code)
}

pub(crate) fn cleanup_installer_leftovers() -> Result<(), DynError> {
    let Some(home) = installer_home_dir() else {
        return Ok(());
    };
    for rel in [
        ".claude/hooks/cbm-code-discovery-gate",
        ".claude/hooks/cbm-session-reminder",
        ".claude/hooks/cbm-subagent-reminder",
    ] {
        remove_file_if_exists(home.join(rel))?;
    }
    cleanup_path_blocks(&home)?;
    for path in known_installer_config_files(&home) {
        cleanup_known_installer_file(&path)?;
    }
    Ok(())
}

pub(crate) fn installer_home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .or_else(|| env::var_os("USERPROFILE").filter(|value| !value.is_empty()))
        .map(PathBuf::from)
}

#[derive(Clone, Copy)]
pub(crate) enum InstallerPlatform {
    Windows,
    Macos,
    Posix,
}

pub(crate) fn installer_platform() -> InstallerPlatform {
    if cfg!(windows) {
        InstallerPlatform::Windows
    } else if cfg!(target_os = "macos") {
        InstallerPlatform::Macos
    } else {
        InstallerPlatform::Posix
    }
}

pub(crate) fn configured_path(value: Option<PathBuf>, fallback: PathBuf) -> PathBuf {
    value
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(fallback)
}

pub(crate) fn installer_config_dir_for(
    platform: InstallerPlatform,
    home: &Path,
    app_data: Option<PathBuf>,
    xdg_config: Option<PathBuf>,
) -> PathBuf {
    match platform {
        InstallerPlatform::Windows => configured_path(app_data, home.join("AppData/Roaming")),
        InstallerPlatform::Macos => home.join("Library/Application Support"),
        InstallerPlatform::Posix => configured_path(xdg_config, home.join(".config")),
    }
}

pub(crate) fn installer_config_dir(home: &Path) -> PathBuf {
    installer_config_dir_for(
        installer_platform(),
        home,
        env::var_os("APPDATA").map(PathBuf::from),
        env::var_os("XDG_CONFIG_HOME").map(PathBuf::from),
    )
}

pub(crate) fn installer_local_dir_for(
    platform: InstallerPlatform,
    home: &Path,
    local_app_data: Option<PathBuf>,
    config_dir: PathBuf,
) -> PathBuf {
    match platform {
        InstallerPlatform::Windows => configured_path(local_app_data, home.join("AppData/Local")),
        InstallerPlatform::Macos | InstallerPlatform::Posix => config_dir,
    }
}

pub(crate) fn installer_local_dir(home: &Path) -> PathBuf {
    installer_local_dir_for(
        installer_platform(),
        home,
        env::var_os("LOCALAPPDATA").map(PathBuf::from),
        installer_config_dir(home),
    )
}

pub(crate) fn known_installer_config_files_for_dirs(
    home: &Path,
    config: &Path,
    local: &Path,
) -> Vec<PathBuf> {
    vec![
        home.join(".claude/settings.json"),
        home.join(".claude/.mcp.json"),
        home.join(".claude.json"),
        home.join(".codex/config.toml"),
        home.join(".codex/AGENTS.md"),
        home.join(".gemini/settings.json"),
        home.join(".gemini/GEMINI.md"),
        home.join(".gemini/config/mcp_config.json"),
        home.join(".gemini/antigravity-cli/settings.json"),
        home.join(".gemini/antigravity-cli/AGENTS.md"),
        home.join(".config/opencode/opencode.json"),
        home.join(".config/opencode/AGENTS.md"),
        local.join("Zed/settings.json"),
        config.join("Code/User/globalStorage/kilocode.kilo-code/settings/mcp_settings.json"),
        config.join("Code/User/mcp.json"),
        home.join(".kilocode/rules/codebase-memory-mcp.md"),
        home.join(".cursor/mcp.json"),
        home.join(".openclaw/openclaw.json"),
        home.join(".kiro/settings/mcp.json"),
        home.join(".junie/mcp/mcp.json"),
        home.join("CONVENTIONS.md"),
    ]
}

pub(crate) fn known_installer_config_files(home: &Path) -> Vec<PathBuf> {
    let config = installer_config_dir(home);
    let local = installer_local_dir(home);
    known_installer_config_files_for_dirs(home, &config, &local)
}

pub(crate) fn cleanup_path_blocks(home: &Path) -> Result<(), DynError> {
    for path in [
        home.join(".profile"),
        home.join(".bashrc"),
        home.join(".bash_profile"),
        home.join(".zshrc"),
        home.join(".config/fish/config.fish"),
    ] {
        if path.exists() {
            cleanup_path_block_file(&path)?;
        }
    }
    Ok(())
}

pub(crate) fn cleanup_path_block_file(path: &Path) -> Result<(), DynError> {
    let text = fs::read_to_string(path)?;
    let lines = text.lines().collect::<Vec<_>>();
    let mut out = Vec::new();
    let mut i = 0;
    let mut changed = false;
    while i < lines.len() {
        if lines[i].trim() == "# Added by codebase-memory-mcp install"
            && lines
                .get(i + 1)
                .is_some_and(|line| line.contains(".local/bin"))
        {
            changed = true;
            i += 2;
        } else {
            out.push(lines[i]);
            i += 1;
        }
    }
    if !changed {
        return Ok(());
    }
    if out.iter().all(|line| line.trim().is_empty()) {
        remove_file_if_exists(path)?;
    } else {
        fs::write(path, format!("{}\n", out.join("\n")))?;
    }
    Ok(())
}

pub(crate) fn cleanup_known_installer_file(path: &Path) -> Result<(), DynError> {
    if !path.exists() {
        return Ok(());
    }
    let text = fs::read_to_string(path)?;
    let cleaned = if path.file_name().and_then(|name| name.to_str()) == Some("config.toml") {
        strip_codex_session_remainder(&text)
    } else {
        text.clone()
    };
    if cleaned != text {
        if cleaned.trim().is_empty() {
            remove_file_if_exists(path)?;
        } else {
            fs::write(path, cleaned)?;
        }
        return Ok(());
    }
    if text.trim().is_empty() || is_empty_json_config(&text) {
        remove_file_if_exists(path)?;
    }
    Ok(())
}

pub(crate) fn strip_codex_session_remainder(text: &str) -> String {
    let begin = "# >>> codebase-memory-mcp SessionStart >>>";
    let end = "# <<< codebase-memory-mcp SessionStart <<<";
    let mut out = text.to_string();
    while let Some(end_start) = out.find(end) {
        let end_after = (end_start + end.len()).min(out.len());
        let remove_start = out[..end_start]
            .rfind(begin)
            .or_else(|| out[..end_start].rfind("[[hooks.SessionStart]]"))
            .unwrap_or(end_start);
        let remove_start = out[..remove_start]
            .rfind('\n')
            .map_or(remove_start, |idx| idx + 1);
        let remove_end = if out[end_after..].starts_with('\n') {
            end_after + 1
        } else {
            end_after
        };
        out.replace_range(remove_start..remove_end, "");
    }
    out
}

pub(crate) fn is_empty_json_config(text: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return false;
    };
    json_value_is_empty(&value)
}

pub(crate) fn json_value_is_empty(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(object) => {
            object.is_empty()
                || object.iter().all(|(key, value)| {
                    matches!(
                        key.as_str(),
                        "mcpServers" | "hooks" | "mcp" | "servers" | "context_servers"
                    ) && json_value_is_empty(value)
                })
        }
        serde_json::Value::Array(array) => array.is_empty(),
        serde_json::Value::Null => true,
        _ => false,
    }
}

pub(crate) fn remove_file_if_exists(path: impl AsRef<Path>) -> Result<(), DynError> {
    match fs::remove_file(path.as_ref()) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}
