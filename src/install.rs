//! Registers `mcp-warden hook` in Claude Code settings for every tool, once.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use crate::wrap_config::write_with_backup;

const EVENTS: [&str; 2] = ["PreToolUse", "PostToolUse"];
const TIMEOUT_SECONDS: u64 = 30;

/// `~/.claude/settings.json`, the user-wide Claude Code settings.
pub fn default_settings() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|home| home.join(".claude").join("settings.json"))
        .context("no home directory; supply --settings")
}

/// Adds (or with `install == false` removes) warden's hooks, keeping everything
/// else in the file and an exact backup of it.
pub fn claude_code(settings: &Path, executable: &Path, install: bool) -> Result<Value> {
    let command = hook_command(executable);
    if !install && !settings.exists() {
        return Ok(
            json!({"removed": false, "settings": settings, "command": command, "backup": null}),
        );
    }
    if let Some(parent) = settings.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(settings)
        .with_context(|| format!("opening {}", settings.display()))?;
    File::lock(&file).context("locking Claude Code settings")?;
    if file.metadata()?.len() > 16_777_216 {
        bail!("Claude Code settings exceed size limit");
    }
    let mut original = Vec::new();
    file.read_to_end(&mut original)?;
    let existed = !original.iter().all(u8::is_ascii_whitespace);
    let before: Value = if existed {
        serde_json::from_slice(&original).context("Claude Code settings must be strict JSON")?
    } else {
        json!({})
    };
    let mut after = before.clone();
    let root = after
        .as_object_mut()
        .context("Claude Code settings must be a JSON object")?;
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .context("settings `hooks` must be an object")?;
    for event in EVENTS {
        remove_warden(hooks, event)?;
        if install {
            let groups = hooks
                .entry(event)
                .or_insert_with(|| Value::Array(Vec::new()))
                .as_array_mut()
                .context("hook event entries must be an array")?;
            groups.push(json!({
                "matcher": "*",
                "hooks": [{"type": "command", "command": command, "timeout": TIMEOUT_SECONDS}],
            }));
        }
    }
    if hooks.is_empty() && before.get("hooks").is_none() {
        root.remove("hooks");
    }
    let changed = after != before;
    let mut backup = None;
    if changed {
        let mut updated = serde_json::to_vec_pretty(&after)?;
        updated.push(b'\n');
        if existed {
            backup = Some(write_with_backup(&mut file, settings, &original, &updated)?);
        } else {
            file.write_all(&updated)?;
            file.sync_all()?;
        }
    }
    let key = if install { "installed" } else { "removed" };
    Ok(json!({ key: changed, "settings": settings, "command": command, "backup": backup }))
}

/// Quoted, with forward slashes, so it survives both cmd and POSIX shells.
fn hook_command(executable: &Path) -> String {
    let path = executable.to_string_lossy().replace('\\', "/");
    format!("\"{path}\" hook")
}

fn is_warden(hook: &Value) -> bool {
    hook["command"]
        .as_str()
        .is_some_and(|c| c.contains("mcp-warden") && c.ends_with(" hook"))
}

fn remove_warden(hooks: &mut Map<String, Value>, event: &str) -> Result<()> {
    let Some(groups) = hooks.get_mut(event) else {
        return Ok(());
    };
    let groups = groups
        .as_array_mut()
        .context("hook event entries must be an array")?;
    for group in groups.iter_mut() {
        if let Some(entries) = group.get_mut("hooks").and_then(Value::as_array_mut) {
            entries.retain(|hook| !is_warden(hook));
        }
    }
    groups.retain(|group| {
        group
            .get("hooks")
            .and_then(Value::as_array)
            .is_none_or(|entries| !entries.is_empty())
    });
    if groups.is_empty() {
        hooks.remove(event);
    }
    Ok(())
}
