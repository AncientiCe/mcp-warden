//! Registers `mcp-warden hook` for every tool in an agent client's hook settings, once.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use crate::hook::Client;
use crate::wrap_config::write_with_backup;

const EVENTS: [&str; 2] = ["PreToolUse", "PostToolUse"];
const TIMEOUT_SECONDS: u64 = 30;

/// The user-wide hook settings of `client`.
pub fn default_settings(client: Client) -> Result<PathBuf> {
    let home = dirs::home_dir().context("no home directory; supply --settings")?;
    Ok(match client {
        Client::ClaudeCode => home.join(".claude").join("settings.json"),
        Client::Codex => home.join(".codex").join("hooks.json"),
    })
}

/// Adds (or with `install == false` removes) warden's hooks, keeping everything
/// else in the file and an exact backup of it.
pub fn hook_settings(
    settings: &Path,
    executable: &Path,
    client: Client,
    install: bool,
) -> Result<Value> {
    let command = hook_command(executable, client);
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
    File::lock(&file).context("locking hook settings")?;
    if file.metadata()?.len() > 16_777_216 {
        bail!("hook settings exceed size limit");
    }
    let mut original = Vec::new();
    file.read_to_end(&mut original)?;
    let existed = !original.iter().all(u8::is_ascii_whitespace);
    let before: Value = if existed {
        serde_json::from_slice(&original).context("hook settings must be strict JSON")?
    } else {
        json!({})
    };
    let mut after = before.clone();
    let root = after
        .as_object_mut()
        .context("hook settings must be a JSON object")?;
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
fn hook_command(executable: &Path, client: Client) -> String {
    let path = executable.to_string_lossy().replace('\\', "/");
    match client {
        Client::ClaudeCode => format!("\"{path}\" hook"),
        Client::Codex => format!("\"{path}\" hook --client codex"),
    }
}

fn is_warden(hook: &Value) -> bool {
    hook["command"].as_str().is_some_and(|c| {
        c.contains("mcp-warden") && (c.ends_with(" hook") || c.contains(" hook --client "))
    })
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
