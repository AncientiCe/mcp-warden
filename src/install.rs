//! Registers `mcp-warden hook` for every tool in an agent client's hook settings, once.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use crate::hook::Client;
use crate::wrap_config::write_with_backup;

const TIMEOUT_SECONDS: u64 = 30;

pub fn home() -> Result<PathBuf> {
    dirs::home_dir().context("no home directory; supply --home or --settings")
}

/// The directory a client keeps its user settings in, under `home`.
fn client_dir(home: &Path, client: Client) -> PathBuf {
    home.join(match client {
        Client::ClaudeCode => ".claude",
        Client::Codex => ".codex",
        Client::Cursor => ".cursor",
        Client::Gemini => ".gemini",
    })
}

/// The user-wide hook settings of `client` under `home`.
pub fn settings_in(home: &Path, client: Client) -> PathBuf {
    let file = match client {
        Client::ClaudeCode | Client::Gemini => "settings.json",
        Client::Codex | Client::Cursor => "hooks.json",
    };
    client_dir(home, client).join(file)
}

/// Installs (or removes) the hook for every supported client found under `home`.
pub fn all_clients(home: &Path, executable: &Path, install: bool) -> Result<Value> {
    let mut reports = Vec::new();
    for client in Client::ALL {
        if !client_dir(home, client).is_dir() {
            continue;
        }
        let mut report = hook_settings(&settings_in(home, client), executable, client, install)?;
        report["client"] = json!(client.name());
        reports.push(report);
    }
    if reports.is_empty() {
        bail!(
            "no supported agent client found in {} (looked for .claude, .codex, .cursor and .gemini)",
            home.display()
        );
    }
    Ok(json!({ "clients": reports }))
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
    match client {
        Client::Cursor => edit_cursor(root, &command, install)?,
        // Gemini CLI names its events differently and counts timeouts in milliseconds.
        Client::Gemini => edit_grouped(
            root,
            &command,
            install,
            ["BeforeTool", "AfterTool"],
            TIMEOUT_SECONDS * 1000,
        )?,
        Client::ClaudeCode | Client::Codex => edit_grouped(
            root,
            &command,
            install,
            ["PreToolUse", "PostToolUse"],
            TIMEOUT_SECONDS,
        )?,
    }
    if root
        .get("hooks")
        .and_then(Value::as_object)
        .is_some_and(Map::is_empty)
        && before.get("hooks").is_none()
    {
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

fn hooks_object(root: &mut Map<String, Value>) -> Result<&mut Map<String, Value>> {
    root.entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
        .context("settings `hooks` must be an object")
}

/// Claude Code, Codex and Gemini CLI: `hooks.EVENT[] = {matcher, hooks: [{type, command, timeout}]}`.
fn edit_grouped(
    root: &mut Map<String, Value>,
    command: &str,
    install: bool,
    events: [&str; 2],
    timeout: u64,
) -> Result<()> {
    let hooks = hooks_object(root)?;
    for event in events {
        let groups = hooks
            .entry(event)
            .or_insert_with(|| Value::Array(Vec::new()))
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
        if install {
            groups.push(json!({
                "matcher": "*",
                "hooks": [{"type": "command", "command": command, "timeout": timeout}],
            }));
        }
        if groups.is_empty() {
            hooks.remove(event);
        }
    }
    Ok(())
}

/// Cursor: `{version: 1, hooks: {event: [{command, matcher?, timeout?}]}}`.
fn edit_cursor(root: &mut Map<String, Value>, command: &str, install: bool) -> Result<()> {
    if install {
        root.entry("version").or_insert(json!(1));
    }
    let hooks = hooks_object(root)?;
    for event in ["preToolUse", "postToolUse"] {
        let entries = hooks
            .entry(event)
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .context("hook event entries must be an array")?;
        entries.retain(|hook| !is_warden(hook));
        if install {
            entries.push(json!({"command": command, "matcher": "*", "timeout": TIMEOUT_SECONDS}));
        }
        if entries.is_empty() {
            hooks.remove(event);
        }
    }
    Ok(())
}

/// Quoted, with forward slashes, so it survives both cmd and POSIX shells.
fn hook_command(executable: &Path, client: Client) -> String {
    let path = executable.to_string_lossy().replace('\\', "/");
    match client {
        Client::ClaudeCode => format!("\"{path}\" hook"),
        Client::Codex => format!("\"{path}\" hook --client codex"),
        Client::Cursor => format!("\"{path}\" hook --client cursor"),
        Client::Gemini => format!("\"{path}\" hook --client gemini"),
    }
}

fn is_warden(hook: &Value) -> bool {
    hook["command"].as_str().is_some_and(|c| {
        c.contains("mcp-warden") && (c.ends_with(" hook") || c.contains(" hook --client "))
    })
}
