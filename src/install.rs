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
        Client::Copilot => ".copilot",
        Client::Factory => ".factory",
        Client::Qwen => ".qwen",
        Client::Augment => ".augment",
        Client::Kiro => ".kiro",
        Client::Cline => "Documents/Cline",
    })
}

/// The user-wide hook settings of `client` under `home`.
pub fn settings_in(home: &Path, client: Client) -> PathBuf {
    let file = match client {
        Client::ClaudeCode | Client::Gemini | Client::Qwen | Client::Augment => "settings.json",
        Client::Codex | Client::Cursor | Client::Factory => "hooks.json",
        // These read every file in their hooks directory; warden owns one.
        Client::Copilot | Client::Kiro => "hooks/mcp-warden.json",
        // Cline runs one executable file per event from this directory.
        Client::Cline => "Hooks",
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
            "no supported agent client found in {} (looked for .claude, .codex, .cursor, .gemini, .copilot, .factory, .qwen, .augment, .kiro and Documents/Cline)",
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
    if client == Client::Cline {
        return cline_scripts(settings, &command, install);
    }
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
        Client::Copilot => edit_copilot(root, &command, install)?,
        Client::Kiro => edit_kiro(root, &command, install)?,
        Client::Cline => bail!("Cline hooks are scripts in a directory, not a settings file"),
        // Gemini CLI names its events differently and counts timeouts in milliseconds.
        Client::Gemini => edit_grouped(
            hooks_object(root)?,
            install,
            ["BeforeTool", "AfterTool"],
            &group("*", &command, TIMEOUT_SECONDS * 1000),
        )?,
        Client::ClaudeCode | Client::Codex | Client::Qwen => edit_grouped(
            hooks_object(root)?,
            install,
            ["PreToolUse", "PostToolUse"],
            &group("*", &command, TIMEOUT_SECONDS),
        )?,
        // Factory's hooks file holds the events at the top level.
        Client::Factory => edit_grouped(
            root,
            install,
            ["PreToolUse", "PostToolUse"],
            &group("*", &command, TIMEOUT_SECONDS),
        )?,
        // Augment matches by regex, counts milliseconds, and names an MCP
        // tool's server only when asked to.
        Client::Augment => {
            let mut group = group(".*", &command, TIMEOUT_SECONDS * 1000);
            group["metadata"] = json!({"includeMCPMetadata": true});
            edit_grouped(
                hooks_object(root)?,
                install,
                ["PreToolUse", "PostToolUse"],
                &group,
            )?
        }
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

/// Claude Code, Codex, Gemini CLI, Factory Droid, Qwen Code and Augment: `hooks.EVENT[] = {matcher, hooks: [{type, command, timeout}]}`.
fn edit_grouped(
    hooks: &mut Map<String, Value>,
    install: bool,
    events: [&str; 2],
    group: &Value,
) -> Result<()> {
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
            groups.push(group.clone());
        }
        if groups.is_empty() {
            hooks.remove(event);
        }
    }
    Ok(())
}

/// One matcher group running warden's hook.
fn group(matcher: &str, command: &str, timeout: u64) -> Value {
    json!({
        "matcher": matcher,
        "hooks": [{"type": "command", "command": command, "timeout": timeout}],
    })
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

/// Copilot CLI: `{version: 1, hooks: {event: [{type, command, timeoutSec}]}}`;
/// leaving out the matcher sends every tool to the hook.
fn edit_copilot(root: &mut Map<String, Value>, command: &str, install: bool) -> Result<()> {
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
            entries.push(
                json!({"type": "command", "command": command, "timeoutSec": TIMEOUT_SECONDS}),
            );
        }
        if entries.is_empty() {
            hooks.remove(event);
        }
    }
    Ok(())
}

/// Kiro: `{version: "v1", hooks: [{name, trigger, matcher, action: {type, command}, timeout}]}`.
fn edit_kiro(root: &mut Map<String, Value>, command: &str, install: bool) -> Result<()> {
    if install {
        root.entry("version").or_insert(json!("v1"));
    }
    let hooks = root
        .entry("hooks")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .context("Kiro `hooks` must be an array")?;
    hooks.retain(|hook| !is_warden(&hook["action"]));
    if install {
        for trigger in ["PreToolUse", "PostToolUse"] {
            hooks.push(json!({
                "name": format!("mcp-warden {trigger}"),
                "trigger": trigger,
                "matcher": "*",
                "action": {"type": "command", "command": command},
                "timeout": TIMEOUT_SECONDS,
            }));
        }
    }
    Ok(())
}

/// Marks a Cline hook script as warden's own.
const CLINE_MARKER: &str = "Installed by mcp-warden";

/// Cline: an executable script per event in `dir` that hands stdin to warden.
/// A hook file of the user's own is never touched.
fn cline_scripts(dir: &Path, command: &str, install: bool) -> Result<Value> {
    let scripts = ["PreToolUse", "PostToolUse"].map(|event| {
        let name = if cfg!(windows) {
            format!("{event}.ps1")
        } else {
            event.to_string()
        };
        dir.join(name)
    });
    let ours = |path: &Path| -> Result<Option<bool>> {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(Some(text.contains(CLINE_MARKER))),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
        }
    };
    let mut changed = false;
    if install {
        for path in &scripts {
            if ours(path)? == Some(false) {
                bail!(
                    "{} is a Cline hook of your own; merge `{command}` into it by hand",
                    path.display()
                );
            }
        }
        let body = if cfg!(windows) {
            format!(
                "# {CLINE_MARKER}; `mcp-warden uninstall cline` removes it.\n\
                 $data = [Console]::In.ReadToEnd()\n$data | & {command}\nexit $LASTEXITCODE\n"
            )
        } else {
            format!(
                "#!/bin/sh\n# {CLINE_MARKER}; `mcp-warden uninstall cline` removes it.\nexec {command}\n"
            )
        };
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        for path in &scripts {
            if std::fs::read_to_string(path).ok().as_deref() == Some(body.as_str()) {
                continue;
            }
            std::fs::write(path, &body).with_context(|| format!("writing {}", path.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
            }
            changed = true;
        }
    } else {
        for path in &scripts {
            if ours(path)? == Some(true) {
                std::fs::remove_file(path)
                    .with_context(|| format!("removing {}", path.display()))?;
                changed = true;
            }
        }
    }
    let key = if install { "installed" } else { "removed" };
    Ok(json!({ key: changed, "settings": dir, "command": command, "backup": null }))
}

/// Quoted, with forward slashes, so it survives both cmd and POSIX shells.
fn hook_command(executable: &Path, client: Client) -> String {
    let path = executable.to_string_lossy().replace('\\', "/");
    match client {
        Client::ClaudeCode => format!("\"{path}\" hook"),
        Client::Codex => format!("\"{path}\" hook --client codex"),
        Client::Cursor => format!("\"{path}\" hook --client cursor"),
        Client::Gemini => format!("\"{path}\" hook --client gemini"),
        Client::Copilot => format!("\"{path}\" hook --client copilot"),
        Client::Factory => format!("\"{path}\" hook --client factory"),
        Client::Qwen => format!("\"{path}\" hook --client qwen"),
        Client::Augment => format!("\"{path}\" hook --client augment"),
        Client::Kiro => format!("\"{path}\" hook --client kiro"),
        Client::Cline => format!("\"{path}\" hook --client cline"),
    }
}

fn is_warden(hook: &Value) -> bool {
    hook["command"].as_str().is_some_and(|c| {
        c.contains("mcp-warden") && (c.ends_with(" hook") || c.contains(" hook --client "))
    })
}
