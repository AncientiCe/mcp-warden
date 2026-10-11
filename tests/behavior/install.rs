//! `mcp-warden install claude-code`: registers the hook once for every tool and server.

use std::path::Path;

use assert_cmd::Command;
use serde_json::{Value, json};
use tempfile::TempDir;

use crate::harness::warden_exe;

fn run(args: &[&str], settings: &Path) -> std::process::Output {
    Command::new(warden_exe())
        .args(args)
        .arg("--settings")
        .arg(settings)
        .output()
        .unwrap()
}

fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// Commands registered for `event` with a match-all matcher.
fn warden_commands(settings: &Value, event: &str) -> Vec<String> {
    settings["hooks"][event]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|group| group["matcher"] == "*")
        .flat_map(|group| group["hooks"].as_array().cloned().unwrap_or_default())
        .filter_map(|hook| hook["command"].as_str().map(str::to_string))
        .filter(|command| command.contains("mcp-warden"))
        .collect()
}

fn backups(dir: &Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.to_string_lossy().contains(".warden-backup-"))
        .collect()
}

#[test]
fn install_registers_scan_and_policy_hooks_for_every_tool() {
    let dir = TempDir::new().unwrap();
    let settings = dir.path().join(".claude").join("settings.json");
    let output = run(&["install", "claude-code"], &settings);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = read(&settings);
    for event in ["PreToolUse", "PostToolUse"] {
        let commands = warden_commands(&value, event);
        assert_eq!(commands.len(), 1, "{event}: {commands:?}");
        assert!(commands[0].ends_with(" hook"), "{}", commands[0]);
    }
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["installed"], true);
    assert_eq!(report["backup"], Value::Null);
}

#[test]
fn installed_command_runs_the_hook() {
    let dir = TempDir::new().unwrap();
    let settings = dir.path().join("settings.json");
    run(&["install", "claude-code"], &settings);
    let command = warden_commands(&read(&settings), "PostToolUse").remove(0);
    let exe = command
        .strip_suffix(" hook")
        .unwrap()
        .trim_matches('"')
        .to_string();
    assert!(Path::new(&exe).exists(), "{exe}");
}

#[test]
fn existing_settings_and_hooks_are_preserved_with_an_exact_backup() {
    let dir = TempDir::new().unwrap();
    let settings = dir.path().join("settings.json");
    let original = serde_json::to_string_pretty(&json!({
        "model": "opus",
        "permissions": {"allow": ["Bash(git status)"]},
        "hooks": {
            "PostToolUse": [
                {"matcher": "Read", "hooks": [{"type": "command", "command": "palace hook post"}]}
            ],
            "SessionStart": [
                {"hooks": [{"type": "command", "command": "impact hook start"}]}
            ]
        }
    }))
    .unwrap();
    std::fs::write(&settings, &original).unwrap();

    let output = run(&["install", "claude-code"], &settings);
    assert!(output.status.success());
    let value = read(&settings);
    assert_eq!(value["model"], "opus");
    assert_eq!(value["permissions"]["allow"][0], "Bash(git status)");
    assert_eq!(
        value["hooks"]["PostToolUse"][0]["hooks"][0]["command"],
        "palace hook post"
    );
    assert_eq!(
        value["hooks"]["SessionStart"][0]["hooks"][0]["command"],
        "impact hook start"
    );
    assert_eq!(warden_commands(&value, "PostToolUse").len(), 1);
    assert_eq!(warden_commands(&value, "PreToolUse").len(), 1);

    let backups = backups(dir.path());
    assert_eq!(backups.len(), 1);
    assert_eq!(std::fs::read_to_string(&backups[0]).unwrap(), original);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["backup"], json!(backups[0]));
}

#[test]
fn installing_twice_changes_nothing() {
    let dir = TempDir::new().unwrap();
    let settings = dir.path().join("settings.json");
    run(&["install", "claude-code"], &settings);
    let first = std::fs::read(&settings).unwrap();
    let output = run(&["install", "claude-code"], &settings);
    assert!(output.status.success());
    assert_eq!(std::fs::read(&settings).unwrap(), first);
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["installed"], false);
    assert!(backups(dir.path()).is_empty());
}

#[test]
fn uninstall_removes_only_warden_hooks() {
    let dir = TempDir::new().unwrap();
    let settings = dir.path().join("settings.json");
    std::fs::write(
        &settings,
        r#"{"hooks":{"PostToolUse":[{"matcher":"Read","hooks":[{"type":"command","command":"palace hook post"}]}]}}"#,
    )
    .unwrap();
    run(&["install", "claude-code"], &settings);
    let output = run(&["uninstall", "claude-code"], &settings);
    assert!(output.status.success());
    let value = read(&settings);
    assert!(warden_commands(&value, "PostToolUse").is_empty());
    assert!(value["hooks"].get("PreToolUse").is_none());
    assert_eq!(
        value["hooks"]["PostToolUse"][0]["hooks"][0]["command"],
        "palace hook post"
    );
}

#[test]
fn uninstall_without_settings_creates_nothing() {
    let dir = TempDir::new().unwrap();
    let settings = dir.path().join("settings.json");
    let output = run(&["uninstall", "claude-code"], &settings);
    assert!(output.status.success());
    assert!(!settings.exists());
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["removed"], false);
}

#[test]
fn invalid_settings_are_left_untouched() {
    let dir = TempDir::new().unwrap();
    let settings = dir.path().join("settings.json");
    std::fs::write(&settings, "{ // comments are not JSON\n}").unwrap();
    let output = run(&["install", "claude-code"], &settings);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        std::fs::read_to_string(&settings).unwrap(),
        "{ // comments are not JSON\n}"
    );
    assert!(backups(dir.path()).is_empty());
}

fn run_all(verb: &str, home: &Path) -> std::process::Output {
    Command::new(warden_exe())
        .args([verb, "--home"])
        .arg(home)
        .output()
        .unwrap()
}

#[test]
fn install_without_a_client_sets_up_every_client_found() {
    let home = TempDir::new().unwrap();
    std::fs::create_dir_all(home.path().join(".claude")).unwrap();
    std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
    let output = run_all("install", home.path());
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let claude = read(&home.path().join(".claude").join("settings.json"));
    assert_eq!(warden_commands(&claude, "PostToolUse").len(), 1);
    let cursor = read(&home.path().join(".cursor").join("hooks.json"));
    assert_eq!(cursor["hooks"]["postToolUse"].as_array().unwrap().len(), 1);
    assert!(!home.path().join(".codex").exists());

    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    let clients: Vec<&str> = report["clients"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["client"].as_str().unwrap())
        .collect();
    assert_eq!(clients, ["claude-code", "cursor"]);

    let output = run_all("uninstall", home.path());
    assert!(output.status.success());
    let claude = read(&home.path().join(".claude").join("settings.json"));
    assert!(warden_commands(&claude, "PostToolUse").is_empty());
}

#[test]
fn install_without_any_client_present_is_an_error() {
    let home = TempDir::new().unwrap();
    let output = run_all("install", home.path());
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no supported agent"));
}
