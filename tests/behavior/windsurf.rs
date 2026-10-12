//! Windsurf (Cascade): its hooks cannot block, rewrite or comment on a tool
//! result, so warden protects it through the proxy: `mcp-warden wrap` on
//! `~/.codeium/windsurf/mcp_config.json`.

use assert_cmd::Command;
use serde_json::Value;

use crate::harness::warden_exe;

#[test]
fn wrap_covers_a_windsurf_mcp_config() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("mcp_config.json");
    let original = r#"{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "test-only"},
      "disabled": false,
      "disabledTools": ["delete_repository"]
    },
    "remote": {"serverUrl": "https://example.com/mcp"}
  }
}
"#;
    std::fs::write(&path, original).unwrap();
    let output = Command::new(warden_exe())
        .arg("wrap")
        .arg(&path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        std::fs::read_to_string(report["backup"].as_str().unwrap()).unwrap(),
        original
    );
    let config: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let github = &config["mcpServers"]["github"];
    assert_eq!(github["disabledTools"][0], "delete_repository");
    assert_eq!(github["env"]["GITHUB_PERSONAL_ACCESS_TOKEN"], "test-only");
    let args = github["args"].as_array().unwrap();
    assert!(args.contains(&Value::from("--detect")));
    assert_eq!(
        &args[args.len() - 4..],
        &[
            Value::from("--"),
            Value::from("npx"),
            Value::from("-y"),
            Value::from("@modelcontextprotocol/server-github"),
        ]
    );
    // Remote servers have no command to wrap and stay as they are.
    assert_eq!(
        config["mcpServers"]["remote"],
        serde_json::json!({"serverUrl": "https://example.com/mcp"})
    );
}
