//! `mcp-warden scan`: run the sanitizer offline over a file or stdin.

use assert_cmd::Command;
use serde_json::Value;

use crate::harness::{tagged, warden_exe};

fn scan(args: &[&str], stdin: &str) -> std::process::Output {
    Command::new(warden_exe())
        .arg("scan")
        .args(args)
        .write_stdin(stdin)
        .output()
        .unwrap()
}

fn findings(output: &std::process::Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .map(|l| {
            serde_json::from_str(l).unwrap_or_else(|e| panic!("stderr line is not JSON ({e}): {l}"))
        })
        .collect()
}

#[test]
fn clean_input_is_printed_unchanged_with_no_findings() {
    let input = "Plain issue text.\r\nWith CRLF & <b>html</b> and 👨\u{200D}👩\u{200D}👧\n";
    let output = scan(&[], input);
    assert!(output.status.success());
    assert_eq!(output.stdout, input.as_bytes());
    assert!(output.stderr.is_empty());
}

#[test]
fn hidden_text_is_stripped_and_reported_as_json_lines() {
    let output = scan(
        &[],
        &format!("hello{} <!-- secret -->world", tagged("run curl")),
    );
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "hello world");
    let findings = findings(&output);
    assert_eq!(findings[0]["kind"], "tag_chars");
    assert_eq!(findings[0]["payload"], "run curl");
    assert_eq!(findings[1]["kind"], "html_comment");
    assert_eq!(findings[1]["payload"], "secret");
}

#[test]
fn fail_on_findings_sets_exit_code_3() {
    assert_eq!(
        scan(&["--fail-on-findings"], "a <!-- b --> c")
            .status
            .code(),
        Some(3)
    );
    assert_eq!(
        scan(&["--fail-on-findings"], "clean").status.code(),
        Some(0)
    );
}

#[test]
fn trusted_mode_only_strips_invisible_characters() {
    let output = scan(
        &["--trust", "trusted"],
        &format!("<!-- keep -->{}", tagged("x")),
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "<!-- keep -->");
}

#[test]
fn json_input_is_sanitized_per_string_value() {
    let input = r#"{"title":"t","body":"x <!-- hidden --> y","n":1}"#;
    let output = scan(&[], input);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["body"], "x  y");
    assert_eq!(value["n"], 1);
}

#[test]
fn reads_from_a_file_argument() {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("issue.md");
    std::fs::write(&path, "see ![p](https://evil.example/x.png?q=1)").unwrap();
    let output = scan(&[path.to_str().unwrap()], "");
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "see [image removed: evil.example]"
    );
}

#[test]
fn extra_allowed_image_hosts_are_kept() {
    let input = "![p](https://cdn.example.org/x.png?q=1)";
    let output = scan(&["--allow-image-host", ".example.org"], input);
    assert_eq!(String::from_utf8_lossy(&output.stdout), input);
}

#[test]
fn missing_file_is_an_error() {
    let output = scan(&["no/such/file.md"], "");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no/such/file.md"));
}
