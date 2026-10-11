//! The attack and benign corpora (`tests/corpus/*.json`) run through `mcp-warden scan`.
//!
//! Malicious cases carry the roadmap phase whose layer is expected to catch
//! them; cases for later phases are kept in the corpus but skipped here until
//! that layer exists.

use std::collections::BTreeSet;

use assert_cmd::Command;
use serde_json::Value;

use crate::harness::warden_exe;

/// Highest roadmap phase implemented so far.
const IMPLEMENTED_PHASE: u64 = 1;

fn load(name: &str) -> Vec<Value> {
    let path = format!("{}/tests/corpus/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn scan(text: &str) -> (String, Vec<Value>) {
    let output = Command::new(warden_exe())
        .arg("scan")
        .write_stdin(text)
        .output()
        .unwrap();
    assert!(output.status.success());
    let findings = String::from_utf8_lossy(&output.stderr)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    (String::from_utf8(output.stdout).unwrap(), findings)
}

#[test]
fn every_implemented_malicious_case_is_caught() {
    let mut failures = Vec::new();
    for case in load("malicious") {
        if case["phase"].as_u64().unwrap() > IMPLEMENTED_PHASE {
            continue;
        }
        let id = case["id"].as_str().unwrap();
        let (_, findings) = scan(case["text"].as_str().unwrap());
        let found: BTreeSet<&str> = findings
            .iter()
            .map(|f| f["kind"].as_str().unwrap())
            .collect();
        for expected in case["expect"].as_array().unwrap() {
            if !found.contains(expected.as_str().unwrap()) {
                failures.push(format!("{id}: expected {expected}, found {found:?}"));
            }
        }
        if let Some(needle) = case["payload_contains"].as_str() {
            let payloads: String = findings
                .iter()
                .filter_map(|f| f["payload"].as_str())
                .collect();
            if !payloads.contains(needle) {
                failures.push(format!("{id}: no payload containing {needle:?}"));
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn every_benign_case_passes_through_unchanged() {
    let mut failures = Vec::new();
    for case in load("benign") {
        let text = case["text"].as_str().unwrap();
        let (out, findings) = scan(text);
        if out != text || !findings.is_empty() {
            failures.push(format!("{}: {findings:?}", case["id"]));
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

#[test]
fn later_phase_cases_stay_in_the_corpus() {
    // Guards against "fixing" the suite by deleting cases a later layer must catch.
    let pending = load("malicious")
        .iter()
        .filter(|c| c["phase"].as_u64().unwrap() > IMPLEMENTED_PHASE)
        .count();
    assert!(pending >= 6, "only {pending} later-phase cases left");
}
