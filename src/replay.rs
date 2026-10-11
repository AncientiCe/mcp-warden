//! Measure sanitizer/detector findings over labeled, on-disk corpus fixtures.

use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use crate::extract::sanitize_string;
use crate::sanitize::{Policy, Sanitizer, Trust};

pub fn corpus(path: &Path) -> Result<Value> {
    let sanitizer = Sanitizer::new(Policy {
        detect: true,
        ..Policy::default()
    })?;
    let mut counts = [0usize; 4]; // malicious, benign, true positives, false positives
    let mut latency = Vec::new();
    for (name, malicious) in [("malicious", true), ("benign", false)] {
        let input = std::fs::read_to_string(path.join(format!("{name}.json")))?;
        let cases: Vec<Value> = serde_json::from_str(&input)?;
        for case in cases {
            let text = case["text"].as_str().context("corpus case requires text")?;
            let started = Instant::now();
            let mut findings = Vec::new();
            sanitize_string(&sanitizer, text, Trust::Untrusted, &mut findings);
            latency.push(started.elapsed().as_micros() as u64);
            let bucket = usize::from(!malicious);
            counts[bucket] += 1;
            if !findings.is_empty() {
                counts[bucket + 2] += 1;
            }
        }
    }
    latency.sort_unstable();
    let [malicious, benign, tp, fp] = counts;
    Ok(json!({
        "malicious":malicious,"benign":benign,"true_positives":tp,"false_positives":fp,
        "false_negatives":malicious-tp,
        "recall":if malicious == 0 {0.0} else {tp as f64 / malicious as f64},
        "precision":if tp+fp == 0 {0.0} else {tp as f64 / (tp+fp) as f64},
        "false_positive_rate":if benign == 0 {0.0} else {fp as f64 / benign as f64},
        "p50_us":latency.get(latency.len()/2).copied().unwrap_or(0),
        "p99_us":latency.get(latency.len().saturating_sub(1)*99/100).copied().unwrap_or(0)
    }))
}
