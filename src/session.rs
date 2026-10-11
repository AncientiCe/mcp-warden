//! Per-connection state: which request each response answers, and what gets
//! sanitized on its way to the client.

use std::sync::Mutex;

use indexmap::IndexMap;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::audit::{self, Audit, Entry};
use crate::extract::sanitize_json;
use crate::sanitize::{Finding, Sanitizer, Trust};

/// Unanswered requests must not accumulate for the lifetime of a connection.
const MAX_PENDING_REQUESTS: usize = 4096;

struct Pending {
    method: String,
    /// Tool or prompt name, or resource URI.
    target: Option<String>,
}

struct Report {
    method: String,
    target: Option<String>,
    trust: Trust,
    findings: Vec<Finding>,
}

pub struct Session {
    server_id: String,
    trust: Trust,
    sanitizer: Sanitizer,
    audit: Option<Audit>,
    pending: Mutex<IndexMap<String, Pending>>,
}

impl Session {
    pub fn new(
        server_id: String,
        trust: Trust,
        sanitizer: Sanitizer,
        audit: Option<Audit>,
    ) -> Self {
        Self {
            server_id,
            trust,
            sanitizer,
            audit,
            pending: Mutex::new(IndexMap::new()),
        }
    }

    /// Remembers client requests so their responses can be matched up.
    /// The line itself is always forwarded unchanged.
    pub fn on_client_line(&self, line: &[u8]) {
        let Ok(value) = serde_json::from_slice::<Value>(split_eol(line).0) else {
            return;
        };
        let Ok(mut pending) = self.pending.lock() else {
            return;
        };
        for msg in messages(&value) {
            if msg.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
                && msg.get("id").is_none()
            {
                if let Some(id) = msg.get("params").and_then(|params| params.get("requestId")) {
                    pending.shift_remove(&id.to_string());
                }
                continue;
            }
            let (Some(id), Some(method)) =
                (msg.get("id"), msg.get("method").and_then(Value::as_str))
            else {
                continue;
            };
            let target = msg
                .get("params")
                .and_then(|p| p.get("name").or_else(|| p.get("uri")))
                .and_then(Value::as_str)
                .map(str::to_string);
            let key = id.to_string();
            pending.shift_remove(&key);
            if pending.len() >= MAX_PENDING_REQUESTS {
                pending.shift_remove_index(0);
            }
            pending.insert(
                key,
                Pending {
                    method: method.to_string(),
                    target,
                },
            );
        }
    }

    /// Returns the rewritten line, or `None` to forward the original bytes.
    pub fn on_server_line(&self, line: &[u8]) -> Option<Vec<u8>> {
        let (body, eol) = split_eol(line);
        let mut value: Value = serde_json::from_slice(body).ok()?;
        let mut reports = Vec::new();
        match &mut value {
            Value::Array(batch) => batch
                .iter_mut()
                .for_each(|msg| self.inspect(msg, &mut reports)),
            msg => self.inspect(msg, &mut reports),
        }
        if reports.is_empty() {
            return None;
        }
        let mut out = serde_json::to_vec(&value).ok()?;
        self.report(&reports, body, &out);
        out.extend_from_slice(eol);
        Some(out)
    }

    fn inspect(&self, msg: &mut Value, reports: &mut Vec<Report>) {
        let Some(obj) = msg.as_object_mut() else {
            return;
        };
        let (method, target, trust, field) =
            if let Some(method) = obj.get("method").and_then(Value::as_str) {
                // Server-to-client requests whose text reaches a model or a human.
                if !matches!(method, "sampling/createMessage" | "elicitation/create") {
                    return;
                }
                (method.to_string(), None, self.trust, "params")
            } else {
                let Some(id) = obj.get("id") else {
                    return;
                };
                if !obj.contains_key("result") && !obj.contains_key("error") {
                    return;
                }
                // A cancelled or evicted request can still receive a response.
                // Losing correlation must never become a sanitizer bypass.
                let pending = self.take_pending(id).unwrap_or_else(|| Pending {
                    method: "unmatched_response".to_string(),
                    target: None,
                });
                let trust = match pending.method.as_str() {
                    "tools/call" | "resources/read" | "prompts/get" | "unmatched_response" => {
                        self.trust
                    }
                    // Descriptions and instructions are written by the server's
                    // author, not by outsiders: strip only what hides.
                    "initialize"
                    | "tools/list"
                    | "prompts/list"
                    | "resources/list"
                    | "resources/templates/list" => Trust::Trusted,
                    _ => return,
                };
                let field = if obj.contains_key("error") {
                    "error"
                } else {
                    "result"
                };
                (pending.method, pending.target, trust, field)
            };
        let Some(payload) = obj.get_mut(field) else {
            return;
        };
        let mut findings = Vec::new();
        sanitize_json(&self.sanitizer, payload, trust, &mut findings);
        if !findings.is_empty() {
            reports.push(Report {
                method,
                target,
                trust,
                findings,
            });
        }
    }

    fn take_pending(&self, id: &Value) -> Option<Pending> {
        self.pending.lock().ok()?.shift_remove(&id.to_string())
    }

    fn report(&self, reports: &[Report], before: &[u8], after: &[u8]) {
        let (before_sha256, after_sha256) = (sha256(before), sha256(after));
        for report in reports {
            let summary: Vec<String> = report
                .findings
                .iter()
                .map(|f| format!("{}({})", f.kind.name(), f.count))
                .collect();
            eprintln!(
                "mcp-warden[{}]: {} {}: removed {}",
                self.server_id,
                report.method,
                report.target.as_deref().unwrap_or("-"),
                summary.join(", ")
            );
            let Some(audit) = &self.audit else {
                continue;
            };
            let entry = Entry {
                ts: audit::timestamp(),
                server: &self.server_id,
                method: &report.method,
                target: report.target.as_deref(),
                trust: report.trust,
                findings: &report.findings,
                before_sha256: before_sha256.clone(),
                after_sha256: after_sha256.clone(),
            };
            if let Err(err) = audit.record(&entry) {
                eprintln!(
                    "mcp-warden[{}]: could not write audit log: {err}",
                    self.server_id
                );
            }
        }
    }
}

fn messages(value: &Value) -> Vec<&Value> {
    match value {
        Value::Array(batch) => batch.iter().collect(),
        msg => vec![msg],
    }
}

/// Splits a line into its body and its line ending (`\n`, `\r\n` or none).
fn split_eol(line: &[u8]) -> (&[u8], &[u8]) {
    let body_len = match line {
        [.., b'\r', b'\n'] => line.len() - 2,
        [.., b'\n'] => line.len() - 1,
        _ => line.len(),
    };
    line.split_at(body_len)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
