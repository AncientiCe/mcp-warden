//! Per-connection state: which request each response answers, and what gets
//! sanitized on its way to the client.

use std::sync::Mutex;

use anyhow::Result;
use indexmap::IndexMap;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::audit::{self, Audit, Entry};
use crate::extract::sanitize_json;
use crate::sanitize::{Finding, Sanitizer, Trust};

/// Unanswered requests must not accumulate for the lifetime of a connection.
const MAX_PENDING_REQUESTS: usize = 4096;

pub struct ClientLine {
    pub forwarded: Option<Vec<u8>>,
    pub reply: Option<Vec<u8>>,
}

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
    labeler: Option<crate::label::Labeler>,
    gate: Option<crate::policy::Gate>,
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
            labeler: None,
            gate: None,
        }
    }

    pub fn with_labeler(mut self, labeler: Option<crate::label::Labeler>) -> Self {
        self.labeler = labeler;
        self
    }

    pub fn with_gate(mut self, gate: Option<crate::policy::Gate>) -> Self {
        self.gate = gate;
        self
    }

    /// Forwarded bytes plus an optional local reply. Batch members are gated individually.
    pub fn authorize_client_line(&self, line: &[u8]) -> Result<ClientLine> {
        let Some(gate) = &self.gate else {
            return Ok(ClientLine {
                forwarded: Some(line.to_vec()),
                reply: None,
            });
        };
        let Ok(value) = serde_json::from_slice::<Value>(split_eol(line).0) else {
            return Ok(ClientLine {
                forwarded: Some(line.to_vec()),
                reply: None,
            });
        };
        let mut allowed = Vec::new();
        let mut blocked = Vec::new();
        for message in messages(&value) {
            if let Some(reply) = gate.check(&self.server_id, message)? {
                let report = Report {
                    method: "tools/call".into(),
                    target: message["params"]["name"].as_str().map(str::to_string),
                    trust: self.trust,
                    findings: vec![Finding {
                        kind: crate::sanitize::FindingKind::Policy,
                        count: 1,
                        payload: reply["result"]["content"][0]["text"]
                            .as_str()
                            .map(str::to_string),
                        rule_ids: Vec::new(),
                        score: None,
                    }],
                };
                self.report(
                    &[report],
                    &serde_json::to_vec(message)?,
                    &serde_json::to_vec(&reply)?,
                );
                // JSON-RPC notifications have no response, but are still gated.
                if message.get("id").is_some() {
                    blocked.push(reply);
                }
            } else {
                allowed.push(message.clone());
            }
        }
        if allowed.len() == messages(&value).len() {
            return Ok(ClientLine {
                forwarded: Some(line.to_vec()),
                reply: None,
            });
        }
        let encode = |items: Vec<Value>| -> Result<Option<Vec<u8>>> {
            if items.is_empty() {
                return Ok(None);
            }
            let value = if value.is_array() {
                Value::Array(items)
            } else {
                items.into_iter().next().unwrap_or(Value::Null)
            };
            let mut bytes = serde_json::to_vec(&value)?;
            bytes.extend_from_slice(split_eol(line).1);
            Ok(Some(bytes))
        };
        Ok(ClientLine {
            forwarded: encode(allowed)?,
            reply: encode(blocked)?,
        })
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
    pub fn on_server_line(&self, line: &[u8]) -> Result<Option<Vec<u8>>> {
        let (body, eol) = split_eol(line);
        let Ok(mut value) = serde_json::from_slice::<Value>(body) else {
            return Ok(None);
        };
        let mut reports = Vec::new();
        match &mut value {
            Value::Array(batch) => {
                for msg in batch {
                    self.inspect(msg, &mut reports)?;
                }
            }
            msg => self.inspect(msg, &mut reports)?,
        }
        if reports.is_empty() {
            return Ok(None);
        }
        let mut out = serde_json::to_vec(&value)?;
        self.report(&reports, body, &out);
        out.extend_from_slice(eol);
        Ok(Some(out))
    }

    fn inspect(&self, msg: &mut Value, reports: &mut Vec<Report>) -> Result<()> {
        let Some(obj) = msg.as_object_mut() else {
            return Ok(());
        };
        let (method, target, trust, field) =
            if let Some(method) = obj.get("method").and_then(Value::as_str) {
                // Server-to-client requests whose text reaches a model or a human.
                if !matches!(method, "sampling/createMessage" | "elicitation/create") {
                    return Ok(());
                }
                (method.to_string(), None, self.trust, "params")
            } else {
                let Some(id) = obj.get("id") else {
                    return Ok(());
                };
                if !obj.contains_key("result") && !obj.contains_key("error") {
                    return Ok(());
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
                    _ => return Ok(()),
                };
                let field = if obj.contains_key("error") {
                    "error"
                } else {
                    "result"
                };
                (pending.method, pending.target, trust, field)
            };
        let Some(payload) = obj.get_mut(field) else {
            return Ok(());
        };
        let mut findings = Vec::new();
        if let Some(labeler) = &self.labeler
            && !matches!(
                method.as_str(),
                "initialize"
                    | "tools/list"
                    | "prompts/list"
                    | "resources/list"
                    | "resources/templates/list"
            )
        {
            labeler.apply(
                &self.sanitizer,
                payload,
                &self.server_id,
                target.as_deref().unwrap_or(&method),
                trust,
                &mut findings,
            );
        } else {
            sanitize_json(&self.sanitizer, payload, trust, &mut findings);
        }
        if let Some(gate) = &self.gate
            && trust == Trust::Untrusted
        {
            let score = findings
                .iter()
                .filter_map(|f| f.score)
                .fold(0.0_f64, f64::max);
            let level = if score >= 0.75 {
                crate::taint::Level::Hostile
            } else if score >= 0.5 {
                crate::taint::Level::Suspicious
            } else {
                crate::taint::Level::Tainted
            };
            gate.store.observe(
                level,
                &format!(
                    "{}:{}",
                    self.server_id,
                    target.as_deref().unwrap_or(&method)
                ),
            )?;
        }
        if !findings.is_empty() {
            reports.push(Report {
                method,
                target,
                trust,
                findings,
            });
        }
        Ok(())
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
                "mcp-warden[{}]: {} {}: applied {}",
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
