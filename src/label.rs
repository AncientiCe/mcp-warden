//! Preserve MCP envelopes while labeling untrusted human-readable data.

use serde_json::Value;

use crate::config::TrustMap;
use crate::extract::sanitize_json;
use crate::sanitize::{Finding, FindingKind, Sanitizer, Trust};

pub struct Labeler {
    pub map: TrustMap,
    pub visible: bool,
}

struct Walk<'a> {
    sanitizer: &'a Sanitizer,
    map: &'a TrustMap,
    server: &'a str,
    tool: &'a str,
    fallback: Trust,
    findings: &'a mut Vec<Finding>,
    untrusted_seen: bool,
    visible: bool,
}

impl Labeler {
    pub fn apply(
        &self,
        sanitizer: &Sanitizer,
        value: &mut Value,
        server: &str,
        tool: &str,
        trust: Trust,
        findings: &mut Vec<Finding>,
    ) -> bool {
        let mut walk = Walk {
            sanitizer,
            map: &self.map,
            server,
            tool,
            fallback: trust,
            findings,
            untrusted_seen: false,
            visible: self.visible,
        };
        walk.envelope(value);
        walk.untrusted_seen
    }
}

impl Walk<'_> {
    fn envelope(&mut self, value: &mut Value) {
        match value {
            Value::Array(items) => {
                for item in items {
                    self.envelope(item);
                }
            }
            Value::Object(object) => {
                let binary = object.contains_key("mimeType");
                for (key, item) in object {
                    if binary && matches!(key.as_str(), "data" | "blob") {
                        continue;
                    }
                    if key == "structuredContent"
                        || (matches!(key.as_str(), "text" | "message") && item.is_string())
                    {
                        self.data(item, "$", false);
                    } else {
                        self.envelope(item);
                    }
                }
            }
            // Envelope metadata is not prose and must not gain tag delimiters.
            _ => {
                sanitize_json(self.sanitizer, value, Trust::Trusted, self.findings);
            }
        }
    }

    fn data(&mut self, value: &mut Value, path: &str, semi: bool) {
        // Authorship belongs to this record, never to a nested comment or event.
        let semi = if value.is_object() {
            self.map.semi_trusted(self.tool, value).unwrap_or(false)
        } else {
            semi
        };
        match value {
            Value::Object(object) => {
                for (key, item) in object {
                    let child_path = if !key.is_empty()
                        && key
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
                    {
                        format!("{path}.{key}")
                    } else {
                        // Quoted keys cannot collide with configured dotted paths.
                        format!("{path}[{}]", Value::String(key.clone()))
                    };
                    self.data(item, &child_path, semi);
                }
            }
            Value::Array(items) => {
                for (index, item) in items.iter_mut().enumerate() {
                    self.data(item, &format!("{path}[{index}]"), semi);
                }
            }
            Value::String(text) => {
                if let Ok(mut embedded) = serde_json::from_str::<Value>(text)
                    && (embedded.is_object() || embedded.is_array())
                {
                    let before = self.findings.len();
                    self.data(&mut embedded, path, semi);
                    if self.findings.len() != before {
                        let encoded = if text.contains('\n') {
                            serde_json::to_string_pretty(&embedded)
                        } else {
                            serde_json::to_string(&embedded)
                        };
                        if let Ok(encoded) = encoded {
                            *text = encoded;
                        }
                    }
                    return;
                }
                let trust = self.map.trust(self.tool, path, self.fallback);
                self.untrusted_seen |= trust == Trust::Untrusted;
                if let Some(clean) = self.sanitizer.text(text, trust, self.findings) {
                    *text = clean;
                }
                if self.visible && trust == Trust::Untrusted && !semi && !text.is_empty() {
                    *text = format!(
                        "<untrusted source=\"{}:{}\" field=\"{}\">\n{}\n</untrusted>",
                        escape(self.server),
                        escape(self.tool),
                        escape(path),
                        escape(text)
                    );
                    self.findings.push(Finding {
                        kind: FindingKind::Provenance,
                        count: 1,
                        payload: None,
                        rule_ids: Vec::new(),
                        score: None,
                    });
                }
            }
            _ => {}
        }
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
