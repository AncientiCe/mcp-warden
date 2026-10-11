//! Walks MCP payloads and sanitizes every string in them.

use serde_json::Value;

use crate::sanitize::{Finding, Sanitizer, Trust};

/// Sanitizes every string inside `value` in place. Returns whether anything changed.
pub fn sanitize_json(
    sanitizer: &Sanitizer,
    value: &mut Value,
    trust: Trust,
    findings: &mut Vec<Finding>,
) -> bool {
    match value {
        Value::String(text) => match sanitize_string(sanitizer, text, trust, findings) {
            Some(clean) => {
                *text = clean;
                true
            }
            None => false,
        },
        Value::Array(items) => items.iter_mut().fold(false, |changed, item| {
            sanitize_json(sanitizer, item, trust, findings) | changed
        }),
        Value::Object(map) => {
            // `data`/`blob` next to a `mimeType` are base64 image, audio or
            // resource bytes, not text anyone reads.
            let binary = map.contains_key("mimeType");
            map.iter_mut()
                .filter(|(key, _)| !(binary && matches!(key.as_str(), "data" | "blob")))
                .fold(false, |changed, (_, item)| {
                    sanitize_json(sanitizer, item, trust, findings) | changed
                })
        }
        _ => false,
    }
}

/// Sanitizes one string. API-backed servers often return JSON as text (with
/// `<` escaped as `<`, as Go does), so text that parses as a JSON object or
/// array is sanitized per inner string and only re-serialized if it changed.
pub fn sanitize_string(
    sanitizer: &Sanitizer,
    text: &str,
    trust: Trust,
    findings: &mut Vec<Finding>,
) -> Option<String> {
    let Some(mut embedded) = parse_embedded(text) else {
        return sanitizer.text(text, trust, findings);
    };
    if !sanitize_json(sanitizer, &mut embedded, trust, findings) {
        return None;
    }
    let reserialized = if text.contains('\n') {
        serde_json::to_string_pretty(&embedded)
    } else {
        serde_json::to_string(&embedded)
    };
    reserialized.ok()
}

fn parse_embedded(text: &str) -> Option<Value> {
    let trimmed = text.trim_start();
    if !trimmed.starts_with('{') && !trimmed.starts_with('[') {
        return None;
    }
    serde_json::from_str::<Value>(text)
        .ok()
        .filter(|v| v.is_object() || v.is_array())
}
