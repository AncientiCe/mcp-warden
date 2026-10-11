//! Validated per-server and per-field trust configuration.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;

use crate::sanitize::Trust;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    #[serde(default)]
    servers: BTreeMap<String, ServerConfig>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerConfig {
    default_trust: Option<Trust>,
    #[serde(default)]
    fields: Vec<FieldConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FieldConfig {
    tools: Vec<String>,
    #[serde(default)]
    trusted: Vec<String>,
    #[serde(default)]
    untrusted: Vec<String>,
    dynamic_trust: Option<DynamicTrust>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DynamicTrust {
    field: String,
    trusted_values: Vec<String>,
    effect: String,
}

pub struct FieldRule {
    tools: Vec<String>,
    trusted: Vec<Regex>,
    untrusted: Vec<Regex>,
    dynamic: Option<DynamicTrust>,
}

#[derive(Default)]
pub struct TrustMap {
    pub default_trust: Option<Trust>,
    fields: Vec<FieldRule>,
}

impl TrustMap {
    pub fn load(path: Option<&Path>, server: &str) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        let config: FileConfig = toml::from_str(&text).context("parsing trust configuration")?;
        let mut maps = BTreeMap::new();
        // Validate every server, so an unused misspelled rule cannot lie dormant.
        for (name, settings) in config.servers {
            let mut fields = Vec::new();
            for field in settings.fields {
                if field.tools.is_empty() {
                    bail!("field trust rule must select at least one tool");
                }
                if let Some(dynamic) = &field.dynamic_trust
                    && (dynamic.effect != "semi" || !simple_path(&dynamic.field))
                {
                    bail!("dynamic trust requires a simple $.field path and effect = semi");
                }
                fields.push(FieldRule {
                    tools: field.tools,
                    trusted: field
                        .trusted
                        .iter()
                        .map(|p| compile_path(p))
                        .collect::<Result<_>>()?,
                    untrusted: field
                        .untrusted
                        .iter()
                        .map(|p| compile_path(p))
                        .collect::<Result<_>>()?,
                    dynamic: field.dynamic_trust,
                });
            }
            maps.insert(
                name,
                Self {
                    default_trust: settings.default_trust,
                    fields,
                },
            );
        }
        Ok(maps.remove(server).unwrap_or_default())
    }

    fn rules<'a>(&'a self, tool: &'a str) -> impl Iterator<Item = &'a FieldRule> {
        self.fields
            .iter()
            .filter(move |rule| rule.tools.iter().any(|t| t == tool || t == "*"))
    }

    pub fn trust(&self, tool: &str, path: &str, fallback: Trust) -> Trust {
        let rules: Vec<_> = self.rules(tool).collect();
        // Explicit untrusted rules win over any overlapping trusted rule.
        if rules
            .iter()
            .any(|r| r.untrusted.iter().any(|p| p.is_match(path)))
        {
            Trust::Untrusted
        } else if rules
            .iter()
            .any(|r| r.trusted.iter().any(|p| p.is_match(path)))
        {
            Trust::Trusted
        } else {
            fallback
        }
    }

    pub fn semi_trusted(&self, tool: &str, object: &Value) -> Option<bool> {
        for rule in self.rules(tool) {
            let Some(dynamic) = &rule.dynamic else {
                continue;
            };
            let mut value = object;
            for key in dynamic.field.trim_start_matches("$.").split('.') {
                value = &value[key];
            }
            if let Some(association) = value.as_str() {
                let bot = object["user"]["type"].as_str() == Some("Bot")
                    || object["user"]["login"]
                        .as_str()
                        .is_some_and(|s| s.ends_with("[bot]"));
                return Some(!bot && dynamic.trusted_values.iter().any(|v| v == association));
            }
        }
        None
    }
}

fn simple_path(path: &str) -> bool {
    path.starts_with("$.")
        && path[2..].split('.').all(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        })
}

/// JSON-path subset: root, dotted keys, numeric indexes, [*], and ..key.
fn compile_path(path: &str) -> Result<Regex> {
    let Some(mut rest) = path.strip_prefix('$') else {
        bail!("JSON path must start with $: {path}")
    };
    let mut pattern = String::from(r"^\$");
    while !rest.is_empty() {
        if let Some(tail) = rest.strip_prefix("[*]") {
            pattern.push_str(r"\[\d+\]");
            rest = tail;
        } else if let Some(tail) = rest.strip_prefix('[') {
            let Some(end) = tail.find(']') else {
                bail!("invalid JSON path: {path}")
            };
            let index = &tail[..end];
            if index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
                bail!("invalid JSON index: {path}");
            }
            pattern.push_str(&regex::escape(&format!("[{index}]")));
            rest = &tail[end + 1..];
        } else if rest.starts_with('.') {
            if let Some(tail) = rest.strip_prefix("..") {
                pattern.push_str(r"(?:\.[^.\[\]]+|\[\d+\])*");
                rest = tail;
            } else {
                rest = &rest[1..];
            }
            let end = rest.find(['.', '[']).unwrap_or(rest.len());
            let key = &rest[..end];
            if key.is_empty()
                || !key
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
            {
                bail!("unsupported JSON path: {path}");
            }
            pattern.push_str(&regex::escape(&format!(".{key}")));
            rest = &rest[end..];
        } else {
            bail!("unsupported JSON path: {path}");
        }
    }
    pattern.push('$');
    Regex::new(&pattern).context("compiling JSON path")
}
