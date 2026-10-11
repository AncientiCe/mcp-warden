//! Validated per-server and per-field trust configuration.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

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
    egress: Option<EgressConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EgressConfig {
    allow_hosts: Vec<String>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerConfig {
    default_trust: Option<Trust>,
    fields: Option<Vec<FieldConfig>>,
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
    pub allowed_egress_hosts: Option<Vec<String>>,
    fields: Vec<FieldRule>,
}

impl TrustMap {
    pub fn has_fields(&self) -> bool {
        !self.fields.is_empty()
    }

    pub fn load(path: Option<&Path>, server: &str) -> Result<Self> {
        let home = std::env::var_os("MCP_WARDEN_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME")
                    .or_else(|| std::env::var_os("USERPROFILE"))
                    .map(|p| PathBuf::from(p).join(".mcp-warden"))
            });
        let mut paths = Vec::new();
        if let Some(home) = home {
            paths.push((home.join("config.toml"), false));
        }
        paths.push((std::env::current_dir()?.join(".mcp-warden.toml"), false));
        if let Some(path) = path {
            paths.push((path.to_path_buf(), true));
        }
        let mut result = Self::default();
        for (path, required) in paths {
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(err) if !required && err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(err).with_context(|| format!("reading config {}", path.display()));
                }
            };
            let config: FileConfig = toml::from_str(&text)
                .with_context(|| format!("parsing trust configuration {}", path.display()))?;
            let replace_fields = config
                .servers
                .get(server)
                .is_some_and(|s| s.fields.is_some());
            let next = Self::compile(config, server)
                .with_context(|| format!("validating config {}", path.display()))?;
            if next.default_trust.is_some() {
                result.default_trust = next.default_trust;
            }
            if next.allowed_egress_hosts.is_some() {
                result.allowed_egress_hosts = next.allowed_egress_hosts;
            }
            if replace_fields {
                result.fields = next.fields;
            }
        }
        Ok(result)
    }

    fn compile(config: FileConfig, server: &str) -> Result<Self> {
        let allowed_egress_hosts = config.egress.map(|egress| {
            egress.allow_hosts.into_iter().map(|host| {
                let normalized = host.to_ascii_lowercase();
                let url = url::Url::parse(&format!("https://{normalized}/"))
                    .context("invalid egress host")?;
                if url.host_str() != Some(normalized.as_str()) || normalized.contains('*')
                    || !url.username().is_empty() || url.password().is_some()
                    || url.port().is_some() || url.path() != "/"
                    || url.query().is_some() || url.fragment().is_some()
                {
                    bail!("egress allow_hosts requires exact hosts without URLs, ports or wildcards: {host}");
                }
                Ok(normalized)
            }).collect::<Result<Vec<_>>>()
        }).transpose()?;
        let mut maps = BTreeMap::new();
        // Validate every server, so an unused misspelled rule cannot lie dormant.
        for (name, settings) in config.servers {
            let mut fields = Vec::new();
            for field in settings.fields.unwrap_or_default() {
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
                    allowed_egress_hosts: None,
                    fields,
                },
            );
        }
        let mut map = maps.remove(server).unwrap_or_default();
        map.allowed_egress_hosts = allowed_egress_hosts;
        Ok(map)
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
