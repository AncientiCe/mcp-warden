//! Outside content withheld from the agent, kept for the user to review.
//! Only the user's own `show`/`release` commands read it back.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::sanitize::Finding;

const RELEASED: &str = "released.json";

#[derive(Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub ts: String,
    pub tool: String,
    pub input: Value,
    pub rules: Vec<String>,
    pub withheld: Vec<String>,
}

pub struct Quarantine {
    dir: PathBuf,
}

impl Quarantine {
    /// `$MCP_WARDEN_HOME/quarantine`, defaulting to `~/.mcp-warden/quarantine`.
    pub fn open() -> Result<Self> {
        let dir = crate::audit::warden_home()
            .context("no home directory for the quarantine")?
            .join("quarantine");
        Ok(Self { dir })
    }

    /// A fresh random id: 12 lowercase hex digits.
    pub fn new_id() -> Result<String> {
        let mut random = [0u8; 6];
        getrandom::fill(&mut random).map_err(|e| anyhow::anyhow!("quarantine id: {e}"))?;
        Ok(hex::encode(random))
    }

    pub fn save(
        &self,
        id: &str,
        tool: &str,
        input: &Value,
        findings: &[Finding],
        withheld: Vec<String>,
    ) -> Result<()> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        let record = Record {
            id: id.to_string(),
            ts: crate::audit::timestamp(),
            tool: tool.to_string(),
            input: input.clone(),
            rules: rules(findings),
            withheld,
        };
        std::fs::write(self.path(id)?, serde_json::to_vec_pretty(&record)?)
            .context("writing quarantine record")
    }

    pub fn load(&self, id: &str) -> Result<Record> {
        let path = self.path(id)?;
        let bytes = std::fs::read(&path)
            .with_context(|| format!("no quarantined item {id} in {}", self.dir.display()))?;
        serde_json::from_slice(&bytes).context("invalid quarantine record")
    }

    /// Lets the withheld text of `id` through from now on.
    pub fn release(&self, id: &str) -> Result<Record> {
        let record = self.load(id)?;
        let mut released = self.released()?;
        for text in &record.withheld {
            let hash = digest(text);
            if !released.contains(&hash) {
                released.push(hash);
            }
        }
        std::fs::write(self.dir.join(RELEASED), serde_json::to_vec(&released)?)
            .context("writing released list")?;
        Ok(record)
    }

    /// SHA-256 of every released string.
    pub fn released(&self) -> Result<Vec<String>> {
        match std::fs::read(self.dir.join(RELEASED)) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("invalid released list"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(err) => Err(err).context("reading released list"),
        }
    }

    fn path(&self, id: &str) -> Result<PathBuf> {
        if id.len() != 12 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("invalid quarantine id {id:?}");
        }
        Ok(Path::new(&self.dir).join(format!("{}.json", id.to_ascii_lowercase())))
    }
}

/// Distinct rule ids across findings, in first-seen order.
pub fn rules(findings: &[Finding]) -> Vec<String> {
    let mut rules: Vec<String> = Vec::new();
    for rule in findings.iter().flat_map(|f| &f.rule_ids) {
        if !rules.contains(rule) {
            rules.push(rule.clone());
        }
    }
    rules
}

fn digest(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}
