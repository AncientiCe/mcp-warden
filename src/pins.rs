//! Trust-on-first-use tool definition fingerprints; changed pins are never auto-accepted.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::sanitize::{Finding, FindingKind};

pub struct Pins {
    pub path: PathBuf,
}

impl Pins {
    pub fn check(
        &self,
        server: &str,
        payload: &mut Value,
        findings: &mut Vec<Finding>,
    ) -> Result<()> {
        let Some(tools) = payload.get_mut("tools").and_then(Value::as_array_mut) else {
            return Ok(());
        };
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.path)?;
        File::lock(&file)?;
        if file.metadata()?.len() > 4_194_304 {
            bail!("tool pin file exceeds size limit");
        }
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        let mut pins: BTreeMap<String, String> = if text.is_empty() {
            BTreeMap::new()
        } else {
            serde_json::from_str(&text).context("invalid tool pin file")?
        };
        for tool in tools {
            let Some(name) = tool["name"].as_str().map(str::to_string) else {
                continue;
            };
            let key = serde_json::to_string(&(server, &name))?;
            let digest = hex::encode(Sha256::digest(serde_json::to_vec(tool)?));
            match pins.get(&key) {
                Some(original) if original != &digest => {
                    let description = tool["description"].as_str().unwrap_or_default();
                    tool["description"] = Value::String(format!(
                        "[mcp-warden: tool definition changed since first use; review before calling]\n{description}"
                    ));
                    findings.push(Finding {
                        kind: FindingKind::ToolChanged,
                        count: 1,
                        payload: Some(name),
                        rule_ids: vec!["R-TOOL-CHANGED".into()],
                        score: Some(0.8),
                    });
                }
                None => {
                    if pins.len() >= 10_000 {
                        bail!("tool pin capacity exceeded");
                    }
                    pins.insert(key, digest);
                }
                _ => {}
            }
        }
        let bytes = serde_json::to_vec(&pins)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.set_len(bytes.len() as u64)?;
        file.sync_data()?;
        Ok(())
    }
}
