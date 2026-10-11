//! Projects the agent cloned are SUSPICIOUS until the user trusts them.
//! Everything else on disk is the user's own.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    /// Canonical directories whose files count as outside content.
    suspicious: Vec<PathBuf>,
}

pub struct Projects {
    path: PathBuf,
}

impl Projects {
    /// `$MCP_WARDEN_HOME/projects.json`, defaulting to `~/.mcp-warden/projects.json`.
    pub fn open() -> Result<Self> {
        let home = crate::audit::warden_home().context("no home directory for project trust")?;
        Ok(Self {
            path: home.join("projects.json"),
        })
    }

    /// Marks `dir` (which must exist) suspicious or trusted. Returns its canonical path.
    pub fn set(&self, dir: &Path, suspicious: bool) -> Result<PathBuf> {
        let dir = std::fs::canonicalize(dir)
            .with_context(|| format!("no project directory {}", dir.display()))?;
        let mut registry = self.load()?;
        registry.suspicious.retain(|known| *known != dir);
        if suspicious {
            registry.suspicious.push(dir.clone());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&self.path, serde_json::to_vec_pretty(&registry)?)
            .context("writing project trust")?;
        Ok(dir)
    }

    /// The suspicious project containing `path`, if any. Missing paths are in none.
    pub fn suspicious_root(&self, path: &Path) -> Result<Option<PathBuf>> {
        let Ok(path) = std::fs::canonicalize(path) else {
            return Ok(None);
        };
        Ok(self
            .load()?
            .suspicious
            .into_iter()
            .find(|dir| path.starts_with(dir)))
    }

    fn load(&self) -> Result<Registry> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).context("invalid project trust file"),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Registry::default()),
            Err(err) => Err(err).context("reading project trust"),
        }
    }
}

/// Options of `git clone` that take a separate value.
const VALUE_OPTIONS: &[&str] = &[
    "-b",
    "--branch",
    "--depth",
    "-o",
    "--origin",
    "-c",
    "--config",
    "--reference",
    "--separate-git-dir",
    "-j",
    "--jobs",
    "--filter",
    "-u",
    "--upload-pack",
    "--template",
    "--shallow-since",
    "--shallow-exclude",
];

/// For `git clone SOURCE [DIR]` or `gh repo clone REPO [DIR]` anywhere in a
/// command line: the source and the directory the clone lands in.
pub fn clone_target(command: &str) -> Option<(String, String)> {
    command.split(['&', '|', ';', '\n']).find_map(|segment| {
        let words: Vec<&str> = segment
            .split_whitespace()
            .map(|w| w.trim_matches(|c| c == '"' || c == '\''))
            .collect();
        let start = words
            .windows(2)
            .position(|w| w == ["git", "clone"])
            .map(|i| i + 2)
            .or_else(|| {
                words
                    .windows(3)
                    .position(|w| w == ["gh", "repo", "clone"])
                    .map(|i| i + 3)
            })?;
        let mut positional = Vec::new();
        let mut rest = words[start..].iter();
        while let Some(word) = rest.next() {
            if word == &"--" {
                positional.extend(rest.by_ref());
            } else if word.starts_with('-') {
                if VALUE_OPTIONS.contains(word) {
                    rest.next();
                }
            } else {
                positional.push(word);
            }
        }
        let source = positional.first()?.to_string();
        let dir = match positional.get(1) {
            Some(dir) => dir.to_string(),
            None => {
                let name = source
                    .trim_end_matches('/')
                    .rsplit(['/', ':'])
                    .next()
                    .unwrap_or(&source);
                name.strip_suffix(".git").unwrap_or(name).to_string()
            }
        };
        (!dir.is_empty()).then_some((source, dir))
    })
}
