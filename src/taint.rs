//! Cross-process taint and single-use approvals, protected by an OS file lock.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

const TTL_SECONDS: u64 = 120 * 60;

#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Debug)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Level {
    #[default]
    Clean,
    Tainted,
    Suspicious,
    Hostile,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub hash: String,
    pub tool: String,
    pub expires: u64,
    pub approved: bool,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub level: Level,
    pub updated: u64,
    pub source: String,
    pub approvals: BTreeMap<String, Approval>,
}

pub struct Store {
    pub path: PathBuf,
}

impl Store {
    pub fn open(path: Option<PathBuf>) -> Result<Self> {
        let path = path
            .or_else(|| {
                std::env::var_os("MCP_WARDEN_HOME")
                    .map(PathBuf::from)
                    .or_else(|| dirs::home_dir().map(|p| p.join(".mcp-warden")))
                    .map(|p| p.join("state.json"))
            })
            .context("no home directory; supply --state-file")?;
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let store = Self { path };
        store.with_state(|_| Ok(()))?;
        Ok(store)
    }

    pub fn with_state<T>(&self, change: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.path)
            .context("opening shared taint state")?;
        File::lock(&file).context("locking shared taint state")?;
        if file.metadata()?.len() > 1_048_576 {
            bail!("taint state exceeds size limit");
        }
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        let mut state: State = if text.is_empty() {
            State::default()
        } else {
            serde_json::from_str(&text).context("invalid taint state; refusing to assume CLEAN")?
        };
        let now = now();
        if state.updated != 0 && now.saturating_sub(state.updated) > TTL_SECONDS {
            state = State::default();
        }
        state.approvals.retain(|_, a| a.expires >= now);
        let result = change(&mut state)?;
        state.updated = now;
        let bytes = serde_json::to_vec(&state)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&bytes)?;
        file.set_len(bytes.len() as u64)?;
        file.sync_data()?;
        // File drop releases the lock, including on error or process termination.
        Ok(result)
    }

    pub fn observe(&self, level: Level, source: &str) -> Result<()> {
        self.with_state(|state| {
            if level > state.level {
                state.level = level;
                state.source = source.chars().take(256).collect();
                state.approvals.clear();
            }
            Ok(())
        })
    }

    pub fn approve(&self, token: &str) -> Result<()> {
        self.with_state(|state| {
            let approval = state
                .approvals
                .get_mut(token)
                .context("approval token not found or expired")?;
            approval.approved = true;
            Ok(())
        })
    }

    pub fn is_state_path(&self, candidate: &str) -> bool {
        let actual = std::fs::canonicalize(&self.path).ok();
        actual.is_some() && std::fs::canonicalize(Path::new(candidate)).ok() == actual
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
