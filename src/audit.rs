//! Append-only JSONL audit log of everything warden changed, one file per UTC day.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::sanitize::{Finding, Trust};

/// Audit files older than this are deleted when warden starts.
const RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

#[derive(Serialize)]
pub struct Entry<'a> {
    pub ts: String,
    pub server: &'a str,
    pub method: &'a str,
    pub target: Option<&'a str>,
    pub trust: Trust,
    pub findings: &'a [Finding],
    pub before_sha256: String,
    pub after_sha256: String,
}

pub struct Audit {
    dir: PathBuf,
    current: Mutex<Option<(String, File)>>,
}

impl Audit {
    pub fn open(dir: PathBuf) -> io::Result<Self> {
        fs::create_dir_all(&dir)?;
        prune(&dir);
        Ok(Self {
            dir,
            current: Mutex::new(None),
        })
    }

    /// `$MCP_WARDEN_HOME/audit`, defaulting to `~/.mcp-warden/audit`.
    pub fn default_dir() -> Option<PathBuf> {
        Some(warden_home()?.join("audit"))
    }

    pub fn record(&self, entry: &Entry) -> io::Result<()> {
        let line = serde_json::to_string(entry)?;
        let today = OffsetDateTime::now_utc().date().to_string();
        let mut current = self
            .current
            .lock()
            .map_err(|_| io::Error::other("audit log lock poisoned"))?;
        if current.as_ref().is_none_or(|(day, _)| *day != today) {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.dir.join(format!("{today}.jsonl")))?;
            *current = Some((today, file));
        }
        match current.as_mut() {
            Some((_, file)) => writeln!(file, "{line}"),
            None => Err(io::Error::other("audit log file not open")),
        }
    }
}

/// `$MCP_WARDEN_HOME`, defaulting to `~/.mcp-warden`.
pub fn warden_home() -> Option<PathBuf> {
    match std::env::var_os("MCP_WARDEN_HOME") {
        Some(dir) => Some(PathBuf::from(dir)),
        None => Some(dirs::home_dir()?.join(".mcp-warden")),
    }
}

pub fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn prune(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let expired = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > RETENTION);
        if expired && path.extension().is_some_and(|ext| ext == "jsonl") {
            // Best effort: a file another warden still holds open is retried next start.
            let _ = fs::remove_file(path);
        }
    }
}
