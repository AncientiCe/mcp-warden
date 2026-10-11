//! Upgrade stdio server entries while preserving exact backups and unrelated settings.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

pub fn rewrite(path: &Path, executable: &Path) -> Result<Value> {
    let path = std::fs::canonicalize(path).context("opening client configuration")?;
    let mut file = OpenOptions::new().read(true).write(true).open(&path)?;
    File::lock(&file)?;
    if file.metadata()?.len() > 16_777_216 {
        bail!("client configuration exceeds size limit");
    }
    let mut original = Vec::new();
    file.read_to_end(&mut original)?;
    let mut config: Value =
        serde_json::from_slice(&original).context("client configuration must be JSON")?;
    let root = config
        .as_object_mut()
        .context("client configuration must be an object")?;
    let mut wrapped = Vec::new();
    let mut skipped = Vec::new();
    let mut recognized = false;
    let parent = path
        .parent()
        .context("configuration has no parent directory")?;
    let pins = parent.join(".mcp-warden-tools.json");
    for section in ["mcpServers", "servers"] {
        let Some(entries) = root.get_mut(section) else {
            continue;
        };
        recognized = true;
        for (name, server) in entries
            .as_object_mut()
            .context("server section must be an object")?
        {
            let server = server
                .as_object_mut()
                .context("server entry must be an object")?;
            let Some(command) = server.get("command") else {
                skipped.push(name.clone());
                continue;
            };
            let command = command
                .as_str()
                .context("server command must be a string")?
                .to_string();
            if command.is_empty() {
                bail!("server command cannot be empty");
            }
            let basename = Path::new(&command)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("");
            if basename.eq_ignore_ascii_case("mcp-warden") || Path::new(&command) == executable {
                skipped.push(name.clone());
                continue;
            }
            let old_args = match server.get("args") {
                None => Vec::new(),
                Some(Value::Array(args)) if args.iter().all(Value::is_string) => args.clone(),
                _ => bail!("server {name} args must be an array of strings"),
            };
            let mut args = vec![
                json!("--server-id"),
                json!(name),
                json!("--label"),
                json!("--detect"),
                json!("--enforce"),
                json!("--pin-tools"),
                json!(pins),
                json!("--"),
                json!(command),
            ];
            args.extend(old_args);
            server.insert("command".into(), json!(executable));
            server.insert("args".into(), Value::Array(args));
            wrapped.push(name.clone());
        }
    }
    if !recognized {
        bail!("expected mcpServers or servers in client configuration");
    }
    if wrapped.is_empty() {
        return Ok(json!({"wrapped":wrapped,"skipped":skipped,"backup":null}));
    }
    let mut updated = serde_json::to_vec_pretty(&config)?;
    updated.push(b'\n');
    let mut random = [0u8; 12];
    getrandom::fill(&mut random).map_err(|e| anyhow::anyhow!("backup randomness: {e}"))?;
    let filename = path
        .file_name()
        .context("configuration has no filename")?
        .to_string_lossy();
    let backup = parent.join(format!("{filename}.warden-backup-{}", hex::encode(random)));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut backup_file = options.open(&backup)?;
    backup_file.set_permissions(file.metadata()?.permissions())?;
    backup_file.write_all(&original)?;
    backup_file.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&updated).with_context(|| {
        format!(
            "writing client configuration; original backup: {}",
            backup.display()
        )
    })?;
    file.set_len(updated.len() as u64)?;
    file.sync_all()?;
    Ok(json!({"wrapped":wrapped,"skipped":skipped,"backup":backup}))
}
