//! Harness for driving the real `mcp-warden` binary over stdio, with the
//! `fake_server` example as the wrapped MCP server.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tempfile::TempDir;

pub const TIMEOUT: Duration = Duration::from_secs(15);

pub fn warden_exe() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_mcp-warden"))
}

/// `cargo test` builds examples next to the binaries.
pub fn fake_server_exe() -> PathBuf {
    let exe = warden_exe();
    let dir = exe.parent().expect("binary has a parent dir");
    dir.join("examples")
        .join(format!("fake_server{}", std::env::consts::EXE_SUFFIX))
}

/// Encodes text as invisible Unicode tag characters (ASCII smuggling).
pub fn tagged(s: &str) -> String {
    s.chars()
        .map(|c| char::from_u32(0xE0000 + c as u32).unwrap())
        .collect()
}

pub struct Session {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<Vec<u8>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    pub audit_dir: TempDir,
}

impl Session {
    /// `mcp-warden --server-id fake --audit-dir <tmp> <extra> -- fake_server`
    pub fn wrapped(extra: &[&str]) -> Self {
        let audit_dir = TempDir::new().unwrap();
        let mut cmd = Command::new(warden_exe());
        cmd.args(["--server-id", "fake", "--audit-dir"])
            .arg(audit_dir.path())
            .args(extra)
            .arg("--")
            .arg(fake_server_exe());
        Self::spawn(cmd, audit_dir)
    }

    /// The fake server on its own, to compare against what warden forwards.
    pub fn direct() -> Self {
        Self::spawn(Command::new(fake_server_exe()), TempDir::new().unwrap())
    }

    pub fn spawn(mut cmd: Command, audit_dir: TempDir) -> Self {
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().unwrap();
        let mut stderr_pipe = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                match reader.read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        if tx.send(line).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let sink = stderr.clone();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = stderr_pipe.read(&mut buf) {
                if n == 0 {
                    break;
                }
                sink.lock().unwrap().extend_from_slice(&buf[..n]);
            }
        });
        Self {
            child,
            stdin,
            lines,
            stderr,
            audit_dir,
        }
    }

    pub fn send_raw(&mut self, bytes: &[u8]) {
        let stdin = self.stdin.as_mut().expect("stdin still open");
        stdin.write_all(bytes).unwrap();
        stdin.flush().unwrap();
    }

    pub fn send(&mut self, msg: &Value) {
        self.send_raw(format!("{msg}\n").as_bytes());
    }

    /// Next raw line (including its newline) the client receives.
    pub fn read_raw(&mut self) -> Vec<u8> {
        self.lines
            .recv_timeout(TIMEOUT)
            .expect("timed out waiting for a line on stdout")
    }

    pub fn read(&mut self) -> Value {
        let line = self.read_raw();
        serde_json::from_slice(&line)
            .unwrap_or_else(|e| panic!("not JSON ({e}): {}", String::from_utf8_lossy(&line)))
    }

    pub fn request(&mut self, msg: &Value) -> Value {
        self.send(msg);
        self.read()
    }

    pub fn initialize(&mut self) -> Value {
        let reply = self.request(&json!({
            "jsonrpc": "2.0", "id": 0, "method": "initialize",
            "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "test", "version": "0" } }
        }));
        self.send(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        reply
    }

    pub fn call_tool(&mut self, id: u64, name: &str, arguments: Value) -> Value {
        self.request(&json!({
            "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": name, "arguments": arguments }
        }))
    }

    /// Text of the first content block of a tool result.
    pub fn call_tool_text(&mut self, id: u64, name: &str, arguments: Value) -> String {
        let reply = self.call_tool(id, name, arguments);
        reply["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("no text content in {reply}"))
            .to_string()
    }

    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.stderr.lock().unwrap()).into_owned()
    }

    /// Closes stdin (client disconnect) and waits for the process to exit.
    pub fn finish(mut self) -> (ExitStatus, Self) {
        self.stdin.take();
        let status = self.wait();
        (status, self)
    }

    pub fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() > deadline {
                self.child.kill().ok();
                panic!("process did not exit within {TIMEOUT:?}");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[cfg(windows)]
    pub fn kill(&mut self) {
        self.child.kill().unwrap();
        self.wait();
    }

    /// Every audit entry written so far, across all files in the audit dir.
    pub fn audit(&self) -> Vec<Value> {
        read_audit(self.audit_dir.path())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.child.kill().ok();
    }
}

pub fn read_audit(dir: &Path) -> Vec<Value> {
    let mut entries = Vec::new();
    let Ok(files) = std::fs::read_dir(dir) else {
        return entries;
    };
    for file in files.flatten() {
        let text = std::fs::read_to_string(file.path()).unwrap();
        entries.extend(
            text.lines()
                .map(|l| serde_json::from_str::<Value>(l).unwrap()),
        );
    }
    entries
}

/// Finding kinds of an audit entry.
pub fn kinds(entry: &Value) -> Vec<String> {
    entry["findings"]
        .as_array()
        .map(|f| {
            f.iter()
                .map(|x| x["kind"].as_str().unwrap().to_string())
                .collect()
        })
        .unwrap_or_default()
}
