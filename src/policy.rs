//! MCP action policy. Unknown tool semantics require confirmation after taint.

use anyhow::Result;
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::taint::{Approval, Level, Store, now};

#[derive(Clone, Copy)]
enum Action {
    Read,
    Edit,
    Secret,
    EgressAllowed,
    EgressOther,
    Publish,
    Workflow,
    Install,
    Config,
    Memory,
    Destructive,
    Unknown,
}

#[derive(Clone, Copy, PartialEq)]
enum Decision {
    Allow,
    Confirm,
    Deny,
}

pub struct Gate {
    pub store: Store,
    pub allowed_hosts: Vec<String>,
}

pub fn default_egress_hosts() -> Vec<String> {
    [
        "github.com",
        "api.github.com",
        "crates.io",
        "docs.rs",
        "registry.npmjs.org",
        "pypi.org",
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

impl Gate {
    /// Returns a tool error for blocked requests; allowed calls are untouched.
    pub fn check(&self, server: &str, request: &Value) -> Result<Option<Value>> {
        if request["method"] != "tools/call" {
            return Ok(None);
        }
        let name = request["params"]["name"].as_str().unwrap_or("");
        let arguments = &request["params"]["arguments"];
        let action = classify(name, arguments, &self.store, &self.allowed_hosts);
        let digest = hex::encode(Sha256::digest(serde_json::to_vec(&json!([
            server, name, arguments
        ]))?));
        self.store.with_state(|state| {
            let decision = decide(action, state.level);
            if decision == Decision::Allow { return Ok(None); }
            if decision == Decision::Confirm {
                let approved = state.approvals.iter().find(|(_, a)|a.hash==digest && a.approved).map(|(key,_)|key.clone());
                if let Some(token) = approved {
                    state.approvals.remove(&token);
                    return Ok(None);
                }
            }
            let mut token = None;
            if decision == Decision::Confirm {
                token = state.approvals.iter().find(|(_,a)|a.hash==digest).map(|(key,_)|key.clone());
                if token.is_none() {
                    if state.approvals.len() >= 128
                        && let Some(oldest) = state.approvals.iter().min_by_key(|(_,a)|a.expires).map(|(k,_)|k.clone())
                    { state.approvals.remove(&oldest); }
                    let mut random = [0u8; 24];
                    getrandom::fill(&mut random).map_err(|e|anyhow::anyhow!("approval randomness: {e}"))?;
                    let key = hex::encode(random);
                    state.approvals.insert(key.clone(), Approval { hash:digest, tool:format!("{server}:{name}"), expires:now()+600, approved:false });
                    token = Some(key);
                }
            }
            let reason = if token.is_some() { "approval required" } else { "denied" };
            let message = format!("mcp-warden: {reason} for {server}:{name}; session {:?}; untrusted source: {}. Sensitive calls require a human decision outside the MCP session.",state.level,state.source);
            let mut result = json!({"isError":true,"content":[{"type":"text","text":message}]});
            if let Some(token) = token { result["_meta"] = json!({"mcp-warden/approval_token":token}); }
            Ok(Some(json!({"jsonrpc":"2.0","id":request.get("id").cloned().unwrap_or(Value::Null),"result":result})))
        })
    }
}

fn strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.to_string()),
        Value::Array(items) => {
            for item in items {
                strings(item, out);
            }
        }
        Value::Object(items) => {
            for item in items.values() {
                strings(item, out);
            }
        }
        _ => {}
    }
}

fn classify(name: &str, args: &Value, store: &Store, allowed_hosts: &[String]) -> Action {
    let name = name.to_ascii_lowercase();
    let mut values = Vec::new();
    strings(args, &mut values);
    if values.iter().any(|s| {
        store.is_state_path(s)
            || s.lines().any(|line| {
                [
                    "*** Update File: ",
                    "*** Add File: ",
                    "*** Delete File: ",
                    "*** Move to: ",
                ]
                .iter()
                .filter_map(|prefix| line.strip_prefix(prefix))
                .any(|path| store.is_state_path(path.trim()))
            })
    }) {
        return Action::Config;
    }
    let text = values.join(" ").replace('\\', "/").to_ascii_lowercase();
    if [
        ".env",
        ".ssh/",
        "id_rsa",
        ".npmrc",
        "credentials",
        "keychain",
    ]
    .iter()
    .any(|s| text.contains(s))
    {
        return Action::Secret;
    }
    let destructive = ["delete", "remove", "drop", "destroy", "force_push"]
        .iter()
        .any(|s| name.contains(s));
    if destructive {
        return Action::Destructive;
    }
    let read = matches!(
        name.as_str(),
        "echo"
            | "json"
            | "json_pretty"
            | "read_file"
            | "read_text_file"
            | "read_multiple_files"
            | "list_directory"
            | "search_files"
            | "get_file_contents"
            | "issue_read"
            | "pull_request_read"
            | "list_issues"
            | "search_issues"
            | "search_code"
            | "search_repositories"
            | "get_commit"
            | "list_commits"
            | "get_me"
            | "impact_index"
            | "impact_file"
            | "impact_change"
            | "impact_diff"
            | "palace_search"
            | "palace_kg_query"
            | "palace_diary_search"
    );
    if !read
        && [
            ".github/workflows",
            ".gitlab-ci",
            "dockerfile",
            "package.json",
        ]
        .iter()
        .any(|s| text.contains(s))
    {
        return Action::Workflow;
    }
    if !read
        && [
            ".mcp.json",
            "claude.md",
            "agents.md",
            ".mcp-warden",
            "settings.json",
            "hooks/",
        ]
        .iter()
        .any(|s| text.contains(s))
    {
        return Action::Config;
    }
    if name.starts_with("palace_") && !read {
        return Action::Memory;
    }
    if ["install", "add_dependency"]
        .iter()
        .any(|s| name.contains(s))
    {
        return Action::Install;
    }
    if [
        "push",
        "create_issue",
        "issue_write",
        "pull_request_write",
        "create_pull_request",
        "comment",
        "send",
        "post",
        "publish",
        "create_or_update_file",
    ]
    .iter()
    .any(|s| name.contains(s))
    {
        return Action::Publish;
    }
    if matches!(
        name.as_str(),
        "fetch" | "http_request" | "web_fetch" | "browser_navigate" | "firecrawl_scrape"
    ) {
        let urls: Vec<_> = values
            .iter()
            .filter_map(|s| url::Url::parse(s).ok())
            .collect();
        let allowed = !urls.is_empty()
            && urls.iter().all(|u| {
                matches!(u.scheme(), "http" | "https")
                    && u.username().is_empty()
                    && u.password().is_none()
                    && u.host_str()
                        .is_some_and(|host| allowed_hosts.iter().any(|allowed| allowed == host))
            });
        return if allowed {
            Action::EgressAllowed
        } else {
            Action::EgressOther
        };
    }
    if read {
        return Action::Read;
    }
    if matches!(name.as_str(), "write_file" | "edit_file" | "apply_patch") {
        return Action::Edit;
    }
    Action::Unknown
}

fn decide(action: Action, level: Level) -> Decision {
    use Action::*;
    use Decision::*;
    use Level::*;
    match (action, level) {
        (Read, _) => Allow,
        (Destructive, Clean | Tainted) => Confirm,
        (Destructive, _) => Deny,
        (_, Clean) => Allow,
        (Edit, Hostile) => Confirm,
        (Edit, _) => Allow,
        (EgressAllowed, Hostile) => Confirm,
        (EgressAllowed, _) => Allow,
        (Secret | EgressOther | Workflow | Config, Suspicious | Hostile) => Deny,
        (Publish, Hostile) => Deny,
        (Install, Tainted) => Allow,
        (Memory, Tainted) => Allow,
        (Memory, Hostile) => Deny,
        (Unknown, Hostile) => Deny,
        _ => Confirm,
    }
}

/// What the hook tells the client about one of the agent's own tool calls.
pub enum Permission {
    /// Stay silent: the client's own permission rules decide.
    Allow,
    /// Force the client's confirmation prompt, with this reason.
    Ask(String),
    /// Refuse the call, with this reason.
    Deny(String),
}

impl Gate {
    /// Applies the taint policy to a client tool call (Bash, WebFetch, Write, MCP tools, ...).
    pub fn check_agent_tool(&self, tool: &str, input: &Value) -> Result<Permission> {
        let action = classify_agent_tool(tool, input, &self.store, &self.allowed_hosts)?;
        self.store.with_state(|state| {
            let source = if state.source.is_empty() {
                "an unknown source"
            } else {
                &state.source
            };
            let context = format!(
                "mcp-warden: {} ({tool}) in a session that read untrusted content from {source}; taint {:?}.",
                action.describe(),
                state.level
            );
            Ok(match decide(action, state.level) {
                Decision::Allow => Permission::Allow,
                Decision::Confirm => Permission::Ask(format!(
                    "{context} Approve only if you asked for this action."
                )),
                Decision::Deny => Permission::Deny(format!(
                    "{context} Denied. Review the session, then run `mcp-warden untaint` yourself to continue."
                )),
            })
        })
    }
}

impl Action {
    fn describe(self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Edit => "local change",
            Action::Secret => "access to secrets",
            Action::EgressAllowed => "request to an allowed host",
            Action::EgressOther => "outbound network access",
            Action::Publish => "publishing",
            Action::Workflow => "CI or build configuration change",
            Action::Install => "package installation",
            Action::Config => "agent or warden configuration change",
            Action::Memory => "memory write",
            Action::Destructive => "destructive action",
            Action::Unknown => "unrecognized action",
        }
    }
}

fn classify_agent_tool(
    tool: &str,
    input: &Value,
    store: &Store,
    allowed_hosts: &[String],
) -> Result<Action> {
    if let Some(rest) = tool.strip_prefix("mcp__") {
        let name = rest.split_once("__").map_or(rest, |(_, name)| name);
        return Ok(classify(name, input, store, allowed_hosts));
    }
    Ok(match tool {
        "Bash" | "PowerShell" => shell_action(
            input["command"].as_str().unwrap_or(""),
            store,
            allowed_hosts,
        )?,
        "WebFetch" => classify("fetch", &json!([input["url"]]), store, allowed_hosts),
        "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => {
            let path = input
                .get("file_path")
                .or_else(|| input.get("notebook_path"))
                .cloned()
                .unwrap_or(Value::Null);
            classify("write_file", &json!([path]), store, allowed_hosts)
        }
        "Read" | "Grep" | "Glob" | "LS" | "NotebookRead" => {
            classify("read_file", input, store, allowed_hosts)
        }
        _ => Action::Read,
    })
}

const SECRET_MARKERS: &[&str] = &[
    ".env",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    ".npmrc",
    ".netrc",
    "credentials",
    "keychain",
    "printenv",
    "env:",
];
const CONFIG_MARKERS: &[&str] = &[
    ".mcp.json",
    "claude.md",
    "agents.md",
    ".mcp-warden",
    "settings.json",
    "hooks/",
];
const WORKFLOW_MARKERS: &[&str] = &[
    ".github/workflows",
    ".gitlab-ci",
    "dockerfile",
    "package.json",
];
const NETWORK_PROGRAMS: &[&str] = &[
    "nc", "ncat", "netcat", "socat", "telnet", "scp", "sftp", "ftp", "rsync", "ssh",
];
const FETCH_PROGRAMS: &[&str] = &[
    "curl",
    "wget",
    "http",
    "https",
    "xh",
    "iwr",
    "irm",
    "invoke-webrequest",
    "invoke-restmethod",
    "lynx",
    "w3m",
];
/// Programs that only read local state.
const READ_PROGRAMS: &[&str] = &[
    "ls",
    "dir",
    "cat",
    "type",
    "head",
    "tail",
    "less",
    "more",
    "grep",
    "rg",
    "egrep",
    "fgrep",
    "find",
    "fd",
    "wc",
    "sort",
    "uniq",
    "cut",
    "tr",
    "echo",
    "printf",
    "pwd",
    "cd",
    "pushd",
    "popd",
    "which",
    "where",
    "whoami",
    "hostname",
    "date",
    "stat",
    "file",
    "du",
    "df",
    "tree",
    "diff",
    "cmp",
    "jq",
    "yq",
    "sha256sum",
    "shasum",
    "md5sum",
    "get-content",
    "gc",
    "get-childitem",
    "gci",
    "select-string",
    "sls",
    "get-location",
    "get-filehash",
    "test",
    "true",
    "false",
    "sleep",
    "basename",
    "dirname",
    "realpath",
    "readlink",
    "column",
    "nl",
    "tac",
    "start-sleep",
    "write-host",
    "write-output",
    "measure-object",
    "select-object",
    "where-object",
    "foreach-object",
];
/// Programs that change only the local checkout or build output.
const LOCAL_PROGRAMS: &[&str] = &[
    "make",
    "cmake",
    "ninja",
    "pytest",
    "tsc",
    "eslint",
    "prettier",
    "dotnet",
    "mvn",
    "gradle",
    "gradlew",
    "mkdir",
    "touch",
    "cp",
    "mv",
    "copy-item",
    "move-item",
    "new-item",
    "sed",
    "awk",
    "tar",
    "unzip",
    "gzip",
    "gunzip",
    "zip",
    "rustc",
    "rustfmt",
    "go",
];
const GIT_READ: &[&str] = &[
    "status",
    "log",
    "diff",
    "show",
    "branch",
    "rev-parse",
    "ls-files",
    "blame",
    "remote",
    "tag",
    "describe",
    "shortlog",
    "reflog",
    "grep",
];
const GIT_LOCAL: &[&str] = &[
    "add",
    "commit",
    "checkout",
    "switch",
    "restore",
    "merge",
    "rebase",
    "stash",
    "fetch",
    "pull",
    "cherry-pick",
    "revert",
    "init",
    "mv",
    "rm",
    "worktree",
    "submodule",
];
const CARGO_LOCAL: &[&str] = &[
    "build", "test", "check", "clippy", "fmt", "run", "doc", "bench", "tree", "metadata", "clean",
    "nextest", "audit",
];
const JS_LOCAL: &[&str] = &["test", "run", "build", "lint", "exec", "start"];
/// Wrappers that run the next word as the actual program.
const PREFIXES: &[&str] = &["rtk", "time", "nohup", "command", "builtin"];

struct ShellRules {
    redirect: Regex,
    url: Regex,
    upload: Regex,
    destructive: Regex,
    pipe_to_shell: Regex,
    publish: Regex,
    install: Regex,
}

impl ShellRules {
    fn new() -> Result<Self, regex::Error> {
        Ok(Self {
            redirect: Regex::new(r"\d*>&\d*|\d*>>?\s*\S+|<\s*\S+")?,
            url: Regex::new(r#"(?i)https?://[^\s'"<>)]+"#)?,
            upload: Regex::new(
                r"\s(?:-d|--data[a-z-]*|-f|--form|-t|--upload-file|-infile|-body|-x\s*(?:post|put|patch|delete)|--method[\s=]+(?:post|put|patch|delete))(?:\s|$)",
            )?,
            destructive: Regex::new(
                r"\brm\s+(?:-[a-z]*\s+)*-[a-z]*[rf]|\bremove-item\b[^;|&]*-recurse|\bgit\s+reset\s+--hard|\bgit\s+push\b[^;|&]*(?:\s--force|\s-f\b|\s\+)|\bgit\s+clean\s+-[a-z]*f|\bdrop\s+(?:table|database|schema)\b|\bdel\s+/[sq]|\brmdir\s+/s|\bmkfs|\bdd\s+if=",
            )?,
            pipe_to_shell: Regex::new(
                r"\|\s*(?:sudo\s+)?(?:sh|bash|zsh|dash|fish|pwsh|powershell|python3?|node|ruby|perl)\b|\b(?:iex|invoke-expression)\b",
            )?,
            publish: Regex::new(
                r"\bgit\s+push\b|\bgh\s+(?:pr|issue|release|gist|repo|label|secret|variable|workflow)\s+(?:create|comment|edit|merge|close|reopen|delete|review|upload|fork|run|set|enable|disable|archive|rename|transfer)\b|\bgh\s+api\b[^|;&]*(?:\s-x\s*(?:post|put|patch|delete)|--method[\s=]+(?:post|put|patch|delete)|\s-f\s|--field|--raw-field|--input)|\b(?:npm|pnpm|yarn|cargo|twine|gem|docker|podman)\s+(?:publish|push|upload)\b",
            )?,
            install: Regex::new(
                r"\b(?:npm|pnpm|yarn|bun)\s+(?:install|i|add|ci)\b|\bpip3?\s+install\b|\bpython3?\s+-m\s+pip\s+install\b|\bcargo\s+(?:install|add)\b|\b(?:brew|winget|choco|scoop|apt|apt-get|dnf|yum|gem)\s+install\b|\bgo\s+(?:install|get)\b|\b(?:npx|bunx|uvx|pipx)\s",
            )?,
        })
    }
}

fn unquote(word: &str) -> &str {
    word.trim_matches(|c| c == '"' || c == '\'')
}

/// Classifies a shell command by its most sensitive part.
fn shell_action(command: &str, store: &Store, allowed_hosts: &[String]) -> Result<Action> {
    let rules = ShellRules::new()?;
    let text = command.replace('\\', "/").to_ascii_lowercase();
    let unredirected = rules.redirect.replace_all(&text, " ");
    let segments: Vec<Vec<&str>> = unredirected
        .split(['&', '|', ';', '\n', '`', '(', ')', '{', '}', '$'])
        .map(|segment| {
            let words: Vec<&str> = segment
                .split_whitespace()
                .map(unquote)
                .filter(|w| !w.is_empty())
                .collect();
            let start = words
                .iter()
                .position(|w| !(PREFIXES.contains(w) || w.contains('=')))
                .unwrap_or(words.len());
            words[start..].to_vec()
        })
        .filter(|words| !words.is_empty())
        .collect();
    let programs: Vec<String> = segments.iter().map(|words| program(words[0])).collect();

    if programs.iter().any(|p| p == "mcp-warden")
        || CONFIG_MARKERS.iter().any(|m| text.contains(m))
        || command
            .split_whitespace()
            .any(|w| store.is_state_path(unquote(w)))
    {
        return Ok(Action::Config);
    }
    if SECRET_MARKERS.iter().any(|m| text.contains(m))
        || programs.iter().any(|p| p == "env" || p == "set")
    {
        return Ok(Action::Secret);
    }
    if rules.destructive.is_match(&text) {
        return Ok(Action::Destructive);
    }
    if rules.pipe_to_shell.is_match(&text)
        || programs
            .iter()
            .any(|p| NETWORK_PROGRAMS.contains(&p.as_str()))
    {
        return Ok(Action::EgressOther);
    }
    if programs
        .iter()
        .any(|p| FETCH_PROGRAMS.contains(&p.as_str()))
    {
        let urls: Vec<_> = rules
            .url
            .find_iter(command)
            .filter_map(|m| url::Url::parse(m.as_str()).ok())
            .collect();
        let allowed = !urls.is_empty()
            && !rules.upload.is_match(&text)
            && urls.iter().all(|u| {
                u.username().is_empty()
                    && u.password().is_none()
                    && u.host_str()
                        .is_some_and(|host| allowed_hosts.iter().any(|allowed| allowed == host))
            });
        return Ok(if allowed {
            Action::EgressAllowed
        } else {
            Action::EgressOther
        });
    }
    if rules.publish.is_match(&text) {
        return Ok(Action::Publish);
    }
    if WORKFLOW_MARKERS.iter().any(|m| text.contains(m)) {
        return Ok(Action::Workflow);
    }
    if rules.install.is_match(&text) {
        return Ok(Action::Install);
    }
    let mut action = Action::Read;
    for (words, program) in segments.iter().zip(&programs) {
        let sub = words.get(1).copied().unwrap_or("");
        let local = match program.as_str() {
            "git" if GIT_READ.contains(&sub) => false,
            "git" if GIT_LOCAL.contains(&sub) => true,
            "cargo" if CARGO_LOCAL.contains(&sub) => true,
            "npm" | "pnpm" | "yarn" | "bun" if JS_LOCAL.contains(&sub) => true,
            p if READ_PROGRAMS.contains(&p) => false,
            p if LOCAL_PROGRAMS.contains(&p) => true,
            _ => return Ok(Action::Unknown),
        };
        if local {
            action = Action::Edit;
        }
    }
    Ok(action)
}

/// `/usr/bin/git.exe` -> `git`.
fn program(word: &str) -> String {
    let name = word.rsplit('/').next().unwrap_or(word);
    name.strip_suffix(".exe").unwrap_or(name).to_string()
}
