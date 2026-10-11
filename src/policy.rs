//! MCP action policy. Unknown tool semantics require confirmation after taint.

use anyhow::Result;
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
}

impl Gate {
    /// Returns a tool error for blocked requests; allowed calls are untouched.
    pub fn check(&self, server: &str, request: &Value) -> Result<Option<Value>> {
        if request["method"] != "tools/call" {
            return Ok(None);
        }
        let name = request["params"]["name"].as_str().unwrap_or("");
        let arguments = &request["params"]["arguments"];
        let action = classify(name, arguments, &self.store);
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

fn classify(name: &str, args: &Value, store: &Store) -> Action {
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
                    && u.host_str().is_some_and(|host| {
                        matches!(
                            host,
                            "github.com"
                                | "api.github.com"
                                | "crates.io"
                                | "docs.rs"
                                | "registry.npmjs.org"
                                | "pypi.org"
                        )
                    })
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
