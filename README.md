# mcp-warden

`mcp-warden` is a stdio proxy for [MCP](https://modelcontextprotocol.io) servers. It sits in front of a server you already run, relays JSON-RPC in both directions, and cleans tool output before an agent reads it.

Prompt injection is ordinary text, and a filter can always be reworded around. Warden removes content a person would not see, can mark untrusted fields, and can flag suspicious text. With `--enforce`, shared taint gates subsequent sensitive MCP calls, even with detection disabled. It does not confine the agent's built-in tools or the wrapped server. Keep a sandbox and least-privilege credentials as well.

```jsonc
// before
{ "command": "github-mcp-server", "args": ["stdio"] }

// after
{ "command": "mcp-warden", "args": ["--server-id", "github", "--", "github-mcp-server", "stdio"] }
```

The client speaks MCP only to warden. Warden spawns the real server and forwards its stderr and exit code. Lines that nothing rewrites are forwarded byte for byte, including notifications, non-JSON lines, and requests the server sends to the client. Diagnostics go to stderr. The protocol stream stays on stdout.

## Install

You need a current stable Rust toolchain (edition 2024). From a checkout:

```bash
cargo build --release --locked
```

The binary is `target/release/mcp-warden` (`target\release\mcp-warden.exe` on Windows). Put that directory on `PATH`, or point the MCP client at the full path. Warden resolves the wrapped server through `PATH` / `PATHEXT`, so `npx` works on Windows.

This crate is not published yet. Install from this repository, not from crates.io.

Use `cargo install --path . --locked` from a checkout, or
`cargo install --git https://github.com/AncientiCe/mcp-warden --locked` for the published Git revision.

## Upgrade a client configuration

`mcp-warden wrap PATH/TO/config.json` wraps stdio entries under `mcpServers` or `servers`,
enabling labeling, detection, enforcement and tool pinning. It prints an exact backup path and lists
wrapped/skipped entries. Environment settings and original arguments are preserved. Repeated runs
leave already-wrapped entries unchanged. Only strict JSON is accepted; JSON with comments requires
manual configuration. URL entries are left intact. Review the generated configuration and restart
the MCP client. Restore by copying the reported backup over the configuration with the client stopped.

## Wrap a server

```text
mcp-warden [OPTIONS] -- <SERVER COMMAND>...
```

Everything after `--` is the real server, unchanged. A client config looks like this:

```json
{
  "mcpServers": {
    "github": {
      "command": "mcp-warden",
      "args": [
        "--server-id", "github",
        "--label",
        "--config", "C:/path/to/trust.toml",
        "--",
        "github-mcp-server", "stdio"
      ]
    }
  }
}
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--server-id ID` | `server` | Name used in stderr and the audit log. Also selects that server's block in `--config`. |
| `--trust untrusted\|trusted` | `untrusted` | `untrusted` applies every sanitizer rule. `trusted` strips only invisible and control characters. |
| `--allow-image-host HOST` | GitHub hosts | Extra image host to leave in place. Repeat the flag to add more. A leading `.` matches subdomains. |
| `--label` | off | Wrap untrusted result text in provenance tags. Off, so benign text stays byte for byte. |
| `--config FILE` | global + project | Additional TOML trust map overriding discovered settings. |
| `--detect` | off | Annotate suspicious untrusted text, and withhold it when the score is high. |
| `--enforce` | off | Gate outbound MCP calls using shared taint, independent of detection. |
| `--state-file PATH` | `~/.mcp-warden/state.json` | Shared taint and single-use approvals. |
| `--pin-tools PATH` | none | Record first-seen tool definitions and warn on changes. |
| `--audit-dir DIR` | `~/.mcp-warden/audit` | Where rewritten messages are logged. `$MCP_WARDEN_HOME/audit` overrides the default home. |
| `--no-audit` | off | Skip the audit log. Sanitizing still runs. |

On Windows, warden puts the server process in a kill-on-close job before spawning it, so the server tree exits when warden exits, including forced termination.

Unknown methods pass through. These responses are sanitized:

- `tools/call`, `resources/read`, and `prompts/get` use the server's trust level
- `initialize`, `tools/list`, `prompts/list`, `resources/list`, and `resources/templates/list` lose invisible characters only, because that text comes from the server author
- server requests `sampling/createMessage` and `elicitation/create` are sanitized too
- a response that arrives after its request was cancelled, or after the pending map overflowed, is still sanitized; the audit line says `unmatched_response`

The pending map holds 4096 requests. Image and audio `data`, and resource `blob` bytes, are left untouched.

## What the sanitizer removes

Every server, including ones you mark trusted, loses:

- Unicode tag characters (the hidden payload is decoded into the audit finding)
- variation-selector smuggling
- zero-width characters, keeping real emoji ZWJ sequences, emoji presentation selectors, keycaps, CJK variation sequences, and ZWJ/ZWNJ in Indic and Persian text
- bidi overrides
- ANSI escapes and other control characters

Untrusted servers (the default) also lose:

- HTML comments, including an unclosed comment that would hide the rest of the document
- markdown and HTML images whose host is not allowlisted (`github.com`, `.github.com`, `.githubusercontent.com`, `.githubassets.com`, plus any `--allow-image-host`)
- base64 or hex runs of 200 characters or more
- whitespace padding

JSON returned as text is parsed and cleaned per string. The message is re-serialized only when something changed, so a clean result stays byte for byte.

## Trust labels

`--label` wraps untrusted text:

```text
<untrusted source="github:issue_read" field="$.body">
...
</untrusted>
```

Tag characters in the text are escaped, so a payload cannot forge the closing boundary. Labels describe where the text came from. They are not an authorization check.

`--config` loads a TOML file. `examples/trust.toml` is a starting map, not a statement that any server or field is safe. Read it before you use it: the `impact` block is `trusted` except for a few outsider-controlled fields, which is only appropriate when you control that server. Unknown server ids stay untrusted. Unknown keys and unsupported paths fail at startup.

The proxy reads `~/.mcp-warden/config.toml` (or `$MCP_WARDEN_HOME/config.toml`), then
`.mcp-warden.toml` in its working directory, then an explicit `--config` file. Later files
override a server's supplied `default_trust` and replace its supplied `fields` array; omitted
settings are inherited. An explicit `--trust` overrides the configured server default.
Only missing automatically discovered files are ignored. Invalid or unreadable files stop
startup, including invalid rules for other servers. Treat project configuration as security
policy: review it before starting a client in a downloaded repository. Field labeling still
requires `--label`; server default trust applies even without labeling. Offline `scan` uses
its command-line options and does not discover these files.

Rules select tools by exact name. `"*"` selects every tool. Paths support `$`, dotted keys, numeric indexes, `[*]`, and descendant keys such as `$..body`. An explicit untrusted path wins over a trusted path on the same field.

`dynamic_trust` looks at one field on the enclosing record, for example `$.author_association`. A member's issue does not make its comments trusted. Bots stay untrusted (`user.type` of `Bot`, or a login ending in `[bot]`). Semi-trusted text skips the provenance tag and is still sanitized.

## Heuristic detection

`--detect` is off unless you pass it. With it on, untrusted text is scored locally after the sanitizer runs. A score of at least 0.5 keeps the text and prefixes an annotation that names the rule ids. A score of at least 0.9 replaces the field with a withheld notice, so the original text is not sent to the client. The finding still records a truncated payload in the audit log.

The rules look for instruction overrides, role markers, suspicious commands, exfiltration hints, secret paths, concealment, and attempts to plant persistent memory. They also probe a bounded amount of base64. Rewording defeats them. Benign text that matches nothing is forwarded byte for byte.

Measure the checked-in corpora with:

```bash
mcp-warden replay tests/corpus
```

The directory must contain `malicious.json` and `benign.json`. The command prints one JSON object with case counts, true positives, false positives, recall, precision, and latency percentiles. It always runs with detection enabled.

## Scan a file

`mcp-warden scan` runs the same sanitizer outside a live session. Clean text goes to stdout. Findings go to stderr as JSON lines. Omit the path to read stdin. The input must be UTF-8.

```bash
mcp-warden scan notes.md
mcp-warden scan --fail-on-findings --detect notes.md
```

`--fail-on-findings` exits with code 3 when anything was found. Other errors exit with code 1. The same `--trust`, `--allow-image-host`, and `--detect` flags apply. `--label` is a proxy flag; `scan` does not add provenance tags.

## Audit log

Each rewritten message appends one JSON line to `~/.mcp-warden/audit/YYYY-MM-DD.jsonl` (UTC). The line has the server id, method, tool, trust level, findings (including a decoded hidden payload when there is one), and SHA-256 of the message body before and after. Stderr gets a one-line summary.

Files older than 30 days are deleted the next time warden starts. The log can contain whatever the server returned, including secrets that were hidden in the content. Keep that directory private to your user. See [SECURITY.md](SECURITY.md).

## Limits

- Warden sees MCP traffic on stdio. A client tool that runs a shell, fetches a URL, or reads a file never passes through it.
- HTTP and SSE transports are not implemented.
- Marking a server `--trust trusted`, or a field trusted in the config, turns off the untrusted rules for that text.
- `--detect` and `--label` are optional. The default proxy only strips the hidden-content rules above.
- Action blocking requires `--enforce` on every participating server; unwrapped and built-in tools bypass it.

## MCP action control

Add `--enforce` to every wrapped server to share taint and gate subsequent sensitive calls.
All instances use `~/.mcp-warden/state.json` (or `$MCP_WARDEN_HOME/state.json`) unless
`--state-file PATH` selects a separate scope. This intentionally shares taint across clients;
use one explicit path per client session when isolation is required. Untrusted responses set taint
even with `--detect` disabled. Detection can raise it to SUSPICIOUS or HOSTILE.

Read/search calls remain allowed, while secret reads, external fetches, publishing, workflow/config
changes, destructive actions and unknown tool semantics receive confirmation or denial according to
taint. The initial egress allowlist is github.com, api.github.com, crates.io, docs.rs,
registry.npmjs.org and pypi.org; only exact parsed hosts match. Tool classification uses known names
and argument paths, not server-provided safety annotations. This does not police redirects or the
server's network behavior.

Blocked tool calls return `isError: true`, a reason, and (when confirmation is permitted) an
`_meta["mcp-warden/approval_token"]`. A human can run `mcp-warden approve TOKEN` with the same
state-file option, then retry the exact call. Approval expires after ten minutes and is single-use;
changing the server, tool, arguments, or escalating taint invalidates it. Review the requested call
before approving. `mcp-warden status` displays taint and pending approvals; `mcp-warden untaint`
clears them after review. State expires after two hours of inactivity.

This enforcement covers MCP traffic through warden. Built-in terminal/file/browser tools bypass
it, and direct access to the state file or approval CLI must stay under human/client control.
Do not grant an agent unrestricted approval authority. Unknown tool names require confirmation
after taint; add support deliberately rather than trusting arbitrary `readOnlyHint` claims.

## Tool definition changes

`--pin-tools PATH` keeps first-seen fingerprints of tool definitions. Changed definitions gain a
warning and an audit finding; the original fingerprint is retained. Review a server upgrade before
manually removing its pin file to establish a new baseline. Keep the pin file outside agent-writable
locations where possible. This is trust on first use: it cannot attest that the first definition was safe.
`--detect` additionally scans tool descriptions. With `--enforce`, a changed definition or high-scoring
description raises shared taint before the client sees it.

## Development

Behavior is tested by running the `mcp-warden` binary against `examples/fake_server.rs` and the corpora in `tests/corpus/`. `AGENTS.md` is the working agreement for this repository.

The gate suite is formatting, Clippy, `cargo audit`, `cargo test --workspace`, and `cargo build --workspace --locked`.

```bash
make check                 # Linux and macOS
pwsh scripts/check.ps1     # Windows
```

GitHub Actions (`.github/workflows/ci.yml`) runs those gates on every push and pull request. Tests and the locked build run on Ubuntu and Windows.

## Security

Report a vulnerability in private. The threat model, operator assumptions, and contact path are in [SECURITY.md](SECURITY.md).

## License

Licensed under either of

- MIT license ([LICENSE-MIT](LICENSE-MIT) or https://opensource.org/licenses/MIT)
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or https://www.apache.org/licenses/LICENSE-2.0)

at your option.
