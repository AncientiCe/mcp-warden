# Changelog

All notable changes to `mcp-warden` are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- Asking the agent to hide something from the user ("do not tell the user", "without telling the
  user", "keep this secret from") is a new strong signal (`R-SECRECY`) and withholds the field on
  its own. Fake authority alone ("as the AI assistant you must") stays a weak signal.
- In outside content, smuggling characters (Unicode tags, variation-selector runs, bidi controls
  such as Trojan Source overrides) now withhold the field instead of only being stripped. Ordinary
  hidden markup (HTML comments, zero-width characters, colors) is still stripped silently.

## [0.3.2] - 2026-10-11

### Changed

- The quarantine notice asks the agent to suggest closing a flagged issue or pull request as a
  suspected prompt injection once the user has reviewed it, and never to reply or close without
  the user's go-ahead.

## [0.3.1] - 2026-10-11

### Fixed

- The hook blocks the agent only from running the user-only commands (show, release, trust,
  distrust) or reading quarantine paths. Notes, docs, commit messages and other text that merely
  mention those commands are no longer denied.

## [0.3.0] - 2026-10-11

### Changed

- The Claude Code hook quarantines instead of tainting. Outside content that looks like prompt
  injection is withheld per field and stored for review; the agent is told to report it to the
  user. The user's own project (files, builds, tests, local commands) is never flagged, and the
  hook no longer raises session taint or asks for permission on the agent's actions.
- The agent is never shown hidden text the hook removed, only what kind of content it was.

### Added

- `mcp-warden show ID` prints quarantined content; `mcp-warden release ID` lets the agent see it.
  The hook denies the agent running either command or reading the quarantine directory.
- Projects the agent clones start SUSPICIOUS: their files and commands are checked like outside
  content until the user runs `mcp-warden trust DIR` (`distrust` reverses it). Cloning does not
  prompt; a flag in such a project tells the user how to trust it.
- The hook stays silent unless it withholds injection or removes smuggling characters; ordinary
  hidden markup such as issue-template comments is stripped without a message.
- Codex support: `mcp-warden install codex` registers the hook in `~/.codex/hooks.json`
  (`hook --client codex`). Codex cannot substitute cleaned output, so withheld injection and
  smuggled text replace the whole tool result with the quarantine notice. Codex asks once, via
  `/hooks`, to trust a new hook.
- Cursor support: `mcp-warden install cursor` registers the hook in `~/.cursor/hooks.json`
  (`hook --client cursor`). Flagged MCP output is replaced; Cursor cannot replace Shell or Read
  output, so the agent is told to treat a flagged result as data and tell the user. Cursor does
  not name the server behind an MCP tool, so every MCP result is checked as outside content.
- `mcp-warden install` and `mcp-warden uninstall` without a client handle every supported client
  found in the home directory (`--home` to look elsewhere).

### Removed

- Taint-based permission prompts from the Claude Code hook (`PreToolUse`), which flagged the
  user's own projects.

## [0.2.0] - 2026-10-11

### Added

- `mcp-warden hook` scans every Claude Code tool result regardless of source (Bash, WebFetch,
  WebSearch, Read, and every MCP tool), so servers do not need wrapping one by one. External
  content (web tools, `gh`/`curl`-style commands, MCP servers whose names indicate public sources,
  or servers configured `untrusted`) taints the shared session; hidden text is stripped from what
  the agent sees and injection evidence raises taint to SUSPICIOUS or HOSTILE with a warning to
  the agent. Local files and commands are never rewritten and only warn on smuggled text or
  injection attempts. Findings are written to the audit log.
- `mcp-warden hook` also gates the agent's own tool calls (PreToolUse) on shared taint: Bash and
  PowerShell commands are classified by their most sensitive part (publishing, network egress,
  piping downloads into a shell, secrets, destructive commands, agent configuration and warden's
  own state), as are WebFetch, file writes and MCP tools. Confirmation uses Claude Code's own
  permission prompt, even for pre-approved commands; clean sessions and routine local work stay
  silent.
- `mcp-warden install claude-code` registers the hook for every tool in `~/.claude/settings.json`
  (or `--settings PATH`), preserving existing settings and hooks with an exact backup. Re-running
  changes nothing; `mcp-warden uninstall claude-code` removes only warden's entries.

### Fixed

- Install scripts retry transient GitHub download and API errors instead of failing on the first
  5xx response.

## [0.1.0] - 2026-10-11

### Changed

- `[egress].allow_hosts` replaces the built-in outbound host exemptions using validated exact
  host names. Subdomains and credential-bearing URLs do not inherit an exemption.

- Proxy trust configuration now layers global, working-directory, and explicit TOML files.
  Explicit command-line trust takes precedence, and server defaults work without labeling.
  Invalid discovered configuration stops startup instead of silently disabling protection.

### Fixed

- Field trust governs sanitization and shared taint even when visible labels are disabled.

- Explicitly untrusted fields taint the session even on otherwise trusted servers, including
  semi-trusted records whose provenance labels are suppressed.
- Pending request tracking is capped at 4096 entries and releases cancelled requests. Late or
  unmatched responses still receive sanitization at the server's configured trust level; their audit
  entries use `unmatched_response` because the original method and target are no longer known.
- Windows now terminates the wrapped server process tree when warden exits, including forced
  termination. Job membership is established before spawning the server to avoid orphan races.

### Added

- Install scripts `scripts/install.sh` (Linux/macOS) and `scripts/install.ps1` (Windows) download a
  release archive, verify its SHA-256 checksum and install `mcp-warden`. `MCP_WARDEN_VERSION` pins a
  release and `MCP_WARDEN_INSTALL_DIR` chooses the destination.
- Tagged releases (`v*`) build Linux (x86_64, aarch64), macOS (Apple Silicon, Intel) and Windows
  (x86_64) archives with checksums. Release notes come from the tag's `CHANGELOG.md` section; the
  release fails if that section is missing or the tag disagrees with `Cargo.toml`. A smoke job then
  installs the published release with the install scripts on all three platforms.
- Homebrew tap `ancientice/mcp-warden`. Each successful release opens a pull request on
  `AncientiCe/homebrew-mcp-warden` with the new version and per-platform checksums.
- `mcp-warden wrap CONFIG` upgrades stdio entries under `mcpServers` or `servers`, enables labeling,
  detection, enforcement and tool pinning, preserves original arguments/environment and unrelated
  settings, and creates an exact backup before writing. Repeated runs are idempotent; invalid entries
  abort before any changes. Remote URL entries are reported as skipped.
- `--pin-tools FILE` records first-seen tool definitions and warns/audits subsequent changes without
  silently accepting a new baseline. `--detect` also scans tool descriptions, preserving input schemas.
  Definition changes and detected tool poisoning raise shared taint when enforcement is enabled.
- Opt-in `--enforce` shared taint-based MCP action policy, independent of heuristic detection.
  Untrusted responses taint the shared session before delivery; sensitive and unknown calls require
  confirmation or are denied at higher taint. Approved calls are bound to server, tool and arguments,
  expire after ten minutes, and are consumed once. `status`, `approve TOKEN`, and `untaint` manage
  the shared state; `--state-file` selects an isolated scope. State uses an OS file lock, a two-hour
  inactivity TTL, bounded pending approvals, and fail-closed handling of corrupt or inaccessible state.
  Blocks appear as MCP tool errors and audit findings. Direct client tools remain outside this boundary.
- Opt-in `--detect` heuristics for the proxy and `scan`: normalized override/role/tool/exfiltration/
  secret/urgency/memory rules, bounded base64 probes, rule ids and scores in findings, annotations
  at score 0.5 and field withholding at 0.9. Detection is advisory and does not replace action policy.
- `mcp-warden replay DIRECTORY` reports precision, recall, false positives and latency for
  `malicious.json` / `benign.json` corpus files using the sanitizer plus detector.
- The project is dual-licensed under MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
- `SECURITY.md` states the threat model, what operators should assume, and how to report a vulnerability in private.
- Opt-in `--label` provenance boundaries for untrusted text and JSON-in-text fields, with escaping
  of forged boundaries. `--config FILE` loads validated TOML trust rules per server/tool/JSON path,
  including wildcard arrays and descendant keys. Explicit untrusted rules take precedence.
  Dynamic author associations can suppress labels for semi-trusted records, but never for bots
  or nested records without their own authorship. MCP envelopes and binary data remain intact.
- Stdio proxy: `mcp-warden [--server-id ID] [--trust untrusted|trusted] -- <server command>` spawns the real
  MCP server and relays JSON-RPC both ways. Lines it doesn't rewrite are forwarded byte for byte, including
  notifications, non-JSON lines and server-to-client requests. Server stderr passes through and the server's
  exit code is propagated. Programs are resolved through `PATH`/`PATHEXT`, so `npx` works on Windows.
- Layer 1 sanitizing of tool results (`tools/call`), `resources/read`, `prompts/get` and server-initiated
  `sampling/createMessage` / `elicitation/create` requests:
  - always: Unicode tag characters (decoded into the finding), variation-selector smuggling, zero-width
    characters, bidi overrides, ANSI escapes and control characters. Legitimate emoji ZWJ sequences, emoji
    presentation selectors, keycaps, CJK variation sequences and ZWJ/ZWNJ in Indic and Persian text are kept;
  - untrusted servers (the default) also lose HTML comments (including unclosed ones), images on
    non-allowlisted hosts (`--allow-image-host`; GitHub hosts are allowed by default), base64/hex blobs of
    200+ characters, and whitespace padding.
  - JSON returned as text, as API-backed servers like github-mcp-server do (`<` escaped as `<`), is
    parsed and sanitized per string, and re-serialized only when something changed.
  - Image/audio `data` and resource `blob` bytes are never touched.
- Tool, prompt and resource listings and `initialize` instructions lose invisible characters only.
- Audit log: one JSON line per rewritten message in `~/.mcp-warden/audit/YYYY-MM-DD.jsonl`
  (`--audit-dir`, `$MCP_WARDEN_HOME`, `--no-audit`) with server, method, tool, findings with decoded
  payloads, and before/after SHA-256. Files older than 30 days are deleted at startup. Each rewrite is also
  summarized on stderr.
- `mcp-warden scan [FILE]`: runs the same sanitizer offline; clean text on stdout, findings as JSON lines on
  stderr, `--fail-on-findings` exits with 3.
- Attack corpus (`tests/corpus/malicious.json`, 18 cases tagged with the roadmap phase expected to catch
  them) and benign corpus (`tests/corpus/benign.json`).
