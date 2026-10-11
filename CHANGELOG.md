# Changelog

All notable changes to `mcp-warden` are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Changed

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
