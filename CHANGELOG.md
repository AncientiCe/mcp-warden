# Changelog

All notable changes to `mcp-warden` are documented here. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- Pending request tracking is capped at 4096 entries and releases cancelled requests. Late or
  unmatched responses still receive sanitization at the server's configured trust level; their audit
  entries use `unmatched_response` because the original method and target are no longer known.
- Windows now terminates the wrapped server process tree when warden exits, including forced
  termination. Job membership is established before spawning the server to avoid orphan races.

### Added

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
