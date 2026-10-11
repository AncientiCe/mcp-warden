# mcp-warden

A drop-in stdio proxy for MCP servers. It cleans untrusted tool output before your agent reads it, and (in later phases) stops the agent from taking damaging actions after it has read untrusted content.

```jsonc
// before
{ "command": "github-mcp-server", "args": ["stdio"] }
// after
{ "command": "mcp-warden", "args": ["--server-id", "github", "--", "github-mcp-server", "stdio"] }
```

> **Not a guarantee.** Prompt injection can't be filtered out reliably, because injected instructions are just text and can always be reworded. mcp-warden is defense in depth: it strips hidden content and labels untrusted data, and its last layer controls *actions* (egress, pushes, secret reads) once untrusted text has entered the session. Use it alongside sandboxing and least-privilege tokens, not instead of them.

## Status

Early development. See `CHANGELOG.md` for what works today.

## Development

See `AGENTS.md` for the rules (TDD behavior tests, quality gates). Run every gate with `make check`, or `pwsh scripts/check.ps1` on Windows.
