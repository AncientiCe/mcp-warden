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

## Trust labeling

Add `--label` to wrap untrusted result text in provenance tags. `--config examples/trust.toml`
selects trust rules using `--server-id`. Without a configuration, every server remains untrusted
unless explicitly started with `--trust trusted`. Labeling is opt-in; the default sanitizer mode
continues to preserve benign traffic byte for byte.

Trust rules select tools by exact name (`"*"` selects all). Paths support `$`, dotted keys,
numeric indexes, `[*]`, and descendant keys such as `$..body`. Unknown configuration keys and
unsupported paths fail at startup. Explicit untrusted paths take precedence over trusted paths.
Dynamic `author_association` rules affect only the enclosing record: a member's issue does not
make its comments trusted. Bots stay untrusted. Semi-trusted text is still sanitized.

The supplied map is a starting configuration, not proof that a field or server is trustworthy.
It leaves Palace untrusted until provenance is available. Tags describe data provenance; they
are not an authorization boundary.

## Detection and corpus replay

`--detect` enables local heuristic annotations (score ≥0.5) and critical-field withholding
(score ≥0.9), both on the proxy and on `scan`. It uses Unicode normalization, common letter/number
substitutions, bounded base64 probes, and weighted rule families. Findings include rule ids and scores;
audit snippets are limited to 1000 characters. Withheld content is not a recoverable archive.

Run `mcp-warden replay tests/corpus` to measure the combined sanitizer and detector on the bundled
fixtures. These small, curated corpora are regression checks, not a real-world safety benchmark.
Detection is optional and cannot establish that a response is safe.

## Development

See `AGENTS.md` for the rules (TDD behavior tests, quality gates). Run every gate with `make check`, or `pwsh scripts/check.ps1` on Windows.
