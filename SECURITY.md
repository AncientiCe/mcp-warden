# Security policy

`mcp-warden` reduces how much hidden or untrusted MCP output reaches an agent. It is not a guarantee that a model will ignore instructions, and it is not a sandbox.

## Reporting a vulnerability

Report privately. Please do not open a public issue for an unfixed bypass, and do not include live credentials.

- GitHub private advisory: https://github.com/AncientiCe/mcp-warden/security/advisories/new
- Email: ionut.riza@gmail.com

Include the commit you ran, the operating system, the flags and trust config (redact secrets and private repository names), the smallest input that triggers the bug, and what the client actually received. A proxy bug that drops, reorders, or corrupts MCP messages, or that writes anything other than relayed JSON-RPC to stdout, is in scope even when it is not an injection bypass.

There is no bug bounty. We will acknowledge the report and work on a fix. This project is early; only the latest `main` is maintained, and `0.1.0` has not been released.

## What a report should show

In scope:

- A sanitizer bypass: hidden text that the documented rules should have removed still reaches the client. That includes Unicode tags, variation-selector smuggling, zero-width and bidi controls, ANSI and other control characters, HTML comments, non-allowlisted images, long base64 or hex blobs, and whitespace padding, on a server that is untrusted.
- A provenance breakout when `--label` is on: untrusted text that closes the boundary early or forges a trusted span.
- A response that skips sanitizing because the request id was cancelled, evicted, or never correlated.
- The wrapped server process tree surviving after warden exits, on Windows.
- Audit-log handling that writes findings somewhere other than the configured directory, or that disables sanitizing when the log cannot be opened.
- A known-vulnerable dependency (`cargo audit`).
- An outbound MCP call bypassing the documented taint policy with `--enforce`, including replayed or mismatched approvals.
- A changed tool definition failing to produce an alert with `--pin-tools` and an intact previously established baseline.

Out of scope:

- A model that follows instructions which were visible in the tool result. The default pipeline forwards ordinary visible text unchanged.
- A bypass of `--detect` by rewording. Those rules are a local heuristic. They are off unless you pass the flag, and turning them on does not make the result trusted.
- Shell, web fetch, file read, and other client tools that never go through this proxy.
- A compromised `mcp-warden` binary or wrapped server. Warden does not scan server source. Tool pinning is trust on first use, so it cannot attest to the first definition's safety.
- HTTP and SSE MCP transports. They are not implemented.
- Denial of service against the model provider.

## Operator assumptions

- The default trust level is `untrusted`. `--trust trusted` is for a server whose output you control. It strips invisible and control characters only.
- `examples/trust.toml` is an example. A field or server marked trusted there is trusted because the file says so, not because warden verified it. Explicit untrusted paths win. Bots stay untrusted. A trusted author on a parent record does not cover nested comments.
- `--label` tells the model where text came from. It does not authorize a tool call.
- `--detect` may annotate (score at least 0.5) or withhold (score at least 0.9). Withholding keeps the original text out of the client and stores a truncated copy in the audit finding. A miss means the text is delivered.
- `--no-audit` turns off the log. It does not turn off sanitizing. When a home directory or `--audit-dir` is set and that directory cannot be opened, warden exits. With no home directory and no `--audit-dir`, it warns and continues without a log.
- The audit directory (`~/.mcp-warden/audit`, or `$MCP_WARDEN_HOME/audit`, or `--audit-dir`) stores decoded hidden payloads and hashes of full message bodies. Treat it as secret. It is per user, and files older than 30 days are removed at the next startup.
- Give the wrapped server the least privilege it needs. Warden does not shrink that server's token. `--enforce` gates later MCP calls only when all participating servers share the same state file; built-in tools bypass this boundary.
- Keep the state, pin files and `approve`/`untaint` CLI under human control. Direct write access to those files or unrestricted terminal execution can bypass the policy. Approval is exact-call, single-use, and expires after ten minutes; taint expires after two hours of inactivity.
- Pair this proxy with an OS or container sandbox. Warden only sees stdio MCP traffic.

## Hardening already in the proxy

These are properties to test against, not a promise that every future change keeps them:

- Unchanged messages are forwarded as the original bytes.
- Server stderr is passed through, and the server's exit code is propagated.
- On Windows the server joins a kill-on-close job before it is spawned.
- At most 4096 client requests are remembered. When the map is full, the oldest entry is dropped. A response for that dropped id is still sanitized and recorded as `unmatched_response`.
- Listing and `initialize` text is treated as server-authored by default. `--detect` also scans tool descriptions, and `--pin-tools` alerts on changed definitions.
- Binary `data` and `blob` fields are not rewritten.
