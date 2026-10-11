# Agent Rules

When working on this codebase, follow these rules on every task. They bind every agent (Claude Code, Cursor, Codex or any other) and every human. The plan this project follows lives outside the repo (rule 3), in Palace memory, wing `mcp_warden`: start with the room `start_here`, then the rooms vision, architecture, layers, policy, config, roadmap, testing, decisions and open_questions. These rules govern *how* that plan gets built.

---

## 1. Test-Driven Development (TDD) — Behavior Tests Only

- **Write behavioral tests first.** Define the expected behavior in tests before implementing.
- **See them fail.** Run the test suite and confirm the new tests fail (red). A test that already passes before the implementation exists is not a valid starting point.
- **Implement.** Write the minimum code to make the tests pass.
- **See them pass.** Run the test suite and confirm all tests pass (green).

Do not implement behavior without a failing test that defines it.

**"Behavioral" means exercising `mcp-warden` from the outside:**
- **the proxy:** run the `mcp-warden` binary in front of the test-double server `examples/fake_server.rs`, speak MCP JSON-RPC to it over stdio, and assert on the bytes the client actually receives, the exit code, and the audit log written to disk;
- **the CLI:** run `mcp-warden scan`, for example with `assert_cmd`, and assert on its stdout, stderr and exit code;
- **the corpora:** checked-in attack and benign fixtures under `tests/corpus/`, each with hand-verified expected findings, run through the binary.

It does **not** mean unit-testing internal functions.

Forbidden: these are not what this project means by "test":
- Unit tests that call private functions or internal modules directly (for example the sanitizer's regex passes, or the id-correlation map).
- Snapshot tests of internal data structures.
- Tests that assert on intermediate state instead of what a client or user would see.
- `#[cfg(test)] pub` exposure hacks added only so a test can reach something.

Exception: pure, stateless helpers that carry no domain behavior of their own (for example URL host parsing) may get direct unit tests. This is the exception, not the default. When in doubt, write the behavior test.

**Transparency is behavior.** Every slice that rewrites output needs a matching test that benign traffic passes through **byte for byte**. A guard that mangles normal work gets disabled, and then it protects nothing.

---

## 2. Quality Gates on Every Task

Before considering a task done, ensure all of the following pass:

- **`cargo fmt --all -- --check`**: code is formatted.
- **`cargo clippy --all-targets --all-features --workspace -- -D warnings`**: no clippy warnings or errors.
- **`cargo audit`**: no known security advisories in dependencies.
- **`cargo test --workspace`**: the full behavior-test suite passes.
- **`cargo build --workspace --locked`**: builds reproducibly from the committed `Cargo.lock`, with no silent lockfile drift.

Run all five with `make check` (Linux/macOS) or `pwsh scripts/check.ps1` (Windows). That target is the actual definition of "green", not a subset picked by judgment in the moment. Match CI locally with the exact commands above (see `.github/workflows/ci.yml`). Windows is a first-class platform, since the primary user works there, and CI runs the tests on Linux, macOS and Windows.

No `--no-verify`, no skipping a gate, no `#[allow(clippy::...)]` without a comment explaining why the lint doesn't apply, and no narrowing a test's assertions or deleting a fixture just to turn a red gate green. If a gate is red, the code is wrong, not the test. The exception is when investigation shows the test encoded the wrong expected behavior: then fix it deliberately and say so. `cargo audit` findings get triaged (upgrade, or document an accepted risk), never ignored.

Fix any failure before marking the task complete.

---

## 3. No Plan Markdown Files

- **Do not create `.md` files for plans** (for example `PLAN.md`, `TODO.md` or task plans) inside this repo.
- Create markdown only for **documentation** (README, configuration reference, runbooks and similar) when necessary.
- Plans, roadmaps, decisions and progress live in Palace memory (wing `mcp_warden`; record progress in the room `progress`), not as plan documents committed here.

---

## 4. Proxy Discipline

`mcp-warden` sits between an MCP client and a real server. The client sees only what warden lets through, so a bug here breaks every tool behind it.

- **Stdout is the protocol channel.** Never write anything to stdout except relayed JSON-RPC messages. Diagnostics go to stderr; findings go to stderr and the audit log.
- **Unchanged means byte-identical.** When nothing in a message is rewritten, forward the original bytes. Never re-serialize a message that didn't change.
- **Never drop or reorder messages.** Lines that aren't JSON, unknown methods, notifications and server-to-client requests all pass through.
- **Mirror the child.** Propagate its exit code, pass its stderr through, and never leave it orphaned.
- **Security is defense in depth, not detection.** The layered model (sanitize → label → detect → taint-based action policy) and the decision log are in Palace. Don't weaken a layer because another layer exists.

---

## 5. No Unused Variables or Dead Code

- **No unused variables.** Every declared variable must be used; remove it, or name it `_` if it is intentionally unused.
- **No dead code.** Remove unreachable functions, branches, types and imports. Do not leave them commented out or hidden behind `#[allow(dead_code)]`.
- Treat compiler warnings for unused items as errors: they must be resolved before a task is complete.

---

## 6. No Mocks

- **Do not use mocks** in tests (mock objects, mock servers, mock crates).
- Prefer **real implementations** and real fixtures. Where a real dependency genuinely can't be used, use an explicit, minimal test double. `examples/fake_server.rs` is the one double for MCP servers: it speaks real JSON-RPC over real stdio and returns scripted payloads.
- Before a phase's exit criteria count as met, also verify against real servers (for example GitHub MCP) as the roadmap says.

---

## 7. No Placeholders

- **No placeholders. Ever.** Do not leave `todo!()`, `unimplemented!()`, stub returns, or "coming soon" code in the codebase.
- Deliver **only real implementations**. Every committed code path must do the real work or fail in a defined way (for example return `Err`, not panic with "unimplemented").
- If a feature is not ready, do not merge it. Ship a phase only when its exit criteria are actually met.

---

## 8. No Unsafe `unwrap`/`expect`

- **Do not use `unwrap()` or `expect()` in production code.** A panic in warden kills the connection to the wrapped server in the middle of the user's session.
- Handle failures with explicit error propagation (`Result`/`?`), recoverable branches, or well-defined fallbacks (for example, a line that fails to parse is forwarded unchanged).
- Compile fixed regexes and similar fallible setup once at startup, returning `Result`, rather than `unwrap`ping inside `LazyLock`.
- `unwrap()` and `expect()` are acceptable **only** in test code and examples.

---

## 9. Close Running Instances When Done

- If you start a long-running process for verification (warden wrapping a real server, a `cargo watch`, a test client), make sure it is stopped before marking the task complete.
- Don't leave stuck processes behind; resolve or terminate them so they don't interfere with future tasks.

---

## 10. Keep the Changelog Current

- **Update `CHANGELOG.md` as part of every feature, fix or behavior change**, not as an afterthought before release.
- Add entries under a top **`## [Unreleased]`** section while work is in progress. Do not invent a version number or date for in-progress work.
- Use the Keep a Changelog headings (`### Added`, `### Changed`, `### Fixed`, `### Removed`, `### Deprecated`, `### Security`).
- When a release is tagged, the `## [Unreleased]` entries are renamed to `## [x.y.z] - YYYY-MM-DD`.

---

## 11. Commits

- Commit as soon as a slice is green, since small commits are easy to review and to revert.
- Plain commit messages: no `Co-Authored-By` or other attribution trailers.

---

## Definition of Done

A change (a phase increment, a bug fix, anything) is done only when **all** of:
1. It corresponds to a specific exit criterion in the plan (or an explicitly agreed deviation).
2. A behavior test exists per rule 1, was seen failing before the implementation, and passes now.
3. All five gates in rule 2 are green.
4. Nothing was skipped, allowed or narrowed to get there.
5. `CHANGELOG.md` reflects the change under `## [Unreleased]`.

"I implemented it" is not done. "The gates are green" is not done on its own either: a green gate suite with no new behavior test just means nothing new was verified. Done means all of the above together.

---

## Quick Reference

| Rule | Action |
|------|--------|
| TDD (behavior tests) | Failing test against the binary (proxy + fake server, `scan`, corpora) first → see it fail → implement → see it pass. Benign passthrough stays byte-identical. |
| Quality gates | `cargo fmt --all -- --check` \| `cargo clippy --all-targets --all-features --workspace -- -D warnings` \| `cargo audit` \| `cargo test --workspace` \| `cargo build --workspace --locked`, via `make check` / `scripts/check.ps1` |
| No plan files | Plans live in Palace (wing `mcp_warden`); only real documentation in the repo |
| Proxy discipline | Stdout = protocol only; unchanged = byte-identical; never drop messages; mirror the child |
| No dead code | No unused variables, dead code, or `#[allow(dead_code)]` |
| No mocks | Real implementations, fixtures, or the explicit `examples/fake_server.rs` double |
| No placeholders | No `todo!()`/`unimplemented!()`/stubs |
| No unsafe unwrap/expect | Never in production code |
| Close running instances | Stop any verification processes when done |
| Keep changelog current | Entries under `## [Unreleased]` as you build |
| Commits | Commit each green slice; no co-author trailers |
