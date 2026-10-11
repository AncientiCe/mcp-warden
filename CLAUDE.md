# Claude Notes

See `AGENTS.md` for the full rules governing this project (TDD behavior tests, quality gates, proxy discipline, no mocks/placeholders/unwrap, changelog and commit discipline). Those rules are binding, so read them before making changes. The plan lives in Palace memory, wing `mcp_warden` (start with the room `start_here`).

Development commands:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --workspace -- -D warnings
cargo test --workspace
cargo audit
cargo build --workspace --locked
```

Or run all five at once: `make check` (Linux/macOS) or `pwsh scripts/check.ps1` (Windows).
