# provider-core

A local Rust service that exposes Codex- and Claude-compatible APIs for upstream AI providers.

## Workspace

- `crates/provider-core`: stable provider, account, and proxy contracts
- `crates/provider-protocol`: downstream wire protocol conversion
- `crates/provider-drivers`: built-in upstream provider drivers
- `crates/provider-runtime`: live accounts and credential refresh coordination
- `crates/provider-storage`: SQLx and SQLite persistence
- `crates/provider-server`: Axum HTTP server and process composition

~~~bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
~~~
