# provider-core

A local Rust service that exposes Codex- and Claude-compatible APIs for upstream AI providers.

## Workspace

- `crates/provider-core`: stable provider, account, and proxy contracts
- `crates/provider-protocol`: downstream wire protocol conversion
- `crates/provider-drivers`: built-in upstream provider drivers
- `crates/provider-runtime`: live accounts and credential refresh coordination
- `crates/provider-storage`: SQLx and SQLite persistence
- `crates/provider-server`: Axum HTTP server and process composition

## Containers

The default `Dockerfile` builds the all-in-one image: `provider-core` serves
both the API and the compiled `provider-ui` SPA on port `8317`.

~~~bash
docker buildx build --load -t provider-core .
docker buildx build --load --build-arg UI_REF=<branch-tag-or-commit> -t provider-core .
~~~

For a backend-only image, build the `core-runtime` target. It does not require
the UI checkout:

~~~bash
docker buildx build --load --target core-runtime -t provider-core:core .
~~~

~~~bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
~~~
