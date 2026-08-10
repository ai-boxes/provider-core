FROM rust:1.97.1-bookworm AS builder
ENV RUSTUP_TOOLCHAIN=1.97.1
WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml rustfmt.toml ./
COPY crates ./crates

RUN --mount=type=cache,id=provider-core-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=provider-core-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=provider-core-target,target=/src/target,sharing=locked \
    cargo build --release --locked -p provider-server \
    && cp /src/target/release/provider-core /tmp/provider-core

FROM debian:bookworm-slim AS runtime
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /app --shell /usr/sbin/nologin provider \
    && mkdir -p /app/data \
    && chown -R provider:provider /app

COPY --from=builder /tmp/provider-core /usr/local/bin/provider-core

USER provider
ENV PODE_LISTEN_ADDRESS=0.0.0.0:8317
EXPOSE 8317
VOLUME ["/app/data"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8317/livez >/dev/null

CMD ["provider-core"]
