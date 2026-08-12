# syntax=docker/dockerfile:1.7

FROM rust:1.97.1-bookworm AS core-builder
ENV RUSTUP_TOOLCHAIN=1.97.1 \
    CARGO_PROFILE_RELEASE_STRIP=symbols
WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates

ARG TARGETARCH
RUN --mount=type=cache,id=provider-core-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=provider-core-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=provider-core-target-${TARGETARCH},target=/src/target,sharing=locked \
    cargo build --release --locked -p provider-server \
    && install -Dm755 /src/target/release/provider-core /tmp/provider-core

FROM debian:bookworm-slim AS core-runtime
WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --home /app --shell /usr/sbin/nologin provider \
    && mkdir -p /app/data \
    && chown -R provider:provider /app

COPY --from=core-builder /tmp/provider-core /usr/local/bin/provider-core

USER provider
ENV PODE_LISTEN_ADDRESS=0.0.0.0:8317
EXPOSE 8317
VOLUME ["/app/data"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD curl -fsS http://127.0.0.1:8317/livez >/dev/null

CMD ["provider-core"]

FROM scratch AS ui-source
ARG UI_REF=main
ADD https://github.com/ai-boxes/provider-ui.git#${UI_REF} /ui

FROM --platform=$BUILDPLATFORM node:24-bookworm-slim AS ui-builder
WORKDIR /ui

COPY --from=ui-source /ui/package.json /ui/package-lock.json ./
RUN --mount=type=cache,id=provider-ui-npm,target=/root/.npm,sharing=locked \
    npm ci --no-audit --no-fund

COPY --from=ui-source /ui/ ./
RUN npm run build

FROM core-runtime AS runtime
COPY --from=ui-builder --chown=provider:provider /ui/dist /app/public
