# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.97.1
ARG DEBIAN_VERSION=bookworm
FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder

WORKDIR /workspace

COPY Cargo.toml Cargo.lock ./
COPY boring-logtail/Cargo.toml ./boring-logtail/
COPY blt-model/Cargo.toml ./blt-model/
COPY blt-otel/Cargo.toml ./blt-otel/
COPY blt-store/Cargo.toml ./blt-store/
COPY boring-collector/Cargo.toml boring-collector/build.rs ./boring-collector/
COPY boring-logtail/src ./boring-logtail/src
COPY blt-model/src ./blt-model/src
COPY blt-otel/src ./blt-otel/src
COPY blt-store/src ./blt-store/src
COPY boring-collector/proto ./boring-collector/proto
COPY boring-collector/src ./boring-collector/src

RUN cargo build --locked --package boring-logtail --package boring-collector --release

FROM debian:${DEBIAN_VERSION}-slim AS runtime-base

LABEL org.opencontainers.image.source="https://github.com/boring-hosting/boring-logtail" \
      org.opencontainers.image.description="tiny CRI log tailer with kubernetes-aware enrichment" \
      org.opencontainers.image.licenses="GPL-3.0-or-later"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

USER 0:0

FROM runtime-base AS collector
COPY --from=builder /workspace/target/release/boring-collector /usr/local/bin/boring-collector
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/boring-collector"]

FROM runtime-base AS logtail
COPY --from=builder /workspace/target/release/boring-logtail /usr/local/bin/boring-logtail
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/boring-logtail"]
