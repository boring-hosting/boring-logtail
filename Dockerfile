# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.97.1
ARG DEBIAN_VERSION=bookworm
ARG NIGHTLY_VERSION=nightly-2026-07-29

FROM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder

ARG BPF_LINKER_VERSION=0.10.4
ARG NIGHTLY_VERSION

RUN apt-get update \
    && apt-get install --yes --no-install-recommends clang llvm lld \
    && rm -rf /var/lib/apt/lists/* \
    && cargo install bpf-linker --version "${BPF_LINKER_VERSION}" --locked \
    && rustup toolchain install "${NIGHTLY_VERSION}" --component rust-src --profile minimal \
    && ln --symbolic "$(rustc +${NIGHTLY_VERSION} --print sysroot)" \
        "${RUSTUP_HOME}/toolchains/nightly-$(rustc --version --verbose | sed -n 's/^host: //p')"

WORKDIR /workspace

COPY Cargo.toml Cargo.lock ./
COPY boring-logtail/Cargo.toml boring-logtail/build.rs ./boring-logtail/
COPY blt-abi/Cargo.toml ./blt-abi/
COPY blt-ebpf/Cargo.toml blt-ebpf/build.rs ./blt-ebpf/
COPY blt-emitter/Cargo.toml ./blt-emitter/
COPY blt-model/Cargo.toml ./blt-model/
COPY blt-otel/Cargo.toml ./blt-otel/
COPY blt-store/Cargo.toml ./blt-store/
COPY boring-collector/Cargo.toml ./boring-collector/
COPY boring-logtail/src ./boring-logtail/src
COPY blt-abi/src ./blt-abi/src
COPY blt-ebpf/src ./blt-ebpf/src
COPY blt-emitter/src ./blt-emitter/src
COPY blt-model/src ./blt-model/src
COPY blt-otel/src ./blt-otel/src
COPY blt-store/src ./blt-store/src
COPY boring-collector/src ./boring-collector/src

RUN cargo build --locked --package boring-logtail --package boring-collector --release

FROM debian:${DEBIAN_VERSION}-slim AS runtime-base

LABEL org.opencontainers.image.source="https://github.com/alfredosa/boring-logtail" \
      org.opencontainers.image.description="very fast and furious eBPF log scraper, with kubernetes aware enrichment" \
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
ENTRYPOINT ["/usr/local/bin/boring-logtail"]
