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
COPY boring-logtail-common/Cargo.toml ./boring-logtail-common/
COPY boring-logtail-ebpf/Cargo.toml boring-logtail-ebpf/build.rs ./boring-logtail-ebpf/
COPY boring-logtail/src ./boring-logtail/src
COPY boring-logtail-common/src ./boring-logtail-common/src
COPY boring-logtail-ebpf/src ./boring-logtail-ebpf/src

RUN cargo build --locked --package boring-logtail --release

FROM debian:${DEBIAN_VERSION}-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/boring-logtail /usr/local/bin/boring-logtail

USER 0:0
ENTRYPOINT ["/usr/local/bin/boring-logtail"]
