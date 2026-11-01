# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b

# Docker Hardened Images, pinned by multi-arch index digest (amd64 + arm64).
# Renovate keeps the digests (and the syntax directive) up to date.
FROM dhi.io/rust:1-alpine3.24-dev@sha256:77de5f93fcfa37ede037c590c57f6460c976158aea65bc133dd1739d6235e3ed AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
# Fully static binary: the runtime image needs neither musl nor libgcc.
# An explicit --target keeps RUSTFLAGS away from proc-macros, which must
# stay dynamic.
ENV RUSTFLAGS="-C target-feature=+crt-static"
RUN --mount=type=cache,target=/root/.cargo/registry,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    target="$(rustc -vV | sed -n 's/^host: //p')" \
 && cargo build --release --locked --target "$target" \
 && cp "target/$target/release/pingwarden" /pingwarden

# Minimal hardened runtime: CA certificates and a non-root user, ~3 MB.
FROM dhi.io/alpine-base:3.24@sha256:7b06d747fcb428a0699679955e903b13322c92c79d94ce94c108634f13a714f1

LABEL org.opencontainers.image.title="Pingwarden" \
      org.opencontainers.image.description="Headless, configuration-as-code uptime monitor" \
      org.opencontainers.image.source="https://github.com/sebastka/pingwarden" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build --chmod=0755 /pingwarden /usr/local/bin/pingwarden

# Unprivileged. ICMP works through datagram sockets when the container's
# net.ipv4.ping_group_range covers its GID (Docker's default), or with
# CAP_NET_RAW. See docs/deployment.md.
USER 65532:65532
ENV PINGWARDEN_CONFIG=/etc/pingwarden
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
    CMD ["/usr/local/bin/pingwarden", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/pingwarden"]
CMD ["run"]
