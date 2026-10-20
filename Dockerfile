# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b

# Docker Hardened Images, pinned by multi-arch index digest (amd64 + arm64).
# Dependabot keeps the digests up to date.
FROM dhi.io/rust:1-alpine3.24-dev@sha256:6bbcb7ee79ca392423153a27f9d738ade51052b2282420dbae22babbd27774ab AS build

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
FROM dhi.io/alpine-base:3.24@sha256:a741d4f1ccaf31f9394a36477e50df4620a8030dbff3d9a2ea8e84672b683ada

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
