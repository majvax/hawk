# syntax=docker/dockerfile:1
# The relay and its dashboard in one small image. Built from the
# repository's root, which holds the Cargo workspace:
#
#   docker build -t hawk-relay .
#
# See compose.yaml for running it, and "Run it in a container" in
# src/server/frontend/docs/02-relay.md for the settings.

# ---- the dashboard -------------------------------------------------------
# The bun that wrote src/server/bun.lock, so --frozen-lockfile reads it.
FROM oven/bun:1.4.2 AS dashboard
WORKDIR /src/server
COPY src/server/package.json src/server/bun.lock ./
COPY src/server/frontend/package.json frontend/
RUN bun install --frozen-lockfile
COPY src/server/frontend frontend
RUN bun run --cwd frontend build

# ---- the relay -----------------------------------------------------------
FROM rust:1.89.0-slim-bookworm AS relay
WORKDIR /src
# Every workspace member's manifest has to be there for cargo to read the
# workspace; only the relay is built.
COPY Cargo.toml Cargo.lock ./
COPY src/update src/update
COPY src/installer src/installer
COPY src/app src/app
COPY src/server/relay src/server/relay
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -p hawk-relay \
    && cp target/release/hawk-relay /hawk-relay
# Where the database and backups go, made here: the final image has no shell.
RUN mkdir -p /state/hawk /state/hawk-backups

# ---- what runs -----------------------------------------------------------
# glibc and libgcc, no shell, no package manager; "nonroot" is uid 65532.
# A tag, so rebuilds pick up Debian's security fixes. To pin it instead:
# `docker buildx imagetools inspect gcr.io/distroless/cc-debian12:nonroot`
# gives the digest; write it as gcr.io/distroless/cc-debian12:nonroot@sha256:<digest>.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=relay /hawk-relay /usr/local/bin/hawk-relay
COPY --from=dashboard /src/server/frontend/dist /opt/hawk/dashboard
COPY --from=relay --chown=65532:65532 /state/hawk /var/lib/hawk
COPY --from=relay --chown=65532:65532 /state/hawk-backups /var/lib/hawk-backups

# The relay's own defaults point into a source checkout; these point into
# the image. TLS is used when both files are there (mount them read-only);
# without them the relay serves plain HTTP, for a proxy in front that
# terminates TLS. HAWK_BACKUP_DIR is left unset: backups are off until
# it's given, ideally on a volume of its own (compose.yaml does that).
ENV HOST=0.0.0.0 \
    PORT=8443 \
    HAWK_SERVER_ROOT=/opt/hawk \
    FRONTEND_DIST=/opt/hawk/dashboard \
    HAWK_DB_PATH=/var/lib/hawk/hawk.db \
    TLS_CERT_PATH=/etc/hawk/tls/cert.pem \
    TLS_KEY_PATH=/etc/hawk/tls/key.pem

VOLUME ["/var/lib/hawk"]
EXPOSE 8443
USER nonroot
# The relay drains requests, closes sockets and writes out its audit log
# within 10 seconds of SIGTERM, Docker's default before it kills.
STOPSIGNAL SIGTERM
# No curl here: the relay asks itself for /healthz, over TLS when it has a
# certificate, checking that it's the relay's own key.
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD ["/usr/local/bin/hawk-relay", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/hawk-relay"]
