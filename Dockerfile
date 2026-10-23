# Production image: static-ish release binary on a slim Debian, running as an unprivileged user.
#   docker build -t rostdav .
#   docker run -d --name rostdav -p 8080:8080 -v rostdav-data:/data rostdav
# Rostdav does not terminate TLS: put a reverse proxy in front (see deploy/compose.yaml).

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p rostdav \
    && install -D target/release/rostdav /out/rostdav

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin rostdav \
    && install -d -o rostdav -g rostdav -m 0700 /data
COPY --from=build /out/rostdav /usr/local/bin/rostdav
USER rostdav
# the program does not replace itself in a container: it tells the administrator to pull the new image
ENV RD_INSTALL=container \
    ROSTDAV_SERVER__LISTEN=0.0.0.0:8080 \
    ROSTDAV_STORAGE__DATA_DIR=/data \
    ROSTDAV_LOG__FORMAT=json
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["rostdav", "healthcheck"]
ENTRYPOINT ["rostdav"]
CMD ["serve"]
