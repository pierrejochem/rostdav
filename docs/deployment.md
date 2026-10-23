# Installation and operation

Rostdav is one process with one data directory. It does not terminate TLS: run it behind a reverse proxy.

## Requirements

- Linux (the container image is `debian:bookworm-slim` based; the binary needs nothing but glibc).
- A data directory on a local file system with enough space for the files **and** their versions and trash (`rostdav admin user list` shows usage). `blobs/` and `tmp/` must be on the same file system (atomic rename).
- A reverse proxy with TLS in front, reachable at the address your users and apps use.

## Quick start with containers

```sh
export ROSTDAV_DOMAIN=files.example.org
docker compose -f deploy/compose.yaml up -d --build
docker compose -f deploy/compose.yaml exec rostdav rostdav admin user add alice --admin   # password on stdin
```

[`deploy/compose.yaml`](../deploy/compose.yaml) runs Rostdav and Caddy (automatic HTTPS). Rostdav publishes no port; only the proxy talks to it, from a fixed address that is configured as the trusted proxy. Without `ROSTDAV_DOMAIN` the site is `https://localhost` with Caddy's internal CA (for trying it out).

The stack was tried end to end on 2026-10-23 (Docker Desktop): health through the proxy, a 200 MB upload and an identical download over HTTPS (no proxy body limit), `Secure` session cookie, the event log shows the client address and not the proxy's.

Image only: `docker build -t rostdav .`, then `docker run -d -p 127.0.0.1:8080:8080 -v rostdav-data:/data rostdav`. The container runs as user 10001, data in the volume `/data` (mode 0700), health check `rostdav healthcheck`, logs as JSON on stdout.

## Released builds

Each version tag (`v0.1.0`, …) is built by the [Release workflow](../.github/workflows/release.yml) after the tests pass:

- **Linux binaries:** `rostdav-<version>-x86_64-unknown-linux-gnu.tar.gz` and `rostdav-<version>-aarch64-unknown-linux-gnu.tar.gz`, each with a `.sha256`, on the GitHub release page. Check one with `sha256sum -c <file>.sha256`. The archive holds the binary, both licences, the README, the changelog and `rostdav.example.toml`. The binary is built on Debian bookworm (glibc 2.36 or newer needed).
- **Container image:** `ghcr.io/pierrejochem/rostdav:<version>` (also `:<major>.<minor>`, `:<major>` and `:latest` for final releases). The workflow starts the image and checks health, user 10001 and the data directory mode before it pushes. A new ghcr.io package is private until its owner makes it public; a private one needs `docker login ghcr.io`.
- Version 0.1.0 has the x86_64 binary and image only. From 0.2.0 on there is an arm64 binary as well, and the image tag covers both architectures (`docker pull` picks the right one).

## Building from source

```sh
cargo build --release --locked -p rostdav
./target/release/rostdav --version
```

Run it as an unprivileged service user, for example with systemd:

```ini
[Unit]
Description=Rostdav
After=network.target

[Service]
User=rostdav
Group=rostdav
ExecStart=/usr/local/bin/rostdav serve
Environment=ROSTDAV_CONFIG=/etc/rostdav/rostdav.toml
Restart=on-failure
# an update installed from the web interface ends the process with status 75 so that this restarts it
# the data directory is the only place it writes to
ProtectSystem=strict
ReadWritePaths=/var/lib/rostdav
PrivateTmp=true
NoNewPrivileges=true
ProtectHome=true

[Install]
WantedBy=multi-user.target
```

## Configuration

Template: [`rostdav.example.toml`](../rostdav.example.toml). Precedence: environment variables (`ROSTDAV_<SECTION>__<KEY>`) > file > defaults. Unknown keys are an error. Show the effective values (secrets are hidden) with `rostdav check-config`. File: `--config <path>` or `ROSTDAV_CONFIG`, else `./rostdav.toml` if present.

| Setting | Meaning | Default |
|---|---|---|
| `server.listen` | Address and port | `127.0.0.1:8080` |
| `server.trusted_proxies` | Addresses of reverse proxies whose `X-Forwarded-For` is believed (exact addresses, no ranges) | none |
| `server.public_url` | Address users and apps use, e.g. `https://files.example.org` | from the request |
| `storage.data_dir` | Data directory | `./data` |
| `database.url` | Database file (`sqlite://<path>`; the file format is SQLite's) | `sqlite://<data_dir>/db/rostdav.sqlite` |
| `limits.*`, `versioning.*`, `trash.*`, `audit.*`, `web.*` | Limits and retention, see [admin.md](admin.md) | |
| `security.totp_key`, `security.totp_key_file` | Key for two-factor secrets, see [admin.md](admin.md) | `<data_dir>/totp.key` |
| `log.format`, `log.level` | `json` or `pretty`; `info` (`RUST_LOG` wins) | `json`, `info` |

## Data directory

```text
data/
  blobs/    file contents (immutable)
  tmp/      writes in progress (cleaned at start)
  uploads/  chunks of unfinished chunked uploads
  db/       metadata database (Turso Database, SQLite file format)
  totp.key  key for two-factor secrets (created at the first setup)
```

Mode 0700, owned by the service user.

## Reverse proxy

Requirements for any proxy:

- TLS; redirect HTTP to HTTPS. Send `X-Forwarded-For` and `X-Forwarded-Proto: https` (the session cookie gets `Secure` from the latter).
- **No request body limit and long timeouts** (or at least larger than your biggest file: plain `PUT` uploads are one request; the Nextcloud apps use chunks of up to 100 MiB). Do not buffer request bodies to disk or memory.
- Stream responses (no buffering of downloads).
- Tell Rostdav the proxy's address in `server.trusted_proxies`, and set `server.public_url`. If the proxy address is wrong, the event log and the lockout limits see the proxy instead of the client; if it is too broad, clients can fake their address.
- `/.well-known/caldav` and `/.well-known/carddav` are not needed.

### Caddy

See [`deploy/Caddyfile`](../deploy/Caddyfile): `request_body { max_size 0 }`, `reverse_proxy rostdav:8080`, no read/write timeouts.

### nginx

```nginx
server {
    listen 443 ssl http2;
    server_name files.example.org;
    # ssl_certificate ...; ssl_certificate_key ...;

    client_max_body_size 0;          # no limit; Rostdav enforces limits.max_upload_bytes
    proxy_request_buffering off;     # stream uploads
    proxy_buffering off;             # stream downloads
    proxy_read_timeout 1h;
    proxy_send_timeout 1h;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

`server.trusted_proxies = ["127.0.0.1"]`. A 413 for large uploads means `client_max_body_size` is still set somewhere.

### Traefik (labels)

```yaml
labels:
  - traefik.enable=true
  - traefik.http.routers.rostdav.rule=Host(`files.example.org`)
  - traefik.http.routers.rostdav.tls.certresolver=letsencrypt
  - traefik.http.services.rostdav.loadbalancer.server.port=8080
  # entrypoint timeouts must not cut long transfers:
  #   --entrypoints.websecure.transport.respondingtimeouts.readtimeout=0
  #   --entrypoints.websecure.transport.respondingtimeouts.writetimeout=0
```

Traefik has no body limit unless you add the `buffering` middleware: do not.

## First start and users

```sh
rostdav admin user add alice --admin     # password as one line on stdin
rostdav admin user list
```

Browser: `https://<domain>/`. Nextcloud app: enter the server address; the app opens the Login Flow page and receives its own app password. Details: [admin.md](admin.md).

## Health and monitoring

- `GET /healthz` (process alive), `GET /readyz` (database reachable), `rostdav healthcheck` (what the container health check runs).
- Logs: JSON lines on stdout; request lines carry method, path (tokens in paths are masked), status and latency; no secrets, no `Authorization` or cookies.
- Event log: Administration › Event log, `rostdav admin audit export`.
- Disk space of the data directory and the size of `db/rostdav.sqlite` are the things to watch. `rostdav admin fsck` compares database and files, runs the database's own integrity check and looks for rows whose parent row is gone. The database engine (Turso Database) is young: run `fsck` now and then, and keep backups.

## Backup and restore

Backup while the server runs:

```sh
rostdav admin backup /backups/rostdav-2026-10-23          # new directory
```

It writes a consistent snapshot of the database first (`VACUUM INTO`), then hard-links the blobs (no extra space on the same file system, a copy otherwise). Blobs are immutable and the database never points at an incomplete blob, so this order is consistent. The two-factor key file is **not** included unless you pass `--include-key`; back it up separately (a backup that holds database and key together lets whoever steals it read the secrets).

Hard links are not a safeguard against disk loss: copy the backup directory to another machine (`rsync -a`, `restic`, …).

Restore into an empty data directory with the service stopped:

```sh
cp -a /backups/rostdav-2026-10-23/db /backups/rostdav-2026-10-23/blobs /var/lib/rostdav/
cp /safe/place/totp.key /var/lib/rostdav/      # only if two-factor is in use
chown -R rostdav:rostdav /var/lib/rostdav && chmod 700 /var/lib/rostdav
rostdav admin fsck --verify                      # exit code 0 = consistent; re-reads every file
systemctl start rostdav
```

Files written after the snapshot were not part of it and are lost; blobs written between the snapshot and the end of the copy are left over and removed by `fsck --repair`. This procedure is covered by tests (`backup_taken_while_files_are_written_restores_cleanly`, `backup_and_restore_through_the_command_line`). Practice the restore once before you need it.

## Upgrade

1. `rostdav admin backup …` (migrations only go forward; there is no downgrade).
2. Stop, replace the binary or image, start. Migrations run at start and are logged (`migrations applied`).
3. Check `rostdav --version`, `/readyz` and the log.

Rollback means restoring the backup together with the old binary.

**From a SQLite-based version (0.2.x or older) to the Turso-based one:** take the backup first, then start the new version. On its first start it adopts the migration history of the old database, rebuilds the `favorites` table as an ordinary table (the new engine cannot write to a `WITHOUT ROWID` table) and adds some indexes; this is logged and takes moments. The file keeps its name and its SQLite format, but the old versions were not tested against a file that the new engine has written: the way back is the backup. See [ADR 0008](adr/0008-metadata-database-turso.md).

## Hardening checklist

- Rostdav listens on a private address only; the proxy is the only way in.
- `server.trusted_proxies` contains exactly the proxy addresses; `server.public_url` is the HTTPS address.
- The service user owns the data directory (0700) and nothing else; systemd/container sandboxing as above.
- Set `limits.default_quota` and `limits.max_upload_bytes` to values that fit the disk.
- Users with 2FA: back up `totp.key` separately; WebDAV clients use app passwords.
- Keep the event log retention at a value that fits your policy (`audit.retention_days`, `audit.anonymize_ip`).
- Update regularly; `cargo deny check` (CI) reports advisories for dependencies.

## Troubleshooting

| Symptom | Cause |
|---|---|
| 413 or an aborted large upload | The proxy limits the body size or buffers it |
| 429 / "too many attempts" | Ten wrong passwords per address or user in 15 minutes; wait, or check that `trusted_proxies` is right (all users share the proxy's address otherwise) |
| Login page works, apps cannot connect | `server.public_url` is wrong or the proxy does not pass `X-Forwarded-Proto` |
| Two-factor codes are always wrong | The server clock is off by more than 30 seconds (use NTP) |
| `could not open data directory` | Wrong owner or mode of the data directory |
| Everything answers 500 after many parallel requests | Fixed in the version that contains commit "fix a connection-pool deadlock"; update |

## Measured performance (load tests)

`cargo test --release -p rostdav --test load -- --ignored --nocapture --test-threads=1`, 2026-10-22 and 2026-10-23, one developer machine (Linux, release build, test data on a RAM-backed `/tmp`). The tests call the router in-process: no TCP, TLS or reverse proxy, so these numbers are what the application itself does, not what a client sees.

| Scenario | SQLite (0.2.0) | Turso Database |
|---|---|---|
| One 512 MiB file | upload 480 MiB/s, download 197 MiB/s | upload 799 MiB/s, download 202 MiB/s (the file is streamed in both: peak memory about 57 MiB) |
| 5000 small files (1 KiB, sequential) | PUT ≈ 420 files/s | PUT ≈ 245 files/s |
| the same files | PROPFIND depth 1 of all 5000: 146 ms | 163 ms |
| the same files | GET ≈ 1100 files/s | GET ≈ 660 files/s |
| 32 parallel uploads of 8 MiB | 256 MiB in 0.56 s | 256 MiB in 0.43 s, all complete and not mixed up, peak memory about 200 MiB |

Small files cost more with the new engine: a call to it takes about 70 µs where SQLite took a few, and a PUT makes 18 statements, a GET 9. Large files, listings and parallel uploads are not affected. Only sequential small files were measured, not many clients with many files. The release binary is 47 MB (it was about 20 MB), and a first build takes much longer, because the engine is compiled with it.
