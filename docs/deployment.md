# Installation and operation

> Status M0: for development only. Production use only from phase 5.

## Building

```sh
cargo build --release
./target/release/rostdav --version
```

## Configuration

Template: [`rostdav.example.toml`](../rostdav.example.toml). Precedence: environment variables > file > defaults.

| Key | Environment variable | Default |
|---|---|---|
| `server.listen` | `ROSTDAV_SERVER__LISTEN` | `127.0.0.1:8080` |
| `storage.data_dir` | `ROSTDAV_STORAGE__DATA_DIR` | `./data` |
| `database.url` | `ROSTDAV_DATABASE__URL` | `sqlite://<data_dir>/db/rostdav.sqlite` |
| `log.format` | `ROSTDAV_LOG__FORMAT` | `json` |
| `log.level` | `ROSTDAV_LOG__LEVEL` | `info` (`RUST_LOG` takes precedence) |

Configuration file: `--config <path>` or `ROSTDAV_CONFIG`; if neither is given, `./rostdav.toml` is read if present. Unknown keys are an error. Show effective values:

```sh
rostdav check-config
```

## Data directory

```text
data/
  blobs/    file contents (immutable)
  tmp/      in-progress writes
  uploads/  chunks of in-progress uploads
  db/       SQLite database
```

Mode 0700, owned by the service user. `tmp/` and `blobs/` must be on the same file system.

## Reverse proxy (planned)

Rostdav does not terminate TLS. Example configurations for Caddy, nginx and Traefik follow in phase 5. Things to note:

- Allow large uploads (body limit and timeouts of the proxy)
- `/.well-known/caldav` and `/.well-known/carddav` are not needed
- Restrict the trusted-proxy configuration in Rostdav to the proxy

## Health-Checks

- Liveness: `GET /healthz`
- Readiness: `GET /readyz`

## Backup and restore (planned)

1. Back up the database (SQLite online backup or `pg_dump`).
2. Then back up `blobs/`. Since blobs are immutable and the database never points to incomplete blobs, this order is consistent.
3. Restore: restore both, run `rostdav admin fsck` (from M1).

## Shutdown

`SIGTERM` or `Ctrl-C`: in-flight requests are completed, then the database is closed. Exit code 0.


## Measured performance (load tests)

`cargo test --release -p rostdav --test load -- --ignored --nocapture --test-threads=1`, 2026-10-22, one developer machine (Linux, local SSD, release build). The tests call the router in-process: no TCP, TLS or reverse proxy, so these numbers are what the application itself does, not what a client sees. SQLite runs with `synchronous = FULL` (every commit is fsynced).

| Scenario | Result |
|---|---|
| One 512 MiB file | upload 480 MiB/s, download 197 MiB/s, peak memory 29 → 33 MiB (the file is streamed) |
| 5000 small files (1 KiB, sequential) | PUT ≈ 420 files/s, PROPFIND depth 1 of all 5000 in 146 ms (1.9 MB of XML), GET ≈ 1100 files/s |
| 32 parallel uploads of 8 MiB (16 plain, 16 chunked) | 256 MiB in 0.56 s, all files complete and not mixed up, peak memory 157 MiB |

Small-file throughput is bound by the fsync of each commit, not by the CPU. Only sequential small files were measured, not many clients with many files.
