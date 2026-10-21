# Installation und Betrieb

> Stand M0: nur für die Entwicklung. Produktivbetrieb erst ab Phase 5.

## Bauen

```sh
cargo build --release
./target/release/rostdav --version
```

## Konfiguration

Vorlage: [`rostdav.example.toml`](../rostdav.example.toml). Vorrang: Umgebungsvariablen > Datei > Defaults.

| Schlüssel | Umgebungsvariable | Standard |
|---|---|---|
| `server.listen` | `ROSTDAV_SERVER__LISTEN` | `127.0.0.1:8080` |
| `storage.data_dir` | `ROSTDAV_STORAGE__DATA_DIR` | `./data` |
| `database.url` | `ROSTDAV_DATABASE__URL` | `sqlite://<data_dir>/db/rostdav.sqlite` |
| `log.format` | `ROSTDAV_LOG__FORMAT` | `json` |
| `log.level` | `ROSTDAV_LOG__LEVEL` | `info` (`RUST_LOG` hat Vorrang) |

Konfigurationsdatei: `--config <pfad>` oder `ROSTDAV_CONFIG`; ohne Angabe wird `./rostdav.toml` gelesen, falls vorhanden. Unbekannte Schlüssel sind ein Fehler. Wirksame Werte anzeigen:

```sh
rostdav check-config
```

## Datenverzeichnis

```text
data/
  blobs/    Dateiinhalte (unveränderlich)
  tmp/      laufende Schreibvorgänge
  uploads/  Chunks laufender Uploads
  db/       SQLite-Datenbank
```

Rechte 0700, Eigentümer ist der Dienstbenutzer. `tmp/` und `blobs/` müssen auf demselben Dateisystem liegen.

## Reverse Proxy (geplant)

Rostdav terminiert kein TLS. Beispielkonfigurationen für Caddy, nginx und Traefik folgen in Phase 5. Zu beachten:

- Große Uploads erlauben (Body-Limit und Timeouts des Proxys)
- `/.well-known/caldav` und `/.well-known/carddav` werden nicht benötigt
- Trusted-Proxy-Konfiguration in Rostdav auf den Proxy beschränken

## Health-Checks

- Liveness: `GET /healthz`
- Readiness: `GET /readyz`

## Backup und Wiederherstellung (geplant)

1. Datenbank sichern (SQLite-Online-Backup bzw. `pg_dump`).
2. Danach `blobs/` sichern. Da Blobs unveränderlich sind und die Datenbank nie auf unvollständige Blobs zeigt, ist diese Reihenfolge konsistent.
3. Wiederherstellung: beides zurückspielen, `rostdav admin fsck` ausführen (ab M1).

## Herunterfahren

`SIGTERM` oder `Ctrl-C`: laufende Anfragen werden beendet, dann schließt die Datenbank. Exit-Code 0.
