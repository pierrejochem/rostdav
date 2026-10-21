# ADR 0001: Technologie-Stack

- Status: **Akzeptiert** am 2026-10-21
- Datum: 2026-10-21

## Kontext

Rostdav ist ein schlanker Dateiserver, der die unveränderten Nextcloud-Apps unterstützt. Anforderungen mit Einfluss auf den Stack:

- Streaming großer Dateien in beide Richtungen ohne Pufferung im Speicher
- Volle Kontrolle über WebDAV-Antworten (Nextcloud-Properties `oc:`/`nc:`, Header wie `OC-FileId`, Chunked Upload v2)
- Sicherheit als Pflichtkriterium (Speichersicherheit, sichere Defaults, kleine Angriffsfläche)
- Einfacher Betrieb: ein Binary, ein Datenverzeichnis, SQLite als Standard
- Wartbarkeit durch einen Entwickler, wenige Abhängigkeiten

## Betrachtete Optionen

| Kriterium | Rust (axum/tokio) | Kotlin (Spring Boot) | Go (net/http) |
|---|---|---|---|
| Streaming | Sehr gut (tokio, `Body`-Streams, Backpressure) | Gut mit WebFlux, mit MVC umständlicher | Sehr gut (`io.Reader`) |
| Reife WebDAV-Bausteine | `dav-server` vorhanden, für Nextcloud-Erweiterungen aber zu starr; XML mit `quick-xml` gut machbar | Kaum gepflegte Bibliotheken (Milton u. ä.) | `x/net/webdav` vorhanden, ebenfalls schwer erweiterbar |
| Sicherheit | Speichersicher, keine Laufzeit-Reflection, kleines Binary | Gute Frameworks, große Abhängigkeitsfläche, Reflection | Speichersicher, kleine Abhängigkeitsfläche |
| Wartbarkeit | Hohe Typsicherheit, längere Compile-Zeiten | Sehr vertraut für Spring-Entwickler, viel „Magie“ | Einfach, aber weniger Ausdrucksstärke im Typsystem |
| Deployment-Größe | Ein statisches Binary, ~10–20 MB, geringer RAM-Bedarf | JVM, 200+ MB RAM im Leerlauf | Ein statisches Binary, geringer RAM-Bedarf |
| Läuft auf Raspberry Pi / NAS | Sehr gut | Möglich, aber schwer | Sehr gut |

Zusätzlich betrachtet: **auf ein bestehendes Projekt aufsetzen** (z. B. OxiCloud, Rust, MIT-Lizenz, WebDAV vorhanden). Ob es die Nextcloud-Apps unterstützt und wie es Metadaten, Datei-IDs und Chunked Upload umsetzt, ist nicht geprüft.

## Entscheidung (Vorschlag)

**Rust** mit folgenden Bausteinen (jeweils aktuelle stabile Version bei Projektstart, fixiert über `Cargo.lock`):

| Zweck | Crate | Begründung |
|---|---|---|
| Async-Laufzeit | `tokio` | De-facto-Standard, Dateisystem- und Netzwerk-Streaming |
| HTTP | `axum` + `tower` / `tower-http` | Eigene Methoden (PROPFIND, MKCOL, MOVE …) über `MethodFilter`/Fallback, Middleware als Tower-Layer |
| XML | `quick-xml` | Streaming-Parser und -Writer; DTD/Entitäten werden nicht aufgelöst (XXE-sicher) |
| Datenbank | `sqlx` (SQLite, optional PostgreSQL) | Compile-Zeit-geprüfte Queries, Migrationen |
| Passwörter | `argon2` | Argon2id gemäß Anforderung |
| TOTP | `totp-rs` | RFC 6238 |
| Verschlüsselung von Secrets | `chacha20poly1305` | AEAD für TOTP-Secrets |
| Zufall | `rand` / `getrandom` | Tokens, App-Passwörter |
| Unicode | `unicode-normalization` | NFC-Normalisierung von Dateinamen |
| Templates | `askama` | Compile-Zeit-Templates, automatisches HTML-Escaping |
| Interaktivität UI | `htmx` (eine statische JS-Datei, CSP-kompatibel) | Wenig eigenes JavaScript |
| Konfiguration | `figment` oder `config` | Datei + Umgebungsvariablen mit Vorrang |
| CLI | `clap` | `rostdav serve`, `rostdav admin …` |
| Logging | `tracing` + `tracing-subscriber` (JSON) | Strukturierte Logs, zentrale Schwärzung |
| Rate Limiting | `governor` | Brute-Force-Schutz pro IP und Benutzer |
| Prüfsummen | `blake3` | Schnelle Inhalts-Prüfsummen |

**WebDAV wird selbst implementiert** (auf `axum` + `quick-xml`), nicht über `dav-server`. Grund: Die Nextcloud-Kompatibilität verlangt stabile Datei-IDs aus der Datenbank, eigene Properties, eigene Header und den Chunked-Upload-Ablauf. Das passt schlecht auf ein Dateisystem-Trait. Der Methodenumfang (OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, DELETE, MOVE, COPY, später SEARCH) ist überschaubar. Zur Absicherung wird die WebDAV-Konformitätssuite **litmus** im CI ausgeführt.

## Konsequenzen

- Positiv: ein Binary, geringer Ressourcenbedarf, volle Kontrolle über das Protokoll, starke Typsicherheit an Sicherheitsgrenzen.
- Negativ: WebDAV-Protokollarbeit liegt bei uns; längere Compile-Zeiten.
- Risiko: Abweichungen von den Erwartungen der Apps. Gegenmaßnahme: Vertragstests gegen Mitschnitte einer echten Nextcloud (siehe Plan, Meilenstein M5).

## Freigabe (2026-10-21)

1. Rust bestätigt.
2. Kein Spike zu OxiCloud; Rostdav wird eigenständig entwickelt.
3. Lizenz: MIT OR Apache-2.0 (Dual-Lizenz, Rust-üblich).
4. Referenz-App: aktuelle stabile Nextcloud-Android-App zum Start von M3; die genaue Version wird dann in `docs/compatibility.md` eingetragen.
