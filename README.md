# Rostdav

Schlanker, selbst gehosteter Dateiserver in Rust mit WebDAV, der mit den offiziellen Nextcloud-Apps genutzt werden kann.

> Rostdav ist kein Nextcloud-Produkt und nicht mit der Nextcloud GmbH verbunden. Es implementiert nur die Schnittstellen, die für die unterstützten Funktionen nötig sind.

## Status

Phase 2, Meilenstein M0: lauffähiges Gerüst ohne Dateifunktionen.

- Architektur: [docs/architecture.md](docs/architecture.md)
- Entscheidungen: [docs/adr/](docs/adr/)
- Umsetzungsplan: [docs/plan.md](docs/plan.md)

## Geplante Funktionen

- Mehrere Benutzer mit getrennten Dateibereichen
- WebDAV für Dateien und Ordner, Streaming großer Dateien
- Anmeldung aus der Nextcloud-App über Login Flow v2 mit eigenem App-Passwort pro Gerät
- Versionen, Freigaben, Papierkorb
- Web-Oberfläche mit Hell- und Dunkelmodus, Administration, optionale Zwei-Faktor-Anmeldung

Was tatsächlich mit welcher App-Version getestet ist, steht künftig in `docs/compatibility.md`.

## Voraussetzungen (geplant)

- Rust (stable) zum Bauen, sonst ein einzelnes Binary oder Container-Image
- Reverse Proxy mit TLS für den Produktivbetrieb

## Lizenz

Lizenziert unter einer der folgenden Lizenzen, nach Wahl:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

Beiträge werden, sofern nicht ausdrücklich anders angegeben, unter denselben beiden Lizenzen eingebracht.
