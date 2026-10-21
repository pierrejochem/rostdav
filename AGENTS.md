# Arbeitsregeln für Coding-Agenten

Kurzfassung der Projektanweisung. Bei Widersprüchen gilt die vollständige Anweisung bzw. die ADRs.

## Ziel

Rostdav: schlanker Dateiserver, kompatibel mit den unveränderten Nextcloud-Apps. So wenig eigene Implementierung wie möglich, so viel echte Protokollkompatibilität wie nötig.

## Architekturregeln

- Modularer Monolith, Crates und Abhängigkeitsrichtung laut `docs/architecture.md`.
- Protokoll-Crates (`dav`, `compat`, `web`) greifen nie direkt auf Datenbank oder Dateisystem zu.
- Autorisierung nur über `authorize()` in `rostdav-app`, auf dem aufgelösten Knoten.
- Physische Pfade nie aus Benutzereingaben ableiten.
- Datenbank referenziert nie einen unvollständigen Blob.

## Kompatibilität

- Kein Antwortfeld erfinden. Jede Kompatibilitätsaussage nennt ihre Quelle (Client-Code, Doku oder Fixture).
- Capabilities kündigen nur Getestetes an.

## Sicherheit

- Keine Passwörter, Tokens, `Authorization`-Header oder Dateiinhalte in Logs.
- Tokens nur gehasht speichern, zeitkonstant vergleichen.
- XML ohne DTD/Entitäten parsen, Größen- und Tiefenlimits.
- Negativtests für Autorisierung, Pfade und Freigaben sind Pflicht.

## Arbeitsweise

- Kleine Schritte, je Schritt ein Commit. Tests für jede Funktion und jeden behobenen Fehler.
- Vor jedem Commit: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`.
- Neue Abhängigkeiten nur mit Begründung im Commit oder ADR.
- Testergebnisse nie erfinden; nicht ausgeführte Tests als solche kennzeichnen.

## Freigabepunkte (anhalten und fragen)

1. Stack und Architektur
2. Datenbankschema vor der ersten Persistierung
3. Änderungen an Authentifizierung, Token-Format oder Berechtigungsmodell nach Phase 2
4. Irreversible Operationen auf Daten oder Repositories

## Abschlussbericht nach jeder Arbeitseinheit

Implementiert · geänderte Dateien · ausgeführte und nicht ausgeführte Tests · tatsächliche Ergebnisse · Annahmen und Risiken · nächster Schritt.
