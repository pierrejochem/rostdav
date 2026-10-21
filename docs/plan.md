# Umsetzungsplan

Priorisiert nach dem kleinsten testbaren Nutzen. Jeder Meilenstein endet mit grünen Tests und einem Abschlussbericht.

## Freigabepunkt 1 – erledigt (2026-10-21)

- [x] Stack: Rust ([ADR 0001](adr/0001-technologie-stack.md))
- [x] Kein OxiCloud-Spike
- [x] Lizenz: MIT OR Apache-2.0
- [x] Referenz-App: aktuelle stabile Android-Version zum Start von M3

## Phase 2: Minimaler Prototyp (P0)

### M0 – Gerüst ✅ (2026-10-21)
- Cargo-Workspace mit den Crates aus `docs/architecture.md`
- `rostdav serve`, Konfiguration, strukturierte Logs, `/healthz`, `/readyz`
- CI: `cargo fmt --check`, `clippy -D warnings`, Tests, `cargo deny` / `cargo audit`
- **Abnahme:** Server startet, Health-Endpunkte antworten, CI grün

### M1 – Metadaten und Speicher ✅ (2026-10-21)
- Freigabepunkt 2: Schema nach [ADR 0002](adr/0002-speichermodell.md)
- Migrationen, `BlobStore` mit atomarem Ablegen, Pfadvalidierung und -auflösung
- `rostdav admin user add` (CLI), Argon2id
- **Abnahme:** Unit-Tests für Namensregeln (inkl. Unicode, `..`, Prozentkodierung), Absturzsimulation zwischen Blob und Commit hinterlässt keinen inkonsistenten Zustand

### M2 – WebDAV-Kern
- Basic Auth mit Kontopasswort (App-Passwörter folgen in M4)
- OPTIONS, PROPFIND (Depth 0/1), GET/HEAD mit Range, PUT (Streaming), MKCOL, DELETE, MOVE, COPY
- ETag, Last-Modified, `If-Match`/`If-None-Match`, `Overwrite`, rekursive Ordner-ETags
- **Abnahme:** Integrationstests aller Methoden inkl. Fehlerfälle; zweiter Benutzer kann nachweislich nicht auf Dateien des ersten zugreifen; `rclone` und `cadaver` funktionieren; litmus-Basistests laufen im CI

## Phase 3: App-Kompatibilität (P1)

### M3 – Referenz-Mitschnitte
- Nextcloud (gleiche Major-Version wie emuliert) in Docker, Referenz-App im Android-Emulator, Verkehr per mitmproxy aufzeichnen
- Abläufe: Server hinzufügen, Login Flow v2, Ordner öffnen, Upload klein/groß, Download, Umbenennen, Verschieben, Löschen, Abmelden
- Bereinigte Fixtures nach `tests/fixtures/nextcloud/`, Erkenntnisse mit Quellen in `docs/compatibility.md`
- **Abnahme:** Jeder Ablauf als Fixture vorhanden, offene Fragen dokumentiert

### M4 – Anmeldung wie Nextcloud
- `status.php`, Capabilities (nur Implementiertes), OCS-Benutzerendpunkte
- Login Flow v2 inkl. HTML-Anmeldeseite, App-Passwörter (Erzeugen, Hashen, Widerrufen, letzte Nutzung)
- Rate Limiting für alle Anmeldewege
- **Abnahme:** Vertragstests gegen Fixtures grün; App-Passwort widerrufen führt zu 401

### M5 – Nextcloud-WebDAV-Erweiterungen
- `oc:`/`nc:`-Properties, Upload-Header (`X-OC-MTime`, `OC-Checksum`, `OC-FileId`, `OC-ETag`)
- Chunked Upload v2, Quota-Properties und HTTP 507
- Vorschau- und Avatar-Endpunkte sauber mit 404
- **Abnahme:** Vertragstests grün; Upload > 100 MB über Chunks

### M6 – Ende-zu-Ende mit der App
- Manueller bzw. automatisierter Test mit der unveränderten App (Emulator)
- Abweichungen als reproduzierbare Tests erfassen und beheben
- **Abnahme:** Abnahmeliste aus Abschnitt 6 der Anweisung vollständig, Teststatus in `docs/compatibility.md`

## Phase 4: Erweiterungen (P2)

| # | Inhalt | Abhängig von |
|---|---|---|
| M7 | Admin-CLI vollständig, Ereignisprotokoll | M4 |
| M8 | Versionierung inkl. Versions-DAV-Endpunkt und Wiederherstellen | M5 |
| M9 | Freigaben: Benutzer, dann öffentliche Links (OCS Sharing API, Mountpunkte) | M5 |
| M10 | Papierkorb (Trashbin-DAV-Endpunkt) | M5 |
| M11 | Web-Oberfläche: Dateien, Geräte, Einstellungen, Administration, Hell/Dunkel | M7–M10 |
| M12 | Optionale Zwei-Faktor-Anmeldung | M11 |
| M13 | Aufbewahrungsregeln, Datenexport | M8, M10 |

## Phase 5: Härtung und Auslieferung

- Sicherheitstests (Autorisierungs-Matrix, Fuzzing von Pfaden und XML mit `cargo fuzz`), Lasttests (große Dateien, viele kleine Dateien, parallele Uploads)
- Container-Image, Compose-Beispiel mit Reverse Proxy, Backup/Restore-Test
- Betriebsdokumentation

## Größte Risiken

| Risiko | Auswirkung | Gegenmaßnahme |
|---|---|---|
| App erwartet undokumentiertes Verhalten | Login oder Upload scheitert | Früh Mitschnitte (M3) statt Annahmen |
| App lehnt gemeldete Version ab oder ändert Anforderungen in Updates | Kompatibilität bricht | Version konfigurierbar, App-Version festlegen, Vertragstests im CI |
| SQLite-Schreibsperre bei vielen parallelen Uploads | Wartezeiten | Transaktionen kurz halten (nur Schritt 3), PostgreSQL optional |
| Freigaben mit Mountpunkten sind komplex | Rechtefehler | Eigene Autorisierungs-Matrix-Tests, Freigaben erst nach stabiler Basis |
