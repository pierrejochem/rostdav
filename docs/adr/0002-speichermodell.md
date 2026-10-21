# ADR 0002: Speichermodell für Dateien und Metadaten

- Status: **Vorgeschlagen** (Freigabepunkt 2)
- Datum: 2026-10-21

## Kontext

Anforderungen: stabile Datei-IDs über Umbenennen/Verschieben, Trennung logischer und physischer Pfade, Versionierung, atomare Schreibvorgänge, Schutz vor Path Traversal, rekursive Ordner-ETags, konsistentes Verhalten bei Abstürzen.

## Entscheidung (Vorschlag)

### Inhalte als unveränderliche Blobs

- Jeder Dateiinhalt ist ein **Blob** mit zufälliger ID (ULID). Physischer Pfad: `<data>/blobs/<id[0..2]>/<id[2..4]>/<id>`. Kein Teil des Pfads stammt aus Benutzereingaben.
- Blobs werden nie verändert. Eine geänderte Datei bekommt einen neuen Blob; der alte bleibt als Version oder wird von der Speicherbereinigung entfernt.
- Kopien und Versionen dürfen denselben Blob referenzieren. Ein Blob wird gelöscht, sobald ihn weder ein Knoten noch eine Version mehr referenziert (Mark-and-Sweep im Hintergrund, keine Referenzzähler im Request-Pfad).
- Keine Deduplizierung über Inhalts-Hashes (vermeidet Hash-Kollisionsfragen und Seitenkanäle zwischen Benutzern). BLAKE3-Prüfsumme wird gespeichert, für `OC-Checksum` und Integritätsprüfung.

### Metadaten in der Datenbank

- Tabelle `nodes` bildet den Baum: `id`, `owner_id`, `parent_id`, `name`, `name_key` (NFC, für Eindeutigkeit), `kind` (file/dir), `size`, `mtime`, `etag`, `blob_id`, `checksum`, `created_at`, `updated_at`.
- Eindeutigkeit: `UNIQUE(parent_id, name_key)`.
- Jeder Benutzer hat einen Wurzelknoten. Freigaben werden über Mountpunkte in der Sicht des Empfängers abgebildet, nicht durch Kopieren.
- Die öffentliche **Datei-ID** (`oc:fileid`) ist die numerische `nodes.id` (Nextcloud-Clients erwarten Zahlen); `oc:id` ist die mit einer Instanz-ID aufgefüllte Form, wie Nextcloud sie bildet (genaues Format in M5 verifizieren).
- ETag: zufälliger Wert pro Knoten, bei jeder Änderung neu. Bei Änderungen in einem Ordner werden die ETags aller Vorfahren in derselben Transaktion erneuert (Aufwand O(Tiefe)).

### Schreibablauf (PUT, Chunk-Zusammenführung)

1. Stream in eine temporäre Datei unter `<data>/tmp/` (gleiches Dateisystem), dabei Größe und BLAKE3 berechnen, Quota und Größenlimit laufend prüfen.
2. `fsync` der Datei, atomares `rename` nach `blobs/…`, `fsync` des Verzeichnisses.
3. Datenbank-Transaktion: `If-Match`/`If-None-Match` prüfen, Blob eintragen, alten Blob als Version ablegen (falls Versionierung aktiv), Knoten aktualisieren, ETags der Vorfahren erneuern, Quota-Zähler anpassen.
4. Commit. Schlägt Schritt 3 fehl, bleibt nur ein unreferenzierter Blob übrig, den die Bereinigung entfernt.

Invariante: **Die Datenbank referenziert nie einen Blob, der nicht vollständig auf der Platte liegt.**

### Löschen, Verschieben, Kopieren

- DELETE: Knoten (rekursiv) in einer Transaktion entfernen bzw. später in den Papierkorb verschieben; Blobs räumt die Bereinigung auf.
- MOVE: reine Metadatenoperation, Datei-ID bleibt erhalten.
- COPY: neue Knoten mit neuen IDs, die dieselben Blobs referenzieren.

### Datenbank

- Standard SQLite im WAL-Modus, `busy_timeout`, Fremdschlüssel aktiv. Schreibzugriffe werden serialisiert; Uploads blockieren die Datenbank nur in Schritt 3.
- PostgreSQL optional für größere Installationen, gleiches Schema über `sqlx`-Migrationen.

## Konsequenzen

- Physischer Speicher ist ohne Datenbank nicht lesbar. Backups müssen Datenbank und Blob-Verzeichnis gemeinsam sichern (Verfahren in `docs/deployment.md`).
- Direkter Zugriff auf Dateien über das Host-Dateisystem ist nicht vorgesehen; Import erfolgt über `rostdav admin import`.
- Konsistenzprüfung (`rostdav admin fsck`) vergleicht Datenbank und Blob-Verzeichnis.

## Alternativen

- **Spiegeln des logischen Baums im Dateisystem:** einfacher zu inspizieren, aber Pfade aus Benutzereingaben, Probleme mit Unicode und Groß-/Kleinschreibung je Dateisystem, nicht-atomares Umbenennen von Ordnern. Verworfen.
- **Objektspeicher (S3) als erster Speicher:** später über das Storage-Trait möglich, nicht im Prototyp.
