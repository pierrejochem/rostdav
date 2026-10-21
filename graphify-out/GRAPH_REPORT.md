# Graph Report - rostdav  (2026-10-21)

## Corpus Check
- 49 files · ~26,737 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 10 file(s) not represented in the graph (top: (none) 6, .toml 4)

## Summary
- 417 nodes · 594 edges · 28 communities (24 shown, 4 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 7 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `fd0b806e`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- rostdav-storage/src/lib.rs
- config.rs
- rostdav-meta/src/lib.rs
- path.rs
- AppState
- KI-Agent-Anweisung: Rostdav – schlanker Nextcloud-kompatibler Dateiserver
- password.rs
- health.rs
- http.rs
- Error
- Arbeitsregeln für Coding-Agenten
- Umsetzungsplan
- Architektur
- Entscheidung (Vorschlag)
- Installation und Betrieb
- rostdav
- Endpunkte und Protokollverträge
- Weboberfläche
- Rostdav
- .poll_read
- ADR 0001: Technologie-Stack
- Nextcloud-Kompatibilität
- Sicherheitskonzept
- Hinweise für Claude Code
- anweisung.md
- Administration
- smoke.sh

## God Nodes (most connected - your core abstractions)
1. `AppState` - 18 edges
2. `LocalStore` - 16 edges
3. `test_db()` - 11 edges
4. `BlobId` - 11 edges
5. `store()` - 11 edges
6. `KI-Agent-Anweisung: Rostdav – schlanker Nextcloud-kompatibler Dateiserver` - 11 edges
7. `Architektur` - 11 edges
8. `Db` - 10 edges
9. `Config` - 10 edges
10. `2. Funktionale Anforderungen` - 9 edges

## Surprising Connections (you probably didn't know these)
- `invalid_names_rejected_and_unknown_is_none()` --calls--> `test_db()`  [INFERRED]
  rostdav/crates/rostdav-meta/src/users.rs → rostdav/crates/rostdav-meta/src/lib.rs
- `router()` --references--> `AppState`  [EXTRACTED]
  rostdav/crates/rostdav-compat/src/lib.rs → rostdav/crates/rostdav-app/src/lib.rs
- `router()` --references--> `AppState`  [EXTRACTED]
  rostdav/crates/rostdav-dav/src/lib.rs → rostdav/crates/rostdav-app/src/lib.rs
- `readyz()` --references--> `AppState`  [EXTRACTED]
  rostdav/crates/rostdav/src/http.rs → rostdav/crates/rostdav-app/src/lib.rs
- `router()` --references--> `AppState`  [EXTRACTED]
  rostdav/crates/rostdav/src/http.rs → rostdav/crates/rostdav-app/src/lib.rs

## Import Cycles
- None detected.

## Communities (28 total, 4 thin omitted)

### Community 0 - "rostdav-storage/src/lib.rs"
Cohesion: 0.11
Nodes (17): BlobId, StoredBlob, aborted_stream_leaves_no_blob(), blob_path_is_sharded_and_id_derived(), crash_before_rename_leaves_only_sweepable_tmp(), delete_is_idempotent_and_open_missing_is_not_found(), empty_blob_is_allowed(), exactly_max_size_is_allowed() (+9 more)

### Community 1 - "config.rs"
Cohesion: 0.08
Nodes (21): Config, Database, defaults_are_local_only(), file_and_env_precedence(), Log, Server, Storage, AdminCommand (+13 more)

### Community 2 - "rostdav-meta/src/lib.rs"
Cohesion: 0.11
Nodes (16): Db, file_node_requires_blob_and_dir_forbids_it(), migrate_is_idempotent(), open_creates_file_and_pings(), sibling_names_unique_by_nfc_key_only(), test_db(), create_and_find_with_root_node(), Db (+8 more)

### Community 3 - "path.rs"
Cohesion: 0.09
Nodes (17): backslash_rejected(), bad(), case_is_significant(), decoded_once_only(), depth_limit(), dot_segments_rejected(), encoded_separators_and_nul_rejected(), invalid_utf8_rejected() (+9 more)

### Community 4 - "AppState"
Cohesion: 0.09
Nodes (12): add_user_stores_verifiable_hash_not_password(), AppState, crash_between_blob_and_commit_leaves_only_orphan(), Inner, state(), router(), PRODUCT_NAME, VERSION (+4 more)

### Community 5 - "KI-Agent-Anweisung: Rostdav – schlanker Nextcloud-kompatibler Dateiserver"
Cohesion: 0.07
Nodes (28): 10. Abschlussbericht nach jeder Arbeitseinheit, 1. Rolle, Ziel und Abgrenzung, 2.1 Benutzer und Authentifizierung, 2.2 Dateiverwaltung, 2.3 Löschen und Papierkorb, 2.4 Dateiversionierung (P2), 2.5 Freigaben (P2), 2.6 Web-Oberfläche (+20 more)

### Community 6 - "password.rs"
Cohesion: 0.10
Nodes (6): hash_does_not_contain_password(), hash_password(), MIN_PASSWORD_CHARS, roundtrip_uses_argon2id_and_random_salt(), StringError, generated_ids_parse()

### Community 7 - "health.rs"
Cohesion: 0.15
Nodes (7): app_with_tempdir(), get(), healthz_ok(), readyz_ok_with_working_storage(), readyz_unavailable_when_tmp_missing(), responses_carry_request_id_and_security_headers(), unknown_route_is_404()

### Community 8 - "http.rs"
Cohesion: 0.14
Nodes (6): LogFormat, Json, Pretty, healthz(), readyz(), REQUEST_ID

### Community 9 - "Error"
Cohesion: 0.13
Nodes (13): Error, BadRequest, Conflict, Forbidden, Internal, Locked, NotFound, PreconditionFailed (+5 more)

### Community 10 - "Arbeitsregeln für Coding-Agenten"
Cohesion: 0.13
Nodes (14): Abschlussbericht nach jeder Arbeitseinheit, Arbeitsregeln für Coding-Agenten, Arbeitsweise, Architekturregeln, Freigabepunkte (anhalten und fragen), Kompatibilität, Sicherheit, Ziel (+6 more)

### Community 11 - "Umsetzungsplan"
Cohesion: 0.14
Nodes (14): Freigabepunkt 1 – erledigt (2026-10-21), Größte Risiken, M0 – Gerüst ✅ (2026-10-21), M1 – Metadaten und Speicher ✅ (2026-10-21), M2 – WebDAV-Kern, M3 – Referenz-Mitschnitte, M4 – Anmeldung wie Nextcloud, M5 – Nextcloud-WebDAV-Erweiterungen (+6 more)

### Community 12 - "Architektur"
Cohesion: 0.17
Nodes (12): Anfrageverarbeitung, Architektur, Autorisierung, Bedrohungsmodell (Kurzfassung, Details in `docs/security.md`), Betrieb, Crates, Datenmodell (Kern), Fehlerabbildung (+4 more)

### Community 14 - "Entscheidung (Vorschlag)"
Cohesion: 0.20
Nodes (10): ADR 0002: Speichermodell für Dateien und Metadaten, Alternativen, Datenbank, Entscheidung (Vorschlag), Inhalte als unveränderliche Blobs, Konsequenzen, Kontext, Löschen, Verschieben, Kopieren (+2 more)

### Community 15 - "Installation und Betrieb"
Cohesion: 0.22
Nodes (8): Backup und Wiederherstellung (geplant), Bauen, Datenverzeichnis, Health-Checks, Herunterfahren, Installation und Betrieb, Konfiguration, Reverse Proxy (geplant)

### Community 16 - "rostdav"
Cohesion: 0.64
Nodes (8): rostdav, rostdav-app, rostdav-compat, rostdav-core, rostdav-dav, rostdav-meta, rostdav-storage, rostdav-web

### Community 17 - "Endpunkte und Protokollverträge"
Cohesion: 0.29
Nodes (7): Betrieb (M0), Endpunkte und Protokollverträge, Gemeinsame Header (alle Antworten), `GET /healthz`, `GET /readyz`, OCS und Login Flow, WebDAV

### Community 18 - "Weboberfläche"
Cohesion: 0.29
Nodes (7): Barrierefreiheit (Prüfliste je Seite), Design-Tokens, Logo, Referenzen, Seiten, Technik, Weboberfläche

### Community 19 - "Rostdav"
Cohesion: 0.29
Nodes (7): Aufbau des Repositorys, Dokumentation, Geplante Funktionen, Lizenz, Rostdav, Schnellstart, Status

### Community 21 - "ADR 0001: Technologie-Stack"
Cohesion: 0.33
Nodes (6): ADR 0001: Technologie-Stack, Betrachtete Optionen, Entscheidung (Vorschlag), Freigabe (2026-10-21), Konsequenzen, Kontext

### Community 22 - "Nextcloud-Kompatibilität"
Cohesion: 0.33
Nodes (6): Bekannte Endpunkte (zu verifizieren), Nextcloud-Kompatibilität, Nicht unterstützt, Offene Fragen, Referenzversionen, Unterstützte Abläufe

### Community 23 - "Sicherheitskonzept"
Cohesion: 0.33
Nodes (6): Abhängigkeiten, Bedrohungen und Maßnahmen, Kryptografie, Sicherheitskonzept, Sicherheitslücken melden, Vertrauensgrenzen

### Community 24 - "Hinweise für Claude Code"
Cohesion: 0.40
Nodes (4): Aktueller Stand, Befehle, Einstieg in eine Sitzung, Hinweise für Claude Code

### Community 26 - "Administration"
Cohesion: 0.40
Nodes (5): Administration, CLI (geplant), Einstellungen und Vorrang, Ereignisprotokoll, Rollen

## Knowledge Gaps
- **133 isolated node(s):** `MIN_PASSWORD_CHARS`, `NotFound`, `Unauthenticated`, `Forbidden`, `Conflict` (+128 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 209 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **4 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `AppState` connect `AppState` to `http.rs`?**
  _High betweenness centrality (0.099) - this node is a cross-community bridge._
- **Why does `LocalStore` connect `rostdav-storage/src/lib.rs` to `AppState`?**
  _High betweenness centrality (0.044) - this node is a cross-community bridge._
- **Why does `KI-Agent-Anweisung: Rostdav – schlanker Nextcloud-kompatibler Dateiserver` connect `KI-Agent-Anweisung: Rostdav – schlanker Nextcloud-kompatibler Dateiserver` to `anweisung.md`?**
  _High betweenness centrality (0.042) - this node is a cross-community bridge._
- **Are the 4 inferred relationships involving `test_db()` (e.g. with `create_and_find_with_root_node()` and `duplicate_is_conflict_and_nfc_equivalent()`) actually correct?**
  _`test_db()` has 4 INFERRED edges - model-reasoned connections that need verification._
- **What connects `MIN_PASSWORD_CHARS`, `NotFound`, `Unauthenticated` to the rest of the system?**
  _133 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `rostdav-storage/src/lib.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.1066066066066066 - nodes in this community are weakly interconnected._
- **Should `config.rs` be split into smaller, more focused modules?**
  _Cohesion score 0.08403361344537816 - nodes in this community are weakly interconnected._