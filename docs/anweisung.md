# KI-Agent-Anweisung: Rostdav – schlanker Nextcloud-kompatibler Dateiserver

## 1. Rolle, Ziel und Abgrenzung

Du bist ein autonom arbeitender Senior Software Engineer. Du entwickelst **Rostdav**, einen schlanken, sicheren und wartbaren Dateiserver, mit dem die **unveränderte offizielle Nextcloud-App** (Android und iOS) für grundlegende Dateioperationen genutzt werden kann.

**Ziel:** So wenig eigene Implementierung wie möglich, so viel echte Protokollkompatibilität wie nötig. Sicherheit, Testbarkeit und Wartbarkeit haben Vorrang vor Funktionsumfang.

**Referenzversionen (vor Beginn festlegen und in `docs/compatibility.md` eintragen):**

- Nextcloud-Android-App: Version `<X.Y.Z>`
- Nextcloud-iOS-App: Version `<X.Y.Z>` (optional, Phase 3b)
- Emulierte Server-Version (gemeldet über `status.php` und Capabilities): `<Major.Minor.Patch>` – muss von der Referenz-App als unterstützt akzeptiert werden; konfigurierbar halten.

**Nicht-Ziele (explizit nicht implementieren, sofern nicht später beauftragt):**

- Nextcloud-Apps-Ökosystem, Talk, Kalender, Kontakte, Notizen, Deck, Office
- Serverseitige Verschlüsselung, Ende-zu-Ende-Verschlüsselung
- Föderation (Federated Cloud Sharing), LDAP, SSO/SAML/OIDC
- Desktop-Sync-Client-Kompatibilität (nur als spätere Option dokumentieren)
- Vollständige Nextcloud-Web-Oberfläche

## 2. Funktionale Anforderungen

Jede Anforderung hat eine Priorität: **P0** = Prototyp, **P1** = App-Kompatibilität, **P2** = Erweiterung.

### 2.1 Benutzer und Authentifizierung

- **P0** Mehrere Benutzer mit strikt getrennten Dateibereichen.
- **P0** Passwort-Hashing mit Argon2id (Parameter konfigurierbar, dokumentiert); niemals Klartext.
- **P0** HTTP Basic Auth gegen WebDAV/OCS (die Nextcloud-Apps senden nach dem Login Benutzername + **App-Passwort** per Basic Auth).
- **P1** **Login Flow v2** (`POST /index.php/login/v2`, Browser-Login-Seite, Polling-Endpunkt), der ein gerätespezifisches App-Passwort ausstellt.
- **P1** App-Passwörter: zufällig generiert, nur gehasht gespeichert, einzeln widerrufbar, mit Gerätebezeichnung und Zeitpunkt der letzten Nutzung.
- **P1** Benutzerkonten deaktivieren; Deaktivierung macht alle Sitzungen und App-Passwörter sofort ungültig.
- **P2** Sitzungsbasierte Anmeldung für die Web-Oberfläche (HttpOnly, Secure, SameSite-Cookies, CSRF-Schutz).
- **P2** **Optionale Zwei-Faktor-Anmeldung (TOTP, RFC 6238)** pro Benutzer, standardmäßig aus:
  - Einrichtung: Secret serverseitig erzeugen (≥ 160 Bit), als QR-Code (`otpauth://`) und manuell anzeigen, erst nach Eingabe eines gültigen Codes aktivieren.
  - Secret verschlüsselt speichern (Schlüssel aus der Konfiguration, nicht in der Datenbank); Zeitfenster ±1 Schritt; jeder Code nur einmal verwendbar (Replay-Schutz).
  - Zehn einmalige Wiederherstellungscodes, nur gehasht gespeichert, neu erzeugbar; Anzeige der verbleibenden Anzahl.
  - Abfrage nur bei interaktiver Browser-Anmeldung (Web-UI und Login-Flow-v2-Seite). App-Passwörter umgehen 2FA bewusst, wie bei Nextcloud – die Nextcloud-Apps bleiben dadurch kompatibel.
  - Ist 2FA aktiv, wird Basic Auth mit dem **Kontopasswort** an WebDAV/OCS abgelehnt; nur App-Passwörter sind dort zulässig.
  - Deaktivieren und Neuerzeugen der Codes erfordert erneute Eingabe von Passwort und Code. Ein Administrator kann 2FA für gesperrte Benutzer zurücksetzen (protokolliert).
  - Brute-Force-Schutz für Code-Eingabe wie für Passwörter; Secrets und Codes nie protokollieren.
  - In den Capabilities nichts ankündigen, was die Nextcloud-App zu einem nicht implementierten 2FA-Ablauf veranlasst; Verhalten der Referenz-App mit aktivierter 2FA testen und in `docs/compatibility.md` festhalten.

Login- und App-Passwort-Logik werden von Weboberfläche, WebDAV und OCS gemeinsam genutzt (ein Identity-Modul, keine Duplikate).

### 2.2 Dateiverwaltung

- **P0** Hochladen, Herunterladen, Umbenennen, Verschieben, Kopieren, Löschen von Dateien und Ordnern; Ordner anlegen und auflisten.
- **P0** Streaming in beide Richtungen; keine vollständige Pufferung im Arbeitsspeicher.
- **P0** Atomare Schreibvorgänge: Upload in temporäre Datei im selben Dateisystem, `fsync`, danach atomares Umbenennen.
- **P0** Metadaten in einer Datenbank (Standard: SQLite, PostgreSQL optional): stabile **Datei-ID**, die bei Umbenennen/Verschieben erhalten bleibt, Größe, mtime, ETag, Besitzer, Pfad.
- **P0** Physische Speicherpfade werden **nicht** aus Benutzereingaben abgeleitet (z. B. inhaltsadressiert oder ID-basiert); logische Pfade existieren nur in der Datenbank.
- **P0** Ordner-ETags ändern sich, wenn sich darin rekursiv etwas ändert (Clients erkennen Änderungen darüber).
- **P1** Client-mtime über `X-OC-MTime` übernehmen und mit `X-OC-MTime: accepted` bestätigen.
- **P1** Chunked Upload (Nextcloud Chunking v2, siehe Abschnitt 3) für große Dateien.
- **P1** Quota pro Benutzer (`quota-available-bytes`, `quota-used-bytes`).
- **P0** Dateinamen: Unicode-Normalisierung festlegen (NFC speichern, Vergleich normalisiert), verbotene Namen (`.`, `..`, leere Segmente, Steuerzeichen, `/`), Längenbegrenzung. Groß-/Kleinschreibung: Verhalten festlegen und dokumentieren.

### 2.3 Löschen und Papierkorb

- **P0** Löschen ist endgültig; Capabilities dürfen **keinen** Papierkorb ankündigen, solange er nicht existiert.
- **P2** Optionaler Papierkorb über den Nextcloud-Trashbin-DAV-Endpunkt.

### 2.4 Dateiversionierung (P2)

- Bei Überschreiben bisherige Version aufbewahren.
- Versionshistorie über den Nextcloud-Versions-DAV-Endpunkt bereitstellen; Wiederherstellung über den dort üblichen `MOVE`-Ablauf.
- Aufbewahrungsregeln konfigurierbar (Anzahl, Alter, Speicheranteil an der Quota); Bereinigung als Hintergrundaufgabe, nie während eines Requests.
- Versionen zählen zur Quota (dokumentierte Entscheidung).
- Erst in den Capabilities ankündigen, wenn implementiert und getestet.

### 2.5 Freigaben (P2)

- Benutzer-zu-Benutzer-Freigaben von Dateien und Ordnern mit Rechten Lesen / Schreiben / Anlegen / Löschen / Weiterteilen (Nextcloud-Rechte-Bitmaske).
- Öffentliche Links mit mindestens 128 Bit zufälligem Token, optional Passwort (gehasht) und Ablaufdatum; standardmäßig deaktiviert.
- Widerruf wirkt sofort.
- Über die OCS-Sharing-API (`/ocs/v2.php/apps/files_sharing/api/v1/shares`) bereitstellen; Freigaben erscheinen beim Empfänger als Einträge in seinem Dateibaum.
- Berechtigungsprüfung bei jeder Operation auf der effektiven Freigabe, nicht auf dem Pfad.

### 2.6 Web-Oberfläche

Referenzentwurf: Design-Canvas „Rostdav Web-UI“ (Seiten Dateien, Geräte & Sicherheit, Einstellungen, Administration, Gerät verbinden, zweiter Faktor). Farben, Schriften und Logo stammen aus dem Canvas „Rostdav Logo“. Der Entwurf ist verbindlich für Struktur und Inhalte, nicht pixelgenau.

- **P1** Anmeldeseite für Login Flow v2 inklusive Ablehnen-Option, Anzeige des anfragenden Clients und Phishing-Hinweis.
- **P2** Dateibrowser: Liste mit Name, Größe, Änderungsdatum, Freigabestatus; Detailspalte mit Versionen, Freigaben, Datei-ID und ETag; Upload mit Fortschritt (Chunked Upload) und Abbruch.
- **P2** Seite „Geräte & Sicherheit“: verbundene Geräte und Sitzungen mit letzter Nutzung und Widerruf, App-Passwort erstellen (Klartext nur einmal anzeigen), Zwei-Faktor-Einrichtung, „Alle Geräte abmelden“.
- **P2** Persönliche Einstellungen (Abschnitt 2.7) und Administration (Abschnitt 2.8).
- **Technik:** Serverseitig gerendertes HTML mit wenig JavaScript bevorzugen (kein SPA-Framework ohne Begründung im ADR). Die Oberfläche nutzt ausschließlich dieselben internen Dienste wie WebDAV/OCS, keine eigene Geschäftslogik.
- **Darstellung:** Hell- und Dunkelmodus über Design-Tokens (CSS-Variablen); Standard folgt `prefers-color-scheme`, Benutzerwahl überschreibt und wird im Profil gespeichert.
- **Barrierefreiheit:** WCAG 2.1 AA – echte Buttons, Links und Formularfelder mit Labels, Tastaturbedienung, sichtbarer Fokus, Kontrast mindestens 4,5:1, Klickflächen mindestens 44 px. Mobile Breite ab 360 px nutzbar (Navigation stapelt sich).
- **Sicherheit:** CSRF-Schutz für alle zustandsändernden Requests, strikte Content-Security-Policy (keine Inline-Skripte), `X-Frame-Options: DENY` bzw. `frame-ancestors 'none'`, keine Geheimnisse in URLs. Gefährliche Aktionen (Benutzer deaktivieren, 2FA zurücksetzen, alle Geräte abmelden) mit Bestätigung; Anzeige von Dateinamen immer HTML-escaped.
- **Sprache:** Deutsch und Englisch; Texte in Ressourcendateien, keine fest eingebauten Strings.

### 2.7 Persönliche Einstellungen (P2)

- Anzeigename, E-Mail-Adresse für Benachrichtigungen, Sprache, Farbschema (Hell / Dunkel / wie System), Profilbild (Größe und Typ begrenzt, serverseitig neu kodiert).
- Benutzername ist nicht änderbar.
- Dateieinstellungen: versteckte Dateien anzeigen, vor dem Löschen nachfragen, Vorschaubilder laden, Versionen behalten (sofern der Administrator Versionierung erlaubt).
- Anzeige der persönlichen WebDAV-Adresse zum Kopieren.
- Speicherübersicht: Belegung durch Dateien, Versionen und Papierkorb im Verhältnis zum Kontingent.
- Datenexport aller eigenen Dateien als Archiv (gestreamt, als Hintergrundaufgabe bei großen Datenmengen, Download-Link nur für den Benutzer und zeitlich begrenzt).
- Passwort ändern erfordert das alte Passwort; danach werden alle Browser-Sitzungen außer der aktuellen beendet, App-Passwörter bleiben gültig (dokumentierte Entscheidung).

### 2.8 Administration (P2)

Nur für Benutzer mit Rolle `admin`; jede Admin-Aktion wird serverseitig autorisiert und im Ereignisprotokoll erfasst. Für alle Funktionen gibt es zusätzlich ein CLI (`rostdav admin …`), damit der Server ohne Weboberfläche betreibbar bleibt; der erste Administrator wird per CLI angelegt.

- **Benutzer:** anlegen (mit Einmal-Passwort oder Einladungslink), bearbeiten, Rolle setzen, Kontingent setzen, deaktivieren/aktivieren, löschen (mit Wahl: Daten löschen oder an anderen Benutzer übertragen), 2FA zurücksetzen. Ein Administrator kann sich nicht selbst deaktivieren oder die letzte Admin-Rolle entfernen. Suche und Sortierung; Anzeige von Speicherauslastung und 2FA-Status.
- **Server – Uploads & Speicher:** Standard-Kontingent, maximale Dateigröße, Aufbewahrung verwaister Chunk-Uploads.
- **Server – Versionen & Papierkorb:** maximale Versionen pro Datei, Aufbewahrungsdauer, maximaler Anteil am Kontingent, Papierkorb-Aufbewahrung.
- **Server – Freigaben:** öffentliche Links erlauben, Passwort für Links verlangen, Ablaufdatum erzwingen (mit Standardfrist).
- **Sicherheit:** 2FA für alle verlangen (Standard aus; Benutzer ohne 2FA richten sie bei der nächsten Browser-Anmeldung ein), WebDAV/OCS nur mit App-Passwörtern (Standard an), Fehlversuche bis zur Sperre und Sperrdauer, Liste aktiver Sperren mit Aufheben.
- **Ereignisprotokoll:** Anmeldungen, fehlgeschlagene Anmeldungen und Sperren, Geräteverbindungen und -widerrufe, 2FA-Änderungen, Admin-Aktionen, Freigabe-Erstellung. Felder: Zeitpunkt, Akteur, Aktion, Ziel, IP (konfigurierbar anonymisiert). Keine Dateiinhalte, Passwörter oder Tokens. Aufbewahrungsdauer konfigurierbar; Export als JSON Lines.
- **Kompatibilität:** Anzeige von `productname`, gemeldeter Version und getesteten App-Versionen; Liste der in den Capabilities angekündigten Funktionen (nur lesend, abgeleitet aus dem tatsächlichen Code-Stand); Wartungsmodus (setzt `maintenance: true` in `status.php`, Schreibzugriffe werden mit 503 abgelehnt).
- **Status:** Serverversion, Speicherbelegung gesamt, Zustand der Hintergrundaufgaben (Versionsbereinigung, Chunk-Aufräumen, Konsistenzprüfung).
- Einstellungen werden in der Datenbank gespeichert; Werte aus Konfigurationsdatei/Umgebungsvariablen haben Vorrang und erscheinen in der Oberfläche als „durch Konfiguration festgelegt“ (nicht editierbar).

## 3. Nextcloud-Kompatibilität

### 3.1 Vorgehen

Die Kompatibilität wird **aus Primärquellen abgeleitet, nicht geraten**:

1. **Quellcode der Clients** lesen: `nextcloud/android`, `nextcloud/android-library`, `nextcloud/ios`, `nextcloud/NextcloudKit` (jeweils am Tag der Referenzversion).
2. **Nextcloud-Entwicklerdokumentation** (Client-APIs: Login Flow, WebDAV, Chunked Upload, OCS, Sharing, Versions).
3. **Referenz-Mitschnitte**: Wenn möglich, eine echte Nextcloud-Instanz (Docker, gleiche Major-Version wie emuliert) mit der Referenz-App bedienen und den Verkehr mit einem Proxy (z. B. mitmproxy) aufzeichnen. Mitschnitte als bereinigte Fixtures (ohne Zugangsdaten) in `tests/fixtures/nextcloud/` ablegen und als Grundlage für Vertragstests verwenden.
4. Für jeden unterstützten App-Ablauf einen Vertragstest schreiben, der Request/Response gegen die Fixtures prüft.
5. Ende-zu-Ende-Test mit der unveränderten App auf Emulator oder Gerät. **Kannst du das in deiner Umgebung nicht ausführen, kennzeichne den Test als „nicht ausgeführt“ und liefere eine reproduzierbare manuelle Testanleitung.**

Jede Kompatibilitätsaussage in der Dokumentation nennt ihre Quelle (Datei/Zeile im Client-Code, Dokuseite oder Fixture). Erfinde keine Antwortfelder; unbekannte Felder werden recherchiert oder weggelassen und dokumentiert.

### 3.2 Zu prüfende Schnittstellen (Startliste, gegen Quellen verifizieren)

| Bereich | Endpunkt / Verhalten | Priorität |
|---|---|---|
| Server-Erkennung | `GET /status.php` (installed, maintenance, needsDbUpgrade, version, versionstring, edition, productname, extendedSupport) | P1 |
| Login | Login Flow v2: `POST /index.php/login/v2`, Browser-Seite, `POST /index.php/login/v2/poll` → server, loginName, appPassword | P1 |
| Capabilities | `GET /ocs/v2.php/cloud/capabilities` (JSON und XML), nur tatsächlich implementierte Features ankündigen | P1 |
| Benutzer | `GET /ocs/v2.php/cloud/user`, ggf. `/ocs/v1.php/cloud/users/{id}` inkl. Quota | P1 |
| OCS allgemein | Header `OCS-APIRequest: true` verlangen; Envelope `ocs.meta.{status,statuscode,message}` + `ocs.data`; v1- vs. v2-Statuscodes beachten; `?format=json` | P1 |
| WebDAV | `/remote.php/dav/files/{userId}/…`; Legacy `/remote.php/webdav/…` prüfen, ob die Referenz-App sie noch nutzt | P0 |
| DAV-Properties | `d:` Standard-Props plus `oc:` (`http://owncloud.org/ns`) und `nc:` (`http://nextcloud.org/ns`), u. a. `oc:fileid`, `oc:id`, `oc:permissions`, `oc:size`, `oc:owner-id`, `oc:share-types`, `nc:has-preview`; unbekannte Props korrekt mit 404 im `propstat` | P0/P1 |
| Upload-Header | `X-OC-MTime`, `OC-Checksum`, Antwort-Header `OC-FileId`, `OC-ETag`, `ETag` | P1 |
| Chunked Upload | `/remote.php/dav/uploads/{userId}/{transferId}/`: `MKCOL`, nummerierte Chunk-`PUT`s, `MOVE …/.file` mit `Destination` und `OC-Total-Length`; Aufräumen verwaister Uploads | P1 |
| Suche | WebDAV `SEARCH` (RFC 5323) – wird von der App u. a. für Medien/Zuletzt-geändert genutzt; mindestens sauber mit 501 o. ä. ablehnen, wenn nicht unterstützt, und App-Verhalten dokumentieren | P2 |
| Vorschaubilder | `/index.php/core/preview` bzw. Avatar-Endpunkte: anfangs mit 404 beantworten, nie mit 500; `nc:has-preview=false` | P1 |
| Versionen | `/remote.php/dav/versions/{userId}/…` | P2 |
| Papierkorb | `/remote.php/dav/trashbin/{userId}/…` | P2 |
| Freigaben | OCS Sharing API; öffentliche Links `/s/{token}` und `public.php`-DAV | P2 |
| Optional | Notifications, Activity, Push: in Capabilities **nicht** ankündigen | – |

### 3.3 Weitere Kompatibilitätsregeln

- `OPTIONS` liefert `DAV`- und `Allow`-Header, die zum tatsächlichen Funktionsumfang passen. `LOCK`/`UNLOCK` nur, wenn ein unterstützter Client sie braucht (relevant v. a. für macOS Finder / Windows Explorer, nicht für die Mobile-App).
- `PROPFIND` mit `Depth: 0` und `1`; `Depth: infinity` ablehnen (403 mit DAV-Fehlerelement).
- Bedingte Requests: `If-Match`, `If-None-Match`, `Overwrite`, `Destination` korrekt behandeln; 412 bei ETag-Konflikt.
- Statuscodes nach RFC 4918 (201, 204, 207, 409, 412, 415, 423, 507 bei Quota-Überschreitung).
- Die gemeldete Serverversion ist eine Kompatibilitätsangabe; README und Web-UI müssen klarstellen, dass es sich **nicht** um Nextcloud handelt. `productname` in `status.php` und Capabilities lautet `Rostdav`, sofern die Referenz-App das akzeptiert (prüfen und in `docs/compatibility.md` festhalten).
- Projektname konsistent verwenden: Binary, Container-Image, Konfigurationsschlüssel und Umgebungsvariablen mit Präfix `rostdav` bzw. `ROSTDAV_`. Den Namen zentral als Konstante führen, damit eine spätere Umbenennung billig bleibt.

## 4. Technische Architektur

Modularer Monolith mit klaren Modulgrenzen und expliziten Schnittstellen:

- **Identity** – Benutzer, Passwort-Hashes, App-Passwörter, Sitzungen, Login Flow v2
- **Metadata** – Datenbankschema, Datei-IDs, Pfadbaum, ETags, Migrationen
- **Storage** – Abstraktion des physischen Speichers (lokales Dateisystem zuerst), atomare Writes
- **File Service** – Dateioperationen, Berechtigungsprüfung, Quota; einzige Stelle, die Metadata und Storage koordiniert
- **Versioning** (P2), **Sharing** (P2), **Trash** (P2)
- **WebDAV-Adapter** – reine Protokollübersetzung, keine Geschäftslogik
- **Nextcloud-Compat-Adapter** – status.php, Capabilities, OCS, Login Flow
- **Web UI** – Login-Seite für Login Flow v2 (P1); Dateibrowser, Geräte, Einstellungen, Administration (P2); siehe Abschnitte 2.6–2.8
- **Admin** – Rollen, Server-Einstellungen, Ereignisprotokoll, CLI; nutzt Identity und File Service, nie direkt Storage
- **Configuration** – Datei + Umgebungsvariablen, Geheimnisse nur aus der Umgebung/Secret-Dateien

Regeln:

- Protokolladapter greifen nur auf den File Service zu, nie direkt auf Storage oder Datenbank.
- Dateisystem- und Datenbankzustand werden konsistent gehalten (Reihenfolge der Schritte dokumentieren; Reparaturjob/Konsistenzprüfung für Abstürze zwischen beiden).
- Nebenläufigkeit: Schreibzugriffe auf denselben Knoten serialisieren (DB-Transaktion/Row-Lock); MOVE/COPY über Ordnergrenzen atomar in der Metadatenebene.

### 4.1 Technologie-Stack

- Existiert ein Repository mit festgelegtem Stack, verwende diesen.
- Andernfalls vergleiche höchstens drei Kandidaten in einer kurzen Tabelle (Kriterien: Streaming, Reife verfügbarer WebDAV-Bausteine, Sicherheit, Wartbarkeit, Deployment-Größe) und **lege die Wahl als Architekturentscheidung (ADR) in `docs/adr/` vor, bevor du mit Phase 2 beginnst.** Dies ist ein Freigabepunkt (siehe Abschnitt 7).
- Bevorzugter Kandidat, sofern kein Gegengrund: `<Stack eintragen, z. B. Kotlin/Spring Boot oder Go oder Rust>`.

## 5. Sicherheitsanforderungen

Verbindlich:

- Berechtigungsprüfung serverseitig bei jeder Ressource, über die Datei-ID und die effektive Freigabe – nie nur über den Pfad.
- Kein Zugriff auf fremde Dateien, Versionen, Uploads in Arbeit oder Papierkorbeinträge.
- Path Traversal ausgeschlossen durch Design (physische Pfade nicht aus Benutzereingaben); zusätzlich Eingabevalidierung. Keine Symlinks im Speicherbereich folgen.
- Prozentkodierung, doppelte Kodierung, Unicode-Varianten und `Destination`-Header (inkl. fremder Hosts) werden normalisiert und validiert.
- XML-Parser: externe Entitäten und DTDs deaktiviert (XXE), Größen- und Tiefenlimits.
- TLS im Produktivbetrieb; HSTS; Hinweis auf Betrieb hinter Reverse Proxy mit korrekt konfigurierten Trusted-Proxy-Headern.
- Konfigurierbare Limits: Upload-Größe, Chunk-Größe, Anzahl paralleler Uploads, Request-Body für XML, Anzahl Einträge pro PROPFIND.
- Brute-Force-Schutz pro Benutzer **und** pro IP für Passwort-Login, Basic Auth, Login-Flow-Polling und Link-Passwörter; zeitkonstante Vergleiche für Tokens.
- Login-Flow-Tokens: kurzlebig, einmalig verwendbar, ausreichend lang.
- Fehlerantworten ohne interne Pfade, Stacktraces oder Geheimnisse.
- Keine Protokollierung von Passwörtern, App-Passwörtern, Authorization-Headern, Share-Tokens oder Dateiinhalten; Log-Felder werden zentral geschwärzt.
- Abhängigkeiten minimal halten und auf bekannte Schwachstellen prüfen (Tool des Stacks im CI).

Vor sicherheitsrelevanten Änderungen: kurze Bedrohungsanalyse (STRIDE-Stichpunkte reichen) in `docs/security.md` ergänzen. Für Autorisierung, Path-Handling und Freigaben sind Negativtests Pflicht (Zugriff auf fremde IDs, manipulierte Pfade, abgelaufene/widerrufene Freigaben).

## 6. Entwicklungsworkflow

### Phase 1: Bestandsaufnahme

- Repository, Dokumentation, Build, Tests und vorhandene Architektur untersuchen.
- Ist kein Projekt vorhanden: Architekturvorschlag, Stack-ADR und priorisierten Umsetzungsplan erstellen.
- Referenzversionen der App festlegen (Abschnitt 1).
- **Freigabepunkt:** Plan und ADR vorlegen.

Keine vorhandenen Dateien überschreiben und keine Funktionen entfernen, bevor ihre Bedeutung geklärt ist.

### Phase 2: Minimaler Prototyp (P0)

1. Serverstart, Konfiguration, Datenbankmigrationen.
2. Benutzer anlegen (CLI), Basic Auth.
3. Benutzerbezogene Dateibereiche mit Metadaten und stabilen Datei-IDs.
4. WebDAV: OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, DELETE, MOVE, COPY.
5. Integrationstests für alle Kernabläufe, inkl. Negativ- und Berechtigungstests.
6. Interoperabilitätstest mit einem Standard-WebDAV-Client (z. B. `rclone` oder `cadaver`) als Plausibilitätsprüfung.

**Abnahme Phase 2:** Alle Tests grün; ein zweiter Benutzer kann nachweislich nicht auf Dateien des ersten zugreifen.

### Phase 3: App-Kompatibilität (P1)

- Referenz-Mitschnitte erstellen (Abschnitt 3.1).
- status.php, Capabilities, OCS-Benutzerendpunkt, Login Flow v2 inkl. Login-Seite, App-Passwörter.
- Nextcloud-DAV-Properties, Upload-Header, Chunked Upload, Quota.
- Vorschau-/Avatar-Endpunkte sauber ablehnen.

**Abnahme Phase 3:** Mit der Referenz-App: Server hinzufügen, anmelden, Ordner durchsuchen, Datei hochladen (klein und > 100 MB), herunterladen, umbenennen, verschieben, löschen, abmelden; App-Passwort widerrufen führt zum Abmelden in der App. Jeder Schritt hat einen Vertragstest; der Gerätetest ist ausgeführt oder ausdrücklich als nicht ausgeführt gekennzeichnet.

### Phase 4: Erweiterungen (P2)

Admin-CLI und Ereignisprotokoll → Versionierung → Freigaben (Benutzer, dann öffentliche Links) → Papierkorb → Web-Oberfläche (Dateien, Geräte, Einstellungen, Administration, Hell/Dunkel) → optionale Zwei-Faktor-Anmeldung → Aufbewahrungsregeln und Datenexport. Jedes Feature wird erst nach bestandenen Tests in den Capabilities angekündigt.

### Phase 5: Härtung und Auslieferung

Sicherheits- und Lasttests (große Dateien, viele kleine Dateien, parallele Uploads), strukturierte Logs, Health-Endpunkt, Container-Image und Compose-Beispiel, Backup-/Restore-Konzept (Datenbank und Speicher konsistent sichern, Restore-Test), Betriebsdokumentation.

## 7. Regeln für Codeänderungen und Entscheidungen

- Kleine, überprüfbare Schritte; je Schritt ein Commit mit aussagekräftiger Nachricht.
- Vor größeren Änderungen einen Plan erstellen.
- Tests für neue Funktionen und für jeden behobenen Fehler (Regressionstest).
- Nach Änderungen relevante Tests und Build ausführen; neu eingeführte Fehler beheben.
- Bestehende Projektkonventionen einhalten; neue Abhängigkeiten nur mit Begründung im Commit oder ADR.
- **Erfinde keine Testergebnisse.** Nicht ausgeführte Tests ausdrücklich als solche kennzeichnen.
- Bei Fehlern: reproduzieren, Ursache ermitteln, gezielt korrigieren, erneut testen.

**Freigabepunkte (hier anhalten und Rückmeldung einholen):**

1. Stack-Wahl und Architektur (Ende Phase 1).
2. Datenbankschema für Metadaten, bevor Daten persistiert werden, die später migriert werden müssten.
3. Jede Änderung an Authentifizierung, Token-Format oder Berechtigungsmodell nach Phase 2.
4. Irreversible Operationen auf vorhandenen Daten oder Repositories.

Alle übrigen Entscheidungen selbstständig treffen und in den Abschlussberichten bzw. ADRs dokumentieren.

## 8. Definition of Done

Eine Funktion ist abgeschlossen, wenn:

- die Implementierung vorhanden ist,
- Unit-, Integrations- und (falls protokollrelevant) Vertragstests bestehen,
- Fehlerfälle und Berechtigungen inklusive Negativtests abgedeckt sind,
- API-Verträge mit Quellenangabe in `docs/api.md` bzw. `docs/compatibility.md` dokumentiert sind,
- der Build erfolgreich ist (soweit die Umgebung es erlaubt),
- keine bekannten kritischen Sicherheitsprobleme offen sind,
- Capabilities nur das ankündigen, was getestet funktioniert.

## 9. Dokumentation

- `README.md` – Rostdav: Ziel, Funktionsumfang, Hinweis „nicht Nextcloud, nicht verbunden mit Nextcloud GmbH“, Voraussetzungen, Schnellstart
- `AGENTS.md` – dauerhafte Arbeitsregeln für Coding-Agenten (Kurzfassung dieser Anweisung)
- `docs/architecture.md` – Module, Abhängigkeitsrichtung, Konsistenzmodell
- `docs/adr/` – Architekturentscheidungen
- `docs/compatibility.md` – Referenzversionen, unterstützte App-Abläufe mit Teststatus, nicht unterstützte Funktionen, beobachtetes App-Verhalten bei fehlenden Features
- `docs/security.md` – Bedrohungsmodell, Schutzmaßnahmen, offene Risiken
- `docs/api.md` – implementierte Endpunkte und Protokollverträge mit Quellen
- `docs/deployment.md` – Installation, Konfiguration, Reverse Proxy/TLS, Backup und Restore, Betrieb
- `docs/admin.md` – Rollen, Admin-Oberfläche und CLI-Befehle, Einstellungen mit Vorrangregeln, Ereignisprotokoll
- `docs/ui.md` – Seitenstruktur, Design-Tokens (hell/dunkel), Barrierefreiheits-Prüfung

## 10. Abschlussbericht nach jeder Arbeitseinheit

1. Was wurde implementiert?
2. Welche Dateien wurden erstellt oder geändert?
3. Welche Tests und Builds wurden ausgeführt – und welche **nicht**?
4. Welche Ergebnisse wurden tatsächlich erzielt (mit Ausgabeauszug bei Fehlschlägen)?
5. Welche Annahmen wurden getroffen, welche Einschränkungen und Risiken bestehen?
6. Was ist der sinnvollste nächste Schritt?

---

**Starte jetzt mit Phase 1.** Ist noch kein Projekt vorhanden, liefere Architekturvorschlag, Stack-ADR und priorisierten Plan und halte am ersten Freigabepunkt an.
