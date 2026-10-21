# Sicherheitskonzept

Verbindliche Anforderungen: Abschnitt 5 der [Anweisung](anweisung.md). Kurzfassung des Bedrohungsmodells: [architecture.md](architecture.md#bedrohungsmodell-kurzfassung-details-in-docssecuritymd).

## Vertrauensgrenzen

1. **Internet ↔ Reverse Proxy:** TLS, HSTS. Rostdav selbst spricht nur HTTP auf localhost oder einem internen Netz.
2. **Reverse Proxy ↔ Rostdav:** Client-IP und Schema nur aus konfigurierten Trusted Proxies übernehmen (noch nicht implementiert, M4).
3. **Rostdav ↔ Datenverzeichnis:** nur der Dienstbenutzer, Rechte 0700 (implementiert in M0).
4. **Benutzer ↔ Benutzer:** strikte Trennung der Dateibereiche, Zugriff nur über Freigaben.

## Bedrohungen und Maßnahmen

| ID | Bedrohung | Maßnahme | Status |
|---|---|---|---|
| S1 | Passwort-Raten über WebDAV/OCS/Login | Rate Limit pro IP und Benutzer, Sperren, App-Passwort-Pflicht, 2FA | offen (M4, M12) |
| S2 | Gestohlenes App-Passwort | Pro Gerät widerrufbar, letzte Nutzung sichtbar, nur Hash gespeichert | offen (M4) |
| S3 | Session-Diebstahl in der Weboberfläche | HttpOnly, Secure, SameSite=Lax, kurze Laufzeit, Neuausstellung nach Anmeldung | offen (M11) |
| T1 | Path Traversal | Physische Pfade unabhängig von Eingaben, Segmentvalidierung | offen (M1) |
| T2 | `Destination`-Header auf fremden Host | Nur eigener Host und Basis-URL | offen (M2) |
| T3 | XXE / XML-Bomben | Parser ohne DTD/Entitäten, Größen- und Tiefenlimit | offen (M2) |
| T4 | CSRF in der Weboberfläche | Token pro Sitzung, nur POST für Änderungen | offen (M11) |
| R1 | Unbemerkte Admin-Aktionen | Ereignisprotokoll | offen (M7) |
| I1 | Zugriff auf fremde Datei-IDs | Autorisierung pro Knoten, Negativtests | offen (M2) |
| I2 | Interne Details in Fehlern | Generische Antworten, Details nur im Log mit Request-ID | M0 für `/readyz` |
| I3 | Geheimnisse in Logs | `Authorization`/`Cookie` sensibel, Spans ohne Query | M0 umgesetzt, Smoke-Test prüft es |
| I4 | Erratbare Freigabelinks | ≥ 128 Bit Zufall, nur Hash gespeichert, optional Passwort und Ablauf | offen (M9) |
| D1 | Ressourcenerschöpfung | Body-Limits je Route, `Depth: infinity` abgelehnt, Quota, Timeouts | offen (M2) |
| D2 | Verwaiste Uploads füllen die Platte | Ablaufzeit, Aufräumjob | offen (M5) |
| E1 | Benutzer ruft Admin-Funktion auf | Rollenprüfung im Dienst, nicht nur in der Oberfläche | offen (M7) |
| E2 | XSS über Dateinamen | Automatisches Escaping (askama), strikte CSP | offen (M11) |

## Kryptografie

| Zweck | Verfahren |
|---|---|
| Kontopasswörter, Link-Passwörter | Argon2id (Parameter konfigurierbar, Standard nach OWASP-Empfehlung zum Zeitpunkt der Umsetzung) |
| App-Passwörter, Sitzungs- und Link-Tokens | ≥ 128 Bit aus `getrandom`, gespeichert als SHA-256, zeitkonstanter Vergleich |
| TOTP-Secrets | ChaCha20-Poly1305, Schlüssel aus Umgebung/Secret-Datei |
| Wiederherstellungscodes | Argon2id |
| Inhalts-Prüfsummen | BLAKE3 (keine Sicherheitsfunktion, nur Integrität) |

## Abhängigkeiten

- `cargo deny` im CI: Sicherheitsmeldungen, Lizenzen, Herkunft.
- Neue Abhängigkeiten nur mit Begründung (Commit oder ADR).
- `unsafe_code = "forbid"` im ganzen Workspace.

## Sicherheitslücken melden

[Kontaktweg festlegen, z. B. GitHub Security Advisories des Repositorys.]
