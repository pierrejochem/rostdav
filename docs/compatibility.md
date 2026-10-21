# Nextcloud-Kompatibilität

> Stand: **noch nichts getestet.** Dieses Dokument wird in M3 (Mitschnitte) und M6 (Ende-zu-Ende) gefüllt. Jede Aussage nennt ihre Quelle: Client-Code (Repository, Datei, Zeile, Version), Nextcloud-Dokumentation (URL) oder Fixture (`tests/fixtures/nextcloud/…`).

## Referenzversionen

| Komponente | Version | Festgelegt am |
|---|---|---|
| Nextcloud Android | [beim Start von M3 eintragen] | |
| Nextcloud iOS | optional, später | |
| Nextcloud-Server für Mitschnitte | [gleiche Major-Version wie emuliert] | |
| Gemeldete Server-Version (`status.php`) | [eintragen] | |

## Unterstützte Abläufe

| Ablauf | Status | Vertragstest | Gerätetest | Quelle |
|---|---|---|---|---|
| Server hinzufügen (`status.php`) | offen | – | – | |
| Anmeldung über Login Flow v2 | offen | – | – | |
| Ordner auflisten | offen | – | – | |
| Datei hochladen (klein) | offen | – | – | |
| Datei hochladen (> 100 MB, Chunked Upload v2) | offen | – | – | |
| Herunterladen | offen | – | – | |
| Umbenennen, Verschieben | offen | – | – | |
| Löschen | offen | – | – | |
| Abmelden / App-Passwort widerrufen | offen | – | – | |

Status: `offen` · `implementiert` · `Vertragstest grün` · `Gerätetest bestanden`

## Bekannte Endpunkte (zu verifizieren)

Startliste aus Abschnitt 3.2 der Anweisung. Nichts davon ist bestätigt, bis eine Quelle eingetragen ist.

| Endpunkt | Zweck | Verifiziert | Quelle |
|---|---|---|---|
| `GET /status.php` | Server-Erkennung | nein | |
| `POST /index.php/login/v2`, `POST /index.php/login/v2/poll` | Login Flow v2 | nein | |
| `GET /ocs/v2.php/cloud/capabilities` | Capabilities | nein | |
| `GET /ocs/v2.php/cloud/user` | Benutzerinfo | nein | |
| `/remote.php/dav/files/{userId}/` | Dateien | nein | |
| `/remote.php/webdav/` | Legacy-Pfad | nein | |
| `/remote.php/dav/uploads/{userId}/{transferId}/` | Chunked Upload | nein | |

## Nicht unterstützt

| Funktion | Verhalten der App ohne Unterstützung | Quelle |
|---|---|---|
| Vorschaubilder | [in M5 beobachten] | |
| Benachrichtigungen, Aktivitäten, Push | [beobachten] | |
| Ende-zu-Ende-Verschlüsselung | [beobachten] | |
| Talk, Kalender, Kontakte | nicht vorgesehen | |

## Offene Fragen

- Genaues Format von `oc:id` (Datei-ID plus Instanz-ID).
- Fehler-XML-Format für WebDAV-Fehler, das die App auswertet.
- Welche Mindestversion verlangt die App, und wie reagiert sie auf ältere Versionen?
- Verhalten der App bei aktivierter Zwei-Faktor-Anmeldung im Login Flow.
