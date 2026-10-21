# Administration

Anforderungen: Abschnitt 2.8 der [Anweisung](anweisung.md). Entwurf: `design/mockups/web-ui/Admin.dc.html`.

> Stand M0: noch nicht implementiert. Erste CLI-Befehle folgen in M1, vollständig in M7.

## Rollen

| Rolle | Rechte |
|---|---|
| `user` | Eigene Dateien, Freigaben, Geräte, Einstellungen |
| `admin` | Zusätzlich Benutzerverwaltung, Server- und Sicherheitseinstellungen, Ereignisprotokoll |

Regeln: Ein Administrator kann sich nicht selbst deaktivieren; die letzte Admin-Rolle lässt sich nicht entfernen.

## CLI (geplant)

| Befehl | Meilenstein |
|---|---|
| `rostdav admin user add <login> [--admin]` | M1 |
| `rostdav admin user list` | M7 |
| `rostdav admin user disable <login>` / `enable` | M7 |
| `rostdav admin user reset-2fa <login>` | M12 |
| `rostdav admin user set-quota <login> <größe>` | M7 |
| `rostdav admin fsck` | M1 |
| `rostdav admin import <pfad> --user <login>` | M7 |
| `rostdav admin audit export --since <datum>` | M7 |

## Einstellungen und Vorrang

Kommandozeile > Umgebung (`ROSTDAV_*`) > Konfigurationsdatei > Datenbank (Oberfläche) > Defaults. Werte aus den oberen Ebenen sind in der Oberfläche schreibgeschützt und als „durch Konfiguration festgelegt“ markiert.

## Ereignisprotokoll

Felder: Zeitpunkt, Akteur, Aktion, Ziel, IP (konfigurierbar anonymisiert), Details als JSON. Niemals Dateiinhalte, Passwörter oder Tokens. Export als JSON Lines.

| Aktion | Beispiel |
|---|---|
| `auth.login`, `auth.login_failed`, `auth.locked` | Anmeldungen und Sperren |
| `device.connected`, `device.revoked` | Login Flow, App-Passwörter |
| `2fa.enabled`, `2fa.disabled`, `2fa.reset` | Zwei-Faktor |
| `admin.user_created`, `admin.user_disabled`, `admin.settings_changed` | Admin-Aktionen |
| `share.created`, `share.revoked` | Freigaben |
