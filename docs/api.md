# Endpunkte und Protokollverträge

Nur tatsächlich implementierte Endpunkte. Geplante stehen in [compatibility.md](compatibility.md) und [plan.md](plan.md).

## Betrieb (M0)

### `GET /healthz`

Prozess lebt. Prüft keine Abhängigkeiten.

```http
HTTP/1.1 200 OK
content-type: application/json
x-request-id: <uuid>

{"status":"ok"}
```

### `GET /readyz`

Datenbank antwortet und Datenverzeichnis ist beschreibbar.

| Zustand | Status | Body |
|---|---|---|
| bereit | `200` | `{"status":"ok"}` |
| nicht bereit | `503` | `{"status":"unavailable"}` |

Ursachen werden nur geloggt (mit Request-ID), nie ausgeliefert.

## Gemeinsame Header (alle Antworten)

| Header | Wert |
|---|---|
| `x-request-id` | UUID; ein eingehender Wert wird übernommen |
| `x-content-type-options` | `nosniff` |
| `referrer-policy` | `no-referrer` |

## WebDAV

Folgt in M2.

## OCS und Login Flow

Folgt in M4.
