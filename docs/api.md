# Endpoints and protocol contracts

Only endpoints that are actually implemented. Planned ones are listed in [compatibility.md](compatibility.md) and [plan.md](plan.md).

## Operations (M0)

### `GET /healthz`

Process is alive. Does not check dependencies.

```http
HTTP/1.1 200 OK
content-type: application/json
x-request-id: <uuid>

{"status":"ok"}
```

### `GET /readyz`

Database responds and the data directory is writable.

| State | Status | Body |
|---|---|---|
| ready | `200` | `{"status":"ok"}` |
| not ready | `503` | `{"status":"unavailable"}` |

Causes are only logged (with request ID), never returned.

## Common headers (all responses)

| Header | Value |
|---|---|
| `x-request-id` | UUID; an incoming value is adopted |
| `x-content-type-options` | `nosniff` |
| `referrer-policy` | `no-referrer` |

## WebDAV

Follows in M2.

## OCS and Login Flow

Follows in M4.
