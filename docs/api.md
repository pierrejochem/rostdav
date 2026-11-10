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

## RustMFA device API

Used by the RustMFA Android app ([ADR 0014](adr/0014-push-mfa.md)). The machine-readable contract is `rustmfa-v1.yaml` in the `rostdav-mfa` repository; its JSON mirror is exported by the `rustmfa-contract` crate and is what the tests read. All paths are under `/api/v1`. Bodies are JSON, at most 64 KiB, and fields the contract does not name are refused. Every response has `cache-control: no-store`.

**Signing.** Every route except registration needs

```http
Authorization: RustMFA-Sig device_id="…",ts="…",nonce="…",sig="…"
```

`ts` is Unix seconds (at most 60 seconds from the server clock). A `nonce` is accepted once per device in 5 minutes. `sig` is the raw 64-byte R‖S ES256 signature, base64url without padding, made with the phone's request key over `METHOD \n path-and-query \n ts \n nonce \n base64url(sha256(body))`. The path and query are the ones the phone sent, as received. Exactly one `Authorization` header counts. Five failures for one device in 15 minutes block it for 15 minutes.

| Route | Needs | Success | Purpose |
|---|---|---|---|
| `POST /devices/register` | enrollment token in the body | `201` `{device_id, status}` | Register a phone with its two public keys and key attestation |
| `GET /devices` | signature | `200` `{devices}` | The caller's phones |
| `DELETE /devices/{device_id}` | signature | `204` | Revoke a phone of the caller's account (also ends its open approvals) |
| `PUT /devices/{device_id}/push-token` | signature, own device | `200` `{device_id, status}` | Change push channel and token |
| `POST /devices/{device_id}/rotate-key` | signature, own device | `200` `{device_id, status}` | Replace both keys (needs a fresh attestation) |
| `GET /mfa/challenges?status=pending` | signature | `200` `{challenges}` | Open approvals of the phone; only `pending` can be listed |
| `GET /mfa/challenges/{challenge_id}` | signature | `200` | Details of one approval, with three candidate numbers and no marker of the right one |
| `POST /mfa/challenges/{challenge_id}/approve` | signature, approval-key signature in the body | `200` `{challenge_id, status}` | Approve with the picked number |
| `POST /mfa/challenges/{challenge_id}/deny` | signature, approval-key signature in the body | `200` `{challenge_id, status}` | Deny |
| `GET /audit` | signature | `200` `{events}` | The user's own security events |

Creating an enrollment token is a web-session route and not part of this API yet. Creating a challenge is not an HTTP operation: the sign-in code of the server does it.

**Errors.** `{"error":{"code","message"}}`; messages never hold keys, tokens or signatures.

| Status | Code | When |
|---|---|---|
| 400 | `INVALID_REQUEST` | Malformed body, unknown field, bad query, bad key or signature encoding, failed attestation |
| 401 | `UNAUTHENTICATED` | Missing, malformed or wrong signature, stale timestamp, replayed nonce, unknown phone, disabled account |
| 403 | `DEVICE_NOT_AUTHORIZED` | The approval signature does not verify, or the request names another phone |
| 403 | `DEVICE_REVOKED` | The phone was revoked (shown only to a caller whose request signature verified) |
| 404 | `RESOURCE_NOT_FOUND` | Unknown challenge or phone, or one that belongs to another user (the same answer) |
| 409 | `CHALLENGE_ALREADY_CONSUMED` | The approval was already answered |
| 409 | `CHALLENGE_NUMBER_MISMATCH` | Wrong number; the approval is now denied |
| 410 | `CHALLENGE_EXPIRED` | The time ran out |
| 413 | `INVALID_REQUEST` | Body over 64 KiB |
| 429 | `RATE_LIMITED` | Too many attempts; `Retry-After` gives the seconds |
| 500 | `INTERNAL_ERROR` | Cause only in the log |

## WebDAV

Follows in M2.

## OCS and Login Flow

Follows in M4.
