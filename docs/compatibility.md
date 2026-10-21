# Nextcloud compatibility

> Status: **server side recorded, app side not yet.** M3 recorded a real Nextcloud server with *synthetic* requests (written by `scripts/record_nextcloud.py`, not sent by the Android app). Responses are authentic; what the app actually sends is still open. Every statement names its source: client code (repository, file, line, version), Nextcloud documentation (URL) or fixture (`tests/fixtures/nextcloud/…`).

## Reference versions

| Component | Version | Fixed on |
|---|---|---|
| Nextcloud Android | [enter when M3 starts] | |
| Nextcloud iOS | optional, later | |
| Nextcloud server for recordings | 35.0.2 (`nextcloud:apache` Docker image, SQLite) | 2026-10-21 |
| Reported server version (`status.php`) | [to be entered] | |

## Supported flows

| Flow | Status | Contract test | Device test | Source |
|---|---|---|---|---|
| Add server (`status.php`) | contract test green | `crates/rostdav/tests/signin.rs` | – | `01-discovery/01-status` |
| Sign-in via Login Flow v2 | contract test green (shapes only) | `signin.rs` | – | `02-login-flow-v2/` |
| List folder | contract test green (property sets) | `nextcloud_dav.rs` | – | `04-webdav/01`, `16` |
| Upload file (small) | contract test green | `crates/rostdav/tests/nextcloud_dav.rs` | – | `04-webdav/10`, `08-m5-probes/` |
| Upload file (> 100 MB, chunked upload v2) | contract test green (105 MiB) | `nextcloud_dav.rs` | – | `05-chunked-upload/`, `08-m5-probes/` |
| Download | contract test green | `dav.rs`, `nextcloud_dav.rs` | – | `04-webdav/17`–`19` |
| Rename, move | contract test green | `nextcloud_dav.rs` | – | `04-webdav/23`–`26` |
| Delete | contract test green | `dav.rs` | – | `04-webdav/27`–`29` |
| Sign out / revoke app password | contract test green | `signin.rs` | – | `07-logout/` |

Status: `open` · `implemented` · `contract test green` · `device test passed`

## Recording setup

```sh
docker run -d --name nc-ref -p 127.0.0.1:18081:80 -e SQLITE_DATABASE=nc \
  -e NEXTCLOUD_ADMIN_USER=admin -e NEXTCLOUD_ADMIN_PASSWORD=admin-ref-password-1 \
  -e NEXTCLOUD_TRUSTED_DOMAINS="localhost:18081 127.0.0.1:18081" nextcloud:apache
python3 scripts/record_nextcloud.py      # rewrites tests/fixtures/nextcloud/
```

Fixtures are JSON (`request`, `response`, `note`), sanitized: host → `{{host}}`, passwords/tokens/cookies replaced by placeholders, HTML pages reduced to status, headers and length. Dates, ETags and file IDs are real values and must be ignored or normalized by contract tests. The instance ID in `oc:id` / `OC-FileId` (`00000125ocb0ngxhatbv`) is not a secret.

## Findings (server side, Nextcloud 35.0.2)

Each line cites its fixture below `tests/fixtures/nextcloud/`. "Differs" marks where Rostdav M2 behaves differently; these are inputs for M4/M5, not yet decisions.

### Discovery and login

- `GET /status.php` → 200 JSON `installed, maintenance, needsDbUpgrade, version, versionstring, edition, productname, extendedSupport` (`01-discovery/01-status`).
- `GET /` → 302; `/.well-known/caldav` → 301 (`01-discovery/03`, `04`).
- Login Flow v2: `POST /index.php/login/v2` → 200 `{poll:{token,endpoint}, login}`; `POST <endpoint>` with `token=…` → **404** until granted, then **200** `{server, loginName, appPassword}` (`02-login-flow-v2/01`, `02`, `08`). The `login` URL redirects (303) to `/login/v2/flow`; the browser then logs in via `POST /login` (needs `Origin`/`Referer` and a `requesttoken` or it answers `invalidOrigin`), lands on `/login/v2/grant` and confirms with `POST /login/v2/grant` (`stateToken`, `requesttoken` header) (`02-login-flow-v2/03`–`07`).

### OCS

- Requests without `OCS-APIRequest: true` → **412** `{"message":"CSRF check failed"}` (`03-ocs/03`).
- Not logged in / wrong password → HTTP 401, body `{"ocs":{"meta":{"status":"failure","statuscode":997,"message":"Current user is not logged in"|"Unauthorised"},"data":[]}}`, no `WWW-Authenticate` (`03-ocs/07`, `08`).
- `capabilities` lists `core, dav, files, files_sharing, notifications, …`. Relevant: `core.webdav-root = remote.php/webdav`, `dav.chunking = "1.0"`, `files.bigfilechunking = true`, `files.chunked_upload = {max_size: 104857600, max_parallel_count: 5}`, `files.forbidden_filename_extensions = [".filepart", ".part"]` (`03-ocs/01`).
- `cloud/user` returns `id, displayname, email, quota{free,used,total,relative,quota}, groups, language, …` (`03-ocs/04`).

### WebDAV

- Error bodies are Sabre XML: `<d:error xmlns:d="DAV:" xmlns:s="http://sabredav.org/ns"><s:exception>…</s:exception><s:message>…</s:message></d:error>` (`04-webdav/08`, `13`, `05`). Rostdav M2 sends empty bodies. Open: which parts the app evaluates.
- 401 on WebDAV: `WWW-Authenticate: Basic realm="Nextcloud", charset="UTF-8"` (`04-webdav/06`).
- `OPTIONS`: `DAV: 1, 3, extended-mkcol, access-control, …, 2`; `Allow` includes `PROPPATCH, REPORT, LOCK, UNLOCK` (`04-webdav/32`). Differs: Rostdav advertises class 1 only.
- PROPFIND: `oc:id` / `OC-FileId` = 8-digit zero-padded numeric ID + instance ID (`00000078ocb0ngxhatbv`), `oc:fileid` = plain number, `oc:permissions` e.g. `RGDNVCK` (dir) / `RGDNVW` (file), ETag on files is an MD5-like string, on folders a short hex string (`04-webdav/16`). Properties the server does not have come back in a 404 `propstat`.
- `PROPFIND Depth: infinity` → 207 without entries (`04-webdav/04`). Differs: Rostdav answers 403 `propfind-finite-depth`.
- `PUT`: 201 new / 204 replace; response headers `OC-FileId`, `ETag`, `OC-ETag`, `X-OC-MTime: accepted` (`04-webdav/10`, `11`). Differs: Rostdav sets only `ETag`.
- `PUT` into a missing parent → **404** (`04-webdav/12`); `MKCOL` into a missing parent → 409 (`04-webdav/09`). Differs: Rostdav answers 409 for both.
- `MKCOL` on an existing name → 405 (`04-webdav/08`); `If-None-Match: *` on an existing file → 412 (`04-webdav/13`); stale `If-Match` → 412 (`04-webdav/14`); stale `If-Match` on DELETE → 412 (`04-webdav/27`).
- `GET` on a directory → **200** `text/html` (`04-webdav/21`). Differs: Rostdav answers 405.
- `MOVE` with `Overwrite: F` onto an existing target → 412 (`04-webdav/24`). A `Destination` with a foreign host is **accepted** (path only is used, 201) (`04-webdav/25`). Differs: Rostdav answers 502.
- URL user ≠ authenticated user → 404 "Principal with name … not found" (`04-webdav/30`). Differs: Rostdav answers 403.
- `..` in the path → 404 (`04-webdav/31`).
- Legacy `/remote.php/webdav/` answers PROPFIND with 207 (`04-webdav/33`). `SEARCH` probe with an empty request → 400 (`04-webdav/34`).
- Observed oddity: `PUT` with an invalid `OC-Checksum` answered 423 "is locked" (`04-webdav/15`). Cause unknown; do not copy.

### Chunked upload (v2)

- `MKCOL /remote.php/dav/uploads/{user}/{id}` (headers `Destination`, `OC-Total-Length`) → 201; chunks `PUT …/{id}/{00001}` → 201; `MOVE …/{id}/.file` with `Destination`, `OC-Total-Length`, `X-OC-MTime` → 201 and the assembled file is readable; the session folder is gone afterwards (404) (`05-chunked-upload/01`–`07`).
- Total length mismatch on assembly → 400 Sabre `BadRequest` "Chunks on server do not sum up to 50 but to 10 bytes" (`05-chunked-upload/10`). `DELETE` of a session → 204 (`11`).

### Other endpoints

- `core/preview` → 404 without body; avatar → 200 PNG (`06-misc/01`, `02`). `notifications`, `activity`, `dashboard` answer 200, `user_status` 404 or 200 depending on app state (`06-misc/03`–`06`). Rostdav must not advertise these in the capabilities.

### Sign-out

- `DELETE /ocs/v2.php/core/apppassword` → 200; the revoked app password is rejected afterwards with 401 on WebDAV and OCS (`07-logout/01`–`03`).

## Known endpoints

Initial list from section 3.2 of the instructions. None of this is confirmed until a source is entered.

| Endpoint | Purpose | Recorded (server) | Source |
|---|---|---|---|
| `GET /status.php` | Server discovery | yes | `01-discovery/01-status` |
| `POST /index.php/login/v2`, `POST /login/v2/poll` | Login Flow v2 | yes | `02-login-flow-v2/` |
| `GET /ocs/v2.php/cloud/capabilities` | Capabilities | yes | `03-ocs/01` |
| `GET /ocs/v2.php/cloud/user` | User info | yes | `03-ocs/04` |
| `/remote.php/dav/files/{userId}/` | Files | yes | `04-webdav/` |
| `/remote.php/webdav/` | Legacy path | yes (answers) | `04-webdav/33`; whether the app still uses it: open |
| `/remote.php/dav/uploads/{userId}/{transferId}/` | Chunked Upload | yes | `05-chunked-upload/` |

## Implemented in M4 and known gaps

- `status.php`, `capabilities` (only `version` and `core.{pollinterval, webdav-root}`), `cloud/user` (subset of the reference fields; tests fail on any field the reference does not have), `DELETE core/apppassword`, Login Flow v2 start/poll/page. Contract tests compare against the fixtures above.
- Not recorded, therefore chosen by us: the body of the 429 response (OCS failure code 429, `Retry-After` set), the v1 variant of the 401 body (same as v2), the 400 answer for sign-out with the account password.
- The reference redirects `/login/v2/flow/{token}` (303) to a Vue login page and needs a second step to grant; Rostdav serves one form (allow/deny) directly. Whether the app cares is open until M6.
- Capabilities deliberately omit `files`, `dav` (chunking), sharing, notifications, etc. until implemented (M5+). Whether the Android app starts without `files.*` capabilities is open until M6.
- `/remote.php/webdav/` is served (maps to the signed-in user) because `core.webdav-root` points to it.

## Implemented in M5 and known gaps

Values and sets come from the fixtures; `crates/rostdav/tests/nextcloud_dav.rs` compares them.

- **Properties:** `oc:id` (8-digit file ID + instance ID, e.g. `00000042ocabc123def4`), `oc:fileid`, `oc:size` (folders: sum below), `oc:permissions` (`RGDNVCK` folders, `RGDNVW` files, owner only), `oc:favorite` (`0`), `oc:owner-id`, `oc:owner-display-name`, `oc:share-types` (empty), `oc:checksums` (files with a client checksum), `oc:downloadURL` (files, empty), `nc:has-preview` (`false`: no previews exist), `nc:mount-type` (empty), `nc:creation_time` (`0`), `nc:upload_time` (files), `d:quota-used-bytes` / `d:quota-available-bytes` (folders only, `-3` = unlimited). Unknown properties, `nc:is-encrypted` and folder-only/file-only mismatches answer 404 in their own `propstat`. `allprop` returns the reference's sets (`04-webdav/03`: folders get quota properties, no content length).
- **Headers:** `PUT` returns `OC-FileId`, `ETag`, `OC-ETag` (and `X-OC-MTime: accepted` when sent); `MKCOL` and `COPY` return `OC-FileId`; `MOVE` returns `OC-ETag`, `ETag`, `OC-FileId`; `GET`/`HEAD` add `OC-ETag`.
- **`X-OC-MTime`** sets the modification time. **`OC-Checksum`** is stored verbatim and reported; like the reference (`08-m5-probes/03`–`09`) it is **not verified**, any algorithm and even wrong digests are accepted. Values that are not `ALGO:hex` are ignored.
- **Errors:** Sabre XML bodies (`<d:error><s:exception>Sabre\DAV\Exception\…</s:exception><s:message>…</s:message></d:error>`). Exception classes seen in the fixtures: `NotFound`, `Conflict`, `MethodNotAllowed`, `PreconditionFailed`, `BadRequest`, `NotAuthenticated`. Not recorded and taken from Sabre's class names: `Forbidden`, `InsufficientStorage` (507), `PayloadTooLarge`, `Locked`, `TooManyRequests`, `ServiceUnavailable`.
- **Aligned with the reference** (differences found in M3, fixed here): `PUT` into a missing parent → 404 (`MKCOL` stays 409); another user's URL space → 404; the host of `Destination` is ignored; `.part`/`.filepart` names, `\`, control characters and over-long names → 400 with the reference messages.
- **Chunked upload v2** (`/remote.php/dav/uploads/<user>/<id>`): `MKCOL` 201 (405 if it exists), `PUT <chunk>` 201/204, `PROPFIND` lists `.file` and chunks, `MOVE .file` with `Destination`, `Overwrite`, `OC-Total-Length`, `X-OC-MTime` assembles (201, or 204 when replacing), `DELETE` 204, other users' sessions are 404, listing all sessions is 405. Chunks are joined in natural name order (numbers by value). Capabilities advertise `dav.chunking = "1.0"`, `files.chunked_upload.{max_size, max_parallel_count}` and `files.forbidden_filename_extensions`. Sessions older than 24 h are removed by the garbage collector.
- **Previews and avatars:** `core/preview` and `avatar` answer 404 without body. The reference serves an avatar image; Rostdav has none. How the app reacts is open until M6.

Known differences that remain, all open for M6:

| Reference | Rostdav | Why |
|---|---|---|
| `GET` on a folder → 200 HTML | 405 | no web UI yet |
| `PROPFIND Depth: infinity` → 207, no entries | 403 `propfind-finite-depth` | RFC 4918 allows refusing; avoids unbounded work |
| `OPTIONS`: `DAV: 1, 3, extended-mkcol, …`; `Allow` incl. `PROPPATCH, REPORT, LOCK, UNLOCK` | `DAV: 1` | only advertise what is implemented |
| Failed assembly with `Overwrite: F` (412) destroys the session | session is kept | safer for retries |
| Chunk assembly with a missing `Destination` → 500 | 400 | reference answer is an internal error |
| `X-OC-MTime` garbage → 500 | 400 | same |
| `.htaccess` upload → 500 "Invalid path" | allowed | not a PHP server |
| `nc:has-preview` true for text files | `false` | no previews |
| `nc:creation_time` `0` | `0` | same, upload time is separate |
| `PROPPATCH`, `REPORT`, `SEARCH`, `LOCK` | 405 | not implemented |
| Chunk file names: anything | `[A-Za-z0-9_-]{1,32}` | names must never form paths |

## Not supported

| Feature | App behavior without support | Source |
|---|---|---|
| Preview images | server answers 404 (`06-misc/01`); app behavior: observe in M6 | |
| Notifications, activities, push | [observe] | |
| End-to-end encryption | [observe] | |
| Talk, calendar, contacts | not planned | |

## Open questions

- `oc:id` format is now known from the server (8-digit padded file ID + instance ID, `04-webdav/16`); whether the app depends on it: open.
- Error XML format for WebDAV errors that the app evaluates.
- Which minimum version does the app require, and how does it react to older versions?
- Behavior of the app when two-factor authentication is enabled in the login flow.
