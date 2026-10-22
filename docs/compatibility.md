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

- **Properties:** `oc:id` (8-digit file ID + instance ID, e.g. `00000042ocabc123def4`), `oc:fileid`, `oc:size` (folders: sum below), `oc:permissions` (`RGDNVCK` folders, `RGDNVW` files, owner only), `oc:favorite` (`0`/`1`, per user, see Favorites), `oc:owner-id`, `oc:owner-display-name`, `oc:share-types` (empty), `oc:checksums` (files with a client checksum), `oc:downloadURL` (files, empty), `nc:has-preview` (`false`: no previews exist), `nc:mount-type` (empty), `nc:creation_time` (`0`), `nc:upload_time` (files), `d:quota-used-bytes` / `d:quota-available-bytes` (folders only, `-3` = unlimited). Unknown properties, `nc:is-encrypted` and folder-only/file-only mismatches answer 404 in their own `propstat`. `allprop` returns the reference's sets (`04-webdav/03`: folders get quota properties, no content length).
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

## Implemented in M8: versions

Source: `tests/fixtures/nextcloud/09-versions/` (recorded with `scripts/record_nextcloud_extra.py versions`), compared by `crates/rostdav/tests/versions.rs`.

- **Policy:** an overwrite (PUT, chunked assembly, import) keeps the previous content as a version unless it is identical (same checksum). Versions count toward the user's quota (documented decision, `docs/instructions.md` 2.4), also in `quota-used-bytes` of the root folder. Limits: `[versioning]` (`max_versions` per file, `max_age_days`, `max_quota_share_percent`), applied on write and by the background cleanup. Copies get no history; a move keeps it; deleting a file deletes its versions (trash comes in M10).
- **Capabilities:** `files.versioning` and `files.version_deletion` are advertised only while versioning is enabled. `files.version_labeling` is not: `PROPPATCH` is not implemented.
- **Endpoint** `/remote.php/dav/versions/<user>/`: collection with `versions/` and `restore/`; `versions/<file id>/` lists one entry per archived version **and the live content**, ascending by name; the name of a version is the modification time of its content (moved to the next free second if two versions of a file share a time). Entries have `getlastmodified`, `getcontentlength`, `getcontenttype`, `getetag` (the plain name, unquoted, as in the reference), `resourcetype` and `nc:version-author`; `nc:version-label` and `oc:fileid` answer 404. `GET`/`HEAD` return the content with `ETag`/`OC-ETag` = name and support ranges. `DELETE` removes an archived version (404 if it does not exist). `MOVE` to `.../restore/target` restores: the version becomes the live content (with its modification time) and the replaced content is archived. File IDs are the plain numeric IDs (`oc:fileid`), not the padded `oc:id`.
- **Errors:** another user's space or file, unknown file or version, non-numeric names → 404; `PUT`/`MKCOL` below `versions/` → 403.

| Reference | Rostdav | Why |
|---|---|---|
| `GET` of the live entry → 404 (but `HEAD` → 200) | 200 with the content | looks like an oversight; harmless |
| `DELETE` of the live entry → 204 and unclear effect | 403 | the live file must not vanish this way |
| `MOVE` to any destination other than `restore/target` → 201 and the version is moved out as a file | 400 | not needed; avoids surprising data movement |
| `MOVE` without `Destination` → 500 (`TypeError`) | 400 | |
| `Depth: infinity` → 207 | 403 | as for files |
| `PROPPATCH` of `nc:version-label` | 405 | not implemented |
| Versions of a deleted file stay reachable through the trash | gone with the file | M10 |
| Identical re-upload still creates a version (not recorded) | no new version | saves space |

## Implemented in M9: shares

Source: `tests/fixtures/nextcloud/10-shares/` (`scripts/record_nextcloud_extra.py shares`), compared by `crates/rostdav/tests/sharing.rs`; design and decisions in [ADR 0004](adr/0004-shares-and-permissions.md).

- **OCS Sharing API** (`/ocs/v{1,2}.php/apps/files_sharing/api/v1/`): `POST/GET shares` (by path, `subfiles`, `shared_with_me`), `GET/PUT/DELETE shares/{id}`, `GET shares/pending` (always empty), `GET sharees`. Status codes and messages are the reference's ("Cannot share with yourself", "Wrong path, file/folder does not exist", ...). The share object is a subset of the reference's fields (`storage`, `storage_id` are left out). `GET shares/{id}` answers with a one-element list, like the reference.
- **Share types:** user (0) and public link (3). No groups, federation, mail, circles or talk.
- **Permissions:** bits read 1, update 2, create 4, delete 8. Bit 16 (share) is accepted and ignored, so `31` is stored and reported as `15`; resharing is refused with 403 "Resharing is not allowed". Files keep only read/update. A link may be create-only (`4`, "file drop"); user shares need read.
- **Mount points:** the recipient's root lists each share under the shared item's name (a free name: `Docs (2)` if taken). Properties as in the reference: `oc:permissions` starts with `S`, `nc:mount-type` = `shared`, `nc:is-mount-root` = `true` on the root only, `oc:owner-id` = owner, `oc:share-types` on the mount root and on the owner's shared node. The recipient may rename a mount (`MOVE` inside the root) and leave it (`DELETE`, which ends the share for the owner too). The root ETag of a user with mounts is derived from all mounted ETags, so clients notice changes inside shares.
- **Writes** need the right bit: create (4) for new files/folders, update (2) to overwrite, delete (8) to delete; renaming needs delete + create. Denied writes answer **403**; things you may not see answer **404**. Quota and versions of writes into a share belong to the **owner**. Copies may cross trees (the copy belongs to the destination owner); **moves across trees are refused (409)**.
- **Public links:** `/public.php/webdav/` with `Authorization: Basic <token>:<password>` (password empty if none); the shared node is the root (a file link serves the file as `/`). Tokens are 24 random characters; passwords are Argon2id hashes and never shown (`"password": "protected"`); failures count per address and per link (429 after 10). Expired or deleted links answer 401.
- **Not for links/recipients:** versions, chunked uploads (sessions are the signed-in user's), OCS user data, share management. A link cannot reach any user namespace and a user cannot use the public one.
- **Events:** `share.created` and `share.revoked` (owner or recipient) go to the event log.

| Reference | Rostdav | Why |
|---|---|---|
| Resharing (`R` letter, share bit) | refused; the `R` letter appears only on the owner's own items | ADR 0004 |
| Read-only link shows `RG` | `G` | no resharing |
| `password` of a link share: the hash | `"protected"` | never expose hashes |
| Link web page `/s/<token>` | 404 until M11 | scope |
| Pending shares | always empty | shares are active immediately |
| Groups, federation, mail shares | not offered | scope |
| Duplicate user share: returns the existing share | same | |
| Create-only link reveals nothing about existing names in the reference | a PUT onto an existing name is 403 instead of 201 (reveals existence) | accepted, documented |

## Implemented in M10: trash

Source: `tests/fixtures/nextcloud/11-trash/` (`scripts/record_nextcloud_extra.py trash`), compared by `crates/rostdav/tests/trash.rs`; design in [ADR 0005](adr/0005-trash.md).

- **Behavior:** `DELETE` of a file or folder moves it to the owner's trash (when `[trash] enabled`, default). Its space (and that of its versions) keeps counting toward the quota until the item is purged. Items are purged by `DELETE`, by emptying, or by `[trash] retention_days` (30). Restoring brings back the item under its old parent (else the root), with the same file ID, its versions and its shares; a taken name becomes `name (restored).ext`.
- **Capabilities:** `files.undelete` and `files.delete_from_trash` while the trash is enabled.
- **Endpoint** `/remote.php/dav/trashbin/<user>/`: members `restore/` and `trash/`; each item is `trash/<name>.d<deletion time>` (folders end in `/`) with `nc:trashbin-filename`, `-original-location` (no leading slash), `-deletion-time`, `-title`, `-deleted-by-id`, `-deleted-by-display-name`, `getlastmodified` (the deletion time), `getcontentlength`/`getcontenttype` (files), `getetag` (empty for files, the deletion time for folders), `oc:fileid` and `oc:id` (the plain number), `oc:size`, `oc:permissions` = `GD`, `nc:has-preview` = `false`. `GET`/`HEAD` with ranges read files; folders can be browsed (`PROPFIND`, `GET` below them). `MOVE trash/<item>` to `restore/<anything>` restores (201), `DELETE trash/<item>` purges (204), `DELETE trash/` empties (204). `PUT`/`MKCOL`/`COPY` → 403, other users' trash → 404.
- **Shares:** deletions by recipients or through editable links go to the **owner's** trash (recorded as `deleted-by`); the recipient's trash is not filled. A share on a trashed folder (or of something inside it) is inactive while it is in the trash and active again after the restore.

| Reference | Rostdav | Why |
|---|---|---|
| Deleted by a recipient: item appears in the recipient's trash and in the owner's | only the owner's | recipients cannot restore things they do not own |
| `MOVE` of an item to any destination → the item is moved there | 400 unless `…/restore/*` | avoids surprising data movement |
| `MOVE` without `Destination` → 500 (`TypeError`) | 400 | |
| `Depth: infinity` → 207 | 403 | as elsewhere |
| `nc:has-preview` true for text files | `false` | no previews |
| `ETag` header of a trashed file empty | not sent | |
| Name conflict on restore: not recorded | `name (restored).ext` | chosen |
| `MOVE`/`COPY` with `Overwrite: T` over an existing file | the replaced file is deleted for good | not recorded for the reference |

## Implemented in M12: two-factor authentication

Source: requirements (Nextcloud behaviour as described in `docs/instructions.md`), [ADR 0007](adr/0007-two-factor-authentication.md); **not** recorded from the reference server or the real app.

| Topic | Behaviour here | Status |
|---|---|---|
| App passwords and Login Flow polling | Unchanged; they bypass 2FA | by design, as in Nextcloud |
| Account password via Basic on WebDAV/OCS with 2FA on | Rejected (401) | tested here; the real app's reaction is **not tested** |
| Capabilities | Nothing added, so the app starts no 2FA flow of its own | as intended |
| Login Flow page with 2FA | Second step on the page (code or recovery code) before the app password is granted | tested here; the real app was not used |

To check in M6 (emulator): connect the Nextcloud app to an account with 2FA on (through the Login Flow page) and use it afterwards.

## M6: the real Android app (Nextcloud Android 35.0.1, Android 15 emulator, 2026-10-22)

Server address entered as `http://10.0.2.2:8081`. The app was driven through `adb`; every row below was seen, not assumed.

| Step | Finding | Fix |
|---|---|---|
| Server check | The app sends `HEAD /remote.php/dav` and says "Server not found" unless it gets 401 (not signed in). Rostdav answered 404 | `/remote.php/dav[/]`: 401 for strangers; GET/HEAD 200 text, OPTIONS 200, PROPFIND 207 for signed-in users (as the reference) |
| Right after the sign-in | `HEAD /remote.php/dav/files/<user>/` got 405; the app then **restarted the whole login** (endless loop) | GET/HEAD on a collection answer 200 with the one-line text, as the reference |
| Login Flow in the app's browser tab | The page renders and works; the app polls after the tab is closed | none; the client name shown is the whole user agent (`Mozilla/5.0 (Android) Nextcloud-android/35.0.1`) |
| After the sign-in | File list (PROPFIND), capabilities, user info work; avatar, notifications and recommendations answer 404 and the app shrugs them off | none |
| Connectivity probe | `GET /index.php/204` answered 404: the app saw a captive portal, cached that and created folders offline without any MKCOL. Reference: 204 without authentication | route added (`tests/signin.rs`); the app caches the verdict, restart it after a server fix |
| Create folder | `MKCOL` 201 | none |
| Upload 1 KB | `PUT` 201, hash identical | none |
| Upload 30 MB | chunked v2: `MKCOL uploads/…`, `PUT …/000001`, `MOVE …/.file` 201, hash identical | none |
| Download 30 MB | `GET` 200, hash identical on the device | none |
| Rename | `MOVE` 201 | none |
| Delete | `DELETE` 204, file appears in `trashbin/<user>/trash` | none |
| Favorite | `PROPPATCH` on the file answered 405 (`oc:favorite` was always 0, the Favorites tab needs `REPORT` `oc:filter-files`) | implemented, see Favorites below; seen with the app: `PROPPATCH` 207 on the folder, star and Favorites tab show it (the app did not send a `REPORT` in this run) |
| Capabilities | The app's parser throws `No value for bigfilechunking` and then stores **no** capabilities at all (so undelete, versioning and sharing options stay off). Reference sends `files.bigfilechunking: true` | `files.bigfilechunking: false` added (old chunking is not implemented, only v2); test in `tests/signin.rs`; capabilities parse now ("Get Capabilities completed") |
| Share with a user | Sharee search (`sharees`) finds bob; `POST shares`, `GET/PUT shares/1` all 200; bob sees `/Docs` (permissions 15) in `shared_with_me`, lists it and writes `from-bob.txt` into it; the owner sees the new file | none |
| Trash in the app | After the capabilities fix the left sidebar still has no "Deleted files" entry (the app version may hide it or it lives elsewhere); trash restore through the app is **not verified**; the trashbin is covered by `tests/trash.rs` against reference fixtures | open |
| Login Flow with 2FA | Account with two-factor on: the flow page asks user and password, then "Confirm your sign-in" with the six-digit code; after the code "Device connected"; closing the tab, the app lists the account's files. The account password alone on WebDAV answers 401 (ADR 0007) | none |
| Public link | "Create link" on a folder: `POST shares` 200, `GET shares/2` 200; the returned URL `http://10.0.2.2:8081/s/<token>` opens the public page (200) and `public.php/webdav` answers 207 with the token as user; permissions 1 (read) | none |
| Offline, then reconnect | Server stopped, 2 KB file queued for upload in the app, server started again: the app retried by itself (`HEAD` 404, `PUT` 201, `PROPFIND` 207) within 90 s, hash identical | none |

Both bugs were invisible to the contract tests because the fixtures contained neither request.

## Favorites

Source: Nextcloud 35.0.2 reference, 2026-10-23, and the Android app (M6).

- `PROPPATCH` with `oc:favorite` `1`/`0`: 207, the property in a 200 `propstat` (as the reference). The mark is per user (table `favorites`, migration 0010) and works on every node the user can read.
- `PROPFIND` `oc:favorite`: `1` or `0` for the caller.
- `REPORT` on a folder of the user with `oc:filter-files` and the rule `oc:favorite` = `1`: the caller's favorites below that folder, with the requested properties. Other filter rules answer 400.
- **Deviations:** the reference also stores arbitrary dead properties in `PROPPATCH`; Rostdav answers 403 for every property except `oc:favorite` rather than pretend. The `REPORT` lists favorites in the user's own tree only (not nodes received through shares).

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
