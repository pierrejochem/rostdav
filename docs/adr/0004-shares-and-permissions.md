# ADR 0004: Shares and the permission model

- Status: **Accepted** by the project owner on 2026-10-22 as proposed (no resharing; cross-owner MOVE refused, COPY allowed; link web page deferred to M11). Approval point 3 granted.
- Date: 2026-10-22
- Evidence: reference recordings `tests/fixtures/nextcloud/10-shares/` (Nextcloud 35.0.2, `scripts/record_nextcloud_extra.py shares`).

## Context

Until now a node is reachable only by its owner (`authorize()` compares owner IDs). M9 adds sharing with other users and public links, as the Nextcloud apps use them: the OCS Sharing API, shared folders that appear as *mount points* in the recipient's file tree, and `public.php/webdav` for links. This is the first time a user can reach nodes of somebody else, so the risk is wrong access. The plan names it as risky ("Rechtefehler"); the rules require a dedicated authorization matrix test.

## What the reference does (observed)

- **Permissions** are a bit mask: read 1, update 2, create 4, delete 8, share 16. Folders default to 31, files to 19/1. Invalid values → 403 "Valid permissions are required for sharing", no read bit → 403 "File share needs at least read permission." (`10-shares/14`, `55`).
- **Creating:** the path is resolved in the caller's own tree, so a non-owner gets 404 "Wrong path, file/folder does not exist" (`17`). Sharing with yourself → 403, unknown user → 404, unknown type → 400.
- **Recipient view:** the share appears in the recipient's root under the folder's name (a mount point): `oc:permissions` starts with `S`, `nc:mount-type` is `shared`, `nc:is-mount-root` is `true` on the root only, `oc:owner-id` is the owner (`29`, `30`). Read-only: the root shows `SGDN` (the recipient may still delete = leave, and rename the mount), writes below give **403** (`43`–`48`); create-only (5): new files yes, overwrite 403 (`52`, `53`). Copying out of a read-only share into your own space works (`49`).
- **Recipient actions:** renaming the mount point works and keeps the share (`60`–`63`); deleting it deletes the share for everybody (the owner's GET answers 404, `64`–`66`); changing a received share → 403 "You are not allowed to edit incoming shares" (`56`).
- **Owner actions:** moving the shared folder keeps the share (`96`, `97`); deleting it ends the share (`98`, `99`). Strangers get 404 everywhere (`39`, `40`, `20`).
- **Links:** `shareType=3` returns a token and `url` (`/s/<token>`); the DAV entry is `/public.php/webdav/` with Basic auth, user name = token, password = the link's password or empty; wrong token or missing password → 401 (`74`, `75`, `84`–`86`); read-only link: PUT → 403, with edit permission PUT works (`73`, `80`). Expiry in the past is rejected (`88`).

## Proposal

### Data

New table `shares` (migration 0006):

| column | meaning |
|---|---|
| `id` | share ID (the OCS ID) |
| `kind` | 0 = user, 3 = link |
| `owner_id` | who created it (always the node's owner: no resharing) |
| `node_id` | the shared file or folder, `ON DELETE CASCADE` (deleting the node ends the share, as in the reference) |
| `recipient_id` | user shares; `NULL` for links |
| `permissions` | 1–15 (bit 16, "share", is accepted but has no effect: no resharing) |
| `mount_name` | name of the mount point in the recipient's root (user shares) |
| `token`, `password_hash` | links: 24 random characters; Argon2id hash of the optional password |
| `expires_at`, `note`, `label`, `hide_download`, `created_at` | as in the OCS fields |

Unique: `(node_id, recipient_id)`, `token`, and the mount name per recipient root.

### Authorization

One function decides, in `rostdav-app`, on the *resolved* node (unchanged rule), but resolution now yields an **access grant**:

```
Access { node, perms: u8 (bits as above), origin: Own | Share(id) | Link(id) }
```

- Resolution of a path in a user's tree: the first segment is looked up among the user's own children and among their mount points. Below a mount point the walk happens inside the owner's tree and carries the share's `perms`. Own nodes carry 15 (+16 irrelevant). Nothing below the shared node can be left through `..` (segments are validated, parents are never followed upwards out of the shared node).
- Each operation names the bit it needs: read = 1; overwrite an existing file or change metadata = 2; create file/folder = 4; delete = 8; move = 8 on the source side and 4 on the destination side, both within the *same* access origin. Everything else is denied. The decision is `authorize(principal, &access, Needs::…)`; protocol crates only translate the error (403 for a visible-but-denied item, 404 for an invisible one, as recorded).
- **Cross-owner moves are refused** (409): moving between two trees would silently change ownership and quota. Copies across trees are allowed when the source has read and the destination has create: the new nodes belong to the destination owner and count against *their* quota.
- **Quota and versions of writes inside a share count against the node's owner**, as in the reference. A recipient writing into a full owner quota gets 507.
- Administrators get no implicit access to other users' files (unchanged).
- Links: the principal is `Link(share)`, authenticated by `Basic token:password` on `/public.php/webdav/`. It sees exactly the shared node as its root, with the link's permissions; failures count in the rate limiter (key: IP and token). Tokens and passwords are compared only through hashes/Argon2id; expired links answer 401/404 like unknown tokens.
- Mount points: the recipient's root listing adds them; a name that collides with an own child gets a numeric suffix at share creation; creating an own child with a mount's name is a conflict. The ETag of the recipient's root is derived from its own ETag and the ETags of all mounted nodes, so clients notice changes inside a share without any extra writes.
- Not included: groups, resharing, federation, share-by-mail, "pending" shares (the list endpoint answers empty), moving a mount point into a sub folder.

### API surface

`/ocs/v{1,2}.php/apps/files_sharing/api/v1/shares` (POST, GET list/by path/`shared_with_me`/`subfiles`, GET/PUT/DELETE by ID), `…/shares/pending`, `…/sharees`; share capabilities limited to what exists (`api_enabled`, `public.*` subset, `resharing: false`, `default_permissions`, `sharee`); DAV: mount points in `files/<user>/`, `public.php/webdav/`; web page `/s/<token>` (minimal download/list page, password form) in M11. Share events go to the event log (`share.created`, `share.revoked`).

### Tests that gate this milestone

An authorization matrix (owner, recipient with 1/3/5/7/15, link read/edit/create-only, link with wrong or missing password, stranger, admin, expired link) × (GET, HEAD, PROPFIND, PUT new, PUT overwrite, MKCOL, DELETE, MOVE inside, MOVE across trees, COPY out/in, versions list/restore/delete, chunked upload, OCS share management, share enumeration by ID), each with its expected status from the fixtures, plus path traversal through mount points and through `Destination` headers, and quota accounting to the owner.

## Decisions of the project owner (2026-10-22)

1. Resharing stays off; the apps send `permissions=31`, we store and report 15.
2. Cross-owner **move** is refused.
3. Public links in M9 are WebDAV + OCS only; the HTML page `/s/<token>` follows with the web UI (M11).

## Consequences

- `authorize()` grows from a single owner comparison to a small permission evaluation; every file-service function changes its signature to take an `Access`. This is the largest change to the security-critical path so far, hence the matrix test as acceptance criterion.
- A share survives renames and moves of the node but not its deletion; trash (M10) must decide whether a trashed node keeps its shares.
