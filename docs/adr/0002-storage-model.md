# ADR 0002: Storage model for files and metadata

- Status: **Accepted** (approval point 2, 2026-10-21)
- Date: 2026-10-21

## Context

Requirements: stable file IDs across rename/move, separation of logical and physical paths, versioning, atomic writes, protection against path traversal, recursive folder ETags, consistent behavior on crashes.

## Decision

### Contents as immutable blobs

- Every file content is a **blob** with a random ID (ULID). Physical path: `<data>/blobs/<id[0..2]>/<id[2..4]>/<id>`. No part of the path comes from user input.
- Blobs are never modified. A modified file gets a new blob; the old one stays as a version or is removed by garbage collection.
- Copies and versions may reference the same blob. A blob is deleted as soon as neither a node nor a version references it any more (mark-and-sweep in the background, no reference counters in the request path).
- No deduplication via content hashes (avoids hash collision questions and side channels between users). A BLAKE3 checksum is stored, for `OC-Checksum` and integrity checking.

### Metadata in the database

- The `nodes` table models the tree: `id`, `owner_id`, `parent_id`, `name`, `name_key` (NFC, for uniqueness), `kind` (file/dir), `size`, `mtime`, `etag`, `blob_id`, `checksum`, `created_at`, `updated_at`.
- Uniqueness: `UNIQUE(parent_id, name_key)`.
- Every user has a root node. Shares are represented via mount points in the recipient's view, not by copying.
- The public **file ID** (`oc:fileid`) is the numeric `nodes.id` (Nextcloud clients expect numbers); `oc:id` is the form padded with an instance ID, as Nextcloud builds it (verify exact format in M5).
- ETag: random value per node, renewed on every change. When something in a folder changes, the ETags of all ancestors are renewed in the same transaction (cost O(depth)).

### Write flow (PUT, chunk assembly)

1. Stream into a temporary file under `<data>/tmp/` (same file system), computing size and BLAKE3 on the fly and continuously checking quota and size limit.
2. `fsync` the file, atomic `rename` to `blobs/…`, `fsync` the directory.
3. Database transaction: check `If-Match`/`If-None-Match`, insert the blob, store the old blob as a version (if versioning is active), update the node, renew the ancestors' ETags, adjust the quota counter.
4. Commit. If step 3 fails, only an unreferenced blob remains, which cleanup removes.

Invariant: **The database never references a blob that is not completely on disk.**

### Delete, move, copy

- DELETE: remove nodes (recursively) in one transaction or, later, move them to the trash; cleanup removes the blobs.
- MOVE: pure metadata operation, the file ID is preserved.
- COPY: new nodes with new IDs that reference the same blobs.

### Database

- SQLite by default in WAL mode, `busy_timeout`, foreign keys enabled. Writes are serialized; uploads block the database only in step 3.
- PostgreSQL optional for larger installations, same schema via `sqlx` migrations.

## Consequences

- Physical storage is not readable without the database. Backups must capture the database and the blob directory together (procedure in `docs/deployment.md`).
- Direct access to files via the host file system is not intended; import goes through `rostdav admin import`.
- A consistency check (`rostdav admin fsck`) compares the database and the blob directory.

## Alternatives

- **Mirroring the logical tree in the file system:** easier to inspect, but paths derived from user input, problems with Unicode and case sensitivity per file system, non-atomic folder renames. Rejected.
- **Object storage (S3) as the first storage:** possible later via the storage trait, not in the prototype.
