# ADR 0005: Trash

- Status: **Accepted** (extends [ADR 0002](0002-storage-model.md), which announced a trash; no change to authentication, tokens or the permission model)
- Date: 2026-10-22
- Evidence: `tests/fixtures/nextcloud/11-trash/` (Nextcloud 35.0.2, `scripts/record_nextcloud_extra.py trash`).

## Context

Clients delete with `DELETE` and later list, restore or purge through `/remote.php/dav/trashbin/<user>/`. Versions and shares of a deleted file must come back with it, deleted folders must come back with their content, and space must keep counting until the trash is emptied.

## What the reference does (observed)

- `trashbin/<user>/` has two members, `trash/` and `restore/` (`10-trash-root-d1-empty`).
- Each deleted item is `trash/<name>.d<deletion unix time>` (folders with a trailing slash). Properties: `nc:trashbin-filename`, `-original-location` (`folder/a.txt`, no leading slash), `-deletion-time`, `-title`, `-deleted-by-id`, `-deleted-by-display-name`, `d:getlastmodified` (= deletion time), `getcontentlength` / `getcontenttype` for files only, `oc:fileid` and `oc:id` both the plain number, `oc:size`, `oc:permissions` = `GD`, `nc:has-preview`; `getetag` is empty for files and the deletion time for folders (`15-trash-list`, `28-trash-list-with-folder`).
- `GET` (with ranges) reads a trashed file (`19`, `21`). `PUT`/`MKCOL` → 403 (`24`, `25`). Other users' trash → 404 (`23`).
- Restore is `MOVE trash/<item>` to `trashbin/<user>/restore/<anything>`; the file returns to its original location. If the original folder is gone it lands in the root (`45`, `46`). The reference also happily moves an item to any other destination (`33`) and answers 500 without `Destination` (`32`).
- `DELETE trash/<item>` purges one item (204, then 404); `DELETE trash/` empties (204) (`49`).
- The same name deleted twice gives two entries (`31`). Deleted space keeps counting for the user.
- A file deleted by a share recipient appears in the trash of the recipient and of the owner (`57`, `58`); deleting a shared folder as owner ends the share for the recipient (`60`).
- Capabilities: `files.undelete`, `files.delete_from_trash` (`63`).

## Decision

### Soft delete without moving rows

- Table `trash(id, node_id UNIQUE, owner_id, orig_path, orig_name, deleted_at, deleted_by)` and column `nodes.trash_id` (NULL = live).
- `DELETE` of a node (when the trash is enabled) marks **every node of the subtree** with the new `trash_id`, re-homes the top node under the owner's root (its original location lives in `orig_path`, not in `parent_id`) and keeps all rows, blobs and versions. Nothing is copied or moved on disk.
- Every query that looks at the live tree filters `trash_id IS NULL`: child listing, name lookup, path resolution, subtree sizes, copy, mount-name clashes, `file_of_owner`, share lookup (a share on a trashed node, or inside a trashed folder, is inactive while it is in the trash and active again after restore). The unique name index becomes partial (`WHERE trash_id IS NULL`), so a new `a.txt` can be created next to a trashed one.
- Because the top node is re-homed, permanently deleting a parent can never cascade into items that were trashed earlier.
- **Space** keeps counting for the owner (`used_bytes` is unchanged by a trash operation) and is freed when an item is purged. `fsck` therefore sums live and trashed nodes plus versions.
- **Restore** puts the item back under `orig_path`'s parent when that is a live folder, else under the root; a name that is taken becomes `name (restored)` (`name (restored 2)`, ...; extension kept). The IDs stay, so versions and shares return. Only the owner can restore.
- **Whose trash:** a delete by a recipient or through an editable link goes to the **owner's** trash only (the reference also fills the recipient's; recipients cannot restore things they do not own), recorded with `deleted_by`.
- **Retention:** `[trash] enabled`, `retention_days` (default 30); the background cleanup purges older items. With the trash disabled `DELETE` is permanent as before. Replacing a target by `MOVE`/`COPY` with `Overwrite: T` stays a permanent delete.

### Endpoint

`/remote.php/dav/trashbin/<user>/` as recorded: `PROPFIND` (Depth 0/1), `GET`/`HEAD`, `MOVE` to `restore/…`, `DELETE`. Differences kept on purpose: `MOVE` to anything but `…/restore/*` → 400, missing `Destination` → 400, `Depth: infinity` → 403. Content of trashed folders is browsable below the item with the normal file properties.

## Consequences

- The trash is part of the quota. A user whose quota is full of trash must purge it (a later step may purge the oldest items automatically when space runs out).
- Item names (`<name>.d<time>`) are made unique by moving the time forward by whole seconds if needed.
- Deleting a user deletes their trash with them.
