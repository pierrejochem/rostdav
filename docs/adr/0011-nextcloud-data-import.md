# ADR 0011: Importing a Nextcloud data directory

- Status: **Accepted** by the project owner on 2026-10-24 ("migrate into Rostdav; Nextcloud keeps running"). Built the same day.
- Date: 2026-10-24

## Context

A server that already runs Nextcloud has a data directory with the files of its users (`<user>/files/…`), the versions Nextcloud kept (`<user>/files_versions/<path>.v<time>`), the trash (`<user>/files_trashbin/…`), and folders that are not users (`appdata_*`, `__groupfolders`, `files_external`, `updater-*`, logs). The owner asked that Rostdav be "100% compatible with this structure" and, when asked what that means, chose: **migrate into Rostdav**, and **Nextcloud keeps running** next to it.

Rostdav's storage is not Nextcloud's layout ([ADR 0002](0002-storage-model.md): content-addressed blobs and a database), and it does not read Nextcloud's database. Using the Nextcloud folder as Rostdav's own data directory would be wrong in two ways: Rostdav sets the mode of its data directory to 0700 and writes `blobs/`, `db/` and more into it, and a live Nextcloud writes to the same files.

## Decision

`rostdav admin import-nextcloud <data-dir> [--map NC=USER]… [--only NC]… [--update] [--dry-run]` reads the directory **and never writes to it**. It can be repeated; Nextcloud can run the whole time.

- **Users.** Each folder with a `files` folder is a Nextcloud user. It goes to the Rostdav user of the same name, or the one given with `--map`. The Rostdav user must exist (create it first, with its own password: Nextcloud's password hashes are not used). Folders without `files`, and users without a Rostdav account, are listed with the reason, not imported.
- **Files.** Content, names and **modification times** come over (the time is what the apps compare). Names Rostdav refuses (a `.part` ending, characters it does not allow, names that differ only in Unicode form) are skipped and listed.
- **Versions.** The versions of a file (`<name>.v<unix time>`, named by the modification time of the old content) are imported for files that are new in Rostdav: oldest first, each overwrite archives the one before, so Rostdav ends up with the same list of versions, named by the same times. Retention limits of Rostdav (`max_versions` and so on) apply.
- **Repeating.** A file that exists already is skipped. With `--update` it is replaced when size or modification time differ from the Nextcloud copy; the old content becomes a version. Files deleted in Nextcloud are **not** deleted in Rostdav; shares, favorites, tags and comments are not copied (they are in Nextcloud's database, which this does not read).
- **Not imported, and said so in the report:** the trash (its original places are only in the database), group folders, external storage, previews and other app data, and files that Nextcloud encrypted (server-side encryption; they start with `HBEGIN:oc_encryption_module`).
- **`--dry-run`** counts what would be imported and writes nothing.

The data directory has to be readable by the user the server runs as. In the container, mount it read-only (`-v /data:/nextcloud:ro`, plus `--group-add` for the group that owns it) and give the in-container path.

## Consequences

- No risk to the Nextcloud data from this command: it only opens files for reading (tested: names, sizes and times of the whole tree are the same afterwards).
- File IDs and ETags are new, so every client that was connected to Nextcloud syncs as to a new server. That is how a new server looks to the apps anyway.
- Two copies of the content exist until Nextcloud is switched off. Equal files inside Rostdav are stored once (content-addressed).
- A one-way, periodic import is the only safe way to run both side by side. A two-way sync is not offered.
- Mounting the whole Nextcloud data directory into the Rostdav container makes it readable from there. Remove the mount (recreate the container) when the import is done.

## Alternatives considered

- **Rostdav on Nextcloud's layout, in place:** needs a new storage model and a replacement for Nextcloud's file IDs and ETags; cannot be safe beside a live Nextcloud. Rejected by the owner's choice.
- **Read-only view of the folder:** nothing could be changed through Rostdav, no versions, shares or trash for those files.
- **Reading Nextcloud's database for trash, shares and favorites:** would need credentials of that database and its several dialects. Possible later as a separate step.
