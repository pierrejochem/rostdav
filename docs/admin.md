# Administration

Requirements: section 2.8 of the [instructions](instructions.md). Design: `design/mockups/web-ui/Admin.html`.

> Status M7: roles, the CLI and the event log are implemented. The web administration (`design/mockups/web-ui/Admin.html`) follows in M11, two-factor reset in M12.

## Roles

| Role | Permissions |
|---|---|
| `user` | Own files, shares, devices, settings |
| `admin` | Additionally user management, server and security settings, event log |

Rules: An administrator cannot disable themselves; the last admin role cannot be removed.

## CLI

The commands work while the server runs: they are handed to it through the admin socket in the data directory ([ADR 0010](adr/0010-admin-socket.md)); only root and the user the server runs as can use it. Without a running server they open the database themselves.

The CLI works on the data directory directly, next to a running server. It is trusted (whoever can run it can read the data) and shows up as actor `cli` in the event log. Secrets are read from stdin, never from arguments.

| Command | Purpose |
|---|---|
| `rostdav admin user add <login> [--admin]` | Create a user; password as one line on stdin (at least 10 characters) |
| `rostdav admin user list [--json]` | Role, state, usage, quota, number of devices |
| `rostdav admin user disable <login>` / `enable <login>` | Block / allow every sign-in (account password, app passwords, login flow); data and devices stay |
| `rostdav admin user role <login> admin\|user` | Change the role |
| `rostdav admin user set-quota <login> <10G\|500M\|bytes\|unlimited>` | Quota |
| `rostdav admin user set-password <login> [--revoke-devices]` | New password from stdin; optionally sign out all devices |
| `rostdav admin user delete <login> [--transfer-to <login>] --yes` | Delete the account; the files are deleted, or moved to the folder `<login> (transferred)` of the other user |
| `rostdav admin import-nextcloud <data-dir> [--map NC=USER] [--only NC] [--update] [--dry-run]` | Import a Nextcloud data directory (files with their times, and versions); read-only on the source, repeatable, see [below](#migrating-from-nextcloud) |
| `rostdav admin search status` / `rebuild` | The search index: numbers, or throw it away and build it again, see [Search](#search) |
| `rostdav admin fsck [--verify] [--repair] [--min-orphan-age <s>]` | Consistency check, see below; exit code 1 if damage remains |
| `rostdav admin import <path> --user <login> [--dest <folder>] [--overwrite]` | Copy a host directory into a user's files |
| `rostdav admin backup <new-dir> [--include-key]` | Consistent copy of database and blobs while the server runs (hard links on the same file system), see [deployment.md](deployment.md) |
| `rostdav admin audit export [--since <date>]` | Event log as JSON Lines |
| `rostdav admin user reset-2fa <login>` | Remove the two-factor secret and recovery codes of a locked-out user and end their browser sessions (app passwords stay) |

Rules enforced by the service (CLI and later the web UI alike): an administrator cannot disable or delete themselves; the last enabled administrator cannot be disabled, demoted or deleted; a user can only be deleted with `--yes`; data can only be transferred to an existing, enabled, different user.

### fsck

Compares database and storage:

- **Damage** (reported, never "repaired" away): a registered blob whose file is missing, or (`--verify`) whose size or BLAKE3 differs from the record. The report names user and file name of up to 20 affected files.
- **Orphans** (removed with `--repair`): blob files without a database row that are older than `--min-orphan-age` (default 3600 s, so uploads in flight survive), upload directories without a session row, session rows without data.
- **Counters**: a user's stored usage that differs from the sum of the file sizes is corrected with `--repair`.

Without `--repair` nothing is changed. Run `--verify` off-peak: it reads every blob.

### import

Walks the directory without following symbolic links (they are skipped and reported), keeps modification times, applies the same name rules as uploads (`.part`, control characters, ... are skipped and reported), respects the user's quota (and stops when it is exceeded), and by default skips files that already exist.

## Search

Users search by name and by the words in the text of their files (`/search`). Names are found by any part of them; text is found by **whole words** (not word beginnings, and in Chinese, Japanese or Korean text only whole runs). The index lives in `<data_dir>/db/search.sqlite`, is built and kept up to date in the background (first start: a few seconds for the names, then the text of files a little at a time, newest first) and can be removed at any time: it is built again from the database and the files ([ADR 0012](adr/0012-search-index.md)).

- **What is read:** files with a text name (`txt`, `md`, `csv`, `json`, `xml`, `html`, source code, `README`, …) whose content is text, up to 64 MiB, keeping at most 1 MiB of text per file.
- **PDF and Office files:** PDF, Word (`docx`, `doc`), Excel (`xlsx`, `xls`), PowerPoint (`pptx`, `ppt`) and OpenDocument (`odt`, `ods`, `odp`) files up to 128 MiB are read as well, by a **separate short-lived process** (`rostdav internal-extract`, started with a 3 GiB memory limit, a CPU limit and a 60 second time-out, without the server's environment), because these readers parse files that anybody can upload: a file that crashes or hangs a reader costs that one file. A file that cannot be read is skipped; one that crashes the reader is tried three times. Scanned PDFs (pictures of text) have no text to read. Administration, Server, "Search PDF and Office files" (or `[search] documents = false`) switches this off and removes their stored texts at the next pass.
- **Privacy:** the index holds the **text of these files in plain form**, in a file in the data directory (mode 0700), so it is as sensitive as the files. It is not part of `rostdav admin backup` (restore, and it is built again). Administration, Server, "Search the text of files" (or `[search] content_indexing = false` in the configuration) switches reading off: the stored texts are removed at the next pass, names stay searchable; switching it on reads every file again.
- **Limits** (same page): "Largest file whose text is read" (for PDF and Office files at most 128 MiB) and "Most text kept per file".
- **Commands:** `rostdav admin search status` (files read, waiting, too big, not text, failed, size) and `rostdav admin search rebuild`. The Server page shows the same numbers.
- **Access:** a search never shows a file the user could not open: own files and received shares only, nothing in the trash, and a share that ends stops showing at once.

## Migrating from Nextcloud

`rostdav admin import-nextcloud` copies the contents of a Nextcloud data directory into Rostdav ([ADR 0011](adr/0011-nextcloud-data-import.md)). It only **reads** the directory, so Nextcloud can keep running, and it can be repeated.

1. Create the users in Rostdav first (`rostdav admin user add alice`; passwords are new, Nextcloud's are not used). Use the same names, or map them with `--map nc_name=rostdav_name`.
2. Make the directory readable for the Rostdav process. In a container: mount it read-only, for example `-v /data:/nextcloud:ro`, and add the group that owns it (`--group-add 33` for `www-data`).
3. Look first: `rostdav admin import-nextcloud /nextcloud --dry-run` lists the users and counts files, versions and skipped items.
4. Run it without `--dry-run`. For a big directory start it in the background (`nohup … > import.log &`) and read the log.
5. While Nextcloud keeps running, repeat it with `--update` to bring over changed files (the old content becomes a version).

What comes over: every user's files with names and modification times, and the versions Nextcloud kept. What does not, and is listed at the end of the output: the trash bin, group folders, external storage, shares, favorites, tags, comments, and files encrypted by Nextcloud. Files deleted in Nextcloud stay in Rostdav. Rostdav refuses some names Nextcloud allows (a `.part` ending, some characters); they are listed as skipped.

When the import is done and you switched Nextcloud off, recreate the Rostdav container without the mount.

## Settings and precedence

Command line > environment (`ROSTDAV_*`) > configuration file > database (UI) > defaults. Values from the upper levels are read-only in the UI and marked as "set by configuration".

Adjustable in the web interface (Administration, Server), stored in the `settings` table as `cfg.<key>`, applied at once and kept across restarts:

| Key | Meaning |
|---|---|
| `limits.default_quota` | Quota of users created from now on |
| `limits.upload_retention_hours` | Unfinished chunked uploads are removed after this many hours (1 to 8760) |
| `versioning.max_versions` | Versions kept per file (0 = all) |
| `versioning.max_age_days` | Versions are removed after this many days (0 = no age limit) |
| `versioning.max_quota_share_percent` | Share of a user's quota that versions may use (0 = no limit) |
| `trash.retention_days` | Deleted files are removed after this many days (0 = keep) |
| `audit.retention_days` | Event log entries are removed after this many days (0 = keep) |

A key that the file or an environment variable sets (even to the default value) is locked: the page shows it as "set by configuration" and a change stored earlier is ignored. "Back to default" removes the change and returns to the value from the file. Everything else (sign-in limits, sessions, locations, security keys) stays in the file. Every change is recorded in the event log (`admin.setting_changed`, with the old and new value).

## Web sessions

Browser sessions live in the `sessions` table (token hash only). Set the lifetimes in `[web]`:
`session_idle_hours` (default 8) and `session_max_days` (default 14). Disabling a user ends
their browser sessions at the next request; expired sessions are removed by the garbage run.
Users can end their other sessions on the Devices page.

## Retention and cleanup

One background task runs every five minutes (never inside a request). It applies these rules; all are set in the configuration file or `ROSTDAV_<SECTION>__<KEY>` variables (see `rostdav.example.toml`) and shown on Administration › Server.

| What | Setting | Default |
|---|---|---|
| Versions per file | `[versioning] max_versions` | 50 (0 = unlimited) |
| Age of versions | `[versioning] max_age_days` | 365 (0 = keep) |
| Share of a user's quota that versions may use | `[versioning] max_quota_share_percent` | 50 (0 = no limit) |
| Trash | `[trash] retention_days` | 30 (0 = until emptied) |
| Unfinished chunked uploads | `[limits] upload_retention_hours` | 24 |
| Event log | `[audit] retention_days` | 365 (0 = keep) |
| Browser sessions | `[web] session_idle_hours`, `session_max_days` | 8 h, 14 d |
| Unconfirmed two-factor setups | fixed | 1 h |
| Unreferenced blobs | always | after retention released them |

New users get `[limits] default_quota` (default `unlimited`); existing users keep their quota.

## Two-factor authentication

Users turn on TOTP (authenticator app) themselves under Devices & security; see [ADR 0007](adr/0007-two-factor-authentication.md). What an administrator needs to know:

- **Key file.** The secrets are encrypted with a key that is *not* in the database: `totp.key` in the data directory (32 random bytes, mode 0600, created when the first user starts a setup). Back it up with the data, but keep it apart from copies of the database if you want a stolen database dump to be useless. Without the key, existing secrets cannot be read: reset 2FA for the affected users. Alternatives: `[security] totp_key_file = "/path"` or `ROSTDAV_SECURITY__TOTP_KEY` (base64 of 32 bytes).
- **WebDAV and OCS.** While 2FA is on for a user, their *account password* no longer works there (401); app passwords do. Tell users who still use the account password in a WebDAV client to create an app password first.
- **Lockout.** Five wrong codes lock the second step for that user for 15 minutes. A user who lost the authenticator and the recovery codes needs `rostdav admin user reset-2fa <login>` or Administration › Users › Manage › Reset two-factor authentication.
- **Event log:** `auth.2fa_enabled`, `auth.2fa_disabled`, `auth.2fa_codes_regenerated`, `admin.2fa_reset`, failed codes as `auth.login_failed` with `second_factor`. Codes and secrets are never logged.

## Version check

Off by default. Administration, Server, "Updates" turns it on: the server then asks the GitHub releases API once a day (and on "Check now") which version is the newest, and shows a newer one with its release notes. The request carries only `User-Agent: rostdav/<version>`. While it is off, the server makes no outbound connection. After an error the server tries again in an hour; the page shows the reason. The switch is kept in the database, so a restart keeps it. Events: `admin.update_check_on`, `admin.update_check_off`, `admin.update_installed`. The About page (every user) shows the release notes of the running build and the versions before it; they are compiled in and need no network. 

### Installing an update from the page

When a newer version is found, the card offers the next step that fits this server:

- **Container image:** the card shows the steps (make a backup, `docker compose pull`, `docker compose up -d`). The image is replaced, never patched in place.
- **Plain binary with an update signing key built in, and a program folder the server may write to:** the card asks for **your password** and an **Install version x.y.z** button. The server then downloads the release file from GitHub, checks its minisign signature against the key compiled into the program, runs it once with `--version`, saves the database to `backups/before-x.y.z.sqlite` in the data directory, keeps the old program as `rostdav.previous` next to it, replaces its program file and exits with status 75. **Something must start it again**: systemd with `Restart=on-failure` (as in the example unit) does.
- **No key in this build, or a read-only program folder:** the card says so and you replace the program file by hand.

If the new version does not work: stop the server, move `rostdav.previous` back over the program file and, if the update converted the database (the release notes say so), restore the backup over `db/rostdav.sqlite`. A failed check of any step (signature, version, backup) installs nothing. Details: [ADR 0009](adr/0009-version-check-and-updater.md).


## Event log

Fields: timestamp, actor, action, target, IP, details as JSON. Never file contents, passwords or tokens. Export as JSON Lines (`rostdav admin audit export`):

```json
{"id":7,"ts":1700000000,"time":"2023-11-14T22:13:20Z","actor":"anna","action":"device.connected","target":"Nextcloud-Android","ip":"203.0.113.0","details":{}}
```

Configuration (`[audit]`): `anonymize_ip` stores IPv4 addresses as /24 and IPv6 as /48; `retention_days` (default 365, `0` = keep) is applied by the background cleanup every five minutes. Free text from clients (user names of failed sign-ins, device names) is stripped of control characters and cut at 128 characters.

| Action | Example |
|---|---|
| `auth.login`, `auth.login_failed`, `auth.locked` | Browser sign-in (Login Flow), every failed credential check (also reason `disabled`), a rate-limit lockout (once per key) |
| `device.connected`, `device.revoked` | Login flow granted, app password revoked by sign-out |
| `2fa.enabled`, `2fa.disabled`, `2fa.reset` | Two-factor |
| `admin.user_created`, `admin.user_disabled`, `admin.user_enabled`, `admin.user_role_changed`, `admin.user_quota_set`, `admin.user_password_reset`, `admin.user_deleted`, `admin.fsck`, `admin.import` | Admin actions |
| `share.created`, `share.revoked` | A share was created / ended (by the owner, or by the recipient leaving); details hold type and permissions, never tokens |
