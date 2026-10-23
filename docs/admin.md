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
