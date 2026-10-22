# Administration

Requirements: section 2.8 of the [instructions](instructions.md). Design: `design/mockups/web-ui/Admin.dc.html`.

> Status M7: roles, the CLI and the event log are implemented. The web administration (`design/mockups/web-ui/Admin.dc.html`) follows in M11, two-factor reset in M12.

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
| `rostdav admin audit export [--since <date>]` | Event log as JSON Lines |
| `rostdav admin user reset-2fa <login>` | M12 |

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

## Web sessions

Browser sessions live in the `sessions` table (token hash only). Set the lifetimes in `[web]`:
`session_idle_hours` (default 8) and `session_max_days` (default 14). Disabling a user ends
their browser sessions at the next request; expired sessions are removed by the garbage run.
Users can end their other sessions on the Devices page.

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
