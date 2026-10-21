# Administration

Requirements: section 2.8 of the [instructions](instructions.md). Design: `design/mockups/web-ui/Admin.dc.html`.

> Status M0: not yet implemented. The first CLI commands follow in M1, the full set in M7.

## Roles

| Role | Permissions |
|---|---|
| `user` | Own files, shares, devices, settings |
| `admin` | Additionally user management, server and security settings, event log |

Rules: An administrator cannot disable themselves; the last admin role cannot be removed.

## CLI (planned)

| Command | Milestone |
|---|---|
| `rostdav admin user add <login> [--admin]` | M1 |
| `rostdav admin user list` | M7 |
| `rostdav admin user disable <login>` / `enable` | M7 |
| `rostdav admin user reset-2fa <login>` | M12 |
| `rostdav admin user set-quota <login> <size>` | M7 |
| `rostdav admin fsck` | M1 |
| `rostdav admin import <path> --user <login>` | M7 |
| `rostdav admin audit export --since <date>` | M7 |

## Settings and precedence

Command line > environment (`ROSTDAV_*`) > configuration file > database (UI) > defaults. Values from the upper levels are read-only in the UI and marked as "set by configuration".

## Event log

Fields: timestamp, actor, action, target, IP (anonymization configurable), details as JSON. Never file contents, passwords or tokens. Export as JSON Lines.

| Action | Example |
|---|---|
| `auth.login`, `auth.login_failed`, `auth.locked` | Sign-ins and lockouts |
| `device.connected`, `device.revoked` | Login flow, app passwords |
| `2fa.enabled`, `2fa.disabled`, `2fa.reset` | Two-factor |
| `admin.user_created`, `admin.user_disabled`, `admin.settings_changed` | Admin actions |
| `share.created`, `share.revoked` | Shares |
