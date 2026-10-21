# Nextcloud compatibility

> Status: **nothing tested yet.** This document is filled in M3 (recordings) and M6 (end-to-end). Every statement names its source: client code (repository, file, line, version), Nextcloud documentation (URL) or fixture (`tests/fixtures/nextcloud/…`).

## Reference versions

| Component | Version | Fixed on |
|---|---|---|
| Nextcloud Android | [enter when M3 starts] | |
| Nextcloud iOS | optional, later | |
| Nextcloud server for recordings | [same major version as emulated] | |
| Reported server version (`status.php`) | [to be entered] | |

## Supported flows

| Flow | Status | Contract test | Device test | Source |
|---|---|---|---|---|
| Add server (`status.php`) | open | – | – | |
| Sign-in via Login Flow v2 | open | – | – | |
| List folder | open | – | – | |
| Upload file (small) | open | – | – | |
| Upload file (> 100 MB, chunked upload v2) | open | – | – | |
| Download | open | – | – | |
| Rename, move | open | – | – | |
| Delete | open | – | – | |
| Sign out / revoke app password | open | – | – | |

Status: `open` · `implemented` · `contract test green` · `device test passed`

## Known endpoints (to be verified)

Initial list from section 3.2 of the instructions. None of this is confirmed until a source is entered.

| Endpoint | Purpose | Verified | Source |
|---|---|---|---|
| `GET /status.php` | Server discovery | no | |
| `POST /index.php/login/v2`, `POST /index.php/login/v2/poll` | Login Flow v2 | no | |
| `GET /ocs/v2.php/cloud/capabilities` | Capabilities | no | |
| `GET /ocs/v2.php/cloud/user` | User info | no | |
| `/remote.php/dav/files/{userId}/` | Files | no | |
| `/remote.php/webdav/` | Legacy path | no | |
| `/remote.php/dav/uploads/{userId}/{transferId}/` | Chunked Upload | no | |

## Not supported

| Feature | App behavior without support | Source |
|---|---|---|
| Preview images | [observe in M5] | |
| Notifications, activities, push | [observe] | |
| End-to-end encryption | [observe] | |
| Talk, calendar, contacts | not planned | |

## Open questions

- Exact format of `oc:id` (file ID plus instance ID).
- Error XML format for WebDAV errors that the app evaluates.
- Which minimum version does the app require, and how does it react to older versions?
- Behavior of the app when two-factor authentication is enabled in the login flow.
