# AI Agent Instructions: Rostdav – a lean Nextcloud-compatible file server

## 1. Role, goal and scope

You are an autonomously working senior software engineer. You are developing **Rostdav**, a lean, secure and maintainable file server that lets the **unmodified official Nextcloud app** (Android and iOS) be used for basic file operations.

**Goal:** As little custom implementation as possible, as much real protocol compatibility as necessary. Security, testability and maintainability take precedence over feature scope.

**Reference versions (define before starting and record in `docs/compatibility.md`):**

- Nextcloud Android app: version `<X.Y.Z>`
- Nextcloud iOS app: version `<X.Y.Z>` (optional, phase 3b)
- Emulated server version (reported via `status.php` and capabilities): `<Major.Minor.Patch>` – must be accepted as supported by the reference app; keep it configurable.

**Non-goals (explicitly do not implement unless commissioned later):**

- Nextcloud apps ecosystem, Talk, Calendar, Contacts, Notes, Deck, Office
- Server-side encryption, end-to-end encryption
- Federation (Federated Cloud Sharing), LDAP, SSO/SAML/OIDC
- Desktop sync client compatibility (document only as a later option)
- Full Nextcloud web interface

## 2. Functional requirements

Every requirement has a priority: **P0** = prototype, **P1** = app compatibility, **P2** = extension.

### 2.1 Users and authentication

- **P0** Multiple users with strictly separated file areas.
- **P0** Password hashing with Argon2id (parameters configurable, documented); never plaintext.
- **P0** HTTP Basic Auth against WebDAV/OCS (after login, the Nextcloud apps send username + **app password** via Basic Auth).
- **P1** **Login Flow v2** (`POST /index.php/login/v2`, browser login page, polling endpoint) that issues a device-specific app password.
- **P1** App passwords: randomly generated, stored only hashed, individually revocable, with a device name and time of last use.
- **P1** Disable user accounts; disabling immediately invalidates all sessions and app passwords.
- **P2** Session-based sign-in for the web interface (HttpOnly, Secure, SameSite cookies, CSRF protection).
- **P2** **Optional two-factor authentication (TOTP, RFC 6238)** per user, off by default:
  - Setup: generate the secret server-side (≥ 160 bits), display it as a QR code (`otpauth://`) and manually, activate only after a valid code has been entered.
  - Store the secret encrypted (key from the configuration, not in the database); time window ±1 step; each code usable only once (replay protection).
  - Ten one-time recovery codes, stored only hashed, regenerable; display the remaining count.
  - Prompt only for interactive browser sign-in (web UI and Login Flow v2 page). App passwords deliberately bypass 2FA, as in Nextcloud – this keeps the Nextcloud apps compatible.
  - If 2FA is active, Basic Auth with the **account password** against WebDAV/OCS is rejected; only app passwords are permitted there.
  - Disabling 2FA and regenerating the codes requires re-entering the password and a code. An administrator can reset 2FA for locked-out users (logged).
  - Brute-force protection for code entry as for passwords; never log secrets and codes.
  - Do not advertise anything in the capabilities that would cause the Nextcloud app to start a 2FA flow that is not implemented; test the reference app's behavior with 2FA enabled and record it in `docs/compatibility.md`.

Login and app password logic is shared by the web interface, WebDAV and OCS (one identity module, no duplicates).

### 2.2 File management

- **P0** Upload, download, rename, move, copy, delete files and folders; create and list folders.
- **P0** Streaming in both directions; no complete buffering in memory.
- **P0** Atomic writes: upload to a temporary file on the same file system, `fsync`, then atomic rename.
- **P0** Metadata in a database (default: SQLite, PostgreSQL optional): stable **file ID** that is preserved on rename/move, size, mtime, ETag, owner, path.
- **P0** Physical storage paths are **not** derived from user input (e.g. content-addressed or ID-based); logical paths exist only in the database.
- **P0** Folder ETags change when anything inside them changes recursively (clients detect changes through this).
- **P1** Adopt the client mtime via `X-OC-MTime` and confirm with `X-OC-MTime: accepted`.
- **P1** Chunked upload (Nextcloud chunking v2, see section 3) for large files.
- **P1** Per-user quota (`quota-available-bytes`, `quota-used-bytes`).
- **P0** File names: define Unicode normalization (store NFC, compare normalized), forbidden names (`.`, `..`, empty segments, control characters, `/`), length limit. Case sensitivity: define and document the behavior.

### 2.3 Deletion and trash

- **P0** Deletion is permanent; capabilities must **not** advertise a trash as long as it does not exist.
- **P2** Optional trash via the Nextcloud trashbin DAV endpoint.

### 2.4 File versioning (P2)

- Keep the previous version on overwrite.
- Provide the version history via the Nextcloud versions DAV endpoint; restore via the `MOVE` flow customary there.
- Retention rules configurable (count, age, share of the quota); cleanup as a background task, never during a request.
- Versions count toward the quota (documented decision).
- Advertise in the capabilities only once implemented and tested.

### 2.5 Shares (P2)

- User-to-user shares of files and folders with the permissions read / write / create / delete / reshare (Nextcloud permission bitmask).
- Public links with a random token of at least 128 bits, optionally a password (hashed) and an expiry date; disabled by default.
- Revocation takes effect immediately.
- Provide via the OCS Sharing API (`/ocs/v2.php/apps/files_sharing/api/v1/shares`); shares appear for the recipient as entries in their file tree.
- Permission checks on every operation use the effective share, not the path.

### 2.6 Web interface

Reference design: design canvas "Rostdav Web UI" (pages Files, Devices & security, Settings, Administration, Connect device, Second factor). Colors, fonts and logo come from the canvas "Rostdav Logo". The design is binding for structure and content, not pixel-exact.

- **P1** Sign-in page for Login Flow v2 including a deny option, display of the requesting client and a phishing notice.
- **P2** File browser: list with name, size, modification date, share status; detail column with versions, shares, file ID and ETag; upload with progress (chunked upload) and cancel.
- **P2** "Devices & security" page: connected devices and sessions with last use and revocation, create app password (show plaintext only once), two-factor setup, "Sign out all devices".
- **P2** Personal settings (section 2.7) and administration (section 2.8).
- **Technology:** Prefer server-side rendered HTML with little JavaScript (no SPA framework without justification in an ADR). The interface uses exactly the same internal services as WebDAV/OCS, no business logic of its own.
- **Appearance:** Light and dark mode via design tokens (CSS variables); the default follows `prefers-color-scheme`, the user's choice overrides it and is stored in the profile.
- **Accessibility:** WCAG 2.1 AA – real buttons, links and form fields with labels, keyboard operation, visible focus, contrast of at least 4.5:1, click targets of at least 44 px. Usable from a mobile width of 360 px (navigation stacks).
- **Security:** CSRF protection for all state-changing requests, strict Content Security Policy (no inline scripts), `X-Frame-Options: DENY` or `frame-ancestors 'none'`, no secrets in URLs. Dangerous actions (disable user, reset 2FA, sign out all devices) with confirmation; file names are always displayed HTML-escaped.
- **Language:** German and English; texts in resource files, no hard-coded strings.

### 2.7 Personal settings (P2)

- Display name, email address for notifications, language, color scheme (light / dark / same as system), profile picture (size and type limited, re-encoded server-side).
- The username cannot be changed.
- File settings: show hidden files, confirm before deleting, load preview images, keep versions (provided the administrator allows versioning).
- Display of the personal WebDAV address for copying.
- Storage overview: usage by files, versions and trash relative to the quota.
- Data export of all own files as an archive (streamed, as a background task for large amounts of data, download link only for the user and time-limited).
- Changing the password requires the old password; afterwards all browser sessions except the current one are terminated, app passwords remain valid (documented decision).

### 2.8 Administration (P2)

Only for users with the `admin` role; every admin action is authorized server-side and recorded in the event log. All functions additionally have a CLI (`rostdav admin …`) so that the server remains operable without the web interface; the first administrator is created via the CLI.

- **Users:** create (with one-time password or invitation link), edit, set role, set quota, disable/enable, delete (with a choice: delete data or transfer it to another user), reset 2FA. An administrator cannot disable themselves or remove the last admin role. Search and sorting; display of storage usage and 2FA status.
- **Server – uploads & storage:** default quota, maximum file size, retention of orphaned chunk uploads.
- **Server – versions & trash:** maximum versions per file, retention period, maximum share of the quota, trash retention.
- **Server – shares:** allow public links, require a password for links, enforce an expiry date (with a default period).
- **Security:** require 2FA for everyone (default off; users without 2FA set it up at their next browser sign-in), WebDAV/OCS with app passwords only (default on), failed attempts before lockout and lockout duration, list of active lockouts with release.
- **Event log:** sign-ins, failed sign-ins and lockouts, device connections and revocations, 2FA changes, admin actions, share creation. Fields: timestamp, actor, action, target, IP (anonymization configurable). No file contents, passwords or tokens. Retention period configurable; export as JSON Lines.
- **Compatibility:** display of `productname`, reported version and tested app versions; list of the features advertised in the capabilities (read-only, derived from the actual state of the code); maintenance mode (sets `maintenance: true` in `status.php`, write access is rejected with 503).
- **Status:** server version, total storage usage, state of the background tasks (version cleanup, chunk cleanup, consistency check).
- Settings are stored in the database; values from the configuration file/environment variables take precedence and appear in the interface as "set by configuration" (not editable).

## 3. Nextcloud compatibility

### 3.1 Approach

Compatibility is **derived from primary sources, not guessed**:

1. Read the **client source code**: `nextcloud/android`, `nextcloud/android-library`, `nextcloud/ios`, `nextcloud/NextcloudKit` (each at the tag of the reference version).
2. **Nextcloud developer documentation** (client APIs: Login Flow, WebDAV, chunked upload, OCS, sharing, versions).
3. **Reference recordings**: If possible, operate a real Nextcloud instance (Docker, same major version as emulated) with the reference app and record the traffic with a proxy (e.g. mitmproxy). Store recordings as sanitized fixtures (without credentials) in `tests/fixtures/nextcloud/` and use them as the basis for contract tests.
4. For every supported app flow, write a contract test that checks request/response against the fixtures.
5. End-to-end test with the unmodified app on an emulator or device. **If you cannot run this in your environment, mark the test as "not executed" and provide reproducible manual test instructions.**

Every compatibility statement in the documentation names its source (file/line in the client code, documentation page or fixture). Do not invent response fields; unknown fields are researched or omitted and documented.

### 3.2 Interfaces to verify (starting list, verify against sources)

| Area | Endpoint / behavior | Priority |
|---|---|---|
| Server discovery | `GET /status.php` (installed, maintenance, needsDbUpgrade, version, versionstring, edition, productname, extendedSupport) | P1 |
| Login | Login Flow v2: `POST /index.php/login/v2`, browser page, `POST /index.php/login/v2/poll` → server, loginName, appPassword | P1 |
| Capabilities | `GET /ocs/v2.php/cloud/capabilities` (JSON and XML), advertise only features that are actually implemented | P1 |
| User | `GET /ocs/v2.php/cloud/user`, possibly `/ocs/v1.php/cloud/users/{id}` incl. quota | P1 |
| OCS in general | Require header `OCS-APIRequest: true`; envelope `ocs.meta.{status,statuscode,message}` + `ocs.data`; observe v1 vs. v2 status codes; `?format=json` | P1 |
| WebDAV | `/remote.php/dav/files/{userId}/…`; check whether the reference app still uses the legacy `/remote.php/webdav/…` | P0 |
| DAV properties | `d:` standard props plus `oc:` (`http://owncloud.org/ns`) and `nc:` (`http://nextcloud.org/ns`), including `oc:fileid`, `oc:id`, `oc:permissions`, `oc:size`, `oc:owner-id`, `oc:share-types`, `nc:has-preview`; answer unknown props correctly with 404 in the `propstat` | P0/P1 |
| Upload headers | `X-OC-MTime`, `OC-Checksum`, response headers `OC-FileId`, `OC-ETag`, `ETag` | P1 |
| Chunked upload | `/remote.php/dav/uploads/{userId}/{transferId}/`: `MKCOL`, numbered chunk `PUT`s, `MOVE …/.file` with `Destination` and `OC-Total-Length`; cleanup of orphaned uploads | P1 |
| Search | WebDAV `SEARCH` (RFC 5323) – used by the app for media/recently modified, among other things; at least reject cleanly with 501 or similar if unsupported, and document the app behavior | P2 |
| Preview images | `/index.php/core/preview` and avatar endpoints: answer with 404 at first, never with 500; `nc:has-preview=false` | P1 |
| Versions | `/remote.php/dav/versions/{userId}/…` | P2 |
| Trash | `/remote.php/dav/trashbin/{userId}/…` | P2 |
| Shares | OCS Sharing API; public links `/s/{token}` and `public.php` DAV | P2 |
| Optional | Notifications, activity, push: do **not** advertise in the capabilities | – |

### 3.3 Further compatibility rules

- `OPTIONS` returns `DAV` and `Allow` headers that match the actual feature scope. `LOCK`/`UNLOCK` only if a supported client needs them (relevant mainly for macOS Finder / Windows Explorer, not for the mobile app).
- `PROPFIND` with `Depth: 0` and `1`; reject `Depth: infinity` (403 with a DAV error element).
- Handle conditional requests correctly: `If-Match`, `If-None-Match`, `Overwrite`, `Destination`; 412 on ETag conflict.
- Status codes per RFC 4918 (201, 204, 207, 409, 412, 415, 423, 507 on quota exceeded).
- The reported server version is a compatibility statement; the README and web UI must make clear that this is **not** Nextcloud. `productname` in `status.php` and capabilities is `Rostdav`, provided the reference app accepts it (verify and record in `docs/compatibility.md`).
- Use the project name consistently: binary, container image, configuration keys and environment variables with the prefix `rostdav` or `ROSTDAV_`. Keep the name centrally as a constant so that a later rename stays cheap.

## 4. Technical architecture

Modular monolith with clear module boundaries and explicit interfaces:

- **Identity** – users, password hashes, app passwords, sessions, Login Flow v2
- **Metadata** – database schema, file IDs, path tree, ETags, migrations
- **Storage** – abstraction of the physical storage (local file system first), atomic writes
- **File Service** – file operations, permission checks, quota; the only place that coordinates Metadata and Storage
- **Versioning** (P2), **Sharing** (P2), **Trash** (P2)
- **WebDAV adapter** – pure protocol translation, no business logic
- **Nextcloud compat adapter** – status.php, capabilities, OCS, Login Flow
- **Web UI** – login page for Login Flow v2 (P1); file browser, devices, settings, administration (P2); see sections 2.6–2.8
- **Admin** – roles, server settings, event log, CLI; uses Identity and File Service, never Storage directly
- **Configuration** – file + environment variables, secrets only from the environment/secret files

Rules:

- Protocol adapters access only the File Service, never Storage or the database directly.
- Keep file system and database state consistent (document the order of steps; repair job/consistency check for crashes between the two).
- Concurrency: serialize writes to the same node (DB transaction/row lock); MOVE/COPY across folder boundaries atomic at the metadata level.

### 4.1 Technology stack

- If a repository with a fixed stack exists, use that one.
- Otherwise compare at most three candidates in a short table (criteria: streaming, maturity of available WebDAV building blocks, security, maintainability, deployment size) and **submit the choice as an architecture decision (ADR) in `docs/adr/` before starting phase 2.** This is an approval point (see section 7).
- Preferred candidate, unless there is a reason against it: `<enter stack, e.g. Kotlin/Spring Boot or Go or Rust>`.

## 5. Security requirements

Binding:

- Permission checks server-side on every resource, via the file ID and the effective share – never via the path alone.
- No access to other users' files, versions, uploads in progress or trash entries.
- Path traversal excluded by design (physical paths not derived from user input); additionally input validation. Do not follow symlinks in the storage area.
- Percent-encoding, double encoding, Unicode variants and `Destination` headers (including foreign hosts) are normalized and validated.
- XML parser: external entities and DTDs disabled (XXE), size and depth limits.
- TLS in production; HSTS; note on operation behind a reverse proxy with correctly configured trusted-proxy headers.
- Configurable limits: upload size, chunk size, number of parallel uploads, request body for XML, number of entries per PROPFIND.
- Brute-force protection per user **and** per IP for password login, Basic Auth, login flow polling and link passwords; constant-time comparisons for tokens.
- Login flow tokens: short-lived, single-use, sufficiently long.
- Error responses without internal paths, stack traces or secrets.
- No logging of passwords, app passwords, Authorization headers, share tokens or file contents; log fields are redacted centrally.
- Keep dependencies minimal and check them for known vulnerabilities (stack tooling in CI).

Before security-relevant changes: add a short threat analysis (STRIDE bullet points suffice) to `docs/security.md`. For authorization, path handling and shares, negative tests are mandatory (access to other users' IDs, manipulated paths, expired/revoked shares).

## 6. Development workflow

### Phase 1: Inventory

- Examine the repository, documentation, build, tests and existing architecture.
- If no project exists: create an architecture proposal, a stack ADR and a prioritized implementation plan.
- Define the reference versions of the app (section 1).
- **Approval point:** present plan and ADR.

Do not overwrite existing files and do not remove features before their meaning has been clarified.

### Phase 2: Minimal prototype (P0)

1. Server start, configuration, database migrations.
2. Create users (CLI), Basic Auth.
3. Per-user file areas with metadata and stable file IDs.
4. WebDAV: OPTIONS, PROPFIND, GET, HEAD, PUT, MKCOL, DELETE, MOVE, COPY.
5. Integration tests for all core flows, including negative and permission tests.
6. Interoperability test with a standard WebDAV client (e.g. `rclone` or `cadaver`) as a plausibility check.

**Acceptance phase 2:** All tests green; a second user demonstrably cannot access the first user's files.

### Phase 3: App compatibility (P1)

- Create reference recordings (section 3.1).
- status.php, capabilities, OCS user endpoint, Login Flow v2 including login page, app passwords.
- Nextcloud DAV properties, upload headers, chunked upload, quota.
- Cleanly reject preview/avatar endpoints.

**Acceptance phase 3:** With the reference app: add server, sign in, browse folders, upload a file (small and > 100 MB), download, rename, move, delete, sign out; revoking the app password leads to sign-out in the app. Every step has a contract test; the device test has been executed or is explicitly marked as not executed.

### Phase 4: Extensions (P2)

Admin CLI and event log → versioning → shares (users, then public links) → trash → web interface (files, devices, settings, administration, light/dark) → optional two-factor authentication → retention rules and data export. Each feature is advertised in the capabilities only after tests have passed.

### Phase 5: Hardening and delivery

Security and load tests (large files, many small files, parallel uploads), structured logs, health endpoint, container image and Compose example, backup/restore concept (back up database and storage consistently, restore test), operations documentation.

## 7. Rules for code changes and decisions

- Small, reviewable steps; one commit per step with a meaningful message.
- Create a plan before larger changes.
- Tests for new features and for every fixed bug (regression test).
- After changes, run the relevant tests and build; fix newly introduced errors.
- Follow existing project conventions; new dependencies only with a justification in the commit or an ADR.
- **Do not invent test results.** Explicitly mark tests that were not run as such.
- On errors: reproduce, determine the cause, fix in a targeted way, test again.

**Approval points (stop here and ask for feedback):**

1. Stack choice and architecture (end of phase 1).
2. Database schema for metadata, before data is persisted that would later have to be migrated.
3. Any change to authentication, token format or permission model after phase 2.
4. Irreversible operations on existing data or repositories.

Make all other decisions independently and document them in the final reports or ADRs.

## 8. Definition of done

A feature is complete when:

- the implementation exists,
- unit, integration and (if protocol-relevant) contract tests pass,
- error cases and permissions, including negative tests, are covered,
- API contracts with source references are documented in `docs/api.md` or `docs/compatibility.md`,
- the build succeeds (as far as the environment allows),
- no known critical security issues are open,
- capabilities advertise only what has been tested to work.

## 9. Documentation

- `README.md` – Rostdav: goal, feature scope, note "not Nextcloud, not affiliated with Nextcloud GmbH", prerequisites, quick start
- `AGENTS.md` – lasting working rules for coding agents (short version of these instructions)
- `docs/architecture.md` – modules, dependency direction, consistency model
- `docs/adr/` – architecture decisions
- `docs/compatibility.md` – reference versions, supported app flows with test status, unsupported features, observed app behavior for missing features
- `docs/security.md` – threat model, protective measures, open risks
- `docs/api.md` – implemented endpoints and protocol contracts with sources
- `docs/deployment.md` – installation, configuration, reverse proxy/TLS, backup and restore, operation
- `docs/admin.md` – roles, admin interface and CLI commands, settings with precedence rules, event log
- `docs/ui.md` – page structure, design tokens (light/dark), accessibility checks

## 10. Final report after every unit of work

1. What was implemented?
2. Which files were created or changed?
3. Which tests and builds were run – and which were **not**?
4. Which results were actually achieved (with an output excerpt for failures)?
5. Which assumptions were made, which limitations and risks exist?
6. What is the most sensible next step?

---

**Start with phase 1 now.** If no project exists yet, deliver an architecture proposal, a stack ADR and a prioritized plan, and stop at the first approval point.
