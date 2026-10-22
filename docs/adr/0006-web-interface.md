# ADR 0006: Web interface — sessions, CSRF, first slice

- Status: **Accepted** by the project owner on 2026-10-22 as proposed (approval point 3 granted; fonts follow later).
- Date: 2026-10-22
- Inputs: [docs/ui.md](../ui.md), requirements 2.6–2.8 in [instructions.md](../instructions.md), the mockups in `design/mockups/web-ui-glass/`.

## Context

Until now only apps sign in (Basic with app password / account password, Login Flow v2). The web interface is the first place where a *browser* holds credentials, so it needs sessions and CSRF protection. The full interface (files, devices, settings, administration, share dialog, trash, versions, 2FA) is large; it is delivered in slices, each usable on its own.

## Decision

### Slices

| Slice | Content |
|---|---|
| **11a** (this ADR) | Sign-in/sign-out, base layout and design tokens, **Files** (browse, download, new folder, upload, rename, delete), **Trash** (list, restore, delete, empty), **Devices** (list app passwords with last use, create one — shown once —, revoke, sign out all browser sessions), personal **Settings** (theme, WebDAV address, storage overview), public link page `/s/<token>` (list, download, password form), migrate the Login Flow page to the shared layout |
| 11b | Sharing dialog, versions panel, details column (file ID, ETag), search |
| 11c | **Administration**: users, server settings, security, event log, compatibility, status (everything also exists as CLI) |
| 11d | Languages (German/English, texts in resource files), profile (display name, e-mail), data export |
| M12 | Second factor (the sign-in gets a second step) |

### Browser sessions

- A session is a random 256-bit token (43 base-62 characters) in the cookie `rostdav_session`: `HttpOnly`, `SameSite=Lax`, `Path=/`, `Secure` whenever the configured public URL is `https`. Only `BLAKE3(token)` is stored (table `sessions`: user, created, last seen, expiry, address, user agent). The cookie is accepted **only** on web routes; WebDAV, OCS and public.php keep rejecting it, so a browser session can never be used by a request forged against the file protocols.
- Lifetime: idle timeout 8 hours (sliding), absolute maximum 14 days; both configurable. A new token is issued at every sign-in (no fixation). Sign-out deletes the row. The Devices page lists sessions and can end all others. Changing the password (slice 11d) ends all other sessions. Disabling or deleting a user ends their sessions at once (a session is re-checked against the user on every request).
- Sign-in uses the account password only, with the existing limiter (10 failures / 15 minutes per address and per user) and the event log (`auth.login`, `auth.login_failed`, `auth.locked`). A sign-in does not create an app password.

### CSRF

- Every state-changing request is a `POST` (or `PUT`/`DELETE` through a form-method override is **not** supported) and carries a `csrf` field: `MAC(server key, "web-csrf" ‖ session ID)`, constant-time compared. The anonymous sign-in form uses a MAC over a short-lived random value in a second cookie (double submit).
- Additionally `Origin` (or, absent, `Referer`) must match the request host when present; a mismatch is refused with 403 regardless of the token.
- GET never changes state. Downloads are plain GETs with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`; file contents are never rendered inline by the interface (no stored XSS through uploads). Names are HTML-escaped by the template engine.

### Rendering and assets

- Server-side HTML with `askama` (compile-time checked templates; dependency justified in the commit), plain forms first; `htmx` only where a form cannot do the job (upload progress), self-hosted, no CDN. No inline scripts and no `style=` attributes, so the CSP is strict: `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`. The Login Flow page moves to the same stylesheet and CSP.
- Static files (`tokens.css`, `app.css`, favicon, later fonts and htmx) are embedded in the binary and served with long cache headers and content hashes in the URL. Fonts: Space Grotesk / JetBrains Mono are not in the repository yet; until the font files are added the CSS falls back to `system-ui` / `ui-monospace`.
- All file operations go through the same `AppState` functions as WebDAV (same permission checks, trash, versions, quota); the web crate contains no storage or database code.

### Routes (checked against `docs/compatibility.md`: none is used by the apps)

`/login`, `/logout`, `/apps/files/` (folder path as query `?dir=`), `/apps/files/download`, `/apps/files/actions/*` (POST), `/apps/trash/`, `/settings/devices`, `/settings/personal`, `/s/<token>`, `/static/*`. `/` redirects to the files page when signed in, otherwise to `/login`. `/login/v2/*` stays the Login Flow.

## Consequences

- Cookies and sessions are a new attack surface; the above plus tests (CSRF missing/forged/foreign origin, cross-session token, expired and revoked sessions, disabled user, session cookie on WebDAV and OCS ignored, cookie flags, headers) are the acceptance criteria.
- The sessions table grows with sign-ins; expired rows are removed by the existing background cleanup.
- Upload through the browser is a normal `multipart/form-data` POST limited by `max_upload_bytes` in slice 11a; chunked browser upload (progress, resume) comes with 11b.

## Decisions of the project owner (2026-10-22)

1. Browser sessions approved as designed.
2. `askama` is allowed as dependency; htmx only later if needed.
3. System fonts for now; the two OFL font files are added later.
