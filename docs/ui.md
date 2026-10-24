# Web interface

Requirements: sections 2.6–2.8 in [instructions.md](instructions.md). The design is binding for structure and content, not pixel-exact.

## References

| Source | Contents |
|---|---|
| Design canvas "Rostdav Web UI" (claude.ai, private) | Interactive design of all pages |
| [`design/mockups/web-ui/`](../design/mockups/web-ui/) | Design ("liquid glass"): self-contained pages (`Files.html`, …) and sources (`src/*.dc.html`) |
| [`design/mockups/logo/`](../design/mockups/logo/) | Logo, variants, color palette |
| [`assets/brand/`](../assets/brand/) | Logo files as SVG |
| [`crates/rostdav-web/static/app.css`](../crates/rostdav-web/static/app.css) | Implemented stylesheet with the design tokens for light and dark |

The `*.html` mockups open directly in a browser. The readable sources are `src/*.dc.html` (HTML with inline styles and a small logic class per page; they need the canvas runtime). For the implementation, structure, texts, spacing and colors matter, not the mechanism.

## Pages

| Page | Mockup | Route (proposal) | Priority |
|---|---|---|---|
| Connect device (Login Flow v2) | `Login.html` | `/login/v2/flow/{token}` (verify from recordings) | P1 |
| Second factor | `Login2FA.html` | `/login/2fa` | P2 |
| Files | `Files.html` | `/apps/files/` or `/files/` | P2 |
| Devices & security | `Devices.html` | `/settings/devices` | P2 |
| Settings | `Settings.html` | `/settings/personal` | P2 |
| Administration | `Admin.html` | `/settings/admin/{users,server,security,compat}` | P2 |

Avoid collisions with Nextcloud paths that the apps call: check the UI routes against `docs/compatibility.md` before M11.

## Implemented (slice 11a, ADR 0006)

| Route | Page |
|---|---|
| `/login`, `POST /logout` | Sign-in with account password, sign-out |
| `/files[/<path>]`, `/download/<path>`, `/action/{mkdir,upload,delete}` | Files: browse, download, new folder, upload, delete (confirm page) |
| `/trash`, `/trash/{restore,delete,empty}` | Trash: restore, permanent delete, empty (confirm pages) |
| `/devices`, `/devices/{create,revoke,sign-out-others}` | App passwords (shown once), browser sessions |
| `/settings`, `POST /settings/{theme,profile,export}`, `/settings/password` | Profile (display name, e-mail), change password (ends other browser sessions), theme, WebDAV address, storage overview, data export (tar of own files; no shares received, versions or trash) |
| `/s/<token>`, `/s/<token>/{unlock,dl,upload}` | Public link page: list, download, password form, upload |
| `POST /settings/avatar`, `POST /settings/avatar/delete`, `/avatar/<user>/<size>` | Profile picture: upload (PNG or JPEG, up to 256 KiB), remove, and the picture itself for the pages |
| `/about` | About: version, licence, source code, release notes of all versions (`CHANGELOG.md` compiled in, English only). Any signed-in user. Version check and updater: [ADR 0009](adr/0009-version-check-and-updater.md), proposed |
| `/search?q=&scope=&kind=&page=` | Search by name in everything the user can reach: own files and received shares, all folders below `scope` (default: everywhere), files and/or folders, 50 per page, best match first (exact name, then names that start with the text, then the rest). Case, accents and the two spellings of an accented letter (`é` or `e` + accent) do not matter; `ß` is `ss`. Each hit passes the normal read check (`resolve_access` + `authorize_access`) and trashed items are not visited; public-link principals cannot search. Results beyond 200,000 visited nodes are cut with a notice. Content search and the apps' search: [plan](../CHANGELOG.md) |
| `/recent` | Recent: the 100 own files that changed last (not trash, not files shared with me), each linking to its folder with the file selected |
| `/shares`, `POST /shares/delete` | Overview of all shares: shared by me (with recipient or link address, access, expiry, "Stop sharing") and shared with me (owner, access) |
| `/share?path=`, `/share/{user,link,delete}` | Sharing dialog: share with a user, create/stop public links (password, expiry, view/edit/upload-only) |
| `/versions?path=`, `/versions/{restore,delete}` | Versions panel of a file |
| `/files[/<path>]?q=&sel=&sort=&dir=` | Files page as designed (column headers sort by name, size or modified, folders stay first): search/filter box, tiles per type, "Shared" chip, details panel (selected file via `sel`, else the open folder: download, share, delete, versions with restore, shares, file ID and ETag), upload progress card, storage meter in the sidebar |
| `POST /web/mkdir` | Makes one folder (JSON `{"path": "a/b"}`, `X-CSRF-Token`); an existing folder answers 200, a file of that name 409. Used by the page script to recreate dropped or picked folders |
| `/web/upload/<id>[/<chunk>\|/finish]` | Chunked, resumable browser upload (used by `/static/upload.js`; session + `X-CSRF-Token` header) |
| `/admin/users`, `/admin/users/{create,manage,disabled,role,quota,password,delete}` | Administration: users (add, block, role, quota, password reset, delete with transfer) |
| `/admin/events` | Administration: event log (period filter, newest 500) |
| `/admin/status`, `POST /admin/status/check` | Administration: version, usage, consistency check (optional checksums and repair) |
| `/admin/server`, `POST /admin/server/{set,reset}` | Administration: adjustable limits (quota for new users, unfinished-upload expiry, version, trash and event log retention; "Back to default"), and the other effective settings (read-only) |
| `/admin/security`, `POST /admin/security/{maintenance,unlock}` | Administration: maintenance mode on/off; active sign-in lockouts (address, user, two-factor) with "Unlock" |
| `/login/2fa`, `/settings/2fa[/disable\|/codes]` | Second sign-in step; set up, turn off and recovery codes of two-factor authentication (ADR 0007); admin reset at `/admin/users/two-factor-reset` |
| (all sign-in pages) | Layout of `layout::bare`: a dark brand panel with the full logo (`assets/brand/rostdav-logo-dark.svg`, put into the page so the wordmark uses Space Grotesk; the file's own dark tile is cut out) beside the form; below 860 px the panel is a band above it. This replaces the single folder tile of `design/mockups/web-ui/Login.html`; the mockup was not updated. |
| `/login/v2/flow/<token>` | Connect device (Login Flow v2; second step on the same page) |
| `/static/{app,login}.css` | Embedded stylesheets |

Route check against `docs/compatibility.md`: none of these paths is used by the Nextcloud apps' WebDAV, OCS or `status.php` calls. `/s/<token>` is the address Nextcloud itself uses for public links, so links created through the OCS API open in this page.

Security properties (each has a test in `crates/rostdav/tests/web.rs`):

- Session cookie `rostdav_session`: random 256-bit value, stored only as a hash, `HttpOnly`, `SameSite=Lax`, `Secure` behind HTTPS (`X-Forwarded-Proto`). Accepted on web routes only, never on WebDAV or OCS.
- Every state-changing request needs a same-origin `Origin`/`Referer` and a CSRF token bound to the session. Anonymous forms (sign-in, link password, link upload) use a double-submit cookie.
- Content-Security-Policy `default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'self'; …`: no inline styles or scripts. The only script is `/static/upload.js` (chunked upload; the plain form works without it). All user-controlled text is HTML-escaped.
- Downloads are always `attachment` with `nosniff` and `sandbox`.
- Two-factor: after a correct password the browser holds only a 5-minute ticket cookie (`rostdav_2fa`, path `/login`, HttpOnly); the session exists only after a valid code. Codes are single-use and rate limited.
- Public link password proof: a one-hour ticket cookie tied to the link and scoped to `/s/<token>`.

Administration pages call the same `Actor`-checked service methods as the CLI; a non-administrator gets 403 on every `/admin/*` route. Fonts: Space Grotesk (variable, latin) and JetBrains Mono 500 (latin), SIL OFL 1.1, taken from `design/Rostdav Web-UI.html`, stored in `crates/rostdav-web/static/fonts/` with their licences and served from `/static/` (CSP `font-src 'self'`). Latin only: umlauts work, other scripts fall back to the system font. Pages follow the design: Files, Devices & security (with the two-factor card), Settings (appearance, WebDAV address, storage; no file options yet), Administration (users, event log, status, server; no security/compatibility tabs). Not yet: Recent and Shares sidebar entries (no backing feature), folder item counts in the list, security and compatibility pages (rate-limit and capability views), language/profile settings, recursive search,  administration pages, second factor (slices 11b–11d, M12).

Checks done on every page (14 pages × 360/768/1440 px × light/dark, Playwright + axe-core 4.10, tags wcag2a/aa, wcag21a/aa, wcag22aa, best-practice): no horizontal page overflow, no axe violations. Tables scroll inside a focusable region on small screens; password fields get a show/hide button (`/static/password.js`, `aria-pressed`, field name kept stable); sign-in pages have a `main` landmark. Not covered by automated checks: screen-reader announcements and keyboard order were not tried by hand.

## Languages

English and German. The language comes from the user's setting (Settings › Profile › Language: Same as browser, English, Deutsch); "Same as browser" and the pages without a signed-in user (sign-in, Login Flow, public links) follow the `Accept-Language` header and fall back to English.

- Texts are written in English in the code and looked up with `t(lang, "English text")` / `tf(lang, "… {0} …", &[arg])` (`crates/rostdav-web/src/i18n.rs`). The German version lives in `crates/rostdav-web/i18n/de.tsv` (`English<TAB>Deutsch`). A missing entry falls back to English.
- Adding a language: add a variant to `Lang`, a table next to `de.tsv`, and the language to the allowed values of the `language` preference (`crates/rostdav-app/src/web.rs`).
- `german_interface_is_complete` (`crates/rostdav/tests/web.rs`) renders every page in German and fails if any text has no translation; the dictionary test checks keys and placeholders.
- Not translated: messages that come from the server core (for example share error texts from the OCS layer), event-log action names, and technical values on the administration Server page.
- The scripts (`upload.js`, `password.js`, `copy.js`) carry their own small German tables and read the page language from `<html lang>`.

## Data export

Settings › Export your data streams a tar archive of the user's own files (folder structure kept; no received shares, versions or trash). The requirement asked for a background job with a time-limited download link for large amounts; this implementation streams the archive directly instead: nothing is written to disk, nothing is stored, there is no link that could leak, and a cancelled download stops the work. The price is that the browser must stay connected for the whole transfer. If that turns out to be a problem for very large accounts, a resumable job can be added later.

Development with live reload: `docker compose up --build` (see the file header). The container rebuilds and restarts the server when files under `crates/` change.

## Design-Tokens

- All colors come from `tokens.css`; templates use only `var(--…)`.
- Light/dark: the default follows `prefers-color-scheme`. The user's choice (Settings → Appearance) sets `data-theme="light"` or `data-theme="dark"` on `<html>`; "Same as system" sets nothing.
- The navigation is dark in both modes (`--nav-bg`); rust (`--accent`) is the only accent color.
- Fonts: Space Grotesk (text, headings), JetBrains Mono (labels, code, technical values). Both are available under the SIL Open Font License and are **self-hosted** (no Google Fonts requests from the interface, because of CSP and privacy).

## Logo

- Logo mark: an iron folder with flaking rust; do not combine with the Rust Foundation gear logo.
- The wordmark in `rostdav-logo-*.svg` is set as `<text>` and depends on the installed font. Convert to paths before publishing (e.g. with Inkscape: Object to Path).
- Favicon and app icon use a simplified mark with a single flake.

## Technology

- Server-side rendered HTML with `askama`, interaction with `htmx` (self-hosted), no custom JavaScript without reason.
- CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'`. Therefore no inline styles in templates: styles in CSS files, classes instead of `style=`.
- Forms with CSRF token, state-changing actions via POST only.

## Accessibility (checklist per page)

- [ ] All actions are `<button>` or `<a href>`, inputs have a `<label>`
- [ ] Fully operable by keyboard, visible focus
- [ ] Contrast ≥ 4.5:1 for text in light and dark
- [ ] Click targets ≥ 44 px
- [ ] Usable from 360 px width, navigation stacks
- [ ] Switches with `role="switch"` and `aria-checked`, tabs with `role="tab"`
