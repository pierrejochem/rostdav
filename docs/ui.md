# Web interface

Requirements: sections 2.6–2.8 in [instructions.md](instructions.md). The design is binding for structure and content, not pixel-exact.

## References

| Source | Contents |
|---|---|
| Design canvas "Rostdav Web UI" (claude.ai, private) | Interactive design of all pages |
| [`design/mockups/web-ui/`](../design/mockups/web-ui/) | Source files of the canvas pages (`.dc.html`) |
| [`design/mockups/logo/`](../design/mockups/logo/) | Logo, variants, color palette |
| [`assets/brand/`](../assets/brand/) | Logo files as SVG |
| [`crates/rostdav-web/static/tokens.css`](../crates/rostdav-web/static/tokens.css) | Design tokens for light and dark |

The `.dc.html` files are sources of the design canvas and need its runtime (`support.js`); they do not run directly in the browser but are easy to read (HTML with inline styles and a small logic class per page). For the implementation, structure, texts, spacing and colors matter, not the mechanism.

## Pages

| Page | Mockup | Route (proposal) | Priority |
|---|---|---|---|
| Connect device (Login Flow v2) | `Login.dc.html` | `/login/v2/flow/{token}` (verify from recordings) | P1 |
| Second factor | `Login2FA.dc.html` | `/login/2fa` | P2 |
| Files | `Main.dc.html` | `/apps/files/` or `/files/` | P2 |
| Devices & security | `Devices.dc.html` | `/settings/devices` | P2 |
| Settings | `Settings.dc.html` | `/settings/personal` | P2 |
| Administration | `Admin.dc.html` | `/settings/admin/{users,server,security,compat}` | P2 |

Avoid collisions with Nextcloud paths that the apps call: check the UI routes against `docs/compatibility.md` before M11.

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
