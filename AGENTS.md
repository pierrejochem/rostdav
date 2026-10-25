# Working rules for coding agents

Short version of the project instructions. In case of conflict, the full instructions and the ADRs prevail.

## Goal

Rostdav: lean file server, compatible with the unmodified Nextcloud apps. As little custom implementation as possible, as much real protocol compatibility as necessary.

## Architecture rules

- Modular monolith; crates and dependency direction as per `docs/architecture.md`.
- Protocol crates (`dav`, `compat`, `web`) never access the database or file system directly.
- Authorization only via `authorize()` in `rostdav-app`, on the resolved node.
- Never derive physical paths from user input.
- The database never references an incomplete blob.

## Compatibility

- Never invent a response field. Every compatibility statement names its source (client code, documentation or fixture).
- Capabilities only advertise what has been tested.

## Security

- No passwords, tokens, `Authorization` headers or file contents in logs.
- Store tokens only hashed, compare in constant time.
- Parse XML without DTD/entities, with size and depth limits.
- Negative tests for authorization, paths and shares are mandatory.

## Web interface

- Mobile first: design and write CSS for a phone (360 px wide) first, widen with `min-width` queries. No horizontal page scroll, touch targets at least 44 px, no hover-only functions.
- One look everywhere: same font on all elements, including `button`, `input`, `select`, `textarea` (they do not inherit by default: use `font: inherit`). Only the two bundled fonts (Inter, JetBrains Mono); no external font or CDN requests.
- Consistent controls: same height, radius, spacing, focus ring and states (hover, active, disabled, error) for the same kind of control on every page. Reuse existing classes and tokens in `app.css` before adding new ones. Check new and changed pages against the others.
- Keyboard and accessibility: everything reachable by keyboard, visible focus, labels on every input, sufficient contrast in light and dark, `prefers-reduced-motion` respected.
- All user-visible text goes through i18n (`en` and `de`); all output is escaped.
- Verify user experience, not only tests: use the page like a user (sign in, do the task, make a mistake, recover). Error, empty and loading states must say what happened and what to do next.
- Verify with Playwright (headless Chromium) at phone (360x740), tablet and desktop widths, light and dark: screenshot, no console errors, no failed requests, no horizontal overflow, computed font family equal on all controls. Add a regression test for every UI bug fixed.

## Security (additions)

- Treat all input as hostile: validate on the server, escape on output, parameterised queries only, size limits on everything read from the network.
- Cookies `HttpOnly`, `Secure` (behind TLS), `SameSite`; CSRF protection on every state-changing form; strict `Content-Security-Policy`, no inline script.
- Rate-limit sign-in and other guessable endpoints. Do not leak whether a user, file or share exists to someone who may not know.
- Run `cargo deny` before a release; new dependencies are a risk: smallest set, maintained, licence checked.
- Never put secrets in the repository, test fixtures, screenshots or logs.

## Code quality

- Match the surrounding code: naming, comment density, idiom. Comments say why, not what.
- Small functions, no duplicated logic, no dead code, no `unwrap`/`expect` on runtime input, errors typed and propagated with context.
- Prefer the simplest change that works; no speculative features, no unrelated refactors in the same commit.
- Public behaviour is covered by tests (unit, integration, negative); fix a bug by writing the failing test first.

## Way of working

- Small steps, one commit per step. Tests for every function and every fixed bug.
- Before every commit: `just verify` (runs `just check`, `just smoke`, then builds the container image and runs the Playwright UI checks in it). Minimum when Docker is unavailable: `just check` and `just smoke`; say so in the report.
- Before every commit that changes behaviour, also check in the container: build the image (`docker build`), start it with `compose.yaml` and run the changed flow against it (health endpoint, the feature, the Playwright check). A change that works only outside the container is not done.
- Documentation is part of the change, in the same commit: `CHANGELOG.md`, `README.md`, `docs/` (`plan.md`, `architecture.md`, `api.md`, `security.md`, `ui.md`, `admin.md`, `deployment.md`, `compatibility.md`), ADRs for decisions, `CLAUDE.md` current state, `site/`. Search the docs for every renamed or removed thing. Documentation that disagrees with the code is a bug.
- Operability: every new setting has a default, an entry in `rostdav.example.toml` and the docs; every new failure mode has a clear log line (without secrets) and an error message the user can act on.
- Data safety: migrations are reversible or backed up first; test backup/restore after schema changes; never trade data integrity for speed.
- Performance: measure before optimising; keep pages light (no needless JS, images, requests); stream large bodies instead of buffering.
- New dependencies only with a justification in the commit or an ADR.
- Never invent test results; mark tests that were not run as such.

## Approval points (stop and ask)

1. Stack and architecture
2. Database schema before first persistence
3. Changes to authentication, token format or permission model after phase 2
4. Irreversible operations on data or repositories

## Final report after every unit of work

Implemented · changed files · tests run and not run · actual results · assumptions and risks · next step.
