# Web UI design ("liquid glass")

Source: design canvas "Rostdav Web-UI" (claude.ai artifact `Em35p8vW6s8MKa2ZZYYTua`), exported as
[`../../Rostdav Web-UI.html`](../../Rostdav%20Web-UI.html) (all six pages in one file).

| File | Page |
|---|---|
| `Files.html` | Files |
| `Devices.html` | Devices & security |
| `Settings.html` | Settings |
| `Admin.html` | Administration |
| `Login.html` | Connect device (Login Flow v2) |
| `Login2FA.html` | Second factor |

Each `*.html` is self-contained (runtime and fonts embedded) and opens directly in a browser. The pages are
interactive mockups (theme switch, selection); links between them do not work outside the canvas.
`src/` holds the readable page sources (`.dc.html`, the canvas's component format) and the canvas index
`canvas.json`; they need the canvas runtime and are for reading, not for opening.

The mockups use Space Grotesk and JetBrains Mono; the implementation ships the same font files (`crates/rostdav-web/static/fonts/`, ADR 0006 decision 3).
