# Web UI design "liquid glass"

Source: design canvas "Rostdav Web-UI" (claude.ai artifact `Em35p8vW6s8MKa2ZZYYTua`, page `dcb81aee8d83`), copied 2026-10-22.
This is the design the web interface implements (`crates/rostdav-web/static/app.css`). The earlier design is kept in [`../web-ui/`](../web-ui/).

Same six artboards as before (Files, Devices, Settings, Administration, Connect device, Second factor); `canvas.json` is the canvas index.
Implementation notes: system fonts instead of the Google Fonts links (the CSP allows no external requests), no inline styles, the colour tokens are CSS variables in `app.css` with dark/light via `prefers-color-scheme` or `data-theme`.
