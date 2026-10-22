# Design

| Folder | Contents |
|---|---|
| `mockups/logo/` | Logo draft: main logo, variants, colors and fonts |
| `mockups/web-ui/` | Web UI design: files, devices & security, settings, administration, connect device, second factor (standalone `*.html`, readable sources in `src/`) |
| `Rostdav Web-UI.html` | The same six pages in one exported file |

The logo `.dc.html` files come from the "Rostdav Logo" design canvas on claude.ai. They need the canvas runtime and do not open directly in a browser; they are readable as a reference for structure, text and colors. The web UI pages are exported as self-contained `.html` files that open directly in a browser; their `.dc.html` sources are in `mockups/web-ui/src/`.

Implementation notes: [`docs/ui.md`](../docs/ui.md). Finished logo files: [`assets/brand/`](../assets/brand/).
