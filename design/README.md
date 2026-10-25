# Design

| Folder | Contents |
|---|---|
| `mockups/logo/` | Logo draft: main logo, variants, colors and fonts |
| `mockups/web-ui/` | Web UI design: files, devices & security, settings, administration, connect device, second factor (standalone `*.html`, readable sources in `src/`) |
| `mockups/web-ui/mobile/` | Mobile-first redesign (floating glass tab bar, round upload buttons, file sheet, More page; light and dark; Inter): open `index.html`. Snapshots of the real pages, made by `scripts/screenshots.mjs` |
| `Rostdav Web-UI.html` | The same six pages in one exported file |

The six canvas pages above are the original desktop design (Space Grotesk, sidebar); the phone layout and the font were changed afterwards and are shown only in `mockups/web-ui/mobile/`. The logo `.dc.html` files come from the "Rostdav Logo" design canvas on claude.ai. They need the canvas runtime and do not open directly in a browser; they are readable as a reference for structure, text and colors. The web UI pages are exported as self-contained `.html` files that open directly in a browser; their `.dc.html` sources are in `mockups/web-ui/src/`.

Implementation notes: [`docs/ui.md`](../docs/ui.md). Finished logo files: [`assets/brand/`](../assets/brand/).
