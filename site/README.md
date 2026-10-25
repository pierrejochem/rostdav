# Documentation site

Published at <https://pierrejochem.github.io/rostdav/> by `.github/workflows/pages.yml` (GitHub Pages, source "GitHub Actions").

- `content/manual/` – the user manual (written here).
- `content/admin/_index.md`, `content/reference/_index.md`, `content/_index.md` – section and home pages (written here).
- `content/admin/deployment.md`, `administration.md`, `content/reference/*.md`, `content/reference/adr/*.md` – **generated** by `scripts/site-sync.py` from `docs/`, `docs/adr/` and `CHANGELOG.md`; they are not committed. Edit the originals.
- `static/img/` is generated too (copies of `assets/brand/`). `static/media/` (screenshots, social preview) and `static/fonts/` (the web interface's fonts, SIL OFL) are committed.
- `templates/`, `static/site.css` – the theme: the colours, fonts and glass look of the web interface, dark by default and light when the visitor's system asks for it; no JavaScript.

Build and preview with [Zola](https://www.getzola.org/) 0.21 (the version CI pins; later versions changed the template engine):

```sh
just site          # sync + build into site/public
just site-serve    # sync + preview at http://127.0.0.1:1111
```

The build fails on a broken internal link or anchor. Every page needs a `description` (it becomes the search-result snippet); the generated pages take it from the document's first paragraph.

Screenshots in `static/media/screens/` are taken from a demo server in dark mode at 1280×800; retake them with `scripts/screenshots.mjs` (the file header says how to prepare the server) when the interface changes noticeably.
