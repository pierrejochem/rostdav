#!/usr/bin/env python3
"""Copies the project's Markdown documents into the site (site/content) and the brand files into
site/static/img, so the site never holds a second copy that can drift.

The generated files are not committed (see site/.gitignore). Links between documents are
rewritten to Zola's internal links (checked by `zola build`); links to source files and folders
point to GitHub. Run from anywhere: `python3 scripts/site-sync.py`.
"""

import re
import shutil
import sys
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
REPO = "https://github.com/pierrejochem/rostdav"

# source -> (target below site/content, weight, description)
DOCS = {
    "docs/deployment.md": ("admin/deployment.md", 20, "Install Rostdav from the released binary, the container image or source, run it behind a reverse proxy, back it up, restore it and upgrade it."),
    "docs/admin.md": ("admin/administration.md", 30, "Roles, the rostdav admin command line, settings and their precedence, retention, two-factor authentication and the event log."),
    "docs/architecture.md": ("reference/architecture.md", 10, "How Rostdav is built: modules, request handling, the data model and the threat model."),
    "docs/security.md": ("reference/security.md", 20, "The security concept of Rostdav: trust boundaries, threats and the measures against them."),
    "docs/compatibility.md": ("reference/compatibility.md", 30, "Which Nextcloud apps and which versions were tried against Rostdav, what works and what does not, with the evidence."),
    "docs/api.md": ("reference/api.md", 40, "The HTTP endpoints Rostdav implements: WebDAV, status.php, capabilities, OCS and Login Flow v2."),
    "docs/ui.md": ("reference/web-interface.md", 50, "The web interface: pages, routes, security properties, design tokens and accessibility."),
    "docs/plan.md": ("reference/roadmap.md", 60, "Milestones, acceptance criteria and the state of the project."),
    "CHANGELOG.md": ("reference/changelog.md", 70, "Every change in every release of Rostdav, newest first."),
}
for f in sorted((ROOT / "docs/adr").glob("0*.md")):
    DOCS[f"docs/adr/{f.name}"] = (f"reference/adr/{f.name}", int(f.name[:4]), "")

BRAND = ["rostdav-logo-dark.svg", "rostdav-logo-light.svg", "rostdav-mark.svg", "rostdav-mark-mono.svg", "rostdav-app-icon.svg", "favicon.svg"]


def site_path(rel_target: str) -> str:
    return "@/" + rel_target


def first_paragraph(body: str) -> str:
    for block in re.split(r"\n\s*\n", body):
        block = block.strip()
        if not block or block.startswith(("#", "|", "-", "*", "```", ">", "1.", "<")):
            continue
        text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", block)
        text = re.sub(r"[`*_]", "", text)
        text = " ".join(text.split())
        if len(text) > 160:
            text = text[:157].rsplit(" ", 1)[0] + "..."
        return text
    return ""


def rewrite(body: str, src: str, warn: list) -> str:
    srcdir = PurePosixPath(src).parent
    out, fenced = [], False
    for line in body.split("\n"):
        if line.lstrip().startswith("```"):
            fenced = not fenced
        if fenced:
            out.append(line)
            continue

        def fix(m):
            label, target = m.group(1), m.group(2)
            if re.match(r"^([a-z]+:|#|/)", target):
                return m.group(0)
            path, _, anchor = target.partition("#")
            resolved = PurePosixPath(*[p for p in (srcdir / path).parts]).as_posix()
            # normalise ".." without touching the file system
            parts = []
            for p in resolved.split("/"):
                if p == "..":
                    if parts:
                        parts.pop()
                elif p not in ("", "."):
                    parts.append(p)
            resolved = "/".join(parts)
            suffix = f"#{anchor}" if anchor else ""
            if resolved in DOCS:
                return f"[{label}]({site_path(DOCS[resolved][0])}{suffix})"
            real = ROOT / resolved
            if resolved == "docs/adr":
                return f"[{label}]({site_path('reference/adr/_index.md')})"
            if real.is_dir():
                return f"[{label}]({REPO}/tree/main/{resolved}{suffix})"
            if real.exists():
                return f"[{label}]({REPO}/blob/main/{resolved}{suffix})"
            warn.append(f"{src}: link target not found: {target}")
            return m.group(0)

        out.append(re.sub(r"\[([^\]]*)\]\(([^)\s]+)\)", fix, line))
    return "\n".join(out)


def toml_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main() -> int:
    warn: list = []
    for src, (target, weight, desc) in DOCS.items():
        text = (ROOT / src).read_text(encoding="utf-8")
        m = re.match(r"# (.+)\n", text)
        title = m.group(1).strip() if m else Path(src).stem
        body = text[m.end():] if m else text
        body = rewrite(body.lstrip("\n"), src, warn)
        if src.startswith("docs/adr/"):
            title = re.sub(r"^ADR (\d+): ", r"ADR \1 · ", title)
        if src == "CHANGELOG.md":
            title = "Changelog"
        description = desc or first_paragraph(body) or title
        dest = SITE / "content" / target
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            "+++\n"
            f"title = {toml_str(title)}\n"
            f"description = {toml_str(description)}\n"
            f"weight = {weight}\n"
            f"[extra]\nsource = {toml_str(src)}\n"
            "+++\n\n" + body,
            encoding="utf-8",
        )
    img = SITE / "static" / "img"
    img.mkdir(parents=True, exist_ok=True)
    for name in BRAND:
        shutil.copy(ROOT / "assets/brand" / name, img / name)
    for w in warn:
        print("warning:", w, file=sys.stderr)
    print(f"synced {len(DOCS)} documents and {len(BRAND)} brand files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
