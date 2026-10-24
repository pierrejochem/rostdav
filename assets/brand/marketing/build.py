#!/usr/bin/env python3
"""Generate the HTML sources of the marketing assets into src/. Render with render.sh."""
from pathlib import Path
SRC = Path(__file__).parent / "src"

def page(name, w, h, body, cls="dark", extra=""):
    (SRC / f"{name}.html").write_text(f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>{name}</title>
<link rel="stylesheet" href="brand.css"><style>@page{{size:A4;margin:0}}
html,body{{width:{w}px;height:{h}px;overflow:hidden}}
.c{{position:relative;width:{w}px;height:{h}px;overflow:hidden}}{extra}</style></head>
<body><div class="c {cls}">{body}</div></body></html>""")

LOGO = lambda h, mark="rostdav-mark.svg": f'<img src="{mark}" style="height:{h}px">'
WM = lambda s: f'<span class="wordmark" style="font-size:{s}px">rost<b>dav</b></span>'
LOCKUP = lambda s, icon=False: f'<div style="display:flex;align-items:center;gap:{s*.22}px">{LOGO(s*1.1, "rostdav-app-icon.svg") if icon else LOGO(s*1.1)}{WM(s)}</div>'
URL = "pierrejochem.github.io/rostdav"

# --- GitHub social preview 1280x640 / OG 1200x630
for name, w, h in [("social-preview", 1280, 640), ("og", 1200, 630)]:
    page(name, w, h, f"""<div class="grid-bg"></div><div class="glow" style="width:520px;height:520px;right:-120px;top:-160px"></div>
<div style="position:absolute;inset:0;padding:{h*.11}px {w*.07}px;display:flex;flex-direction:column;justify-content:space-between">
{LOCKUP(54)}
<div><div style="font-size:{w*.058}px;font-weight:700;letter-spacing:-.035em;line-height:1.04">Your files.<br>Your server.<br><span class="accent">One small program.</span></div>
<div style="margin-top:26px;font-size:{w*.0235}px;color:#C9C2B9;max-width:{w*.72}px;line-height:1.35">Self-hosted file server in Rust. WebDAV that works with the official Nextcloud apps.</div></div>
<div class="mono" style="font-size:22px;color:#A9A39C;display:flex;justify-content:space-between"><span>{URL}</span><span>Apache-2.0 OR MIT</span></div></div>""")

# --- X header 1500x500
page("x-header", 1500, 500, f"""<div class="grid-bg"></div><div class="glow" style="width:500px;height:500px;right:100px;top:-200px"></div>
<div style="position:absolute;left:80px;top:0;bottom:0;display:flex;flex-direction:column;justify-content:center;gap:22px">
{LOCKUP(60)}<div style="font-size:40px;font-weight:700;letter-spacing:-.02em">Self-hosted files. <span class="accent">No PHP. No stack.</span></div>
<div class="mono" style="font-size:22px;color:#A9A39C">WebDAV · Nextcloud apps · Linux x86-64 + arm64</div></div>
<img src="rostdav-mark.svg" style="position:absolute;right:90px;top:90px;height:320px;opacity:.95">""")

# --- LinkedIn 1584x396
page("linkedin-banner", 1584, 396, f"""<div style="position:absolute;left:90px;top:0;bottom:0;display:flex;flex-direction:column;justify-content:center;gap:16px">
<div style="font-size:54px;font-weight:700;letter-spacing:-.03em;line-height:1.05">One small program.<br>All your files.</div>
<div style="font-size:26px;opacity:.9">Open-source file server that speaks Nextcloud's language.</div></div>
<div style="position:absolute;right:90px;top:0;bottom:0;display:flex;align-items:center;gap:20px"><img src="rostdav-app-icon.svg" style="height:150px"><span class="wordmark" style="font-size:80px">rost<b>dav</b></span></div>""", cls="rust")

# --- Instagram post 1080x1080
page("ig-post", 1080, 1080, f"""<div style="position:absolute;inset:0;padding:90px;display:flex;flex-direction:column;justify-content:space-between">
{LOCKUP(48)}
<div style="font-size:112px;font-weight:700;letter-spacing:-.045em;line-height:.98">No PHP.<br>No web stack.<br><span class="accent">Just your files.</span></div>
<div style="display:flex;gap:14px;font-size:28px"><span class="pill">WebDAV</span><span class="pill">Nextcloud apps</span><span class="pill">Rust</span></div></div>""", cls="light")

# --- Instagram story 1080x1920
page("ig-story", 1080, 1920, f"""<div class="grid-bg"></div><div class="glow" style="width:700px;height:700px;left:-200px;top:1200px"></div>
<div style="position:absolute;inset:0;padding:140px 90px;display:flex;flex-direction:column;justify-content:space-between">
{LOCKUP(52)}
<div><img src="rostdav-mark.svg" style="height:320px;margin-bottom:60px">
<div style="font-size:120px;font-weight:700;letter-spacing:-.045em;line-height:.98">Your files.<br>Your server.<br><span class="accent">One program.</span></div>
<div style="margin-top:44px;font-size:38px;color:#C9C2B9;line-height:1.35">Self-hosted WebDAV that works with the official Nextcloud apps.</div></div>
<div class="mono" style="font-size:30px;color:#A9A39C">{URL}</div></div>""")

# --- Feature cards 1080x1080
cards = [
 ("sync", "Sync with the apps you know.", "Sign in from the official Nextcloud Android app or desktop client with Login Flow v2 and a separate app password per device.", "dark"),
 ("safety", "Mistakes are undoable.", "Versions for every file, a trash with retention, and shares with public links, all in the web interface.", "light"),
 ("small", "One binary. One folder.", "No PHP, no web server stack, no separate database server. Back up with a single command-line call.", "rust"),
]
for key, head, sub, cls in cards:
    page(f"card-{key}", 1080, 1080, f"""<div style="position:absolute;inset:0;padding:90px;display:flex;flex-direction:column;justify-content:space-between">
<div style="display:flex;justify-content:space-between;align-items:center">{LOCKUP(40, cls=='rust')}<span class="mono" style="font-size:24px;opacity:.7">0{[c[0] for c in cards].index(key)+1}/03</span></div>
<div><div style="font-size:104px;font-weight:700;letter-spacing:-.04em;line-height:1">{head}</div>
<div style="margin-top:40px;font-size:40px;line-height:1.35;max-width:880px;opacity:.85">{sub}</div></div>
<div class="mono" style="font-size:24px;opacity:.7">{URL}</div></div>""", cls=cls)

# --- Avatar 800x800
page("avatar", 800, 800, '<img src="rostdav-app-icon.svg" style="width:800px;height:800px">', cls="dark")

# --- Business card 1050x600
page("card-front", 1050, 600, f'<div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center">{LOCKUP(96)}</div>', cls="dark")
page("card-back", 1050, 600, f"""<div style="position:absolute;inset:0;padding:70px;display:flex;flex-direction:column;justify-content:space-between">
<div><div style="font-size:44px;font-weight:700;letter-spacing:-.02em">Your Name</div><div style="font-size:26px;color:var(--text-2);margin-top:6px">Role · Rostdav</div></div>
<div class="mono" style="font-size:24px;line-height:1.7">name@example.org<br>{URL}<br>github.com/pierrejochem/rostdav</div></div>
<img src="rostdav-mark.svg" style="position:absolute;right:60px;bottom:50px;height:120px">""", cls="light")

# --- One-pager A4 (794x1123 css px)
feat = [("Works with Nextcloud apps","Android app and desktop sync client, Login Flow v2, chunked upload, favorites."),
        ("Versions, trash, shares","Restore older versions and deleted files; public links and user shares."),
        ("Search","By name and by the text of files, over everything you can reach."),
        ("Web interface","Light and dark, English and German, administration, optional two-factor."),
        ("Operations","Event log, consistency check, maintenance mode, backup and restore from the CLI."),
        ("Open source","Apache-2.0 or MIT. Linux x86-64 and arm64, as a binary or container image.")]
fh = "".join(f'<div style="border-top:3px solid var(--rust);padding-top:14px"><div style="font-weight:700;font-size:19px;margin-bottom:6px">{a}</div><div style="font-size:15px;line-height:1.45;color:var(--text-2)">{b}</div></div>' for a,b in feat)
page("one-pager", 794, 1123, f"""<div style="position:absolute;left:0;right:0;top:0;height:490px;background:var(--iron);color:var(--ivory);padding:56px 56px">
<div style="display:flex;justify-content:space-between;align-items:center">{LOCKUP(40)}<span class="mono" style="font-size:14px;color:#A9A39C">v0.7</span></div>
<div style="margin-top:56px;font-size:64px;font-weight:700;letter-spacing:-.04em;line-height:1.02">Your files.<br>Your server.<br><span style="color:var(--copper)">One small program.</span></div>
<div style="margin-top:22px;font-size:20px;color:#C9C2B9;max-width:560px;line-height:1.4">A lean, self-hosted file server in Rust with WebDAV that works with the official Nextcloud apps.</div></div>
<div style="position:absolute;left:56px;right:56px;top:535px;display:grid;grid-template-columns:1fr 1fr;gap:30px 36px">{fh}</div>
<div style="position:absolute;left:56px;right:56px;top:920px;background:#fff;border-radius:14px;padding:22px 26px;border:1px solid #E6DFD5">
<div style="font-weight:700;font-size:16px;margin-bottom:8px">Start in a minute</div>
<div class="mono" style="font-size:15px;line-height:1.7">cargo run -p rostdav -- serve<br>curl http://127.0.0.1:8080/healthz</div></div>
<div style="position:absolute;left:56px;right:56px;bottom:40px;display:flex;justify-content:space-between;font-size:13px;color:var(--text-2)">
<span class="mono">{URL}</span><span>Not a Nextcloud product; not affiliated with Nextcloud GmbH.</span></div>""", cls="light")
print("written")
