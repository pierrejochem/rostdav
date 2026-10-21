# Weboberfläche

Anforderungen: Abschnitte 2.6–2.8 in [anweisung.md](anweisung.md). Der Entwurf ist verbindlich für Struktur und Inhalte, nicht pixelgenau.

## Referenzen

| Quelle | Inhalt |
|---|---|
| Design-Canvas „Rostdav Web-UI“ (claude.ai, privat) | Interaktiver Entwurf aller Seiten |
| [`design/mockups/web-ui/`](../design/mockups/web-ui/) | Quelltexte der Canvas-Seiten (`.dc.html`) |
| [`design/mockups/logo/`](../design/mockups/logo/) | Logo, Varianten, Farbpalette |
| [`assets/brand/`](../assets/brand/) | Logo-Dateien als SVG |
| [`crates/rostdav-web/static/tokens.css`](../crates/rostdav-web/static/tokens.css) | Design-Tokens für Hell und Dunkel |

Die `.dc.html`-Dateien sind Quellen des Design-Canvas und benötigen dessen Laufzeit (`support.js`); sie sind nicht direkt im Browser lauffähig, aber gut lesbar (HTML mit Inline-Styles und einer kleinen Logikklasse je Seite). Für die Umsetzung zählen Struktur, Texte, Abstände und Farben, nicht der Mechanismus.

## Seiten

| Seite | Mockup | Route (Vorschlag) | Priorität |
|---|---|---|---|
| Gerät verbinden (Login Flow v2) | `Login.dc.html` | `/login/v2/flow/{token}` (aus Mitschnitten verifizieren) | P1 |
| Zweiter Faktor | `Login2FA.dc.html` | `/login/2fa` | P2 |
| Dateien | `Main.dc.html` | `/apps/files/` oder `/files/` | P2 |
| Geräte & Sicherheit | `Devices.dc.html` | `/settings/devices` | P2 |
| Einstellungen | `Settings.dc.html` | `/settings/personal` | P2 |
| Administration | `Admin.dc.html` | `/settings/admin/{users,server,security,compat}` | P2 |

Kollisionen mit Nextcloud-Pfaden, die die Apps aufrufen, vermeiden: Routen der Oberfläche vor M11 gegen `docs/compatibility.md` prüfen.

## Design-Tokens

- Alle Farben kommen aus `tokens.css`; Templates verwenden ausschließlich `var(--…)`.
- Hell/Dunkel: Standard folgt `prefers-color-scheme`. Die Benutzerwahl (Einstellungen → Darstellung) setzt `data-theme="light"` oder `data-theme="dark"` auf `<html>`; „Wie System“ setzt nichts.
- Navigation ist in beiden Modi dunkel (`--nav-bg`), Rost (`--accent`) ist die einzige Akzentfarbe.
- Schriften: Space Grotesk (Text, Überschriften), JetBrains Mono (Labels, Code, technische Werte). Beide sind unter der SIL Open Font License verfügbar und werden **selbst gehostet** (keine Google-Fonts-Anfragen aus der Oberfläche, wegen CSP und Datenschutz).

## Logo

- Bildmarke: Ordner aus Eisen mit abplatzenden Rostflocken; nicht mit dem Zahnrad-Logo der Rust Foundation kombinieren.
- Die Wortmarke in `rostdav-logo-*.svg` ist als `<text>` gesetzt und hängt von der installierten Schrift ab. Vor einer Veröffentlichung in Pfade umwandeln (z. B. mit Inkscape: Objekt in Pfad).
- Favicon und App-Icon verwenden eine vereinfachte Marke mit einer Flocke.

## Technik

- Serverseitig gerendertes HTML mit `askama`, Interaktion mit `htmx` (selbst gehostet), kein eigenes JavaScript ohne Grund.
- CSP: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'`. Daher keine Inline-Styles in Templates: Styles in CSS-Dateien, Klassen statt `style=`.
- Formulare mit CSRF-Token, zustandsändernde Aktionen nur per POST.

## Barrierefreiheit (Prüfliste je Seite)

- [ ] Alle Aktionen sind `<button>` oder `<a href>`, Eingaben haben `<label>`
- [ ] Vollständig per Tastatur bedienbar, sichtbarer Fokus
- [ ] Kontrast ≥ 4,5:1 für Text in Hell und Dunkel
- [ ] Klickflächen ≥ 44 px
- [ ] Nutzbar ab 360 px Breite, Navigation stapelt sich
- [ ] Schalter mit `role="switch"` und `aria-checked`, Reiter mit `role="tab"`
