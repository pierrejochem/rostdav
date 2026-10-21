# Mitarbeit

## Einrichtung

1. Rust über [rustup](https://rustup.rs) installieren. `rust-toolchain.toml` wählt die passende Toolchain mit `rustfmt` und `clippy` automatisch.
2. Optional: [`just`](https://github.com/casey/just) und `cargo-deny` installieren:
   ```sh
   cargo install just cargo-deny --locked
   ```
3. IDE: VS Code mit den empfohlenen Erweiterungen (`.vscode/extensions.json`) oder RustRover. Beide lesen den Cargo-Workspace direkt.

## Täglicher Ablauf

```sh
just          # Liste aller Befehle
just run      # Server mit Pretty-Logs und ./data starten
just check    # fmt, clippy, Tests – vor jedem Commit
just smoke    # Smoke-Test gegen das gebaute Binary
just deny     # Abhängigkeiten, Lizenzen, Sicherheitsmeldungen
```

Ohne `just`: die Befehle stehen in der `justfile`.

## Regeln

- Arbeitsregeln für Menschen und Agenten: [`AGENTS.md`](AGENTS.md).
- Kleine Commits, je Commit ein Thema; Tests für jede Funktion und jeden behobenen Fehler.
- Entscheidungen mit Langzeitwirkung als ADR unter `docs/adr/` (fortlaufende Nummer).
- Kompatibilitätsaussagen nur mit Quelle in `docs/compatibility.md`.

## Commit-Nachrichten

Deutsch oder Englisch, erste Zeile ≤ 72 Zeichen, mit Meilenstein-Präfix, z. B. `M2: PROPFIND mit Depth 1`.

## Lizenz von Beiträgen

Beiträge werden, sofern nicht ausdrücklich anders angegeben, unter MIT OR Apache-2.0 eingebracht.
