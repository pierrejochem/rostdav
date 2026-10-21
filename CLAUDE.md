# Hinweise für Claude Code

Die verbindlichen Arbeitsregeln stehen in [AGENTS.md](AGENTS.md). Die vollständige Projektanweisung ist [docs/anweisung.md](docs/anweisung.md).

## Einstieg in eine Sitzung

1. `docs/plan.md` lesen: Welcher Meilenstein ist offen, welcher Freigabepunkt steht an?
2. `docs/architecture.md` und die ADRs unter `docs/adr/` für Modulgrenzen und Speichermodell.
3. Vor Änderungen: `just check` muss grün sein.

## Aktueller Stand

- M0 abgeschlossen (Gerüst, Konfiguration, Logs, Health-Endpunkte, CI).
- Freigabepunkt 2 erteilt (ADR 0002 akzeptiert). M1 abgeschlossen (Schema, BlobStore, Namensregeln, `admin user add`).
- Nächster Meilenstein: M2 – WebDAV-Kern.

## Befehle

```sh
just check   # fmt --check, clippy -D warnings, test
just smoke   # Prozess starten und Health, Log-Schwärzung, Shutdown prüfen
just run     # lokal starten
```
