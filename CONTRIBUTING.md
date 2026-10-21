# Contributing

## Setup

1. Install Rust via [rustup](https://rustup.rs). `rust-toolchain.toml` automatically selects the matching toolchain with `rustfmt` and `clippy`.
2. Optional: install [`just`](https://github.com/casey/just) and `cargo-deny`:
   ```sh
   cargo install just cargo-deny --locked
   ```
3. IDE: VS Code with the recommended extensions (`.vscode/extensions.json`) or RustRover. Both read the Cargo workspace directly.

## Daily workflow

```sh
just          # list all commands
just run      # start the server with pretty logs and ./data
just check    # fmt, clippy, tests – before every commit
just smoke    # smoke test against the built binary
just deny     # dependencies, licenses, security advisories
```

Without `just`: the commands are in the `justfile`.

## Rules

- Working rules for humans and agents: [`AGENTS.md`](AGENTS.md).
- Small commits, one topic per commit; tests for every function and every fixed bug.
- Decisions with long-term impact as an ADR under `docs/adr/` (sequential number).
- Compatibility statements only with a source in `docs/compatibility.md`.

## Commit messages

First line ≤ 72 characters, with a milestone prefix, e.g. `M2: PROPFIND with Depth 1`.

## License of contributions

Unless explicitly stated otherwise, contributions are submitted under MIT OR Apache-2.0.
