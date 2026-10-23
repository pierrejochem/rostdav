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

## Documentation site

The user manual is `site/content/manual/`; the other pages come from `docs/` and `CHANGELOG.md`. `just site` builds it (Zola 0.21), see [site/README.md](site/README.md). Link every compatibility statement in the manual to the [compatibility report](docs/compatibility.md) and describe only what the interface really shows.

## Dependency updates

Dependabot (`.github/dependabot.yml`) opens pull requests for Cargo, GitHub Actions and Docker updates; CI runs the tests, clippy and `cargo deny` on each. The `turso` crates are ignored on purpose: the version is pinned exactly ([ADR 0008](docs/adr/0008-metadata-database-turso.md)) and changed by hand.

## Release signing key (maintainer, once)

The updater only installs files signed with the project's minisign key; its public half is compiled into the program from `crates/rostdav-app/update-key.pub`.

```sh
minisign -G -p update-key.pub -s ~/rostdav-release.key     # asks for a password; keep the .key file and the password safe
cp update-key.pub crates/rostdav-app/update-key.pub        # commit this file
gh secret set MINISIGN_SECRET_KEY < ~/rostdav-release.key
gh secret set MINISIGN_PASSWORD                            # paste the password
```

Until the public key is committed, builds report "no update signing key" and the updater stays off. The release workflow signs every bare binary and checks the signature against the committed public key before it creates the release. A lost or leaked key means a new key, a new release, and a manual update for every server (the key in a running program cannot be replaced remotely).

