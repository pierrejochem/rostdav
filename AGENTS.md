# Working rules for coding agents

Short version of the project instructions. In case of conflict, the full instructions and the ADRs prevail.

## Goal

Rostdav: lean file server, compatible with the unmodified Nextcloud apps. As little custom implementation as possible, as much real protocol compatibility as necessary.

## Architecture rules

- Modular monolith; crates and dependency direction as per `docs/architecture.md`.
- Protocol crates (`dav`, `compat`, `web`) never access the database or file system directly.
- Authorization only via `authorize()` in `rostdav-app`, on the resolved node.
- Never derive physical paths from user input.
- The database never references an incomplete blob.

## Compatibility

- Never invent a response field. Every compatibility statement names its source (client code, documentation or fixture).
- Capabilities only advertise what has been tested.

## Security

- No passwords, tokens, `Authorization` headers or file contents in logs.
- Store tokens only hashed, compare in constant time.
- Parse XML without DTD/entities, with size and depth limits.
- Negative tests for authorization, paths and shares are mandatory.

## Way of working

- Small steps, one commit per step. Tests for every function and every fixed bug.
- Before every commit: `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo test`.
- New dependencies only with a justification in the commit or an ADR.
- Never invent test results; mark tests that were not run as such.

## Approval points (stop and ask)

1. Stack and architecture
2. Database schema before first persistence
3. Changes to authentication, token format or permission model after phase 2
4. Irreversible operations on data or repositories

## Final report after every unit of work

Implemented · changed files · tests run and not run · actual results · assumptions and risks · next step.
