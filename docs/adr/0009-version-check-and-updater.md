# ADR 0009: Version check and updater

- Status: **Proposed** (approval point 1: a new outbound HTTPS client is a new part of the stack; the update path is also a new trust root). The About page and the embedded release notes need no decision and are already built; everything below is not.
- Date: 2026-10-23

## Context

The project owner asked for an About page, release notes, a version check and an updater. The About page and the release notes of the running build are `CHANGELOG.md` compiled into the binary (`rostdav_core::release`): no network, and they say exactly what is running.

The version check and the updater are different in kind. Until now the server made **no outbound connection at all**. A check adds one (to GitHub), and an updater lets a web click replace the program that holds every user's files. Both need an explicit design.

## Decision

### Version check (opt-in)

- **Off by default.** An administrator switches it on (Administration, Server; `update.check` in the configuration, locked there when set as for the other limits). Reason: a file server that calls out without being told to surprises people who run it on an isolated network.
- Once a day and on "Check now": `GET https://api.github.com/repos/pierrejochem/rostdav/releases/latest`. The request carries no instance identifier, no user data and no cookies; the only thing that identifies the caller is `User-Agent: rostdav/<version>`. Pre-releases and drafts are ignored (that endpoint already skips them). Response size is capped (1 MiB), time-out 10 s.
- The answer is parsed as JSON; only `tag_name` (must parse as a SemVer version), `html_url` (must start with `https://github.com/pierrejochem/rostdav/`), `published_at` and `body` are used. A failure is shown on the page and logged; it never affects serving files.
- The notes of a newer version are the release `body`, which the release workflow writes from the `CHANGELOG.md` section of that version. They are rendered by the same restricted Markdown renderer as the embedded notes (text, `code`, **bold**, links to https and repository paths; no HTML).
- Result and time of the last check are kept in the `settings` table (`update.latest`, `update.checked_at`), so a restart does not trigger a check.
- A banner on the administration pages says "version x.y.z is available" for administrators only.

New dependency: a small HTTPS client, **`ureq`** (blocking, run on `spawn_blocking`) with **rustls** and bundled root certificates (`webpki-roots`), so the container image needs no CA package. Cost to be measured and recorded here before acceptance: binary size and the licences it brings (`cargo deny`).

### Updater

The updater never runs by itself and never runs in a container.

- **Container image** (`ROSTDAV_INSTALL=container`, set in the Dockerfile): notify only. The page shows the new version, its notes and the steps (`docker compose pull && docker compose up -d`, back up first). The image is replaced, never patched.
- **Plain binary**: "Install update" appears when the binary's directory is writable by the server's user. Without it, the page shows the manual steps.

An update is accepted only if all of these hold:

1. The administrator confirms with their **password** in the same request (an administrator session alone is not enough to replace the program), with CSRF protection.
2. The target version is **newer** than the running one (no downgrade through the page) and equal to the version found by the check.
3. The files are downloaded from `https://github.com/pierrejochem/rostdav/releases/download/v<version>/`, with the URL built by Rostdav from the validated version, not taken from the API answer. Redirects are followed only to `https` and the hosts GitHub serves release files from.
4. **The signature verifies.** The release workflow signs the bare binary of each architecture with a [minisign](https://jedisct1.github.io/minisign/) key; the public key is compiled into Rostdav (`minisign-verify`, a small crate without dependencies). A checksum file from the same place as the file proves nothing about who made it, so it is not used as the check; it stays in the release for people who download by hand. **Without a key built in, the updater is switched off** and says so.
5. The downloaded binary is run once with `--version` and must report the expected version.
6. A **database backup** is written first (`backups/before-<version>.db`, the same code as `rostdav admin backup`). If it fails, nothing is replaced. The backup is the way back for an update that converts the database (as 0.3.0 did).

Then the new binary is written next to the old one, the old one is kept as `rostdav.previous`, the new one is moved into place with `rename` (atomic), an event `admin.update_installed` is written to the event log, and the server shuts down gracefully with exit status 75. A supervisor restarts it: `Restart=on-failure` (as in `docs/deployment.md`) does. Without a supervisor the page says to start it again. Rostdav does not re-execute itself: file descriptors and the running tasks stay out of it.

New release assets: `rostdav-<version>-<target>` (the bare binary) and `rostdav-<version>-<target>.minisig`, next to the tarball and checksum that exist today.

### What stays the owner's

The signing key cannot be made by the agent. The owner generates it (`minisign -G`), commits the public key (`crates/rostdav-app/update-key.pub`) and stores the secret key and its password as repository secrets (`MINISIGN_SECRET_KEY`, `MINISIGN_PASSWORD`). Until then the workflow skips signing, and the updater stays off. A lost or leaked key means: new key, new release, manual update (the compiled-in key cannot be replaced remotely). That is intended.

## Consequences

- Rostdav makes outbound connections only if an administrator asked for the check; the update download happens only on a confirmed click.
- The trust root of updates is the signing key, not GitHub's account or TLS. A hijacked repository account can still ship a malicious *new* key in a source change, which users see in review of any update they build themselves; a signed binary from the old key cannot be forged.
- More code to keep correct; the updater is the part of the project that can cause the most damage, so it gets negative tests: bad signature, wrong version, older version, wrong password, no CSRF, non-admin, container mode, unwritable directory, failed backup, redirect to another host.

## Alternatives considered

- **Check on by default**: rejected, see above.
- **Checksum only**: rejected (integrity, not authenticity).
- **Replace via tarball**: rejected; needs `tar` and `flate2` for no gain over a bare signed binary.
- **Re-exec the new binary**: rejected, see above.
- **No updater, check only**: the smallest option, if the owner prefers it after reading the above.
