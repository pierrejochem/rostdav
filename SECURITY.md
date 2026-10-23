# Security policy

## Reporting a vulnerability

Please do **not** open a public issue for a security problem. Use GitHub's private reporting instead: on the repository page choose **Security → Report a vulnerability**. Describe what you found, how to reproduce it and which version you tested.

You get an answer as soon as possible, and the fix is released with a note in the [changelog](CHANGELOG.md). Rostdav is maintained by one person, so please allow some days.

## Supported versions

Only the newest release receives fixes.

## What is in scope

Everything in this repository: the server, the web interface, the Nextcloud-compatible endpoints and the release files. How Rostdav is meant to be secured, and what it assumes about the environment (HTTPS reverse proxy, a data directory only the service user can read), is described in the [security concept](docs/security.md).
