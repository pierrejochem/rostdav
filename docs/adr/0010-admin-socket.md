# ADR 0010: The admin socket

- Status: **Accepted** by the project owner on 2026-10-24 (approval point 3: a new way to reach privileged functions). Built the same day.
- Date: 2026-10-24

## Context

Since the move to Turso Database ([ADR 0008](0008-metadata-database-turso.md), release 0.3.0) the process that opens the database locks its file for itself. A second process, such as `rostdav admin user add …` started beside a running server, fails with `Locking error: … File is locked by another process`. This was found on 2026-10-24 by a user whose container could not add its first user. It affected every `rostdav admin` command (users, `fsck`, `backup`, `audit export`, `import`) and made the documented online backup impossible. Before the switch, SQLite allowed two processes, so the commands, the documentation and the container instructions all assumed it; no test started the server and the command line together.

## Decision

The running server listens on a **Unix socket** `<data_dir>/admin.sock`. `rostdav admin …` first looks for that socket:

- **Socket there and answering:** the command line sends the words after `admin`, one piece of standard input (a password line) and its working directory as one JSON request; the server parses the words with the same parser, runs the same command code with the actor `Cli`, and answers with the output, the error text and the exit code. The client prints them and exits with that code.
- **Socket there, nobody answers** (a leftover from a crash): the database is free, the command opens it directly, as before.
- **No socket, database locked:** the command says that a server is using the database and what to do (start the server of this version, or stop it).
- **No server:** the command opens the database directly, as before.

Relative paths (`admin backup mybackup`, `admin import ./files`) are taken relative to where the command was typed, not to the server.

### Who may connect

No new network port, no token, no password. The circle is the one that could open the database file itself:

1. The data directory must be closed to everybody but its owner (no group or other bits); otherwise the server does not open the socket and logs why.
2. The socket is mode 0600.
3. Every connection is checked with the peer's user ID (`SO_PEERCRED`, read with the safe `peer_cred()` of the runtime): only **root** and the **owner of the socket** (the user the server runs as) are served. Others are dropped without an answer and logged.
4. A request is limited to 1 MiB and 10 s to arrive.

In the container image the server runs as user 10001, so `docker exec` (which starts as that user, or as root with `-u 0`) works, and a process of another user on the host does not.

### What is not in the request

Passwords are never arguments; they travel as the standard input line, as before, and the server never logs the request body. The log line for a command says only which user ID sent one.

## Consequences

- All `rostdav admin` commands work beside a running server again, including the online `backup`; `docs/deployment.md` and `docs/admin.md` are right again.
- A second privileged entry exists besides the web interface. It is not reachable from the network; anyone who can use it already has the files and the database.
- The command code runs inside the server process: a long `fsck --verify` shares its CPU and database writer. It was the same before (one writer at a time), only in two processes.
- The protocol has a version number (1). A client and server of different versions that disagree get a clear error.
- Not tested: a connection from a user other than owner and root (the test host has one unprivileged user). The decision itself is tested (`peer_allowed`), as is everything else: commands over the socket, exit codes, relative paths, stale socket, no socket, a data directory open to others, garbage, wrong protocol version and an oversized request.

## Alternatives considered

- **Stop the server for every command:** gives up online backup and makes adding the first user a stop-start dance.
- **Commands over the HTTP interface with an admin token:** a new credential to store and rotate, and a privileged surface on the network port.
- **A second, read-only database connection from the command line:** the engine does not allow it either, and the commands write.
