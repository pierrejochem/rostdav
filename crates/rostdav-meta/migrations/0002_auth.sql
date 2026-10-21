-- App passwords, Login Flow v2 and server settings (ADR 0003).

CREATE TABLE settings (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;

CREATE TABLE app_passwords (
    id           INTEGER PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    -- Hex BLAKE3 of the token; the token itself is never stored.
    token_hash   TEXT    NOT NULL UNIQUE,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER
) STRICT;
CREATE INDEX app_passwords_user ON app_passwords(user_id);

CREATE TABLE login_flows (
    id           INTEGER PRIMARY KEY,
    poll_hash    TEXT    NOT NULL UNIQUE,
    login_hash   TEXT    NOT NULL UNIQUE,
    client_name  TEXT    NOT NULL,
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    -- Set when the user granted access; cleared with the row after the poll.
    user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
    app_password TEXT,
    CHECK ((user_id IS NULL) = (app_password IS NULL))
) STRICT;
