-- M11a: browser sessions and per-user preferences (ADR 0006).

CREATE TABLE sessions (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- hex BLAKE3 of the cookie value; the cookie itself is never stored
    token_hash TEXT    NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    last_seen  INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip         TEXT    NOT NULL DEFAULT '',
    user_agent TEXT    NOT NULL DEFAULT ''
) STRICT;
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE user_prefs (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key     TEXT    NOT NULL,
    value   TEXT    NOT NULL,
    PRIMARY KEY (user_id, key)
) STRICT;
