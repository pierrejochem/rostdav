-- M12: optional two-factor authentication (ADR 0007).

-- One row per user. `enabled_at IS NULL` = setup started, not confirmed yet.
-- The secret is encrypted with a key that lives outside the database.
CREATE TABLE totp (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_enc BLOB    NOT NULL,
    nonce      BLOB    NOT NULL,
    created_at INTEGER NOT NULL,
    enabled_at INTEGER,
    -- last accepted time step: a code is accepted only for a larger step (replay protection)
    last_step  INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE recovery_codes (
    id        INTEGER PRIMARY KEY,
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT    NOT NULL,
    used_at   INTEGER
) STRICT;
CREATE INDEX recovery_codes_user ON recovery_codes(user_id);
