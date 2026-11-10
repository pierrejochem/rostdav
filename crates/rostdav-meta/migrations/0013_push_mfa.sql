-- M14: push sign-in approval with the RustMFA app (ADR 0014).
--
-- Every foreign key column has a plain index (see 0012 and the schema test in `lib.rs`).

-- A phone of a user. The server keeps only public keys (base64 of the X.509 SubjectPublicKeyInfo DER):
-- `request_pub` verifies request signatures, `approval_pub` verifies challenge answers.
CREATE TABLE mfa_devices (
    id              TEXT    PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name            TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    request_pub     TEXT    NOT NULL,
    approval_pub    TEXT    NOT NULL,
    push_channel    TEXT    NOT NULL CHECK (push_channel IN ('fcm', 'unifiedpush')),
    push_token      TEXT    NOT NULL,
    hardware_backed INTEGER NOT NULL,
    strongbox       INTEGER NOT NULL,
    created_at      INTEGER NOT NULL,
    last_seen_at    INTEGER,
    revoked_at      INTEGER
) STRICT;
CREATE INDEX mfa_devices_user ON mfa_devices(user_id);

-- Single-use enrollment tokens. Only the hash is stored.
CREATE TABLE mfa_enroll_tokens (
    token_hash TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    used_at    INTEGER
) STRICT;
CREATE INDEX mfa_enroll_tokens_user ON mfa_enroll_tokens(user_id);

-- One sign-in approval request for one phone. `login_ref` ties it to the sign-in that asked;
-- `released_at` is set once, when the browser took the approval.
-- `candidates` is a JSON array of the three numbers shown on the phone, `number` the right one.
CREATE TABLE mfa_challenges (
    id          TEXT    PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id   TEXT    NOT NULL REFERENCES mfa_devices(id) ON DELETE CASCADE,
    login_ref   TEXT    NOT NULL,
    nonce       TEXT    NOT NULL,
    number      INTEGER NOT NULL CHECK (number BETWEEN 10 AND 99),
    candidates  TEXT    NOT NULL,
    audience    TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
    consumed_at INTEGER,
    login_device TEXT   NOT NULL DEFAULT '',
    released_at INTEGER
) STRICT;
CREATE INDEX mfa_challenges_user   ON mfa_challenges(user_id);
CREATE INDEX mfa_challenges_device ON mfa_challenges(device_id, status);
CREATE INDEX mfa_challenges_login  ON mfa_challenges(login_ref);

-- Request nonces seen within the replay window.
CREATE TABLE mfa_nonces (
    device_id  TEXT    NOT NULL REFERENCES mfa_devices(id) ON DELETE CASCADE,
    nonce      TEXT    NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (device_id, nonce)
) STRICT;
CREATE INDEX mfa_nonces_device ON mfa_nonces(device_id);
CREATE INDEX mfa_nonces_expiry ON mfa_nonces(expires_at);

-- The own-events view of the app reads the events of one actor by action prefix.
CREATE INDEX events_actor ON events(actor, action);
