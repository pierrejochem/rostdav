-- M9: shares (ADR 0004).

CREATE TABLE shares (
    id            INTEGER PRIMARY KEY,
    -- 0 = user share, 3 = public link (the OCS share types)
    kind          INTEGER NOT NULL CHECK (kind IN (0, 3)),
    owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id       INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    recipient_id  INTEGER REFERENCES users(id) ON DELETE CASCADE,
    -- read 1, update 2, create 4, delete 8 (bit 16 "share" is never stored: no resharing)
    permissions   INTEGER NOT NULL CHECK (permissions BETWEEN 1 AND 15),
    -- name of the mount point in the recipient's root, and its NFC key
    mount_name    TEXT,
    mount_key     TEXT,
    token         TEXT UNIQUE,
    password_hash TEXT,
    expires_at    INTEGER,
    note          TEXT    NOT NULL DEFAULT '',
    label         TEXT    NOT NULL DEFAULT '',
    hide_download INTEGER NOT NULL DEFAULT 0 CHECK (hide_download IN (0, 1)),
    created_at    INTEGER NOT NULL,
    CHECK ((kind = 0) = (recipient_id IS NOT NULL)),
    CHECK ((kind = 0) = (mount_key IS NOT NULL)),
    CHECK ((kind = 3) = (token IS NOT NULL))
) STRICT;
CREATE UNIQUE INDEX shares_mount_unique ON shares(recipient_id, mount_key) WHERE recipient_id IS NOT NULL;
CREATE UNIQUE INDEX shares_user_node_unique ON shares(node_id, recipient_id) WHERE recipient_id IS NOT NULL;
CREATE INDEX shares_owner ON shares(owner_id);
CREATE INDEX shares_node ON shares(node_id);
