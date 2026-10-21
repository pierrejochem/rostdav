-- M8: file versions (ADR 0002: a changed file gets a new blob, the old one
-- stays referenced here). Versions count toward the owner's usage.

CREATE TABLE versions (
    id              INTEGER PRIMARY KEY,
    node_id         INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    -- Name in the DAV URL: the modification time of the archived content
    -- (made unique per file by moving to the next free second).
    version_time    INTEGER NOT NULL,
    mtime           INTEGER NOT NULL,
    size            INTEGER NOT NULL CHECK (size >= 0),
    blob_id         TEXT    NOT NULL REFERENCES blobs(id),
    checksum        TEXT    NOT NULL,
    client_checksum TEXT,
    author_id       INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at      INTEGER NOT NULL,
    UNIQUE (node_id, version_time)
) STRICT;
CREATE INDEX versions_blob ON versions(blob_id);
CREATE INDEX versions_created ON versions(created_at);
