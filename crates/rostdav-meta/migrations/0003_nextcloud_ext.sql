-- M5: client-provided checksum, upload time, chunked upload sessions.

-- Verbatim `OC-Checksum` value (e.g. "SHA1:ab12…"); reported as oc:checksums.
ALTER TABLE nodes ADD COLUMN client_checksum TEXT;
-- Unix time the content was stored (nc:upload_time); 0 = unknown.
ALTER TABLE nodes ADD COLUMN upload_time INTEGER NOT NULL DEFAULT 0;

CREATE TABLE upload_sessions (
    id          INTEGER PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Client-chosen name from the URL; never used as a path.
    transfer_id TEXT    NOT NULL,
    -- Server-chosen ULID naming the directory below <data>/uploads/.
    dir         TEXT    NOT NULL UNIQUE CHECK (length(dir) = 26),
    created_at  INTEGER NOT NULL,
    UNIQUE (user_id, transfer_id)
) STRICT;
