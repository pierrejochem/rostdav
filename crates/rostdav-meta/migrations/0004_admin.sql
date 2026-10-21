-- M7: disabled users and the event log (docs/admin.md).

ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1));

-- Never holds file contents, passwords or tokens (details are written by Rostdav code only).
CREATE TABLE events (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    actor   TEXT    NOT NULL,
    action  TEXT    NOT NULL,
    target  TEXT    NOT NULL DEFAULT '',
    ip      TEXT    NOT NULL DEFAULT '',
    details TEXT    NOT NULL DEFAULT '{}'
) STRICT;
CREATE INDEX events_ts ON events(ts);
