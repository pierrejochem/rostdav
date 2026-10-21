-- Schema nach ADR 0002 (Freigabepunkt 2, akzeptiert 2026-10-21).

CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    name          TEXT    NOT NULL,
    name_key      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0 CHECK (is_admin IN (0, 1)),
    quota_bytes   INTEGER CHECK (quota_bytes IS NULL OR quota_bytes >= 0),
    used_bytes    INTEGER NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    created_at    INTEGER NOT NULL
) STRICT;

-- Blobs sind unveränderlich; eine Zeile existiert erst, wenn der Blob
-- vollständig auf der Platte liegt (Invariante aus ADR 0002).
CREATE TABLE blobs (
    id         TEXT    PRIMARY KEY CHECK (length(id) = 26),
    size       INTEGER NOT NULL CHECK (size >= 0),
    checksum   TEXT    NOT NULL,
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE nodes (
    id         INTEGER PRIMARY KEY,
    owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id  INTEGER REFERENCES nodes(id) ON DELETE CASCADE,
    name       TEXT    NOT NULL,
    name_key   TEXT    NOT NULL,
    kind       TEXT    NOT NULL CHECK (kind IN ('file', 'dir')),
    size       INTEGER NOT NULL DEFAULT 0 CHECK (size >= 0),
    mtime      INTEGER NOT NULL,
    etag       TEXT    NOT NULL,
    blob_id    TEXT    REFERENCES blobs(id),
    checksum   TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    -- Dateien haben einen Blob, Ordner nie.
    CHECK ((kind = 'file') = (blob_id IS NOT NULL)),
    -- Nur Wurzelknoten haben keinen Elternknoten und den leeren Namen.
    CHECK ((parent_id IS NULL) = (name = ''))
) STRICT;

-- UNIQUE(parent_id, name_key); NULL-Eltern (Wurzeln) sind je Benutzer eindeutig.
CREATE UNIQUE INDEX nodes_child_unique ON nodes(parent_id, name_key) WHERE parent_id IS NOT NULL;
CREATE UNIQUE INDEX nodes_root_unique  ON nodes(owner_id) WHERE parent_id IS NULL;
CREATE INDEX nodes_blob ON nodes(blob_id) WHERE blob_id IS NOT NULL;
