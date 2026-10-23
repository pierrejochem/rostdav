-- Profile pictures: one small PNG or JPEG per user (web settings and the Nextcloud avatar
-- endpoint). Kept in the database because they are at most 256 KiB and belong to the user row.
CREATE TABLE avatars (
    user_id    INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    mime       TEXT    NOT NULL CHECK (mime IN ('image/png', 'image/jpeg')),
    data       BLOB    NOT NULL CHECK (length(data) <= 262144),
    etag       TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
) STRICT;
