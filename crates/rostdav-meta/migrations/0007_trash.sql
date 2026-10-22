-- M10: trash (ADR 0005). Deleted subtrees stay in `nodes`, marked with a trash ID.

CREATE TABLE trash (
    id         INTEGER PRIMARY KEY,
    -- the top node of the deleted subtree
    node_id    INTEGER NOT NULL UNIQUE REFERENCES nodes(id) ON DELETE CASCADE,
    owner_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- location before deletion, below the owner's root, without a leading slash
    orig_path  TEXT    NOT NULL,
    orig_name  TEXT    NOT NULL,
    deleted_at INTEGER NOT NULL,
    deleted_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (owner_id, orig_name, deleted_at)
) STRICT;

-- NULL = part of the live tree; otherwise the ID of the trash entry it belongs to.
ALTER TABLE nodes ADD COLUMN trash_id INTEGER;
CREATE INDEX nodes_trash ON nodes(trash_id) WHERE trash_id IS NOT NULL;

-- A trashed item may share its name with a live one.
DROP INDEX nodes_child_unique;
CREATE UNIQUE INDEX nodes_child_unique ON nodes(parent_id, name_key)
    WHERE parent_id IS NOT NULL AND trash_id IS NULL;
