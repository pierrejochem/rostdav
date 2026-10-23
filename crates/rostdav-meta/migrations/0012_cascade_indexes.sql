-- Plain indexes on foreign key columns, and one plain index for the lookup of a child by name.
--
-- The database engine (Turso Database) can skip rows during `ON DELETE CASCADE` of a parent with
-- several children when the foreign key column has no plain index; a partial index does not
-- count. Deleting a folder must remove everything below it, so each foreign key column that is
-- not a row id gets an ordinary index (and the schema test in `lib.rs` keeps it that way).
--
-- `nodes(parent_id, name_key)`, plain and not unique, serves two purposes: it is the index for the
-- cascade over `parent_id`, and the way to find one child by name without reading all children
-- of the folder. The engine does not use the partial unique index `nodes_child_unique` (unique
-- among live nodes only, see 0007) for that lookup, and a plain index on `parent_id` alone made
-- every path lookup read all children of the folder.
CREATE INDEX nodes_child_lookup ON nodes(parent_id, name_key);
CREATE INDEX nodes_owner        ON nodes(owner_id);
CREATE INDEX nodes_blob_all     ON nodes(blob_id);
CREATE INDEX login_flows_user   ON login_flows(user_id);
CREATE INDEX versions_author    ON versions(author_id);
CREATE INDEX shares_recipient   ON shares(recipient_id);
CREATE INDEX trash_deleted_by   ON trash(deleted_by);
