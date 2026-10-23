-- Plain indexes on foreign key columns.
--
-- The database engine (Turso Database) can skip rows during `ON DELETE CASCADE` of a parent with
-- several children when the foreign key column has no plain index; a partial index does not
-- count. Deleting a folder must remove everything below it, so each foreign key column that is
-- not a row id gets an ordinary index (and the schema test in `lib.rs` keeps it that way).
CREATE INDEX nodes_parent       ON nodes(parent_id);
CREATE INDEX nodes_owner        ON nodes(owner_id);
CREATE INDEX nodes_blob_all     ON nodes(blob_id);
CREATE INDEX login_flows_user   ON login_flows(user_id);
CREATE INDEX versions_author    ON versions(author_id);
CREATE INDEX shares_recipient   ON shares(recipient_id);
CREATE INDEX trash_deleted_by   ON trash(deleted_by);
