-- (WITHOUT ROWID was dropped when the database engine changed to Turso, which cannot write to
-- such tables. Databases made earlier are converted by `Db::migrate`.)
-- M6: favorites (`oc:favorite`, PROPPATCH, REPORT oc:filter-files). Per user, so a
-- shared node can be a favorite of the receiver without touching the owner's view.
CREATE TABLE favorites (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, node_id)
) STRICT;
CREATE INDEX favorites_node ON favorites(node_id);
