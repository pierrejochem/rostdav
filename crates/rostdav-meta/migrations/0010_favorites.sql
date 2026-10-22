-- M6: favorites (`oc:favorite`, PROPPATCH, REPORT oc:filter-files). Per user, so a
-- shared node can be a favorite of the receiver without touching the owner's view.
CREATE TABLE favorites (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    node_id INTEGER NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, node_id)
) STRICT, WITHOUT ROWID;
CREATE INDEX favorites_node ON favorites(node_id);
