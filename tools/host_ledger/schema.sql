PRAGMA user_version = 1;

CREATE TABLE permit_commits (
    sequence INTEGER PRIMARY KEY CHECK (sequence > 0),
    ledger_id TEXT NOT NULL CHECK (length(ledger_id) > 0),
    target_id TEXT NOT NULL CHECK (length(target_id) > 0),
    permit_id TEXT NOT NULL CHECK (length(permit_id) > 0),
    generation INTEGER NOT NULL CHECK (generation > 0),
    state TEXT NOT NULL CHECK (state IN ('issued', 'consumed', 'revoked'))
) STRICT;

CREATE INDEX permit_commits_by_permit ON permit_commits (permit_id, sequence DESC);
