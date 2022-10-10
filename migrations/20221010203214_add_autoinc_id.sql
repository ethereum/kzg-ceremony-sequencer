CREATE TABLE new_contributors (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    uid         TEXT     NOT NULL,
    started_at  INTEGER  NOT NULL,
    finished_at INTEGER,
    expired_at  INTEGER
);

INSERT INTO new_contributors (uid, started_at, finished_at, expired_at)
SELECT uid, started_at, finished_at, expired_at from contributors;

DROP TABLE contributors;

ALTER TABLE new_contributors RENAME TO contributors;
