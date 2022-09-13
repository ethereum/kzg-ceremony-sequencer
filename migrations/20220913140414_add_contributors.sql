CREATE TABLE IF NOT EXISTS contributors (
    uid           TEXT     PRIMARY KEY NOT NULL,
    started_at    INTEGER              NOT NULL,
    finished_at   INTEGER,
    expired_at    INTEGER
);