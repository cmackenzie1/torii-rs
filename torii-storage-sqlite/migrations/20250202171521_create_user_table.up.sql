-- Add up migration script here
-- dialect: sqlite
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT,
    email TEXT,
    email_verified_at INTEGER,
    password_hash TEXT,
    created_at INTEGER DEFAULT (unixepoch()),
    updated_at INTEGER DEFAULT (unixepoch()),
    UNIQUE(email),
    UNIQUE(id)
);
