-- Add up migration script here
-- dialect: sqlite
CREATE TABLE IF NOT EXISTS oidc_accounts (
    id INTEGER PRIMARY KEY,
    user_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id),
    UNIQUE(user_id, provider, subject)
);

CREATE TABLE IF NOT EXISTS nonces (
    id TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    expires_at DATETIME NOT NULL
);
