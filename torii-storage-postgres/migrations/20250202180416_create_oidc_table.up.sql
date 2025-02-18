-- Add up migration script here
-- dialect: postgres
CREATE TABLE IF NOT EXISTS oauth_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    provider TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at timestamptz NOT NULL DEFAULT NOW(),
    updated_at timestamptz NOT NULL DEFAULT NOW(),
    FOREIGN KEY(user_id) REFERENCES users(id),
    UNIQUE(user_id, provider, subject)
);

CREATE TABLE IF NOT EXISTS nonces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    value TEXT NOT NULL,
    expires_at timestamptz NOT NULL
);
