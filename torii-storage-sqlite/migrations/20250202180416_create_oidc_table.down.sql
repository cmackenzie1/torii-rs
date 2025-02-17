-- Add down migration script here
-- dialect: sqlite
DROP TABLE IF EXISTS oauth_accounts;
DROP TABLE IF EXISTS nonces;
