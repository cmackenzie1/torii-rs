-- Add down migration script here
-- dialect: postgres
DROP TABLE IF EXISTS oauth_accounts;
DROP TABLE IF EXISTS nonces;
