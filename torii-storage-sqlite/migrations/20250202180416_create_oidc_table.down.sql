-- Add down migration script here
-- dialect: sqlite
DROP TABLE IF EXISTS oidc_accounts;
DROP TABLE IF EXISTS nonces;
