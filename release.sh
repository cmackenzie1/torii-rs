#!/bin/bash
set -e

echo "Publishing torii workspace crates..."

# Level 1
echo "Publishing torii-core..."
cargo publish -p torii-core
echo "Waiting for crates.io to index..."
sleep 30

# Level 2
echo "Publishing torii-migration..."
cargo publish -p torii-migration
sleep 30

# Level 3 - Storage
echo "Publishing storage crates..."
cargo publish -p torii-storage-sqlite
cargo publish -p torii-storage-postgres
cargo publish -p torii-storage-seaorm

# Level 3 - Auth
echo "Publishing auth crates..."
cargo publish -p torii-auth-password
cargo publish -p torii-auth-oauth
cargo publish -p torii-auth-passkey
cargo publish -p torii-auth-magic-link

echo "Waiting for all Level 3 crates to be indexed..."
sleep 60

# Level 4
echo "Publishing main torii crate..."
cargo publish -p torii

echo "All crates published successfully!"
