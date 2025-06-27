# Releasing Torii

This document outlines the complete release process for the Torii workspace crates.

## Prerequisites

- A clean git working directory with no uncommitted changes
- The `cargo-release` tool installed: `cargo install cargo-release`
- Publishing permissions on crates.io for all workspace crates

## Pre-release Checklist

- [ ] Run `make check` to ensure all tests pass, code is formatted, and linting passes
- [ ] Update version numbers in all Cargo.toml files
- [ ] Update CHANGELOG.md with the new changes
- [ ] Ensure all dependencies between workspace crates include both `path` and `version`
- [ ] Commit all changes

## Release Methods

### Method 1: Using cargo-release (Recommended)

The simplest method is to use `cargo-release` which handles version bumping, tagging, and publishing:

```bash
# Dry run to see what will happen
cargo release <major|minor|patch>

# Execute the release
cargo release <major|minor|patch> --execute
```

This will:
- Bump the version in all related `Cargo.toml` files
- Create a new git tag
- Push the new tag to the remote repository
- Publish all crates to crates.io in the correct order

### Method 2: Manual Publishing

If you need more control over the release process, follow this manual publishing order:

#### Publishing Order

Due to dependency constraints, crates must be published in this specific order:

##### Level 1: Core (no internal dependencies)
- [ ] `cargo publish -p torii-core`
- [ ] Wait for crates.io to index (usually 1-2 minutes)

##### Level 2: Migration (depends on torii-core)
- [ ] `cargo publish -p torii-migration`
- [ ] Wait for crates.io to index

##### Level 3: Storage and Auth Crates (depend on torii-core/migration)
These can be published in any order within this level:

Storage backends:
- [ ] `cargo publish -p torii-storage-sqlite`
- [ ] `cargo publish -p torii-storage-postgres`
- [ ] `cargo publish -p torii-storage-seaorm`

Auth plugins:
- [ ] `cargo publish -p torii-auth-password`
- [ ] `cargo publish -p torii-auth-oauth`
- [ ] `cargo publish -p torii-auth-passkey`
- [ ] `cargo publish -p torii-auth-magic-link`

Wait for all Level 3 crates to be indexed before proceeding.

##### Level 4: Main Library (depends on all above)
- [ ] `cargo publish -p torii`

## Post-release Tasks

- [ ] Create a git tag: `git tag v0.3.0`
- [ ] Push the tag: `git push origin v0.3.0`
- [ ] Create a GitHub release with changelog
- [ ] Update documentation if needed
- [ ] Announce the release (if applicable)

## Automation Script

For manual publishing, you can use this script to automate the process:

```bash
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
```

Note: The sleep times may need adjustment based on crates.io indexing speed.

## Troubleshooting

- If a crate fails to publish, check that all its dependencies are already published and indexed
- Ensure version numbers are correctly updated in all Cargo.toml files
- Verify that workspace dependencies use both `path` and `version` fields
- Check that you have publishing permissions for all crates