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

## Using cargo-release

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

## Troubleshooting

- If a crate fails to publish, check that all its dependencies are already published and indexed
- Ensure version numbers are correctly updated in all Cargo.toml files
- Verify that workspace dependencies use both `path` and `version` fields
- Check that you have publishing permissions for all crates
