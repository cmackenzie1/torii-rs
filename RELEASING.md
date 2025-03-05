# Releasing Torii

This is manual process that must be done from a clean git working directory with no uncommitted changes. The order of operations is roughly as follows:

1. Ensure CHANGELOG.md is updated with the new changes.
2. Build the project to ensure everything is working.
3. Release the new version.

## Prerequisites

- A clean git working directory with no uncommitted changes.
- The `cargo-release` tool must be installed using `cargo install cargo-release`.
- CHANGELOG.md must be updated with the new changes.

## Releasing

Before releasing, ensure the CHANGELOG.md is updated with the new changes and that the following command builds successfully:

```bash
cargo release <major|minor|patch>
```

If the build succeeds, rerun the command with the `--execute` flag to publish the release:

```bash
cargo release <major|minor|patch> --execute
```

This will:

- Bump the version in the related `Cargo.toml` files.
- Create a new git tag.
- Push the new tag to the remote repository.
- Publish the release to crates.io.
