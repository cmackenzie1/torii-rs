# Torii-rs Project Guidelines

## Build and Test Commands
- **Build:** `make build` or `cargo build --all-features`
- **Format:** `make fmt` or `cargo fmt --all`
- **Lint:** `make lint` or `cargo clippy --all-features -- -D warnings`
- **Run all tests:** `make test` or `cargo nextest run --no-fail-fast --all-features`
- **Run single test:** `cargo nextest run test_name` or `cargo test -- test_name`
- **Run with coverage:** `make coverage` or `cargo llvm-cov nextest --all-features`
- **Full check:** `make check` (runs fmt, lint, test)
- **Documentation:** `make docs` or `cargo doc --all-features --no-deps --open`
- **Always use `make test` to run project tests**

## Code Style Guidelines
- **Error Handling:** Use `thiserror` with structured error types and `#[from]` for conversions
- **Naming:** PascalCase for types, snake_case for functions/variables, SCREAMING_SNAKE_CASE for constants
- **Types:** Use newtype pattern for type safety (e.g., `UserId`, `SessionToken`)
- **Imports:** Group by category (std lib first, external crates, then internal modules)
- **Traits:** Use `async_trait` for async interfaces; design with composition in mind
- **Documentation:** Add doc comments to public interfaces and modules
- **Testing:** Write unit tests in modules with `#[cfg(test)]`; use `#[tokio::test]` for async tests
- **Builder Pattern:** Use for complex struct creation with validation at build time
- **Always use `make fmt` to format rust code**
- **Always use `make lint` to lint rust code**

## Project Structure
- Core functionality in `torii-core` crate
- Storage backends in separate crates (`torii-storage-*`)
