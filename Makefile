.PHONY: all setup fmt lint test coverage watch-test watch-lint audit clean build release check update help

# Default target when running just 'make'
all: help

# Colors for help output
BLUE := \033[36m
RESET := \033[0m

# Install all dependencies and tools
setup:
	@cargo install cargo-nextest
	@rustup component add clippy
	@rustup component add rustfmt

# Format code
fmt:
	@cargo fmt --all

# Run clippy with all features
lint:
	@cargo clippy --all-features -- -D warnings

# Run tests using nextest
test:
	@cargo nextest run --no-fail-fast --all-features

# Run tests with coverage report
coverage:
	@cargo llvm-cov nextest --all-features

# Clean build artifacts
clean:
	@cargo clean

# Build with all features
build:
	@cargo build --all-features

# Build for release
release:
	@cargo build --release

# Run all checks (format, lint, test)
check: fmt lint test

# Update dependencies
update:
	@cargo update

# Generate documentation
docs:
	@cargo doc --all-features --no-deps --open

# Help command to list all available commands
help:
	@echo "Available commands:"
	@echo "${BLUE}make setup${RESET}        - Install all dependencies and tools"
	@echo "${BLUE}make fmt${RESET}          - Format code"
	@echo "${BLUE}make lint${RESET}         - Run clippy with all features"
	@echo "${BLUE}make test${RESET}         - Run tests using nextest"
	@echo "${BLUE}make coverage${RESET}     - Run tests with coverage report"
	@echo "${BLUE}make clean${RESET}        - Clean build artifacts"
	@echo "${BLUE}make build${RESET}        - Build with all features"
	@echo "${BLUE}make release${RESET}      - Build for release"
	@echo "${BLUE}make check${RESET}        - Run all checks (format, lint, test)"
	@echo "${BLUE}make update${RESET}       - Update dependencies"
	@echo "${BLUE}make docs${RESET}         - Generate documentation"
