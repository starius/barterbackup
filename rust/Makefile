# Simple helpers for the Rust workspace.

CARGO ?= cargo

.PHONY: unit build fmt clean

# Run all unit tests in the Rust workspace.
unit:
	$(CARGO) test -p keys -p clitls -p node --all-features

# Build the whole workspace in debug mode.
build:
	$(CARGO) build --workspace

# Format (if rustfmt is available).
fmt:
	$(CARGO) fmt --all || true

clean:
	$(CARGO) clean
