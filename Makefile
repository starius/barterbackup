CARGO ?= cargo

.PHONY: build test unit fmt clippy install clean

build:
	$(CARGO) build --workspace

test:
	$(CARGO) test --workspace

unit: test

fmt:
	$(CARGO) fmt --all

clippy:
	$(CARGO) clippy --workspace --all-targets

install:
	$(CARGO) install --path cmd/bbd --locked
	$(CARGO) install --path cmd/bbcli --locked

clean:
	$(CARGO) clean
