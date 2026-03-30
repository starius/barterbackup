CARGO ?= cargo
CLANG_FORMAT ?= clang-format
PROTO_FILES := $(shell find bbrpc clirpc storedpb -type f -name '*.proto' | sort)

.PHONY: build test unit fmt clippy install clean

build:
	$(CARGO) build --workspace

test:
	$(CARGO) test --workspace

unit: test

fmt:
	$(CARGO) fmt --all
	$(CLANG_FORMAT) -i $(PROTO_FILES)

clippy:
	$(CARGO) clippy --workspace --all-targets

install:
	$(CARGO) install --path cmd/bbd --locked
	$(CARGO) install --path cmd/bbcli --locked

clean:
	$(CARGO) clean
