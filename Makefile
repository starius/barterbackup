CARGO ?= cargo
RUSTC ?= rustc
CLANG_FORMAT ?= clang-format
PROTO_FILES := $(shell find bbrpc clirpc storedpb -type f -name '*.proto' | sort)
HOST_TRIPLE := $(shell $(RUSTC) -vV | sed -n 's/^host: //p')
WINDOWS_TARGET := x86_64-pc-windows-msvc
STATIC_TARGET_DIR ?= target-static
WINDOWS_TARGET_DIR ?= target-windows
SANITIZER_TARGET_DIR ?= target-sanitize

ifeq ($(HOST_TRIPLE),x86_64-unknown-linux-gnu)
STATIC_TARGET := x86_64-unknown-linux-musl
STATIC_CC_ENV := \
	CC_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-gcc \
	CXX_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-g++ \
	AR_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-ar
else ifeq ($(HOST_TRIPLE),aarch64-unknown-linux-gnu)
STATIC_TARGET := aarch64-unknown-linux-musl
STATIC_CC_ENV := \
	CC_aarch64_unknown_linux_musl=aarch64-unknown-linux-musl-gcc \
	CXX_aarch64_unknown_linux_musl=aarch64-unknown-linux-musl-g++ \
	AR_aarch64_unknown_linux_musl=aarch64-unknown-linux-musl-ar
endif

.PHONY: build test unit fmt clippy install build-static build-windows sanitize-address clean

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

build-static:
ifndef STATIC_TARGET
	$(error build-static requires an x86_64-linux or aarch64-linux host)
endif
	# Work around a current nightly rustc ICE in MIR jump-threading for musl.
	env -u CC -u CXX -u AR \
		$(STATIC_CC_ENV) \
		RUSTFLAGS="-Zmir-opt-level=0" \
		CARGO_TARGET_DIR=$(STATIC_TARGET_DIR) \
		$(CARGO) build --release --target $(STATIC_TARGET) -p bbd -p bbcli

build-windows:
	RUSTFLAGS="-Zmir-opt-level=0" \
		CARGO_TARGET_DIR=$(WINDOWS_TARGET_DIR) \
		cargo xwin build --release --target $(WINDOWS_TARGET) -p bbd -p bbcli

sanitize-address:
ifeq ($(findstring -linux-gnu,$(HOST_TRIPLE)),)
	$(error sanitize-address currently supports Linux GNU hosts only)
endif
	RUSTFLAGS="-Zsanitizer=address" \
		CARGO_TARGET_DIR=$(SANITIZER_TARGET_DIR) \
		$(CARGO) test --workspace -Zbuild-std --target $(HOST_TRIPLE)

clean:
	$(CARGO) clean
