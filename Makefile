CARGO ?= cargo
RUSTC ?= rustc
CLANG_FORMAT ?= clang-format
PROTO_FILES := $(shell find bbrpc clirpc storedpb -type f -name '*.proto' | sort)
HOST_TRIPLE := $(shell $(RUSTC) -vV | sed -n 's/^host: //p')
WINDOWS_TARGET := x86_64-pc-windows-msvc
STATIC_LINUX_AMD64_TARGET := x86_64-unknown-linux-musl
STATIC_LINUX_ARM64_TARGET := aarch64-unknown-linux-musl
STATIC_TARGET_DIR ?= target-static
WINDOWS_TARGET_DIR ?= target-windows
SANITIZER_TARGET_DIR ?= target-sanitize

ifeq ($(HOST_TRIPLE),x86_64-unknown-linux-gnu)
STATIC_TARGET := $(STATIC_LINUX_AMD64_TARGET)
else ifeq ($(HOST_TRIPLE),aarch64-unknown-linux-gnu)
STATIC_TARGET := $(STATIC_LINUX_ARM64_TARGET)
endif

STATIC_LINUX_AMD64_ENV := \
	CC_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-gcc \
	CXX_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-g++ \
	AR_x86_64_unknown_linux_musl=x86_64-unknown-linux-musl-ar
STATIC_LINUX_ARM64_ENV := \
	CC_aarch64_unknown_linux_musl=aarch64-unknown-linux-musl-gcc \
	CXX_aarch64_unknown_linux_musl=aarch64-unknown-linux-musl-g++ \
	AR_aarch64_unknown_linux_musl=aarch64-unknown-linux-musl-ar

.PHONY: build test unit fmt clippy install build-static build-static-linux-amd64 build-static-linux-arm64 build-windows sanitize-address clean

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
ifeq ($(STATIC_TARGET),$(STATIC_LINUX_AMD64_TARGET))
	$(MAKE) build-static-linux-amd64
else ifeq ($(STATIC_TARGET),$(STATIC_LINUX_ARM64_TARGET))
	$(MAKE) build-static-linux-arm64
else
	$(error unsupported static target $(STATIC_TARGET))
endif

build-static-linux-amd64:
	# Work around a current nightly rustc ICE in MIR jump-threading for musl.
	# Keep static builds in a per-target cargo dir and disable pipelining to
	# avoid stale or missing rmeta artifacts on reused local build trees.
	env -u CC -u CXX -u AR \
		$(STATIC_LINUX_AMD64_ENV) \
		CARGO_BUILD_PIPELINING=false \
		RUSTFLAGS="-Zmir-opt-level=0" \
		CARGO_TARGET_DIR=$(STATIC_TARGET_DIR)/$(STATIC_LINUX_AMD64_TARGET) \
		$(CARGO) build --release --target $(STATIC_LINUX_AMD64_TARGET) -p bbd -p bbcli

build-static-linux-arm64:
	# Work around a current nightly rustc ICE in MIR jump-threading for musl.
	# Keep static builds in a per-target cargo dir and disable pipelining to
	# avoid stale or missing rmeta artifacts on reused local build trees.
	env -u CC -u CXX -u AR \
		$(STATIC_LINUX_ARM64_ENV) \
		CARGO_BUILD_PIPELINING=false \
		RUSTFLAGS="-Zmir-opt-level=0" \
		CARGO_TARGET_DIR=$(STATIC_TARGET_DIR)/$(STATIC_LINUX_ARM64_TARGET) \
		$(CARGO) build --release --target $(STATIC_LINUX_ARM64_TARGET) -p bbd -p bbcli

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
