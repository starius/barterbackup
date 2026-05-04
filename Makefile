CARGO ?= cargo
RUSTC ?= rustc
CLANG_FORMAT ?= clang-format
GO ?= go
GOFMT ?= gofmt
PROTOC_GEN_GO ?= protoc-gen-go
PROTOC_GEN_GO_GRPC ?= protoc-gen-go-grpc
PROTOC_INCLUDE ?= $(shell dirname $(shell dirname $(shell command -v protoc)))/include
PROTO_FILES := $(shell find bbrpc clirpc storedpb -type f -name '*.proto' | sort)
GO_FILES := $(shell find integration/docker -type f -name '*.go' 2>/dev/null | sort)
HOST_TRIPLE := $(shell $(RUSTC) -vV | sed -n 's/^host: //p')
WINDOWS_TARGET := x86_64-pc-windows-msvc
STATIC_LINUX_AMD64_TARGET := x86_64-unknown-linux-musl
STATIC_LINUX_ARM64_TARGET := aarch64-unknown-linux-musl
STATIC_TARGET_DIR ?= target-static
WINDOWS_TARGET_DIR ?= target-windows
SANITIZER_TARGET_DIR ?= target-sanitize
GO_RPC_MODULE := barterbackup/integration/docker
GO_RPC_OUT_DIR := integration/docker/gen/clirpc

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

.PHONY: build test unit fmt clippy install rpc cli-docs integration-test-docker-tor-smoke docker-dev-env-build docker-dev-env build-static build-static-bbd build-static-linux-amd64 build-static-linux-arm64 build-windows sanitize-address clean

build:
	$(CARGO) build --workspace

test:
	$(CARGO) test --workspace

unit: test

fmt:
	$(CARGO) fmt --all
	$(CLANG_FORMAT) -i $(PROTO_FILES)
	$(GOFMT) -w $(GO_FILES)

clippy:
	$(CARGO) clippy --workspace --all-targets

rpc:
	rm -rf $(GO_RPC_OUT_DIR)
	mkdir -p $(GO_RPC_OUT_DIR)
	PATH="$(dir $(shell command -v $(PROTOC_GEN_GO))):$(dir $(shell command -v $(PROTOC_GEN_GO_GRPC))):$$PATH" \
		protoc -I . -I $(PROTOC_INCLUDE) \
			--go_out=integration/docker \
			--go_opt=module=$(GO_RPC_MODULE) \
			--go_opt=Mclirpc/barter_backup_client.proto=$(GO_RPC_MODULE)/gen/clirpc \
			--go-grpc_out=integration/docker \
			--go-grpc_opt=module=$(GO_RPC_MODULE) \
			--go-grpc_opt=Mclirpc/barter_backup_client.proto=$(GO_RPC_MODULE)/gen/clirpc \
			clirpc/barter_backup_client.proto

cli-docs:
	$(CARGO) run -p cli-docs --

integration-test-docker-tor-smoke:
	$(MAKE) build-static-bbd
	$(MAKE) rpc
	cd integration/docker && BB_DOCKER_REAL_TOR=1 $(GO) test -run TestDockerRealTorRecoverySmoke -count=1 -timeout 30m

docker-dev-env-build:
	$(MAKE) build-static
	$(MAKE) rpc

docker-dev-env:
	cd integration/docker && $(GO) run ./cmd/bbdevenv -- $(ARGS)

install:
	$(CARGO) install --path cmd/bbd --locked
	$(CARGO) install --path cmd/bbcli --locked --profile release-bbcli

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

build-static-bbd:
ifndef STATIC_TARGET
	$(error build-static-bbd requires an x86_64-linux or aarch64-linux host)
endif
ifeq ($(STATIC_TARGET),$(STATIC_LINUX_AMD64_TARGET))
	env -u CC -u CXX -u AR \
		$(STATIC_LINUX_AMD64_ENV) \
		CARGO_BUILD_PIPELINING=false \
		CARGO_TARGET_DIR=$(STATIC_TARGET_DIR)/$(STATIC_LINUX_AMD64_TARGET) \
		$(CARGO) build --release --target $(STATIC_LINUX_AMD64_TARGET) -p bbd
else ifeq ($(STATIC_TARGET),$(STATIC_LINUX_ARM64_TARGET))
	env -u CC -u CXX -u AR \
		$(STATIC_LINUX_ARM64_ENV) \
		CARGO_BUILD_PIPELINING=false \
		CARGO_TARGET_DIR=$(STATIC_TARGET_DIR)/$(STATIC_LINUX_ARM64_TARGET) \
		$(CARGO) build --release --target $(STATIC_LINUX_ARM64_TARGET) -p bbd
else
	$(error unsupported static target $(STATIC_TARGET))
endif

build-static-linux-amd64:
	# Keep static builds in a per-target cargo dir and disable pipelining to
	# avoid stale or missing rmeta artifacts on reused local build trees.
	env -u CC -u CXX -u AR \
		$(STATIC_LINUX_AMD64_ENV) \
		CARGO_BUILD_PIPELINING=false \
		CARGO_TARGET_DIR=$(STATIC_TARGET_DIR)/$(STATIC_LINUX_AMD64_TARGET) \
		$(CARGO) build --release --target $(STATIC_LINUX_AMD64_TARGET) -p bbd
	env -u CC -u CXX -u AR \
		$(STATIC_LINUX_AMD64_ENV) \
		CARGO_BUILD_PIPELINING=false \
		CARGO_TARGET_DIR=$(STATIC_TARGET_DIR)/$(STATIC_LINUX_AMD64_TARGET) \
		$(CARGO) build --profile release-bbcli --target $(STATIC_LINUX_AMD64_TARGET) -p bbcli

build-static-linux-arm64:
	# Keep static builds in a per-target cargo dir and disable pipelining to
	# avoid stale or missing rmeta artifacts on reused local build trees.
	env -u CC -u CXX -u AR \
		$(STATIC_LINUX_ARM64_ENV) \
		CARGO_BUILD_PIPELINING=false \
		CARGO_TARGET_DIR=$(STATIC_TARGET_DIR)/$(STATIC_LINUX_ARM64_TARGET) \
		$(CARGO) build --release --target $(STATIC_LINUX_ARM64_TARGET) -p bbd
	env -u CC -u CXX -u AR \
		$(STATIC_LINUX_ARM64_ENV) \
		CARGO_BUILD_PIPELINING=false \
		CARGO_TARGET_DIR=$(STATIC_TARGET_DIR)/$(STATIC_LINUX_ARM64_TARGET) \
		$(CARGO) build --profile release-bbcli --target $(STATIC_LINUX_ARM64_TARGET) -p bbcli

build-windows:
	CARGO_TARGET_DIR=$(WINDOWS_TARGET_DIR) \
		cargo xwin build --release --target $(WINDOWS_TARGET) -p bbd
	CARGO_TARGET_DIR=$(WINDOWS_TARGET_DIR) \
		cargo xwin build --profile release-bbcli --target $(WINDOWS_TARGET) -p bbcli

sanitize-address:
ifeq ($(findstring -linux-gnu,$(HOST_TRIPLE)),)
	$(error sanitize-address currently supports Linux GNU hosts only)
endif
	RUSTFLAGS="-Zsanitizer=address" \
		CARGO_TARGET_DIR=$(SANITIZER_TARGET_DIR) \
		$(CARGO) test --workspace -Zbuild-std --target $(HOST_TRIPLE)

clean:
	$(CARGO) clean
