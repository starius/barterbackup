RPC_IMAGE ?= barterbackup-rpc:bookworm

.PHONY: install rpc rpc-image

# Install the daemon binary.
install:
	CGO_ENABLED=0 go install ./cmd/bbdaemon

# Build the Docker image that contains Debian's protoc and Go plugins pinned
# by the tool directives in go.mod.
rpc-image:
	docker build --network=host -f Dockerfile.rpc -t $(RPC_IMAGE) .

# Generate Go protobuf and gRPC stubs inside Docker for reproducibility.
rpc: rpc-image
	docker run --network=host --rm \
	  -v $(PWD):/work \
	  -w /work \
	  $(RPC_IMAGE)

fmt:
	go fmt ./...
