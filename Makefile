RPC_IMAGE ?= barterbackup-rpc:bookworm

.PHONY: rpc rpc-image

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
