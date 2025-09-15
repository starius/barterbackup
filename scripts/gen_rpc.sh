#!/usr/bin/env bash
set -euo pipefail

# Generate Go protobuf and gRPC stubs from .proto files.
# - protoc must be available (installed via Debian in Dockerfile.rpc).
# - protoc-gen-go and protoc-gen-go-grpc are installed according to tool lines
#   pinned in go.mod.

export PATH="/usr/local/bin:${PATH}"

cd "$(dirname "$0")/.."

# Verify protoc is available (installed from apt).
command -v protoc >/dev/null || { echo "protoc missing in image" >&2; exit 1; }

# Verify plugins are available (installed during image build).
command -v protoc-gen-go >/dev/null || { echo "protoc-gen-go missing in image" >&2; exit 1; }
command -v protoc-gen-go-grpc >/dev/null || { echo "protoc-gen-go-grpc missing in image" >&2; exit 1; }

set -x

# Generate with source_relative paths so outputs land next to proto files.
protoc \
  --go_out=paths=source_relative:. \
  --go-grpc_out=paths=source_relative:. \
  clirpc/*.proto bbrpc/*.proto storedpb/*.proto

echo "RPC generation complete."
