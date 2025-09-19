#!/usr/bin/env bash
set -euo pipefail

# Generate Rust gRPC stubs using a container with protoc available.
# Requires Docker. Output is written to rust/crates/protos/src/generated/.

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")"/.. && pwd)
set -x
docker run --rm \
  -v "$ROOT_DIR":/work \
  -w /work/rust \
  rust:1-bookworm bash -lc '
    apt-get update -qq && apt-get install -y -qq protobuf-compiler && \
    cd tools/proto-gen && cargo run --release
  '

echo "Generated files under rust/crates/protos/src/generated" >&2

