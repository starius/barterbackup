.PHONY: install unit rpc fmt

# Install the daemon binary.
install:
	CGO_ENABLED=0 go install ./cmd/bbd
	CGO_ENABLED=0 go install ./cmd/bbcli


unit:
	CGO_ENABLED=0 go test ./...

# Generate Go protobuf and gRPC stubs inside the Nix dev shell.
rpc:
	nix develop --command sh -c '\
	  protoc --go_out=paths=source_relative:. --go-grpc_out=paths=source_relative:. clirpc/*.proto bbrpc/*.proto storedpb/*.proto \
	'

fmt:
	clang-format -i */*.proto
	go fmt ./...
