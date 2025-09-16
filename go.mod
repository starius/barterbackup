module github.com/starius/barterbackup

go 1.24.6

require (
	github.com/cretz/bine v0.2.0
	golang.org/x/crypto v0.24.0
	google.golang.org/grpc v1.65.0
	google.golang.org/protobuf v1.36.9
)

require (
	golang.org/x/net v0.26.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	golang.org/x/text v0.16.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240604185151-ef581f913117 // indirect
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.5.1 // indirect
)

tool (
	google.golang.org/grpc/cmd/protoc-gen-go-grpc
	google.golang.org/protobuf/cmd/protoc-gen-go
)
