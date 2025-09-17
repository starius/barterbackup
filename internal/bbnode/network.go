package bbnode

import (
	"context"
	"crypto/ed25519"
	"net"

	"google.golang.org/grpc"
)

// Network abstracts P2P communications between nodes.
// Implementations must provide TLS 1.3 transport with ONLY X25519MLKEM768.
type Network interface {
	// Register serves the provided gRPC server for this address and returns
	// an unregister function to stop serving and clean up resources.
	// addr is the onion hostname (e.g., "xxx.onion").
	Register(ctx context.Context, addr string, priv ed25519.PrivateKey,
		srv *grpc.Server) (unregister func() error, err error)

	// Dial opens a transport connection to addr and returns a net.Conn.
	// Node will wrap this in a grpc.WithContextDialer to integrate with gRPC.
	Dial(ctx context.Context, addr string) (net.Conn, error)
}
