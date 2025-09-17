package bbnode

import (
	"context"

	"github.com/cretz/bine/torutil"
	torutiled25519 "github.com/cretz/bine/torutil/ed25519"
	"github.com/starius/barterbackup/bbrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// HealthCheck implements bbrpc.HealthCheck and returns client/server onion
// hostnames inferred from the connection context.
func (n *Node) HealthCheck(ctx context.Context, _ *bbrpc.HealthCheckRequest) (*bbrpc.HealthCheckResponse, error) {
	// Compute client onion from TLS client cert when available.
	pub, err := ClientPubKeyFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}

	id := torutil.OnionServiceIDFromV3PublicKey(torutiled25519.PublicKey(pub))
	clientOnion := id + ".onion"

	// Server onion is our address.
	serverOnion := n.addr

	return &bbrpc.HealthCheckResponse{
		ClientOnion: clientOnion,
		ServerOnion: serverOnion,
	}, nil
}
