package bbnode

import (
	"context"
	"sort"

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

// PeerExchange ingests peer pubkeys from the caller and returns our known set.
func (n *Node) PeerExchange(_ context.Context, req *bbrpc.PeerExchangeRequest) (*bbrpc.PeerExchangeResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}
	n.mu.Lock()
	for _, p := range req.GetPeers() {
		if len(p.GetOnionPubkey()) == 0 {
			continue
		}
		n.knownPubs[string(p.GetOnionPubkey())] = struct{}{}
	}
	out := make([][]byte, 0, len(n.knownPubs))
	for k := range n.knownPubs {
		out = append(out, []byte(k))
	}
	n.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return string(out[i]) < string(out[j]) })
	peers := make([]*bbrpc.Peer, 0, len(out))
	for _, pub := range out {
		peers = append(peers, &bbrpc.Peer{OnionPubkey: pub})
	}
	return &bbrpc.PeerExchangeResponse{Peers: peers}, nil
}

// GetContentRevision reports our current content info; requester fields are empty for now.
func (n *Node) GetContentRevision(_ context.Context, _ *bbrpc.GetContentRevisionRequest) (*bbrpc.GetContentRevisionResponse, error) {
	if n.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "node not started")
	}
	cid := n.store.CurrentContentID()
	resp := &bbrpc.GetContentRevisionResponse{}
	if len(cid) > 0 {
		resp.ResponderContent = &bbrpc.ContentInfo{
			ContentId:     cid,
			ContentLength: n.store.ContentLength(),
		}
	}
	return resp, nil
}

// SetContentRevision currently accepts the request and returns success without persistence.
func (n *Node) SetContentRevision(_ context.Context, req *bbrpc.SetContentRevisionRequest) (*bbrpc.SetContentRevisionResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}
	return &bbrpc.SetContentRevisionResponse{}, nil
}

// Download is not yet implemented.
func (n *Node) Download(context.Context, *bbrpc.DownloadRequest) (*bbrpc.DownloadResponse, error) {
	return nil, status.Error(codes.Unimplemented, "download not implemented")
}
