package bbnode

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"

	"github.com/cretz/bine/torutil"
	torutiled25519 "github.com/cretz/bine/torutil/ed25519"
	"github.com/starius/barterbackup/bbrpc"
	"github.com/starius/barterbackup/internal/bbnode/userstorage"
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
func (n *Node) Download(ctx context.Context, req *bbrpc.DownloadRequest) (*bbrpc.DownloadResponse, error) {
	if ctx.Err() != nil {
		if st := status.FromContextError(ctx.Err()); st != nil {
			return nil, st.Err()
		}
		return nil, ctx.Err()
	}
	if n.store == nil {
		return nil, status.Error(codes.FailedPrecondition, "node not started")
	}
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}
	if len(req.GetContentId()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "content id is required")
	}
	if req.GetOffset() < 0 {
		return nil, status.Error(codes.InvalidArgument, "offset must be non-negative")
	}
	cid := n.store.CurrentContentID()
	if len(cid) == 0 || !bytes.Equal(cid, req.GetContentId()) {
		return nil, status.Error(codes.NotFound, "content not found")
	}

	reader, _, err := n.store.OpenContent()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "open content: %v", err)
	}
	defer reader.Close()

	totalLen := reader.Size()
	if req.GetOffset() > totalLen {
		return nil, status.Error(codes.InvalidArgument, "offset beyond end of content")
	}

	sha, err := n.store.ContentHash()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "hash content: %v", err)
	}

	chunk, err := readChunk(reader, req.GetOffset(), 16*1024)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read content: %v", err)
	}

	return &bbrpc.DownloadResponse{
		TotalLength: totalLen,
		Sha256:      sha,
		Section: &bbrpc.DownloadResponse_RawBytes{
			RawBytes: &bbrpc.RawBytes{Value: chunk},
		},
	}, nil
}

// readChunk reads up to length bytes from offset in the content.
func readChunk(reader userstorage.ReadFile, offset int64, length int) ([]byte, error) {
	if length < 0 {
		return nil, errors.New("length must be non-negative")
	}
	if offset < 0 {
		return nil, errors.New("offset must be non-negative")
	}
	if offset >= reader.Size() {
		return []byte{}, nil
	}
	toRead := int64(length)
	if max := reader.Size() - offset; toRead > max {
		toRead = max
	}
	buf := make([]byte, toRead)
	var readTotal int64
	for readTotal < toRead {
		n, err := reader.ReadAt(buf[readTotal:], offset+readTotal)
		readTotal += int64(n)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, errors.New("short read")
		}
	}
	return buf[:readTotal], nil
}
