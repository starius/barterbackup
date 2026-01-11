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

// GetContentRevision reports our current content info; requester fields are populated when caller is authenticated.
func (n *Node) GetContentRevision(ctx context.Context, _ *bbrpc.GetContentRevisionRequest) (*bbrpc.GetContentRevisionResponse, error) {
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
	if pub, err := ClientPubKeyFromContext(ctx); err == nil {
		n.mu.RLock()
		if info, ok := n.requester[string(pub)]; ok {
			rc := *info
			resp.RequesterContent = &rc
		}
		n.mu.RUnlock()
	}
	return resp, nil
}

// SetContentRevision records the caller's requested content to store if it fits policy.
func (n *Node) SetContentRevision(ctx context.Context, req *bbrpc.SetContentRevisionRequest) (*bbrpc.SetContentRevisionResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is nil")
	}
	info := req.GetRequesterContent()
	if info != nil {
		if info.GetContentLength() <= 0 {
			return nil, status.Error(codes.InvalidArgument, "content length must be positive")
		}
		const maxContent = 4 * 1024 * 1024
		if info.GetContentLength() > maxContent {
			return nil, status.Errorf(codes.InvalidArgument, "content too large: %d > %d", info.GetContentLength(), maxContent)
		}
		if len(info.GetContentId()) == 0 {
			return nil, status.Error(codes.InvalidArgument, "content id required")
		}
	}

	pub, err := ClientPubKeyFromContext(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}

	n.mu.Lock()
	if info == nil {
		delete(n.requester, string(pub))
	} else {
		cp := *info
		n.requester[string(pub)] = &cp
	}
	n.mu.Unlock()

	if info != nil {
		if err := n.store.SetPeerContentID(pub, info.GetContentId()); err != nil {
			return nil, status.Errorf(codes.Internal, "persist peer: %v", err)
		}
		n.schedulePeerDownload(pub, info.GetContentId())
	} else {
		if err := n.store.RemovePeerContent(pub); err != nil {
			return nil, status.Errorf(codes.Internal, "remove peer: %v", err)
		}
		n.cancelDownload(pub)
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
	allowed := bytes.Equal(cid, req.GetContentId())
	if !allowed {
		pub, err := ClientPubKeyFromContext(ctx)
		if err != nil {
			return nil, status.Error(codes.NotFound, "content not found")
		}
		n.mu.RLock()
		info := n.requester[string(pub)]
		n.mu.RUnlock()
		if info == nil || !bytes.Equal(info.GetContentId(), req.GetContentId()) {
			return nil, status.Error(codes.NotFound, "content not found")
		}
		allowed = true
	}

	if !allowed {
		return nil, status.Error(codes.NotFound, "content not found")
	}

	if !n.store.ContentExists(req.GetContentId()) {
		return nil, status.Error(codes.NotFound, "content not found")
	}

	var reader userstorage.ReadFile
	var err error
	if allowed && bytes.Equal(cid, req.GetContentId()) {
		reader, _, err = n.store.OpenContent()
	} else {
		reader, err = n.store.OpenContentByID(req.GetContentId())
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "open content: %v", err)
	}
	defer reader.Close()

	totalLen := reader.Size()
	if req.GetOffset() > totalLen {
		return nil, status.Error(codes.InvalidArgument, "offset beyond end of content")
	}

	sha, err := n.store.ContentHashByID(req.GetContentId())
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
