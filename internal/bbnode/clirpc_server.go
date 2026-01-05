package bbnode

import (
	"context"
	"errors"
	"time"

	"github.com/starius/barterbackup/clirpc"
	"github.com/starius/barterbackup/internal/bbnode/userstorage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// LocalHealthCheck implements clirpc.LocalHealthCheck and returns local
// daemon information including onion address and uptime.
func (n *Node) LocalHealthCheck(ctx context.Context, _ *clirpc.HealthCheckRequest) (*clirpc.HealthCheckResponse, error) {
	// Compute uptime since Start was called. Zero if not started yet.
	var uptime int64
	if !n.startedAt.IsZero() {
		uptime = int64(time.Since(n.startedAt).Seconds())
	}

	return &clirpc.HealthCheckResponse{
		ServerOnion:   n.addr,
		UptimeSeconds: uptime,
	}, nil
}

// SetFile stores or updates a file in encrypted local storage and updates
// the current content blob.
func (n *Node) SetFile(ctx context.Context, req *clirpc.SetFileRequest) (*clirpc.SetFileResponse, error) {
	if ctx.Err() != nil {
		st := status.FromContextError(ctx.Err())
		if st != nil {
			return nil, st.Err()
		}
		return nil, ctx.Err()
	}
	if n.state == nil {
		return nil, status.Error(codes.FailedPrecondition, "node not started")
	}
	if req == nil || req.GetFile() == nil {
		return nil, status.Error(codes.InvalidArgument, "file is required")
	}
	name := req.GetFile().GetName()
	data := req.GetFile().GetData()
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "file name is required")
	}
	if err := n.state.SetFile(ctx, name, data); err != nil {
		return nil, mapStorageError(err)
	}
	return &clirpc.SetFileResponse{}, nil
}

// DeleteFile removes a file from encrypted local storage and updates the
// current content blob.
func (n *Node) DeleteFile(ctx context.Context, req *clirpc.DeleteFileRequest) (*clirpc.DeleteFileResponse, error) {
	if ctx.Err() != nil {
		st := status.FromContextError(ctx.Err())
		if st != nil {
			return nil, st.Err()
		}
		return nil, ctx.Err()
	}
	if n.state == nil {
		return nil, status.Error(codes.FailedPrecondition, "node not started")
	}
	if req == nil || req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "file name is required")
	}
	if err := n.state.DeleteFile(ctx, req.GetName()); err != nil {
		return nil, mapStorageError(err)
	}
	return &clirpc.DeleteFileResponse{}, nil
}

// GetFile retrieves a file from local encrypted storage.
func (n *Node) GetFile(ctx context.Context, req *clirpc.GetFileRequest) (*clirpc.GetFileResponse, error) {
	if ctx.Err() != nil {
		st := status.FromContextError(ctx.Err())
		if st != nil {
			return nil, st.Err()
		}
		return nil, ctx.Err()
	}
	if n.state == nil {
		return nil, status.Error(codes.FailedPrecondition, "node not started")
	}
	if req == nil || req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "file name is required")
	}
	data, err := n.state.GetFile(ctx, req.GetName())
	if err != nil {
		return nil, mapStorageError(err)
	}
	return &clirpc.GetFileResponse{
		File: &clirpc.File{
			Name: req.GetName(),
			Data: data,
		},
	}, nil
}

// ListFiles returns file names from local encrypted storage.
func (n *Node) ListFiles(ctx context.Context, _ *clirpc.ListFilesRequest) (*clirpc.ListFilesResponse, error) {
	if ctx.Err() != nil {
		st := status.FromContextError(ctx.Err())
		if st != nil {
			return nil, st.Err()
		}
		return nil, ctx.Err()
	}
	if n.state == nil {
		return nil, status.Error(codes.FailedPrecondition, "node not started")
	}
	names, err := n.state.ListFiles(ctx)
	if err != nil {
		return nil, mapStorageError(err)
	}
	return &clirpc.ListFilesResponse{Name: names}, nil
}

// Unlock accepts the main password and completes initialization. Currently a no-op placeholder.
func (n *Node) Unlock(ctx context.Context, req *clirpc.UnlockRequest) (*clirpc.UnlockResponse, error) {
	if ctx.Err() != nil {
		if st := status.FromContextError(ctx.Err()); st != nil {
			return nil, st.Err()
		}
		return nil, ctx.Err()
	}
	if req == nil || req.GetMainPassword() == "" {
		return nil, status.Error(codes.InvalidArgument, "main password is required")
	}
	return &clirpc.UnlockResponse{}, nil
}

// ConnectPeer tracks a peer onion identifier locally.
func (n *Node) ConnectPeer(ctx context.Context, req *clirpc.ConnectPeerRequest) (*clirpc.ConnectPeerResponse, error) {
	if ctx.Err() != nil {
		if st := status.FromContextError(ctx.Err()); st != nil {
			return nil, st.Err()
		}
		return nil, ctx.Err()
	}
	if req == nil || req.GetPeer() == nil || req.GetPeer().GetOnionServiceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "peer onion is required")
	}
	n.mu.Lock()
	if n.peers == nil {
		n.peers = make(map[string]struct{})
	}
	n.peers[req.GetPeer().GetOnionServiceId()] = struct{}{}
	n.mu.Unlock()
	return &clirpc.ConnectPeerResponse{}, nil
}

// ConnectedPeers returns the currently known peers (no reachability detection yet).
func (n *Node) ConnectedPeers(ctx context.Context, _ *clirpc.ConnectedPeersRequest) (*clirpc.ConnectedPeersResponse, error) {
	if ctx.Err() != nil {
		if st := status.FromContextError(ctx.Err()); st != nil {
			return nil, st.Err()
		}
		return nil, ctx.Err()
	}
	n.mu.RLock()
	peers := make([]*clirpc.Peer, 0, len(n.peers))
	for p := range n.peers {
		peers = append(peers, &clirpc.Peer{OnionServiceId: p})
	}
	n.mu.RUnlock()
	return &clirpc.ConnectedPeersResponse{ConnectedPeers: peers}, nil
}

// SetStorageConfig stores the provided storage configuration.
func (n *Node) SetStorageConfig(ctx context.Context, req *clirpc.SetStorageConfigRequest) (*clirpc.SetStorageConfigResponse, error) {
	if ctx.Err() != nil {
		if st := status.FromContextError(ctx.Err()); st != nil {
			return nil, st.Err()
		}
		return nil, ctx.Err()
	}
	if req == nil || req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "config is required")
	}
	n.mu.Lock()
	n.storageCfg = *req.GetConfig()
	n.mu.Unlock()
	return &clirpc.SetStorageConfigResponse{}, nil
}

// GetStorageConfig returns the stored config along with derived info.
func (n *Node) GetStorageConfig(ctx context.Context, _ *clirpc.GetStorageConfigRequest) (*clirpc.GetStorageConfigResponse, error) {
	if ctx.Err() != nil {
		if st := status.FromContextError(ctx.Err()); st != nil {
			return nil, st.Err()
		}
		return nil, ctx.Err()
	}
	n.mu.RLock()
	cfg := n.storageCfg
	n.mu.RUnlock()
	var info *clirpc.StorageInfo
	if n.store != nil {
		info = &clirpc.StorageInfo{
			OurContentBytes: n.store.ContentLength(),
		}
	}
	return &clirpc.GetStorageConfigResponse{
		Config: &cfg,
		Info:   info,
	}, nil
}

// GetContracts returns currently tracked contracts (none yet).
func (n *Node) GetContracts(ctx context.Context, _ *clirpc.GetContractsRequest) (*clirpc.GetContractsResponse, error) {
	if ctx.Err() != nil {
		if st := status.FromContextError(ctx.Err()); st != nil {
			return nil, st.Err()
		}
		return nil, ctx.Err()
	}
	return &clirpc.GetContractsResponse{}, nil
}

// ProposeContract is not yet implemented.
func (n *Node) ProposeContract(*clirpc.ProposeContractRequest, clirpc.BarterBackupClient_ProposeContractServer) error {
	return status.Error(codes.Unimplemented, "propose contract not implemented")
}

// CheckContract is not yet implemented.
func (n *Node) CheckContract(*clirpc.CheckContractRequest, clirpc.BarterBackupClient_CheckContractServer) error {
	return status.Error(codes.Unimplemented, "check contract not implemented")
}

// RecoverContent is not yet implemented.
func (n *Node) RecoverContent(*clirpc.RecoverContentRequest, clirpc.BarterBackupClient_RecoverContentServer) error {
	return status.Error(codes.Unimplemented, "recover content not implemented")
}

func mapStorageError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		st := status.FromContextError(err)
		if st != nil {
			return st.Err()
		}
		return err
	}
	switch {
	case errors.Is(err, userstorage.ErrFileNotFound):
		return status.Error(codes.NotFound, "file not found")
	case errors.Is(err, ErrStopped):
		return status.Error(codes.Unavailable, "storage stopped")
	default:
		return status.Errorf(codes.Internal, "storage error: %v", err)
	}
}
