package bbnode

import (
	"context"
	"errors"
	"time"

	"github.com/starius/barterbackup/clirpc"
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
	if req == nil || req.GetFile() == nil {
		return nil, status.Error(codes.InvalidArgument, "file is required")
	}
	name := req.GetFile().GetName()
	data := req.GetFile().GetData()
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "file name is required")
	}
	if err := n.store.SetFile(name, data); err != nil {
		return nil, status.Errorf(codes.Internal, "store file: %v", err)
	}
	return &clirpc.SetFileResponse{}, nil
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
	if req == nil || req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "file name is required")
	}
	data, err := n.store.GetFile(req.GetName())
	if err != nil {
		if errors.Is(err, errFileNotFound) {
			return nil, status.Error(codes.NotFound, "file not found")
		}
		return nil, status.Errorf(codes.Internal, "load file: %v", err)
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
	names := n.store.ListFiles()
	return &clirpc.ListFilesResponse{Name: names}, nil
}
