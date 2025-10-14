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
	if err := n.store.SetFile(ctx, name, data); err != nil {
		return nil, mapStorageError(err)
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
	data, err := n.store.GetFile(ctx, req.GetName())
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
	names, err := n.store.ListFiles(ctx)
	if err != nil {
		return nil, mapStorageError(err)
	}
	return &clirpc.ListFilesResponse{Name: names}, nil
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
	case errors.Is(err, errFileNotFound):
		return status.Error(codes.NotFound, "file not found")
	case errors.Is(err, errStorageNotReady):
		return status.Error(codes.FailedPrecondition, "storage not ready")
	case errors.Is(err, errStorageStopped):
		return status.Error(codes.Unavailable, "storage stopped")
	default:
		return status.Errorf(codes.Internal, "storage error: %v", err)
	}
}
