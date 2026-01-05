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
