package node

import (
	"context"
	"time"

	"github.com/starius/barterbackup/clirpc"
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
