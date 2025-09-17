package node

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/starius/barterbackup/clirpc"
	"github.com/starius/barterbackup/internal/netmock"
	"github.com/stretchr/testify/require"
)

func TestLocalHealthCheck_UptimeAndOnion(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		netw := netmock.NewMockNetwork()
		n, err := New("password", netw)
		require.NoError(t, err)

		require.NoError(t, n.Start(ctx))
		defer func() { _ = n.Stop() }()

		r1, err := n.LocalHealthCheck(ctx, &clirpc.HealthCheckRequest{})
		require.NoError(t, err)
		require.Equal(t, n.Address(), r1.GetServerOnion())

		// Wait a long time. Under synctest this is time-compressed.
		time.Sleep(10 * time.Hour)

		r2, err := n.LocalHealthCheck(ctx, &clirpc.HealthCheckRequest{})
		require.NoError(t, err)
		require.Equal(t, n.Address(), r2.GetServerOnion())

		// Expect at least 10 hours of uptime increase.
		uptimeGrowth := r2.GetUptimeSeconds() - r1.GetUptimeSeconds()
		require.Equal(t, uptimeGrowth, int64(10*3600))
	})
}
