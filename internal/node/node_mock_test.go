package node

import (
	"context"
	"testing"
	"time"

	"github.com/starius/barterbackup/bbrpc"
	"github.com/starius/barterbackup/internal/netmock"
	"github.com/stretchr/testify/require"
)

func TestHealthCheckWithMockNetwork(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	mock := netmock.NewMockNetwork()
	t.Cleanup(func() { _ = mock.Close() })

	n1, err := New("pw1", mock)
	require.NoError(t, err)
	n2, err := New("pw2", mock)
	require.NoError(t, err)

	require.NoError(t, n1.Start(ctx))
	t.Cleanup(func() { _ = n1.Stop() })
	require.NoError(t, n2.Start(ctx))
	t.Cleanup(func() { _ = n2.Stop() })

	t.Logf("node1 address: %v", n1.Address())
	t.Logf("node2 address: %v", n2.Address())

	// n1 -> n2
	c12, conn12, err := n1.DialPeer(ctx, n2.Address())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn12.Close() })
	r12, err := c12.HealthCheck(ctx, &bbrpc.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, n1.Address(), r12.GetClientOnion())
	require.Equal(t, n2.Address(), r12.GetServerOnion())

	// n2 -> n1
	c21, conn21, err := n2.DialPeer(ctx, n1.Address())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn21.Close() })
	r21, err := c21.HealthCheck(ctx, &bbrpc.HealthCheckRequest{})
	require.NoError(t, err)
	require.Equal(t, n2.Address(), r21.GetClientOnion())
	require.Equal(t, n1.Address(), r21.GetServerOnion())
}
