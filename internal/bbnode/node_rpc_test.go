package bbnode

import (
	"context"
	"testing"
	"time"

	"github.com/starius/barterbackup/bbrpc"
	"github.com/starius/barterbackup/clirpc"
	"github.com/starius/barterbackup/internal/netmock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing/synctest"
)

// TestLocalHealthCheckUptime uses synctest to advance time and verify uptime reporting.
func TestLocalHealthCheckUptime(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		node := startTestNode(t)
		t.Cleanup(func() { _ = node.Stop() })

		time.Sleep(2 * time.Hour)

		resp, err := node.LocalHealthCheck(t.Context(), &clirpc.HealthCheckRequest{})
		require.NoError(t, err)
		require.GreaterOrEqual(t, resp.GetUptimeSeconds(), int64(2*time.Hour/time.Second))
	})
}

// TestConnectAndListPeers ensures peers added via ConnectPeer are returned by ConnectedPeers.
func TestConnectAndListPeers(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		node := startTestNode(t)
		t.Cleanup(func() { _ = node.Stop() })

		_, err := node.ConnectPeer(t.Context(), &clirpc.ConnectPeerRequest{
			Peer: &clirpc.Peer{OnionServiceId: "peer.onion"},
		})
		require.NoError(t, err)

		list, err := node.ConnectedPeers(t.Context(), &clirpc.ConnectedPeersRequest{})
		require.NoError(t, err)
		require.Len(t, list.GetConnectedPeers(), 1)
		require.Equal(t, "peer.onion", list.GetConnectedPeers()[0].GetOnionServiceId())
	})
}

// TestGetContentRevisionReflectsStore checks responder content is populated after storing a file.
func TestGetContentRevisionReflectsStore(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		node := startTestNode(t)
		t.Cleanup(func() { _ = node.Stop() })

		_, err := node.SetFile(t.Context(), &clirpc.SetFileRequest{
			File: &clirpc.File{Name: "a.txt", Data: []byte("hello")},
		})
		require.NoError(t, err)

		time.Sleep(3 * time.Hour)

		resp, err := node.GetContentRevision(t.Context(), &bbrpc.GetContentRevisionRequest{})
		require.NoError(t, err)
		require.NotNil(t, resp.GetResponderContent())
		require.NotEmpty(t, resp.GetResponderContent().GetContentId())
		require.Greater(t, resp.GetResponderContent().GetContentLength(), int64(0))
	})
}

// TestUnimplementedDownloads ensures Download and EncryptedDownload return unimplemented.
func TestUnimplementedDownloads(t *testing.T) {
	t.Parallel()

	node := startTestNode(t)
	t.Cleanup(func() { _ = node.Stop() })

	_, err := node.Download(context.Background(), &bbrpc.DownloadRequest{})
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unimplemented, st.Code())

	_, err = node.EncryptedDownload(context.Background(), &bbrpc.EncryptedDownloadRequest{})
	st, ok = status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unimplemented, st.Code())
}

// startTestNode constructs and starts a Node with the in-memory mock network.
func startTestNode(t *testing.T) *Node {
	t.Helper()
	netw := netmock.NewMockNetwork()
	node, err := New("test-seed", netw, t.TempDir())
	require.NoError(t, err)
	require.NoError(t, node.Start(t.Context()))
	return node
}
