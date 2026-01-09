package bbnode

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"testing"
	"time"

	"github.com/starius/barterbackup/bbrpc"
	"github.com/starius/barterbackup/clirpc"
	"github.com/starius/barterbackup/internal/netmock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
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

// TestDownloadMissingContentID errors when required fields are absent.
func TestDownloadMissingContentID(t *testing.T) {
	t.Parallel()

	node := startTestNode(t)
	t.Cleanup(func() { _ = node.Stop() })

	_, err := node.Download(context.Background(), &bbrpc.DownloadRequest{})
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
}

// TestDownloadHappyPath verifies Download returns content bytes and metadata.
func TestDownloadHappyPath(t *testing.T) {
	t.Parallel()

	node := startTestNode(t)
	t.Cleanup(func() { _ = node.Stop() })

	_, err := node.SetFile(context.Background(), &clirpc.SetFileRequest{
		File: &clirpc.File{Name: "x", Data: []byte("payload")},
	})
	require.NoError(t, err)

	reader, cid, err := node.store.OpenContent()
	require.NoError(t, err)
	defer reader.Close()

	resp, err := node.Download(context.Background(), &bbrpc.DownloadRequest{
		ContentId: cid,
		Offset:    0,
	})
	require.NoError(t, err)
	require.Equal(t, reader.Size(), resp.GetTotalLength())

	expectedChunk, err := readChunk(reader, 0, 16*1024)
	require.NoError(t, err)
	require.Equal(t, expectedChunk, resp.GetRawBytes().GetValue())

	// Validate the returned digest matches a direct hash of the content blob.
	sum, err := node.store.ContentHash()
	require.NoError(t, err)
	require.Equal(t, sum, resp.GetSha256())
}

// TestDownloadHashStable captures the hash and verifies it matches on subsequent downloads.
func TestDownloadHashStable(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		node := startTestNode(t)
		t.Cleanup(func() { _ = node.Stop() })

		_, err := node.SetFile(t.Context(), &clirpc.SetFileRequest{
			File: &clirpc.File{Name: "x", Data: []byte("payload")},
		})
		require.NoError(t, err)

		reader, cid, err := node.store.OpenContent()
		require.NoError(t, err)
		defer reader.Close()

		expectedHash, err := node.store.ContentHash()
		require.NoError(t, err)
		require.Equal(t,
			"4288656a58fe9f1a66bc86615a12f127c4067b832b4045fff233faadee0271ab",
			hex.EncodeToString(expectedHash))

		first, err := node.Download(t.Context(), &bbrpc.DownloadRequest{
			ContentId: cid,
			Offset:    0,
		})
		require.NoError(t, err)
		require.Equal(t, expectedHash, first.GetSha256())

		second, err := node.Download(t.Context(), &bbrpc.DownloadRequest{
			ContentId: cid,
			Offset:    2,
		})
		require.NoError(t, err)
		require.Equal(t, expectedHash, second.GetSha256())
		require.Equal(t, first.GetTotalLength(), second.GetTotalLength())
	})
}

// TestDownloadBadContentID returns NotFound for unknown CID.
func TestDownloadBadContentID(t *testing.T) {
	t.Parallel()

	node := startTestNode(t)
	t.Cleanup(func() { _ = node.Stop() })

	_, err := node.Download(context.Background(), &bbrpc.DownloadRequest{
		ContentId: []byte("unknown"),
	})
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.NotFound, st.Code())
}

// TestSetContentRevisionValidation enforces size and argument checks.
func TestSetContentRevisionValidation(t *testing.T) {
	t.Parallel()

	node := startTestNode(t)
	t.Cleanup(func() { _ = node.Stop() })

	ctx := peerCtx(t)

	// Too large.
	_, err := node.SetContentRevision(ctx, &bbrpc.SetContentRevisionRequest{
		RequesterContent: &bbrpc.ContentInfo{
			ContentId:     []byte("id"),
			ContentLength: 5 * 1024 * 1024,
		},
	})
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())

	// Missing ID when length set.
	_, err = node.SetContentRevision(ctx, &bbrpc.SetContentRevisionRequest{
		RequesterContent: &bbrpc.ContentInfo{
			ContentLength: 1,
		},
	})
	st, ok = status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())

	// Non-positive length.
	_, err = node.SetContentRevision(ctx, &bbrpc.SetContentRevisionRequest{
		RequesterContent: &bbrpc.ContentInfo{
			ContentId:     []byte("id"),
			ContentLength: 0,
		},
	})
	st, ok = status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
}

// TestSetContentRevisionPersistsRequester ensures requester content is reflected in GetContentRevision.
func TestSetContentRevisionPersistsRequester(t *testing.T) {
	t.Parallel()

	node := startTestNode(t)
	t.Cleanup(func() { _ = node.Stop() })

	ctx := peerCtx(t)

	info := &bbrpc.ContentInfo{
		ContentId:     []byte("peer"),
		ContentLength: 123,
	}
	_, err := node.SetContentRevision(ctx, &bbrpc.SetContentRevisionRequest{
		RequesterContent: info,
	})
	require.NoError(t, err)

	resp, err := node.GetContentRevision(ctx, &bbrpc.GetContentRevisionRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp.GetRequesterContent())
	require.Equal(t, info.GetContentId(), resp.GetRequesterContent().GetContentId())
	require.Equal(t, info.GetContentLength(), resp.GetRequesterContent().GetContentLength())

	// Clearing removes it.
	_, err = node.SetContentRevision(ctx, &bbrpc.SetContentRevisionRequest{})
	require.NoError(t, err)
	resp, err = node.GetContentRevision(ctx, &bbrpc.GetContentRevisionRequest{})
	require.NoError(t, err)
	require.Nil(t, resp.GetRequesterContent())
}

// TestDownloadOffsetValidation checks offset bounds.
func TestDownloadOffsetValidation(t *testing.T) {
	t.Parallel()

	node := startTestNode(t)
	t.Cleanup(func() { _ = node.Stop() })

	_, err := node.SetFile(context.Background(), &clirpc.SetFileRequest{
		File: &clirpc.File{Name: "x", Data: []byte("payload")},
	})
	require.NoError(t, err)
	cid := node.store.CurrentContentID()

	_, err = node.Download(context.Background(), &bbrpc.DownloadRequest{
		ContentId: cid,
		Offset:    -1,
	})
	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())

	reader, _, err := node.store.OpenContent()
	require.NoError(t, err)
	defer reader.Close()

	_, err = node.Download(context.Background(), &bbrpc.DownloadRequest{
		ContentId: cid,
		Offset:    reader.Size() + 1,
	})
	st, ok = status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
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

// peerCtx builds a context containing a fake TLS peer certificate with an ed25519 public key.
func peerCtx(t *testing.T) context.Context {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	cert := &x509.Certificate{
		PublicKey: pub,
	}
	ti := credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{cert},
		},
	}
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: ti})
	_, err = ClientPubKeyFromContext(ctx)
	require.NoError(t, err)
	return ctx
}
