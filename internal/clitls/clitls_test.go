package clitls

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
	"time"

	"github.com/starius/barterbackup/clirpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/test/bufconn"
)

func TestGenerateEd25519(t *testing.T) {
	t.Parallel()
	pub, priv, err := GenerateEd25519()
	require.NoError(t, err)
	require.Len(t, priv, ed25519.PrivateKeySize)
	require.Len(t, pub, ed25519.PublicKeySize)
	// Verify that pub matches priv.
	require.Equal(t, ed25519.PublicKey(priv.Public().(ed25519.PublicKey)), pub)
}

func TestNewSelfSignedServerCert(t *testing.T) {
	t.Parallel()
	_, priv, err := GenerateEd25519()
	require.NoError(t, err)
	cert, err := NewSelfSignedServerCert(priv)
	require.NoError(t, err)
	require.NotEmpty(t, cert.Certificate)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	require.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth)
	require.GreaterOrEqual(t, leaf.NotAfter.Sub(leaf.NotBefore), 9*365*24*time.Hour)
}

func TestNewSelfSignedClientCert(t *testing.T) {
	t.Parallel()
	_, priv, err := GenerateEd25519()
	require.NoError(t, err)
	cert, err := NewSelfSignedClientCert(priv)
	require.NoError(t, err)
	require.NotEmpty(t, cert.Certificate)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	require.Contains(t, leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
}

func TestWriteReadKeys(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	serverPub, clientPriv, err := GenerateEd25519()
	require.NoError(t, err)
	require.NoError(t, WriteKeys(dir, serverPub, clientPriv))
	sp, cp, err := ReadKeys(dir)
	require.NoError(t, err)
	require.Equal(t, serverPub, sp)
	require.Equal(t, clientPriv, cp)
	// Ensure files exist
	_, err = os.Stat(filepath.Join(dir, "server.pub"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(dir, "client.key"))
	require.NoError(t, err)
}

// e2e test: start a tiny clirpc server with mutual TLS pinning and call HealthCheck.
func TestE2E_CLITLS_HealthCheck(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// Keys
		serverPub, serverPriv, err := GenerateEd25519()
		require.NoError(t, err)
		clientPub, clientPriv, err := GenerateEd25519()
		require.NoError(t, err)

		// TLS configs
		srvTLS, err := BuildServerTLS(clientPub, serverPriv)
		require.NoError(t, err)
		cliTLS, err := BuildClientTLSF(serverPub, clientPriv)
		require.NoError(t, err)

		// Server (bufconn)
		lis := bufconn.Listen(1024 * 1024)
		t.Cleanup(func() { _ = lis.Close() })
		srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(srvTLS)))
		t.Cleanup(srv.Stop)
		clirpc.RegisterBarterBackupClientServer(srv, &hcServer{})
		go func() { _ = srv.Serve(lis) }()

		// Client
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		bufDialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
		conn, err := grpc.DialContext(
			ctx,
			"bufnet",
			grpc.WithContextDialer(bufDialer),
			grpc.WithTransportCredentials(credentials.NewTLS(cliTLS)),
			grpc.WithBlock(),
		)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })

		cli := clirpc.NewBarterBackupClientClient(conn)
		resp, err := cli.LocalHealthCheck(ctx, &clirpc.HealthCheckRequest{})
		require.NoError(t, err)
		require.Equal(t, "", resp.GetServerOnion())
		require.Equal(t, int64(1), resp.GetUptimeSeconds())
	})
}

// Control: server is using wrong key.
func TestE2E_CLITLS_WrongServerKey(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// Keys
		serverPub, _, err := GenerateEd25519()
		require.NoError(t, err)
		_, serverPriv, err := GenerateEd25519()
		require.NoError(t, err)
		clientPub, clientPriv, err := GenerateEd25519()
		require.NoError(t, err)

		// TLS configs
		srvTLS, err := BuildServerTLS(clientPub, serverPriv)
		require.NoError(t, err)
		cliTLS, err := BuildClientTLSF(serverPub, clientPriv)
		require.NoError(t, err)

		// Server (bufconn)
		lis := bufconn.Listen(1024 * 1024)
		t.Cleanup(func() { _ = lis.Close() })
		srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(srvTLS)))
		t.Cleanup(srv.Stop)
		clirpc.RegisterBarterBackupClientServer(srv, &hcServer{})
		go func() { _ = srv.Serve(lis) }()

		// Client
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		bufDialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
		_, err = grpc.DialContext(
			ctx,
			"bufnet",
			grpc.WithContextDialer(bufDialer),
			grpc.WithTransportCredentials(credentials.NewTLS(cliTLS)),
			grpc.WithBlock(),
		)
		require.Error(t, err)
	})
}

// Control: client is using wrong key.
func TestE2E_CLITLS_WrongClientKey(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// Keys
		serverPub, serverPriv, err := GenerateEd25519()
		require.NoError(t, err)
		clientPub, _, err := GenerateEd25519()
		require.NoError(t, err)
		_, clientPriv, err := GenerateEd25519()
		require.NoError(t, err)

		// TLS configs
		srvTLS, err := BuildServerTLS(clientPub, serverPriv)
		require.NoError(t, err)
		cliTLS, err := BuildClientTLSF(serverPub, clientPriv)
		require.NoError(t, err)

		// Server (bufconn)
		lis := bufconn.Listen(1024 * 1024)
		t.Cleanup(func() { _ = lis.Close() })
		srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(srvTLS)))
		t.Cleanup(srv.Stop)
		clirpc.RegisterBarterBackupClientServer(srv, &hcServer{})
		go func() { _ = srv.Serve(lis) }()

		// Client
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		bufDialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
		_, err = grpc.DialContext(
			ctx,
			"bufnet",
			grpc.WithContextDialer(bufDialer),
			grpc.WithTransportCredentials(credentials.NewTLS(cliTLS)),
			grpc.WithBlock(),
		)
		require.Error(t, err)
	})
}

type hcServer struct {
	clirpc.UnimplementedBarterBackupClientServer
}

func (s *hcServer) LocalHealthCheck(ctx context.Context, _ *clirpc.HealthCheckRequest) (*clirpc.HealthCheckResponse, error) {
	return &clirpc.HealthCheckResponse{ServerOnion: "", UptimeSeconds: 1}, nil
}
