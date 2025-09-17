package nettor

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/cretz/bine/tor"
	"google.golang.org/grpc"
)

// TorNetwork is a Network implementation backed by Tor (bine).
type TorNetwork struct {
	t       *tor.Tor
	dataDir string
}

// NewTorNetwork creates a Tor-backed network transport.
func NewTorNetwork(dataDir string) *TorNetwork { return &TorNetwork{dataDir: dataDir} }

// Close releases resources. No-op for now.
func (tNet *TorNetwork) Close() error {
	return nil
}

// Register starts a Tor onion service and serves the provided gRPC registrar.
func (tNet *TorNetwork) Register(ctx context.Context, addr string,
	priv ed25519.PrivateKey, srv *grpc.Server) (func() error, error) {

	if tNet.dataDir == "" {
		return nil, fmt.Errorf("tor data dir not set")
	}
	// Log whether we reuse or create Tor directory.
	_, statErr := os.Stat(tNet.dataDir)
	existed := statErr == nil
	if err := os.MkdirAll(tNet.dataDir, 0o700); err != nil {
		return nil, err
	}
	if existed {
		log.Printf("bbd: Tor data dir: %s (reuse)", tNet.dataDir)
	} else {
		log.Printf("bbd: Tor data dir: %s (created)", tNet.dataDir)
	}

	t, err := tor.Start(ctx, &tor.StartConf{DataDir: tNet.dataDir})
	if err != nil {
		return nil, err
	}

	listenCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	onion, err := t.Listen(listenCtx, &tor.ListenConf{
		RemotePorts: []int{80},
		Key:         priv,
	})
	if err != nil {
		cancel()
		_ = t.Close()
		return nil, err
	}
	_, lport, _ := net.SplitHostPort(onion.LocalListener.Addr().String())
	log.Printf("bbd: Tor onion service started (remote port 80, local port %s)", lport)

	// Serve provided gRPC server on the onion listener.
	go func() { _ = srv.Serve(onion) }()

	unregister := func() error { srv.Stop(); _ = onion.Close(); cancel(); return t.Close() }

	// store tor for reuse in Dial
	tNet.t = t

	return unregister, nil
}

// Dial prepares a dial target and dialer using the Tor instance started in Register.
func (tNet *TorNetwork) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if tNet.t == nil {
		return nil, fmt.Errorf("tor not started; call Register first")
	}

	normAddr := strings.TrimSpace(addr)
	if !strings.Contains(normAddr, ".onion") {
		return nil, fmt.Errorf("address must be a .onion hostname")
	}
	if !strings.Contains(normAddr, ":") {
		normAddr = normAddr + ":80"
	}
	d, err := tNet.t.Dialer(ctx, nil)
	if err != nil {
		return nil, err
	}
	return d.DialContext(ctx, "tcp", normAddr)
}

// TLS is constructed by Node.
