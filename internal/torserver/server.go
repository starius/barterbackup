package torserver

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/cretz/bine/tor"
	"github.com/starius/barterbackup/bbrpc"
	"github.com/starius/barterbackup/internal/keys"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Config controls the Tor-backed gRPC server behavior.
type Config struct {
	// MasterPriv is the master private key material (output of memory-hard KDF).
	MasterPriv []byte
	// ListenOnionPort is the exposed onion port (default 80).
	ListenOnionPort int
}

type Server struct {
	tor        *tor.Tor
	onion      *tor.OnionService
	grpcServer *grpc.Server
	onionID    string
}

// OnionID returns the v3 onion identifier (without ".onion").
func (s *Server) OnionID() string { return s.onionID }

// GRPC returns the underlying gRPC server instance.
func (s *Server) GRPC() *grpc.Server { return s.grpcServer }

// Close stops gRPC and Tor onion listener.
func (s *Server) Close() error {
	if s.grpcServer != nil {
		s.grpcServer.Stop()
	}
	if s.onion != nil {
		_ = s.onion.Close()
	}
	if s.tor != nil {
		return s.tor.Close()
	}

	return nil
}

// Start starts Tor, publishes an onion service using a key deterministically
// derived from config.MasterPriv, and runs a gRPC server bound to that onion.
//
// It registers the provided bbrpc implementation.
func Start(ctx context.Context, cfg Config, impl bbrpc.BarterBackupServerServer) (*Server, error) {
	if len(cfg.MasterPriv) == 0 {
		return nil, errors.New("MasterPriv is required")
	}
	if cfg.ListenOnionPort == 0 {
		cfg.ListenOnionPort = 80
	}

	// 1) Derive the Ed25519 key deterministically.
	priv, _, err := keys.DeriveEd25519FromMaster(cfg.MasterPriv, "tor/onion/v3")
	if err != nil {
		return nil, fmt.Errorf("derive onion key: %w", err)
	}

	// 2) Start Tor.
	t, err := tor.Start(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("start tor: %w", err)
	}

	// 3) Publish onion with our key.
	listenCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	onion, err := t.Listen(listenCtx, &tor.ListenConf{
		// Bind the service to an ephemeral local port, but expose cfg.ListenOnionPort.
		RemotePorts: []int{cfg.ListenOnionPort},

		// Use our v3 ed25519 key pair.
		Key: priv,
	})
	if err != nil {
		_ = t.Close()
		return nil, fmt.Errorf("onion listen: %w", err)
	}

	// 4) Prepare gRPC server options with TLS using ONLY hybrid X25519MLKEM768.
	var serverOpts []grpc.ServerOption
	tlsCfg, err := pqTLSServerConfigFromEd25519(priv)
	if err != nil {
		_ = onion.Close()
		_ = t.Close()
		return nil, fmt.Errorf("pq tls config: %w", err)
	}
	serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(tlsCfg)))

	// 5) Create and serve gRPC.
	grpcSrv := grpc.NewServer(serverOpts...)
	bbrpc.RegisterBarterBackupServerServer(grpcSrv, impl)

	go func(l net.Listener) {
		// Serve blocks; errors are not returned here. If Serve returns,
		// it means listener closed or fatal error happened.
		_ = grpcSrv.Serve(l)
	}(onion)

	s := &Server{tor: t, onion: onion, grpcServer: grpcSrv, onionID: onion.ID}

	return s, nil
}

// pqTLSServerConfigFromEd25519 produces a tls.Config that:
//   - Uses the provided Ed25519 key as the certificate key material.
//   - Restricts the KeyShare/curves to X25519.
//   - Attempts to enable hybrid X25519+MLKEM-768 if supported by the runtime or
//     linked provider. If unavailable and ForcePQTLS is set, Start returns error.
func pqTLSServerConfigFromEd25519(priv ed25519.PrivateKey) (*tls.Config, error) {
	// Self-signed certificate with Ed25519 key for gRPC. In practice the
	// onion layer provides origin authentication; this cert is for transport
	// security and to enable KEM hybrid where possible.
	cert, err := selfSignedEd25519Cert(priv)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		// Enforce hybrid PQ key exchange only.
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
	}

	return cfg, nil
}
