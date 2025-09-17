package bbdapp

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	flags "github.com/jessevdk/go-flags"
	"github.com/starius/barterbackup/clirpc"
	"github.com/starius/barterbackup/internal/bbnode"
	"github.com/starius/barterbackup/internal/clitls"
	"github.com/starius/barterbackup/internal/keys"
	"github.com/starius/barterbackup/internal/nettor"
	"github.com/starius/flock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// Config holds bbd configuration.
// Tags: flag name, env var, and default value.
type Config struct {
	// DataDir is the base directory for all daemon data.
	DataDir string `long:"data-dir" env:"BBD_DATA_DIR" description:"Base directory for daemon data (keys, tor, etc)." default:"~/.barterbackup"`

	// CLIAddr is the local loopback address (host:port) where the daemon exposes clirpc for bbcli.
	CLIAddr string `long:"cli-addr" env:"BBD_CLI_ADDR" description:"Local clirpc bind address (127.0.0.1:PORT)." default:"127.0.0.1:9911"`
}

// Parse options
type parseOptions struct{ args []string }
type ParseOption func(*parseOptions)

func WithOSArgs() ParseOption { return func(o *parseOptions) { o.args = os.Args[1:] } }
func WithArgs(a []string) ParseOption {
	return func(o *parseOptions) { o.args = append([]string{}, a...) }
}

// Parse parses flags/env into Config using go-flags.
func Parse(opts ...ParseOption) (*Config, error) {
	var po parseOptions
	for _, opt := range opts {
		opt(&po)
	}
	cfg := &Config{}
	p := flags.NewParser(cfg, flags.Default)
	var err error
	if len(po.args) > 0 {
		_, err = p.ParseArgs(po.args)
	} else {
		_, err = p.Parse()
	}
	if err != nil {
		if ferr, ok := err.(*flags.Error); ok && ferr.Type == flags.ErrHelp {
			return nil, nil
		}
		return nil, err
	}
	return cfg, nil
}

// Run starts the daemon and blocks until ctx is cancelled.
func Run(ctx context.Context, cfg Config) error {
	// Compute data subdirs and prepare ephemeral CLI keys dir.
	baseDir, err := expandPath(cfg.DataDir)
	if err != nil {
		return err
	}
	// Tor dir computed during unlock
	cliDir := filepath.Join(baseDir, "cli-keys")
	if err := os.MkdirAll(baseDir, 0o700); err != nil {
		return fmt.Errorf("creating data dir: %w", err)
	}
	if err := os.RemoveAll(cliDir); err != nil {
		return fmt.Errorf("clean cli-keys dir: %w", err)
	}
	log.Printf("bbd: using CLI key dir %s", cliDir)
	if err := os.MkdirAll(cliDir, 0o700); err != nil {
		return fmt.Errorf("creating cli keys dir: %w", err)
	}
	// Acquire directory lock using flock and write PID into the file.
	rel, err := acquireDirLock(cliDir)
	if err != nil {
		return err
	}
	log.Printf("bbd: acquired lock %s", filepath.Join(cliDir, ".lock"))

	// Prepare mutual-TLS for local clirpc server.
	// 1) Ephemeral server keypair (in-memory private key) + self-signed cert.
	log.Printf("bbd: generating ephemeral server keypair")
	srvPub, srvPriv, err := clitls.GenerateEd25519()
	if err != nil {
		return fmt.Errorf("gen server key: %w", err)
	}
	// Server cert created inside BuildServerTLS
	// Persist server PUBLIC key for client to pin.
	// 2) Generate client keypair and write keys for CLI.
	log.Printf("bbd: generating client keypair for CLI")
	cliPub, cliPriv, err := clitls.GenerateEd25519()
	if err != nil {
		return fmt.Errorf("gen client key: %w", err)
	}
	if err := clitls.WriteKeys(cliDir, srvPub, cliPriv); err != nil {
		return err
	}
	log.Printf("bbd: wrote server public key and client private key in %s", cliDir)
	expectedClientPub := cliPub

	// Build server TLS config pinned to the client public key.
	srvTLS, err := clitls.BuildServerTLS(expectedClientPub, srvPriv)
	if err != nil {
		return fmt.Errorf("server TLS: %w", err)
	}

	log.Printf("bbd: binding local CLI gRPC on %s", cfg.CLIAddr)
	lis, err := net.Listen("tcp", cfg.CLIAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.CLIAddr, err)
	}

	grpcSrv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(srvTLS)),
	)
	svc := &cliService{startedAt: time.Now(), dataDir: baseDir}
	clirpc.RegisterBarterBackupClientServer(grpcSrv, svc)

	errCh := make(chan error, 1)
	go func() {
		log.Printf("bbd: local CLI gRPC serving on %s", cfg.CLIAddr)
		errCh <- grpcSrv.Serve(lis)
	}()

	var retErr error
	select {
	case <-ctx.Done():
		log.Printf("bbd: shutdown requested, stopping...")
		grpcSrv.GracefulStop()
	case serveErr := <-errCh:
		retErr = serveErr
		if serveErr != nil {
			log.Printf("bbd: gRPC server error: %v", serveErr)
		}
	}

	// Cleanup and accumulate errors.
	if n := svc.getNode(); n != nil {
		if err := n.Stop(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("node stop: %w", err))
		}
	}
	if err := os.Remove(filepath.Join(cliDir, "client.key")); err != nil && !errors.Is(err, os.ErrNotExist) {
		retErr = errors.Join(retErr, fmt.Errorf("remove client.key: %w", err))
	}
	if err := os.Remove(filepath.Join(cliDir, "server.pub")); err != nil && !errors.Is(err, os.ErrNotExist) {
		retErr = errors.Join(retErr, fmt.Errorf("remove server.pub: %w", err))
	}
	if err := rel(); err != nil {
		retErr = errors.Join(retErr, fmt.Errorf("release lock: %w", err))
	}
	if err := os.RemoveAll(cliDir); err != nil {
		retErr = errors.Join(retErr, fmt.Errorf("remove cli-keys dir: %w", err))
	}
	return retErr
}

// cliService implements the local clirpc service before and after unlock.
type cliService struct {
	clirpc.UnimplementedBarterBackupClientServer

	mu        sync.RWMutex
	node      *bbnode.Node
	startedAt time.Time
	dataDir   string
}

func (s *cliService) getNode() *bbnode.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.node
}

// LocalHealthCheck returns onion addr (if unlocked) and uptime.
func (s *cliService) LocalHealthCheck(ctx context.Context, _ *clirpc.HealthCheckRequest) (*clirpc.HealthCheckResponse, error) {
	var uptime int64
	if !s.startedAt.IsZero() {
		uptime = int64(time.Since(s.startedAt).Seconds())
	}
	var addr string
	if n := s.getNode(); n != nil {
		addr = n.Address()
	}
	return &clirpc.HealthCheckResponse{ServerOnion: addr, UptimeSeconds: uptime}, nil
}

// Unlock creates and starts the P2P node with the provided password.
func (s *cliService) Unlock(ctx context.Context, req *clirpc.UnlockRequest) (*clirpc.UnlockResponse, error) {
	if req == nil || req.MainPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "password required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.node != nil {
		return nil, status.Error(codes.FailedPrecondition, "already unlocked")
	}
	// Fingerprint verification/creation
	fpPath := filepath.Join(s.dataDir, "fingerprint.txt")
	master := keys.DeriveMasterPriv(req.MainPassword)
	fp, err := keys.DeriveKey(master, "fingerprint", 32)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "derive fingerprint: %v", err)
	}
	hexfp := fmt.Sprintf("%x", fp)
	if b, err := os.ReadFile(fpPath); err == nil {
		onDisk := strings.TrimSpace(string(b))
		if onDisk != hexfp {
			log.Printf("bbd: fingerprint mismatch; rejecting unlock")
			return nil, status.Error(codes.PermissionDenied, "invalid password for this data directory")
		}
		log.Printf("bbd: fingerprint verified (existing instance)")
	} else if errors.Is(err, os.ErrNotExist) {
		if err := os.WriteFile(fpPath, []byte(hexfp+"\n"), 0o600); err != nil {
			return nil, status.Errorf(codes.Internal, "write fingerprint: %v", err)
		}
		log.Printf("bbd: fingerprint created at %s (fresh instance)", fpPath)
	} else {
		return nil, status.Errorf(codes.Internal, "read fingerprint: %v", err)
	}

	// Start node asynchronously and return immediately.
	dataDir := s.dataDir
	go func(pw string) {
		torDir := filepath.Join(dataDir, "tor")
		log.Printf("bbd: unlocking and starting P2P node (tor dir: %s)", torDir)
		netw := nettor.NewTorNetwork(torDir)
		node, err := bbnode.New(pw, netw)
		if err != nil {
			log.Printf("bbd: create node failed: %v", err)
			return
		}
		if err := node.Start(context.Background()); err != nil {
			log.Printf("bbd: node start failed: %v", err)
			return
		}
		s.mu.Lock()
		s.node = node
		s.mu.Unlock()
		log.Printf("bbd: node unlocked at %s", node.Address())
	}(req.MainPassword)

	return &clirpc.UnlockResponse{}, nil
}

// Helpers

func expandPath(p string) (string, error) {
	if strings.HasPrefix(p, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		p = filepath.Join(home, strings.TrimPrefix(p, "~"))
	}
	return p, nil
}

// acquireDirLock locks a file in the directory and writes our PID.
func acquireDirLock(dir string) (func() error, error) {
	lockPath := filepath.Join(dir, ".lock")
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	if err := flock.LockFile(f); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("daemon already running (lock held)")
	}
	// Keep file open for the duration of the lock; unlock removes file.
	return func() error {
		var e error
		if err := flock.UnlockFile(f); err != nil {
			e = errors.Join(e, fmt.Errorf("unlock: %w", err))
		}
		if err := f.Close(); err != nil {
			e = errors.Join(e, fmt.Errorf("close lock: %w", err))
		}
		if err := os.Remove(lockPath); err != nil {
			e = errors.Join(e, fmt.Errorf("remove lock: %w", err))
		}
		return e
	}, nil
}
