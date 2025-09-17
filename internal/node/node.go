package node

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"time"

	torutil "github.com/cretz/bine/torutil"
	torutiled25519 "github.com/cretz/bine/torutil/ed25519"
	"github.com/starius/barterbackup/bbrpc"
	"github.com/starius/barterbackup/internal/keys"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// grpcMaxMsg bounds the maximum gRPC message size we accept and send.
// This small limit (16 KiB) is a simple DoS mitigation to prevent peers from
// forcing large allocations or bandwidth usage with oversized messages.
// Increase carefully if larger messages become necessary.
const grpcMaxMsg = 16 * 1024

// Node represents a single BarterBackup node that serves both bbrpc (P2P)
// and clirpc (local) APIs. Networking to other nodes is abstracted by the
// Network interface so we can swap Tor-backed and in-memory implementations.
type Node struct {
	bbrpc.UnimplementedBarterBackupServerServer

	net        Network
	masterPriv []byte
	priv       ed25519.PrivateKey
	addr       string
	stop       func() error

	mu    sync.RWMutex
	conns map[string]*pooledConn

	evictStop chan struct{}
	evictDone chan struct{}
}

type pooledConn struct {
	conn     *grpc.ClientConn
	lastUsed time.Time
}

// New creates a Node from a user-provided password/seed and a Network.
func New(seed string, netw Network) (*Node, error) {
	if netw == nil {
		return nil, errors.New("network is nil")
	}

	master := keys.DeriveMasterPriv(seed)
	priv, pub, err := keys.DeriveEd25519FromMaster(master, "tor/onion/v3")
	if err != nil {
		return nil, err
	}
	onionID := torutil.OnionServiceIDFromV3PublicKey(torutiled25519.PublicKey(pub))
	addr := onionID + ".onion"

	return &Node{
		net:        netw,
		masterPriv: master,
		priv:       priv,
		addr:       addr,
		conns:      make(map[string]*pooledConn),
	}, nil
}

// Start registers the node on the network and starts serving bbrpc.
func (n *Node) Start(ctx context.Context) error {
	if n.stop != nil {
		return errors.New("already started")
	}
	// Build server TLS config and gRPC server.
	cert, err := selfSignedEd25519Cert(n.priv)
	if err != nil {
		return err
	}
	srvTLS := &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		ClientAuth:       tls.RequireAnyClientCert,
	}
	grpcSrv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(srvTLS)),
		grpc.MaxRecvMsgSize(grpcMaxMsg),
		grpc.MaxSendMsgSize(grpcMaxMsg),
	)
	bbrpc.RegisterBarterBackupServerServer(grpcSrv, n)

	unregister, err := n.net.Register(ctx, n.addr, n.priv, grpcSrv)
	if err != nil {
		return err
	}
	n.stop = unregister

	// Start background eviction of idle connections.
	n.startEvictor()

	return nil
}

// Stop unregisters the node from the network and stops serving.
func (n *Node) Stop() error {
	if n.stop == nil {
		return nil
	}
	n.stopEvictor()
	err := n.stop()
	n.stop = nil

	// Close pooled connections.
	n.mu.Lock()
	for a, pc := range n.conns {
		_ = pc.conn.Close()
		delete(n.conns, a)
	}
	n.mu.Unlock()

	return err
}

// Address returns the onion address of this node.
func (n *Node) Address() string {
	return n.addr
}

// Server methods for bbrpc and client methods for clirpc are implemented
// in dedicated files to avoid name collisions and keep responsibilities
// separated. See bbrpc_server.go and clirpc_server.go.

// DialPeer dials another node onion address and returns a bbrpc client and conn.
func (n *Node) DialPeer(ctx context.Context, addr string) (bbrpc.BarterBackupServerClient, *grpc.ClientConn, error) {
	conn, err := n.getConn(ctx, addr)
	if err != nil {
		return nil, nil, err
	}
	client := bbrpc.NewBarterBackupServerClient(conn)
	return client, conn, nil
}

// getConn returns a pooled gRPC ClientConn to addr or dials and caches one.
func (n *Node) getConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
	// Fast path: existing connection in pool.
	n.mu.RLock()
	pc := n.conns[addr]
	n.mu.RUnlock()
	if pc != nil {
		// Update last used under write lock to avoid races.
		n.mu.Lock()
		if cur := n.conns[addr]; cur != nil {
			cur.lastUsed = time.Now()
			c := cur.conn
			n.mu.Unlock()
			return c, nil
		}
		n.mu.Unlock()
	}

	// Build the connection.
	dialer := func(ctx context.Context, target string) (net.Conn, error) {
		return n.net.Dial(ctx, target)
	}

	cliCert, err := selfSignedEd25519Cert(n.priv)
	if err != nil {
		return nil, err
	}
	clientTLS := &tls.Config{
		Certificates:       []tls.Certificate{cliCert},
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
		InsecureSkipVerify: true,
	}

	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithBlock(),
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(grpcMaxMsg),
			grpc.MaxCallSendMsgSize(grpcMaxMsg),
		),
	)
	if err != nil {
		return nil, err
	}

	// Publish to pool if not already present.
	n.mu.Lock()
	if existing := n.conns[addr]; existing != nil {
		n.mu.Unlock()
		_ = conn.Close()
		return existing.conn, nil
	}
	n.conns[addr] = &pooledConn{conn: conn, lastUsed: time.Now()}
	n.mu.Unlock()

	return conn, nil
}

func (n *Node) startEvictor() {
	n.mu.Lock()
	if n.evictStop != nil {
		n.mu.Unlock()
		return
	}
	n.evictStop = make(chan struct{})
	n.evictDone = make(chan struct{})
	stopCh := n.evictStop
	doneCh := n.evictDone
	n.mu.Unlock()

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer func() {
			ticker.Stop()
			close(doneCh)
		}()
		for {
			select {
			case <-ticker.C:
				n.evictIdle(5 * time.Minute)
			case <-stopCh:
				return
			}
		}
	}()
}

func (n *Node) stopEvictor() {
	n.mu.Lock()
	stopCh := n.evictStop
	doneCh := n.evictDone
	n.evictStop = nil
	n.evictDone = nil
	n.mu.Unlock()
	if stopCh != nil {
		close(stopCh)
	}
	if doneCh != nil {
		<-doneCh
	}
}

func (n *Node) evictIdle(idle time.Duration) {
	cutoff := time.Now().Add(-idle)
	n.mu.Lock()
	for addr, pc := range n.conns {
		if pc.lastUsed.Before(cutoff) {
			_ = pc.conn.Close()
			delete(n.conns, addr)
		}
	}
	n.mu.Unlock()
}
