package bbnode

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/cretz/bine/torutil"
	torutiled25519 "github.com/cretz/bine/torutil/ed25519"
	"github.com/starius/barterbackup/bbrpc"
	"github.com/starius/barterbackup/clirpc"
	"github.com/starius/barterbackup/internal/bbnode/userstorage"
	"github.com/starius/barterbackup/internal/fswrap"
	"github.com/starius/barterbackup/internal/keys"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Node represents a single BarterBackup node that serves both bbrpc (P2P)
// and clirpc (local) APIs. Networking to other nodes is abstracted by the
// Network interface so we can swap Tor-backed and in-memory implementations.
//
// Event loop rules:
//   - All mutable state lives behind the nodeState interface. RPC handlers
//     interact with the event loop exclusively through those methods.
//   - The event loop performs only in-memory work or disk operations via the
//     Filesystem abstraction. Networking is handled outside the loop.
//   - Disk access is provided by an fs.FS implementation (os.Root in production
//     and fstest-backed filesystems in tests).
//   - bbrpc handlers authenticate peers and pass the extracted peer public key
//     when state methods require it.
type Node struct {
	bbrpc.UnimplementedBarterBackupServerServer
	clirpc.UnimplementedBarterBackupClientServer

	net  Network
	priv ed25519.PrivateKey
	addr string
	stop func() error

	mu    sync.RWMutex
	conns map[string]*pooledConn

	evictStop chan struct{}
	evictDone chan struct{}

	store *userstorage.Store
	state nodeState

	peers      map[string]struct{}
	storageCfg clirpc.StorageConfig
	knownPubs  map[string]struct{}
	requester  map[string]*bbrpc.ContentInfo
	downloads  map[string]context.CancelFunc

	startedAt time.Time
}

type pooledConn struct {
	conn     *grpc.ClientConn
	lastUsed time.Time
}

// New creates a Node from a user-provided password/seed, storage directory,
// and a Network implementation.
func New(seed string, netw Network, storageDir string) (*Node, error) {
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

	fsys, err := userstorage.NewOSFilesystem(storageDir)
	if err != nil {
		return nil, err
	}

	keyForWrap, err := keys.DeriveKey(master, "wrap", 32)
	if err != nil {
		return nil, err
	}
	wrappedFS, err := fswrap.New(fsys, keyForWrap)
	if err != nil {
		return nil, err
	}

	keyForOurContent, err := keys.DeriveKey(master, "our-content", 32)
	if err != nil {
		return nil, err
	}
	store, err := userstorage.NewStore(wrappedFS, keyForOurContent)
	if err != nil {
		return nil, err
	}

	n := &Node{
		net:       netw,
		priv:      priv,
		addr:      addr,
		conns:     make(map[string]*pooledConn),
		peers:     make(map[string]struct{}),
		knownPubs: make(map[string]struct{}),
		requester: make(map[string]*bbrpc.ContentInfo),
		downloads: make(map[string]context.CancelFunc),
		store:     store,
	}
	for _, p := range store.Peers() {
		if len(p.GetOnionPubkey()) == 0 || len(p.GetContentId()) == 0 {
			continue
		}
		n.requester[string(p.GetOnionPubkey())] = &bbrpc.ContentInfo{
			ContentId: append([]byte(nil), p.GetContentId()...),
		}
	}

	return n, nil
}

// Start registers the node on the network and starts serving bbrpc.
func (n *Node) Start(ctx context.Context) error {
	if n.stop != nil {
		return errors.New("already started")
	}
	n.state = newEventState(n.store)

	// Build server TLS config and gRPC server.
	cert, err := selfSignedEd25519Cert(n.priv)
	if err != nil {
		n.state.Close()
		n.state = nil
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
		grpc.MaxRecvMsgSize(bbrpc.GRPCMaxMsgSize),
		grpc.MaxSendMsgSize(bbrpc.GRPCMaxMsgSize),
	)
	bbrpc.RegisterBarterBackupServerServer(grpcSrv, n)
	clirpc.RegisterBarterBackupClientServer(grpcSrv, n)

	unregister, err := n.net.Register(ctx, n.addr, n.priv, grpcSrv)
	if err != nil {
		n.state.Close()
		n.state = nil
		return err
	}
	n.stop = unregister

	n.startedAt = time.Now()

	// Start background eviction of idle connections.
	n.startEvictor()

	valid := make(map[string]struct{})
	if cid := n.store.CurrentContentID(); len(cid) > 0 {
		valid[string(cid)] = struct{}{}
	}
	for pubKey, info := range n.requester {
		if len(info.GetContentId()) > 0 {
			valid[string(info.GetContentId())] = struct{}{}
			n.schedulePeerDownload([]byte(pubKey), info.GetContentId())
		}
	}
	_ = n.store.CleanupForeign(valid)

	return nil
}

// Stop unregisters the node from the network and stops serving.
func (n *Node) Stop() error {
	if n.stop == nil {
		if n.state != nil {
			n.state.Close()
			n.state = nil
		}
		return nil
	}
	n.stopEvictor()
	n.mu.Lock()
	for _, cancel := range n.downloads {
		cancel()
	}
	n.downloads = make(map[string]context.CancelFunc)
	n.mu.Unlock()
	err := n.stop()
	n.stop = nil

	// Close pooled connections.
	n.mu.Lock()
	for a, pc := range n.conns {
		_ = pc.conn.Close()
		delete(n.conns, a)
	}
	n.mu.Unlock()

	if n.store != nil {
		_ = n.store.Close()
	}

	if n.state != nil {
		n.state.Close()
		n.state = nil
	}

	return err
}

// Address returns the onion address of this node.
func (n *Node) Address() string {
	return n.addr
}

// Server methods for bbrpc and client methods for clirpc are implemented
// in dedicated files to avoid name collisions and keep responsibilities
// separated. See bbrpc_server.go and clirpc_server.go.

// dialPeer dials another node onion address and returns a bbrpc client and conn.
// It is used internally by the node when talking to peers.
func (n *Node) dialPeer(ctx context.Context, addr string) (bbrpc.BarterBackupServerClient, *grpc.ClientConn, error) {
	conn, err := n.getPeerConn(ctx, addr)
	if err != nil {
		return nil, nil, err
	}
	client := bbrpc.NewBarterBackupServerClient(conn)
	return client, conn, nil
}

// getConn returns a pooled gRPC ClientConn to addr or dials and caches one.
// getPeerConn returns a pooled gRPC ClientConn to a peer onion address or
// dials and caches one. This is used for peer-to-peer connections.
func (n *Node) getPeerConn(ctx context.Context, addr string) (*grpc.ClientConn, error) {
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
		Certificates:     []tls.Certificate{cliCert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		ServerName:       addr,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			verified, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pub, ok := verified.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("peer certificate is not ed25519")
			}
			id := torutil.OnionServiceIDFromV3PublicKey(torutiled25519.PublicKey(pub)) + ".onion"
			if id != addr {
				return fmt.Errorf("peer onion mismatch: got %s expected %s", id, addr)
			}
			return nil
		},
		InsecureSkipVerify: true,
	}

	conn, err := grpc.DialContext(ctx, addr,
		grpc.WithBlock(),
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(bbrpc.GRPCMaxMsgSize),
			grpc.MaxCallSendMsgSize(bbrpc.GRPCMaxMsgSize),
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

func (n *Node) schedulePeerDownload(pub, cid []byte) {
	if len(cid) == 0 {
		return
	}
	n.mu.Lock()
	if cancel := n.downloads[string(pub)]; cancel != nil {
		cancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.downloads[string(pub)] = cancel
	n.mu.Unlock()

	go n.downloadPeerContent(ctx, pub, cid)
}

func (n *Node) cancelDownload(pub []byte) {
	n.mu.Lock()
	if cancel := n.downloads[string(pub)]; cancel != nil {
		cancel()
		delete(n.downloads, string(pub))
	}
	n.mu.Unlock()
}

func (n *Node) downloadPeerContent(ctx context.Context, pub, cid []byte) {
	addr := torutil.OnionServiceIDFromV3PublicKey(torutiled25519.PublicKey(pub)) + ".onion"

	prev := []byte{}
	n.mu.RLock()
	if info, ok := n.requester[string(pub)]; ok {
		prev = append([]byte(nil), info.GetContentId()...)
	}
	n.mu.RUnlock()

	if n.store.ContentExists(cid) {
		n.cancelDownload(pub)
		return
	}

	client, conn, err := n.dialPeer(ctx, addr)
	if err != nil {
		return
	}
	defer conn.Close()

	var prevReader userstorage.ReadFile
	if len(prev) > 0 && n.store.ContentExists(prev) {
		prevReader, _ = n.store.OpenContentByID(prev)
	}
	defer func() {
		if prevReader != nil {
			_ = prevReader.Close()
		}
	}()

	hasher := sha256.New()
	writeErr := n.store.WriteContentBlob(cid, func(w userstorage.WriteFile) error {
		offset := int64(0)
		var total int64 = -1
		var expectedSha []byte
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}
			req := &bbrpc.DownloadRequest{
				ContentId: cid,
				Offset:    offset,
			}
			if len(prev) > 0 {
				req.ReferenceContentId = prev
			}
			resp, err := client.Download(ctx, req)
			if err != nil {
				return err
			}
			if total == -1 {
				total = resp.GetTotalLength()
				expectedSha = resp.GetSha256()
			}
			switch sec := resp.Section.(type) {
			case *bbrpc.DownloadResponse_RawBytes:
				data := sec.RawBytes.GetValue()
				if len(data) == 0 {
					return errors.New("empty raw bytes")
				}
				if _, err := hasher.Write(data); err != nil {
					return err
				}
				if _, err := w.Write(data); err != nil {
					return err
				}
				offset += int64(len(data))
			case *bbrpc.DownloadResponse_Reference:
				if prevReader == nil {
					return errors.New("reference provided without prev content")
				}
				ref := sec.Reference
				data, err := readChunk(prevReader, ref.GetOffsetInReference(), int(ref.GetLength()))
				if err != nil {
					return err
				}
				if _, err := hasher.Write(data); err != nil {
					return err
				}
				if _, err := w.Write(data); err != nil {
					return err
				}
				offset += int64(len(data))
			default:
				return errors.New("unknown download section")
			}

			if offset >= total {
				break
			}
		}
		if len(expectedSha) > 0 && !bytes.Equal(hasher.Sum(nil), expectedSha) {
			return errors.New("peer content hash mismatch")
		}
		return nil
	})

	if writeErr != nil {
		n.store.RemoveContentByID(cid)
		n.cancelDownload(pub)
		return
	}

	// Cleanup previous content if different.
	if len(prev) > 0 && !bytes.Equal(prev, cid) {
		_ = n.store.RemoveContentByID(prev)
	}
	n.cancelDownload(pub)
}
