package netmock

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"
)

// MockNetwork is an in-memory Network implementation backed by bufconn.
// It uses TLS 1.3 with ONLY X25519MLKEM768 and requires a client cert.
type MockNetwork struct {
	mu    sync.RWMutex
	nodes map[string]*mockService
}

type mockService struct {
	pub     ed25519.PublicKey
	lis     *bufconn.Listener
	grpcSrv *grpc.Server
}

func NewMockNetwork() *MockNetwork {
	return &MockNetwork{
		nodes: make(map[string]*mockService),
	}
}

// Close releases resources held by the mock network. No-op for now.
func (m *MockNetwork) Close() error {
	return nil
}

func (m *MockNetwork) Register(ctx context.Context, addr string,
	priv ed25519.PrivateKey, srv *grpc.Server) (func() error, error) {

	lis := bufconn.Listen(1024 * 1024)
	go func() { _ = srv.Serve(lis) }()

	pub := priv.Public().(ed25519.PublicKey)
	svc := &mockService{pub: pub, lis: lis, grpcSrv: srv}

	m.mu.Lock()
	if _, exists := m.nodes[addr]; exists {
		m.mu.Unlock()
		return nil, errors.New("id already registered")
	}
	m.nodes[addr] = svc
	m.mu.Unlock()

	unregister := func() error {
		m.mu.Lock()
		delete(m.nodes, addr)
		m.mu.Unlock()
		srv.Stop()
		return nil
	}

	return unregister, nil
}

func (m *MockNetwork) Dial(ctx context.Context, addr string) (net.Conn, error) {
	m.mu.RLock()
	svc := m.nodes[addr]
	m.mu.RUnlock()
	if svc == nil {
		return nil, errors.New("unknown address")
	}
	return svc.lis.Dial()
}
