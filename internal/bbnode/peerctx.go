package bbnode

import (
	"context"
	"crypto/ed25519"
	"errors"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// ClientPubKeyFromContext extracts the client's Ed25519 public key from a
// gRPC server context when mutual TLS is used. Returns an error if missing.
func ClientPubKeyFromContext(ctx context.Context) (ed25519.PublicKey, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, errors.New("no peer auth info in context")
	}

	// credentials.TLSInfo is the concrete type for TLS auth info.
	switch ti := p.AuthInfo.(type) {
	case credentials.TLSInfo:
		if len(ti.State.PeerCertificates) == 0 {
			return nil, errors.New("no peer certificate")
		}
		if pub, ok := ti.State.PeerCertificates[0].PublicKey.(ed25519.PublicKey); ok {
			return pub, nil
		}
		return nil, errors.New("peer certificate is not ed25519")

	case *credentials.TLSInfo:
		if ti == nil || len(ti.State.PeerCertificates) == 0 {
			return nil, errors.New("no peer certificate")
		}
		if pub, ok := ti.State.PeerCertificates[0].PublicKey.(ed25519.PublicKey); ok {
			return pub, nil
		}
		return nil, errors.New("peer certificate is not ed25519")

	default:
		return nil, errors.New("unexpected peer auth type")
	}
}
