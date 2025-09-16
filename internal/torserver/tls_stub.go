package torserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"time"
)

// Hybrid PQ key exchange (X25519MLKEM768) is available in Go 1.24+.
// No additional configuration is required beyond setting CurvePreferences
// in the TLS config (see server.go).

// selfSignedEd25519Cert creates a self-signed X.509 certificate using the
// provided Ed25519 private key. The cert is valid for a short duration and
// intended only for securing the local gRPC transport over Tor.
func selfSignedEd25519Cert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	// Encode into a tls.Certificate structure without writing files.
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, err := marshalPKCS8Ed25519(priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}

func marshalPKCS8Ed25519(priv ed25519.PrivateKey) ([]byte, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	b := pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}
	out := pem.EncodeToMemory(&b)
	if len(out) == 0 {
		return nil, errors.New("failed to PEM encode private key")
	}

	return out, nil
}
