package clitls

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// GenerateEd25519 returns a fresh Ed25519 keypair.
func GenerateEd25519() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

// NewSelfSignedServerCert creates a self-signed X.509 cert for server usage with a long expiry.
func NewSelfSignedServerCert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	return newSelfSignedCert(priv, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

// NewSelfSignedClientCert creates a self-signed X.509 cert for client usage with a long expiry.
func NewSelfSignedClientCert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	return newSelfSignedCert(priv, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
}

func newSelfSignedCert(priv ed25519.PrivateKey, ku []x509.ExtKeyUsage) (tls.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          bigRand(),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           ku,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           toIPs([]string{"127.0.0.1", "::1"}),
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func bigRand() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	return n
}

func toIPs(strs []string) []net.IP {
	out := make([]net.IP, 0, len(strs))
	for _, s := range strs {
		if ip, err := netip.ParseAddr(s); err == nil {
			out = append(out, net.IP(ip.AsSlice()))
		}
	}
	return out
}

// WritePrivateKey writes an Ed25519 private key in PKCS#8 PEM format.
// WriteKeys writes server.pub and client.key under dirPath.
func WriteKeys(dirPath string, serverPub ed25519.PublicKey, clientPriv ed25519.PrivateKey) error {
	if err := os.MkdirAll(dirPath, 0o700); err != nil {
		return err
	}
	// server.pub
	der, err := x509.MarshalPKIXPublicKey(serverPub)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dirPath, "server.pub"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	// client.key
	pkcs8, err := x509.MarshalPKCS8PrivateKey(clientPriv)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dirPath, "client.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), 0o600); err != nil {
		return err
	}
	return nil
}

// ReadKeys reads server.pub and client.key from dirPath.
func ReadKeys(dirPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	spem, err := os.ReadFile(filepath.Join(dirPath, "server.pub"))
	if err != nil {
		return nil, nil, err
	}
	sblk, _ := pem.Decode(spem)
	if sblk == nil || sblk.Type != "PUBLIC KEY" {
		return nil, nil, errors.New("invalid server pub file")
	}
	pubIf, err := x509.ParsePKIXPublicKey(sblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	serverPub, ok := pubIf.(ed25519.PublicKey)
	if !ok {
		return nil, nil, errors.New("server pub is not ed25519")
	}

	kpem, err := os.ReadFile(filepath.Join(dirPath, "client.key"))
	if err != nil {
		return nil, nil, err
	}
	kblk, _ := pem.Decode(kpem)
	if kblk == nil || kblk.Type != "PRIVATE KEY" {
		return nil, nil, errors.New("invalid client key file")
	}
	keyIf, err := x509.ParsePKCS8PrivateKey(kblk.Bytes)
	if err != nil {
		return nil, nil, err
	}
	clientPriv, ok := keyIf.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, errors.New("client key is not ed25519")
	}
	return serverPub, clientPriv, nil
}

// BuildServerTLS builds a TLS config for the server pinning a specific client pubkey.
func BuildServerTLS(expectedClientPub ed25519.PublicKey, serverPriv ed25519.PrivateKey) (*tls.Config, error) {
	cert, err := NewSelfSignedServerCert(serverPriv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:     []tls.Certificate{cert},
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		ClientAuth:       tls.RequireAnyClientCert,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no client certificate")
			}
			pk, ok := cs.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("client cert not ed25519")
			}
			if !bytes.Equal(pk, expectedClientPub) {
				return errors.New("unauthorized client certificate")
			}
			return nil
		},
	}, nil
}

// NewClientTLSFromFiles builds a client TLS that pins the server public key read from PEM file.
func BuildClientTLSF(serverPub ed25519.PublicKey, clientPriv ed25519.PrivateKey) (*tls.Config, error) {
	cert, err := NewSelfSignedClientCert(clientPriv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519MLKEM768},
		InsecureSkipVerify: true, // we pin instead of verifying chain
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("no server certificate")
			}
			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}
			pk, ok := cert.PublicKey.(ed25519.PublicKey)
			if !ok {
				return errors.New("server cert is not ed25519")
			}
			if !bytes.Equal(pk, serverPub) {
				return errors.New("server public key mismatch")
			}
			return nil
		},
	}, nil
}
