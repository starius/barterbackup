package harness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"barterbackup/integration/docker/gen/clirpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// DialLocalClient connects to one daemon's local clirpc endpoint using the
// session keys in keysDir.
func DialLocalClient(
	ctx context.Context,
	localAddr string,
	keysDir string,
) (clirpc.BarterBackupClientClient, *grpc.ClientConn, error) {
	tlsConfig, err := buildLocalTLSConfig(keysDir)
	if err != nil {
		return nil, nil, err
	}

	conn, err := grpc.DialContext(
		ctx,
		localAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("dial local clirpc %s: %w", localAddr, err)
	}
	return clirpc.NewBarterBackupClientClient(conn), conn, nil
}

func buildLocalTLSConfig(keysDir string) (*tls.Config, error) {
	serverPublicKey, err := readServerPublicKey(filepath.Join(keysDir, "server.pub"))
	if err != nil {
		return nil, err
	}
	clientPrivateKey, err := readClientPrivateKey(filepath.Join(keysDir, "client.key"))
	if err != nil {
		return nil, err
	}
	clientCertificate, err := makeClientCertificate(clientPrivateKey)
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{clientCertificate},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("server did not present a certificate")
			}
			certificate, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("parse server certificate: %w", err)
			}
			publicKey, ok := certificate.PublicKey.(ed25519.PublicKey)
			if !ok {
				return fmt.Errorf("server certificate is not ed25519")
			}
			if !publicKeysEqual(publicKey, serverPublicKey) {
				return fmt.Errorf("server public key mismatch")
			}
			return nil
		},
	}, nil
}

func makeClientCertificate(clientPrivateKey ed25519.PrivateKey) (tls.Certificate, error) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "bbcli-integration",
		},
		NotBefore:             time.Unix(0, 0),
		NotAfter:              time.Unix(1<<31-1, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		clientPrivateKey.Public(),
		clientPrivateKey,
	)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create client certificate: %w", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: clientPrivateKey}, nil
}

func readServerPublicKey(path string) (ed25519.PublicKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("decode %s: missing PEM block", path)
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	edPublicKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%s does not contain an ed25519 public key", path)
	}
	return edPublicKey, nil
}

func readClientPrivateKey(path string) (ed25519.PrivateKey, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("decode %s: missing PEM block", path)
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	edPrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s does not contain an ed25519 private key", path)
	}
	return edPrivateKey, nil
}

func publicKeysEqual(left ed25519.PublicKey, right ed25519.PublicKey) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
