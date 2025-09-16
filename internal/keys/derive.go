package keys

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// DeriveMasterPriv derives master private material from a user-provided
// password/seed string using a memory-hard function (Argon2id). The salt is
// derived deterministically from the input for reproducibility across runs.
func DeriveMasterPriv(seed string) []byte {
	in := []byte(seed)
	h1 := sha256.Sum256(in)
	h2 := sha256.Sum256([]byte("deriveMasterPriv"))
	salt := sha256.Sum256(append(h1[:], h2[:]...))
	const (
		timeCost   = 1
		memoryCost = 64 * 1024
		threads    = 4
		keyLen     = 64
	)

	return argon2.IDKey(in, salt[:], timeCost, memoryCost, threads, keyLen)
}

// DeriveKey derives a key of length keyLen from masterPriv using HKDF-SHA256
// and a purpose label for domain separation.
func DeriveKey(masterPriv []byte, purpose string, keyLen int) ([]byte, error) {
	r := hkdf.New(sha256.New, masterPriv, []byte("deriveKey"), []byte(purpose))
	key := make([]byte, keyLen)
	n, err := r.Read(key)
	if err != nil {
		return nil, err
	}
	if n != keyLen {
		return nil, errors.New("short HKDF read")
	}

	return key, nil
}

// DeriveEd25519FromMaster derives a deterministic Ed25519 keypair from the
// given master private material using HKDF. The same master input always
// yields the same keypair for a given purpose string.
//
// masterPriv: output of the project's memory-hard KDF.
// purpose: domain separation label, e.g. "tor/onion/v3".
func DeriveEd25519FromMaster(masterPriv []byte, purpose string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if len(masterPriv) == 0 {
		return nil, nil, errors.New("empty masterPriv")
	}
	seed, err := DeriveKey(masterPriv, purpose, ed25519.SeedSize)
	if err != nil {
		return nil, nil, err
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	return priv, pub, nil
}
