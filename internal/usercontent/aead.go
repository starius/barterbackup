package usercontent

import (
	"errors"
	"fmt"

	"github.com/ericlagergren/siv"
)

const contentIDNonceString = "bb-contentID"

// Static assert that the nonce matches the required size.
var _ [0]struct{} = [len(contentIDNonceString) - siv.NonceSize]struct{}{}

// SealFunc encrypts the provided plaintext with optional associated data.
type SealFunc func(plaintext, associatedData []byte) ([]byte, error)

// OpenFunc decrypts the provided ciphertext with optional associated data.
type OpenFunc func(ciphertext, associatedData []byte) ([]byte, error)

// NewAEAD returns sealing and opening helpers backed by AES-GCM-SIV.
func NewAEAD(key []byte) (SealFunc, OpenFunc, error) {
	if len(key) != 32 {
		return nil, nil, fmt.Errorf("usercontent: aead key must be 32 bytes, got %d", len(key))
	}
	aead, err := siv.NewGCM(key)
	if err != nil {
		return nil, nil, err
	}
	if len(contentIDNonceString) != siv.NonceSize {
		return nil, nil, errors.New("usercontent: invalid nonce length")
	}
	nonce := []byte(contentIDNonceString)

	seal := func(plain, ad []byte) ([]byte, error) {
		ct := aead.Seal(nil, nonce, plain, ad)
		return ct, nil
	}

	open := func(ciphertext, ad []byte) ([]byte, error) {
		plain, err := aead.Open(nil, nonce, ciphertext, ad)
		if err != nil {
			return nil, err
		}

		if len(plain) == 0 {
			plain = []byte{}
		}

		return plain, nil
	}

	return seal, open, nil
}
