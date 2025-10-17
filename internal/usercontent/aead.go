package usercontent

import (
	"errors"
	"fmt"

	"github.com/ericlagergren/siv"
)

const (
	contentIDNonceString = "bb-contentID"
	contentIDBlockSize   = 16
	contentIDMaxPayload  = contentIDBlockSize - 1
)

// Static assert for equality.
var _ [0]struct{} = [siv.NonceSize - len(contentIDNonceString)]struct{}{}

// SealFunc encrypts the provided plaintext deterministically.
type SealFunc func([]byte) ([]byte, error)

// OpenFunc decrypts the provided ciphertext and returns the plaintext.
type OpenFunc func([]byte) ([]byte, error)

// NewAEAD returns sealing and opening helpers backed by AES-GCM-SIV.
// The returned seal function always yields a 32-byte output.
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

	seal := func(plain []byte) ([]byte, error) {
		if len(plain) > contentIDMaxPayload {
			return nil, errors.New("usercontent: content id payload too large")
		}
		buf := make([]byte, contentIDBlockSize)
		buf[0] = byte(len(plain))
		copy(buf[1:], plain)

		ct := aead.Seal(nil, nonce, buf, nil)
		if len(ct) != 2*contentIDBlockSize {
			return nil, errors.New("usercontent: unexpected ciphertext length")
		}

		return ct, nil
	}

	open := func(ciphertext []byte) ([]byte, error) {
		if len(ciphertext) != 2*contentIDBlockSize {
			return nil, errInvalidContentID
		}

		plain, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, err
		}
		if len(plain) != contentIDBlockSize {
			return nil, errors.New("usercontent: invalid plaintext length")
		}
		length := int(plain[0])
		if length < 0 {
			return nil, errors.New("usercontent: negative length")
		}
		if length > contentIDMaxPayload {
			return nil, errors.New("usercontent: invalid payload length")
		}
		if length > len(plain)-1 {
			return nil, errors.New("usercontent: truncated payload")
		}
		out := make([]byte, length)
		copy(out, plain[1:1+length])

		return out, nil
	}

	return seal, open, nil
}
