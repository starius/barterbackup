package usercontent

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"github.com/starius/barterbackup/storedpb"
	"google.golang.org/protobuf/proto"
)

var errInvalidContentID = errors.New("usercontent: invalid content id")

// MakeContentID encrypts the provided revision using the supplied AEAD.
// The nonce is derived deterministically from the revision fields.
func MakeContentID(revision *storedpb.ContentRevision, aead cipher.AEAD) ([]byte, error) {
	if revision == nil {
		return nil, errors.New("usercontent: revision is nil")
	}
	if aead == nil {
		return nil, errors.New("usercontent: content AEAD is nil")
	}
	nonce := makeRevisionNonce(revision, aead.NonceSize())
	plain, err := proto.Marshal(revision)
	if err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plain, nil)
	out := make([]byte, len(nonce)+len(ciphertext))
	copy(out, nonce)
	copy(out[len(nonce):], ciphertext)
	return out, nil
}

// ParseContentID verifies and decrypts a content identifier into a revision.
func ParseContentID(contentID []byte, aead cipher.AEAD) (*storedpb.ContentRevision, error) {
	if aead == nil {
		return nil, errors.New("usercontent: content AEAD is nil")
	}
	nonceSize := aead.NonceSize()
	if len(contentID) <= nonceSize {
		return nil, errInvalidContentID
	}
	nonce := contentID[:nonceSize]
	ciphertext := contentID[nonceSize:]
	plain, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	var revision storedpb.ContentRevision
	if err := proto.Unmarshal(plain, &revision); err != nil {
		return nil, err
	}
	if !bytes.Equal(nonce, makeRevisionNonce(&revision, nonceSize)) {
		return nil, errInvalidContentID
	}
	return &revision, nil
}

func makeRevisionNonce(rev *storedpb.ContentRevision, nonceSize int) []byte {
	nonce := make([]byte, nonceSize)
	if nonceSize >= 8 {
		binary.BigEndian.PutUint64(nonce[nonceSize-8:], uint64(rev.GetCreatedAtNs()))
	}
	if nonceSize >= 12 {
		binary.BigEndian.PutUint32(nonce[nonceSize-12:], uint32(rev.GetCreatedAt()))
	}
	return nonce
}
