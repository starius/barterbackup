package usercontent

import (
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/starius/barterbackup/storedpb"
	"google.golang.org/protobuf/proto"
)

var errInvalidContentID = errors.New("usercontent: invalid content id")

// MakeContentID encrypts the provided revision using the supplied block cipher
// and authenticates it with the MAC factory.
func MakeContentID(revision *storedpb.ContentRevision, block cipher.Block, macFactory MACFactory) ([]byte, error) {
	if revision == nil {
		return nil, errors.New("usercontent: revision is nil")
	}
	if block == nil {
		return nil, errors.New("usercontent: content block cipher is nil")
	}
	if macFactory == nil {
		return nil, errors.New("usercontent: MAC factory is nil")
	}
	mac := macFactory()
	if mac == nil {
		return nil, errors.New("usercontent: MAC factory returned nil")
	}

	plain, err := proto.Marshal(revision)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	if len(plain) > blockSize-2 {
		return nil, fmt.Errorf("usercontent: revision too large (%d bytes)", len(plain))
	}
	buf := make([]byte, blockSize)
	binary.BigEndian.PutUint16(buf[:2], uint16(len(plain)))
	copy(buf[2:], plain)
	ciphertext := make([]byte, blockSize)
	block.Encrypt(ciphertext, buf)

	mac.Reset()
	if _, err := mac.Write(ciphertext); err != nil {
		return nil, err
	}
	tag := mac.Sum(nil)

	out := make([]byte, len(ciphertext)+len(tag))
	copy(out, ciphertext)
	copy(out[len(ciphertext):], tag)
	return out, nil
}

// ParseContentID verifies and decrypts a content identifier into a revision.
func ParseContentID(contentID []byte, block cipher.Block, macFactory MACFactory) (*storedpb.ContentRevision, error) {
	if block == nil {
		return nil, errors.New("usercontent: content block cipher is nil")
	}
	if macFactory == nil {
		return nil, errors.New("usercontent: MAC factory is nil")
	}
	mac := macFactory()
	if mac == nil {
		return nil, errors.New("usercontent: MAC factory returned nil")
	}
	blockSize := block.BlockSize()
	tagSize := mac.Size()
	if tagSize == 0 {
		return nil, errors.New("usercontent: MAC size is zero")
	}
	if len(contentID) != blockSize+tagSize {
		return nil, errInvalidContentID
	}

	ciphertext := contentID[:blockSize]
	tag := contentID[blockSize:]

	mac.Reset()
	if _, err := mac.Write(ciphertext); err != nil {
		return nil, err
	}
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, tag) {
		return nil, errInvalidContentID
	}

	plainBlock := make([]byte, blockSize)
	block.Decrypt(plainBlock, ciphertext)
	length := int(binary.BigEndian.Uint16(plainBlock[:2]))
	if length > blockSize-2 {
		return nil, errInvalidContentID
	}
	plain := make([]byte, length)
	copy(plain, plainBlock[2:2+length])
	var revision storedpb.ContentRevision
	if err := proto.Unmarshal(plain, &revision); err != nil {
		return nil, err
	}
	return &revision, nil
}
