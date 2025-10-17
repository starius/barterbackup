package usercontent

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/starius/barterbackup/storedpb"
)

const (
	contentIDVersion       = 1
	contentIDPlaintextSize = 1 + 3 + 8
	maxMetadataLen         = 0xFFFFFF
)

var errInvalidContentID = errors.New("usercontent: invalid content id")

// MakeContentID encrypts the provided revision using the supplied seal helper.
func MakeContentID(revision *storedpb.ContentRevision, aeadSeal SealFunc) ([]byte, error) {
	if revision == nil {
		return nil, errors.New("usercontent: revision is nil")
	}
	if aeadSeal == nil {
		return nil, errors.New("usercontent: seal function is nil")
	}

	if revision.GetMetadataAeadLength() < 0 {
		return nil, errors.New("usercontent: negative metadata aead length")
	}
	if revision.GetMetadataAeadLength() > 0xFFFFFF {
		return nil, fmt.Errorf("usercontent: metadata aead length too large (%d)", revision.GetMetadataAeadLength())
	}

	if revision.GetCreatedAt() < 0 {
		return nil, errors.New("usercontent: negative created_at")
	}
	if revision.GetCreatedAtNs() < 0 {
		return nil, errors.New("usercontent: negative created_at_ns")
	}
	if revision.GetCreatedAtNs() >= 1_000_000_000 {
		return nil, errors.New("usercontent: created_at_ns out of range")
	}

	createdAt := revision.GetCreatedAt()
	createdAtNs := revision.GetCreatedAtNs()

	const maxInt64 = int64(^uint64(0) >> 1)
	if createdAt > maxInt64/1_000_000_000 {
		return nil, errors.New("usercontent: created_at overflow")
	}
	unixNano := uint64(createdAt)*1_000_000_000 + uint64(createdAtNs)
	if unixNano > uint64(maxInt64) {
		return nil, errors.New("usercontent: timestamp overflow")
	}
	if int64(unixNano/1_000_000_000) != createdAt || int64(unixNano%1_000_000_000) != createdAtNs {
		return nil, errors.New("usercontent: timestamp overflow")
	}

	plaintext := make([]byte, contentIDPlaintextSize)
	plaintext[0] = contentIDVersion
	metaLen := uint32(revision.GetMetadataAeadLength())
	plaintext[1] = byte(metaLen >> 16)
	plaintext[2] = byte(metaLen >> 8)
	plaintext[3] = byte(metaLen)
	binary.BigEndian.PutUint64(plaintext[4:], unixNano)

	contentID, err := aeadSeal(plaintext, nil)
	if err != nil {
		return nil, fmt.Errorf("usercontent: seal failed: %w", err)
	}

	return contentID, nil
}

// ParseContentID verifies and decrypts a content identifier into a revision.
func ParseContentID(contentID []byte, aeadOpen OpenFunc) (*storedpb.ContentRevision, error) {
	if aeadOpen == nil {
		return nil, errors.New("usercontent: open function is nil")
	}

	plain, err := aeadOpen(contentID, nil)
	if err != nil {
		return nil, fmt.Errorf("usercontent: open failed: %w", err)
	}

	if len(plain) != contentIDPlaintextSize {
		return nil, errInvalidContentID
	}

	if plain[0] != contentIDVersion {
		return nil, errInvalidContentID
	}

	metaLen := uint32(plain[1])<<16 | uint32(plain[2])<<8 | uint32(plain[3])
	unixNano := binary.BigEndian.Uint64(plain[4:])

	createdAt := int64(unixNano / 1_000_000_000)
	createdAtNs := int64(unixNano % 1_000_000_000)

	revision := &storedpb.ContentRevision{
		CreatedAt:          createdAt,
		CreatedAtNs:        createdAtNs,
		MetadataAeadLength: int64(metaLen),
	}

	return revision, nil
}
