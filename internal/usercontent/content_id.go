package usercontent

import (
	"errors"
	"fmt"

	"github.com/starius/barterbackup/storedpb"
	"google.golang.org/protobuf/proto"
)

var errInvalidContentID = errors.New("invalid content id")

// MakeContentID encrypts the provided revision using the supplied seal helper.
func MakeContentID(revision *storedpb.ContentRevision, aeadSeal SealFunc) ([]byte, error) {
	if revision == nil {
		return nil, errors.New("content_id: revision is nil")
	}
	if aeadSeal == nil {
		return nil, errors.New("content_id: seal function is nil")
	}

	plain, err := proto.Marshal(revision)
	if err != nil {
		return nil, err
	}
	if len(plain) > contentIDMaxPayload {
		return nil, fmt.Errorf("content_id: revision too large (%d bytes)", len(plain))
	}

	contentID, err := aeadSeal(plain)
	if err != nil {
		return nil, fmt.Errorf("content_id: seal failed: %w", err)
	}

	return contentID, nil
}

// ParseContentID verifies and decrypts a content identifier into a revision.
func ParseContentID(contentID []byte, aeadOpen OpenFunc) (*storedpb.ContentRevision, error) {
	if aeadOpen == nil {
		return nil, errors.New("content_id: open function is nil")
	}

	plain, err := aeadOpen(contentID)
	if err != nil {
		return nil, fmt.Errorf("content_id: open failed: %w", err)
	}

	var revision storedpb.ContentRevision
	if err := proto.Unmarshal(plain, &revision); err != nil {
		return nil, fmt.Errorf("content_id: proto.Unmarshal failed: %w", err)
	}

	return &revision, nil
}
