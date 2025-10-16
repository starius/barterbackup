package usercontent

import (
	"errors"
	"fmt"

	"github.com/starius/barterbackup/storedpb"
	"google.golang.org/protobuf/proto"
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

	plain, err := proto.Marshal(revision)
	if err != nil {
		return nil, err
	}
	if len(plain) > contentIDMaxPayload {
		return nil, fmt.Errorf("usercontent: revision too large (%d bytes)", len(plain))
	}
	contentID, err := aeadSeal(plain)
	if err != nil {
		return nil, err
	}
	return contentID, nil
}

// ParseContentID verifies and decrypts a content identifier into a revision.
func ParseContentID(contentID []byte, aeadOpen OpenFunc) (*storedpb.ContentRevision, error) {
	if aeadOpen == nil {
		return nil, errors.New("usercontent: open function is nil")
	}
	plain, err := aeadOpen(contentID)
	if err != nil {
		return nil, err
	}
	var revision storedpb.ContentRevision
	if err := proto.Unmarshal(plain, &revision); err != nil {
		return nil, err
	}
	return &revision, nil
}
