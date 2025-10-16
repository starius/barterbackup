package usercontent

import (
	"testing"
	"time"

	"github.com/starius/barterbackup/storedpb"
	"github.com/stretchr/testify/require"
)

func TestContentIDRoundTrip(t *testing.T) {
	block := makeBlock(t)
	macFactory := makeMACFactory(t)
	revision := &storedpb.ContentRevision{
		CreatedAt:          123,
		CreatedAtNs:        456,
		MetadataAeadLength: 789,
	}

	cid, err := MakeContentID(revision, block, macFactory)
	require.NoError(t, err)

	parsed, err := ParseContentID(cid, block, macFactory)
	require.NoError(t, err)
	require.Equal(t, revision.GetCreatedAt(), parsed.GetCreatedAt())
	require.Equal(t, revision.GetCreatedAtNs(), parsed.GetCreatedAtNs())
	require.Equal(t, revision.GetMetadataAeadLength(), parsed.GetMetadataAeadLength())
}

func TestContentIDTampering(t *testing.T) {
	block := makeBlock(t)
	macFactory := makeMACFactory(t)
	revision := &storedpb.ContentRevision{CreatedAt: time.Now().Unix()}
	cid, err := MakeContentID(revision, block, macFactory)
	require.NoError(t, err)

	cipherTampered := append([]byte(nil), cid...)
	cipherTampered[0] ^= 0xff
	_, err = ParseContentID(cipherTampered, block, macFactory)
	require.Error(t, err)

	macTampered := append([]byte(nil), cid...)
	macTampered[block.BlockSize()] ^= 0xff
	_, err = ParseContentID(macTampered, block, macFactory)
	require.Error(t, err)
}
