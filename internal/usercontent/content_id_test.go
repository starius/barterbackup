package usercontent

import (
	"testing"
	"time"

	"github.com/starius/barterbackup/storedpb"
	"github.com/stretchr/testify/require"
)

func TestContentIDRoundTrip(t *testing.T) {
	aead := makeAEAD(t)
	revision := &storedpb.ContentRevision{
		CreatedAt:          123,
		CreatedAtNs:        456,
		MetadataAeadLength: 789,
	}

	cid, err := MakeContentID(revision, aead)
	require.NoError(t, err)

	parsed, err := ParseContentID(cid, aead)
	require.NoError(t, err)
	require.Equal(t, revision.GetCreatedAt(), parsed.GetCreatedAt())
	require.Equal(t, revision.GetCreatedAtNs(), parsed.GetCreatedAtNs())
	require.Equal(t, revision.GetMetadataAeadLength(), parsed.GetMetadataAeadLength())
}

func TestContentIDTampering(t *testing.T) {
	aead := makeAEAD(t)
	revision := &storedpb.ContentRevision{CreatedAt: time.Now().Unix()}
	cid, err := MakeContentID(revision, aead)
	require.NoError(t, err)

	cid[0] ^= 0xff
	_, err = ParseContentID(cid, aead)
	require.Error(t, err)
}
