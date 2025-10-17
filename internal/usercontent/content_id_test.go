package usercontent

import (
	"testing"
	"time"

	"github.com/starius/barterbackup/storedpb"
	"github.com/stretchr/testify/require"
)

func TestContentIDRoundTrip(t *testing.T) {
	seal, open := makeContentIDAEAD(t)
	revision := &storedpb.ContentRevision{
		CreatedAt:          1760123456,
		CreatedAtNs:        123456789,
		MetadataAeadLength: 10_000_000,
	}

	cid, err := MakeContentID(revision, seal)
	require.NoError(t, err)

	parsed, err := ParseContentID(cid, open)
	require.NoError(t, err)
	require.Equal(t, revision.GetCreatedAt(), parsed.GetCreatedAt())
	require.Equal(t, revision.GetCreatedAtNs(), parsed.GetCreatedAtNs())
	require.Equal(t, revision.GetMetadataAeadLength(), parsed.GetMetadataAeadLength())
}

func TestContentIDTampering(t *testing.T) {
	seal, open := makeContentIDAEAD(t)
	revision := &storedpb.ContentRevision{CreatedAt: time.Now().Unix()}
	cid, err := MakeContentID(revision, seal)
	require.NoError(t, err)

	cipherTampered := append([]byte(nil), cid...)
	cipherTampered[0] ^= 0xff
	_, err = ParseContentID(cipherTampered, open)
	require.ErrorContains(t, err, "message authentication failure")

	macTampered := append([]byte(nil), cid...)
	macTampered[len(macTampered)-1] ^= 0xff
	_, err = ParseContentID(macTampered, open)
	require.ErrorContains(t, err, "message authentication failure")
}
