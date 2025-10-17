package usercontent

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/starius/barterbackup/storedpb"
	"github.com/stretchr/testify/require"
)

func TestContentIDRoundTrip(t *testing.T) {
	seal, open := newDeterministicAEAD(t)
	revision := &storedpb.ContentRevision{
		CreatedAt:          1760123456,
		CreatedAtNs:        123456789,
		MetadataAeadLength: 10_000_000,
	}

	cid, err := MakeContentID(revision, seal)
	require.NoError(t, err)
	require.Equal(t, "69607f035df1660823d71f56deba50ccacdda65d9a9e14628d80c73a", hex.EncodeToString(cid))

	parsed, err := ParseContentID(cid, open)
	require.NoError(t, err)
	require.Equal(t, revision.GetCreatedAt(), parsed.GetCreatedAt())
	require.Equal(t, revision.GetCreatedAtNs(), parsed.GetCreatedAtNs())
	require.Equal(t, revision.GetMetadataAeadLength(), parsed.GetMetadataAeadLength())
}

func TestContentIDTampering(t *testing.T) {
	seal, open := newDeterministicAEAD(t)
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

func TestContentIDTimestampOverflow(t *testing.T) {
	seal, _ := newDeterministicAEAD(t)

	const maxInt64 = int64(^uint64(0) >> 1)
	const maxSeconds = maxInt64 / 1_000_000_000
	const remainder = maxInt64 % 1_000_000_000

	revision := &storedpb.ContentRevision{
		CreatedAt:          maxSeconds + 1,
		CreatedAtNs:        0,
		MetadataAeadLength: 1,
	}
	_, err := MakeContentID(revision, seal)
	require.ErrorContains(t, err, "overflow")

	revision = &storedpb.ContentRevision{
		CreatedAt:          maxSeconds,
		CreatedAtNs:        remainder + 1,
		MetadataAeadLength: 1,
	}

	_, err = MakeContentID(revision, seal)
	require.ErrorContains(t, err, "overflow")
}

func newDeterministicAEAD(t *testing.T) (SealFunc, OpenFunc) {
	t.Helper()

	key, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	require.NoError(t, err)
	seal, open, err := NewAEAD(key)
	require.NoError(t, err)
	return seal, open
}
